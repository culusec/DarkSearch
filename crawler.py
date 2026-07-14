#!/usr/bin/env python3
"""Dark web crawler — persistent daemon that continuously crawls .onion pages via Tor.
When queue is empty, auto-harvests seeds from OnionClaw search engines."""

import sqlite3
import hashlib
import time
import os
import sys
import signal
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

# Add shared module and sicry
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, '/home/kplat/.pi/agent/skills/onionclaw')
from shared import classify_page, CATEGORIES

BASE = Path('/mnt/darkweb')
DB_PATH = BASE / 'index.db'
SEEDS_PATH = BASE / 'seeds.txt'
CRAWLED_PATH = BASE / 'crawled.txt'
QUEUE_PATH = BASE / 'queue.txt'
SCREENSHOT_DIR = BASE / 'screenshots'
LOG_PATH = BASE / 'logs' / 'crawler.log'

TOR_PROXY = 'socks5h://127.0.0.1:9050'
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'}
REQUEST_TIMEOUT = 30
CRAWL_DELAY = 1.5         # seconds between requests (aggressive but Tor-safe)
MAX_PAGES_PER_CYCLE = 200  # crawl this many then re-check for new seeds
IDLE_SLEEP = 30            # seconds to sleep when queue is empty
STALE_THRESHOLD = 600      # if DB unchanged for this many seconds, force seed harvest
HARVEST_INTERVAL = 1800    # auto-harvest seeds every 30 min
HARVEST_COOLDOWN = 120      # seconds to wait when all URLs exhausted (rotate keywords)

# Pages that get screenshots (high-value threat intel)
SCREENSHOT_CATEGORIES = {'ransomware', 'leak_site'}

# ── CSAM FILTER ──────────────────────────────────────────────
# Aggressive: blocks CSAM + porn/NSFW. Word-boundary matching
# prevents false positives like 'pre' matching "prepaid".
CSAM_BLOCKLIST = [
    'child porn', 'child pornography', 'preteen', 'pedo', 'pedophile',
    'lolita', 'pthc', 'ptsc', 'hussyfan', 'child model', 'underage',
    'jailbait', 'teen model', 'young girl', 'young boy', 'toddler',
    'kindergarten', 'nursery', 'diaper', 'pacifier',
    'nudism', 'naturist', 'family nudism',
    'hard candy', 'cheese pizza', 'cp company',
    'boy lover', 'girl lover', 'child lover',
    'years old nude', 'years old naked', 'years old sex',
    'pedo empire', 'pedo world',
]

import re as _re

_BROAD_PATTERNS = [
    r'\bkids?\b', r'\bchild(ren)?\b', r'\bteen(s|age)?\b',
    r'\bboy(s|hood)?\b', r'\bgirl(s|hood)?\b',
    r'\bpre\b', r'\byoung\b', r'\bunderage\b',
]
_SEXUAL_PATTERNS = [
    r'\bnude\b', r'\bnaked\b', r'\bsex(ual)?\b',
    r'\bporn\b', r'\bxxx\b', r'\bhardcore\b', r'\berotic\b',
    r'\bescort\b', r'\bprostitute\b', r'\bintercourse\b',
]
_BROAD_RE = _re.compile('|'.join(_BROAD_PATTERNS), _re.IGNORECASE)
_SEXUAL_RE = _re.compile('|'.join(_SEXUAL_PATTERNS), _re.IGNORECASE)

def is_csam(title: str, body: str) -> bool:
    """Check page content for CSAM/porn. Returns True to BLOCK indexing."""
    text = f"{title or ''} {body or ''}".lower()
    for term in CSAM_BLOCKLIST:
        if term in text:
            return True
    if _BROAD_RE.search(text) and _SEXUAL_RE.search(text):
        return True
    return False


def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute('''CREATE TABLE IF NOT EXISTS pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE,
        title TEXT,
        body TEXT,
        snippet TEXT,
        categories TEXT DEFAULT "",
        crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(title, body, content=pages, content_rowid=id)')
    cols = [c[1] for c in conn.execute('PRAGMA table_info(pages)').fetchall()]
    if 'screenshot' not in cols:
        conn.execute('ALTER TABLE pages ADD COLUMN screenshot TEXT DEFAULT ""')
    conn.commit()
    conn.execute('''CREATE TRIGGER IF NOT EXISTS pages_ai AFTER INSERT ON pages BEGIN
        INSERT INTO pages_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
    END''')
    conn.execute('''CREATE TRIGGER IF NOT EXISTS pages_ad AFTER DELETE ON pages BEGIN
        INSERT INTO pages_fts(pages_fts, rowid, title, body) VALUES('delete', old.id, old.title, old.body);
    END''')
    conn.commit()
    return conn


def load_set(path):
    if not path.exists():
        return set()
    return set(l.strip() for l in path.read_text().splitlines() if l.strip())


def save_line(path, line):
    with open(path, 'a') as f:
        f.write(line + '\n')


def extract_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        full = urljoin(base_url, href)
        if '.onion' in full:
            links.add(full.split('#')[0])
    return links


def extract_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
        tag.decompose()
    title = soup.title.string.strip() if soup.title else ''
    body = ' '.join(soup.get_text(separator=' ', strip=True).split())[:64000]
    snippet = body[:500] if body else ''
    return title, body, snippet


def screenshot_page(url: str) -> str | None:
    """Take a Playwright screenshot of an onion page via Tor. Returns S3 key or None."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    
    url_hash = hashlib.md5(url.encode()).hexdigest()[:16]
    fname = f'{url_hash}.png'
    s3_key = f'screenshots/{fname}'
    local_path = SCREENSHOT_DIR / fname
    
    try:
        import boto3
        s3 = boto3.Session(profile_name='oc-cassi', region_name='us-east-2').client('s3')
        s3.head_object(Bucket='threat-intel-raw-dumps', Key=s3_key)
        return s3_key
    except Exception:
        pass
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                user_agent="Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
                proxy={"server": "socks5://127.0.0.1:9050"},
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.goto(url if url.startswith('http') else f'http://{url}',
                      timeout=30000, wait_until='domcontentloaded')
            page.wait_for_timeout(2000)
            page.screenshot(path=str(local_path), full_page=False)
            browser.close()
            
            s3 = __import__('boto3').Session(profile_name='oc-cassi', region_name='us-east-2').client('s3')
            s3.upload_file(str(local_path), 'threat-intel-raw-dumps', s3_key)
            local_path.unlink(missing_ok=True)
            return s3_key
    except Exception:
        if local_path.exists():
            local_path.unlink(missing_ok=True)
        return None


# Rotating keyword pools for seed harvesting — avoids querying the same terms repeatedly
_HARVEST_KEYWORD_POOLS = [
    ['onion directory links', 'hidden wiki tor', 'darknet link list', 'onion index', 'tor directory', 'dark web links 2026', 'fresh onion sites'],
    ['darknet market forum', 'darknet marketplace', 'vendor shop onion', 'escrow service tor', 'bitcoin mixer onion', 'monero exchange darknet'],
    ['ransomware leak site', 'data breach dump', 'leaked database onion', 'hacked data leak', 'stolen credentials forum', 'ransomware group blog'],
    ['hacking forum community', 'exploit tools malware', 'ddos booter stresser', 'botnet c2 panel', 'carding cvv dumps', 'cracking tutorial onion'],
    ['cryptocurrency exchange onion', 'anonymous email service', 'secure messaging tor', 'whistleblower submit leak', 'darknet search engine', 'privacy tools onion'],
    ['darknet paste', 'tor pastebin', 'onion paste dump', 'anonymous text paste', 'dark web forum', 'tor chat room'],
    ['counterfeit money onion', 'fake id documents', 'passport template darknet', 'buy cc dumps', 'bank login onion', 'paypal transfer darknet'],
    ['drug market onion', 'cannabis delivery tor', 'prescription pills darknet', 'mdma lsd vendor', 'steroids shop onion'],
]
_harvest_pool_idx = 0

def harvest_seeds(keywords: list[str] = None) -> int:
    """Use OnionClaw/sicry to search for new .onion URLs and feed them into the queue.
    Also directly fetches known directory/link-list pages to extract fresh seeds.
    Filters out already-crawled URLs. Rotates keyword pools.
    Returns number of genuinely new seeds added."""
    global _harvest_pool_idx
    
    if keywords is None:
        keywords = _HARVEST_KEYWORD_POOLS[_harvest_pool_idx % len(_HARVEST_KEYWORD_POOLS)]
        _harvest_pool_idx += 1
    
    existing = load_set(QUEUE_PATH)
    crawled = load_set(CRAWLED_PATH)
    added = 0
    
    # Method 1: OnionClaw keyword search
    for kw in keywords[:5]:
        try:
            import sicry
            results = sicry.search(kw, max_results=15, engines=['Ahmia-clearnet', 'Tor66', 'Excavator', 'OnionLand', 'TheDeepSearches'])
            for r in results:
                url = r.get('url', '') or r.get('link', '')
                if '.onion' in url and url not in existing and url not in crawled:
                    save_line(QUEUE_PATH, url)
                    existing.add(url)
                    crawled.add(url)
                    added += 1
        except Exception as e:
            log(f'  seed harvest error ({kw}): {e}')
            continue
        time.sleep(3)
    
    # Method 2: Directly scrape directory/link-list pages for fresh links
    # These are high-value seed pages with hundreds of .onion links each
    DIRECTORY_SEEDS = [
        'http://deeeepv4bfndyatwkdzeciebqcwwlvgqa6mofdtsvwpon4elfut7lfqd.onion/',  # DeepLink
        'http://tordexu73joywapk2txdr54jed4imqledpcvcuf75qsas2gwdgksvnyd.onion/',  # Tordex
        'http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/',  # Tor66
    ]
    try:
        session = requests.Session()
        session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'})
        for seed_url in DIRECTORY_SEEDS:
            try:
                resp = session.get(seed_url, timeout=25)
                if resp.status_code == 200:
                    links = extract_links(resp.text, seed_url)
                    for link in links:
                        if link not in existing and link not in crawled:
                            save_line(QUEUE_PATH, link)
                            existing.add(link)
                            crawled.add(link)
                            added += 1
                    log(f'  directory scrape: +{len(links & (existing - set()))} from {seed_url[:50]}')
            except Exception:
                continue
            time.sleep(3)
        session.close()
    except Exception:
        pass
    
    return added


# ── Bridge to collect.py dump pipeline ──
DUMP_QUEUE_PATH = Path('/mnt/threat_intel/raw/darkweb_dump_queue.jsonl')
DUMP_FILE_EXTS = ['.sql', '.csv', '.tsv', '.txt', '.tar.gz', '.tar', '.gz',
                  '.zip', '.rar', '.7z', '.json', '.xml', '.db', '.sqlite',
                  '.dump', '.backup', '.bak', '.bson', '.ndjson', '.xlsx', '.xls']

def _feed_dump_queue(page_url: str, title: str, html: str):
    """Extract data file links from a leak_site page and feed to collect.py's download queue."""
    import json as _json
    
    # Extract all .onion links that look like data files
    soup = BeautifulSoup(html, 'html.parser')
    data_links = []
    for a in soup.find_all('a', href=True):
        href = a['href'].lower()
        if any(href.endswith(ext) for ext in DUMP_FILE_EXTS):
            full = urljoin(page_url, a['href'])
            if '.onion' in full:
                data_links.append(full)
    
    if not data_links:
        return
    
    try:
        existing = set()
        if DUMP_QUEUE_PATH.exists():
            for line in DUMP_QUEUE_PATH.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        existing.add(_json.loads(line).get('url', ''))
                    except:
                        pass
        
        new = 0
        with open(DUMP_QUEUE_PATH, 'a') as f:
            for link in data_links[:20]:  # Cap at 20 per page
                if link not in existing:
                    entry = {"url": link, "source_page": page_url, "source_title": title,
                              "source": "darkweb_crawler", "discovered_at": time.strftime('%Y-%m-%d %H:%M:%S')}
                    f.write(_json.dumps(entry) + '\n')
                    existing.add(link)
                    new += 1
        if new:
            log(f'  → fed {new} dump URLs to collect.py queue')
    except Exception as e:
        log(f'  → dump queue write error: {e}')


def log(msg: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f'{ts} {msg}'
    try:
        print(line, flush=True)
    except (BrokenPipeError, OSError):
        pass
    try:
        with open(LOG_PATH, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


# ── Signal handling for clean shutdown ──
_shutdown = False

def handle_signal(sig, frame):
    global _shutdown
    log(f'Received signal {sig}, shutting down gracefully...')
    _shutdown = True

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


# ═══════════════════════════════════════════════
# MAIN DAEMON LOOP
# ═══════════════════════════════════════════════

def main():
    global _shutdown
    
    # Prevent duplicate instances
    import fcntl
    lockfile = Path('/tmp/darksearch_crawler.lock')
    lock_fd = open(lockfile, 'w')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log('Another crawler instance is already running. Exiting.')
        sys.exit(0)
    
    # Write PID for watchdog
    lock_fd.write(str(os.getpid()))
    lock_fd.flush()
    
    log('=== DarkSearch crawler daemon starting ===')
    
    session = requests.Session()
    session.proxies = {'http': TOR_PROXY, 'https': TOR_PROXY}
    session.headers.update(HEADERS)
    
    seeds = load_lines(SEEDS_PATH)
    crawled = load_set(CRAWLED_PATH)
    
    total_crawled = 0
    total_skipped_csam = 0
    last_harvest = time.time() - HARVEST_INTERVAL  # trigger first harvest soon
    last_db_change = time.time()
    cycle = 0
    
    while not _shutdown:
        cycle += 1
        queue = load_lines(QUEUE_PATH)
        
        if not queue:
            # Queue empty — try seed harvest or idling
            now = time.time()
            if now - last_harvest >= HARVEST_INTERVAL:
                log('Queue empty — harvesting seeds...')
                added = harvest_seeds()
                last_harvest = now
                if added > 0:
                    log(f'  +{added} new seeds harvested, resuming crawl')
                    queue = load_lines(QUEUE_PATH)
                    if not queue:
                        time.sleep(5)
                        continue
                else:
                    log('  No new seeds found, idle for {}s'.format(IDLE_SLEEP))
                    # Re-seed from seed file every few cycles
                    if cycle % 10 == 0 and seeds:
                        log(f'  Re-seeding from {len(seeds)} base seeds')
                        for s in seeds:
                            if s not in crawled:
                                save_line(QUEUE_PATH, s)
                                crawled.add(s)
                                total_crawled += 1
                    time.sleep(IDLE_SLEEP)
                    continue
            else:
                # Wait for harvest interval
                sleep_time = min(IDLE_SLEEP, HARVEST_INTERVAL - (now - last_harvest))
                if sleep_time > 0:
                    time.sleep(sleep_time)
                continue
        
        # Crawl up to MAX_PAGES_PER_CYCLE from queue
        db = get_db()
        cycle_count = 0
        cycle_csam = 0
        
        for url in queue[:MAX_PAGES_PER_CYCLE]:
            if _shutdown:
                break
            if cycle_count >= MAX_PAGES_PER_CYCLE:
                break
            
            if url in crawled:
                continue
            
            log(f'[{total_crawled + 1}] {url[:90]}...')
            crawled.add(url)
            save_line(CRAWLED_PATH, url)
            
            try:
                resp = session.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code != 200:
                    log(f'  -> HTTP {resp.status_code}')
                    time.sleep(CRAWL_DELAY)
                    continue
                
                html = resp.text
                title, body, snippet = extract_text(html)
                
                if not body or len(body) < 100:
                    log(f'  -> too little content ({len(body)} chars)')
                    time.sleep(CRAWL_DELAY)
                    continue
                
                # ── CSAM CHECK ──
                if is_csam(title, body):
                    log(f'  -> CSAM BLOCKED')
                    cycle_csam += 1
                    total_skipped_csam += 1
                    time.sleep(CRAWL_DELAY)
                    continue
                
                categories = classify_page(title, body)
                
                db.execute(
                    'INSERT OR REPLACE INTO pages (url, title, body, snippet, categories) VALUES (?, ?, ?, ?, ?)',
                    (url, title, body, snippet, ','.join(categories))
                )
                db.commit()
                last_db_change = time.time()
                
                # Screenshot ransomware/leak_site pages
                if SCREENSHOT_CATEGORIES & set(categories):
                    ss = screenshot_page(url)
                    if ss:
                        db.execute('UPDATE pages SET screenshot=? WHERE url=?', (ss, url))
                        db.commit()
                
                # ── Bridge to collect.py: feed leak_site URLs to dump download queue ──
                if 'leak_site' in categories:
                    _feed_dump_queue(url, title, html)
                
                # Extract new links
                new_links = extract_links(html, url) - crawled
                for link in new_links:
                    save_line(QUEUE_PATH, link)
                
                total_crawled += 1
                cycle_count += 1
                log(f'  -> OK [{",".join(categories[:3])}] +{len(new_links)} links, {len(body)} chars')
                
            except requests.Timeout:
                log(f'  -> timeout')
            except requests.ConnectionError:
                log(f'  -> connection failed (dead?)')
            except Exception as e:
                log(f'  -> error: {e}')
            
            time.sleep(CRAWL_DELAY)
        
        # Remove processed URLs from queue
        remaining = [u for u in queue if u not in crawled]
        QUEUE_PATH.write_text('\n'.join(remaining) + ('\n' if remaining else ''))
        
        total_indexed = db.execute('SELECT COUNT(*) FROM pages').fetchone()[0]
        db.close()
        
        log(f'Cycle {cycle}: crawled {cycle_count}, CSAM blocked {cycle_csam}, index={total_indexed}, queue={len(remaining)}')
        
        if cycle_count == 0 and len(remaining) == 0:
            # All URLs exhausted — wait with cooldown, then rotate keyword pool
            log(f'  All URLs exhausted, waiting {HARVEST_COOLDOWN}s then rotating keywords')
            last_harvest = time.time() - HARVEST_INTERVAL + HARVEST_COOLDOWN  # trigger after cooldown
    
    log(f'=== Daemon stopped. Total crawled: {total_crawled}, CSAM blocked: {total_skipped_csam} ===')


# Compatibility wrapper for old load_lines
def load_lines(path):
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip()]


if __name__ == '__main__':
    main()
