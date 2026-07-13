#!/usr/bin/env python3
"""Dark web crawler — feeds .onion pages through Tor into the indexer."""

import sqlite3
import hashlib
import time
import os
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

# Add shared module
sys.path.insert(0, str(Path(__file__).parent))
from shared import classify_page

BASE = Path('/mnt/darkweb')
DB_PATH = BASE / 'index.db'
SEEDS_PATH = BASE / 'seeds.txt'
CRAWLED_PATH = BASE / 'crawled.txt'
QUEUE_PATH = BASE / 'queue.txt'

TOR_PROXY = 'socks5h://127.0.0.1:9050'
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'}
REQUEST_TIMEOUT = 30
CRAWL_DELAY = 2   # seconds between requests
MAX_PAGES = 5000  # per run


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
    # Add screenshot column if it doesn't exist
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


def load_lines(path):
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip()]


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


SCREENSHOT_DIR = BASE / 'screenshots'
SCREENSHOT_DIR.mkdir(exist_ok=True)

# Categories that get screenshots (high-value threat intel pages)
SCREENSHOT_CATEGORIES = {'ransomware', 'leak_site'}


def screenshot_page(url: str) -> str | None:
    """Take a Playwright screenshot of an onion page via Tor.
    Uploads to S3: s3://threat-intel-raw-dumps/screenshots/<hash>.png
    Returns the S3 key on success, None on failure."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    
    import hashlib as _hashlib
    url_hash = _hashlib.md5(url.encode()).hexdigest()[:16]
    fname = f'{url_hash}.png'
    s3_key = f'screenshots/{fname}'
    local_path = SCREENSHOT_DIR / fname
    
    # Don't re-screenshot if already in S3
    try:
        import boto3
        s3 = boto3.Session(profile_name='oc-cassi', region_name='us-east-2').client('s3')
        s3.head_object(Bucket='threat-intel-raw-dumps', Key=s3_key)
        return s3_key  # Already exists
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
            
            # Upload to S3
            import boto3 as _boto3
            s3 = _boto3.Session(profile_name='oc-cassi', region_name='us-east-2').client('s3')
            s3.upload_file(str(local_path), 'threat-intel-raw-dumps', s3_key)
            local_path.unlink(missing_ok=True)  # Clean up local copy
            return s3_key
    except Exception:
        if local_path.exists():
            local_path.unlink(missing_ok=True)
        return None


def crawl(max_pages=MAX_PAGES):
    db = get_db()
    session = requests.Session()
    session.proxies = {'http': TOR_PROXY, 'https': TOR_PROXY}
    session.headers.update(HEADERS)
    
    # Load state
    seeds = load_lines(SEEDS_PATH)
    queue = load_lines(QUEUE_PATH)
    crawled = set(load_lines(CRAWLED_PATH))
    
    if not queue and seeds:
        queue = seeds[:]
        print(f'Loaded {len(seeds)} seeds')
    
    count = 0
    for url in queue[:]:
        if count >= max_pages:
            break
        
        if url in crawled:
            continue
        
        print(f'[{count+1}/{max_pages}] {url[:80]}...')
        crawled.add(url)
        save_line(CRAWLED_PATH, url)
        
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                print(f'  -> HTTP {resp.status_code}, skipping')
                time.sleep(CRAWL_DELAY)
                continue
            
            html = resp.text
            title, body, snippet = extract_text(html)
            
            if not body or len(body) < 100:
                print(f'  -> too little content ({len(body)} chars), skipping')
                time.sleep(CRAWL_DELAY)
                continue
            
            db.execute(
                'INSERT OR REPLACE INTO pages (url, title, body, snippet, categories) VALUES (?, ?, ?, ?, ?)',
                (url, title, body, snippet, ','.join(classify_page(title, body)))
            )
            db.commit()
            
            # ── Screenshot ransomware/leak_site pages ──
            categories = classify_page(title, body)
            if SCREENSHOT_CATEGORIES & set(categories):
                ss = screenshot_page(url)
                if ss:
                    db.execute('UPDATE pages SET screenshot=? WHERE url=?', (ss, url))
                    db.commit()
            
            # Extract new links
            new_links = extract_links(html, url) - crawled
            for link in new_links:
                save_line(QUEUE_PATH, link)
            
            count += 1
            print(f'  -> OK, {len(new_links)} new links, {len(body)} chars')
            
        except requests.Timeout:
            print(f'  -> timeout')
        except requests.ConnectionError:
            print(f'  -> connection failed (dead onion?)')
        except Exception as e:
            print(f'  -> error: {e}')
        
        time.sleep(CRAWL_DELAY)
    
    # Remove processed urls from queue
    remaining = [u for u in queue if u not in crawled]
    QUEUE_PATH.write_text('\n'.join(remaining))
    
    total_indexed = db.execute('SELECT COUNT(*) FROM pages').fetchone()[0]
    db.close()
    print(f'\nDone. Crawled {count} pages. Total in DB: {total_indexed}')


if __name__ == '__main__':
    crawl()
