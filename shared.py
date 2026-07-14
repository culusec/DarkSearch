#!/usr/bin/env python3
"""
Shared utilities for DarkSearch + Threat Intel integration.
Import this from anywhere to query the search index, feed seeds, or check for changes.
"""

import sqlite3
import hashlib
import json
import time
from pathlib import Path
from datetime import datetime

DB_PATH = Path('/mnt/darkweb/index.db')
QUEUE_PATH = Path('/mnt/darkweb/queue.txt')


# ═══════════════════════════════════════════════
# 1. DIRECT QUERY API — threat intel queries the index
# ═══════════════════════════════════════════════

def search(query: str, limit: int = 50) -> list[dict]:
    """Query the dark web index directly. No Tor, no API key, sub-millisecond.

    Usage from threat intel app:
        from shared import search
        results = search('ransomware AND citibank')
        for r in results:
            print(r['title'], r['url'])

    Returns list of dicts: {url, title, snippet, score}
    """
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    t0 = time.time()
    rows = db.execute('''
        SELECT p.url, p.title, p.snippet, p.screenshot, rank AS score
        FROM pages_fts f
        JOIN pages p ON p.id = f.rowid
        WHERE pages_fts MATCH ?
        ORDER BY rank
        LIMIT ?
    ''', (query, limit)).fetchall()
    elapsed = round(time.time() - t0, 4)
    total = db.execute('SELECT COUNT(*) FROM pages').fetchone()[0]
    db.close()
    results = [dict(r) for r in rows]
    # Add full S3 URL for screenshots
    for r in results:
        if r.get('screenshot'):
            r['screenshot_url'] = f'https://threat-intel-raw-dumps.s3.us-east-2.amazonaws.com/{r["screenshot"]}'
    return {
        'results': results,
        'total_indexed': total,
        'query_time': elapsed,
        'count': len(results),
    }


def stats() -> dict:
    """Quick stats: how many pages, unique sites, last crawl time."""
    db = sqlite3.connect(str(DB_PATH))
    total = db.execute('SELECT COUNT(*) FROM pages').fetchone()[0]
    unique = db.execute(
        "SELECT COUNT(DISTINCT substr(url, 8, instr(substr(url, 8), '/')-1+7)) FROM pages"
    ).fetchone()[0]
    newest = db.execute('SELECT MAX(crawled_at) FROM pages').fetchone()[0]
    db.close()
    return {
        'total_pages': total,
        'unique_sites': unique,
        'newest_crawl': newest,
    }


# ═══════════════════════════════════════════════
# 2. SEED FEEDER — threat intel drops .onion URLs into the queue
# ═══════════════════════════════════════════════

def feed_seeds(urls: list[str]) -> int:
    """Add .onion URLs to the crawl queue. Call this from anywhere that
    encounters .onion links — threat intel searches, manual browsing, etc.

    Args:
        urls: List of URLs (only .onion ones will be kept)

    Returns:
        Number of new URLs added to queue

    Usage:
        from shared import feed_seeds
        feed_seeds(['http://example.onion', 'https://clearweb.com'])
    """
    existing = set()
    if QUEUE_PATH.exists():
        for line in open(QUEUE_PATH):
            existing.add(line.strip())

    added = 0
    with open(QUEUE_PATH, 'a') as f:
        for url in urls:
            url = url.strip().split('#')[0]
            if '.onion' in url and url not in existing:
                f.write(url + '\n')
                existing.add(url)
                added += 1

    return added


def feed_seeds_from_onionclaw(search_results: list[dict]) -> int:
    """Extract .onion URLs from OnionClaw/sicry search results and feed them.

    Args:
        search_results: The list of dicts returned by sicry.search()

    Returns:
        Number of new seeds added
    """
    urls = []
    for r in search_results:
        url = r.get('url', '') or r.get('link', '')
        if url:
            urls.append(url)
    return feed_seeds(urls)


# ═══════════════════════════════════════════════
# 3. CHANGE DETECTION — re-crawl existing pages, flag diffs
# ═══════════════════════════════════════════════

# Tiered re-crawl: priority pages checked more frequently
# Tier 1: ransomware + leak_site → every 3 hours (victims appear mid-day)
# Tier 2: forum + paste → every 12 hours (moderate churn)
# Tier 3: marketplace, directory, uncategorized → every 24 hours (rarely changes)
TIER_CONFIG = {
    1: {'categories': ['ransomware', 'leak_site'], 'age_hours': 3,  'max_per_run': 200},
    2: {'categories': ['forum', 'paste'],               'age_hours': 12, 'max_per_run': 100},
    3: {'categories': ['marketplace', 'directory', 'financial', 'drugs', 'porn',
                        'hosting', 'email', 'tools', 'uncategorized'],
         'age_hours': 24, 'max_per_run': 150},
}


def check_for_changes(tier: int = None, min_content_length: int = 200) -> list[dict]:
    """Re-crawl existing pages with tiered priority.
    
    Args:
        tier: 1 (ransomware/leak_site), 2 (forum/paste), 3 (everything else), or None (all tiers)
        min_content_length: minimum page content to consider
    
    Returns list of pages with significant content changes.
    Each result: {url, title, old_snippet, new_snippet, change_ratio, checked_at, tier}
    """
    import requests
    from bs4 import BeautifulSoup

    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row

    tiers_to_check = [tier] if tier else [1, 2, 3]
    all_changes = []

    for t in tiers_to_check:
        config = TIER_CONFIG.get(t)
        if not config:
            continue

        cutoff = (datetime.now() - __import__('datetime').timedelta(hours=config['age_hours'])).isoformat()
        
        # Build category filter: pages matching any of this tier's categories
        cat_clauses = ' OR '.join([f"categories LIKE '%{c}%'" for c in config['categories']])
        sql = f'''
            SELECT url, title, snippet, body, categories
            FROM pages 
            WHERE crawled_at < ? 
            AND ({cat_clauses})
            ORDER BY crawled_at ASC 
            LIMIT ?
        '''
        rows = db.execute(sql, (cutoff, config['max_per_run'])).fetchall()

        if not rows:
            continue

        session = requests.Session()
        session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        session.headers.update({'User-Agent': 'Mozilla/5.0'})

        for row in rows:
            try:
                resp = session.get(row['url'], timeout=25)
                if resp.status_code != 200:
                    continue

                soup = BeautifulSoup(resp.text, 'html.parser')
                for tag in soup(['script', 'style', 'nav', 'footer']):
                    tag.decompose()
                new_body = ' '.join(soup.get_text(separator=' ', strip=True).split())[:64000]

                if len(new_body) < min_content_length:
                    continue

                new_hash = hashlib.md5(new_body.encode()).hexdigest()
                old_hash = hashlib.md5((row['body'] or '').encode()).hexdigest()

                if new_hash == old_hash:
                    # Content unchanged — update crawled_at so we don't re-check it immediately
                    db.execute('UPDATE pages SET crawled_at=CURRENT_TIMESTAMP WHERE url=?', (row['url'],))
                    time.sleep(1)
                    continue

                old_len = len(row['body'] or '')
                new_len = len(new_body)
                ratio = abs(new_len - old_len) / max(old_len, 1)

                all_changes.append({
                    'url': row['url'],
                    'title': row['title'],
                    'categories': row['categories'],
                    'old_snippet': (row['snippet'] or '')[:200],
                    'new_snippet': new_body[:200],
                    'change_ratio': round(ratio, 3),
                    'checked_at': datetime.now().isoformat(),
                    'tier': t,
                })

                # Update the page in index with new content
                new_title = soup.title.string.strip() if soup.title else row['title']
                db.execute(
                    'UPDATE pages SET title=?, body=?, snippet=?, crawled_at=CURRENT_TIMESTAMP WHERE url=?',
                    (new_title, new_body, new_body[:300], row['url'])
                )

                time.sleep(2)

            except Exception:
                time.sleep(2)
                continue

    db.commit()
    db.close()
    return all_changes


# ── CSAM CONTENT FILTER ─────────────────────────────────────
# Pages matching these terms are BLOCKED from indexing.
# Aggressive: blocks porn/NSFW/adult content in addition to CSAM.
# Uses word-boundary matching so 'pre' flags "pre teen" but not "prepaid".

CSAM_BLOCKLIST = [
    # Direct CSAM terms (substring match — these are unambiguous)
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

# Broad age terms — ONLY flag if the page ALSO contains sexual keywords.
# Word-boundary matching prevents 'pre' from matching "prepaid", "premium", etc.
import re as _re

_CSAM_BROAD_PATTERNS = [
    r'\bkids?\b', r'\bchild(ren)?\b', r'\bteen(s|age)?\b',
    r'\bboy(s|hood)?\b', r'\bgirl(s|hood)?\b',
    r'\bpre\b', r'\byoung\b', r'\bunderage\b',
]

_CSAM_SEXUAL_PATTERNS = [
    r'\bnude\b', r'\bnaked\b', r'\bsex(ual)?\b',
    r'\bporn\b', r'\bxxx\b', r'\bhardcore\b', r'\berotic\b',
    r'\bescort\b', r'\bprostitute\b', r'\bintercourse\b',
]

_BROAD_RE = _re.compile('|'.join(_CSAM_BROAD_PATTERNS), _re.IGNORECASE)
_SEXUAL_RE = _re.compile('|'.join(_CSAM_SEXUAL_PATTERNS), _re.IGNORECASE)


def is_csam(title: str, body: str) -> bool:
    """Check page content for CSAM/porn. Returns True to BLOCK indexing."""
    text = f"{title or ''} {body or ''}".lower()
    
    # Direct hits — immediate block
    for term in CSAM_BLOCKLIST:
        if term in text:
            return True
    
    # Broad age term + sexual term combination — word boundary matched
    if _BROAD_RE.search(text) and _SEXUAL_RE.search(text):
        return True
    
    return False


# ═══════════════════════════════════════════════
# 4. CATEGORY TAGGING — classify pages during indexing
# ═══════════════════════════════════════════════

CATEGORIES = {
    'marketplace': ['buy', 'sell', 'vendor', 'escrow', 'cart', 'checkout', 'order', 'price',
                    'shipping', 'bitcoin', 'monero', 'wallet', 'shop', 'market', 'store',
                    'listing', 'product', 'payment', 'delivery'],
    'ransomware': ['ransom', 'decrypt', 'encrypted', 'leak', 'leaked', 'victim', 'pay',
                   'published', 'stolen data', 'dump', 'exfiltrated', 'hacked', 'compromised'],
    'forum': ['thread', 'reply', 'post', 'register', 'login', 'member', 'topic', 'board',
              'discussion', 'signature', 'avatar', 'pm', 'private message', 'moderator'],
    'leak_site': ['breach', 'database', 'dump', 'leaked', 'exposed', 'credentials', 'passwords',
                  'emails', 'combos', 'fullz', 'ssn', 'dob', 'pii', 'personal data'],
    'paste': ['paste', 'anonymous', 'plain text', 'raw', 'snippet', 'expires', 'burn'],
    'directory': ['directory', 'links', 'index', 'hidden wiki', 'list of', 'onion links'],
    'financial': ['credit card', 'cvv', 'dumps', 'bank account', 'transfer', 'western union',
                  'paypal', 'cashapp', 'venmo', 'fullz', 'carding', 'cashing out'],
    'drugs': ['cannabis', 'cocaine', 'mdma', 'lsd', 'xanax', 'prescription', 'pill',
              'ship', 'stealth', 'domestic', 'international', 'narcotic'],
    'porn': ['porn', 'adult', 'nsfw', 'xxx', 'premium', 'onlyfans', 'nude',
             'cam', 'hardcore', 'video', 'photo set'],
    'hosting': ['vps', 'hosting', 'server', 'bulletproof', 'anonymous hosting', 'domain',
                'offshore', 'no logs', 'dmca', 'web hosting'],
    'email': ['email', 'mail', 'inbox', 'protonmail', 'tutanota', 'cock.li', 'encrypted email',
              'secure email', 'anonymous email'],
    'tools': ['tool', 'hack', 'exploit', 'botnet', 'rat', 'malware', 'spyware', 'keylogger',
              'ddos', 'stressor', 'booter', 'crypter', 'binder'],
}

def classify_page(title: str, body: str) -> list[str]:
    """Classify a page into one or more categories based on keyword matching.

    Returns list of category names, or ['uncategorized'] if nothing matches.
    """
    text = f"{title or ''} {body or ''} ".lower()
    matched = []
    for category, keywords in CATEGORIES.items():
        score = sum(1 for kw in keywords if kw in text)
        threshold = max(2, len(keywords) * 0.03)  # 3% of keywords
        if score >= threshold:
            matched.append(category)
    return matched if matched else ['uncategorized']


def get_by_category(category: str, limit: int = 50) -> list[dict]:
    """Get pages by category. Requires categories to have been stored during indexing."""
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    # Check if categories column exists
    cols = [c[1] for c in db.execute('PRAGMA table_info(pages)').fetchall()]
    if 'categories' not in cols:
        db.execute('ALTER TABLE pages ADD COLUMN categories TEXT DEFAULT ""')
        db.commit()
    rows = db.execute(
        'SELECT url, title, snippet, categories FROM pages WHERE categories LIKE ? ORDER BY crawled_at DESC LIMIT ?',
        (f'%{category}%', limit)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]
