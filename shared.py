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
        SELECT p.url, p.title, p.snippet, rank AS score
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

def check_for_changes(age_hours: int = 24, min_content_length: int = 200) -> list[dict]:
    """Re-crawl pages last seen more than N hours ago.
    Returns list of pages with significant content changes.

    Each result: {url, title, old_snippet, new_snippet, change_ratio, checked_at}
    """
    import requests
    from bs4 import BeautifulSoup

    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row

    cutoff = (datetime.now() - __import__('datetime').timedelta(hours=age_hours)).isoformat()
    rows = db.execute(
        'SELECT url, title, snippet, body FROM pages WHERE crawled_at < ? ORDER BY crawled_at ASC LIMIT 100',
        (cutoff,)
    ).fetchall()

    if not rows:
        db.close()
        return []

    session = requests.Session()
    session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    changes = []
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

            if new_hash != old_hash:
                # Calculate how much changed
                old_len = len(row['body'] or '')
                new_len = len(new_body)
                ratio = abs(new_len - old_len) / max(old_len, 1)

                changes.append({
                    'url': row['url'],
                    'title': row['title'],
                    'old_snippet': (row['snippet'] or '')[:200],
                    'new_snippet': new_body[:200],
                    'change_ratio': round(ratio, 3),
                    'checked_at': datetime.now().isoformat(),
                })

                # Update the page in index
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
    return changes


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
    'porn': ['porn', 'adult', 'nsfw', 'xxx', 'premium', 'onlyfans', 'nude', 'teen',
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
