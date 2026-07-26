#!/usr/bin/env python3
"""
Shared utilities for DarkSearch + Threat Intel integration.
Uses PostgreSQL on RDS via db.py pool — no local SQLite.
"""

import hashlib, json, time, re
from pathlib import Path
from datetime import datetime
import sys
sys.path.insert(0, '/mnt/threat_intel/scripts')
from db import db_fetchall, db_fetchone, db_execute

QUEUE_PATH = Path('/mnt/darkweb/queue.txt')

# ═══════════════════════════════════════════════
# 1. DIRECT QUERY API — threat intel queries the index
# ═══════════════════════════════════════════════

def search(query: str, limit: int = 50) -> dict:
    """Full-text search over darkweb pages using PostgreSQL tsvector."""
    t0 = time.time()
    rows = db_fetchall(
        "SELECT url, title, snippet, screenshot, "
        "ts_rank(to_tsvector('english', coalesce(title,'') || ' ' || coalesce(body,'')), "
        "plainto_tsquery('english', %s)) as score "
        "FROM darkweb_pages "
        "WHERE to_tsvector('english', coalesce(title,'') || ' ' || coalesce(body,'')) "
        "@@ plainto_tsquery('english', %s) "
        "ORDER BY score DESC LIMIT %s",
        (query, query, limit)
    )
    elapsed = round(time.time() - t0, 4)
    total = db_fetchone("SELECT COUNT(*) as cnt FROM darkweb_pages")['cnt']
    results = [dict(r) for r in rows]
    for r in results:
        if r.get('screenshot'):
            r['screenshot_url'] = f'https://threat-intel-raw-dumps.s3.us-east-2.amazonaws.com/{r["screenshot"]}'
    return {
        'results': results, 'total_indexed': total,
        'query_time': elapsed, 'count': len(results),
    }


def stats() -> dict:
    """Quick stats: total pages, unique sites, newest crawl."""
    total = db_fetchone("SELECT COUNT(*) as cnt FROM darkweb_pages")['cnt']
    unique = db_fetchone(
        "SELECT COUNT(DISTINCT split_part(replace(url,'http://',''),'.onion',1)) as cnt FROM darkweb_pages"
    )['cnt']
    newest = db_fetchone("SELECT MAX(crawled_at) as ts FROM darkweb_pages")['ts']
    return {
        'total_pages': total, 'unique_sites': unique,
        'newest_crawl': str(newest) if newest else None,
    }


# ═══════════════════════════════════════════════
# 2. SEED FEEDER — threat intel drops .onion URLs into the queue
# ═══════════════════════════════════════════════

def feed_seed(url: str) -> bool:
    """Add a .onion URL to the crawler queue."""
    if '.onion' not in url:
        return False
    existing = set()
    if QUEUE_PATH.exists():
        existing = set(l.strip() for l in QUEUE_PATH.read_text().splitlines() if l.strip())
    if url in existing:
        return False
    with open(QUEUE_PATH, 'a') as f:
        f.write(url + '\n')
    return True


# ═══════════════════════════════════════════════
# 3. CHANGE DETECTION — tiered re-crawl for threat intel
# ═══════════════════════════════════════════════

TIER_CONFIG = {
    1: {'categories': ['ransomware', 'leak_site'], 'age_hours': 3, 'max_per_run': 20},
    2: {'categories': ['forum', 'paste'], 'age_hours': 12, 'max_per_run': 30},
    3: {'categories': ['marketplace', 'directory', 'financial', 'drugs', 'porn',
                        'hosting', 'email', 'tools', 'uncategorized'],
         'age_hours': 24, 'max_per_run': 50},
}


def get_by_category(category: str, limit: int = 50) -> list[dict]:
    """Get pages by category from the PostgreSQL index."""
    rows = db_fetchall(
        "SELECT url, title, snippet, categories, screenshot "
        "FROM darkweb_pages WHERE categories LIKE %s "
        "ORDER BY crawled_at DESC LIMIT %s",
        (f'%{category}%', limit)
    )
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════
# 4. CLASSIFICATION — page categorization
# ═══════════════════════════════════════════════

CATEGORIES = [
    ('marketplace', ['market', 'shop', 'vendor', 'escrow', 'autoshop', 'order', 'cart', 'price', 'buy', 'sell', 'payment', 'checkout', 'product']),
    ('ransomware', ['ransom', 'leak site', 'victim', 'decrypt', 'ransomware', 'extortion', 'data leak', 'stolen data', 'breach']),
    ('forum', ['forum', 'thread', 'topic', 'board', 'discussion', 'reply', 'post', 'member', 'register', 'login']),
    ('leak_site', ['leaked', 'database dump', 'data breach', 'full database', 'leaked data', 'exposed', 'dump', 'breach']),
    ('financial', ['bitcoin', 'crypto', 'wallet', 'exchange', 'mixer', 'tumbler', 'monero', 'xmr', 'btc']),
    ('email', ['email', 'protonmail', 'tutanota', 'mail', 'inbox', 'secure email']),
    ('tools', ['tool', 'utility', 'generator', 'checker', 'lookup', 'search', 'crawler']),
    ('drugs', ['cannabis', 'cocaine', 'mdma', 'lsd', 'xanax', 'pills', 'drug', 'steroid', 'prescription']),
    ('porn', ['porn', 'adult', 'nsfw', 'escort', 'cam', 'sex', 'xxx']),
    ('hosting', ['hosting', 'vps', 'server', 'bulletproof', 'offshore', 'domain']),
    ('directory', ['directory', 'links', 'index of', 'listing', 'wiki', 'catalog']),
    ('paste', ['paste', 'pastebin', 'text', 'anonymous']),
    ('uncategorized', []),
]

def classify_page(title: str, body: str) -> list[str]:
    """Classify a page into categories based on title and body text."""
    text = f"{title or ''} {body or ''}".lower()
    categories = []
    for cat, keywords in CATEGORIES:
        if cat == 'uncategorized':
            continue
        for kw in keywords:
            if kw in text:
                categories.append(cat)
                break
    return categories if categories else ['uncategorized']
