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
