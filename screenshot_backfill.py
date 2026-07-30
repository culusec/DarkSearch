#!/usr/bin/env python3
"""
screenshot_backfill.py — One-time backfill of screenshots for existing Tier 1 pages.
=====================================================================================
Screenshots all existing index pages tagged ransomware or leak_site that
don't already have a screenshot. Runs once, then the crawler handles new pages.

Usage: python3 screenshot_backfill.py
       python3 screenshot_backfill.py --limit 50   # Do 50 at a time
       python3 screenshot_backfill.py --force       # Re-screenshot even if exists
"""
import sys, time
from pathlib import Path
from datetime import datetime

BASE = Path('/opt/darkweb')

sys.path.insert(0, '/mnt/threat_intel/scripts')
from db import db_fetchall, db_fetchone, db_execute

def screenshot_page(url: str, existing_file: str = None, force: bool = False) -> str | None:
    """Take a Playwright screenshot, upload to S3. Returns S3 key or None."""
    import hashlib
    from playwright.sync_api import sync_playwright
    import boto3
    
    url_hash = hashlib.md5(url.encode()).hexdigest()[:16]
    fname = f'{url_hash}.png'
    s3_key = f'screenshots/{fname}'
    local_path = BASE / 'screenshots' / fname
    local_path.parent.mkdir(exist_ok=True)
    
    # Check if already in S3
    if not force:
        try:
            s3_check = boto3.Session(profile_name='oc-cassi', region_name='us-east-2').client('s3')
            s3_check.head_object(Bucket='threat-intel-raw-dumps', Key=s3_key)
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
            full_url = url if url.startswith('http') else f'http://{url}'
            page.goto(full_url, timeout=30000, wait_until='domcontentloaded')
            page.wait_for_timeout(3000)
            page.screenshot(path=str(local_path), full_page=False)
            browser.close()
            
            # Upload to S3
            s3 = boto3.Session(profile_name='oc-cassi', region_name='us-east-2').client('s3')
            s3.upload_file(str(local_path), 'threat-intel-raw-dumps', s3_key)
            local_path.unlink(missing_ok=True)
            return s3_key
    except Exception as e:
        if local_path.exists():
            local_path.unlink(missing_ok=True)
        print(f'  ✗ {url[:60]}: {e}')
        return None


def main():
    force = '--force' in sys.argv
    limit = None
    for i, arg in enumerate(sys.argv):
        if arg == '--limit' and i + 1 < len(sys.argv):
            limit = int(sys.argv[i + 1])
    
    db = sqlite3.connect(str(DB_PATH))
    db.execute('PRAGMA journal_mode=WAL')
    
    # Find Tier 1 pages without screenshots
    query = """
        SELECT url, title, categories FROM darkweb_pages 
        WHERE (categories LIKE '%ransomware%' OR categories LIKE '%leak_site%')
        AND (screenshot IS NULL OR screenshot = '')
        ORDER BY crawled_at DESC
    """
    if limit:
        query += f' LIMIT {limit}'
    
    if force:
        query = """
            SELECT url, title, categories FROM darkweb_pages 
            WHERE (categories LIKE '%ransomware%' OR categories LIKE '%leak_site%')
            ORDER BY crawled_at DESC
        """ + (f' LIMIT {limit}' if limit else '')
    
    rows = db_fetchall(query)
    total = len(rows)
    print(f'Pages to screenshot: {total}')
    print(f'Force mode: {force}')
    print()
    
    done = 0
    failed = 0
    for i, (url, title, cats) in enumerate(rows):
        print(f'[{i+1}/{total}] {title[:60]}')
        print(f'  {url[:80]}')
        
        ss = screenshot_page(url, force=force)
        if ss:
            db_execute('UPDATE darkweb_pages SET screenshot=%s WHERE url=%s', (ss, url))
            done += 1
            print(f'  ✅ {ss}')
        else:
            failed += 1
        
        # Brief pause between screenshots
        if i < total - 1:
            time.sleep(3)
    
    print(f'Done. {done} screenshots saved, {failed} failed.')
    print(f'Screenshots in: {BASE / "screenshots"}')


if __name__ == '__main__':
    main()
