#!/usr/bin/env python3
"""Dark web crawler — persistent daemon that continuously crawls .onion pages via Tor.
When queue is empty, auto-harvests seeds from OnionClaw search engines.
Uses PostgreSQL on RDS (via db.py pool) — no local SQLite."""

import hashlib
import time
import os
import sys
import signal
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

# PostgreSQL via shared pool
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, '/opt/threat_intel/scripts')
sys.path.insert(0, '/opt/threat_intel/scripts')
from db import db_fetchall, db_fetchone, db_execute, get_pool
from shared import classify_page, CATEGORIES

# Shared connection pool
_pool = get_pool()

BASE = Path('/opt/darkweb')
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

# Safe domains — legitimate services that discuss CSAM filtering
CSAM_SAFELIST = [
    'juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd',  # Ahmia onion
    'ahmia.fi',
]

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

def is_csam(title: str, body: str, url: str = '') -> bool:
    """Check page content for CSAM/porn. Returns True to BLOCK indexing."""
    # Safe domains — never block
    for safe in CSAM_SAFELIST:
        if safe in url:
            return False
    
    text = f"{title or ''} {body or ''}".lower()
    for term in CSAM_BLOCKLIST:
        if term in text:
            return True
    if _BROAD_RE.search(text) and _SEXUAL_RE.search(text):
        return True
    return False


def get_db():
    """Return a psycopg2 connection from the shared pool (RDS)."""
    conn = _pool.getconn()
    conn.autocommit = False
    # Ensure schema exists (once)
    with conn.cursor() as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS darkweb_pages (
            id SERIAL PRIMARY KEY,
            url TEXT UNIQUE NOT NULL,
            title TEXT DEFAULT '',
            body TEXT DEFAULT '',
            snippet TEXT DEFAULT '',
            categories TEXT DEFAULT '',
            screenshot TEXT DEFAULT '',
            crawled_at TIMESTAMP DEFAULT NOW()
        )''')
        cur.execute("""CREATE INDEX IF NOT EXISTS idx_darkweb_pages_fts 
            ON darkweb_pages USING gin(to_tsvector('english', coalesce(title,'') || ' ' || coalesce(body,'')))""")
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
    # Fresh pools — 2026-07-17
    ['initial access broker', 'ransomware affiliate panel', 'data extortion blog', 'leak site mirror', 'ransomware negotiation chat', 'stolen data marketplace'],
    ['AI jailbreak prompt', 'chatgpt exploit darknet', 'deepfake generator onion', 'voice clone service', 'AI hacking tool', 'LLM prompt injection'],
    ['api key leak', 'cloud credential dump', 'aws access key', 'azure tenant hack', 's3 bucket leak', 'terraform state exposure'],
    ['sim swap service', 'telegram account hack', 'whatsapp spy tool', 'signal intercept', 'sms redirection', 'phone number lookup darknet'],
    ['crypto drainer script', 'nft scam template', 'wallet cracker tool', 'ethereum private key', 'solana drainer', 'metamask seed phrase'],
    ['supply chain attack', 'software backdoor', 'zero day exploit sell', 'vulnerability broker', 'exploit chain forum', 'cve exploit code'],
    ['bank wire transfer', 'ach fraud method', 'check kiting tutorial', 'money mule recruitment', 'drop account service', 'emi account opening'],
    ['dark web news 2026', 'onion site update', 'hidden service launch', 'tor project news', 'darknet bust arrest', 'exit scam warning'],
    # Fresh pools — 2026-07-18 (discovery, credentials, exploits, platform footprints)
    ['onion list v3', 'active mirrors tor', 'tor link list 2026', 'dark web directory links', 'hidden service onion', 'onion service index'],
    ['combo list dump', 'email password leak', 'stealer logs onion', 'fullz dump forum', 'login combo database', 'credential stuffing target'],
    ['0day exploit sell', 'cve exploit code 2026', 'rce payload onion', 'malware source code leak', 'ransomware payload builder', 'red tearm c2 framework'],
    ['rdp access sell', 'vpn logs compromised', 'server root access', 'citrix access broker', 'backdoor shell access', 'corporate network access'],
    ['.env leak database', 'config file exposure', 'aws keys leaked', 'api keys dump', 'private ssh key leak', 'cloud credential github'],
    ['autoshop carding', 'cloned cards vendor', 'cvv shop onion', 'bank logs market', 'carding forum 2026', 'paypal logs shop'],
    ['fake passport template', 'counterfeit cash onion', 'cloned bills vendor', 'scam kit phishing', 'phishing template darknet', 'novelty id documents'],
    ['btc wallet cracker', 'xmr address lookup', 'crypto mixer onion', 'bitcoin tumbler service', 'coinjoin implementation', 'monero exchange anonymous'],
    ['powered by vbulletin onion', 'xenforo forum darknet', 'phpbb hidden service', 'mybb dark web', 'simple machines forum tor', 'discourse onion site'],
    # Forum & community names — 2026-07-18
    ['Dread forum onion', 'XSS forum darknet', 'Exploit.in tor', 'Endchan onion', 'cryptbb dark web', 'SuprBay forum onion'],
    ['index.php forum tor', 'viewforum.php onion', 'register account darknet', 'captcha tor forum', 'pgp key required', 'invite code onion'],
    # Active marketplace names & patterns
    ['TorZon market onion', 'BriansClub onion', 'Russian Market darknet', 'WeTheNorth market tor', 'Abacus market onion', 'Archetyp market darknet'],
    ['escrow service tor', 'vendor panel onion', 'wallet balance darknet', 'dispute resolution market', 'Monero accepted', 'XMR multisig'],
    ['multisig escrow onion', 'BTC wallet darknet', 'finalize early', 'FE allowed market', 'trusted vendor tor', 'verified seller onion'],
    # Privacy, dev & whistleblowing
    ['SecureDrop onion', 'leak submission tor', 'anonymous tip darknet', 'whistleblower submit', 'onion mirror site', 'Gitea hidden service'],
    ['XMPP server onion', 'Matrix bridge tor', 'censorship circumvention', 'samizdat darknet', 'monero node onion', 'tor relay operator'],
]

# Broad search terms — used when keyword pools are exhausted
# Queries Torch directly for .onion links (no OnionClaw dependency)
_BROAD_SEARCH_TERMS = [
    'breach', 'hack', 'leak', 'dump', 'database', 'stolen', 'ransomware',
    'exploit', 'malware', 'botnet', 'phishing', 'spyware', 'trojan', 'rootkit',
    'bitcoin', 'monero', 'wallet', 'crypto', 'exchange', 'mixer', 'tumbler',
    'forum', 'market', 'shop', 'vendor', 'escrow', 'carding', 'cvv', 'fullz',
    'passport', 'id card', 'driver license', 'ssn', 'credit card', 'bank account',
    'paypal', 'western union', 'transfer', 'cashapp', 'venmo', 'money',
    'drugs', 'cannabis', 'cocaine', 'mdma', 'lsd', 'xanax', 'pills', 'steroids',
    'hosting', 'vps', 'server', 'domain', 'bulletproof', 'offshore', 'anonymous',
    'email', 'protonmail', 'tutanota', 'encrypted', 'secure', 'private',
    'vpn', 'proxy', 'tor', 'onion', 'darknet', 'darkweb', 'hidden',
    'wiki', 'directory', 'links', 'list', 'index', 'catalog',
    'counterfeit', 'fake', 'cloned', 'prepaid', 'gift card', 'coupon',
    'weapon', 'gun', 'ammo', 'knife', 'self defense',
    'porn', 'adult', 'nsfw', 'escort', 'dating', 'sex',
    'gambling', 'casino', 'betting', 'poker', 'slots', 'lottery',
    'ebook', 'pdf', 'book', 'library', 'document', 'archive', 'research',
    'music', 'movie', 'video', 'streaming', 'download', 'torrent',
    'news', 'blog', 'journal', 'article', 'media', 'press',
    'chat', 'messaging', 'jabber', 'xmpp', 'irc', 'telegram', 'signal',
    'file', 'upload', 'share', 'cloud', 'storage', 'backup',
    'search engine', 'crawler', 'scraper', 'spider',
    # Fresh batch — more specific and varied
    'stolen data', 'data leak', 'leaked database', 'breach database',
    'hacked database', 'dump database', 'company leak', 'corporate leak',
    'credential leak', 'password dump', 'email leak', 'combo list',
    'buy account', 'sell account', 'bank log', 'paypal log',
    'rdp shop', 'socks proxy', 'cpanel shell', 'smtp access',
    'scan result', 'vulnerability', '0day exploit', 'zero day',
    'keylogger', 'stealer log', 'redline log', 'vidar log', 'raccoon log',
    'ransomware victim', 'ransom demand', 'decrypt tool', 'decryptor',
    'darknet news', 'deep web', 'hidden service', 'onion service',
    'anonymous market', 'dark market', 'underground forum',
    'hacker group', 'hacking team', 'pentest tool', 'red team',
    'bitcoin wallet', 'ethereum wallet', 'crypto wallet', 'private key',
    'seed phrase', 'mnemonic', 'recovery phrase', 'brain wallet',
    'counterfeit money', 'fake passport', 'fake driver license',
    'credit card dumps', 'track1 track2', 'pin code', 'atm skimmer',
    'western union transfer', 'moneygram', 'ria transfer',
    'bulletproof hosting', 'anonymous vps', 'offshore hosting',
    'no logs vpn', 'anonymous proxy', 'socks5 proxy',
    'tor bridge', 'tor relay', 'obfs4', 'meek',
    'pgp key', 'gpg key', 'encrypted message', 'private message',
    'darknet bible', 'tor guide', 'opsec guide', 'security guide',
    'hacking tutorial', 'carding tutorial', 'fraud tutorial',
    'cashout method', 'money laundering', 'bitcoin tumbler',
    'monero mixer', 'crypto mixer', 'coinjoin',
    'fake id template', 'novelty id', 'scannable id',
    'fullz info', 'background check', 'credit report',
    'osint tool', 'dox tool', 'people search',
    'sim swap', 'phone clone', 'sms bypass', '2fa bypass',
    'ransomware builder', 'crypter service', 'fud crypter',
    'malware panel', 'c2 panel', 'bot admin panel',
    'spam tool', 'mailer tool', 'sms bomber', 'call bomber',
    'ddos attack', 'stress test', 'booter service',
    'sql injection', 'xss payload', 'web shell', 'backdoor',
    'reverse shell', 'bind shell', 'meterpreter', 'empire agent',
    'phishing kit', 'scam page', 'cloning script',
    'bank drop', 'money mule', 'cashout service',
    'bitcoin doubler', 'crypto doubler', 'investment scam',
    'ponzi scheme', 'hyip script', 'mlm script',
    'darknet market link', 'darknet shop', 'darknet store',
    'verified vendor', 'trusted seller', 'escrow service',
    'bitcoin escrow', 'multisig escrow', 'p2p exchange',
    'anonymous chat', 'private forum', 'invite only',
    'referral code', 'affiliate program', 'commission',
    'free sample', 'test order', 'trial offer',
    'dropshipping', 'reseller program', 'wholesale',
    'bitcoin atm', 'crypto exchange', 'localbitcoins',
    'paypal account', 'stripe account', 'square account',
    'bank account', 'emi account', 'payment processor',
    'aged account', 'verified account', 'business account',
    'stealth account', 'shadow account', 'anonymous account',
    # Fresh broad terms — 2026-07-18
    'breached data', 'database dump', 'leaked database', 'combo list', 'email list',
    'password dump', 'login combo', 'fullz dump', 'stealer logs', 'infostealer',
    'session cookie', 'cookie log', 'token steal', 'cookie dump', 'browser data',
    # Discord & chat platform monitoring — 2026-07-25
    'discord.gg', 'discord invite', 'discord server', 'discord com invite',
    'telegram join', 'telegram invite', 't.me joinchat', 'signal group',
    'matrix room', 'xmpp conference', 'session group', 'tox chat',
    'rdp access', 'vpn logs', 'server root', 'citrix access', 'shell access',
    '.env leak', 'config file', 'aws keys', 'api keys', 'private ssh key',
    'cloned cards', 'cvv shop', 'bank logs', 'carding forum', 'paypal logs',
    'fake passport', 'counterfeit cash', 'cloned bills', 'scam kit', 'phishing template',
    'btc wallet', 'xmr address', 'crypto mixer', 'bitcoin tumbler', 'coinjoin',
    'vbulletin', 'xenforo', 'phpbb', 'mybb', 'discourse onion',
    'ransomware payload', 'malware source', '0day exploit', 'rce payload',
    'cve exploit', 'backdoor access', 'c2 panel', 'red team tool',
    # Forum & marketplace names — 2026-07-18
    'Dread forum', 'XSS forum', 'Exploit.in', 'Endchan', 'cryptbb', 'SuprBay',
    'TorZon', 'BriansClub', 'Russian Market', 'WeTheNorth', 'Abacus market', 'Archetyp',
    'escrow service', 'vendor panel', 'multisig', 'Monero XMR', 'finalize early',
    'SecureDrop', 'Gitea onion', 'XMPP server', 'Matrix bridge', 'samizdat',
    'index.php', 'viewforum.php', 'register account', 'pgp key', 'invite code',
]

_harvest_pool_idx = 0
_broad_search_idx = 0

def harvest_seeds(keywords: list[str] = None) -> int:
    """Use OnionClaw/sicry to search for new .onion URLs and feed them into the queue.
    Also directly scrapes Torch search results when keyword pools are stale.
    Filters out already-crawled URLs. Rotates keyword pools.
    Returns number of genuinely new seeds added."""
    global _harvest_pool_idx, _broad_search_idx
    
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
            results = sicry.search(kw, max_results=15, engines=['Ahmia-clearnet', 'Ahmia', 'Tor66', 'Excavator', 'OnionLand', 'TheDeepSearches', 'Amnesia', 'Torland', 'Onionway', 'Torgol', 'DuckDuckGo-Tor', 'OSS'])
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
    DIRECTORY_SEEDS = [
        'http://deeeepv4bfndyatwkdzeciebqcwwlvgqa6mofdtsvwpon4elfut7lfqd.onion/',
        'http://tordexu73joywapk2txdr54jed4imqledpcvcuf75qsas2gwdgksvnyd.onion/',
        'http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/',
        # Fresh directory seeds — added 2026-07-17
        'http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/',
        'http://phobosxilamwcg75xt22id7aywkzol6q6rfl2flipcqoc4e4ahima5id.onion/',
        'http://onionlnqbvsmi2p2x7jmxwvfparu7bdhpsjeyustp3h7hgtlldhhtyqd.onion/',
        'http://6nhmgdpnyoljh5uzr5kwlatx2u3diou4ldeommfxjz3wkhalzgjqxzqd.onion/',
        'http://2fd6cemt4gmbyflmiu5m4lctdqnvm7zanaassnj3w4vekvp5qp4zbyad.onion/',
        'http://jgwe5cjqdbyrumglkqniu5cwfakox8er6lyuafcuibknu7xye4wrf6qd.onion/',
        'http://n3hdukibtwvrxkzvihn3w2iubqb6cpjq5iy3me6qevwcqnreav2ixhqd.onion/',
        'http://linksmybq3cz6cgheo5tdnlprfiog3vcf25p7g64eadkpngeco6qtiid.onion/',
        'http://visitorfi5kl7q7ei56t2ngx2n3yoqafezk4ugjccv6sho7p6gg2eekqd.onion/',
        # Hidden Wiki mirrors + OnionLand — 2026-07-18
        'http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/index.php',
        'http://6nhmgdpnyoljh5uzr5kwlatx2u3diou4ldeommfxjz3wkhalzgjqxzqd.onion/index.php',
        'http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/',
        'http://wikitjerrta4qgz4pi3hm36fmkbmrhwfuk3bmguk2y7xypan2w3pnoyd.onion/',
        'http://wiki6dtqpuvwtc5hopuj33eeavwa6sik7sy57cor35chkx5nrbmmolqd.onion/',
        # Clearnet sources that list onions (scraped via Tor exit or direct)
        'https://raw.githubusercontent.com/alecmuffett/real-world-onion-sites/main/README.md',
        'https://raw.githubusercontent.com/onionltd/onion-sites-list/main/onion-sites.md',
    ]
    try:
        # Tor session for .onion URLs
        tor_session = requests.Session()
        tor_session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        tor_session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'})
        # Clearnet session for GitHub etc.
        clear_session = requests.Session()
        clear_session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'})
        for seed_url in DIRECTORY_SEEDS:
            try:
                s = clear_session if seed_url.startswith('https://') else tor_session
                resp = s.get(seed_url, timeout=25)
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
    
    # Method 3: Broad search — queries Torch AND Ahmia directly with rotating terms
    # Kicks in when methods 1 and 2 return nothing (pool exhausted)
    if added == 0:
        batch = []
        for _ in range(5):
            term = _BROAD_SEARCH_TERMS[_broad_search_idx % len(_BROAD_SEARCH_TERMS)]
            _broad_search_idx += 1
            batch.append(term)
        
        try:
            session = requests.Session()
            session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'})
            for term in batch:
                # Search Torch
                try:
                    torch_url = f'http://torchsfe235y6d7wguqo6g4ucxqq7frrm5fpgkjssdhthsq4kjmmisid.onion/search?query={term}'
                    resp = session.get(torch_url, timeout=30)
                    if resp.status_code == 200:
                        links = extract_links(resp.text, torch_url)
                        for link in links:
                            if link not in existing and link not in crawled:
                                save_line(QUEUE_PATH, link)
                                existing.add(link)
                                crawled.add(link)
                                added += 1
                except Exception:
                    continue
                time.sleep(2)
                
                # Search Ahmia onion
                try:
                    ahmia_url = f'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={term}'
                    resp = session.get(ahmia_url, timeout=30)
                    if resp.status_code == 200:
                        links = extract_links(resp.text, ahmia_url)
                        # Filter out Ahmia's own navigation pages
                        ahmia_domain = 'juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd'
                        for link in links:
                            if ahmia_domain in link:  # skip Ahmia's own pages
                                continue
                            if link not in existing and link not in crawled:
                                save_line(QUEUE_PATH, link)
                                existing.add(link)
                                crawled.add(link)
                                added += 1
                except Exception:
                    continue
                time.sleep(2)
            session.close()
        except Exception:
            pass

    # Method 4: Search Dark Engine and OnionLand directly (additional sources)
    if added == 0:
        try:
            session = requests.Session()
            session.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
            session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"})
            for term in batch:
                # Search Dark Engine
                try:
                    de_url = f"http://darkent74yfc3qe7vhd2ms53ynr3l5hbjz4on2x76e7odjiyrjlirvid.onion/search?q={term}"
                    resp = session.get(de_url, timeout=30)
                    if resp.status_code == 200:
                        links = extract_links(resp.text, de_url)
                        for link in links:
                            if link not in existing and link not in crawled:
                                save_line(QUEUE_PATH, link)
                                existing.add(link)
                                crawled.add(link)
                                added += 1
                except Exception:
                    pass
                time.sleep(2)
                # Search OnionLand
                try:
                    ol_url = f"http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={term}"
                    resp = session.get(ol_url, timeout=30)
                    if resp.status_code == 200:
                        links = extract_links(resp.text, ol_url)
                        for link in links:
                            if link not in existing and link not in crawled:
                                save_line(QUEUE_PATH, link)
                                existing.add(link)
                                crawled.add(link)
                                added += 1
                except Exception:
                    pass
                time.sleep(2)
            session.close()
        except Exception:
            pass

    return added


# ── Bridge to collect.py dump pipeline ──
DUMP_QUEUE_PATH = Path('/opt/threat_intel/raw/darkweb_dump_queue.jsonl')
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
                if is_csam(title, body, url):
                    log(f'  -> CSAM BLOCKED')
                    cycle_csam += 1
                    total_skipped_csam += 1
                    time.sleep(CRAWL_DELAY)
                    continue
                
                categories = classify_page(title, body)
                
                conn = get_db()
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            'INSERT INTO darkweb_pages (url, title, body, snippet, categories) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (url) DO UPDATE SET title=%s, body=%s, snippet=%s, categories=%s, crawled_at=NOW()',
                            (url, title, body, snippet, ','.join(categories),
                             title, body, snippet, ','.join(categories))
                        )
                    conn.commit()
                finally:
                    _pool.putconn(conn, close=False)
                last_db_change = time.time()
                
                # Screenshot ransomware/leak_site pages
                if SCREENSHOT_CATEGORIES & set(categories):
                    ss = screenshot_page(url)
                    if ss:
                        conn2 = get_db()
                        try:
                            with conn2.cursor() as cur:
                                cur.execute('UPDATE darkweb_pages SET screenshot=%s WHERE url=%s', (ss, url))
                            conn2.commit()
                        finally:
                            _pool.putconn(conn2, close=False)
                
                # ── Extract CVEs from page content ──
                try:
                    sys.path.insert(0, '/opt/threat_intel/scripts')
                    from cve_extract import extract_and_store
                    from zeroday_extract import extract_and_store as extract_zd
                    page_text = title + ' ' + body
                    cves = extract_and_store(page_text, source='darkweb_crawl', source_url=url)
                    if cves:
                        log(f'  🔓 CVEs: {", ".join(cves[:5])}')
                    if extract_zd(page_text, source='darkweb_crawl', source_url=url):
                        log(f'  🚨 Zero-day signal detected')
                except Exception:
                    pass
                
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
        
        total_indexed = db_fetchone('SELECT COUNT(*) as cnt FROM darkweb_pages')['cnt']
        
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
