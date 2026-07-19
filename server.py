#!/usr/bin/env python3
"""Dark web search engine — Flask UI served over Tor hidden service."""

import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from flask import Flask, request, render_template_string, abort

BASE = Path('/mnt/darkweb')
DB_PATH = BASE / 'index.db'

app = Flask(__name__)

# Rate limiting: 10 requests per 10 seconds per IP
RATE_LIMIT = 10
RATE_WINDOW = 10
_hits = defaultdict(list)

@app.before_request
def ratelimit():
    ip = request.remote_addr or '127.0.0.1'
    now = time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < RATE_WINDOW]
    if len(_hits[ip]) >= RATE_LIMIT:
        abort(429)
    _hits[ip].append(now)

SEARCH_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DarkSearch — query</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #1a1a2e; color: #e0e0e0; font-family: system-ui, sans-serif; }
  .container { max-width: 720px; margin: 0 auto; padding: 20px; }
  h1 { color: #7b68ee; font-size: 1.8em; margin-bottom: 5px; }
  .tagline { color: #888; font-size: 0.85em; margin-bottom: 30px; }
  form { margin-bottom: 30px; }
  input[type="text"] {
    width: 100%; padding: 14px 18px; font-size: 1.1em;
    background: #16213e; border: 2px solid #0f3460; border-radius: 8px;
    color: #e0e0e0; outline: none;
  }
  input[type="text"]:focus { border-color: #7b68ee; }
  .stats { color: #666; font-size: 0.85em; margin-bottom: 20px; }
  .result { margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid #222; }
  .result a { color: #7b68ee; text-decoration: none; font-size: 1.1em; }
  .result a:hover { text-decoration: underline; }
  .result .url { color: #2e8b57; font-size: 0.8em; margin: 4px 0; word-break: break-all; }
  .result .snippet { color: #aaa; font-size: 0.9em; line-height: 1.5; }
  .empty { color: #666; text-align: center; padding: 60px 0; font-size: 1.1em; }
  .footer { margin-top: 50px; padding-top: 20px; border-top: 1px solid #222; color: #555; font-size: 0.75em; text-align: center; }
</style>
</head>
<body>
<div class="container">
  <h1>DarkSearch</h1>
  <p class="tagline">.onion search engine</p>
  <form method="get" action="/search">
    <input type="text" name="q" value="{{ query }}" placeholder="Search the dark web..." autofocus>
  </form>
  {% if query %}
    <p class="stats">{{ results|length }} results ({{ elapsed }}s)</p>
    {% if results %}
      {% for r in results %}
      <div class="result">
        <a href="{{ r.url }}" target="_blank" rel="noopener">{{ r.title or r.url[:60] }}</a>
        <div class="url">{{ r.url[:120] }}</div>
        <div class="snippet">{{ r.snippet[:300] }}</div>
      </div>
      {% endfor %}
    {% else %}
      <div class="empty">No results for "{{ query }}"</div>
    {% endif %}
  {% endif %}
  <div class="footer">DarkSearch — Tor hidden service</div>
</div>
</body>
</html>'''


def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute('PRAGMA journal_mode=WAL')
    conn.row_factory = sqlite3.Row
    return conn


def search(query, limit=50):
    db = get_db()
    t0 = __import__('time').time()
    
    # BM25-style ranking via FTS5
    rows = db.execute('''
        SELECT p.url, p.title, p.snippet,
               rank AS score
        FROM pages_fts f
        JOIN pages p ON p.id = f.rowid
        WHERE pages_fts MATCH ?
        ORDER BY rank
        LIMIT ?
    ''', (query, limit)).fetchall()
    
    elapsed = round(__import__('time').time() - t0, 3)
    total = db.execute('SELECT COUNT(*) FROM pages').fetchone()[0]
    db.close()
    return [dict(r) for r in rows], total, elapsed


@app.route('/')
def index():
    db = get_db()
    total = db.execute('SELECT COUNT(*) FROM pages').fetchone()[0]
    db.close()
    return render_template_string(SEARCH_TEMPLATE, query='', results=[], total=total, elapsed=0)


@app.route('/search')
def search_route():
    query = request.args.get('q', '').strip()
    if not query:
        db = get_db()
        total = db.execute('SELECT COUNT(*) FROM pages').fetchone()[0]
        db.close()
        return render_template_string(SEARCH_TEMPLATE, query='', results=[], total=total, elapsed=0)
    
    results, total, elapsed = search(query)
    return render_template_string(SEARCH_TEMPLATE, query=query, results=results, total=total, elapsed=elapsed)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8082, debug=False)
