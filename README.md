# DarkSearch

A self-hosted dark web search engine running as a Tor hidden service. Crawls `.onion` sites, indexes them with SQLite FTS5, and serves a clean search UI over Tor.

## Features

- **Tor hidden service** — your `.onion` address never changes (keys are portable)
- **SQLite FTS5** — full-text search with BM25 ranking, sub-millisecond queries
- **Self-sustaining crawler** — discovers new `.onion` links as it crawls
- **Auto-restart** — systemd services survive reboots
- **Category tagging** — auto-classifies pages (marketplace, ransomware, forum, etc.)
- **Change detection** — re-crawls old pages and flags content changes
- **Threat intel integration** — shared.py API for querying the index, feeding seeds
- **Portable** — entire stack on a single drive, works on Debian and Raspberry Pi

## Quick Start

```bash
# Install deps and launch
bash setup.sh

# Or manually:
pip3 install flask requests beautifulsoup4
tor -f torrc --runasdaemon 1
python3 server.py
```

Local: `http://127.0.0.1:8082/`  
Tor: `http://<your-onion>.onion`

## Components

| File | Purpose |
|------|---------|
| `server.py` | Flask search UI |
| `crawler.py` | Tor-based .onion crawler |
| `shared.py` | Query API, seed feeder, change detection, classifier |
| `setup.sh` | Portable one-command setup |
| `launch.sh` | Systemd launcher (Tor → Flask) |
| `seeds.txt` | Initial .onion URLs |

## Architecture

```
Tor network → Tor daemon (darkweb) → Flask (127.0.0.1:8082)
Tor network → Tor daemon (system, :9050) → Crawler → SQLite
```

## Cron Jobs

- `check_ahmia.sh` — polls Ahmia for seed list every 30 min
- `check_crawler.sh` — watchdog, restarts stuck crawler

## License

MIT
