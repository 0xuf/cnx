# CNX — Subdomain Takeover Scanner

```
 ██████╗███╗   ██╗██╗  ██╗
██╔════╝████╗  ██║╚██╗██╔╝
██║     ██╔██╗ ██║ ╚███╔╝
██║     ██║╚██╗██║ ██╔██╗
╚██████╗██║ ╚████║██╔╝ ██╗
 ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝
```

High-performance, async subdomain takeover scanner built for scale.  
Detects misconfigured DNS records pointing to unclaimed third-party services
using a **live** fingerprint database of 76+ providers — fetched fresh on every run.

- [Features](#features)
- [Installation](#installation)
  - [Local (Python 3.11+)](#local-python-311)
  - [Docker](#docker)
- [Usage](#usage)
  - [Basic scan](#basic-scan)
  - [High-speed scan](#high-speed-scan)
  - [Only vulnerable results](#only-vulnerable-results)
  - [Save reports](#save-reports)
  - [No output files](#no-output-files)
  - [Silent mode](#silent-mode)
  - [Stdin / pipe input](#stdin--pipe-input)
  - [Docker usage](#docker-usage)
- [CLI Reference](#cli-reference)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Fingerprint Matching Logic](#fingerprint-matching-logic)
- [Sample JSON Output](#sample-json-output)
- [Performance](#performance)
- [Credits & Acknowledgements](#credits--acknowledgements)

---

## Features

| Feature | Detail |
|---|---|
| ⚡ Async engine | Queue-based producer / worker / collector pipeline |
| 🔍 DNS CNAME chain | Full chain following + NXDOMAIN detection |
| 🌐 HTTP fingerprinting | Body regex, plain-text, and HTTP-status matching |
| 📊 Live dashboard | Real-time Rich terminal UI with hits table |
| 📁 Multi-format reports | JSON, CSV, HTML |
| 🚦 Rate limiter | Token-bucket — prevents network flooding |
| 🐳 Docker ready | Single-command containerised scanning |
| 🔗 Pipe-friendly | Read from file **or** stdin — composable with other tools |
| 🔇 Silent mode | Plain-text vulnerable-only output for scripting |
| 🔄 Live fingerprints | Always fetches latest data from upstream (no stale local copy) |

---

## Installation

### Local (Python 3.11+)

```bash
git clone https://github.com/0xuf/cnx.git
cd cnx
pip install -r requirements.txt
python main.py --help
```

### Docker

```bash
# Pull and build the image
docker build -t cnx .

# Verify it works
docker run --rm cnx --help
```

---

## Usage

### Basic scan

```bash
python main.py -l input/domains.txt
```

### High-speed scan

```bash
python main.py -l input/domains.txt -c 300 --rate-limit 200
```

### Only vulnerable results

```bash
python main.py -l input/domains.txt --only-vulnerable
```

### Save reports

```bash
# JSON only
python main.py -l input/domains.txt --format json -o results/client

# All formats  (json + csv + html)
python main.py -l input/domains.txt --format all -o results/client
```

### No output files

```bash
# Omit -o entirely → nothing is written to disk
python main.py -l input/domains.txt
```

### Silent mode

Suppresses the banner, live dashboard and summary.  
Prints **only vulnerable** domain names to stdout, one per line.

```bash
python main.py -l input/domains.txt --silent

# Save vulnerable list to a file
python main.py -l input/domains.txt --silent > hits.txt
```

### Stdin / pipe input

```bash
cat input/domains.txt | python main.py --silent

# Full recon pipeline
subfinder -d example.com -silent | python main.py --silent

# Recon + save reports
subfinder -d example.com -silent | python main.py --silent -o results/example
```

### Docker usage

```bash
# Scan a local file (mount input + results directories)
docker run --rm \
  -v $(pwd)/input:/app/input \
  -v $(pwd)/results:/app/results \
  cnx -l input/domains.txt -o results/scan

# Pipe from another tool  (-i keeps stdin open)
subfinder -d example.com -silent | \
  docker run --rm -i cnx --silent

# Silent mode + save reports
docker run --rm \
  -v $(pwd)/input:/app/input \
  -v $(pwd)/results:/app/results \
  cnx -l input/domains.txt --silent -o results/scan

# High-concurrency Docker scan
docker run --rm \
  -v $(pwd)/input:/app/input \
  -v $(pwd)/results:/app/results \
  cnx -l input/domains.txt -c 300 --rate-limit 200 -o results/scan
```

---

## CLI Reference

| Flag | Description | Default |
|---|---|---|
| `-l, --list FILE` | Path to newline-separated domain list | reads from stdin if omitted |
| `-f, --fingerprints FILE` | Local fallback fingerprints JSON | `fingerprints.json` |
| `-o, --output PATH` | Output base path without extension | no files written |
| `--format` | `json` / `csv` / `html` / `all` | `all` |
| `-c, --concurrency N` | Concurrent scan workers | `150` |
| `--timeout SEC` | Per-domain HTTP timeout in seconds | `10` |
| `--rate-limit RPS` | Max requests/sec (`0` = unlimited) | `0` |
| `--only-vulnerable` | Only include vulnerable targets in report | off |
| `--silent` | Suppress UI; print vulnerable domains to stdout only | off |

---

## Project Structure

```
cnx/
├── main.py               ← CLI entry point
├── Dockerfile            ← Multi-stage container build
├── .dockerignore
├── requirements.txt
│
├── core/
│   ├── engine.py         ← Async queue pipeline (producer/worker/collector)
│   ├── scanner.py        ← Per-domain DNS + HTTP + fingerprint orchestration
│   ├── resolver.py       ← Async DNS with full CNAME chain following
│   └── matcher.py        ← Fingerprint matching engine (regex + NXDOMAIN + HTTP status)
│
├── output/
│   ├── dashboard.py      ← Live Rich terminal dashboard
│   └── writer.py         ← JSON / CSV / HTML report writers
│
├── utils/
│   ├── models.py         ← ScanResult dataclass + Verdict enum
│   ├── limiter.py        ← Token-bucket async rate limiter
│   └── logger.py         ← Rich-backed structured logger
│
├── input/
│   └── domains.txt       ← Target list (one domain per line, # = comment)
│
└── results/              ← Reports saved here
```

---

## How It Works

```
stdin / domains.txt
        │
        ▼
┌──────────┐      ┌──────────────────────────────┐
│ Producer │─────▶│   asyncio.Queue (work queue)  │
└──────────┘      └──────────────────────────────┘
                        │         │         │
                     Worker    Worker    Worker    (N concurrent)
                        │         │         │
              ┌─────────▼─────────▼─────────▼──────────┐
              │            Scanner.scan(domain)          │
              │  1. DNS  → resolve + follow CNAME chain  │
              │           detect NXDOMAIN                │
              │  2. HTTP → fetch body + status code      │
              │  3. Match → check against fingerprints   │
              └──────────────────────────────────────────┘
                                   │
                             result_queue
                                   │
                           ┌───────▼────────┐
                           │   Collector    │
                           └───────┬────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
             Live Dashboard               JSON / CSV / HTML
              (Rich terminal)                  Reports
```

---

## Fingerprint Matching Logic

For each domain, three checks run in order — first match wins:

| # | Check | Condition |
|---|---|---|
| 1 | **NXDOMAIN** | DNS returns NXDOMAIN **and** CNAME chain includes a known provider |
| 2 | **HTTP body** | Response body matches a regex/substring fingerprint (optionally gated by CNAME) |
| 3 | **HTTP status** | Specific status code matched together with a CNAME check |

---

## Sample JSON Output

```json
{
  "domain": "status.acme.com",
  "vulnerable": true,
  "verdict": "VULNERABLE",
  "service": "GitHub Pages",
  "status": "Edge case",
  "fingerprint_matched": "There isn't a GitHub Pages site here.",
  "cname_chain": ["acme.github.io"],
  "nxdomain": false,
  "http_status": 404,
  "error": null
}
```

---

## Performance

Speed is governed by DNS/HTTP round-trip latency, not CPU.
Raise `--concurrency` and `--rate-limit` on a fast network.

| Domains | ~Time | ~Speed |
|---|---|---|
| 1,000 | 8 s | 125/s |
| 10,000 | 75 s | 133/s |
| 100,000 | ~12 min | 140/s |

---

## Credits & Acknowledgements

Fingerprint data is sourced **live** from  
**[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)**  
by [@EdOverflow](https://github.com/EdOverflow) and contributors —  
a community-maintained database of subdomain takeover fingerprints covering 76+ services.

> 🙏 Big props to the **can-i-take-over-xyz** project and its contributors for maintaining
> a clean, structured fingerprint dataset. Having a well-engineered public resource like that
> means we could focus entirely on building a fast, reliable engine rather than
> spending time curating provider signatures from scratch.

---

## License

MIT
