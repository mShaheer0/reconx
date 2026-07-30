# Recon Orchestrator

CLI orchestrator for passive and active reconnaissance. Runs `subfinder` + `dnsx` + `httpx` by default, with optional `nuclei` active scanning and an AI-generated summary.

WARNING: Only run active scans against targets you own or have written permission to test.

## Prerequisites

- Python 3.10+
- ProjectDiscovery tools: `subfinder`, `dnsx`, `httpx`, `nuclei`
  ```bash
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ```
  Make sure `~/go/bin` (or `$(go env GOPATH)/bin`) is on your PATH.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

## Usage

```bash
# Passive scan only
python3 main.py example.com

# Passive + active scan
python3 main.py example.com --active

# Custom output directory and timeout
python3 main.py example.com --active --output-dir ./scan_results --timeout 600

# JSON output alongside summary.md
python3 main.py example.com --json
```

## Output

- `output/summary.md` — Markdown report with attack surface summary, technologies, findings, and risk assessment.
- `output/aggregated.json` — Machine-readable aggregated payload (only with `--json`).
- Raw tool outputs: `subfinder.json`, `dnsx.json`, `httpx.json`, `nuclei.json`.

## Configuration

Environment variables (in `.env` or shell):

| Variable | Purpose |
|----------|---------|
| `GROQ_API_KEY` | Groq LLM key (required) |
| `GROQ_API_URL` | Groq API base URL |
| `GROQ_MODEL` | Groq model name |
| `PD_SUBFINDER_BIN` | Override subfinder binary path |
| `PD_DNSX_BIN` | Override dnsx binary path |
| `PD_HTTPX_BIN` | Override httpx binary path |
| `PD_NUCLEI_BIN` | Override nuclei binary path |

## Docker

```bash
docker build -t recon-orchestrator .
docker run --rm -v $(pwd)/output:/app/output recon-orchestrator example.com
```

## Project Structure

```
recon-orchestrator/
  main.py           CLI entrypoint
  config/
    settings.py     Constants and defaults
  recon/
    passive.py      subfinder + dnsx + httpx wrappers
    active.py       nuclei wrapper
    aggregator.py   Cleaning, masking, deduplication
    ai_summary.py   LLM summary generation (Groq only)
    tools.py        ProjectDiscovery binary resolver
  tests/            Unit tests
  output/           Scan results (gitignored)
```

## Troubleshooting

**"tool not found" / "command not found"**
Ensure Go binaries are on PATH:
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

**"No Groq API key configured"**
Copy `.env.example` to `.env` and add your key:
```bash
cp .env.example .env
# edit .env and set GROQ_API_KEY
```

**"python-dotenv is not installed"**
You're using system Python instead of the venv. Either activate the venv or install deps:
```bash
source .venv/bin/activate
```
