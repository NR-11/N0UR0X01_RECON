# subrecon

An automated subdomain enumeration workflow, written in Go. One binary, a few setup questions, then it runs the full pipeline on its own and hands you back every subdomain file you need.

Pipeline (in order):

1. **Passive**: `subfinder`, `github-subdomains`, `gitlab-subdomains`, `gau` (run in parallel)
2. **Active bruteforce**: `puredns` with your wordlist + resolvers
3. **Merge + resolve + probe**: `dnsx`, `httpx`
4. **Scraping**: `katana` crawl, subdomains extracted from the crawled URLs (no second crawl)
5. **Permutations**: `alterx` + `puredns resolve`
6. **Final output**: full list, live list, and `status_404.txt` / `status_403.txt` for later fuzzing
7. **Screenshots**: `gowitness` against the live subdomains only
8. **Stats**: per-tool output count + how many *new* subdomains each tool actually added on top of subfinder

## Requirements

Go 1.21+ to build. The following tools must be installed and in your `$PATH`:

| Tool | Install |
|---|---|
| subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| github-subdomains | `go install github.com/gwen001/github-subdomains@latest` |
| gitlab-subdomains | `go install github.com/gwen001/gitlab-subdomains@latest` |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| puredns | `go install github.com/d3mondev/puredns/v2@latest` (also needs [massdns](https://github.com/blechschmidt/massdns) built and in PATH) |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| alterx | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` |
| dnsx | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| gowitness | `go install github.com/sensepost/gowitness@latest` |

`github-subdomains` and `gitlab-subdomains` are optional — if you leave their tokens blank, those steps are skipped and the rest of the pipeline still runs.

For subfinder to return a lot more than the default, put your API keys in `~/.config/subfinder/provider-config.yaml` ([format here](https://github.com/projectdiscovery/subfinder#post-installation-instructions)). subrecon checks this file before starting and warns you if it's missing or empty, with a chance to continue anyway.

## Installation

This tool lives inside the [N0UR0X01_RECON](https://github.com/NR-11/N0UR0X01_RECON) repo, under `SubRecon/`. Pick one of the two options below.

### Option 1: go install (recommended)

Installs the `subrecon` binary straight into `$GOPATH/bin` (usually `$HOME/go/bin`), so you can run it from anywhere.

```bash
go install github.com/NR-11/N0UR0X01_RECON/SubRecon@latest
```

Make sure that directory is in your `$PATH`:

```bash
echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.zshrc   # or ~/.bashrc
source ~/.zshrc
```

Then run it from anywhere:

```bash
subrecon
```

### Option 2: build from source

```bash
git clone https://github.com/NR-11/N0UR0X01_RECON
cd N0UR0X01_RECON/SubRecon
go build -o subrecon .
```

```bash
./subrecon
```

## Usage

```bash
subrecon        # if installed with go install
./subrecon      # if built from source
```

You'll be asked for:

- Target domain (e.g. `target.com`)
- Platform short name (e.g. `h1`) — used to name the output folder `target.com_h1`
- GitHub token (classic, `public_repo` scope — fine-grained tokens can silently return 0 results)
- GitLab token
- Path to an existing DNS wordlist, or leave blank to auto-download [best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- Directory to store resolver files (resolvers are **always re-downloaded** on every run — they go stale fast)

After that, it runs unattended.

## Output

Everything lands under `<domain>_<platform>/`:

```
target.com_h1/
├── subdomains/
│   ├── sub_subfinder.txt
│   ├── sub_github.txt
│   ├── sub_gitlab.txt
│   ├── sub_gau.txt
│   ├── sub_puredns.txt
│   ├── sub_katana.txt
│   ├── all_subs.txt
│   ├── resolved.txt
│   ├── live_urls.txt
│   ├── perms_raw.txt / perms.txt
│   ├── final_all_subs.txt      <- every subdomain found, dead or alive
│   ├── final_live_subs.txt     <- only subdomains answering on HTTP/HTTPS
│   ├── httpx.txt                <- status code / title / tech per live subdomain
│   ├── status_404.txt           <- candidates for fuzzing / takeover checks
│   └── status_403.txt           <- candidates for fuzzing
├── urls/
│   └── katana_urls.txt          <- full crawl, reusable later for JS/endpoint extraction
├── resolvers/
│   ├── resolvers.txt
│   └── resolvers-trusted.txt
├── wordlists/
│   └── best-dns-wordlist.txt
└── screenshots/
    └── ... (gowitness output)
```

At the end, subrecon prints a stats block: how many subdomains each tool returned, and — more importantly — how many of those were genuinely **new** compared to subfinder alone. Use that to decide which tools are worth keeping for a given target.

## Quick test

Want to confirm everything works before pointing it at a real target? Use a light, safe-to-scan domain:

- `scanme.nmap.org` — made specifically for scanning practice, no legal concerns at all.
- `projectdiscovery.io` — the company behind most of the tools this workflow uses; a moderate, well-known target.
- `hackerone.com` — a wider scope if you want to see the full pipeline return a large, realistic result set.

```bash
./subrecon
# Target domain: scanme.nmap.org
# Platform: test
```

## Notes

- Every shell step is run exactly as documented in the original recon workflow this is based on — nothing was changed in tool flags or step order, only automated.
- If a required tool is missing from `$PATH`, subrecon warns you and asks whether to continue; missing optional tools (github/gitlab-subdomains) just get skipped if no token was given.
- Be mindful of `puredns`'s `--rate-limit` on a weak/limited connection — lower it in the source if needed before building.
