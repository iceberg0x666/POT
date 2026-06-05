<h1 align="center">
  <br>
  <br>
  POT - Professional Offensive Tool
  <br>
</h1>

<h4 align="center">The Ultimate Automated Bug Bounty Reconnaissance Engine</h4>

<p align="center">
  <a href="#disclaimer">Disclaimer</a> •
  <a href="#what-is-pot">What is POT?</a> •
  <a href="#the-intelligence-complete-working">How It Works</a> •
  <a href="#robustness--reliability">Robustness</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#donate">Donate</a>
</p>

---

## Disclaimer
> **⚠️ FOR EDUCATIONAL AND AUTHORIZED USE ONLY ⚠️**
> 
> This tool is strictly designed for cybersecurity professionals, penetration testers, and bug bounty hunters to use on targets where they have **explicit, written permission** to test. 
> 
> The developers and contributors assume no liability and are not responsible for any misuse or damage caused by this program. Do not use this tool on any infrastructure you do not own or are not explicitly authorized to assess.

---

## What is POT?
**POT (Professional Offensive Tool)** is a hyper-optimized, highly concurrent reconnaissance framework built natively for Kali Linux. It fully automates the manual methodology of top-tier bug bounty hunters by chaining together over 30+ industry-standard tools into a single, cohesive, fault-tolerant pipeline.

Instead of running dozens of bash scripts, piping data into text files, and manually managing timeouts, **POT handles everything**. It goes from a single domain name all the way to a structured vulnerability report, discovering attack surfaces that competitors miss.

---

## The Intelligence: Complete Working
POT executes a strict, 4-phase methodology on every target.

### Phase 1: Passive Reconnaissance (Stealth OSINT)
Before ever touching the target, POT gathers intelligence silently across the internet:
*   **Infrastructure Mapping:** Queries WHOIS, BGP/ASN databases, and DNS records to map the organization's entire digital footprint.
*   **Subdomain Hunting:** Aggregates subdomains from 7 different passive APIs (including Certificate Transparency logs, Chaos, and the Wayback Machine).
*   **Shodan API Integration:** Queries Shodan to identify open ports, exposed services, and known critical CVEs without sending a single active packet to the target.
*   **Google Dorking:** Automates dork queries to find exposed PDFs, SQL dumps, and admin dashboards safely.

### Phase 2: Active Reconnaissance (Target Engagement)
POT actively probes the discovered infrastructure to identify live attack surfaces:
*   **Port & Service Scanning:** Utilizes `nmap`, `masscan`, and `naabu` to find exposed backend ports.
*   **HTTP Crawling:** Spiders the live web servers using `katana` to extract internal links, hidden endpoints, and API routes.
*   **JavaScript Parsing:** Downloads all target JavaScript files and uses `linkfinder` to extract hardcoded AWS keys, Slack tokens, and internal developer API endpoints.
*   **Cloud Bucket Enum:** Automatically brute-forces and identifies exposed AWS S3, GCP, and Azure storage buckets associated with the target domain.
*   **Directory Brute-Forcing:** Uses `ffuf` to uncover hidden directories like `/.git/`, `/backup.zip`, and `/admin`.

### Phase 3: Vulnerability Assessment (Exploitation)
POT weaponizes the discovered attack surface:
*   **Nuclei Engine Integration:** Runs massive template libraries against the live targets, strictly prioritizing Critical and High severity flaws.
*   **Advanced API Fuzzing:** Uses embedded wordlists to hunt for hidden endpoints like `/api/v1/admin`, `/swagger.json`, and `/v2/api-docs`.
*   **CMS & GraphQL Scanner:** Automatically fingerprints WordPress, Joomla, and Drupal to extract user lists, and hunts for unprotected `/graphql` endpoints to dump database schemas.
*   **Header & Protocol Flaws:** Tests for Subdomain Takeovers across 20+ cloud providers, CORS misconfigurations, Open Redirects, and Host Header Injections.

### Phase 4: Reporting
*   Saves all raw data into a structured directory (e.g., `target.com/subdomains`, `target.com/vulns`).
*   Generates a beautiful, dark-themed interactive HTML report and a machine-readable JSON file.

---

## Robustness & Reliability
POT is designed to run unsupervised for days without crashing.

*   **Global Execution:** The installer automatically symlinks the tool to `/usr/local/bin/pot`, meaning you can run it securely from **anywhere** on your Kali Linux machine just by typing `sudo pot target.com`.
*   **Subprocess Isolation & Timeouts:** Every external tool is executed through a strict wrapper. If a tool hangs indefinitely, the engine forcefully kills it via `timeout` and moves on. Your scan will never freeze.
*   **VPN/Network Resilience:** If your internet connection drops momentarily, the engine pauses, applies an exponential backoff, and retries the command up to 3 times once the connection to `1.1.1.1` is restored.
*   **Thread Safety:** POT safely manages 50+ concurrent threads using strict Python locks (`threading.Lock()`) to guarantee zero data corruption when writing to log files.
*   **Crash Checkpoints:** If your VM runs out of memory or you press `Ctrl+C`, the engine saves a `.pot_checkpoint.json` file. Next time you run the tool on the same target with the `--resume` flag, it automatically skips completed modules and resumes exactly where it died.
*   **Native Proxy/Tor Routing:** Built-in support for `--tor` or `--proxy socks5://127.0.0.1:9050` routes all active scanning traffic securely through anonymity networks.

---

## Installation
POT requires a Kali Linux environment. The setup script automatically installs Go, Python dependencies, SecLists, and over 30 external tools natively.

```bash
git clone https://github.com/yourusername/pot.git
cd pot
chmod +x install.sh
sudo ./install.sh
```

---

## Usage
The tool features a beautifully minimal, grep-able interface styled heavily after Nuclei.

### Basic Scan
```bash
sudo pot https://example.com
```

### Advanced Scan (Tor, Custom Headers, Scope)
```bash
sudo pot example.com \
    --tor \
    --header "Authorization: Bearer xyz" \
    --notarget "admin.example.com" \
    --threads 100 \
    -o ./results
```

### Multi-Target Batch Scanning
Feed it a list of 100 bug bounty targets and let it run overnight.
```bash
sudo pot --targets bounty_list.txt --resume
```

### Passive Intel Only (Stealth Mode)
Executes only Phase 1, never touching the target's servers.
```bash
sudo pot example.com --passive
```

---

## Donate
If this tool has helped you land a high-paying bug bounty, consider supporting the continued development of POT!

[**Donate XMR (Monero)**](monero:8BQ91yxDC2ChBCefXJLXN1JjSeRar5xj2WdE2Td4BVFQbMAkjTb1NdWBXaYuGDyNaTD7ueQ99gfnbDFVH2zauYGr6uaEWeP)
`8BQ91yxDC2ChBCefXJLXN1JjSeRar5xj2WdE2Td4BVFQbMAkjTb1NdWBXaYuGDyNaTD7ueQ99gfnbDFVH2zauYGr6uaEWeP`

<br>
<p align="center">
  <i>Discovery Before Exploitation - iceberg</i>
</p>
