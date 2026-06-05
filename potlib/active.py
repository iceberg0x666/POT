#!/usr/bin/env python3
"""
POT - Professional Offensive Tool
Active Reconnaissance Module
DNS resolution, port scanning, HTTP probing, web crawling,
directory bruteforcing, parameter discovery, JS analysis, screenshots.
"""

import os
import re
import json
import time
from urllib.parse import urlparse, urljoin

from potlib.ui import (
    log_info, log_warning, log_error, log_debug,
    log_found, log_module_start, log_module_end, log_phase,
    progress_bar, Colors
)
from potlib.engine import (
    parse_lines, dedup_lines, write_lines, read_file_lines,
    safe_filename, extract_domain_from_url
)


def run_all(config, runner, scope, results):
    """Execute all active reconnaissance modules."""
    log_phase("PHASE 2 — ACTIVE RECONNAISSANCE")

    if config.passive_only:
        log_info("Passive-only mode — skipping active reconnaissance")
        return

    modules = [
        ('waf_detect',  waf_detection),
        ('resolve',     dns_resolution),
        ('ports',       port_scanning),
        ('httpx',       http_probing),
        ('crawl',       web_crawling),
        ('dirs',        directory_bruteforce),
        ('params',      parameter_discovery),
        ('js',          js_analysis),
        ('screenshots', screenshot_capture),
        ('cloud_buckets', cloud_bucket_enum),
        ('api_fuzz',        api_fuzzing),
    ]

    for name, func in modules:
        if name in config.skip_modules:
            log_info(f"Skipping module: {name}")
            continue
        try:
            func(config, runner, scope, results)
        except Exception as e:
            log_error(f"Module {name} failed: {e}")

    results.save_to_disk()
    log_info(f"Active recon complete — {len(results.get_live_hosts())} live hosts found")


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

def dns_resolution(config, runner, scope, results):
    log_module_start("DNS Resolution")
    subdomains = results.get_subdomains()

    if not subdomains:
        log_warning("No subdomains to resolve")
        log_module_end("DNS Resolution", 0)
        return

    # Write subdomains to file for bulk tools
    subs_file = os.path.join(config.dirs['subdomains'], 'all_subdomains.txt')
    write_lines(subs_file, sorted(subdomains))
    resolved_file = os.path.join(config.dirs['subdomains'], 'resolved.txt')
    count = 0

    # ── 1. dnsx (preferred) ──
    if runner.is_available('dnsx'):
        log_info(f"Resolving {len(subdomains)} subdomains with dnsx...")
        stdout, _, _ = runner.run(
            ['bash', '-c', f'cat {subs_file} | dnsx -silent -a -resp -t {min(config.threads, 100)}'],
            timeout=300
        )
        if stdout:
            live = set()
            for line in parse_lines(stdout):
                # dnsx outputs: subdomain [ip]
                parts = line.split()
                hostname = parts[0].strip()
                if scope.is_in_scope(hostname):
                    live.add(hostname)
            results.add_live_subdomains(live)
            write_lines(resolved_file, sorted(live))
            count = len(live)
            log_info(f"dnsx resolved: {count}/{len(subdomains)} alive")

    # ── 2. massdns fallback ──
    elif runner.is_available('massdns'):
        resolvers = config.resolvers or _find_resolvers_file()
        if resolvers:
            log_info(f"Resolving {len(subdomains)} subdomains with massdns...")
            out_file = os.path.join(config.dirs['dns'], 'massdns_output.txt')
            stdout = runner.run_tool('massdns', [
                '-r', resolvers,
                '-t', 'A',
                '-o', 'S',
                '-w', out_file,
                subs_file,
            ], timeout=300)
            # Parse massdns output
            live = set()
            if os.path.exists(out_file):
                for line in read_file_lines(out_file):
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == 'A':
                        hostname = parts[0].rstrip('.')
                        if scope.is_in_scope(hostname):
                            live.add(hostname)
            results.add_live_subdomains(live)
            write_lines(resolved_file, sorted(live))
            count = len(live)
            log_info(f"massdns resolved: {count}/{len(subdomains)} alive")

    # ── 3. Manual dig fallback ──
    else:
        log_info(f"Resolving {len(subdomains)} subdomains with dig...")
        live = set()
        total = len(subdomains)

        def resolve_one(sub):
            stdout = runner.run_tool('dig', ['+short', 'A', sub],
                                     timeout=10, retries=1)
            if stdout and stdout.strip() and not stdout.startswith(';'):
                return sub
            return None

        tasks = [(resolve_one, (sub,)) for sub in subdomains]
        resolved = runner.run_parallel(tasks, max_workers=min(20, config.threads))

        for result in resolved:
            if result:
                live.add(result)

        results.add_live_subdomains(live)
        write_lines(resolved_file, sorted(live))
        count = len(live)
        log_info(f"dig resolved: {count}/{len(subdomains)} alive")

    log_module_end("DNS Resolution", count)


def _find_resolvers_file():
    """Find a resolvers file."""
    paths = [
        '/usr/share/seclists/Miscellaneous/dns-resolvers.txt',
        '/tmp/pot_resolvers.txt',
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    # Create one
    resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '8.8.4.4', '1.0.0.1']
    path = '/tmp/pot_resolvers.txt'
    with open(path, 'w') as f:
        f.write('\n'.join(resolvers) + '\n')
    return path


# ═══════════════════════════════════════════════════════════════════════════════
#  PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

def port_scanning(config, runner, scope, results):
    log_module_start("Port Scanning")
    domain = config.target_domain
    live_subs = results.get_live_subdomains()
    targets = live_subs if live_subs else {domain}
    count = 0

    # Limit targets for scanning
    scan_targets = sorted(targets)[:100]  # Max 100 targets for port scan
    if len(targets) > 100:
        log_warning(f"Limiting port scan to first 100 of {len(targets)} targets")

    targets_file = os.path.join(config.dirs['ports'], 'scan_targets.txt')
    write_lines(targets_file, scan_targets)

    # ── 1. Nmap scan ──
    if runner.is_available('nmap'):
        log_info(f"Running nmap on {len(scan_targets)} targets...")
        xml_out = os.path.join(config.dirs['ports'], 'nmap_scan.xml')
        txt_out = os.path.join(config.dirs['ports'], 'nmap_scan.txt')

        # Use aggressive but smart scan options
        nmap_args = [
            '-sS', '-sV',                           # SYN scan + version detection
            '--top-ports', '1000' if config.quick else '3000',
            '-T4',                                    # Aggressive timing
            '--min-rate', str(min(config.rate_limit, 500)),
            '--max-retries', '2',
            '--host-timeout', '300s',
            '--script-timeout', '60s',
            '-oX', xml_out,
            '-oN', txt_out,
            '-iL', targets_file,
            '--open',                                 # Only show open ports
        ]

        # Add script scans if not quick mode
        if not config.quick:
            nmap_args.extend([
                '--script', 'default,vuln,http-title,ssl-cert,http-headers',
            ])

        stdout, stderr, rc = runner.run(
            ['nmap'] + nmap_args,
            timeout=max(config.timeout, 900),
            retries=2
        )

        if stdout:
            port_data = _parse_nmap_output(stdout)
            for host, ports in port_data.items():
                results.add_ports(host, ports)
                count += len(ports)
                for port, service, state in ports:
                    log_found("nmap", f"{host}:{port} [{state}] {service}")

    # ── 2. Masscan (fast port scan, supplement nmap) ──
    if runner.is_available('masscan') and not config.quick:
        log_info("Running masscan for additional coverage...")
        masscan_out = os.path.join(config.dirs['ports'], 'masscan.json')

        # Resolve targets to IPs for masscan
        ip_targets = set()
        for target in scan_targets[:50]:
            try:
                import socket
                ips = socket.getaddrinfo(target, None)
                for ip_info in ips:
                    ip = ip_info[4][0]
                    if ':' not in ip:  # Skip IPv6 for masscan
                        ip_targets.add(ip)
            except Exception:
                pass

        if ip_targets:
            ip_file = os.path.join(config.dirs['ports'], 'ip_targets.txt')
            write_lines(ip_file, sorted(ip_targets))

            stdout = runner.run_tool('masscan', [
                '-iL', ip_file,
                '-p', '0-65535' if not config.quick else '1-10000',
                '--rate', str(min(config.rate_limit, 1000)),
                '--wait', '3',
                '-oJ', masscan_out,
            ], timeout=max(config.timeout, 600), retries=1)

            if os.path.exists(masscan_out):
                try:
                    with open(masscan_out) as f:
                        content = f.read().strip()
                        if content:
                            # Fix masscan JSON (trailing comma issue)
                            content = content.rstrip(',\n')
                            if not content.startswith('['):
                                content = '[' + content + ']'
                            data = json.loads(content)
                            for entry in data:
                                ip = entry.get('ip', '')
                                for port_info in entry.get('ports', []):
                                    port = port_info.get('port', 0)
                                    proto = port_info.get('proto', 'tcp')
                                    service = port_info.get('service', {}).get('name', '')
                                    results.add_ports(ip, [(port, f"{proto}/{service}", 'open')])
                                    count += 1
                except (json.JSONDecodeError, KeyError):
                    pass

    # ── 3. Naabu (fast port scanner from ProjectDiscovery) ──
    elif runner.is_available('naabu') and not runner.is_available('nmap'):
        log_info("Running naabu...")
        stdout, _, _ = runner.run(
            ['bash', '-c', f'cat {targets_file} | naabu -silent -top-ports 1000 -rate {config.rate_limit}'],
            timeout=300
        )
        if stdout:
            for line in parse_lines(stdout):
                if ':' in line:
                    host, port = line.rsplit(':', 1)
                    try:
                        port_num = int(port)
                        results.add_ports(host, [(port_num, '', 'open')])
                        log_found("naabu", f"{host}:{port_num}")
                        count += 1
                    except ValueError:
                        pass

    log_module_end("Port Scanning", count)


def _parse_nmap_output(output):
    """Parse nmap text output for open ports."""
    port_data = {}
    current_host = None

    for line in output.split('\n'):
        line = line.strip()

        # Detect host
        host_match = re.search(r'Nmap scan report for\s+(\S+)', line)
        if host_match:
            current_host = host_match.group(1)
            # Remove parenthesized IP if present
            current_host = re.sub(r'\s*\(.*?\)', '', current_host).strip()
            continue

        # Detect open port
        port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|filtered)\s+(.*)', line)
        if port_match and current_host:
            port = int(port_match.group(1))
            state = port_match.group(3)
            service = port_match.group(4).strip()
            if current_host not in port_data:
                port_data[current_host] = []
            port_data[current_host].append((port, service, state))

    return port_data


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP PROBING
# ═══════════════════════════════════════════════════════════════════════════════

def http_probing(config, runner, scope, results):
    log_module_start("HTTP Probing")
    subdomains = results.get_live_subdomains() or results.get_subdomains()

    if not subdomains:
        subdomains = {config.target_domain}

    subs_file = os.path.join(config.dirs['subdomains'], 'to_probe.txt')
    write_lines(subs_file, sorted(subdomains))
    count = 0

    # ── 1. httpx (preferred) ──
    if runner.is_available('httpx'):
        log_info(f"Probing {len(subdomains)} hosts with httpx...")
        out_file = os.path.join(config.dirs['subdomains'], 'httpx_output.json')

        stdout, _, _ = runner.run(
            ['bash', '-c',
             f'cat {subs_file} | httpx -silent -status-code -title -tech-detect '
             f'-content-length -web-server -cdn -follow-redirects '
             f'-threads {min(config.threads, 50)} -timeout 15 -retries 2 '
             f'-json -o {out_file}'],
            timeout=600
        )

        # Parse JSON lines output
        if os.path.exists(out_file):
            for line in read_file_lines(out_file):
                try:
                    data = json.loads(line)
                    url = data.get('url', '')
                    status = data.get('status_code', 0)
                    title = data.get('title', '')
                    server = data.get('webserver', '')
                    techs = data.get('tech', [])

                    if url and scope.is_in_scope(url):
                        results.add_live_hosts([url])
                        count += 1

                        status_color = Colors.BGREEN if 200 <= status < 300 else \
                                       Colors.BYELLOW if 300 <= status < 400 else \
                                       Colors.BRED
                        detail = f"[{status_color}{status}{Colors.RESET}]"
                        if title:
                            detail += f" {title[:60]}"
                        if server:
                            detail += f" | {server}"
                        log_found("httpx", f"{url} {detail}")

                        if techs:
                            host = extract_domain_from_url(url)
                            results.add_technologies(host, techs)

                except json.JSONDecodeError:
                    continue

    # ── 2. httprobe fallback ──
    elif runner.is_available('httprobe'):
        log_info(f"Probing {len(subdomains)} hosts with httprobe...")
        stdout, _, _ = runner.run(
            ['bash', '-c', f'cat {subs_file} | httprobe -c {min(config.threads, 50)}'],
            timeout=300
        )
        if stdout:
            hosts = [h for h in parse_lines(stdout) if scope.is_in_scope(h)]
            results.add_live_hosts(hosts)
            count = len(hosts)
            for h in hosts:
                log_found("httprobe", h)

    # ── 3. Manual curl fallback ──
    else:
        log_info(f"Probing {len(subdomains)} hosts with curl...")
        live = set()

        def probe_host(sub):
            for scheme in ['https', 'http']:
                url = f'{scheme}://{sub}'
                stdout = runner.run_tool('curl', [
                    '-s', '-o', '/dev/null', '-w', '%{http_code}',
                    '-m', '10', '-L',
                    '-A', 'Mozilla/5.0',
                    url
                ], timeout=15, retries=1)
                if stdout and stdout.strip() not in ('000', ''):
                    return url
            return None

        tasks = [(probe_host, (sub,)) for sub in sorted(subdomains)[:200]]
        probe_results = runner.run_parallel(tasks, max_workers=min(20, config.threads))

        for result in probe_results:
            if result:
                live.add(result)
                log_found("curl", result)

        results.add_live_hosts(live)
        count = len(live)

    log_module_end("HTTP Probing", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  WEB CRAWLING
# ═══════════════════════════════════════════════════════════════════════════════

def web_crawling(config, runner, scope, results):
    log_module_start("Web Crawling")
    live_hosts = results.get_live_hosts()

    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    all_crawled = set()

    # Limit hosts for crawling
    crawl_targets = sorted(live_hosts)[:30]
    targets_file = os.path.join(config.dirs['crawl'], 'crawl_targets.txt')
    write_lines(targets_file, crawl_targets)

    # ── 1. Katana (ProjectDiscovery - preferred) ──
    if runner.is_available('katana'):
        log_info(f"Crawling {len(crawl_targets)} hosts with katana...")
        out_file = os.path.join(config.dirs['crawl'], 'katana_output.txt')

        stdout, _, _ = runner.run(
            ['bash', '-c',
             f'cat {targets_file} | katana -silent -d 3 -ct 10 '
             f'-c {min(config.threads, 20)} -timeout 10 '
             f'-jc -kf all -ef png,jpg,gif,svg,ico,woff,woff2,ttf,eot,css '
             f'-o {out_file}'],
            timeout=600
        )
        if os.path.exists(out_file):
            urls = [u for u in read_file_lines(out_file) if scope.is_in_scope(u)]
            all_crawled.update(urls)
            log_info(f"katana: {len(urls)} URLs crawled")

    # ── 2. GoSpider ──
    if runner.is_available('gospider') and not config.quick:
        log_info("Crawling with gospider...")
        out_dir = os.path.join(config.dirs['crawl'], 'gospider')
        os.makedirs(out_dir, exist_ok=True)

        stdout = runner.run_tool('gospider', [
            '-S', targets_file,
            '-d', '2',
            '-c', str(min(config.threads, 10)),
            '-t', '10',
            '--no-redirect',
            '-o', out_dir,
        ], timeout=600)

        # Parse gospider output files
        if os.path.exists(out_dir):
            for f in os.listdir(out_dir):
                fp = os.path.join(out_dir, f)
                for line in read_file_lines(fp):
                    # gospider format: [source] [type] - url
                    url_match = re.search(r'https?://\S+', line)
                    if url_match:
                        url = url_match.group(0)
                        if scope.is_in_scope(url):
                            all_crawled.add(url)

        log_info(f"gospider: {len(all_crawled)} total URLs")

    # ── 3. Hakrawler ──
    if runner.is_available('hakrawler') and not config.quick:
        log_info("Crawling with hakrawler...")
        stdout, _, _ = runner.run(
            ['bash', '-c',
             f'cat {targets_file} | hakrawler -d 2 -t {min(config.threads, 10)} -timeout 10'],
            timeout=300
        )
        if stdout:
            urls = [u for u in parse_lines(stdout) if scope.is_in_scope(u)]
            all_crawled.update(urls)
            log_info(f"hakrawler: {len(urls)} URLs")

    # Process crawled URLs
    if all_crawled:
        results.add_crawled_urls(all_crawled)
        results.add_urls(all_crawled)

        # Extract JS files
        js_files = [u for u in all_crawled
                    if re.search(r'\.js(\?|$)', u, re.IGNORECASE)]
        if js_files:
            results.add_js_files(js_files)
            log_info(f"Extracted {len(js_files)} JavaScript files from crawl")

        # Identify interesting endpoints
        api_endpoints = [u for u in all_crawled
                        if re.search(r'/api/|/v[0-9]+/|graphql|rest|swagger|openapi', u, re.IGNORECASE)]
        if api_endpoints:
            out_file = os.path.join(config.dirs['crawl'], 'api_endpoints.txt')
            write_lines(out_file, sorted(api_endpoints))
            log_info(f"Found {len(api_endpoints)} potential API endpoints")

        # Identify forms and upload endpoints
        form_urls = [u for u in all_crawled
                    if re.search(r'upload|submit|form|login|register|signup|contact', u, re.IGNORECASE)]
        if form_urls:
            out_file = os.path.join(config.dirs['crawl'], 'form_endpoints.txt')
            write_lines(out_file, sorted(form_urls))
            log_info(f"Found {len(form_urls)} potential form/upload endpoints")

        count = len(all_crawled)

    log_module_end("Web Crawling", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  DIRECTORY BRUTEFORCE
# ═══════════════════════════════════════════════════════════════════════════════

def directory_bruteforce(config, runner, scope, results):
    log_module_start("Directory Bruteforce")
    live_hosts = results.get_live_hosts()

    if not live_hosts:
        live_hosts = {config.target_base}

    # Only bruteforce top targets
    brute_targets = sorted(live_hosts)[:10]
    count = 0
    wordlist = config.wordlist or _find_dir_wordlist()

    if not wordlist:
        log_warning("No wordlist found for directory bruteforce — skipping")
        log_module_end("Directory Bruteforce", 0)
        return

    for target_url in brute_targets:
        # ── 1. ffuf (preferred) ──
        if runner.is_available('ffuf'):
            log_info(f"Running ffuf on {target_url}...")
            safe_name = safe_filename(extract_domain_from_url(target_url))
            out_file = os.path.join(config.dirs['dirs'], f'ffuf_{safe_name}.json')

            stdout = runner.run_tool('ffuf', [
                '-u', f'{target_url.rstrip("/")}/FUZZ',
                '-w', wordlist,
                '-t', str(min(config.threads, 40)),
                '-timeout', '10',
                '-mc', '200,201,202,204,301,302,307,308,401,403,405',
                '-fc', '404',
                '-ac',                                # Auto-calibrate
                '-sf',                                 # Stop on floods
                '-se',                                 # Stop on errors
                '-recursion', '-recursion-depth', '2',
                '-o', out_file,
                '-of', 'json',
                '-s',                                  # Silent
            ], timeout=600)

            if os.path.exists(out_file):
                try:
                    with open(out_file) as f:
                        data = json.loads(f.read())
                    for result in data.get('results', []):
                        url = result.get('url', '')
                        status = result.get('status', 0)
                        length = result.get('length', 0)
                        if url:
                            results.add_directories([url])
                            log_found("ffuf", f"{url} [{status}] [{length}B]")
                            count += 1
                except (json.JSONDecodeError, KeyError):
                    pass

        # ── 2. gobuster fallback ──
        elif runner.is_available('gobuster'):
            log_info(f"Running gobuster on {target_url}...")
            safe_name = safe_filename(extract_domain_from_url(target_url))
            out_file = os.path.join(config.dirs['dirs'], f'gobuster_{safe_name}.txt')

            stdout = runner.run_tool('gobuster', [
                'dir',
                '-u', target_url,
                '-w', wordlist,
                '-t', str(min(config.threads, 40)),
                '--timeout', '10s',
                '-s', '200,201,202,204,301,302,307,308,401,403,405',
                '-o', out_file,
                '-q', '--no-color',
                '-e',                                   # Expanded mode (full URLs)
            ], timeout=600)

            if stdout:
                for line in parse_lines(stdout):
                    url_match = re.search(r'(https?://\S+)', line)
                    if url_match:
                        found_url = url_match.group(1)
                        results.add_directories([found_url])
                        log_found("gobuster", found_url)
                        count += 1

        # ── 3. dirsearch fallback ──
        elif runner.is_available('dirsearch'):
            log_info(f"Running dirsearch on {target_url}...")
            stdout = runner.run_tool('dirsearch', [
                '-u', target_url,
                '-w', wordlist,
                '-t', str(min(config.threads, 30)),
                '--timeout', '10',
                '-q', '--plain-text-report=-',
            ], timeout=600)
            if stdout:
                for line in parse_lines(stdout):
                    if re.match(r'\d{3}', line):
                        parts = line.split()
                        if len(parts) >= 2:
                            found_url = parts[-1]
                            results.add_directories([found_url])
                            count += 1

    log_module_end("Directory Bruteforce", count)


def _find_dir_wordlist():
    """Find a suitable directory wordlist."""
    paths = [
        '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        '/usr/share/dirb/wordlists/common.txt',
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  PARAMETER DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

def parameter_discovery(config, runner, scope, results):
    log_module_start("Parameter Discovery")
    live_hosts = results.get_live_hosts()

    if not live_hosts:
        live_hosts = {config.target_base}

    param_targets = sorted(live_hosts)[:10]
    count = 0

    # ── 1. ParamSpider ──
    if runner.is_available('paramspider'):
        log_info("Running paramspider...")
        for target_url in param_targets[:5]:
            domain = extract_domain_from_url(target_url)
            stdout = runner.run_tool('paramspider', [
                '-d', domain,
                '--level', 'high',
                '-o', os.path.join(config.dirs['params'], f'paramspider_{safe_filename(domain)}.txt'),
            ], timeout=180)
            if stdout:
                urls = [u for u in parse_lines(stdout) if scope.is_in_scope(u)]
                for url in urls:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]
                        results.add_parameters(url, params)
                        count += len(params)

    # ── 2. Arjun ──
    if runner.is_available('arjun') and not config.quick:
        log_info("Running arjun for hidden parameter discovery...")
        for target_url in param_targets[:5]:
            safe_name = safe_filename(extract_domain_from_url(target_url))
            out_file = os.path.join(config.dirs['params'], f'arjun_{safe_name}.json')

            stdout = runner.run_tool('arjun', [
                '-u', target_url,
                '-t', str(min(config.threads, 10)),
                '-o', out_file,
                '--stable',
            ], timeout=300)

            if os.path.exists(out_file):
                try:
                    with open(out_file) as f:
                        data = json.loads(f.read())
                    for url, params in data.items():
                        if isinstance(params, list):
                            results.add_parameters(url, params)
                            for p in params:
                                log_found("arjun", f"{url} → {p}")
                            count += len(params)
                except (json.JSONDecodeError, KeyError):
                    pass

    # ── 3. Extract params from existing URLs ──
    all_urls = results.get_urls() | results.get_wayback_urls() | results.get_crawled_urls()
    param_urls = [u for u in all_urls if '?' in u and scope.is_in_scope(u)]

    if param_urls:
        param_set = set()
        for url in param_urls:
            parsed = urlparse(url)
            if parsed.query:
                for pair in parsed.query.split('&'):
                    if '=' in pair:
                        param = pair.split('=')[0]
                        param_set.add(param)

        if param_set:
            out_file = os.path.join(config.dirs['params'], 'unique_params.txt')
            write_lines(out_file, sorted(param_set))
            log_info(f"Extracted {len(param_set)} unique parameters from collected URLs")
            count += len(param_set)

    log_module_end("Parameter Discovery", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  JAVASCRIPT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def js_analysis(config, runner, scope, results):
    log_module_start("JavaScript Analysis")
    js_files = results.get_js_files()

    if not js_files:
        # Try to find JS from live hosts
        live_hosts = results.get_live_hosts()
        if live_hosts:
            log_info("No JS files found yet, extracting from live hosts...")
            for host in sorted(live_hosts)[:10]:
                stdout = runner.run_tool('curl', [
                    '-s', '-m', '15', '-L',
                    '-A', 'Mozilla/5.0',
                    host
                ], timeout=20, retries=1)
                if stdout:
                    # Extract JS URLs from HTML
                    js_matches = re.findall(
                        r'(?:src|href)\s*=\s*["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
                        stdout, re.IGNORECASE
                    )
                    for js_url in js_matches:
                        if js_url.startswith('//'):
                            js_url = 'https:' + js_url
                        elif js_url.startswith('/'):
                            js_url = host.rstrip('/') + js_url
                        elif not js_url.startswith('http'):
                            js_url = host.rstrip('/') + '/' + js_url
                        if scope.is_in_scope(js_url):
                            js_files.add(js_url)

            results.add_js_files(js_files)

    if not js_files:
        log_warning("No JavaScript files to analyze")
        log_module_end("JavaScript Analysis", 0)
        return

    count = 0
    log_info(f"Analyzing {len(js_files)} JavaScript files...")
    js_files_list = sorted(js_files)[:100]  # Limit

    all_endpoints = set()
    all_secrets = []

    # ── 1. LinkFinder ──
    if runner.is_available('linkfinder'):
        for js_url in js_files_list[:30]:
            stdout = runner.run_tool('linkfinder', [
                '-i', js_url,
                '-o', 'cli',
            ], timeout=30, retries=1)
            if stdout:
                for line in parse_lines(stdout):
                    line = line.strip()
                    if line and line.startswith('/'):
                        all_endpoints.add(line)

    # ── 2. Manual JS analysis (always runs) ──
    secret_patterns = [
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key'),
        (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', 'Secret/Token'),
        (r'(?:aws_access_key_id)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', 'AWS Access Key'),
        (r'(?:aws_secret_access_key)\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'AWS Secret Key'),
        (r'(?:firebase|google)[\w]*\s*[:=]\s*["\']([a-zA-Z0-9_\-]{30,})["\']', 'Firebase/Google Key'),
        (r'(?:gh[pousr]_[a-zA-Z0-9_]{36,})', 'GitHub Token'),
        (r'(?:sk_live_[a-zA-Z0-9]{24,})', 'Stripe Secret Key'),
        (r'(?:sq0[a-z]{3}-[a-zA-Z0-9_\-]{22,})', 'Square Key'),
        (r'(?:xox[bpoa]-[0-9]{10,}-[a-zA-Z0-9-]+)', 'Slack Token'),
        (r'(?:eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.?[a-zA-Z0-9_-]*)', 'JWT Token'),
        (r'(?:https?://[^"\'\s]*(?:internal|staging|dev|test|admin|private)[^"\'\s]*)', 'Internal URL'),
        (r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', 'IP Address'),
        (r's3\.amazonaws\.com[/\w.-]*|[\w.-]+\.s3\.amazonaws\.com', 'S3 Bucket'),
    ]

    endpoint_patterns = [
        r'["\'](\/[a-zA-Z0-9_\-/.]+)["\']',
        r'["\'](https?://[^"\']+)["\']',
        r'(?:url|endpoint|path|api|route)\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    def analyze_js(js_url):
        findings = {'endpoints': set(), 'secrets': []}
        content = runner.run_tool('curl', [
            '-s', '-m', '15', '-L',
            '-A', 'Mozilla/5.0',
            js_url
        ], timeout=20, retries=1)
        if not content:
            return findings

        # Find secrets
        for pattern, name in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                finding = {
                    'type': name,
                    'value': match[:80],
                    'source': js_url,
                }
                findings['secrets'].append(finding)

        # Find endpoints
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if len(match) > 3 and not match.endswith(('.png', '.jpg', '.gif', '.svg', '.css', '.ico')):
                    findings['endpoints'].add(match)

        return findings

    tasks = [(analyze_js, (js_url,)) for js_url in js_files_list[:50]]
    js_results = runner.run_parallel(tasks, max_workers=min(10, config.threads))

    for result in js_results:
        if result:
            all_endpoints.update(result.get('endpoints', set()))
            for secret in result.get('secrets', []):
                all_secrets.append(secret)
                log_vuln_helper('medium', f"[JS] {secret['type']}: {secret['value'][:40]}...",
                               secret['source'])
                results.add_vuln({
                    'type': 'js_secret',
                    'severity': 'medium',
                    'title': f"Exposed {secret['type']} in JavaScript",
                    'detail': secret['value'][:80],
                    'url': secret['source'],
                })
                count += 1

    # Save endpoints
    if all_endpoints:
        out_file = os.path.join(config.dirs['js'], 'js_endpoints.txt')
        write_lines(out_file, sorted(all_endpoints))
        results.add_urls(all_endpoints)
        log_info(f"Found {len(all_endpoints)} endpoints in JavaScript files")
        count += len(all_endpoints)

    # Save secrets
    if all_secrets:
        out_file = os.path.join(config.dirs['js'], 'js_secrets.json')
        with open(out_file, 'w') as f:
            json.dump(all_secrets, f, indent=2)
        log_info(f"Found {len(all_secrets)} potential secrets in JavaScript files")

    log_module_end("JavaScript Analysis", count)


def log_vuln_helper(severity, title, detail=""):
    """Helper to log vulns from active module."""
    from potlib.ui import log_vuln
    log_vuln(severity, title, detail)


# ═══════════════════════════════════════════════════════════════════════════════
#  SCREENSHOT CAPTURE
# ═══════════════════════════════════════════════════════════════════════════════

def screenshot_capture(config, runner, scope, results):
    log_module_start("Screenshot Capture")
    live_hosts = results.get_live_hosts()

    if not live_hosts:
        log_warning("No live hosts for screenshots")
        log_module_end("Screenshot Capture", 0)
        return

    screenshot_targets = sorted(live_hosts)[:50]
    targets_file = os.path.join(config.dirs['screenshots'], 'targets.txt')
    write_lines(targets_file, screenshot_targets)
    count = 0

    # ── 1. gowitness ──
    if runner.is_available('gowitness'):
        log_info(f"Capturing screenshots with gowitness ({len(screenshot_targets)} targets)...")
        db_file = os.path.join(config.dirs['screenshots'], 'gowitness.sqlite3')

        stdout = runner.run_tool('gowitness', [
            'file', '-f', targets_file,
            '-P', config.dirs['screenshots'],
            '--db-path', db_file,
            '-t', str(min(config.threads, 10)),
            '--timeout', '15',
            '--delay', '2',
        ], timeout=600)
        # Count screenshots
        if os.path.exists(config.dirs['screenshots']):
            pngs = [f for f in os.listdir(config.dirs['screenshots']) if f.endswith('.png')]
            count = len(pngs)
            log_info(f"gowitness: {count} screenshots captured")

    # ── 2. Eyewitness fallback ──
    elif runner.is_available('eyewitness'):
        log_info(f"Capturing screenshots with eyewitness...")
        report_dir = os.path.join(config.dirs['screenshots'], 'eyewitness_report')

        stdout = runner.run_tool('eyewitness', [
            '-f', targets_file,
            '-d', report_dir,
            '--no-prompt',
            '--timeout', '15',
            '--threads', str(min(config.threads, 10)),
        ], timeout=600)
        if os.path.exists(report_dir):
            count = len([f for f in os.listdir(os.path.join(report_dir, 'screens'))
                        if f.endswith('.png')]) if os.path.exists(os.path.join(report_dir, 'screens')) else 0
            log_info(f"eyewitness: {count} screenshots captured")

    # ── 3. cutycapt fallback (Kali built-in) ──
    elif runner.is_available('cutycapt'):
        log_info("Using cutycapt for screenshots...")
        for url in screenshot_targets[:20]:
            safe_name = safe_filename(extract_domain_from_url(url))
            out_file = os.path.join(config.dirs['screenshots'], f'{safe_name}.png')
            runner.run_tool('cutycapt', [
                f'--url={url}',
                f'--out={out_file}',
                '--delay=3000',
                '--min-width=1280',
            ], timeout=30, retries=1)
            if os.path.exists(out_file):
                count += 1

        log_info(f"cutycapt: {count} screenshots captured")

    log_module_end("Screenshot Capture", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  WAF DETECTION & EVASION
# ═══════════════════════════════════════════════════════════════════════════════

# WAF signatures: (header_or_body_pattern, waf_name)
WAF_SIGNATURES = {
    # Header-based detection
    'cf-ray': 'Cloudflare',
    'cf-cache-status': 'Cloudflare',
    'cf-mitigated': 'Cloudflare',
    'x-sucuri': 'Sucuri',
    'x-sucuri-id': 'Sucuri',
    'x-akamai': 'Akamai',
    'x-cdn': 'Incapsula/Imperva',
    'x-iinfo': 'Incapsula/Imperva',
    'x-sigsci': 'Signal Sciences',
    'x-denied-reason': 'Barracuda',
    'x-czid': 'CloudFront',
    'x-amz-cf-id': 'AWS CloudFront',
    'x-amz-cf-pop': 'AWS CloudFront',
    'x-aws-waf': 'AWS WAF',
    'x-bsb-ver': 'BaishanCloud',
    'x-dw-request-base-id': 'Distil/DataDome',
    'datadome': 'DataDome',
    'x-datadome': 'DataDome',
    'x-mod-security': 'ModSecurity',
    'x-webknight': 'WebKnight',
    'x-protected-by': 'Generic WAF',
}

# Body-based detection
WAF_BODY_SIGNATURES = [
    ('access denied', 'Generic WAF'),
    ('attention required! | cloudflare', 'Cloudflare'),
    ('checking your browser', 'Cloudflare'),
    ('please wait while we verify', 'Cloudflare'),
    ('cloudflare ray id', 'Cloudflare'),
    ('incapsula incident', 'Incapsula/Imperva'),
    ('powered by incapsula', 'Incapsula/Imperva'),
    ('request unsuccessful. incapsula', 'Incapsula/Imperva'),
    ('sucuri website firewall', 'Sucuri'),
    ('sucuri cloudproxy', 'Sucuri'),
    ('akamai ghost', 'Akamai'),
    ('akamaighost', 'Akamai'),
    ('this request was blocked by the security rules', 'AWS WAF'),
    ('wordfence', 'Wordfence'),
    ('generated by wordfence', 'Wordfence'),
    ('blocked by mod_security', 'ModSecurity'),
    ('not acceptable! an appropriate representation', 'ModSecurity'),
    ('406 not acceptable', 'ModSecurity'),
    ('fortiweb', 'FortiWeb'),
    ('fortigate', 'FortiGate'),
    ('bigip', 'F5 BIG-IP'),
    ('the requested url was rejected', 'F5 BIG-IP'),
    ('please consult with your administrator', 'F5 BIG-IP'),
    ('secureworks', 'Dell SecureWorks'),
    ('ddos-guard', 'DDoS-Guard'),
    ('blockdos', 'BlockDoS'),
    ('comodo waf', 'Comodo WAF'),
    ('protected by rapid7', 'Rapid7'),
]

# Evasion User-Agents
EVASION_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
]


def waf_detection(config, runner, scope, results):
    """Detect WAF presence, identify vendor, configure evasion."""
    log_module_start("WAF Detection & Evasion")
    target_url = config.target_base
    count = 0
    detected_wafs = set()

    # ── 1. Normal request — check headers ──
    log_info("Probing target for WAF presence...")
    stdout = runner.run_tool('curl', [
        '-s', '-I', '-L',
        '-m', '15',
        '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        target_url
    ], timeout=20, retries=2)

    if stdout:
        response_lower = stdout.lower()
        for header_pattern, waf_name in WAF_SIGNATURES.items():
            if header_pattern.lower() in response_lower:
                detected_wafs.add(waf_name)
                log_found("waf", f"Detected: {waf_name} (header: {header_pattern})")
                count += 1

    # ── 2. Get response body for body-based detection ──
    stdout = runner.run_tool('curl', [
        '-s', '-L',
        '-m', '15',
        '-A', 'Mozilla/5.0',
        target_url
    ], timeout=20, retries=1)

    if stdout:
        body_lower = stdout.lower()
        for pattern, waf_name in WAF_BODY_SIGNATURES:
            if pattern in body_lower:
                detected_wafs.add(waf_name)
                log_found("waf", f"Detected: {waf_name} (body pattern)")
                count += 1

    # ── 3. Provoke WAF with malicious request ──
    provoke_payloads = [
        f"{target_url}/?id=1' OR '1'='1",
        f"{target_url}/?q=<script>alert(1)</script>",
        f"{target_url}/?file=../../../../etc/passwd",
        f"{target_url}/?cmd=;cat /etc/passwd",
    ]

    for payload_url in provoke_payloads:
        stdout = runner.run_tool('curl', [
            '-s', '-I',
            '-m', '10',
            '-o', '/dev/null',
            '-w', '%{http_code}',
            '-A', 'Mozilla/5.0',
            payload_url
        ], timeout=15, retries=1)

        if stdout and stdout.strip() in ('403', '406', '429', '503'):
            # WAF is blocking — get full response for fingerprint
            full_resp = runner.run_tool('curl', [
                '-s', '-I', '-m', '10', payload_url
            ], timeout=15, retries=1)

            if full_resp:
                resp_lower = full_resp.lower()
                for header_pattern, waf_name in WAF_SIGNATURES.items():
                    if header_pattern.lower() in resp_lower:
                        detected_wafs.add(waf_name)

                for pattern, waf_name in WAF_BODY_SIGNATURES:
                    if pattern in resp_lower:
                        detected_wafs.add(waf_name)

            if not detected_wafs:
                detected_wafs.add('Unknown WAF')
                log_found("waf", f"WAF blocking detected (HTTP {stdout.strip()}) but vendor unknown")

    # ── 4. Check via wafw00f if available ──
    if runner.is_available('wafw00f'):
        log_info("Running wafw00f...")
        waf_stdout = runner.run_tool('wafw00f', [
            target_url, '-o', '-'
        ], timeout=60)
        if waf_stdout:
            for line in waf_stdout.split('\n'):
                if 'is behind' in line.lower():
                    # Extract WAF name
                    waf_match = re.search(r'is behind\s+(.+?)\s*(?:WAF|$)', line, re.IGNORECASE)
                    if waf_match:
                        waf_name = waf_match.group(1).strip()
                        detected_wafs.add(waf_name)
                        log_found("wafw00f", f"Detected: {waf_name}")
                        count += 1
                elif 'no waf' in line.lower():
                    log_info("wafw00f: No WAF detected")

    # ── Store results and configure evasion ──
    if detected_wafs:
        waf_list = sorted(detected_wafs)
        log_info(f"WAFs detected: {', '.join(waf_list)}")

        results.add_interesting({
            'type': 'waf_detected',
            'severity': 'info',
            'detail': f"WAF(s) detected: {', '.join(waf_list)}",
            'wafs': waf_list,
        })

        for waf in waf_list:
            results.add_vuln({
                'type': 'waf',
                'severity': 'info',
                'title': f'WAF Detected: {waf}',
                'detail': f'{waf} firewall is protecting {target_url}',
                'url': target_url,
            })

        # Configure WAF evasion on the runner
        _configure_waf_evasion(config, runner, detected_wafs)

        out_file = os.path.join(config.dirs['raw'], 'waf_detection.json')
        import json as _json
        with open(out_file, 'w') as f:
            _json.dump({'target': target_url, 'wafs': waf_list}, f, indent=2)
    else:
        log_info("No WAF detected — proceeding without evasion")

    log_module_end("WAF Detection & Evasion", count)


def _configure_waf_evasion(config, runner, detected_wafs):
    """Apply WAF evasion settings to the runner configuration."""
    log_info("Configuring WAF evasion strategies...")

    # Lower rate limit to avoid triggering rate-based rules
    if config.rate_limit > 50:
        old_rate = config.rate_limit
        config.rate_limit = min(config.rate_limit, 50)
        log_info(f"Rate limit reduced: {old_rate} → {config.rate_limit} req/s (WAF evasion)")

    # Increase timeouts (WAF may add delay)
    if config.timeout < 30:
        config.timeout = 30

    # Add jitter between requests
    runner._waf_evasion = True
    runner._waf_detected = sorted(detected_wafs)
    runner._evasion_agents = EVASION_USER_AGENTS

    waf_names = ', '.join(detected_wafs)
    evasion_tips = []

    if 'Cloudflare' in detected_wafs:
        evasion_tips.append("Cloudflare: Using browser-like UA rotation, slower rate")
    if 'Incapsula/Imperva' in detected_wafs:
        evasion_tips.append("Imperva: Adding realistic headers, randomized delays")
    if 'Akamai' in detected_wafs:
        evasion_tips.append("Akamai: Conservative scanning, extended timeouts")
    if 'ModSecurity' in detected_wafs:
        evasion_tips.append("ModSecurity: Encoding payloads, avoiding common signatures")
    if 'AWS WAF' in detected_wafs or 'AWS CloudFront' in detected_wafs:
        evasion_tips.append("AWS WAF: Rate limiting active, using distributed delays")
    if 'Wordfence' in detected_wafs:
        evasion_tips.append("Wordfence: WordPress WAF detected, reducing aggression")

    for tip in evasion_tips:
        log_info(f"  ↳ {tip}")

    if not evasion_tips:
        log_info(f"  ↳ {waf_names}: Generic evasion (UA rotation, rate limiting, delays)")


# ═══════════════════════════════════════════════════════════════════════════════
#  CLOUD BUCKET ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

def cloud_bucket_enum(config, runner, scope, results):
    """Enumerate cloud storage buckets (S3, GCS, Azure Blob)."""
    log_module_start("Cloud Bucket Enumeration")
    domain = config.target_domain
    count = 0

    # Generate bucket name permutations from domain
    base = domain.replace('.', '-')
    parts = domain.split('.')
    org_name = parts[0] if parts else domain

    # Comprehensive bucket name wordlist
    bucket_permutations = set()
    prefixes = ['', 'www-', 'cdn-', 'assets-', 'media-', 'static-',
                'images-', 'img-', 'files-', 'data-', 'docs-',
                'backup-', 'bak-', 'dev-', 'stg-', 'staging-',
                'prod-', 'production-', 'test-', 'testing-',
                'uat-', 'qa-', 'api-', 'app-', 'web-',
                'public-', 'private-', 'internal-', 'logs-',
                'uploads-', 'download-', 'temp-', 'tmp-']
    suffixes = ['', '-assets', '-cdn', '-media', '-static',
                '-images', '-backup', '-bak', '-dev', '-stg',
                '-staging', '-prod', '-test', '-data', '-files',
                '-public', '-private', '-uploads', '-logs',
                '-web', '-app', '-api', '-docs', '-db',
                '-bucket', '-storage', '-content', '-archive']

    for prefix in prefixes:
        for suffix in suffixes:
            bucket_permutations.add(f"{prefix}{org_name}{suffix}")
            bucket_permutations.add(f"{prefix}{base}{suffix}")

    # Add common patterns
    for name in [org_name, base]:
        bucket_permutations.update([
            name, f"{name}-s3", f"s3-{name}",
            f"{name}.com", f"{name}-com",
            f"{name}-2024", f"{name}-2025", f"{name}-2026",
        ])

    bucket_list = sorted(bucket_permutations)
    log_info(f"Testing {len(bucket_list)} bucket permutations across S3/GCS/Azure...")

    found_buckets = []

    # ── 1. AWS S3 Buckets ──
    def check_s3(bucket_name):
        hits = []
        # Method 1: HTTP check
        stdout = runner.run_tool('curl', [
            '-s', '-o', '/dev/null',
            '-w', '%{http_code}',
            '-m', '5',
            f'https://{bucket_name}.s3.amazonaws.com'
        ], timeout=8, retries=1)

        if stdout and stdout.strip() in ('200', '403', '301'):
            status = stdout.strip()
            listable = (status == '200')
            hits.append({
                'provider': 'AWS S3',
                'name': bucket_name,
                'url': f'https://{bucket_name}.s3.amazonaws.com',
                'status': status,
                'listable': listable,
            })
        return hits

    # ── 2. Google Cloud Storage ──
    def check_gcs(bucket_name):
        hits = []
        stdout = runner.run_tool('curl', [
            '-s', '-o', '/dev/null',
            '-w', '%{http_code}',
            '-m', '5',
            f'https://storage.googleapis.com/{bucket_name}'
        ], timeout=8, retries=1)

        if stdout and stdout.strip() in ('200', '403'):
            status = stdout.strip()
            hits.append({
                'provider': 'Google Cloud Storage',
                'name': bucket_name,
                'url': f'https://storage.googleapis.com/{bucket_name}',
                'status': status,
                'listable': (status == '200'),
            })
        return hits

    # ── 3. Azure Blob Storage ──
    def check_azure(bucket_name):
        hits = []
        # Azure uses <account>.blob.core.windows.net/<container>
        # Try account name = bucket_name
        stdout = runner.run_tool('curl', [
            '-s', '-o', '/dev/null',
            '-w', '%{http_code}',
            '-m', '5',
            f'https://{bucket_name}.blob.core.windows.net/?comp=list'
        ], timeout=8, retries=1)

        if stdout and stdout.strip() in ('200', '403'):
            status = stdout.strip()
            hits.append({
                'provider': 'Azure Blob',
                'name': bucket_name,
                'url': f'https://{bucket_name}.blob.core.windows.net',
                'status': status,
                'listable': (status == '200'),
            })
        return hits

    # Run all checks in parallel
    def check_all_clouds(bucket_name):
        results_list = []
        results_list.extend(check_s3(bucket_name))
        results_list.extend(check_gcs(bucket_name))
        results_list.extend(check_azure(bucket_name))
        return results_list

    tasks = [(check_all_clouds, (bn,)) for bn in bucket_list]
    cloud_results = runner.run_parallel(tasks, max_workers=min(15, config.threads))

    for result_list in cloud_results:
        if result_list:
            for bucket_info in result_list:
                found_buckets.append(bucket_info)
                severity = 'critical' if bucket_info['listable'] else 'medium'
                status_label = 'LISTABLE (PUBLIC)' if bucket_info['listable'] else 'EXISTS (restricted)'

                log_found("cloud",
                    f"{bucket_info['provider']}: {bucket_info['name']} [{status_label}]")

                results.add_vuln({
                    'type': 'cloud_bucket',
                    'severity': severity,
                    'title': f"{bucket_info['provider']} Bucket: {bucket_info['name']} ({status_label})",
                    'detail': f"{bucket_info['url']} [HTTP {bucket_info['status']}]",
                    'url': bucket_info['url'],
                })
                count += 1

    # ── 4. Check for buckets in collected URLs ──
    all_urls = results.get_urls() | results.get_wayback_urls()
    s3_pattern = re.compile(r'([a-zA-Z0-9._-]+)\.s3[.-](?:us|eu|ap|sa|ca|me|af)?-?(?:east|west|north|south|central|southeast|northeast)?-?\d*\.?amazonaws\.com')
    gcs_pattern = re.compile(r'storage\.googleapis\.com/([a-zA-Z0-9._-]+)')
    azure_pattern = re.compile(r'([a-zA-Z0-9._-]+)\.blob\.core\.windows\.net')

    url_buckets = set()
    for url in all_urls:
        for match in s3_pattern.findall(url):
            url_buckets.add(('AWS S3', match))
        for match in gcs_pattern.findall(url):
            url_buckets.add(('GCS', match))
        for match in azure_pattern.findall(url):
            url_buckets.add(('Azure', match))

    if url_buckets:
        for provider, name in url_buckets:
            log_found("cloud", f"Bucket reference in URLs: {provider} → {name}")
            results.add_interesting({
                'type': 'cloud_bucket_ref',
                'severity': 'info',
                'detail': f'{provider} bucket "{name}" referenced in collected URLs',
            })
            count += 1

    # Save results
    if found_buckets:
        out_file = os.path.join(config.dirs['raw'], 'cloud_buckets.json')
        import json as _json
        with open(out_file, 'w') as f:
            _json.dump(found_buckets, f, indent=2)

    log_module_end("Cloud Bucket Enumeration", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  ADVANCED API FUZZING
# ═══════════════════════════════════════════════════════════════════════════════

def api_fuzzing(config, runner, scope, results):
    """Fuzz discovered hosts for hidden API endpoints using ffuf."""
    log_module_start("API Fuzzing")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}
        
    count = 0
    if not runner.is_available('ffuf'):
        log_warning("ffuf not available — skipping API fuzzing")
        log_module_end("API Fuzzing", 0)
        return

    # Basic in-memory wordlist for critical API paths to avoid requiring a huge external file
    api_wordlist = [
        'api/v1', 'api/v2', 'api/v3', 'api/users', 'api/admin', 'api/auth', 
        'api/graphql', 'graphql', 'graphql/console', 'swagger.json', 'v2/api-docs',
        'api/swagger', 'api/docs', 'api/config', 'api/setup', 'api/login',
        'api/register', 'api/metrics', 'api/health', 'api/token', 'api/secret'
    ]
    
    # Write temp wordlist
    wl_path = os.path.join(config.dirs['raw'], '.api_wordlist.txt')
    with open(wl_path, 'w') as f:
        f.write('\n'.join(api_wordlist))
        
    out_file = os.path.join(config.dirs['dirs'], 'api_fuzzing.json')
    
    # We will just scan the first few live hosts to save time/quota
    targets = sorted(live_hosts)[:5]
    all_results = []
    
    for target_url in targets:
        target_url = target_url.rstrip('/')
        
        tmp_out = os.path.join(config.dirs['dirs'], f'.ffuf_api_{safe_filename(extract_domain_from_url(target_url))}.json')
        
        args = [
            '-w', wl_path,
            '-u', f'{target_url}/FUZZ',
            '-o', tmp_out,
            '-of', 'json',
            '-mc', '200,401,403,500',
            '-t', str(min(config.threads, 20)),
            '-rate', str(config.rate_limit)
        ]
        
        runner.run_tool('ffuf', args, timeout=120)
        
        if os.path.exists(tmp_out):
            try:
                with open(tmp_out) as f:
                    data = json.load(f)
                    
                for res in data.get('results', []):
                    url = res.get('url', '')
                    status = res.get('status', 0)
                    length = res.get('length', 0)
                    words = res.get('words', 0)
                    
                    if status in (200, 401, 403) and length > 0:
                        sev = 'high' if status == 200 and ('admin' in url or 'users' in url) else 'medium'
                        log_found("api_fuzz", f"{url} [Status: {status}] [Size: {length}]")
                        
                        results.add_vuln({
                            'type': 'api_endpoint_discovered',
                            'severity': sev,
                            'title': f'Hidden API Endpoint: {res.get("input", {}).get("FUZZ", "")}',
                            'detail': f'Status: {status}, Size: {length}',
                            'url': url
                        })
                        
                        all_results.append({
                            'url': url,
                            'status': status,
                            'length': length,
                            'words': words
                        })
                        count += 1
                        
                os.remove(tmp_out)
            except Exception:
                pass
                
    if all_results:
        with open(out_file, 'w') as f:
            json.dump(all_results, f, indent=2)
            
    if os.path.exists(wl_path):
        os.remove(wl_path)

    log_module_end("API Fuzzing", count)
