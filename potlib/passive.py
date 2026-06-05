#!/usr/bin/env python3
"""
POT - Professional Offensive Tool
Passive Reconnaissance Module
All passive techniques: WHOIS, DNS, subdomain enumeration, cert transparency,
wayback URLs, technology detection, email harvesting, ASN lookup.
"""

import os
import re
import json
import time
import random
import socket
from urllib.parse import urlparse

from potlib.ui import (
    log_info, log_warning, log_error, log_debug,
    log_found, log_module_start, log_module_end, log_phase, Colors
)
from potlib.engine import parse_lines, dedup_lines, write_lines


def run_all(config, runner, scope, results):
    """Execute all passive reconnaissance modules."""
    log_phase("PHASE 1 — PASSIVE RECONNAISSANCE")

    modules = [
        ('whois',            whois_lookup),
        ('dns',              dns_enumeration),
        ('subdomains',       subdomain_enumeration),
        ('crt.sh',           cert_transparency),
        ('wayback',          wayback_urls),
        ('tech',             technology_detection),
        ('emails',           email_harvesting),
        ('asn',              asn_cidr_lookup),
        ('github_dork',      github_dorking),
        ('google_dork',      google_dorking),
        ('shodan',           shodan_lookup),
    ]

    for name, func in modules:
        if name in config.skip_modules:
            log_info(f"Skipping module: {name}")
            continue
        try:
            func(config, runner, scope, results)
        except Exception as e:
            log_error(f"Module {name} failed: {e}")

    # Save intermediate results
    results.save_to_disk()
    total_subs = len(results.get_subdomains())
    log_info(f"Passive recon complete — {total_subs} unique subdomains collected")


# ═══════════════════════════════════════════════════════════════════════════════
#  WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

def whois_lookup(config, runner, scope, results):
    log_module_start("WHOIS Lookup")
    domain = config.target_domain
    count = 0

    stdout = runner.run_tool('whois', [domain], timeout=30)
    if stdout:
        whois_data = _parse_whois(stdout)
        results.set_whois(whois_data)

        # Save raw output
        raw_file = os.path.join(config.dirs['raw'], 'whois_raw.txt')
        with open(raw_file, 'w') as f:
            f.write(stdout)

        # Extract emails from whois
        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', stdout)
        if emails:
            results.add_emails(emails)
            for e in emails:
                log_found("whois", f"Email: {e}")

        # Log key info
        for key in ['registrar', 'creation_date', 'name_servers', 'org']:
            if key in whois_data and whois_data[key]:
                log_found("whois", f"{key}: {whois_data[key]}")
                count += 1

        # Extract nameservers as potential subdomains
        if 'name_servers' in whois_data:
            ns_list = whois_data['name_servers']
            if isinstance(ns_list, str):
                ns_list = [ns_list]
            for ns in ns_list:
                ns = ns.strip().lower().rstrip('.')
                if ns.endswith(f'.{domain}'):
                    results.add_subdomains([ns])
                    log_found("whois", f"NS subdomain: {ns}")

    log_module_end("WHOIS Lookup", count)


def _parse_whois(raw):
    """Parse raw WHOIS output into a structured dict."""
    data = {}
    field_map = {
        'registrar': ['Registrar:', 'registrar:'],
        'creation_date': ['Creation Date:', 'created:'],
        'expiry_date': ['Registry Expiry Date:', 'Expiry Date:', 'expires:'],
        'updated_date': ['Updated Date:', 'Last Updated:'],
        'org': ['Registrant Organization:', 'org:'],
        'country': ['Registrant Country:', 'country:'],
        'status': ['Status:', 'Domain Status:'],
    }

    name_servers = []
    for line in raw.split('\n'):
        line = line.strip()
        if not line or line.startswith('%') or line.startswith('#'):
            continue

        lower = line.lower()

        # Name servers
        if lower.startswith('name server:') or lower.startswith('nserver:'):
            ns = line.split(':', 1)[1].strip()
            name_servers.append(ns)
            continue

        # Other fields
        for key, patterns in field_map.items():
            for pattern in patterns:
                if lower.startswith(pattern.lower()):
                    value = line.split(':', 1)[1].strip()
                    if key == 'status':
                        if key not in data:
                            data[key] = []
                        data[key].append(value)
                    else:
                        data[key] = value
                    break

    if name_servers:
        data['name_servers'] = name_servers

    return data


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

def dns_enumeration(config, runner, scope, results):
    log_module_start("DNS Enumeration")
    domain = config.target_domain
    count = 0
    all_records = {}

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA']

    for rtype in record_types:
        stdout = runner.run_tool('dig', ['+short', rtype, domain], timeout=15, retries=2)
        if stdout:
            values = parse_lines(stdout)
            if values:
                all_records[rtype] = values
                for v in values:
                    log_found("dns", f"{rtype}: {v}")
                    count += 1

                    # Extract subdomains from DNS records
                    if rtype in ('MX', 'NS', 'CNAME', 'SRV'):
                        # MX records have priority prefix
                        if rtype == 'MX':
                            parts = v.split()
                            v = parts[-1] if parts else v
                        v = v.strip().rstrip('.')
                        if v.endswith(f'.{domain}') or v == domain:
                            results.add_subdomains([v])

    results.add_dns_records(domain, all_records)

    # Try dnsrecon for additional records
    if runner.is_available('dnsrecon'):
        stdout = runner.run_tool('dnsrecon', ['-d', domain, '-t', 'std', '--json', '-'], timeout=120)
        if stdout:
            try:
                dns_data = json.loads(stdout)
                for record in dns_data:
                    if isinstance(record, dict):
                        name = record.get('name', '').rstrip('.')
                        if name and scope.is_in_scope(name):
                            results.add_subdomains([name])
                            count += 1
            except json.JSONDecodeError:
                pass

    # Zone transfer attempt
    _try_zone_transfer(config, runner, domain, results)

    # Reverse DNS on found IPs
    a_records = all_records.get('A', [])
    for ip in a_records[:10]:  # Limit to first 10
        stdout = runner.run_tool('dig', ['+short', '-x', ip], timeout=10, retries=1)
        if stdout:
            for line in parse_lines(stdout):
                hostname = line.strip().rstrip('.')
                if scope.is_in_scope(hostname):
                    results.add_subdomains([hostname])
                    log_found("dns", f"Reverse DNS: {ip} → {hostname}")
                    count += 1

    log_module_end("DNS Enumeration", count)


def _try_zone_transfer(config, runner, domain, results):
    """Attempt DNS zone transfer."""
    # Get nameservers
    stdout = runner.run_tool('dig', ['+short', 'NS', domain], timeout=10)
    if not stdout:
        return

    nameservers = parse_lines(stdout)
    for ns in nameservers[:5]:
        ns = ns.strip().rstrip('.')
        stdout = runner.run_tool(
            'dig', ['axfr', domain, f'@{ns}'],
            timeout=30, retries=1
        )
        if stdout and 'XFR size' in stdout:
            log_found("dns", f"🔥 Zone transfer successful on {ns}!")
            # Parse transferred records
            for line in stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 5 and not line.startswith(';'):
                    hostname = parts[0].rstrip('.')
                    if hostname.endswith(f'.{domain}') or hostname == domain:
                        results.add_subdomains([hostname])

            results.add_interesting({
                'type': 'zone_transfer',
                'severity': 'high',
                'detail': f'Zone transfer successful on {ns} for {domain}',
                'nameserver': ns,
            })


# ═══════════════════════════════════════════════════════════════════════════════
#  SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

def subdomain_enumeration(config, runner, scope, results):
    log_module_start("Subdomain Enumeration")
    domain = config.target_domain
    total_new = 0

    # ── 1. Subfinder ──
    if runner.is_available('subfinder'):
        log_info("Running subfinder...")
        out_file = os.path.join(config.dirs['subdomains'], 'subfinder.txt')
        stdout = runner.run_tool('subfinder', [
            '-d', domain,
            '-silent',
            '-all',
            '-t', str(min(config.threads, 30)),
            '-timeout', '30',
        ], timeout=300)
        if stdout:
            subs = scope.filter_scope(parse_lines(stdout))
            new = results.add_subdomains(subs)
            total_new += new
            write_lines(out_file, subs)
            log_info(f"subfinder: {len(subs)} found, {new} new")
    else:
        log_warning("subfinder not installed — skipping")

    # ── 2. Amass (passive mode) ──
    if runner.is_available('amass') and not config.quick:
        log_info("Running amass passive enum...")
        out_file = os.path.join(config.dirs['subdomains'], 'amass.txt')
        stdout = runner.run_tool('amass', [
            'enum', '-passive', '-d', domain,
            '-timeout', '10',
        ], timeout=600)
        if stdout:
            subs = scope.filter_scope(parse_lines(stdout))
            new = results.add_subdomains(subs)
            total_new += new
            write_lines(out_file, subs)
            log_info(f"amass: {len(subs)} found, {new} new")
    elif not runner.is_available('amass'):
        log_warning("amass not installed — skipping")

    # ── 3. Assetfinder ──
    if runner.is_available('assetfinder'):
        log_info("Running assetfinder...")
        out_file = os.path.join(config.dirs['subdomains'], 'assetfinder.txt')
        stdout = runner.run_tool('assetfinder', [
            '--subs-only', domain
        ], timeout=120)
        if stdout:
            subs = scope.filter_scope(parse_lines(stdout))
            new = results.add_subdomains(subs)
            total_new += new
            write_lines(out_file, subs)
            log_info(f"assetfinder: {len(subs)} found, {new} new")

    # ── 4. Findomain ──
    if runner.is_available('findomain'):
        log_info("Running findomain...")
        out_file = os.path.join(config.dirs['subdomains'], 'findomain.txt')
        stdout = runner.run_tool('findomain', [
            '-t', domain, '-q'
        ], timeout=180)
        if stdout:
            subs = scope.filter_scope(parse_lines(stdout))
            new = results.add_subdomains(subs)
            total_new += new
            write_lines(out_file, subs)
            log_info(f"findomain: {len(subs)} found, {new} new")

    # ── 5. crt.sh API (always available via curl) ──
    _crtsh_enum(config, runner, scope, results, domain)

    # ── 6. Chaos (ProjectDiscovery) ──
    if runner.is_available('chaos') and os.environ.get('PDCP_API_KEY'):
        log_info("Running chaos...")
        stdout = runner.run_tool('chaos', [
            '-d', domain, '-silent'
        ], timeout=120)
        if stdout:
            subs = scope.filter_scope(parse_lines(stdout))
            new = results.add_subdomains(subs)
            total_new += new
            log_info(f"chaos: {len(subs)} found, {new} new")

    # ── 7. Gobuster DNS (if not quick mode) ──
    if runner.is_available('gobuster') and not config.quick:
        wordlist = config.wordlist or _find_wordlist()
        if wordlist:
            log_info("Running gobuster DNS brute...")
            out_file = os.path.join(config.dirs['subdomains'], 'gobuster_dns.txt')
            stdout = runner.run_tool('gobuster', [
                'dns', '-d', domain,
                '-w', wordlist,
                '-t', str(min(config.threads, 50)),
                '--no-color', '-q',
                '--timeout', '5s',
            ], timeout=600)
            if stdout:
                # Parse gobuster output: "Found: sub.domain.com"
                subs = []
                for line in parse_lines(stdout):
                    if line.startswith('Found:'):
                        sub = line.replace('Found:', '').strip()
                        subs.append(sub)
                    elif '.' in line and not line.startswith('['):
                        subs.append(line.strip())
                subs = scope.filter_scope(subs)
                new = results.add_subdomains(subs)
                total_new += new
                write_lines(out_file, subs)
                log_info(f"gobuster dns: {len(subs)} found, {new} new")

    # ── 8. Shuffledns (if massdns available) ──
    if runner.is_available('shuffledns') and not config.quick:
        wordlist = config.wordlist or _find_wordlist()
        resolvers = config.resolvers or _find_resolvers()
        if wordlist and resolvers:
            log_info("Running shuffledns...")
            out_file = os.path.join(config.dirs['subdomains'], 'shuffledns.txt')
            stdout = runner.run_tool('shuffledns', [
                '-d', domain,
                '-w', wordlist,
                '-r', resolvers,
                '-silent',
            ], timeout=600)
            if stdout:
                subs = scope.filter_scope(parse_lines(stdout))
                new = results.add_subdomains(subs)
                total_new += new
                write_lines(out_file, subs)
                log_info(f"shuffledns: {len(subs)} found, {new} new")

    # Log all discovered subdomains
    all_subs = results.get_subdomains()
    for sub in sorted(all_subs):
        log_found("subdomain", sub)

    log_module_end("Subdomain Enumeration", len(all_subs))


def _crtsh_enum(config, runner, scope, results, domain):
    """Query crt.sh for certificate transparency subdomains."""
    log_info("Querying crt.sh...")
    stdout = runner.run_tool('curl', [
        '-s', '-m', '60',
        f'https://crt.sh/?q=%25.{domain}&output=json'
    ], timeout=90, retries=3)

    if stdout:
        try:
            certs = json.loads(stdout)
            subs = set()
            for cert in certs:
                name = cert.get('name_value', '')
                for entry in name.split('\n'):
                    entry = entry.strip().lower()
                    entry = entry.lstrip('*.')
                    if entry and scope.is_in_scope(entry):
                        subs.add(entry)

            new = results.add_subdomains(subs)
            out_file = os.path.join(config.dirs['subdomains'], 'crtsh.txt')
            write_lines(out_file, sorted(subs))
            log_info(f"crt.sh: {len(subs)} found, {new} new")
        except json.JSONDecodeError:
            log_warning("crt.sh returned invalid JSON")


def _find_wordlist():
    """Find a suitable DNS wordlist on the system."""
    paths = [
        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
        '/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt',
        '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
        '/usr/share/amass/wordlists/subdomains-top1mil-5000.txt',
        '/usr/share/wordlists/dirb/common.txt',
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def _find_resolvers():
    """Find or create a resolvers file."""
    paths = [
        '/usr/share/seclists/Miscellaneous/dns-resolvers.txt',
        '/usr/share/wordlists/seclists/Miscellaneous/dns-resolvers.txt',
    ]
    for p in paths:
        if os.path.exists(p):
            return p

    # Create a default resolvers file
    default_resolvers = [
        '8.8.8.8', '8.8.4.4',          # Google
        '1.1.1.1', '1.0.0.1',          # Cloudflare
        '9.9.9.9', '149.112.112.112',  # Quad9
        '208.67.222.222',              # OpenDNS
        '64.6.64.6',                   # Verisign
    ]
    resolvers_file = '/tmp/pot_resolvers.txt'
    with open(resolvers_file, 'w') as f:
        f.write('\n'.join(default_resolvers) + '\n')
    return resolvers_file


# ═══════════════════════════════════════════════════════════════════════════════
#  CERTIFICATE TRANSPARENCY
# ═══════════════════════════════════════════════════════════════════════════════

def cert_transparency(config, runner, scope, results):
    """Additional certificate transparency sources beyond crt.sh."""
    log_module_start("Certificate Transparency")
    domain = config.target_domain
    count = 0

    # Certspotter API
    stdout = runner.run_tool('curl', [
        '-s', '-m', '30',
        f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names'
    ], timeout=60, retries=2)

    if stdout:
        try:
            certs = json.loads(stdout)
            subs = set()
            for cert in certs:
                for name in cert.get('dns_names', []):
                    name = name.strip().lower().lstrip('*.')
                    if scope.is_in_scope(name):
                        subs.add(name)
            if subs:
                new = results.add_subdomains(subs)
                count += len(subs)
                log_info(f"certspotter: {len(subs)} found, {new} new")
        except (json.JSONDecodeError, TypeError):
            pass

    # BufferOver API
    stdout = runner.run_tool('curl', [
        '-s', '-m', '30',
        f'https://dns.bufferover.run/dns?q=.{domain}'
    ], timeout=60, retries=2)

    if stdout:
        try:
            data = json.loads(stdout)
            subs = set()
            for record in data.get('FDNS_A', []) + data.get('RDNS', []):
                if isinstance(record, str):
                    parts = record.split(',')
                    for part in parts:
                        part = part.strip().lower()
                        if scope.is_in_scope(part):
                            subs.add(part)
            if subs:
                new = results.add_subdomains(subs)
                count += len(subs)
                log_info(f"bufferover: {len(subs)} found, {new} new")
        except (json.JSONDecodeError, TypeError):
            pass

    # HackerTarget API
    stdout = runner.run_tool('curl', [
        '-s', '-m', '30',
        f'https://api.hackertarget.com/hostsearch/?q={domain}'
    ], timeout=60, retries=2)

    if stdout and 'error' not in stdout.lower() and 'API count' not in stdout:
        subs = set()
        for line in stdout.split('\n'):
            if ',' in line:
                hostname = line.split(',')[0].strip().lower()
                if scope.is_in_scope(hostname):
                    subs.add(hostname)
        if subs:
            new = results.add_subdomains(subs)
            count += len(subs)
            log_info(f"hackertarget: {len(subs)} found, {new} new")

    # ThreatCrowd API
    stdout = runner.run_tool('curl', [
        '-s', '-m', '30',
        f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
    ], timeout=60, retries=1)

    if stdout:
        try:
            data = json.loads(stdout)
            subs = set()
            for sub in data.get('subdomains', []):
                sub = sub.strip().lower()
                if scope.is_in_scope(sub):
                    subs.add(sub)
            if subs:
                new = results.add_subdomains(subs)
                count += len(subs)
                log_info(f"threatcrowd: {len(subs)} found, {new} new")

            # Also grab emails
            for email in data.get('emails', []):
                results.add_emails([email])
        except (json.JSONDecodeError, TypeError):
            pass

    log_module_end("Certificate Transparency", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  WAYBACK URLS
# ═══════════════════════════════════════════════════════════════════════════════

def wayback_urls(config, runner, scope, results):
    log_module_start("Wayback URL Collection")
    domain = config.target_domain
    count = 0
    all_urls = set()

    # ── 1. waybackurls ──
    if runner.is_available('waybackurls'):
        log_info("Running waybackurls...")
        stdout, _, _ = runner.run(
            ['bash', '-c', f'echo "{domain}" | waybackurls'],
            timeout=300
        )
        if stdout:
            urls = [u for u in parse_lines(stdout) if scope.is_in_scope(u)]
            all_urls.update(urls)
            log_info(f"waybackurls: {len(urls)} URLs")

    # ── 2. gau (GetAllUrls) ──
    if runner.is_available('gau'):
        log_info("Running gau...")
        stdout = runner.run_tool('gau', [
            '--threads', str(min(config.threads, 10)),
            '--timeout', '30',
            '--subs',
            domain
        ], timeout=300)
        if stdout:
            urls = [u for u in parse_lines(stdout) if scope.is_in_scope(u)]
            all_urls.update(urls)
            log_info(f"gau: {len(urls)} URLs")

    # ── 3. Wayback Machine API directly ──
    if not all_urls:
        log_info("Querying Wayback Machine API...")
        stdout = runner.run_tool('curl', [
            '-s', '-m', '120',
            f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=10000'
        ], timeout=180, retries=2)
        if stdout:
            urls = [u for u in parse_lines(stdout) if scope.is_in_scope(u)]
            all_urls.update(urls)
            log_info(f"wayback API: {len(urls)} URLs")

    # Filter and categorize
    if all_urls:
        results.add_wayback_urls(all_urls)
        results.add_urls(all_urls)

        # Extract JS files
        js_urls = [u for u in all_urls if u.endswith('.js') or '.js?' in u]
        if js_urls:
            results.add_js_files(js_urls)
            log_info(f"Found {len(js_urls)} JavaScript files in wayback data")

        # Extract potentially interesting URLs
        interesting_patterns = [
            r'\.env', r'\.git', r'\.svn', r'\.bak', r'\.backup',
            r'\.sql', r'\.db', r'\.log', r'\.conf', r'\.config',
            r'admin', r'login', r'api/', r'swagger', r'graphql',
            r'\.xml', r'\.json', r'\.yaml', r'\.yml',
            r'wp-content', r'wp-admin', r'phpinfo',
            r'\.php\?', r'debug', r'test', r'staging',
            r'upload', r'token', r'secret', r'password', r'key=',
        ]
        interesting = set()
        for url in all_urls:
            url_lower = url.lower()
            for pattern in interesting_patterns:
                if re.search(pattern, url_lower):
                    interesting.add(url)
                    break

        if interesting:
            out_file = os.path.join(config.dirs['wayback'], 'interesting_urls.txt')
            write_lines(out_file, sorted(interesting))
            log_info(f"Found {len(interesting)} potentially interesting URLs")

        count = len(all_urls)

    log_module_end("Wayback URL Collection", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  TECHNOLOGY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def technology_detection(config, runner, scope, results):
    log_module_start("Technology Detection")
    domain = config.target_domain
    target_url = config.target_base
    count = 0

    # ── WhatWeb ──
    if runner.is_available('whatweb'):
        log_info("Running whatweb...")
        stdout = runner.run_tool('whatweb', [
            '-q', '-a', '3',
            '--color=never',
            '--log-json=-',
            target_url
        ], timeout=120)
        if stdout:
            try:
                # WhatWeb JSON output can be multiple lines
                for line in stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict):
                            techs = []
                            plugins = data.get('plugins', {})
                            for name, info in plugins.items():
                                version = ''
                                if isinstance(info, dict):
                                    ver_list = info.get('version', [])
                                    if ver_list:
                                        version = ver_list[0] if isinstance(ver_list, list) else str(ver_list)
                                tech_str = f"{name} {version}".strip()
                                techs.append(tech_str)
                                log_found("tech", tech_str)
                                count += 1
                            if techs:
                                results.add_technologies(domain, techs)
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                log_debug(f"WhatWeb parse error: {e}", config.verbose)

    # ── Wappalyzer (webanalyze) ──
    if runner.is_available('webanalyze'):
        log_info("Running webanalyze...")
        stdout = runner.run_tool('webanalyze', [
            '-host', target_url,
            '-output', 'json',
            '-silent',
        ], timeout=60)
        if stdout:
            try:
                data = json.loads(stdout)
                for match in data:
                    if isinstance(match, dict):
                        app = match.get('app', match.get('name', ''))
                        ver = match.get('version', '')
                        cat = ','.join(match.get('categories', []))
                        tech_str = f"{app} {ver} [{cat}]".strip()
                        results.add_technologies(domain, [tech_str])
                        log_found("tech", tech_str)
                        count += 1
            except (json.JSONDecodeError, TypeError):
                pass

    # ── HTTP Headers analysis ──
    log_info("Analyzing HTTP headers...")
    stdout = runner.run_tool('curl', [
        '-s', '-I', '-L',
        '-m', '15',
        '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        target_url
    ], timeout=30)
    if stdout:
        headers = _parse_headers(stdout)
        techs = _detect_tech_from_headers(headers)
        if techs:
            results.add_technologies(domain, techs)
            for t in techs:
                log_found("tech", f"Header: {t}")
                count += 1

        # Save headers
        out_file = os.path.join(config.dirs['tech'], 'http_headers.txt')
        with open(out_file, 'w') as f:
            f.write(stdout)

    log_module_end("Technology Detection", count)


def _parse_headers(raw):
    """Parse HTTP headers into a dict."""
    headers = {}
    for line in raw.split('\n'):
        if ':' in line and not line.startswith('HTTP/'):
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()
    return headers


def _detect_tech_from_headers(headers):
    """Detect technologies from HTTP headers."""
    techs = []
    server = headers.get('server', '')
    if server:
        techs.append(f"Server: {server}")

    powered = headers.get('x-powered-by', '')
    if powered:
        techs.append(f"X-Powered-By: {powered}")

    asp = headers.get('x-aspnet-version', '')
    if asp:
        techs.append(f"ASP.NET: {asp}")

    via = headers.get('via', '')
    if via:
        techs.append(f"Via: {via}")

    if 'x-drupal' in str(headers):
        techs.append("CMS: Drupal")
    if 'x-wordpress' in str(headers) or 'wp-' in str(headers):
        techs.append("CMS: WordPress")
    if 'x-shopify' in str(headers):
        techs.append("Platform: Shopify")

    return techs


# ═══════════════════════════════════════════════════════════════════════════════
#  EMAIL HARVESTING
# ═══════════════════════════════════════════════════════════════════════════════

def email_harvesting(config, runner, scope, results):
    log_module_start("Email Harvesting")
    domain = config.target_domain
    count = 0

    # ── theHarvester ──
    if runner.is_available('theHarvester'):
        log_info("Running theHarvester...")
        stdout = runner.run_tool('theHarvester', [
            '-d', domain,
            '-b', 'all',
            '-l', '200',
        ], timeout=300)
        if stdout:
            emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', stdout)
            if emails:
                results.add_emails(emails)
                for e in set(emails):
                    log_found("email", e)
                    count += 1

            # Also extract hosts
            host_section = False
            for line in stdout.split('\n'):
                line = line.strip()
                if 'Hosts found' in line:
                    host_section = True
                    continue
                if host_section and line and ':' in line:
                    parts = line.split(':')
                    hostname = parts[0].strip()
                    if scope.is_in_scope(hostname):
                        results.add_subdomains([hostname])
    elif runner.is_available('theharvester'):
        log_info("Running theharvester...")
        stdout = runner.run_tool('theharvester', [
            '-d', domain, '-b', 'all', '-l', '200'
        ], timeout=300)
        if stdout:
            emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', stdout)
            if emails:
                results.add_emails(emails)
                for e in set(emails):
                    log_found("email", e)
                    count += 1

    # ── EmailFinder via curl (hunter.io free) ──
    stdout = runner.run_tool('curl', [
        '-s', '-m', '15',
        f'https://api.hunter.io/v2/domain-search?domain={domain}&limit=10'
    ], timeout=30, retries=1)
    if stdout:
        try:
            data = json.loads(stdout)
            for email_obj in data.get('data', {}).get('emails', []):
                email = email_obj.get('value', '')
                if email:
                    results.add_emails([email])
                    log_found("email", email)
                    count += 1
        except (json.JSONDecodeError, TypeError):
            pass

    log_module_end("Email Harvesting", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  ASN / CIDR LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

def asn_cidr_lookup(config, runner, scope, results):
    """Map target's ASN, CIDR ranges, and related infrastructure."""
    log_module_start("ASN / CIDR Lookup")
    domain = config.target_domain
    count = 0

    # Resolve domain to IP first
    import socket as _sock
    target_ips = set()
    try:
        for info in _sock.getaddrinfo(domain, None):
            ip = info[4][0]
            if ':' not in ip:  # IPv4
                target_ips.add(ip)
    except Exception:
        pass

    if not target_ips:
        stdout = runner.run_tool('dig', ['+short', 'A', domain], timeout=10)
        if stdout:
            target_ips.update(l.strip() for l in stdout.split('\n') if l.strip() and l.strip()[0].isdigit())

    if not target_ips:
        log_warning("Could not resolve target IP for ASN lookup")
        log_module_end("ASN / CIDR Lookup", 0)
        return

    asn_data = {}

    for ip in target_ips:
        # ── 1. BGPView API ──
        stdout = runner.run_tool('curl', [
            '-s', '-m', '15',
            f'https://api.bgpview.io/ip/{ip}'
        ], timeout=30, retries=2)

        if stdout:
            try:
                data = json.loads(stdout)
                if data.get('status') == 'ok':
                    ip_data = data.get('data', {})
                    for prefix_info in ip_data.get('prefixes', []):
                        prefix = prefix_info.get('prefix', '')
                        asn_info = prefix_info.get('asn', {})
                        asn_num = asn_info.get('asn', '')
                        asn_name = asn_info.get('name', '')
                        asn_desc = asn_info.get('description', '')

                        asn_entry = {
                            'ip': ip,
                            'asn': f'AS{asn_num}',
                            'name': asn_name,
                            'description': asn_desc,
                            'prefix': prefix,
                        }
                        asn_data[ip] = asn_entry

                        log_found("asn", f"{ip} → AS{asn_num} ({asn_name}) — {prefix}")
                        count += 1

                        # Save CIDR for potential scanning
                        results.add_interesting({
                            'type': 'asn_cidr',
                            'severity': 'info',
                            'detail': f'IP {ip} belongs to AS{asn_num} ({asn_name}), prefix {prefix}',
                            'data': asn_entry,
                        })
            except (json.JSONDecodeError, TypeError, KeyError):
                pass

        # ── 2. Get all prefixes for the ASN ──
        if ip in asn_data:
            asn_num = asn_data[ip].get('asn', '').replace('AS', '')
            if asn_num:
                stdout = runner.run_tool('curl', [
                    '-s', '-m', '15',
                    f'https://api.bgpview.io/asn/{asn_num}/prefixes'
                ], timeout=30, retries=1)

                if stdout:
                    try:
                        data = json.loads(stdout)
                        prefixes = []
                        for p in data.get('data', {}).get('ipv4_prefixes', []):
                            prefix = p.get('prefix', '')
                            if prefix:
                                prefixes.append(prefix)

                        if prefixes:
                            out_file = os.path.join(config.dirs['raw'], f'asn_{asn_num}_cidrs.txt')
                            write_lines(out_file, prefixes)
                            log_info(f"AS{asn_num} owns {len(prefixes)} IPv4 CIDR ranges")
                            count += len(prefixes)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Get peers and upstreams
                stdout = runner.run_tool('curl', [
                    '-s', '-m', '15',
                    f'https://api.bgpview.io/asn/{asn_num}/peers'
                ], timeout=30, retries=1)

                if stdout:
                    try:
                        data = json.loads(stdout)
                        peers = data.get('data', {}).get('ipv4_peers', [])
                        if peers:
                            peer_list = [f"AS{p.get('asn', '')} - {p.get('name', '')}" for p in peers[:20]]
                            out_file = os.path.join(config.dirs['raw'], f'asn_{asn_num}_peers.txt')
                            write_lines(out_file, peer_list)
                            log_info(f"AS{asn_num} has {len(peers)} peers")
                    except (json.JSONDecodeError, TypeError):
                        pass

        # ── 3. Reverse IP — find other domains on same IP ──
        stdout = runner.run_tool('curl', [
            '-s', '-m', '15',
            f'https://api.hackertarget.com/reverseiplookup/?q={ip}'
        ], timeout=30, retries=1)

        if stdout and 'error' not in stdout.lower() and 'API count' not in stdout:
            related_domains = [d.strip() for d in stdout.split('\n') if d.strip() and d.strip() != ip]
            if related_domains:
                # Check if any belong to target
                in_scope = [d for d in related_domains if scope.is_in_scope(d)]
                if in_scope:
                    results.add_subdomains(in_scope)
                    log_info(f"Reverse IP found {len(in_scope)} in-scope domains on {ip}")

                out_file = os.path.join(config.dirs['raw'], f'reverse_ip_{ip.replace(".", "_")}.txt')
                write_lines(out_file, related_domains[:500])
                log_info(f"Reverse IP: {len(related_domains)} domains on {ip}")

    # ── 4. WHOIS for netblock info ──
    for ip in list(target_ips)[:3]:
        stdout = runner.run_tool('whois', [ip], timeout=30, retries=1)
        if stdout:
            # Extract CIDR, NetRange, OrgName
            for line in stdout.split('\n'):
                lower = line.lower().strip()
                if any(k in lower for k in ['cidr:', 'netrange:', 'orgname:', 'org-name:', 'netname:']):
                    log_found("asn", line.strip())
                    count += 1

            out_file = os.path.join(config.dirs['raw'], f'whois_ip_{ip.replace(".", "_")}.txt')
            with open(out_file, 'w') as f:
                f.write(stdout)

    # Save consolidated ASN data
    if asn_data:
        out_file = os.path.join(config.dirs['raw'], 'asn_data.json')
        with open(out_file, 'w') as f:
            json.dump(asn_data, f, indent=2)

    log_module_end("ASN / CIDR Lookup", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  GITHUB DORKING
# ═══════════════════════════════════════════════════════════════════════════════

def github_dorking(config, runner, scope, results):
    """Search GitHub for leaked credentials, configs, and code mentioning target."""
    log_module_start("GitHub Dorking")
    domain = config.target_domain
    count = 0

    # GitHub search API (unauthenticated — rate limited but works)
    # Each query returns up to 30 results
    dork_queries = [
        # Credentials & secrets
        (f'"{domain}" password',              'Password leak'),
        (f'"{domain}" secret',                'Secret leak'),
        (f'"{domain}" api_key',               'API key leak'),
        (f'"{domain}" apikey',                'API key leak'),
        (f'"{domain}" token',                 'Token leak'),
        (f'"{domain}" access_key',            'Access key leak'),
        (f'"{domain}" private_key',           'Private key leak'),
        # Config files
        (f'"{domain}" filename:.env',         'Environment file'),
        (f'"{domain}" filename:.yml',         'YAML config'),
        (f'"{domain}" filename:.json password','JSON with password'),
        (f'"{domain}" filename:.properties',  'Properties file'),
        (f'"{domain}" filename:.xml password', 'XML config'),
        (f'"{domain}" filename:wp-config',    'WordPress config'),
        (f'"{domain}" filename:.htpasswd',    'htpasswd file'),
        (f'"{domain}" filename:id_rsa',       'SSH private key'),
        (f'"{domain}" filename:.npmrc',       'NPM config'),
        (f'"{domain}" filename:.dockercfg',   'Docker config'),
        # Database
        (f'"{domain}" filename:.sql',         'SQL dump'),
        (f'"{domain}" jdbc:',                 'JDBC connection string'),
        (f'"{domain}" mongodb+srv:',          'MongoDB URI'),
        # Infrastructure
        (f'"{domain}" filename:Dockerfile',   'Dockerfile'),
        (f'"{domain}" filename:docker-compose','Docker Compose'),
        (f'"{domain}" filename:.travis.yml',  'CI/CD config'),
        (f'"{domain}" filename:Jenkinsfile',  'Jenkins pipeline'),
        # AWS
        (f'"{domain}" AKIA',                  'AWS access key'),
        (f'"{domain}" s3.amazonaws.com',      'S3 bucket reference'),
        # Internal
        (f'"{domain}" internal',              'Internal reference'),
        (f'"{domain}" staging',               'Staging reference'),
        (f'"{domain}" admin',                 'Admin reference'),
    ]

    all_findings = []

    # GitHub code search (unauthenticated, limited to 10 requests/min)
    for i, (query, category) in enumerate(dork_queries):
        if config.quick and i >= 10:
            break

        # Rate limit: GitHub allows ~10 searches/min unauthenticated
        if i > 0 and i % 8 == 0:
            log_info("Rate limiting GitHub searches (waiting 60s)...")
            time.sleep(60)

        encoded_query = query.replace(' ', '+').replace('"', '%22').replace(':', '%3A').replace('=', '%3D')
        stdout = runner.run_tool('curl', [
            '-s', '-m', '15',
            '-H', 'Accept: application/vnd.github.v3+json',
            '-H', 'User-Agent: POT-Security-Scanner',
            f'https://api.github.com/search/code?q={encoded_query}&per_page=10'
        ], timeout=30, retries=1)

        if not stdout:
            continue

        try:
            data = json.loads(stdout)
            total_count = data.get('total_count', 0)

            if total_count > 0:
                log_found("github", f"[{category}] {total_count} results for: {query[:60]}")

                for item in data.get('items', [])[:5]:
                    repo = item.get('repository', {}).get('full_name', '')
                    path = item.get('path', '')
                    html_url = item.get('html_url', '')

                    finding = {
                        'query': query,
                        'category': category,
                        'repo': repo,
                        'file': path,
                        'url': html_url,
                        'total_results': total_count,
                    }
                    all_findings.append(finding)
                    count += 1

                    results.add_interesting({
                        'type': 'github_dork',
                        'severity': 'medium',
                        'detail': f'GitHub: [{category}] {repo}/{path}',
                        'url': html_url,
                    })

                    # Flag high-severity findings
                    if any(kw in category.lower() for kw in ['password', 'private key', 'aws', 'secret']):
                        results.add_vuln({
                            'type': 'github_leak',
                            'severity': 'high',
                            'title': f'GitHub Leak: {category} in {repo}',
                            'detail': f'{html_url}',
                            'url': html_url,
                        })

        except (json.JSONDecodeError, TypeError):
            # Rate limited or error
            if '"message"' in (stdout or '') and 'rate limit' in (stdout or '').lower():
                log_warning("GitHub API rate limit hit — waiting 60s")
                time.sleep(60)
            continue

    # Save all findings
    if all_findings:
        out_file = os.path.join(config.dirs['raw'], 'github_dorks.json')
        with open(out_file, 'w') as f:
            json.dump(all_findings, f, indent=2)

        # Summary by category
        categories = {}
        for f_item in all_findings:
            cat = f_item['category']
            categories[cat] = categories.get(cat, 0) + 1
        for cat, c in sorted(categories.items(), key=lambda x: -x[1]):
            log_info(f"  {cat}: {c} results")

    log_module_end("GitHub Dorking", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  GOOGLE DORKING
# ═══════════════════════════════════════════════════════════════════════════════

def google_dorking(config, runner, scope, results):
    """Automated Google dork queries for target recon."""
    log_module_start("Google Dorking")
    domain = config.target_domain
    count = 0

    dorks = [
        (f'site:{domain} filetype:pdf', 'PDF documents'),
        (f'site:{domain} filetype:doc OR filetype:docx', 'Word documents'),
        (f'site:{domain} filetype:xls OR filetype:xlsx', 'Spreadsheets'),
        (f'site:{domain} filetype:sql', 'SQL files'),
        (f'site:{domain} filetype:log', 'Log files'),
        (f'site:{domain} filetype:bak OR filetype:old', 'Backup files'),
        (f'site:{domain} filetype:conf OR filetype:cfg', 'Config files'),
        (f'site:{domain} filetype:env', 'Environment files'),
        (f'site:{domain} inurl:admin', 'Admin panels'),
        (f'site:{domain} inurl:login', 'Login pages'),
        (f'site:{domain} inurl:dashboard', 'Dashboards'),
        (f'site:{domain} inurl:api', 'API endpoints'),
        (f'site:{domain} inurl:config', 'Config pages'),
        (f'site:{domain} inurl:setup', 'Setup pages'),
        (f'site:{domain} inurl:debug', 'Debug pages'),
        (f'site:{domain} inurl:staging', 'Staging environments'),
        (f'site:{domain} intitle:"index of"', 'Directory listings'),
        (f'site:{domain} intext:"sql syntax"', 'SQL errors'),
        (f'site:{domain} intext:"fatal error"', 'PHP errors'),
        (f'site:{domain} intext:"stack trace"', 'Stack traces'),
        (f'site:{domain} inurl:wp-content', 'WordPress content'),
        (f'site:{domain} inurl:wp-admin', 'WordPress admin'),
        (f'site:{domain} inurl:xmlrpc.php', 'WordPress XMLRPC'),
        (f'site:{domain} inurl:phpinfo', 'PHP info pages'),
        (f'site:{domain} inurl:upload', 'Upload endpoints'),
        (f'site:{domain} "not for distribution"', 'Confidential docs'),
        (f'site:{domain} "internal use only"', 'Internal docs'),
    ]

    all_findings = []

    for i, (query, category) in enumerate(dorks):
        if config.quick and i >= 12:
            break

        # Rate limit Google
        if i > 0:
            time.sleep(random.uniform(5, 10))

        encoded = query.replace(' ', '+').replace('"', '%22').replace(':', '%3A')
        url = f'https://www.google.com/search?q={encoded}&num=20'

        stdout = runner.run_tool('curl', [
            '-s', '-m', '15', '-L',
            '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '-H', 'Accept-Language: en-US,en;q=0.9',
            url
        ], timeout=20, retries=1)

        if not stdout:
            continue

        # Extract URLs from Google results
        found_urls = re.findall(r'href="/url\?q=([^&"]+)', stdout)
        found_urls += re.findall(r'(?:href|cite)="(https?://[^"]*' + re.escape(domain) + r'[^"]*)', stdout)

        unique_urls = set()
        for u in found_urls:
            u = u.split('&')[0]
            if domain in u and 'google.com' not in u:
                unique_urls.add(u)

        if unique_urls:
            log_found("google", f"[{category}] {len(unique_urls)} results")
            for u in unique_urls:
                all_findings.append({'query': query, 'category': category, 'url': u})
                results.add_urls([u])
                count += 1

        # Detect CAPTCHA
        if 'unusual traffic' in stdout.lower() or 'captcha' in stdout.lower():
            log_warning("Google CAPTCHA detected — stopping dorking")
            break

    if all_findings:
        out_file = os.path.join(config.dirs['raw'], 'google_dorks.json')
        with open(out_file, 'w') as f:
            json.dump(all_findings, f, indent=2)

    log_module_end("Google Dorking", count)




# ═══════════════════════════════════════════════════════════════════════════════
#  SHODAN API INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

def shodan_lookup(config, runner, scope, results):
    """Passive reconnaissance via Shodan API."""
    log_module_start("Shodan API Lookup")
    count = 0
    api_key = os.environ.get("SHODAN_API_KEY")
    
    if not api_key:
        log_warning("SHODAN_API_KEY not found in environment — skipping Shodan lookup")
        log_module_end("Shodan API Lookup", 0)
        return

    domain = config.target_domain
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
    
    stdout = runner.run_tool('curl', [
        '-s', '-m', '20', url
    ], timeout=30, retries=2)
    
    if not stdout:
        log_module_end("Shodan API Lookup", 0)
        return

    try:
        data = json.loads(stdout)
        matches = data.get('matches', [])
        
        all_findings = []
        for match in matches:
            ip = match.get('ip_str', '')
            port = match.get('port', 0)
            hostnames = match.get('hostnames', [])
            org = match.get('org', '')
            vulns = match.get('vulns', {})  # CVEs
            
            if ip:
                results.add_live_hosts([ip])
                results.add_ports(ip, {str(port): "shodan"})
                
                # Log critical CVEs immediately
                if vulns:
                    log_warning(f"Shodan found CVEs on {ip}:{port} -> {', '.join(vulns.keys())}")
                    for cve in vulns.keys():
                        results.add_vuln({
                            'type': 'shodan_cve',
                            'severity': 'high',
                            'title': f'Shodan: {cve}',
                            'detail': f'{ip}:{port} ({org})',
                            'url': f'http://{ip}:{port}'
                        })
                
                all_findings.append({
                    'ip': ip,
                    'port': port,
                    'hostnames': hostnames,
                    'org': org,
                    'vulns': list(vulns.keys()) if isinstance(vulns, dict) else vulns
                })
                count += 1
                
        if all_findings:
            out_file = os.path.join(config.dirs['raw'], 'shodan_data.json')
            with open(out_file, 'w') as f:
                json.dump(all_findings, f, indent=2)
                
    except json.JSONDecodeError:
        log_error("Invalid JSON response from Shodan")

    log_module_end("Shodan API Lookup", count)
