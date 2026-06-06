#!/usr/bin/env python3
"""
POT - Professional Offensive Tool
Vulnerability Scanning Module
Nuclei, SSL/TLS checks, security headers, CORS, subdomain takeover,
open redirect, CRLF injection, host header injection.
"""

import os
import re
import json
import socket

from potlib.ui import (
    log_info, log_warning, log_error, log_debug,
    log_found, log_vuln, log_module_start, log_module_end, log_phase,
    Colors
)
from potlib.engine import (
    parse_lines, write_lines, read_file_lines,
    safe_filename, extract_domain_from_url
)


def run_all(config, runner, scope, results):
    """Execute all vulnerability scanning modules."""
    log_phase("PHASE 3 — VULNERABILITY ASSESSMENT")

    if config.passive_only:
        log_info("Passive-only mode — skipping vulnerability assessment")
        return

    modules = [
        ('nuclei',          nuclei_scan),
        ('ssl',             ssl_check),
        ('headers',         header_analysis),
        ('cors',            cors_check),
        ('takeover',        subdomain_takeover),
        ('open_redirect',   open_redirect_check),
        ('crlf',            crlf_check),
        ('host_header',     host_header_injection),
        ('misconfig',       misconfiguration_check),
        ('graphql',         graphql_introspection),
        ('cms',             cms_scanner),
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
    vuln_count = len(results.get_vulns())
    log_info(f"Vulnerability assessment complete — {vuln_count} findings")


# ═══════════════════════════════════════════════════════════════════════════════
#  NUCLEI SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

def nuclei_scan(config, runner, scope, results):
    log_module_start("Nuclei Vulnerability Scanner")

    if not runner.is_available('nuclei'):
        log_warning("nuclei not installed — skipping vulnerability scan")
        log_module_end("Nuclei Vulnerability Scanner", 0)
        return

    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    targets_file = os.path.join(config.dirs['vulns'], 'nuclei_targets.txt')
    write_lines(targets_file, sorted(live_hosts))
    count = 0

    # Nuclei scan phases
    scan_configs = [
        {
            'name': 'Critical & High Severity',
            'args': ['-severity', 'critical,high', '-c', str(min(config.threads, 25))],
            'timeout': 900,
        },
        {
            'name': 'Medium & Low Severity',
            'args': ['-severity', 'medium,low', '-c', str(min(config.threads, 15))],
            'timeout': 600,
            'skip_quick': True,
        },
        {
            'name': 'Exposure Templates',
            'args': ['-tags', 'exposure,config,token,cve', '-c', str(min(config.threads, 15))],
            'timeout': 600,
            'skip_quick': True,
        },
    ]

    for scan in scan_configs:
        if config.quick and scan.get('skip_quick'):
            continue

        log_info(f"Nuclei scan: {scan['name']}...")
        out_file = os.path.join(
            config.dirs['vulns'],
            f'nuclei_{safe_filename(scan["name"])}.json'
        )

        nuclei_args = [
            '-l', targets_file,
            '-json', '-o', out_file,
            '-timeout', '15',
            '-retries', '2',
            '-rate-limit', str(min(config.rate_limit, 150)),
            '-bulk-size', '25',
            '-concurrency', '10',
            '-silent',
            '-no-color',
        ] + scan['args']

        # Add custom templates if specified
        if config.nuclei_templates:
            nuclei_args.extend(['-t', config.nuclei_templates])

        stdout, stderr, rc = runner.run(
            ['nuclei'] + nuclei_args,
            timeout=scan.get('timeout', 600),
            retries=2
        )

        # Parse results
        if os.path.exists(out_file):
            for line in read_file_lines(out_file):
                try:
                    finding = json.loads(line)
                    template_id = finding.get('template-id', finding.get('templateID', ''))
                    info = finding.get('info', {})
                    severity = info.get('severity', 'info')
                    name = info.get('name', template_id)
                    matched_url = finding.get('matched-at', finding.get('matched', ''))
                    description = info.get('description', '')

                    vuln_entry = {
                        'type': 'nuclei',
                        'severity': severity,
                        'title': name,
                        'template': template_id,
                        'url': matched_url,
                        'description': description[:300],
                        'reference': info.get('reference', []),
                    }

                    results.add_vuln(vuln_entry)
                    log_vuln(severity, name, matched_url)
                    count += 1

                except json.JSONDecodeError:
                    continue

    log_module_end("Nuclei Vulnerability Scanner", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  SSL/TLS CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def ssl_check(config, runner, scope, results):
    log_module_start("SSL/TLS Analysis")
    domain = config.target_domain
    count = 0

    # ── 1. sslscan ──
    if runner.is_available('sslscan'):
        log_info("Running sslscan...")
        stdout = runner.run_tool('sslscan', [
            '--no-colour', domain
        ], timeout=120)

        if stdout:
            out_file = os.path.join(config.dirs['vulns'], 'sslscan.txt')
            with open(out_file, 'w') as f:
                f.write(stdout)

            # Check for weak configurations
            issues = _analyze_ssl_output(stdout)
            for issue in issues:
                results.add_vuln(issue)
                log_vuln(issue['severity'], issue['title'], issue.get('detail', ''))
                count += 1

    # ── 2. testssl.sh ──
    if runner.is_available('testssl') and not config.quick:
        log_info("Running testssl.sh...")
        json_out = os.path.join(config.dirs['vulns'], 'testssl.json')

        stdout = runner.run_tool('testssl', [
            '--jsonfile', json_out,
            '--quiet',
            '--sneaky',
            '--fast',
            domain
        ], timeout=300)

        if os.path.exists(json_out):
            try:
                with open(json_out) as f:
                    data = json.loads(f.read())
                for finding in data:
                    if isinstance(finding, dict):
                        severity_map = {
                            'CRITICAL': 'critical',
                            'HIGH': 'high',
                            'MEDIUM': 'medium',
                            'LOW': 'low',
                            'WARN': 'low',
                            'INFO': 'info',
                            'OK': None,
                        }
                        sev = finding.get('severity', 'INFO')
                        mapped_sev = severity_map.get(sev)
                        if mapped_sev and mapped_sev != 'info':
                            vuln = {
                                'type': 'ssl',
                                'severity': mapped_sev,
                                'title': f"SSL: {finding.get('id', '')}",
                                'detail': finding.get('finding', ''),
                                'url': domain,
                            }
                            results.add_vuln(vuln)
                            log_vuln(mapped_sev, vuln['title'], vuln['detail'][:100])
                            count += 1
            except (json.JSONDecodeError, KeyError):
                pass

    # ── 3. OpenSSL check (always available) ──
    if runner.is_available('openssl'):
        log_info("Checking certificate with openssl...")
        stdout, _, _ = runner.run(
            ['bash', '-c',
             f'echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -dates -subject -issuer'],
            timeout=30
        )
        if stdout:
            out_file = os.path.join(config.dirs['vulns'], 'cert_info.txt')
            with open(out_file, 'w') as f:
                f.write(stdout)

            # Check expiry
            for line in stdout.split('\n'):
                if 'notAfter=' in line:
                    log_found("ssl", f"Certificate expiry: {line.split('=', 1)[1]}")
                elif 'subject=' in line:
                    log_found("ssl", f"Subject: {line.split('=', 1)[1]}")

    log_module_end("SSL/TLS Analysis", count)


def _analyze_ssl_output(output):
    """Analyze sslscan output for security issues."""
    issues = []
    output_lower = output.lower()

    checks = [
        ('SSLv2', 'critical', 'SSLv2 Protocol Enabled', 'SSLv2 is obsolete and insecure'),
        ('SSLv3', 'high', 'SSLv3 Protocol Enabled', 'SSLv3 is vulnerable to POODLE attack'),
        ('TLSv1.0', 'medium', 'TLSv1.0 Protocol Enabled', 'TLSv1.0 is deprecated'),
        ('TLSv1.1', 'low', 'TLSv1.1 Protocol Enabled', 'TLSv1.1 is deprecated'),
        ('RC4', 'high', 'RC4 Cipher Supported', 'RC4 is a weak cipher'),
        ('DES-CBC', 'high', 'DES Cipher Supported', 'DES is a weak cipher'),
        ('NULL', 'critical', 'NULL Cipher Supported', 'NULL cipher provides no encryption'),
        ('EXPORT', 'critical', 'EXPORT Cipher Supported', 'EXPORT ciphers are extremely weak'),
    ]

    for keyword, severity, title, detail in checks:
        # Look for enabled/accepted status near the keyword
        if keyword.lower() in output_lower:
            # More nuanced check - look for "Accepted" or "Enabled" near keyword
            for line in output.split('\n'):
                if keyword in line and ('Accepted' in line or 'Enabled' in line):
                    issues.append({
                        'type': 'ssl',
                        'severity': severity,
                        'title': title,
                        'detail': detail,
                    })
                    break

    # Check for self-signed cert
    if 'self-signed' in output_lower or 'self signed' in output_lower:
        issues.append({
            'type': 'ssl',
            'severity': 'medium',
            'title': 'Self-Signed Certificate',
            'detail': 'Certificate is self-signed, not trusted by browsers',
        })

    # Check for expired cert
    if 'expired' in output_lower:
        issues.append({
            'type': 'ssl',
            'severity': 'high',
            'title': 'Expired SSL Certificate',
            'detail': 'SSL certificate has expired',
        })

    # Check for heartbleed
    if 'heartbleed' in output_lower and 'vulnerable' in output_lower:
        issues.append({
            'type': 'ssl',
            'severity': 'critical',
            'title': 'Heartbleed Vulnerability (CVE-2014-0160)',
            'detail': 'Server is vulnerable to Heartbleed attack',
        })

    return issues


# ═══════════════════════════════════════════════════════════════════════════════
#  SECURITY HEADER ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def header_analysis(config, runner, scope, results):
    log_module_start("Security Header Analysis")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    check_targets = sorted(live_hosts)[:20]

    required_headers = {
        'strict-transport-security': ('medium', 'Missing HSTS Header',
            'HTTP Strict Transport Security header is not set'),
        'x-frame-options': ('medium', 'Missing X-Frame-Options',
            'Page is potentially vulnerable to clickjacking'),
        'x-content-type-options': ('low', 'Missing X-Content-Type-Options',
            'Browser MIME type sniffing not prevented'),
        'content-security-policy': ('medium', 'Missing Content-Security-Policy',
            'No CSP header, potential XSS risk'),
        'x-xss-protection': ('info', 'Missing X-XSS-Protection',
            'XSS protection header not set (legacy browsers)'),
        'referrer-policy': ('info', 'Missing Referrer-Policy',
            'No referrer policy set'),
        'permissions-policy': ('info', 'Missing Permissions-Policy',
            'No permissions policy set for browser features'),
    }

    dangerous_headers = {
        'server': ('info', 'Server Version Disclosed'),
        'x-powered-by': ('low', 'Technology Stack Disclosed via X-Powered-By'),
        'x-aspnet-version': ('low', 'ASP.NET Version Disclosed'),
        'x-aspnetmvc-version': ('low', 'ASP.NET MVC Version Disclosed'),
    }

    for target_url in check_targets:
        stdout = runner.run_tool('curl', [
            '-s', '-I', '-L',
            '-m', '10',
            '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            target_url
        ], timeout=15, retries=2)

        if not stdout:
            continue

        headers = {}
        for line in stdout.split('\n'):
            if ':' in line and not line.startswith('HTTP/'):
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        host = extract_domain_from_url(target_url)

        # Check missing security headers
        for header, (severity, title, detail) in required_headers.items():
            if header not in headers:
                vuln = {
                    'type': 'header',
                    'severity': severity,
                    'title': f"{title} on {host}",
                    'detail': detail,
                    'url': target_url,
                    'header': header,
                }
                results.add_vuln(vuln)
                log_vuln(severity, title, target_url)
                count += 1

        # Check dangerous headers
        for header, (severity, title) in dangerous_headers.items():
            if header in headers:
                vuln = {
                    'type': 'header',
                    'severity': severity,
                    'title': f"{title}: {headers[header]}",
                    'url': target_url,
                    'header': header,
                    'value': headers[header],
                }
                results.add_vuln(vuln)
                log_vuln(severity, title, f"{target_url} → {headers[header]}")
                count += 1

        # Check for insecure CSP
        csp = headers.get('content-security-policy', '')
        if csp:
            csp_issues = _analyze_csp(csp)
            for issue in csp_issues:
                issue['url'] = target_url
                results.add_vuln(issue)
                log_vuln(issue['severity'], issue['title'], target_url)
                count += 1

        # Check for cookie security
        set_cookies = [v for k, v in headers.items() if k == 'set-cookie']
        for cookie_header in stdout.split('\n'):
            if cookie_header.lower().startswith('set-cookie:'):
                cookie_val = cookie_header.split(':', 1)[1]
                cookie_issues = _analyze_cookie(cookie_val, target_url)
                for issue in cookie_issues:
                    results.add_vuln(issue)
                    count += 1

    log_module_end("Security Header Analysis", count)


def _analyze_csp(csp):
    """Analyze Content-Security-Policy for weaknesses."""
    issues = []
    csp_lower = csp.lower()

    if "'unsafe-inline'" in csp_lower:
        issues.append({
            'type': 'csp',
            'severity': 'medium',
            'title': 'CSP allows unsafe-inline',
            'detail': "Content-Security-Policy contains 'unsafe-inline', weakening XSS protection",
        })
    if "'unsafe-eval'" in csp_lower:
        issues.append({
            'type': 'csp',
            'severity': 'medium',
            'title': 'CSP allows unsafe-eval',
            'detail': "Content-Security-Policy contains 'unsafe-eval', allowing dynamic code execution",
        })
    if 'data:' in csp_lower:
        issues.append({
            'type': 'csp',
            'severity': 'low',
            'title': 'CSP allows data: URIs',
            'detail': 'Content-Security-Policy allows data: URIs which can be used for XSS',
        })
    if '*' in csp and 'default-src' not in csp_lower:
        issues.append({
            'type': 'csp',
            'severity': 'medium',
            'title': 'CSP uses wildcard without default-src',
            'detail': 'Overly permissive CSP with wildcard sources',
        })

    return issues


def _analyze_cookie(cookie_str, url):
    """Analyze Set-Cookie header for security issues."""
    issues = []
    cookie_lower = cookie_str.lower()

    # Only check session-like cookies
    session_indicators = ['session', 'token', 'auth', 'sid', 'jwt', 'login']
    is_session = any(ind in cookie_lower for ind in session_indicators)

    if not is_session:
        return issues

    if 'httponly' not in cookie_lower:
        issues.append({
            'type': 'cookie',
            'severity': 'medium',
            'title': 'Session cookie missing HttpOnly flag',
            'detail': 'Cookie accessible via JavaScript, XSS can steal sessions',
            'url': url,
        })

    if 'secure' not in cookie_lower:
        issues.append({
            'type': 'cookie',
            'severity': 'medium',
            'title': 'Session cookie missing Secure flag',
            'detail': 'Cookie transmitted over HTTP, vulnerable to MitM',
            'url': url,
        })

    if 'samesite' not in cookie_lower:
        issues.append({
            'type': 'cookie',
            'severity': 'low',
            'title': 'Session cookie missing SameSite attribute',
            'detail': 'Cookie may be sent with cross-site requests (CSRF risk)',
            'url': url,
        })

    return issues


# ═══════════════════════════════════════════════════════════════════════════════
#  CORS MISCONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

def cors_check(config, runner, scope, results):
    log_module_start("CORS Misconfiguration Check")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    check_targets = sorted(live_hosts)[:20]

    evil_origins = [
        'https://evil.com',
        'https://attacker.com',
        'null',
    ]

    for target_url in check_targets:
        domain = extract_domain_from_url(target_url)

        for origin in evil_origins:
            stdout = runner.run_tool('curl', [
                '-s', '-I',
                '-H', f'Origin: {origin}',
                '-m', '10',
                '-A', 'Mozilla/5.0',
                target_url
            ], timeout=15, retries=1)

            if not stdout:
                continue

            headers = {}
            for line in stdout.split('\n'):
                if ':' in line and not line.startswith('HTTP/'):
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            acao = headers.get('access-control-allow-origin', '')
            acac = headers.get('access-control-allow-credentials', '')

            if acao:
                vuln_detail = None

                if acao == '*' and acac.lower() == 'true':
                    vuln_detail = {
                        'severity': 'high',
                        'title': f'CORS: Wildcard origin with credentials on {domain}',
                        'detail': f'ACAO: * with credentials=true. Origin: {origin}',
                    }
                elif acao == origin and origin != 'null':
                    sev = 'high' if acac.lower() == 'true' else 'medium'
                    vuln_detail = {
                        'severity': sev,
                        'title': f'CORS: Reflected arbitrary origin on {domain}',
                        'detail': f'Origin {origin} is reflected in ACAO. Credentials: {acac}',
                    }
                elif acao == 'null':
                    sev = 'high' if acac.lower() == 'true' else 'medium'
                    vuln_detail = {
                        'severity': sev,
                        'title': f'CORS: Null origin allowed on {domain}',
                        'detail': f'null origin accepted. Credentials: {acac}',
                    }

                if vuln_detail:
                    vuln_detail['type'] = 'cors'
                    vuln_detail['url'] = target_url
                    results.add_vuln(vuln_detail)
                    log_vuln(vuln_detail['severity'], vuln_detail['title'],
                            target_url)
                    count += 1
                    break  # One finding per host is enough

        # Check if origin reflection is based on subdomain
        subdomain_origin = f'https://evil.{domain}'
        stdout = runner.run_tool('curl', [
            '-s', '-I',
            '-H', f'Origin: {subdomain_origin}',
            '-m', '10',
            target_url
        ], timeout=15, retries=1)

        if stdout:
            for line in stdout.split('\n'):
                if 'access-control-allow-origin' in line.lower():
                    if subdomain_origin in line:
                        results.add_vuln({
                            'type': 'cors',
                            'severity': 'medium',
                            'title': f'CORS: Subdomain prefix accepted on {domain}',
                            'detail': f'evil.{domain} accepted as origin',
                            'url': target_url,
                        })
                        log_vuln('medium', f'CORS: Subdomain prefix accepted',
                                target_url)
                        count += 1

    log_module_end("CORS Misconfiguration Check", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  SUBDOMAIN TAKEOVER
# ═══════════════════════════════════════════════════════════════════════════════

def subdomain_takeover(config, runner, scope, results):
    log_module_start("Subdomain Takeover Check")
    subdomains = results.get_subdomains()
    live_subs = results.get_live_subdomains()
    count = 0

    # Find dangling subdomains (DNS resolves but not in live hosts)
    dangling = subdomains - live_subs if live_subs else set()

    # Known CNAME fingerprints for takeover
    takeover_fingerprints = {
        'github.io': "There isn't a GitHub Pages site here",
        'herokuapp.com': 'No such app',
        'pantheon.io': 'The gods are wise',
        'zendesk.com': 'Help Center Closed',
        'teamwork.com': 'Oops - We didn\'t find your site',
        'helpjuice.com': "We could not find what you're looking for",
        'helpscoutdocs.com': 'No settings were found',
        'ghost.io': 'The thing you were looking for is no longer here',
        's3.amazonaws.com': 'NoSuchBucket',
        'cloudfront.net': 'Bad Request',
        'azure': 'NXDOMAIN',
        'cloudapp.net': 'NXDOMAIN',
        'azurewebsites.net': 'NXDOMAIN',
        'shopify.com': 'Sorry, this shop is currently unavailable',
        'tumblr.com': "There's nothing here",
        'wordpress.com': 'Do you want to register',
        'feedpress.me': 'The feed has not been found',
        'surge.sh': 'project not found',
        'bitbucket.io': 'Repository not found',
        'uservoice.com': 'This UserVoice subdomain is currently available',
        'readme.io': 'Project doesnt exist',
        'fly.io': 'NXDOMAIN',
        'netlify.app': 'Not Found',
        'ngrok.io': 'Tunnel .* not found',
    }

    # ── 1. subjack (if available) ──
    if runner.is_available('subjack') and subdomains:
        log_info("Running subjack...")
        subs_file = os.path.join(config.dirs['subdomains'], 'all_subdomains.txt')
        write_lines(subs_file, sorted(subdomains))

        out_file = os.path.join(config.dirs['vulns'], 'subjack.txt')
        stdout = runner.run_tool('subjack', [
            '-w', subs_file,
            '-t', str(min(config.threads, 20)),
            '-timeout', '15',
            '-o', out_file,
            '-ssl',
            '-a',
        ], timeout=300)

        if stdout:
            for line in parse_lines(stdout):
                if 'Vulnerable' in line or '[VULNERABLE]' in line:
                    results.add_vuln({
                        'type': 'takeover',
                        'severity': 'high',
                        'title': f'Subdomain Takeover: {line}',
                        'detail': line,
                    })
                    log_vuln('high', 'Subdomain Takeover', line)
                    count += 1

    # ── 2. Manual CNAME check ──
    log_info("Checking CNAME records for takeover...")
    check_subs = sorted(subdomains)[:200]

    def check_takeover(sub):
        findings = []
        stdout = runner.run_tool('dig', ['+short', 'CNAME', sub],
                                 timeout=10, retries=1)
        if not stdout:
            return findings

        cnames = parse_lines(stdout)
        for cname in cnames:
            cname = cname.strip().rstrip('.')
            for service, fingerprint in takeover_fingerprints.items():
                if service in cname.lower():
                    # Verify by checking if the CNAME target is dangling
                    try:
                        socket.getaddrinfo(cname, None)
                    except socket.gaierror:
                        findings.append({
                            'type': 'takeover',
                            'severity': 'high',
                            'title': f'Potential Subdomain Takeover: {sub}',
                            'detail': f'CNAME {cname} points to {service} (unresolvable)',
                            'url': sub,
                            'cname': cname,
                        })
                        break
        return findings

    tasks = [(check_takeover, (sub,)) for sub in check_subs]
    cname_results = runner.run_parallel(tasks, max_workers=min(20, config.threads))

    for result_list in cname_results:
        if result_list:
            for vuln in result_list:
                results.add_vuln(vuln)
                log_vuln('high', vuln['title'], vuln.get('detail', ''))
                count += 1

    log_module_end("Subdomain Takeover Check", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  OPEN REDIRECT CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def open_redirect_check(config, runner, scope, results):
    log_module_start("Open Redirect Check")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    check_targets = sorted(live_hosts)[:10]

    redirect_params = [
        'url', 'redirect', 'redirect_url', 'redirect_uri', 'redir',
        'return', 'return_url', 'returnUrl', 'next', 'next_url',
        'dest', 'destination', 'go', 'goto', 'target', 'link',
        'out', 'view', 'ref', 'callback', 'continue', 'return_to',
        'checkout_url', 'login_url', 'image_url', 'forward',
    ]
    evil_url = 'https://evil.com'

    for target_url in check_targets:
        for param in redirect_params:
            test_url = f"{target_url.rstrip('/')}/?{param}={evil_url}"

            stdout = runner.run_tool('curl', [
                '-s', '-I', '-L',
                '-m', '10',
                '--max-redirs', '5',
                '-o', '/dev/null',
                '-w', '%{url_effective}\\n%{redirect_url}',
                '-A', 'Mozilla/5.0',
                test_url
            ], timeout=15, retries=1)

            if stdout and ('evil.com' in stdout):
                results.add_vuln({
                    'type': 'open_redirect',
                    'severity': 'medium',
                    'title': f'Open Redirect via {param} parameter',
                    'detail': f'{test_url} → evil.com',
                    'url': target_url,
                    'parameter': param,
                })
                log_vuln('medium', f'Open Redirect via ?{param}=', target_url)
                count += 1
                break  # One finding per host

    # Also check URLs from wayback that have redirect params
    wayback_urls = results.get_wayback_urls()
    redirect_urls = [u for u in wayback_urls
                    if any(f'{p}=' in u.lower() for p in redirect_params)]
    if redirect_urls:
        out_file = os.path.join(config.dirs['vulns'], 'potential_redirects.txt')
        write_lines(out_file, sorted(redirect_urls)[:1000])
        log_info(f"Found {len(redirect_urls)} URLs with redirect parameters (saved for manual testing)")

    log_module_end("Open Redirect Check", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  CRLF INJECTION CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def crlf_check(config, runner, scope, results):
    log_module_start("CRLF Injection Check")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    check_targets = sorted(live_hosts)[:10]

    crlf_payloads = [
        '%0d%0aSet-Cookie:crlf=injection',
        '%0d%0aX-Injected:true',
        '%0ASet-Cookie:crlf=injection',
        '\\r\\nSet-Cookie:crlf=injection',
        '%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection',  # Unicode CRLF
    ]

    for target_url in check_targets:
        for payload in crlf_payloads:
            test_url = f"{target_url.rstrip('/')}/{payload}"

            stdout = runner.run_tool('curl', [
                '-s', '-I',
                '-m', '10',
                '-A', 'Mozilla/5.0',
                test_url
            ], timeout=15, retries=1)

            if stdout:
                response_lower = stdout.lower()
                if 'set-cookie:crlf=injection' in response_lower or \
                   'x-injected:true' in response_lower:
                    results.add_vuln({
                        'type': 'crlf',
                        'severity': 'medium',
                        'title': f'CRLF Injection on {extract_domain_from_url(target_url)}',
                        'detail': f'Payload: {payload}',
                        'url': target_url,
                    })
                    log_vuln('medium', 'CRLF Injection', target_url)
                    count += 1
                    break

    log_module_end("CRLF Injection Check", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  HOST HEADER INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

def host_header_injection(config, runner, scope, results):
    log_module_start("Host Header Injection")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    check_targets = sorted(live_hosts)[:10]

    for target_url in check_targets:
        domain = extract_domain_from_url(target_url)

        # Test 1: Evil host header
        stdout = runner.run_tool('curl', [
            '-s', '-I',
            '-H', f'Host: evil.com',
            '-m', '10',
            '-A', 'Mozilla/5.0',
            target_url
        ], timeout=15, retries=1)

        if stdout and 'evil.com' in stdout:
            results.add_vuln({
                'type': 'host_header',
                'severity': 'medium',
                'title': f'Host Header Injection on {domain}',
                'detail': 'Evil Host header reflected in response',
                'url': target_url,
            })
            log_vuln('medium', 'Host Header Injection', target_url)
            count += 1

        # Test 2: X-Forwarded-Host
        stdout = runner.run_tool('curl', [
            '-s', '-I',
            '-H', f'X-Forwarded-Host: evil.com',
            '-m', '10',
            target_url
        ], timeout=15, retries=1)

        if stdout and 'evil.com' in stdout:
            results.add_vuln({
                'type': 'host_header',
                'severity': 'low',
                'title': f'X-Forwarded-Host Injection on {domain}',
                'detail': 'X-Forwarded-Host reflected in response',
                'url': target_url,
            })
            log_vuln('low', 'X-Forwarded-Host Injection', target_url)
            count += 1

    log_module_end("Host Header Injection", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  MISCONFIGURATION CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def misconfiguration_check(config, runner, scope, results):
    log_module_start("Misconfiguration Check")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    check_targets = sorted(live_hosts)[:10]

    # Sensitive files/paths to check
    sensitive_paths = [
        ('/.env', 'Environment file'),
        ('/.git/HEAD', 'Git repository'),
        ('/.git/config', 'Git config'),
        ('/.svn/entries', 'SVN repository'),
        ('/.htaccess', 'Apache htaccess'),
        ('/.htpasswd', 'Apache htpasswd'),
        ('/wp-config.php.bak', 'WordPress config backup'),
        ('/web.config', 'IIS config'),
        ('/robots.txt', 'Robots.txt'),
        ('/sitemap.xml', 'Sitemap'),
        ('/crossdomain.xml', 'Flash crossdomain policy'),
        ('/clientaccesspolicy.xml', 'Silverlight access policy'),
        ('/server-status', 'Apache server-status'),
        ('/server-info', 'Apache server-info'),
        ('/phpinfo.php', 'PHP Info'),
        ('/info.php', 'PHP Info'),
        ('/.DS_Store', 'macOS DS_Store'),
        ('/backup.zip', 'Backup archive'),
        ('/backup.tar.gz', 'Backup archive'),
        ('/dump.sql', 'SQL dump'),
        ('/database.sql', 'SQL dump'),
        ('/swagger-ui.html', 'Swagger UI'),
        ('/swagger.json', 'Swagger JSON'),
        ('/api-docs', 'API documentation'),
        ('/graphql', 'GraphQL endpoint'),
        ('/actuator', 'Spring Actuator'),
        ('/actuator/health', 'Spring Health'),
        ('/actuator/env', 'Spring Environment'),
        ('/elmah.axd', 'ELMAH error log'),
        ('/trace.axd', 'ASP.NET trace'),
        ('/.well-known/security.txt', 'Security.txt'),
        ('/debug/pprof/', 'Go debug profile'),
        ('/console', 'Debug console'),
        ('/_debug_toolbar/', 'Django debug toolbar'),
    ]

    for target_url in check_targets:
        domain = extract_domain_from_url(target_url)

        def check_path(path_info):
            path, desc = path_info
            url = f"{target_url.rstrip('/')}{path}"
            stdout = runner.run_tool('curl', [
                '-s', '-o', '/dev/null',
                '-w', '%{http_code}:%{size_download}',
                '-m', '8',
                '-A', 'Mozilla/5.0',
                url
            ], timeout=10, retries=1)

            if stdout:
                parts = stdout.strip().split(':')
                if len(parts) == 2:
                    status = parts[0]
                    size = int(parts[1]) if parts[1].isdigit() else 0
                    if status in ('200', '403') and size > 0:
                        severity = 'medium' if status == '200' else 'low'
                        # Special cases
                        if '.git' in path or '.env' in path or 'phpinfo' in path:
                            severity = 'high'
                        if 'actuator/env' in path or 'dump.sql' in path:
                            severity = 'critical'

                        return {
                            'type': 'misconfig',
                            'severity': severity,
                            'title': f'{desc} exposed ({status})',
                            'detail': f'{url} [{status}] [{size}B]',
                            'url': url,
                            'status': status,
                        }
            return None

        tasks = [(check_path, (pi,)) for pi in sensitive_paths]
        check_results = runner.run_parallel(tasks, max_workers=min(10, config.threads))

        for result in check_results:
            if result:
                results.add_vuln(result)
                log_vuln(result['severity'], result['title'], result['detail'])
                count += 1

    log_module_end("Misconfiguration Check", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  GRAPHQL INTROSPECTION
# ═══════════════════════════════════════════════════════════════════════════════

def graphql_introspection(config, runner, scope, results):
    """Detect GraphQL endpoints and dump schema via introspection."""
    log_module_start("GraphQL Introspection")
    live_hosts = results.get_live_hosts()
    if not live_hosts:
        live_hosts = {config.target_base}

    count = 0
    graphql_paths = [
        '/graphql', '/graphiql', '/v1/graphql', '/v2/graphql',
        '/api/graphql', '/graphql/console', '/gql',
        '/query', '/graphql/query',
    ]

    introspection_query = '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'  

    for target_url in sorted(live_hosts)[:10]:
        for path in graphql_paths:
            url = f"{target_url.rstrip('/')}{path}"

            # Step 1: Check if endpoint exists
            stdout = runner.run_tool('curl', [
                '-s', '-o', '/dev/null',
                '-w', '%{http_code}',
                '-m', '8',
                '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-d', introspection_query,
                url
            ], timeout=12, retries=1)

            if not stdout or stdout.strip() not in ('200', '400', '405'):
                continue

            # Step 2: Try introspection
            full_query = '{"query":"{__schema{queryType{name},mutationType{name},types{name,kind,fields{name,args{name,type{name}},type{name,kind,ofType{name}}}}}}"}'  
            stdout = runner.run_tool('curl', [
                '-s', '-m', '15',
                '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-d', full_query,
                url
            ], timeout=20, retries=1)

            if not stdout:
                continue

            try:
                data = json.loads(stdout)
                if 'data' in data and '__schema' in (data.get('data') or {}):
                    schema = data['data']['__schema']
                    types = schema.get('types', [])
                    user_types = [t for t in types if not t.get('name', '').startswith('__')]

                    log_vuln('high', f'GraphQL Introspection Enabled at {path}',
                             f'{len(user_types)} types exposed')

                    results.add_vuln({
                        'type': 'graphql',
                        'severity': 'high',
                        'title': f'GraphQL Introspection Enabled',
                        'detail': f'{url} — {len(user_types)} types, '
                                  f'query: {schema.get("queryType", {}).get("name", "N/A")}, '
                                  f'mutation: {schema.get("mutationType", {}).get("name", "N/A")}',
                        'url': url,
                    })
                    count += 1

                    # Save full schema
                    domain = extract_domain_from_url(target_url)
                    safe = safe_filename(domain)
                    out_file = os.path.join(config.dirs['vulns'], f'graphql_schema_{safe}.json')
                    with open(out_file, 'w') as f:
                        json.dump(data, f, indent=2)

                    # Extract interesting types
                    for t in user_types:
                        tname = t.get('name', '')
                        fields = t.get('fields') or []
                        field_names = [ff.get('name', '') for ff in fields]
                        interesting = [fn for fn in field_names if any(
                            kw in fn.lower() for kw in
                            ['password', 'token', 'secret', 'admin', 'email', 'user',
                             'auth', 'credit', 'ssn', 'private', 'key', 'session']
                        )]
                        if interesting:
                            log_found("graphql",
                                f"Type '{tname}' has sensitive fields: {', '.join(interesting)}")
                            results.add_vuln({
                                'type': 'graphql_sensitive',
                                'severity': 'medium',
                                'title': f'GraphQL Sensitive Fields in {tname}',
                                'detail': f"Fields: {', '.join(interesting)}",
                                'url': url,
                            })
                            count += 1

                    break  # Found working GraphQL, skip other paths

                elif 'errors' in data:
                    # GraphQL endpoint exists but introspection may be disabled
                    log_found("graphql", f"GraphQL endpoint at {path} (introspection disabled)")
                    results.add_vuln({
                        'type': 'graphql',
                        'severity': 'info',
                        'title': f'GraphQL Endpoint Found (introspection disabled)',
                        'detail': url,
                        'url': url,
                    })
                    count += 1
                    break

            except (json.JSONDecodeError, TypeError, KeyError):
                continue

    log_module_end("GraphQL Introspection", count)


# ═══════════════════════════════════════════════════════════════════════════════
#  CMS SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def cms_scanner(config, runner, scope, results):
    """Auto-detect CMS and run specialized scanners."""
    log_module_start("CMS Scanner")
    count = 0
    techs = results.get_technologies()

    # Flatten all detected technologies
    all_techs = []
    for host, tech_list in techs.items():
        if isinstance(tech_list, list):
            all_techs.extend(t.lower() if isinstance(t, str) else str(t).lower() for t in tech_list)
        elif isinstance(tech_list, str):
            all_techs.append(tech_list.lower())

    all_techs_str = ' '.join(all_techs)
    target_url = config.target_base

    # ── WordPress Detection + WPScan ──
    is_wordpress = ('wordpress' in all_techs_str or 'wp-' in all_techs_str)
    if not is_wordpress:
        # Double-check via common WP paths
        for wp_path in ['/wp-login.php', '/wp-admin/', '/wp-content/']:
            stdout = runner.run_tool('curl', [
                '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '-m', '8', f"{target_url}{wp_path}"
            ], timeout=10, retries=1)
            if stdout and stdout.strip() in ('200', '301', '302', '403'):
                is_wordpress = True
                break

    if is_wordpress:
        log_info("WordPress detected!")
        if runner.is_available('wpscan'):
            log_info("Running WPScan...")
            out_file = os.path.join(config.dirs['vulns'], 'wpscan_results.json')
            stdout = runner.run_tool('wpscan', [
                '--url', target_url,
                '--enumerate', 'vp,vt,u1-20,dbe',
                '--format', 'json',
                '-o', out_file,
                '--random-user-agent',
                '--throttle', '500',
            ], timeout=600)

            if os.path.exists(out_file):
                try:
                    with open(out_file) as f:
                        wp_data = json.load(f)
                    # Extract vulns
                    for vuln in wp_data.get('vulnerabilities', []):
                        results.add_vuln({
                            'type': 'cms_wordpress',
                            'severity': 'high',
                            'title': f"WPScan: {vuln.get('title', 'WordPress Vulnerability')}",
                            'detail': vuln.get('url', ''),
                            'url': target_url,
                        })
                        count += 1
                    # Users
                    for user in wp_data.get('users', {}):
                        log_found("wpscan", f"WordPress user: {user}")
                        count += 1
                    # Version
                    version = wp_data.get('version', {}).get('number', '')
                    if version:
                        log_found("wpscan", f"WordPress version: {version}")
                        results.add_vuln({
                            'type': 'cms_version',
                            'severity': 'info',
                            'title': f'WordPress {version} detected',
                            'detail': target_url,
                            'url': target_url,
                        })
                        count += 1
                except (json.JSONDecodeError, TypeError):
                    pass
        else:
            # Manual WordPress checks without wpscan
            log_info("WPScan not available — running manual WordPress checks")
            wp_checks = [
                ('/wp-json/wp/v2/users', 'WordPress REST API user enumeration'),
                ('/wp-json/', 'WordPress REST API'),
                ('/xmlrpc.php', 'WordPress XMLRPC'),
                ('/?author=1', 'WordPress author enumeration'),
                ('/readme.html', 'WordPress readme (version disclosure)'),
                ('/wp-content/debug.log', 'WordPress debug log'),
                ('/wp-config.php.bak', 'WordPress config backup'),
                ('/wp-content/uploads/', 'WordPress uploads directory'),
            ]
            for path, desc in wp_checks:
                url = f"{target_url}{path}"
                stdout = runner.run_tool('curl', [
                    '-s', '-o', '/dev/null', '-w', '%{http_code}:%{size_download}',
                    '-m', '8', url
                ], timeout=10, retries=1)
                if stdout:
                    parts = stdout.strip().split(':')
                    if len(parts) == 2:
                        status = parts[0]
                        size = int(parts[1]) if parts[1].isdigit() else 0
                        if status == '200' and size > 0:
                            severity = 'high' if 'debug' in path or 'bak' in path else 'medium'
                            if 'users' in path:
                                severity = 'medium'
                            log_found("cms", f"{desc} [{status}] [{size}B]")
                            results.add_vuln({
                                'type': 'cms_wordpress',
                                'severity': severity,
                                'title': f'{desc}',
                                'detail': f'{url} [{status}] [{size}B]',
                                'url': url,
                            })
                            count += 1

    # ── Joomla Detection ──
    is_joomla = 'joomla' in all_techs_str
    if not is_joomla:
        stdout = runner.run_tool('curl', [
            '-s', '-o', '/dev/null', '-w', '%{http_code}',
            '-m', '8', f"{target_url}/administrator/"
        ], timeout=10, retries=1)
        if stdout and stdout.strip() in ('200', '301', '302'):
            check = runner.run_tool('curl', ['-s', '-m', '8', f"{target_url}/administrator/"], timeout=10, retries=1)
            if check and 'joomla' in check.lower():
                is_joomla = True

    if is_joomla:
        log_info("Joomla detected!")
        joomla_checks = [
            ('/administrator/', 'Joomla admin panel'),
            ('/configuration.php.bak', 'Joomla config backup'),
            ('/configuration.php~', 'Joomla config backup'),
            ('/administrator/manifests/files/joomla.xml', 'Joomla version file'),
            ('/plugins/system/', 'Joomla plugins directory'),
            ('/README.txt', 'Joomla readme'),
        ]
        for path, desc in joomla_checks:
            url = f"{target_url}{path}"
            stdout = runner.run_tool('curl', [
                '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '-m', '8', url
            ], timeout=10, retries=1)
            if stdout and stdout.strip() in ('200',):
                sev = 'high' if 'bak' in path or 'backup' in path else 'medium'
                log_found("cms", f"{desc} found")
                results.add_vuln({
                    'type': 'cms_joomla',
                    'severity': sev,
                    'title': desc,
                    'detail': url,
                    'url': url,
                })
                count += 1

    # ── Drupal Detection ──
    is_drupal = 'drupal' in all_techs_str
    if not is_drupal:
        stdout = runner.run_tool('curl', [
            '-s', '-m', '8', f"{target_url}/misc/drupal.js"
        ], timeout=10, retries=1)
        if stdout and 'drupal' in stdout.lower():
            is_drupal = True

    if is_drupal:
        log_info("Drupal detected!")
        drupal_checks = [
            ('/CHANGELOG.txt', 'Drupal changelog (version)'),
            ('/core/CHANGELOG.txt', 'Drupal 8+ changelog'),
            ('/user/login', 'Drupal login'),
            ('/admin/', 'Drupal admin'),
            ('/core/install.php', 'Drupal installer'),
            ('/update.php', 'Drupal update script'),
        ]
        for path, desc in drupal_checks:
            url = f"{target_url}{path}"
            stdout = runner.run_tool('curl', [
                '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '-m', '8', url
            ], timeout=10, retries=1)
            if stdout and stdout.strip() in ('200',):
                sev = 'medium' if 'install' in path or 'update' in path else 'low'
                log_found("cms", f"{desc} found")
                results.add_vuln({
                    'type': 'cms_drupal',
                    'severity': sev,
                    'title': desc,
                    'detail': url,
                    'url': url,
                })
                count += 1

    if not is_wordpress and not is_joomla and not is_drupal:
        log_info("No CMS detected — skipping CMS-specific checks")

    log_module_end("CMS Scanner", count)
