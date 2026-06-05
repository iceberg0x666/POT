#!/usr/bin/env python3
"""
POT - Professional Offensive Tool
Engine Module - Configuration, subprocess runner, scope manager, result store.
Handles all core logic: retries, timeouts, VPN resilience, resource management.
"""

import os
import sys
import json
import time
import random
import signal
import shutil
import socket
import hashlib
import subprocess
import threading
try:
    import resource as res_mod
except ImportError:
    res_mod = None
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from potlib.ui import (
    log_info, log_warning, log_error, log_debug,
    log_found, print_tool_status
)


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class PotConfig:
    """Central configuration for a POT scan."""

    def __init__(self, target, notargets=None, output_dir=None,
                 threads=50, timeout=600, rate_limit=150,
                 verbose=False, passive_only=False, quick=False,
                 resolvers=None, wordlist=None, nuclei_templates=None,
                 skip_modules=None, proxy=None, headers=None,
                 scope_file=None, max_errors=10):
        self.target = target.rstrip('/')
        self.notargets = [n.rstrip('/') for n in (notargets or [])]
        self.threads = threads
        self.timeout = timeout          # per-tool timeout in seconds
        self.rate_limit = rate_limit    # requests per second
        self.verbose = verbose
        self.passive_only = passive_only
        self.quick = quick              # quick mode = fewer tools, faster
        self.resolvers = resolvers      # custom resolvers file
        self.wordlist = wordlist        # custom wordlist
        self.nuclei_templates = nuclei_templates
        self.skip_modules = skip_modules or []
        self.max_errors = max_errors    # max errors before aborting a module
        self.start_time = datetime.now()

        # Custom headers for authenticated scanning
        self.headers = headers or []  # list of 'Header: Value' strings

        # Scope file
        self.scope_file = scope_file

        # Proxy / Tor support
        # Accepted formats: socks5://127.0.0.1:9050, http://127.0.0.1:8080, tor
        if proxy and proxy.lower() == 'tor':
            self.proxy = 'socks5://127.0.0.1:9050'
            self.proxy_type = 'tor'
        elif proxy:
            self.proxy = proxy
            self.proxy_type = 'socks5' if 'socks' in proxy.lower() else 'http'
        else:
            self.proxy = None
            self.proxy_type = None

        # Derive domain from target
        parsed = urlparse(self.target if '://' in self.target
                          else f'https://{self.target}')
        self.target_domain = parsed.hostname or self.target
        self.target_scheme = parsed.scheme or 'https'
        self.target_base = f"{self.target_scheme}://{self.target_domain}"

        # Setup output directory
        if output_dir:
            self.output_dir = output_dir
        else:
            safe_name = self.target_domain.replace('.', '_').replace(':', '_')
            ts = self.start_time.strftime('%Y%m%d_%H%M%S')
            self.output_dir = os.path.join(os.getcwd(), f'pot_results_{safe_name}_{ts}')

        os.makedirs(self.output_dir, exist_ok=True)

        # Sub-directories
        self.dirs = {}
        for d in ['subdomains', 'dns', 'ports', 'urls', 'screenshots',
                   'js', 'params', 'vulns', 'reports', 'wayback',
                   'dirs', 'tech', 'crawl', 'raw']:
            path = os.path.join(self.output_dir, d)
            os.makedirs(path, exist_ok=True)
            self.dirs[d] = path

    def to_dict(self):
        return {
            'target': self.target,
            'target_domain': self.target_domain,
            'notargets': self.notargets,
            'output_dir': self.output_dir,
            'threads': self.threads,
            'timeout': self.timeout,
            'rate_limit': self.rate_limit,
            'passive_only': self.passive_only,
            'quick': self.quick,
            'proxy': self.proxy,
            'proxy_type': self.proxy_type,
            'start_time': self.start_time.isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  SCOPE MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeManager:
    """Manages target scope - filters out-of-scope domains/URLs."""

    def __init__(self, target_domain, notargets=None):
        self.target_domain = target_domain.lower().strip()
        self.excluded = set()
        for nt in (notargets or []):
            parsed = urlparse(nt if '://' in nt else f'https://{nt}')
            domain = (parsed.hostname or nt).lower().strip()
            self.excluded.add(domain)

    def _extract_domain(self, item):
        """Extract domain from a URL or domain string."""
        item = item.strip().lower()
        if '://' in item:
            parsed = urlparse(item)
            return parsed.hostname or item
        # Could be domain:port
        if ':' in item:
            return item.split(':')[0]
        return item

    def is_in_scope(self, item):
        """Check if an item (URL or domain) is in scope."""
        domain = self._extract_domain(item)
        if not domain:
            return False

        # Must be the target domain or a subdomain of it
        if domain != self.target_domain and not domain.endswith(f'.{self.target_domain}'):
            return False

        # Must not be excluded
        for excl in self.excluded:
            if domain == excl or domain.endswith(f'.{excl}'):
                return False

        return True

    def filter_scope(self, items):
        """Filter a list of items to only in-scope ones."""
        return [i for i in items if self.is_in_scope(i)]

    def filter_scope_set(self, items):
        """Filter and deduplicate."""
        return set(i for i in items if self.is_in_scope(i))

    def load_scope_file(self, scope_file):
        """Load scope rules from file. Prefix with ! to exclude."""
        if not scope_file or not os.path.exists(scope_file):
            return
        try:
            with open(scope_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('!'):
                        self.excluded.add(line[1:].strip().lower())
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMAND RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

class Runner:
    """
    Robust subprocess runner with:
    - Retries with exponential backoff
    - Configurable timeouts
    - VPN-friendly error handling
    - Tool availability checking
    """

    def __init__(self, config):
        self.config = config
        self._tool_cache = {}
        self._lock = threading.Lock()
        # WAF evasion state (set by active.waf_detection)
        self._waf_evasion = False
        self._waf_detected = []
        self._evasion_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15',
        ]
        self._request_count = 0

        # ── Intelligence: adaptive network monitoring ──
        self._net_intel = {
            'total_requests': 0,
            'successful': 0,
            'failed': 0,
            'timeouts': 0,
            'consecutive_fails': 0,    # circuit breaker counter
            'circuit_open': False,      # True = stop sending requests temporarily
            'circuit_open_until': 0,    # timestamp when circuit closes
            'avg_response_ms': 0,       # rolling average response time
            'response_times': [],       # last 20 response times
            'timeout_multiplier': 1.0,  # scales up if network is slow
            'slow_network': False,      # True if detected slow network
        }
        # Detect if we're behind a proxy/Tor → preemptively increase timeouts
        if config.proxy:
            self._net_intel['timeout_multiplier'] = 2.0 if config.proxy_type == 'tor' else 1.5
            self._net_intel['slow_network'] = True

    def is_available(self, tool_name):
        """Check if a tool is available in PATH."""
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]
        available = shutil.which(tool_name) is not None
        self._tool_cache[tool_name] = available
        return available

    def check_tools(self, tool_list):
        """Check availability of multiple tools. Returns dict."""
        return {t: self.is_available(t) for t in tool_list}

    def run(self, cmd, timeout=None, retries=3, cwd=None,
            stdin_data=None, env=None, shell=False):
        """
        Run a command with retry logic, timeout handling, and network intelligence.

        Returns: (stdout: str, stderr: str, returncode: int)
        """
        # ── Intelligence: circuit breaker check ──
        intel = self._net_intel
        if intel['circuit_open']:
            if time.time() < intel['circuit_open_until']:
                # Circuit is open — wait for cooldown
                wait_remaining = intel['circuit_open_until'] - time.time()
                if wait_remaining > 0:
                    log_debug(f"Circuit breaker open, waiting {wait_remaining:.0f}s...", self.config.verbose)
                    time.sleep(min(wait_remaining, 30))
            # Reset circuit after cooldown
            with self._lock:
                intel['circuit_open'] = False
                intel['consecutive_fails'] = 0

        # ── Intelligence: adaptive timeout ──
        base_timeout = timeout or self.config.timeout
        effective_timeout = base_timeout * intel['timeout_multiplier']
        # If recent responses have been slow, extend timeout further
        if intel['avg_response_ms'] > 5000:  # >5s average
            effective_timeout = max(effective_timeout, base_timeout * 2)

        last_err = None

        for attempt in range(1, retries + 1):
            try:
                if self.config.verbose:
                    cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
                    log_debug(f"[attempt {attempt}/{retries}] {cmd_str}",
                              self.config.verbose)

                merged_env = os.environ.copy()
                if env:
                    merged_env.update(env)
                # Force non-interactive, disable pagers
                merged_env['PAGER'] = 'cat'
                merged_env['GIT_PAGER'] = 'cat'

                # Proxy / Tor: set environment variables for all subprocesses
                if self.config.proxy:
                    proxy_url = self.config.proxy
                    merged_env['HTTP_PROXY'] = proxy_url
                    merged_env['HTTPS_PROXY'] = proxy_url
                    merged_env['ALL_PROXY'] = proxy_url
                    merged_env['http_proxy'] = proxy_url
                    merged_env['https_proxy'] = proxy_url
                    merged_env['all_proxy'] = proxy_url

                start_ts = time.time()

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
                    cwd=cwd,
                    env=merged_env,
                    shell=shell
                )

                stdout, stderr = proc.communicate(
                    input=stdin_data.encode() if stdin_data else None,
                    timeout=effective_timeout
                )

                elapsed_ms = (time.time() - start_ts) * 1000

                stdout_str = stdout.decode('utf-8', errors='replace').strip()
                stderr_str = stderr.decode('utf-8', errors='replace').strip()

                # ── Intelligence: record success ──
                with self._lock:
                    intel['total_requests'] += 1
                    intel['successful'] += 1
                    intel['consecutive_fails'] = 0
                    # Rolling average of last 20 response times
                    intel['response_times'].append(elapsed_ms)
                    if len(intel['response_times']) > 20:
                        intel['response_times'] = intel['response_times'][-20:]
                    intel['avg_response_ms'] = sum(intel['response_times']) / len(intel['response_times'])
                    # If network recovered from slow, ease off the multiplier
                    if intel['avg_response_ms'] < 2000 and intel['timeout_multiplier'] > 1.0:
                        intel['timeout_multiplier'] = max(1.0, intel['timeout_multiplier'] - 0.1)

                # Success or acceptable exit
                if proc.returncode == 0 or stdout_str:
                    return stdout_str, stderr_str, proc.returncode

                # Non-zero exit with no output might be an issue
                last_err = f"Exit code {proc.returncode}: {stderr_str[:200]}"

            except subprocess.TimeoutExpired:
                last_err = f"Timeout after {effective_timeout:.0f}s"
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except Exception:
                    pass

                # ── Intelligence: timeout tracking ──
                with self._lock:
                    intel['total_requests'] += 1
                    intel['timeouts'] += 1
                    intel['consecutive_fails'] += 1
                    intel['failed'] += 1
                    # Increase timeout multiplier on repeated timeouts
                    if intel['timeouts'] > 3 and intel['timeout_multiplier'] < 3.0:
                        intel['timeout_multiplier'] = min(3.0, intel['timeout_multiplier'] + 0.3)
                        if not intel['slow_network']:
                            intel['slow_network'] = True
                            log_warning(f"Slow network detected — increasing timeouts (x{intel['timeout_multiplier']:.1f})")

                if self.config.verbose:
                    log_debug(f"Timeout on attempt {attempt}: {cmd}", True)

                # Increase timeout for next retry of same command
                effective_timeout = min(effective_timeout * 1.5, 1800)

            except FileNotFoundError:
                tool = cmd[0] if isinstance(cmd, list) else cmd.split()[0]
                return "", f"Tool not found: {tool}", 127

            except PermissionError:
                tool = cmd[0] if isinstance(cmd, list) else cmd.split()[0]
                return "", f"Permission denied: {tool}", 126

            except (OSError, ConnectionError, BrokenPipeError) as e:
                # Network-level errors
                last_err = str(e)
                with self._lock:
                    intel['total_requests'] += 1
                    intel['failed'] += 1
                    intel['consecutive_fails'] += 1

            except Exception as e:
                last_err = str(e)
                with self._lock:
                    intel['total_requests'] += 1
                    intel['failed'] += 1
                    intel['consecutive_fails'] += 1

            # ── Intelligence: circuit breaker ──
            with self._lock:
                if intel['consecutive_fails'] >= 10:
                    cooldown = min(60, intel['consecutive_fails'] * 5)
                    intel['circuit_open'] = True
                    intel['circuit_open_until'] = time.time() + cooldown
                    log_warning(f"Circuit breaker triggered ({intel['consecutive_fails']} consecutive failures) — "
                                f"pausing {cooldown}s to let network recover")

            # Exponential backoff between retries
            if attempt < retries:
                wait = min(2 ** attempt, 30)
                # Extra jitter to avoid thundering herd
                wait += random.uniform(0, wait * 0.3)
                if self.config.verbose:
                    log_debug(f"Retrying in {wait:.1f}s...", True)
                time.sleep(wait)

        # All retries exhausted
        if self.config.verbose:
            log_debug(f"All {retries} attempts failed: {last_err}", True)
        return "", last_err or "Unknown error", 1

    def get_health_stats(self):
        """Return current network health stats for reporting."""
        intel = self._net_intel
        total = intel['total_requests'] or 1
        return {
            'total_requests': intel['total_requests'],
            'success_rate': f"{intel['successful'] / total * 100:.1f}%",
            'timeout_count': intel['timeouts'],
            'avg_response_ms': f"{intel['avg_response_ms']:.0f}ms",
            'timeout_multiplier': f"{intel['timeout_multiplier']:.1f}x",
            'slow_network': intel['slow_network'],
        }

    def run_tool(self, tool_name, args, timeout=None, retries=3):
        """
        Run a named tool with arguments.
        Checks availability first.
        Applies WAF evasion (UA rotation, jitter) if WAF was detected.
        Returns stdout string, or empty string on failure.
        """
        if not self.is_available(tool_name):
            if self.config.verbose:
                log_debug(f"Tool not available: {tool_name}", True)
            return ""

        # WAF evasion: add jitter between requests
        if self._waf_evasion:
            with self._lock:
                self._request_count += 1
            # Random delay between 0.1-0.5s to avoid rate limiting
            if self._request_count % 3 == 0:
                time.sleep(random.uniform(0.1, 0.5))

        # WAF evasion: rotate User-Agent for curl commands
        if self._waf_evasion and tool_name == 'curl':
            # Check if -A or --user-agent is already specified
            has_ua = any(a in args for a in ['-A', '--user-agent'])
            if not has_ua:
                ua = random.choice(self._evasion_agents)
                args = ['-A', ua] + list(args)
            # Add realistic browser headers
            if '-H' not in str(args) or 'Accept-Language' not in str(args):
                args = [
                    '-H', 'Accept-Language: en-US,en;q=0.9',
                    '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                ] + list(args)

        # Custom headers injection for curl
        if self.config.headers and tool_name == 'curl':
            args = list(args)
            for hdr in self.config.headers:
                args = ['-H', hdr] + args

        # Proxy / Tor: inject proxy flags for specific tools
        if self.config.proxy:
            proxy_url = self.config.proxy
            args = list(args)  # ensure mutable

            if tool_name == 'curl':
                # curl: --proxy or --socks5-hostname for Tor
                has_proxy = any(a in args for a in ['--proxy', '-x', '--socks5-hostname'])
                if not has_proxy:
                    if self.config.proxy_type == 'tor':
                        # socks5h resolves DNS through Tor too
                        socks_host = proxy_url.replace('socks5://', '')
                        args = ['--socks5-hostname', socks_host] + args
                    else:
                        args = ['--proxy', proxy_url] + args

            elif tool_name in ('httpx', 'nuclei', 'subfinder', 'katana',
                               'dnsx', 'naabu', 'shuffledns', 'chaos'):
                # ProjectDiscovery tools: -proxy flag
                if '-proxy' not in str(args) and '--proxy' not in str(args):
                    pd_proxy = proxy_url
                    if self.config.proxy_type == 'tor':
                        pd_proxy = proxy_url  # PD tools accept socks5://
                    args = args + ['-proxy', pd_proxy]

            elif tool_name in ('ffuf', 'gobuster'):
                # ffuf/gobuster: -x flag
                if '-x' not in args:
                    args = args + ['-x', proxy_url]

            elif tool_name == 'nmap':
                # nmap: --proxies flag (supports socks4/http)
                if '--proxies' not in str(args):
                    nmap_proxy = proxy_url
                    if self.config.proxy_type == 'tor':
                        # nmap needs socks4:// for Tor
                        nmap_proxy = proxy_url.replace('socks5://', 'socks4://')
                    args = args + ['--proxies', nmap_proxy]

            elif tool_name in ('gospider', 'hakrawler'):
                if '--proxy' not in str(args) and '-p' not in args:
                    args = args + ['--proxy', proxy_url]

            elif tool_name in ('arjun',):
                if '--proxy' not in str(args):
                    args = args + ['--proxy', proxy_url]

        cmd = [tool_name] + args
        stdout, stderr, rc = self.run(cmd, timeout=timeout, retries=retries)
        return stdout

    def run_tool_to_file(self, tool_name, args, output_file,
                         timeout=None, retries=3):
        """Run a tool and write stdout to a file. Returns line count."""
        stdout = self.run_tool(tool_name, args, timeout=timeout, retries=retries)
        if stdout:
            with open(output_file, 'w') as f:
                f.write(stdout)
            return len(stdout.strip().split('\n'))
        return 0

    def run_parallel(self, tasks, max_workers=None):
        """
        Run multiple tasks in parallel.
        tasks: list of (func, args_tuple) or (func, args_tuple, kwargs_dict)
        Returns: list of results
        """
        max_workers = max_workers or min(self.config.threads, len(tasks), 20)
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for task in tasks:
                if len(task) == 3:
                    func, args, kwargs = task
                else:
                    func, args = task
                    kwargs = {}
                future = executor.submit(func, *args, **kwargs)
                futures[future] = (func.__name__, args)

            for future in as_completed(futures):
                name, args = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    if self.config.verbose:
                        log_debug(f"Parallel task {name} failed: {e}", True)
                    results.append(None)

        return results


# ═══════════════════════════════════════════════════════════════════════════════
#  RESULT STORE
# ═══════════════════════════════════════════════════════════════════════════════

class ResultStore:
    """
    Thread-safe storage for scan results.
    Persists results to disk in the output directory.
    """

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self._lock = threading.Lock()
        self._data = {
            'subdomains': set(),
            'live_subdomains': set(),
            'urls': set(),
            'live_hosts': set(),       # scheme://host format
            'ports': {},               # host -> [(port, service, state)]
            'technologies': {},        # host -> [techs]
            'js_files': set(),
            'parameters': {},          # url -> [params]
            'wayback_urls': set(),
            'directories': set(),
            'emails': set(),
            'dns_records': {},         # domain -> {type: [values]}
            'whois': {},
            'vulns': [],               # list of vuln dicts
            'screenshots': [],
            'crawled_urls': set(),
            'interesting': [],         # interesting findings
        }

    # ── Subdomains ──────────────────────────────────────────────────────

    def add_subdomains(self, subs):
        with self._lock:
            before = len(self._data['subdomains'])
            self._data['subdomains'].update(
                s.strip().lower() for s in subs if s.strip()
            )
            new = len(self._data['subdomains']) - before
        return new

    def get_subdomains(self):
        with self._lock:
            return set(self._data['subdomains'])

    # ── Live Subdomains ────────────────────────────────────────────────

    def add_live_subdomains(self, subs):
        with self._lock:
            self._data['live_subdomains'].update(
                s.strip().lower() for s in subs if s.strip()
            )

    def get_live_subdomains(self):
        with self._lock:
            return set(self._data['live_subdomains'])

    # ── Live Hosts (HTTP) ──────────────────────────────────────────────

    def add_live_hosts(self, hosts):
        with self._lock:
            self._data['live_hosts'].update(
                h.strip() for h in hosts if h.strip()
            )

    def get_live_hosts(self):
        with self._lock:
            return set(self._data['live_hosts'])

    # ── URLs ───────────────────────────────────────────────────────────

    def add_urls(self, urls):
        with self._lock:
            self._data['urls'].update(u.strip() for u in urls if u.strip())

    def get_urls(self):
        with self._lock:
            return set(self._data['urls'])

    # ── Ports ──────────────────────────────────────────────────────────

    def add_ports(self, host, ports_list):
        """ports_list: list of (port, service, state) tuples."""
        with self._lock:
            if host not in self._data['ports']:
                self._data['ports'][host] = []
            self._data['ports'][host].extend(ports_list)

    def get_ports(self):
        with self._lock:
            return dict(self._data['ports'])

    # ── Technologies ───────────────────────────────────────────────────

    def add_technologies(self, host, techs):
        with self._lock:
            if host not in self._data['technologies']:
                self._data['technologies'][host] = []
            self._data['technologies'][host].extend(techs)

    def get_technologies(self):
        with self._lock:
            return dict(self._data['technologies'])

    # ── JS Files ───────────────────────────────────────────────────────

    def add_js_files(self, files):
        with self._lock:
            self._data['js_files'].update(f.strip() for f in files if f.strip())

    def get_js_files(self):
        with self._lock:
            return set(self._data['js_files'])

    # ── Wayback URLs ───────────────────────────────────────────────────

    def add_wayback_urls(self, urls):
        with self._lock:
            self._data['wayback_urls'].update(
                u.strip() for u in urls if u.strip()
            )

    def get_wayback_urls(self):
        with self._lock:
            return set(self._data['wayback_urls'])

    # ── Directories ────────────────────────────────────────────────────

    def add_directories(self, dirs):
        with self._lock:
            self._data['directories'].update(
                d.strip() for d in dirs if d.strip()
            )

    def get_directories(self):
        with self._lock:
            return set(self._data['directories'])

    # ── DNS Records ────────────────────────────────────────────────────

    def add_dns_records(self, domain, records):
        with self._lock:
            if domain not in self._data['dns_records']:
                self._data['dns_records'][domain] = {}
            for rtype, values in records.items():
                if rtype not in self._data['dns_records'][domain]:
                    self._data['dns_records'][domain][rtype] = []
                self._data['dns_records'][domain][rtype].extend(values)

    def get_dns_records(self):
        with self._lock:
            return dict(self._data['dns_records'])

    # ── WHOIS ──────────────────────────────────────────────────────────

    def set_whois(self, data):
        with self._lock:
            self._data['whois'] = data

    def get_whois(self):
        with self._lock:
            return dict(self._data['whois'])

    # ── Emails ─────────────────────────────────────────────────────────

    def add_emails(self, emails):
        with self._lock:
            self._data['emails'].update(
                e.strip().lower() for e in emails if e.strip()
            )

    def get_emails(self):
        with self._lock:
            return set(self._data['emails'])

    # ── Vulnerabilities ────────────────────────────────────────────────

    def add_vuln(self, vuln_dict):
        with self._lock:
            self._data['vulns'].append(vuln_dict)

    def get_vulns(self):
        with self._lock:
            return list(self._data['vulns'])

    # ── Parameters ─────────────────────────────────────────────────────

    def add_parameters(self, url, params):
        with self._lock:
            if url not in self._data['parameters']:
                self._data['parameters'][url] = []
            self._data['parameters'][url].extend(params)

    def get_parameters(self):
        with self._lock:
            return dict(self._data['parameters'])

    # ── Crawled URLs ───────────────────────────────────────────────────

    def add_crawled_urls(self, urls):
        with self._lock:
            self._data['crawled_urls'].update(
                u.strip() for u in urls if u.strip()
            )

    def get_crawled_urls(self):
        with self._lock:
            return set(self._data['crawled_urls'])

    # ── Interesting Findings ───────────────────────────────────────────

    def add_interesting(self, finding):
        with self._lock:
            self._data['interesting'].append(finding)

    def get_interesting(self):
        with self._lock:
            return list(self._data['interesting'])

    # ── Persistence ────────────────────────────────────────────────────

    def save_to_disk(self):
        """Persist all results to disk as files."""
        try:
            # Save sets as line-delimited files
            set_mappings = {
                'subdomains': ('subdomains', 'all_subdomains.txt'),
                'live_subdomains': ('subdomains', 'live_subdomains.txt'),
                'live_hosts': ('subdomains', 'live_hosts.txt'),
                'urls': ('urls', 'all_urls.txt'),
                'js_files': ('js', 'js_files.txt'),
                'wayback_urls': ('wayback', 'wayback_urls.txt'),
                'directories': ('dirs', 'directories.txt'),
                'emails': ('raw', 'emails.txt'),
                'crawled_urls': ('crawl', 'crawled_urls.txt'),
            }

            for key, (subdir, filename) in set_mappings.items():
                data = self._data.get(key, set())
                if data:
                    filepath = os.path.join(self.output_dir, subdir, filename)
                    with open(filepath, 'w') as f:
                        f.write('\n'.join(sorted(data)) + '\n')

            # Save dicts as JSON
            dict_mappings = {
                'ports': ('ports', 'ports.json'),
                'technologies': ('tech', 'technologies.json'),
                'dns_records': ('dns', 'dns_records.json'),
                'whois': ('raw', 'whois.json'),
                'parameters': ('params', 'parameters.json'),
            }

            for key, (subdir, filename) in dict_mappings.items():
                data = self._data.get(key, {})
                if data:
                    filepath = os.path.join(self.output_dir, subdir, filename)
                    # Convert sets in values for JSON serialization
                    serializable = self._make_serializable(data)
                    with open(filepath, 'w') as f:
                        json.dump(serializable, f, indent=2, default=str)

            # Save vulns
            vulns = self._data.get('vulns', [])
            if vulns:
                filepath = os.path.join(self.output_dir, 'vulns', 'vulnerabilities.json')
                with open(filepath, 'w') as f:
                    json.dump(vulns, f, indent=2, default=str)

            # Save interesting findings
            findings = self._data.get('interesting', [])
            if findings:
                filepath = os.path.join(self.output_dir, 'raw', 'interesting.json')
                with open(filepath, 'w') as f:
                    json.dump(findings, f, indent=2, default=str)

            # Master JSON with everything
            master = self._make_serializable(self._data)
            filepath = os.path.join(self.output_dir, 'reports', 'results.json')
            with open(filepath, 'w') as f:
                json.dump(master, f, indent=2, default=str)

        except Exception as e:
            log_error(f"Failed to save results: {e}")

    def _make_serializable(self, obj):
        """Convert sets to sorted lists for JSON serialization."""
        if isinstance(obj, set):
            return sorted(list(obj))
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(i) for i in obj]
        return obj

    def save_checkpoint(self, completed_modules):
        """Save scan checkpoint for resume support."""
        checkpoint = {
            'completed_modules': list(completed_modules),
            'timestamp': datetime.now().isoformat(),
        }
        filepath = os.path.join(self.output_dir, '.pot_checkpoint.json')
        try:
            with open(filepath, 'w') as f:
                json.dump(checkpoint, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def load_checkpoint(output_dir):
        """Load scan checkpoint. Returns set of completed module names."""
        filepath = os.path.join(output_dir, '.pot_checkpoint.json')
        if not os.path.exists(filepath):
            return set()
        try:
            with open(filepath) as f:
                data = json.load(f)
            return set(data.get('completed_modules', []))
        except Exception:
            return set()

    def load_from_disk(self):
        """Load previous results from disk for resume."""
        # Load sets
        set_mappings = {
            'subdomains': ('subdomains', 'all_subdomains.txt'),
            'live_subdomains': ('subdomains', 'live_subdomains.txt'),
            'live_hosts': ('subdomains', 'live_hosts.txt'),
            'urls': ('urls', 'all_urls.txt'),
            'js_files': ('js', 'js_files.txt'),
            'wayback_urls': ('wayback', 'wayback_urls.txt'),
            'directories': ('dirs', 'directories.txt'),
            'emails': ('raw', 'emails.txt'),
            'crawled_urls': ('crawl', 'crawled_urls.txt'),
        }
        for key, (subdir, filename) in set_mappings.items():
            filepath = os.path.join(self.output_dir, subdir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath) as f:
                        lines = set(l.strip() for l in f if l.strip())
                    with self._lock:
                        self._data[key].update(lines)
                except Exception:
                    pass

        # Load dicts
        dict_mappings = {
            'ports': ('ports', 'ports.json'),
            'technologies': ('tech', 'technologies.json'),
            'dns_records': ('dns', 'dns_records.json'),
            'parameters': ('params', 'parameters.json'),
        }
        for key, (subdir, filename) in dict_mappings.items():
            filepath = os.path.join(self.output_dir, subdir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    with self._lock:
                        self._data[key].update(data)
                except Exception:
                    pass

        # Load vulns
        vuln_file = os.path.join(self.output_dir, 'vulns', 'vulnerabilities.json')
        if os.path.exists(vuln_file):
            try:
                with open(vuln_file) as f:
                    vulns = json.load(f)
                with self._lock:
                    self._data['vulns'].extend(vulns)
            except Exception:
                pass

    def get_summary(self):
        """Get a summary dict of all result counts."""
        return {
            'subdomains': len(self._data['subdomains']),
            'live_subdomains': len(self._data['live_subdomains']),
            'live_hosts': len(self._data['live_hosts']),
            'urls': len(self._data['urls']),
            'ports': sum(len(v) for v in self._data['ports'].values()),
            'technologies': sum(len(v) for v in self._data['technologies'].values()),
            'js_files': len(self._data['js_files']),
            'wayback_urls': len(self._data['wayback_urls']),
            'directories': len(self._data['directories']),
            'emails': len(self._data['emails']),
            'vulns_critical': len([v for v in self._data['vulns'] if v.get('severity') == 'critical']),
            'vulns_high': len([v for v in self._data['vulns'] if v.get('severity') == 'high']),
            'vulns_medium': len([v for v in self._data['vulns'] if v.get('severity') == 'medium']),
            'vulns_low': len([v for v in self._data['vulns'] if v.get('severity') == 'low']),
            'vulns_info': len([v for v in self._data['vulns'] if v.get('severity') == 'info']),
            'vulns_total': len(self._data['vulns']),
            'crawled_urls': len(self._data['crawled_urls']),
            'interesting': len(self._data['interesting']),
            'parameters': sum(len(v) for v in self._data['parameters'].values()),
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def check_root():
    """Check if running as root / administrator."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows compatibility check for administrator
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def check_internet():
    """Quick internet connectivity check."""
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=5)
        return True
    except OSError:
        return False


def get_system_info():
    """Get system resource info (cross-platform)."""
    try:
        cpu_count = os.cpu_count() or 2
        mem_gb = 0
        # Try /proc/meminfo (Linux)
        try:
            with open('/proc/meminfo') as f:
                for line in f:
                    if line.startswith('MemAvailable:'):
                        mem_kb = int(line.split()[1])
                        mem_gb = round(mem_kb / (1024 * 1024), 1)
                        break
        except Exception:
            pass
        # Try Windows approach
        if mem_gb == 0:
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                c_ulonglong = ctypes.c_ulonglong

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', ctypes.c_ulong),
                        ('dwMemoryLoad', ctypes.c_ulong),
                        ('ullTotalPhys', c_ulonglong),
                        ('ullAvailPhys', c_ulonglong),
                        ('ullTotalPageFile', c_ulonglong),
                        ('ullAvailPageFile', c_ulonglong),
                        ('ullTotalVirtual', c_ulonglong),
                        ('ullAvailVirtual', c_ulonglong),
                        ('ullAvailExtendedVirtual', c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                mem_gb = round(stat.ullAvailPhys / (1024 ** 3), 1)
            except Exception:
                pass
        return {'cpus': cpu_count, 'memory_gb': mem_gb}
    except Exception:
        return {'cpus': 2, 'memory_gb': 0}


def optimize_threads(config):
    """Auto-tune thread count based on system resources."""
    info = get_system_info()
    max_threads = info['cpus'] * 10  # 10 threads per CPU core
    if info['memory_gb'] > 0:
        # Limit based on memory (roughly 50MB per thread)
        mem_threads = int(info['memory_gb'] * 1024 / 50)
        max_threads = min(max_threads, mem_threads)
    config.threads = min(config.threads, max(max_threads, 10))
    return config


def dedup_lines(text):
    """Deduplicate lines from text output."""
    seen = set()
    result = []
    for line in text.strip().split('\n'):
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            result.append(line)
    return result


def parse_lines(text):
    """Parse non-empty lines from text."""
    return [l.strip() for l in text.strip().split('\n') if l.strip()]


def safe_filename(name):
    """Create a safe filename from a string."""
    return "".join(c if c.isalnum() or c in '._-' else '_' for c in name)


def merge_files(file_list, output_file):
    """Merge multiple files into one, deduplicating lines."""
    seen = set()
    with open(output_file, 'w') as out:
        for fp in file_list:
            if os.path.exists(fp):
                with open(fp) as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in seen:
                            seen.add(line)
                            out.write(line + '\n')
    return len(seen)


def read_file_lines(filepath):
    """Read lines from a file, returning empty list if file doesn't exist."""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath) as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []


def write_lines(filepath, lines):
    """Write lines to a file."""
    with open(filepath, 'w') as f:
        f.write('\n'.join(lines) + '\n' if lines else '')


def extract_domain_from_url(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        return parsed.hostname or url
    except Exception:
        return url


def resolve_domain(domain, timeout=5):
    """Resolve a domain to IP addresses."""
    try:
        socket.setdefaulttimeout(timeout)
        return list(set(
            addr[4][0] for addr in socket.getaddrinfo(domain, None)
        ))
    except Exception:
        return []
