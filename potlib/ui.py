#!/usr/bin/env python3
"""
POT - Professional Offensive Tool
UI Module - Banner, colors, and terminal output formatting
Styled exactly after Nuclei's clean, professional terminal output.
"""

import sys
import threading
from datetime import datetime

class Colors:
    """ANSI color codes for terminal output."""
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    ITALIC  = '\033[3m'
    UNDER   = '\033[4m'
    BLINK   = '\033[5m'
    STRIKE  = '\033[9m'

    BLACK   = '\033[30m'
    RED     = '\033[31m'
    GREEN   = '\033[32m'
    YELLOW  = '\033[33m'
    BLUE    = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN    = '\033[36m'
    WHITE   = '\033[37m'

    BRED    = '\033[91m'
    BGREEN  = '\033[92m'
    BYELLOW = '\033[93m'
    BBLUE   = '\033[94m'
    BMAGENTA= '\033[95m'
    BCYAN   = '\033[96m'
    BWHITE  = '\033[97m'

    BG_RED    = '\033[41m'
    BG_GREEN  = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE   = '\033[44m'
    BG_CYAN   = '\033[46m'

VERSION = "1.0.0"

BANNER = r"""
{bc}{bold}
    ____  ____  ______
   / __ \/ __ \/_  __/
  / /_/ / / / / / /   
 / ____/ /_/ / / /    
/_/    \____/ /_/     
{reset}

                  {italic}Discovery Before Exploitation - iceberg{reset}

    {dim}XMR: 8BQ91yxDC2ChBCefXJLXN1JjSeRar5xj2WdE2Td4BVFQbMAkjTb1NdWBXaYuGDyNaTD7ueQ99gfnbDFVH2zauYGr6uaEWeP{reset}
""".format(
    bc=Colors.BCYAN, bold=Colors.BOLD, reset=Colors.RESET,
    dim=Colors.DIM, italic=Colors.ITALIC, ver=VERSION
)

# Thread lock for safe terminal output
_print_lock = threading.Lock()

def _safe_print(msg):
    """Thread-safe print."""
    with _print_lock:
        print(msg)
        sys.stdout.flush()

def print_banner():
    """Display the POT banner."""
    _safe_print(BANNER)

def _timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_info(msg):
    _safe_print(
        f"[{Colors.BCYAN}{_timestamp()}{Colors.RESET}] "
        f"[{Colors.BCYAN}inf{Colors.RESET}] {msg}"
    )

def log_warning(msg):
    _safe_print(
        f"[{Colors.BCYAN}{_timestamp()}{Colors.RESET}] "
        f"[{Colors.BYELLOW}wrn{Colors.RESET}] {msg}"
    )

def log_error(msg):
    _safe_print(
        f"[{Colors.BCYAN}{_timestamp()}{Colors.RESET}] "
        f"[{Colors.BRED}err{Colors.RESET}] {msg}"
    )

def log_debug(msg, verbose=True):
    if verbose:
        _safe_print(
            f"[{Colors.BCYAN}{_timestamp()}{Colors.RESET}] "
            f"[{Colors.DIM}dbg{Colors.RESET}] {msg}"
        )

def log_found(module, item):
    """Log a discovered item (subdomain, URL, etc.)."""
    slug = module.replace(' ', '-').lower()
    _safe_print(
        f"[{Colors.BCYAN}{_timestamp()}{Colors.RESET}] "
        f"[{Colors.BGREEN}{slug}{Colors.RESET}] "
        f"[{Colors.BCYAN}extracted{Colors.RESET}] "
        f"{item}"
    )

def log_vuln(severity, title, detail=""):
    """Log a vulnerability finding with severity color."""
    sev_map = {
        'critical': (Colors.BOLD + Colors.BRED,  'critical'),
        'high':     (Colors.RED,                 'high'),
        'medium':   (Colors.BYELLOW,             'medium'),
        'low':      (Colors.BGREEN,              'low'),
        'info':     (Colors.BBLUE,               'info'),
    }
    color, label = sev_map.get(severity.lower(), (Colors.WHITE, 'unknown'))
    extra = f" {detail}" if detail else ""
    slug = title.replace(' ', '-').lower()
    
    # Format: [2026-06-05 10:45:01] [title-slug] [http] [severity] target
    _safe_print(
        f"[{Colors.BCYAN}{_timestamp()}{Colors.RESET}] "
        f"[{Colors.BWHITE}{slug}{Colors.RESET}] "
        f"[{Colors.BCYAN}http{Colors.RESET}] "
        f"[{color}{label}{Colors.RESET}]"
        f"{extra}"
    )

def log_phase(name):
    """Print a phase separator banner."""
    log_info(f"Starting {name.title()}")

def log_module_start(name):
    """Nuclei doesn't usually use huge boxes for phases, just debug logs."""
    log_debug(f"Executing module: {name}", verbose=False)

def log_module_end(name, count=0):
    pass  # We omit the end logs to keep the interface purely finding-based like Nuclei

def log_summary_line(label, value, color=None):
    """Print a summary stat line."""
    c = color or Colors.BWHITE
    _safe_print(
        f"[{Colors.BCYAN}inf{Colors.RESET}] {label:<30s} : {c}{value}{Colors.RESET}"
    )

def progress_bar(current, total, prefix='', length=40):
    """In-place progress bar (hidden by default to match Nuclei unless specifically enabled)."""
    pass 

def print_tool_status(tools_status):
    """Print a table of available/missing tools."""
    available = sum(1 for v in tools_status.values() if v)
    total = len(tools_status)
    log_info(f"Using {available}/{total} external engines")

def print_config(config):
    """Print current scan configuration."""
    log_info(f"Target: {config.target}")
    log_info(f"Threads: {config.threads} | Timeout: {config.timeout}s | Rate-Limit: {config.rate_limit}")
    if config.proxy:
        log_info(f"Proxy: {config.proxy}")
