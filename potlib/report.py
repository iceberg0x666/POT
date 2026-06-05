#!/usr/bin/env python3
"""
POT - Professional Offensive Tool
Report Generator Module
Generates JSON and HTML reports from scan results.
"""

import os
import json
from datetime import datetime

from potlib.ui import (
    log_info, log_phase, log_summary_line, Colors
)


def generate_report(config, results):
    """Generate comprehensive scan reports."""
    log_phase("PHASE 4 — REPORT GENERATION")

    # Save all raw data first
    results.save_to_disk()

    summary = results.get_summary()
    elapsed = datetime.now() - config.start_time

    # Generate JSON report
    json_report = _build_json_report(config, results, summary, elapsed)
    json_path = os.path.join(config.dirs['reports'], 'pot_report.json')
    with open(json_path, 'w') as f:
        json.dump(json_report, f, indent=2, default=str)
    log_info(f"JSON report saved: {json_path}")

    # Generate CSV report
    import csv
    csv_path = os.path.join(config.dirs['reports'], 'pot_report.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Severity', 'Type', 'Title', 'URL/Detail'])
        for v in results.get_vulns():
            writer.writerow([
                v.get('severity', 'info').upper(),
                v.get('type', ''),
                v.get('title', ''),
                v.get('url', v.get('detail', ''))
            ])
    log_info(f"CSV report saved: {csv_path}")

    # Print terminal summary
    _print_summary(config, summary, elapsed)

    return json_path, csv_path


def _build_json_report(config, results, summary, elapsed):
    """Build comprehensive JSON report."""
    return {
        'meta': {
            'tool': 'POT - Professional Offensive Tool',
            'version': '1.0.0',
            'target': config.target,
            'target_domain': config.target_domain,
            'excluded': config.notargets,
            'start_time': config.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration': str(elapsed),
            'config': config.to_dict(),
        },
        'summary': summary,
        'subdomains': sorted(results.get_subdomains()),
        'live_subdomains': sorted(results.get_live_subdomains()),
        'live_hosts': sorted(results.get_live_hosts()),
        'dns_records': results.get_dns_records(),
        'ports': results.get_ports(),
        'technologies': results.get_technologies(),
        'urls': sorted(list(results.get_urls())[:5000]),
        'wayback_urls_count': len(results.get_wayback_urls()),
        'js_files': sorted(results.get_js_files()),
        'parameters': results.get_parameters(),
        'emails': sorted(results.get_emails()),
        'vulnerabilities': results.get_vulns(),
        'interesting': results.get_interesting(),
        'whois': results.get_whois(),
    }


def _build_html_report(config, results, summary, elapsed):
    """Build professional HTML report."""
    vulns = results.get_vulns()
    subdomains = sorted(results.get_subdomains())
    live_hosts = sorted(results.get_live_hosts())
    technologies = results.get_technologies()
    ports = results.get_ports()
    emails = sorted(results.get_emails())

    # Group vulnerabilities by severity
    vuln_groups = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
    for v in vulns:
        sev = v.get('severity', 'info').lower()
        if sev in vuln_groups:
            vuln_groups[sev].append(v)

    # Build vulnerability rows
    vuln_rows = ""
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        for v in vuln_groups[sev]:
            sev_class = f'sev-{sev}'
            vuln_rows += f"""
            <tr>
                <td><span class="badge {sev_class}">{sev.upper()}</span></td>
                <td>{_html_escape(v.get('title', ''))}</td>
                <td class="mono">{_html_escape(v.get('url', v.get('detail', '')))}</td>
                <td>{_html_escape(v.get('type', ''))}</td>
            </tr>"""

    # Build subdomain rows
    sub_rows = ""
    for sub in subdomains[:500]:
        sub_rows += f"<tr><td class='mono'>{_html_escape(sub)}</td></tr>\n"

    # Build live host rows
    host_rows = ""
    for host in live_hosts[:500]:
        host_rows += f"<tr><td class='mono'>{_html_escape(host)}</td></tr>\n"

    # Build port rows
    port_rows = ""
    for host, port_list in ports.items():
        for port, service, state in port_list:
            port_rows += f"""
            <tr>
                <td class="mono">{_html_escape(host)}</td>
                <td>{port}</td>
                <td>{_html_escape(service)}</td>
                <td><span class="badge sev-info">{state}</span></td>
            </tr>"""

    # Build tech rows
    tech_rows = ""
    for host, techs in technologies.items():
        for tech in techs:
            tech_rows += f"""
            <tr>
                <td class="mono">{_html_escape(host)}</td>
                <td>{_html_escape(tech)}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POT Report — {_html_escape(config.target_domain)}</title>
    <style>
        :root {{
            --bg: #0a0e17;
            --surface: #111827;
            --surface2: #1a2332;
            --border: #1e2d3d;
            --text: #e2e8f0;
            --text-dim: #64748b;
            --accent: #00d4ff;
            --accent2: #7c3aed;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #3b82f6;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}

        header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            border-bottom: 1px solid var(--border);
            padding: 40px 0;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5rem;
            background: linear-gradient(90deg, var(--accent), var(--accent2));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}

        header .subtitle {{
            color: var(--text-dim);
            font-size: 1.1rem;
        }}

        .meta-bar {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }}

        .meta-item {{
            color: var(--text-dim);
            font-size: 0.9rem;
        }}

        .meta-item strong {{
            color: var(--accent);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 30px 0;
        }}

        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent);
        }}

        .stat-card .value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
        }}

        .stat-card .label {{
            color: var(--text-dim);
            font-size: 0.85rem;
            margin-top: 4px;
        }}

        .stat-card.critical .value {{ color: var(--critical); }}
        .stat-card.high .value {{ color: var(--high); }}
        .stat-card.medium .value {{ color: var(--medium); }}
        .stat-card.low .value {{ color: var(--low); }}

        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin: 24px 0;
            overflow: hidden;
        }}

        .section-header {{
            background: var(--surface2);
            padding: 16px 24px;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .section-header h2 {{
            font-size: 1.2rem;
            color: var(--accent);
        }}

        .section-header .count {{
            background: var(--border);
            color: var(--text);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
        }}

        .section-body {{
            padding: 16px 24px;
            max-height: 600px;
            overflow-y: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 2px solid var(--border);
            color: var(--text-dim);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }}

        tr:hover td {{ background: rgba(0, 212, 255, 0.03); }}

        .mono {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85rem; }}

        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .sev-critical {{ background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid var(--critical); }}
        .sev-high {{ background: rgba(249,115,22,0.15); color: var(--high); border: 1px solid var(--high); }}
        .sev-medium {{ background: rgba(234,179,8,0.15); color: var(--medium); border: 1px solid var(--medium); }}
        .sev-low {{ background: rgba(34,197,94,0.15); color: var(--low); border: 1px solid var(--low); }}
        .sev-info {{ background: rgba(59,130,246,0.15); color: var(--info); border: 1px solid var(--info); }}

        footer {{
            text-align: center;
            padding: 40px;
            color: var(--text-dim);
            font-size: 0.85rem;
        }}

        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg); }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--accent); }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>⚡ POT Reconnaissance Report</h1>
            <p class="subtitle">Professional Offensive Tool — Automated Bug Bounty Recon</p>
            <div class="meta-bar">
                <span class="meta-item">Target: <strong>{_html_escape(config.target_domain)}</strong></span>
                <span class="meta-item">Started: <strong>{config.start_time.strftime('%Y-%m-%d %H:%M:%S')}</strong></span>
                <span class="meta-item">Duration: <strong>{str(elapsed).split('.')[0]}</strong></span>
                <span class="meta-item">Findings: <strong>{summary['vulns_total']}</strong></span>
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{summary['subdomains']}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="value">{summary['live_hosts']}</div>
                <div class="label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="value">{summary['ports']}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="value">{summary['urls']}</div>
                <div class="label">URLs</div>
            </div>
            <div class="stat-card critical">
                <div class="value">{summary['vulns_critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="value">{summary['vulns_high']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="value">{summary['vulns_medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="value">{summary['vulns_low']}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <!-- Vulnerabilities -->
        <div class="section">
            <div class="section-header" onclick="toggle('vulns')">
                <h2>🔥 Vulnerabilities</h2>
                <span class="count">{summary['vulns_total']} findings</span>
            </div>
            <div class="section-body" id="vulns">
                <table>
                    <thead>
                        <tr><th>Severity</th><th>Title</th><th>Detail</th><th>Type</th></tr>
                    </thead>
                    <tbody>
                        {vuln_rows if vuln_rows else '<tr><td colspan="4" style="text-align:center;color:var(--text-dim)">No vulnerabilities found</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Subdomains -->
        <div class="section">
            <div class="section-header" onclick="toggle('subs')">
                <h2>🌐 Subdomains</h2>
                <span class="count">{summary['subdomains']} found</span>
            </div>
            <div class="section-body" id="subs">
                <table>
                    <thead><tr><th>Subdomain</th></tr></thead>
                    <tbody>{sub_rows if sub_rows else '<tr><td style="text-align:center;color:var(--text-dim)">No subdomains found</td></tr>'}</tbody>
                </table>
            </div>
        </div>

        <!-- Live Hosts -->
        <div class="section">
            <div class="section-header" onclick="toggle('hosts')">
                <h2>🟢 Live Hosts</h2>
                <span class="count">{summary['live_hosts']} alive</span>
            </div>
            <div class="section-body" id="hosts">
                <table>
                    <thead><tr><th>Host</th></tr></thead>
                    <tbody>{host_rows if host_rows else '<tr><td style="text-align:center;color:var(--text-dim)">No live hosts found</td></tr>'}</tbody>
                </table>
            </div>
        </div>

        <!-- Open Ports -->
        <div class="section">
            <div class="section-header" onclick="toggle('ports')">
                <h2>🔓 Open Ports</h2>
                <span class="count">{summary['ports']} ports</span>
            </div>
            <div class="section-body" id="ports">
                <table>
                    <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>State</th></tr></thead>
                    <tbody>{port_rows if port_rows else '<tr><td colspan="4" style="text-align:center;color:var(--text-dim)">No open ports found</td></tr>'}</tbody>
                </table>
            </div>
        </div>

        <!-- Technologies -->
        <div class="section">
            <div class="section-header" onclick="toggle('tech')">
                <h2>🔧 Technologies</h2>
                <span class="count">{summary['technologies']} detected</span>
            </div>
            <div class="section-body" id="tech">
                <table>
                    <thead><tr><th>Host</th><th>Technology</th></tr></thead>
                    <tbody>{tech_rows if tech_rows else '<tr><td colspan="2" style="text-align:center;color:var(--text-dim)">No technologies detected</td></tr>'}</tbody>
                </table>
            </div>
        </div>

        <!-- Additional Stats -->
        <div class="section">
            <div class="section-header">
                <h2>📊 Additional Statistics</h2>
            </div>
            <div class="section-body">
                <table>
                    <tbody>
                        <tr><td>Wayback URLs</td><td class="mono">{summary['wayback_urls']}</td></tr>
                        <tr><td>JavaScript Files</td><td class="mono">{summary['js_files']}</td></tr>
                        <tr><td>Parameters</td><td class="mono">{summary['parameters']}</td></tr>
                        <tr><td>Crawled URLs</td><td class="mono">{summary['crawled_urls']}</td></tr>
                        <tr><td>Directories Found</td><td class="mono">{summary['directories']}</td></tr>
                        <tr><td>Emails</td><td class="mono">{summary['emails']} — {', '.join(list(emails)[:10])}</td></tr>
                        <tr><td>Interesting Findings</td><td class="mono">{summary['interesting']}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <footer>
        <p>Generated by <strong>POT v1.0.0</strong> — Professional Offensive Tool</p>
        <p>Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </footer>

    <script>
        function toggle(id) {{
            const el = document.getElementById(id);
            el.style.display = el.style.display === 'none' ? 'block' : 'none';
        }}
    </script>
</body>
</html>"""

    return html


def _print_summary(config, summary, elapsed):
    """Print final summary to terminal."""
    from potlib.ui import log_phase, Colors

    log_phase("SCAN COMPLETE")

    print(f"\n  {Colors.BOLD}Target:{Colors.RESET}  {Colors.BCYAN}{config.target_domain}{Colors.RESET}")
    print(f"  {Colors.BOLD}Duration:{Colors.RESET} {str(elapsed).split('.')[0]}")
    print(f"  {Colors.BOLD}Output:{Colors.RESET}   {config.output_dir}")
    print()

    print(f"  {Colors.BOLD}{'─' * 50}{Colors.RESET}")
    log_summary_line("Subdomains", summary['subdomains'])
    log_summary_line("Live Subdomains", summary['live_subdomains'], Colors.BGREEN)
    log_summary_line("Live HTTP Hosts", summary['live_hosts'], Colors.BGREEN)
    log_summary_line("Open Ports", summary['ports'])
    log_summary_line("Technologies", summary['technologies'])
    log_summary_line("URLs Collected", summary['urls'])
    log_summary_line("Wayback URLs", summary['wayback_urls'])
    log_summary_line("JS Files", summary['js_files'])
    log_summary_line("Parameters", summary['parameters'])
    log_summary_line("Emails", summary['emails'])
    log_summary_line("Crawled URLs", summary['crawled_urls'])
    log_summary_line("Directories", summary['directories'])
    print(f"  {Colors.BOLD}{'─' * 50}{Colors.RESET}")

    if summary['vulns_total'] > 0:
        print(f"\n  {Colors.BOLD}Vulnerability Summary:{Colors.RESET}")
        if summary['vulns_critical']:
            log_summary_line("  Critical", summary['vulns_critical'], Colors.BRED)
        if summary['vulns_high']:
            log_summary_line("  High", summary['vulns_high'], Colors.RED)
        if summary['vulns_medium']:
            log_summary_line("  Medium", summary['vulns_medium'], Colors.BYELLOW)
        if summary['vulns_low']:
            log_summary_line("  Low", summary['vulns_low'], Colors.BGREEN)
        if summary['vulns_info']:
            log_summary_line("  Info", summary['vulns_info'], Colors.BBLUE)
        log_summary_line("  Total", summary['vulns_total'], Colors.BWHITE)
    else:
        print(f"\n  {Colors.DIM}No vulnerabilities found{Colors.RESET}")

    print(f"\n  {Colors.BGREEN}Reports saved to: {config.output_dir}/reports/{Colors.RESET}")
    print()


def _html_escape(text):
    """Basic HTML escaping."""
    if not isinstance(text, str):
        text = str(text)
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))
