import os

# ── PASSIVE.PY ──
passive_path = r"c:\Users\DAD\Desktop\check\pot\potlib\passive.py"
with open(passive_path, "r", encoding="utf-8") as f:
    passive_content = f.read()

if "shodan_lookup" not in passive_content:
    # 1. Add to modules list
    passive_content = passive_content.replace(
        "('google_dork',      google_dorking),",
        "('google_dork',      google_dorking),\n        ('shodan',           shodan_lookup),"
    )
    
    # 2. Add function
    shodan_code = """
# ═══════════════════════════════════════════════════════════════════════════════
#  SHODAN API INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

def shodan_lookup(config, runner, scope, results):
    \"\"\"Passive reconnaissance via Shodan API.\"\"\"
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
"""
    with open(passive_path, "w", encoding="utf-8") as f:
        f.write(passive_content + "\n" + shodan_code)


# ── ACTIVE.PY ──
active_path = r"c:\Users\DAD\Desktop\check\pot\potlib\active.py"
with open(active_path, "r", encoding="utf-8") as f:
    active_content = f.read()

if "api_fuzzing" not in active_content:
    # 1. Add to modules list
    active_content = active_content.replace(
        "('cloud_buckets', cloud_bucket_enum),",
        "('cloud_buckets', cloud_bucket_enum),\n        ('api_fuzz',        api_fuzzing),"
    )
    
    # 2. Add function
    api_fuzz_code = """
# ═══════════════════════════════════════════════════════════════════════════════
#  ADVANCED API FUZZING
# ═══════════════════════════════════════════════════════════════════════════════

def api_fuzzing(config, runner, scope, results):
    \"\"\"Fuzz discovered hosts for hidden API endpoints using ffuf.\"\"\"
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
        f.write('\\n'.join(api_wordlist))
        
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
"""
    with open(active_path, "w", encoding="utf-8") as f:
        f.write(active_content + "\n" + api_fuzz_code)

print("Patch applied successfully.")
