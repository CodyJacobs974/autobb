import os
import re
import shutil
import subprocess
from rich.console import Console
from rich.prompt import Prompt
from .utils import read_config # Assuming this is for target-specific config.txt
from autobb.config_manager import get_config_value # For global autobb_config.yaml

console = Console()

def _get_tool_path(tool_name: str, friendly_name: str = None) -> str:
    """
    Helper to get tool path from global config or shutil.which.
    Returns the path if found, None otherwise.
    Prints a message if using a configured path.
    """
    if not friendly_name:
        friendly_name = tool_name.capitalize()

    configured_path = get_config_value(f"tool_paths.{tool_name.lower()}")
    if configured_path:
        # Expand user path like ~
        expanded_path = os.path.expanduser(configured_path)
        if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
            console.print(f"[dim]Using configured path for {friendly_name}: {expanded_path}[/dim]")
            return expanded_path
        else:
            console.print(f"[yellow]Warning: Configured path for {friendly_name} ('{configured_path}') is invalid or not executable. Trying PATH.[/yellow]")

    system_path = shutil.which(tool_name)
    # if system_path:
    #     console.print(f"[dim]Using {friendly_name} from PATH: {system_path}[/dim]")
    return system_path


def run_whois(target_base_path: str):
    console.print("\n[cyan]Starting Whois scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]"); return
    target_identifier = config["TARGET_IDENTIFIER"]

    tool_path = _get_tool_path("whois")
    if not tool_path:
        console.print("[yellow]whois not found (not in PATH or configured). Install: sudo apt install whois[/yellow]"); return

    output_dir = os.path.join(target_base_path, "recon", "whois")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "whois_results.txt")
    console.print(f"Running whois for [blue]{target_identifier}[/blue] (using: {tool_path})...")
    try:
        process = subprocess.run([tool_path, target_identifier], capture_output=True, text=True, check=False, timeout=60)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"WHOIS results for: {target_identifier}\nCmd: {tool_path} {target_identifier}\n" + "="*30 + "\n")
            f.write(process.stdout)
            if process.stderr: f.write("\n\n---STDERR---\n" + process.stderr)
        console.print(f"[green]Whois results saved to: {output_file}[/green]")
    except Exception as e: console.print(f"[red]Error running whois: {e}[/red]")


def run_nmap(target_base_path: str):
    console.print("\n[cyan]Starting Nmap scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]"); return
    target_identifier = config["TARGET_IDENTIFIER"]

    tool_path = _get_tool_path("nmap", "Nmap")
    if not tool_path:
        console.print("[yellow]Nmap not found. Install: sudo apt install nmap[/yellow]"); return

    output_dir = os.path.join(target_base_path, "recon", "nmap")
    os.makedirs(output_dir, exist_ok=True)
    scan_options = {
        "1": {"name": "Quick Scan (-T4 -F)", "args": ["-T4", "-F"]},
        "2": {"name": "Basic TCP Full Port Scan (-p-)", "args": ["-p-"]},
        "3": {"name": "Service Version Detection Scan (-sV)", "args": ["-sV"]},
        "4": {"name": "Custom Scan", "args": None}
    }
    console.print("\n[bold]Select Nmap Scan Type:[/bold]")
    for key, val in scan_options.items():
        console.print(f"  [magenta][{key}][/magenta] {val['name']}" + (f" ([dim]{tool_path} {' '.join(val['args'])} {target_identifier}[/dim])" if val['args'] else ""))
    choice = Prompt.ask("Enter scan option", choices=scan_options.keys(), default="1")
    selected_scan_info = scan_options[choice]

    nmap_scan_args = selected_scan_info["args"]
    if not nmap_scan_args:
        custom_flags_str = Prompt.ask("Enter custom Nmap flags (e.g., -sS -A -O)")
        nmap_scan_args = custom_flags_str.split()

    slug = selected_scan_info['name'].lower().replace(" ", "_").replace("(-","").replace(")","").replace("-","") if choice != "4" else "custom"
    xml_out = os.path.join(output_dir, f"nmap_results_{slug}.xml")
    txt_out = os.path.join(output_dir, f"nmap_results_{slug}.txt")
    nmap_cmd = [tool_path] + nmap_scan_args + [target_identifier, "-oX", xml_out, "-oN", txt_out]

    console.print(f"\nRunning Nmap: [blue]{' '.join(nmap_cmd)}[/blue]")
    console.print("[yellow]Nmap scans can take time...[/yellow]")
    try:
        process = subprocess.run(nmap_cmd, capture_output=True, text=True, check=False, timeout=3600) # 1hr timeout
        if process.stdout: console.print(f"[dim]Nmap stdout:\n{process.stdout[:1000].strip()}...[/dim]")
        if process.stderr: console.print(f"[yellow]Nmap stderr:\n{process.stderr.strip()}[/yellow]")
        if os.path.exists(xml_out) and os.path.getsize(xml_out) > 0: console.print(f"[green]Nmap XML results: {xml_out}[/green]")
        else: console.print(f"[yellow]Nmap XML output not found/empty: {xml_out}[/yellow]")
        if os.path.exists(txt_out) and os.path.getsize(txt_out) > 0: console.print(f"[green]Nmap text results: {txt_out}[/green]")
        else: console.print(f"[yellow]Nmap text output not found/empty: {txt_out}[/yellow]")
    except Exception as e: console.print(f"[red]Error running Nmap: {e}[/red]")


def run_subdomain_enum(target_base_path: str):
    console.print("\n[cyan]Starting Subdomain Enumeration...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config: console.print("[red]No target in config.[/red]"); return
    target_domain = config["TARGET_IDENTIFIER"]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_domain):
        console.print(f"[yellow]Target {target_domain} is IP. Subdomain tools need a domain. Skipping.[/yellow]"); return

    output_dir = os.path.join(target_base_path, "recon", "subdomains")
    os.makedirs(output_dir, exist_ok=True)
    found_file = os.path.join(output_dir, "subdomains_found.txt")
    tool_used, cmd, tool_path = (None, None, None)

    tools_pref = [("amass", ["enum", "-d", target_domain]),
                  ("subfinder", ["-d", target_domain]),
                  ("sublist3r", ["-d", target_domain])] # sublist3r needs -o specified separately

    for tool_name, args in tools_pref:
        current_path = _get_tool_path(tool_name)
        if current_path:
            tool_used, tool_path = tool_name, current_path
            raw_out_file = os.path.join(output_dir, f"{tool_name}_output.txt")
            cmd = [tool_path] + args
            if tool_name in ["amass", "subfinder", "sublist3r"]: # These tools support -o
                cmd.extend(["-o", raw_out_file])
            console.print(f"Using {tool_name.capitalize()} (path: {tool_path}).")
            break
    if not tool_used: console.print("[yellow]No subdomain tool (Amass, Subfinder, Sublist3r) found/configured. Skipping.[/yellow]"); return

    console.print(f"Running: [blue]{' '.join(cmd)}[/blue]")
    console.print("[yellow]Subdomain enumeration can take time...[/yellow]")
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=1800)
        if process.stderr and process.returncode != 0: console.print(f"[yellow]{tool_used.capitalize()} stderr (RC {process.returncode}):\n[dim]{process.stderr}[/dim]")

        subdomains = set()
        # For tools with -o, raw_out_file should contain the list or detailed logs.
        if os.path.exists(raw_out_file):
            console.print(f"[green]{tool_used.capitalize()} raw output: {raw_out_file}[/green]")
            with open(raw_out_file, 'r', encoding='utf-8', errors='ignore') as f_in:
                for line in f_in:
                    line = line.strip()
                    if tool_used == "amass": # Amass -o output can be verbose, extract domain names
                        match = re.search(r'([a-zA-Z0-9_-]+\.)+' + re.escape(target_domain.split('.')[-2] + '.' + target_domain.split('.')[-1]), line) # Heuristic
                        if match: subdomains.add(match.group(0))
                    elif line and '.' in line and target_domain in line: # For subfinder/sublist3r -o is usually clean
                        subdomains.add(line)
        elif process.stdout: # Fallback to stdout if -o failed or tool doesn't use it as expected
            console.print(f"[dim]{tool_used.capitalize()} stdout parsing fallback.[/dim]")
            for line in process.stdout.splitlines():
                line = line.strip()
                if target_domain in line: subdomains.add(line)

        if subdomains:
            with open(found_file, 'w', encoding='utf-8') as f_out:
                for sub in sorted(list(subdomains)): f_out.write(sub + '\n')
            console.print(f"[green]{len(subdomains)} unique subdomains saved to: {found_file}[/green]")
        else: console.print(f"[yellow]No subdomains found/parsed by {tool_used}.[/yellow]")
    except Exception as e: console.print(f"[red]Error with {tool_used}: {e}[/red]")


def run_dir_bruteforce(target_base_path: str):
    console.print("\n[cyan]Starting Directory Brute-force Scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config: console.print("[red]No target in config.[/red]"); return
    target_identifier = config["TARGET_IDENTIFIER"]
    urls_to_scan = []
    if not target_identifier.startswith(("http://", "https://")):
        urls_to_scan.extend([f"http://{target_identifier}", f"https://{target_identifier}"])
    else: urls_to_scan.append(target_identifier)

    default_wl = get_config_value("wordlists.directory_bruteforce")
    if not (default_wl and os.path.exists(os.path.expanduser(default_wl))):
        system_wls = ["/usr/share/seclists/Discovery/Web-Content/common.txt", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"]
        default_wl = next((p for p in system_wls if os.path.exists(p)), None)

    wordlist_path = Prompt.ask("Enter path to wordlist for directory brute-forcing", default=os.path.expanduser(default_wl) if default_wl else None)
    if not wordlist_path or not os.path.exists(wordlist_path):
        console.print(f"[red]Wordlist not found: '{wordlist_path}'. Skipping.[/red]"); return

    tool_used, tool_path, cmd_template_args, specific_output_dir = None, None, [], None
    dir_tools = {"gobuster": ["dir", "-u", "{URL}", "-w", "{WORDLIST}", "-o", "{OUTPUT_FILE}", "-k", "--no-error"],
                 "dirsearch": ["-u", "{URL}", "-w", "{WORDLIST}", "--output={OUTPUT_FILE}"]}

    for name, args in dir_tools.items():
        path = _get_tool_path(name) or (name == "dirsearch" and _get_tool_path("dirsearch.py"))
        if path:
            tool_used, tool_path, cmd_template_args = name.replace(".py",""), path, args
            specific_output_dir = os.path.join(target_base_path, "recon", tool_used)
            console.print(f"Using {tool_used.capitalize()} (path: {tool_path}).")
            break
    if not tool_used: console.print("[yellow]Neither Gobuster nor Dirsearch found/configured. Skipping.[/yellow]"); return
    os.makedirs(specific_output_dir, exist_ok=True)

    for base_url in urls_to_scan:
        console.print(f"\nScanning URL: [blue]{base_url}[/blue] with {tool_used}")
        s_fn = base_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
        out_fp = os.path.join(specific_output_dir, f"{tool_used}_results_{s_fn}.txt")
        cmd = [tool_path] + [arg.replace("{URL}", base_url).replace("{WORDLIST}", wordlist_path).replace("{OUTPUT_FILE}", out_fp) for arg in cmd_template_args]
        console.print(f"Running: [dim]{' '.join(cmd)}[/dim]")
        console.print("[yellow]Directory brute-forcing can be very long...[/yellow]")
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=3600) # 1hr timeout
            if process.stderr and (process.returncode != 0 or "error" in process.stderr.lower() or tool_used != "gobuster"):
                console.print(f"[yellow]{tool_used.capitalize()} stderr for {base_url}:\n[dim]{process.stderr.strip()}[/dim]")
            if os.path.exists(out_fp) and os.path.getsize(out_fp) > 0: console.print(f"[green]Results for {base_url} saved to: {out_fp}[/green]")
            else:
                console.print(f"[yellow]Output file not found/empty for {base_url}: {out_fp}.[/yellow]")
                if process.stdout: console.print(f"[dim]{tool_used.capitalize()} stdout:\n{process.stdout.strip()}[/dim]")
        except Exception as e: console.print(f"[red]Error with {tool_used} for {base_url}: {e}[/red]")


def run_archive_scan(target_base_path: str):
    console.print("\n[cyan]Starting Wayback/Archive URL Scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config: console.print("[red]No target in config.[/red]"); return
    target_domain = config["TARGET_IDENTIFIER"]
    original_target = target_domain
    if target_domain.startswith(("http://", "https://")): target_domain = target_domain.split("://", 1)[1]
    if "/" in target_domain: target_domain = target_domain.split("/",1)[0]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_domain):
        console.print(f"[yellow]Target '{original_target}' is IP. Archive scan needs domain. Skipping.[/yellow]"); return

    output_dir = os.path.join(target_base_path, "recon", "wayback")
    os.makedirs(output_dir, exist_ok=True)
    tool_used, cmd, tool_path = (None, None, None)
    for name in ["gau", "waybackurls"]:
        path = _get_tool_path(name)
        if path:
            tool_used, tool_path, cmd = name, path, [path, target_domain]
            console.print(f"Using {name.capitalize()} (path: {path}).")
            break
    if not tool_used: console.print("[yellow]Neither GAU nor Waybackurls found/configured. Skipping.[/yellow]"); return

    raw_out_file = os.path.join(output_dir, f"archive_urls_raw_{tool_used}.txt")
    unique_out_file = os.path.join(output_dir, "archive_urls_unique.txt")
    console.print(f"Running: [blue]{' '.join(cmd)}[/blue]")
    console.print("[yellow]Archive scanning can take time...[/yellow]")
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=600)
        if process.stderr and process.returncode != 0: console.print(f"[yellow]{tool_used.capitalize()} stderr (RC {process.returncode}):\n[dim]{process.stderr}[/dim]")
        urls = set()
        if process.stdout:
            with open(raw_out_file, "w", encoding="utf-8") as f: f.write(process.stdout)
            console.print(f"[green]Raw {tool_used.capitalize()} output: {raw_out_file}[/green]")
            for line in process.stdout.splitlines():
                url = line.strip()
                if url: urls.add(url)
        if urls:
            with open(unique_out_file, "w", encoding="utf-8") as f:
                for url in sorted(list(urls)): f.write(url + "\n")
            console.print(f"[green]Found {len(urls)} unique URLs: {unique_out_file}[/green]")
        else: console.print(f"[yellow]No URLs found by {tool_used}.[/yellow]")
    except Exception as e: console.print(f"[red]Error with {tool_used}: {e}[/red]")


def run_httprobe(target_base_path: str):
    console.print("\n[cyan]Starting HTTP Probe (httprobe)...[/cyan]")
    tool_path = _get_tool_path("httprobe")
    if not tool_path: console.print("[yellow]httprobe not found/configured. Skipping. Install: go install -v github.com/tomnomnom/httprobe@latest[/yellow]"); return

    subdomains_file = os.path.join(target_base_path, "recon", "subdomains", "subdomains_found.txt")
    if not (os.path.exists(subdomains_file) and os.path.getsize(subdomains_file) > 0):
        console.print(f"[yellow]Subdomain list {subdomains_file} not found/empty. Run Subdomain Enumeration first. Skipping.[/yellow]"); return

    output_dir = os.path.join(target_base_path, "recon", "httprobe")
    os.makedirs(output_dir, exist_ok=True)
    live_hosts_file = os.path.join(output_dir, "live_hosts.txt")
    console.print(f"Probing subdomains from [blue]{subdomains_file}[/blue]...")
    console.print("[yellow]HTTP probing can take time...[/yellow]")
    try:
        with open(subdomains_file, 'r', encoding='utf-8') as f_in:
            subdomain_content = f_in.read()
        if not subdomain_content.strip(): console.print("[yellow]Subdomain file is empty. Skipping httprobe.[/yellow]"); return

        cmd = [tool_path, "-p", "http:80", "-p", "https:443", "-c", "50"] # Concurrency 50
        process = subprocess.run(cmd, input=subdomain_content, capture_output=True, text=True, check=False, timeout=600)

        if process.stderr and process.returncode != 0:
            if any(err_key in process.stderr.lower() for err_key in ["err", "ftl", "fail"]):
                console.print(f"[yellow]httprobe stderr (RC {process.returncode}):\n[dim]{process.stderr}[/dim]")
            elif process.stderr.strip(): console.print(f"[dim]httprobe info/debug (stderr):\n{process.stderr}[/dim]")

        if process.stdout and process.stdout.strip():
            with open(live_hosts_file, "w", encoding="utf-8") as f_out: f_out.write(process.stdout.strip() + "\n")
            console.print(f"[green]Live hosts saved to: {live_hosts_file}[/green]")
            console.print(f"Found {len(process.stdout.strip().splitlines())} live hosts.")
        else:
            with open(live_hosts_file, "w", encoding="utf-8") as f_out: f_out.write("") # Create empty file
            console.print(f"[yellow]No live hosts found by httprobe. Empty file created: {live_hosts_file}[/yellow]")
    except Exception as e: console.print(f"[red]Error with httprobe: {e}[/red]")


def run_tech_scan(target_base_path: str):
    console.print("\n[cyan]Starting Technology Stack Scan (WhatWeb)...[/cyan]")
    config = read_config(target_base_path) # To get main target if needed
    tool_path = _get_tool_path("whatweb", "WhatWeb")
    if not tool_path: console.print("[yellow]WhatWeb not found/configured. Skipping. Install: sudo apt install whatweb[/yellow]"); return

    targets = []
    live_hosts_file = os.path.join(target_base_path, "recon", "httprobe", "live_hosts.txt")
    if os.path.exists(live_hosts_file) and os.path.getsize(live_hosts_file) > 0:
        with open(live_hosts_file, 'r', encoding='utf-8') as f: targets = [line.strip() for line in f if line.strip()]
    if not targets and config and "TARGET_IDENTIFIER" in config:
        main_target = config["TARGET_IDENTIFIER"]
        console.print("[yellow]No live hosts from httprobe. Falling back to main target for WhatWeb.[/yellow]")
        targets.append(main_target if main_target.startswith(("http://","https://")) else f"http://{main_target}") # Whatweb needs scheme
    if not targets: console.print("[red]No targets for WhatWeb. Skipping.[/red]"); return

    output_dir = os.path.join(target_base_path, "recon", "whatweb")
    os.makedirs(output_dir, exist_ok=True)
    console.print(f"Found {len(targets)} target(s) for WhatWeb. Scanning can take time...")

    for target_url in targets:
        console.print(f"\nScanning [blue]{target_url}[/blue] with WhatWeb...")
        s_name = target_url.replace("http://","").replace("https://","").replace("/","_").replace(":","_")[:100]
        json_out = os.path.join(output_dir, f"whatweb_{s_name}.json")
        txt_out = os.path.join(output_dir, f"whatweb_{s_name}.txt")
        cmd = [tool_path, "--log-json", json_out, target_url]
        console.print(f"Running: [dim]{' '.join(cmd)}[/dim]")
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=300)
            if process.stdout:
                with open(txt_out, "w", encoding="utf-8") as f: f.write(f"WhatWeb text summary for: {target_url}\n{'='*30}\n{process.stdout}")
                console.print(f"[green]WhatWeb text summary: {txt_out}[/green]")
            if os.path.exists(json_out) and os.path.getsize(json_out) > 0: console.print(f"[green]WhatWeb JSON data: {json_out}[/green]")
            else:
                console.print(f"[yellow]WhatWeb JSON output not found/empty: {json_out}[/yellow]")
                if process.stdout and not os.path.exists(json_out): # Fallback if JSON failed
                    with open(json_out, "w", encoding="utf-8") as f_fall: f_fall.write(f"--- FALLBACK: STDOUT ---\n{process.stdout}")
            if process.stderr: console.print(f"[dim]WhatWeb stderr for {target_url}:\n{process.stderr.strip()}[/dim]")
        except Exception as e: console.print(f"[red]Error with WhatWeb for {target_url}: {e}[/red]")

def reconnaissance_menu(target_base_path: str):
    # ... (Menu structure unchanged, calls the above functions) ...
    while True:
        console.print("\n[bold green]--- Reconnaissance Menu ---[/bold green]")
        recon_options = {
            "1": "Run Whois Scan", "2": "Run Nmap Scan", "3": "Run Subdomain Enumeration",
            "4": "Run Directory Brute-force", "5": "Run Wayback/Archive Scan",
            "6": "Run HTTP Probe", "7": "Run Technology Stack Scan",
            "8": "Run All Recon Scans", "9": "Back to Main Menu"
        }
        for key, value in recon_options.items(): console.print(f"[magenta][{key}][/magenta] {value}")
        choice = Prompt.ask("Select a recon task", choices=list(recon_options.keys()), default="9")

        if choice == "1": run_whois(target_base_path)
        elif choice == "2": run_nmap(target_base_path)
        elif choice == "3": run_subdomain_enum(target_base_path)
        elif choice == "4": run_dir_bruteforce(target_base_path)
        elif choice == "5": run_archive_scan(target_base_path)
        elif choice == "6": run_httprobe(target_base_path)
        elif choice == "7": run_tech_scan(target_base_path)
        elif choice == "8":
            console.print("\n[blue]Running all reconnaissance scans...[/blue]")
            run_whois(target_base_path)
            run_nmap(target_base_path) # Interactive
            run_subdomain_enum(target_base_path)
            run_dir_bruteforce(target_base_path) # Interactive
            run_archive_scan(target_base_path)
            run_httprobe(target_base_path)
            run_tech_scan(target_base_path)
            console.print("\n[blue]All reconnaissance scans initiated/guidance displayed.[/blue]")
        elif choice == "9": break
        else: console.print("[red]Invalid option.[/red]")
>>>>>>> REPLACE
