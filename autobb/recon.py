import os
import subprocess
import shutil # For checking if a command exists
import re # For IP checking and parsing
from rich.console import Console
from rich.prompt import Prompt
from .utils import read_config

console = Console()

def run_whois(target_base_path: str):
    console.print("\n[cyan]Starting Whois scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return
    target_identifier = config["TARGET_IDENTIFIER"]
    if not shutil.which("whois"):
        console.print("[yellow]whois command not found. Please install it (e.g., sudo apt install whois).[/yellow]")
        return
    whois_output_dir = os.path.join(target_base_path, "recon", "whois")
    os.makedirs(whois_output_dir, exist_ok=True)
    output_file = os.path.join(whois_output_dir, "whois_results.txt")
    try:
        console.print(f"Running whois for [blue]{target_identifier}[/blue]...")
        process = subprocess.run(["whois", target_identifier], capture_output=True, text=True, check=False)
        if process.returncode != 0 and process.stderr:
            console.print(f"[yellow]Whois command warning (exit code {process.returncode}):[/yellow][dim]{process.stderr}[/dim]")
        with open(output_file, "w") as f:
            f.write(f"WHOIS results for: {target_identifier}\n" + "="*30 + "\n" + process.stdout)
            if process.stderr:
                 f.write("\n" + "="*30 + " ERRORS/WARNINGS " + "="*30 + "\n" + process.stderr)
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            console.print(f"[green]Whois results saved to:[/green] {output_file}")
        else:
            console.print(f"[yellow]Whois command executed but output file is empty/not created.[/yellow]")
    except Exception as e:
        console.print(f"[red]An error occurred while running whois: {e}[/red]")


def run_nmap(target_base_path: str):
    console.print("\n[cyan]Starting Nmap scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return
    target_identifier = config["TARGET_IDENTIFIER"]
    if not shutil.which("nmap"):
        console.print("[yellow]nmap command not found. Please install it (e.g., sudo apt install nmap).[/yellow]")
        return
    nmap_output_dir = os.path.join(target_base_path, "recon", "nmap")
    os.makedirs(nmap_output_dir, exist_ok=True)
    scan_options = {
        "1": {"name": "Quick Scan (-T4 -F)", "command": ["nmap", "-T4", "-F"]},
        "2": {"name": "Basic TCP Full Port Scan (-p-)", "command": ["nmap", "-p-"]},
        "3": {"name": "Service Version Detection Scan (-sV)", "command": ["nmap", "-sV"]},
        "4": {"name": "Custom Scan", "command": None}
    }
    console.print("\n[bold]Select Nmap Scan Type:[/bold]")
    for key, val in scan_options.items():
        console.print(f"  [magenta][{key}][/magenta] {val['name']}" + (f" ([dim]{' '.join(val['command'])} {target_identifier}[/dim])" if val['command'] else ""))
    choice = Prompt.ask("Enter scan option", choices=scan_options.keys(), default="1")
    selected_scan = scan_options[choice]
    nmap_command_base = selected_scan["command"] if selected_scan["command"] else ["nmap"] + Prompt.ask("Enter custom Nmap flags (e.g., -sS -A -O)").split()
    scan_type_slug = selected_scan['name'].lower().replace(" ", "_").replace("(-","").replace(")","").replace("-","") if choice != "4" else "custom"

    xml_output_file = os.path.join(nmap_output_dir, f"nmap_results_{scan_type_slug}.xml")
    text_output_file = os.path.join(nmap_output_dir, f"nmap_results_{scan_type_slug}.txt")
    nmap_command = nmap_command_base + [target_identifier, "-oX", xml_output_file, "-oN", text_output_file]

    console.print(f"\nRunning Nmap scan: [blue]{' '.join(nmap_command)}[/blue]")
    console.print(f"[yellow]Nmap scans can take a while, please be patient...[/yellow]")
    try:
        process = subprocess.run(nmap_command, capture_output=True, text=True, check=False)
        if process.stdout: console.print(f"[dim]Nmap stdout:\n{process.stdout}[/dim]")
        if process.stderr: console.print(f"[yellow]Nmap stderr:\n{process.stderr}[/yellow]")
        if os.path.exists(xml_output_file) and os.path.getsize(xml_output_file) > 0:
            console.print(f"[green]Nmap XML results saved to:[/green] {xml_output_file}")
        else:
            console.print(f"[yellow]Nmap XML output file not found/empty: {xml_output_file}[/yellow]")
        if os.path.exists(text_output_file) and os.path.getsize(text_output_file) > 0:
            console.print(f"[green]Nmap text results saved to:[/green] {text_output_file}")
        else:
            console.print(f"[yellow]Nmap text output file not found/empty: {text_output_file}[/yellow]")
    except Exception as e:
        console.print(f"[red]An error occurred while running Nmap: {e}[/red]")


def run_subdomain_enum(target_base_path: str):
    console.print("\n[cyan]Starting Subdomain Enumeration...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return
    target_domain = config["TARGET_IDENTIFIER"]
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(target_domain):
        console.print(f"[yellow]Target {target_domain} is an IP. Subdomain tools need a domain. Skipping.[/yellow]")
        return
    subdomain_output_dir = os.path.join(target_base_path, "recon", "subdomains")
    os.makedirs(subdomain_output_dir, exist_ok=True)
    found_subdomains_file = os.path.join(subdomain_output_dir, "subdomains_found.txt")
    raw_output_file = ""
    tool_used, subdomain_command = (None, None)

    if shutil.which("amass"):
        tool_used, raw_output_file = "amass", os.path.join(subdomain_output_dir, "amass_output.txt")
        subdomain_command = ["amass", "enum", "-d", target_domain, "-o", raw_output_file]
        console.print("Using Amass for subdomain enumeration.")
    elif shutil.which("sublist3r"):
        tool_used, raw_output_file = "sublist3r", os.path.join(subdomain_output_dir, "sublist3r_output.txt")
        subdomain_command = ["sublist3r", "-d", target_domain, "-o", raw_output_file]
        console.print("Amass not found. Using Sublist3r.")
    elif shutil.which("subfinder"):
        tool_used, raw_output_file = "subfinder", os.path.join(subdomain_output_dir, "subfinder_output.txt")
        subdomain_command = ["subfinder", "-d", target_domain, "-o", raw_output_file]
        console.print("Amass & Sublist3r not found. Using Subfinder.")
    else:
        console.print("[yellow]Nessun tool di enumerazione sottodomini (Amass, Sublist3r, Subfinder) trovato.[/yellow]")
        return

    console.print(f"Running: [blue]{' '.join(subdomain_command)}[/blue]")
    console.print("[yellow]Subdomain enumeration can take time...[/yellow]")
    try:
        process = subprocess.run(subdomain_command, capture_output=True, text=True, check=False)
        if process.stderr and process.returncode != 0:
            console.print(f"[yellow]{tool_used.capitalize()} stderr (RC: {process.returncode}):[/yellow][dim]{process.stderr}[/dim]")

        subdomains = set()
        if os.path.exists(raw_output_file):
            console.print(f"[green]{tool_used.capitalize()} raw output: {raw_output_file}[/green]")
            with open(raw_output_file, 'r') as f_in:
                for line in f_in:
                    line = line.strip()
                    if tool_used == "amass": # Basic parsing for amass if -o is used for its log
                        parts = line.split()
                        potential_subdomain = parts[-1]
                        if target_domain in potential_subdomain: subdomains.add(potential_subdomain)
                    elif line and '.' in line: # For sublist3r/subfinder -o output
                        subdomains.add(line)
        elif process.stdout: # Fallback for tools that might not use -o as expected or if -o failed
            console.print(f"[dim]{tool_used.capitalize()} stdout parsing fallback.[/dim]")
            for line in process.stdout.splitlines():
                line = line.strip()
                if target_domain in line: subdomains.add(line) # very basic parsing

        if subdomains:
            with open(found_subdomains_file, 'w') as f_out:
                for sub in sorted(list(subdomains)): f_out.write(sub + '\n')
            console.print(f"[green]Unique subdomains saved to: {found_subdomains_file}[/green]")
        else:
            console.print(f"[yellow]No subdomains found/parsed by {tool_used}.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error during subdomain enumeration with {tool_used}: {e}[/red]")


def run_dir_bruteforce(target_base_path: str):
    console.print("\n[cyan]Starting Directory Brute-force Scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return
    target_identifier = config["TARGET_IDENTIFIER"]
    dir_brute_output_main_dir = os.path.join(target_base_path, "recon")

    urls_to_scan = []
    if not target_identifier.startswith(("http://", "https://")):
        urls_to_scan.extend([f"http://{target_identifier}", f"https://{target_identifier}"])
    else:
        urls_to_scan.append(target_identifier)

    common_wordlists = ["/usr/share/seclists/Discovery/Web-Content/common.txt", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"]
    default_wordlist = next((p for p in common_wordlists if os.path.exists(p)), None)
    wordlist_path = Prompt.ask("Enter path to wordlist", default=default_wordlist)
    if not wordlist_path or not os.path.exists(wordlist_path):
        console.print(f"[red]Wordlist not found: '{wordlist_path}'. Skipping.[/red]")
        return

    tool_used, cmd_template, specific_output_dir = (None, [], None)
    if shutil.which("gobuster"):
        tool_used = "gobuster"
        cmd_template = ["gobuster", "dir", "-u", "{URL}", "-w", wordlist_path, "-o", "{OUTPUT_FILE}", "-k", "--no-error"]
        specific_output_dir = os.path.join(dir_brute_output_main_dir, "gobuster")
        console.print("Using Gobuster.")
    elif shutil.which("dirsearch") or shutil.which("dirsearch.py"):
        tool_used = "dirsearch"
        dirsearch_exec = shutil.which("dirsearch") or shutil.which("dirsearch.py")
        cmd_template = [dirsearch_exec, "-u", "{URL}", "-w", wordlist_path, "--output={OUTPUT_FILE}"]
        specific_output_dir = os.path.join(dir_brute_output_main_dir, "dirsearch")
        console.print("Using Dirsearch.")
    else:
        console.print("[yellow]Neither Gobuster nor Dirsearch found. Skipping.[/yellow]")
        return
    os.makedirs(specific_output_dir, exist_ok=True)

    for base_url in urls_to_scan:
        console.print(f"\nScanning URL: [blue]{base_url}[/blue] with {tool_used}")
        sanitized_fn = base_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
        output_fp = os.path.join(specific_output_dir, f"{tool_used}_results_{sanitized_fn}.txt")
        current_cmd = [item.replace("{URL}", base_url).replace("{OUTPUT_FILE}", output_fp) for item in cmd_template]
        console.print(f"Running: [dim]{' '.join(current_cmd)}[/dim]")
        console.print("[yellow]Directory brute-forcing can be very long...[/yellow]")
        try:
            process = subprocess.run(current_cmd, capture_output=True, text=True, check=False)
            if process.stderr and (process.returncode != 0 or "error" in process.stderr.lower() or tool_used != "gobuster"):
                console.print(f"[yellow]{tool_used.capitalize()} stderr for {base_url}:[/yellow][dim]{process.stderr}[/dim]")
            if os.path.exists(output_fp) and os.path.getsize(output_fp) > 0:
                console.print(f"[green]Results for {base_url} saved to: {output_fp}[/green]")
            else:
                console.print(f"[yellow]Output file not found/empty for {base_url}: {output_fp}.[/yellow]")
                if process.stdout: console.print(f"[dim]{tool_used.capitalize()} stdout:\n{process.stdout}[/dim]")
        except Exception as e:
            console.print(f"[red]Error with {tool_used} for {base_url}: {e}[/red]")


def run_archive_scan(target_base_path: str):
    console.print("\n[cyan]Starting Wayback/Archive URL Scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return
    target_domain = config["TARGET_IDENTIFIER"]
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    original_target = target_domain # Save original for messages
    if target_domain.startswith(("http://", "https://")): # Strip scheme
        target_domain = target_domain.split("://", 1)[1]
    if "/" in target_domain: # Strip path
        target_domain = target_domain.split("/",1)[0]
    if ip_pattern.match(target_domain):
        console.print(f"[yellow]Target '{original_target}' resolved to IP '{target_domain}'. Archive scan needs a domain. Skipping.[/yellow]")
        return

    wayback_output_dir = os.path.join(target_base_path, "recon", "wayback")
    os.makedirs(wayback_output_dir, exist_ok=True)
    tool_used, archive_command = (None, None)
    raw_fn_template = "archive_urls_raw_{tool}.txt"
    unique_fn = "archive_urls_unique.txt"

    if shutil.which("gau"):
        tool_used = "gau"
        archive_command = ["gau", target_domain]
        console.print("Using GAU (Get All URLs).")
    elif shutil.which("waybackurls"):
        tool_used = "waybackurls"
        archive_command = ["waybackurls", target_domain]
        console.print("GAU not found. Using waybackurls.")
    else:
        console.print("[yellow]Neither GAU nor waybackurls found. Skipping archive scan.[/yellow]")
        return

    raw_output_file = os.path.join(wayback_output_dir, raw_fn_template.format(tool=tool_used))
    unique_output_file_path = os.path.join(wayback_output_dir, unique_fn)

    console.print(f"Running: [blue]{' '.join(archive_command)}[/blue]")
    console.print("[yellow]Archive scanning can take some time...[/yellow]")
    try:
        process = subprocess.run(archive_command, capture_output=True, text=True, check=False, timeout=600)
        if process.stderr and process.returncode != 0:
            console.print(f"[yellow]{tool_used.capitalize()} stderr (RC {process.returncode}):[/yellow][dim]{process.stderr}[/dim]")

        urls_found = set()
        if process.stdout:
            with open(raw_output_file, "w") as f_raw: f_raw.write(process.stdout)
            console.print(f"[green]Raw {tool_used.capitalize()} output: {raw_output_file}[/green]")
            for line in process.stdout.splitlines():
                url = line.strip()
                if url: urls_found.add(url)
            if urls_found:
                with open(unique_output_file_path, "w") as f_unique:
                    for url in sorted(list(urls_found)): f_unique.write(url + "\n")
                console.print(f"[green]Unique URLs ({len(urls_found)}) saved to: {unique_output_file_path}[/green]")
            else:
                console.print(f"[yellow]No URLs found by {tool_used}.[/yellow]")
        else:
            console.print(f"[yellow]No output (stdout) from {tool_used}.[/yellow]")
    except subprocess.TimeoutExpired:
        console.print(f"[red]{tool_used.capitalize()} timed out (10 min).[/red]")
    except Exception as e:
        console.print(f"[red]Error during archive scan with {tool_used}: {e}[/red]")


def run_httprobe(target_base_path: str):
    console.print("\n[cyan]Starting HTTP Probe (httprobe)...[/cyan]")

    config = read_config(target_base_path) # Needed for target_identifier for context if required later
    if not config or "TARGET_IDENTIFIER" not in config: # Though not directly used for httprobe cmd
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return

    if not shutil.which("httprobe"):
        console.print("[yellow]httprobe command not found. Please install it to use this feature.[/yellow]")
        console.print("e.g., [dim]go install -v github.com/tomnomnom/httprobe@latest[/dim]")
        return

    subdomains_file_path = os.path.join(target_base_path, "recon", "subdomains", "subdomains_found.txt")
    if not os.path.exists(subdomains_file_path) or os.path.getsize(subdomains_file_path) == 0:
        console.print(f"[yellow]Subdomain list not found or empty at {subdomains_file_path}.[/yellow]")
        console.print("[yellow]Please run Subdomain Enumeration first to generate a list of subdomains to probe.[/yellow]")
        console.print("[yellow]Skipping HTTP Probe.[/yellow]")
        return

    httprobe_output_dir = os.path.join(target_base_path, "recon", "httprobe")
    os.makedirs(httprobe_output_dir, exist_ok=True)
    live_hosts_file = os.path.join(httprobe_output_dir, "live_hosts.txt")

    # httprobe typically takes input from stdin.
    # Command: cat subdomains_found.txt | httprobe
    # We can achieve this by passing the content of subdomains_file_path as stdin to httprobe.

    console.print(f"Probing subdomains from: [blue]{subdomains_file_path}[/blue]")
    console.print(f"Live hosts will be saved to: [blue]{live_hosts_file}[/blue]")
    console.print("[yellow]HTTP probing can take some time...[/yellow]")

    try:
        with open(subdomains_file_path, 'r') as f_subdomains:
            subdomain_content = f_subdomains.read()

        if not subdomain_content.strip():
            console.print(f"[yellow]Subdomain file {subdomains_file_path} is empty after reading. Skipping httprobe.[/yellow]")
            return

        # httprobe command. Adding -p http:80,https:443 to be explicit, though it's often default.
        # Can also add -c for concurrency, e.g., -c 50
        httprobe_command = ["httprobe", "-p", "http:80", "-p", "https:443"]

        process = subprocess.run(
            httprobe_command,
            input=subdomain_content, # Pass content as stdin
            capture_output=True,
            text=True,
            check=False, # httprobe might exit non-zero if no hosts are live
            timeout=600 # 10 minute timeout
        )

        if process.stderr and process.returncode != 0 : # httprobe might print "INF" messages to stderr
            is_error = False
            for line in process.stderr.splitlines():
                if "ERR" in line or "FTL" in line or "failed" in line.lower(): # Check for actual error keywords
                    is_error = True
                    break
            if is_error:
                console.print(f"[yellow]httprobe stderr (Return Code: {process.returncode}):[/yellow]")
                console.print(f"[dim]{process.stderr}[/dim]")
            elif process.stderr.strip(): # Print if there's other non-error stderr
                 console.print(f"[dim]httprobe info/debug (stderr):\n{process.stderr}[/dim]")


        if process.stdout:
            live_hosts_output = process.stdout.strip()
            if live_hosts_output:
                with open(live_hosts_file, "w") as f_live:
                    f_live.write(live_hosts_output + "\n") # Ensure newline at end
                console.print(f"[green]Live hosts saved to: {live_hosts_file}[/green]")
                console.print(f"Found {len(live_hosts_output.splitlines())} live hosts.")
            else:
                console.print("[yellow]No live hosts found by httprobe from the provided subdomains.[/yellow]")
                # Create an empty file to signify the scan ran but found nothing
                with open(live_hosts_file, "w") as f_live:
                    f_live.write("")
                console.print(f"[dim]Empty live_hosts.txt created at {live_hosts_file}[/dim]")
        else:
            console.print("[yellow]No output (stdout) from httprobe.[/yellow]")
             # Create an empty file to signify the scan ran but found nothing
            with open(live_hosts_file, "w") as f_live:
                f_live.write("")
            console.print(f"[dim]Empty live_hosts.txt created at {live_hosts_file}[/dim]")


    except FileNotFoundError: # For httprobe itself
        console.print("[red]httprobe command not found. This should have been caught by shutil.which earlier.[/red]")
    except subprocess.TimeoutExpired:
        console.print("[red]httprobe command timed out (10 minutes).[/red]")
    except Exception as e:
        console.print(f"[red]An error occurred during HTTP probing with httprobe:[/red] {e}")


def run_tech_scan(target_base_path: str):
    console.print("\n[cyan]Starting Technology Stack Scan (whatweb)...[/cyan]")

    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return

    if not shutil.which("whatweb"):
        console.print("[yellow]whatweb command not found. Please install it to use this feature.[/yellow]")
        console.print("e.g., [dim]sudo apt install whatweb[/dim]")
        return

    targets_to_scan = []
    live_hosts_file_path = os.path.join(target_base_path, "recon", "httprobe", "live_hosts.txt")

    if os.path.exists(live_hosts_file_path) and os.path.getsize(live_hosts_file_path) > 0:
        console.print(f"Reading live hosts from [blue]{live_hosts_file_path}[/blue]")
        with open(live_hosts_file_path, 'r') as f:
            targets_to_scan = [line.strip() for line in f if line.strip()]
        if not targets_to_scan:
            console.print(f"[yellow]Live hosts file {live_hosts_file_path} was empty after reading.[/yellow]")

    if not targets_to_scan: # Fallback or if file was empty
        console.print("[yellow]No live hosts found from httprobe. Falling back to main target identifier.[/yellow]")
        main_target = config["TARGET_IDENTIFIER"]
        # WhatWeb can often handle plain domains, but providing scheme can be more reliable.
        if not main_target.startswith(("http://", "https://")):
            # We don't know if it's http or https, whatweb might try both or default to http.
            # For safety, we could try to add http if no scheme, or let whatweb handle it.
            # Whatweb is generally good at figuring this out.
            targets_to_scan.append(main_target)
            # Optionally, could try adding both http and https versions if it's just a domain
            # targets_to_scan.append(f"http://{main_target}")
            # targets_to_scan.append(f"https://{main_target}")
        else:
            targets_to_scan.append(main_target)

        if not targets_to_scan: # Should not happen if main_target is always present
            console.print("[red]No targets to scan for technology stack (main target also missing/invalid). Skipping.[/red]")
            return
        console.print(f"Scanning main target: {targets_to_scan}")


    whatweb_output_dir = os.path.join(target_base_path, "recon", "whatweb")
    os.makedirs(whatweb_output_dir, exist_ok=True)

    console.print(f"Found {len(targets_to_scan)} target(s) for WhatWeb scan.")
    console.print("[yellow]Technology scanning can take some time depending on the number of targets...[/yellow]")

    for target_url in targets_to_scan:
        console.print(f"\nScanning target: [blue]{target_url}[/blue] with WhatWeb")

        # Sanitize URL for filename
        sanitized_target_name = target_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
        # Limit filename length if necessary
        max_fn_len = 100
        if len(sanitized_target_name) > max_fn_len:
            sanitized_target_name = sanitized_target_name[:max_fn_len]

        output_json_file = os.path.join(whatweb_output_dir, f"whatweb_{sanitized_target_name}.json")
        # Whatweb also has a verbose plain text output by default, which can be useful too.
        # We'll capture that via stdout and save it.
        output_text_file = os.path.join(whatweb_output_dir, f"whatweb_{sanitized_target_name}.txt")


        # Command: whatweb --log-json <file.json> <target>
        # We will also capture stdout for a simple text log.
        # WhatWeb's --log-object / --log-brief / --log-xml / --log-json-verbose are other options.
        # --log-json is a good balance for parseable structured data.

        whatweb_command = ["whatweb", "--log-json", output_json_file, target_url]
        # Add --color=never, --no-errors for cleaner stdout if we decide to save it more formally.
        # For now, stdout is just for console display.

        console.print(f"Running: [dim]{' '.join(whatweb_command)}[/dim]")

        try:
            process = subprocess.run(
                whatweb_command,
                capture_output=True,
                text=True,
                check=False,
                timeout=300
            )

            # WhatWeb with --log-json outputs JSON to the specified file.
            # Its stdout will contain a human-readable summary.
            if process.stdout:
                with open(output_text_file, "w", encoding="utf-8") as f_text:
                    f_text.write(f"WhatWeb text summary for: {target_url}\n")
                    f_text.write("="*30 + "\n")
                    f_text.write(process.stdout) # Save human-readable summary
                console.print(f"[green]WhatWeb text summary saved to: {output_text_file}[/green]")
            else:
                console.print(f"[yellow]No text summary (stdout) from WhatWeb for {target_url}.[/yellow]")

            # Verify JSON output file creation from --log-json
            if os.path.exists(output_json_file) and os.path.getsize(output_json_file) > 0:
                console.print(f"[green]WhatWeb JSON data saved to: {output_json_file}[/green]")
            else:
                # This case means --log-json might have failed or produced empty output.
                console.print(f"[yellow]WhatWeb JSON output file not found or empty for {target_url} at {output_json_file}.[/yellow]")
                # Try to write stdout to the JSON file's intended path if JSON failed but stdout has content,
                # though this isn't ideal as it won't be JSON.
                if process.stdout and not os.path.exists(output_json_file): # only if json file truly missing
                    console.print(f"[dim]Saving stdout to {output_json_file} as a fallback text log.[/dim]")
                    with open(output_json_file, "w", encoding="utf-8") as f_json_fallback:
                         f_json_fallback.write("--- FALLBACK: STDOUT (JSON generation failed) ---\n")
                         f_json_fallback.write(process.stdout)


            if process.stderr:
                console.print(f"[dim]WhatWeb stderr for {target_url}:\n{process.stderr}[/dim]")

        except FileNotFoundError:
            console.print("[red]whatweb command not found. This should have been caught earlier.[/red]")
            break # Stop if whatweb is missing
        except subprocess.TimeoutExpired:
            console.print(f"[red]WhatWeb scan for {target_url} timed out (5 minutes).[/red]")
        except Exception as e:
            console.print(f"[red]An error occurred during WhatWeb scan for {target_url}:[/red] {e}")


def reconnaissance_menu(target_base_path: str):
    while True:
        console.print("\n[bold green]--- Reconnaissance Menu ---[/bold green]")
        recon_options = {
            "1": "Run Whois Scan",
            "2": "Run Nmap Scan",
            "3": "Run Subdomain Enumeration",
            "4": "Run Directory Brute-force",
            "5": "Run Wayback/Archive Scan",
            "6": "Run HTTP Probe",
            "7": "Run Technology Stack Scan",
            "8": "Run All Recon Scans",
            "9": "Back to Main Menu"
        }
        for key, value in recon_options.items():
            console.print(f"[magenta][{key}][/magenta] {value}")
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
            run_nmap(target_base_path)
            run_subdomain_enum(target_base_path)
            run_dir_bruteforce(target_base_path)
            run_archive_scan(target_base_path)
            run_httprobe(target_base_path)
            run_tech_scan(target_base_path)
            console.print("\n[blue]All reconnaissance scans initiated.[/blue]")
        elif choice == "9": break
        else: console.print("[red]Invalid option.[/red]")
