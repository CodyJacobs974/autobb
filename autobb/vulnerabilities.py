import os
import re # For param name guessing in BAC, and IP check in SSRF
import shutil
import subprocess
from rich.console import Console
from rich.prompt import Prompt
from .utils import read_config

# Try to import requests, but don't make it a hard dependency if user just wants guidance.
try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

console = Console()

# --- Broken Access Control ---
def check_broken_access_control(target_base_path: str):
    console.print("\n[bold #FFD700]--- Testing for Broken Access Control (BAC) ---[/bold #FFD700]")
    config = read_config(target_base_path)
    target_identifier = config.get("TARGET_IDENTIFIER", "the target") if config else "the target"
    console.print(f"\n[italic]Target: {target_identifier}[/italic]")
    console.print("\n[bold u]Understanding Broken Access Control:[/bold u]")
    console.print("...") # Keep existing guidance
    bac_guidance = ["[cyan]1. Insecure Direct Object References (IDORs):[/cyan]",...] # Keep existing
    for line in bac_guidance: console.print(line) # Keep existing

    console.print("\n[bold #ADD8E6]--- Automated IDOR Fuzzing with FFuF ---[/bold #ADD8E6]")
    if not shutil.which("ffuf"):
        console.print("[yellow]ffuf not found. Skipping FFuF IDOR fuzzing.[/yellow]")
        return
    # ... (rest of existing ffuf logic for BAC - unchanged) ...
    # (idor_url prompt, wordlist prompt, ffuf_command, subprocess.run, output handling)
    # Example parts of existing ffuf logic:
    ffuf_output_dir = os.path.join(target_base_path, "vulnerabilities", "broken_access_control")
    os.makedirs(ffuf_output_dir, exist_ok=True)
    idor_url = Prompt.ask("Enter URL with 'FUZZ' for IDOR parameter (e.g., /items/FUZZ/details)")
    if not idor_url or "FUZZ" not in idor_url:
        console.print("[yellow]Invalid URL or FUZZ keyword missing. Skipping.[/yellow]")
        return
    id_wordlist = Prompt.ask("Enter path to wordlist for IDs", default=None)
    if not id_wordlist or not os.path.exists(id_wordlist):
        console.print(f"[red]ID wordlist not found: '{id_wordlist}'. Skipping.[/red]")
        return
    ffuf_extra_options_str = Prompt.ask("Additional ffuf options?", default="")
    ffuf_extra_options = ffuf_extra_options_str.split()
    param_name_guess = "idor" # Simplified
    output_filename = f"ffuf_idor_{param_name_guess}_{config.get('TARGET_IDENTIFIER','target').replace('http://','').replace('https://','').replace('/','_')}.txt"
    output_file_path = os.path.join(ffuf_output_dir, output_filename)
    ffuf_command = ["ffuf", "-w", id_wordlist, "-u", idor_url] + ffuf_extra_options + ["-o", output_file_path, "-of", "csv"]
    console.print(f"\nRunning FFuF: [blue]{' '.join(ffuf_command)}[/blue]")
    try:
        process = subprocess.run(ffuf_command, capture_output=True, text=True, check=False, timeout=600)
        if process.stdout and not any(opt in ["-silent", "-s"] for opt in ffuf_extra_options) : console.print(f"[dim]FFuF stdout:\n{process.stdout}[/dim]")
        if process.stderr: console.print(f"[yellow]FFuF stderr:\n{process.stderr}[/yellow]")
        if os.path.exists(output_file_path) and os.path.getsize(output_file_path) > 0: console.print(f"[green]FFuF results: {output_file_path}[/green]")
        else: console.print(f"[yellow]FFuF output file not found/empty: {output_file_path}[/yellow]")
    except Exception as e: console.print(f"[red]Error during FFuF IDOR scan: {e}[/red]")


# --- SQL Injection ---
def check_sql_injection(target_base_path: str):
    console.print("\n[bold #FF8C00]--- Testing for SQL Injection (SQLi) ---[/bold #FF8C00]")
    # ... (Keep existing SQLi guidance and SQLMap integration code - unchanged) ...
    # Example parts:
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding SQL Injection:[/bold u] ...")
    sqlmap_executable = shutil.which("sqlmap") or shutil.which("sqlmap.py")
    if not sqlmap_executable: console.print("[yellow]SQLMap not found. Skipping.[/yellow]"); return
    # ... (sqlmap URL prompt, options prompt, command construction, subprocess.run, output handling) ...


# --- Cross-Site Scripting (XSS) ---
def check_xss(target_base_path: str):
    console.print("\n[bold #D2691E]--- Testing for Cross-Site Scripting (XSS) ---[/bold #D2691E]")
    # ... (Keep existing XSS guidance and Dalfox/XSSer integration code - unchanged) ...
    # Example parts:
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding XSS:[/bold u] ...")
    dalfox_path = shutil.which("dalfox")
    if dalfox_path:
        # ... (dalfox URL prompt, options prompt, command construction, subprocess.run, output handling) ...
        pass # Placeholder for existing dalfox logic
    # ... (elif xsser_path, else no tools found) ...


# --- Command Injection ---
def check_command_injection(target_base_path: str):
    console.print("\n[bold #B22222]--- Testing for Command Injection ---[/bold #B22222]")
    # ... (Keep existing Command Injection guidance - unchanged) ...
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding Command Injection:[/bold u] ...")


# --- Server-Side Request Forgery (SSRF) ---
def check_ssrf(target_base_path: str):
    console.print("\n[bold #FF4500]--- Testing for Server-Side Request Forgery (SSRF) ---[/bold #FF4500]")
    # ... (Keep existing SSRF guidance - unchanged) ...
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding SSRF:[/bold u] ...")


# --- Server-Side Template Injection (SSTI) ---
def check_ssti(target_base_path: str):
    console.print("\n[bold #DA70D6]--- Testing for Server-Side Template Injection (SSTI) ---[/bold #DA70D6]")
    # ... (Keep existing SSTI guidance - unchanged) ...
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding SSTI:[/bold u] ...")


# --- Open Redirect ---
def check_open_redirect(target_base_path: str):
    console.print("\n[bold #008080]--- Testing for Open Redirect ---[/bold #008080]")
    # ... (Keep existing Open Redirect guidance - unchanged) ...
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding Open Redirect:[/bold u] ...")


# --- Insecure Deserialization ---
def check_insecure_deserialization(target_base_path: str):
    console.print("\n[bold #8B008B]--- Testing for Insecure Deserialization ---[/bold #8B008B]")
    # ... (Keep existing Insecure Deserialization guidance - unchanged) ...
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding Insecure Deserialization:[/bold u] ...")


# --- File Upload Vulnerabilities ---
def check_file_upload_vulns(target_base_path: str):
    console.print("\n[bold #2E8B57]--- Testing for File Upload Vulnerabilities ---[/bold #2E8B57]")
    # ... (Keep existing File Upload guidance - unchanged) ...
    config = read_config(target_base_path)
    console.print(f"\n[italic]Target context: {config.get('TARGET_IDENTIFIER', 'the target')}[/italic]")
    console.print("\n[bold u]Understanding File Upload Vulnerabilities:[/bold u] ...")


# --- Security Misconfigurations ---
def check_security_misconfigurations(target_base_path: str):
    console.print("\n[bold #6A5ACD]--- Testing for Security Misconfigurations ---[/bold #6A5ACD]")
    config = read_config(target_base_path)
    target_identifier_display = config.get("TARGET_IDENTIFIER", "the target") if config else "the target"
    console.print(f"\n[italic]Target context: {target_identifier_display}[/italic]")

    base_output_dir = os.path.join(target_base_path, "vulnerabilities", "security_misconfigurations")
    os.makedirs(base_output_dir, exist_ok=True)

    console.print("\n[bold u]Understanding Security Misconfigurations:[/bold u]")
    console.print("Security Misconfiguration covers issues like default credentials, unnecessary services, improper permissions, verbose errors, missing security headers, and outdated software.")

    targets_for_scans = []
    live_hosts_file = os.path.join(target_base_path, "recon", "httprobe", "live_hosts.txt")
    if os.path.exists(live_hosts_file) and os.path.getsize(live_hosts_file) > 0:
        with open(live_hosts_file, 'r') as f: targets_for_scans = [line.strip() for line in f if line.strip()]

    if not targets_for_scans and config and "TARGET_IDENTIFIER" in config:
        main_target_id = config["TARGET_IDENTIFIER"]
        if not main_target_id.startswith(("http://", "https://")):
            targets_for_scans.extend([f"http://{main_target_id}", f"https://{main_target_id}"])
        else:
            targets_for_scans.append(main_target_id)

    if not targets_for_scans: console.print("[yellow]No targets for Nikto/Nuclei/Headers scans.[/yellow]")
    else: console.print(f"[dim]Targets for scans: {targets_for_scans}[/dim]")

    # Nikto
    console.print("\n[bold #FF6347]--- Scanning with Nikto ---[/bold #FF6347]")
    nikto_path = shutil.which("nikto") or shutil.which("nikto.pl")
    if not nikto_path: console.print("[yellow]Nikto not found. Skipping.[/yellow]")
    elif not targets_for_scans: console.print("[yellow]No targets for Nikto.[/yellow]")
    else:
        nikto_output_dir = os.path.join(base_output_dir, "nikto")
        os.makedirs(nikto_output_dir, exist_ok=True)
        for target_url in targets_for_scans:
            console.print(f"\nScanning [blue]{target_url}[/blue] with Nikto...")
            from urllib.parse import urlparse
            parsed_url = urlparse(target_url)
            host, port, scheme = parsed_url.hostname, parsed_url.port, parsed_url.scheme
            if not host: console.print(f"[yellow]Invalid URL for Nikto: {target_url}. Skipping.[/yellow]"); continue

            sanitized_name = host.replace(".","_") + (f"_{port}" if port else "")
            output_file = os.path.join(nikto_output_dir, f"nikto_{sanitized_name}.txt")
            nikto_cmd = [nikto_path, "-h", host]
            if port: nikto_cmd.extend(["-p", str(port)])
            if scheme == "https": nikto_cmd.append("-ssl")
            nikto_cmd.extend(["-o", output_file, "-Format", "txt", "-Tuning", "x 6", "-ask", "no"]) # Added -ask no

            console.print(f"Running: [dim]{' '.join(nikto_cmd)}[/dim]")
            try:
                process = subprocess.run(nikto_cmd, capture_output=True, text=True, check=False, timeout=1800)
                if process.stdout: console.print(f"[dim]Nikto stdout (snippet):\n{process.stdout[:1000]}...[/dim]")
                if process.stderr: console.print(f"[yellow]Nikto stderr:\n{process.stderr}[/yellow]")
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0: console.print(f"[green]Nikto results: {output_file}[/green]")
                else: console.print(f"[yellow]Nikto output not found/empty: {output_file}[/yellow]")
            except Exception as e: console.print(f"[red]Error running Nikto for {target_url}: {e}[/red]")

    # Nuclei
    console.print("\n[bold #BA55D3]--- Scanning with Nuclei ---[/bold #BA55D3]")
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path: console.print("[yellow]Nuclei not found. Skipping.[/yellow]")
    elif not targets_for_scans: console.print("[yellow]No targets for Nuclei.[/yellow]")
    else:
        nuclei_output_dir = os.path.join(base_output_dir, "nuclei")
        os.makedirs(nuclei_output_dir, exist_ok=True)
        console.print("[cyan]Consider `nuclei -update-templates` regularly.[/cyan]")

        output_file_nuclei = os.path.join(nuclei_output_dir, "nuclei_results.txt")
        nuclei_cmd = [nuclei_path]
        temp_target_list_file = None

        if len(targets_for_scans) > 1:
            temp_target_list_file = os.path.join(nuclei_output_dir, "temp_nuclei_targets.txt")
            with open(temp_target_list_file, 'w') as f: f.write("\n".join(targets_for_scans))
            nuclei_cmd.extend(["-list", temp_target_list_file])
        else:
            nuclei_cmd.extend(["-u", targets_for_scans[0]])

        nuclei_user_opts_str = Prompt.ask("Additional Nuclei options? (e.g., -t cves/ -s critical,high)", default="-s critical,high,medium -etags \"dos,misc,tech-detect,fuzz\"")
        if nuclei_user_opts_str: nuclei_cmd.extend(nuclei_user_opts_str.split())
        nuclei_cmd.extend(["-o", output_file_nuclei])

        console.print(f"Running: [dim]{' '.join(nuclei_cmd)}[/dim]")
        try:
            process = subprocess.run(nuclei_cmd, capture_output=True, text=True, check=False, timeout=3600)
            if process.stdout: console.print(f"[dim]Nuclei stdout (snippet):\n{process.stdout[:2000]}...[/dim]")
            if process.stderr: console.print(f"[yellow]Nuclei stderr:\n{process.stderr}[/yellow]")
            if os.path.exists(output_file_nuclei) and os.path.getsize(output_file_nuclei) > 0: console.print(f"[green]Nuclei results: {output_file_nuclei}[/green]")
            else: console.print(f"[yellow]Nuclei output not found/empty: {output_file_nuclei}[/yellow]")
        except Exception as e: console.print(f"[red]Error running Nuclei: {e}[/red]")
        finally:
            if temp_target_list_file and os.path.exists(temp_target_list_file): os.remove(temp_target_list_file)

    # Security Headers Check
    console.print("\n[bold #20B2AA]--- Security Headers Check ---[/bold #20B2AA]")
    if not REQUESTS_AVAILABLE:
        console.print("[yellow]`requests` library not found. Skipping Python-based headers check. Install with `pip install requests`[/yellow]")
    elif not targets_for_scans: console.print("[yellow]No targets for Headers check.[/yellow]")
    else:
        headers_output_dir = os.path.join(base_output_dir, "headers_analysis")
        os.makedirs(headers_output_dir, exist_ok=True)
        common_sec_headers = {"Strict-Transport-Security":None, "Content-Security-Policy":None, "X-Content-Type-Options":"nosniff", "X-Frame-Options":["DENY","SAMEORIGIN"], "Referrer-Policy":None, "Permissions-Policy":None}

        for target_url in targets_for_scans:
            console.print(f"\nChecking headers for [blue]{target_url}[/blue]...")
            sanitized_name = target_url.replace("http://","").replace("https://","").replace("/","_").replace(":","_")
            headers_file = os.path.join(headers_output_dir, f"headers_{sanitized_name}.txt")
            report = [f"Headers for: {target_url}\n" + "="*30]
            try:
                res = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
                report.append(f"Final URL: {res.url}\nStatus: {res.status_code}\n\n[Detected Headers]")
                for h,v in res.headers.items(): report.append(f"  {h}: {v}")
                report.append("\n[Security Header Check]")
                for sech, exp_val in common_sec_headers.items():
                    val = res.headers.get(sech)
                    if val:
                        report.append(f"  [+] {sech}: {val} (Present)")
                        if isinstance(exp_val, str) and val.lower() != exp_val.lower(): report.append(f"    WARN: Expected '{exp_val}'")
                        elif isinstance(exp_val, list) and val.upper() not in exp_val: report.append(f"    WARN: Expected one of {exp_val}")
                    else: report.append(f"  [-] {sech} (Missing)")
            except Exception as e: report.append(f"  Error fetching/analyzing headers: {e}")

            # Print to console (simplified, without Rich for brevity here)
            console.print("\n".join(report).replace("[+]","[green][+][/green]").replace("[-]","[red][-][/red]").replace("WARN:","[yellow]WARN:[/yellow]"))
            with open(headers_file, "w") as f: f.write("\n".join(report)) # Write raw to file
            console.print(f"[green]Headers analysis saved to: {headers_file}[/green]")


# --- Main Vulnerability Analysis Menu ---
def vulnerability_analysis_menu(target_base_path: str):
    """Displays the vulnerability analysis menu and handles user choice."""
    # ... (Keep existing menu structure and calls - unchanged) ...
    # Example:
    while True:
        console.print("\n[bold yellow]--- Vulnerability Analysis Menu ---[/bold yellow]")
        vuln_options = {
            "1": "Broken Access Control", "2": "SQL Injection (SQLi)", "3": "Cross-Site Scripting (XSS)",
            "4": "Command Injection", "5": "Server-Side Request Forgery (SSRF)",
            "6": "Server-Side Template Injection (SSTI)", "7": "Open Redirect",
            "8": "Insecure Deserialization", "9": "File Upload Vulnerabilities",
            "10": "Security Misconfigurations", "11": "Run All (Placeholders)", "12": "Back to Main Menu"
        }
        for key, value in vuln_options.items(): console.print(f"[magenta][{key}][/magenta] {value}")
        choice = Prompt.ask("Select a task", choices=list(vuln_options.keys()), default="12")

        if choice == "1": check_broken_access_control(target_base_path)
        elif choice == "2": check_sql_injection(target_base_path)
        elif choice == "3": check_xss(target_base_path)
        elif choice == "4": check_command_injection(target_base_path)
        elif choice == "5": check_ssrf(target_base_path)
        elif choice == "6": check_ssti(target_base_path)
        elif choice == "7": check_open_redirect(target_base_path)
        elif choice == "8": check_insecure_deserialization(target_base_path)
        elif choice == "9": check_file_upload_vulns(target_base_path)
        elif choice == "10": check_security_misconfigurations(target_base_path)
        elif choice == "11": # Run all (placeholders for now, or actual calls)
            console.print("\n[blue]Running all vulnerability checks...[/blue]")
            check_broken_access_control(target_base_path)
            check_sql_injection(target_base_path) # This will prompt for URL
            check_xss(target_base_path) # This will prompt for URL
            check_command_injection(target_base_path)
            check_ssrf(target_base_path)
            check_ssti(target_base_path)
            check_open_redirect(target_base_path)
            check_insecure_deserialization(target_base_path)
            check_file_upload_vulns(target_base_path)
            check_security_misconfigurations(target_base_path) # This will run Nikto/Nuclei on targets
            console.print("\n[blue]All vulnerability checks initiated.[/blue]")
        elif choice == "12": break
        else: console.print("[red]Invalid option.[/red]")
