import os
import re
import shutil
import subprocess
from rich.console import Console
from rich.prompt import Prompt
from .utils import read_config
from autobb.config_manager import get_config_value

console = Console()

def _get_tool_path(tool_name: str, friendly_name: str = None) -> str:
    if not friendly_name: friendly_name = tool_name.capitalize()
    configured_path = get_config_value(f"tool_paths.{tool_name.lower()}")
    if configured_path:
        expanded_path = os.path.expanduser(configured_path)
        if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
            console.print(f"[dim]Using configured path for {friendly_name}: {expanded_path}[/dim]")
            return expanded_path
        else:
            console.print(f"[yellow]Warning: Configured path for {friendly_name} ('{configured_path}') is invalid. Trying PATH.[/yellow]")
    return shutil.which(tool_name)

def _get_default_tool_options(tool_name: str) -> list:
    options_str = get_config_value(f"default_tool_options.{tool_name.lower()}")
    if options_str and isinstance(options_str, str):
        # console.print(f"[dim]Using default options for {tool_name} from config: {options_str}[/dim]")
        return options_str.split()
    return []

def run_whois(target_base_path: str):
    console.print("\n[cyan]Starting Whois scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]"); return
    target_identifier = config["TARGET_IDENTIFIER"]
    tool_path = _get_tool_path("whois")
    if not tool_path:
        console.print("[yellow]whois not found. Install: sudo apt install whois[/yellow]"); return
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
    if not config or "TARGET_IDENTIFIER" not in config: console.print("[red]No target in config.[/red]"); return
    target_identifier = config["TARGET_IDENTIFIER"]
    tool_path = _get_tool_path("nmap", "Nmap")
    if not tool_path: console.print("[yellow]Nmap not found. Install: sudo apt install nmap[/yellow]"); return

    output_dir = os.path.join(target_base_path, "recon", "nmap")
    os.makedirs(output_dir, exist_ok=True)

    default_nmap_opts = _get_default_tool_options("nmap")

    scan_options_map = {
        "1": {"name": "Quick Scan", "args": ["-T4", "-F"]},
        "2": {"name": "Basic TCP Full Port Scan", "args": ["-p-"]},
        "3": {"name": "Service Version Detection Scan", "args": ["-sV"]},
        "4": {"name": "Custom Scan", "args": []}
    }
    console.print("\n[bold]Select Nmap Scan Type:[/bold]")
    for key, val in scan_options_map.items():
        preview_cmd_parts = [tool_path] + default_nmap_opts + val['args'] + [target_identifier] if val['args'] else [tool_path] + default_nmap_opts + ["[custom_flags]"] + [target_identifier]
        console.print(f"  [magenta][{key}][/magenta] {val['name']}" + (f" ([dim]{' '.join(preview_cmd_parts)}[/dim])" if val['name'] != "Custom Scan" else ""))

    choice = Prompt.ask("Enter scan option", choices=scan_options_map.keys(), default="1")
    selected_scan_info = scan_options_map[choice]

    nmap_scan_specific_args = selected_scan_info["args"]
    if choice == "4":
        custom_flags_str = Prompt.ask("Enter ALL custom Nmap flags (e.g., -sS -A -O). Global defaults will NOT be applied for custom scan.")
        nmap_scan_specific_args = custom_flags_str.split()
        final_nmap_args = nmap_scan_specific_args
    else:
        final_nmap_args = default_nmap_opts + nmap_scan_specific_args

    slug = selected_scan_info['name'].lower().replace(" ", "_").replace("-","").replace("(","").replace(")","") if choice != "4" else "custom"
    xml_out = os.path.join(output_dir, f"nmap_results_{slug}.xml")
    txt_out = os.path.join(output_dir, f"nmap_results_{slug}.txt")

    nmap_cmd = [tool_path] + final_nmap_args + [target_identifier, "-oX", xml_out, "-oN", txt_out]

    console.print(f"\nRunning Nmap: [blue]{' '.join(nmap_cmd)}[/blue]")
    try:
        process = subprocess.run(nmap_cmd, capture_output=True, text=True, check=False, timeout=3600)
        if process.stdout: console.print(f"[dim]Nmap stdout:\n{process.stdout[:1000].strip()}...[/dim]")
        if process.stderr: console.print(f"[yellow]Nmap stderr:\n{process.stderr.strip()}[/yellow]")
        if os.path.exists(xml_out) and os.path.getsize(xml_out) > 0: console.print(f"[green]Nmap XML results: {xml_out}[/green]")
        else: console.print(f"[yellow]Nmap XML output not found/empty: {xml_out}[/yellow]")
        if os.path.exists(txt_out) and os.path.getsize(txt_out) > 0: console.print(f"[green]Nmap text results: {txt_out}[/green]")
        else: console.print(f"[yellow]Nmap text output not found/empty: {txt_out}[/yellow]")
    except Exception as e: console.print(f"[red]Error running Nmap: {e}[/red]")


def run_subdomain_enum(target_base_path: str):
    console.print("\n[cyan]Starting Subdomain Enumeration...[/cyan]")
    # Actual implementation for subdomain enumeration tools (amass, subfinder, sublist3r)
    # This is a placeholder; specific tool logic would go here.
    console.print("[dim]Subdomain enumeration logic would execute here (e.g., calling amass, subfinder).[/dim]")
    Prompt.ask("Press Enter to simulate completion...")


def run_dir_bruteforce(target_base_path: str):
    console.print("\n[cyan]Starting Directory Brute-force Scan...[/cyan]")
    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config: console.print("[red]No target in config.[/red]"); return
    target_identifier = config["TARGET_IDENTIFIER"]
    urls_to_scan = []
    if not target_identifier.startswith(("http://", "https://")):
        protocol_choice = Prompt.ask(f"Target '{target_identifier}' has no protocol. Scan HTTP, HTTPS, or both?", choices=["http", "https", "both"], default="both")
        if protocol_choice == "http": urls_to_scan.append(f"http://{target_identifier}")
        elif protocol_choice == "https": urls_to_scan.append(f"https://{target_identifier}")
        else: urls_to_scan.extend([f"http://{target_identifier}", f"https://{target_identifier}"])
    else: urls_to_scan.append(target_identifier)

    wordlist_path_config = get_config_value("wordlists.directory_bruteforce")
    wordlist_path = Prompt.ask("Enter path to wordlist for directory brute-force", default=os.path.expanduser(wordlist_path_config) if wordlist_path_config else "")

    if not wordlist_path or not os.path.exists(wordlist_path):
        console.print(f"[red]Wordlist not found at '{wordlist_path}' or not provided. Skipping directory brute-force.[/red]")
        return

    tool_used_name, tool_path, cmd_template_args_only, specific_output_dir = None, None, [], None
    dir_tools_map = {
        "gobuster": ["dir", "-u", "{URL}", "-w", "{WORDLIST}", "-o", "{OUTPUT_FILE}", "-k", "--no-error"],
        "dirsearch": ["-u", "{URL}", "-w", "{WORDLIST}", "--output={OUTPUT_FILE}", "--force-recursive"] # Example, adjust as needed
    }

    available_tools = {name: _get_tool_path(name) for name in dir_tools_map if _get_tool_path(name)}
    if not available_tools:
        console.print("[yellow]Neither Gobuster nor Dirsearch found/configured. Skipping directory brute-force.[/yellow]"); return

    tool_choice = Prompt.ask("Choose tool for directory brute-force", choices=list(available_tools.keys()), default=list(available_tools.keys())[0])
    tool_used_name = tool_choice
    tool_path = available_tools[tool_used_name]
    cmd_template_args_only = dir_tools_map[tool_used_name]
    specific_output_dir = os.path.join(target_base_path, "recon", tool_used_name)
    console.print(f"Using {tool_used_name.capitalize()} (path: {tool_path}).")
    os.makedirs(specific_output_dir, exist_ok=True)

    default_opts_for_tool = _get_default_tool_options(tool_used_name)

    for base_url in urls_to_scan:
        console.print(f"\nScanning URL: [blue]{base_url}[/blue] with {tool_used_name}")
        s_fn = base_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
        out_fp = os.path.join(specific_output_dir, f"{tool_used_name}_results_{s_fn}.txt")

        current_cmd_specific_args = [arg.replace("{URL}", base_url).replace("{WORDLIST}", wordlist_path).replace("{OUTPUT_FILE}", out_fp) for arg in cmd_template_args_only]
        cmd = [tool_path] + default_opts_for_tool + current_cmd_specific_args

        console.print(f"Running: [dim]{' '.join(cmd)}[/dim]")
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=3600)
            # Basic output handling, can be expanded
            if process.stdout: console.print(f"[dim]Output (first 500 chars):\n{process.stdout[:500]}[/dim]")
            if process.stderr: console.print(f"[yellow]Stderr:\n{process.stderr[:500]}[/yellow]")
            console.print(f"[green]Scan for {base_url} complete. Results (if any) in {out_fp}[/green]")
        except Exception as e: console.print(f"[red]Error with {tool_used_name} for {base_url}: {e}[/red]")


def run_archive_scan(target_base_path: str):
    console.print("\n[cyan]Starting Wayback/Archive URL Scan...[/cyan]")
    console.print("[dim]Archive scan logic (gau, waybackurls) would execute here.[/dim]")
    Prompt.ask("Press Enter to simulate completion...")


def run_httprobe(target_base_path: str):
    console.print("\n[cyan]Starting HTTP Probe (httprobe)...[/cyan]")
    tool_path = _get_tool_path("httprobe")
    if not tool_path: console.print("[yellow]httprobe not found/configured. Skipping.[/yellow]"); return
    default_opts = _get_default_tool_options("httprobe")
    console.print(f"[dim]httprobe logic with tool path '{tool_path}' and defaults '{' '.join(default_opts)}' would run here.[/dim]")
    Prompt.ask("Press Enter to simulate completion...")


def run_tech_scan(target_base_path: str):
    console.print("\n[cyan]Starting Technology Stack Scan (WhatWeb)...[/cyan]")
    tool_path = _get_tool_path("whatweb", "WhatWeb")
    if not tool_path: console.print("[yellow]WhatWeb not found/configured. Skipping.[/yellow]"); return
    default_opts = _get_default_tool_options("whatweb")
    console.print(f"[dim]WhatWeb logic with tool path '{tool_path}' and defaults '{' '.join(default_opts)}' would run here.[/dim]")
    Prompt.ask("Press Enter to simulate completion...")


def reconnaissance_menu(target_base_path: str):
    """Displays the reconnaissance menu and handles user choices."""
    while True:
        console.print("\n[bold blue]--- Reconnaissance Menu ---[/bold blue]")
        recon_options = {
            "1": "Whois Scan",
            "2": "Nmap Scan",
            "3": "Subdomain Enumeration",
            "4": "Directory Brute-force",
            "5": "Wayback/Archive Scan",
            "6": "HTTP Probe (Live Hosts)",
            "7": "Technology Scan (WhatWeb)",
            "8": "Run All Recon Scans",
            "9": "Back to Main Menu"
        }
        for key, value in recon_options.items():
            console.print(f"[magenta][{key}][/magenta] {value}")

        choice = Prompt.ask("Select a recon task", choices=list(recon_options.keys()), default="9")

        if choice == "1":
            run_whois(target_base_path)
        elif choice == "2":
            run_nmap(target_base_path)
        elif choice == "3":
            run_subdomain_enum(target_base_path)
        elif choice == "4":
            run_dir_bruteforce(target_base_path)
        elif choice == "5":
            run_archive_scan(target_base_path)
        elif choice == "6":
            run_httprobe(target_base_path)
        elif choice == "7":
            run_tech_scan(target_base_path)
        elif choice == "8":
            console.print("\n[blue]Running all reconnaissance scans...[/blue]")
            run_whois(target_base_path)
            run_nmap(target_base_path)
            run_subdomain_enum(target_base_path)
            run_httprobe(target_base_path)
            run_dir_bruteforce(target_base_path)
            run_archive_scan(target_base_path)
            run_tech_scan(target_base_path)
            console.print("\n[blue]All reconnaissance scans initiated.[/blue]")
        elif choice == "9":
            break
        else:
            console.print("[red]Invalid option selected.[/red]")
