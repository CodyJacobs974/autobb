import os
from rich.console import Console
from .utils import read_config # Import from utils

console = Console()

# Helper function to read config (can be refactored to utils.py)
# def read_config_from_reporting(target_base_path: str) -> dict: # Removed
#     config_path = os.path.join(target_base_path, "config.txt")
#     config = {}
#     try:
#         with open(config_path, "r") as f:
#             for line in f:
#                 if "=" in line:
#                     key, value = line.strip().split("=", 1)
#                     config[key.strip()] = value.strip()
#     except FileNotFoundError:
#         console.print(f"[red]Error: Configuration file not found at {config_path}[/red]")
#         return None
#     except Exception as e:
#         console.print(f"[red]Error reading configuration file: {e}[/red]")
#         return None
#     return config

def generate_report(target_base_path: str):
    """
    Generates a bug bounty summary report.
    This is a placeholder and will be expanded to collect data from all stages.
    """
    console.print("\n[bold magenta]--- Generating Bug Bounty Summary Report ---[/bold magenta]")

    config = read_config(target_base_path) # Use read_config from utils
    if not config or "TARGET_IDENTIFIER" not in config or "TARGET_PATH" not in config:
        console.print("[red]Could not retrieve target identifier or path from config. Ensure config.txt exists and is valid.[/red]")
        return

    target_identifier = config["TARGET_IDENTIFIER"]
    report_path = os.path.join(config["TARGET_PATH"], "summary.txt") # Or report.md as per plan

    console.print(f"Target: {target_identifier}")
    console.print(f"Report will be saved to: {report_path}")

    report_content = f"# Bug Bounty Summary Report for: {target_identifier}\n\n"

    # 1. Scope Summary (Placeholder)
    report_content += "## Scope Summary\n"
    report_content += f"- Target: {target_identifier}\n"
    report_content += "- Scope: (Details to be manually added or defined by engagement)\n\n"

    # 2. Reconnaissance Findings
    report_content += "## Reconnaissance Findings\n\n"

    recon_base_dir = os.path.join(target_base_path, "recon")

    # Whois
    report_content += "### Whois Information:\n"
    whois_file = os.path.join(recon_base_dir, "whois", "whois_results.txt")
    if os.path.exists(whois_file):
        report_content += f"- Full Whois report saved at: recon/whois/whois_results.txt\n"
        # Add a snippet?
        try:
            with open(whois_file, 'r') as f:
                snippet = "".join(f.readline() for _ in range(15)) # First 15 lines
            report_content += f"  Snippet:\n```\n{snippet.strip()}\n```\n"
        except Exception:
            report_content += "  (Could not read snippet)\n"
    else:
        report_content += "- No Whois data found.\n"
    report_content += "\n"

    # Nmap Scans
    report_content += "### Nmap Scans:\n"
    nmap_dir = os.path.join(recon_base_dir, "nmap")
    if os.path.isdir(nmap_dir) and any(os.scandir(nmap_dir)):
        nmap_files = [f for f in os.listdir(nmap_dir) if f.startswith("nmap_results_") and (f.endswith(".txt") or f.endswith(".xml"))]
        if nmap_files:
            for nf in sorted(list(set(f.split('.')[0] for f in nmap_files))): # Get unique base names
                report_content += f"- Scan results for '{nf}':\n"
                if os.path.exists(os.path.join(nmap_dir, f"{nf}.txt")):
                    report_content += f"  - Text output: recon/nmap/{nf}.txt\n"
                if os.path.exists(os.path.join(nmap_dir, f"{nf}.xml")):
                    report_content += f"  - XML output: recon/nmap/{nf}.xml\n"
                # TODO: Light parsing of XML/text for open ports summary
        else:
            report_content += "- No Nmap result files found in recon/nmap/.\n"
    else:
        report_content += "- Nmap scans not run or no results found.\n"
    report_content += "\n"

    # Subdomain Enumeration
    report_content += "### Subdomain Enumeration:\n"
    subdomains_found_file = os.path.join(recon_base_dir, "subdomains", "subdomains_found.txt")
    raw_subdomain_files = []
    subdomain_tools_dir = os.path.join(recon_base_dir, "subdomains")
    if os.path.isdir(subdomain_tools_dir):
        raw_subdomain_files = [f for f in os.listdir(subdomain_tools_dir) if "_output.txt" in f]

    if os.path.exists(subdomains_found_file) and os.path.getsize(subdomains_found_file) > 0:
        with open(subdomains_found_file, 'r') as f:
            num_subdomains = len(f.readlines())
        report_content += f"- Found {num_subdomains} unique subdomains. See: recon/subdomains/subdomains_found.txt\n"
    else:
        report_content += "- No unique subdomains list found.\n"
    if raw_subdomain_files:
        report_content += "- Raw tool outputs:\n"
        for rf in raw_subdomain_files:
            report_content += f"  - recon/subdomains/{rf}\n"
    else:
        report_content += "- No raw subdomain tool outputs found.\n"
    report_content += "\n"

    # Directory Brute-force
    report_content += "### Directory Brute-force:\n"
    gobuster_dir = os.path.join(recon_base_dir, "gobuster")
    dirsearch_dir = os.path.join(recon_base_dir, "dirsearch")
    dir_results_found = False
    if os.path.isdir(gobuster_dir) and any(os.scandir(gobuster_dir)):
        report_content += "- Gobuster results:\n"
        for f_name in os.listdir(gobuster_dir):
            report_content += f"  - recon/gobuster/{f_name}\n"
        dir_results_found = True
    if os.path.isdir(dirsearch_dir) and any(os.scandir(dirsearch_dir)):
        report_content += "- Dirsearch results:\n"
        for f_name in os.listdir(dirsearch_dir):
            report_content += f"  - recon/dirsearch/{f_name}\n"
        dir_results_found = True
    if not dir_results_found:
        report_content += "- No directory brute-force results found.\n"
    report_content += "\n"

    # Wayback/Archive Scan
    report_content += "### Wayback/Archive URLs:\n"
    archive_unique_file = os.path.join(recon_base_dir, "wayback", "archive_urls_unique.txt")
    archive_raw_files = []
    wayback_dir_path = os.path.join(recon_base_dir, "wayback")
    if os.path.isdir(wayback_dir_path):
        archive_raw_files = [f for f in os.listdir(wayback_dir_path) if f.startswith("archive_urls_raw_")]

    if os.path.exists(archive_unique_file) and os.path.getsize(archive_unique_file) > 0:
        with open(archive_unique_file, 'r') as f:
            num_archive_urls = len(f.readlines())
        report_content += f"- Found {num_archive_urls} unique archived URLs. See: recon/wayback/archive_urls_unique.txt\n"
    else:
        report_content += "- No unique archived URLs list found.\n"
    if archive_raw_files:
        report_content += "- Raw tool outputs:\n"
        for rf in archive_raw_files:
            report_content += f"  - recon/wayback/{rf}\n"
    report_content += "\n"

    # HTTP Probe
    report_content += "### Live Hosts (HTTP Probe):\n"
    live_hosts_file = os.path.join(recon_base_dir, "httprobe", "live_hosts.txt")
    if os.path.exists(live_hosts_file) and os.path.getsize(live_hosts_file) > 0:
        with open(live_hosts_file, 'r') as f:
            num_live_hosts = len(f.readlines())
        report_content += f"- Found {num_live_hosts} live hosts. See: recon/httprobe/live_hosts.txt\n"
    else:
        report_content += "- No live hosts identified by httprobe or scan not run.\n"
    report_content += "\n"

    # Technology Stack Scan
    report_content += "### Technology Stack (WhatWeb):\n"
    whatweb_dir = os.path.join(recon_base_dir, "whatweb")
    whatweb_results_found = False
    if os.path.isdir(whatweb_dir) and any(os.scandir(whatweb_dir)):
        report_content += "- WhatWeb scan results:\n"
        for f_name in os.listdir(whatweb_dir):
            if f_name.endswith(".json") or f_name.endswith(".txt"):
                 report_content += f"  - recon/whatweb/{f_name}\n"
        whatweb_results_found = True
    if not whatweb_results_found:
        report_content += "- No WhatWeb scan results found.\n"
    report_content += "\n"

    # 3. Vulnerability Findings (Placeholder - to be populated from vulnerabilities/ files)
    report_content += "## Vulnerability Findings (Organized by Type)\n"
    report_content += "*(Details of discovered vulnerabilities, e.g., XSS, SQLi, SSRF, will be listed here)*\n"
    # Example: Iterate through vulnerabilities folders
    vuln_dir = os.path.join(target_base_path, "vulnerabilities")
    if os.path.isdir(vuln_dir):
        for vuln_type_dir in os.listdir(vuln_dir):
            vuln_type_path = os.path.join(vuln_dir, vuln_type_dir)
            if os.path.isdir(vuln_type_path):
                report_content += f"\n### {vuln_type_dir.upper()} Findings:\n"
                # List files or summaries from this directory
                for finding_file in os.listdir(vuln_type_path):
                     report_content += f"- Evidence: {os.path.join(vuln_type_dir, finding_file)}\n" # Simplified
    report_content += "\n"


    # 4. Proof of Concept (Placeholder)
    report_content += "## Proof of Concept (PoC)\n"
    report_content += "*(Each issue with reproduction steps will be detailed here)*\n"
    exploitation_dir = os.path.join(target_base_path, "exploitation")
    if os.path.isdir(exploitation_dir) and os.listdir(exploitation_dir):
         report_content += "*(Refer to files in the 'exploitation' directory for PoCs)*\n"
         for item in os.listdir(exploitation_dir):
             report_content += f"- {item}\n"
    else:
        report_content += "*(No PoCs found in exploitation directory or directory doesn't exist)*\n"
    report_content += "\n"


    # 5. Impact Assessment (Placeholder)
    report_content += "## Impact Assessment\n"
    report_content += "*(Assessment of the potential impact of discovered vulnerabilities)*\n\n"

    # 6. Remediation Suggestions (Placeholder)
    report_content += "## Remediation Suggestions\n"
    report_content += "*(Recommendations to fix the identified vulnerabilities)*\n\n"

    # 7. Screenshots / Logs / Headers (Placeholder)
    report_content += "## Supporting Evidence (Screenshots, Logs, Headers)\n"
    screenshots_dir = os.path.join(target_base_path, "screenshots")
    if os.path.isdir(screenshots_dir) and os.listdir(screenshots_dir):
        report_content += "*(Refer to files in the 'screenshots' directory)*\n"
        for item in os.listdir(screenshots_dir):
            report_content += f"- {item}\n"
    else:
        report_content += "*(No items found in screenshots directory or directory doesn't exist)*\n"
    report_content += "\n"

    try:
        with open(report_path, "w") as f:
            f.write(report_content)
        console.print(f"[green]Report generated successfully and saved to:[/green] {report_path}")
        console.print("Note: This is a basic report. Detailed findings need to be populated from tool outputs and manual analysis.")
    except IOError as e:
        console.print(f"[red]Error saving report:[/red] {e}")
    except Exception as e:
        console.print(f"[red]An unexpected error occurred during report generation:[/red] {e}")

# Example: generate_report("/path/to/target_folder_name")
# This function would be called from main.py
