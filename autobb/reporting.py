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

    # 2. Reconnaissance Findings (Placeholder - to be populated from recon/ files)
    report_content += "## Reconnaissance Findings\n"
    report_content += "*(Data from Whois, Nmap, Subdomains, Directories, Wayback, etc. will be summarized here)*\n"
    # Example: Iterate through recon folders and summarize key files
    recon_dir = os.path.join(target_base_path, "recon")
    if os.path.isdir(recon_dir):
        for tool_dir in os.listdir(recon_dir):
            tool_path = os.path.join(recon_dir, tool_dir)
            if os.path.isdir(tool_path):
                report_content += f"\n### {tool_dir.capitalize()} Findings:\n"
                # Look for primary output files, e.g., whois_results.txt
                # This is a simplified example; actual parsing would be more complex
                for item in os.listdir(tool_path):
                    if item.endswith(".txt") or item.endswith(".xml"): # Example file types
                        report_content += f"- Raw output: {os.path.join(tool_dir, item)}\n"
                        # In a real scenario, you'd read and summarize key points from these files.
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
