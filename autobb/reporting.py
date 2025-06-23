import os
import re # Added for dirsearch parsing & other regex needs
import xml.etree.ElementTree as ET # For Nmap XML parsing
import json # For Nuclei JSONL parsing
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
        nmap_file_basenames = sorted(list(set(
            f.split('.')[0] for f in os.listdir(nmap_dir)
            if f.startswith("nmap_results_") and (f.endswith(".txt") or f.endswith(".xml"))
        )))

        if nmap_file_basenames:
            for basename in nmap_file_basenames:
                report_content += f"- Scan results for '{basename}':\n"
                text_file_path = os.path.join(nmap_dir, f"{basename}.txt")
                xml_file_path = os.path.join(nmap_dir, f"{basename}.xml")

                if os.path.exists(text_file_path):
                    report_content += f"  - Text output: recon/nmap/{basename}.txt\n"
                if os.path.exists(xml_file_path):
                    report_content += f"  - XML output: recon/nmap/{basename}.xml\n"
                    # Attempt to parse XML for open ports
                    try:
                        tree = ET.parse(xml_file_path)
                        root = tree.getroot()
                        parsed_hosts_info = []

                        for host_node in root.findall('host'):
                            host_ip = "N/A"
                            address_node = host_node.find('address[@addrtype="ipv4"]')
                            if address_node is not None:
                                host_ip = address_node.get('addr')
                            else: # Fallback to hostname if IP not found or other addrtypes
                                hostnames_node = host_node.find('hostnames')
                                if hostnames_node is not None:
                                    hostname_node = hostnames_node.find('hostname')
                                    if hostname_node is not None:
                                        host_ip = hostname_node.get('name', "N/A")

                            open_ports_for_host = []
                            ports_node = host_node.find('ports')
                            if ports_node is not None:
                                for port_node in ports_node.findall('port'):
                                    state_node = port_node.find('state')
                                    if state_node is not None and state_node.get('state') == 'open':
                                        portid = port_node.get('portid')
                                        protocol = port_node.get('protocol')
                                        service_info_str = ""
                                        service_node = port_node.find('service')
                                        if service_node is not None:
                                            name = service_node.get('name', '')
                                            product = service_node.get('product', '')
                                            version = service_node.get('version', '')
                                            service_info_str = name
                                            if product: service_info_str += f" ({product}"
                                            if version: service_info_str += f" {version}"
                                            if product: service_info_str += ")"

                                        open_ports_for_host.append(f"    - Port {portid}/{protocol}: open - {service_info_str if service_info_str else 'unknown service'}")

                            if open_ports_for_host:
                                parsed_hosts_info.append(f"  - Host: {host_ip}\n" + "\n".join(open_ports_for_host))

                        if parsed_hosts_info:
                            report_content += "  - Identified Open Ports (from XML):\n" + "\n".join(parsed_hosts_info) + "\n"
                        else:
                            report_content += "  - No open ports found or detailed in XML for this scan.\n"
                    except ET.ParseError:
                        report_content += "  - Could not parse Nmap XML data (malformed file?).\n"
                    except Exception as e_xml:
                        report_content += f"  - Error parsing Nmap XML: {str(e_xml)[:100]}\n" # Avoid overly long error messages
        else:
            report_content += "- No Nmap result files found in recon/nmap/.\n"
    else:
        report_content += "- Nmap scans not run or no results directory found.\n"
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
    gobuster_dir_path = os.path.join(recon_base_dir, "gobuster")
    dirsearch_dir_path = os.path.join(recon_base_dir, "dirsearch")
    found_any_dir_results = False

    interesting_status_codes = [200, 204, 301, 302, 307, 401, 403, 500] # Codes to highlight

    def parse_dir_output(file_path, tool_name):
        """Helper to parse gobuster or dirsearch text output."""
        found_paths = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"): # Skip empty lines or comments (dirsearch)
                        continue

                    path = ""
                    status = 0

                    if tool_name == "gobuster":
                        # Gobuster format: /path (Status: XXX) [Size: YYY] or /path (Status: XXX)
                        match = re.search(r"^(.+?)\s+\(Status:\s*(\d+)\)", line)
                        if match:
                            path = match.group(1).strip()
                            try:
                                status = int(match.group(2))
                            except ValueError:
                                continue # Skip if status is not an int
                    elif tool_name == "dirsearch":
                        # Dirsearch format: [HH:MM:SS] XXX - YYYB - /path
                        match = re.match(r"\[\d{2}:\d{2}:\d{2}\]\s+(\d+)\s+-\s+[\w\.]+\s+-\s+(.+)", line)
                        if match:
                            try:
                                status = int(match.group(1))
                                path = match.group(2).strip()
                            except ValueError:
                                continue

                    if path and status in interesting_status_codes:
                        found_paths.append(f"    - Path: {path} (Status: {status})")
            return found_paths
        except Exception: # Broad catch for file reading/parsing issues
            return ["    - Error parsing output file."]

    if os.path.isdir(gobuster_dir_path) and any(os.scandir(gobuster_dir_path)):
        report_content += "- Gobuster Results:\n"
        found_any_dir_results = True
        for f_name in sorted(os.listdir(gobuster_dir_path)):
            if f_name.startswith("gobuster_results_") and f_name.endswith(".txt"):
                report_content += f"  - File: recon/gobuster/{f_name}\n"
                parsed_paths = parse_dir_output(os.path.join(gobuster_dir_path, f_name), "gobuster")
                if parsed_paths:
                    report_content += "\n".join(parsed_paths[:20]) # Show top 20
                    if len(parsed_paths) > 20:
                        report_content += "\n    - ...and more (see full file)."
                    report_content += "\n"
                else:
                    report_content += "    - No interesting paths (200,30x,401,403,500) found in this file or parse error.\n"
        report_content += "\n"

    if os.path.isdir(dirsearch_dir_path) and any(os.scandir(dirsearch_dir_path)):
        report_content += "- Dirsearch Results:\n"
        found_any_dir_results = True
        for f_name in sorted(os.listdir(dirsearch_dir_path)):
            if f_name.startswith("dirsearch_results_") and f_name.endswith(".txt"):
                report_content += f"  - File: recon/dirsearch/{f_name}\n"
                parsed_paths = parse_dir_output(os.path.join(dirsearch_dir_path, f_name), "dirsearch")
                if parsed_paths:
                    report_content += "\n".join(parsed_paths[:20]) # Show top 20
                    if len(parsed_paths) > 20:
                        report_content += "\n    - ...and more (see full file)."
                    report_content += "\n"
                else:
                    report_content += "    - No interesting paths (200,30x,401,403,500) found in this file or parse error.\n"
        report_content += "\n"

    if not found_any_dir_results:
        report_content += "- No directory brute-force results found (Gobuster or Dirsearch).\n"
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
    if os.path.isdir(whatweb_dir) and any(os.scandir(whatweb_dir)):
        found_whatweb_files = False
        for f_name in sorted(os.listdir(whatweb_dir)):
            if f_name.startswith("whatweb_") and f_name.endswith(".json"):
                found_whatweb_files = True
                report_content += f"- WhatWeb JSON output: recon/whatweb/{f_name}\n"
                json_file_path = os.path.join(whatweb_dir, f_name)
                try:
                    with open(json_file_path, 'r', encoding='utf-8') as f_json:
                        # WhatWeb JSON output is an array of objects, one per plugin match.
                        # For multiple targets in one JSON file (not current use case but robust for future):
                        # data = json.load(f_json) # if it's a single JSON object/array for multiple targets
                        # For --log-json, it's one JSON object per target URL, but might be an array if target has multiple IPs/redirects.
                        # Let's assume it's typically a list of lists/dictionaries or a single dictionary for one target.
                        # The first element in the outer list usually contains the target URI.
                        # Each plugin match is an object with plugin name and results.

                        # Reading the file content first
                        content = f_json.read()
                        if not content.strip():
                            report_content += "  - JSON file is empty.\n"
                            continue

                        # WhatWeb --log-json can output multiple JSON objects if it follows redirects or has multiple IPs.
                        # It's not a single valid JSON array but a stream of JSON objects.
                        # Or, it can be a single JSON object which is an array of two items: [target_info, plugins_dict]
                        # Let's try to handle both simple list of plugins and the two-item array structure.

                        parsed_data = None
                        try: # Try parsing as a single JSON object/array first
                            parsed_data = json.loads(content)
                        except json.JSONDecodeError: # If that fails, it might be a stream of JSON objects (not standard)
                                                     # For now, we'll assume the --log-json is one object for the target.
                            report_content += "  - Could not parse WhatWeb JSON as a single object. File might contain multiple JSON objects or be malformed.\n"
                            # If it were a stream, we'd do:
                            # for line in content.splitlines(): try: obj = json.loads(line) ... catch ...
                            # But WhatWeb's --log-json for a single target is usually one JSON structure.
                            # If it's the "stdout fallback" text, this will also fail here.
                            if "--- FALLBACK: STDOUT ---" in content:
                                report_content += "  - This file contains fallback text output, not parseable JSON.\n"
                            continue


                        technologies = {} # plugin_name: [versions_or_strings]

                        # WhatWeb JSON structure: often a list like [target_info_dict, plugins_dict]
                        # target_info_dict: {"target":"http://target.com", "http_status":200, ...}
                        # plugins_dict: {"PluginName": {"version":["1.2"], "string":["details"]}, ...}

                        data_to_parse = None
                        if isinstance(parsed_data, list) and len(parsed_data) == 2 and isinstance(parsed_data[0], dict) and isinstance(parsed_data[1], dict):
                            # This is the common structure for a single target scan
                            target_scanned = parsed_data[0].get("target", f_name)
                            plugins_dict = parsed_data[1]
                            report_content += f"  - Technologies for Target: {target_scanned}\n"
                            data_to_parse = plugins_dict
                        elif isinstance(parsed_data, dict): # If it's just the plugins_dict directly (less common for --log-json)
                            report_content += f"  - Technologies for Target: {f_name}\n" # Use filename as placeholder
                            data_to_parse = parsed_data

                        if data_to_parse:
                            for plugin_name, plugin_data in data_to_parse.items():
                                tech_details = []
                                if "version" in plugin_data and plugin_data["version"]:
                                    tech_details.append(f"Version(s): {', '.join(map(str, plugin_data['version']))}")
                                if "string" in plugin_data and plugin_data["string"]:
                                    tech_details.append(f"Details: {', '.join(map(str, plugin_data['string']))}")
                                if "os" in plugin_data and plugin_data["os"]:
                                     tech_details.append(f"OS: {', '.join(map(str, plugin_data['os']))}")
                                if "account" in plugin_data and plugin_data["account"]: # e.g. Google-Analytics account
                                     tech_details.append(f"Account: {', '.join(map(str, plugin_data['account']))}")

                                if tech_details:
                                    report_content += f"    - {plugin_name}: {'; '.join(tech_details)}\n"
                                else:
                                    report_content += f"    - {plugin_name} (No specific version/details in JSON)\n"
                        elif not ("--- FALLBACK: STDOUT ---" in content): # Avoid double message if already handled
                            report_content += "  - Could not determine technology structure in WhatWeb JSON.\n"

                except json.JSONDecodeError:
                    report_content += f"  - Error decoding WhatWeb JSON from {f_name}. File might be corrupted or not valid JSON.\n"
                    # Check if it's the fallback text
                    try:
                        with open(json_file_path, 'r', encoding='utf-8') as f_check_fallback:
                            fallback_content_check = f_check_fallback.read(100) # Read first 100 chars
                        if "--- FALLBACK: STDOUT ---" in fallback_content_check:
                             report_content += "    (File contains fallback text output from WhatWeb.)\n"
                    except:
                        pass # Ignore error during fallback check
                except Exception as e_whatweb_parse:
                    report_content += f"  - Error parsing WhatWeb JSON {f_name}: {str(e_whatweb_parse)[:100]}\n"

            # Also list the .txt summary files
            txt_files = [f for f in os.listdir(whatweb_dir) if f.startswith("whatweb_") and f.endswith(".txt")]
            if txt_files:
                report_content += "- WhatWeb text summaries:\n"
                for txt_f in txt_files:
                    report_content += f"  - recon/whatweb/{txt_f}\n"

            if not found_whatweb_files and not txt_files: # If neither JSON nor TXT files were found
                report_content += "- No WhatWeb output files found in recon/whatweb/.\n"

        if not found_whatweb_files: # This message is a bit redundant if txt_files were found and listed
             report_content += "- No WhatWeb JSON files found for parsing. Check for .txt summaries or if scan ran.\n"
    else:
        report_content += "- WhatWeb scan not run or no results directory found.\n"
    report_content += "\n"

    # 3. Vulnerability Findings
    report_content += "## Vulnerability Analysis Findings\n\n"
    vuln_base_dir = os.path.join(target_base_path, "vulnerabilities")

    if not os.path.isdir(vuln_base_dir):
        report_content += "- No vulnerability analysis data directory found.\n\n"
    else:
        # Broken Access Control (ffuf for IDOR)
        report_content += "### Broken Access Control / IDOR:\n"
        bac_dir = os.path.join(vuln_base_dir, "broken_access_control")
        if os.path.isdir(bac_dir) and any(os.scandir(bac_dir)):
            found_bac_files = False
            for f_name in os.listdir(bac_dir):
                if f_name.startswith("ffuf_idor_") and (f_name.endswith(".txt") or f_name.endswith(".csv")):
                    report_content += f"- FFuF IDOR results: vulnerabilities/broken_access_control/{f_name}\n"
                    found_bac_files = True
            if not found_bac_files:
                report_content += "- No specific ffuf IDOR output files found. Review directory for other files.\n"
        else:
            report_content += "- BAC/IDOR checks (ffuf) not run or no results directory found. Manual testing guidance was provided.\n"
        report_content += "- Reminder: Review manual testing guidance for other BAC aspects.\n\n"

        # SQL Injection (sqlmap)
        report_content += "### SQL Injection (SQLMap):\n"
        sqli_dir = os.path.join(vuln_base_dir, "sqli")
        if os.path.isdir(sqli_dir) and any(os.scandir(sqli_dir)):
            found_sqlmap_sessions = False
            for session_dir_name in os.listdir(sqli_dir):
                if session_dir_name.startswith("sqlmap_session_"):
                    found_sqlmap_sessions = True
                    report_content += f"- SQLMap session data and full results: vulnerabilities/sqli/{session_dir_name}/\n"
                    log_file = os.path.join(sqli_dir, session_dir_name, "log")
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f_log:
                                log_lines = f_log.readlines()

                            log_content_lower = "".join(log_lines).lower() # For keyword search

                            # Overall status (existing logic)
                            if "critical" in log_content_lower or "high" in log_content_lower or "sql injection vulnerability has been found" in log_content_lower or "identified the following injection point" in log_content_lower:
                                report_content += "  - [!] Status: Potential SQL injection vulnerabilities indicated by SQLMap log.\n"
                            elif "does not seem to be injectable" in log_content_lower or "all tested parameters do not appear to be injectable" in log_content_lower:
                                report_content += "  - Status: SQLMap log indicates target/parameters may not be injectable with current options.\n"
                            else:
                                report_content += "  - Status: SQLMap log summary inconclusive; manual review of session files needed.\n"

                            # Extract DBMS
                            dbms_found = set()
                            for line in log_lines:
                                if "back-end DBMS:" in line:
                                    dbms = line.split("back-end DBMS:", 1)[-1].strip()
                                    dbms_found.add(dbms)
                            if dbms_found:
                                report_content += f"  - Identified DBMS: {', '.join(sorted(list(dbms_found)))}\n"

                            # Extract Injectable Parameters
                            # Example log line: [INFO] GET parameter 'id' is vulnerable
                            # Example: [INFO] POST parameter 'search' is vulnerable
                            # Example: [INFO] Cookie parameter 'user_id' is vulnerable
                            # Example: User-Agent is vulnerable
                            injectable_params = set()
                            param_pattern = re.compile(r"parameter '([^']+)' is vulnerable|(\w[\w-]+(?:\s+HTTP header)?) is vulnerable", re.IGNORECASE)
                            for line in log_lines:
                                match = param_pattern.search(line)
                                if match:
                                    param_name = match.group(1) or match.group(2)
                                    param_location = ""
                                    if "GET parameter" in line: param_location = " (GET)"
                                    elif "POST parameter" in line: param_location = " (POST)"
                                    elif "Cookie parameter" in line: param_location = " (Cookie)"
                                    elif "HTTP header" in line or "User-Agent" in line or "Referer" in line : param_location = " (Header)" # Heuristic
                                    injectable_params.add(f"{param_name}{param_location}")
                            if injectable_params:
                                report_content += f"  - Identified Vulnerable Parameters: {', '.join(sorted(list(injectable_params)))}\n"

                            # Extract SQLi Types
                            # Example: [INFO] testing 'Boolean-based blind - Parameter replace'
                            # Example: [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
                            # Example: [INFO] testing 'PostgreSQL UNION query (NULL) - 1 to 20 columns'
                            sqli_types_found = set()
                            type_pattern = re.compile(r"testing '(.+?)'", re.IGNORECASE) # Generic, might need refinement
                            # More specific patterns could be:
                            # type_pattern = re.compile(r"testing '(boolean-based blind|error-based|union query|time-based blind|stacked queries)'", re.IGNORECASE)
                            for line in log_lines:
                                if " testing '" in line.lower() and "is vulnerable" not in line.lower(): # Avoid param lines
                                    match = type_pattern.search(line)
                                    if match:
                                        # Clean up common technique details for brevity
                                        type_desc = match.group(1)
                                        if " - Parameter replace" in type_desc: type_desc = type_desc.split(" - Parameter replace")[0]
                                        if " - WHERE, HAVING" in type_desc: type_desc = type_desc.split(" - WHERE, HAVING")[0]
                                        if " columns" in type_desc and "query" in type_desc: type_desc = type_desc.split(" columns")[0] + " columns"
                                        sqli_types_found.add(type_desc.strip("'"))
                            if sqli_types_found:
                                report_content += f"  - Potential SQLi Types/Techniques Tested/Identified: {', '.join(sorted(list(sqli_types_found)))}\n"

                        except Exception as e_log_parse:
                            report_content += f"  - Could not fully parse SQLMap log for details: {str(e_log_parse)[:100]}\n"
                    else:
                        report_content += "  - SQLMap session log file not found at default path.\n"

                    # Check for dumped data
                    dump_dir_path = os.path.join(sqli_dir, session_dir_name, "output") # SQLMap output dir often has hostname subdir
                    # SQLMap's actual dump path is usually <output_dir>/<target_host>/dump/<db_name>/<table_name>.csv
                    # We'll do a simpler recursive search for .csv files under the session's output directory.
                    found_dump_files = []
                    # Need to walk through potential host-named subdirectories in output path.
                    if os.path.isdir(dump_dir_path): # Check if 'output' subdir exists
                        for host_subdir_name in os.listdir(dump_dir_path):
                            host_subdir_full_path = os.path.join(dump_dir_path, host_subdir_name)
                            if os.path.isdir(host_subdir_full_path):
                                actual_dump_root = os.path.join(host_subdir_full_path, "dump")
                                if os.path.isdir(actual_dump_root):
                                    for root, _, files in os.walk(actual_dump_root):
                                        for file in files:
                                            if file.endswith(".csv"):
                                                # Get relative path from 'dump' onwards
                                                relative_dump_path = os.path.relpath(os.path.join(root, file), actual_dump_root)
                                                found_dump_files.append(f"dump/{relative_dump_path}")
                    if found_dump_files:
                        report_content += "  - Potential Dumped Data Files (CSV):\n"
                        for df in found_dump_files:
                            report_content += f"    - vulnerabilities/sqli/{session_dir_name}/output/{host_subdir_name}/{df}\n" # Path relative to target folder

            if not found_sqlmap_sessions:
                 report_content += "- No SQLMap session directories found.\n"
        else:
            report_content += "- SQLMap scans not run or no results directory found. Manual testing guidance was provided.\n"
        report_content += "\n"

        # XSS (dalfox)
        report_content += "### Cross-Site Scripting (XSS - Dalfox):\n"
        xss_dir = os.path.join(vuln_base_dir, "xss")
        if os.path.isdir(xss_dir) and any(os.scandir(xss_dir)):
            found_dalfox_files = False
            for f_name in os.listdir(xss_dir):
                if f_name.startswith("dalfox_results_") and f_name.endswith(".txt"):
                    report_content += f"- Dalfox results: vulnerabilities/xss/{f_name}\n"
                    found_dalfox_files = True
                    try:
                        with open(os.path.join(xss_dir, f_name), 'r', errors='ignore') as f_dalfox:
                            dalfox_content = f_dalfox.read()
                        if "[VULN]" in dalfox_content or "[POC]" in dalfox_content:
                            report_content += "  - [!] Potential XSS vulnerabilities indicated by Dalfox output.\n"
                        else:
                            report_content += "  - Dalfox output does not contain explicit [VULN] or [POC] tags. Manual review advised.\n"
                    except Exception:
                        report_content += "  - Could not read or parse Dalfox output file for quick summary.\n"
            if not found_dalfox_files:
                report_content += "- No Dalfox output files found.\n"
        else:
            report_content += "- Dalfox scans not run or no results directory found. Manual testing guidance was provided.\n"
        report_content += "\n"

        # Security Misconfigurations (Nikto, Nuclei, Headers)
        report_content += "### Security Misconfigurations:\n"
        sec_misc_dir = os.path.join(vuln_base_dir, "security_misconfigurations")
        found_sec_misc_data = False
        if os.path.isdir(sec_misc_dir):
            # Nikto
            nikto_out_dir = os.path.join(sec_misc_dir, "nikto")
            if os.path.isdir(nikto_out_dir) and any(os.scandir(nikto_out_dir)):
                report_content += "- Nikto Scan Results:\n"
                for f_name in os.listdir(nikto_out_dir):
                    report_content += f"  - vulnerabilities/security_misconfigurations/nikto/{f_name}\n"
                found_sec_misc_data = True
            # Nuclei
            nuclei_out_dir = os.path.join(sec_misc_dir, "nuclei")
            if os.path.isdir(nuclei_out_dir) and any(os.scandir(nuclei_out_dir)):
                report_content += "- Nuclei Scan Results:\n"
                for f_name in os.listdir(nuclei_out_dir):
                    report_content += f"  - vulnerabilities/security_misconfigurations/nuclei/{f_name}\n"
                found_sec_misc_data = True

# ... (other imports like ET, os, Console)

# ... (generate_report function up to Security Misconfigurations)
            # Headers Analysis
            headers_out_dir = os.path.join(sec_misc_dir, "headers_analysis")
            if os.path.isdir(headers_out_dir) and any(os.scandir(headers_out_dir)):
                report_content += "- Security Headers Analysis:\n"
                for f_name in os.listdir(headers_out_dir):
                    if f_name.startswith("headers_") and f_name.endswith(".txt"):
                        report_content += f"  - vulnerabilities/security_misconfigurations/headers_analysis/{f_name}\n"
                        # Light parsing for missing headers summary
                        try:
                            with open(os.path.join(headers_out_dir, f_name), 'r', errors='ignore') as hf:
                                missing_headers_summary = []
                                for line in hf:
                                    if "[ Missing ]" in line:
                                        missing_header_name = line.split("]")[1].split("(")[0].strip()
                                        missing_headers_summary.append(missing_header_name)
                                if missing_headers_summary:
                                    report_content += f"    - Key Missing/Suboptimal Headers Noted: {', '.join(missing_headers_summary)}\n"
                        except Exception:
                            report_content += "    - (Could not quickly parse header file for summary)\n"
                found_sec_misc_data = True

            # Nuclei JSONL Parsing
            nuclei_jsonl_file = os.path.join(nuclei_out_dir if os.path.isdir(nuclei_out_dir) else "", "nuclei_results.jsonl") # Check if nuclei_out_dir was created
            if os.path.exists(nuclei_jsonl_file):
                report_content += "- Nuclei JSONL Output Parsed Summary:\n"
                found_nuclei_issues = {} # severity: count
                try:
                    with open(nuclei_jsonl_file, 'r', errors='ignore') as f_jsonl:
                        for line in f_jsonl:
                            try:
                                finding = json.loads(line)
                                severity = finding.get("info", {}).get("severity", "unknown").lower()
                                found_nuclei_issues[severity] = found_nuclei_issues.get(severity, 0) + 1
                            except json.JSONDecodeError:
                                continue # Skip malformed lines
                    if found_nuclei_issues:
                        for severity, count in sorted(found_nuclei_issues.items(), key=lambda item: ["critical", "high", "medium", "low", "info", "unknown"].index(item[0])):
                            report_content += f"  - Severity '{severity.capitalize()}': {count} finding(s)\n"
                        report_content += f"  - Full JSONL details: vulnerabilities/security_misconfigurations/nuclei/nuclei_results.jsonl\n"
                    else:
                        report_content += "  - No specific findings parsed from JSONL, or file was empty.\n"
                except Exception as e_nuclei_parse:
                    report_content += f"  - Error parsing Nuclei JSONL: {str(e_nuclei_parse)[:100]}\n"
            elif os.path.isdir(nuclei_out_dir) and any(f.endswith(".txt") for f in os.listdir(nuclei_out_dir)): # If only text file exists
                 report_content += "- Nuclei text output found (JSONL not available for parsing). Review manually.\n"


        if not found_sec_misc_data and not (os.path.exists(nuclei_jsonl_file) and found_nuclei_issues): # Adjusted condition
            report_content += "- No automated security misconfiguration scan results (Nikto, Nuclei, Headers) found or parsed.\n"

        report_content += "- Reminder: Review manual testing guidance for other misconfigurations.\n\n"

        # Guidance-Only Vulnerabilities
        guidance_vulns = [
            "Command Injection", "Server-Side Request Forgery (SSRF)",
            "Server-Side Template Injection (SSTI)", "Open Redirect",
            "Insecure Deserialization", "File Upload Vulnerabilities"
        ]
        report_content += "### Guidance-Based Vulnerability Checks:\n"
        report_content += "The following vulnerability categories were primarily checked via detailed manual testing guidance provided by AutoBB:\n"
        for gv_name in guidance_vulns:
            report_content += f"- {gv_name}\n"
        report_content += "Please consult `notes/user_notes.md` and any evidence manually saved in the `exploitation/` directory for findings related to these categories.\n\n"

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
