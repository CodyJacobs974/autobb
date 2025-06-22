# AutoBugBounty (AutoBB)

AutoBugBounty (AutoBB) is a command-line toolkit designed to assist bug bounty hunters by guiding them through a structured bug bounty workflow. It automates various tasks where appropriate and provides detailed guidance for manual testing.

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/example/autobb.git # Replace with actual repo URL when available
    cd autobb
    ```

2.  **Install Python Dependencies:**
    It's recommended to use a Python virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install .
    # Or for development: pip install -e .
    ```
    This will install `rich`, `requests`, `PyYAML`, and other Python libraries listed in `requirements.txt` and register the `autobb` command.

3.  **Install External Tool Dependencies:**
    AutoBB relies on several external command-line tools for its functionality. You need to install these separately using your system's package manager. AutoBB will check for these on startup and warn you if core tools are missing.

    Common tools include (but are not limited to):
    *   `whois`, `nmap`, `sqlmap`, `nikto`, `nuclei`, `ffuf`
    *   Subdomain tools: `amass`, `sublist3r`, `subfinder`
    *   Directory busters: `gobuster`, `dirsearch`
    *   Archive URL finders: `gau`, `waybackurls`
    *   `httprobe`, `whatweb`, `dalfox`, `searchsploit` (from `exploitdb` package)
    *   A terminal text editor like `nano`, `vim`, or `vi` (for notes).

    Example installation on Debian/Ubuntu:
    ```bash
    sudo apt update
    sudo apt install whois nmap sqlmap nikto ffuf amass gobuster httprobe whatweb exploitdb nano vim -y
    # For Nuclei, Dalfox, Subfinder, GAU, Waybackurls - follow their official installation guides (often via Go or releases)
    # e.g., go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    # pip install sublist3r PyYAML
    ```
    Refer to the `AGENTS.md` file for more specific dependency details and the `autobb/utils.py` for the list of checked tools.

## Usage

Once installed, you can run AutoBugBounty from your terminal:

```bash
autobb
```

This will launch the interactive menu.

**Development Usage:**
If you have cloned the repository and installed in editable mode (`pip install -e .`) or just want to run from the source without full installation, you can use:
```bash
python3 autobb/main.py
```
(Ensure `autobb/main.py` is executable if running as `./autobb/main.py`).

## Global Configuration (Optional)

AutoBB supports a global YAML configuration file to customize default wordlist paths and provide specific paths for external tools if they are not in your system's PATH.

1.  **Create the Configuration File:**
    Copy the `autobb_config.yaml.example` file (from the project root) to one of these locations:
    *   User-specific (recommended): `~/.config/autobb/autobb_config.yaml` (Linux/macOS)
    *   Project root (for development/portable): `./autobb_config.yaml` (in the same directory as the `autobb` project folder)

    AutoBB will check these locations in order (project root first, then user config).

2.  **Customize `autobb_config.yaml`:**
    Edit your copied `autobb_config.yaml` to set:
    *   `tool_paths`: Specify absolute paths (or using `~`) to tools like `nmap`, `sqlmap`, etc., if they are not in your system PATH or you want to use a specific version.
    *   `wordlists`: Define default paths for various wordlist types (e.g., for directory brute-forcing, specific parameter fuzzing categories like XSS, SQLi).
    *   `default_tool_options`: Set default command-line options/flags for supported tools (e.g., default `nmap` scan intensity, default `ffuf` rate). These are prepended to commands, and user-prompted options are typically appended.

    Refer to the comments within `autobb_config.yaml.example` for details on all available keys and structure (e.g., `tool_paths.nmap`, `wordlists.parameter_fuzzing_xss`, `default_tool_options.ffuf`). If the config file is not found or a specific key is missing, AutoBB will use its built-in defaults or prompt the user.

## Core Features

*   **Target Management:** Saves target information and organizes outputs.
*   **Modular Workflow:** Menu-driven process for Recon, Vulnerability Analysis, Fuzzing, etc.
*   **Tool Integration & Guidance:** Leverages popular tools and provides manual testing advice.
*   **Note-Taking:** Per-target notes using a terminal editor.
*   **Dependency Checking:** Warns about missing external tools.
*   **Global Configuration:** Allows users to set default tool paths, wordlist locations, and default command-line options for integrated tools.

## Implemented Capabilities by Stage

### 1. Reconnaissance
Automated scans: Whois, Nmap, Subdomain Enumeration (Amass, Sublist3r, Subfinder), Directory Brute-force (Gobuster, Dirsearch), Wayback/Archive Scan (GAU, Waybackurls), HTTP Probe, Tech Scan (WhatWeb).

### 2. Vulnerability Analysis
Guidance & tool integration: BAC (ffuf for IDORs - **now with CSV parsing and interactive `curl` PoC generation for interesting results**), SQLi (sqlmap), XSS (dalfox - **now with interactive HTML PoC generation for reported findings**), Command Injection, SSRF, SSTI, Open Redirect, Insecure Deserialization, File Uploads, Security Misconfigs (Nikto, Nuclei, header checks).

### 3. Fuzzing & Automation
Tools and guidance for discovering vulnerabilities through fuzzing:
*   **Parameter Fuzzing:** Uses `ffuf` for GET parameters, POST data, and HTTP Headers.
    *   Can **suggest URLs with parameters found during reconnaissance** (from Wayback scan) for easier targeting.
    *   Users can select a **payload category (XSS, SQLi, LFI, CMDi, Generic, Custom)** to use corresponding default wordlists if configured in `autobb_config.yaml`.
    *   If no wordlist is provided or configured, a **small, built-in generic fallback list** is used with a warning (providing a proper wordlist is highly recommended).
    *   (Output: `fuzzing/ffuf_parameter_fuzz/`)
*   **HTTP Header Fuzzing Guidance:** Detailed advice on which headers to fuzz and what to look for, directing users to the `ffuf` parameter fuzzing option (Header type) for automation.
*   **Burp Suite Integration Guidance:** Advice on how to effectively use Burp Suite in conjunction with AutoBB's workflow.

### 4. Exploitation
SearchSploit integration, PoC building guidance, exploitation tools guidance, evidence capture guidance.

### 5. Generate Bug Bounty Summary Report
Creates `summary.txt` with findings from Recon (Nmap XML, WhatWeb JSON, DirBuster parsing, etc.) and Vulnerability Analysis (SQLMap logs, Dalfox tags, Nuclei severity counts, Header issues).
The report now includes more detailed parsed information:
*   **Nmap:** Open ports, services, and versions from XML.
*   **Directory Brute-force:** Top interesting paths found with status codes.
*   **WhatWeb:** Identified technologies and versions from JSON.
*   **SQLMap:** Identified DBMS, vulnerable parameters, SQLi types, and lists of dumped data files from logs and output directories.
*   **Dalfox:** Indicates if `[VULN]` or `[POC]` tags were found.
*   **Nuclei:** Summary of findings by severity from JSONL.
*   **Headers Analysis:** Summary of key missing/suboptimal headers.

### 6. View Notes
Edit `notes/user_notes.md`.

## Target Folder Structure
When you provide a target and a save location, AutoBB will create a folder for that target (e.g., `your_save_location/sanitized_target_name/`). This folder will contain:

```
sanitized_target_name/
├── config.txt                # User-entered target, save path, full target path.
├── summary.txt               # Generated bug bounty summary report.
├── recon/
│   ├── whois/                # whois_results.txt
│   ├── nmap/                 # nmap_results_*.txt, nmap_results_*.xml
│   ├── subdomains/           # subdomains_found.txt, amass_output.txt, etc.
│   ├── gobuster/             # gobuster_results_*.txt (if gobuster used)
│   ├── dirsearch/            # dirsearch_results_*.txt (if dirsearch used)
│   ├── wayback/              # archive_urls_unique.txt, archive_urls_raw_*.txt
│   ├── httprobe/             # live_hosts.txt
│   └── whatweb/              # whatweb_*.json, whatweb_*.txt
├── vulnerabilities/
│   ├── broken_access_control/# ffuf_idor_*.txt
│   ├── sqli/                 # sqlmap_session_<target_details>/ (contains sqlmap logs & data)
│   ├── xss/                  # dalfox_results_*.txt
│   ├── command_injection/    # (Primarily guidance, no specific tool output by default)
│   ├── ssrf/                 # (Primarily guidance)
│   ├── ssti/                 # (Primarily guidance)
│   ├── open_redirect/        # (Primarily guidance)
│   ├── insecure_deserialization/ # (Primarily guidance)
│   ├── file_upload/          # (Primarily guidance)
│   └── security_misconfigurations/
│       ├── nikto/            # nikto_*.txt
│       ├── nuclei/           # nuclei_results.jsonl, nuclei_results_summary.txt
│       └── headers_analysis/ # headers_*.txt
├── fuzzing/
│   └── ffuf_parameter_fuzz/  # ffuf_param_*.txt, .json, .html etc. (if -of all used)
├── exploitation/
│   ├── searchsploit_results/ # searchsploit_*.txt
│   ├── xss_pocs/             # Generated HTML PoCs for XSS from Dalfox
│   └── (User-saved PoCs, etc.)
├── screenshots/              # (User-managed screenshots)
└── notes/
    └── user_notes.md         # Custom notes for the target.
```

## Disclaimer

AutoBugBounty is intended for educational and ethical security testing purposes only. Always obtain proper authorization before testing any target. The developers are not responsible for any misuse of this tool.
```
