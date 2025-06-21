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
    This will install `rich`, `requests`, and other Python libraries listed in `requirements.txt` and register the `autobb` command.

3.  **Install External Tool Dependencies:**
    AutoBB relies on several external command-line tools for its functionality. You need to install these separately using your system's package manager. AutoBB will check for these on startup and warn you if core tools are missing.

    Common tools include (but are not limited to):
    *   `whois`
    *   `nmap`
    *   `sqlmap`
    *   `nikto`
    *   `nuclei`
    *   `ffuf`
    *   `amass` and/or `sublist3r` and/or `subfinder`
    *   `gobuster` and/or `dirsearch`
    *   `gau` and/or `waybackurls`
    *   `httprobe`
    *   `whatweb`
    *   `dalfox`
    *   `searchsploit` (from exploit-db package)
    *   A terminal text editor like `nano`, `vim`, or `vi` (for notes).

    Example installation on Debian/Ubuntu:
    ```bash
    sudo apt update
    sudo apt install whois nmap sqlmap nikto ffuf amass gobuster httprobe whatweb exploitdb nano vim -y
    # For Nuclei, Dalfox, Subfinder, GAU, Waybackurls - follow their official installation guides (often via Go or releases)
    # e.g., go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    # pip install sublist3r
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
Or, after making `autobb/main.py` executable (`chmod +x autobb/main.py`):
```bash
./autobb/main.py
```

## Core Features

*   **Target Management:** Saves target information (IP/domain, save path) and organizes all outputs into a dedicated target folder.
*   **Modular Workflow:** Guides the user through a logical bug bounty process via a menu-driven interface.
*   **Tool Integration:** Leverages popular open-source security tools for various tasks.
*   **Guidance for Manual Testing:** Provides detailed information, techniques, and payload examples for vulnerabilities that require manual assessment.
*   **Note-Taking:** Allows users to maintain custom notes (`user_notes.md`) for each target, accessible via the menu.
*   **Dependency Checking:** Checks for necessary external tools on startup and informs the user if core components are missing.

## Implemented Capabilities by Stage

### 1. Reconnaissance
Automated scans and information gathering:
*   **Whois:** Basic domain ownership and contact information. (Output: `recon/whois/`)
*   **Nmap:** Network scanning with selectable types (Quick, Full TCP, Service Detection, Custom). (Output: `recon/nmap/`)
*   **Subdomain Enumeration:** Uses Amass, Sublist3r, or Subfinder to find subdomains. (Output: `recon/subdomains/`)
*   **Directory Brute-force:** Uses Gobuster or Dirsearch with a user-provided wordlist against HTTP/HTTPS. (Output: `recon/gobuster/` or `recon/dirsearch/`)
*   **Wayback/Archive Scan:** Uses GAU (Get All URLs) or Waybackurls to find historical URLs. (Output: `recon/wayback/`)
*   **HTTP Probe:** Uses `httprobe` on discovered subdomains to find live HTTP/HTTPS servers. (Output: `recon/httprobe/`)
*   **Technology Stack Scan:** Uses WhatWeb to identify technologies on live web servers. (Output: `recon/whatweb/`)

### 2. Vulnerability Analysis
A combination of automated tool integration and detailed guidance for manual testing:
*   **Broken Access Control:** Guidance & `ffuf` for IDORs. (Output: `vulnerabilities/broken_access_control/`)
*   **SQL Injection (SQLi):** Guidance & `sqlmap` integration. (Output: `vulnerabilities/sqli/sqlmap_session_<target>/`)
*   **Cross-Site Scripting (XSS):** Guidance & `dalfox` integration. (Output: `vulnerabilities/xss/`)
*   **Command Injection:** Detailed guidance for manual testing.
*   **Server-Side Request Forgery (SSRF):** In-depth guidance for manual testing.
*   **Server-Side Template Injection (SSTI):** Comprehensive guidance for detection and manual testing.
*   **Open Redirect:** Extensive guidance for manual testing.
*   **Insecure Deserialization:** Detailed guidance for manual testing.
*   **File Upload Vulnerabilities:** Comprehensive guidance for manual testing.
*   **Security Misconfigurations:** Guidance, `nikto` & `nuclei` integration, Python-based header checks. (Output: `vulnerabilities/security_misconfigurations/`)

### 3. Fuzzing & Automation
Tools and guidance for discovering vulnerabilities through fuzzing:
*   **Parameter Fuzzing:** Uses `ffuf` for GET parameters, POST data, and HTTP Headers. (Output: `fuzzing/ffuf_parameter_fuzz/`)
*   **HTTP Header Fuzzing Guidance:** Detailed advice, directing users to the `ffuf` parameter fuzzing option.
*   **Burp Suite Integration Guidance:** Advice on using Burp Suite with AutoBB.

### 4. Exploitation
Guidance and tools to help confirm and demonstrate vulnerabilities:
*   **SearchSploit Integration:** Search Exploit-DB for public exploits. (Output: `exploitation/searchsploit_results/`)
*   **PoC Building Guidance:** Advice on creating simple PoCs for common vulnerabilities.
*   **Exploitation Tools Guidance:** Tips for using `curl`, `httpie`, and Burp Repeater.
*   **Evidence Capture Guidance:** Advice on documenting findings (screenshots, logs, etc.).

### 5. Generate Bug Bounty Summary Report
Creates a text-based summary report (`summary.txt`) from collected findings. Includes:
*   Target & Scope Information.
*   Detailed Reconnaissance Findings.
*   Summaries and pointers to Vulnerability Analysis tool outputs.

### 6. View Notes
Allows users to create and view target-specific notes in `notes/user_notes.md` using a terminal editor (`nano`, `vim`, `vi`).

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
│       ├── nuclei/           # nuclei_results.txt
│       └── headers_analysis/ # headers_*.txt
├── fuzzing/
│   └── ffuf_parameter_fuzz/  # ffuf_param_*.txt, .json, .html etc. (if -of all used)
├── exploitation/
│   ├── searchsploit_results/ # searchsploit_*.txt
│   └── (User-saved PoCs, notes, etc.)
├── screenshots/              # (User-managed screenshots)
└── notes/
    └── user_notes.md         # Custom notes for the target.
```

## Disclaimer

AutoBugBounty is intended for educational and ethical security testing purposes only. Always obtain proper authorization before testing any target. The developers are not responsible for any misuse of this tool.
```
