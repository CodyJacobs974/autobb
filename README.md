# AutoBugBounty (AutoBB)

AutoBugBounty (AutoBB) is a command-line toolkit designed to assist bug bounty hunters by guiding them through a structured bug bounty workflow. It automates various tasks where appropriate and provides detailed guidance for manual testing.

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
*   **Broken Access Control:**
    *   Guidance on testing IDORs, Privilege Escalation, Function/Data-Level Access Control.
    *   Integration of `ffuf` for fuzzing potential IDOR parameters. (Output: `vulnerabilities/broken_access_control/`)
*   **SQL Injection (SQLi):**
    *   Guidance on manual SQLi detection techniques.
    *   Integration of `sqlmap` for automated detection and exploration. (Output: `vulnerabilities/sqli/sqlmap_session_<target>/`)
*   **Cross-Site Scripting (XSS):**
    *   Guidance on Reflected, Stored, and DOM-based XSS, including manual payloads.
    *   Integration of `dalfox` for automated XSS scanning. (Output: `vulnerabilities/xss/`)
    *   Notes on `xsser` as a limited alternative if Dalfox is unavailable.
*   **Command Injection:** Detailed guidance for manual testing, covering techniques, payloads, and bypass methods. No automated execution due to risk.
*   **Server-Side Request Forgery (SSRF):** In-depth guidance on manual testing, impact, parameters, payloads (internal IPs, cloud metadata, schemes, bypasses), and using OOB tools. No automated execution.
*   **Server-Side Template Injection (SSTI):** Comprehensive guidance on detection (polyglot payloads), common engines, and manual testing. Points to resources like PayloadsAllTheThings for exploitation. No automated exploitation.
*   **Open Redirect:** Extensive guidance on manual testing, impact, common parameters, various payloads, and bypass techniques. No automated execution.
*   **Insecure Deserialization:** Detailed guidance on common languages/formats, signatures, impact, detection, and tools like `ysoserial`. No automated exploitation.
*   **File Upload Vulnerabilities:** Comprehensive guidance on common issues (extension bypasses, content-type, filename sanitization, content validation) and testing steps. No automated exploitation.
*   **Security Misconfigurations:**
    *   Guidance on common misconfiguration types.
    *   Integration of `nikto` for web server scanning. (Output: `vulnerabilities/security_misconfigurations/nikto/`)
    *   Integration of `nuclei` for template-based vulnerability scanning. (Output: `vulnerabilities/security_misconfigurations/nuclei/`)
    *   Python-based check for common security headers (HSTS, CSP, X-Frame-Options, etc.). (Output: `vulnerabilities/security_misconfigurations/headers_analysis/`)

### 3. Fuzzing & Automation
Tools and guidance for discovering vulnerabilities through fuzzing:
*   **Parameter Fuzzing:** Uses `ffuf` for fuzzing GET parameters, POST data, and HTTP Headers with user-provided wordlists and configurations. (Output: `fuzzing/ffuf_parameter_fuzz/`)
*   **HTTP Header Fuzzing Guidance:** Detailed advice on which headers to fuzz and what to look for, directing users to the `ffuf` parameter fuzzing option for automation.
*   **Burp Suite Integration Guidance:** Advice on how to effectively use Burp Suite in conjunction with AutoBB's workflow.

### 4. Exploitation (Placeholder)
This stage will focus on guidance for PoC development and leveraging findings. Currently a placeholder in the menu.

### 5. Generate Bug Bounty Summary Report
Creates a text-based summary report (`summary.txt`) from collected findings. Includes:
*   Target & Scope Information.
*   Detailed Reconnaissance Findings (counts, file locations, snippets).
*   Placeholders for Vulnerability Findings (to be enhanced to pull from vulnerability output).

### 6. View Notes
Allows users to create and view target-specific notes in `notes/user_notes.md` using a terminal editor (`nano`, `vim`, `vi`).

## Usage

Ensure all dependencies listed in `AGENTS.md` (external tools like nmap, sqlmap, etc.) and `requirements.txt` (Python libraries) are installed.

To run the toolkit (from the root directory of the project):

```bash
python3 autobb/main.py
```
Or, if you've made `autobb/main.py` executable:
```bash
./autobb/main.py
```
The script is now located inside the `autobb` package.

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
│   └── ffuf_parameter_fuzz/  # ffuf_param_*.txt, .json, .html etc.
├── exploitation/             # (Placeholder for future PoCs, manual exploit notes)
├── screenshots/              # (User-managed screenshots)
└── notes/
    └── user_notes.md         # Custom notes for the target.
```

## Disclaimer

AutoBugBounty is intended for educational and ethical security testing purposes only. Always obtain proper authorization before testing any target. The developers are not responsible for any misuse of this tool.
```
