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
    *   `tool_paths`: Specify absolute paths (or using `~`) to tools like `nmap`, `sqlmap`, etc.
    *   `wordlists`: Define default paths for wordlists used by modules like directory brute-forcing or parameter fuzzing (e.g., `wordlists.directory_bruteforce`).

    Refer to the comments within `autobb_config.yaml.example` for details on available keys and structure. If the config file is not found or a specific key is missing, AutoBB will use its default behavior (e.g., search PATH for tools, prompt for wordlists without a default).

## Core Features

*   **Target Management:** Saves target information and organizes outputs.
*   **Modular Workflow:** Menu-driven process for Recon, Vulnerability Analysis, Fuzzing, etc.
*   **Tool Integration & Guidance:** Leverages popular tools and provides manual testing advice.
*   **Note-Taking:** Per-target notes using a terminal editor.
*   **Dependency Checking:** Warns about missing external tools.
*   **Global Configuration:** Allows user to set default tool paths and wordlists.

## Implemented Capabilities by Stage
(Brief summary - detailed list omitted for brevity here, but was present in previous README version and should be maintained)

### 1. Reconnaissance
Automated scans: Whois, Nmap, Subdomain Enumeration (Amass, Sublist3r, Subfinder), Directory Brute-force (Gobuster, Dirsearch), Wayback/Archive Scan (GAU, Waybackurls), HTTP Probe, Tech Scan (WhatWeb).

### 2. Vulnerability Analysis
Guidance & tool integration: BAC (ffuf for IDORs), SQLi (sqlmap), XSS (dalfox), Command Injection, SSRF, SSTI, Open Redirect, Insecure Deserialization, File Uploads, Security Misconfigs (Nikto, Nuclei, header checks).

### 3. Fuzzing & Automation
Tools and guidance for discovering vulnerabilities through fuzzing:
*   **Parameter Fuzzing:** Uses `ffuf` for GET parameters, POST data, and HTTP Headers. Can **suggest URLs with parameters found during reconnaissance** (from Wayback scan) for easier targeting. (Output: `fuzzing/ffuf_parameter_fuzz/`)
*   **HTTP Header Fuzzing Guidance:** Detailed advice on which headers to fuzz and what to look for, directing users to the `ffuf` parameter fuzzing option (Header type) for automation.
*   **Burp Suite Integration Guidance:** Advice on how to effectively use Burp Suite in conjunction with AutoBB's workflow.

### 4. Exploitation
SearchSploit integration, PoC building guidance, exploitation tools guidance, evidence capture guidance.

### 5. Generate Bug Bounty Summary Report
Creates `summary.txt` with findings from Recon (Nmap XML, WhatWeb JSON, DirBuster parsing, etc.) and Vulnerability Analysis (SQLMap logs, Dalfox tags, Nuclei severity counts, Header issues).

### 6. View Notes
Edit `notes/user_notes.md`.

## Target Folder Structure
(Detailed structure omitted for brevity here, but was present in previous README version and should be maintained, including paths like `vulnerabilities/security_misconfigurations/nuclei/nuclei_results.jsonl`)

```
sanitized_target_name/
├── config.txt
├── summary.txt
├── recon/
│   ├── whois/, nmap/, subdomains/, gobuster/, dirsearch/, wayback/, httprobe/, whatweb/
├── vulnerabilities/
│   ├── broken_access_control/, sqli/, xss/, command_injection/, ssrf/, ssti/,
│   │   open_redirect/, insecure_deserialization/, file_upload/, security_misconfigurations/
│   │   (within security_misconfigurations: nikto/, nuclei/, headers_analysis/)
├── fuzzing/
│   └── ffuf_parameter_fuzz/
├── exploitation/
│   ├── searchsploit_results/
│   └── (User-saved PoCs, etc.)
├── screenshots/
└── notes/
    └── user_notes.md
```

## Disclaimer

AutoBugBounty is intended for educational and ethical security testing purposes only. Always obtain proper authorization before testing any target. The developers are not responsible for any misuse of this tool.
```
