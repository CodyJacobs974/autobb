import shutil
from rich.console import Console

console = Console()

# List of core external command-line tool dependencies
CORE_DEPENDENCIES = [
    "whois",
    "nmap",
    "sqlmap",
    "nikto",
    "nuclei",
    "ffuf", # or wfuzz - can make this logic more complex later to check for either
    "sublist3r", # Note: sublist3r might be a Python script installed via pip
    "amass",
    "gobuster", # or dirsearch
    "waybackurls", # or gau
    "httprobe",
    "whatweb", # or wappalyzer (wappalyzer is often a browser extension or npm package)
    "searchsploit",
    # Editors for notes are checked in notes_manager.py, but can be listed here for info
    # "nano",
    # "vim",
]

# Less critical, or might have Python alternatives/internal implementations later
# Or tools that are very specific and might not be on all systems
OPTIONAL_DEPENDENCIES = [
    "wfuzz",
    "dirsearch",
    "gau",
    "dalfox", # For XSS
    "xsser",  # For XSS
    # "wappalyzer-cli" # If a CLI version is targeted
]


def check_dependencies():
    """
    Checks for core command-line tool dependencies and warns if any are missing.
    """
    console.print("\n[bold cyan]--- Checking Dependencies ---[/bold cyan]")
    missing_core = []
    missing_optional = []

    for tool in CORE_DEPENDENCIES:
        if not shutil.which(tool):
            missing_core.append(tool)

    for tool in OPTIONAL_DEPENDENCIES:
        if not shutil.which(tool):
            missing_optional.append(tool)

    if not missing_core and not missing_optional:
        console.print("[green]All checked dependencies appear to be installed.[/green]")
        return True

    if missing_core:
        console.print("\n[bold red]Warning: The following CORE dependencies are MISSING:[/bold red]")
        for tool in missing_core:
            console.print(f"- [red]{tool}[/red]")
        console.print("\n[yellow]AutoBB relies on these tools for full functionality.[/yellow]")
        console.print("Please install them using your system's package manager (e.g., apt, dnf, pacman, brew).")
        console.print("Example: [dim]'sudo apt install nmap whois sqlmap nikto nuclei ffuf amass gobuster httprobe whatweb searchsploit sublist3r waybackurls'[/dim]")
        console.print("([dim]Note: Package names might vary slightly. 'sublist3r' might require pip install.)[/dim]")

    if missing_optional:
        console.print("\n[bold yellow]Note: The following OPTIONAL dependencies are MISSING:[/bold yellow]")
        for tool in missing_optional:
            console.print(f"- [yellow]{tool}[/yellow]")
        console.print("These tools provide alternative or supplementary capabilities.")
        console.print("You can install them if you wish to use features that depend on them.")

    if missing_core: # Prioritize missing core dependencies for return status
        # console.print("\n[red]Please install missing core dependencies to ensure proper operation.[/red]")
        return False # Indicate that core dependencies are missing

    return True # All core dependencies are present, optional might be missing

def read_config(target_base_path: str) -> dict:
    """
    Reads the config.txt file and returns a dictionary of configurations.
    Moved here from recon.py to be a common utility.
    """
    config_path = os.path.join(target_base_path, "config.txt")
    config = {}
    try:
        with open(config_path, "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    config[key.strip()] = value.strip()
    except FileNotFoundError:
        # console.print(f"[red]Error: Configuration file not found at {config_path}[/red]")
        # This function is a utility; let the caller decide how to handle missing file if critical
        return None
    except Exception as e:
        # console.print(f"[red]Error reading configuration file: {e}[/red]")
        return None
    return config


if __name__ == '__main__':
    check_dependencies()
