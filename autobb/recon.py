import os
import subprocess
import shutil # For checking if a command exists
from rich.console import Console
from .utils import read_config # Import from utils

console = Console()

# def read_config(target_base_path: str) -> dict: # Removed, now using utils.read_config
#     """Reads the config.txt file and returns a dictionary of configurations."""
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

def run_whois(target_base_path: str):
    """
    Runs the whois command for the target domain/IP.
    Saves the output to target_folder/recon/whois/whois_results.txt.
    """
    console.print("\n[cyan]Starting Whois scan...[/cyan]")

    config = read_config(target_base_path)
    if not config or "TARGET_IDENTIFIER" not in config:
        console.print("[red]Could not retrieve target identifier from config.[/red]")
        return

    target_identifier = config["TARGET_IDENTIFIER"]

    # Check if whois is installed
    if not shutil.which("whois"):
        console.print("[yellow]whois command not found. Please install it to use this feature.[/yellow]")
        console.print("On Debian/Ubuntu: sudo apt install whois")
        console.print("On Fedora: sudo dnf install whois")
        console.print("On Arch: sudo pacman -S whois")
        # TODO: Add a check for other OS and guide for installation
        return

    whois_output_dir = os.path.join(target_base_path, "recon", "whois")
    os.makedirs(whois_output_dir, exist_ok=True)
    output_file = os.path.join(whois_output_dir, "whois_results.txt")

    try:
        console.print(f"Running whois for [blue]{target_identifier}[/blue]...")
        # We need to handle potential errors from whois itself (e.g., target not found by whois servers)
        process = subprocess.run(
            ["whois", target_identifier],
            capture_output=True,
            text=True,
            check=False # Do not throw exception for non-zero exit codes from whois
        )

        if process.returncode != 0 and process.stderr :
            # Some whois versions print errors to stderr for things like "No match for domain"
            # which are not fatal for our purposes. We still save the output.
            console.print(f"[yellow]Whois command returned an error or warning (exit code {process.returncode}):[/yellow]")
            console.print(f"[dim]{process.stderr}[/dim]")

        with open(output_file, "w") as f:
            f.write(f"WHOIS results for: {target_identifier}\n")
            f.write("=" * 30 + "\n")
            f.write(process.stdout)
            if process.stderr: # Also save stderr if any
                 f.write("\n" + "="*30 + " ERRORS/WARNINGS " + "="*30 + "\n")
                 f.write(process.stderr)


        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            console.print(f"[green]Whois results saved to:[/green] {output_file}")
            # Optionally, print a snippet of the output
            # console.print("\n[bold]Whois Output Snippet:[/bold]")
            # console.print(process.stdout[:500] + "..." if len(process.stdout) > 500 else process.stdout)
        else:
            console.print(f"[yellow]Whois command executed but output file is empty or not created.[/yellow]")
            if process.stdout:
                 console.print("[bold]STDOUT from whois was:[/bold]")
                 console.print(process.stdout)
            if process.stderr:
                 console.print("[bold]STDERR from whois was:[/bold]")
                 console.print(process.stderr)


    except FileNotFoundError: # Should be caught by shutil.which, but as a fallback
        console.print("[red]whois command not found. Please install it.[/red]")
    except subprocess.TimeoutExpired:
        console.print("[red]whois command timed out.[/red]")
    except Exception as e:
        console.print(f"[red]An error occurred while running whois:[/red] {e}")

# Placeholder for other recon functions
def run_nmap(target_base_path: str):
    console.print("\n[cyan]Nmap scan (Not implemented yet).[/cyan]")
    config = read_config(target_base_path)
    if config and "TARGET_IDENTIFIER" in config:
        console.print(f"Target: {config['TARGET_IDENTIFIER']}")

def run_subdomain_enum(target_base_path: str):
    console.print("\n[cyan]Subdomain Enumeration (Not implemented yet).[/cyan]")

def run_dir_bruteforce(target_base_path: str):
    console.print("\n[cyan]Directory Brute-force (Not implemented yet).[/cyan]")

def run_wayback(target_base_path: str):
    console.print("\n[cyan]Wayback/Archive Scan (Not implemented yet).[/cyan]")

def run_httprobe(target_base_path: str):
    console.print("\n[cyan]HTTP Probe (Not implemented yet).[/cyan]")

def run_tech_scan(target_base_path: str):
    console.print("\n[cyan]Technology Stack Scan (Not implemented yet).[/cyan]")


def reconnaissance_menu(target_base_path: str):
    """Displays the reconnaissance menu and handles user choice."""
    while True:
        console.print("\n[bold green]--- Reconnaissance Menu ---[/bold green]")
        recon_options = {
            "1": "Run Whois Scan",
            "2": "Run Nmap Scan",
            "3": "Run Subdomain Enumeration (sublist3r, amass)",
            "4": "Run Directory Brute-force (gobuster, dirsearch)",
            "5": "Run Wayback/Archive Scan (waybackurls, gau)",
            "6": "Run HTTP Probe (httprobe)",
            "7": "Run Technology Stack Scan (whatweb, wappalyzer)",
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
            run_wayback(target_base_path)
        elif choice == "6":
            run_httprobe(target_base_path)
        elif choice == "7":
            run_tech_scan(target_base_path)
        elif choice == "8":
            console.print("\n[blue]Running all reconnaissance scans...[/blue]")
            run_whois(target_base_path)
            run_nmap(target_base_path)
            run_subdomain_enum(target_base_path)
            run_dir_bruteforce(target_base_path)
            run_wayback(target_base_path)
            run_httprobe(target_base_path)
            run_tech_scan(target_base_path)
            console.print("\n[blue]All reconnaissance scans initiated.[/blue]")
        elif choice == "9":
            break
        else:
            console.print("[red]Invalid option.[/red]")
