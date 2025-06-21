#!/usr/bin/env python3

import os
import argparse
from rich.console import Console
from rich.prompt import Prompt
import subprocess
from autobb import recon
from autobb import vulnerabilities
from autobb import fuzzing
from autobb import exploitation
from autobb import reporting
from autobb import notes_manager
from autobb import utils
from autobb.config_manager import load_global_config, ensure_user_config_dir_exists # Import config funcs

console = Console()

CURRENT_TARGET_BASE_PATH = None
CURRENT_TARGET_IDENTIFIER = None


def create_target_directory_structure(base_path: str, target_name: str) -> str:
    global CURRENT_TARGET_BASE_PATH
    target_path = os.path.join(base_path, target_name)
    CURRENT_TARGET_BASE_PATH = target_path

    directories = [
        "recon/nmap", "recon/subdomains", "recon/gobuster", "recon/wayback", "recon/whois",
        "vulnerabilities/xss", "vulnerabilities/sqli", "vulnerabilities/ssrf",
        "vulnerabilities/open_redirect", "vulnerabilities/command_injection", "vulnerabilities/ssti",
        "vulnerabilities/insecure_deserialization", "vulnerabilities/file_upload",
        "vulnerabilities/security_misconfigurations",
        "fuzzing",
        "exploitation",
        "screenshots",
        "notes"
    ]
    try:
        os.makedirs(target_path, exist_ok=True)
        for directory in directories:
            full_dir_path = os.path.join(target_path, directory)
            os.makedirs(full_dir_path, exist_ok=True)
        console.print(f"[green]Created directory structure within:[/green] {target_path}")
        return target_path
    except OSError as e:
        console.print(f"[red]Error creating directory structure:[/red] {e}")
        CURRENT_TARGET_BASE_PATH = None
        return None

def save_config(target_path: str, target_identifier: str, output_location: str) -> bool:
    config_file_path = os.path.join(target_path, "config.txt")
    try:
        with open(config_file_path, "w") as f:
            f.write(f"TARGET_IDENTIFIER={target_identifier}\n")
            f.write(f"OUTPUT_LOCATION={output_location}\n")
            f.write(f"TARGET_PATH={target_path}\n")
        console.print(f"[green]Configuration saved to:[/green] {config_file_path}")
        return True
    except IOError as e:
        console.print(f"[red]Error saving configuration to {config_file_path}:[/red] {e}")
        return False

def display_main_menu():
    console.print("\n[bold cyan]AutoBugBounty (AutoBB) - Main Menu[/bold cyan]")
    menu_options = {
        "1": "Reconnaissance",
        "2": "Vulnerability Analysis",
        "3": "Fuzzing & Automation",
        "4": "Exploitation",
        "5": "Generate Bug Bounty Summary Report",
        "6": "View Notes",
        "7": "Exit"
    }
    for key, value in menu_options.items():
        console.print(f"[magenta][{key}][/magenta] {value}")

    choice = Prompt.ask("Select an option", choices=list(menu_options.keys()), default="7")
    return choice

def initial_setup():
    global CURRENT_TARGET_IDENTIFIER, CURRENT_TARGET_BASE_PATH

    console.print("[bold blue]Welcome to AutoBugBounty (AutoBB)![/bold blue]")

    # Dependency check moved to main() before initial_setup()

    target_identifier_prompt = Prompt.ask("Enter the target IP address or domain name")
    sanitized_target_name = "".join(c if c.isalnum() or c in ('.', '-', '_') else '_' for c in target_identifier_prompt)
    if not sanitized_target_name:
        sanitized_target_name = "default_target"
        console.print(f"[yellow]Target identifier was sanitized to '{sanitized_target_name}'[/yellow]")

    CURRENT_TARGET_IDENTIFIER = target_identifier_prompt

    output_location_default = os.path.join(os.getcwd(), "autobb_targets")
    output_location = Prompt.ask(f"Enter the location to save the target folder", default=output_location_default)

    if not os.path.isdir(output_location):
        try:
            os.makedirs(output_location, exist_ok=True)
            console.print(f"[yellow]Output location '{output_location}' did not exist. Created it.[/yellow]")
        except OSError as e:
            console.print(f"[red]The specified output location '{output_location}' is invalid and could not be created: {e}[/red]")
            return False

    target_base_path_val = create_target_directory_structure(output_location, sanitized_target_name)

    if not target_base_path_val:
        console.print("[red]Failed to create target directory structure. Exiting.[/red]")
        return False

    save_config(CURRENT_TARGET_BASE_PATH, CURRENT_TARGET_IDENTIFIER, output_location)
    return True


def main():
    parser = argparse.ArgumentParser(description="AutoBugBounty (AutoBB) - CLI Bug Bounty Toolkit")
    args = parser.parse_args()

    # Perform dependency check at the start
    if not utils.check_dependencies():
        # Ask user if they want to continue if core dependencies are missing
        if not Prompt.ask("[bold red]Core dependencies missing. Continue anyway? (yes/no)[/bold red]", choices=["yes", "no"], default="no") == "yes":
            console.print("[yellow]Exiting due to missing core dependencies.[/yellow]")
            return

    if not initial_setup():
        return

    while True:
        if not CURRENT_TARGET_BASE_PATH or not CURRENT_TARGET_IDENTIFIER:
            console.print("[red]Critical error: Target context is not set. Please restart.[/red]")
            break

        choice = display_main_menu()

        if choice == "1":
            recon.reconnaissance_menu(CURRENT_TARGET_BASE_PATH)
        elif choice == "2":
            vulnerabilities.vulnerability_analysis_menu(CURRENT_TARGET_BASE_PATH)
        elif choice == "3":
            fuzzing.fuzzing_automation_menu(CURRENT_TARGET_BASE_PATH)
        elif choice == "4":
            exploitation.exploitation_menu(CURRENT_TARGET_BASE_PATH)
        elif choice == "5":
            reporting.generate_report(CURRENT_TARGET_BASE_PATH)
        elif choice == "6":
            notes_manager.view_notes(CURRENT_TARGET_BASE_PATH)
        elif choice == "7":
            console.print("[bold blue]Exiting AutoBugBounty. Goodbye![/bold blue]")
            break

if __name__ == "__main__":
    main()
