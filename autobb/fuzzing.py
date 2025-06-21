import os
from rich.console import Console
from rich.prompt import Prompt
from .utils import read_config # Import from utils

console = Console()

# Helper function to read config (can be refactored to utils.py)
# def read_config_from_fuzzing(target_base_path: str) -> dict: # Removed
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

# Placeholder functions for fuzzing tasks
def run_parameter_fuzzing(target_base_path: str):
    console.print("\n[cyan]Performing Parameter Fuzzing (e.g., ffuf, wfuzz) (Not implemented yet).[/cyan]")
    config = read_config(target_base_path)
    if config and "TARGET_IDENTIFIER" in config:
        console.print(f"Target: {config['TARGET_IDENTIFIER']}")
    console.print("This would use known endpoints from recon/ and wayback/.")
    console.print("Interesting responses would be saved in target_folder/fuzzing/.")

def check_burp_integration(target_base_path: str):
    console.print("\n[cyan]Checking Burp Suite Integration (Not implemented yet).[/cyan]")
    config = read_config(target_base_path)
    if config and "TARGET_IDENTIFIER" in config:
        console.print(f"Target: {config['TARGET_IDENTIFIER']}")
    console.print("If Burp Suite is installed and configured, this section could provide guidance or hooks for automated tests via its API (advanced).")
    console.print("For now, manual proxying through Burp is assumed if user desires.")

def run_header_fuzzing(target_base_path: str):
    console.print("\n[cyan]Performing Custom Header Fuzzing (Not implemented yet).[/cyan]")
    config = read_config(target_base_path)
    if config and "TARGET_IDENTIFIER" in config:
        console.print(f"Target: {config['TARGET_IDENTIFIER']}")
    console.print("This would involve custom scripts to fuzz headers like X-Forwarded-For, Host, User-Agent etc.")


def fuzzing_automation_menu(target_base_path: str):
    """Displays the fuzzing & automation menu and handles user choice."""
    while True:
        console.print("\n[bold blue]--- Fuzzing & Automation Menu ---[/bold blue]")
        fuzzing_options = {
            "1": "Parameter Fuzzing (ffuf/wfuzz)",
            "2": "Burp Suite Integration/Guidance",
            "3": "Custom Header Fuzzing Scripts",
            "4": "Run All Fuzzing Tasks (Placeholders)",
            "5": "Back to Main Menu"
        }
        for key, value in fuzzing_options.items():
            console.print(f"[magenta][{key}][/magenta] {value}")

        choice = Prompt.ask("Select a fuzzing/automation task", choices=list(fuzzing_options.keys()), default="5")

        if choice == "1":
            run_parameter_fuzzing(target_base_path)
        elif choice == "2":
            check_burp_integration(target_base_path)
        elif choice == "3":
            run_header_fuzzing(target_base_path)
        elif choice == "4":
            console.print("\n[blue]Running all fuzzing & automation tasks (placeholders)...[/blue]")
            run_parameter_fuzzing(target_base_path)
            check_burp_integration(target_base_path)
            run_header_fuzzing(target_base_path)
            console.print("\n[blue]All fuzzing & automation tasks (placeholders) initiated.[/blue]")
        elif choice == "5":
            break
        else:
            console.print("[red]Invalid option.[/red]")
