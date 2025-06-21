import os
import shutil
import subprocess
import re
from rich.console import Console
from rich.prompt import Prompt
from .utils import read_config # For target-specific config
from autobb.config_manager import get_config_value # For global autobb_config.yaml

console = Console()

def _get_tool_path_fuzz(tool_name: str, friendly_name: str = None) -> str:
    """Helper to get tool path from config or shutil.which for fuzzing module."""
    if not friendly_name:
        friendly_name = tool_name.capitalize()
    configured_path = get_config_value(f"tool_paths.{tool_name.lower()}")
    if configured_path:
        expanded_path = os.path.expanduser(configured_path)
        if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
            console.print(f"[dim]Using configured path for {friendly_name}: {expanded_path}[/dim]")
            return expanded_path
        else:
            console.print(f"[yellow]Warning: Configured path for {friendly_name} ('{configured_path}') is invalid. Trying PATH.[/yellow]")
    return shutil.which(tool_name)

def run_parameter_fuzzing(target_base_path: str):
    console.print("\n[bold #FFD700]--- Parameter Fuzzing with FFuF ---[/bold #FFD700]")
    config = read_config(target_base_path)
    target_identifier_display = config.get("TARGET_IDENTIFIER", "the target") if config else "the target"
    console.print(f"\n[italic]Target context: {target_identifier_display}[/italic]")

    console.print("\n[bold u]Understanding Parameter Fuzzing:[/bold u]")
    console.print(
        "Parameter fuzzing involves sending a variety of inputs (payloads) in URL parameters (GET), "
        "request bodies (POST), or HTTP headers to discover vulnerabilities. This can help find XSS, "
        "SQLi, command injection, Local File Inclusion (LFI), information disclosure, etc."
    )

    if not shutil.which("ffuf"):
        console.print("[yellow]ffuf command not found. Please install ffuf to use this feature.[/yellow]")
        return

    fuzz_output_dir = os.path.join(target_base_path, "fuzzing", "ffuf_parameter_fuzz")
    os.makedirs(fuzz_output_dir, exist_ok=True)

    console.print("\n[bold]Fuzzing Configuration:[/bold]")

    fuzz_type_choices = {
        "1": "GET Parameter (URL)",
        "2": "POST Parameter (Request Body)",
        "3": "HTTP Header"
    }
    console.print("Select Fuzzing Type:")
    for k, v in fuzz_type_choices.items():
        console.print(f"  [magenta][{k}][/magenta] {v}")
    fuzz_type_choice = Prompt.ask("Enter choice", choices=fuzz_type_choices.keys(), default="1")

    target_url = Prompt.ask("Enter the full target URL (e.g., https://example.com/page)")
    if not target_url:
        console.print("[red]Target URL cannot be empty. Skipping parameter fuzzing.[/red]")
        return

    payload_wordlist = Prompt.ask("Enter path to payload wordlist (e.g., /usr/share/seclists/Fuzzing/LFI-Jhaddix.txt)")
    if not payload_wordlist or not os.path.exists(payload_wordlist):
        console.print(f"[red]Payload wordlist not found at '{payload_wordlist}'. Skipping.[/red]")
        return

    ffuf_command = ["ffuf", "-w", f"{payload_wordlist}:FUZZ"]
    fuzz_description = ""

    if fuzz_type_choice == "1": # GET Parameter
        get_param_url = Prompt.ask(
            "Enter URL with FUZZ in the parameter value (e.g., https://example.com/search?q=FUZZ&cat=books)",
            default=f"{target_url}?param=FUZZ"
        )
        if "FUZZ" not in get_param_url:
            console.print("[red]FUZZ keyword missing in GET parameter URL. Skipping.[/red]")
            return
        ffuf_command.extend(["-u", get_param_url])
        fuzz_description = "get_" + (get_param_url.split('?')[1].split('=FUZZ')[0].split('&')[-1] if '?' in get_param_url and '=FUZZ' in get_param_url.split('?')[1] else "param")

    elif fuzz_type_choice == "2": # POST Parameter
        post_data = Prompt.ask(
            "Enter POST data with FUZZ keyword (e.g., username=FUZZ&pass=secret or {\"key\":\"FUZZ\"})",
            default="param=FUZZ"
        )
        if "FUZZ" not in post_data:
            console.print("[red]FUZZ keyword missing in POST data. Skipping.[/red]")
            return
        ffuf_command.extend(["-u", target_url, "-X", "POST", "-d", post_data])
        content_type_post = Prompt.ask("Enter Content-Type for POST (e.g., application/x-www-form-urlencoded, application/json)", default="application/x-www-form-urlencoded")
        ffuf_command.extend(["-H", f"Content-Type: {content_type_post}"])
        fuzz_description = "post_" + (post_data.split('=FUZZ')[0].split('&')[-1] if '=' in post_data else "data")

    elif fuzz_type_choice == "3": # HTTP Header
        header_to_fuzz = Prompt.ask(
            "Enter Header to fuzz (e.g., X-Custom-Header: FUZZ or User-Agent: FUZZ)",
            default="X-Test-Header: FUZZ"
        )
        if "FUZZ" not in header_to_fuzz:
            console.print("[red]FUZZ keyword missing in Header. Skipping.[/red]")
            return
        ffuf_command.extend(["-u", target_url, "-H", header_to_fuzz])
        fuzz_description = "header_" + header_to_fuzz.split(':')[0].strip()

    additional_ffuf_options_str = Prompt.ask(
        "Enter any additional ffuf options (e.g., -fs <size>, -mc 200,302, -rate 50)",
        default="-mc 200,204,301,302,307,401,403,500"
    )
    if additional_ffuf_options_str:
        ffuf_command.extend(additional_ffuf_options_str.split())

    sanitized_target_filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', target_url.replace("http://","").replace("https://",""))
    sanitized_fuzz_desc = re.sub(r'[^a-zA-Z0-9_.-]', '_', fuzz_description)
    output_filename_base = f"ffuf_{sanitized_fuzz_desc}_{sanitized_target_filename[:50]}"
    # Output path for ffuf's -o option (it appends .json, .html etc based on -of)
    output_ffuf_option_path = os.path.join(fuzz_output_dir, output_filename_base)

    user_defined_output = False
    for opt in ffuf_command:
        if opt in ['-o', '--output']:
            user_defined_output = True
            break

    if not user_defined_output:
        ffuf_command.extend(["-o", output_ffuf_option_path, "-of", "all"])
        console.print(f"FFuF output (all formats) will be saved to files starting with: [blue]{output_ffuf_option_path}[/blue] (e.g., .txt, .json, .html)")
    else:
        console.print(f"FFuF output will be handled by user-provided output options.")

    console.print(f"\nRunning FFuF: [blue]{' '.join(ffuf_command)}[/blue]")
    console.print("[yellow]FFuF scan may take some time...[/yellow]")

    try:
        process = subprocess.run(ffuf_command, capture_output=True, text=True, check=False, timeout=1800)
        if process.stdout: console.print(f"[dim]FFuF stdout:\n{process.stdout}[/dim]")
        if process.stderr: console.print(f"[yellow]FFuF stderr:\n{process.stderr}[/yellow]")

        # Check if any output file was created by ffuf if we specified the name
        # This is a bit heuristic as ffuf with -of all creates multiple files.
        # We'll check for the .txt version if we set the base name.
        final_text_output_path = output_ffuf_option_path + ".txt" if not user_defined_output else "user_defined_output_file"

        if not user_defined_output:
            if os.path.exists(final_text_output_path) and os.path.getsize(final_text_output_path) > 0 :
                 console.print(f"[green]FFuF parameter fuzzing results saved (check files starting with {output_ffuf_option_path}).[/green]")
            else:
                 console.print(f"[yellow]FFuF primary output file ({final_text_output_path}) not found or empty. Check ffuf's stdout/stderr.[/yellow]")
        else: # User specified output, so we don't know the exact filename to check easily
            console.print("[green]FFuF scan complete. Please check the output location you specified in options.[/green]")

    except Exception as e:
        console.print(f"[red]An error occurred during FFuF parameter fuzzing: {e}[/red]")


def provide_header_fuzzing_guidance(target_base_path: str):
    console.print("\n[bold #48D1CC]--- HTTP Header Fuzzing Guidance ---[/bold #48D1CC]")
    config = read_config(target_base_path)
    target_identifier_display = config.get("TARGET_IDENTIFIER", "the target") if config else "the target"
    console.print(f"\n[italic]Target context: {target_identifier_display}[/italic]")
    console.print("\n[bold u]Understanding HTTP Header Fuzzing:[/bold u]")
    console.print("Fuzzing HTTP headers involves sending various payloads in standard or custom HTTP request headers to uncover vulnerabilities like SQLi, XSS, cache poisoning, or access control bypasses.")
    console.print("\n[bold]Common Headers to Target & Payloads/Techniques:[/bold]")
    guidance = [
        "- [cyan]User-Agent, Referer:[/cyan] Test with long strings, XSS/SQLi payloads, command injection characters.",
        "- [cyan]Host / X-Forwarded-Host:[/cyan] Inject different hostnames, internal IPs, full URLs. Can lead to cache poisoning or bypasses.",
        "- [cyan]X-Forwarded-For / X-Real-IP etc.:[/cyan] Test for SQLi/command injection if logged/processed. Try multiple IPs.",
        "- [cyan]Cookie:[/cyan] Fuzz individual cookie values for SQLi, XSS, logic flaws.",
        "- [cyan]Authorization / X-API-Key etc.:[/cyan] Test with malformed tokens, default creds, SQLi/XSS.",
        "- [cyan]Custom Headers (X-Client-ID etc.):[/cyan] Test with unexpected inputs, boolean/numeric values."
    ]
    for line in guidance: console.print(f"  {line}")
    console.print("\n[bold]Automated Header Fuzzing with FFuF (via Parameter Fuzzing Option):[/bold]")
    console.print("  1. Select 'Parameter Fuzzing (with ffuf...)' from the Fuzzing & Automation menu.")
    console.print("  2. Choose fuzzing type '[magenta][3][/magenta] HTTP Header'.")
    console.print("  3. Enter target URL, payload wordlist, and the Header to fuzz (e.g., `User-Agent: FUZZ`).")
    console.print("\n[bold]Manual Header Testing:[/bold]")
    console.print("  - Use Burp Repeater or `curl` to craft requests with modified headers. Observe changes in responses.")
    console.print("\n[green]Combine automated approach with manual inspection for best results.[/green]")


def check_burp_integration(target_base_path: str):
    console.print("\n[bold #FF7F50]--- Burp Suite Integration/Guidance ---[/bold #FF7F50]")
    config = read_config(target_base_path)
    target_identifier_display = config.get("TARGET_IDENTIFIER", "the target") if config else "the target"
    console.print(f"\n[italic]Target context: {target_identifier_display}[/italic]")
    console.print("\n[bold u]Using Burp Suite with AutoBB:[/bold u]")
    guidance = [
        "1. [bold]Proxy Traffic:[/bold] Configure your system/terminal to proxy HTTP/S traffic via Burp Suite (e.g., 127.0.0.1:8080). Requests from AutoBB's tools (if they respect system proxy) or your manual follow-ups will appear in Burp.",
        "2. [bold]Scope Definition:[/bold] Use AutoBB's recon output (subdomains, live hosts) to define your scope in Burp for targeted manual testing and active scanning.",
        "3. [bold]Manual Payload Crafting:[/bold] When AutoBB provides guidance (e.g., for Command Injection, SSRF, BAC), use Burp Repeater to send customized payloads.",
        "4. [bold]Targeted Fuzzing:[/bold] Use Burp Intruder for fine-grained fuzzing based on suspicions from AutoBB's guidance or tool outputs, complementing AutoBB's `ffuf` integration.",
        "5. [bold]Exploitation & Verification:[/bold] Use Burp Repeater to manually verify and exploit findings.",
        "6. [bold]Session Handling:[/bold] Burp excels at managing complex session handling, which can be crucial when testing authenticated parts of applications."
    ]
    for line in guidance: console.print(f"  {line}")
    console.print("\n[green]AutoBB and Burp Suite are complementary: AutoBB for guided workflow & initial scans, Burp for deep-dive manual analysis and exploitation.[/green]")


def fuzzing_automation_menu(target_base_path: str):
    while True:
        console.print("\n[bold blue]--- Fuzzing & Automation Menu ---[/bold blue]")
        fuzzing_options = {
            "1": "Parameter Fuzzing (with ffuf - GET, POST, Headers)",
            "2": "HTTP Header Fuzzing (Guidance & ffuf Reminder)", # Renamed & points to guidance
            "3": "Burp Suite Integration/Guidance", # Order changed
            "4": "Run All Fuzzing Guidance/Tasks",
            "5": "Back to Main Menu"
        }
        for key, value in fuzzing_options.items():
            console.print(f"[magenta][{key}][/magenta] {value}")

        choice = Prompt.ask("Select a task", choices=list(fuzzing_options.keys()), default="5")

        if choice == "1":
            run_parameter_fuzzing(target_base_path)
        elif choice == "2":
            provide_header_fuzzing_guidance(target_base_path) # Updated call
        elif choice == "3":
            check_burp_integration(target_base_path) # Updated call
        elif choice == "4":
            console.print("\n[blue]Running all fuzzing & automation guidance/prompts...[/blue]")
            console.print("\n[cyan]1. Parameter Fuzzing (ffuf):[/cyan]")
            run_parameter_fuzzing(target_base_path)
            console.print("\n[cyan]2. HTTP Header Fuzzing Guidance:[/cyan]")
            provide_header_fuzzing_guidance(target_base_path)
            console.print("\n[cyan]3. Burp Suite Guidance:[/cyan]")
            check_burp_integration(target_base_path)
            console.print("\n[blue]All fuzzing guidance/prompts displayed.[/blue]")
        elif choice == "5":
            break
        else:
            console.print("[red]Invalid option.[/red]")
