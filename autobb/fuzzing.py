import os
import shutil
import subprocess
import re
import tempfile # For fallback wordlist
from rich.console import Console
from rich.prompt import Prompt
from .utils import read_config # For target-specific config
from autobb.config_manager import get_config_value # For global autobb_config.yaml

console = Console()

DEFAULT_FALLBACK_PAYLOADS = [
    # Common words & special characters
    "test", "admin", "user", "pass", "FUZZ", "null", "true", "false", "1", "0", "-1",
    "'", "\"", "<", ">", ";", "|", "&", "$", "(", ")", "{", "}", "[", "]", "`", "\\",
    # Basic XSS
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><svg/onload=alert(1)>",
    # Basic SQLi
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    # Basic LFI/Path Traversal
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    # Basic CMDi (very simple, often needs context)
    ";id",
    "|id",
    "&id", # Windows
    # Basic SSTI-like probes
    "{{7*7}}",
    "${7*7}",
    # Common parameters often found in logs or default configs
    "id", "user_id", "username", "password", "filename", "file", "page", "redirect", "url", "next", "cmd", "exec"
]

DEFAULT_FALLBACK_FUZZ_PAYLOADS = [
    # Common words & tests
    "test", "admin", "user", "pass", "password", "login", "key", "id", "FUZZ", "null",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    # Basic SQLi
    "'", "\"", "`", "')", "\")", "`)", "OR 1=1 --", "OR '1'='1", "' OR 1=1 --",
    "admin'--", "admin' OR '1'='1",
    # Basic XSS
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><svg/onload=alert(1)>",
    # Basic CMDi
    "|id", ";id", "&&id",
    "|whoami", ";whoami",
    "& dir", "& ipconfig",
    # Basic SSTI
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
    # Basic Path Traversal / Other
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "WEB-INF/web.xml",
    # Common backup/config files (often found via dir busting but can be params too)
    ".env", ".git/config", "config.json", "settings.py"
]

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

    # --- URL Suggestion Logic ---
    suggested_urls = []
    wayback_file_path = os.path.join(target_base_path, "recon", "wayback", "archive_urls_unique.txt")
    selected_target_url_from_suggestion = None

    if os.path.exists(wayback_file_path) and os.path.getsize(wayback_file_path) > 0:
        try:
            with open(wayback_file_path, 'r', encoding='utf-8', errors='ignore') as f_wayback:
                urls_with_params = set() # Use a set to store unique URLs with params
                for line in f_wayback:
                    url = line.strip()
                    if '?' in url and '=' in url: # Basic check for query parameters
                        # Extract base URL + path + query string (without fragment)
                        base_with_query = url.split('#')[0]
                        urls_with_params.add(base_with_query)

                suggested_urls = sorted(list(urls_with_params))[:20] # Limit to top 20 suggestions

            if suggested_urls:
                console.print("\n[bold green]Found URLs with parameters from Recon data (Wayback):[/bold green]")
                for i, sug_url in enumerate(suggested_urls):
                    console.print(f"  [magenta][{i+1}][/magenta] {sug_url}")
                console.print(f"  [magenta][M][/magenta] Enter URL Manually")

                url_choice_options = [str(i+1) for i in range(len(suggested_urls))] + ["M", "m"]
                url_choice = Prompt.ask("Select a URL to fuzz or [M]anual entry", choices=url_choice_options, default="M")

                if url_choice.upper() != "M":
                    try:
                        selected_target_url_from_suggestion = suggested_urls[int(url_choice)-1]
                        console.print(f"Selected URL for fuzzing: [blue]{selected_target_url_from_suggestion}[/blue]")
                    except (ValueError, IndexError):
                        console.print("[yellow]Invalid selection, proceeding to manual URL entry.[/yellow]")
                        selected_target_url_from_suggestion = None # Fallback to manual
                else:
                    selected_target_url_from_suggestion = None # Manual entry chosen
        except Exception as e_wayback_read:
            console.print(f"[yellow]Could not read or parse wayback URLs file: {e_wayback_read}. Proceeding with manual URL entry.[/yellow]")
            selected_target_url_from_suggestion = None

    if selected_target_url_from_suggestion:
        target_url = selected_target_url_from_suggestion # Use the selected URL
    else:
        target_url = Prompt.ask("Enter the full target URL (e.g., https://example.com/page or https://example.com/search?q=test)")

    if not target_url:
        console.print("[red]Target URL cannot be empty. Skipping parameter fuzzing.[/red]")
        return

    # --- Payload Type and Wordlist Selection ---
    console.print("\n[bold]Payload Type Selection for Fuzzing:[/bold]")
    payload_categories = {
        "1": "Generic (Default/Broad)",
        "2": "XSS (Cross-Site Scripting)",
        "3": "SQLi (SQL Injection)",
        "4": "LFI (Local File Inclusion)",
        "5": "CMDi (Command Injection)",
        "6": "Custom (Specify wordlist directly)"
    }
    for k, v in payload_categories.items():
        console.print(f"  [magenta][{k}][/magenta] {v}")
    payload_type_choice_key = Prompt.ask("Select payload category for wordlist suggestion", choices=payload_categories.keys(), default="1")

    selected_payload_category_name = payload_categories[payload_type_choice_key].split(" ")[0].lower() # e.g., "generic", "xss"
    if payload_type_choice_key == "6": # Custom
        selected_payload_category_name = "custom" # Will just prompt for path without specific suggestion

    effective_default_fuzz_wl = None
    specific_wl_key = f"wordlists.parameter_fuzzing_{selected_payload_category_name}"
    generic_wl_key = "wordlists.parameter_fuzzing_generic"

    if selected_payload_category_name != "custom":
        specific_wl_path_config = get_config_value(specific_wl_key)
        if specific_wl_path_config and os.path.exists(os.path.expanduser(specific_wl_path_config)):
            effective_default_fuzz_wl = os.path.expanduser(specific_wl_path_config)
            console.print(f"[dim]Using configured wordlist for '{selected_payload_category_name}': {effective_default_fuzz_wl}[/dim]")

    if not effective_default_fuzz_wl and selected_payload_category_name != "custom": # If specific not found/valid, try generic
        generic_wl_path_config = get_config_value(generic_wl_key)
        if generic_wl_path_config and os.path.exists(os.path.expanduser(generic_wl_path_config)):
            effective_default_fuzz_wl = os.path.expanduser(generic_wl_path_config)
            console.print(f"[dim]Specific wordlist for '{selected_payload_category_name}' not found/configured. Using generic fuzzing wordlist: {effective_default_fuzz_wl}[/dim]")

    payload_wordlist_str = Prompt.ask(
        f"Enter path to payload wordlist for '{selected_payload_category_name.upper()}' fuzzing (or press Enter for basic fallback)",
        default=effective_default_fuzz_wl if effective_default_fuzz_wl else "" # Ensure default is "" if None for Prompt
    )

    payload_wordlist_to_use = None
    temp_payload_file_obj = None # To hold the tempfile object for later cleanup
    using_temp_wordlist = False

    if payload_wordlist_str: # User provided a path
        expanded_user_path = os.path.expanduser(payload_wordlist_str)
        if os.path.exists(expanded_user_path):
            payload_wordlist_to_use = expanded_user_path
        else:
            console.print(f"[red]User-provided wordlist not found at '{expanded_user_path}'. Skipping.[/red]")
            return
    elif effective_default_fuzz_wl: # User pressed Enter, but a configured default was found and used by Prompt
        # This case means effective_default_fuzz_wl was used by Prompt as it was not empty.
        # Prompt.ask returns the default if user input is empty.
        # So, if payload_wordlist_str IS effective_default_fuzz_wl, it means user accepted default.
        if payload_wordlist_str == effective_default_fuzz_wl : # Actually, Prompt returns the default if input is empty
             payload_wordlist_to_use = effective_default_fuzz_wl
             console.print(f"[dim]Using configured default wordlist: {payload_wordlist_to_use}[/dim]")
        # This logic branch might be tricky if Prompt.ask default="" when effective_default_fuzz_wl is None
        # Corrected logic: if payload_wordlist_str is EMPTY and effective_default_fuzz_wl was also None, THEN use fallback.
        # If payload_wordlist_str is NOT empty, it's either user input or the passed default.
        # The Prompt.ask default behavior needs to be handled carefully.
        # Let's simplify: if payload_wordlist_str (after prompt) is effectively empty, and no valid default was used.
        # Re-evaluating the condition for fallback:
        # Fallback is used if:
        # 1. User presses Enter (payload_wordlist_str is empty from Prompt if default was also empty).
        # 2. AND effective_default_fuzz_wl was None (meaning no valid config path was found to offer as default).

        # Simpler logic:
        # payload_wordlist_str will be the value from Prompt.ask.
        # If it's empty, it means user pressed Enter AND the default passed to Prompt.ask was also empty/None.
        if not payload_wordlist_str: # This implies effective_default_fuzz_wl was None or empty
            console.print("[yellow]Warning: No wordlist path provided and no valid default configured. Using a small built-in basic payload list.[/yellow]")
            console.print("[yellow]For comprehensive fuzzing, it is strongly recommended to provide a dedicated wordlist path or configure defaults in autobb_config.yaml.[/yellow]")
            try:
                temp_payload_file_obj = tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', suffix=".txt")
                for payload in DEFAULT_FALLBACK_PAYLOADS:
                    temp_payload_file_obj.write(payload + '\n')
                temp_payload_file_obj.close()
                payload_wordlist_to_use = temp_payload_file_obj.name
                using_temp_wordlist = True
                console.print(f"[dim]Using temporary fallback wordlist: {payload_wordlist_to_use}[/dim]")
            except Exception as e_temp:
                console.print(f"[red]Error creating temporary fallback wordlist: {e_temp}. Skipping fuzzing.[/red]")
                return
        else: # User provided a path, or a valid default from config was accepted
            payload_wordlist_to_use = os.path.expanduser(payload_wordlist_str)
            if not os.path.exists(payload_wordlist_to_use): # Should be caught by initial check if user provided, but double check if default was bad
                 console.print(f"[red]Wordlist path '{payload_wordlist_to_use}' does not exist. Skipping fuzzing.[/red]")
                 return

    if not payload_wordlist_to_use: # Should not happen if logic above is correct, but as a safeguard
        console.print("[red]Wordlist determination failed. Skipping fuzzing.[/red]")
        return
    # --- End of Payload Type and Wordlist Selection ---

    ffuf_command = [ffuf_path, "-w", f"{payload_wordlist_to_use}:FUZZ"]
    fuzz_description = selected_payload_category_name # Use category for filename

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
