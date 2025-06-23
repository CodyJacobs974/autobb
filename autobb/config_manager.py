import os
import yaml # PyYAML
from rich.console import Console
from pathlib import Path

console = Console()

CONFIG_FILE_NAME = "autobb_config.yaml" # User's custom config
# Standard user config directory: ~/.config/autobb/autobb_config.yaml
USER_CONFIG_DIR = Path.home() / ".config" / "autobb"
USER_CONFIG_PATH = USER_CONFIG_DIR / CONFIG_FILE_NAME
# Fallback to project root for development/portability: ./autobb_config.yaml
PROJECT_ROOT_CONFIG_PATH = Path(".") / CONFIG_FILE_NAME

# Global variable to hold the loaded configuration
_global_config = None
_config_loaded = False

def load_global_config(config_path_override: str = None) -> dict:
    """
    Loads the global configuration from standard locations or an override path.
    Locations checked in order:
    1. `config_path_override` (if provided)
    2. Project root: `./autobb_config.yaml`
    3. User config dir: `~/.config/autobb/autobb_config.yaml`

    Returns the loaded config dictionary, or an empty dict if not found or error.
    """
    global _global_config, _config_loaded

    paths_to_check = []
    if config_path_override:
        paths_to_check.append(Path(config_path_override))

    paths_to_check.extend([PROJECT_ROOT_CONFIG_PATH, USER_CONFIG_PATH])

    loaded_path = None
    for path in paths_to_check:
        if path.exists() and path.is_file():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    _global_config = yaml.safe_load(f)
                if not isinstance(_global_config, dict): # Ensure it's a dict
                    console.print(f"[yellow]Warning: Config file at {path} is not a valid dictionary. Using empty config.[/yellow]")
                    _global_config = {}
                else:
                    console.print(f"[dim]Loaded global configuration from: {path}[/dim]")
                    loaded_path = path
                _config_loaded = True
                return _global_config
            except yaml.YAMLError as e:
                console.print(f"[red]Error parsing YAML configuration file at {path}: {e}[/red]")
                _global_config = {} # Reset to empty on error
                _config_loaded = True # Mark as "loaded" (with error state / empty config)
                return _global_config
            except Exception as e:
                console.print(f"[red]Error reading configuration file at {path}: {e}[/red]")
                _global_config = {}
                _config_loaded = True
                return _global_config

    # If no config file was found after checking all paths
    if not loaded_path:
        console.print(f"[dim]No global configuration file ({CONFIG_FILE_NAME}) found in standard locations. Using default behavior.[/dim]")
        _global_config = {}

    _config_loaded = True
    return _global_config

def get_config_value(key_path: str, default=None):
    """
    Retrieves a value from the loaded global configuration using a dot-separated key_path.
    e.g., get_config_value("tool_paths.sqlmap", "/usr/bin/sqlmap")

    If the global config hasn't been loaded yet, it attempts to load it first.
    """
    global _global_config, _config_loaded

    if not _config_loaded:
        load_global_config() # Attempt to load if not already tried

    if _global_config is None: # Should be {} if load_global_config ran, but defensive check
        return default

    keys = key_path.split('.')
    value = _global_config
    try:
        for key in keys:
            if isinstance(value, dict):
                value = value[key]
            else: # Key path leads to a non-dict intermediate value
                return default
        return value
    except KeyError: # Key not found at some level
        return default
    except TypeError: # value is not a dict where expected
        return default

def ensure_user_config_dir_exists():
    """Ensures the user-specific config directory exists."""
    try:
        USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # console.print(f"[dim]Ensured user config directory exists: {USER_CONFIG_DIR}[/dim]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not create user config directory {USER_CONFIG_DIR}: {e}[/yellow]")


# Example of how it might be initialized in main.py:
# from autobb.config_manager import load_global_config, ensure_user_config_dir_exists
# ensure_user_config_dir_exists() # Call once at startup
# GLOBAL_CONFIG = load_global_config()
# And then other modules can import get_config_value or receive GLOBAL_CONFIG

if __name__ == '__main__':
    # Example Usage & Testing
    ensure_user_config_dir_exists()

    # Create a dummy project root config for testing
    dummy_project_config_content = """
tool_paths:
  nmap: /usr/local/bin/nmap_custom
  # nikto: null # Example of a null value
wordlists:
  directory_bruteforce: ~/wordlists/project_specific_dirs.txt
  xss: /opt/custom_xss.txt
nested:
  level1:
    level2: "hello from project config"
"""
    with open(PROJECT_ROOT_CONFIG_PATH, 'w') as f:
        f.write(dummy_project_config_content)

    # Create a dummy user config for testing (will be overridden by project if both exist, due to check order)
    if not USER_CONFIG_DIR.exists():
        USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    dummy_user_config_content = """
tool_paths:
  sqlmap: /opt/sqlmap/sqlmap.py
wordlists:
  directory_bruteforce: ~/.wordlists/user_dirs.txt # This would be overridden by project root one
nested:
  level1:
    level2: "hello from user config" # Overridden
    level3: "user specific value"
"""
    with open(USER_CONFIG_PATH, 'w') as f:
        f.write(dummy_user_config_content)

    print(f"--- Testing Config Loading (Project root should take precedence for overlapping keys) ---")
    loaded_cfg = load_global_config()
    # print("Loaded Config:", loaded_cfg)

    print(f"\n--- Testing get_config_value ---")
    print(f"Nmap Path: {get_config_value('tool_paths.nmap', 'nmap_default_from_code')}") # Should be /usr/local/bin/nmap_custom
    print(f"SQLMap Path: {get_config_value('tool_paths.sqlmap', 'sqlmap_default_from_code')}") # Should be None from project, then default. If project root missing, then /opt/sqlmap...
    print(f"Nikto Path: {get_config_value('tool_paths.nikto', 'nikto_default_from_code')}") # Should be None, then default
    print(f"NonExistentTool Path: {get_config_value('tool_paths.nonexistent', 'default_nonexistent')}") # default_nonexistent

    print(f"Dir Wordlist: {get_config_value('wordlists.directory_bruteforce', 'default_dir_wl')}") # project_specific_dirs.txt
    print(f"XSS Wordlist: {get_config_value('wordlists.xss', 'default_xss_wl')}") # /opt/custom_xss.txt
    print(f"LFI Wordlist: {get_config_value('wordlists.lfi', 'default_lfi_wl')}") # default_lfi_wl

    print(f"Nested L2: {get_config_value('nested.level1.level2', 'default_l2')}") # hello from project config
    print(f"Nested L3: {get_config_value('nested.level1.level3', 'default_l3')}") # default_l3 (since project root doesn't have it)
    print(f"Nested L4 (non-existent): {get_config_value('nested.level1.level4.level5', 'default_l4')}") # default_l4

    # Clean up dummy files
    if PROJECT_ROOT_CONFIG_PATH.exists():
        os.remove(PROJECT_ROOT_CONFIG_PATH)
    if USER_CONFIG_PATH.exists():
        os.remove(USER_CONFIG_PATH)
    # Note: USER_CONFIG_DIR is not removed by this test script.
    print("\n--- Test complete. Dummy config files removed. ---")

# Ensure __init__.py exists in autobb for package recognition
# (This should already be there from previous steps)
# touch autobb/__init__.py
