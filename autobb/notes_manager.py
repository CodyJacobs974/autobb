import os
import subprocess
import shutil # To check for editor availability
from rich.console import Console

console = Console()

def view_notes(target_base_path: str):
    """
    Opens or creates and then opens user_notes.md in a terminal editor.
    """
    console.print("\n[bold cyan]--- Managing User Notes ---[/bold cyan]")

    notes_dir = os.path.join(target_base_path, "notes")
    notes_file_path = os.path.join(notes_dir, "user_notes.md")

    try:
        os.makedirs(notes_dir, exist_ok=True)
        if not os.path.exists(notes_file_path):
            with open(notes_file_path, "w") as f:
                f.write(f"# Notes for Target\n\n") # Basic title
            console.print(f"[green]Created new notes file:[/green] {notes_file_path}")
        else:
            console.print(f"[green]Opening existing notes file:[/green] {notes_file_path}")

        # Determine preferred editor
        editor = None
        if shutil.which("nano"):
            editor = "nano"
        elif shutil.which("vim"):
            editor = "vim"
        elif shutil.which("vi"):
            editor = "vi"
        # Add other common Linux editors if desired, e.g., emacs, pico

        if editor:
            console.print(f"Attempting to open with [blue]{editor}[/blue]...")
            try:
                # Using subprocess.call waits for the editor to close
                subprocess.call([editor, notes_file_path])
                console.print(f"[green]Finished editing notes with {editor}.[/green]")
            except Exception as e:
                console.print(f"[red]Error opening notes with {editor}: {e}[/red]")
                console.print(f"Please open manually: {notes_file_path}")
        else:
            console.print("[yellow]No preferred terminal editor (nano, vim, vi) found in PATH.[/yellow]")
            console.print(f"Please open and edit the notes file manually: {notes_file_path}")

    except OSError as e:
        console.print(f"[red]Error accessing notes directory or file: {e}[/red]")
    except Exception as e:
        console.print(f"[red]An unexpected error occurred while trying to manage notes: {e}[/red]")

# Example usage (if you were to run this file directly for testing)
if __name__ == '__main__':
    # This is just for testing the module directly.
    # You'd need to create a dummy target structure.
    dummy_target_path = "test_target_for_notes"
    if not os.path.exists(dummy_target_path):
        os.makedirs(os.path.join(dummy_target_path, "notes"))

    # Create a dummy config.txt for testing read_config if it were used here
    # with open(os.path.join(dummy_target_path, "config.txt"), "w") as f:
    #     f.write("TARGET_IDENTIFIER=test.com\n")
    #     f.write(f"TARGET_PATH={os.path.abspath(dummy_target_path)}\n")

    view_notes(dummy_target_path)
    # Clean up dummy structure
    # import shutil
    # shutil.rmtree(dummy_target_path)
