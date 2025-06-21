## Development Guidelines for AutoBugBounty (AutoBB)

This document provides guidelines for AI agents contributing to the AutoBugBounty project.

### General Principles

1.  **Modularity:** Strive to create modular code. Each major function (Reconnaissance, Vulnerability Analysis, etc.) should ideally reside in its own Python module or a well-defined section of the code.
2.  **Extensibility:** Design the code with extensibility in mind. It should be relatively easy to add new tools or checks to each stage of the workflow.
3.  **User Experience:** Prioritize a clear and user-friendly command-line interface. Use libraries like `rich` for better output formatting.
4.  **Tool Invocation:**
    *   Use the `subprocess` module for running external command-line tools.
    *   Ensure that tool outputs are captured and saved to the correct directories within the target's folder.
    *   Always check if a tool is installed before attempting to run it. Provide helpful messages if a tool is missing.
5.  **Configuration:**
    *   The primary configuration (target domain/IP, save location) should be stored in `target_folder/config.txt`.
    *   Subsequent stages should read from this `config.txt` and other generated files.
6.  **Error Handling:** Implement robust error handling. Catch exceptions, provide informative error messages, and ensure the application can gracefully handle common issues (e.g., tool not found, network errors, permission issues).
7.  **Security:** Since this is a security tool, be mindful of potential security implications in the code itself (e.g., command injection if user inputs are improperly handled when constructing shell commands). Sanitize inputs where necessary.
8.  **Cross-Platform Compatibility (Linux Focus):** While Python is cross-platform, the primary target environment for AutoBB is Linux. Ensure that tool commands and paths are generally compatible with standard Linux distributions.
9.  **Dependencies:**
    *   List all Python dependencies in `requirements.txt`.
    *   The tool should check for external binary dependencies (e.g., nmap, sqlmap) and guide the user on installation if they are missing.

### Workflow Specifics

1.  **Reconnaissance:**
    *   Ensure each recon tool saves its raw output to a dedicated file (e.g., `recon/nmap/nmap_output.txt`).
    *   Extract key findings from raw outputs and consolidate them, potentially in `summary.txt` or a dedicated recon summary file.
2.  **Vulnerability Analysis:**
    *   Leverage data collected during the reconnaissance phase.
    *   For automated scanners (e.g., `sqlmap`, `nikto`), ensure their outputs are also saved.
    *   For manual testing guidance, provide clear instructions or checklists.
3.  **Reporting:**
    *   The final report should be comprehensive, drawing information from all stages.
    *   Markdown (`report.md`) is preferred for the final report format due to its readability and ease of conversion.

### Code Style

*   Follow PEP 8 Python style guidelines.
*   Use clear and descriptive variable and function names.
*   Add comments to explain complex logic.

### Testing

*   Manually test each feature thoroughly.
*   Consider adding automated tests for core utility functions if the complexity warrants it.

### Submission

*   Ensure all code changes are related to the current task or bug fix.
*   Write clear and concise commit messages.

By adhering to these guidelines, we can build a robust and effective AutoBugBounty toolkit.
