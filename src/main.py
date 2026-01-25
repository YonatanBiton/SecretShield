"""
Main Entry Point for SecretShield.

This module serves as the Command Line Interface (CLI) for the application.
It uses 'Typer' to handle arguments and 'Rich' for formatted console output.

Key Responsibilities:
1. Parse user arguments (target directory or Git URL).
2. Clone remote repositories if a URL is provided.
3. Orchestrate the scanning process using the `scanner` module.
4. Dispatch results to the `reporter` module (HTML/Console/GitHub).
5. Manage exit codes for CI/CD pipeline integration.

Dependencies:
    - typer: CLI framework.
    - rich: Terminal formatting.
    - shutil, tempfile, subprocess: File and process management.
"""

import os
import shutil
import subprocess
import tempfile
from typing import List, Dict, Any

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Local application imports
from scanner import scan_directory
from reporter import generate_html_report, generate_github_summary

# Initialize CLI app and Console
app = typer.Typer(help="SecretShield: A Security Scanner for Docker and Secrets.")
console = Console()


def clone_repo_to_temp(git_url: str) -> str:
    """Clones a remote Git repository to a temporary directory.

    This function creates a unique temporary folder and attempts to shallow clone
    (depth=1) the target repository into it. It includes a visual spinner
    for better User Experience (UX).

    Args:
        git_url (str): The valid HTTP(S) or SSH URL of the Git repository.

    Returns:
        str: The absolute path to the temporary directory containing the cloned code.

    Raises:
        typer.Exit(1): If 'git' is not installed or the cloning process fails.
    """
    temp_dir = tempfile.mkdtemp(prefix="docksentry_")
    
    # UX Improvement: A Spinner that shows "Working..." during network ops
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        transient=True,  # Disappears when done so it doesn't clutter logs
    ) as progress:
        progress.add_task(description=f"Cloning {git_url}...", total=None)
        
        try:
            # Run git clone quietly (-q not used, strictly diverting stdout/stderr)
            subprocess.check_call(
                ["git", "clone", "--depth", "1", git_url, temp_dir],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return temp_dir
            
        except subprocess.CalledProcessError:
            console.print("[bold red]Error: Failed to clone repository. Please check the URL.[/bold red]")
            shutil.rmtree(temp_dir) # Clean up the empty temp dir
            raise typer.Exit(code=1)
            
        except FileNotFoundError:
            console.print("[bold red]Error: 'git' command not found. Is Git installed?[/bold red]")
            shutil.rmtree(temp_dir)
            raise typer.Exit(code=1)


def print_table(findings: List[Dict[str, Any]], target: str) -> None:
    """Prints a formatted table of security findings to the console.

    Args:
        findings (List[Dict[str, Any]]): The list of finding dictionaries.
        target (str): The name of the target that was scanned (for the header).
    """
    table = Table(title=f"Security Report: {target}")
    
    # Define columns with specific styles
    table.add_column("File", style="cyan", overflow="fold")
    table.add_column("Line", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Message", style="white")

    for issue in findings:
        sev = issue["severity"]
        
        # Color coding logic for severity visualization in the terminal
        if sev == "CRITICAL":
            color = "bold red"
        elif sev == "HIGH":
            color = "yellow"
        else:
            color = "white"

        table.add_row(
            issue["file"], 
            str(issue["line"]), 
            f"[{color}]{sev}[/{color}]", 
            issue["message"]
        )
    
    console.print(table)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to local folder OR Git URL to scan."),
    html: bool = typer.Option(False, "--html", help="Generate a browser-friendly HTML report.")
) -> None:
    """
    Scans a local folder OR a remote Git repository for secrets and Docker issues.

    This is the main command. It detects if the input is a URL or a path,
    runs the scanner, and outputs the results in the requested format.
    """
    scan_path = target
    is_temp = False
    
    # 1. Handle URL vs Local Path
    # We check standard protocols to detect if it's a remote repo
    if target.startswith(("http://", "https://", "git@")):
        scan_path = clone_repo_to_temp(target)
        is_temp = True
    
    # Verify path existence before starting
    if not os.path.exists(scan_path):
        console.print(f"[bold red]Error: Path '{scan_path}' not found.[/bold red]")
        raise typer.Exit(code=1)

    # 2. Run the Scan Logic
    console.print(f"[bold green] Scanning target: {target}...[/bold green]")
    findings = scan_directory(scan_path)
    
    # 3. Output Handling
    if not findings:
        console.print("[bold green] No issues found! Clean scan.[/bold green]")
    else:
        # If user requested HTML, generate it regardless of findings count
        if html:
            report_path = generate_html_report(findings, target)
            console.print(f" HTML Report generated: [underline]{report_path}[/underline]")
        else:
            # Default to console table
            print_table(findings, target)

    # Always generate the GitHub summary (it safely exits if not in CI)
    generate_github_summary(findings)

    # 4. Cleanup & Exit Code
    if is_temp:
        # cleanup temporary directories from git clone
        shutil.rmtree(scan_path, ignore_errors=True)
        console.print("[dim] Temp cleanup complete.[/dim]")
    
    # CI/CD Integration: Return Non-Zero exit code if issues found
    if len(findings) > 0:
        console.print(f"[bold red]Pipeline Failed: Found {len(findings)} security issues.[/bold red]")
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)


if __name__ == "__main__":
    app()