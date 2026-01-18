import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from scanner import scan_directory
import shutil
import tempfile
import subprocess
import os
from reporter import generate_html_report, generate_github_summary
app = typer.Typer()
console = Console()

def clone_repo_to_temp(git_url: str):
    """
    Clones a remote Git repo to a temporary directory with a nice loading spinner.
    """
    temp_dir = tempfile.mkdtemp(prefix="docksentry_")
    
    # UX Improvement: A Spinner that shows "Working..."
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        transient=True, # Disappears when done
    ) as progress:
        progress.add_task(description=f"Cloning {git_url}...", total=None)
        
        try:
            # Run git clone quietly
            subprocess.check_call(
                ["git", "clone", "--depth", "1", git_url, temp_dir],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return temp_dir
        except subprocess.CalledProcessError:
            console.print("[bold red]Failed to clone repository. Check URL.[/bold red]")
            shutil.rmtree(temp_dir)
            raise typer.Exit(code=1)
        except FileNotFoundError:
            console.print("[bold red] 'git' is not installed.[/bold red]")
            raise typer.Exit(code=1)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to folder OR Git URL"),
    html: bool = typer.Option(False, "--html", help="Generate a browser-friendly report")
):
    """
    Scans a local folder OR a remote Git repository.
    """
    scan_path = target
    is_temp = False
    
    # 1. Handle URL vs Local
    if target.startswith(("http://", "https://", "git@")):
        scan_path = clone_repo_to_temp(target)
        is_temp = True
    
    if not os.path.exists(scan_path):
        console.print(f"[bold red] Path '{scan_path}' not found.[/bold red]")
        raise typer.Exit()

    # 2. Run Scan
    console.print(f"[bold green] Scanning...[/bold green]")
    findings = scan_directory(scan_path)
    
    # 3. Output Logic (CLI Table vs HTML)
    if not findings:
        console.print("[bold green] No issues found![/bold green]")
        if html:
            report_path = generate_html_report(findings, target)
            console.print(f"HTML Report generated: {report_path}")
    else:
        if html:
            report_path = generate_html_report(findings, target)
            console.print(f"HTML Report generated: {report_path}")
        else:
            print_table(findings, target)

    generate_github_summary(findings)

    # 4. Cleanup
    if is_temp:
        # UX: Simple text, no spinner needed for fast deletion
        shutil.rmtree(scan_path, ignore_errors=True)
        console.print("[dim]🧹 Cleanup complete.[/dim]")
    if len(findings) > 0:
        console.print(f"Pipeline Faild: Found {len(findings)} security issues.")
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)

def print_table(findings, target):
    table = Table(title=f"Security Report: {target}")
    table.add_column("File", style="cyan", overflow="fold")
    table.add_column("Line", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Message", style="white")

    for issue in findings:
        sev = issue["severity"]
        color = "bold red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "white"
        table.add_row(
            issue["file"], 
            str(issue["line"]), 
            f"[{color}]{sev}[/{color}]", 
            issue["message"]
        )
    console.print(table)

if __name__ == "__main__":
    app()