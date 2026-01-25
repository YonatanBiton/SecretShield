"""
Reporter Module for SecretShield.

This module handles the formatting and output of security scan results.
It translates raw finding dictionaries into human-readable formats:
1. GitHub Actions Summary (Markdown): For CI/CD pipeline visibility.
2. HTML Report (Bootstrap 5): For detailed, interactive developer review.

Dependencies:
    - os: For accessing environment variables and file paths.
    - re: For stripping/converting terminal color codes.
    - datetime: For timestamping reports.
"""

import os
import re
from datetime import datetime
from typing import List, Dict, Any

def generate_github_summary(findings: List[Dict[str, Any]]) -> None:
    """Writes a Markdown summary specifically for the GitHub Actions UI.

    This function checks for the 'GITHUB_STEP_SUMMARY' environment variable,
    which is automatically provided by GitHub Actions runners. If present,
    it appends a summary table of the findings to that file so they appear
    in the workflow run summary page.

    Args:
        findings (List[Dict[str, Any]]): List of finding dictionaries containing
            'severity', 'type', 'file', and 'line'.
    """
    # Get the special GitHub output file path
    github_summary_path = os.getenv('GITHUB_STEP_SUMMARY')
    
    # If the env var isn't set, we are likely running locally, so skip this.
    if not github_summary_path:
        return 

    # Header
    md_content = "# SecretShield Scan Results\n\n"
    
    if not findings:
        md_content += "**No secrets found. Great job!**"
    else:
        md_content += f"Found **{len(findings)}** potential secrets.\n\n"
        
        # Table Header
        md_content += "| Severity | Type | File | Line | Status |\n"
        md_content += "| :--- | :--- | :--- | :--- | :--- |\n"
        
        # Table Rows
        for f in findings:
            md_content += f"| **{f['severity']}** | {f['type']} | `{f['file']}` | {f['line']} |\n"

    # Write to the GitHub environment file
    # We use 'a' (append) because other steps might have written to the summary too.
    try:
        with open(github_summary_path, "a", encoding="utf-8") as f:
            f.write(md_content)
    except IOError as e:
        # Fail silently or log error depending on preference; usually non-critical
        print(f"Warning: Could not write to GITHUB_STEP_SUMMARY: {e}")


def clean_and_convert_markup(text: str) -> str:
    """Converts 'Rich' terminal library tags to HTML Bootstrap badges/spans.

    The scanner uses the 'Rich' library for colored console output (e.g., [bold red]).
    This function translates those tags into web-safe HTML (e.g., <span class="text-danger">)
    so the HTML report retains the visual cues of the terminal output.

    Args:
        text (str): The raw text string with Rich markup.

    Returns:
        str: The HTML-safe string with Bootstrap classes.
    """
    if not text: 
        return ""

    # 1. Convert specific "Active" tags to Bootstrap Badges (Red/Danger)
    text = text.replace("[bold white on red]", '<span class="badge bg-danger">')
    text = text.replace("[/bold white on red]", '</span>')
    
    text = text.replace("[red]", '<span class="text-danger fw-bold">')
    text = text.replace("[/red]", '</span>')

    # 2. Convert "Dim" (Inactive) tags to muted text (Gray)
    text = text.replace("[dim]", '<span class="text-muted">')
    text = text.replace("[/dim]", '</span>')
    
    # 3. Convert Yellow warnings
    text = text.replace("[bold yellow]", '<span class="text-warning fw-bold">')
    text = text.replace("[/bold yellow]", '</span>')
    
    text = text.replace("[yellow]", '<span class="text-warning">')
    text = text.replace("[/yellow]", '</span>')

    # 4. Convert Orange warnings (Medium Severity)
    text = text.replace("[bold white on orange]", '<span class="badge bg-orange text-white">')
    text = text.replace("[/bold white on orange]", '</span>')
    
    text = text.replace("[orange]", '<span class="text-orange fw-bold">')
    text = text.replace("[/orange]", '</span>')

    # 5. Cleanup: Strip any remaining Rich tags using Regex
    text = re.sub(r'\[/?bold.*?\]', '', text) 
    text = re.sub(r'\[/?white.*?\]', '', text) 
    
    # 6. Formatting: Convert Newlines to HTML line breaks
    text = text.replace('\n', '<br>')
    
    return text


def generate_html_report(findings: List[Dict[str, Any]], target_dir: str = ".") -> str:
    """Generates a standalone HTML report using Bootstrap 5.

    This report includes:
    - A dashboard with counters for Critical, High, Medium, and Low issues.
    - A detailed list of findings sorted by severity.
    - Visual indicators for verified (active) vs. unverified secrets.

    Args:
        findings (List[Dict[str, Any]]): List of finding objects.
        target_dir (str, optional): The directory that was scanned. Defaults to ".".

    Returns:
        str: The absolute path to the generated 'security_report.html' file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # --- Statistics Calculation ---
    total_issues = len(findings)
    critical_count = len([f for f in findings if f['severity'] == 'CRITICAL'])
    high_count = len([f for f in findings if f['severity'] == 'HIGH'])
    medium_count = len([f for f in findings if f['severity'] == 'MEDIUM'])
    low_count = len([f for f in findings if f['severity'] == 'LOW'])
    
    # --- HTML Header & CSS ---
    # Using f-string for template generation
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SecretShield Report</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background-color: #f8f9fa; padding: 20px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            .card {{ margin-bottom: 15px; border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            
            /* Custom Severity Borders */
            .severity-critical {{ border-left: 8px solid #8B0000; }} /* bordo */
            .severity-high {{ border-left: 8px solid #dc3545; }}      /* red */
            .severity-medium {{ border-left: 8px solid #F0AD4E; }}    /* Orange */
            .severity-low {{ border-left: 8px solid #5CB85C; }}       /* Green */
            
            /* Custom Colors */
            .bg-orange {{ background-color: #fd7e14 !important; color: white; }}
            .text-orange {{ color: #fd7e14 !important; }}
            
            .badge-type {{ font-size: 0.9em; margin-right: 10px; }}
            .stat-card {{ transition: transform 0.2s; }}
            .stat-card:hover {{ transform: translateY(-5px); }}
            .bg-critical {{background-color: #8B0000 !important; color: white;}}
            .text-critical {{color: #8B0000 !important;}}

        </style>
    </head>
    <body>
        <div class="container">
            <div class="d-flex justify-content-between align-items-center mb-5 pb-3 border-bottom">
                <div>
                    <h1 class="display-6">SecretShield Scan</h1>
                    <p class="text-muted mb-0">Target: <code>{target_dir}</code></p>
                </div>
                <div class="text-end">
                    <p class="mb-0 text-muted">Scan Date</p>
                    <h5>{timestamp}</h5>
                </div>
            </div>

            <div class="row row-cols-2 row-cols-md-5 g-4 mb-5">
                <div class="col">
                    <div class="card text-white bg-critical stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Critical</h6>
                            <h2 class="display-5 fw-bold">{critical_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card bg-danger text-white stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">High</h6>
                            <h2 class="display-5 fw-bold">{high_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card bg-orange text-white stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Medium</h6>
                            <h2 class="display-5 fw-bold">{medium_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-white  bg-success stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Low</h6>
                            <h2 class="display-5 fw-bold">{low_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-white bg-primary stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Total</h6>
                            <h2 class="display-5 fw-bold">{total_issues}</h2>
                        </div>
                    </div>
                </div>
            </div>

            <h4 class="mb-4">Detailed Findings</h4>
    """

    # --- Findings Loop ---
    if not findings:
        html_content += (
            '<div class="alert alert-success p-4">'
            '<strong>Clean Scan!</strong> No secrets were detected in this repository.'
            '</div>'
        )
    else:
        # Sort findings by severity (Critical -> Low)
        # We map severity strings to integers for sorting: Lower number = Higher Priority
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 99))

        for f in findings:
            sev = f['severity'].upper()
            
            # Determine styling based on severity
            if sev == "CRITICAL": 
                sev_class = "severity-critical"
                badge_class = "bg-critical"
            elif sev == "HIGH": 
                sev_class = "severity-high"
                badge_class = "bg-danger " 
            elif sev == "MEDIUM": 
                sev_class = "severity-medium"
                badge_class = "bg-orange "
            elif sev == "LOW": 
                sev_class = "severity-low"
                badge_class = "bg-success"
            else:
                sev_class = "severity-medium"
                badge_class = "bg-secondary "

            # Clean the message for HTML (convert Rich tags to spans)
            cleaned_message = clean_and_convert_markup(f['message'])
            
            html_content += f"""
            <div class="card {sev_class}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <h5 class="card-title d-flex align-items-center">
                                <span class="badge {badge_class} badge-type">{sev}</span>
                                <span class="text-primary">{f['type']}</span>
                            </h5>
                            <div class="mt-2">
                                <span class="fw-bold text-dark" style="font-family: monospace; font-size: 1.1em;">{f['file']}</span>
                                <span class="badge bg-light text-secondary border ms-2">Line {f['line']}</span>
                            </div>
                        </div>
                    </div>
                    
                    <p class="card-text mt-3 text-secondary">{cleaned_message}</p>
                    
                    <div class="bg-light p-3 rounded mt-2 border d-flex align-items-center">
                        <span class="me-3 text-muted small text-uppercase fw-bold">Secret:</span>
                        <code class="text-danger fw-bold" style="font-size: 1em;">{f.get('secret', '******')}</code>
                    </div>
                </div>
            </div>
            """

    # --- HTML Footer ---
    html_content += """
        </div>
        <footer class="text-center mt-5 mb-5 text-muted border-top pt-4">
            <small>Generated by <strong>SecretShield</strong> Security Scanner</small>
        </footer>
    </body>
    </html>
    """

    output_filename = "security_report.html"
    
    # Write to file
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return os.path.abspath(output_filename)