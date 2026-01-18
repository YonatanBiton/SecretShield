import os
import re
from datetime import datetime

def generate_github_summary(findings):
    """
    Writes a Markdown summary specifically for GitHub Actions UI.
    """
    # Get the special GitHub output file path
    github_summary_path = os.getenv('GITHUB_STEP_SUMMARY')
    
    if not github_summary_path:
        return # We are not running in GitHub Actions

    # Create Markdown Table
    md_content = "# SecretShield Scan Results\n\n"
    
    if not findings:
        md_content += "**No secrets found. Great job!**"
    else:
        md_content += f"Found **{len(findings)}** potential secrets.\n\n"
        md_content += "| Severity | Type | File | Line | Status |\n"
        md_content += "| :--- | :--- | :--- | :--- | :--- |\n"
        
        for f in findings:
            # Format the row
            md_content += f"| **{f['severity']}** | {f['type']} | `{f['file']}` | {f['line']} |\n"

    # Write to the GitHub environment file
    with open(github_summary_path, "a", encoding="utf-8") as f:
        f.write(md_content)

def clean_and_convert_markup(text):
    """
    Converts Rich terminal tags to HTML Bootstrap badges/spans.
    """
    if not text: return ""

    # 1. Convert specific "Active" tags to Bootstrap Badges
    text = text.replace("[bold white on red]", '<span class="badge bg-danger">')
    text = text.replace("[/bold white on red]", '</span>')
    
    text = text.replace("[red]", '<span class="text-danger fw-bold">')
    text = text.replace("[/red]", '</span>')

    # 2. Convert "Dim" (Inactive) tags to muted text
    text = text.replace("[dim]", '<span class="text-muted">')
    text = text.replace("[/dim]", '</span>')
    
    # 3. Convert Yellow warnings
    text = text.replace("[bold yellow]", '<span class="text-warning fw-bold">')
    text = text.replace("[/bold yellow]", '</span>')
    
    text = text.replace("[yellow]", '<span class="text-warning">')
    text = text.replace("[/yellow]", '</span>')

    # 4. Convert Orange warnings
    text = text.replace("[bold white on orange]", '<span class="badge bg-orange text-white">')
    text = text.replace("[/bold white on orange]", '</span>')
    
    text = text.replace("[orange]", '<span class="text-orange fw-bold">')
    text = text.replace("[/orange]", '</span>')

    # 5. Strip any other remaining brackets (regex) just in case
    text = re.sub(r'\[/?bold.*?\]', '', text) 
    text = re.sub(r'\[/?white.*?\]', '', text) 
    
    # 6. Convert Newlines to <br> for HTML
    text = text.replace('\n', '<br>')
    
    return text

def generate_html_report(findings, target_dir="."):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate Stats
    total_issues = len(findings)
    critical_count = len([f for f in findings if f['severity'] == 'CRITICAL'])
    high_count = len([f for f in findings if f['severity'] == 'HIGH'])
    medium_count = len([f for f in findings if f['severity'] == 'MEDIUM'])
    low_count = len([f for f in findings if f['severity'] == 'LOW'])
    
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
            
            /* Custom Severity Colors */
            .severity-critical {{ border-left: 8px solid #dc3545; }} /* Red */
            .severity-high {{ border-left: 8px solid #ffc107; }}     /* Yellow */
            .severity-medium {{ border-left: 8px solid #fd7e14; }}   /* Orange */
            .severity-low {{ border-left: 8px solid #198754; }}      /* Green */
            
            /* Custom Badges for cards */
            .bg-orange {{ background-color: #fd7e14 !important; color: white; }}
            .text-orange {{ color: #fd7e14 !important; }}
            
            .badge-type {{ font-size: 0.9em; margin-right: 10px; }}
            .stat-card {{ transition: transform 0.2s; }}
            .stat-card:hover {{ transform: translateY(-5px); }}
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
                    <div class="card text-white bg-danger stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Critical</h6>
                            <h2 class="display-5 fw-bold">{critical_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-dark bg-warning stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">High</h6>
                            <h2 class="display-5 fw-bold">{high_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-white bg-orange stat-card h-100">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Medium</h6>
                            <h2 class="display-5 fw-bold">{medium_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-white bg-success stat-card h-100">
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

    if not findings:
        html_content += '<div class="alert alert-success p-4"><strong>Clean Scan!</strong> No secrets were detected in this repository.</div>'
    else:
        # Sort findings by severity (Critical -> Low)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 99))

        for f in findings:
            sev = f['severity'].upper()
            
            # --- COLOR LOGIC ---
            if sev == "CRITICAL": 
                sev_class = "severity-critical"
                badge_class = "bg-danger"
            elif sev == "HIGH": 
                sev_class = "severity-high"
                badge_class = "bg-warning text-dark" # Yellow needs dark text to be readable
            elif sev == "MEDIUM": 
                sev_class = "severity-medium"
                badge_class = "bg-orange" # Custom class defined in CSS above
            elif sev == "LOW": 
                sev_class = "severity-low"
                badge_class = "bg-success"
            else:
                sev_class = "severity-medium"
                badge_class = "bg-secondary"

            # Clean the terminal message for HTML
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

    html_content += """
        </div>
        <footer class="text-center mt-5 mb-5 text-muted border-top pt-4">
            <small>Generated by <strong>SecretShield</strong> Security Scanner</small>
        </footer>
    </body>
    </html>
    """

    output_filename = "security_report.html"
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return os.path.abspath(output_filename)