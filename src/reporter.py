import os
import re
from datetime import datetime

def clean_and_convert_markup(text):
    """
    Converts Rich terminal tags to HTML Bootstrap badges/spans.
    """
    if not text: return ""

    # 1. Convert specific "Active" tags to Bootstrap Badges
    # [bold white on red]...[/...]  ->  <span class="badge bg-danger">...</span>
    text = text.replace("[red]", '<span class="badge bg-danger">')
    text = text.replace("[red]", '</span>')

    # 2. Convert "Dim" (Inactive) tags to muted text
    # [dim]...[/dim]  ->  <span class="text-muted">...</span>
    text = text.replace("[dim]", '<span class="text-muted">')
    text = text.replace("[/dim]", '</span>')
    
    # 3. Convert Yellow warnings
    text = text.replace("[yellow]", '<span class="text-warning fw-bold">')
    text = text.replace("[/yellow]", '</span>')

    #4. converte Orange warnings
    text = text.replace("[bold white on orange]", '<span class="badge bg-warning text-dark">')
    text = text.replace("[/bold white on orange]", '</span>')

    # 4. Strip any other remaining brackets (regex) just in case
    # This removes [bold], [red], etc. that we didn't handle explicitly
    # so the text remains readable.
    text = re.sub(r'\[/?bold.*?\]', '', text) 
    text = re.sub(r'\[/?white.*?\]', '', text) 
    
    # 5. Convert Newlines to <br> for HTML
    text = text.replace('\n', '<br>')
    
    return text

def generate_html_report(findings, target_dir="."):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate Stats
    total_issues = len(findings)
    critical_count = len([f for f in findings if f['severity'] == 'CRITICAL'])
    medium_count = len([f for f in findings if f['severity'] == 'MEDIUM'])
    
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
            .severity-critical {{ border-left: 5px solid #dc3545; }}
            .severity-high {{ border-left: 5px solid #ffc107; }}
            .severity-medium {{ border-left: 5px solid #ffc107; }}
            .badge-type {{ font-size: 0.9em; margin-right: 10px; }}
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

            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card text-white bg-danger">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Critical</h6>
                            <h2 class="display-4">{critical_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-dark bg-warning">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Medium</h6>
                            <h2 class="display-4">{medium_count}</h2>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-primary">
                        <div class="card-body text-center">
                            <h6 class="card-title text-uppercase">Total</h6>
                            <h2 class="display-4">{total_issues}</h2>
                        </div>
                    </div>
                </div>
            </div>

            <h4 class="mb-4">Detailed Findings</h4>
    """

    if not findings:
        html_content += '<div class="alert alert-success p-4"><strong>Clean Scan!</strong> No secrets were detected in this repository.</div>'
    else:
        for f in findings:
            sev_class = "severity-medium"
            badge_color = "secondary"
            
            if f['severity'] == "CRITICAL": 
                sev_class = "severity-critical"
                badge_color = "danger"
            elif f['severity'] == "HIGH": 
                sev_class = "severity-high"
                badge_color = "warning text-dark"
            elif f['severity'] == "MEDIUM": 
                sev_class = "severity-medium"
                badge_color = "warning text-dark"

            # --- USE THE HELPER FUNCTION HERE ---
            cleaned_message = clean_and_convert_markup(f['message'])
            
            html_content += f"""
            <div class="card {sev_class}">
                <div class="card-body">
                    <div class="d-flex justify-content-between">
                        <h5 class="card-title">
                            <span class="badge bg-{badge_color} badge-type">{f['severity']}</span>
                            <span class="text-primary">{f['type']}</span>
                        </h5>
                        <div>
                            <span class="fw-bold text-dark" style="font-size: 1.1em;">{f['file']}</span>
                            <span class="text-muted small ms-2">Line {f['line']}</span>
                        </div>
                    </div>
                    <p class="card-text mt-3">{cleaned_message}</p>
                    <div class="bg-light p-2 rounded mt-2 border">
                        <code class="text-danger">{f.get('secret', '******')}</code>
                    </div>
                </div>
            </div>
            """

    html_content += """
        </div>
        <footer class="text-center mt-5 mb-5 text-muted">
            <small>Generated by SecretShield Security Scanner</small>
        </footer>
    </body>
    </html>
    """

    output_filename = "security_report.html"
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return os.path.abspath(output_filename)