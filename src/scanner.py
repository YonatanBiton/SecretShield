"""
Scanner Module for SecretShield.

This module contains the core logic for traversing directories and files to detect:
1. Hardcoded secrets (API keys, tokens) in source code.
2. Security misconfigurations in Dockerfiles.

It uses a 'SAST' (Static Application Security Testing) approach but enhances it
with 'Active Verification' (checking if found keys are actually live).
"""

import os
from typing import List, Dict, Any, Optional

# Local application imports
from rules import check_secrets, check_user_exists, check_docker_rules
from validator import (
    verify_stripe_key, 
    verify_github_token, 
    verify_slack_token, 
    verify_google_api_key, 
    verify_digital_ocean_api, 
    verify_gitlab_api, 
    verify_aws_access_key
)

# --- CONFIGURATION ---

# Directories to ignore during traversal to improve performance
IGNORE_DIRS = {'.git', 'node_modules', 'venv', '__pycache__', 'tests', '.idea', '.vscode'}

# File extensions to ignore (Images, Binary, Archives, etc.)
IGNORE_EXTS = {
    # Images & Media
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".ico", ".svg", ".mp4", ".mp3", ".wav",
    # Compiled/Binary
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".o", ".a", ".class", ".jar",
    # Archives 
    ".zip", ".tar", ".gz", ".7z", ".rar",
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # Lockfiles (High entropy causes false positives)
    ".lock", "package-lock.json", "yarn.lock", "composer.lock"
}


def normalize_line(line: str) -> str:
    """Attempts to merge split strings to detect obfuscated secrets.

    Malicious actors (or careless developers) sometimes split strings to hide them.
    E.g., "sk_live_" + "12345". This function merges them back for analysis.

    Args:
        line (str): The raw line of code.

    Returns:
        str: The normalized line with concatenation artifacts removed.
    """
    clean = line
    
    # 1. Handle "tight" concatenation: "A"+"B"
    clean = clean.replace('"+"', '')
    clean = clean.replace("'+'", "")
    
    # 2. Handle "spaced" concatenation: "A" + "B"
    clean = clean.replace('" + "', '')
    clean = clean.replace("' + '", "")
    
    # 3. Handle mixed quotes: "A" + 'B'
    clean = clean.replace('" + \'', '')
    clean = clean.replace('\' + "', '')

    return clean


def scan_dockerfile(file_path: str) -> List[Dict[str, Any]]:
    """Scans a specific Dockerfile for security best practices and secrets.

    Checks included:
    1. Base Image Safety (avoiding 'latest' tag).
    2. User Permissions (ensuring a non-root user is created/switched to).
    3. Secrets hardcoded in ENV or ARG instructions.

    Args:
        file_path (str): Absolute path to the Dockerfile.

    Returns:
        List[Dict[str, Any]]: A list of findings/issues detected.
    """
    findings = []
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        # --- Line-by-Line Checks ---
        for i, line in enumerate(lines):
            line_num = i + 1
            clean_line = line.strip()
            
            # Skip comments
            if clean_line.startswith("#"): 
                continue

            # Rule 1: Docker Best Practices (e.g., Tag pinning)
            res_docker = check_docker_rules(clean_line, line_num)
            if res_docker:
                res_docker['file'] = "Dockerfile"
                findings.append(res_docker)

            # Rule 2: Secrets in ENV/ARG
            res_secrets = check_secrets(clean_line, line_num)
            if res_secrets:
                res_secrets['file'] = "Dockerfile"
                findings.append(res_secrets)

        # --- Whole File Checks ---
        # Check if the Dockerfile ever switches to a non-root user
        res_user = check_user_exists(lines)
        if res_user:
            res_user['file'] = "Dockerfile"
            findings.append(res_user)

    except FileNotFoundError:
        print(f"Error: Dockerfile '{file_path}' not found.")
    
    return findings


def scan_directory(folder_path: str) -> List[Dict[str, Any]]:
    """Recursively scans a folder for secrets in code files (SAST).

    This function traverses the directory tree, respecting ignore lists.
    For every file, it runs regex rules to find secrets. If a secret is found,
    it attempts to 'Verify' the secret by calling the provider's API.

    Args:
        folder_path (str): The root directory to start the scan.

    Returns:
        List[Dict[str, Any]]: A flattened list of all security findings.
    """
    findings = []

    for root, dirs, files in os.walk(folder_path):
        # Modify 'dirs' in-place to skip ignored directories (optimization)
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for filename in files:
            # Skip ignored extensions
            if filename.lower().endswith(tuple(IGNORE_EXTS)):
                continue

            full_path = os.path.join(root, filename)
            
            try:
                # Open with errors='ignore' to prevent crashing on binary files
                with open(full_path, 'r', errors='ignore') as f:
                    lines = f.readlines()
            except Exception:
                continue 

            # --- Scan File Content ---
            for i, line in enumerate(lines):
                try:
                    # 1. Normal Scan (Raw Line)
                    res_raw = check_secrets(line, i+1, all_lines=lines)
                    
                    # 2. Obfuscation Scan (Normalized Line)
                    clean_line = normalize_line(line)
                    res_clean = None
                    
                    if clean_line != line:
                        res_clean = check_secrets(clean_line, i+1, all_lines=lines)
                    
                    # 3. Determine best finding (if any)
                    res = None
                    if res_raw and not res_clean:
                        res = res_raw
                    elif res_clean and not res_raw:
                        res = res_clean
                    elif res_raw and res_clean:
                        # If both found something, pick the one that captured a longer secret
                        len_raw = len(res_raw.get("secret", ""))
                        len_clean = len(res_clean.get("secret", ""))
                        res = res_clean if len_clean > len_raw else res_raw

                    # --- Active Verification ---
                    if res:
                        verify_msg = ""
                        secret_type = res.get("type", "").upper()
                        secret_val = res.get("secret")

                        # Dispatch validation based on key type
                        if secret_type == "STRIPE":
                            verify_msg = verify_stripe_key(secret_val)
                        elif secret_type == "GITHUB":
                            verify_msg = verify_github_token(secret_val)
                        elif secret_type == "SLACK_TOKEN":
                            verify_msg = verify_slack_token(secret_val)
                        elif secret_type == "GOOGLE_API":
                            verify_msg = verify_google_api_key(secret_val)
                        elif secret_type == "DIGITALOCEAN":
                            verify_msg = verify_digital_ocean_api(secret_val)
                        elif secret_type == "GITLAB":
                            verify_msg = verify_gitlab_api(secret_val)
                        elif secret_type == "AWS_PAIR":
                            verify_msg = verify_aws_access_key(res.get("key_id"), res.get("secret_key"))

                        # Update Findings with Validation Result
                        if verify_msg:
                            if "ACTIVE" in verify_msg:
                                # Confirmed Real Secret -> Alert user strongly
                                res['message'] += f" [bold white on red]{verify_msg}[/bold white on red]"
                            elif "inactive" in verify_msg.lower():
                                # Dead Secret -> Lower severity to reduce noise
                                res['severity'] = "MEDIUM"
                                res['message'] += f" [dim]{verify_msg}[/dim]"
                            else:
                                res['message'] += f" [orange]{verify_msg}[/orange]"
                        
                        # Store finding with relative path for readability
                        res['file'] = os.path.relpath(full_path, folder_path)
                        findings.append(res)
                        
                except Exception:
                    continue # Fail safe: skip lines that cause regex errors

    return findings