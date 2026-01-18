import os
import shutil
from rich.console import Console
from rules import check_secrets, check_user_exists, check_docker_rules
from validator import *
import re
def scan_dockerfile(file_path):
    """
    Scans a specific Dockerfile for all security rules (IaC + Secrets).
    """
    findings = []
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        # --- Line-by-Line Checks ---
        for i, line in enumerate(lines):
            line_num = i + 1
            clean_line = line.strip()
            
            if clean_line.startswith("#"): continue

            # Rule: Latest Tag
            res_docker = check_docker_rules(clean_line, line_num)
            if res_docker:
                res_docker['file'] = "Dockerfile" # Add context
                findings.append(res_docker)

            # Rule: Secrets (in Dockerfile ENV/ARG)
            res_secrets = check_secrets(clean_line, line_num)
            if res_secrets:
                res_secrets['file'] = "Dockerfile"
                findings.append(res_secrets)

        # --- Whole File Checks ---
        res_user = check_user_exists(lines)
        if res_user:
            # check_user_exists returns a string or None, let's normalize it to Dict
            res_user['file'] = "DockerFile"
            findings.append(res_user)

    except FileNotFoundError:
        print(f"Error: Dockerfile '{file_path}' not found.")
    
    return findings

def normalaize_line(line):
    """
    Safely merges split strings using simple replace.
    Does NOT use regex to avoid accidental deletion of content.
    """
    # Create a copy of the line to avoid modifying the original list in memory
    clean = line
    
    # 1. Handle "tight" concatenation: "A"+"B"
    clean = clean.replace('"+"', '')
    clean = clean.replace("'+'", "")
    
    # 2. Handle "spaced" concatenation: "A" + "B"
    clean = clean.replace('" + "', '')
    clean = clean.replace("' + '", "")
    
    # 3. Handle mixed quotes: "A" + 'B' (Less common but possible)
    clean = clean.replace('" + \'', '')
    clean = clean.replace('\' + "', '')

    return clean
    


def scan_directory(folder_path):
    """
    Recursively scans a folder for secrets in code files (SAST).
    Ignores git, binary files, and node_modules.
    """
    findings = []
    
    # Files/Folders to ignore to speed up scan and avoid false positives
    IGNORE_DIRS = {'.git', 'node_modules', 'venv', '__pycache__', 'tests'}
    IGNORE_EXTS = {
    # Images & Media
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".ico", ".svg", ".mp4", ".mp3", ".wav",
    # Compiled/Binary
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".o", ".a", ".class", ".jar",
    # Archives (project cant unzip files yet)
    ".zip", ".tar", ".gz", ".7z", ".rar",
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # Lockfiles (High false positive rate for entropy checks)
    ".lock", "package-lock.json", "yarn.lock", "composer.lock"
}

    for root, dirs, files in os.walk(folder_path):
        # Modify 'dirs' in-place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for filename in files:
            if filename.lower().endswith(tuple(IGNORE_EXTS)):
                continue

            full_path = os.path.join(root, filename)
            
            try:
                # errors='ignore' prevents crashing on weird binary files
                with open(full_path, 'r', errors='ignore') as f:
                    lines = f.readlines()
            except Exception:
                continue
            for i, line in enumerate(lines):
                try:
                    # ONLY run secret check on code files
                    clean_line = normalaize_line(line)
                    res_raw = check_secrets(line, i+1, all_lines=lines)
                    res_clean = None
                    
                    if clean_line != line:
                        res_clean = check_secrets(clean_line, i+1, all_lines=lines)
                     #   print(res_clean.get("secret"))
                    #print(res_raw.get("secret"))
                    res = None
                    if res_raw and not res_clean:
                        res = res_raw
                    elif res_clean and not res_raw:
                        res = res_clean
                    elif res_raw and res_clean:
                        len_raw = len(res_raw.get("secret"), "")
                        len_clean = len(res_clean.get("secret", ""))
                        if len_clean > len_raw:
                            res = res_clean
                        else:
                            res = res_raw
                    if res:
                        verify_msg = ""
                        secret_type = res.get("type")
                        #Check if stripe key is valid
                        if secret_type.upper() == "STRIPE":
                            verify_msg = verify_stripe_key(res.get("secret"))
                        #Check if Github key is valid
                        elif secret_type.upper() == "GITHUB":
                            verify_msg = verify_github_token(res.get("secret"))
                        #SLACK
                        elif secret_type.upper() == "SLACK_TOKEN":
                            verify_msg = verify_slack_token(res.get("secret"))
                        #Google
                        elif secret_type.upper() == "GOOGLE_API":
                             verify_msg = verify_google_api_key(res.get("secret"))
                        #DigitalOcean
                        elif secret_type.upper() == "DIGITALOCEAN":
                            verify_msg = verify_digital_ocean_api(res.get("secret"))
                        #Gitlab
                        elif secret_type.upper() == "GITLAB":
                            verify_msg = verify_gitlab_api(res.get("secret"))
                        #currently we cant find both AWS_ID and secret key - so just point out
                        elif secret_type.upper() == "AWS_PAIR":
                            verify_msg = verify_aws_access_key(res.get("key_id"), res.get("secret_key"))
                        #adding check msg to the end message
                        #checking if a key is inactive then severity goes down to medium.
                        if verify_msg != "":
                            if "ACTIVE" in verify_msg:
                                res['message'] += f"[red]{verify_msg}[/red]"
                            elif "inactive" in verify_msg.lower():
                                res['severity'] = "MEDIUM"
                                res['message'] += f"[yellow]{verify_msg}[/yellow]"
                            else:
                                res['message'] += f"[orange]{verify_msg}[/orange]"
                        # We found a secret in a code file!
                        res['file'] = os.path.relpath(full_path, folder_path) # Capture filename
                        findings.append(res)
                except Exception:
                    continue # Skip files we can't open

    return findings