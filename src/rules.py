import re
import math
# --- Constants & Patterns ---

# High Fidelity Patterns (These are almost 99% sure to be secrets)
SPECIFIC_PATTERNS = {
    "AWS": r'(AKIA[0-9A-Z]{16})',
    "Google_API": r'(AIza[0-9A-Za-z\\-_]{35})',
    "Slack_Token": r'(xox[baprs]-[a-zA-Z0-9-]+)',
    "GitHub": r'(ghp_[0-9a-zA-Z]{36})',
    "Stripe": r'(sk_live_[0-9a-zA-Z]{20,})',
    "Private Key Header": r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
    "DigitalOcean": r'(dop_v1_[0-9a-fA-F]{64})',
    "GitLab" : r'(glpat-[0-9a-zA-Z\-]{20})'
}

# Generic Suspicious Variable Names
# We look for these words in the variable NAME, not the value.
SUSPICIOUS_NAMES = r'(?i)(password|secret|token|api_key|access_key|auth_key|credentials|key)'

def find_aws_secret_candidate(lines, index):
    """
    Scans nearby lines (window of +/- 4 lines) for a potential AWS Secret Key.
    An AWS Secret Key is exactly 40 characters long, usually alphanumeric + / + +.
    """
    start = max(0, index - 4)
    end = min(len(lines), index + 5)
    
    # Regex for a standard AWS Secret Key (40 chars)
    # It looks for assignments like: "secret_key" = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    secret_pattern = r'(?i)(secret|key).*?[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
    
    for i in range(start, end):
        # Don't check the line that has the AKIA ID (it's not there)
        if i == index: 
            continue
            
        line = lines[i]
        match = re.search(secret_pattern, line)
        if match:
            return match.group(2) # Return the found secret string
            
    return None

def calculate_shannon_entropy(data):
    """
    Calculates the Shannon Entropy of a string.
    Returns a float representing bits of randomness.
    """
    if not data:
        return 0
        
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
            
    return entropy

def is_high_entropy(value):
    """
    Revised Logic: Uses Math (Shannon Entropy) instead of simple counting.
    """
    # 1. Length Check (Still essential)
    if len(value) < 8:
        print("less then 8")
        return False
        
    # 2. Dynamic Value & Placeholder Checks (Keep these!)
    if value.strip().startswith(("$", "{{", "<%", "openssl", "base64")):
        print("start with dynamic")
        return False

    upper_val = value.upper()
    if "EXAMPLE" in upper_val or "CHANGE_ME" in upper_val:
        print("has example")
        return False
        
    # 3. THE NEW MATH LOGIC
    entropy = calculate_shannon_entropy(value)
    

    # Standard English text usually has entropy between 3.5 and 4.5.
    
    # Special Case: Hex Strings (0-9, a-f) need slightly lower entropy to trigger
    is_hex = bool(re.match(r'^[0-9a-fA-F]+$', value))
    
    if is_hex:
        # Hex strings have less variety (only 16 chars), so max entropy is 4.0.
        # We check for > 3.0 to catch random Hex keys.
        return entropy > 3.0
    else:
        # Standard strings (Base64 / Ascii)
        return entropy > 3.6

def check_secrets(line, line_num, all_lines):
    """
    Smart detection:
    1. Checks High-Fidelity patterns first (Critical).
    2. Checks Generic patterns ONLY if the value looks like a real secret (Heuristic).
    """
   # --- Layer 1: Specific Patterns (Critical) ---
    for secret_type, pattern in SPECIFIC_PATTERNS.items():
        match = re.search(pattern, line) # Capture the match object
        if match:
            # Extract the actual secret string found (e.g., "sk_live_123...")
            # We assume the regex pattern captures the key in group 0 or 1
            detected_value = match.group(0) 
            # Special handling for AWS (We usually capture the ID, AKIA...)
            if "AWS" in secret_type:
                if all_lines:
                    partner_secret = find_aws_secret_candidate(all_lines, line_num - 1)
                    if partner_secret:
                        return {
                            "line": line_num,
                            "type": "AWS_PAIR",
                            "key_id": detected_value,
                            "secret_key": partner_secret,
                            "severity": "CRITICAL",
                            "message": "Full AWS Credential pair found (ID + Secret)!"
                        }
                return {
                    "line": line_num,
                    "type": "AWS_ID", # Special tag for AWS
                    "key_id": detected_value,
                    "severity": "CRITICAL",
                    "message": f"{secret_type} ID found ({detected_value}) - Couldn't find the secret key"
                }

            # Standard handling for single-string keys (Stripe, GitHub)
            return {
                "line": line_num,
                "type": secret_type, # e.g., "STRIPE", "GITHUB_TOKEN"
                "secret": detected_value, # The actual key to verify!
                "severity": "CRITICAL",
                "message": f"{secret_type} found. This is a high-confidence leak."
            }

    # --- Layer 2: Generic Keyword + Heuristic Check (High) ---
    # We regex for: VARIABLE_NAME = "VALUE"
    # Group 1: Name, Group 2: Quote, Group 3: Value
    generic_match = re.search(rf"""{SUSPICIOUS_NAMES}\s*=\s*(['"])(.*?)(\2)""", line)

    if generic_match:
        variable_name = generic_match.group(1) # e.g., "DB_PASSWORD"
        secret_value = generic_match.group(3)  # e.g., "x8!sPa2@1"
        try:
        # Apply Logic: Is this actually a secret?
            if is_high_entropy(secret_value):
                return {
                    "line": line_num,
                    "severity": "HIGH",
                    "type": "Unkown",
                    "secret": secret_value,
                    "message": f"Suspicious hardcoded secret found in variable '{variable_name}'."
                }
        except Exception as e:
            print(e)

    return None

def check_docker_rules(line, line_num):
    """
    Expanded Docker rules for real-world scenarios.
    """
    clean_line = line.strip().upper()
    
    # Rule 1: Latest Tag
    if clean_line.startswith("FROM"):
        if "latest" in line or ":" not in line:
            return {
                "line": line_num,
                "severity": "MEDIUM",
                "message": "Base image uses 'latest' tag. Pin a specific version."
            }
            
    # Rule 2: Using 'ADD' instead of 'COPY'
    # ADD is dangerous because it can fetch remote URLs and unpack zips automatically.
    if clean_line.startswith("ADD"):
        return {
            "line": line_num,
            "severity": "LOW",
            "message": "Using 'ADD' is discouraged. Use 'COPY' unless you need auto-extraction."
        }
        
    # Rule 3: Using 'sudo'
    if "sudo " in line:
        return {
            "line": line_num,
            "severity": "HIGH",
            "message": "Avoid using 'sudo' in Dockerfiles. It adds unnecessary weight and risk."
        }
        
    # Rule 4: Pip install without pinning or cleanup
    # (Simplified check for pip install)
    if "pip install" in line and "requirements.txt" not in line:
        if "==" not in line: # Not pinning version
             return {
                "line": line_num,
                "severity": "LOW",
                "message": "Pip install found without version pinning (e.g. package==1.0)."
            }

    return None

def check_user_exists(file_content):
    """
    Rule: The Dockerfile must switch to a non-root user.
    """
    has_user = False
    for line in file_content:
        clean_line = line.strip().upper()
        if clean_line.startswith("USER"):
            has_user = True
            break
            
    if not has_user:
        return {
            "line": 0,
            "severity": "CRITICAL",
            "message": "Container running as root (No USER instruction)."
        }
    return None