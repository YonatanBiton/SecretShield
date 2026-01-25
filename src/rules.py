"""
Rules Engine for SecretShield.

This module defines the detection logic for finding secrets and security flaws.
It operates on three layers:
1.  **High-Fidelity Regex:** Matches specific patterns like AWS AKIA keys, Slack tokens, etc.
2.  **Heuristic Entropy Analysis:** Detects "random-looking" strings assigned to sensitive variables 
    (e.g., "PASSWORD = 'x8!z...'" vs "PASSWORD = 'default'").
3.  **Docker Best Practices:** Linting rules to ensure container security.

Dependencies:
    - re: For regular expression matching.
    - math: For Shannon entropy calculations.
"""

import re
import math
from typing import List, Dict, Any, Optional

# --- Constants & Patterns ---

# High Fidelity Patterns (Confidence: ~99%)
# These patterns match strict formats defined by the service providers.
SPECIFIC_PATTERNS = {
    "AWS": r'(AKIA[0-9A-Z]{16})',
    "Google_API": r'(AIza[0-9A-Za-z\\-_]{35})',
    "Slack_Token": r'(xox[baprs]-[a-zA-Z0-9-]+)',
    "GitHub": r'(ghp_[0-9a-zA-Z]{36})',
    "Stripe": r'(sk_live_[0-9a-zA-Z]{20,})',
    "Private Key Header": r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
    "DigitalOcean": r'(dop_v1_[0-9a-fA-F]{64})',
    "GitLab": r'(glpat-[0-9a-zA-Z\-]{20})'
}

# Generic Suspicious Variable Names
# Used for heuristic detection. We look for these keywords in variable assignments.
# The (?i) flag makes it case-insensitive.
SUSPICIOUS_NAMES = r'(?i)(password|secret|token|api_key|access_key|auth_key|credentials|key)'


def find_aws_secret_candidate(lines: List[str], index: int) -> Optional[str]:
    """Scans nearby lines for a potential AWS Secret Key.
    
    An AWS Access Key ID (AKIA...) is rarely useful without its paired Secret Key.
    This function looks at a window of +/- 4 lines around the ID to find the
    corresponding 40-character secret key.

    Args:
        lines (List[str]): The entire file content.
        index (int): The line number where the Access Key ID was found.

    Returns:
        Optional[str]: The secret key if found, otherwise None.
    """
    start = max(0, index - 4)
    end = min(len(lines), index + 5)
    
    # Regex for a standard AWS Secret Key (40 chars, alphanumeric + symbols)
    # Matches: secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    secret_pattern = r'(?i)(secret|key).*?[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
    
    for i in range(start, end):
        # Don't re-check the line that triggered the ID search
        if i == index: 
            continue
            
        line = lines[i]
        match = re.search(secret_pattern, line)
        if match:
            return match.group(2) # Return the captured secret string
            
    return None


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon Entropy of a string.

    Entropy is a measure of randomness.
    - Low Entropy (e.g., "password123"): Predictable, repetitive characters.
    - High Entropy (e.g., "8x!a$2_p9"): Random, uniform distribution of characters.

    Formula: H(X) = -sum(p(x) * log2(p(x)))

    Args:
        data (str): The string to analyze.

    Returns:
        float: The entropy score (typically between 0 and 8).
    """
    if not data:
        return 0
        
    entropy = 0
    length = len(data)
    
    # Iterate over ASCII range (0-255) to find character frequencies
    for x in range(256):
        p_x = float(data.count(chr(x))) / length
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
            
    return entropy


def is_high_entropy(value: str) -> bool:
    """Determines if a string is "random enough" to be a secret.

    This function uses Shannon Entropy combined with heuristics to reduce
    false positives (e.g., avoiding high-entropy placeholders like {{VARIABLE}}).

    Args:
        value (str): The potential secret string.

    Returns:
        bool: True if it looks like a real secret, False otherwise.
    """
    # 1. Length Check: Real secrets are rarely short
    if len(value) < 8:
        return False
        
    # 2. Filter out Common False Positives (Placeholders, Template Tags)
    if value.strip().startswith(("$", "{{", "<%", "openssl", "base64")):
        return False

    upper_val = value.upper()
    if "EXAMPLE" in upper_val or "CHANGE_ME" in upper_val:
        return False
        
    # 3. Calculate Entropy
    entropy = calculate_shannon_entropy(value)

    # 4. Context-Aware Thresholds
    # Hexadecimal strings (0-9, A-F) have a smaller character set (16 chars),
    # so their maximum entropy is lower (4.0 bits).
    is_hex = bool(re.match(r'^[0-9a-fA-F]+$', value))
    
    if is_hex:
        # Threshold > 3.0 usually catches random 32-64 char hex keys
        return entropy > 3.0
    else:
        # Standard strings (Base64 / Ascii) have higher variety
        # Threshold > 3.9 usually filters out English words
        return entropy > 3.9


def check_secrets(line: str, line_num: int, all_lines: List[str] = None) -> Optional[Dict[str, Any]]:
    """Analyzes a single line for secrets using specific and generic rules.

    Args:
        line (str): The content of the line.
        line_num (int): The current line number (1-based).
        all_lines (List[str], optional): Full file context for multi-line checks (like AWS).

    Returns:
        Optional[Dict]: A dictionary containing finding details if a secret is found.
    """
    
    # --- Layer 1: Specific Patterns (High Confidence / Critical) ---
    for secret_type, pattern in SPECIFIC_PATTERNS.items():
        match = re.search(pattern, line)
        
        if match:
            detected_value = match.group(0) 
            
            # Special Handling for AWS: Try to find the pair
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
                
                # Fallback if we only found the ID
                return {
                    "line": line_num,
                    "type": "AWS_ID",
                    "key_id": detected_value,
                    "severity": "CRITICAL",
                    "message": f"{secret_type} ID found ({detected_value}) - Couldn't find the secret key"
                }

            # Standard handling for single-string keys (Stripe, GitHub, etc.)
            return {
                "line": line_num,
                "type": secret_type,
                "secret": detected_value, # The actual key for active verification
                "severity": "CRITICAL",
                "message": f"{secret_type} found. High-confidence leak."
            }

    # --- Layer 2: Generic Keyword + Entropy Check (Medium/High) ---
    # Regex: Look for suspicious variable names assigned to quoted values
    # Matches: PASSWORD = "..." or api_key='...'
    generic_match = re.search(rf"""{SUSPICIOUS_NAMES}\s*=\s*(['"])(.*?)(\2)""", line)

    if generic_match:
        variable_name = generic_match.group(1) # e.g., "DB_PASSWORD"
        secret_value = generic_match.group(3)  # e.g., "x8!sPa2@1"
        
        try:
            # Apply Entropy Logic: Is this value random?
            if is_high_entropy(secret_value):
                return {
                    "line": line_num,
                    "severity": "HIGH",
                    "type": f"Unknown {variable_name}", # Generic type since we don't know the provider
                    "secret": secret_value,
                    "message": f"Suspicious hardcoded secret found in variable '{variable_name}'."
                }
        except Exception as e:
            # In production code, we might log this error
            pass

    return None


def check_docker_rules(line: str, line_num: int) -> Optional[Dict[str, Any]]:
    """Checks a single line of a Dockerfile for security misconfigurations.

    Args:
        line (str): Raw line content.
        line_num (int): Line number.

    Returns:
        Optional[Dict]: Finding dictionary if an issue is detected.
    """
    clean_line = line.strip().upper()
    
    # Rule 1: Latest Tag
    # Detects: FROM node:latest OR FROM ubuntu (implies latest)
    if clean_line.startswith("FROM"):
        if "latest" in line or ":" not in line:
            return {
                "line": line_num,
                "severity": "MEDIUM",
                "message": "Base image uses 'latest' tag. Pin a specific version (e.g., node:14-alpine)."
            }
            
    # Rule 2: Using 'ADD' instead of 'COPY'
    # ADD has unexpected side effects (unzipping, fetching URLs). COPY is safer.
    if clean_line.startswith("ADD"):
        return {
            "line": line_num,
            "severity": "LOW",
            "message": "Using 'ADD' is discouraged. Use 'COPY' unless you need auto-extraction."
        }
        
    # Rule 3: Using 'sudo'
    # Containers generally run as root by default, or should rely on USER instruction.
    if "sudo " in line:
        return {
            "line": line_num,
            "severity": "HIGH",
            "message": "Avoid using 'sudo' in Dockerfiles. It adds attack surface and is usually unnecessary."
        }
        
    # Rule 4: Pip install pinning
    # Detects: pip install requests (Bad) vs pip install requests==2.0 (Good)
    if "pip install" in line and "requirements.txt" not in line:
        if "==" not in line:
            return {
                "line": line_num,
                "severity": "LOW",
                "message": "Pip install found without version pinning. Builds may break or pull malicious versions."
            }

    return None


def check_user_exists(file_content: List[str]) -> Optional[Dict[str, Any]]:
    """Global Check: Ensures the Dockerfile switches to a non-root user.

    Running containers as root is a major security risk. This checks for the
    presence of the 'USER' instruction.

    Args:
        file_content (List[str]): All lines of the Dockerfile.

    Returns:
        Optional[Dict]: Finding if the check fails.
    """
    has_user = False
    for line in file_content:
        clean_line = line.strip().upper()
        if clean_line.startswith("USER"):
            has_user = True
            break
            
    if not has_user:
        return {
            "line": 0, # Global file issue, no specific line
            "severity": "CRITICAL",
            "message": "Container running as root. Add a 'USER' instruction to drop privileges."
        }
    return None