"""
Unit Tests for SecretShield Rules Engine.

This module validates the core detection logic, ensuring that:
1. Heuristics correctly identify high-entropy strings.
2. Regex patterns catch specific provider keys (AWS, Stripe, etc.).
3. Dockerfile linting rules flag insecure practices.
4. Obfuscation techniques (string concatenation) are detected.

Usage:
    Run from the root directory:
    $ pytest tests/test_rules.py
"""

import sys
import os
import pytest

# --- Path Setup ---
# Add the project root to sys.path so we can import from 'src'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.rules import check_secrets, check_docker_rules, check_user_exists, is_high_entropy
from src.scanner import normalize_line

# ==============================================================================
# 1. Testing the "Brain" (Entropy & Heuristics)
# ==============================================================================

@pytest.mark.parametrize("value, expected", [
    # --- TRUE POSITIVES (Long, Random API Tokens) ---
    # These must be long enough (>16 chars) to mathematically exceed 3.9 entropy
    ("Xy9#mP!2_ZqRwK9@vN3$", True),       
    ("gH7@bL9$kP2!mX5#nR8*", True),       
    ("A1b2C3d4E5f6G7h8I9j0", True),
    ("sk_live_51Mz9abcdefghijklmnopqr", True), # Real-looking Stripe key
    
    # --- FALSE POSITIVES (Safe or Too Short) ---
    ("password", False),           # Just lowercase
    ("123456", False),             # Just digits
    ("CHANGE_ME", False),          # Known placeholder
    ("EXAMPLE_KEY", False),        # Known placeholder
    ("admin", False),              # Common word
    ("localhost", False),          # Config value
    # Short random string (8 chars). 
    # Max entropy for length 8 is 3.0, so this MUST return False (Threshold is 3.9)
    ("Xy9#mP!2", False),           
])
def test_is_high_entropy(value, expected):
    """Verifies that the heuristic engine correctly flags random strings."""
    assert is_high_entropy(value) == expected, f"Entropy check failed for: {value}"


# ==============================================================================
# 2. Testing Secret Detection (Regex + Logic)
# ==============================================================================

@pytest.mark.parametrize("line, expected_severity", [
    # --- HIGH FIDELITY (Critical) ---
    # These match specific vendor patterns (AWS, GitHub, Stripe)
    ('AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"', "CRITICAL"), 
    ('key = "ghp_123456789012345678901234567890123456"', "CRITICAL"),
    ('stripe = "sk_live_51Mz9abcdefghijklmnopqr"', "CRITICAL"),
    
    # --- GENERIC HEURISTICS (High) ---
    # Good matches (Suspicious Name + Complex Value)
    ('DB_PASSWORD = "Xy9#mP!2_ZqRwK9@vN3$"', "HIGH"), 
    ('export SECRET_TOKEN="gH7@bL9$kP2!mX5#nR8*"', "HIGH"),
    ('   api_key  =  "Z9@#12kL!mN_LONG_ENOUGH"', "HIGH"),

    # --- FALSE ALARMS (Should be Ignored) ---
    ('DB_PASSWORD = "password"', None),         # Placeholder value
    ('API_KEY = "123456"', None),               # Too short/simple
    ('AUTH_TOKEN = "CHANGE_ME"', None),         # Placeholder
    ('image_id = "AKIA_BUT_FAKE"', None),       # Looks like AWS but wrong regex length
])
def test_check_secrets(line, expected_severity):
    """Verifies that we catch real secrets and ignore fake ones."""
    # We pass 'None' for all_lines since these are single-line checks
    result = check_secrets(line, 1, all_lines=None)
    
    if expected_severity is None:
        assert result is None, f"Should NOT have flagged: {line}"
    else:
        assert result is not None, f"Failed to flag: {line}"
        assert result['severity'] == expected_severity


# ==============================================================================
# 3. Testing Docker Rules (Infrastructure)
# ==============================================================================

@pytest.mark.parametrize("line, expected_message_part", [
    # --- LATEST TAG ---
    ("FROM node", "latest"),              # Implied latest
    ("FROM node:latest", "latest"),       # Explicit latest
    ("FROM python:3.9", None),            # Safe (Pinned)
    ("FROM my-reg/image:v1", None),       # Safe (Custom reg)

    # --- ADD vs COPY ---
    ("ADD . /app", "Use 'COPY'"),         # Bad practice
    ("COPY . /app", None),                # Good practice

    # --- SUDO ---
    ("RUN sudo apt-get update", "sudo"),  # Security risk
    ("RUN apt-get update", None),         # Safe

    # --- PIP INSTALL ---
    ("RUN pip install requests", "version pinning"),      # Bad (Supply chain risk)
    ("RUN pip install requests==2.0", None),              # Good
    ("RUN pip install -r requirements.txt", None),        # Good (Indirect pinning)
])
def test_docker_rules(line, expected_message_part):
    """Verifies IaC (Infrastructure as Code) rules for Dockerfiles."""
    result = check_docker_rules(line, 1)
    
    if expected_message_part is None:
        assert result is None, f"False positive on Docker rule: {line}"
    else:
        assert result is not None, f"Failed to catch Docker issue: {line}"
        assert expected_message_part in result['message']


# ==============================================================================
# 4. Testing User Existence (Global Check)
# ==============================================================================

def test_user_check_missing():
    """Test that a Dockerfile running as root (no USER instruction) is flagged."""
    content = [
        "FROM python:3.9\n",
        "WORKDIR /app\n",
        "CMD ['python']\n"
    ]
    result = check_user_exists(content)
    assert result is not None
    assert result['severity'] == "CRITICAL"
    assert "root" in result['message']

def test_user_check_present():
    """Test that a Dockerfile with a USER instruction is considered safe."""
    content = [
        "FROM python:3.9\n",
        "RUN useradd myuser\n",
        "USER myuser\n",  # <--- Safe!
        "CMD ['python']\n"
    ]
    result = check_user_exists(content)
    assert result is None


# ==============================================================================
# 5. Testing Obfuscation (String Concatenation)
# ==============================================================================

def test_obfuscated_secret():
    """
    Test that a secret split into multiple parts (concatenation) is detected.
    This simulates evasion techniques like: "part1" + "part2"
    """
    # 1. The sneaky line of code (Stripe key split in half)
    sneaky_line = 'API_Key = "sk_live_51Mz" + "9abcdefghijklmnopqr"'
    
    # 2. Run the normalization logic (just like scanner.py does)
    cleaned_line = normalize_line(sneaky_line)
    
    # 3. Verify normalization worked
    # Should look like: API_Key = "sk_live_51Mz9abcdefghijklmnopqr"
    assert "sk_live_51Mz9abcdefghijklmnopqr" in cleaned_line
    
    # 4. Now check for secrets on the cleaned line
    result = check_secrets(cleaned_line, 1, all_lines=None)
    
    assert result is not None, "Failed to detect concatenated secret!"
    assert result['type'] == 'Stripe'
    assert result['severity'] == 'CRITICAL'