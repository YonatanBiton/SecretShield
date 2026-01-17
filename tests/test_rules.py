import pytest
from src.rules import check_secrets, check_docker_rules, check_user_exists, is_high_entropy

# ==============================================================================
# 1. Testing the "Brain" (Entropy & Heuristics)
# ==============================================================================

@pytest.mark.parametrize("value, expected", [
    # --- TRUE POSITIVES (Should be High Entropy / Dangerous) ---
    ("Xy9#mP!2", True),           # Mixed case + symbols + numbers
    ("gH7@bL9$kP2!", True),       # Long complex string
    ("SuperSecret1!", True),      # Borderline, but meets criteria (Upper+Lower+Digit+Symbol)
    ("A1b2C3d4E5", True),         # High variance alphanumeric
    
    # --- FALSE POSITIVES (Should be Low Entropy / Safe) ---
    ("password", False),          # Just lowercase
    ("123456", False),            # Just digits
    ("CHANGE_ME", False),         # Known placeholder
    ("EXAMPLE_KEY", False),       # Known placeholder
    ("true", False),              # Boolean
    ("false", False),             # Boolean
    ("admin", False),             # Common word
    ("localhost", False),         # Config value
    ("postgres", False),          # Database name
    ("root", False),              # User name
    ("short", False),             # Too short (<12 chars)
])
def test_is_high_entropy(value, expected):
    """
    Verifies that the heuristic engine correctly identifies random/complex strings
    while ignoring common placeholders.
    """
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
    ('DB_PASSWORD = "Xy9#mP!2"', "HIGH"), 
    ('export SECRET_TOKEN="gH7@bL9$kP2!"', "HIGH"),
    ('   api_key  =  "Z9@#12kL!mN"', "HIGH"), # Weird spacing handling

    # --- FALSE ALARMS (Should be Ignored) ---
    ('DB_PASSWORD = "password"', None),        # Placeholder value
    ('API_KEY = "123456"', None),              # Too short/simple
    ('AUTH_TOKEN = "CHANGE_ME"', None),        # Placeholder
    ('public_key = "MIIBIjANBgkq..."', None),  # Public keys are safe (usually)
    ('image_id = "AKIA_BUT_FAKE"', None),      # Looks like AWS but wrong regex length/format
])
def test_check_secrets(line, expected_severity):
    """
    Verifies that we catch real secrets and ignore fake ones.
    """
    result = check_secrets(line, 1)
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
    """
    Verifies IaC (Infrastructure as Code) rules for Dockerfiles.
    """
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
    """
    Test that a Dockerfile running as root (no USER instruction) is flagged.
    """
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
    """
    Test that a Dockerfile with a USER instruction is considered safe.
    """
    content = [
        "FROM python:3.9\n",
        "RUN useradd myuser\n",
        "USER myuser\n",  # <--- Safe!
        "CMD ['python']\n"
    ]
    result = check_user_exists(content)
    assert result is None