"""
Validator Module for SecretShield.

This module performs 'Active Verification' of detected secrets.
While the regex rules find *potential* secrets, this module connects to the 
actual service providers (AWS, GitHub, Stripe, etc.) to check if the keys 
are live, revoked, or restricted.

Dependencies:
    - boto3: AWS SDK for Python (for validating AWS credentials).
    - requests: HTTP library for validating REST API keys.
"""

import boto3
import requests
from botocore.exceptions import ClientError
from typing import Optional

def verify_aws_access_key(access_key_id: str, secret_access_key: str) -> str:
    """Verifies AWS credentials using the STS GetCallerIdentity endpoint.

    This is the safest way to check AWS keys as it returns identity info
    without performing any destructive actions.

    Args:
        access_key_id (str): The AWS Access Key ID (AKIA...).
        secret_access_key (str): The AWS Secret Access Key.

    Returns:
        str: Status message (ACTIVE with Account ID, or inactive).
    """
    if not access_key_id or not secret_access_key:
        return "UNVERIFIED (Missing Key Pair)"
        
    try:
        # Create a session with the specific keys found
        client = boto3.client(
            'sts',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key
        )
        # Try to make a real API call
        identity = client.get_caller_identity()
        return f"ACTIVE! (Account: {identity['Account']}, ARN: {identity['Arn']})"
        
    except ClientError:
        return "inactive (Invalid Permissions or Credentials)"
    except Exception as e:
        return f"Error: {str(e)}"


def verify_stripe_key(api_key: str) -> str:
    """Verifies a Stripe Secret Key by hitting the Balance endpoint.
    
    Args:
        api_key (str): The Stripe Secret Key (sk_live_...).

    Returns:
        str: Status message indicating if the key is live.
    """
    try:
        # Stripe uses Basic Auth with the key as the username, password empty
        response = requests.get('https://api.stripe.com/v1/balance', auth=(api_key, ''))
        
        if response.status_code == 200:
            return "ACTIVE! (Live Stripe Key)"
        elif response.status_code == 401:
            return "inactive (Revoked)"
        else:
            return f"ACTIVE! (Restricted Permissions: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"


def verify_github_token(token: str) -> str:
    """Verifies a GitHub Personal Access Token.

    Args:
        token (str): The GitHub PAT (ghp_...).

    Returns:
        str: Status message with the username if valid.
    """
    headers = {'Authorization': f'token {token}'}
    try:
        response = requests.get('https://api.github.com/user', headers=headers)
        
        if response.status_code == 200:
            user = response.json().get('login', 'Unknown')
            return f"ACTIVE! (User: {user})"
        elif response.status_code == 401:
            return "inactive (Revoked)"
        else:
            return f"ACTIVE! (Status: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"


def verify_slack_token(token: str) -> str:
    """Verifies a Slack Token (xoxb/xoxp) by calling auth.test.

    Args:
        token (str): The Slack token.

    Returns:
        str: Status message with Team/User info if valid.
    """
    try:
        response = requests.post(
            'https://slack.com/api/auth.test',
            headers={'Authorization': f'Bearer {token}'}
        )
        data = response.json()
        
        if data.get('ok'):
            return f"ACTIVE! (Team: {data.get('team')}, User: {data.get('user')})"
        elif data.get('error') == 'invalid_auth':
            return "inactive (Revoked)"
        else:
            return f"inactive (Error: {data.get('error')})"
    except Exception:
        return "Error: Connection Failed"


def verify_google_api_key(api_key: str) -> str:
    """Verifies a Google API Key.
    
    Note: Google keys are often scoped to specific APIs. We test against the 
    WebFonts API as it is commonly enabled and non-sensitive.

    Args:
        api_key (str): The Google API Key (AIza...).

    Returns:
        str: Status message.
    """
    try:
        response = requests.get(f'https://www.googleapis.com/webfonts/v1/webfonts?key={api_key}')
        
        if response.status_code == 200:
            return "ACTIVE! (Google API Key)"
        elif response.status_code == 400 and 'API key not valid' in response.text:
            return "inactive (Invalid Key)"
        elif response.status_code == 403:
            # 403 means the key is VALID (recognized by Google) but not allowed 
            # to access WebFonts. It is still a security risk.
            return "ACTIVE! (Restricted Permissions)"
        else:
            return f"inactive (Status: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"


def verify_digital_ocean_api(api_key: str) -> str:
    """Verifies a Digital Ocean Personal Access Token.

    Args:
        api_key (str): The Digital Ocean Token (dop_v1_...).
    """
    try:
        response = requests.get(
            'https://api.digitalocean.com/v2/account',
            headers={'Authorization': f'Bearer {api_key}'}
        )
        if response.status_code == 200:
            return "ACTIVE! (Digital Ocean API)"
        elif response.status_code == 401:
            return "inactive (Invalid Key)"
        else:
            return f"inactive (Status: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"


def verify_gitlab_api(api_key: str) -> str:
    """Verifies a GitLab Personal Access Token.

    Args:
        api_key (str): The GitLab Token (glpat-...).
    """
    try:
        response = requests.get(
            'https://gitlab.com/api/v4/user',
            headers={'PRIVATE-TOKEN': f'{api_key}'}
        )
        if response.status_code == 200:
            return "ACTIVE! (GitLab API)"
        elif response.status_code == 401:
            return "inactive (Invalid Key)"
        elif response.status_code == 403:
            return "ACTIVE! (Restricted Permissions)"
        else:
            return f"inactive (Status: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"