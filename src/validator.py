import boto3
import requests
from botocore.exceptions import ClientError

def verify_aws_access_key(access_key_id, secret_access_key):
    """
    Verifies AWS credentials using STS GetCallerIdentity.
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

def verify_stripe_key(api_key):
    """
    Verifies a Stripe Secret Key by hitting the Balance endpoint.
    """
    try:
        # Stripe uses Basic Auth with the key as the username
        response = requests.get('https://api.stripe.com/v1/balance', auth=(api_key, ''))
        
        if response.status_code == 200:
            return "ACTIVE! (Live Stripe Key)"
        elif response.status_code == 401:
            return "inactive (Revoked)"
        else:
            return f"ACTIVE! (Restricted Permissions: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"

def verify_github_token(token):
    """
    Verifies a GitHub Personal Access Token.
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
    
def verify_slack_token(token):
    """
    Verifies a Slack Token (xoxb/xoxp) by calling auth.test.
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

def verify_google_api_key(api_key):
    """
    Verifies a Google API Key.
    Note: Google requires enabling specific APIs, so we test a generic endpoint.
    """
    try:
        # We try to hit the Google Maps API or similar open endpoint
        response = requests.get(f'https://www.googleapis.com/webfonts/v1/webfonts?key={api_key}')
        
        if response.status_code == 200:
            return "ACTIVE! (Google API Key)"
        elif response.status_code == 400 and 'API key not valid' in response.text:
            return "inactive (Invalid Key)"
        elif response.status_code == 403:
             # 403 usually means the key is VALID but doesn't have WebFonts permission.
             # This is still a security risk!
            return "ACTIVE! (Restricted Permissions)"
        else:
            return f"inactive (Status: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"
    
def verify_digital_ocean_api(api_key):
    try:
        response = requests.get(
            'https://api.digitalocean.com/v2/account',
            headers={'Authorization': f'Bearer {api_key}'}
        )
        if response.status_code == 200:
            return "ACTIVE! (Digital Ocean API)"
        elif response.status_code == 400:
            return "inactive (Invalid Key)"
        elif response.status_code == 403:
             # 403 usually means the key is VALID but doesn't have WebFonts permission.
             # This is still a security risk!
            return "ACTIVE! (Restricted Permissions)"
        else:
            return f"inactive (Status: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"
    
def verify_gitlab_api(api_key):
    try:
        response = requests.get(
            'https://gitlab.com/api/v4/user',
            headers={'PRIVATE-TOKEN': f'{api_key}'}
        )
        if response.status_code == 200:
            return "ACTIVE! (Gitlab API)"
        elif response.status_code == 400:
            return "inactive (Invalid Key)"
        elif response.status_code == 403:
             # 403 usually means the key is VALID but doesn't have WebFonts permission.
             # This is still a security risk!
            return "ACTIVE! (Restricted Permissions)"
        else:
            return f"inactive (Status: {response.status_code})"
    except Exception:
        return "Error: Connection Failed"
