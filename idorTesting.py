import requests
import re
import time
from urllib.parse import urljoin

# Base URL for the DVWA instance
BASE_URL = "http://localhost:8080/"

# Define the users to test, including their IDs and first names for verification
USERS = [
    {'id': '1', 'username': 'admin', 'password': 'password', 'role': 'admin', 'name': 'admin'},
    {'id': '2', 'username': 'gordonb', 'password': 'password', 'role': 'user', 'name': 'Gordon'},
    {'id': '3', 'username': 'pablo', 'password': 'password', 'role': 'user', 'name': 'Pablo'},
]

class IDORScanner:
    def __init__(self):
        self.findings = []

    def _get_csrf_token(self, session, url):
        """Helper function to fetch a CSRF token from a given page."""
        try:
            response = session.get(url)
            response.raise_for_status()
            pattern = r"name=['\"]user_token['\"]\s*value=['\"](.*?)['\"]"
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                return match.group(1)
            return None
        except requests.RequestException:
            return None

    def setup_session(self, username, password):
        """
        Handles the entire setup process for a user: login and set security level.
        Returns a fully configured session object if successful, otherwise None.
        """
        session = requests.Session()
        login_url = urljoin(BASE_URL, 'login.php')
        security_url = urljoin(BASE_URL, 'security.php')

        # --- Step 1: Login ---
        login_token = self._get_csrf_token(session, login_url)
        if not login_token:
            print(f"  [FAIL] Login failed for {username}: Could not get login CSRF token.")
            return None

        login_data = {
            'username': username,
            'password': password,
            'user_token': login_token,
            'Login': 'Login'
        }
        
        try:
            response = session.post(login_url, data=login_data, allow_redirects=True)
            if "index.php" not in response.url:
                print(f"  [FAIL] Login failed for {username}: Check credentials.")
                return None
            print(f"  [SUCCESS] Logged in as {username}")
        except requests.RequestException as e:
            print(f"  [FAIL] Login request failed for {username}: {e}")
            return None

        # --- Step 2: Set Security Level ---
        security_token = self._get_csrf_token(session, security_url)
        if not security_token:
            print(f"  [FAIL] Failed to set security for {username}: Could not get security CSRF token.")
            return None
            
        security_data = {
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': security_token
        }
        
        headers = {'Referer': security_url}
        
        try:
            response = session.post(security_url, data=security_data, headers=headers)
            if "Security level is currently: low" in response.text:
                print("  [SUCCESS] Security level set to low.")
                return session # Return the fully configured session
            else:
                debug_file = f"security_fail_debug_{username}.html"
                with open(debug_file, "w", encoding="utf-8") as f:
                    f.write(response.text)
                print(f"  [FAIL] Failed to set security level. See {debug_file} for details.")
                return None
        except requests.RequestException as e:
            print(f"  [FAIL] Request to set security level failed: {e}")
            return None

    def test_horizontal_escalation(self, session, current_user, target_user):
        """Tests if the current user can access the target user's data."""
        idor_url = urljoin(BASE_URL, f"vulnerabilities/idor/?id={target_user['id']}")
        try:
            response = session.get(idor_url)
            expected_text = f"First name: {target_user['name']}"
            if response.status_code == 200 and expected_text in response.text:
                print(f"  [VULNERABLE] User '{current_user['username']}' accessed User '{target_user['username']}'s data.")
                finding = {
                    "type": "IDOR", "endpoint": idor_url, "severity": "High",
                    "mitigation": "Ensure server-side authorization checks prevent users from accessing unauthorized resources.",
                    "param": "id", "payload": target_user['id'],
                    "evidence": f"Successfully viewed profile of {target_user['username']}",
                    "username": current_user['username']
                }
                if finding not in self.findings:
                    self.findings.append(finding)
            else:
                print(f"  [SECURE] Access to User '{target_user['username']}'s data properly denied.")
        except requests.RequestException as e:
            print(f"  [ERROR] IDOR test request failed: {e}")

    def logout(self, session):
        """Logs out the current session."""
        try:
            session.get(urljoin(BASE_URL, 'logout.php'))
            print("  [INFO] Logged out.")
        except requests.RequestException:
            pass

    def run(self, pages):
        print("\n[*] Running IDOR scanner...")
        for current_user in USERS:
            print(f"\n[TESTING AS] User: {current_user['username']} (Role: {current_user['role']})")
            
            session = self.setup_session(current_user['username'], current_user['password'])
            
            if session:
                # Test access to all OTHER users' data
                for target_user in USERS:
                    if current_user['id'] != target_user['id']:
                        print(f"  - Testing: Can {current_user['username']} access {target_user['username']}'s data?")
                        self.test_horizontal_escalation(session, current_user, target_user)
                
                self.logout(session)
            
            time.sleep(0.5)

        print(f"\n[*] IDOR scanner finished. Found {len(self.findings)} issues.")
        return self.findings

