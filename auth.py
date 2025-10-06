import requests
import re
import os
from urllib.parse import urlparse

DVWA_URL = "http://localhost:8080/"
LOGIN_URL = DVWA_URL + "login.php"
PROFILE_URL = DVWA_URL + "index.php"
SECURITY_LEVEL = "low"

class AuthTester:
    def __init__(self, session=None, username="admin", password="password", security_level=SECURITY_LEVEL):
        self.session = session or requests.Session()
        self.username = username
        self.password = password
        self.security_level = security_level

    def get_csrf_token(self, login_url):
        """
        Fetches the login page and extracts the CSRF token ('user_token').
        """
        try:
            resp = self.session.get(login_url)
            resp.raise_for_status() 
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to fetch login page at {login_url}. Error: {e}")
            raise

        with open("response_debug.html", "w", encoding="utf-8") as f:
            f.write(resp.text)

        print("[DEBUG] Status code from login page:", resp.status_code)
        print("[DEBUG] Response snippet from login page:", resp.text[:500])

        pattern = r"name=['\"]user_token['\"]\s*value=['\"](.*?)['\"]"
        match = re.search(pattern, resp.text, re.IGNORECASE)

        if match:
            token = match.group(1)
            print(f"[DEBUG] CSRF token found: {token}")
            return token

        print("[ERROR] CSRF token pattern did not match. Please inspect 'response_debug.html' to see why.")
        raise Exception("CSRF token not found. Check 'response_debug.html' for HTML content.")

    def dvwa_login(self):
        """
        Performs a login to DVWA using the retrieved CSRF token.
        """
        try:
            user_token = self.get_csrf_token(LOGIN_URL)
        except Exception as e:
            print(f"[ERROR] Could not proceed with login: {e}")
            return None

        cookies = {"security": self.security_level}
        data = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
            "user_token": user_token,
        }
        
        try:
            resp = self.session.post(LOGIN_URL, data=data, cookies=cookies)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Login POST request failed. Error: {e}")
            return None

        print("[DEBUG] Login POST response status:", resp.status_code)

        if "welcome.php" in resp.url or "index.php" in resp.url:
            print("Login successful!")
            return self.session.cookies
        else:
            print("Login failed. Check credentials and security level.")
            return None

    def check_cookie_flags(self):
        print("\n[AuthTester] Checking cookie flags...")
        if not self.session.cookies:
            print("  No cookies to check.")
            return
            
        for cookie in self.session.cookies:
            is_secure = "Yes" if cookie.secure else "No"
            is_http_only = "Yes" if "httponly" in cookie._rest else "No"
            print(f"  - Cookie: {cookie.name}, Secure: {is_secure}, HttpOnly: {is_http_only}")

    def test_session_fixation(self):
        """
        Tests for session fixation vulnerability in an isolated session to prevent conflicts.
        """
        print("\n[AuthTester] Testing session fixation vulnerability...")
        
        # Create an isolated AuthTester instance for this specific test.
        # This gives it a clean session and prevents cookie conflicts.
        fixation_tester = AuthTester(username=self.username, password=self.password, security_level=self.security_level)
        
        # Determine the hostname from the login URL to avoid hardcoding localhost/127.0.0.1
        target_host = urlparse(LOGIN_URL).hostname
        fixed_session_id = "fixedsessionid123"
        
        # Set the malicious cookie on the isolated session before logging in.
        fixation_tester.session.cookies.set("PHPSESSID", fixed_session_id, path="/", domain=target_host)
        print(f"  - Set a fixed PHPSESSID on domain '{target_host}'. Attempting login...")
        
        # Perform the login using the manipulated, isolated session.
        fixation_tester.dvwa_login()
        
        # FIX: Make the cookie retrieval unambiguous by specifying the domain.
        # This prevents the CookieConflictError by telling requests exactly which cookie to get.
        new_sessionid = fixation_tester.session.cookies.get("PHPSESSID", domain=target_host)
        
        print(f"  - Old (fixed) Session ID: {fixed_session_id}")
        print(f"  - New Session ID from server: {new_sessionid}")
        
        if new_sessionid and new_sessionid != fixed_session_id:
            print("  [PASS] Session ID was rotated after login. Secure against this fixation method.")
        else:
            print("  [FAIL] Session ID was not rotated. Potentially vulnerable to session fixation.")


    def test_profile_access(self):
        print("\n[AuthTester] Testing authenticated access...")
        try:
            resp = self.session.get(PROFILE_URL)
            if "Welcome to Damn Vulnerable Web Application" in resp.text:
                print("  [PASS] Authenticated access to main page confirmed.")
            else:
                print("  [FAIL] Could not access authenticated page after login.")
        except requests.exceptions.RequestException as e:
            print(f"  [ERROR] Failed to access profile page. Error: {e}")

    def run(self, pages):
        findings = []

        print("[AuthTester] Performing initial login and checks...")
        cookies = self.dvwa_login()
        if cookies is None:
            findings.append({"type": "auth", "issue": "Critical: Login failed. Subsequent auth tests skipped."})
            return findings

        # Run checks that require the now-authenticated main session.
        self.check_cookie_flags()
        self.test_profile_access()
        
        # Run the session fixation test, which is self-contained and manages its own session.
        self.test_session_fixation()

        findings.append({"type": "auth", "issue": "Completed authentication-related tests."})
        return findings
