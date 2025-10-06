import time
import copy
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from .scanner_utils import get_session

def find_sql_errors(html_text):
    """
    Looks for common SQL error messages in a string.
    Returns (True, pattern) if an error is found, else (False, None).
    """
    if not html_text:
        return (False, None)
        
    # Common SQL error patterns, made more robust
    sql_errors = [
        r"you have an error in your sql syntax",
        r"warning: mysql_fetch_array\(\)",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sql command not properly ended",
        r"microsoft ole db provider for odbc drivers error",
        r"invalid querystring",
        r"odbc driver error",
        r"jet database engine error",
        r"microsoft jet database engine error",
        r"error connecting to database",
        r"supplied argument is not a valid mysql result resource",
        r"syntax error",
    ]
    
    for error in sql_errors:
        if re.search(error, html_text, re.IGNORECASE):
            return (True, error)
    return (False, None)


class SQLiScanner:
    def __init__(self, base_url, timeout=5, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or get_session()
        self.timeout = timeout
        self.findings = []

        # Common SQL Injection payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "admin'--",
            "' OR 'x'='x",
        ]

    def test_url_params(self, url):
        """Test query parameters for SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        for param in params:
            for payload in self.payloads:
                test_params = copy.deepcopy(params)
                test_params[param] = [payload]
                test_url = base + "?" + urlencode(test_params, doseq=True)

                try:
                    r = self.session.get(test_url, timeout=self.timeout)
                    vulnerable, pattern = find_sql_errors(r.text)

                    if vulnerable:
                        finding = {
                            "type": "SQLi",
                            "endpoint": test_url,
                            "severity": "High",
                            "mitigation": "Use parameterized queries or prepared statements.",
                            "param": param,
                            "payload": payload,
                            "evidence": f"Detected pattern: {pattern}"
                        }
                        if finding not in self.findings:
                            self.findings.append(finding)
                except Exception as e:
                    print(f"[!] Request failed for {test_url}: {e}")

                time.sleep(0.1)

    def test_forms(self, forms):
        """Test HTML forms for SQL injection."""
        for page_url, form_list in forms.items():
            for form in form_list:
                action = form.get("action") or page_url
                method = form.get("method", "get").lower()
                inputs = form.get("inputs", [])

                # Convert list of inputs to a dictionary for baseline data
                form_data = {}
                for input_field in inputs:
                    name = input_field.get('name')
                    value = input_field.get('value', 'test')
                    if name:
                        form_data[name] = value

                # Iterate through each input field to inject payload
                for input_to_test in inputs:
                    field_name = input_to_test.get('name')
                    if not field_name:
                        continue # Skip inputs without a name

                    for payload in self.payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload

                        try:
                            if method == "post":
                                r = self.session.post(action, data=test_data, timeout=self.timeout)
                            else:
                                r = self.session.get(action, params=test_data, timeout=self.timeout)

                            vulnerable, pattern = find_sql_errors(r.text)

                            if vulnerable:
                                finding = {
                                    "type": "SQLi",
                                    "endpoint": action,
                                    "severity": "High",
                                    "mitigation": "Use parameterized queries and validate user input.",
                                    "param": field_name,
                                    "payload": payload,
                                    "evidence": f"Detected pattern: {pattern}"
                                }
                                if finding not in self.findings:
                                    self.findings.append(finding)
                        except Exception as e:
                            print(f"[!] Form request failed: {e}")

                        time.sleep(0.1)

    def run(self, url_list, form_dict):
        """Run scanner on URLs and forms."""
        for url in url_list:
            self.test_url_params(url)

        self.test_forms(form_dict)
        return self.findings
