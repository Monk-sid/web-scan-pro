import re
import time
import logging
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import requests
from bs4 import BeautifulSoup

# --- Configuration ---
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>'
]

REFLECT_PATTERNS = [re.compile(re.escape(p), re.IGNORECASE) for p in XSS_PAYLOADS]
SLEEP_SECONDS = 0.1

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def sleep(seconds=SLEEP_SECONDS):
    time.sleep(seconds)

def get_params(url):
    parsed = urlsplit(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return params

def is_payload_reflected(body_text, patterns=REFLECT_PATTERNS):
    for pat in patterns:
        if pat.search(body_text):
            return True
    return False

def test_url_params(url, session=None):
    if session is None:
        session = requests.Session()
    findings = []
    params = get_params(url)
    if not params:
        logging.info("No query parameters to test for %s", url)
        return findings
    for param in list(params.keys()):
        for payload in XSS_PAYLOADS:
            parsed = urlsplit(url)
            query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            built = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
            logging.info('Testing param "%s" with payload "%s" on %s', param, payload, built)
            try:
                resp = session.get(built, timeout=15, allow_redirects=True)
                body = resp.text
                if is_payload_reflected(body):
                    findings.append({
                        'type': 'param',
                        'endpoint': built,
                        'param': param,
                        'payload': payload,
                        'evidence': 'Payload reflected in response'
                    })
                sleep()
            except requests.RequestException as e:
                logging.error('Request failed: %s for URL: %s', str(e), built)
    return findings

def get_forms(url, session=None):
    if session is None:
        session = requests.Session()
    try:
        resp = session.get(url, timeout=15)
        html = resp.text
        soup = BeautifulSoup(html, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException as e:
        logging.error('Failed to GET %s: %s', url, e)
        return []

def _get_default_value_for_input(elem):
    tag_name = elem.name.lower()
    if tag_name == 'input':
        input_type = (elem.get('type') or '').lower()
        if input_type in ('checkbox', 'radio'):
            return elem.get('value', 'on')
        if input_type in ('submit', 'button', 'image', 'file'):
            return elem.get('value', '')
        return elem.get('value', 'test')
    elif tag_name == 'textarea':
        return elem.text or 'test'
    elif tag_name == 'select':
        option = elem.find('option', selected=True) or elem.find('option')
        if option:
            return option.get('value', option.text)
        return 'test'
    else:
        return 'test'

def test_forms(url, session=None):
    if session is None:
        session = requests.Session()
    findings = []
    forms = get_forms(url, session=session)
    logging.info('Found %d form(s) on %s', len(forms), url)
    for form in forms:
        action = form.get('action') or url
        action = urljoin(url, action)
        method = (form.get('method') or 'GET').upper()
        form_data = {}
        elements = form.find_all(['input', 'textarea', 'select'])
        for elem in elements:
            name = elem.get('name')
            if not name:
                continue
            form_data[name] = _get_default_value_for_input(elem)
        if not form_data:
            logging.info('No named inputs found for form action %s', action)
            continue
        for input_name in list(form_data.keys()):
            for payload in XSS_PAYLOADS:
                test_data = form_data.copy()
                test_data[input_name] = payload
                logging.info('Testing form action "%s" method "%s" input "%s" with payload "%s"',
                             action, method, input_name, payload)
                try:
                    if method == 'POST':
                        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                        resp = session.post(action, data=test_data, headers=headers, timeout=20, allow_redirects=True)
                    else:
                        parsed = urlsplit(action)
                        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
                        merged = {**existing, **{k: v for k, v in test_data.items()}}
                        new_query = urlencode(merged, doseq=True)
                        get_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
                        resp = session.get(get_url, timeout=20, allow_redirects=True)
                    body = resp.text
                    if is_payload_reflected(body):
                        findings.append({
                            'type': 'form',
                            'endpoint': action,
                            'param': input_name,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                    sleep()
                except requests.RequestException as e:
                    logging.error('Form request failed: %s for action: %s', str(e), action)
    return findings

class XSSScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()

    def run(self, pages, forms):
        findings = []
        for url in pages.keys():
            findings.extend(test_url_params(url, session=self.session))
            findings.extend(test_forms(url, session=self.session))
        return findings
