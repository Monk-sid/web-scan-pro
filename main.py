import argparse
from urllib.parse import urljoin
from webscanPro.crawler import Crawler
from webscanPro.sqli import SQLiScanner
from webscanPro.xssTester import XSSScanner
from webscanPro.auth import AuthTester
from webscanPro.idorTesting import IDORScanner
from webscanPro.generate_report import Reporter
from webscanPro.scanner_utils import get_session, extract_links, extract_forms, normalize_url, is_same_domain

def run_all(target, max_pages=200, use_selenium=False):
    # This session is for modules that don't manage their own complex auth state.
    shared_session = get_session()
    print(f"[*] Crawling target: {target}")
    crawler = Crawler(base_url=target, max_pages=max_pages, session=shared_session)
    crawl_result = crawler.crawl()
    pages = crawl_result['pages']
    forms = crawl_result['forms']
    findings = []

    print("[*] Running SQLi scanner...")
    sqli = SQLiScanner(base_url=target, session=shared_session)
    sqli_findings = sqli.run(pages, forms)
    findings.extend(sqli_findings)
    print(f"    Found {len(sqli_findings)} potential SQLi issues.")

    print("[*] Running XSS scanner...")
    xss = XSSScanner(session=shared_session)
    xss_findings = xss.run(pages, forms)
    findings.extend(xss_findings)
    print(f"    Found {len(xss_findings)} potential XSS issues.")

    print("[*] Running Auth Bypass tester...")
    # This module will use the shared session and leave it in a logged-in state.
    auth = AuthTester(session=shared_session)
    auth_findings = auth.run(pages)
    findings.extend(auth_findings)
    print(f"    Found {len(auth_findings)} potential authentication/logic issues.")

    # Log out of the shared session to ensure a clean state for the IDOR scanner.
    print("[*] Terminating shared session to ensure a clean slate for subsequent tests...")
    logout_url = urljoin(target, "logout.php")
    shared_session.get(logout_url)

    print("[*] Running IDOR scanner...")
    # The IDORScanner is self-contained. It manages its own sessions, logins,
    # and logouts for each user it tests.
    idor = IDORScanner()
    idor_findings = idor.run(pages)
    findings.extend(idor_findings)
    print(f"    Found {len(idor_findings)} potential IDOR issues.")

    # Generate and print/save report
    print("[*] Generating report...")
    reporter = Reporter()
    reporter.generate(findings, output_file="scan_report.html")
    print("Scan complete. Report saved to scan_report.html.")

def main():
    parser = argparse.ArgumentParser(description="WebScanPro - Modular Web Vulnerability Scanner")
    parser.add_argument("target", help="Target base URL (e.g., http://localhost:8080/)")
    parser.add_argument("--pages", type=int, default=200, help="Maximum number of pages to crawl (default: 200)")
    parser.add_argument("--selenium", action="store_true", help="Use Selenium for crawling (optional)")
    args = parser.parse_args()

    run_all(target=args.target, max_pages=args.pages, use_selenium=args.selenium)

if __name__ == "__main__":
    main()

