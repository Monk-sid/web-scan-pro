import time
import sys
from urllib.parse import urldefrag, urljoin, urlparse
from webscanPro.scanner_utils import get_session, extract_links, extract_forms, normalize_url, is_same_domain
from tqdm import tqdm


def normalize_link(href, base_url):
    """
    Return a normalized absolute URL for href resolved against base_url,
    or None if href should be skipped or invalid.
    """
    if not href:
        return None

    href = str(href).strip()
    if not href or href.lower() in ("none", "null"):
        return None

    # Skip unwanted or invalid schemes
    skip_prefixes = (
        "javascript:",
        "mailto:",
        "tel:",
        "data:",
        "vbscript:",
        "#",
    )
    if href.lower().startswith(skip_prefixes):
        return None

    try:
        abs_url = urljoin(base_url, href)
    except Exception:
        return None

    parsed = urlparse(abs_url)
    if parsed.scheme not in ("http", "https"):
        return None

    # Strip fragments like #section
    return parsed._replace(fragment="").geturl()


def ensure_valid_base(base_url):
    """
    Return a valid http(s) base URL or None.
    Tries the given URL, and if missing scheme tries adding http://
    """
    if not base_url:
        return None

    base_url = str(base_url).strip().rstrip('/')
    # Try direct normalization
    normalized = normalize_link(base_url, base_url)
    if normalized:
        return normalized

    # If user passed something like 'localhost:8080', try adding http://
    if not urlparse(base_url).scheme:
        try_url = "http://" + base_url
        normalized = normalize_link(try_url, try_url)
        if normalized:
            return normalized

    return None


class Crawler:
    def __init__(self, base_url, max_pages=200, delay=0.2, session=None):
        # validate base URL robustly to avoid None in queue
        valid_base = ensure_valid_base(base_url)
        if not valid_base:
            raise ValueError(f"Invalid base URL provided to Crawler: {base_url!r}")

        # Use the normalized valid base
        self.base = valid_base

        # keep existing behavior for normalize_url use (used later)
        self.max_pages = max_pages
        self.delay = delay
        self.session = session or get_session()
        self.visited = set()
        self.queue = [self.base]
        self.pages = {}
        self.forms = {}

    def crawl(self):
        pbar = tqdm(total=self.max_pages, desc="Crawling")
        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.pop(0)

            # Safety: skip if somehow None sneaks in
            if not current_url:
                # debug line — remove or change to logging.debug later
                print("Skipping invalid queue item: None", file=sys.stderr)
                continue

            if current_url in self.visited:
                continue
            if not is_same_domain(self.base, current_url):
                continue

            try:
                r = self.session.get(current_url, timeout=10, allow_redirects=True)
                html = r.text
            except Exception as e:
                print(f"failed to fetch {current_url}: {e}", file=sys.stderr)
                self.visited.add(current_url)
                continue

            self.visited.add(current_url)
            self.pages[current_url] = html

            forms = extract_forms(html, current_url)
            if forms:
                self.forms[current_url] = forms

            links = extract_links(html, current_url)
            for link in links:
                safe_link = normalize_link(link, current_url)
                if not safe_link:
                    # skip bad or unsupported URLs
                    continue

                # keep using normalize_url for final canonicalization if you rely on it elsewhere
                clean_link = normalize_url(self.base, str(urldefrag(safe_link)[0]).rstrip('/'))
                if (
                    clean_link
                    and clean_link not in self.visited
                    and clean_link not in self.queue
                    and is_same_domain(self.base, clean_link)
                ):
                    self.queue.append(clean_link)

            pbar.update(1)
            time.sleep(self.delay)
        pbar.close()

        return {'pages': self.pages, 'forms': self.forms}