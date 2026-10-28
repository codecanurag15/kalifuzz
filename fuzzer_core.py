#!/usr/bin/env python3
"""
fuzzer_core.py
--------------
Shared directory/file fuzzing engine for KaliFuzz.

Both the CLI (kalifuzz_cli.py) and the GUI (kalifuzz_gui.py) import this
module and drive the same FuzzEngine, so scanning logic lives in exactly
one place. The engine is callback-driven: it doesn't know or care whether
it's being watched by a terminal or a Tkinter window.

For authorized security testing / learning only. Only scan targets you
own or have explicit written permission to test.
"""

import concurrent.futures
import random
import string
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Status codes shown by default -- tuned like gobuster/dirb defaults.
DEFAULT_STATUS_CODES = {200, 204, 301, 302, 307, 401, 403, 405}


@dataclass
class ScanOptions:
    target: str
    wordlist_path: str
    extensions: List[str] = field(default_factory=list)
    threads: int = 30
    timeout: float = 8.0
    status_codes: Set[int] = field(default_factory=lambda: set(DEFAULT_STATUS_CODES))
    exclude_codes: Set[int] = field(default_factory=set)
    user_agent: str = "KaliFuzz/1.0 (+security-assessment)"
    proxy: Optional[str] = None          # e.g. http://127.0.0.1:8080 for Burp/ZAP
    verify_ssl: bool = True
    recursive: bool = False
    max_recursion_depth: int = 2
    delay: float = 0.0                   # seconds between requests, per thread
    follow_redirects: bool = False
    extra_headers: dict = field(default_factory=dict)
    cookies: Optional[dict] = None


@dataclass
class Finding:
    url: str
    path: str
    status_code: int
    content_length: int
    redirect_location: Optional[str] = None
    depth: int = 0


class FuzzEngine:
    """
    Thread-pooled HTTP path fuzzer with wildcard-response (soft-404)
    detection, optional recursion into discovered directories, and
    pluggable callbacks for progress/results/log lines.
    """

    def __init__(
        self,
        options: ScanOptions,
        on_result: Optional[Callable[[Finding], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ):
        self.options = options
        self.on_result = on_result or (lambda f: None)
        self.on_progress = on_progress or (lambda done, total: None)
        self.on_log = on_log or (lambda msg: None)

        self._stop_event = threading.Event()
        self.findings: List[Finding] = []
        self._session = requests.Session()
        self._wildcard_signature = None  # (status_code, content_length) | None

    def stop(self):
        self._stop_event.set()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    # ---------------- wordlist ----------------
    def _load_wordlist(self) -> List[str]:
        words = []
        try:
            with open(self.options.wordlist_path, "r", errors="ignore") as fh:
                for line in fh:
                    w = line.strip()
                    if w and not w.startswith("#"):
                        words.append(w)
        except OSError as exc:
            raise RuntimeError(f"Could not read wordlist: {exc}")
        if not words:
            raise RuntimeError("Wordlist is empty.")
        return words

    def _build_candidates(self, words: List[str]) -> List[str]:
        candidates = []
        for w in words:
            candidates.append(w)
            for ext in self.options.extensions:
                ext = ext.lstrip(".")
                candidates.append(f"{w}.{ext}")
        return candidates

    # ---------------- wildcard / soft-404 detection ----------------
    def _detect_wildcard(self):
        probe = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        url = urljoin(self.options.target.rstrip("/") + "/", probe)
        try:
            resp = self._request(url)
        except requests.RequestException:
            self._wildcard_signature = None
            return
        self._wildcard_signature = (resp.status_code, len(resp.content))
        self.on_log(
            f"Wildcard baseline: HTTP {resp.status_code}, {len(resp.content)} bytes "
            f"-- matching responses will be filtered as false positives."
        )

    # ---------------- HTTP ----------------
    def _request(self, url: str):
        headers = {"User-Agent": self.options.user_agent}
        headers.update(self.options.extra_headers)
        proxies = None
        if self.options.proxy:
            proxies = {"http": self.options.proxy, "https": self.options.proxy}
        return self._session.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=self.options.timeout,
            verify=self.options.verify_ssl,
            allow_redirects=self.options.follow_redirects,
            cookies=self.options.cookies,
        )

    def _check_one(self, base: str, path: str, depth: int = 0) -> Optional[Finding]:
        if self._stop_event.is_set():
            return None
        url = urljoin(base.rstrip("/") + "/", path)
        try:
            resp = self._request(url)
        except requests.RequestException:
            return None
        finally:
            if self.options.delay:
                time.sleep(self.options.delay)

        sig = (resp.status_code, len(resp.content))
        if self._wildcard_signature and sig == self._wildcard_signature:
            return None
        if resp.status_code in self.options.exclude_codes:
            return None
        if resp.status_code not in self.options.status_codes:
            return None

        finding = Finding(
            url=url,
            path="/" + path,
            status_code=resp.status_code,
            content_length=len(resp.content),
            redirect_location=resp.headers.get("Location"),
            depth=depth,
        )
        self.findings.append(finding)
        self.on_result(finding)
        return finding

    # ---------------- orchestration ----------------
    def run(self) -> List[Finding]:
        words = self._load_wordlist()
        candidates = self._build_candidates(words)
        self.on_log(f"Loaded {len(words)} words -> {len(candidates)} candidate requests.")
        self._detect_wildcard()

        self._scan_level(self.options.target, candidates, depth=0)

        if self.options.recursive and not self._stop_event.is_set():
            self._recurse(candidates)

        return self.findings

    def _scan_level(self, base: str, candidates: List[str], depth: int):
        total = len(candidates)
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.options.threads) as pool:
            futures = [pool.submit(self._check_one, base, c, depth) for c in candidates]
            for _ in concurrent.futures.as_completed(futures):
                done += 1
                self.on_progress(done, total)
                if self._stop_event.is_set():
                    break

    def _recurse(self, candidates: List[str]):
        depth = 1
        frontier = [f for f in self.findings if f.status_code in (200, 301, 302) and f.depth == 0]
        seen_bases = set()
        while frontier and depth <= self.options.max_recursion_depth and not self._stop_event.is_set():
            next_frontier = []
            for finding in frontier:
                base = finding.url if finding.url.endswith("/") else finding.url + "/"
                if base in seen_bases:
                    continue
                seen_bases.add(base)
                self.on_log(f"Recursing into {base} (depth {depth})")
                before = len(self.findings)
                self._scan_level(base, candidates, depth=depth)
                next_frontier.extend(
                    f for f in self.findings[before:] if f.status_code in (200, 301, 302)
                )
            frontier = next_frontier
            depth += 1
