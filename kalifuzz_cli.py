#!/usr/bin/env python3
"""
kalifuzz_cli.py
----------------
Advanced CLI directory & file fuzzing / enumeration tool for Kali Linux,
in the spirit of gobuster / dirb / ffuf -- with a colored banner, live
colorized hits, a progress bar, wildcard filtering, recursion, and an
auto-generated HTML report saved under ./fuzzing_reports/.

Usage:
    python3 kalifuzz_cli.py -u http://target.local -w wordlists/common.txt -x php,html -t 50 -r

For authorized security testing / learning only.
"""

import argparse
import os
import sys
import time
from datetime import datetime

try:
    from rich.console import Console
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
    from rich.table import Table
    from rich import box
except ImportError:
    print("Missing dependency 'rich'. Install with: pip3 install -r requirements.txt")
    sys.exit(1)

try:
    import pyfiglet
except ImportError:
    pyfiglet = None

from fuzzer_core import ScanOptions, FuzzEngine, DEFAULT_STATUS_CODES, Finding
from report_generator import generate_html_report

console = Console(highlight=False)

STATUS_STYLE = {2: "bold green", 3: "bold yellow", 4: "bold magenta", 5: "bold red"}


def status_style(code: int) -> str:
    return STATUS_STYLE.get(code // 100, "white")


def print_banner():
    if pyfiglet:
        text = pyfiglet.figlet_format("KaliFuzz", font="slant")
    else:
        text = "== KaliFuzz ==\n"
    console.print(text, style="bold green")
    console.print("  Advanced Directory & File Enumeration Tool for Kali Linux", style="dim")
    console.print("  In the spirit of gobuster / dirb / ffuf\n", style="dim")
    console.rule(style="green")


def parse_args():
    p = argparse.ArgumentParser(
        prog="kalifuzz",
        description="Advanced CLI directory & file fuzzing / enumeration tool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    default_wordlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "common.txt")
    p.add_argument("-u", "--url", required=True, help="Target base URL, e.g. http://target.local")
    p.add_argument("-w", "--wordlist", default=default_wordlist, help="Path to wordlist")
    p.add_argument("-x", "--extensions", default="", help="Comma-separated extensions, e.g. php,html,txt")
    p.add_argument("-t", "--threads", type=int, default=30, help="Concurrent threads")
    p.add_argument("-to", "--timeout", type=float, default=8.0, help="Request timeout (seconds)")
    p.add_argument(
        "-c", "--status-codes",
        default=",".join(str(c) for c in sorted(DEFAULT_STATUS_CODES)),
        help="Comma-separated status codes to show",
    )
    p.add_argument("--exclude-codes", default="", help="Comma-separated status codes to hide")
    p.add_argument("-r", "--recursive", action="store_true", help="Recursively fuzz discovered directories")
    p.add_argument("--max-depth", type=int, default=2, help="Max recursion depth")
    p.add_argument("-a", "--user-agent", default="KaliFuzz/1.0 (+security-assessment)", help="Custom User-Agent")
    p.add_argument("--proxy", default=None, help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp/ZAP)")
    p.add_argument("-k", "--no-ssl-verify", action="store_true", help="Disable SSL certificate verification")
    p.add_argument("--delay", type=float, default=0.0, help="Delay (seconds) between requests, per thread")
    p.add_argument("-o", "--output", default=None, help="Output HTML report filename (saved in fuzzing_reports/)")
    p.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")
    return p.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    if not os.path.isfile(args.wordlist):
        console.print(f"[bold red]Wordlist not found:[/bold red] {args.wordlist}")
        sys.exit(1)

    status_codes = {int(c) for c in args.status_codes.split(",") if c.strip()}
    exclude_codes = {int(c) for c in args.exclude_codes.split(",") if c.strip()}
    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]

    options = ScanOptions(
        target=args.url,
        wordlist_path=args.wordlist,
        extensions=extensions,
        threads=args.threads,
        timeout=args.timeout,
        status_codes=status_codes,
        exclude_codes=exclude_codes,
        user_agent=args.user_agent,
        proxy=args.proxy,
        verify_ssl=not args.no_ssl_verify,
        recursive=args.recursive,
        max_recursion_depth=args.max_depth,
        delay=args.delay,
    )

    console.print(f"[bold]Target     :[/bold] {args.url}")
    console.print(f"[bold]Wordlist   :[/bold] {args.wordlist}")
    console.print(f"[bold]Threads    :[/bold] {args.threads}")
    console.print(f"[bold]Extensions :[/bold] {', '.join(extensions) or '(none)'}")
    recur_str = f"yes (max depth {args.max_depth})" if args.recursive else "no"
    console.print(f"[bold]Recursive  :[/bold] {recur_str}")
    console.rule(style="green")

    findings = []
    start_time = time.time()
    progress_state = {"done": 0, "total": 0}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Fuzzing", total=1)

        def on_result(f: Finding):
            style = status_style(f.status_code)
            line = f"[{style}]{f.status_code}[/{style}]  {f.path:<42}  ({f.content_length} bytes)"
            if f.redirect_location:
                line += f"  -> {f.redirect_location}"
            progress.console.print(line)

        def on_progress(done, total):
            progress.update(task_id, completed=done, total=total)
            progress_state["done"], progress_state["total"] = done, total

        def on_log(msg):
            progress.console.print(f"[dim][*] {msg}[/dim]")

        engine = FuzzEngine(options, on_result=on_result, on_progress=on_progress, on_log=on_log)
        try:
            findings = engine.run()
        except RuntimeError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            sys.exit(1)
        except KeyboardInterrupt:
            engine.stop()
            console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")

    elapsed = time.time() - start_time

    console.rule(style="green")
    table = Table(title="Scan Summary", box=box.ROUNDED, show_lines=False)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value")
    table.add_row("Target", args.url)
    table.add_row("Paths found", str(len(findings)))
    table.add_row("Requests sent", str(progress_state["total"]))
    table.add_row("Elapsed time", f"{elapsed:.2f}s")
    if elapsed > 0 and progress_state["total"]:
        table.add_row("Requests / sec", f"{progress_state['total'] / elapsed:.1f}")
    console.print(table)

    report_dir = os.path.join(os.getcwd(), "fuzzing_reports")
    os.makedirs(report_dir, exist_ok=True)
    if args.output:
        report_path = os.path.join(report_dir, args.output)
    else:
        host = args.url.replace("https://", "").replace("http://", "").strip("/").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"report_{host}_{ts}.html")

    generate_html_report(
        report_path,
        target=args.url,
        findings=findings,
        wordlist=args.wordlist,
        threads=args.threads,
        elapsed=elapsed,
        total_requests=progress_state["total"],
        extensions=extensions,
    )
    console.print(f"\n[bold green]HTML report saved ->[/bold green] {report_path}")


if __name__ == "__main__":
    main()
