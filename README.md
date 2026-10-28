# KaliFuzz

An advanced CLI + GUI directory/file enumeration (fuzzing) tool for Kali
Linux, in the spirit of **gobuster**, **dirb**, and **ffuf** — colored
terminal banner and live hit coloring, a Tkinter GUI, multithreading,
wildcard (soft-404) filtering, optional recursion into found directories,
and a styled HTML report auto-saved to `fuzzing_reports/`.

> **Use responsibly.** Only scan systems you own or have explicit written
> authorization to test. Unauthorized scanning of systems you don't control
> can be illegal.

## Layout

```
kalifuzz/
├── fuzzer_core.py       # shared scan engine (used by both CLI and GUI)
├── kalifuzz_cli.py       # CLI front-end (rich banner/colors/progress bar)
├── kalifuzz_gui.py       # Tkinter GUI front-end
├── report_generator.py   # builds the HTML report
├── wordlists/common.txt  # bundled default wordlist (~300 entries)
├── requirements.txt
├── install.sh
└── fuzzing_reports/      # created automatically; every scan's HTML report lands here
```

## Install (Kali / Debian)

```bash
chmod +x install.sh
./install.sh
```

This installs `python3-tk` (for the GUI) and the pip packages in
`requirements.txt` (`requests`, `rich`, `pyfiglet`).

Manual install, if you prefer:

```bash
sudo apt install python3-tk
pip3 install -r requirements.txt --break-system-packages
```

## CLI usage

```bash
python3 kalifuzz_cli.py -u http://target.local -w wordlists/common.txt
```

Common options:

| Flag | Meaning |
|---|---|
| `-u, --url` | Target base URL (required) |
| `-w, --wordlist` | Path to wordlist (default: bundled `wordlists/common.txt`) |
| `-x, --extensions` | Comma-separated extensions to also try, e.g. `php,html,txt,bak` |
| `-t, --threads` | Concurrent threads (default 30) |
| `-c, --status-codes` | Status codes to show (default `200,204,301,302,307,401,403,405`) |
| `--exclude-codes` | Status codes to hide |
| `-r, --recursive` | Recurse into discovered directories |
| `--max-depth` | Max recursion depth (default 2) |
| `--proxy` | Route through a proxy, e.g. `http://127.0.0.1:8080` for Burp/ZAP |
| `-k, --no-ssl-verify` | Skip TLS certificate verification |
| `--delay` | Delay between requests per thread, for rate limiting |
| `-o, --output` | Report filename (still saved under `fuzzing_reports/`) |

For bigger wordlists, Kali already ships some good ones:

```bash
python3 kalifuzz_cli.py -u http://target.local -w /usr/share/wordlists/dirb/big.txt -t 60 -x php,html,bak -r
```

Press `Ctrl+C` at any time to stop early — a report is still generated
from whatever was found so far.

## GUI usage

```bash
python3 kalifuzz_gui.py
```

Fill in the target URL and (optionally) browse to a different wordlist,
hit **Start Scan**, and watch results stream in, color-coded by status
code (green = 2xx, yellow = 3xx, magenta = 4xx, red = 5xx). When the scan
finishes, click **Open Last Report** to view the HTML report in your
browser.

## How it avoids false positives

Before fuzzing, KaliFuzz requests a random, almost-certainly-nonexistent
path and records its status code + response length. Any later response
that matches that exact signature is treated as a "soft 404" (a server
that returns 200 for everything) and filtered out automatically.

## Reports

Every scan — CLI or GUI — writes a self-contained, dark-themed HTML file
to `fuzzing_reports/report_<host>_<timestamp>.html`, with a sortable-by-eye
table of every hit (status, path, length, redirect target, recursion
depth) and a summary of status-code counts.
