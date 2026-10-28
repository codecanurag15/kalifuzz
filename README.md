<div align="center">

```
 _  __     _ _ _____             
| |/ /__ _| (_)  ___|   _ ________
| ' // _` | | | |_ | | | |_  /_  /
| . \ (_| | | |  _|| |_| |/ / / / 
|_|\_\__,_|_|_|_|   \__,_/___/___|
        Advanced Directory & File Enumeration Tool
```

### ⚡ CLI + GUI directory/file fuzzer for Kali Linux — in the spirit of `gobuster`, `dirb`, and `ffuf`

![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Python](https://img.shields.io/badge/python-3.8+-00ff41?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-brightgreen?style=for-the-badge)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)

</div>

---

## 📖 Table of Contents

- [What is KaliFuzz?](#-what-is-kalifuzz)
- [Features](#-features)
- [Demo](#-demo)
- [Project Layout](#-project-layout)
- [Installation](#-installation)
- [CLI Usage](#-cli-usage)
- [GUI Usage](#-gui-usage)
- [How Wildcard Filtering Works](#-how-wildcard-filtering-works)
- [HTML Reports](#-html-reports)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## 🕵️ What is KaliFuzz?

**KaliFuzz** is a multithreaded directory and file enumeration tool for web
application reconnaissance. Point it at a target and a wordlist, and it
brute-forces hidden paths — admin panels, backup files, forgotten API
routes, exposed configs — the same way `gobuster`/`dirb`/`ffuf` do, but with
a **colorized terminal UI, a live progress bar, a Tkinter GUI, and
auto-generated HTML reports** on top of a single shared scanning engine.

---

## ✨ Features

| | |
|---|---|
| 🎨 | Colorized banner + live, color-coded hits (green = 2xx, yellow = 3xx, magenta = 4xx, red = 5xx) |
| 🖥️ | Full Tkinter **GUI** alongside the CLI — same engine, same results |
| ⚙️ | Multithreaded scanning with configurable thread count |
| 🧩 | Extension bruteforcing (`-x php,html,bak,txt`) |
| 🧠 | Automatic **wildcard / soft-404 filtering** — no false-positive spam |
| 🔁 | Optional **recursive** fuzzing into discovered directories |
| 🌐 | Proxy support for routing through Burp Suite / ZAP |
| 📊 | Live progress bar + requests/sec, elapsed time, found count |
| 📄 | Self-contained, dark-themed **HTML report** auto-saved per scan |
| 🧰 | Works with Kali's built-in wordlists (`dirb`, `SecLists`, etc.) |

---

## 🎬 Demo

```
$ python3 kalifuzz_cli.py -u http://target.local -x php,bak -t 50 -r

  _  __     _ _ _____
 | |/ /__ _| (_)  ___|   _ ________
 | ' // _` | | | |_ | | | |_  /_  /
 | . \ (_| | | |  _|| |_| |/ / / /
 |_|\_\__,_|_|_|_|   \__,_/___/___|

  Advanced Directory & File Enumeration Tool for Kali Linux
  In the spirit of gobuster / dirb / ffuf
─────────────────────────────────────────────────────────────
Target     : http://target.local
Wordlist   : wordlists/common.txt
Threads    : 50
Extensions : php, bak
Recursive  : yes (max depth 2)
─────────────────────────────────────────────────────────────
⠋ Fuzzing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 812/1024  00:03
200  /admin.php                             (1842 bytes)
301  /backup                                (0 bytes)      -> /backup/
403  /config.php.bak                        (278 bytes)
200  /api                                   (512 bytes)
─────────────────────────────────────────────────────────────
                    Scan Summary
┌────────────────┬──────────────────────────┐
│ Target          │ http://target.local      │
│ Paths found     │ 4                        │
│ Requests sent   │ 1024                     │
│ Elapsed time    │ 6.21s                    │
│ Requests / sec  │ 164.9                    │
└────────────────┴──────────────────────────┘

HTML report saved -> fuzzing_reports/report_target.local_20261029_142201.html
```

---

## 📂 Project Layout

```
kalifuzz/
├── fuzzer_core.py        # shared scan engine (used by both CLI and GUI)
├── kalifuzz_cli.py        # CLI front-end — banner, colors, progress bar
├── kalifuzz_gui.py        # Tkinter GUI front-end
├── report_generator.py    # builds the dark-themed HTML report
├── wordlists/
│   └── common.txt         # bundled default wordlist (~300 entries)
├── fuzzing_reports/        # every scan's HTML report lands here
├── requirements.txt
├── install.sh
└── README.md
```

---

## 🛠️ Installation

### Quick install (Kali / Debian)

```bash
chmod +x install.sh
./install.sh
```

This installs `python3-tk` (for the GUI) plus the Python dependencies
(`requests`, `rich`, `pyfiglet`).

### Manual install

```bash
sudo apt install python3-tk
pip3 install -r requirements.txt --break-system-packages
```

---

## 💻 CLI Usage

```bash
python3 kalifuzz_cli.py -u http://target.local -w wordlists/common.txt
```

| Flag | Description |
|---|---|
| `-u, --url` | Target base URL **(required)** |
| `-w, --wordlist` | Path to wordlist (default: bundled `wordlists/common.txt`) |
| `-x, --extensions` | Comma-separated extensions to also try, e.g. `php,html,txt,bak` |
| `-t, --threads` | Concurrent threads (default `30`) |
| `-c, --status-codes` | Status codes to show (default `200,204,301,302,307,401,403,405`) |
| `--exclude-codes` | Status codes to hide |
| `-r, --recursive` | Recurse into discovered directories |
| `--max-depth` | Max recursion depth (default `2`) |
| `--proxy` | Route through a proxy, e.g. `http://127.0.0.1:8080` for Burp/ZAP |
| `-k, --no-ssl-verify` | Skip TLS certificate verification |
| `--delay` | Delay between requests per thread, for rate limiting |
| `-o, --output` | Report filename (still saved under `fuzzing_reports/`) |
| `--no-banner` | Suppress the startup banner |

**Bigger wordlists** ship with Kali already:

```bash
python3 kalifuzz_cli.py -u http://target.local \
  -w /usr/share/wordlists/dirb/big.txt -t 60 -x php,html,bak -r
```

Press `Ctrl+C` any time to stop early — a report is still generated from
whatever was found so far.

---

## 🖥️ GUI Usage

```bash
python3 kalifuzz_gui.py
```

1. Enter the **target URL**, or **Browse** to a different wordlist
2. Toggle **Recursive** / **Verify SSL** as needed
3. Hit **▶ Start Scan** and watch hits stream in, color-coded live
4. Click **⤴ Open Last Report** when it's done

---

## 🧠 How Wildcard Filtering Works

Before fuzzing starts, KaliFuzz requests a random, near-certainly-nonexistent
path and records its status code + response length as a baseline. Any later
response matching that exact signature is recognized as a **soft-404** (a
server that returns `200` for everything instead of a real `404`) and is
automatically filtered out — so you only see genuine hits.

---

## 📄 HTML Reports

Every scan — CLI or GUI — writes a self-contained, dark-themed HTML file to:

```
fuzzing_reports/report_<host>_<timestamp>.html
```

Each report includes a full results table (status, path, content length,
redirect target, recursion depth) and a summary of status-code counts.

---

## ⚠️ Disclaimer

KaliFuzz is built for **authorized security testing and learning only**.
Only scan systems you **own** or have **explicit written permission** to
test. Unauthorized scanning of systems you don't control may be illegal in
your jurisdiction.

---

## 📜 License

MIT — use it, learn from it, extend it. Attribution appreciated.

<div align="center">

**Built by Anurag**

</div>
