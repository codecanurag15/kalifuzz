#!/usr/bin/env python3
"""
kalifuzz_gui.py
-----------------
Tkinter GUI front-end for the KaliFuzz engine. Dark "hacker terminal"
theme, live colorized results pane, progress bar, and one-click HTML
report generation/opening. Uses only the Python standard library for
the GUI itself (tkinter), so it runs anywhere kalifuzz_cli.py does.

On Debian/Kali, if tkinter isn't already installed:
    sudo apt install python3-tk

For authorized security testing / learning only.
"""

import os
import queue
import threading
import time
import webbrowser
from datetime import datetime
from tkinter import (
    Tk, Frame, Label, Entry, Button, Checkbutton, IntVar, StringVar,
    Text, END, DISABLED, NORMAL, filedialog, messagebox, ttk
)

from fuzzer_core import ScanOptions, FuzzEngine, DEFAULT_STATUS_CODES, Finding
from report_generator import generate_html_report

BG = "#0b0f0c"
PANEL = "#11170f"
GREEN = "#00ff41"
DIM = "#5c7d5c"
FG = "#d6ffd6"
FONT = ("Consolas", 10)
FONT_BOLD = ("Consolas", 11, "bold")

ASCII_BANNER = r"""
 _  __     _ _ _____
| |/ /__ _| (_)  ___|   _ ________
| ' // _` | | | |_ | | | |_  /_  /
| . \ (_| | | |  _|| |_| |/ / / /
|_|\_\__,_|_|_|_|   \__,_/___/___|
      Advanced Directory Fuzzer
"""

STATUS_TAGS = {2: "s2", 3: "s3", 4: "s4", 5: "s5"}
STATUS_COLORS = {"s2": "#39d353", "s3": "#e3c13b", "s4": "#ff7b72", "s5": "#ff4d4d"}


class KaliFuzzGUI:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("KaliFuzz -- Directory & File Enumeration")
        self.root.configure(bg=BG)
        self.root.geometry("1000x700")
        self.root.minsize(820, 560)

        self.engine = None
        self.scan_thread = None
        self.last_options = None
        self.result_queue = queue.Queue()
        self.start_time = None
        self.last_report_path = None
        self.total_candidates = 1

        self._build_layout()
        self._poll_queue()

    # ---------------- layout ----------------
    def _build_layout(self):
        Label(self.root, text=ASCII_BANNER, bg=BG, fg=GREEN,
              font=("Consolas", 10, "bold"), justify="left").pack(anchor="w", padx=12, pady=(10, 0))

        form = Frame(self.root, bg=BG)
        form.pack(fill="x", padx=12, pady=8)

        default_wordlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "common.txt")
        self.url_var = StringVar()
        self.wordlist_var = StringVar(value=default_wordlist)
        self.ext_var = StringVar()
        self.threads_var = StringVar(value="30")
        self.recursive_var = IntVar(value=0)
        self.ssl_verify_var = IntVar(value=1)

        self._field(form, "Target URL:", self.url_var, 0, width=48)
        self._field(form, "Wordlist:", self.wordlist_var, 1, width=48, browse=True)
        self._field(form, "Extensions (csv):", self.ext_var, 2, width=22)
        self._field(form, "Threads:", self.threads_var, 3, width=8)

        Checkbutton(form, text="Recursive", variable=self.recursive_var, bg=BG, fg=FG,
                    selectcolor=PANEL, activebackground=BG, activeforeground=GREEN,
                    font=FONT).grid(row=4, column=1, sticky="w", pady=4)
        Checkbutton(form, text="Verify SSL", variable=self.ssl_verify_var, bg=BG, fg=FG,
                    selectcolor=PANEL, activebackground=BG, activeforeground=GREEN,
                    font=FONT).grid(row=4, column=2, sticky="w", pady=4)

        btn_frame = Frame(self.root, bg=BG)
        btn_frame.pack(fill="x", padx=12, pady=4)
        self.start_btn = Button(btn_frame, text="\u25b6 Start Scan", command=self.start_scan,
                                 bg=GREEN, fg="#001a00", font=FONT_BOLD, relief="flat", padx=14, pady=4)
        self.start_btn.pack(side="left")
        self.stop_btn = Button(btn_frame, text="\u25a0 Stop", command=self.stop_scan,
                                bg="#3a0d0d", fg="#ff7b72", font=FONT_BOLD, relief="flat",
                                padx=14, pady=4, state=DISABLED)
        self.stop_btn.pack(side="left", padx=8)
        self.report_btn = Button(btn_frame, text="\u21aa Open Last Report", command=self.open_report,
                                  bg=PANEL, fg=GREEN, font=FONT, relief="flat", padx=10, pady=4,
                                  state=DISABLED)
        self.report_btn.pack(side="left", padx=8)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Kali.Horizontal.TProgressbar", troughcolor=PANEL, background=GREEN,
                         bordercolor=BG, lightcolor=GREEN, darkcolor=GREEN)
        self.progress = ttk.Progressbar(self.root, mode="determinate", length=960,
                                         style="Kali.Horizontal.TProgressbar")
        self.progress.pack(padx=12, pady=(6, 0), fill="x")

        self.stats_var = StringVar(value="Idle.")
        Label(self.root, textvariable=self.stats_var, bg=BG, fg=DIM, font=FONT, anchor="w").pack(
            fill="x", padx=12, pady=(2, 6))

        self.output = Text(self.root, bg="#07090a", fg=FG, insertbackground=GREEN,
                            font=FONT, relief="flat", wrap="none")
        self.output.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        for tag, color in STATUS_COLORS.items():
            self.output.tag_configure(tag, foreground=color, font=FONT_BOLD)
        self.output.tag_configure("dim", foreground=DIM)
        self.output.configure(state=DISABLED)

    def _field(self, parent, label, var, row, width=30, browse=False):
        Label(parent, text=label, bg=BG, fg=FG, font=FONT, anchor="w", width=16).grid(
            row=row, column=0, sticky="w", pady=2)
        entry = Entry(parent, textvariable=var, width=width, bg=PANEL, fg=FG,
                       insertbackground=GREEN, font=FONT, relief="flat")
        entry.grid(row=row, column=1, sticky="w", pady=2)
        if browse:
            Button(parent, text="Browse", command=lambda: self._browse(var), bg=PANEL, fg=GREEN,
                   font=FONT, relief="flat", padx=8).grid(row=row, column=2, padx=6)
        return entry

    def _browse(self, var):
        path = filedialog.askopenfilename(title="Select wordlist")
        if path:
            var.set(path)

    # ---------------- logging ----------------
    def _log(self, text, tag=None):
        self.output.configure(state=NORMAL)
        self.output.insert(END, text + "\n", tag)
        self.output.see(END)
        self.output.configure(state=DISABLED)

    # ---------------- scan control ----------------
    def start_scan(self):
        url = self.url_var.get().strip()
        wordlist = self.wordlist_var.get().strip()
        if not url:
            messagebox.showerror("KaliFuzz", "Please enter a target URL.")
            return
        if not os.path.isfile(wordlist):
            messagebox.showerror("KaliFuzz", f"Wordlist not found:\n{wordlist}")
            return
        try:
            threads = max(1, int(self.threads_var.get()))
        except ValueError:
            threads = 30

        extensions = [e.strip() for e in self.ext_var.get().split(",") if e.strip()]

        options = ScanOptions(
            target=url,
            wordlist_path=wordlist,
            extensions=extensions,
            threads=threads,
            status_codes=set(DEFAULT_STATUS_CODES),
            recursive=bool(self.recursive_var.get()),
            verify_ssl=bool(self.ssl_verify_var.get()),
        )

        self.output.configure(state=NORMAL)
        self.output.delete("1.0", END)
        self.output.configure(state=DISABLED)
        self._log(f"[*] Target: {url}", "dim")
        self._log(f"[*] Wordlist: {wordlist}", "dim")
        self._log(f"[*] Threads: {threads}  Extensions: {extensions or 'none'}", "dim")

        self.engine = FuzzEngine(
            options,
            on_result=lambda f: self.result_queue.put(("result", f)),
            on_progress=lambda d, t: self.result_queue.put(("progress", (d, t))),
            on_log=lambda m: self.result_queue.put(("log", m)),
        )
        self.start_time = time.time()
        self.total_candidates = 1
        self.start_btn.configure(state=DISABLED)
        self.stop_btn.configure(state=NORMAL)
        self.report_btn.configure(state=DISABLED)
        self.last_options = options

        self.scan_thread = threading.Thread(target=self._run_engine, daemon=True)
        self.scan_thread.start()

    def _run_engine(self):
        try:
            self.engine.run()
        except RuntimeError as exc:
            self.result_queue.put(("error", str(exc)))
        self.result_queue.put(("done", None))

    def stop_scan(self):
        if self.engine:
            self.engine.stop()
            self._log("[!] Stopping...", "s3")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.result_queue.get_nowait()
                if kind == "result":
                    f: Finding = payload
                    tag = STATUS_TAGS.get(f.status_code // 100)
                    line = f"{f.status_code}  {f.path:<45} ({f.content_length} bytes)"
                    if f.redirect_location:
                        line += f"  -> {f.redirect_location}"
                    self._log(line, tag)
                elif kind == "progress":
                    done, total = payload
                    self.total_candidates = max(total, 1)
                    self.progress["maximum"] = self.total_candidates
                    self.progress["value"] = done
                    elapsed = time.time() - self.start_time
                    found = len(self.engine.findings) if self.engine else 0
                    self.stats_var.set(f"{done}/{total} requests | {found} found | {elapsed:.1f}s elapsed")
                elif kind == "log":
                    self._log(f"[*] {payload}", "dim")
                elif kind == "error":
                    messagebox.showerror("KaliFuzz", payload)
                elif kind == "done":
                    self._finish_scan()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _finish_scan(self):
        self.start_btn.configure(state=NORMAL)
        self.stop_btn.configure(state=DISABLED)
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        findings = self.engine.findings if self.engine else []
        self._log(f"\n[+] Scan complete: {len(findings)} paths found in {elapsed:.2f}s", "s2")

        report_dir = os.path.join(os.getcwd(), "fuzzing_reports")
        os.makedirs(report_dir, exist_ok=True)
        host = self.last_options.target.replace("https://", "").replace("http://", "").strip("/").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"report_{host}_{ts}.html")
        generate_html_report(
            report_path,
            target=self.last_options.target,
            findings=findings,
            wordlist=self.last_options.wordlist_path,
            threads=self.last_options.threads,
            elapsed=elapsed,
            total_requests=self.total_candidates,
            extensions=self.last_options.extensions,
        )
        self.last_report_path = report_path
        self.report_btn.configure(state=NORMAL)
        self._log(f"[+] HTML report saved -> {report_path}", "s2")

    def open_report(self):
        if self.last_report_path and os.path.isfile(self.last_report_path):
            webbrowser.open(f"file://{self.last_report_path}")


def main():
    root = Tk()
    KaliFuzzGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
