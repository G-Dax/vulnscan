#!/usr/bin/env python3
"""
Guardian UI - desktop interface for guardian.py (tkinter, no extra installs).
Keep this file in the same folder as guardian.py, then run:  python guardian_ui.py
Optional: pip install psutil   (lets "Computer check" see every running program)
"""
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk, font as tkfont

import guardian as g

# ---- palette -------------------------------------------------------------
NAVY, NAVY_HI = "#14213D", "#25386A"
PAPER, WHITE = "#EEF2F6", "#FFFFFF"
INK, MUTED, LINE = "#1B2433", "#66748A", "#D5DCE6"
BLUE, RED, TEAL = "#2F6FED", "#D64545", "#1F9D8B"
ROW_HIGH, ROW_MID = "#FBE4E4", "#FFF3D6"


def pick_font(root):
    have = set(tkfont.families(root))
    for name in ("Segoe UI", "SF Pro Text", "Helvetica Neue", "Noto Sans", "DejaVu Sans"):
        if name in have:
            return name
    return "TkDefaultFont"


def reveal(path):
    """Show a file in the system file manager."""
    try:
        if sys.platform.startswith("win"):
            subprocess.Popen(["explorer", f"/select,{path}"])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(Path(path).parent)])
    except OSError:
        pass


def computer_advice(score):
    if score >= 70:
        return ("Treat this as dangerous. Close the program and remove it from startup. Then scan its "
                "folder with Scan files and quarantine the file.")
    if score >= 40:
        return ("Check whether you installed or recognize this. If you do not, close it, remove it "
                "from startup and scan its folder.")
    return "No action needed."


class Findings:
    """Sortable results table with a plain-language 'what we found / what to do' panel."""

    def __init__(self, app, parent, columns, hint, advice=g.advice):
        self.app, self.columns, self.hint, self.advice = app, columns, hint, advice
        self.rows, self.seq = {}, 0

        self.detail = tk.Label(parent, text=hint, font=app.f(10), bg=WHITE, fg=MUTED, anchor="w",
                               justify="left", padx=14, pady=10, highlightthickness=1,
                               highlightbackground=LINE)
        self.detail.pack(side="bottom", fill="x", pady=(8, 0))
        self.detail.bind("<Configure>", lambda e: self.detail.configure(wraplength=max(200, e.width - 30)))

        box = tk.Frame(parent, bg=LINE, padx=1, pady=1)
        box.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(box, columns=[c[0] for c in columns], show="headings",
                                 selectmode="extended")
        for key, title, width in columns:
            self.tree.heading(key, text=title, anchor="w",
                              command=lambda k=key: self.sort(k, False))
            self.tree.column(key, width=width, anchor="w")
        self.tree.tag_configure("high", background=ROW_HIGH)
        self.tree.tag_configure("mid", background=ROW_MID)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        self.tree.bind("<Double-1>", self.on_double_click)

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.show_detail()

    def add(self, score, values, path="", reasons=(), note=""):
        self.seq += 1
        iid = f"r{self.seq}"
        self.rows[iid] = {"score": score, "values": values, "path": path,
                          "reasons": list(reasons), "note": note}
        cells = [f"{g.verdict(score)} ({score})"] + [values.get(k, "") for k, _t, _w in self.columns[1:]]
        self.tree.insert("", "end", iid=iid, values=cells, tags=("high" if score >= 70 else "mid",))

    def sort(self, col, reverse):
        def key(iid):
            r = self.rows[iid]
            return r["score"] if col == "risk" else str(r["values"].get(col, "")).lower()
        for i, iid in enumerate(sorted(self.tree.get_children(), key=key, reverse=reverse)):
            self.tree.move(iid, "", i)
        self.tree.heading(col, command=lambda: self.sort(col, not reverse))

    def selection_ids(self):
        return [i for i in self.tree.selection() if i in self.rows]

    def selected(self):
        return [self.rows[i] for i in self.selection_ids()]

    def remove(self, iid):
        self.tree.delete(iid)
        self.rows.pop(iid, None)

    def show_detail(self, _event=None):
        sel = self.selection_ids()
        if not sel:
            text, color = self.hint, MUTED
        elif len(sel) > 1:
            text, color = f"{len(sel)} items selected.", INK
        else:
            r = self.rows[sel[0]]
            title = r["path"] or r["values"].get("item", "")
            lines = [title] + [f"\u2022 {x}" for x in r["reasons"]]
            if r["note"]:
                lines.append(f"Command: {r['note']}")
            lines.append("")
            lines.append(f"What to do: {self.advice(r['score'])}")
            text, color = "\n".join(lines), INK
        self.detail.configure(text=text, fg=color)

    def on_double_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid in self.rows and self.rows[iid]["path"]:
            reveal(self.rows[iid]["path"])


class App:
    def __init__(self, root):
        self.root = root
        root.title("Guardian")
        root.geometry("1040x700")
        root.minsize(860, 600)
        root.configure(bg=PAPER)

        self.cfg = g.load_config()
        self.family = pick_font(root)
        self.q = queue.Queue()

        self.scanning = False
        self.scan_stop = threading.Event()
        self.scan_error = None
        self.checking = False
        self.watching = False
        self.watch_stop = threading.Event()
        self.watch_thread = None
        self.download_thread = None
        self.protection_workers = 0
        self.alert_reset = None
        self.qitems = []
        self.bad_hashes = set()

        home = Path.home()
        self.scan_path = tk.StringVar(value=self.cfg.get("scan_path", str(home / "Downloads")))
        self.scan_mode = tk.StringVar(value=self.cfg.get("scan_mode", "deep"))
        self.watch_path = tk.StringVar(value=self.cfg.get("watch_path", str(home / "Downloads")))
        self.threshold = tk.IntVar(value=self.cfg.get("threshold", 10))
        self.hash_label = tk.StringVar(value="No blocklist loaded")

        self.styles()
        self.layout()
        self.show("scan")
        bl = self.cfg.get("blocklist")
        if bl and os.path.isfile(bl):
            self.load_hashes(bl, quiet=True)
        root.after(100, self.poll)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------------------------------------------------ styling
    def f(self, size=10, weight="normal"):
        return (self.family, size, weight)

    def styles(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure("Treeview", font=self.f(10), rowheight=30, background=WHITE,
                    fieldbackground=WHITE, foreground=INK, borderwidth=0)
        s.configure("Treeview.Heading", font=self.f(10, "bold"), background=PAPER,
                    foreground=MUTED, relief="flat", padding=(8, 6))
        s.map("Treeview", background=[("selected", BLUE)], foreground=[("selected", WHITE)])
        s.configure("Bar.Horizontal.TProgressbar", troughcolor=LINE, background=BLUE,
                    borderwidth=0, thickness=6)
        s.configure("TEntry", padding=6, fieldbackground=WHITE)
        s.configure("TRadiobutton", background=PAPER, foreground=INK, font=self.f(10, "bold"))
        s.map("TRadiobutton", background=[("active", PAPER)])
        for name, bg, fg, hi in (("Primary", BLUE, WHITE, "#1F58C9"),
                                 ("Plain", WHITE, INK, "#E4EAF2"),
                                 ("Danger", RED, WHITE, "#B53434")):
            s.configure(f"{name}.TButton", font=self.f(10, "bold"), background=bg,
                        foreground=fg, padding=(14, 8), borderwidth=1, bordercolor=LINE,
                        focuscolor=bg)
            s.map(f"{name}.TButton", background=[("active", hi), ("disabled", LINE)],
                  foreground=[("disabled", MUTED)])

    def btn(self, parent, text, cmd, kind="Plain"):
        return ttk.Button(parent, text=text, command=cmd, style=f"{kind}.TButton")

    def link(self, parent, text, cmd):
        lb = tk.Label(parent, text=text, font=self.f(9, "bold"), bg=PAPER, fg=BLUE, cursor="hand2")
        lb.bind("<Button-1>", lambda e: cmd())
        return lb

    def header(self, parent, title, sub):
        tk.Label(parent, text=title, font=self.f(20, "bold"), bg=PAPER, fg=INK,
                 anchor="w").pack(fill="x")
        s = tk.Label(parent, text=sub, font=self.f(10), bg=PAPER, fg=MUTED, anchor="w",
                     justify="left")
        s.pack(fill="x", pady=(2, 0))
        s.bind("<Configure>", lambda e: s.configure(wraplength=max(200, e.width - 4)))

    def quick_picks(self, parent, var):
        row = tk.Frame(parent, bg=PAPER)
        tk.Label(row, text="Quick pick:", font=self.f(9), bg=PAPER, fg=MUTED).pack(side="left")
        for name in ("Downloads", "Documents", "Desktop"):
            p = Path.home() / name
            if p.is_dir():
                self.link(row, name, lambda p=p: var.set(str(p))).pack(side="left", padx=(10, 0))
        return row

    # ------------------------------------------------------------ layout
    def layout(self):
        side = tk.Frame(self.root, bg=NAVY, width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="Guardian", font=self.f(18, "bold"), bg=NAVY, fg=WHITE,
                 anchor="w").pack(fill="x", padx=22, pady=(26, 24))

        self.nav, self.views = {}, {}
        for key, label in (("scan", "Scan files"), ("comp", "Computer check"),
                           ("live", "Live protection"), ("quar", "Quarantine")):
            b = tk.Label(side, text=label, font=self.f(11), bg=NAVY, fg="#C9D3E6",
                         anchor="w", padx=22, pady=11, cursor="hand2")
            b.pack(fill="x")
            b.bind("<Button-1>", lambda e, k=key: self.show(k))
            self.nav[key] = b

        host = tk.Frame(self.root, bg=PAPER)
        host.pack(side="right", fill="both", expand=True)
        host.grid_rowconfigure(0, weight=1)
        host.grid_columnconfigure(0, weight=1)
        for key, build in (("scan", self.build_scan), ("comp", self.build_comp),
                           ("live", self.build_live), ("quar", self.build_quar)):
            frame = tk.Frame(host, bg=PAPER)
            frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=26)
            build(frame)
            self.views[key] = frame

    def show(self, key):
        self.views[key].tkraise()
        for k, b in self.nav.items():
            b.configure(bg=NAVY_HI if k == key else NAVY, fg=WHITE if k == key else "#C9D3E6")
        if key == "quar":
            self.refresh_quarantine()

    # ------------------------------------------------------------ scan view
    def build_scan(self, f):
        self.header(f, "Scan files",
                    "Check a folder for viruses, disguised programs and ransomware traces.")
        row = tk.Frame(f, bg=PAPER)
        row.pack(fill="x", pady=(14, 4))
        ttk.Entry(row, textvariable=self.scan_path).pack(side="left", fill="x", expand=True)
        self.btn(row, "Choose folder", self.pick_scan_dir).pack(side="left", padx=(8, 0))
        self.quick_picks(f, self.scan_path).pack(fill="x", pady=(0, 8))

        for value, title, text in (
                ("deep", "Deep scan (recommended)",
                 "Slower. Also looks inside zip files, Word and Excel files, PDFs, scripts and programs."),
                ("quick", "Quick scan",
                 "Fast. Checks file names, file types and known threats.")):
            r = tk.Frame(f, bg=PAPER)
            r.pack(fill="x")
            ttk.Radiobutton(r, text=title, value=value, variable=self.scan_mode).pack(side="left")
            tk.Label(r, text=text, font=self.f(9), bg=PAPER, fg=MUTED).pack(side="left", padx=(10, 0))

        row2 = tk.Frame(f, bg=PAPER)
        row2.pack(fill="x", pady=(8, 10))
        tk.Label(row2, textvariable=self.hash_label, font=self.f(9), bg=PAPER,
                 fg=MUTED).pack(side="left")
        self.link(row2, "Load a blocklist (optional)", self.pick_hashes).pack(side="right")

        self.scan_btn = self.btn(f, "Start scan", self.toggle_scan, "Primary")
        self.scan_btn.pack(anchor="w")
        self.bar = ttk.Progressbar(f, style="Bar.Horizontal.TProgressbar", mode="determinate")
        self.bar.pack(fill="x", pady=(12, 4))
        self.scan_status = tk.Label(f, text="Ready. Choose a folder and press Start scan.",
                                    font=self.f(10), bg=PAPER, fg=MUTED, anchor="w")
        self.scan_status.pack(fill="x", pady=(0, 8))

        bottom = tk.Frame(f, bg=PAPER)
        bottom.pack(side="bottom", fill="x", pady=(10, 0))
        self.btn(bottom, "Show in folder", lambda: self.show_in_folder(self.scan_f)).pack(side="left")
        self.btn(bottom, "Export report", self.export_report).pack(side="left", padx=(8, 0))
        self.btn(bottom, "Move selected to quarantine", self.quarantine_selected,
                 "Danger").pack(side="right")

        self.scan_f = Findings(self, f, [("risk", "Verdict", 130), ("file", "File", 300),
                                         ("why", "What we found", 340)],
                               "Select a result to see what was found and what to do.")

    def pick_scan_dir(self):
        d = filedialog.askdirectory(title="Choose a folder to scan")
        if d:
            self.scan_path.set(d)

    def pick_hashes(self):
        p = filedialog.askopenfilename(title="Choose a blocklist of SHA-256 hashes")
        if p:
            self.load_hashes(p)

    def load_hashes(self, path, quiet=False):
        try:
            self.bad_hashes = g.load_blocklist(path)
        except OSError as e:
            if not quiet:
                messagebox.showerror("Guardian", f"Could not read the blocklist.\n{e}")
            return
        self.cfg["blocklist"] = path
        self.hash_label.set(f"Blocklist: {len(self.bad_hashes):,} hashes from {Path(path).name}")

    def show_in_folder(self, findings):
        for r in findings.selected():
            if r["path"]:
                reveal(r["path"])
                return

    def toggle_scan(self):
        if self.scanning:
            if not self.scan_stop.is_set():
                self.scan_stop.set()
                self.scan_status.configure(text="Stopping...", fg=MUTED)
            return
        path = self.scan_path.get().strip()
        if not os.path.exists(path):
            messagebox.showinfo("Guardian", "Choose a folder to scan first.")
            return
        self.scan_f.clear()
        self.bar.configure(value=0, maximum=1)
        self.scan_btn.configure(text="Stop scan")
        self.scan_status.configure(text="Collecting files...", fg=MUTED)
        self.scanning, self.scan_error = True, None
        self.scan_stop = threading.Event()
        threading.Thread(target=self.scan_worker,
                         args=(path, set(self.bad_hashes), self.scan_mode.get() == "deep",
                               self.scan_stop), daemon=True).start()

    def scan_worker(self, path, bad, deep, stop):
        start = time.time()
        done = flagged = skipped = 0
        try:
            files = []
            for p in g.iter_files(path):
                if stop.is_set():
                    break
                files.append(p)
                if len(files) % 500 == 0:
                    self.q.put(("collecting", len(files)))
            total = len(files)
            for p in files:
                if stop.is_set():
                    break
                done += 1
                try:
                    score, why = g.analyze(p, bad, deep=deep)
                except OSError:
                    skipped += 1
                    continue
                if score >= 40:
                    flagged += 1
                    self.q.put(("hit", score, str(p), why))
                if deep or done % 10 == 0 or done == total:
                    self.q.put(("progress", done, total, p.name))
        except Exception as e:  # never leave the interface stuck in "scanning"
            self.q.put(("scan_error", str(e)))
        finally:
            self.q.put(("scan_done", done, flagged, skipped, stop.is_set(), time.time() - start))

    def export_report(self):
        rows = self.scan_f.rows
        if not rows:
            messagebox.showinfo("Guardian", "There are no results to export yet.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="guardian-report.csv",
                                         filetypes=[("CSV file", "*.csv")])
        if not p:
            return
        data = sorted(((r["score"], r["path"], "; ".join(r["reasons"])) for r in rows.values()),
                      reverse=True)
        try:
            g.write_report(data, p)
            self.scan_status.configure(text=f"Report saved to {p}", fg=TEAL)
        except OSError as e:
            messagebox.showerror("Guardian", f"Could not save the report.\n{e}")

    def quarantine_selected(self):
        ids = self.scan_f.selection_ids()
        if not ids:
            messagebox.showinfo("Guardian", "Select one or more files in the results first.")
            return
        if not messagebox.askyesno("Guardian", f"Move {len(ids)} file(s) to quarantine?"):
            return
        failed = []
        for iid in ids:
            r = self.scan_f.rows[iid]
            try:
                g.quarantine(r["path"], r["score"], r["reasons"])
                self.scan_f.remove(iid)
            except OSError as e:
                failed.append(f"{Path(r['path']).name}: {e}")
        if failed:
            messagebox.showerror("Guardian", "Some files could not be moved:\n" + "\n".join(failed))

    # ------------------------------------------------------------ computer check view
    def build_comp(self, f):
        self.header(f, "Computer check",
                    "Finds programs that start by themselves and programs running right now, "
                    "and flags the ones that look unsafe.")
        self.comp_btn = self.btn(f, "Check my computer", self.start_comp, "Primary")
        self.comp_btn.pack(anchor="w", pady=(16, 8))
        self.comp_status = tk.Label(f, text="Ready. This usually takes under a minute.",
                                    font=self.f(10), bg=PAPER, fg=MUTED, anchor="w")
        self.comp_status.pack(fill="x", pady=(0, 8))
        bottom = tk.Frame(f, bg=PAPER)
        bottom.pack(side="bottom", fill="x", pady=(10, 0))
        self.btn(bottom, "Show in folder", lambda: self.show_in_folder(self.comp_f)).pack(side="left")
        self.comp_f = Findings(self, f, [("risk", "Verdict", 130), ("kind", "Type", 160),
                                         ("item", "Item", 230), ("why", "What we found", 280)],
                               "Select a result to see what was found and what to do.",
                               advice=computer_advice)

    def start_comp(self):
        if self.checking:
            return
        self.checking = True
        self.comp_f.clear()
        self.comp_btn.state(["disabled"])
        self.comp_status.configure(text="Starting...", fg=MUTED)
        threading.Thread(target=self.comp_worker, args=(set(self.bad_hashes),), daemon=True).start()

    def comp_worker(self, bad):
        startup = running = 0
        note, err = "", None
        try:
            self.q.put(("comp_status", "Checking programs that start automatically..."))
            rows = g.check_persistence(bad)
            startup = len(rows)
            for r in rows:
                if r["score"] >= 40:
                    self.q.put(("comp_hit", r["score"], r["where"], r["name"], r["path"],
                                r["reasons"], r["command"]))
            self.q.put(("comp_status", "Checking programs running right now..."))
            procs, running, note = g.check_processes(bad)
            for r in procs:
                if r["score"] >= 40:
                    self.q.put(("comp_hit", r["score"], "Running now",
                                f"{r['name']} (PID {r['pids'][0]})", r["path"], r["reasons"], ""))
        except Exception as e:
            err = str(e)
        finally:
            self.q.put(("comp_done", startup, running, note, err))

    # ------------------------------------------------------------ live view
    def build_live(self, f):
        self.header(f, "Live protection",
                    "Scans completed downloads for suspicious files and watches for ransomware-like "
                    "changes. Choose your browser’s download folder below.")
        row = tk.Frame(f, bg=PAPER)
        row.pack(fill="x", pady=(16, 4))
        ttk.Entry(row, textvariable=self.watch_path).pack(side="left", fill="x", expand=True)
        self.btn(row, "Choose download folder", self.pick_watch_dir).pack(side="left", padx=(8, 0))
        self.quick_picks(f, self.watch_path).pack(fill="x", pady=(0, 6))

        opt = tk.Frame(f, bg=PAPER)
        opt.pack(fill="x", pady=(0, 14))
        tk.Label(opt, text="Also alert when this many files are rewritten within 10 seconds:",
                 font=self.f(10), bg=PAPER, fg=MUTED).pack(side="left")
        tk.Spinbox(opt, from_=3, to=100, width=4, textvariable=self.threshold,
                   font=self.f(10), relief="flat", highlightthickness=1,
                   highlightbackground=LINE).pack(side="left", padx=8)

        card = tk.Frame(f, bg=WHITE, highlightthickness=1, highlightbackground=LINE)
        card.pack(fill="x")
        self.dot = tk.Label(card, text="\u25CF", font=self.f(26), bg=WHITE, fg=MUTED)
        self.dot.pack(side="left", padx=(20, 12), pady=16)
        text = tk.Frame(card, bg=WHITE)
        text.pack(side="left", pady=16)
        self.live_title = tk.Label(text, text="Protection is off", font=self.f(14, "bold"),
                                   bg=WHITE, fg=INK, anchor="w")
        self.live_title.pack(fill="x")
        self.live_sub = tk.Label(text, text="Choose a folder, then turn protection on.",
                                 font=self.f(10), bg=WHITE, fg=MUTED, anchor="w",
                                 justify="left", wraplength=480)
        self.live_sub.pack(fill="x")
        self.live_btn = self.btn(card, "Turn on", self.toggle_watch, "Primary")
        self.live_btn.pack(side="right", padx=20)

        tk.Label(f, text="Activity", font=self.f(11, "bold"), bg=PAPER, fg=INK,
                 anchor="w").pack(fill="x", pady=(18, 6))
        box = tk.Frame(f, bg=LINE, padx=1, pady=1)
        box.pack(fill="both", expand=True)
        self.log = tk.Text(box, font=self.f(10), bg=WHITE, fg=INK, relief="flat", wrap="word",
                           padx=12, pady=10, state="disabled", height=8)
        self.log.tag_configure("info", foreground=MUTED)
        self.log.tag_configure("alert", foreground=RED, font=self.f(10, "bold"))
        self.log.pack(fill="both", expand=True)
        tk.Label(f, text="Guardian is an experimental, signature and heuristic based scanner. It can miss threats and flag safe files; keep your operating system’s security protection enabled.",
                 font=self.f(9), bg=PAPER, fg=MUTED, anchor="w", justify="left",
                 wraplength=680).pack(fill="x", pady=(8, 0))

    def pick_watch_dir(self):
        d = filedialog.askdirectory(title="Choose a folder to protect")
        if d:
            self.watch_path.set(d)

    def safe_threshold(self):
        try:
            return max(3, min(100, int(self.threshold.get())))
        except (tk.TclError, ValueError):
            return 10

    def set_live(self, state):
        colors = {"off": MUTED, "on": TEAL, "alert": RED}
        titles = {"off": "Protection is off", "on": "Protection is on",
                  "alert": "Possible ransomware activity"}
        subs = {"off": "Choose a folder, then turn protection on.",
                "on": f"Watching {self.watch_path.get()}",
                "alert": "Disconnect from the network and close unknown programs. "
                         "Check the activity log for the affected files."}
        self.dot.configure(fg=colors[state])
        self.live_title.configure(text=titles[state])
        self.live_sub.configure(text=subs[state])

    def write_log(self, kind, msg):
        self.log.configure(state="normal")
        self.log.insert("end", f"{time.strftime('%H:%M:%S')}  {msg}\n", kind)
        self.log.see("end")
        self.log.configure(state="disabled")

    def toggle_watch(self):
        if self.watching:  # turn off; the worker confirms with "watch_stopped"
            self.watch_stop.set()
            self.live_btn.configure(text="Turning off...")
            self.live_btn.state(["disabled"])
            return
        path = self.watch_path.get().strip()
        if not os.path.isdir(path):
            messagebox.showinfo("Guardian", "Choose a folder to protect first.")
            return
        self.watching = True
        self.watch_stop = threading.Event()
        self.live_btn.configure(text="Turn off")
        self.set_live("on")
        self.protection_workers = 2
        self.watch_thread = threading.Thread(
            target=self.watch_worker, args=(path, self.watch_stop, self.safe_threshold()),
            daemon=True)
        self.watch_thread.start()
        self.download_thread = threading.Thread(
            target=self.download_worker, args=(path, self.watch_stop), daemon=True)
        self.download_thread.start()

    def watch_worker(self, folder, stop, threshold):
        def notify(kind, msg):
            self.q.put(("alert", msg) if kind == "alert" else ("log", "info", msg))
        try:
            g.RansomwareMonitor(folder, threshold, 10, notify).run(stop)
        except Exception as e:
            self.q.put(("alert", f"Protection stopped unexpectedly: {e}"))
        finally:
            self.q.put(("protection_worker_stopped",))

    def download_worker(self, folder, stop):
        def result(path, score, reasons, action, quarantined_to):
            self.q.put(("download_result", path, score, reasons, action, quarantined_to))
        def notify(kind, msg):
            self.q.put(("alert", msg) if kind == "alert" else ("log", "info", msg))
        try:
            g.DownloadGuard([folder], bad_hashes=set(self.bad_hashes), on_result=result,
                            notify=notify).run(stop)
        except Exception as e:
            self.q.put(("alert", f"Download scanning stopped unexpectedly: {e}"))
        finally:
            self.q.put(("protection_worker_stopped",))

    def clear_alert(self):
        self.alert_reset = None
        if self.watching and not self.watch_stop.is_set():
            self.set_live("on")

    # ------------------------------------------------------------ quarantine view
    def build_quar(self, f):
        self.header(f, "Quarantine",
                    f"Isolated files are kept in {g.QUARANTINE_DIR} with all permissions removed.")
        bottom = tk.Frame(f, bg=PAPER)
        bottom.pack(side="bottom", fill="x")
        self.qempty = tk.Label(bottom, text="", font=self.f(10), bg=PAPER, fg=MUTED)
        self.qempty.pack(side="left")
        self.btn(bottom, "Delete permanently", self.delete_quarantined, "Danger").pack(side="right")
        self.btn(bottom, "Restore", self.restore_quarantined).pack(side="right", padx=(0, 8))

        box = tk.Frame(f, bg=LINE, padx=1, pady=1)
        box.pack(fill="both", expand=True, pady=(16, 10))
        self.qtree = ttk.Treeview(box, columns=("name", "folder", "date"), show="headings",
                                  selectmode="extended")
        for col, text, w in (("name", "File", 240), ("folder", "Original folder", 320),
                             ("date", "Quarantined", 150)):
            self.qtree.heading(col, text=text, anchor="w")
            self.qtree.column(col, width=w, anchor="w")
        self.qtree.pack(fill="both", expand=True)
        self.refresh_quarantine()

    def refresh_quarantine(self):
        self.qtree.delete(*self.qtree.get_children())
        self.qitems = g.list_quarantine()
        for i, it in enumerate(self.qitems):
            orig = Path(it.get("original_path", ""))
            when = (time.strftime("%Y-%m-%d %H:%M", time.localtime(it["time"]))
                    if it.get("time") else "")
            folder = str(orig.parent) if orig.is_absolute() else ""
            self.qtree.insert("", "end", iid=str(i), values=(orig.name, folder, when))
        self.qempty.configure(text="" if self.qitems else "Nothing in quarantine.")

    def selected_quarantined(self):
        return [self.qitems[int(i)] for i in self.qtree.selection()]

    def restore_quarantined(self):
        sel = self.selected_quarantined()
        if not sel:
            return
        if not messagebox.askyesno("Guardian", "Restore the selected files to where they came "
                                   "from? Only do this if you are sure they are safe."):
            return
        restored, failed = [], []
        for it in sel:
            try:
                restored.append(g.restore(it))
            except OSError as e:
                failed.append(f"{Path(it.get('original_path', '?')).name}: {e}")
        self.refresh_quarantine()
        if failed:
            messagebox.showerror("Guardian", "Some files could not be restored:\n" + "\n".join(failed))
        elif restored:
            messagebox.showinfo("Guardian", f"Restored {len(restored)} file(s).\n{restored[0]}")

    def delete_quarantined(self):
        sel = self.selected_quarantined()
        if not sel or not messagebox.askyesno(
                "Guardian", f"Permanently delete {len(sel)} file(s)? This cannot be undone."):
            return
        failed = []
        for it in sel:
            try:
                g.delete_quarantined(it)
            except OSError as e:
                failed.append(str(e))
        self.refresh_quarantine()
        if failed:
            messagebox.showerror("Guardian", "Some files could not be deleted:\n" + "\n".join(failed))

    # ------------------------------------------------------------ event loop
    def poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                getattr(self, "on_" + msg[0])(*msg[1:])
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def on_collecting(self, n):
        self.scan_status.configure(text=f"Collecting files... {n:,} found", fg=MUTED)

    def on_progress(self, done, total, name):
        self.bar.configure(maximum=max(total, 1), value=done)
        short = name if len(name) <= 48 else name[:45] + "..."
        self.scan_status.configure(text=f"Checking {done:,} of {total:,}: {short}", fg=MUTED)

    def on_hit(self, score, path, why):
        self.scan_f.add(score, {"file": path, "why": "; ".join(why)}, path, why)

    def on_scan_error(self, msg):
        self.scan_error = msg

    def on_scan_done(self, done, flagged, skipped, stopped, secs):
        self.scanning = False
        self.scan_btn.configure(text="Start scan")
        if self.scan_error:
            self.scan_status.configure(text=f"Scan failed: {self.scan_error}", fg=RED)
        else:
            word = "Scan stopped" if stopped else "Scan complete"
            result = f"{flagged} need attention" if flagged else "no threats found"
            text = f"{word}: {done:,} files checked in {secs:.0f}s, {result}"
            if skipped:
                text += f", {skipped:,} could not be read (no access)"
            self.scan_status.configure(text=text + ".", fg=RED if flagged else TEAL)
        self.scan_f.sort("risk", True)

    def on_comp_status(self, text):
        self.comp_status.configure(text=text, fg=MUTED)

    def on_comp_hit(self, score, kind, item, path, reasons, command):
        self.comp_f.add(score, {"kind": kind, "item": item, "why": "; ".join(reasons)},
                        path, reasons, command)

    def on_comp_done(self, startup, running, note, err):
        self.checking = False
        self.comp_btn.state(["!disabled"])
        n = len(self.comp_f.rows)
        if err:
            self.comp_status.configure(text=f"The check failed: {err}", fg=RED)
        else:
            text = (f"Checked {startup:,} startup items and {running:,} running programs: "
                    + (f"{n} need attention." if n else "nothing suspicious found."))
            if note:
                text += " " + note
            self.comp_status.configure(text=text, fg=RED if n else TEAL)
        self.comp_f.sort("risk", True)

    def on_log(self, kind, msg):
        self.write_log(kind, msg)

    def on_alert(self, msg):
        self.write_log("alert", msg)
        if self.watching and not self.watch_stop.is_set():
            self.set_live("alert")
            self.root.bell()
            self.root.deiconify()
            self.root.lift()
            if self.alert_reset:
                self.root.after_cancel(self.alert_reset)
            self.alert_reset = self.root.after(20000, self.clear_alert)

    def on_watch_stopped(self):
        self.watching = False
        self.live_btn.configure(text="Turn on")
        self.live_btn.state(["!disabled"])
        self.set_live("off")

    def on_protection_worker_stopped(self):
        self.protection_workers = max(0, self.protection_workers - 1)
        if self.protection_workers == 0:
            self.on_watch_stopped()

    def on_download_result(self, path, score, reasons, action, quarantined_to):
        name = os.path.basename(path)
        if action == "clean":
            self.write_log("info", f"Download scanned: {name} — no suspicious indicators found.")
        elif action == "error":
            self.on_alert(f"Could not scan download: {name}. {('; '.join(reasons))}")
        else:
            detail = "; ".join(reasons) or "suspicious indicators found"
            location = f" Moved to quarantine: {quarantined_to}" if quarantined_to else ""
            self.on_alert(f"{action.title()} download: {name}. {detail}.{location}")

    def on_close(self):
        self.scan_stop.set()
        self.watch_stop.set()
        if self.watch_thread and self.watch_thread.is_alive():
            self.watch_thread.join(timeout=3)  # lets the monitor remove its decoy files
        if self.download_thread and self.download_thread.is_alive():
            self.download_thread.join(timeout=1)
        self.cfg.update(scan_path=self.scan_path.get(), scan_mode=self.scan_mode.get(),
                        watch_path=self.watch_path.get(), threshold=self.safe_threshold())
        g.save_config(self.cfg)
        self.root.destroy()


if __name__ == "__main__":
    try:  # crisp text on high-DPI Windows screens
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    tk_root = tk.Tk()
    App(tk_root)
    tk_root.mainloop()

