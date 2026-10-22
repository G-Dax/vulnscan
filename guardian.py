#!/usr/bin/env python3
"""
Guardian - defensive anti-malware / anti-ransomware engine and command line (stdlib only).

  python guardian.py scan  <path> [--deep] [--hashes list.txt] [--quarantine] [--report out.csv]
  python guardian.py check                      (auto-start + running programs)
  python guardian.py guard [folder ...]         (scan every new download; Ctrl+C to stop)
  python guardian.py watch <folder> [--threshold 10] [--window 10]

Layers
  1. Signature : SHA-256 blocklist (any text file; the first 64-hex token on each line is used)
  2. Heuristic : encrypted-looking content, ransomware strings, disguised programs, odd names
  3. Deep scan : program internals (PE), inside zip/Office/PDF files, hidden script payloads
  4. Computer  : auto-start programs and running programs (check_persistence / check_processes)
  5. Behavior  : RansomwareMonitor (decoy files + bursts of files turning into random data)
  6. Downloads : DownloadGuard (scans every file as soon as its download finishes)
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import math
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import Counter, deque
from pathlib import Path

QUARANTINE_DIR = Path.home() / ".guardian_quarantine"
CONFIG_FILE = Path.home() / ".guardian_config.json"
MAX_HASH_SIZE = 512 * 1024 * 1024          # do not hash files bigger than this
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".cache"}  # live monitor only

# --------------------------------------------------------------------------- knowledge
# Formats that are legitimately high-entropy. A file with one of these headers is not
# "encrypted"; ransomware output normally loses the original header.
KNOWN_MAGIC = (
    b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh",
    b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"%PDF",
    b"RIFF", b"OggS", b"ID3", b"fLaC", b"\x1aE\xdf\xa3", b"wOFF", b"wOF2", b"\xff\xfb", b"\xff\xf3",
)
COMPRESSED_EXT = {
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".cab", ".msi", ".jar", ".apk",
    ".whl", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".mp3", ".mp4", ".m4a", ".aac",
    ".ogg", ".flac", ".mkv", ".mov", ".avi", ".webm", ".pdf", ".epub", ".docx", ".xlsx", ".pptx",
    ".odt", ".ods", ".dmg", ".iso", ".woff", ".woff2", ".pyc", ".gpg", ".pgp", ".kdbx",
}
EXEC_EXT = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".com", ".dll", ".hta", ".msi"}
SCRIPT_EXT = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"}
PE_EXT = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi", ".drv", ".mui", ".pyd",
          ".node", ".ax", ".com", ".msi"}
DOC_LIKE_EXT = COMPRESSED_EXT | {".txt", ".doc", ".rtf", ".csv"}
SOURCE_EXT = {".py", ".pyc", ".md", ".rst", ".json", ".yar", ".yara", ".c", ".h", ".cpp", ".java",
              ".ts", ".go", ".rs", ".csv", ".log", ".xml", ".yml", ".yaml", ".ini"}
RANSOM_EXT = {".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".lockbit", ".wncry",
              ".wnry", ".ryk", ".conti", ".akira", ".cerber", ".locky", ".zepto"}
RANSOM_NOTE_HINTS = ("readme_decrypt", "how_to_recover", "decrypt_instruction", "restore_files",
                     "how_to_decrypt", "recover_your_files", "decrypt_your_files")

NOTE_STRINGS = [b"your files have been encrypted", b"your files are encrypted",
                b"decrypt_instruction", b"how_to_recover", b"send bitcoin", b"decryption key",
                b"pay the ransom"]
TECH_STRINGS = [b"vssadmin delete shadows", b"wmic shadowcopy delete", b"wbadmin delete catalog",
                b"bcdedit /set {default} recoveryenabled no", b"cryptencrypt",
                b"-encodedcommand", b"powershell -enc"]
SCRIPT_STRINGS = [b"frombase64string", b"invoke-expression", b"downloadstring",
                  b"-nop -w hidden", b"-windowstyle hidden"]

# The standard, harmless antivirus test string (https://www.eicar.org). Joined at runtime so this
# source file does not contain the full signature.
EICAR = b"".join([b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!", b"$H+H*"])
PARTIAL_EXT = {".crdownload", ".part", ".partial", ".tmp", ".temp", ".download", ".opdownload",
               ".crswap", ".!ut"}
HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# ---- deep scan knowledge
DEEP_MAX_SIZE = 300 * 1024 * 1024          # bigger files only get the quick scan
DEEP_READ = 32 * 1024 * 1024               # how much of a file the deep scan reads
MAX_ZIP_ENTRIES, MEMBER_LIMIT, ZIP_TOTAL_LIMIT = 300, 5 * 1024 * 1024, 64 * 1024 * 1024
ARCHIVE_EXEC_EXT = {".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".lnk",
                    ".jar", ".dll", ".com", ".msi", ".iso", ".img"}
OBFUSC_EXT = SCRIPT_EXT | {".txt", ".html", ".htm", ".wsf", ".sct", ".php", ".sh", ".py", ".pl"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
                   ".vmp2", ".petite", ".nsp0", ".nsp1", ".enigma1", ".enigma2", ".mpress1",
                   ".mpress2", "pec1", "pec2", ".perplex"}
API_GROUPS = (  # (names, how many must be present, points, message)
    ([b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"NtUnmapViewOfSection",
      b"SetThreadContext", b"QueueUserAPC"], 3, 30, "can inject code into other programs"),
    ([b"SetWindowsHookEx", b"GetAsyncKeyState", b"GetKeyboardState", b"GetForegroundWindow"],
     3, 20, "can record what you type"),
    ([b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess",
      b"OutputDebugString"], 3, 15, "tries to detect security and analysis tools"),
)
OFFICE_AUTOEXEC = [b"autoopen", b"auto_open", b"document_open", b"workbook_open", b"autoexec",
                   b"document_close", b"auto_close"]
OFFICE_DANGER = [b"shell", b"createobject", b"powershell", b"urldownloadtofile", b"wscript.shell",
                 b"xmlhttp", b"adodb.stream", b"environ("]
DECODED_HINTS = [b"powershell", b"invoke-expression", b"downloadstring", b"cmd.exe",
                 b"wscript.shell", b"net.webclient", b"frombase64string", b"-encodedcommand",
                 b"vssadmin", b"http://", b"https://"]
B64 = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
LOLBIN = [
    (re.compile(r"mshta(\.exe)?\s+(https?:|vbscript|javascript)"), "runs a script from the web (mshta)"),
    (re.compile(r"regsvr32.*(/i:|scrobj).*https?://"), "loads code from the web (regsvr32)"),
    (re.compile(r"rundll32.*javascript:"), "runs a hidden script (rundll32)"),
    (re.compile(r"certutil.*-urlcache"), "downloads a file (certutil)"),
    (re.compile(r"bitsadmin.*/transfer"), "downloads a file (bitsadmin)"),
    (re.compile(r"(curl|wget)[^|;&]*\|\s*(ba|z)?sh"), "downloads and runs a script from the internet"),
    (re.compile(r"base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh"), "decodes and runs hidden commands"),
    (re.compile(r"powershell[^\n]*(-w(indowstyle)?\s+hidden|-nop\b)"), "runs PowerShell out of sight"),
]
TEMP_PATH = re.compile(r"[\\/](temp|tmp)[\\/]|[\\/]users[\\/]public[\\/]|[\\/]downloads[\\/]|/dev/shm")
SYSTEM_PROCS = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
                "smss.exe", "wininit.exe", "taskhostw.exe", "explorer.exe"}
SECURITY_SITES = re.compile(r"(microsoft|windowsupdate|kaspersky|avast|avg|eset|symantec|norton|"
                            r"mcafee|malwarebytes|bitdefender|sophos|virustotal|defender)\.")


# --------------------------------------------------------------------------- primitives
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def read_head(path, size=1 << 20) -> bytes:
    with open(path, "rb") as f:
        return f.read(size)


def has_known_format(head: bytes) -> bool:
    return head.startswith(KNOWN_MAGIC) or head[4:8] == b"ftyp"


def looks_encrypted(head: bytes, ext: str) -> bool:
    """High-entropy data that is not a known compressed/media format."""
    return (len(head) >= 4096 and ext not in COMPRESSED_EXT
            and not has_known_format(head) and entropy(head[:65536]) > 7.5)


def load_blocklist(path) -> set:
    hashes = set()
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if line.lstrip().startswith("#"):
                continue
            m = HEX64.search(line)
            if m:
                hashes.add(m.group(0).lower())
    return hashes


# --------------------------------------------------------------------------- quick checks
def score_content(name, head, size=0):
    """Quick checks on a file name and its first bytes. Returns (score, reasons)."""
    lname = name.lower()
    ext = os.path.splitext(lname)[1]
    score, reasons = 0, []

    if EICAR in head[:300]:
        return 100, ["EICAR test file (a harmless file made to test antivirus programs)"]
    if any(c in BIDI for c in name):
        score += 70
        reasons.append("the file name uses hidden text-direction characters to fake its extension")
    if ext in RANSOM_EXT:
        score += 50
        reasons.append(f"ransomware-style extension ({ext})")
    if any(h in lname for h in RANSOM_NOTE_HINTS):
        score += 50
        reasons.append("file name looks like a ransom note")

    if looks_encrypted(head, ext):
        if ext in EXEC_EXT:
            score += 15
            reasons.append("high entropy (possibly packed)")
        else:
            score += 35
            reasons.append("content looks encrypted or random")

    if ext not in SOURCE_EXT:  # source code legitimately quotes these strings
        low = head.lower()
        pool = NOTE_STRINGS + TECH_STRINGS + (SCRIPT_STRINGS if ext in SCRIPT_EXT else [])
        hits = [s.decode() for s in pool if s in low]
        if hits:
            score += min(75, 25 * len(hits))
            reasons.append("suspicious strings: " + ", ".join(hits))

    parts = lname.split(".")
    if len(parts) > 2 and f".{parts[-1]}" in EXEC_EXT and f".{parts[-2]}" in DOC_LIKE_EXT:
        score += 45
        reasons.append("double extension (program disguised as a document)")

    if head[:2] == b"MZ" and ext not in PE_EXT:
        score += 45
        reasons.append("Windows program with a misleading extension")

    return score, reasons


# --------------------------------------------------------------------------- deep checks
def pe_checks(data, size):
    """Look inside a Windows program (EXE/DLL): sections, entry point, packers, risky functions."""
    if len(data) < 0x40:
        return 0, []
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe < 0x40 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return 20, ["broken program header (damaged or hand-crafted file)"]
    _m, nsec, stamp, _p, _n, optsize, _c = struct.unpack_from("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    if optsize < 96 or opt + optsize > len(data):
        return 20, ["broken program header (damaged or hand-crafted file)"]
    magic = struct.unpack_from("<H", data, opt)[0]
    ep = struct.unpack_from("<I", data, opt + 16)[0]
    dd = opt + (96 if magic == 0x10B else 112)

    def ddir(i):
        o = dd + 8 * i
        return struct.unpack_from("<II", data, o) if o + 8 <= opt + optsize else (0, 0)

    _imp_rva, imp_size = ddir(1)
    cert_off, cert_size = ddir(4)

    secs, sec_off = [], opt + optsize
    for i in range(min(nsec, 96)):
        o = sec_off + 40 * i
        if o + 40 > len(data):
            break
        nm, vsize, vaddr, rsize, rptr, _a, _b, _c2, _d, chars = struct.unpack_from("<8sIIIIIIHHI", data, o)
        secs.append((nm.rstrip(b"\0").decode("latin-1").lower(), vsize, vaddr, rsize, rptr, chars))

    score, why = 0, []
    if stamp > time.time() + 2 * 86400:
        score += 10
        why.append("compile date is in the future (faked)")

    packers = sorted({s[0] for s in secs if s[0] in PACKER_SECTIONS})
    if packers:
        score += 25
        why.append("built with a packer that hides the real program (" + ", ".join(packers) + ")")
    if any(s[5] & 0x20000000 and s[5] & 0x80000000 for s in secs):
        score += 15
        why.append("a program section is both writable and executable (typical of self-modifying code)")

    packed_code = odd_data = False
    for name, _vs, _va, rsize, rptr, chars in secs:
        blob = data[rptr:rptr + min(rsize, 1 << 20)]
        if len(blob) < 4096:
            continue
        ent = entropy(blob[:131072])
        if chars & 0x20000020 and ent > 7.2:
            packed_code = True
        elif ent > 7.4 and name != ".rsrc":
            odd_data = True
    if packed_code:
        score += 25
        why.append("the program code itself is encrypted or compressed")
    elif odd_data:
        score += 10
        why.append("contains a large block of encrypted-looking data")

    if ep and secs:
        host = next((s for s in secs if s[2] <= ep < s[2] + max(s[1], s[3])), None)
        if host is None or not host[5] & 0x20000000:
            score += 20
            why.append("starts running outside its code section (typical of packed or injected programs)")

    end = max((s[4] + s[3] for s in secs), default=0)
    overlay = size - end - (cert_size if cert_off and cert_off >= end else 0)
    if overlay > (1 << 20) and overlay > size * 0.5:
        score += 10
        why.append("most of the file is extra data tacked on after the program")

    for names, need, pts, msg in API_GROUPS:
        if sum(n in data for n in names) >= need:
            score += pts
            why.append(msg)
    if b"URLDownloadToFile" in data and any(x in data for x in (b"ShellExecute", b"WinExec", b"CreateProcess")):
        score += 20
        why.append("can download a file and run it")
    if 0 < imp_size <= 60 and b"GetProcAddress" in data and b"LoadLibrary" in data:
        score += 10
        why.append("hides which system functions it uses (looks them up at runtime)")
    return min(score, 70), why


def pdf_checks(data):
    low = data.lower()
    score, why = 0, []
    if b"/launch" in low:
        score += 35
        why.append("PDF can launch programs when opened")
    if b"/javascript" in low or re.search(rb"/js\b", low):
        score += 15
        why.append("PDF contains JavaScript")
    if b"/openaction" in low:
        score += 10
        why.append("PDF runs an action as soon as it opens")
    if b"/embeddedfile" in low:
        score += 15
        why.append("PDF carries an embedded file")
    if b"/richmedia" in low:
        score += 10
        why.append("PDF contains embedded media (a common attack route)")
    if low.count(b"/#") > 5:
        score += 10
        why.append("PDF hides keywords with character codes")
    return min(score, 60), why


def ole_checks(data, known_macros=False):
    """Old-style Office files (.doc/.xls/.ppt) and vbaProject.bin: macros and what they do."""
    low = data.lower()

    def has(word):
        return word in low or word.decode().encode("utf-16-le") in low

    markers = (b"_vba_project", b"vba", b"macros")
    if not known_macros and not any(has(m) for m in markers):
        return 0, []
    score, why = 20, ["contains macros (small programs inside the document)"]
    if any(has(w) for w in OFFICE_AUTOEXEC):
        score += 20
        why.append("macros run automatically when the document is opened")
    danger = [w.decode() for w in OFFICE_DANGER if has(w)]
    if danger:
        score += min(30, 10 * len(danger))
        why.append("macros mention risky actions: " + ", ".join(danger))
    return min(score, 60), why


def _decode_text(data):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "ignore")
    return data.decode("utf-8", "ignore")


def obfuscation_checks(data, ext):
    """Scripts and text: hidden (base64) payloads and signs of deliberate scrambling."""
    txt = _decode_text(data)
    low = txt.lower()
    score, why = 0, []
    for blob in B64.findall(txt)[:30]:
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except ValueError:
            continue
        if raw[:2] == b"MZ":
            score += 50
            why.append("hides a Windows program inside encoded text")
            break
        text = raw.decode("utf-16-le", "ignore") if raw[1:2] == b"\x00" else raw.decode("utf-8", "ignore")
        probe = text.lower().encode("utf-8", "ignore")
        hits = [h.decode() for h in DECODED_HINTS if h in probe]
        risky = [h for h in hits if not h.startswith("http")]
        if risky or len(hits) >= 2:
            score += 40
            why.append("hides commands inside encoded text (decodes to: " + ", ".join(hits[:3]) + ")")
            break
    for rx, msg in LOLBIN:  # commands that fetch and run code
        if rx.search(low):
            score += 35
            why.append(msg)
            break
    if low.count("fromcharcode") + low.count("chr(") + low.count("chrw(") >= 20:
        score += 20
        why.append("builds its code from character numbers (obfuscation)")
    if ("eval(" in low or "execute(" in low) and ("unescape(" in low or "atob(" in low or "fromcharcode" in low):
        score += 25
        why.append("decodes hidden code and runs it")
    if len(re.findall(r"\\x[0-9a-f]{2}", low)) >= 80:
        score += 15
        why.append("full of escaped byte codes (obfuscation)")
    if ext in SCRIPT_EXT and max((len(l) for l in txt.splitlines()), default=0) > 8000:
        score += 10
        why.append("one extremely long line (typical of scrambled scripts)")
    if "powershell" in low or ext == ".ps1":
        if low.count("`") >= 40 or low.count("'+'") >= 30:
            score += 15
            why.append("PowerShell text is deliberately chopped up to avoid detection")
        if "-bxor" in low and "[char]" in low:
            score += 20
            why.append("decrypts hidden text while running (XOR)")
    return min(score, 70), why


def shortcut_checks(data):
    text = data.decode("latin-1").lower() + " " + data.decode("utf-16-le", "ignore").lower()
    score, why, _ = _score_command(text, follow=False)
    if re.search(r"cmd(\.exe)?\s+/[ck]|powershell|mshta|wscript|cscript", text):
        score += 25
        why.append("shortcut runs a command line instead of opening a file")
    return score, why


def deep_content(name, data, size):
    """Everything the deep scan can learn from a file's bytes alone."""
    ext = os.path.splitext(name.lower())[1]
    parts = []
    if data[:2] == b"MZ":
        parts.append(pe_checks(data, size))
    elif data.startswith(OLE_MAGIC):
        parts.append(ole_checks(data))
    elif data[:5] == b"%PDF-":
        parts.append(pdf_checks(data))
    if ext in OBFUSC_EXT:
        parts.append(obfuscation_checks(data[:2 << 20], ext))
    if ext in (".lnk", ".url"):
        parts.append(shortcut_checks(data))
    return sum(p[0] for p in parts), [w for p in parts for w in p[1]]


def zip_deep(zf, bad_hashes=frozenset(), depth=0):
    """Look inside a zip (and Office .docx/.xlsx/.pptx): contents, macros, remote templates."""
    infos = zf.infolist()[:MAX_ZIP_ENTRIES]
    names = [i.filename.lower() for i in zf.infolist()]
    score, why = 0, []

    total = sum(i.file_size for i in infos)
    packed = sum(i.compress_size for i in infos) or 1
    if total > 500 * 1024 * 1024 and total / packed > 100:
        score += 40
        why.append("possible zip bomb (tiny file that expands to a huge size)")
    execs = [i.filename for i in infos if os.path.splitext(i.filename.lower())[1] in ARCHIVE_EXEC_EXT]
    encrypted = any(i.flag_bits & 1 for i in infos)
    if execs:
        score += 10
        why.append("contains programs or scripts: " + ", ".join(os.path.basename(e) for e in execs[:3]))
    if encrypted:
        score += 35 if (execs or len(infos) <= 3) else 20
        why.append("password-protected archive (hides its contents from scanners)")

    if "[content_types].xml" in names:  # Office Open XML
        for info in zf.infolist():
            if info.filename.lower().endswith("vbaproject.bin") and info.file_size <= MEMBER_LIMIT:
                s, r = ole_checks(zf.read(info), known_macros=True)
                score += s
                why += r
        for info in zf.infolist():
            ln = info.filename.lower()
            if ln.endswith(".rels") and info.file_size <= (1 << 20):
                for tag in re.findall(r"<Relationship\b[^>]*>", zf.read(info).decode("utf-8", "ignore")):
                    if ('TargetMode="External"' in tag and re.search(r'Target="https?://', tag, re.I)
                            and re.search(r'Type="[^"]*(attachedTemplate|oleObject|subDocument|frame)', tag, re.I)):
                        score += 45
                        why.append("loads content from a web address when opened (remote template)")
                        break
            if ln == "word/document.xml" and info.file_size <= 5 * (1 << 20):
                if b"ddeauto" in zf.read(info).lower():
                    score += 40
                    why.append("uses DDE to run commands when opened")

    best, budget = (0, []), ZIP_TOTAL_LIMIT
    for info in infos:
        if info.is_dir() or info.flag_bits & 1 or info.file_size == 0 or info.file_size > MEMBER_LIMIT:
            continue
        if budget <= 0:
            break
        try:
            with zf.open(info) as fh:
                data = fh.read(MEMBER_LIMIT + 1)
        except Exception:
            continue
        if len(data) > MEMBER_LIMIT:
            continue
        budget -= len(data)
        label = info.filename
        if bad_hashes and hashlib.sha256(data).hexdigest() in bad_hashes:
            return 100, [f"'{label}' inside the archive matches a known-malware hash"]
        s, r = score_content(os.path.basename(label), data[:1 << 20], len(data))
        s2, r2 = deep_content(os.path.basename(label), data, len(data))
        s, r = s + s2, r + r2
        if depth < 2 and data[:4] == b"PK\x03\x04":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as inner:
                    s3, r3 = zip_deep(inner, bad_hashes, depth + 1)
                s, r = s + s3, r + r3
            except Exception:
                pass
        if s > best[0]:
            best = (s, [f"inside '{label}': {x}" for x in r])
    return score + best[0], why + best[1]


def analyze(path, bad_hashes=frozenset(), deep=False):
    """Return (score 0-100, reasons). Raises OSError if the file cannot be read.
    deep=True also looks inside programs, archives, documents, PDFs and scripts."""
    path = Path(path)
    size = path.stat().st_size
    if size == 0:
        return 0, []
    if bad_hashes and size <= MAX_HASH_SIZE and sha256(path) in bad_hashes:
        return 100, ["matches a known-malware hash"]

    head = read_head(path)
    score, reasons = score_content(path.name, head, size)
    if deep and size <= DEEP_MAX_SIZE:
        data = head if size <= len(head) else read_head(path, DEEP_READ)
        s, r = deep_content(path.name, data, size)
        score, reasons = score + s, reasons + r
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as zf:
                    s, r = zip_deep(zf, bad_hashes)
                score, reasons = score + s, reasons + r
        except OSError:
            raise
        except Exception:
            pass  # damaged or unusual archive: the quick checks already ran
    return min(score, 100), reasons


def verdict(score):
    return "Dangerous" if score >= 70 else "Suspicious" if score >= 40 else "Looks safe"


def advice(score):
    if score >= 70:
        return "Move it to quarantine and do not open it."
    if score >= 40:
        return ("Do not open it unless you trust where it came from. "
                "If you are unsure, quarantine it.")
    return "No action needed."


_SELF = {os.path.normcase(os.path.abspath(p)) for p in
         (__file__, os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardian_ui.py"))}


def iter_files(root):
    """Yield files under root (or root itself), skipping symlinks, quarantine and Guardian's own files."""
    root = str(root)
    if os.path.isfile(root):
        yield Path(root)
        return
    qdir = os.path.normcase(os.path.abspath(QUARANTINE_DIR))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if os.path.normcase(os.path.abspath(os.path.join(dirpath, d))) != qdir]
        for n in filenames:
            full = os.path.join(dirpath, n)
            if os.path.islink(full) or os.path.normcase(os.path.abspath(full)) in _SELF:
                continue
            yield Path(full)


def write_report(rows, path):
    """rows: iterable of (score, file, reasons)."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["risk_score", "file", "reasons"])
        w.writerows(rows)


# --------------------------------------------------------------------------- quarantine
def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    for i in range(1, 1000):
        cand = path.with_name(f"{path.stem} ({i}){path.suffix}")
        if not cand.exists():
            return cand
    return path.with_name(f"{path.stem}-{uuid.uuid4().hex[:6]}{path.suffix}")


def quarantine(path, score=0, reasons=None):
    """Move a file into quarantine, remember where it came from, strip its permissions."""
    path = Path(path).resolve()
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    qid = f"{int(time.time())}_{uuid.uuid4().hex[:6]}"
    dest, meta_file = QUARANTINE_DIR / f"{qid}.quar", QUARANTINE_DIR / f"{qid}.json"
    meta = {"original_path": str(path), "time": int(time.time()), "score": score,
            "reasons": list(reasons or [])}
    try:
        if path.stat().st_size <= MAX_HASH_SIZE:
            meta["sha256"] = sha256(path)
    except OSError:
        pass
    shutil.move(str(path), dest)
    os.chmod(dest, 0o000)
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return dest


def list_quarantine():
    items = []
    if not QUARANTINE_DIR.exists():
        return items
    for p in sorted(QUARANTINE_DIR.glob("*.quar")):
        meta_file = p.with_suffix(".json")
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            ts, _, orig = p.stem.partition("_")  # entries from older versions
            meta = {"original_path": orig or p.name, "time": int(ts) if ts.isdigit() else 0}
        items.append({**meta, "file": p, "meta_file": meta_file})
    return items


def restore(item):
    """Put a quarantined file back where it came from (or in ~/Guardian Restored)."""
    src = item["file"]
    orig = Path(item.get("original_path") or src.name)
    if orig.is_absolute() and orig.parent.is_dir():
        target = orig
    else:
        target = Path.home() / "Guardian Restored" / orig.name
    target.parent.mkdir(parents=True, exist_ok=True)
    target = _unique(target)
    os.chmod(src, 0o600)
    shutil.move(str(src), target)
    item["meta_file"].unlink(missing_ok=True)
    return target


def delete_quarantined(item):
    os.chmod(item["file"], 0o600)
    item["file"].unlink()
    item["meta_file"].unlink(missing_ok=True)



# --------------------------------------------------------------------------- computer check
def _first_path(cmd):
    """Find the program file a startup command points to ('' if none)."""
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith(('"', "'")):
        end = cmd.find(cmd[0], 1)
        cand = cmd[1:end] if end > 0 else cmd[1:]
        return cand if os.path.isfile(cand) else ""
    toks = cmd.split()
    for i in range(len(toks), 0, -1):
        cand = " ".join(toks[:i])
        if os.path.isfile(cand):
            return cand
    return shutil.which(toks[0]) or "" if toks else ""


def _score_command(cmd, bad_hashes=frozenset(), follow=True):
    """Score a command line. Returns (score, reasons, program_path)."""
    low = cmd.lower()
    raw = low.encode("utf-8", "ignore")
    score, why, path = 0, [], ""
    hits = [s.decode() for s in NOTE_STRINGS + TECH_STRINGS + SCRIPT_STRINGS if s in raw]
    if hits:
        score += min(75, 25 * len(hits))
        why.append("suspicious commands: " + ", ".join(hits))
    for rx, msg in LOLBIN:
        if rx.search(low):
            score += 35
            why.append(msg)
            break
    if TEMP_PATH.search(low):
        score += 25
        why.append("starts a program from a temporary or downloads folder")
    if follow:
        path = _first_path(cmd)
        if path:
            try:
                s, r = analyze(path, bad_hashes, deep=True)
            except OSError:
                s, r = 0, []
            if s >= 20:
                score += s
                why += [f"program file: {x}" for x in r]
    return min(score, 100), why, path


def _startup_items():
    """(where, name, command, extra) for everything that starts by itself on this computer."""
    items = []
    home = Path.home()

    if os.name == "nt":
        try:
            import winreg
            keys = (r"Software\Microsoft\Windows\CurrentVersion\Run",
                    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
            for label, hive in (("current user", winreg.HKEY_CURRENT_USER),
                                ("all users", winreg.HKEY_LOCAL_MACHINE)):
                for sub in keys:
                    try:
                        key = winreg.OpenKey(hive, sub)
                    except OSError:
                        continue
                    with key:
                        i = 0
                        while True:
                            try:
                                name, val, _t = winreg.EnumValue(key, i)
                            except OSError:
                                break
                            items.append((f"Startup registry ({label})", name, str(val), None))
                            i += 1
        except ImportError:
            pass
        for base in (os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")):
            if base:
                d = Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if d.is_dir():
                    items += [("Startup folder", f.name, str(f), None) for f in sorted(d.iterdir())
                              if f.name.lower() != "desktop.ini"]
        try:  # scheduled tasks (skips Microsoft's own)
            import csv as _csv
            out = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"], capture_output=True,
                                 text=True, errors="ignore", timeout=40).stdout
            rows = list(_csv.reader(io.StringIO(out)))
            head = next((r for r in rows if "Task To Run" in r), None)
            if head:
                ti, ci = head.index("TaskName"), head.index("Task To Run")
                for r in rows:
                    if len(r) > ci and r[ci] not in ("Task To Run", "N/A") and not r[ti].startswith("\\Microsoft\\"):
                        items.append(("Scheduled task", r[ti], r[ci], None))
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
        hosts = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
    else:
        hosts = Path("/etc/hosts")

    if sys.platform == "darwin":
        for d in (home / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")):
            for f in sorted(d.glob("*.plist")) if d.is_dir() else []:
                try:
                    with open(f, "rb") as fh:
                        pl = plistlib.load(fh)
                    cmd = " ".join(pl.get("ProgramArguments") or [pl.get("Program", "")])
                    items.append(("Launch agent", pl.get("Label", f.stem), cmd, None))
                except (OSError, ValueError, plistlib.InvalidFileException):
                    continue
    elif os.name != "nt":
        for d in (home / ".config/autostart", Path("/etc/xdg/autostart")):
            for f in sorted(d.glob("*.desktop")) if d.is_dir() else []:
                try:
                    m = re.search(r"^Exec=(.+)$", f.read_text(errors="ignore"), re.M)
                except OSError:
                    continue
                if m:
                    items.append(("Autostart (desktop)", f.stem, m.group(1).strip(), None))
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or re.match(r"^\w+=", line):
                    continue
                cmd = line.split(None, 1)[1] if line.startswith("@") and " " in line else \
                    (line.split(None, 5)[5] if len(line.split(None, 5)) == 6 else line)
                items.append(("Scheduled job (cron)", cmd[:40], cmd, None))
        except (OSError, subprocess.SubprocessError, IndexError):
            pass
        for f in sorted((home / ".config/systemd/user").glob("*.service")) if (home / ".config/systemd/user").is_dir() else []:
            try:
                m = re.search(r"^ExecStart=(.+)$", f.read_text(errors="ignore"), re.M)
            except OSError:
                continue
            if m:
                items.append(("User service", f.stem, m.group(1).strip(), None))
        for fname in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
            try:
                lines = (home / fname).read_text(errors="ignore").splitlines()[:3000]
            except OSError:
                continue
            for n, line in enumerate(lines, 1):
                low = line.lower()
                if any(rx.search(low) for rx, _m in LOLBIN):
                    items.append(("Shell startup file", f"{fname}:{n}", line.strip(), None))
        pre = Path("/etc/ld.so.preload")
        try:
            body = "\n".join(l for l in pre.read_text(errors="ignore").splitlines()
                             if l.strip() and not l.lstrip().startswith("#"))
            if body:
                items.append(("System library preload", str(pre), body[:200],
                              (40, ["forces a library into every program (a rootkit technique)"])))
        except OSError:
            pass

    try:  # a hosts file that blocks or redirects security/update sites
        for line in hosts.read_text(errors="ignore").splitlines():
            line = line.split("#")[0].strip()
            parts = line.split()
            if len(parts) >= 2 and SECURITY_SITES.search(" ".join(parts[1:]).lower() + "."):
                items.append(("Hosts file", parts[1], line, (60, ["blocks or redirects a security or update website"])))
    except OSError:
        pass
    return items


def check_persistence(bad_hashes=frozenset()):
    """Check everything that starts automatically. Returns a list of dicts (all items, scored)."""
    rows = []
    for where, name, cmd, extra in _startup_items():
        score, why, path = _score_command(cmd, bad_hashes)
        if extra:
            score, why = min(100, score + extra[0]), extra[1] + why
        rows.append({"where": where, "name": name, "command": cmd, "path": path,
                     "score": score, "reasons": why})
    return rows


def check_processes(bad_hashes=frozenset()):
    """Check running programs. Returns (rows, how_many_programs, note)."""
    procs = []  # (pid, name, exe)
    try:
        import psutil
        for p in psutil.process_iter(["pid", "name", "exe"]):
            procs.append((p.info["pid"], p.info["name"] or "", p.info["exe"] or ""))
    except ImportError:
        if sys.platform.startswith("linux") and os.path.isdir("/proc"):
            for pid in (d for d in os.listdir("/proc") if d.isdigit()):
                try:
                    exe = os.readlink(f"/proc/{pid}/exe")
                    name = Path(f"/proc/{pid}/comm").read_text().strip()
                except OSError:
                    continue
                procs.append((int(pid), name, exe))
        else:
            return [], 0, "To check running programs, install psutil:  pip install psutil"

    groups = {}
    for pid, name, exe in procs:
        if exe:
            groups.setdefault(exe, {"name": name, "pids": []})["pids"].append(pid)
    sysroot = os.environ.get("SystemRoot", "").lower()
    rows = []
    for exe, info in groups.items():
        clean = exe[:-10] if exe.endswith(" (deleted)") else exe
        # psutil drops the "(deleted)" marker, so also treat a missing file as deleted
        deleted = clean != exe or (not exe.startswith("/memfd:") and not os.path.exists(clean))
        score, why = 0, []
        if deleted:
            score += 40
            why.append("its program file was deleted but it is still running")
        if exe.startswith("/memfd:"):
            score += 25  # also used by some legitimate container tools
            why.append("runs only from memory (no file on disk)")
        temp = bool(TEMP_PATH.search(exe.lower()))
        if temp:
            score += 25
            why.append("running from a temporary or downloads folder")
        if sysroot and info["name"].lower() in SYSTEM_PROCS and not exe.lower().startswith(sysroot):
            score += 50
            why.append("pretends to be a Windows system program but lives somewhere else")
        if os.path.isfile(clean):
            try:
                s, r = analyze(clean, bad_hashes, deep=temp)
            except OSError:
                s, r = 0, []
            score += s
            why += r
        rows.append({"name": info["name"], "path": clean if os.path.isfile(clean) else "",
                     "pids": info["pids"], "score": min(score, 100), "reasons": why})
    return rows, len(rows), ""


# --------------------------------------------------------------------------- live monitor
def snapshot(folder):
    """{path: (mtime_ns, size)} for every regular file under folder."""
    snap, stack = {}, [str(folder)]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if e.name not in SKIP_DIRS:
                                stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            snap[e.path] = (st.st_mtime_ns, st.st_size)
                    except OSError:
                        continue
        except OSError:
            continue
    return snap


class RansomwareMonitor:
    """Watches a folder. notify(kind, message) is called with kind 'info' or 'alert'."""
    MAGIC = b"GUARDIAN-CANARY"
    CANARY_NAMES = ("!aaa_budget.docx", "zzz_family_photos.jpg", "~important_backup.xlsx")
    MAX_READS_PER_CYCLE = 200
    INTERVAL = 1.0

    def __init__(self, folder, threshold=10, window=10, notify=None):
        self.folder = Path(folder).resolve()
        self.threshold = max(1, int(threshold))
        self.window = window
        self.notify = notify or (lambda kind, msg: None)
        self.canaries, self.canary_paths = {}, set()

    def arm(self):
        for i, name in enumerate(self.CANARY_NAMES):
            p = self.folder / (name if os.name == "nt" else "." + name)
            try:
                if p.exists():
                    data = p.read_bytes()
                    if not data.startswith(self.MAGIC):
                        continue  # a real file already uses this name: leave it alone
                else:
                    data = self.MAGIC + b"\n" + bytes([65 + i]) * 4096
                    p.write_bytes(data)
            except OSError:
                continue
            self.canaries[str(p)] = data
            self.canary_paths.add(str(p))
        return len(self.canaries)

    def disarm(self):
        for cp in self.canary_paths:
            try:
                with open(cp, "rb") as f:
                    if f.read(len(self.MAGIC)) == self.MAGIC:
                        os.remove(cp)
            except OSError:
                pass

    def _check_canaries(self, cur):
        for cp, original in list(self.canaries.items()):
            name = os.path.basename(cp)
            if cp not in cur:
                self.notify("alert", f"Decoy file deleted: {name}")
                self.canaries.pop(cp)
                continue
            try:
                data = Path(cp).read_bytes()
            except OSError:
                continue
            if data != original:
                self.notify("alert", f"Decoy file modified: {name}")
                self.canaries[cp] = data

    @staticmethod
    def _encrypted_looking(path, ext):
        try:
            return looks_encrypted(read_head(path, 65536), ext)
        except OSError:
            return False

    def run(self, stop: threading.Event):
        count = self.arm()
        self.notify("info", f"Watching {self.folder} with {count} decoy file(s).")
        try:
            prev = snapshot(self.folder)
            if len(prev) > 100_000:
                self.notify("info", f"Large folder ({len(prev):,} files): checks may lag behind.")
            recent = deque()  # (time, filename)
            while not stop.wait(self.INTERVAL):
                cur, now = snapshot(self.folder), time.time()
                self._check_canaries(cur)
                reads = 0
                for p, meta in cur.items():
                    if p in self.canary_paths or prev.get(p) == meta:
                        continue
                    is_new = p not in prev
                    base = os.path.basename(p)
                    name, ext = base.lower(), os.path.splitext(base)[1].lower()
                    if is_new and any(h in name for h in RANSOM_NOTE_HINTS):
                        self.notify("alert", f"Possible ransom note created: {base}")
                    if is_new and ext in RANSOM_EXT:
                        recent.append((now, base))
                    elif reads < self.MAX_READS_PER_CYCLE:
                        reads += 1
                        if self._encrypted_looking(p, ext):
                            recent.append((now, base))
                while recent and now - recent[0][0] > self.window:
                    recent.popleft()
                if len(recent) >= self.threshold:
                    sample = ", ".join(n for _, n in list(recent)[:3])
                    self.notify("alert", f"{len(recent)} files turned into encrypted-looking data "
                                         f"within {self.window}s (for example: {sample})")
                    recent.clear()
                prev = cur
        finally:
            self.disarm()
            self.notify("info", "Protection stopped. Decoy files removed.")



class DownloadGuard:
    """Scans every file that finishes downloading into the watched folders.

    on_result(path, score, reasons, action, quarantined_to) is called once per file.
    action: 'clean' | 'suspicious' | 'dangerous' | 'quarantined' | 'error'
    Files already in the folder when the guard starts are ignored (use a normal scan for those).
    """
    POLL = 1.0
    SETTLE = 2  # polls in a row with no change before a file counts as "finished downloading"

    def __init__(self, folders, bad_hashes=frozenset(), auto_quarantine=True,
                 on_result=None, notify=None):
        self.folders = [Path(f).resolve() for f in folders]
        self.bad_hashes = bad_hashes
        self.auto_quarantine = auto_quarantine
        self.on_result = on_result or (lambda *a: None)
        self.notify = notify or (lambda kind, msg: None)

    @staticmethod
    def _readable(path):
        try:
            with open(path, "rb") as f:
                f.read(1)
            return True
        except OSError:
            return False  # still being written (locked) or not allowed yet

    def _handle(self, path):
        try:
            score, why = analyze(path, self.bad_hashes, deep=True)
        except OSError as e:
            self.on_result(str(path), 0, [f"could not be scanned: {e}"], "error", None)
            return
        dest = None
        if score >= 70:
            action = "dangerous"
            if self.auto_quarantine:
                try:
                    dest, action = str(quarantine(path, score, why)), "quarantined"
                except OSError as e:
                    why = why + [f"could not be moved to quarantine: {e}"]
        elif score >= 40:
            action = "suspicious"
        else:
            action = "clean"
        self.on_result(str(path), score, why, action, dest)

    def run(self, stop):
        seen, pending = {}, {}
        for folder in self.folders:
            seen.update(snapshot(folder))
        self.notify("info", "Download protection is on. Watching "
                    + ", ".join(str(f) for f in self.folders))
        try:
            while not stop.wait(self.POLL):
                cur = {}
                for folder in self.folders:
                    cur.update(snapshot(folder))
                seen = {p: m for p, m in seen.items() if p in cur}
                pending = {p: v for p, v in pending.items() if p in cur}
                for p, meta in cur.items():
                    if seen.get(p) == meta:
                        continue
                    if os.path.splitext(p)[1].lower() in PARTIAL_EXT:
                        pending.pop(p, None)  # browser temp file; scanned once it is renamed
                        continue
                    entry = pending.get(p)
                    if entry and entry[0] == meta:
                        entry[1] += 1
                    else:
                        pending[p] = entry = [meta, 0]
                    if entry[1] >= self.SETTLE and self._readable(p):
                        pending.pop(p, None)
                        seen[p] = meta
                        self._handle(p)
        finally:
            self.notify("info", "Download protection stopped.")


# --------------------------------------------------------------------------- settings
def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except OSError:
        pass


# --------------------------------------------------------------------------- command line
def cmd_scan(args):
    if not os.path.exists(args.path):
        print(f"Path not found: {args.path}", file=sys.stderr)
        return 2
    bad = set()
    if args.hashes:
        try:
            bad = load_blocklist(args.hashes)
        except OSError as e:
            print(f"Cannot read blocklist: {e}", file=sys.stderr)
            return 2
        print(f"Loaded {len(bad):,} hashes.")
    rows, scanned, skipped = [], 0, 0
    for p in iter_files(args.path):
        scanned += 1
        try:
            score, why = analyze(p, bad, deep=args.deep)
        except OSError:
            skipped += 1
            continue
        if score >= args.min_score:
            rows.append((score, str(p), "; ".join(why)))
            print(f"[{score:3d}] {p}\n      - " + "\n      - ".join(why))
            if args.quarantine and score >= 70:
                try:
                    print(f"      -> quarantined as {quarantine(p, score, why).name}")
                except OSError as e:
                    print(f"      -> could not quarantine: {e}")
    print(f"\nScanned {scanned} files, flagged {len(rows)}, unreadable {skipped}.")
    if args.report:
        write_report(rows, args.report)
        print(f"Report written to {args.report}")
    return 1 if rows else 0


def cmd_check(args):
    bad = load_blocklist(args.hashes) if args.hashes else set()
    flagged = 0
    print("Checking programs that start automatically...")
    startup = check_persistence(bad)
    for r in startup:
        if r["score"] >= 40:
            flagged += 1
            print(f"[{r['score']:3d}] {r['where']}: {r['name']}\n      {r['command']}\n      - "
                  + "\n      - ".join(r["reasons"]))
    print(f"{len(startup)} startup items checked.\n\nChecking running programs...")
    procs, total, note = check_processes(bad)
    for r in procs:
        if r["score"] >= 40:
            flagged += 1
            print(f"[{r['score']:3d}] {r['name']} (pid {', '.join(map(str, r['pids'][:3]))}) {r['path']}\n      - "
                  + "\n      - ".join(r["reasons"]))
    print(note or f"{total} running programs checked.")
    print(f"\n{flagged} item(s) need attention." if flagged else "\nNothing suspicious found.")
    return 1 if flagged else 0


def cmd_guard(args):
    bad = load_blocklist(args.hashes) if args.hashes else set()
    folders = args.folders or [str(Path.home() / "Downloads")]
    for f in folders:
        if not os.path.isdir(f):
            print(f"Folder not found: {f}", file=sys.stderr)
            return 2

    def show(path, score, why, action, dest):
        name = os.path.basename(path)
        if action == "clean":
            print(f"[ OK ] {name}")
        elif action == "error":
            print(f"[ ?? ] {name}: {why[0] if why else ''}", file=sys.stderr)
        else:
            label = {"quarantined": "BLOCKED", "dangerous": "DANGEROUS", "suspicious": "SUSPICIOUS"}[action]
            print(f"\a[{label}] {name} (risk {score})\n      - " + "\n      - ".join(why), file=sys.stderr)
            if dest:
                print(f"      moved to quarantine: {dest}", file=sys.stderr)

    guard = DownloadGuard(folders, bad, not args.no_quarantine, show, lambda k, m: print(m))
    try:
        guard.run(threading.Event())
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_watch(args):
    if not os.path.isdir(args.folder):
        print(f"Folder not found: {args.folder}", file=sys.stderr)
        return 2

    def show(kind, msg):
        if kind == "alert":
            print(f"\a[ALERT {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr)
        else:
            print(msg)

    mon = RansomwareMonitor(args.folder, args.threshold, args.window, show)
    try:
        mon.run(threading.Event())
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Guardian - defensive anti-malware toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a file or folder")
    s.add_argument("path")
    s.add_argument("--hashes", help="text file with SHA-256 hashes of known malware")
    s.add_argument("--quarantine", action="store_true", help="quarantine files scoring 70+")
    s.add_argument("--deep", action="store_true",
                   help="also look inside programs, zip/Office/PDF files and scripts (slower)")
    s.add_argument("--min-score", type=int, default=40)
    s.add_argument("--report", help="write findings to a CSV file")
    s.set_defaults(fn=cmd_scan)
    c = sub.add_parser("check", help="check auto-start and running programs")
    c.add_argument("--hashes", help="text file with SHA-256 hashes of known malware")
    c.set_defaults(fn=cmd_check)
    gp = sub.add_parser("guard", help="scan every new download as soon as it finishes")
    gp.add_argument("folders", nargs="*", help="folders to watch (default: your Downloads folder)")
    gp.add_argument("--no-quarantine", action="store_true", help="only alert, never move files")
    gp.add_argument("--hashes", help="text file with SHA-256 hashes of known malware")
    gp.set_defaults(fn=cmd_guard)
    w = sub.add_parser("watch", help="live ransomware monitor for a folder")
    w.add_argument("folder")
    w.add_argument("--threshold", type=int, default=10)
    w.add_argument("--window", type=int, default=10)
    w.set_defaults(fn=cmd_watch)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()

