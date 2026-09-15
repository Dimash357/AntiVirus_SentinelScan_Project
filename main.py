import os
import re
import json
import hashlib
import subprocess
import tkinter as tk

from datetime import datetime
from tkinter import filedialog, messagebox
from tkinter import ttk


APP_NAME = "SentinelScan"
HISTORY_FILE = "sentinelscan_history.json"

BG = "#0b1220"
PANEL = "#111a2b"
PANEL2 = "#162238"
BORDER = "#263650"

TEXT = "#e6edf7"
MUTED = "#8ea0b8"

GREEN = "#31d17c"
YELLOW = "#f4c95d"
ORANGE = "#ff9f43"
RED = "#ff5c5c"
BLUE = "#4da3ff"

WHITE = "#ffffff"


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def format_size(size):
    if size < 1024:
        return f"{size} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"

    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"

    return f"{size / (1024 * 1024 * 1024):.2f} GB"


# ============================================================
# FINDING
# ============================================================

class Finding:

    def __init__(
        self,
        title,
        description,
        score=0,
        severity="INFO"
    ):
        self.title = title
        self.description = description
        self.score = score
        self.severity = severity

    def to_dict(self):
        return {
            "title": self.title,
            "description": self.description,
            "score": self.score,
            "severity": self.severity
        }


# ============================================================
# HEURISTICS
# ============================================================

SUSPICIOUS_PATTERNS = [

    (
        rb"powershell",
        "PowerShell reference",
        "The file references PowerShell.",
        3
    ),

    (
        rb"cmd\.exe\s*/c",
        "Command shell execution",
        "The file contains a cmd.exe /c execution pattern.",
        3
    ),

    (
        rb"wscript",
        "Windows Script Host",
        "The file references wscript.",
        3
    ),

    (
        rb"cscript",
        "Windows Script Host",
        "The file references cscript.",
        3
    ),

    (
        rb"rundll32",
        "Rundll32 execution",
        "The file references rundll32.",
        4
    ),

    (
        rb"regsvr32",
        "Regsvr32 execution",
        "The file references regsvr32.",
        4
    ),

    (
        rb"mshta",
        "MSHTA execution",
        "The file references mshta.",
        4
    ),

    (
        rb"frombase64string",
        "Base64 PowerShell pattern",
        "The file contains FromBase64String.",
        4
    ),

    (
        rb"downloadstring",
        "PowerShell download pattern",
        "The file contains DownloadString.",
        4
    ),

    (
        rb"invoke-expression",
        "PowerShell Invoke-Expression",
        "The file contains Invoke-Expression.",
        4
    )
]


def heuristics(path):

    findings = []

    try:
        with open(path, "rb") as f:
            data = f.read()

    except Exception as e:

        findings.append(
            Finding(
                "File read error",
                str(e),
                0,
                "ERROR"
            )
        )

        return findings

    filename = os.path.basename(path).lower()

    # --------------------------------------------------------
    # EXE
    # --------------------------------------------------------

    if filename.endswith(".exe"):

        findings.append(
            Finding(
                "Windows executable",
                "The file has an .exe extension.",
                0,
                "INFO"
            )
        )

    # --------------------------------------------------------
    # PE
    # --------------------------------------------------------

    if data[:2] == b"MZ":

        findings.append(
            Finding(
                "Windows PE executable",
                "The file contains the Windows MZ executable signature.",
                0,
                "INFO"
            )
        )

        if len(data) >= 0x40:

            try:

                pe_offset = int.from_bytes(
                    data[0x3C:0x40],
                    "little"
                )

                if (
                    pe_offset + 4 <= len(data)
                    and data[pe_offset:pe_offset + 4] == b"PE\x00\x00"
                ):

                    findings.append(
                        Finding(
                            "Valid PE header",
                            "A valid Windows PE header was detected.",
                            0,
                            "INFO"
                        )
                    )

            except Exception:
                pass

    # --------------------------------------------------------
    # DOUBLE EXTENSIONS
    # --------------------------------------------------------

    suspicious_extensions = [
        ".pdf.exe",
        ".doc.exe",
        ".docx.exe",
        ".xls.exe",
        ".xlsx.exe",
        ".jpg.exe",
        ".jpeg.exe",
        ".png.exe",
        ".txt.exe",
        ".zip.exe",
        ".rar.exe"
    ]

    for ext in suspicious_extensions:

        if filename.endswith(ext):

            findings.append(
                Finding(
                    "Suspicious double extension",
                    f"The filename ends with {ext}.",
                    6,
                    "HIGH"
                )
            )

            break

    # --------------------------------------------------------
    # SUSPICIOUS COMMANDS
    # --------------------------------------------------------

    lower_data = data.lower()

    for (
        pattern,
        title,
        description,
        score
    ) in SUSPICIOUS_PATTERNS:

        if re.search(pattern, lower_data):

            findings.append(
                Finding(
                    title,
                    description,
                    score,
                    "MEDIUM"
                )
            )

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    urls = re.findall(
        rb"https?://[^\s\x00\"'<>]+",
        lower_data
    )

    if urls:

        findings.append(
            Finding(
                "Embedded URL",
                f"Found {len(urls)} URL-like string(s).",
                2,
                "LOW"
            )
        )

    # --------------------------------------------------------
    # HEAVY SCRIPT CONTENT
    # --------------------------------------------------------

    script_keywords = [
        b"powershell",
        b"javascript",
        b"vbscript",
        b"wscript",
        b"cscript"
    ]

    keyword_count = sum(
        lower_data.count(keyword)
        for keyword in script_keywords
    )

    if keyword_count >= 10:

        findings.append(
            Finding(
                "Heavy scripting content",
                f"Multiple scripting strings found ({keyword_count}).",
                4,
                "MEDIUM"
            )
        )

    return findings


# ============================================================
# PE INFORMATION
# ============================================================

def get_pe_info(path):

    result = {
        "is_pe": False,
        "architecture": "Unknown",
        "sections": None
    }

    try:

        with open(path, "rb") as f:
            data = f.read()

        if data[:2] != b"MZ":
            return result

        result["is_pe"] = True

        if len(data) < 0x40:
            return result

        pe_offset = int.from_bytes(
            data[0x3C:0x40],
            "little"
        )

        if pe_offset + 24 > len(data):
            return result

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return result

        machine = int.from_bytes(
            data[pe_offset + 4:pe_offset + 6],
            "little"
        )

        sections = int.from_bytes(
            data[pe_offset + 6:pe_offset + 8],
            "little"
        )

        result["sections"] = sections

        architectures = {
            0x014C: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0xAA64: "ARM64",
            0x01C4: "ARM"
        }

        result["architecture"] = architectures.get(
            machine,
            f"Unknown (0x{machine:04X})"
        )

    except Exception:
        pass

    return result


# ============================================================
# MICROSOFT DEFENDER
# ============================================================

def find_defender():

    candidates = []

    program_files = os.environ.get(
        "ProgramFiles",
        r"C:\Program Files"
    )

    program_data = os.environ.get(
        "ProgramData",
        r"C:\ProgramData"
    )

    candidates.append(
        os.path.join(
            program_files,
            "Windows Defender",
            "MpCmdRun.exe"
        )
    )

    platform_dir = os.path.join(
        program_data,
        "Microsoft",
        "Windows Defender",
        "Platform"
    )

    if os.path.isdir(platform_dir):

        try:

            versions = os.listdir(platform_dir)

            versions.sort(reverse=True)

            for version in versions:

                candidates.append(
                    os.path.join(
                        platform_dir,
                        version,
                        "MpCmdRun.exe"
                    )
                )

        except Exception:
            pass

    for candidate in candidates:

        if os.path.isfile(candidate):
            return candidate

    return None


def defender_scan(path):

    exe = find_defender()

    if not exe:

        return {
            "available": False,
            "success": False,
            "detected": False,
            "error": "MpCmdRun.exe not found.",
            "output": ""
        }

    try:

        result = subprocess.run(
            [
                exe,
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                path
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300
        )

        output = (
            result.stdout +
            "\n" +
            result.stderr
        ).strip()

        # IMPORTANT:
        # We don't consider every non-zero code malicious.
        # Defender can return different codes for different
        # conditions.

        output_lower = output.lower()

        threat_words = [
            "threat detected",
            "threats detected",
            "malware detected",
            "virus detected",
            "угроза обнаружена",
            "обнаружена угроза",
            "вредоносная программа"
        ]

        detected = any(
            word in output_lower
            for word in threat_words
        )

        return {
            "available": True,
            "success": True,
            "detected": detected,
            "error": None,
            "output": output,
            "returncode": result.returncode
        }

    except subprocess.TimeoutExpired:

        return {
            "available": True,
            "success": False,
            "detected": False,
            "error": "Defender scan timed out.",
            "output": ""
        }

    except Exception as e:

        return {
            "available": True,
            "success": False,
            "detected": False,
            "error": str(e),
            "output": ""
        }


# ============================================================
# YARA
# ============================================================

def yara_scan(path):

    try:
        import yara

    except ImportError:

        return {
            "available": False,
            "success": False,
            "detected": False,
            "error": "yara-python is not installed.",
            "matches": []
        }

    rules_source = r'''
rule Suspicious_PowerShell
{
    strings:
        $a = "powershell" nocase
        $b = "Invoke-Expression" nocase
        $c = "DownloadString" nocase
        $d = "FromBase64String" nocase

    condition:
        2 of them
}

rule Suspicious_LivingOffTheLand
{
    strings:
        $a = "rundll32" nocase
        $b = "regsvr32" nocase
        $c = "mshta" nocase
        $d = "wscript" nocase
        $e = "cscript" nocase

    condition:
        2 of them
}
'''

    try:

        rules = yara.compile(
            source=rules_source
        )

        matches = rules.match(
            path,
            timeout=30
        )

        names = [
            match.rule
            for match in matches
        ]

        return {
            "available": True,
            "success": True,
            "detected": bool(matches),
            "error": None,
            "matches": names
        }

    except Exception as e:

        return {
            "available": True,
            "success": False,
            "detected": False,
            "error": str(e),
            "matches": []
        }


# ============================================================
# VERDICT
# ============================================================

def calculate_verdict(
    heuristic_score,
    defender,
    yara
):

    # Defender confirmation has priority.

    if (
        defender.get("success")
        and defender.get("detected")
    ):

        return "MALICIOUS", heuristic_score

    score = heuristic_score

    # YARA match contributes +5.

    if (
        yara.get("success")
        and yara.get("detected")
    ):

        score += 5

    if score >= 10:

        verdict = "SUSPICIOUS"

    elif score >= 4:

        verdict = "LOW RISK"

    else:

        scanner_worked = (
            defender.get("success")
            or yara.get("success")
        )

        if scanner_worked:
            verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

    return verdict, score


# ============================================================
# HISTORY
# ============================================================

def save_history(result):

    history = []

    if os.path.exists(HISTORY_FILE):

        try:

            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                history = json.load(f)

                if not isinstance(history, list):
                    history = []

        except Exception:

            history = []

    history.append(result)

    history = history[-100:]

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                history,
                f,
                indent=2,
                ensure_ascii=False
            )

    except Exception:
        pass


# ============================================================
# SCAN
# ============================================================

def scan_file(path):

    size = os.path.getsize(path)

    sha256 = sha256_file(path)

    findings = heuristics(path)

    heuristic_score = sum(
        finding.score
        for finding in findings
    )

    pe_info = get_pe_info(path)

    defender = defender_scan(path)

    yara = yara_scan(path)

    verdict, risk_score = calculate_verdict(
        heuristic_score,
        defender,
        yara
    )

    result = {

        "timestamp": datetime.now().isoformat(),

        "file": path,

        "filename": os.path.basename(path),

        "size": size,

        "sha256": sha256,

        "verdict": verdict,

        "risk_score": risk_score,

        "pe_info": pe_info,

        "defender": defender,

        "yara": yara,

        "findings": [
            finding.to_dict()
            for finding in findings
        ]
    }

    save_history(result)

    return result


# ============================================================
# GUI
# ============================================================

class SentinelScanApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "SentinelScan"
        )

        self.root.geometry(
            "1100x760"
        )

        self.root.minsize(
            900,
            650
        )

        self.root.configure(
            bg=BG
        )

        self.selected_file = None

        self.result = None

        self.setup_style()

        self.build_gui()

    # ========================================================
    # STYLE
    # ========================================================

    def setup_style(self):

        style = ttk.Style()

        style.theme_use("clam")

        style.configure(
            "Dark.Horizontal.TProgressbar",
            troughcolor=PANEL2,
            background=BLUE,
            bordercolor=PANEL2,
            lightcolor=BLUE,
            darkcolor=BLUE
        )

    # ========================================================
    # GUI
    # ========================================================

    def build_gui(self):
        header = tk.Frame(
            self.root,
            bg=BG
        )

        header.pack(
            fill="x",
            padx=28,
            pady=(22, 12)
        )

        logo = tk.Label(
            header,
            text="◈",
            fg=BLUE,
            bg=BG,
            font=("Segoe UI", 28, "bold")
        )

        logo.pack(
            side="left",
            padx=(0, 12)
        )

        title_frame = tk.Frame(
            header,
            bg=BG
        )

        title_frame.pack(
            side="left"
        )

        tk.Label(
            title_frame,
            text="SentinelScan",
            fg=TEXT,
            bg=BG,
            font=("Segoe UI", 22, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            title_frame,
            text="Windows Malware Scanner",
            fg=MUTED,
            bg=BG,
            font=("Segoe UI", 10)
        ).pack(
            anchor="w"
        )

        # ----------------------------------------------------
        # FILE BAR
        # ----------------------------------------------------

        file_panel = tk.Frame(
            self.root,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        file_panel.pack(
            fill="x",
            padx=28,
            pady=8
        )

        self.file_label = tk.Label(
            file_panel,
            text="No file selected",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 10),
            anchor="w"
        )

        self.file_label.pack(
            side="left",
            fill="x",
            expand=True,
            padx=16,
            pady=13
        )

        self.scan_button = tk.Button(
            file_panel,
            text="SCAN",
            command=self.start_scan,
            bg=BLUE,
            fg=WHITE,
            activebackground=BLUE,
            activeforeground=WHITE,
            relief="flat",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            padx=22,
            pady=8,
            state=tk.DISABLED
        )

        self.scan_button.pack(
            side="right",
            padx=(5, 10),
            pady=7
        )

        self.choose_button = tk.Button(
            file_panel,
            text="Choose file",
            command=self.choose_file,
            bg=PANEL2,
            fg=TEXT,
            activebackground=BORDER,
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            font=("Segoe UI", 10),
            padx=15,
            pady=8
        )

        self.choose_button.pack(
            side="right",
            padx=5,
            pady=7
        )

        # ----------------------------------------------------
        # MAIN CONTENT
        # ----------------------------------------------------

        main = tk.Frame(
            self.root,
            bg=BG
        )

        main.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=10
        )

        main.grid_columnconfigure(
            0,
            weight=1
        )

        main.grid_columnconfigure(
            1,
            weight=2
        )

        main.grid_rowconfigure(
            0,
            weight=1
        )

        # ----------------------------------------------------
        # LEFT
        #         ----------------------------------------------------

        left = tk.Frame(
            main,
            bg=BG
        )

        left.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8)
        )

        # Risk card

        self.risk_card = tk.Frame(
            left,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        self.risk_card.pack(
            fill="x",
            pady=(0, 10)
        )

        tk.Label(
            self.risk_card,
            text="RISK SCORE",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 10, "bold")
        ).pack(
            pady=(18, 2)
        )

        self.risk_number = tk.Label(
            self.risk_card,
            text="—",
            fg=TEXT,
            bg=PANEL,
            font=("Segoe UI", 42, "bold")
        )

        self.risk_number.pack()

        self.verdict_label = tk.Label(
            self.risk_card,
            text="WAITING FOR SCAN",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 12, "bold")
        )

        self.verdict_label.pack(
            pady=(0, 15)
        )

        self.progress = ttk.Progressbar(
            self.risk_card,
            style="Dark.Horizontal.TProgressbar",
            orient="horizontal",
            mode="determinate",
            maximum=20
        )

        self.progress.pack(
            fill="x",
            padx=22,
            pady=(0, 8)
        )

        self.risk_description = tk.Label(
            self.risk_card,
            text="Select a file to begin",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 9),
            wraplength=300
        )

        self.risk_description.pack(
            padx=20,
            pady=(0, 18)
        )

        # Scanner cards

        self.defender_card = self.create_scanner_card(
            left,
            "Microsoft Defender"
        )

        self.yara_card = self.create_scanner_card(
            left,
            "YARA"
        )

        # ----------------------------------------------------
        # RIGHT
        # ----------------------------------------------------

        right = tk.Frame(
            main,
            bg=BG
        )

        right.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(8, 0)
        )

        # File information

        info_panel = tk.Frame(
            right,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        info_panel.pack(
            fill="x",
            pady=(0, 10)
        )

        tk.Label(
            info_panel,
            text="FILE INFORMATION",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 10, "bold")
        ).pack(
            anchor="w",
            padx=18,
            pady=(15, 8)
        )

        self.info_text = tk.Label(
            info_panel,
            text="No file selected",
            fg=TEXT,
            bg=PANEL,
            justify="left",
            anchor="w",
            font=("Consolas", 9)
        )

        self.info_text.pack(
            fill="x",
            padx=18,
            pady=(0, 15)
        )

        # Findings

        findings_panel = tk.Frame(
            right,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        findings_panel.pack(
            fill="both",
            expand=True
        )

        top = tk.Frame(
            findings_panel,
            bg=PANEL
        )

        top.pack(
            fill="x"
        )

        tk.Label(
            top,
            text="RISK FINDINGS",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left",
            padx=18,
            pady=15
        )

        self.finding_count = tk.Label(
            top,
            text="0",
            fg=TEXT,
            bg=PANEL2,
            font=("Segoe UI", 9, "bold"),
            padx=9,
            pady=3
        )

        self.finding_count.pack(
            side="right",
            padx=18
        )

        self.findings_canvas = tk.Canvas(
            findings_panel,
            bg=PANEL,
            highlightthickness=0
        )

        self.findings_scroll = ttk.Scrollbar(
            findings_panel,
            orient="vertical",
            command=self.findings_canvas.yview
        )

        self.findings_frame = tk.Frame(
            self.findings_canvas,
            bg=PANEL
        )

        self.findings_window = self.findings_canvas.create_window(
            (0, 0),
            window=self.findings_frame,
            anchor="nw"
        )

        self.findings_canvas.configure(
            yscrollcommand=self.findings_scroll.set
        )

        self.findings_frame.bind(
            "<Configure>",
            lambda e: self.findings_canvas.configure(
                scrollregion=self.findings_canvas.bbox("all")
            )
        )

        self.findings_canvas.bind(
            "<Configure>",
            self.resize_findings
        )

        self.findings_canvas.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(12, 0),
            pady=(0, 12)
        )

        self.findings_scroll.pack(
            side="right",
            fill="y",
            padx=(0, 8),
            pady=(0, 12)
        )

        self.status = tk.Label(
            self.root,
            text="Ready",
            fg=MUTED,
            bg=BG,
            anchor="w",
            font=("Segoe UI", 9)
        )

        self.status.pack(
            fill="x",
            padx=30,
            pady=(0, 12)
        )

    # ========================================================
    # SCANNER CARD
    # ========================================================

    def create_scanner_card(
        self,
        parent,
        name
    ):

        frame = tk.Frame(
            parent,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        frame.pack(
            fill="x",
            pady=5
        )

        label = tk.Label(
            frame,
            text=name,
            fg=TEXT,
            bg=PANEL,
            font=("Segoe UI", 10, "bold")
        )

        label.pack(
            side="left",
            padx=15,
            pady=14
        )

        state = tk.Label(
            frame,
            text="NOT RUN",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 9, "bold")
        )

        state.pack(
            side="right",
            padx=15
        )

        return {
            "frame": frame,
            "label": label,
            "state": state
        }

    # ========================================================
    # RESIZE
    # ========================================================

    def resize_findings(self, event):

        self.findings_canvas.itemconfigure(
            self.findings_window,
            width=event.width
        )

    # ========================================================
    # CHOOSE FILE
    # ========================================================

    def choose_file(self):

        path = filedialog.askopenfilename(
            title="Select file"
        )

        if not path:
            return

        self.selected_file = path

        self.file_label.config(
            text=path,
            fg=TEXT
        )

        self.scan_button.config(
            state=tk.NORMAL
        )

        self.status.config(
            text="File selected. Ready to scan."
        )

    # ========================================================
    # SCAN
    # ========================================================

    def start_scan(self):

        if not self.selected_file:
            return

        self.scan_button.config(
            state=tk.DISABLED
        )

        self.choose_button.config(
            state=tk.DISABLED
        )

        self.status.config(
            text="Scanning..."
        )

        self.root.update_idletasks()

        try:

            result = scan_file(
                self.selected_file
            )

            self.result = result

            self.update_gui(result)

            self.status.config(
                text="Scan completed."
            )

        except Exception as e:

            messagebox.showerror(
                "Scan error",
                str(e)
            )

            self.status.config(
                text="Scan failed."
            )

        finally:

            self.scan_button.config(
                state=tk.NORMAL
            )

            self.choose_button.config(
                state=tk.NORMAL
            )

    # ========================================================
    # UPDATE GUI
    # ========================================================

    def update_gui(self, result):

        verdict = result["verdict"]

        score = result["risk_score"]

        # ----------------------------------------------------
        # Risk color
        # ----------------------------------------------------

        colors = {
            "CLEAN": GREEN,
            "LOW RISK": YELLOW,
            "SUSPICIOUS": ORANGE,
            "MALICIOUS": RED,
            "UNKNOWN": MUTED
        }

        color = colors.get(
            verdict,
            MUTED
        )

        # ----------------------------------------------------
        # Risk number
        # ----------------------------------------------------

        self.risk_number.config(
            text=str(score),
            fg=color
        )

        self.verdict_label.config(
            text=verdict,
            fg=color
        )

        self.progress["value"] = min(
            score,
            20
        )

        # ----------------------------------------------------
        # Description
        # ----------------------------------------------------

        descriptions = {

            "CLEAN":
                "No known threat was detected and the static risk score is low.",

            "LOW RISK":
                "Some potentially suspicious characteristics were detected.",

            "SUSPICIOUS":
                "Multiple suspicious indicators were detected. Treat the file with caution.",

            "MALICIOUS":
                "Microsoft Defender reported a threat. Do not execute this file.",

            "UNKNOWN":
                "No scanner completed successfully. The result cannot be trusted."
        }

        self.risk_description.config(
            text=descriptions.get(
                verdict,
                ""
            )
        )

        # ----------------------------------------------------
        # File information
        # ----------------------------------------------------

        pe = result["pe_info"]

        info = (
            f"Name:       {result['filename']}\n"
            f"Size:       {format_size(result['size'])}\n"
            f"SHA-256:    {result['sha256']}\n"
            f"PE:         {'YES' if pe['is_pe'] else 'NO'}\n"
        )

        if pe["is_pe"]:

            info += (
                f"Arch:       {pe['architecture']}\n"
                f"Sections:   {pe['sections']}\n"
            )

        self.info_text.config(
            text=info
        )

        # ----------------------------------------------------
        # Defender
        # ----------------------------------------------------

        defender = result["defender"]

        if not defender["available"]:

            self.set_scanner_state(
                self.defender_card,
                "NOT FOUND",
                MUTED
            )

        elif not defender["success"]:

            self.set_scanner_state(
                self.defender_card,
                "ERROR",
                ORANGE
            )

        elif defender["detected"]:

            self.set_scanner_state(
                self.defender_card,
                "THREAT",
                RED
            )

        else:

            self.set_scanner_state(
                self.defender_card,
                "CLEAN",
                GREEN
            )

        # ----------------------------------------------------
        # YARA
        # ----------------------------------------------------

        yara = result["yara"]

        if not yara["available"]:

            self.set_scanner_state(
                self.yara_card,
                "NOT INSTALLED",
                MUTED
            )

        elif not yara["success"]:

            self.set_scanner_state(
                self.yara_card,
                "ERROR",
                ORANGE
            )

        elif yara["detected"]:

            self.set_scanner_state(
                self.yara_card,
                "MATCH",
                ORANGE
            )

        else:

            self.set_scanner_state(
                self.yara_card,
                "CLEAN",
                GREEN
            )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        self.show_findings(
            result["findings"],
            yara
        )

    # ========================================================
    # SCANNER STATE
    # ========================================================

    def set_scanner_state(
        self,
        card,
        text,
        color
    ):

        card["state"].config(
            text=text,
            fg=color
        )

    # ========================================================
    # FINDINGS
    # ========================================================

    def show_findings(
        self,
        findings,
        yara
    ):

        for widget in self.findings_frame.winfo_children():

            widget.destroy()

        total = len(findings)

        if yara.get("detected"):

            total += len(
                yara.get(
                    "matches",
                    []
                )
            )

        self.finding_count.config(
            text=str(total)
        )

        # ----------------------------------------------------
        # YARA matches
        # ----------------------------------------------------

        for match in yara.get(
            "matches",
            []
        ):

            self.create_finding(
                "YARA MATCH",
                match,
                "+5",
                ORANGE
            )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        for finding in findings:

            score = finding["score"]

            severity = finding["severity"]

            if severity == "HIGH":

                color = RED

            elif severity == "MEDIUM":

                color = ORANGE

            elif severity == "LOW":

                color = YELLOW

            else:

                color = MUTED

            if score > 0:

                score_text = f"+{score}"

            else:

                score_text = "INFO"

            self.create_finding(
                finding["title"],
                finding["description"],
                score_text,
                color
            )

        if total == 0:

            tk.Label(
                self.findings_frame,
                text="No risk indicators found.",
                fg=GREEN,
                bg=PANEL,
                font=("Segoe UI", 10)
            ).pack(
                pady=30
            )

    def create_finding(
        self,
        title,
        description,
        score,
        color
    ):

        frame = tk.Frame(
            self.findings_frame,
            bg=PANEL2,
            highlightbackground=BORDER,
            highlightthickness=1
        )

        frame.pack(
            fill="x",
            pady=5,
            padx=5
        )

        score_label = tk.Label(
            frame,
            text=score,
            fg=color,
            bg=PANEL2,
            font=("Segoe UI", 10, "bold"),
            width=5
        )

        score_label.pack(
            side="left",
            padx=(10, 5),
            pady=12
        )

        text_frame = tk.Frame(
            frame,
            bg=PANEL2
        )

        text_frame.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5,
            pady=10
        )

        tk.Label(
            text_frame,
            text=title,
            fg=TEXT,
            bg=PANEL2,
            font=("Segoe UI", 10, "bold"),
            anchor="w"
        ).pack(
            fill="x"
        )

        tk.Label(
            text_frame,
            text=description,
            fg=MUTED,
            bg=PANEL2,
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=550
        ).pack(
            fill="x",
            pady=(2, 0)
        )


if __name__ == "__main__":

    root = tk.Tk()

    app = SentinelScanApp(
        root
    )

    root.mainloop()