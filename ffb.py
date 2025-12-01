import ctypes
import sys

# ------------------------ Admin Elevation ------------------------ #

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Relaunch the script with admin privileges
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1
    )
    sys.exit(0)

# ------------------------ Imports ------------------------ #

import os
import json
import hashlib
import subprocess
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QFileDialog, QLineEdit, QLabel, QCheckBox, QListWidget,
    QListWidgetItem, QMessageBox, QTextEdit, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject


# ------------------------ Constants & Helpers ------------------------ #

APP_NAME = "PyFolderFirewallBlocker"
RULES_FILE_NAME = "pyffb_rules.json"
SNAPSHOT_FILE_NAME = "pyffb_firewall_snapshot.wfw"

# Default "executable" extensions (like classic FFB)
DEFAULT_EXTENSIONS = [
    ".exe", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".msc", ".scr", ".msi", ".cpl", ".ocx", ".dll",
    ".drv", ".sys"
]


def get_app_dir() -> Path:
    """
    Use the script's directory for portability (works well with PyInstaller).
    """
    if getattr(sys, 'frozen', False):
        # Running from PyInstaller bundle
        return Path(sys.executable).parent
    else:
        return Path(__file__).parent


APP_DIR = get_app_dir()
RULES_PATH = APP_DIR / RULES_FILE_NAME
SNAPSHOT_PATH = APP_DIR / SNAPSHOT_FILE_NAME


def is_windows() -> bool:
    return os.name == "nt"


def hash_path(path: str) -> str:
    """
    Stable short hash from normalized path for rule names.
    """
    norm = os.path.normcase(os.path.abspath(path))
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:8]


# ------------------------ Rule Registry ------------------------ #

class RuleRegistry:
    """
    Tracks which rules this app has created so we can reverse them safely.
    JSON structure:
    {
      "rules": [
        {
          "path": "C:\\foo\\bar.exe",
          "rule_out": "PyFFB_OUT_xxxxxxxx",
          "rule_in": "PyFFB_IN_xxxxxxxx"
        },
        ...
      ]
    }
    """

    def __init__(self, json_path: Path):
        self.json_path = json_path
        self.rules = {}  # path -> {"rule_out": ..., "rule_in": ...}
        self._load()

    def _load(self):
        if self.json_path.exists():
            try:
                with self.json_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                for entry in data.get("rules", []):
                    path = entry.get("path")
                    if path:
                        self.rules[path] = {
                            "rule_out": entry.get("rule_out"),
                            "rule_in": entry.get("rule_in"),
                        }
            except Exception:
                # Corrupt file: start fresh but don't crash.
                self.rules = {}

    def save(self):
        data = {
            "rules": [
                {"path": p, "rule_out": v.get("rule_out"), "rule_in": v.get("rule_in")}
                for p, v in self.rules.items()
            ]
        }
        try:
            with self.json_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to save rules JSON: {e}", file=sys.stderr)

    def has_rules_for(self, path: str) -> bool:
        return path in self.rules

    def get_rules_for(self, path: str):
        return self.rules.get(path)

    def set_rules_for(self, path: str, rule_out: str, rule_in: str):
        self.rules[path] = {"rule_out": rule_out, "rule_in": rule_in}

    def remove_path(self, path: str):
        if path in self.rules:
            del self.rules[path]

    def all_entries(self):
        return list(self.rules.items())

    def clear(self):
        self.rules.clear()


# ------------------------ Firewall Manager ------------------------ #

class FirewallManager:
    """
    Simple wrapper around `netsh advfirewall` for add/delete and snapshot.
    No external libs, just subprocess.
    """

    def __init__(self, parent_widget=None):
        self.parent_widget = parent_widget

    def _run_netsh(self, args):
        cmd = ["netsh"] + args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False
            )
            return proc
        except FileNotFoundError:
            self._show_error("netsh not found. Are you on Windows?")
            return None

    def _show_error(self, message: str):
        if self.parent_widget is not None:
            QMessageBox.critical(self.parent_widget, "Error", message)
        else:
            print("ERROR:", message, file=sys.stderr)

    def add_block_rules_for_file(self, path: str):
        """
        Add inbound & outbound block rules for a given file path.
        Returns (rule_out, rule_in) or (None, None) on failure.
        """
        if not is_windows():
            self._show_error("This tool only works on Windows.")
            return None, None

        if not os.path.exists(path):
            self._show_error(f"File not found: {path}")
            return None, None

        safe_path = os.path.abspath(path)
        h = hash_path(safe_path)
        rule_out = f"PyFFB_OUT_{h}"
        rule_in = f"PyFFB_IN_{h}"

        # Outbound
        args_out = [
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_out}",
            "dir=out",
            "action=block",
            f"program={safe_path}",
            "enable=yes",
            "profile=any"
        ]
        # Inbound
        args_in = [
            "advfirewall", "firewall", "add", "rule",
            f"name={rule_in}",
            "dir=in",
            "action=block",
            f"program={safe_path}",
            "enable=yes",
            "profile=any"
        ]

        proc_out = self._run_netsh(args_out)
        if not proc_out or proc_out.returncode != 0:
            self._show_error(
                f"Failed to add outbound rule for:\n{safe_path}\n\n"
                f"Output:\n{proc_out.stdout}\nError:\n{proc_out.stderr}"
                if proc_out else "Unknown netsh error."
            )
            return None, None

        proc_in = self._run_netsh(args_in)
        if not proc_in or proc_in.returncode != 0:
            self._show_error(
                f"Failed to add inbound rule for:\n{safe_path}\n\n"
                f"Output:\n{proc_in.stdout}\nError:\n{proc_in.stderr}"
                if proc_in else "Unknown netsh error."
            )
            # Best-effort cleanup of outbound rule
            self.delete_rule(rule_out)
            return None, None

        return rule_out, rule_in

    def delete_rule(self, rule_name: str):
        """
        Delete a single firewall rule by name.
        """
        if not is_windows():
            return

        args = [
            "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        self._run_netsh(args)
        # No hard error if it fails (rule might not exist).

    def export_snapshot(self, snapshot_path: Path):
        """
        Export all current firewall policy to a .wfw snapshot.
        """
        if not is_windows():
            self._show_error("This tool only works on Windows.")
            return False

        args = [
            "advfirewall", "export", str(snapshot_path)
        ]
        proc = self._run_netsh(args)
        if not proc or proc.returncode != 0:
            self._show_error(
                f"Failed to export firewall snapshot.\n\n"
                f"Output:\n{proc.stdout}\nError:\n{proc.stderr}"
                if proc else "Unknown netsh error."
            )
            return False
        return True

    def import_snapshot(self, snapshot_path: Path):
        """
        Import a previously exported firewall snapshot (.wfw).
        This overwrites current firewall rules.
        """
        if not is_windows():
            self._show_error("This tool only works on Windows.")
            return False

        if not snapshot_path.exists():
            self._show_error(f"Snapshot file not found:\n{snapshot_path}")
            return False

        args = [
            "advfirewall", "import", str(snapshot_path)
        ]
        proc = self._run_netsh(args)
        if not proc or proc.returncode != 0:
            self._show_error(
                f"Failed to import firewall snapshot.\n\n"
                f"Output:\n{proc.stdout}\nError:\n{proc.stderr}"
                if proc else "Unknown netsh error."
            )
            return False
        return True


# ------------------------ Worker for Threaded Blocking ------------------------ #

class BlockWorker(QObject):
    progress = pyqtSignal(int, str)       # (index, file_path)
    finished = pyqtSignal(int, int)       # (blocked_count, skipped_count)
    cancelled = pyqtSignal()

    def __init__(self, files, registry: RuleRegistry, firewall: FirewallManager):
        super().__init__()
        self.files = files
        self.registry = registry
        self.firewall = firewall
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        blocked_count = 0
        skipped_count = 0
        total = len(self.files)

        for index, path in enumerate(self.files, start=1):
            if self._cancel:
                self.cancelled.emit()
                return

            if self.registry.has_rules_for(path):
                skipped_count += 1
            else:
                rule_out, rule_in = self.firewall.add_block_rules_for_file(path)
                if rule_out and rule_in:
                    self.registry.set_rules_for(path, rule_out, rule_in)
                    blocked_count += 1

            self.progress.emit(index, path)

        self.finished.emit(blocked_count, skipped_count)


# ------------------------ Main Window ------------------------ #

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(f"{APP_NAME} (Python)")
        self.resize(900, 650)

        self.registry = RuleRegistry(RULES_PATH)
        self.firewall = FirewallManager(parent_widget=self)

        self.current_folder = ""
        self.file_list = []  # List of file paths from last scan

        self.thread = None
        self.worker = None

        self._build_ui()

    # ---------- UI Construction ---------- #

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Folder selector row
        folder_layout = QHBoxLayout()
        self.folder_edit = QLineEdit()
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.on_browse)

        folder_layout.addWidget(QLabel("Target folder:"))
        folder_layout.addWidget(self.folder_edit)
        folder_layout.addWidget(browse_btn)
        layout.addLayout(folder_layout)

        # Options row
        options_layout = QHBoxLayout()
        self.recursive_checkbox = QCheckBox("Include subfolders (recursive)")
        self.recursive_checkbox.setChecked(True)

        self.extra_types_edit = QLineEdit()
        self.extra_types_edit.setPlaceholderText("Extra types (e.g. .py,.txt)")
        options_layout.addWidget(self.recursive_checkbox)
        options_layout.addWidget(QLabel("Extra file types:"))
        options_layout.addWidget(self.extra_types_edit)
        layout.addLayout(options_layout)

        # Info label
        self.info_label = QLabel(
            "Default types: " + ", ".join(DEFAULT_EXTENSIONS)
        )
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        # Buttons row
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Folder")
        self.scan_btn.clicked.connect(self.on_scan)

        self.block_all_btn = QPushButton("Block ALL")
        self.block_all_btn.clicked.connect(self.on_block_all)

        self.unblock_selected_btn = QPushButton("Unblock Selected")
        self.unblock_selected_btn.clicked.connect(self.on_unblock_selected)

        self.unblock_all_btn = QPushButton("Unblock ALL (created by this app)")
        self.unblock_all_btn.clicked.connect(self.on_unblock_all)

        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.block_all_btn)
        btn_layout.addWidget(self.unblock_selected_btn)
        btn_layout.addWidget(self.unblock_all_btn)
        layout.addLayout(btn_layout)

        # Firewall snapshot buttons
        snap_layout = QHBoxLayout()
        self.snapshot_export_btn = QPushButton("Export Firewall Snapshot")
        self.snapshot_export_btn.clicked.connect(self.on_snapshot_export)

        self.snapshot_import_btn = QPushButton("Import Firewall Snapshot")
        self.snapshot_import_btn.clicked.connect(self.on_snapshot_import)

        snap_layout.addWidget(self.snapshot_export_btn)
        snap_layout.addWidget(self.snapshot_import_btn)
        layout.addLayout(snap_layout)

        # Progress display
        self.progress_label = QLabel("")
        self.progress_label.setVisible(False)
        layout.addWidget(self.progress_label)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self.cancel_blocking)
        layout.addWidget(self.cancel_button)

        # File list
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.ExtendedSelection)
        layout.addWidget(self.list_widget)

        # Status / log
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setPlaceholderText("Log output...")
        layout.addWidget(self.log_edit)

        self.append_log("Ready. Running with Administrator privileges.")

    # ---------- Logging ---------- #

    def append_log(self, message: str):
        self.log_edit.append(message)

    # ---------- UI Handlers ---------- #

    def on_browse(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Select Folder", self.folder_edit.text() or str(Path.home())
        )
        if directory:
            self.folder_edit.setText(directory)

    def on_scan(self):
        folder = self.folder_edit.text().strip()
        if not folder:
            QMessageBox.warning(self, "No Folder", "Please select a folder first.")
            return

        if not os.path.isdir(folder):
            QMessageBox.warning(self, "Invalid Folder", "That path is not a folder.")
            return

        self.current_folder = folder
        recursive = self.recursive_checkbox.isChecked()
        exts = self._get_effective_extensions()

        self.append_log(
            f"Scanning folder: {folder} (recursive={recursive}) "
            f"for extensions: {', '.join(exts)}"
        )

        files = self._scan_folder(folder, exts, recursive)
        self.file_list = files
        self._populate_list_widget()

        self.append_log(f"Scan complete. Found {len(files)} matching files.")

    def on_block_all(self):
        if not self.file_list:
            QMessageBox.information(self, "Nothing to Block", "No files in list. Scan first.")
            return

        # Prevent starting a second worker if one is already running
        if self.thread is not None and self.thread.isRunning():
            QMessageBox.information(self, "Busy", "Blocking is already in progress.")
            return

        reply = QMessageBox.question(
            self,
            "Confirm",
            f"Create firewall block rules for ALL {len(self.file_list)} files?",
        )
        if reply != QMessageBox.Yes:
            return

        total = len(self.file_list)
        self.progress.setMaximum(total)
        self.progress.setValue(0)
        self.progress.setVisible(True)

        self.progress_label.setText(f"Blocking 0 of {total}...")
        self.progress_label.setVisible(True)

        self.cancel_button.setVisible(True)

        # Create worker + thread
        self.thread = QThread()
        self.worker = BlockWorker(self.file_list, self.registry, self.firewall)
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_block_progress)
        self.worker.finished.connect(self.blocking_complete)
        self.worker.cancelled.connect(self.blocking_cancelled)

        # Cleanup thread after done
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.worker.cancelled.connect(self.thread.quit)
        self.worker.cancelled.connect(self.worker.deleteLater)

        self.thread.start()

    def on_unblock_selected(self):
        selected_items = self.list_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Select one or more items first.")
            return

        paths = [i.data(Qt.UserRole) for i in selected_items]
        paths = [p for p in paths if p is not None]

        if not paths:
            return

        reply = QMessageBox.question(
            self,
            "Confirm",
            f"Remove firewall rules for {len(paths)} selected file(s)?",
        )
        if reply != QMessageBox.Yes:
            return

        removed_count = 0
        for path in paths:
            entry = self.registry.get_rules_for(path)
            if not entry:
                continue
            rule_out = entry.get("rule_out")
            rule_in = entry.get("rule_in")

            if rule_out:
                self.firewall.delete_rule(rule_out)
            if rule_in:
                self.firewall.delete_rule(rule_in)

            self.registry.remove_path(path)
            removed_count += 1

        self.registry.save()
        self._populate_list_widget()
        self.append_log(f"Unblocked {removed_count} file(s).")

    def on_unblock_all(self):
        if not self.registry.rules:
            QMessageBox.information(self, "No Rules", "No tracked rules to remove.")
            return

        reply = QMessageBox.question(
            self,
            "Confirm",
            "This will remove ALL firewall rules created by this app.\n"
            "Other firewall rules will NOT be touched.\n\nContinue?",
        )
        if reply != QMessageBox.Yes:
            return

        entries = self.registry.all_entries()
        for path, entry in entries:
            rule_out = entry.get("rule_out")
            rule_in = entry.get("rule_in")
            if rule_out:
                self.firewall.delete_rule(rule_out)
            if rule_in:
                self.firewall.delete_rule(rule_in)

        count = len(entries)
        self.registry.clear()
        self.registry.save()
        self._populate_list_widget()

        self.append_log(f"Removed ALL {count} rule set(s) created by this app.")

    def on_snapshot_export(self):
        reply = QMessageBox.question(
            self,
            "Export Firewall Snapshot",
            f"This will export ALL current firewall rules to:\n\n{SNAPSHOT_PATH}\n\n"
            "Use this if you want a full revert point.\n\nContinue?",
        )
        if reply != QMessageBox.Yes:
            return

        ok = self.firewall.export_snapshot(SNAPSHOT_PATH)
        if ok:
            self.append_log(f"Firewall snapshot exported to: {SNAPSHOT_PATH}")
            QMessageBox.information(
                self, "Snapshot Exported",
                f"Firewall snapshot exported to:\n{SNAPSHOT_PATH}"
            )

    def on_snapshot_import(self):
        if not SNAPSHOT_PATH.exists():
            QMessageBox.warning(
                self,
                "No Snapshot",
                f"No snapshot file found at:\n{SNAPSHOT_PATH}"
            )
            return

        reply = QMessageBox.warning(
            self,
            "Import Firewall Snapshot",
            "IMPORTING a snapshot will overwrite current firewall rules "
            "with those from the snapshot.\n\n"
            "This can undo not only this app's changes, but any firewall "
            "changes made after the snapshot.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        ok = self.firewall.import_snapshot(SNAPSHOT_PATH)
        if ok:
            # Snapshot import overwrites everything, so our registry is no longer valid.
            self.registry.clear()
            self.registry.save()
            self._populate_list_widget()
            self.append_log("Firewall snapshot imported. Local rule registry cleared.")
            QMessageBox.information(
                self,
                "Snapshot Imported",
                "Firewall snapshot imported.\n\n"
                "Tracked rules have been cleared because the firewall "
                "state was fully overwritten."
            )

    # ---------- Internal helpers ---------- #

    def _get_effective_extensions(self):
        """
        Combines DEFAULT_EXTENSIONS with user-specified extra types.
        Normalizes to lowercase, leading dot.
        """
        exts = set([e.lower() for e in DEFAULT_EXTENSIONS])

        extra = self.extra_types_edit.text().strip()
        if extra:
            # Split on comma or whitespace
            raw_parts = [p.strip() for p in extra.replace(";", ",").split(",")]
            for p in raw_parts:
                if not p:
                    continue
                if not p.startswith("."):
                    p = "." + p
                exts.add(p.lower())

        return sorted(exts)

    def _scan_folder(self, folder: str, extensions, recursive: bool):
        """
        Return list of file paths in folder matching given extensions.
        """
        matches = []
        # Realpath + abspath to handle junctions/symlinks nicely
        folder = os.path.realpath(os.path.abspath(folder))

        if recursive:
            for root, dirs, files in os.walk(folder, onerror=lambda e: None):
                for name in files:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in extensions:
                        matches.append(os.path.join(root, name))
        else:
            try:
                for name in os.listdir(folder):
                    full = os.path.join(folder, name)
                    if os.path.isfile(full):
                        ext = os.path.splitext(name)[1].lower()
                        if ext in extensions:
                            matches.append(full)
            except PermissionError:
                # Just skip folders we can't read
                pass

        return matches

    def _populate_list_widget(self):
        self.list_widget.clear()
        blocked_paths = set(self.registry.rules.keys())

        for path in self.file_list:
            is_blocked = path in blocked_paths
            display_text = f"[BLOCKED] {path}" if is_blocked else path
            item = QListWidgetItem(display_text)
            if is_blocked:
                item.setForeground(Qt.red)
            else:
                item.setForeground(Qt.black)
            item.setData(Qt.UserRole, path)
            self.list_widget.addItem(item)

    # ---------- Blocking progress handlers ---------- #

    def update_block_progress(self, index, path):
        self.progress.setValue(index)
        total = self.progress.maximum()
        self.progress_label.setText(f"Blocking {index} of {total}...\n{path}")

    def blocking_complete(self, blocked_count, skipped_count):
        self.registry.save()
        self._populate_list_widget()

        self.append_log(
        f"Blocking complete. New blocked: {blocked_count}, already blocked: {skipped_count}"
            )

        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self.cancel_button.setVisible(False)

    # DO NOT clear worker/thread here!
    # They will be cleaned up safely via deleteLater() after the thread fully stops.

    def blocking_cancelled(self):
        self.append_log("Blocking cancelled by user.")
        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self.cancel_button.setVisible(False)

        # Again: DO NOT clear worker/thread here

    def cancel_blocking(self):
        if self.worker is not None:
            self.worker.cancel()


# ------------------------ Main entry ------------------------ #

def main():
    if not is_windows():
        print("This tool only works on Windows.", file=sys.stderr)
        return

    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
