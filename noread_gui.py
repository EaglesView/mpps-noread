#!/usr/bin/env python3
"""
noread_gui.py - Minimal desktop GUI for the MPPS NOREAD decryptor.

Wraps the pure-stdlib decrypt path in noread.py (decrypt_bytes / find_payload_start
/ xor55aa) behind a small PySide6 window: pick a NOREAD .Bin file or a folder of
them, see a red/green validity indicator, choose a destination, click Decrypt.
No decrypt logic lives here.

Run from source:   python3 noread_gui.py
Prebuilt binaries (no Python needed) are produced by PyInstaller; see README.
"""

import os
import sys
import zlib

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

import noread


def executable_dir():
    """Directory the program lives in — the frozen binary's folder when packaged,
    otherwise this script's folder. Used as the default output destination."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def looks_like_noread(path):
    """Cheap best-effort check: does this file begin like a NOREAD container
    (marker/signature present and the payload starts with a zlib header)?
    Only reads the first block — no full inflate."""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
    except OSError:
        return False
    start = noread.find_payload_start(head)
    if start is None:
        return False
    two = head[start:start + 2]
    if len(two) < 2:
        return False
    # payload index 0 == data[start], so xor a fresh 2-byte buffer
    return noread.xor55aa(two) == noread.ZLIB_MAGIC


class NoreadWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"noread — MPPS NOREAD decryptor {noread.__version__}")
        self.resize(560, 220)

        self.source_path = None      # selected file or folder
        self.source_is_folder = False

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # --- source selection --------------------------------------------- #
        btn_row = QHBoxLayout()
        open_file_btn = QPushButton("Open file…")
        open_file_btn.clicked.connect(self.open_file)
        open_folder_btn = QPushButton("Open folder…")
        open_folder_btn.clicked.connect(self.open_folder)
        btn_row.addWidget(open_file_btn)
        btn_row.addWidget(open_folder_btn)
        btn_row.addStretch(1)
        root.addLayout(btn_row)

        src_row = QHBoxLayout()
        self.source_edit = QLineEdit()
        self.source_edit.setReadOnly(True)
        self.source_edit.setPlaceholderText("No file or folder selected")
        src_row.addWidget(self.source_edit, stretch=1)
        self.indicator = QLabel("●")
        self.indicator.setFixedWidth(20)
        self.indicator.setAlignment(Qt.AlignCenter)
        src_row.addWidget(self.indicator)
        root.addLayout(src_row)

        self.recursive_cb = QCheckBox("Search subfolders (recursive)")
        self.recursive_cb.setEnabled(False)
        self.recursive_cb.toggled.connect(self._validate)
        root.addWidget(self.recursive_cb)

        self.status = QLabel("")
        root.addWidget(self.status)

        # --- destination -------------------------------------------------- #
        root.addWidget(QLabel("Destination folder:"))
        dest_row = QHBoxLayout()
        self.dest_edit = QLineEdit(executable_dir())
        dest_row.addWidget(self.dest_edit, stretch=1)
        dest_btn = QPushButton("Browse…")
        dest_btn.clicked.connect(self.browse_dest)
        dest_row.addWidget(dest_btn)
        root.addLayout(dest_row)

        # --- action ------------------------------------------------------- #
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt)
        root.addWidget(self.decrypt_btn)

        self._set_indicator(None)

    # ------------------------------------------------------------------ #
    # selection
    # ------------------------------------------------------------------ #
    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select NOREAD file", "",
            "NOREAD files (*.Bin *.bin);;All files (*)")
        if path:
            self._set_source(path, is_folder=False)

    def open_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select folder of NOREAD files")
        if path:
            self._set_source(path, is_folder=True)

    def browse_dest(self):
        path = QFileDialog.getExistingDirectory(self, "Select destination folder",
                                                self.dest_edit.text() or "")
        if path:
            self.dest_edit.setText(path)

    def _set_source(self, path, is_folder):
        self.source_path = path
        self.source_is_folder = is_folder
        self.source_edit.setText(path)
        self.recursive_cb.setEnabled(is_folder)
        self._validate()

    # ------------------------------------------------------------------ #
    # validation + indicator
    # ------------------------------------------------------------------ #
    def _candidate_files(self):
        """The NOREAD files implied by the current selection (unfiltered by
        validity for a folder — used both to validate and to decrypt)."""
        if not self.source_path:
            return []
        if not self.source_is_folder:
            return [self.source_path]
        found = []
        if self.recursive_cb.isChecked():
            for dirpath, _dirs, names in os.walk(self.source_path):
                for n in sorted(names):
                    if n.lower().endswith(".bin"):
                        found.append(os.path.join(dirpath, n))
        else:
            try:
                names = sorted(os.listdir(self.source_path))
            except OSError:
                return []
            found = [os.path.join(self.source_path, n) for n in names
                     if n.lower().endswith(".bin") and
                     os.path.isfile(os.path.join(self.source_path, n))]
        return found

    def _valid_files(self):
        return [p for p in self._candidate_files() if looks_like_noread(p)]

    def _validate(self):
        valid = self._valid_files()
        if not self.source_path:
            self._set_indicator(None)
        elif self.source_is_folder:
            ok = bool(valid)
            n = len(valid)
            self._set_indicator(ok, f"{n} NOREAD file{'s' if n != 1 else ''} found"
                                if ok else "No NOREAD files in folder")
        else:
            ok = bool(valid)
            self._set_indicator(ok, "Valid NOREAD file" if ok
                                else "Not a NOREAD file")
        self.decrypt_btn.setEnabled(bool(valid))
        self._valid_cache = valid

    def _set_indicator(self, ok, text=""):
        if ok is None:
            color, text = "gray", "Select a file or folder to decrypt"
        elif ok:
            color = "#2ecc40"   # green
        else:
            color = "#ff4136"   # red
        self.indicator.setStyleSheet(f"color: {color}; font-size: 16px;")
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {color};")

    # ------------------------------------------------------------------ #
    # decrypt
    # ------------------------------------------------------------------ #
    def decrypt(self):
        dest = self.dest_edit.text().strip()
        if not dest or not os.path.isdir(dest):
            QMessageBox.warning(self, "noread",
                                f"Destination folder does not exist:\n{dest}")
            return

        files = getattr(self, "_valid_cache", None) or self._valid_files()
        if not files:
            QMessageBox.warning(self, "noread", "Nothing valid to decrypt.")
            return

        ok = 0
        errors = []
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            for path in files:
                try:
                    data = noread._read(path)
                    firmware, _start, _magic = noread.decrypt_bytes(data)
                    out = os.path.join(
                        dest, os.path.basename(
                            noread._derive(path, ".decrypted.bin")))
                    noread._write(out, firmware)
                    ok += 1
                except (OSError, ValueError, zlib.error) as e:
                    errors.append(f"{os.path.basename(path)}: {e}")
        finally:
            QApplication.restoreOverrideCursor()

        msg = f"Decrypted {ok} file{'s' if ok != 1 else ''} to:\n{dest}"
        if errors:
            msg += "\n\nFailed:\n" + "\n".join(errors)
            QMessageBox.warning(self, "noread", msg)
        else:
            QMessageBox.information(self, "noread", msg)


def main(argv=None):
    app = QApplication(argv if argv is not None else sys.argv)
    win = NoreadWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
