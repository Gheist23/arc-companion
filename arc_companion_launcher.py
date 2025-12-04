import tkinter as tk
from tkinter import PhotoImage, font, ttk
import requests
import zipfile
import os
import sys
import shutil
import threading
import subprocess
import hashlib

# ---------------- Configuration & Security ---------------- #

UPDATE_BASE_URL = "https://ghostworld073.pythonanywhere.com"
LATEST_VERSION_ENDPOINT = f"{UPDATE_BASE_URL}/latest_arc_companion"
DOWNLOAD_ENDPOINT = f"{UPDATE_BASE_URL}/download_latest_arc_companion"

# Map of versions -> trusted SHA256 of the update ZIP.
# IMPORTANT: You must update this table yourself when you release a new version.
# Never accept an update for a version that isn't in this dictionary.
TRUSTED_VERSION_HASHES = {
    # Example:
    # "1.0.1": "your_sha256_hash_here",
}

HTTP_TIMEOUT = 10  # seconds
UPDATE_ZIP_PATH = "arc_companion_update.zip"
EXECUTABLE_NAME = "arc_companion.exe"
VERSION_FILE = "arc_companion_version.txt"

# Global variables
root = None
progress_bar = None
progress_label = None
download_thread = None
latest_version = None  # filled by check_for_update


# ---------------- Utility Functions ---------------- #

def center_window(window: tk.Tk) -> None:
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')


def compute_sha256(file_path: str) -> str:
    """Compute SHA256 checksum of a file in a memory-efficient way."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest().lower()


# ---------------- Update Logic ---------------- #

def check_for_update(current_version: str) -> bool:
    """
    Check the server for the latest version and decide whether to update.

    Security hardening:
    - Uses JSON safely (no eval).
    - Only accepts versions that appear in TRUSTED_VERSION_HASHES.
    """
    global latest_version

    try:
        response = requests.get(LATEST_VERSION_ENDPOINT, timeout=HTTP_TIMEOUT)
        response.raise_for_status()

        data = response.json()
        # Be flexible about response shape: list or dict.
        if isinstance(data, dict):
            latest_version = str(data.get("version", "")).strip()
        elif isinstance(data, list) and data:
            latest_version = str(data[0]).strip()
        else:
            print("Unexpected version response format.")
            return False

        if not latest_version:
            print("Latest version string is empty.")
            return False

        print(f"Current version: {current_version}, latest version: {latest_version}")

        if latest_version == current_version:
            print("No new version available.")
            return False

        # SECURITY: only update if the version is explicitly trusted.
        if latest_version not in TRUSTED_VERSION_HASHES:
            print(
                f"Latest version {latest_version} is NOT in TRUSTED_VERSION_HASHES. "
                f"Refusing to auto-update for security reasons."
            )
            return False

        print(f"New trusted version available: {latest_version}")
        return True

    except requests.RequestException as e:
        print(f"Error checking for updates: {e}")
        return False


def download_update() -> None:
    global download_thread
    download_thread = threading.Thread(target=download_update_thread, daemon=True)
    download_thread.start()
    # Start a periodic UI update to watch the thread
    root.after(100, check_download_thread)


def download_update_thread() -> None:
    """
    Download the update ZIP and verify its checksum before applying it.

    Mitigations:
    - Downloads over HTTPS (requests verifies certificates by default).
    - Verifies SHA256 checksum against a locally trusted value
      before extraction and execution.
    """
    if latest_version is None:
        print("No latest_version set; cannot download update safely.")
        root.after(0, launch_application)
        return

    expected_hash = TRUSTED_VERSION_HASHES.get(latest_version)
    if not expected_hash:
        print(f"No trusted hash for version {latest_version}; aborting update.")
        root.after(0, launch_application)
        return

    try:
        response = requests.get(DOWNLOAD_ENDPOINT, stream=True, timeout=HTTP_TIMEOUT)
        response.raise_for_status()

        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024
        downloaded_size = 0

        # Prepare progress bar for the download
        if total_size > 0:
            progress_bar['maximum'] = total_size

        with open(UPDATE_ZIP_PATH, "wb") as file:
            for data in response.iter_content(block_size):
                if not data:
                    continue
                file.write(data)
                downloaded_size += len(data)
                mb_downloaded = downloaded_size / (1024 * 1024)
                mb_total = total_size / (1024 * 1024) if total_size else 0
                root.after(
                    0,
                    update_progress_ui,
                    downloaded_size,
                    total_size,
                    mb_downloaded,
                    mb_total,
                )

        print(f"File downloaded and saved as {UPDATE_ZIP_PATH}")

        # Verify checksum BEFORE extraction / execution
        try:
            actual_hash = compute_sha256(UPDATE_ZIP_PATH)
            print(f"Expected SHA256: {expected_hash}")
            print(f"Actual   SHA256: {actual_hash}")

            if actual_hash != expected_hash.lower():
                print("Checksum mismatch! Possible tampering. Aborting update.")
                try:
                    os.remove(UPDATE_ZIP_PATH)
                except OSError:
                    pass
                root.after(0, launch_application)
                return
        except Exception as e:
            print(f"Error computing checksum: {e}")
            root.after(0, launch_application)
            return

        # If we get here, checksum is valid: apply update
        root.after(0, apply_update)

    except requests.RequestException as e:
        print(f"Error downloading update: {e}")
        root.after(0, launch_application)


def update_progress_ui(downloaded_size, total_size, mb_downloaded, mb_total) -> None:
    if total_size > 0:
        progress_bar['value'] = downloaded_size
        progress_label.config(
            text=f"Updating: {mb_downloaded:.2f} MB / {mb_total:.2f} MB"
        )
    else:
        # Unknown total size
        progress_label.config(
            text=f"Updating: {mb_downloaded:.2f} MB downloaded"
        )


def check_download_thread() -> None:
    if download_thread and download_thread.is_alive():
        root.after(100, check_download_thread)
    else:
        # Download thread has finished; apply_update or launch_application
        # will be triggered from the download thread via root.after.
        pass


def apply_update() -> None:
    extract_thread = threading.Thread(target=apply_update_thread, daemon=True)
    extract_thread.start()
    root.after(100, check_extract_thread, extract_thread)


def apply_update_thread() -> None:
    try:
        with zipfile.ZipFile(UPDATE_ZIP_PATH, 'r') as zip_ref:
            zip_ref.extractall('.')
        print("Update extracted successfully.")
    except zipfile.BadZipFile:
        print("Error extracting update ZIP.")
    finally:
        # Clean up the ZIP if possible
        try:
            if os.path.exists(UPDATE_ZIP_PATH):
                os.remove(UPDATE_ZIP_PATH)
        except OSError:
            pass

        # Proceed to launch the (updated) application
        root.after(0, launch_application)


def check_extract_thread(extract_thread: threading.Thread) -> None:
    if extract_thread.is_alive():
        root.after(100, check_extract_thread, extract_thread)
    else:
        # Extraction finished; launch_application is already scheduled.
        pass


# ---------------- Launch Logic (Command Injection Fix) ---------------- #

def launch_application() -> None:
    """
    Launch the main application safely.

    Command injection mitigation:
    - Use subprocess.Popen with a fixed argument list.
    - Do NOT use os.system or shell=True.
    """
    try:
        if os.path.isfile(EXECUTABLE_NAME):
            if sys.platform == 'win32':
                # On Windows, run the EXE directly without going through the shell.
                subprocess.Popen([EXECUTABLE_NAME], shell=False)
            else:
                # On other platforms, you may need a different executable or path.
                subprocess.Popen([f'./{EXECUTABLE_NAME}'], shell=False)
        else:
            print(f"Executable '{EXECUTABLE_NAME}' not found.")
    except Exception as e:
        print(f"Error launching application: {e}")

    # Exit the updater
    if root:
        try:
            root.quit()
            root.destroy()
        except Exception:
            pass
    sys.exit(0)


# ---------------- Entry Point UI/Flow ---------------- #

def update_app() -> None:
    try:
        with open(VERSION_FILE, 'r') as version_file:
            current_version = version_file.read().strip()

        if check_for_update(current_version):
            global root, progress_bar, progress_label
            root = tk.Tk()
            root.title("Updating ARC Companion")
            root.configure(bg='black')
            root.minsize(400, 200)

            frame = tk.Frame(root, bg='black')
            frame.pack(fill='both', expand=True)

            custom_font = font.Font(family="Helvetica", size=14)
            progress_label = tk.Label(
                frame,
                text="Updating...",
                bg='black',
                fg='white',
                font=custom_font,
            )
            progress_label.pack(padx=20, pady=30)

            progress_bar = ttk.Progressbar(
                frame,
                orient='horizontal',
                length=300,
                mode='determinate',
            )
            progress_bar.pack(pady=10)

            center_window(root)

            try:
                icon = PhotoImage(file='Companion.png')
                root.iconphoto(False, icon)
            except tk.TclError:
                print("Icon file not found for window icon.")

            # Start the download in a separate thread
            download_update()
            root.mainloop()
        else:
            # No update or update not trusted -> launch current app
            launch_application()

    except FileNotFoundError:
        print("Version file not found; launching existing application.")
        launch_application()


if __name__ == "__main__":
    update_app()
