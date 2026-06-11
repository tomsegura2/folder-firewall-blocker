# Folder Firewall Blocker

Folder Firewall Blocker is a small Windows desktop tool for creating Windows Defender Firewall block rules for every matching file in a selected folder. It is built with Python and PyQt5, and uses `netsh advfirewall` for firewall changes.

## Features

- Scan a folder for executable files.
- Include or exclude subfolders.
- Add extra file extensions, such as `.bat`, `.cmd`, `.ps1`, or `.dll`.
- Create inbound and outbound block rules for all scanned files.
- Skip files already tracked by this app.
- Detect existing firewall rules that already reference a file and let you skip or proceed.
- Unblock selected files.
- Remove all firewall rules created by this app without touching unrelated firewall rules.
- Export and import a full Windows Firewall snapshot.
- Track created rules in a local JSON registry so they can be removed later.

## Requirements

- Windows
- Administrator privileges
- Python 3.10 or newer, if running from source
- PyQt5, if running from source
- PyInstaller, if building the executable

The app relaunches itself with an administrator prompt when needed. Firewall changes will not work without elevation.

## Download / Run

The compiled executable is:

```text
dist\ffb.exe
```

Run it on Windows and approve the administrator prompt.

## Usage

1. Choose a target folder.
2. Leave `Include subfolders` checked if you want a recursive scan.
3. Optionally enter extra file types, separated by commas, such as:

   ```text
   .bat,.cmd,.ps1
   ```

4. Click `Scan Folder`.
5. Review the matching files.
6. Click `Block ALL` to create firewall rules.
7. Use `Unblock Selected` or `Unblock ALL (created by this app)` to remove rules created by this tool.

By default, the app scans for `.exe` files.

## Firewall Rules

For each blocked file, the app creates two rules:

- `PyFFB_OUT_<hash>` for outbound traffic
- `PyFFB_IN_<hash>` for inbound traffic

Rules are created for all firewall profiles and are enabled immediately.

## Local Files

The app stores its local state next to the script or executable:

- `pyffb_rules.json` tracks firewall rules created by this app.
- `pyffb_firewall_snapshot.wfw` stores a full Windows Firewall snapshot when exported.

Do not delete `pyffb_rules.json` if you want the app to remember which rules it created.

## Firewall Snapshot

`Export Firewall Snapshot` saves the entire current Windows Firewall policy to:

```text
pyffb_firewall_snapshot.wfw
```

`Import Firewall Snapshot` restores that snapshot and overwrites the current firewall policy. This can undo firewall changes made outside this app after the snapshot was created.

After importing a snapshot, the app clears its local rule registry because the current firewall state has been replaced.

## Build From Source

Install dependencies:

```powershell
pip install PyQt5 pyinstaller
```

Build the executable:

```powershell
pyinstaller --clean --noconfirm ffb.spec
```

The built executable will be written to:

```text
dist\ffb.exe
```

## Run From Source

```powershell
python ffb.py
```

The tool only works on Windows. It exits on non-Windows platforms.

## Safety Notes

- This tool modifies Windows Defender Firewall rules.
- Use `Export Firewall Snapshot` before making large changes if you want a full restore point.
- `Unblock ALL` only removes rules tracked in `pyffb_rules.json`.
- Importing a firewall snapshot overwrites the full firewall policy, not just rules created by this app.
