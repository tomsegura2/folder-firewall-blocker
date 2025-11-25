PyFolderFirewallBlocker
Copyright (c) 2025

Licensed under the PolyForm Noncommercial License 1.0.0

You may not use this software for commercial purposes including but not limited to:
- Selling this software or derivatives
- Bundling in paid products
- Offering as part of a commercial service

See full license:
https://polyformproject.org/licenses/noncommercial/1.0.0/

# Folder Firewall Blocker 2.0

PyFolderFirewallBlocker is a portable Windows utility that blocks all executable files within a selected folder (and optional subfolders) from accessing the internet by automatically creating Windows Firewall rules.

Inspired by the discontinued Folder Firewall Blocker (2016), this modern replacement adds the features the original lacked — most importantly full reversibility, rule tracking, and firewall state recovery.


**🔒 Core Features**

Block internet access for:

.exe, .dll, .sys, .msi, .bat, .cmd, .js, .vbs and more

Custom file extensions (user-defined)

Recursive folder scanning

Windows Firewall rule creation (inbound + outbound)

Automatic UAC elevation (Admin prompt)

Fully reversible rule management:

Unblock selected files

Unblock all rules created by the app

Firewall snapshot system:

Export full firewall state

Restore firewall to previous snapshot

Visual UI built with PyQt5

Portable design (no installation required)

Safe rule namespace using hashed paths

**💡 Use Cases**

Sandbox legacy software

Prevent telemetry or phone-home behavior

Block background updaters

Restrict game launchers / DRM services

Secure testing environments

**⚙️ How It Works**

The application scans the target directory, detects executable file types, and creates Windows Firewall rules via netsh advfirewall to deny inbound and outbound traffic on a per-file basis. All created rules are tracked in a local JSON registry so they can be cleanly removed or restored later.

✅ Safer Than Manual Firewall Edits

Unlike manual firewall configuration or legacy tools, PyFolderFirewallBlocker guarantees:

No orphaned rules

Full rollback capability

No modification of unrelated firewall policies

**🖥 Requirements**

Windows 10 / 11

Administrator privileges

Python 3.8+

PyQt5

**📦 Packaging**

To create a portable EXE:

_pyinstaller --onefile --noconsole py_folder_firewall_blocker.py_

**🚧 Disclaimer**

This tool modifies Windows Firewall rules. Always export a firewall snapshot before bulk changes.

