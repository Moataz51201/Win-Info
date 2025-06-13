# Win-Info
# Overview
This tool was aid in automated security information gathering and forensics investigations on Windows
operating systems. Its primary objective is to simplify the collection of key
security-related artifacts — including user activity, USB history, event logs,
scheduled tasks, and system configurations — which are essential for both
system hardening and post-incident analysis.
The script is written in Python and allows modular execution using
command-line flags. It also provides an option to export all gathered
information into a structured .txt report for documentation or evidence
preservation during digital forensic cases.

# Key Features: 

Collects basic system information including OS version, hostname, and
architecture.

Enumerates local user accounts — useful for identifying suspicious
accounts.

Retrieves recent Event Logs for incident timeline reconstruction.

Displays USB connection history, a key indicator in forensics.

Lists scheduled tasks, which can be abused for persistence.

Gathers detailed GPU information (often overlooked in profiling).

Scans for security-related services and status.

Retrieves installed drivers — potentially useful for spotting rootkits.

Displays active antivirus software and its current state.

Checks the Windows Firewall status and rules.

Lists installed security tools or software.

Extracts startup applications with emphasis on security tools.

Checks BitLocker encryption status for disk protection evidence.

Displays installed security patches (missing patches = vulnerability).

Shows system performance stats (CPU, RAM, Disk).

Provides extended system information similar to systeminfo.

# Usage Instructions
python3 sysinfo.py --help

Run all modules:
python3 sysinfo.py

Run selected modules:
python3 sysinfo.py --user-accounts --usb-history

Save output to a file:
python3 sysinfo.py --event-logs --output logs.txt
