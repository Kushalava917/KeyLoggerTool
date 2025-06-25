Keylogger Detector
A Python script to detect potential keyloggers on Windows systems by identifying suspicious processes, network activity, and active windows.
Features

Suspicious Process Detection: Flags processes running from non-standard locations (outside C:\Windows\System32), excluding known system processes like winlogon.exe.
Network Activity Monitoring: Identifies established network connections from untrusted applications (e.g., not Chrome, Firefox, or other trusted apps).
Active Window Tracking: Reports the process name of the currently active window for context.
Robust Error Handling: Gracefully handles process access errors and missing information.

Requirements

Python 3.6+
Windows operating system
Required Python packages:pip install psutil pywin32



Installation

Clone the repository:git clone https://github.com/yourusername/keylogger-detector.git
cd keylogger-detector


Install dependencies:pip install -r requirements.txt


Run the script:python keylogger_detector.py



Usage
Run the script to scan for potential keyloggers:
python keylogger_detector.py

Example Output
Scanning for Keyloggers...
[+] No suspicious processes found.
[!] Suspicious Network Activity Detected:
  - unknown_app.exe (PID: 1234) communicating with 192.168.1.100:8080
[+] Active Window: explorer.exe
Scan Complete.

How It Works

Process Check: Compares running processes against a list of known system processes and flags those running from unexpected locations.
Network Check: Monitors active network connections and flags those from non-trusted applications.
Active Window: Identifies the process associated with the currently active window using Windows API calls.

Limitations

Windows-only due to reliance on pywin32 for system calls.
Heuristic-based detection may produce false positives for legitimate processes in non-standard locations.
Trusted application list (trusted_apps) requires manual updates for new software.
Does not perform file hashing or signature verification.

Contributing

Fork the repository.
Create a feature branch (git checkout -b feature/new-feature).
Commit changes (git commit -m "Add new feature").
Push to the branch (git push origin feature/new-feature).
Open a pull request.

License
MIT License. See LICENSE for details.
Disclaimer
This tool is for educational and defensive purposes only. Use responsibly and ensure compliance with local laws and regulations.
