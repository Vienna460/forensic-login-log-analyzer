# forensic-login-log-analyzer

A Python-based forensic tool for analyzing authentication logs and detecting suspicious login activity such as brute-force attempts, repeated login failures, and multi-user attacks from the same IP address.

The tool provides:
- Login statistics
- Suspicious IP detection
- Event timeline reconstruction
- Evidence integrity verification using SHA-256
- Exportable forensic report

# Features

- Analyze authentication logs
- Detect brute force attacks
- Identify suspicious IP activity
- Build login timeline
- Verify evidence integrity using SHA-256
- Export digital forensic reports
- Support log files and SQLite databases
- Visualization Graph

## Installation
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Run
python LogAnalyzerMain.py
on terminal
