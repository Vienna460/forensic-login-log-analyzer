import tkinter as tk
from tkinter import filedialog, messagebox
from collections import defaultdict
import hashlib
import sqlite3
import matplotlib.pyplot as plt

# Global variables (store last analysis)

last_summary = ""
last_suspicious = []
last_timeline = []
last_hash = ""
last_ip_failed = {}

# Hash function (Evidence Integrity)

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


# Core Processing Function

def process_records(records, source_path):
    global last_summary, last_suspicious, last_timeline, last_hash, last_ip_failed

    # Clear GUI
    summary_text.set("")
    hash_text.set("")
    suspicious_box.delete(0, tk.END)
    timeline_box.delete(0, tk.END)

    total = 0
    success = 0
    failed = 0

    ip_failed_count = defaultdict(int)
    ip_users = defaultdict(set)
    timeline = []

    for date, time, status, user, ip in records:
        total += 1

        if status == "LOGIN_SUCCESS":
            success += 1

        elif status == "LOGIN_FAILED":
            failed += 1
            ip_failed_count[ip] += 1
            ip_users[ip].add(user)

        # Limit timeline to avoid GUI freeze
        if len(timeline) < 300:
            timeline.append(f"{date} {time} | {user} | {status} | {ip}")

    # Save failed IP data for graph
    last_ip_failed = dict(ip_failed_count)

    # Sort timeline
    timeline.sort()

    # Detect suspicious IPs
    suspicious = []

    for ip, count in ip_failed_count.items():
        user_count = len(ip_users[ip])

        if count >= 10:
            suspicious.append(f"{ip} → {count} failed attempts (HIGH RISK - POSSIBLE BRUTE FORCE)")

        elif count >= 5:
            suspicious.append(f"{ip} → {count} failed attempts (FLAGGED)")

        elif user_count >= 3:
            suspicious.append(f"{ip} → {count} failed attempts (MULTI-USER ATTEMPTS)")

        else:
            suspicious.append(f"{ip} → {count} failed attempts")

    # Top attacker
    if ip_failed_count:
        top_attacker = max(ip_failed_count, key=ip_failed_count.get)
        top_count = ip_failed_count[top_attacker]
    else:
        top_attacker = "None"
        top_count = 0

    # Evidence hash
    last_hash = calculate_hash(source_path)

    # Summary
    last_summary = (
        f"Total Attempts: {total}\n"
        f"Successful Logins: {success}\n"
        f"Failed Logins: {failed}\n\n"
        f"Top Suspicious IP: {top_attacker} ({top_count} failed attempts)"
    )

    if total > 300:
        last_summary += "\n(Note: Showing first 300 events only)"

    last_suspicious = suspicious
    last_timeline = timeline

    update_gui()


# Analyze From Log File

def analyze_log():
    filepath = filedialog.askopenfilename(
        title="Select Log File",
        filetypes=[("Text Files", "*.txt *.log")]
    )

    if not filepath:
        return

    records = []

    try:
        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                # Honeypot log format
                if "IP=" in line and "USER=" in line:
                    try:
                        ts, rest = line.split(" ", 1)
                        date, time = ts.split("T")

                        parts = rest.split()
                        ip = parts[0].split("=")[1]
                        user = parts[1].split("=")[1]

                        status = "LOGIN_FAILED"

                        records.append((date, time, status, user, ip))
                    except:
                        continue

                # Standard login log format
                else:
                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    try:
                        date = parts[0]
                        time = parts[1]
                        status = parts[2]
                        user = parts[3].split("=")[1]
                        ip = parts[4].split("=")[1]

                        records.append((date, time, status, user, ip))
                    except:
                        continue

    except:
        messagebox.showerror("Error", "Cannot open file.")
        return

    process_records(records, filepath)


# Analyze From Database

def analyze_database():
    db_path = filedialog.askopenfilename(
        title="Select Database File",
        filetypes=[("SQLite Database", "*.db")]
    )

    if not db_path:
        return

    records = []

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT date, time, status, user, ip FROM login_logs")
        rows = cursor.fetchall()

        conn.close()

        for row in rows:
            records.append(row)

    except:
        messagebox.showerror("Error", "Failed to open database or table not found.")
        return

    process_records(records, db_path)


# Update GUI Function

def update_gui():
    summary_text.set(last_summary)
    hash_text.set(last_hash)

    suspicious_box.delete(0, tk.END)
    for item in last_suspicious:
        suspicious_box.insert(tk.END, item)

    timeline_box.delete(0, tk.END)
    for event in last_timeline:
        timeline_box.insert(tk.END, event)


# Export Report Function

def export_report():
    if not last_summary:
        messagebox.showwarning("Warning", "Analyze a log file or database first!")
        return

    filepath = filedialog.asksaveasfilename(
        title="Save Report",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")]
    )

    if not filepath:
        return

    try:
        from datetime import datetime
        analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(filepath, "w") as report:
            report.write("Digital Forensic Log Analysis Report\n")
            report.write("-----------------------------------\n\n")

            report.write(f"Case ID: DF-LOGIN-001\n")
            report.write(f"Analysis Time: {analysis_time}\n")
            report.write("Tool: Digital Forensic Log Analyzer v1.1\n\n")

            report.write("Summary:\n")
            report.write(last_summary + "\n\n")

            report.write("Evidence Hash (SHA-256):\n")
            report.write(last_hash + "\n\n")

            report.write("Suspicious IPs:\n")
            for item in last_suspicious:
                report.write(item + "\n")

            report.write("\nTimeline:\n")
            for event in last_timeline:
                report.write(event + "\n")

        messagebox.showinfo("Success", "Forensic report exported successfully!")

    except:
        messagebox.showerror("Error", "Failed to save report.")


def show_attack_graph():
    if not last_ip_failed:
        messagebox.showwarning("Warning", "Run analysis first!")
        return

    sorted_ips = sorted(last_ip_failed.items(), key=lambda x: x[1], reverse=True)

    ips = [ip for ip, _ in sorted_ips][:10]
    counts = [count for _, count in sorted_ips][:10]

    plt.figure()
    plt.bar(ips, counts)

    plt.xlabel("IP Address")
    plt.ylabel("Failed Login Attempts")
    plt.title("Failed Login Attempts Per IP")

    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# GUI Layout


root = tk.Tk()
root.title("Digital Forensic Log Analyzer")
root.geometry("650x600")

title = tk.Label(root, text="Digital Forensic Log Analyzer", font=("Arial", 16, "bold"))
title.pack(pady=10)

btn = tk.Button(root, text="Analyze Log File", command=analyze_log)
btn.pack(pady=5)

db_btn = tk.Button(root, text="Analyze From Database", command=analyze_database)
db_btn.pack(pady=5)

export_btn = tk.Button(root, text="Export Forensic Report", command=export_report)
export_btn.pack(pady=5)

graph_btn = tk.Button(root, text="Show Attack Graph", command=show_attack_graph)
graph_btn.pack(pady = 5)

# Summary Section
summary_frame = tk.Frame(root)
summary_frame.pack(pady=10)

tk.Label(summary_frame, text="Summary", font=("Arial", 12, "bold")).pack()

summary_text = tk.StringVar()
summary_label = tk.Label(summary_frame, textvariable=summary_text, justify="left")
summary_label.pack()

# Hash Section
hash_frame = tk.Frame(root)
hash_frame.pack(pady=10)

tk.Label(hash_frame, text="Evidence Hash (SHA-256)", font=("Arial", 12, "bold")).pack()

hash_text = tk.StringVar()
hash_label = tk.Label(hash_frame, textvariable=hash_text, wraplength=600)
hash_label.pack()

# Suspicious IP Section
sus_frame = tk.Frame(root)
sus_frame.pack(pady=10)

tk.Label(sus_frame, text="Suspicious IPs", font=("Arial", 12, "bold")).pack()

suspicious_box = tk.Listbox(sus_frame, width=60, height=6)
suspicious_box.pack()

# Timeline Section
time_frame = tk.Frame(root)
time_frame.pack(pady=10)

tk.Label(time_frame, text="Login Timeline", font=("Arial", 12, "bold")).pack()

timeline_box = tk.Listbox(time_frame, width=80, height=10)
timeline_box.pack()


root.mainloop()
