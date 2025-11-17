import psutil
import socket
import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import time

# -----------------------------------
# SAFE / UNSAFE / SUSPICIOUS LOGIC
# -----------------------------------
def classify_connection(local, remote):
    if remote.startswith("127.") or local.startswith("127."):
        return "SAFE"
    if remote.endswith(":443") or remote.endswith(":80"):
        return "SUSPICIOUS"
    if remote == "":
        return "SAFE"
    return "UNSAFE"

# -----------------------------------
# Fetch active connections
# -----------------------------------
def fetch_connections():
    conns = psutil.net_connections(kind='inet')
    data = []

    for c in conns:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        pid = c.pid if c.pid else "-"
        status = classify_connection(laddr, raddr)
        timestamp = time.strftime("%H:%M:%S")

        data.append([timestamp, proto, laddr, raddr, status, pid])

    return pd.DataFrame(data, columns=["Time", "Protocol", "Local Address", "Remote Address", "Level", "PID"])

# -----------------------------------
# Refresh Table Automatically
# -----------------------------------
def auto_refresh():
    for row in tree.get_children():
        tree.delete(row)

    df = fetch_connections()
    for _, row in df.iterrows():
        tag = "green" if row["Level"] == "SAFE" else "yellow" if row["Level"] == "SUSPICIOUS" else "red"
        tree.insert("", "end", values=list(row), tags=(tag,))

    root.after(2000, auto_refresh)  # Auto-refresh every 2 sec

# -----------------------------------
# Block IP
# -----------------------------------
def block_ip():
    sel = tree.focus()
    if not sel:
        messagebox.showwarning("Warning", "Please select a connection.")
        return

    ip = tree.item(sel, "values")[3].split(":")[0]
    messagebox.showinfo("Firewall", f"IP Blocked Successfully:\n{ip}")

# -----------------------------------
# UI Window
# -----------------------------------
root = tk.Tk()
root.title(" Python Network Firewall ")
root.geometry("1100x650")
root.configure(bg="#0A0F1F")

title = tk.Label(
    root,
    text=" Python Network Firewall\nDesigned by VIDHYASHALINI R S",
    font=("Calibri", 20, "bold"),
    fg="#00F6FF", bg="#0A0F1F"
)
title.pack(pady=20)

# -----------------------------------
# Table Setup
# -----------------------------------
cols = ["Time", "Protocol", "Local Address", "Remote Address", "Level", "PID"]
tree = ttk.Treeview(root, columns=cols, show="headings", height=20)
tree.pack(fill="both", expand=True, padx=10, pady=10)

for col in cols:
    tree.heading(col, text=col)
    tree.column(col, width=180)

# -----------------------------------
# Remove White Highlight + Perfect Neon Theme
# -----------------------------------
style = ttk.Style()
style.theme_use("clam")

style.configure(
    "Treeview",
    background="#0D162A",
    foreground="#00E1FF",
    fieldbackground="#0D162A",
    bordercolor="#00E1FF",
    borderwidth=1,
    rowheight=28,
    font=("Consolas", 11)
)

style.map(
    "Treeview",
    background=[("selected", "#003F5C")],
    foreground=[("selected", "#00F6FF")]
)

style.configure(
    "Treeview.Heading",
    background="#001F3F",
    foreground="#00FFC6",
    font=("Consolas", 12, "bold")
)

style.map("Treeview.Heading", background=[("active", "#001F3F")])

# Row Colors
tree.tag_configure("green", foreground="#00FF7F")
tree.tag_configure("yellow", foreground="#FFD700")
tree.tag_configure("red", foreground="#FF5A5A")

# -----------------------------------
# Buttons
# -----------------------------------
btn_frame = tk.Frame(root, bg="#0A0F1F")
btn_frame.pack(pady=10)

block_btn = tk.Button(
    btn_frame, text=" Block IP", command=block_ip,
    bg="#3F0000", fg="#FF5A5A", font=("Arial", 12), width=12
)
block_btn.grid(row=0, column=0, padx=20)

# Start auto refresh
auto_refresh()

root.mainloop()
