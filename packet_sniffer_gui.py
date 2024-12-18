import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime

# Initialize global variables
packets = []
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
ip_filter = None  # Global variable for IP filter

# Function to process packets
def process_packet(packet):
    global packets, protocol_counts, ip_filter
    # Apply IP filter if provided
    if ip_filter and (packet[IP].src != ip_filter and packet[IP].dst != ip_filter):
        return

    packets.append(packet)

    # Extract packet details
    source_ip = packet[IP].src if IP in packet else "N/A"
    destination_ip = packet[IP].dst if IP in packet else "N/A"
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
    length = len(packet)
    protocol_counts[protocol] += 1

    # Add packet details to the table
    table.insert("", "end", values=(source_ip, destination_ip, protocol, length))

    # Update the graphical summary
    update_graph()

# Function to start sniffing
def start_sniffing():
    global ip_filter
    filter_type = protocol_filter.get().lower()
    packet_filter = filter_type if filter_type in ["tcp", "udp", "icmp"] else ""
    ip_filter = ip_entry.get().strip() if ip_entry.get() else None  # Set the IP filter
    try:
        packet_count = int(packet_count_var.get())
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for packet count.")
        return

    # Reset protocol counts
    global protocol_counts
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    table.delete(*table.get_children())  # Clear the table
    sniff(prn=process_packet, filter=packet_filter, count=packet_count)

# Function to save captured packets to a file
def save_packets():
    if not packets:
        messagebox.showerror("Error", "No packets to save!")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        wrpcap(file_path, packets)
        messagebox.showinfo("Success", f"Packets saved to {file_path}")

# Function to toggle dark mode
def toggle_dark_mode():
    if root.cget("bg") == "#2c3e50":  # Dark mode
        root.configure(bg="#ecf0f1")
        style.configure("TLabel", background="#ecf0f1", foreground="#2c3e50")
        style.configure("TButton", background="#3498db", foreground="#ecf0f1")
        style.configure("Treeview", background="#ffffff", foreground="#000000")
        style.configure("Treeview.Heading", background="#3498db", foreground="#ffffff")
    else:  # Light mode
        root.configure(bg="#2c3e50")
        style.configure("TLabel", background="#2c3e50", foreground="#ecf0f1")
        style.configure("TButton", background="#1abc9c", foreground="#ecf0f1")
        style.configure("Treeview", background="#34495e", foreground="#ecf0f1")
        style.configure("Treeview.Heading", background="#1abc9c", foreground="#ecf0f1")

# Function to update the graph
def update_graph():
    global protocol_counts
    bar_chart.clear()
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())
    bar_chart.bar(protocols, counts, color=["#1abc9c", "#3498db", "#9b59b6", "#e74c3c"])
    bar_chart.set_title("Packet Protocol Distribution", fontsize=14, fontweight="bold", color="#ecf0f1" if root.cget("bg") == "#2c3e50" else "#2c3e50")
    bar_chart.set_facecolor("#2c3e50" if root.cget("bg") == "#2c3e50" else "#ffffff")
    bar_chart.set_xlabel("Protocols")
    bar_chart.set_ylabel("Count")
    graph_canvas.draw()

# GUI setup
root = tk.Tk()
root.title("Advanced Network Packet Sniffer")
root.geometry("1200x600")
root.configure(bg="#2c3e50")

# Styles
style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background="#2c3e50", foreground="#ecf0f1", font=("Arial", 12))
style.configure("TButton", background="#1abc9c", foreground="#ecf0f1", font=("Arial", 12))
style.configure("Treeview", background="#34495e", foreground="#ecf0f1", rowheight=25, font=("Arial", 10))
style.configure("Treeview.Heading", background="#1abc9c", foreground="#ecf0f1", font=("Arial", 12, "bold"))

# Title Label
title_label = ttk.Label(root, text="Advanced Network Packet Sniffer", font=("Arial", 18, "bold"))
title_label.grid(row=0, column=0, columnspan=3, pady=20)

# Protocol filter dropdown
ttk.Label(root, text="Protocol Filter:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
protocol_filter = ttk.Combobox(root, values=["All", "TCP", "UDP", "ICMP"], state="readonly", font=("Arial", 12))
protocol_filter.set("All")
protocol_filter.grid(row=1, column=1, padx=10, pady=10, sticky="w")

# IP filter entry field
ttk.Label(root, text="IP Address Filter (Optional):").grid(row=2, column=0, padx=10, pady=10, sticky="e")
ip_entry = ttk.Entry(root, font=("Arial", 12))
ip_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# Packet count
ttk.Label(root, text="Number of Packets to Capture:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
packet_count_var = tk.StringVar(value="10")
packet_count_entry = ttk.Entry(root, textvariable=packet_count_var, font=("Arial", 12))
packet_count_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Start sniffing button
start_button = ttk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=4, column=0, columnspan=3, pady=20)

# Table for displaying captured packets
table_frame = tk.Frame(root, bg="#2c3e50")
table_frame.grid(row=5, column=0, padx=10, pady=10, sticky="nsew")

columns = ("Source IP", "Destination IP", "Protocol", "Length")
table = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
table.grid(row=0, column=0, sticky="nsew")

for col in columns:
    table.heading(col, text=col)
    table.column(col, width=150)

# Scrollbar for the table
scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
table.configure(yscrollcommand=scrollbar.set)
scrollbar.grid(row=0, column=1, sticky="ns")

# Frame for the graph
graph_frame = tk.Frame(root, bg="#2c3e50")
graph_frame.grid(row=5, column=2, padx=10, pady=10, sticky="nsew")

# Graph for protocol distribution
fig = Figure(figsize=(6, 4), dpi=100)
bar_chart = fig.add_subplot(111)
graph_canvas = FigureCanvasTkAgg(fig, graph_frame)
graph_canvas.get_tk_widget().pack(fill="both", expand=True)

# Save button
save_button = ttk.Button(root, text="Save Packets", command=save_packets)
save_button.grid(row=6, column=0, columnspan=3, pady=10)

# Dark mode toggle button
dark_mode_button = ttk.Button(root, text="Toggle Dark Mode", command=toggle_dark_mode)
dark_mode_button.grid(row=7, column=0, columnspan=3, pady=10)

# Column weight configuration for centering
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=2)
root.grid_columnconfigure(2, weight=1)

# Start the GUI event loop
root.mainloop()

