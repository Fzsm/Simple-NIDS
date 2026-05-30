
import tkinter as tk

from tkinter import filedialog, messagebox

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP

import matplotlib.pyplot as plt

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import threading

import os


# Default threshold values

DEFAULT_THRESHOLDS = {

'syn': 500,

'http': 300,

'dns': 300,

'udp': 800,

'icmp': 400,

'arp': 50,

'tcp': 1000,

'slowloris': 200

}



def process_packet(p, data):


if ARP in p:

data['arp'] += 1

if ICMP in p:

data['icmp'] += 1

if IP in p:

if TCP in p:

data['tcp'] += 1

if p[TCP].flags == "S":

data['syn'] += 1


# Check well-known application layer ports


if p[TCP].dport == 80 or p[TCP].dport == 443 or p[TCP].sport == 80:

data['http'] += 1

if p[TCP].dport == 21 or p[TCP].sport == 21:

data['ftp'] += 1

if p[TCP].dport == 22 or p[TCP].sport == 22:

data['ssh'] += 1


if UDP in p:

data['udp'] += 1

if p[UDP].dport == 53 or p[UDP].sport == 53:

data['dns'] += 1

def save_log(attacks, file_name="attack_log.txt"):


try:

with open(file_name, 'w', encoding='utf-8') as log_file:

log_file.write("===== IDS ATTACK LOG REPORT =====\n")

if attacks:

for a in attacks:

log_file.write(f"- {a}\n")

else:

log_file.write("No suspicious activities detected.\n")

except Exception as e:

print(f"Error saving log: {e}")



def plot_bar_chart(values, canvas):


labels = ["TCP", "UDP", "HTTP", "DNS", "SYN", "ICMP", "ARP", "TOTAL"]

fig = plt.Figure(figsize=(6, 4), dpi=100)

ax = fig.add_subplot(111)


# Use different colors for better visualization

colors = ['#3498db', '#e74c3c', '#2ecc71', '#f1c40f', '#9b59b6', '#e67e22', '#95a5a6', '#34495e']

ax.bar(labels, values, color=colors)


ax.set_title("Network Packet Distribution")

ax.set_ylabel("Packet Count")

ax.tick_params(axis='x', rotation=45)


# Replace the old chart with the new one
for widget in canvas.get_tk_widget().pack_slaves():

widget.destroy()


canvas.figure = fig

canvas.draw()



def analyze_pcap(path, text_box, canvas, thresholds):



try:

packets = rdpcap(path)

data = {'arp': 0, 'icmp': 0, 'tcp': 0, 'udp': 0, 'http': 0, 'syn': 0, 'dns': 0, 'ftp': 0, 'ssh': 0}


# Process packets using multithreading

threads = []

for p in packets:

t = threading.Thread(target=process_packet, args=(p, data))

t.start()

threads.append(t)


for t in threads:

t.join()



# Attack detection logic

attacks = []

if data['syn'] > thresholds['syn']: attacks.append(f"SYN FLOOD DETECTED ({data['syn']})")

if data['http'] > thresholds['http']: attacks.append(f"HTTP FLOOD DETECTED ({data['http']})")

if data['dns'] > thresholds['dns']: attacks.append(f"DNS FLOOD DETECTED ({data['dns']})")

if data['udp'] > thresholds['udp']: attacks.append(f"UDP FLOOD DETECTED ({data['udp']})")

if data['icmp'] > thresholds['icmp']: attacks.append(f"ICMP FLOOD DETECTED ({data['icmp']})")

if data['arp'] > thresholds['arp']: attacks.append(f"ARP SCAN DETECTED ({data['arp']})")

if data['tcp'] > thresholds['tcp']: attacks.append(f"TCP ANOMALY DETECTED ({data['tcp']})")

if data['syn'] > thresholds['slowloris']: attacks.append(f"POTENTIAL SLOWLORIS ATTACK ({data['syn']})")



save_log(attacks)




# Display results in the text area

text_box.delete("1.0", tk.END)

text_box.insert(tk.END, "===== PACKET STATISTICS =====\n", "header")

text_box.insert(tk.END, f"Total Packets: {len(packets)}\n")

text_box.insert(tk.END, f"TCP: {data['tcp']} | UDP: {data['udp']} | ICMP: {data['icmp']}\n")

text_box.insert(tk.END, f"HTTP: {data['http']} | DNS: {data['dns']} | ARP: {data['arp']}\n\n")


text_box.insert(tk.END, "===== ATTACK ANALYSIS =====\n", "header")

if attacks:

for a in attacks:

text_box.insert(tk.END, f"⚠️ {a}\n", "warning")

else:

text_box.insert(tk.END, "✅ No attacks detected.\n", "safe")



# Draw the final chart

plot_values = [data['tcp'], data['udp'], data['http'], data['dns'], data['syn'], data['icmp'], data['arp'], len(packets)]

plot_bar_chart(plot_values, canvas)



except Exception as e:

messagebox.showerror("Error", f"Failed to analyze file: {e}")



def gui():

root = tk.Tk()

root.title("Advanced Network IDS Analyzer")

root.geometry("1100x650")



# Text styling

paned_window = tk.PanedWindow(root, orient=tk.HORIZONTAL)

paned_window.pack(fill=tk.BOTH, expand=True)



left_frame = tk.Frame(paned_window, bg="#f0f0f0", padx=10, pady=10)

paned_window.add(left_frame)



right_frame = tk.Frame(paned_window, width=300, bg="#d1d1d1", padx=10, pady=10)

paned_window.add(right_frame)



# Threshold input section

tk.Label(right_frame, text="Detection Thresholds", font=("Arial", 12, "bold"), bg="#d1d1d1").pack(pady=5)


entries = {}

fields = [

("SYN Flood", "syn"), ("HTTP Flood", "http"), ("DNS Flood", "dns"),

("UDP Flood", "udp"), ("ICMP Flood", "icmp"), ("ARP Scan", "arp"),

("TCP Total", "tcp"), ("Slowloris", "slowloris")

]



for label_text, key in fields:

row = tk.Frame(right_frame, bg="#d1d1d1")

row.pack(fill=tk.X, pady=2)

tk.Label(row, text=label_text + ":", width=15, anchor='w', bg="#d1d1d1").pack(side=tk.LEFT)

ent = tk.Entry(row)

ent.insert(0, str(DEFAULT_THRESHOLDS[key]))

ent.pack(side=tk.RIGHT, expand=True, fill=tk.X)

entries[key] = ent



def open_file():

path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap;*.pcapng")])

if path:

try:

user_thresholds = {k: int(v.get()) for k, v in entries.items()}

# Run analysis in a separate thread to prevent GUI freezing

analysis_thread = threading.Thread(target=analyze_pcap, args=(path, text, chart, user_thresholds))

analysis_thread.start()

except ValueError:

messagebox.showerror("Input Error", "Please enter valid numbers for thresholds.")



tk.Button(right_frame, text="🚀 Analyze PCAP File", command=open_file, bg="#27ae60", fg="white", font=("Arial", 10, "bold"), pady=10).pack(fill=tk.X, pady=20)



# Results display section

text = tk.Text(left_frame, width=80, height=15, font=("Consolas", 10))

text.tag_config("header", foreground="blue", font=("Consolas", 11, "bold"))

text.tag_config("warning", foreground="red")

text.tag_config("safe", foreground="green")

text.pack(pady=5)


# Chart section

fig = plt.Figure(figsize=(6, 3), dpi=100)

chart = FigureCanvasTkAgg(fig, left_frame)

chart.get_tk_widget().pack(fill=tk.BOTH, expand=True)



root.mainloop()



if __name__ == "__main__":

gui() 

