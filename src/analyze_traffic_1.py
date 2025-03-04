import pyshark
import matplotlib.pyplot as plt
import numpy as np
import statistics
from collections import Counter
import os

# We assume that 'src' is the current folder.
# 'res' is one level up: ../res
out_dir = "../res"
os.makedirs(out_dir, exist_ok=True)

def save_fig(filename):
    """Save the current matplotlib figure to the 'res' folder and close it."""
    plt.ticklabel_format(style='plain', axis='y', useOffset=False)
    plt.savefig(os.path.join(out_dir, filename), dpi=300)
    plt.close()

# Dictionary mapping application names to their .pcapng files
# We assume that 'data' is also one level up: ../data
apps = {
    "chrome": "../data/chrome_only.pcapng",
    "firefox": "../data/firefox_only.pcapng",
    "youtube music": "../data/youtubeMusic_audioStreaming.pcapng",
    "youtube": "../data/youtube_videoStreaming.pcapng",
    "zoom": "../data/zoom_videoConferencing.pcapng"
}

my_local_ip = "192.168.126.132"

TCP_FLAGS_MAPPING = {
    0x02: "SYN",
    0x12: "SYN-ACK",
    0x10: "ACK",
    0x18: "ACK-PUSH",
    0x11: "ACK-FIN",
}

def parse_tcp_flags(hex_str):
    try:
        val = int(hex_str, 16)
        return TCP_FLAGS_MAPPING.get(val, "OTHER")
    except:
        return "OTHER"

# Initialize data structure
app_data = {}
for app in apps:
    app_data[app] = {
        "tcp_window_sizes": [],
        "ttl_values": [],
        "incoming": 0,
        "outgoing": 0,
        "protocol_counts": Counter(),
        "tls_count": 0,
        "packet_sizes": [],
        "timestamps": [],
        "total_packets": 0,
        "flow_volume": 0,
        "flow_size": 0,
        "avg_inter_arrival": 0,
        "bits_per_second": 0,
        "tcp_flags_detail": Counter(),
    }

# Process each .pcapng file using pyshark
for app, pcap_file in apps.items():
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    for pkt in cap:
        app_data[app]["total_packets"] += 1

        try:
            size = int(pkt.length)
            app_data[app]["packet_sizes"].append(size)
        except:
            pass

        try:
            ts = float(pkt.sniff_timestamp)
            app_data[app]["timestamps"].append(ts)
        except:
            pass

        try:
            src_ip = pkt.ip.src
            if src_ip == my_local_ip:
                app_data[app]["outgoing"] += 1
            else:
                app_data[app]["incoming"] += 1
        except:
            pass

        # Protocol identification
        if 'QUIC' in pkt:
            app_data[app]["protocol_counts"]['QUIC'] += 1
        elif 'TLS' in pkt or 'SSL' in pkt:
            app_data[app]["protocol_counts"]['TLS'] += 1
            app_data[app]["tls_count"] += 1
        elif 'TCP' in pkt:
            app_data[app]["protocol_counts"]['TCP'] += 1
        elif 'UDP' in pkt:
            app_data[app]["protocol_counts"]['UDP'] += 1
        else:
            app_data[app]["protocol_counts"]['OTHER'] += 1

        # TCP-specific fields
        if 'TCP' in pkt:
            try:
                win_size = int(pkt.tcp.window_size)
                app_data[app]["tcp_window_sizes"].append(win_size)
            except:
                pass

            try:
                flags_hex = pkt.tcp.flags
                parsed_flag = parse_tcp_flags(flags_hex)
                app_data[app]["tcp_flags_detail"][parsed_flag] += 1
            except:
                pass

        # TTL if IP layer exists
        if 'IP' in pkt:
            try:
                ttl = int(pkt.ip.ttl)
                app_data[app]["ttl_values"].append(ttl)
            except:
                pass
    cap.close()

# Compute flow stats
for app in app_data:
    app_data[app]["flow_size"] = app_data[app]["total_packets"]
    if app_data[app]["packet_sizes"]:
        app_data[app]["flow_volume"] = sum(app_data[app]["packet_sizes"])
    else:
        app_data[app]["flow_volume"] = 0

    times_sorted = sorted(app_data[app]["timestamps"])
    if len(times_sorted) > 1:
        diffs = [times_sorted[i + 1] - times_sorted[i] for i in range(len(times_sorted) - 1)]
        app_data[app]["avg_inter_arrival"] = statistics.mean(diffs)

        duration = times_sorted[-1] - times_sorted[0]
        if duration > 0:
            total_bytes = sum(app_data[app]["packet_sizes"])
            app_data[app]["bits_per_second"] = (total_bytes * 8) / duration
        else:
            app_data[app]["bits_per_second"] = 0
    else:
        app_data[app]["avg_inter_arrival"] = 0
        app_data[app]["bits_per_second"] = 0

# ----- Start plotting and saving -----

apps_list = list(apps.keys())
x = np.arange(len(apps_list))

# (1) Average TCP Window Size
avg_win_sizes = [
    statistics.mean(app_data[a]["tcp_window_sizes"]) if app_data[a]["tcp_window_sizes"] else 0
    for a in apps_list
]
plt.figure()
plt.bar(apps_list, avg_win_sizes, color='pink')
plt.xlabel("Application")
plt.ylabel("Average TCP Window Size (bytes)")
plt.title("Average TCP Window Size by Application")
save_fig("Average_TCP_Window_Size.png")

# (2) Average TTL
avg_ttl_vals = [
    statistics.mean(app_data[a]["ttl_values"]) if app_data[a]["ttl_values"] else 0
    for a in apps_list
]
plt.figure()
plt.bar(apps_list, avg_ttl_vals, color='purple')
plt.xlabel("Application")
plt.ylabel("Average TTL")
plt.title("Average TTL by Application")
save_fig("Average_TTL.png")

# (3) Protocol Distribution (stacked)
protocols = ["TCP", "UDP", "TLS", "QUIC"]
prot_dist = {p: [] for p in protocols}
for app in apps_list:
    total = app_data[app]["total_packets"]
    for p in protocols:
        cnt = app_data[app]["protocol_counts"][p]
        perc = (cnt / total * 100) if total > 0 else 0
        prot_dist[p].append(perc)

plt.figure()
bottom = np.zeros(len(apps_list))
bar_width = 0.5
for p in protocols:
    plt.bar(x, prot_dist[p], bar_width, bottom=bottom, label=p)
    bottom += prot_dist[p]
plt.xticks(x, apps_list)
plt.xlabel("Application")
plt.ylabel("Percentage of Packets (%)")
plt.title("Protocol Distribution by Application")
plt.legend()
save_fig("Protocol_Distribution.png")

# (4) TLS Usage
tls_perc_list = []
for app in apps_list:
    total = app_data[app]["total_packets"]
    tls_count = app_data[app]["tls_count"]
    tls_perc_list.append((tls_count / total) * 100 if total else 0)

plt.figure()
plt.bar(apps_list, tls_perc_list, color='green')
plt.xlabel("Application")
plt.ylabel("TLS Packets (%)")
plt.title("TLS Usage by Application")
save_fig("TLS_Usage_Percentage.png")

# (5) Flow Volume (Total Bytes)
flow_vols = [app_data[a]["flow_volume"] for a in apps_list]
plt.figure()
plt.bar(apps_list, flow_vols, color='magenta')
plt.xlabel("Application")
plt.ylabel("Total Bytes (Flow Volume)")
plt.title("Flow Volume by Application")
save_fig("Flow_Volume_Total_Bytes_Transmitted.png")

# (6) Flow Size (Total Packets)
flow_sizes = [app_data[a]["flow_size"] for a in apps_list]
plt.figure()
plt.bar(apps_list, flow_sizes, color='orange')
plt.xlabel("Application")
plt.ylabel("Number of Packets (Flow Size)")
plt.title("Flow Size (Total Packets) by Application")
save_fig("Flow_Size_Total_Packets_Transmitted.png")

# (7) Average Inter-Arrival Time
avg_iat = [app_data[a]["avg_inter_arrival"] for a in apps_list]
plt.figure()
plt.bar(apps_list, avg_iat, color='blue')
plt.xlabel("Application")
plt.ylabel("Avg Inter-Arrival Time (seconds)")
plt.title("Average Inter-Arrival Time by Application")
save_fig("Average_Inter_Time_Between_Packets.png")

# (8) Traffic Direction (Incoming vs Outgoing)
incoming_ratio = []
outgoing_ratio = []
for app in apps_list:
    inc = app_data[app]["incoming"]
    out = app_data[app]["outgoing"]
    tot = inc + out
    if tot > 0:
        incoming_ratio.append((inc / tot) * 100)
        outgoing_ratio.append((out / tot) * 100)
    else:
        incoming_ratio.append(0)
        outgoing_ratio.append(0)

plt.figure()
plt.bar(x, incoming_ratio, label='Incoming', color='orange')
plt.bar(x, outgoing_ratio, bottom=incoming_ratio, label='Outgoing', color='blue')
plt.xticks(x, apps_list)
plt.xlabel("Application")
plt.ylabel("Traffic Direction (%)")
plt.title("Traffic Direction (Incoming vs Outgoing) by Application")
plt.legend()
save_fig("Traffic_Direction.png")

# (9) Average Packet Size
avg_pkt_size = []
for app in apps_list:
    pkts = app_data[app]["packet_sizes"]
    if pkts:
        avg_pkt_size.append(statistics.mean(pkts))
    else:
        avg_pkt_size.append(0)

plt.figure()
plt.bar(apps_list, avg_pkt_size, color='cyan')
plt.xlabel("Application")
plt.ylabel("Average Packet Size (bytes)")
plt.title("Average Packet Size by Application")
save_fig("Average_Packet_Size.png")

# (10) Bits per Second (Throughput)
bps_vals = [app_data[a]["bits_per_second"] for a in apps_list]
plt.figure()
plt.bar(apps_list, bps_vals, color='red')
plt.xlabel("Application")
plt.ylabel("Bits per Second")
plt.title("Network Throughput (Bits per Second) by Application")
save_fig("Bit_Rate_Per_Sec.png")

# (11) TCP Flags Distribution (stacked)
flag_categories = ["SYN", "SYN-ACK", "ACK", "ACK-PUSH", "ACK-FIN"]
x_idx = np.arange(len(apps_list))
bar_width = 0.5

plt.figure(figsize=(10, 6))
bottom = np.zeros(len(apps_list))
for flag in flag_categories:
    flag_percents = []
    for app in apps_list:
        total_flags = sum(app_data[app]["tcp_flags_detail"].values())
        count = app_data[app]["tcp_flags_detail"].get(flag, 0)
        percentage = (count / total_flags) * 100 if total_flags > 0 else 0
        flag_percents.append(percentage)
    plt.bar(x_idx, flag_percents, bar_width, bottom=bottom, label=flag)
    bottom += np.array(flag_percents)

plt.xticks(x_idx, apps_list, rotation=30, ha="right")
plt.xlabel("Application")
plt.ylabel("Percentage of TCP Flags (%)")
plt.title("TCP Flags Distribution by Application (Stacked)")
plt.legend(loc='upper left', bbox_to_anchor=(1, 1), title="TCP Flags", fontsize=8)
plt.tight_layout(rect=[0, 0, 0.8, 1])
save_fig("TCP_Flags_Distribution_Stacked.png")

print("All graphs have been generated and saved in the '../res' folder!")
