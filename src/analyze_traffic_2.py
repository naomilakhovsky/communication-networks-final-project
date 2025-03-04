import matplotlib
matplotlib.use('TkAgg')  # Use "TkAgg" backend to avoid the InterAgg error

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import re

# We assume that 'src' is the current folder.
# So data is one level up in the 'data' folder,
# and res is also one level up in 'res' folder.

out_dir = "../res"
os.makedirs(out_dir, exist_ok=True)

def save_fig(filename):
    """Saves the current matplotlib figure to the 'res' folder and closes it."""
    plt.savefig(os.path.join(out_dir, filename), dpi=300)
    plt.close()

# File paths (relative) for CSV data
file_paths = {
    "Zoom": "../data/csv_zoom.csv",
    "YouTube Music": "../data/csv_youtubeMusic.csv",
    "YouTube": "../data/csv_youtube.csv",
    "Firefox": "../data/csv_firefox.csv",
    "Chrome": "../data/csv_chrome.csv"
}

# Load CSV files into DataFrames for each service
dataframes = {name: pd.read_csv(path) for name, path in file_paths.items()}

# Dictionary to store percentage of TLS handshake features by service
tls_handshake_counts = {}
tls_features = ["Client Hello", "Server Hello"]

# Collect TLS handshake counts (excluding 'Finished') and compute percentages
for name, df in dataframes.items():
    if "Protocol" in df.columns and "Info" in df.columns:
        counts = {}
        for feature in tls_features:
            count_feature = len(
                df[
                    df["Protocol"].str.contains("TLS", na=False) &
                    df["Info"].str.contains(feature, na=False)
                ]
            )
            counts[feature] = count_feature

        total = sum(counts.values())
        if total > 0:
            tls_handshake_counts[name] = {k: (v / total) * 100 for k, v in counts.items()}
        else:
            tls_handshake_counts[name] = {k: 0 for k in counts}

# Convert TLS handshake data into a DataFrame
tls_handshake_percent_df = pd.DataFrame(tls_handshake_counts).T

# TLS Handshake Features per Service (Percentage)
plt.figure(figsize=(10, 5))
tls_handshake_percent_df.plot(kind="bar", stacked=True, figsize=(10, 5))
plt.title("TLS Handshake Features per Service (Percentage)")
plt.xlabel("Service")
plt.ylabel("Percentage of TLS Handshake Packets (%)")
plt.legend(title="TLS Feature")
plt.grid(axis='y')
plt.tight_layout()
save_fig("TLS_Handshake_Features_per_Service.png")

# Compare PSH vs SYN,ACK in TCP packets (percentage per service)
push_counts = {}
syn_ack_counts = {}

for name, df in dataframes.items():
    if "Protocol" in df.columns and "Info" in df.columns:
        push_count = len(
            df[
                df["Protocol"].str.contains("TCP", na=False) &
                df["Info"].str.contains("PSH", na=False)
            ]
        )
        syn_ack_count = len(
            df[
                df["Protocol"].str.contains("TCP", na=False) &
                df["Info"].str.contains("SYN, ACK", na=False)
            ]
        )
        push_counts[name] = push_count
        syn_ack_counts[name] = syn_ack_count

comparison_df_abs = pd.DataFrame({
    "PSH": push_counts,
    "SYN, ACK": syn_ack_counts
})

# Convert to percentage counts
comparison_percent_df = comparison_df_abs.astype("float64")
for service in comparison_percent_df.index:
    total = comparison_percent_df.loc[service].sum()
    if total > 0:
        comparison_percent_df.loc[service] = (comparison_percent_df.loc[service] / total) * 100
    else:
        comparison_percent_df.loc[service] = 0

# Comparison of PSH vs. SYN, ACK Packets per Service (Percentage)
plt.figure(figsize=(10, 5))
comparison_percent_df.plot(kind="bar", figsize=(10, 5))
plt.title("Comparison of PSH vs. SYN, ACK Packets per Service (Percentage)")
plt.xlabel("Service")
plt.ylabel("Percentage of Packets (%)")
plt.legend(title="TCP Feature")
plt.grid(axis='y')
plt.tight_layout()
save_fig("Comparison_of_PSH_vs_SYN_ACK.png")

# Analyze TLS versions per service (normalized percentages)
tls_versions_counts = {}
for name, df in dataframes.items():
    if "Protocol" in df.columns:
        tls_versions = df[df["Protocol"].str.contains("TLS", na=False)]["Protocol"]
        version_counts = tls_versions.value_counts().to_dict()
        tls_versions_counts[name] = version_counts

tls_versions_df = pd.DataFrame(tls_versions_counts).fillna(0).T
tls_versions_df = tls_versions_df.div(tls_versions_df.sum(axis=1), axis=0) * 100

# TLS Version Distribution per Service (Percentage)
plt.figure(figsize=(12, 6))
tls_versions_df.plot(kind="bar", stacked=True, figsize=(12, 6))
plt.title("TLS Version Distribution per Service (Percentage)")
plt.xlabel("Service")
plt.ylabel("Percentage of TLS Packets (%)")
plt.legend(title="TLS Version")
plt.grid(axis='y')
plt.tight_layout()
save_fig("TLS_Version_Distribution_per_Service.png")

# Helper functions to extract source/destination ports from the Info column
def extract_source_port(info):
    if isinstance(info, str):
        match = re.match(r'\s*(\d+)\s*>', info)
        if match:
            return int(match.group(1))
    return None

def extract_destination_port(info):
    if isinstance(info, str):
        match = re.search(r'>\s*(\d+)', info)
        if match:
            return int(match.group(1))
    return None

source_port_list = []
destination_port_list = []

for service_name, df in dataframes.items():
    temp_df = df.copy()
    temp_df["Source Port"] = temp_df["Info"].apply(extract_source_port)
    temp_df["Destination Port"] = temp_df["Info"].apply(extract_destination_port)
    temp_df.dropna(subset=["Source Port", "Destination Port"], how="all", inplace=True)
    temp_df["Service"] = service_name

    sp_df = temp_df.dropna(subset=["Source Port"])[["Service", "Source Port"]]
    source_port_list.append(sp_df)

    dp_df = temp_df.dropna(subset=["Destination Port"])[["Service", "Destination Port"]]
    destination_port_list.append(dp_df)

source_port_combined = pd.concat(source_port_list, ignore_index=True)
destination_port_combined = pd.concat(destination_port_list, ignore_index=True)

def plot_top_10_ports_overall(df, port_col, title, filename):
    top_10_ports = df[port_col].value_counts().nlargest(10).index
    df_filtered = df[df[port_col].isin(top_10_ports)]
    pivot_df = df_filtered.groupby(["Service", port_col]).size().unstack(fill_value=0)
    pivot_percent = pivot_df.div(pivot_df.sum(axis=1), axis=0) * 100

    fig, ax = plt.subplots(figsize=(12, 6))
    colors = sns.color_palette("tab10", n_colors=len(pivot_percent.columns))
    pivot_percent.plot(kind="barh", stacked=True, ax=ax, color=colors)
    ax.set_title(title, pad=15)
    ax.set_xlabel("Percentage of Packets (%)")
    ax.set_ylabel("Service")
    ax.legend(title=port_col, bbox_to_anchor=(1.02, 1), loc="upper left", borderaxespad=0)
    ax.grid(axis="x")
    plt.tight_layout(rect=[0, 0, 0.8, 1])
    save_fig(filename)

# Top 10 Source Ports (Overall)
plot_top_10_ports_overall(
    source_port_combined,
    "Source Port",
    "Top 10 Source Ports (Overall) Distribution per Service (Percentage)",
    "Top_10_Source_Ports_Overall.png"
)

# Top 10 Destination Ports (Overall)
plot_top_10_ports_overall(
    destination_port_combined,
    "Destination Port",
    "Top 10 Destination Ports (Overall) Distribution per Service (Percentage)",
    "Top_10_Destination_Ports_Overall.png"
)
