from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Set plotting style
sns.set_theme(style="darkgrid")

def analyze_pcap(file_path):
    print(f"\n[-] Analyzing: {file_path}...")
    
    if not os.path.exists(file_path):
        print(f"[!] Error: File {file_path} not found. Please check your path.")
        return None

    # Read packets using Scapy
    packets = rdpcap(file_path)
    print(f"[+] Total Packets Captured: {len(packets)}")

    data = []
    for pkt in packets:
        if IP in pkt:
            proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "Other")
            data.append({
                "Source": pkt[IP].src,
                "Destination": pkt[IP].dst,
                "Protocol": proto,
                "Length": len(pkt)
            })

    # Convert to pandas DataFrame for easy analysis
    df = pd.DataFrame(data)
    if df.empty:
        print("[!] No IPv4 packets found in this capture.")
        return None

    print(f"[+] Average Packet Size: {df['Length'].mean():.2f} bytes")
    print(f"[+] Max Packet Size: {df['Length'].max()} bytes")
    
    return df

def detect_exfiltration(df, threshold=1500):
    """Detects potential exfiltration based on unusually large packets."""
    print("\n[--- Exfiltration Detection Analysis ---]")
    large_packets = df[df['Length'] > threshold]
    
    if not large_packets.empty:
        print(f"[!] Alert: Found {len(large_packets)} packets exceeding {threshold} bytes!")
        print("Top suspicious large packets:")
        print(large_packets[['Source', 'Destination', 'Protocol', 'Length']].head())
    else:
        print("[+] No suspicious large packets detected above the threshold.")

def generate_visualizations(baseline_df, exfil_df):
    os.makedirs("visualizations", exist_ok=True)
    
    # 1. Packet Size Distribution Comparison
    plt.figure(figsize=(10, 5))
    if baseline_df is not None and not baseline_df.empty:
        sns.kdeplot(baseline_df['Length'], label="Baseline Traffic", fill=True, alpha=0.4)
    if exfil_df is not None and not exfil_df.empty:
        sns.kdeplot(exfil_df['Length'], label="Exfiltration Traffic", fill=True, alpha=0.4, color="red")
    
    plt.title("Packet Size Distribution: Baseline vs Exfiltration")
    plt.xlabel("Packet Length (Bytes)")
    plt.ylabel("Density")
    plt.legend()
    plt.savefig("visualizations/packet_size_comparison.png")
    plt.close()
    print("[+] Saved visualization: visualizations/packet_size_comparison.png")

if __name__ == "__main__":
    # Define file paths
    baseline_path = "data/baseline.pcap"
    exfil_path = "data/exfiltration.pcap"

    # Analyze Baseline
    baseline_df = analyze_pcap(baseline_path)
    
    # Analyze Exfiltration
    exfil_df = analyze_pcap(exfil_path)
    if exfil_df is not None:
        detect_exfiltration(exfil_df, threshold=1200)

    # Generate Graphs
    generate_visualizations(baseline_df, exfil_df)
    print("\n[+] Analysis complete! Check the 'visualizations/' folder for generated graphs.")