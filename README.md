# 🛡️ Network Traffic Analyzer & Data Exfiltration Detector


An automated cybersecurity analysis tool designed to inspect network packet captures (`.pcap`), establish normal baseline traffic patterns, detect anomalous data exfiltration attempts, and generate comparative statistical visualizations.

---

## 📖 Project Overview

In network security, identifying malicious data exfiltration hiding behind legitimate web protocols is a critical challenge. This project implements a dual-capture comparison methodology:
1. **Network Baseline Generation:** Captures everyday standard web browsing traffic (DNS, HTTPS, standard TCP sessions) to map normal behavior.
2. **Exfiltration Simulation:** Ingests targeted malicious or anomalous traffic files containing large payload transfers.
3. **Automated Packet Parsing Engine (`analyzer.py`):** Uses **Scapy** and **Pandas** to extract packet metadata, compute distribution metrics, and flag suspicious high-payload anomalies exceeding configured safety thresholds.
4. **Data Visualization:** Generates professional kernel density estimation (KDE) charts using **Matplotlib** and **Seaborn** to visually contrast baseline density against exfiltration spikes.

---

## 🛠️ Tech Stack & Dependencies

* **Language:** Python 3.14.5
* **Packet Inspection & Sniffing:** Wireshark, Npcap
* **Packet Parsing Library:** Scapy
* **Data Manipulation:** Pandas
* **Visualization Engine:** Matplotlib, Seaborn

---

## 📁 Repository Architecture

```text
network-traffic-analyzer/
├── data/                       
│   ├── baseline.pcap           # Clean network baseline capture (Normal traffic)
│   └── exfiltration.pcap       # Suspicious/anomalous payload transfer capture
├── scripts/                    
│   └── analyzer.py             # Core automation script for packet analysis & alerting
├── visualizations/             
│   └── packet_size_comparison.png  # Generated comparative statistical distribution graph
└── README.md                   # Complete technical documentation.



⚙️ Installation & Setup Guide

1. Clone the Repository
Open your terminal and clone the repository to your local machine:

git clone https://github.com/YOURUSERNAME/network-traffic-analyzer.git
cd network-traffic-analyzer

2. Install Required Python Packages
Ensure you have Python installed, then install the required dependencies:

pip install scapy pandas matplotlib seaborn

3. Verify Packet Capture Files
Ensure your sample capture files are placed correctly in the data/ directory:

data/baseline.pcap

data/exfiltration.pcap

💻 Running the Analysis Script
Execute the core analysis workflow from the root project directory:

python scripts/analyzer.py

Sample Terminal Output:

[-] Analyzing: data/baseline.pcap...
[+] Total Packets Captured: 37955
[+] Average Packet Size: 128.86 bytes
[+] Max Packet Size: 1304 bytes

[-] Analyzing: data/exfiltration.pcap...
[+] Total Packets Captured: 2026
[+] Average Packet Size: 191.47 bytes
[+] Max Packet Size: 1514 bytes

[--- Exfiltration Detection Analysis ---]
[!] Alert: Found 180 packets exceeding 1200 bytes!
Top suspicious large packets:
   Source         Destination Protocol  Length
12 104.28.10.141  10.12.13.103    TCP     1514
14 104.28.10.141  10.12.13.103    TCP     1514
...
[+] Saved visualization: visualizations/packet_size_comparison.png
📊 Results & Visual Analysis
The script automatically outputs a comparative distribution chart to visualizations/packet_size_comparison.png.

Baseline Distribution (Blue Curve): Clustered heavily toward smaller packet lengths, characteristic of typical web navigation, DNS lookups, and short acknowledgement (ACK) packets.

Exfiltration Spike (Red Curve): Features a clear density shift and an anomalous frequency hump pushing toward maximum packet size limits (~1514 bytes), indicating bulk data staging or unauthorized tunneling.

👤 Author
Developed by MD KAMIL HASHMI

GitHub: kamil-9836

Contributions, suggestions, and issue reports are always welcome!