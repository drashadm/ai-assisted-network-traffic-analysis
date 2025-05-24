import pyshark
import csv
import time
import os
from collections import Counter

def extract_http_metadata(packet):
    """Extracts HTTP metadata from a single packet safely."""
    try:
        return {
            "No": packet.number,
            "Source IP": packet.ip.src,
            "Destination IP": packet.ip.dst,
            "Host": getattr(packet.http, "host", ""),
            "Request URI": getattr(packet.http, "request_uri", ""),
            "User-Agent": getattr(packet.http, "user_agent", "")
        }
    except AttributeError:
        return None

def analyze_http_traffic(pcap_file, output_file, summary_file=None):
    print(f"[~] Starting analysis on: {pcap_file}")
    start_time = time.time()

    cap = pyshark.FileCapture(pcap_file, display_filter="http")

    # Output: detailed CSV
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["No", "Source IP", "Destination IP", "Host", "Request URI", "User-Agent"])
        writer.writeheader()

        user_agents = []
        request_hosts = []

        for packet in cap:
            data = extract_http_metadata(packet)
            if data:
                writer.writerow(data)
                if data["User-Agent"]:
                    user_agents.append(data["User-Agent"])
                if data["Host"]:
                    request_hosts.append(data["Host"])

    elapsed = time.time() - start_time
    print(f"[+] Full HTTP analysis written to {output_file}")
    print(f"[i] Processed in {elapsed:.2f} seconds")

    # AI-style summary (automated insights)
    if summary_file:
        ua_count = Counter(user_agents)
        host_count = Counter(request_hosts)
        with open(summary_file, 'w') as f:
            f.write("=== AI-Aided HTTP Traffic Summary ===\n\n")
            f.write("Top 5 Most Frequent User-Agents:\n")
            for ua, count in ua_count.most_common(5):
                f.write(f"- {ua}: {count} times\n")

            f.write("\nTop 5 Requested Hosts:\n")
            for host, count in host_count.most_common(5):
                f.write(f"- {host}: {count} times\n")

        print(f"[+] Summary report written to {summary_file}")

# Example usage
# analyze_http_traffic("sample_data/traffic_sample.pcap", "outputs/parsed_output.csv", "outputs/summary.txt")
