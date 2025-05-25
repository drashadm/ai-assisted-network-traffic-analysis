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

    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="http")
    except Exception as e:
        print(f"[!] Error opening file: {e}")
        return

    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    packet_count = 0
    user_agents = []
    request_hosts = []

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["No", "Source IP", "Destination IP", "Host", "Request URI", "User-Agent"])
            writer.writeheader()

            for packet in cap:
                data = extract_http_metadata(packet)
                if data:
                    writer.writerow(data)
                    packet_count += 1
                    user_agents.append(data["User-Agent"])
                    request_hosts.append(data["Host"])
                    print(f"[+] Packet #{packet_count}: {data['Host']} {data['Request URI']}")
    except Exception as e:
        print(f"[!] Error during packet analysis: {e}")
        return

    elapsed = time.time() - start_time
    print(f"[i] Total HTTP packets processed: {packet_count}")
    print(f"[+] Traffic analysis written to {output_file}")
    print(f"[i] Time taken: {elapsed:.2f} seconds")

    # AI-style summary
    if summary_file and packet_count > 0:
        try:
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("=== AI-Aided HTTP Traffic Summary ===\n\n")

                f.write("Top 5 User-Agents:\n")
                for ua, count in Counter(user_agents).most_common(5):
                    f.write(f"- {ua}: {count} times\n")

                f.write("\nTop 5 Hosts:\n")
                for host, count in Counter(request_hosts).most_common(5):
                    f.write(f"- {host}: {count} times\n")

            print(f"[+] Summary report written to {summary_file}")
        except Exception as e:
            print(f"[!] Error writing summary file: {e}")

# Example usage (uncomment to run directly)
# analyze_http_traffic("sample_data/forage_investigation.pcapng", "outputs/parsed_output.csv", "outputs/summary.txt")
