import csv
import time
from collections import Counter
import os

def analyze_http_csv(input_csv, output_csv, summary_file=None):
    print(f"[~] Reading CSV from: {input_csv}")
    start_time = time.time()

    if not os.path.exists(input_csv):
        print(f"[!] Input file not found: {input_csv}")
        return

    user_agents = []
    hosts = []
    processed_rows = []

    with open(input_csv, 'r', encoding='utf-8', errors='ignore') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            try:
                processed_rows.append({
                    "No": row.get("No.") or row.get("No"),
                    "Source IP": row.get("Source"),
                    "Destination IP": row.get("Destination"),
                    "Host": row.get("Host", ""),
                    "Request URI": row.get("Request URI", ""),
                    "User-Agent": row.get("User-Agent", "")
                })

                if row.get("User-Agent"):
                    user_agents.append(row["User-Agent"])
                if row.get("Host"):
                    hosts.append(row["Host"])

            except Exception as e:
                print(f"[!] Skipping row due to error: {e}")
                continue

    # Write cleaned output
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=["No", "Source IP", "Destination IP", "Host", "Request URI", "User-Agent"])
        writer.writeheader()
        writer.writerows(processed_rows)

    print(f"[+] Parsed CSV written to {output_csv}")
    print(f"[i] Processed {len(processed_rows)} rows in {time.time() - start_time:.2f}s")

    if summary_file:
        os.makedirs(os.path.dirname(summary_file), exist_ok=True)
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=== AI-Aided HTTP Traffic Summary ===\n\n")

            f.write("Top 5 User-Agents:\n")
            for ua, count in Counter(user_agents).most_common(5):
                f.write(f"- {ua}: {count} times\n")

            f.write("\nTop 5 Hosts:\n")
            for host, count in Counter(hosts).most_common(5):
                f.write(f"- {host}: {count} times\n")

        print(f"[+] Summary written to {summary_file}")
