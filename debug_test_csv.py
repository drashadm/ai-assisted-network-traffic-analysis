import csv
import os

def debug_csv_read(input_csv):
    if not os.path.exists(input_csv):
        print(f"[!] File not found: {input_csv}")
        return

    print(f"[~] Opening: {input_csv}")
    with open(input_csv, 'r', encoding='utf-8', errors='ignore') as infile:
        reader = csv.DictReader(infile)
        print(f"[~] Detected fieldnames: {reader.fieldnames}")

        row_count = 0
        for i, row in enumerate(reader, start=1):
            print(f"\n[+] Row #{i}:")
            print(row)
            row_count += 1
            if i >= 3:  # Just preview first 3 rows
                break

        print(f"[i] Total rows read: {row_count}")

# Test run
debug_csv_read("C:\Users\poorm\ai-assisted-network-traffic-analysis\debug_test_csv.py")
