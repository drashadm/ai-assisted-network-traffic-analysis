# ai-assisted-network-traffic-analysis
Python-based PCAP traffic analyzer with AI-powered summarization of HTTP sessions and network patterns.

# 📡 AI-Assisted Network Traffic Analyzer

## 🧠 Purpose
This tool extracts and analyzes network traffic from `.pcap` files using PyShark and Python. It's built for SOC analysts, blue teamers, and students looking to understand HTTP traffic — with an optional AI assistant to summarize the findings.

## 🔧 Features
- This script analyzes `.pcap` files for HTTP traffic and outputs both:
- Supports AI-based summarization of traffic patterns
- Outputs results to `.csv` for easy inspection or import into SIEM tools
- Full detailed CSVs
- AI-style summary insights for User-Agents and Host frequencies

## 🧪 Planned AI Add-ons
- GPT-assisted summaries of suspicious activity
- Log pattern clustering using unsupervised learning
- Auto-flagging based on known IOC heuristics

## 📂 Usage
```bash
python analyze.py sample_data/traffic_sample.pcap outputs/parsed_output.csv
