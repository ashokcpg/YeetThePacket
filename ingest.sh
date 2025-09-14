#!/bin/bash

# PCAP Ingestion Script
echo "🔍 PCAP Ingestion Pipeline"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <pcap_file1> [pcap_file2] ..."
    echo "Example: $0 data/macdc2012/*.pcap"
    exit 1
fi

# Create output directory
mkdir -p output

echo "📁 Processing PCAP files..."

for pcap_file in "$@"; do
    if [ ! -f "$pcap_file" ]; then
        echo "⚠️  File not found: $pcap_file"
        continue
    fi
    
    echo "🔄 Processing: $pcap_file"
    
    # Run ingestion
    python backend/ingest.py "$pcap_file"
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully processed: $pcap_file"
    else
        echo "❌ Failed to process: $pcap_file"
    fi
done

echo "📊 Ingestion complete! Check output/ directory for results." 