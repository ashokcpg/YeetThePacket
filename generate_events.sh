#!/bin/bash

# Event Generation Script
echo "🔍 Event Detection Pipeline"

# Check for flow files
flow_files=$(ls output/flows_*.jsonl 2>/dev/null)

if [ -z "$flow_files" ]; then
    echo "❌ No flow files found in output/ directory"
    echo "   Run ingest.sh first to process PCAP files"
    exit 1
fi

echo "📊 Detecting events from flow files..."

for flow_file in $flow_files; do
    echo "🔄 Processing: $flow_file"
    
    # Run event detection
    python backend/detect.py "$flow_file"
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully processed: $flow_file"
    else
        echo "❌ Failed to process: $flow_file"
    fi
done

# Generate narratives if LLM is configured
if [ -f .env ]; then
    source .env
    if [ ! -z "$COHERE_API_KEY" ] || [ ! -z "$GEMINI_API_KEY" ] || [ ! -z "$OPENAI_API_KEY" ]; then
        echo "🤖 Generating AI narratives..."
        
        event_files=$(ls output/events_*.jsonl 2>/dev/null)
        for event_file in $event_files; do
            echo "🔄 Adding narratives to: $event_file"
            python backend/llm_client.py "$event_file"
        done
    else
        echo "⚠️  No LLM API keys found. Skipping narrative generation."
        echo "   Add API keys to .env file to enable AI narratives."
    fi
else
    echo "⚠️  No .env file found. Skipping narrative generation."
fi

echo "🎉 Event generation complete! Check output/ directory for results." 