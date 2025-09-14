# MACCDC 2012 Processing Guide

## 🎯 Handling Large PCAP Files

The MACCDC 2012 dataset contains very large network captures that can be challenging to process. This guide provides several strategies for efficient analysis.

## 📊 File Size Expectations

- **Compressed (.gz)**: 50-200 MB
- **Extracted (.pcap)**: 500MB - 5GB+
- **Processing time**: 5-30 minutes depending on method

## 🚀 Processing Options

### Option 1: Smart Sampling (Recommended)
Process a representative sample of the traffic for faster analysis:

```bash
# Process 10% sample (default)
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode sample

# Process 5% sample for very large files
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode sample --sample-rate 0.05

# Process 20% sample for more detail
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode sample --sample-rate 0.2
```

### Option 2: Time Window Analysis
Analyze a specific time period (great for incident investigation):

```bash
# Process first hour of traffic
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode window --window-minutes 60

# Process first 30 minutes for quick analysis
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode window --window-minutes 30

# Process first 4 hours for comprehensive view
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode window --window-minutes 240
```

### Option 3: Full Processing
Process the entire file (use for final analysis):

```bash
# Full processing (may take 15-30 minutes)
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode full
```

## 📋 Quick File Information

Check file details before processing:

```bash
# Get PCAP information without processing
python process_maccdc.py data/maccdc2012_00000.pcap.gz --info-only
```

## ⚡ Performance Tips

### 1. **Start Small, Scale Up**
```bash
# Quick test with 1% sample
python process_maccdc.py your_file.pcap.gz --mode sample --sample-rate 0.01

# If results look good, increase to 10%
python process_maccdc.py your_file.pcap.gz --mode sample --sample-rate 0.1
```

### 2. **Skip Narratives for Speed**
```bash
# Process without AI narratives (much faster)
python process_maccdc.py your_file.pcap.gz --mode sample --no-narratives
```

### 3. **Use Time Windows for Incident Analysis**
```bash
# Focus on specific time periods where attacks occurred
python process_maccdc.py your_file.pcap.gz --mode window --window-minutes 15
```

## 🔧 System Requirements

### Minimum:
- **RAM**: 4GB available
- **Disk**: 2x PCAP file size free space
- **Time**: 5-15 minutes for sampling

### Recommended:
- **RAM**: 8GB+ available
- **Disk**: 5x PCAP file size free space  
- **Time**: Allow 30+ minutes for full processing

## 📁 File Organization

```
data/
├── maccdc2012_00000.pcap.gz    # Compressed original
├── maccdc2012_00001.pcap.gz    # Additional captures
└── README.md

output/
├── maccdc_events_sample.jsonl   # Sampled results
├── maccdc_events_window.jsonl   # Time window results
└── maccdc_events_full.jsonl     # Full processing results
```

## 🎯 Recommended Workflow

### 1. **Initial Exploration**
```bash
# Check file info
python process_maccdc.py data/maccdc2012_00000.pcap.gz --info-only

# Quick 5% sample
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode sample --sample-rate 0.05
```

### 2. **Detailed Analysis**
```bash
# 10% sample with narratives
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode sample --sample-rate 0.1

# Focus on first hour if events found
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode window --window-minutes 60
```

### 3. **Production Analysis**
```bash
# Full processing for comprehensive results
python process_maccdc.py data/maccdc2012_00000.pcap.gz --mode full
```

## 🚨 Troubleshooting

### "Memory Error" or System Slowdown
- Reduce sample rate: `--sample-rate 0.01`
- Use time windows: `--mode window --window-minutes 15`
- Close other applications
- Add `--no-narratives` flag

### "No Events Detected"
- Try different sample rates
- Check different time windows
- Verify PCAP file integrity
- Look at raw flow statistics

### Processing Takes Too Long
- Start with `--sample-rate 0.01` (1%)
- Use `--no-narratives` for speed
- Try `--mode window --window-minutes 10`

## 📈 Expected Results

### Typical MACCDC Events Found:
- **Port Scans**: 5-20 events
- **Brute Force**: 2-10 events  
- **Beaconing**: 1-5 events
- **Data Exfiltration**: 0-3 events
- **Suspicious Connections**: 10-50 events

### Processing Times:
- **1% Sample**: 1-2 minutes
- **10% Sample**: 3-8 minutes
- **1 Hour Window**: 2-5 minutes
- **Full Processing**: 15-45 minutes

## 🎉 Next Steps

After processing, use the Streamlit UI to explore results:

```bash
# Start the web interface
streamlit run frontend/streamlit_app.py
```

Then navigate to http://localhost:8501 to explore your events! 