# Packet-to-Prompt Demo Script

## Overview
This 2-3 minute demo showcases how Packet-to-Prompt converts raw network traffic into human-readable security incident narratives using AI.

## Demo Flow

### 1. Setup & Introduction (30 seconds)
"Welcome to Packet-to-Prompt - a tool that transforms complex network traffic into clear, actionable security stories. Let me show you how it works."

**Show:** 
- Main dashboard with clean, professional interface
- Brief explanation of the problem: "Network security analysts spend hours analyzing packet captures. We make it instant."

### 2. Data Upload & Processing (45 seconds)
"Let's start with a real network capture from the MACCDC 2012 dataset."

**Demo Steps:**
1. Navigate to Upload tab
2. Upload a sample PCAP file (pre-prepared, ~5MB)
3. Click "Upload & Process" with narratives enabled
4. Show processing status with real-time progress
5. "In just seconds, we've analyzed thousands of network flows"

**Expected Result:** Processing completes showing "X events detected"

### 3. Event Dashboard (30 seconds)
"Now let's see what security events were discovered."

**Show:**
- Dashboard tab with statistics:
  - Total events found
  - Event type breakdown (port scans, brute force, etc.)
  - Severity distribution
  - Timeline overview

**Highlight:** "Notice we found several high-severity events that need attention"

### 4. Event Analysis (45 seconds)
"Let's investigate a critical security event."

**Demo Steps:**
1. Go to Events tab
2. Click on a high-severity event (port scan or brute force)
3. Show detailed event view with:
   - AI-generated executive summary in plain English
   - Technical analysis with evidence references
   - MITRE ATT&CK tactics identified
   - Specific remediation recommendations

**Key Quote:** "Instead of raw packet data, we get clear explanations like: 'Host X attempted to brute force SSH on Host Y with 47 failed attempts in 3 minutes.'"

### 5. Visual Intelligence (20 seconds)
"The tool also provides visual context."

**Show:**
- Timeline view showing when events occurred
- Network graph showing communication patterns
- "This helps analysts understand the full attack narrative"

### 6. Incident Response (30 seconds)
"For incident response, we can generate executive reports."

**Demo Steps:**
1. Select 2-3 related events
2. Click "Export PDF Report"
3. Show generated PDF with:
   - Executive summary
   - Technical details
   - Recommended actions

**Highlight:** "Perfect for briefing management or documenting incidents"

## Key Messages to Emphasize

### Problem Solved
- **Before:** Hours of manual packet analysis, cryptic technical data
- **After:** Instant, clear security narratives with actionable insights

### Technical Innovation
- **AI-Powered:** Uses advanced LLMs to create human-readable explanations
- **Evidence-Based:** Every conclusion backed by specific network evidence
- **Comprehensive:** Detects multiple attack types automatically

### Business Value
- **Speed:** Minutes instead of hours for analysis
- **Accessibility:** Non-technical stakeholders can understand results
- **Actionable:** Specific remediation steps provided

## Demo Tips

### Preparation
- Pre-load a PCAP file with interesting events
- Have .env configured with working API keys
- Test the full pipeline beforehand
- Prepare backup slides in case of technical issues

### Presentation Style
- Keep energy high and pace brisk
- Use concrete numbers ("47 failed attempts", "3 minutes")
- Emphasize the transformation from complex to simple
- Show confidence in the technology

### Potential Questions & Answers

**Q: "How accurate are the AI narratives?"**
A: "The AI only uses evidence from the actual network traffic. Every claim is backed by specific packet data, and we include confidence scores."

**Q: "What types of attacks can it detect?"**
A: "Currently port scans, brute force, beaconing, data exfiltration, and suspicious connections. The modular design makes it easy to add new detectors."

**Q: "How does it scale?"**
A: "Built on FastAPI and designed for cloud deployment. Can process multiple PCAPs simultaneously and handle enterprise-scale traffic."

## Backup Demos

### If Upload Fails
- Show pre-processed events from sample data
- Focus on narrative quality and visualization features

### If API is Down
- Use static screenshots/video
- Emphasize the technical architecture and potential

## Closing Statement
"Packet-to-Prompt bridges the gap between raw network data and actionable security intelligence. It's not just about detecting threats - it's about understanding them and responding effectively. Thank you!"

---

**Total Time: 3 minutes**
**Key Takeaway: Complex network security made simple through AI** 