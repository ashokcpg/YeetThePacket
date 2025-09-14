# YeetThePacket: Network Event Storyteller

A prototype that ingests PCAP files and converts network events into human-readable narrated "stories" using LLMs. Built for non-technical users to explore network security incidents with supporting evidence, filtering, and exportable reports.

## Features

- 🔍 **PCAP Ingestion**: Process network packet captures (MACCDC 2012 dataset supported)
- 🤖 **AI Narratives**: Convert technical network events into human-readable stories
- 📊 **Interactive UI**: Timeline view, filtering, search, and detailed evidence panels
- 📈 **Network Visualization**: Force-directed graphs showing host relationships
- 📄 **Export Reports**: Generate PDF incident reports for selected events
- 🐳 **Docker Ready**: One-command deployment with Docker Compose

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.9+ (for local development)
- API key for LLM provider (Cohere, Gemini, or OpenAI)

### Setup
1. Clone and navigate to project:
```bash
git clone <repo-url>
cd HTN-Project
```

2. Set up environment variables:
```bash
cp env.example .env
# Edit .env with your LLM API key
```

3. Start the application:
```bash
./run_local.sh
```

4. Access the application:
   - **Frontend UI**: http://localhost:8501
   - **Backend API**: http://localhost:8000
   - **API Documentation**: http://localhost:8000/docs

### Test the System
```bash
python test_system.py
```

### Manual Setup (Development)

1. Install dependencies:
```bash
pip install -r backend/requirements.txt
```

2. Process PCAP files:
```bash
./ingest.sh data/macdc2012/*.pcap
```

3. Generate events:
```bash
./generate_events.sh
```

4. Start services:
```bash
# Terminal 1: Backend
cd backend && python app.py

# Terminal 2: Frontend  
cd frontend && streamlit run streamlit_app.py
```

## Architecture

- **Ingestion Layer**: tshark/pyshark for PCAP parsing → normalized flows
- **Detection Engine**: Heuristic rules for port scans, brute force, beaconing
- **LLM Integration**: Cohere/Gemini/OpenAI for narrative generation
- **Backend API**: FastAPI with endpoints for data processing
- **Frontend UI**: Streamlit for rapid prototyping with rich interactions
- **Storage**: Local files (JSONL) with optional SQLite for queries

## Event Types Detected

- **Port Scans**: High unique destination port counts
- **Brute Force**: Repeated connection attempts to auth services
- **Beaconing**: Periodic communication patterns
- **Suspicious Connections**: Unusual protocols or behaviors
- **Data Exfiltration**: Large data transfers to external hosts

## API Endpoints

- `POST /ingest` - Upload and process PCAP files
- `GET /events` - Retrieve processed events with filtering
- `GET /events/{id}/narrate` - Generate narrative for specific event
- `POST /export` - Generate PDF report for selected events

## Data Pipeline

```
PCAP Files → Flow Extraction → Feature Engineering → Event Detection → LLM Narratives → UI Display
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

MIT License - see LICENSE file for details # YeetThePacket
"# YeetThePacket" 
