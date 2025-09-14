"""
FastAPI Backend Application
Provides REST API endpoints for PCAP ingestion, event processing, and narrative generation
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pandas as pd

from ingest import PCAPProcessor
from detect import EventDetector
from llm_client import LLMClient
from streaming_upload import upload_handler, file_analyzer
from multi_file_processor import multi_file_processor
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="YeetThePacket API",
    description="Convert network events into human-readable stories using LLMs",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
pcap_processor = PCAPProcessor()
event_detector = EventDetector()
llm_client = None

# Data directories
DATA_DIR = Path(os.getenv('DATA_DIR', './data'))
OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './output'))
DATA_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# Pydantic models for API requests/responses
class EventFilter(BaseModel):
    severity: Optional[List[str]] = None
    event_type: Optional[List[str]] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None

class ExportRequest(BaseModel):
    event_ids: List[str]
    format: str = "pdf"  # pdf, json, csv

class ProcessingStatus(BaseModel):
    task_id: str
    status: str  # "pending", "processing", "completed", "failed"
    progress: float = 0.0
    message: str = ""
    result: Optional[Dict[str, Any]] = None

# In-memory task storage (in production, use Redis or database)
processing_tasks: Dict[str, ProcessingStatus] = {}

def get_llm_client():
    """Get or initialize LLM client"""
    global llm_client
    if llm_client is None:
        try:
            llm_client = LLMClient()
            logger.info("Initialized LLM client")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            llm_client = None
    return llm_client

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "YeetThePacket API",
        "version": "1.0.0",
        "endpoints": {
            "upload": "/ingest/upload",
            "process": "/ingest/process",
            "events": "/events",
            "narratives": "/events/{event_id}/narrative",
            "export": "/export",
            "status": "/status/{task_id}"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    llm_status = "available" if get_llm_client() is not None else "unavailable"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "pcap_processor": "available",
            "event_detector": "available", 
            "llm_client": llm_status
        }
    }

@app.post("/ingest/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload a PCAP file with streaming support for large files"""
    if not file.filename.endswith(('.pcap', '.pcapng', '.pcap.gz', '.pcapng.gz')):
        raise HTTPException(status_code=400, detail="File must be a PCAP file (.pcap, .pcapng, .pcap.gz, or .pcapng.gz)")
    
    try:
        # Generate upload ID
        import uuid
        upload_id = str(uuid.uuid4())
        
        # Handle streaming upload
        result = await upload_handler.handle_chunked_upload(file, upload_id)
        
        # Analyze the uploaded file
        analysis = file_analyzer.analyze_file(result["path"])
        
        logger.info(f"Uploaded and analyzed: {file.filename} ({result['size'] / (1024*1024):.1f} MB)")
        
        return {
            "message": "File uploaded successfully",
            "upload_id": upload_id,
            "filename": file.filename,
            "size": result["size"],
            "path": result["path"],
            "md5_hash": result["md5_hash"],
            "analysis": analysis
        }
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")

@app.get("/ingest/upload/{upload_id}/status")
async def get_upload_status(upload_id: str):
    """Get upload progress status"""
    try:
        return upload_handler.get_upload_status(upload_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/ingest/analyze")
async def analyze_file(filename: str):
    """Analyze a file and get processing recommendations"""
    file_path = DATA_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")
    
    try:
        analysis = file_analyzer.analyze_file(str(file_path))
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to analyze file: {str(e)}")

@app.post("/ingest/process")
async def process_pcap(
    background_tasks: BackgroundTasks,
    filename: str,
    generate_narratives: bool = True,
    processing_strategy: Optional[str] = None
):
    """Process a PCAP file with smart strategy selection"""
    file_path = DATA_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")
    
    # Analyze file to determine optimal processing strategy
    try:
        analysis = file_analyzer.analyze_file(str(file_path))
        
        # Use provided strategy or recommended one
        strategy = processing_strategy or analysis["recommended_strategy"]
        
        # Create task ID
        task_id = f"process_{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Initialize task status with analysis info
        processing_tasks[task_id] = ProcessingStatus(
            task_id=task_id,
            status="pending",
            message=f"Task queued - Strategy: {strategy}"
        )
        
        # Start background processing with strategy
        background_tasks.add_task(
            process_pcap_background_smart,
            task_id,
            str(file_path),
            generate_narratives,
            strategy,
            analysis
        )
        
        return {
            "task_id": task_id,
            "status": "pending",
            "message": "Processing started with smart strategy",
            "strategy": strategy,
            "analysis": analysis,
            "check_status_url": f"/status/{task_id}"
        }
        
    except Exception as e:
        logger.error(f"Error analyzing file for processing: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to analyze file: {str(e)}")

@app.post("/ingest/upload-multiple")
async def upload_multiple_pcaps(files: List[UploadFile] = File(...)):
    """Upload multiple PCAP files for batch processing"""
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    uploaded_files = []
    failed_uploads = []
    
    for file in files:
        try:
            if not file.filename.endswith(('.pcap', '.pcapng', '.pcap.gz', '.pcapng.gz')):
                failed_uploads.append({
                    "filename": file.filename,
                    "error": "Invalid file type. Must be PCAP file (.pcap, .pcapng, .pcap.gz, or .pcapng.gz)"
                })
                continue
            
            # Generate upload ID
            upload_id = str(uuid.uuid4())
            
            # Handle streaming upload
            result = await upload_handler.handle_chunked_upload(file, upload_id)
            
            # Add to processing queue
            job_id = await multi_file_processor.add_job(
                filename=file.filename,
                file_size=result["size"],
                file_path=result["path"],
                generate_narratives=True
            )
            
            uploaded_files.append({
                "filename": file.filename,
                "size": result["size"],
                "job_id": job_id,
                "upload_id": upload_id
            })
            
            logger.info(f"Queued file {file.filename} for processing (Job ID: {job_id})")
            
        except Exception as e:
            logger.error(f"Failed to upload {file.filename}: {e}")
            failed_uploads.append({
                "filename": file.filename,
                "error": str(e)
            })
    
    return {
        "message": f"Uploaded {len(uploaded_files)} files successfully",
        "uploaded_files": uploaded_files,
        "failed_uploads": failed_uploads,
        "total_files": len(files)
    }

@app.get("/processing/dashboard")
async def get_processing_dashboard():
    """Get comprehensive processing dashboard data"""
    try:
        # Get queue status
        queue_status = multi_file_processor.get_queue_status()
        
        # Get all jobs
        all_jobs = multi_file_processor.get_all_jobs()
        
        # Calculate additional metrics
        total_events = sum(job.get('events_found', 0) for job in all_jobs)
        total_flows = sum(job.get('flows_processed', 0) for job in all_jobs)
        total_narratives = sum(job.get('narratives_generated', 0) for job in all_jobs)
        
        # Get recent jobs (last 20)
        recent_jobs = sorted(all_jobs, key=lambda x: x.get('upload_time', ''), reverse=True)[:20]
        
        # Calculate average processing time
        completed_jobs = [job for job in all_jobs if job.get('processing_duration')]
        avg_processing_time = sum(job['processing_duration'] for job in completed_jobs) / len(completed_jobs) if completed_jobs else 0
        
        return {
            "queue_status": queue_status,
            "recent_jobs": recent_jobs,
            "metrics": {
                "total_events_found": total_events,
                "total_flows_processed": total_flows,
                "total_narratives_generated": total_narratives,
                "average_processing_time": round(avg_processing_time, 1)
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

@app.get("/processing/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get detailed status of a specific job"""
    job_status = multi_file_processor.get_job_status(job_id)
    
    if not job_status:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job_status

@app.get("/processing/jobs")
async def get_all_jobs(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200)
):
    """Get all jobs with optional filtering"""
    all_jobs = multi_file_processor.get_all_jobs()
    
    # Filter by status if provided
    if status:
        all_jobs = [job for job in all_jobs if job.get('status') == status]
    
    # Sort by upload time (newest first)
    all_jobs.sort(key=lambda x: x.get('upload_time', ''), reverse=True)
    
    # Apply limit
    limited_jobs = all_jobs[:limit]
    
    return {
        "jobs": limited_jobs,
        "total_count": len(all_jobs),
        "filtered_count": len(limited_jobs)
    }

@app.post("/processing/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    """Cancel a specific job"""
    success = await multi_file_processor.cancel_job(job_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Job cannot be cancelled (may have already started or completed)")
    
    return {"message": "Job cancelled successfully", "job_id": job_id}

@app.on_event("startup")
async def startup_event():
    """Initialize multi-file processor on startup"""
    # Workers will be started on first use to avoid event loop issues
    logger.info("Multi-file processor initialized (workers will start on first job)")

@app.on_event("shutdown") 
async def shutdown_event():
    """Clean shutdown of multi-file processor"""
    await multi_file_processor.stop_workers()
    logger.info("Multi-file processor workers stopped")

async def process_pcap_background_smart(task_id: str, file_path: str, generate_narratives: bool, strategy: str, analysis: dict):
    """Smart background processing with strategy-based optimization"""
    try:
        # Update status with strategy info
        processing_tasks[task_id].status = "processing"
        processing_tasks[task_id].progress = 0.05
        processing_tasks[task_id].message = f"Starting {strategy} processing ({analysis['file_size_mb']} MB file)"
        
        # Handle decompression if needed
        if analysis.get("is_compressed"):
            processing_tasks[task_id].message = "Decompressing file..."
            processing_tasks[task_id].progress = 0.1
            file_path = await upload_handler.decompress_if_needed(file_path)
        
        # Configure processor based on strategy
        processor_config = _get_processor_config(strategy, analysis)
        
        processing_tasks[task_id].progress = 0.2
        processing_tasks[task_id].message = f"Extracting flows using {strategy} strategy"
        
        # Process PCAP with strategy-specific configuration
        if strategy.startswith("sample_"):
            # Use sampling
            sample_rate = float(strategy.split("_")[1]) / 100  # e.g., "sample_10" -> 0.1
            flows_data = await _process_with_sampling(file_path, sample_rate, processor_config)
        elif strategy == "full_with_limits":
            # Full processing with packet limits
            flows_data = await _process_with_limits(file_path, processor_config)
        else:
            # Standard full processing
            flows_data = pcap_processor.process_pcap(file_path)
        
        processing_tasks[task_id].progress = 0.5
        processing_tasks[task_id].message = "Detecting security events"
        
        # Detect events
        events = event_detector.run_all_detectors(
            flows_data['flows'], 
            flows_data['host_behavior']
        )
        
        processing_tasks[task_id].progress = 0.7
        processing_tasks[task_id].message = f"Detected {len(events)} events"
        
        # Generate narratives if requested and feasible
        if generate_narratives and events:
            # Limit narrative generation for very large result sets
            events_to_narrate = events[:50] if len(events) > 50 else events
            
            client = get_llm_client()
            if client:
                processing_tasks[task_id].message = f"Generating narratives for {len(events_to_narrate)} events"
                processing_tasks[task_id].progress = 0.8
                
                # Create progress callback to update task status
                def narrative_progress_callback(message: str, progress: float):
                    # Map progress from 0.8 to 0.95
                    mapped_progress = 0.8 + (progress * 0.15)
                    processing_tasks[task_id].progress = mapped_progress
                    processing_tasks[task_id].message = message
                
                enriched_events = client.enrich_events_with_narratives(events_to_narrate, narrative_progress_callback)
                
                # Add non-narrated events back
                if len(events) > 50:
                    enriched_events.extend(events[50:])
                    
                events = enriched_events
            else:
                logger.warning("LLM client not available, skipping narrative generation")
        
        # Save results with strategy info
        output_file = f"events_{Path(file_path).stem}_{strategy}.jsonl"
        event_detector.save_events_to_jsonl(events, output_file)
        
        # Complete task
        processing_tasks[task_id].status = "completed"
        processing_tasks[task_id].progress = 1.0
        processing_tasks[task_id].message = "Processing completed successfully"
        processing_tasks[task_id].result = {
            "events_count": len(events),
            "flows_count": flows_data.get('flow_count', 0),
            "hosts_count": flows_data.get('host_count', 0),
            "output_file": output_file,
            "strategy_used": strategy,
            "file_analysis": analysis
        }
        
        logger.info(f"Completed smart processing task {task_id} using {strategy}")
        
    except Exception as e:
        logger.error(f"Error in smart background task {task_id}: {e}")
        processing_tasks[task_id].status = "failed"
        processing_tasks[task_id].message = f"Processing failed: {str(e)}"

def _get_processor_config(strategy: str, analysis: dict) -> dict:
    """Get processor configuration based on strategy"""
    config = {
        "chunk_size": 50000,
        "max_memory_mb": 2048
    }
    
    if analysis["file_size_mb"] > 1000:
        config["chunk_size"] = 100000
        config["max_memory_mb"] = 4096
    elif analysis["file_size_mb"] > 500:
        config["chunk_size"] = 75000
        config["max_memory_mb"] = 3072
    
    return config

async def _process_with_sampling(file_path: str, sample_rate: float, config: dict):
    """Process PCAP with sampling"""
    # This would integrate with the MACCDCProcessor sampling logic
    import sys
    from pathlib import Path
    
    # Add the parent directory to Python path to import process_maccdc
    parent_dir = Path(__file__).parent.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))
    
    try:
        from process_maccdc import MACCDCProcessor
        maccdc_processor = MACCDCProcessor()
        return maccdc_processor.process_with_sampling(file_path, sample_rate)
    except ImportError as e:
        logger.error(f"Failed to import process_maccdc: {e}")
        # Fallback to regular processing
        processor = PCAPProcessor(
            chunk_size=config.get("chunk_size", 100000),
            max_memory_mb=config.get("max_memory_mb", 1024)
        )
        return processor.process_pcap(file_path)

async def _process_with_limits(file_path: str, config: dict):
    """Process PCAP with packet limits"""
    # Configure processor with limits
    processor = PCAPProcessor(
        chunk_size=config["chunk_size"],
        max_memory_mb=config["max_memory_mb"]
    )
    return processor.process_pcap(file_path)

# Keep original function for backward compatibility
async def process_pcap_background(task_id: str, file_path: str, generate_narratives: bool):
    """Background task for PCAP processing (legacy)"""
    # Analyze file and use smart processing
    analysis = file_analyzer.analyze_file(file_path)
    strategy = analysis["recommended_strategy"]
    
    await process_pcap_background_smart(task_id, file_path, generate_narratives, strategy, analysis)

@app.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """Get status of a processing task"""
    if task_id not in processing_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return processing_tasks[task_id]

@app.get("/events")
async def get_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    filters: Optional[str] = Query(None, description="JSON string of EventFilter")
):
    """Get filtered events with pagination"""
    try:
        # Load all events from JSONL files
        all_events = []
        
        for jsonl_file in OUTPUT_DIR.glob("events_*.jsonl"):
            with open(jsonl_file, 'r') as f:
                for line in f:
                    if line.strip():
                        event = json.loads(line)
                        all_events.append(event)
        
        # Apply filters if provided
        if filters:
            try:
                filter_dict = json.loads(filters)
                filter_obj = EventFilter(**filter_dict)
                all_events = apply_event_filters(all_events, filter_obj)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid filter format: {str(e)}")
        
        # Sort by timestamp (newest first)
        all_events.sort(key=lambda x: x.get('start_ts', 0), reverse=True)
        
        # Apply pagination
        total_count = len(all_events)
        paginated_events = all_events[offset:offset + limit]
        
        return {
            "events": paginated_events,
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total_count
        }
        
    except Exception as e:
        logger.error(f"Error retrieving events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve events: {str(e)}")

def apply_event_filters(events: List[Dict[str, Any]], filters: EventFilter) -> List[Dict[str, Any]]:
    """Apply filters to event list"""
    filtered_events = events
    
    if filters.severity:
        filtered_events = [
            e for e in filtered_events 
            if e.get('narrative', {}).get('severity') in filters.severity
        ]
    
    if filters.event_type:
        filtered_events = [
            e for e in filtered_events 
            if e.get('type') in filters.event_type
        ]
    
    if filters.src_ip:
        filtered_events = [
            e for e in filtered_events 
            if e.get('src_ip') == filters.src_ip
        ]
    
    if filters.dst_ip:
        filtered_events = [
            e for e in filtered_events 
            if e.get('dst_ip') == filters.dst_ip
        ]
    
    if filters.start_time:
        filtered_events = [
            e for e in filtered_events 
            if e.get('start_ts', 0) >= filters.start_time
        ]
    
    if filters.end_time:
        filtered_events = [
            e for e in filtered_events 
            if e.get('end_ts', float('inf')) <= filters.end_time
        ]
    
    return filtered_events

@app.get("/events/stats")
async def get_events_stats():
    """Get statistics about events"""
    try:
        all_events = []
        
        # Load all events
        for jsonl_file in OUTPUT_DIR.glob("events_*.jsonl"):
            with open(jsonl_file, 'r') as f:
                for line in f:
                    if line.strip():
                        event = json.loads(line)
                        all_events.append(event)
        
        if not all_events:
            return {"total_events": 0}
        
        # Calculate statistics
        stats = {
            "total_events": len(all_events),
            "event_types": {},
            "severity_counts": {},
            "time_range": {
                "start": min(e.get('start_ts', 0) for e in all_events),
                "end": max(e.get('end_ts', 0) for e in all_events)
            },
            "top_source_ips": {},
            "top_destination_ips": {}
        }
        
        # Count by type
        for event in all_events:
            event_type = event.get('type', 'unknown')
            stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
            
            # Count by severity
            severity = event.get('narrative', {}).get('severity', 'Unknown')
            stats['severity_counts'][severity] = stats['severity_counts'].get(severity, 0) + 1
            
            # Count source IPs
            src_ip = event.get('src_ip')
            if src_ip and src_ip != 'multiple':
                stats['top_source_ips'][src_ip] = stats['top_source_ips'].get(src_ip, 0) + 1
            
            # Count destination IPs
            dst_ip = event.get('dst_ip')
            if dst_ip and dst_ip != 'multiple':
                stats['top_destination_ips'][dst_ip] = stats['top_destination_ips'].get(dst_ip, 0) + 1
        
        # Get top 10 IPs
        stats['top_source_ips'] = dict(sorted(stats['top_source_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_destination_ips'] = dict(sorted(stats['top_destination_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        return stats
        
    except Exception as e:
        logger.error(f"Error calculating stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to calculate statistics: {str(e)}")

@app.get("/events/{event_id}")
async def get_event(event_id: str):
    """Get a specific event by ID"""
    # Search through all event files
    for jsonl_file in OUTPUT_DIR.glob("events_*.jsonl"):
        with open(jsonl_file, 'r') as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    if event.get('id') == event_id:
                        return event
    
    raise HTTPException(status_code=404, detail="Event not found")

@app.post("/events/{event_id}/narrative")
async def generate_event_narrative(event_id: str):
    """Generate or regenerate narrative for a specific event"""
    # Find the event
    event = None
    for jsonl_file in OUTPUT_DIR.glob("events_*.jsonl"):
        with open(jsonl_file, 'r') as f:
            for line in f:
                if line.strip():
                    candidate = json.loads(line)
                    if candidate.get('id') == event_id:
                        event = candidate
                        break
        if event:
            break
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    # Generate narrative
    client = get_llm_client()
    if not client:
        raise HTTPException(status_code=503, detail="LLM service not available")
    
    try:
        narrative = client.generate_narrative(event)
        return {"event_id": event_id, "narrative": narrative}
    
    except Exception as e:
        logger.error(f"Error generating narrative for event {event_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate narrative: {str(e)}")

@app.post("/export")
async def export_events(request: ExportRequest):
    """Export selected events to various formats"""
    if not request.event_ids:
        raise HTTPException(status_code=400, detail="No event IDs provided")
    
    # Find requested events
    events_to_export = []
    for jsonl_file in OUTPUT_DIR.glob("events_*.jsonl"):
        with open(jsonl_file, 'r') as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    if event.get('id') in request.event_ids:
                        events_to_export.append(event)
    
    if not events_to_export:
        raise HTTPException(status_code=404, detail="No events found with provided IDs")
    
    # Generate export based on format
    if request.format.lower() == "json":
        return {"events": events_to_export}
    
    elif request.format.lower() == "pdf":
        # Generate PDF report (simplified implementation)
        pdf_path = OUTPUT_DIR / f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_pdf_report(events_to_export, pdf_path)
        return FileResponse(pdf_path, filename=pdf_path.name)
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported export format: {request.format}")

def generate_pdf_report(events: List[Dict[str, Any]], output_path: Path):
    """Generate a PDF incident report"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        
        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1  # Center
        )
        story.append(Paragraph("Network Security Incident Report", title_style))
        story.append(Spacer(1, 12))
        
        # Summary
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Paragraph(f"Total Events: {len(events)}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Events
        for i, event in enumerate(events, 1):
            # Event header
            story.append(Paragraph(f"Event {i}: {event.get('type', 'Unknown').replace('_', ' ').title()}", styles['Heading2']))
            
            # Basic info table
            event_data = [
                ['Event ID', event.get('id', 'N/A')],
                ['Source IP', event.get('src_ip', 'N/A')],
                ['Destination IP', event.get('dst_ip', 'N/A')],
                ['Time', datetime.fromtimestamp(event.get('start_ts', 0)).strftime('%Y-%m-%d %H:%M:%S')],
                ['Severity', event.get('narrative', {}).get('severity', 'Unknown')]
            ]
            
            table = Table(event_data, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
            story.append(Spacer(1, 12))
            
            # Narrative
            narrative = event.get('narrative', {})
            if narrative.get('executive_summary'):
                story.append(Paragraph("Executive Summary:", styles['Heading3']))
                story.append(Paragraph(narrative['executive_summary'], styles['Normal']))
                story.append(Spacer(1, 12))
            
            if narrative.get('suggested_remediation'):
                story.append(Paragraph("Recommended Actions:", styles['Heading3']))
                for action in narrative['suggested_remediation']:
                    story.append(Paragraph(f"• {action}", styles['Normal']))
                story.append(Spacer(1, 20))
        
        doc.build(story)
        logger.info(f"Generated PDF report: {output_path}")
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv('API_SERVER_PORT', 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info") 