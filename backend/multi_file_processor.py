"""
Multi-File Processing System
Handles batch uploads, queue management, and live progress tracking
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from enum import Enum
import json

logger = logging.getLogger(__name__)

class ProcessingStatus(Enum):
    QUEUED = "queued"
    UPLOADING = "uploading"
    ANALYZING = "analyzing"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class FileJob:
    job_id: str
    filename: str
    file_size: int
    upload_time: datetime
    status: ProcessingStatus
    progress_percent: float = 0.0
    current_stage: str = ""
    estimated_completion: Optional[datetime] = None
    
    # File analysis
    file_analysis: Optional[Dict[str, Any]] = None
    processing_strategy: Optional[str] = None
    
    # Processing results
    events_found: int = 0
    flows_processed: int = 0
    hosts_analyzed: int = 0
    narratives_generated: int = 0
    
    # Timing info
    start_time: Optional[datetime] = None
    completion_time: Optional[datetime] = None
    processing_duration: Optional[float] = None
    
    # Error info
    error_message: Optional[str] = None
    
    # Output files
    output_files: List[str] = None
    
    def __post_init__(self):
        if self.output_files is None:
            self.output_files = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['status'] = self.status.value
        data['upload_time'] = self.upload_time.isoformat() if self.upload_time else None
        data['start_time'] = self.start_time.isoformat() if self.start_time else None
        data['completion_time'] = self.completion_time.isoformat() if self.completion_time else None
        data['estimated_completion'] = self.estimated_completion.isoformat() if self.estimated_completion else None
        return data

class MultiFileProcessor:
    def __init__(self, max_concurrent_jobs: int = 3):
        self.jobs: Dict[str, FileJob] = {}
        self.processing_queue: Optional[asyncio.Queue] = None
        self.max_concurrent_jobs = max_concurrent_jobs
        self.active_workers = 0
        self.worker_tasks: List[asyncio.Task] = []
        self._running = False
        self._loop = None
        
    async def start_workers(self):
        """Start background worker tasks"""
        if self._running:
            return
        
        # Initialize queue and loop in the current event loop
        self._loop = asyncio.get_running_loop()
        if self.processing_queue is None:
            self.processing_queue = asyncio.Queue()
            
        self._running = True
        logger.info(f"Starting {self.max_concurrent_jobs} worker tasks")
        
        for i in range(self.max_concurrent_jobs):
            task = self._loop.create_task(self._worker(f"worker-{i}"))
            self.worker_tasks.append(task)
    
    async def stop_workers(self):
        """Stop all background workers"""
        self._running = False
        
        # Cancel all worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        self.worker_tasks.clear()
        logger.info("All workers stopped")
    
    async def add_job(self, filename: str, file_size: int, file_path: str, 
                     processing_strategy: Optional[str] = None, 
                     generate_narratives: bool = True) -> str:
        """Add a new file processing job to the queue"""
        # Ensure workers are started
        if not self._running:
            await self.start_workers()
        
        job_id = str(uuid.uuid4())
        
        job = FileJob(
            job_id=job_id,
            filename=filename,
            file_size=file_size,
            upload_time=datetime.now(),
            status=ProcessingStatus.QUEUED,
            current_stage="Queued for processing",
            processing_strategy=processing_strategy
        )
        
        self.jobs[job_id] = job
        
        # Add to processing queue (ensure queue exists)
        if self.processing_queue is None:
            await self.start_workers()
        
        await self.processing_queue.put({
            'job_id': job_id,
            'file_path': file_path,
            'generate_narratives': generate_narratives
        })
        
        logger.info(f"Added job {job_id} for file {filename} to queue")
        return job_id
    
    async def _worker(self, worker_name: str):
        """Background worker that processes jobs from the queue"""
        logger.info(f"Worker {worker_name} started")
        
        while self._running:
            try:
                # Get next job from queue (with timeout to allow checking _running)
                try:
                    job_data = await asyncio.wait_for(
                        self.processing_queue.get(), 
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                job_id = job_data['job_id']
                file_path = job_data['file_path']
                generate_narratives = job_data['generate_narratives']
                
                if job_id not in self.jobs:
                    logger.warning(f"Job {job_id} not found in jobs registry")
                    continue
                
                logger.info(f"Worker {worker_name} processing job {job_id}")
                await self._process_job(job_id, file_path, generate_narratives)
                
            except asyncio.CancelledError:
                logger.info(f"Worker {worker_name} cancelled")
                break
            except Exception as e:
                logger.error(f"Worker {worker_name} error: {e}")
                if 'job_id' in locals():
                    await self._mark_job_failed(job_id, str(e))
        
        logger.info(f"Worker {worker_name} stopped")
    
    async def _process_job(self, job_id: str, file_path: str, generate_narratives: bool):
        """Process a single file job"""
        job = self.jobs[job_id]
        
        try:
            # Start processing
            job.status = ProcessingStatus.ANALYZING
            job.start_time = datetime.now()
            job.current_stage = "Analyzing file"
            job.progress_percent = 5.0
            
            # Import processing modules
            from streaming_upload import file_analyzer
            from ingest import PCAPProcessor
            from detect import EventDetector
            from llm_client import LLMClient
            
            # Analyze file
            analysis = file_analyzer.analyze_file(file_path)
            job.file_analysis = analysis
            
            if not job.processing_strategy:
                job.processing_strategy = analysis['recommended_strategy']
            
            job.current_stage = f"Using {job.processing_strategy} strategy"
            job.progress_percent = 15.0
            
            # Estimate completion time
            processing_time_estimate = self._estimate_processing_time(analysis, job.processing_strategy)
            job.estimated_completion = datetime.now() + processing_time_estimate
            
            # Start actual processing
            job.status = ProcessingStatus.PROCESSING
            job.current_stage = "Extracting network flows"
            job.progress_percent = 25.0
            
            # Process based on strategy
            processor = PCAPProcessor()
            
            if job.processing_strategy.startswith("sample_"):
                sample_rate = float(job.processing_strategy.split("_")[1]) / 100
                flows_data = await self._process_with_sampling(file_path, sample_rate)
            else:
                flows_data = processor.process_pcap(file_path)
            
            job.flows_processed = flows_data.get('flow_count', 0)
            job.hosts_analyzed = flows_data.get('host_count', 0)
            job.progress_percent = 50.0
            job.current_stage = "Detecting security events"
            
            # Detect events
            detector = EventDetector()
            events = detector.run_all_detectors(
                flows_data['flows'], 
                flows_data['host_behavior']
            )
            
            job.events_found = len(events)
            job.progress_percent = 70.0
            job.current_stage = f"Found {len(events)} security events"
            
            # Generate narratives if requested
            if generate_narratives and events:
                job.current_stage = "Generating AI narratives"
                job.progress_percent = 80.0
                
                try:
                    llm_client = LLMClient()
                    # Limit narratives for very large result sets
                    events_to_narrate = events[:50] if len(events) > 50 else events
                    
                    # Create progress callback to update job status
                    def narrative_progress_callback(message: str, progress: float):
                        # Map progress from 80% to 95%
                        mapped_progress = 80.0 + (progress * 15.0)
                        job.progress_percent = mapped_progress
                        job.current_stage = message
                    
                    enriched_events = llm_client.enrich_events_with_narratives(events_to_narrate, narrative_progress_callback)
                    
                    if len(events) > 50:
                        enriched_events.extend(events[50:])
                    
                    events = enriched_events
                    job.narratives_generated = len(events_to_narrate)
                    
                except Exception as e:
                    logger.warning(f"Narrative generation failed for job {job_id}: {e}")
                    job.narratives_generated = 0
            
            # Save results
            job.current_stage = "Saving results"
            job.progress_percent = 95.0
            
            output_file = f"events_{Path(file_path).stem}_{job.processing_strategy}_{job_id[:8]}.jsonl"
            detector.save_events_to_jsonl(events, output_file)
            job.output_files.append(output_file)
            
            # Complete job
            job.status = ProcessingStatus.COMPLETED
            job.completion_time = datetime.now()
            job.processing_duration = (job.completion_time - job.start_time).total_seconds()
            job.progress_percent = 100.0
            job.current_stage = "Processing completed"
            
            logger.info(f"Job {job_id} completed successfully in {job.processing_duration:.1f}s")
            
        except Exception as e:
            await self._mark_job_failed(job_id, str(e))
    
    async def _mark_job_failed(self, job_id: str, error_message: str):
        """Mark a job as failed with error details"""
        if job_id in self.jobs:
            job = self.jobs[job_id]
            job.status = ProcessingStatus.FAILED
            job.error_message = error_message
            job.completion_time = datetime.now()
            if job.start_time:
                job.processing_duration = (job.completion_time - job.start_time).total_seconds()
            job.current_stage = f"Failed: {error_message}"
            logger.error(f"Job {job_id} failed: {error_message}")
    
    def _estimate_processing_time(self, analysis: Dict[str, Any], strategy: str) -> datetime:
        """Estimate processing completion time"""
        from datetime import timedelta
        
        base_time = 60  # 1 minute base
        file_size_mb = analysis.get('file_size_mb', 0)
        
        # Adjust based on strategy
        if strategy == "full":
            time_seconds = base_time + (file_size_mb * 2)
        elif strategy.startswith("sample_"):
            sample_rate = float(strategy.split("_")[1]) / 100
            time_seconds = base_time + (file_size_mb * sample_rate * 5)
        else:
            time_seconds = base_time + (file_size_mb * 1.5)
        
        return timedelta(seconds=min(time_seconds, 1800))  # Cap at 30 minutes
    
    async def _process_with_sampling(self, file_path: str, sample_rate: float):
        """Process file with sampling"""
        # This would integrate with existing sampling logic
        import sys
        from pathlib import Path
        
        # Add the parent directory to Python path to import process_maccdc
        parent_dir = Path(__file__).parent.parent
        if str(parent_dir) not in sys.path:
            sys.path.insert(0, str(parent_dir))
        
        try:
            from process_maccdc import MACCDCProcessor
            processor = MACCDCProcessor()
            return processor.process_with_sampling(file_path, sample_rate)
        except ImportError as e:
            logger.error(f"Failed to import process_maccdc: {e}")
            # Fallback to regular processing
            from ingest import PCAPProcessor
            processor = PCAPProcessor()
            return processor.process_pcap(file_path)
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific job"""
        if job_id not in self.jobs:
            return None
        return self.jobs[job_id].to_dict()
    
    def get_all_jobs(self) -> List[Dict[str, Any]]:
        """Get status of all jobs"""
        return [job.to_dict() for job in self.jobs.values()]
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get overall queue status"""
        total_jobs = len(self.jobs)
        if total_jobs == 0:
            return {
                "total_jobs": 0,
                "active_jobs": 0,
                "completed_jobs": 0,
                "failed_jobs": 0,
                "queue_size": 0
            }
        
        status_counts = {}
        for job in self.jobs.values():
            status = job.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Safe queue size check
        queue_size = 0
        if self.processing_queue is not None:
            try:
                queue_size = self.processing_queue.qsize()
            except:
                queue_size = 0
        
        return {
            "total_jobs": total_jobs,
            "active_jobs": status_counts.get("processing", 0) + status_counts.get("analyzing", 0),
            "completed_jobs": status_counts.get("completed", 0),
            "failed_jobs": status_counts.get("failed", 0),
            "queue_size": queue_size,
            "status_breakdown": status_counts
        }
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a job (if it hasn't started processing yet)"""
        if job_id not in self.jobs:
            return False
        
        job = self.jobs[job_id]
        if job.status in [ProcessingStatus.QUEUED, ProcessingStatus.UPLOADING]:
            job.status = ProcessingStatus.CANCELLED
            job.current_stage = "Cancelled by user"
            job.completion_time = datetime.now()
            return True
        
        return False

# Global instance
multi_file_processor = MultiFileProcessor() 