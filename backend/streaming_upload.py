"""
Streaming Upload Handler for Large PCAP Files
Handles chunked uploads, compression, and progress tracking
"""

import os
import tempfile
import gzip
import shutil
from pathlib import Path
from typing import AsyncGenerator, Optional
import logging
import hashlib
import aiofiles
from fastapi import UploadFile, HTTPException
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)

class StreamingUploadHandler:
    def __init__(self, data_dir: str = "./data", chunk_size: int = 8192):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.chunk_size = chunk_size
        self.active_uploads = {}  # Track ongoing uploads
        
    async def handle_chunked_upload(self, file: UploadFile, upload_id: str) -> dict:
        """Handle large file upload with chunking and progress tracking"""
        try:
            # Create temporary file for upload
            temp_path = self.data_dir / f"temp_{upload_id}_{file.filename}"
            final_path = self.data_dir / file.filename
            
            # Initialize upload tracking
            self.active_uploads[upload_id] = {
                "filename": file.filename,
                "bytes_received": 0,
                "total_size": 0,
                "status": "uploading",
                "temp_path": str(temp_path)
            }
            
            # Stream file to disk
            total_bytes = 0
            hash_md5 = hashlib.md5()
            
            async with aiofiles.open(temp_path, 'wb') as temp_file:
                while chunk := await file.read(self.chunk_size):
                    await temp_file.write(chunk)
                    total_bytes += len(chunk)
                    hash_md5.update(chunk)
                    
                    # Update progress
                    self.active_uploads[upload_id]["bytes_received"] = total_bytes
                    
                    # Log progress every 10MB
                    if total_bytes % (10 * 1024 * 1024) == 0:
                        logger.info(f"Upload {upload_id}: {total_bytes / (1024*1024):.1f} MB received")
            
            # Move to final location
            shutil.move(str(temp_path), str(final_path))
            
            # Update tracking
            self.active_uploads[upload_id].update({
                "status": "completed",
                "total_size": total_bytes,
                "md5_hash": hash_md5.hexdigest(),
                "final_path": str(final_path)
            })
            
            logger.info(f"Upload completed: {file.filename} ({total_bytes / (1024*1024):.1f} MB)")
            
            return {
                "upload_id": upload_id,
                "filename": file.filename,
                "size": total_bytes,
                "md5_hash": hash_md5.hexdigest(),
                "path": str(final_path)
            }
            
        except Exception as e:
            # Update error status
            if upload_id in self.active_uploads:
                self.active_uploads[upload_id]["status"] = "failed"
                self.active_uploads[upload_id]["error"] = str(e)
            
            # Cleanup temp file
            if temp_path.exists():
                temp_path.unlink()
                
            logger.error(f"Upload failed for {upload_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    
    def get_upload_status(self, upload_id: str) -> dict:
        """Get upload progress status"""
        if upload_id not in self.active_uploads:
            raise HTTPException(status_code=404, detail="Upload ID not found")
        
        upload_info = self.active_uploads[upload_id]
        
        # Calculate progress percentage
        if upload_info["total_size"] > 0:
            progress = (upload_info["bytes_received"] / upload_info["total_size"]) * 100
        else:
            progress = 0
        
        return {
            "upload_id": upload_id,
            "filename": upload_info["filename"],
            "status": upload_info["status"],
            "bytes_received": upload_info["bytes_received"],
            "total_size": upload_info.get("total_size", 0),
            "progress_percent": progress,
            "error": upload_info.get("error")
        }
    
    async def decompress_if_needed(self, file_path: str) -> str:
        """Decompress gzipped files if needed"""
        path = Path(file_path)
        
        if not path.name.endswith('.gz'):
            return file_path
        
        logger.info(f"Decompressing {path.name}")
        
        # Create decompressed filename
        decompressed_path = path.with_suffix('')  # Remove .gz
        
        try:
            with gzip.open(path, 'rb') as gz_file:
                with open(decompressed_path, 'wb') as out_file:
                    # Decompress in chunks
                    while chunk := gz_file.read(self.chunk_size):
                        out_file.write(chunk)
            
            # Get sizes for logging
            original_size = path.stat().st_size
            decompressed_size = decompressed_path.stat().st_size
            
            logger.info(f"Decompressed: {original_size / (1024*1024):.1f} MB → {decompressed_size / (1024*1024):.1f} MB")
            
            return str(decompressed_path)
            
        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            # Return original path if decompression fails
            return file_path
    
    def cleanup_upload(self, upload_id: str):
        """Clean up upload tracking and temporary files"""
        if upload_id in self.active_uploads:
            upload_info = self.active_uploads[upload_id]
            
            # Clean up temp file if it exists
            temp_path = upload_info.get("temp_path")
            if temp_path and Path(temp_path).exists():
                Path(temp_path).unlink()
            
            # Remove from tracking
            del self.active_uploads[upload_id]
            
            logger.info(f"Cleaned up upload {upload_id}")

class FileAnalyzer:
    """Analyze files before processing to determine optimal strategy"""
    
    @staticmethod
    def analyze_file(file_path: str) -> dict:
        """Analyze file and recommend processing strategy"""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Get file info
        file_size = path.stat().st_size
        size_mb = file_size / (1024 * 1024)
        size_gb = size_mb / 1024
        
        # Determine file type
        is_compressed = path.name.endswith('.gz')
        is_pcap = path.name.endswith(('.pcap', '.pcapng')) or path.name.endswith(('.pcap.gz', '.pcapng.gz'))
        
        # Estimate processing requirements
        if size_mb < 50:
            strategy = "full"
            estimated_time = "1-3 minutes"
            memory_needed = "500MB"
        elif size_mb < 200:
            strategy = "full_with_limits"
            estimated_time = "3-8 minutes"
            memory_needed = "1GB"
        elif size_mb < 500:
            strategy = "sample_20"
            estimated_time = "5-12 minutes"
            memory_needed = "1.5GB"
        elif size_gb < 2:
            strategy = "sample_10"
            estimated_time = "8-20 minutes"
            memory_needed = "2GB"
        else:
            strategy = "sample_5"
            estimated_time = "10-30 minutes"
            memory_needed = "2.5GB"
        
        # Estimate decompressed size if compressed
        estimated_decompressed_mb = size_mb * 8 if is_compressed else size_mb
        
        return {
            "file_path": str(path),
            "file_size_mb": round(size_mb, 1),
            "file_size_gb": round(size_gb, 2),
            "is_compressed": is_compressed,
            "is_pcap": is_pcap,
            "estimated_decompressed_mb": round(estimated_decompressed_mb, 1),
            "recommended_strategy": strategy,
            "estimated_processing_time": estimated_time,
            "memory_needed": memory_needed,
            "recommendations": FileAnalyzer._get_recommendations(size_mb, is_compressed)
        }
    
    @staticmethod
    def _get_recommendations(size_mb: float, is_compressed: bool) -> list:
        """Get processing recommendations based on file characteristics"""
        recommendations = []
        
        if size_mb > 1000:  # > 1GB
            recommendations.append("Very large file - consider using sampling mode")
            recommendations.append("Process during off-peak hours")
            recommendations.append("Ensure sufficient disk space (3x file size)")
        elif size_mb > 500:  # > 500MB
            recommendations.append("Large file - sampling recommended for faster results")
            recommendations.append("Monitor system memory during processing")
        elif size_mb > 100:  # > 100MB
            recommendations.append("Medium file - full processing should work well")
        else:
            recommendations.append("Small file - full processing recommended")
        
        if is_compressed:
            recommendations.append("Compressed file detected - will be auto-decompressed")
            recommendations.append("Ensure 8-10x disk space for decompression")
        
        return recommendations

# Global instance
upload_handler = StreamingUploadHandler()
file_analyzer = FileAnalyzer() 