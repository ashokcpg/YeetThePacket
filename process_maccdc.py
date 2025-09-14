#!/usr/bin/env python3
"""
MACCDC 2012 Processing Utility
Handles compressed PCAP files and provides multiple processing options
"""

import os
import sys
import gzip
import shutil
import tempfile
import argparse
from pathlib import Path
import subprocess
import logging

# Add backend to path - handle both direct execution and import cases
backend_path = Path(__file__).parent / 'backend'
if backend_path.exists() and str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))
elif 'backend' not in sys.path:
    sys.path.append('backend')

try:
    from ingest import PCAPProcessor
    from detect import EventDetector
    from llm_client import LLMClient
except ImportError as e:
    # Try alternative import paths
    import os
    current_dir = Path(__file__).parent
    backend_dir = current_dir / 'backend' if (current_dir / 'backend').exists() else current_dir.parent / 'backend'
    
    if backend_dir.exists() and str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))
    
    from ingest import PCAPProcessor
    from detect import EventDetector
    from llm_client import LLMClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MACCDCProcessor:
    def __init__(self):
        self.temp_dir = None
        self.processor = PCAPProcessor()
        self.detector = EventDetector()
        
    def extract_gzip_pcap(self, gzip_path: str, output_path: str = None) -> str:
        """Extract gzipped PCAP file to temporary location"""
        if not output_path:
            # Create temp file
            self.temp_dir = tempfile.mkdtemp(prefix="maccdc_")
            output_path = os.path.join(self.temp_dir, "extracted.pcap")
        
        logger.info(f"Extracting {gzip_path} to {output_path}")
        
        try:
            with gzip.open(gzip_path, 'rb') as gz_file:
                with open(output_path, 'wb') as out_file:
                    # Copy in chunks to handle large files
                    chunk_size = 1024 * 1024  # 1MB chunks
                    while True:
                        chunk = gz_file.read(chunk_size)
                        if not chunk:
                            break
                        out_file.write(chunk)
            
            # Check extracted file size
            size_mb = os.path.getsize(output_path) / (1024 * 1024)
            logger.info(f"Extracted PCAP size: {size_mb:.1f} MB")
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error extracting gzip file: {e}")
            raise
    
    def process_with_sampling(self, pcap_path: str, sample_rate: float = 0.1) -> dict:
        """Process PCAP with sampling for very large files"""
        logger.info(f"Processing with {sample_rate:.1%} sampling rate")
        
        # Use tshark to sample the traffic
        temp_sampled = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        temp_sampled.close()
        
        try:
            # Sample packets using tshark
            sample_cmd = [
                'tshark', '-r', pcap_path,
                '-w', temp_sampled.name,
                '-Y', f'frame.number % {int(1/sample_rate)} == 0'  # Sample every Nth packet
            ]
            
            logger.info("Sampling packets...")
            result = subprocess.run(sample_cmd, capture_output=True, text=True, check=True)
            
            # Process the sampled file
            flows_data = self.processor.process_pcap(temp_sampled.name)
            
            # Scale up the results
            if flows_data['flows'] is not None and not flows_data['flows'].empty:
                flows_data['flows']['pkt_count'] = flows_data['flows']['pkt_count'] / sample_rate
                flows_data['flows']['total_bytes'] = flows_data['flows']['total_bytes'] / sample_rate
            
            return flows_data
            
        finally:
            # Cleanup
            if os.path.exists(temp_sampled.name):
                os.unlink(temp_sampled.name)
    
    def process_time_window(self, pcap_path: str, duration_minutes: int = 60) -> dict:
        """Process only a time window from the beginning of the PCAP"""
        logger.info(f"Processing first {duration_minutes} minutes of traffic")
        
        temp_windowed = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        temp_windowed.close()
        
        try:
            # Extract time window using tshark
            window_cmd = [
                'tshark', '-r', pcap_path,
                '-w', temp_windowed.name,
                '-a', f'duration:{duration_minutes * 60}'  # Duration in seconds
            ]
            
            logger.info(f"Extracting {duration_minutes}-minute window...")
            result = subprocess.run(window_cmd, capture_output=True, text=True, check=True)
            
            # Process the windowed file
            return self.processor.process_pcap(temp_windowed.name)
            
        finally:
            # Cleanup
            if os.path.exists(temp_windowed.name):
                os.unlink(temp_windowed.name)
    
    def get_pcap_info(self, pcap_path: str) -> dict:
        """Get basic information about the PCAP file"""
        try:
            cmd = ['capinfos', pcap_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            info = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip()] = value.strip()
            
            return info
            
        except subprocess.CalledProcessError:
            # Fallback to basic file info
            size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
            return {
                'File size': f'{size_mb:.1f} MB',
                'Status': 'Basic info only (capinfos not available)'
            }
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            logger.info("Cleaned up temporary files")

def main():
    parser = argparse.ArgumentParser(description='Process MACCDC 2012 PCAP files')
    parser.add_argument('input_file', help='Input PCAP or PCAP.gz file')
    parser.add_argument('--mode', choices=['full', 'sample', 'window'], default='sample',
                       help='Processing mode (default: sample)')
    parser.add_argument('--sample-rate', type=float, default=0.1,
                       help='Sampling rate for sample mode (default: 0.1 = 10%)')
    parser.add_argument('--window-minutes', type=int, default=60,
                       help='Time window in minutes for window mode (default: 60)')
    parser.add_argument('--info-only', action='store_true',
                       help='Only show PCAP information, don\'t process')
    parser.add_argument('--no-narratives', action='store_true',
                       help='Skip LLM narrative generation')
    
    args = parser.parse_args()
    
    processor = MACCDCProcessor()
    
    try:
        input_path = args.input_file
        
        # Handle gzipped files
        if input_path.endswith('.gz'):
            logger.info("Detected gzipped file, extracting...")
            pcap_path = processor.extract_gzip_pcap(input_path)
        else:
            pcap_path = input_path
        
        # Show PCAP info
        info = processor.get_pcap_info(pcap_path)
        print("\n📊 PCAP File Information:")
        for key, value in info.items():
            print(f"   {key}: {value}")
        
        if args.info_only:
            return
        
        print(f"\n🔄 Processing mode: {args.mode}")
        
        # Process based on mode
        if args.mode == 'full':
            flows_data = processor.processor.process_pcap(pcap_path)
        elif args.mode == 'sample':
            flows_data = processor.process_with_sampling(pcap_path, args.sample_rate)
        elif args.mode == 'window':
            flows_data = processor.process_time_window(pcap_path, args.window_minutes)
        
        if not flows_data or flows_data.get('flow_count', 0) == 0:
            print("❌ No flows extracted. Check the PCAP file.")
            return
        
        print(f"\n✅ Extraction Results:")
        print(f"   Flows: {flows_data.get('flow_count', 0):,}")
        print(f"   Hosts: {flows_data.get('host_count', 0):,}")
        
        # Detect events
        print("\n🔍 Detecting security events...")
        events = processor.detector.run_all_detectors(
            flows_data['flows'], 
            flows_data['host_behavior']
        )
        
        if not events:
            print("ℹ️  No security events detected.")
            return
        
        print(f"✅ Detected {len(events)} security events")
        
        # Generate narratives
        if not args.no_narratives:
            try:
                print("\n🤖 Generating AI narratives...")
                llm_client = LLMClient()
                events = llm_client.enrich_events_with_narratives(events)
                print("✅ Narratives generated successfully")
            except Exception as e:
                print(f"⚠️  Narrative generation failed: {e}")
                print("   Events will be saved without narratives")
        
        # Save results
        output_file = f"maccdc_events_{args.mode}.jsonl"
        processor.detector.save_events_to_jsonl(events, output_file)
        
        print(f"\n🎉 Processing complete!")
        print(f"   Output saved to: output/{output_file}")
        print(f"   Events found: {len(events)}")
        
        # Show event summary
        event_types = {}
        for event in events:
            event_type = event.get('type', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        print(f"\n📈 Event Summary:")
        for event_type, count in event_types.items():
            print(f"   {event_type.replace('_', ' ').title()}: {count}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Processing interrupted by user")
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        print(f"\n❌ Error: {e}")
    finally:
        processor.cleanup()

if __name__ == "__main__":
    main() 