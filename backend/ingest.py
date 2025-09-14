"""
PCAP Ingestion Module
Processes PCAP files and extracts network flows using tshark/pyshark
"""

import os
import subprocess
import pandas as pd
import pyshark
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PCAPProcessor:
    def __init__(self, data_dir: str = "./data", output_dir: str = "./output", 
                 chunk_size: int = 100000, max_memory_mb: int = 1024):
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Configuration for large files
        self.chunk_size = chunk_size  # Process packets in chunks
        self.max_memory_mb = max_memory_mb  # Memory limit in MB
        
    def extract_flows_tshark_chunked(self, pcap_path: str, max_packets: int = None) -> pd.DataFrame:
        """Extract flows using tshark with chunking for large files"""
        logger.info(f"Processing {pcap_path} with tshark (chunked mode)")
        
        # Add packet limit for large files
        cmd = [
            'tshark', '-r', pcap_path,
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'tcp.srcport',
            '-e', 'udp.srcport', 
            '-e', 'ip.dst',
            '-e', 'tcp.dstport',
            '-e', 'udp.dstport',
            '-e', 'frame.len',
            '-e', 'ip.proto',
            '-e', 'tcp.flags',
            '-E', 'separator=,',
            '-E', 'quote=d'
        ]
        
        # Add packet count limit for very large files
        if max_packets:
            cmd.extend(['-c', str(max_packets)])
        
        try:
            logger.info(f"Running tshark with command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=3600)
            
            # Process output in chunks to manage memory
            lines = result.stdout.strip().split('\n')
            logger.info(f"Processing {len(lines)} packets")
            
            flows = []
            for i, line in enumerate(lines):
                if not line.strip():
                    continue
                
                # Process in chunks to avoid memory issues
                if i > 0 and i % self.chunk_size == 0:
                    logger.info(f"Processed {i}/{len(lines)} packets")
                
                try:
                    parts = line.split(',')
                    if len(parts) >= 9:
                        timestamp = parts[0].strip('"') if parts[0] else None
                        src_ip = parts[1].strip('"') if parts[1] else None
                        tcp_src_port = parts[2].strip('"') if parts[2] else None
                        udp_src_port = parts[3].strip('"') if parts[3] else None
                        dst_ip = parts[4].strip('"') if parts[4] else None
                        tcp_dst_port = parts[5].strip('"') if parts[5] else None
                        udp_dst_port = parts[6].strip('"') if parts[6] else None
                        frame_len = parts[7].strip('"') if parts[7] else None
                        ip_proto = parts[8].strip('"') if parts[8] else None
                        tcp_flags = parts[9].strip('"') if len(parts) > 9 and parts[9] else None
                        
                        # Determine source and destination ports
                        src_port = tcp_src_port if tcp_src_port else udp_src_port
                        dst_port = tcp_dst_port if tcp_dst_port else udp_dst_port
                        
                        if timestamp and src_ip and dst_ip:
                            flows.append({
                                'timestamp': float(timestamp),
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': int(src_port) if src_port else 0,
                                'dst_port': int(dst_port) if dst_port else 0,
                                'frame_len': int(frame_len) if frame_len else 0,
                                'ip_proto': int(ip_proto) if ip_proto else 0,
                                'tcp_flags': tcp_flags,
                                'protocol': 'TCP' if ip_proto == '6' else 'UDP' if ip_proto == '17' else 'OTHER'
                            })
                except Exception as e:
                    logger.debug(f"Error parsing line {i}: {e}")
                    continue
            
            logger.info(f"Successfully parsed {len(flows)} flows from {len(lines)} packets")
            return pd.DataFrame(flows)
            
        except subprocess.TimeoutExpired:
            logger.error(f"tshark processing timed out after 1 hour")
            return pd.DataFrame()
        except subprocess.CalledProcessError as e:
            logger.error(f"tshark failed: {e}")
            return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error processing with tshark: {e}")
            return pd.DataFrame()

    def extract_flows_tshark(self, pcap_path: str) -> pd.DataFrame:
        """Extract flows using tshark command line tool - now calls chunked version"""
        # Check file size and decide on packet limit
        try:
            file_size = Path(pcap_path).stat().st_size
            size_mb = file_size / (1024 * 1024)
            
            logger.info(f"PCAP file size: {size_mb:.1f} MB")
            
            # Set packet limits based on file size
            if size_mb > 500:  # > 500MB
                max_packets = 1000000  # 1M packets
                logger.warning(f"Large file detected ({size_mb:.1f}MB). Limiting to {max_packets:,} packets")
            elif size_mb > 100:  # > 100MB  
                max_packets = 500000   # 500K packets
                logger.info(f"Medium file detected ({size_mb:.1f}MB). Limiting to {max_packets:,} packets")
            else:
                max_packets = None     # No limit for smaller files
                
            return self.extract_flows_tshark_chunked(pcap_path, max_packets)
            
        except Exception as e:
            logger.error(f"Error checking file size: {e}")
            # Fallback to chunked processing with default limit
            return self.extract_flows_tshark_chunked(pcap_path, 500000)
    
    def extract_flows_pyshark(self, pcap_path: str) -> pd.DataFrame:
        """Extract flows using pyshark (fallback method)"""
        logger.info(f"Processing {pcap_path} with pyshark")
        
        flows = []
        try:
            cap = pyshark.FileCapture(pcap_path)
            
            for packet in cap:
                try:
                    if hasattr(packet, 'ip'):
                        timestamp = float(packet.sniff_timestamp)
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        frame_len = int(packet.length)
                        ip_proto = int(packet.ip.proto)
                        
                        src_port = 0
                        dst_port = 0
                        tcp_flags = None
                        protocol = 'OTHER'
                        
                        if hasattr(packet, 'tcp'):
                            src_port = int(packet.tcp.srcport)
                            dst_port = int(packet.tcp.dstport)
                            tcp_flags = packet.tcp.flags
                            protocol = 'TCP'
                        elif hasattr(packet, 'udp'):
                            src_port = int(packet.udp.srcport)
                            dst_port = int(packet.udp.dstport)
                            protocol = 'UDP'
                        
                        flows.append({
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'frame_len': frame_len,
                            'ip_proto': ip_proto,
                            'tcp_flags': tcp_flags,
                            'protocol': protocol
                        })
                        
                except Exception as e:
                    logger.debug(f"Skipping packet due to error: {e}")
                    continue
                    
            cap.close()
            return pd.DataFrame(flows)
            
        except Exception as e:
            logger.error(f"Error processing with pyshark: {e}")
            return pd.DataFrame()
    
    def extract_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from raw packet flows"""
        if df.empty:
            return pd.DataFrame()
            
        logger.info("Extracting flow features")
        
        # Group by connection 5-tuple
        grouped = df.groupby(['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'])
        
        flows = []
        for (src_ip, dst_ip, src_port, dst_port, protocol), group in grouped:
            # Basic flow statistics
            start_time = group['timestamp'].min()
            end_time = group['timestamp'].max()
            duration = end_time - start_time
            pkt_count = len(group)
            total_bytes = group['frame_len'].sum()
            
            # Inter-arrival times
            sorted_group = group.sort_values('timestamp')
            iats = sorted_group['timestamp'].diff().dropna()
            avg_iat = iats.mean() if len(iats) > 0 else 0
            
            # TCP-specific features
            syn_count = 0
            fin_count = 0
            rst_count = 0
            
            if protocol == 'TCP':
                tcp_packets = group[group['tcp_flags'].notna()]
                for flags in tcp_packets['tcp_flags']:
                    if flags and 'S' in str(flags):
                        syn_count += 1
                    if flags and 'F' in str(flags):
                        fin_count += 1
                    if flags and 'R' in str(flags):
                        rst_count += 1
            
            flows.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'start_time': start_time,
                'end_time': end_time,
                'duration': duration,
                'pkt_count': pkt_count,
                'total_bytes': total_bytes,
                'avg_iat': avg_iat,
                'syn_count': syn_count,
                'fin_count': fin_count,
                'rst_count': rst_count
            })
        
        return pd.DataFrame(flows)
    
    def aggregate_host_behavior(self, df_flows: pd.DataFrame) -> pd.DataFrame:
        """Aggregate flows by source IP to identify behavioral patterns"""
        if df_flows.empty:
            return pd.DataFrame()
            
        logger.info("Aggregating host behavior patterns")
        
        # Group by source IP
        host_stats = []
        for src_ip, group in df_flows.groupby('src_ip'):
            unique_dst_ips = group['dst_ip'].nunique()
            unique_dst_ports = group['dst_port'].nunique()
            total_connections = len(group)
            total_bytes_sent = group['total_bytes'].sum()
            
            # Port scan indicators
            high_port_diversity = unique_dst_ports > 50
            
            # Beaconing indicators (regular intervals)
            iats = group['avg_iat'].dropna()
            iat_variance = iats.var() if len(iats) > 1 else 0
            regular_intervals = iat_variance < 1.0 and len(iats) > 5
            
            # Failed connection indicators
            failed_connections = group[group['syn_count'] > group['fin_count']]['syn_count'].sum()
            
            host_stats.append({
                'src_ip': src_ip,
                'unique_dst_ips': unique_dst_ips,
                'unique_dst_ports': unique_dst_ports,
                'total_connections': total_connections,
                'total_bytes_sent': total_bytes_sent,
                'failed_connections': failed_connections,
                'high_port_diversity': high_port_diversity,
                'regular_intervals': regular_intervals,
                'avg_iat_variance': iat_variance
            })
        
        return pd.DataFrame(host_stats)
    
    def process_pcap(self, pcap_path: str, use_tshark: bool = True) -> Dict[str, Any]:
        """Main processing pipeline for a single PCAP file"""
        logger.info(f"Starting PCAP processing: {pcap_path}")
        
        # Extract flows
        if use_tshark:
            df_packets = self.extract_flows_tshark(pcap_path)
        else:
            df_packets = self.extract_flows_pyshark(pcap_path)
        
        if df_packets.empty:
            logger.warning(f"No packets extracted from {pcap_path}")
            return {'flows': pd.DataFrame(), 'host_behavior': pd.DataFrame()}
        
        logger.info(f"Extracted {len(df_packets)} packets")
        
        # Extract flow features
        df_flows = self.extract_flow_features(df_packets)
        logger.info(f"Generated {len(df_flows)} flows")
        
        # Aggregate host behavior
        df_host_behavior = self.aggregate_host_behavior(df_flows)
        logger.info(f"Analyzed {len(df_host_behavior)} hosts")
        
        return {
            'flows': df_flows,
            'host_behavior': df_host_behavior,
            'packet_count': len(df_packets),
            'flow_count': len(df_flows),
            'host_count': len(df_host_behavior)
        }
    
    def save_flows_to_jsonl(self, flows_data: Dict[str, Any], output_file: str):
        """Save processed flows to JSONL format"""
        output_path = self.output_dir / output_file
        
        with open(output_path, 'w') as f:
            # Write flows
            for _, row in flows_data['flows'].iterrows():
                flow_record = row.to_dict()
                f.write(json.dumps(flow_record) + '\n')
        
        logger.info(f"Saved flows to {output_path}")
        return str(output_path)

def main():
    """CLI interface for PCAP processing"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    processor = PCAPProcessor()
    
    # Process PCAP
    result = processor.process_pcap(pcap_file)
    
    # Save results
    output_file = f"flows_{Path(pcap_file).stem}.jsonl"
    processor.save_flows_to_jsonl(result, output_file)
    
    print(f"Processing complete:")
    print(f"  Packets: {result['packet_count']}")
    print(f"  Flows: {result['flow_count']}")
    print(f"  Hosts: {result['host_count']}")

if __name__ == "__main__":
    main() 