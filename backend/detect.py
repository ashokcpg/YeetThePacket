"""
Event Detection Engine
Implements heuristic rules to detect network security events from flows
"""

import pandas as pd
import numpy as np
import json
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EventDetector:
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Detection thresholds (configurable)
        self.thresholds = {
            'port_scan_unique_ports': 50,
            'port_scan_min_targets': 5,
            'brute_force_attempts': 20,
            'brute_force_time_window': 300,  # seconds
            'beacon_min_connections': 10,
            'beacon_regularity_threshold': 0.2,
            'data_exfil_bytes_threshold': 10_000_000,  # 10MB
            'suspicious_port_threshold': 1024,
            'failed_connection_ratio': 0.7
        }
        
        # Common service ports for brute force detection
        self.auth_ports = {22, 23, 21, 3389, 5900, 1433, 3306, 5432, 443, 80, 25, 110, 143, 993, 995}
        
    def detect_port_scans(self, df_flows: pd.DataFrame, df_host_behavior: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect port scanning activities"""
        events = []
        
        # Find hosts with high port diversity
        scanners = df_host_behavior[
            (df_host_behavior['unique_dst_ports'] >= self.thresholds['port_scan_unique_ports']) &
            (df_host_behavior['unique_dst_ips'] >= self.thresholds['port_scan_min_targets'])
        ]
        
        for _, scanner in scanners.iterrows():
            src_ip = scanner['src_ip']
            
            # Get flows for this scanner
            scanner_flows = df_flows[df_flows['src_ip'] == src_ip]
            
            if scanner_flows.empty:
                continue
                
            # Calculate time range
            start_ts = scanner_flows['start_time'].min()
            end_ts = scanner_flows['end_time'].max()
            
            # Get target information
            targets = scanner_flows['dst_ip'].unique()
            ports = scanner_flows['dst_port'].unique()
            
            # Create evidence
            evidence = [
                {"type": "flow", "ref": f"scanner-{src_ip}", "description": f"Scanned {len(ports)} unique ports"},
                {"type": "targets", "ref": f"targets-{len(targets)}", "description": f"Targeted {len(targets)} hosts"},
                {"type": "pattern", "ref": "port-diversity", "description": f"High port diversity: {scanner['unique_dst_ports']} ports"}
            ]
            
            # Calculate features
            features = {
                "pkt_count": int(scanner['total_connections']),
                "bytes": int(scanner['total_bytes_sent']),
                "unique_dst_ports": int(scanner['unique_dst_ports']),
                "unique_dst_ips": int(scanner['unique_dst_ips']),
                "scan_duration": float(end_ts - start_ts),
                "failed_connections": int(scanner['failed_connections'])
            }
            
            event = {
                "id": f"evt-portscan-{uuid.uuid4().hex[:8]}",
                "start_ts": float(start_ts),
                "end_ts": float(end_ts),
                "src_ip": src_ip,
                "dst_ip": targets[0] if len(targets) == 1 else "multiple",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "TCP",
                "type": "port_scan",
                "evidence": evidence,
                "features": features,
                "raw_meta": {
                    "detector": "port_scan_heuristic",
                    "targets": targets.tolist(),
                    "ports_scanned": ports.tolist()[:50]  # Limit for storage
                }
            }
            
            events.append(event)
            logger.info(f"Detected port scan from {src_ip}: {len(ports)} ports, {len(targets)} targets")
        
        return events
    
    def detect_brute_force(self, df_flows: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect brute force authentication attempts"""
        events = []
        
        # Focus on authentication service ports
        auth_flows = df_flows[df_flows['dst_port'].isin(self.auth_ports)]
        
        if auth_flows.empty:
            return events
        
        # Group by source IP and destination service
        for (src_ip, dst_ip, dst_port), group in auth_flows.groupby(['src_ip', 'dst_ip', 'dst_port']):
            # Check for multiple short-lived connections
            short_connections = group[group['duration'] < 5.0]  # Less than 5 seconds
            failed_connections = group[group['syn_count'] > group['fin_count']]
            
            total_attempts = len(group)
            failed_attempts = len(failed_connections)
            
            if total_attempts >= self.thresholds['brute_force_attempts']:
                start_ts = group['start_time'].min()
                end_ts = group['end_time'].max()
                time_window = end_ts - start_ts
                
                # Check if attempts are within reasonable time window
                if time_window <= self.thresholds['brute_force_time_window']:
                    # Calculate failure rate
                    failure_rate = failed_attempts / total_attempts if total_attempts > 0 else 0
                    
                    # Create evidence
                    evidence = [
                        {"type": "connections", "ref": f"attempts-{total_attempts}", "description": f"{total_attempts} connection attempts"},
                        {"type": "failures", "ref": f"failed-{failed_attempts}", "description": f"{failed_attempts} failed connections"},
                        {"type": "timing", "ref": f"window-{time_window:.1f}s", "description": f"Within {time_window:.1f} second window"},
                        {"type": "service", "ref": f"port-{dst_port}", "description": f"Targeting service on port {dst_port}"}
                    ]
                    
                    # Calculate features
                    features = {
                        "pkt_count": int(group['pkt_count'].sum()),
                        "bytes": int(group['total_bytes'].sum()),
                        "connection_attempts": total_attempts,
                        "failed_attempts": failed_attempts,
                        "failure_rate": failure_rate,
                        "time_window": float(time_window),
                        "avg_connection_duration": float(group['duration'].mean())
                    }
                    
                    event = {
                        "id": f"evt-bruteforce-{uuid.uuid4().hex[:8]}",
                        "start_ts": float(start_ts),
                        "end_ts": float(end_ts),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": 0,
                        "dst_port": int(dst_port),
                        "protocol": "TCP",
                        "type": "brute_force",
                        "evidence": evidence,
                        "features": features,
                        "raw_meta": {
                            "detector": "brute_force_heuristic",
                            "service_port": int(dst_port),
                            "connection_pattern": "short_lived_attempts"
                        }
                    }
                    
                    events.append(event)
                    logger.info(f"Detected brute force from {src_ip} to {dst_ip}:{dst_port}: {total_attempts} attempts")
        
        return events
    
    def detect_beaconing(self, df_flows: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect beaconing/C2 communication patterns"""
        events = []
        
        # Group by source-destination pairs
        for (src_ip, dst_ip), group in df_flows.groupby(['src_ip', 'dst_ip']):
            if len(group) < self.thresholds['beacon_min_connections']:
                continue
            
            # Calculate inter-arrival times
            sorted_flows = group.sort_values('start_time')
            iats = sorted_flows['start_time'].diff().dropna()
            
            if len(iats) < 3:
                continue
            
            # Check for regularity in timing
            iat_mean = iats.mean()
            iat_std = iats.std()
            coefficient_of_variation = iat_std / iat_mean if iat_mean > 0 else float('inf')
            
            # Regular beaconing has low coefficient of variation
            if coefficient_of_variation <= self.thresholds['beacon_regularity_threshold']:
                start_ts = sorted_flows['start_time'].min()
                end_ts = sorted_flows['end_time'].max()
                
                # Additional checks for beaconing characteristics
                avg_bytes = group['total_bytes'].mean()
                byte_variance = group['total_bytes'].var()
                consistent_size = byte_variance < (avg_bytes * 0.5) if avg_bytes > 0 else False
                
                # Create evidence
                evidence = [
                    {"type": "timing", "ref": f"regular-{coefficient_of_variation:.3f}", "description": f"Regular intervals (CV: {coefficient_of_variation:.3f})"},
                    {"type": "connections", "ref": f"count-{len(group)}", "description": f"{len(group)} periodic connections"},
                    {"type": "pattern", "ref": f"interval-{iat_mean:.1f}s", "description": f"Average interval: {iat_mean:.1f} seconds"}
                ]
                
                if consistent_size:
                    evidence.append({"type": "size", "ref": f"consistent-{avg_bytes:.0f}", "description": f"Consistent data size (~{avg_bytes:.0f} bytes)"})
                
                # Calculate features
                features = {
                    "pkt_count": int(group['pkt_count'].sum()),
                    "bytes": int(group['total_bytes'].sum()),
                    "connection_count": len(group),
                    "avg_interval_seconds": float(iat_mean),
                    "interval_regularity": float(1.0 - coefficient_of_variation),  # Higher = more regular
                    "avg_bytes_per_connection": float(avg_bytes),
                    "size_consistency": consistent_size,
                    "total_duration": float(end_ts - start_ts)
                }
                
                event = {
                    "id": f"evt-beacon-{uuid.uuid4().hex[:8]}",
                    "start_ts": float(start_ts),
                    "end_ts": float(end_ts),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": int(group['src_port'].iloc[0]),
                    "dst_port": int(group['dst_port'].iloc[0]),
                    "protocol": group['protocol'].iloc[0],
                    "type": "beacon",
                    "evidence": evidence,
                    "features": features,
                    "raw_meta": {
                        "detector": "beaconing_heuristic",
                        "regularity_score": float(1.0 - coefficient_of_variation),
                        "interval_stats": {
                            "mean": float(iat_mean),
                            "std": float(iat_std),
                            "cv": float(coefficient_of_variation)
                        }
                    }
                }
                
                events.append(event)
                logger.info(f"Detected beaconing from {src_ip} to {dst_ip}: {len(group)} connections, CV: {coefficient_of_variation:.3f}")
        
        return events
    
    def detect_data_exfiltration(self, df_flows: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration based on large data transfers"""
        events = []
        
        # Find flows with large data transfers
        large_transfers = df_flows[df_flows['total_bytes'] >= self.thresholds['data_exfil_bytes_threshold']]
        
        for _, flow in large_transfers.iterrows():
            # Additional checks for suspicious characteristics
            is_outbound = True  # Assume internal to external (would need network topology info)
            unusual_port = flow['dst_port'] > self.thresholds['suspicious_port_threshold']
            
            # Create evidence
            evidence = [
                {"type": "volume", "ref": f"bytes-{flow['total_bytes']}", "description": f"Large data transfer: {flow['total_bytes']:,} bytes"},
                {"type": "duration", "ref": f"duration-{flow['duration']:.1f}s", "description": f"Transfer duration: {flow['duration']:.1f} seconds"}
            ]
            
            if unusual_port:
                evidence.append({"type": "port", "ref": f"port-{flow['dst_port']}", "description": f"Unusual destination port: {flow['dst_port']}"})
            
            # Calculate transfer rate
            transfer_rate = flow['total_bytes'] / flow['duration'] if flow['duration'] > 0 else 0
            
            # Calculate features
            features = {
                "pkt_count": int(flow['pkt_count']),
                "bytes": int(flow['total_bytes']),
                "transfer_rate_bps": float(transfer_rate),
                "duration": float(flow['duration']),
                "unusual_port": unusual_port,
                "dst_port": int(flow['dst_port'])
            }
            
            event = {
                "id": f"evt-exfil-{uuid.uuid4().hex[:8]}",
                "start_ts": float(flow['start_time']),
                "end_ts": float(flow['end_time']),
                "src_ip": flow['src_ip'],
                "dst_ip": flow['dst_ip'],
                "src_port": int(flow['src_port']),
                "dst_port": int(flow['dst_port']),
                "protocol": flow['protocol'],
                "type": "data_exfil",
                "evidence": evidence,
                "features": features,
                "raw_meta": {
                    "detector": "data_exfiltration_heuristic",
                    "transfer_characteristics": {
                        "bytes_per_second": float(transfer_rate),
                        "megabytes_total": float(flow['total_bytes'] / 1_000_000)
                    }
                }
            }
            
            events.append(event)
            logger.info(f"Detected data exfiltration from {flow['src_ip']} to {flow['dst_ip']}: {flow['total_bytes']:,} bytes")
        
        return events
    
    def detect_suspicious_connections(self, df_flows: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect other suspicious connection patterns"""
        events = []
        
        # Group by source IP to find hosts with many failed connections
        for src_ip, group in df_flows.groupby('src_ip'):
            failed_flows = group[group['syn_count'] > group['fin_count']]
            total_flows = len(group)
            failed_count = len(failed_flows)
            
            if total_flows >= 10 and failed_count / total_flows >= self.thresholds['failed_connection_ratio']:
                start_ts = group['start_time'].min()
                end_ts = group['end_time'].max()
                
                # Get target information
                targets = group['dst_ip'].nunique()
                ports = group['dst_port'].nunique()
                
                # Create evidence
                evidence = [
                    {"type": "failures", "ref": f"failed-{failed_count}", "description": f"{failed_count} failed connections"},
                    {"type": "ratio", "ref": f"ratio-{failed_count/total_flows:.2f}", "description": f"Failure rate: {failed_count/total_flows:.1%}"},
                    {"type": "targets", "ref": f"targets-{targets}", "description": f"Attempted connections to {targets} hosts"}
                ]
                
                # Calculate features
                features = {
                    "pkt_count": int(group['pkt_count'].sum()),
                    "bytes": int(group['total_bytes'].sum()),
                    "total_connections": total_flows,
                    "failed_connections": failed_count,
                    "failure_rate": float(failed_count / total_flows),
                    "unique_targets": targets,
                    "unique_ports": ports
                }
                
                event = {
                    "id": f"evt-suspicious-{uuid.uuid4().hex[:8]}",
                    "start_ts": float(start_ts),
                    "end_ts": float(end_ts),
                    "src_ip": src_ip,
                    "dst_ip": "multiple" if targets > 1 else group['dst_ip'].iloc[0],
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "TCP",
                    "type": "suspicious_connection",
                    "evidence": evidence,
                    "features": features,
                    "raw_meta": {
                        "detector": "suspicious_connections_heuristic",
                        "failure_pattern": "high_failure_rate"
                    }
                }
                
                events.append(event)
                logger.info(f"Detected suspicious connections from {src_ip}: {failed_count}/{total_flows} failed")
        
        return events
    
    def run_all_detectors(self, df_flows: pd.DataFrame, df_host_behavior: pd.DataFrame) -> List[Dict[str, Any]]:
        """Run all detection algorithms and return combined events"""
        logger.info("Running all event detectors")
        
        all_events = []
        
        # Run individual detectors
        port_scan_events = self.detect_port_scans(df_flows, df_host_behavior)
        brute_force_events = self.detect_brute_force(df_flows)
        beacon_events = self.detect_beaconing(df_flows)
        exfil_events = self.detect_data_exfiltration(df_flows)
        suspicious_events = self.detect_suspicious_connections(df_flows)
        
        # Combine all events
        all_events.extend(port_scan_events)
        all_events.extend(brute_force_events)
        all_events.extend(beacon_events)
        all_events.extend(exfil_events)
        all_events.extend(suspicious_events)
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x['start_ts'])
        
        logger.info(f"Detected {len(all_events)} total events:")
        logger.info(f"  Port scans: {len(port_scan_events)}")
        logger.info(f"  Brute force: {len(brute_force_events)}")
        logger.info(f"  Beaconing: {len(beacon_events)}")
        logger.info(f"  Data exfiltration: {len(exfil_events)}")
        logger.info(f"  Suspicious connections: {len(suspicious_events)}")
        
        return all_events
    
    def save_events_to_jsonl(self, events: List[Dict[str, Any]], output_file: str):
        """Save events to JSONL format"""
        output_path = self.output_dir / output_file
        
        def clean_event_data(event):
            """Clean event data to ensure JSON serialization works"""
            import numpy as np
            
            def clean_value(value):
                if isinstance(value, np.bool_):
                    return bool(value)
                elif isinstance(value, (np.integer, np.int64, np.int32)):
                    return int(value)
                elif isinstance(value, (np.floating, np.float64, np.float32)):
                    return float(value)
                elif isinstance(value, np.ndarray):
                    return value.tolist()
                elif isinstance(value, dict):
                    return {k: clean_value(v) for k, v in value.items()}
                elif isinstance(value, list):
                    return [clean_value(item) for item in value]
                else:
                    return value
            
            return clean_value(event)
        
        with open(output_path, 'w') as f:
            for event in events:
                cleaned_event = clean_event_data(event)
                f.write(json.dumps(cleaned_event, default=str) + '\n')
        
        logger.info(f"Saved {len(events)} events to {output_path}")
        return str(output_path)

def main():
    """CLI interface for event detection"""
    import sys
    from ingest import PCAPProcessor
    
    if len(sys.argv) < 2:
        print("Usage: python detect.py <flows_file.jsonl>")
        sys.exit(1)
    
    flows_file = sys.argv[1]
    
    # Load flows from JSONL
    flows = []
    with open(flows_file, 'r') as f:
        for line in f:
            flows.append(json.loads(line))
    
    df_flows = pd.DataFrame(flows)
    
    # Create host behavior summary (simplified)
    host_behavior = []
    for src_ip, group in df_flows.groupby('src_ip'):
        host_behavior.append({
            'src_ip': src_ip,
            'unique_dst_ips': group['dst_ip'].nunique(),
            'unique_dst_ports': group['dst_port'].nunique(),
            'total_connections': len(group),
            'total_bytes_sent': group['total_bytes'].sum(),
            'failed_connections': 0,  # Would need more detailed analysis
            'high_port_diversity': group['dst_port'].nunique() > 50,
            'regular_intervals': False,  # Would need timing analysis
            'avg_iat_variance': 0.0
        })
    
    df_host_behavior = pd.DataFrame(host_behavior)
    
    # Run detection
    detector = EventDetector()
    events = detector.run_all_detectors(df_flows, df_host_behavior)
    
    # Save results
    output_file = f"events_{Path(flows_file).stem}.jsonl"
    detector.save_events_to_jsonl(events, output_file)
    
    print(f"Detection complete: {len(events)} events found")

if __name__ == "__main__":
    main() 