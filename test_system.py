#!/usr/bin/env python3
"""
Simple system test for Packet-to-Prompt
Tests basic functionality without requiring real PCAP files
"""

import sys
import json
import pandas as pd
from pathlib import Path

# Add backend to path
sys.path.append('backend')

from ingest import PCAPProcessor
from detect import EventDetector
from llm_client import LLMClient

def create_sample_flow_data():
    """Create sample flow data for testing"""
    flows = [
        {
            'src_ip': '192.168.1.10',
            'dst_ip': '192.168.1.100',
            'src_port': 12345,
            'dst_port': 22,
            'protocol': 'TCP',
            'start_time': 1640995200.0,
            'end_time': 1640995205.0,
            'duration': 5.0,
            'pkt_count': 10,
            'total_bytes': 800,
            'avg_iat': 0.5,
            'syn_count': 5,
            'fin_count': 2,
            'rst_count': 0
        },
        {
            'src_ip': '192.168.1.10',
            'dst_ip': '192.168.1.100',
            'src_port': 12346,
            'dst_port': 23,
            'protocol': 'TCP',
            'start_time': 1640995210.0,
            'end_time': 1640995215.0,
            'duration': 5.0,
            'pkt_count': 8,
            'total_bytes': 600,
            'avg_iat': 0.6,
            'syn_count': 4,
            'fin_count': 1,
            'rst_count': 0
        }
    ]
    
    # Create host behavior data
    host_behavior = [
        {
            'src_ip': '192.168.1.10',
            'unique_dst_ips': 1,
            'unique_dst_ports': 2,
            'total_connections': 2,
            'total_bytes_sent': 1400,
            'failed_connections': 1,
            'high_port_diversity': False,
            'regular_intervals': False,
            'avg_iat_variance': 0.1
        }
    ]
    
    return pd.DataFrame(flows), pd.DataFrame(host_behavior)

def test_ingestion():
    """Test PCAP processor (without actual PCAP file)"""
    print("🔍 Testing ingestion module...")
    
    processor = PCAPProcessor()
    
    # Test flow feature extraction with sample data
    sample_packets = pd.DataFrame([
        {
            'timestamp': 1640995200.0,
            'src_ip': '192.168.1.10',
            'dst_ip': '192.168.1.100',
            'src_port': 12345,
            'dst_port': 22,
            'frame_len': 80,
            'ip_proto': 6,
            'tcp_flags': 'S',
            'protocol': 'TCP'
        }
    ])
    
    flows = processor.extract_flow_features(sample_packets)
    
    if not flows.empty:
        print("✅ Flow extraction working")
        return True
    else:
        print("❌ Flow extraction failed")
        return False

def test_detection():
    """Test event detection"""
    print("🔍 Testing detection module...")
    
    detector = EventDetector()
    df_flows, df_host_behavior = create_sample_flow_data()
    
    # Test individual detectors
    brute_force_events = detector.detect_brute_force(df_flows)
    suspicious_events = detector.detect_suspicious_connections(df_flows)
    
    total_events = len(brute_force_events) + len(suspicious_events)
    
    if total_events > 0:
        print(f"✅ Detection working - found {total_events} events")
        return brute_force_events + suspicious_events
    else:
        print("❌ Detection failed - no events found")
        return []

def test_llm_client():
    """Test LLM client (may fail if no API keys configured)"""
    print("🔍 Testing LLM client...")
    
    try:
        client = LLMClient()
        
        # Create sample event
        sample_event = {
            "id": "test-event-001",
            "type": "brute_force",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.100",
            "dst_port": 22,
            "evidence": [
                {"type": "attempts", "ref": "20-attempts", "description": "20 connection attempts"},
                {"type": "failures", "ref": "18-failed", "description": "18 failed connections"}
            ],
            "features": {
                "connection_attempts": 20,
                "failed_attempts": 18,
                "failure_rate": 0.9
            }
        }
        
        narrative = client.generate_narrative(sample_event)
        
        if narrative and 'one_line_summary' in narrative:
            print("✅ LLM client working")
            print(f"   Sample narrative: {narrative['one_line_summary']}")
            return True
        else:
            print("⚠️  LLM client returned unexpected response")
            return False
            
    except Exception as e:
        print(f"⚠️  LLM client failed: {str(e)}")
        print("   This is expected if no API keys are configured")
        return False

def test_json_serialization():
    """Test that events can be serialized to JSON"""
    print("🔍 Testing JSON serialization...")
    
    df_flows, df_host_behavior = create_sample_flow_data()
    detector = EventDetector()
    
    events = detector.run_all_detectors(df_flows, df_host_behavior)
    
    try:
        # Test serialization
        json_str = json.dumps(events, indent=2)
        
        # Test deserialization
        parsed_events = json.loads(json_str)
        
        if len(parsed_events) == len(events):
            print("✅ JSON serialization working")
            return True
        else:
            print("❌ JSON serialization failed")
            return False
            
    except Exception as e:
        print(f"❌ JSON serialization error: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("🚀 Running Packet-to-Prompt System Tests\n")
    
    results = {
        'ingestion': test_ingestion(),
        'detection': test_detection(),
        'json_serialization': test_json_serialization(),
        'llm_client': test_llm_client()
    }
    
    print(f"\n📊 Test Results:")
    print(f"   Ingestion: {'✅' if results['ingestion'] else '❌'}")
    print(f"   Detection: {'✅' if results['detection'] else '❌'}")
    print(f"   JSON Serialization: {'✅' if results['json_serialization'] else '❌'}")
    print(f"   LLM Client: {'✅' if results['llm_client'] else '⚠️'}")
    
    passed = sum([results['ingestion'], results['detection'], results['json_serialization']])
    total = 3  # Don't count LLM as required
    
    print(f"\n🎯 Core Tests Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All core tests passed! System is ready.")
        return 0
    else:
        print("⚠️  Some core tests failed. Check configuration.")
        return 1

if __name__ == "__main__":
    exit(main()) 