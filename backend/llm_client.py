"""
LLM Client Module
Handles integration with multiple LLM providers for narrative generation
"""

import os
import json
import logging
import numpy as np
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    def generate_narrative(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate narrative for a single event"""
        pass
    
    @abstractmethod
    def generate_batch_narratives(self, events_data: List[Dict[str, Any]], progress_callback=None) -> List[Dict[str, Any]]:
        """Generate narratives for multiple events with optional progress tracking"""
        pass

class CohereProvider(LLMProvider):
    """Cohere LLM provider implementation"""
    
    def __init__(self, api_key: str):
        try:
            import cohere
            self.client = cohere.Client(api_key)
            self.model = "command-r-plus-08-2024"  # Latest non-deprecated model
            logger.info("Initialized Cohere LLM provider")
        except ImportError:
            raise ImportError("cohere package not installed. Run: pip install cohere")
        except Exception as e:
            raise Exception(f"Failed to initialize Cohere client: {e}")
    
    def _clean_event_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean event data to ensure JSON serialization works"""
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
        
        return clean_value(event_data)
    
    def _create_prompt(self, event_data: Dict[str, Any]) -> str:
        """Create prompt for narrative generation"""
        # Clean event data to ensure JSON serialization works
        cleaned_event_data = self._clean_event_data(event_data)
        
        prompt = f"""You are an expert network forensic analyst and storyteller. Input: a JSON event (see below). Output: a JSON with fields:
  - one_line_summary (<=20 words)
  - technical_narrative (3-6 sentences, referencing evidence lines)
  - executive_summary (1-2 sentences, plain English)
  - severity ("Low"|"Medium"|"High"|"Critical")
  - mitre_tactics (list of probable MITRE ATT&CK tactics)
  - suggested_remediation (3 bullet points)
  - confidence (0.0-1.0)
  - tags (list)

Event JSON:
{json.dumps(cleaned_event_data, indent=2, default=str)}

Instructions: 
- Use only the info in the event JSON to justify claims.
- For each claim include short evidence references like [evidence #2].
- Keep exec summary non-technical.
- Provide severity reasoning in one line.
Return ONLY the JSON."""
        
        return prompt
    
    def generate_narrative(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate narrative for a single event using Cohere"""
        try:
            prompt = self._create_prompt(event_data)
            
            # Use Chat API instead of deprecated Generate API
            response = self.client.chat(
                model=self.model,
                message=prompt,
                max_tokens=800,
                temperature=0.3
            )
            
            # Parse JSON response
            narrative_text = response.text.strip()
            
            # Try to extract JSON from response
            try:
                # Find JSON in response (sometimes has extra text)
                start_idx = narrative_text.find('{')
                end_idx = narrative_text.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = narrative_text[start_idx:end_idx]
                    narrative = json.loads(json_str)
                else:
                    raise ValueError("No JSON found in response")
            except (json.JSONDecodeError, ValueError):
                # Fallback: create structured response from text
                logger.warning(f"Failed to parse JSON response for event {event_data.get('id', 'unknown')}")
                narrative = self._create_fallback_narrative(event_data, narrative_text)
            
            return narrative
            
        except Exception as e:
            logger.error(f"Error generating narrative with Cohere: {e}")
            return self._create_fallback_narrative(event_data, str(e))
    
    def generate_batch_narratives(self, events_data: List[Dict[str, Any]], progress_callback=None) -> List[Dict[str, Any]]:
        """Generate narratives for multiple events with progress tracking"""
        narratives = []
        total_events = len(events_data)
        
        for i, event_data in enumerate(events_data):
            # Update progress if callback provided
            if progress_callback:
                progress = (i / total_events) if total_events > 0 else 0
                progress_callback(f"Generating narrative {i+1}/{total_events} (Cohere)", progress)
            
            narrative = self.generate_narrative(event_data)
            narratives.append(narrative)
            
            logger.info(f"Generated narrative for event {event_data.get('id', 'unknown')} ({i+1}/{total_events})")
        
        # Final progress update
        if progress_callback:
            progress_callback(f"Completed narratives for {total_events} events", 1.0)
            
        return narratives
    
    def _create_fallback_narrative(self, event_data: Dict[str, Any], error_text: str = "") -> Dict[str, Any]:
        """Create a fallback narrative when LLM fails"""
        event_type = event_data.get('type', 'unknown')
        src_ip = event_data.get('src_ip', 'unknown')
        dst_ip = event_data.get('dst_ip', 'unknown')
        
        # Basic narrative based on event type
        type_descriptions = {
            'port_scan': f"Port scan detected from {src_ip} targeting {dst_ip}",
            'brute_force': f"Brute force attack detected from {src_ip} against {dst_ip}",
            'beacon': f"Beaconing communication detected between {src_ip} and {dst_ip}",
            'data_exfil': f"Large data transfer detected from {src_ip} to {dst_ip}",
            'suspicious_connection': f"Suspicious connection pattern from {src_ip}"
        }
        
        summary = type_descriptions.get(event_type, f"Network event detected: {event_type}")
        
        return {
            "one_line_summary": summary,
            "technical_narrative": f"{summary}. Analysis based on network flow patterns and connection characteristics. Review evidence for detailed technical indicators.",
            "executive_summary": f"Network security event detected requiring investigation. Source: {src_ip}",
            "severity": "Medium",
            "mitre_tactics": ["Initial Access"] if event_type in ['port_scan', 'brute_force'] else ["Command and Control"],
            "suggested_remediation": [
                "Investigate source IP for malicious activity",
                "Review network logs for additional indicators",
                "Consider blocking suspicious traffic"
            ],
            "confidence": 0.5,
            "tags": [event_type, "automated_detection"],
            "error": error_text if error_text else None
        }

class GeminiProvider(LLMProvider):
    """Google Gemini LLM provider implementation"""
    
    def __init__(self, api_key: str):
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            logger.info("Initialized Gemini LLM provider")
        except ImportError:
            raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")
        except Exception as e:
            raise Exception(f"Failed to initialize Gemini client: {e}")
    
    def _create_prompt(self, event_data: Dict[str, Any]) -> str:
        """Create prompt for narrative generation"""
        return f"""You are an expert network forensic analyst and storyteller. Input: a JSON event (see below). Output: a JSON with fields:
  - one_line_summary (<=20 words)
  - technical_narrative (3-6 sentences, referencing evidence lines)
  - executive_summary (1-2 sentences, plain English)
  - severity ("Low"|"Medium"|"High"|"Critical")
  - mitre_tactics (list of probable MITRE ATT&CK tactics)
  - suggested_remediation (3 bullet points)
  - confidence (0.0-1.0)
  - tags (list)

Event JSON:
{json.dumps(cleaned_event_data, indent=2, default=str)}

Instructions: 
- Use only the info in the event JSON to justify claims.
- For each claim include short evidence references like [evidence #2].
- Keep exec summary non-technical.
- Provide severity reasoning in one line.
Return ONLY the JSON."""
    
    def generate_narrative(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate narrative for a single event using Gemini"""
        try:
            prompt = self._create_prompt(event_data)
            
            response = self.model.generate_content(prompt)
            narrative_text = response.text.strip()
            
            # Try to extract JSON from response
            try:
                start_idx = narrative_text.find('{')
                end_idx = narrative_text.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = narrative_text[start_idx:end_idx]
                    narrative = json.loads(json_str)
                else:
                    raise ValueError("No JSON found in response")
            except (json.JSONDecodeError, ValueError):
                logger.warning(f"Failed to parse JSON response for event {event_data.get('id', 'unknown')}")
                narrative = self._create_fallback_narrative(event_data, narrative_text)
            
            return narrative
            
        except Exception as e:
            logger.error(f"Error generating narrative with Gemini: {e}")
            return self._create_fallback_narrative(event_data, str(e))
    
    def generate_batch_narratives(self, events_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate narratives for multiple events"""
        narratives = []
        for event_data in events_data:
            narrative = self.generate_narrative(event_data)
            narratives.append(narrative)
        return narratives
    
    def _create_fallback_narrative(self, event_data: Dict[str, Any], error_text: str = "") -> Dict[str, Any]:
        """Create a fallback narrative when LLM fails"""
        # Same as Cohere fallback
        event_type = event_data.get('type', 'unknown')
        src_ip = event_data.get('src_ip', 'unknown')
        dst_ip = event_data.get('dst_ip', 'unknown')
        
        type_descriptions = {
            'port_scan': f"Port scan detected from {src_ip} targeting {dst_ip}",
            'brute_force': f"Brute force attack detected from {src_ip} against {dst_ip}",
            'beacon': f"Beaconing communication detected between {src_ip} and {dst_ip}",
            'data_exfil': f"Large data transfer detected from {src_ip} to {dst_ip}",
            'suspicious_connection': f"Suspicious connection pattern from {src_ip}"
        }
        
        summary = type_descriptions.get(event_type, f"Network event detected: {event_type}")
        
        return {
            "one_line_summary": summary,
            "technical_narrative": f"{summary}. Analysis based on network flow patterns and connection characteristics. Review evidence for detailed technical indicators.",
            "executive_summary": f"Network security event detected requiring investigation. Source: {src_ip}",
            "severity": "Medium",
            "mitre_tactics": ["Initial Access"] if event_type in ['port_scan', 'brute_force'] else ["Command and Control"],
            "suggested_remediation": [
                "Investigate source IP for malicious activity",
                "Review network logs for additional indicators",
                "Consider blocking suspicious traffic"
            ],
            "confidence": 0.5,
            "tags": [event_type, "automated_detection"],
            "error": error_text if error_text else None
        }

class GeminiProvider(LLMProvider):
    """Google Gemini LLM provider implementation"""
    
    def __init__(self, api_key: str):
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            logger.info("Initialized Gemini LLM provider")
        except ImportError:
            raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")
        except Exception as e:
            raise Exception(f"Failed to initialize Gemini client: {e}")
    
    def _clean_event_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean event data to ensure JSON serialization works"""
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
        
        return clean_value(event_data)
    
    def generate_narrative(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate narrative for a single event using Gemini"""
        try:
            # Clean event data to ensure JSON serialization works
            cleaned_event_data = self._clean_event_data(event_data)
            
            prompt = f"""You are an expert network forensic analyst and storyteller. Input: a JSON event (see below). Output: a JSON with fields:
  - one_line_summary (<=20 words)
  - technical_narrative (3-6 sentences, referencing evidence lines)
  - executive_summary (1-2 sentences, plain English)
  - severity ("Low"|"Medium"|"High"|"Critical")
  - mitre_tactics (list of probable MITRE ATT&CK tactics)
  - suggested_remediation (3 bullet points)
  - confidence (0.0-1.0)
  - tags (list)

Event JSON:
{json.dumps(cleaned_event_data, indent=2, default=str)}

Instructions: 
- Use only the info in the event JSON to justify claims.
- For each claim include short evidence references like [evidence #2].
- Keep exec summary non-technical.
- Provide severity reasoning in one line.
Return ONLY the JSON."""
            
            response = self.model.generate_content(prompt)
            narrative_text = response.text.strip()
            
            # Try to extract JSON from response
            try:
                # Find JSON in response (sometimes has extra text)
                start_idx = narrative_text.find('{')
                end_idx = narrative_text.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = narrative_text[start_idx:end_idx]
                    narrative = json.loads(json_str)
                else:
                    raise ValueError("No JSON found in response")
            except (json.JSONDecodeError, ValueError):
                # Fallback: create structured response from text
                logger.warning(f"Failed to parse JSON response for event {event_data.get('id', 'unknown')}")
                narrative = self._create_fallback_narrative(event_data, narrative_text)
            
            return narrative
            
        except Exception as e:
            logger.error(f"Error generating narrative with Gemini: {e}")
            return self._create_fallback_narrative(event_data, str(e))
    
    def generate_batch_narratives(self, events_data: List[Dict[str, Any]], progress_callback=None) -> List[Dict[str, Any]]:
        """Generate narratives for multiple events with progress tracking"""
        narratives = []
        total_events = len(events_data)
        
        for i, event_data in enumerate(events_data):
            # Update progress if callback provided
            if progress_callback:
                progress = (i / total_events) if total_events > 0 else 0
                progress_callback(f"Generating narrative {i+1}/{total_events} (Gemini)", progress)
            
            narrative = self.generate_narrative(event_data)
            narratives.append(narrative)
            
            logger.info(f"Generated narrative for event {event_data.get('id', 'unknown')} ({i+1}/{total_events})")
        
        # Final progress update
        if progress_callback:
            progress_callback(f"Completed narratives for {total_events} events", 1.0)
            
        return narratives
    
    def _create_fallback_narrative(self, event_data: Dict[str, Any], error_text: str = "") -> Dict[str, Any]:
        """Create a fallback narrative when LLM fails"""
        event_type = event_data.get('type', 'unknown')
        src_ip = event_data.get('src_ip', 'unknown')
        dst_ip = event_data.get('dst_ip', 'unknown')
        
        return {
            "one_line_summary": f"{event_type.replace('_', ' ').title()} detected from {src_ip} to {dst_ip}",
            "technical_narrative": f"A {event_type} event was detected involving source IP {src_ip} and destination IP {dst_ip}. This event was flagged by our detection systems based on network flow patterns and behavioral analysis.",
            "executive_summary": f"Security event detected involving suspicious {event_type.replace('_', ' ')} activity.",
            "severity": "Medium",
            "mitre_tactics": [],
            "suggested_remediation": [
                "Monitor the involved IP addresses for additional suspicious activity",
                "Review network logs for related events",
                "Consider blocking or restricting access if confirmed malicious"
            ],
            "confidence": 0.5,
            "tags": [event_type, "automated_detection"],
            "error": error_text if error_text else None
        }

class OpenAIProvider(LLMProvider):
    """OpenAI LLM provider implementation"""
    
    def __init__(self, api_key: str):
        try:
            import openai
            self.client = openai.OpenAI(api_key=api_key)
            self.model = "gpt-3.5-turbo"
            logger.info("Initialized OpenAI LLM provider")
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")
        except Exception as e:
            raise Exception(f"Failed to initialize OpenAI client: {e}")
    
    def _clean_event_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean event data to ensure JSON serialization works"""
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
        
        return clean_value(event_data)
    
    def generate_narrative(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate narrative for a single event using OpenAI"""
        try:
            # Clean event data to ensure JSON serialization works
            cleaned_event_data = self._clean_event_data(event_data)
            
            prompt = f"""You are an expert network forensic analyst and storyteller. Input: a JSON event (see below). Output: a JSON with fields:
  - one_line_summary (<=20 words)
  - technical_narrative (3-6 sentences, referencing evidence lines)
  - executive_summary (1-2 sentences, plain English)
  - severity ("Low"|"Medium"|"High"|"Critical")
  - mitre_tactics (list of probable MITRE ATT&CK tactics)
  - suggested_remediation (3 bullet points)
  - confidence (0.0-1.0)
  - tags (list)

Event JSON:
{json.dumps(cleaned_event_data, indent=2, default=str)}

Instructions: 
- Use only the info in the event JSON to justify claims.
- For each claim include short evidence references like [evidence #2].
- Keep exec summary non-technical.
- Provide severity reasoning in one line.
Return ONLY the JSON."""
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=800,
                temperature=0.3
            )
            
            narrative_text = response.choices[0].message.content.strip()
            
            # Try to extract JSON from response
            try:
                start_idx = narrative_text.find('{')
                end_idx = narrative_text.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = narrative_text[start_idx:end_idx]
                    narrative = json.loads(json_str)
                else:
                    raise ValueError("No JSON found in response")
            except (json.JSONDecodeError, ValueError):
                logger.warning(f"Failed to parse JSON response for event {event_data.get('id', 'unknown')}")
                narrative = self._create_fallback_narrative(event_data, narrative_text)
            
            return narrative
            
        except Exception as e:
            logger.error(f"Error generating narrative with OpenAI: {e}")
            return self._create_fallback_narrative(event_data, str(e))
    
    def generate_batch_narratives(self, events_data: List[Dict[str, Any]], progress_callback=None) -> List[Dict[str, Any]]:
        """Generate narratives for multiple events with progress tracking"""
        narratives = []
        total_events = len(events_data)
        
        for i, event_data in enumerate(events_data):
            # Update progress if callback provided
            if progress_callback:
                progress = (i / total_events) if total_events > 0 else 0
                progress_callback(f"Generating narrative {i+1}/{total_events} (OpenAI)", progress)
            
            narrative = self.generate_narrative(event_data)
            narratives.append(narrative)
            
            logger.info(f"Generated narrative for event {event_data.get('id', 'unknown')} ({i+1}/{total_events})")
        
        # Final progress update
        if progress_callback:
            progress_callback(f"Completed narratives for {total_events} events", 1.0)
            
        return narratives
    
    def _create_fallback_narrative(self, event_data: Dict[str, Any], error_text: str = "") -> Dict[str, Any]:
        """Create a fallback narrative when LLM fails"""
        # Same as other providers
        event_type = event_data.get('type', 'unknown')
        src_ip = event_data.get('src_ip', 'unknown')
        dst_ip = event_data.get('dst_ip', 'unknown')
        
        type_descriptions = {
            'port_scan': f"Port scan detected from {src_ip} targeting {dst_ip}",
            'brute_force': f"Brute force attack detected from {src_ip} against {dst_ip}",
            'beacon': f"Beaconing communication detected between {src_ip} and {dst_ip}",
            'data_exfil': f"Large data transfer detected from {src_ip} to {dst_ip}",
            'suspicious_connection': f"Suspicious connection pattern from {src_ip}"
        }
        
        summary = type_descriptions.get(event_type, f"Network event detected: {event_type}")
        
        return {
            "one_line_summary": summary,
            "technical_narrative": f"{summary}. Analysis based on network flow patterns and connection characteristics. Review evidence for detailed technical indicators.",
            "executive_summary": f"Network security event detected requiring investigation. Source: {src_ip}",
            "severity": "Medium",
            "mitre_tactics": ["Initial Access"] if event_type in ['port_scan', 'brute_force'] else ["Command and Control"],
            "suggested_remediation": [
                "Investigate source IP for malicious activity",
                "Review network logs for additional indicators",
                "Consider blocking suspicious traffic"
            ],
            "confidence": 0.5,
            "tags": [event_type, "automated_detection"],
            "error": error_text if error_text else None
        }

class LLMClient:
    """Main LLM client that manages different providers"""
    
    def __init__(self, provider_name: str = None):
        self.provider_name = provider_name or os.getenv('LLM_PROVIDER', 'cohere').lower()
        self.provider = self._initialize_provider()
        
    def _initialize_provider(self) -> LLMProvider:
        """Initialize the selected LLM provider"""
        if self.provider_name == 'cohere':
            api_key = os.getenv('COHERE_API_KEY')
            if not api_key:
                raise ValueError("COHERE_API_KEY environment variable not set")
            return CohereProvider(api_key)
        
        elif self.provider_name == 'gemini':
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                raise ValueError("GEMINI_API_KEY environment variable not set")
            return GeminiProvider(api_key)
        
        elif self.provider_name == 'openai':
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OPENAI_API_KEY environment variable not set")
            return OpenAIProvider(api_key)
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider_name}")
    
    def generate_narrative(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate narrative for a single event"""
        return self.provider.generate_narrative(event_data)
    
    def generate_batch_narratives(self, events_data: List[Dict[str, Any]], progress_callback=None) -> List[Dict[str, Any]]:
        """Generate narratives for multiple events with progress tracking"""
        return self.provider.generate_batch_narratives(events_data, progress_callback)
    
    def enrich_events_with_narratives(self, events: List[Dict[str, Any]], progress_callback=None) -> List[Dict[str, Any]]:
        """Add narratives to existing events with progress tracking"""
        logger.info(f"Generating narratives for {len(events)} events using {self.provider_name}")
        
        # Use batch processing with progress callback
        try:
            narratives = self.generate_batch_narratives(events, progress_callback)
            
            enriched_events = []
            for i, event in enumerate(events):
                try:
                    if i < len(narratives):
                        event['narrative'] = narratives[i]
                    enriched_events.append(event)
                    logger.debug(f"Added narrative for event {event.get('id', 'unknown')}")
                except Exception as e:
                    logger.error(f"Failed to add narrative for event {event.get('id', 'unknown')}: {e}")
                    event['narrative'] = {
                        "error": str(e),
                        "one_line_summary": f"Event {event.get('type', 'unknown')} - narrative generation failed",
                        "severity": "Medium"
                    }
                    enriched_events.append(event)
            
            return enriched_events
            
        except Exception as e:
            logger.error(f"Batch narrative generation failed: {e}")
            # Fallback to individual processing
            enriched_events = []
            total_events = len(events)
            
            for i, event in enumerate(events):
                try:
                    if progress_callback:
                        progress = (i / total_events) if total_events > 0 else 0
                        progress_callback(f"Generating narrative {i+1}/{total_events} (fallback)", progress)
                    
                    narrative = self.generate_narrative(event)
                    event['narrative'] = narrative
                    enriched_events.append(event)
                    logger.debug(f"Generated narrative for event {event.get('id', 'unknown')}")
                    
                except Exception as e:
                    logger.error(f"Failed to generate narrative for event {event.get('id', 'unknown')}: {e}")
                    event['narrative'] = {
                        "error": str(e),
                        "one_line_summary": f"Event {event.get('type', 'unknown')} - narrative generation failed",
                        "severity": "Medium"
                    }
                    enriched_events.append(event)
        
        logger.info(f"Successfully enriched {len(enriched_events)} events with narratives")
        return enriched_events

def main():
    """CLI interface for narrative generation"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python llm_client.py <events_file.jsonl>")
        sys.exit(1)
    
    events_file = sys.argv[1]
    
    # Load events from JSONL
    events = []
    with open(events_file, 'r') as f:
        for line in f:
            events.append(json.loads(line))
    
    # Generate narratives
    llm_client = LLMClient()
    enriched_events = llm_client.enrich_events_with_narratives(events)
    
    # Save enriched events
    output_file = events_file.replace('.jsonl', '_enriched.jsonl')
    with open(output_file, 'w') as f:
        for event in enriched_events:
            f.write(json.dumps(event) + '\n')
    
    print(f"Narrative generation complete: {len(enriched_events)} events enriched")
    print(f"Output saved to: {output_file}")

if __name__ == "__main__":
    main() 