"""
LLM-based Sigma Rule Generator using Gemini API - FIXED VERSION
Generates Sigma rules from TTP data using LLM
"""

import os
import json
import re
from typing import Dict, List, Any, Optional
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
from datetime import datetime
import uuid
import asyncio


class LLMSigmaGenerator:
    """Generate Sigma rules using LLM (Gemini) with google-generativeai SDK"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize LLM Sigma Generator
        
        Args:
            config: Configuration dict with:
                - api_key: Gemini API key
                - model: Model name (default: gemini-2.0-flash-lite)
                - temperature: Generation temperature
                - max_retries: Max retry attempts
        """
        self.config = config or {}
        
        # Get API key from config or environment
        self.api_key = self.config.get('api_key') or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key not found. Set GEMINI_API_KEY environment variable or pass in config")
        
        # Set API key as environment variable (newer google.genai way)
        os.environ['GOOGLE_API_KEY'] = self.api_key
        
        # No need to configure - just initialize the client
        try:
            print(f"Debug: Gemini API key set successfully")
        except Exception as e:
            print(f"Debug: Failed to set API key: {type(e).__name__}: {str(e)}")
            raise ValueError(f"Failed to configure Gemini API: {str(e)}")
        
        # Initialize the client with API key
        self.client = genai.Client(api_key=self.api_key)
        
        # Model configuration
        self.model_name = self.config.get('model', 'gemini-2.0-flash-lite')
        self.temperature = self.config.get('temperature', 0.3)
        self.max_retries = self.config.get('max_retries', 3)
        
        print(f"LLM Generator initialized with model: {self.model_name}")
    
    def _build_sigma_prompt(self, ttp_data: Dict[str, Any]) -> str:
        """Build prompt for Sigma rule generation"""
        
        # Extract TTP information
        attack_id = ttp_data.get('attack_id', 'UNKNOWN')
        technique_name = ttp_data.get('technique_name', '')
        tactic = ttp_data.get('tactic', '')
        description = ttp_data.get('description', '')
        
        # Context information
        context = ttp_data.get('context', {})
        threat_actor = context.get('threat_actor', '')
        malware = context.get('malware_used', [])
        tools = ttp_data.get('tools', [])
        
        # IOCs
        iocs = ttp_data.get('iocs', {})
        
        # Feedback context (if available)
        feedback_context = ttp_data.get('feedback_context')
        feedback_section = ""
        if feedback_context:
            improvements = feedback_context.get('improvements_needed', [])
            suggestions = feedback_context.get('actionable_suggestions', [])
            
            if improvements or suggestions:
                feedback_section = "\n\n## Previous Evaluation Feedback:\n"
                feedback_section += "Please improve the rule based on this feedback:\n"
                
                for imp in improvements:
                    feedback_section += f"- {imp.get('metric', 'General')}: {imp.get('suggestion', '')}\n"
                
                for sug in suggestions:
                    feedback_section += f"- {sug}\n"
                
                feedback_section += "\nIncorporate these improvements into the new rule generation.\n"
        
        prompt = f"""You are a cybersecurity expert specializing in SIEM detection rules and Sigma rule creation.

Generate a high-quality Sigma detection rule for the following MITRE ATT&CK technique:{feedback_section}

**Technique Information:**
- ATT&CK ID: {attack_id}
- Technique Name: {technique_name}
- Tactic: {tactic}
- Description: {description}

**Threat Context:**
- Threat Actor: {threat_actor}
- Malware: {', '.join(malware) if malware else 'N/A'}
- Tools: {', '.join(tools) if tools else 'N/A'}

**Available IOCs:**
{json.dumps(iocs, indent=2)}

**Requirements:**
1. Generate a COMPLETE and VALID Sigma rule in JSON format
2. Include realistic and specific detection patterns (NOT generic terms like "malicious", "suspicious")
3. Use appropriate field names based on the log source (Image, CommandLine, ProcessName, etc.)
4. Include multiple detection selections if needed for better coverage
5. Add proper filters to reduce false positives
6. Set appropriate severity level (low/medium/high/critical)
7. Include specific false positive scenarios
8. Add MITRE ATT&CK tags
9. **CRITICAL: STRICTLY use ONLY the IOCs, malware, and tools provided in the input. DO NOT invent IPs (e.g. 192.168.1.1), domains, or filenames.**
10. If specific IOCs are missing, use generic behavioral patterns (e.g. command line flags), do NOT hallucinate values.
11. Weigh specific file paths (e.g. %ALLUSERSPROFILE%, %TEMP%) higher than generic wildcards.

**Output Format:**
Return ONLY a valid JSON object with this structure:
{{
  "title": "Descriptive title",
  "id": "uuid",
  "status": "experimental|test|stable",
  "description": "Detailed description",
  "references": ["URLs"],
  "author": "Multi-Agent SIEM Framework",
  "date": "YYYY/MM/DD",
  "modified": "YYYY/MM/DD",
  "tags": ["attack.{attack_id.lower()}", "attack.{tactic.lower().replace(' ', '_')}"],
  "logsource": {{
    "category": "process_creation|network_connection|file_event",
    "product": "windows|linux|macos",
    "service": "security|sysmon"
  }},
  "detection": {{
    "selection": {{
      "FieldName|modifier": "value or [list]"
    }},
    "filter": {{
      "FieldName": "legitimate patterns to exclude"
    }},
    "condition": "selection and not filter"
  }},
  "falsepositives": ["Specific scenarios"],
  "level": "low|medium|high|critical"
}}

**Important Detection Logic Rules:**
1. For credential dumping (T1003): Detect mimikatz.exe, procdump.exe accessing lsass, NOT lsass.exe itself
2. For PowerShell (T1059.001): Look for encoded commands, download cradles, execution bypasses
3. For phishing (T1566): Detect Office spawning processes (ParentImage: WINWORD.EXE -> Image: cmd.exe/powershell.exe)
4. Use process relationships (ParentImage → Image) when relevant
5. Include both binary name AND command line patterns
6. **Hallucination Check:** Do not include "192.168.x.x" or "example.com" unless explicitly in the Input IOCs.

Generate the Sigma rule now:"""
        
        return prompt
    
    async def generate_sigma_rule(self, ttp_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Sigma rule using LLM
        
        Args:
            ttp_data: TTP information dict
            
        Returns:
            Generated Sigma rule dict
        """
        attack_id = ttp_data.get('attack_id', 'UNKNOWN')
        technique_name = ttp_data.get('technique_name', '')
        
        print(f"\n🤖 Generating Sigma rule for {attack_id}: {technique_name}")
        
        # Build prompt
        prompt = self._build_sigma_prompt(ttp_data)
        
        # Generate with retries
        for attempt in range(self.max_retries):
            try:
                print(f"   Attempt {attempt + 1}/{self.max_retries}...")
                
                # Generate response
                response = await self._generate_with_model(prompt)
                
                # Extract JSON from response
                sigma_rule = self._extract_json_from_response(response)
                
                if sigma_rule:
                    # Validate and enhance
                    sigma_rule = self._validate_and_enhance(sigma_rule, ttp_data)
                    
                    print(f"   Generated: {sigma_rule.get('title', 'Untitled')}")
                    return sigma_rule
                else:
                    print(f"   Failed to extract valid JSON, retrying...")
                    
            except Exception as e:
                print(f"   Error: {type(e).__name__}: {str(e)}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"   Max retries reached, using fallback")
                    return self._generate_fallback_rule(ttp_data)
        
        return self._generate_fallback_rule(ttp_data)
    
    async def _generate_with_model(self, prompt: str) -> str:
        """Generate response using Gemini model"""
        def _generate_sync():
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
                # Removed config parameter as it may not be supported in current version
            )
            return response.text
        
        # Run in thread pool to maintain async interface
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _generate_sync)
    
    def _extract_json_from_response(self, response_text: str) -> Optional[Dict]:
        """Extract JSON object from LLM response"""
        
        if not response_text:
            return None
        
        # Try to find JSON block
        # Look for ```json ... ``` or just {...}
        json_patterns = [
            r'```json\s*(\{.*?\})\s*```',
            r'```\s*(\{.*?\})\s*```',
            r'(\{.*\})'
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, response_text, re.DOTALL)
            if match:
                json_str = match.group(1)
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    continue
        
        # Try parsing entire response as JSON
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            return None
    
    def _validate_and_enhance(self, sigma_rule: Dict, ttp_data: Dict) -> Dict:
        """Validate and enhance generated Sigma rule"""
        
        # Ensure required fields
        if 'id' not in sigma_rule or not sigma_rule['id']:
            sigma_rule['id'] = str(uuid.uuid4())
        
        if 'date' not in sigma_rule:
            sigma_rule['date'] = datetime.now().strftime('%Y/%m/%d')
        
        if 'modified' not in sigma_rule:
            sigma_rule['modified'] = sigma_rule['date']
        
        if 'author' not in sigma_rule:
            sigma_rule['author'] = 'Multi-Agent SIEM Framework'
        
        if 'status' not in sigma_rule:
            sigma_rule['status'] = 'experimental'
        
        # Add metadata
        sigma_rule['metadata'] = {
            'ttp_id': ttp_data.get('ttp_id'),
            'technique_id': ttp_data.get('attack_id'),
            'confidence': ttp_data.get('confidence_score', 0.5),
            'extraction_method': ttp_data.get('extraction_method', 'llm'),
            'threat_actor': ttp_data.get('context', {}).get('threat_actor', ''),
            'malware': ttp_data.get('context', {}).get('malware_used', []),
            'tools': ttp_data.get('tools', []),
            'campaign': ttp_data.get('context', {}).get('campaign', ''),
            'generated_by': 'llm',
            'llm_model': self.model_name
        }
        
        # Validate detection section
        if 'detection' not in sigma_rule or not sigma_rule['detection']:
            print(f"   Invalid detection section, using fallback")
            return self._generate_fallback_rule(ttp_data)
        
        return sigma_rule
    
    def _generate_fallback_rule(self, ttp_data: Dict) -> Dict:
        """Generate basic fallback rule if LLM fails"""
        
        attack_id = ttp_data.get('attack_id', 'UNKNOWN')
        technique_name = ttp_data.get('technique_name', 'Unknown Technique')
        description = ttp_data.get('description', 'No description available')
        tactic = ttp_data.get('tactic', 'Unknown')
        
        # Extract indicators
        indicators = self._extract_indicators_from_ttp(ttp_data)
        
        # Build basic detection
        detection = {
            'selection': {},
            'condition': 'selection'
        }
        
        # Add process indicators if available
        process_indicators = [ind['value'] for ind in indicators if ind['type'] == 'process_image']
        if process_indicators:
            if len(process_indicators) == 1:
                detection['selection']['Image|endswith'] = process_indicators[0]
            else:
                detection['selection']['Image|endswith'] = process_indicators
        
        # Add command line indicators
        cmdline_indicators = [ind['value'] for ind in indicators if ind['type'] == 'command_line']
        if cmdline_indicators:
            detection['selection']['CommandLine|contains'] = cmdline_indicators
        
        # If no indicators, add a basic pattern
        if not detection['selection']:
            detection['selection']['Image|endswith'] = f"{technique_name.lower().replace(' ', '_')}.exe"
        
        return {
            'title': f"{technique_name} Detection",
            'id': str(uuid.uuid4()),
            'status': 'experimental',
            'description': description,
            'references': [
                f"https://attack.mitre.org/techniques/{attack_id}/"
            ],
            'author': 'Multi-Agent SIEM Framework',
            'date': datetime.now().strftime('%Y/%m/%d'),
            'modified': datetime.now().strftime('%Y/%m/%d'),
            'tags': [
                f"attack.{attack_id.lower()}",
                f"attack.{tactic.lower().replace(' ', '_')}"
            ],
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': detection,
            'falsepositives': [
                'Legitimate administrative activity'
            ],
            'level': 'medium',
            'metadata': {
                'ttp_id': ttp_data.get('ttp_id'),
                'technique_id': attack_id,
                'confidence': ttp_data.get('confidence_score', 0.5),
                'extraction_method': 'fallback',
                'generated_by': 'fallback_generator'
            }
        }
    
    def _extract_indicators_from_ttp(self, ttp_data: Dict) -> List[Dict]:
        """Extract indicators from TTP data"""
        indicators = []
        
        # From IOCs
        iocs = ttp_data.get('iocs', {})
        for ioc_type, values in iocs.items():
            if isinstance(values, list):
                for value in values:
                    indicators.append({
                        'type': ioc_type,
                        'value': value
                    })
            elif isinstance(values, str):
                indicators.append({
                    'type': ioc_type,
                    'value': values
                })
        
        # From tools
        tools = ttp_data.get('tools', [])
        for tool in tools:
            indicators.append({
                'type': 'process_image',
                'value': f'{tool}.exe'
            })
        
        # From malware
        context = ttp_data.get('context', {})
        malware = context.get('malware_used', [])
        for mal in malware:
            indicators.append({
                'type': 'process_image',
                'value': f'{mal}.exe'
            })
        
        return indicators


# Async wrapper for batch processing
async def generate_sigma_rules_batch(ttp_list: List[Dict], config: Optional[Dict] = None) -> List[Dict]:
    """
    Generate Sigma rules for multiple TTPs in batch
    
    Args:
        ttp_list: List of TTP data dicts
        config: Generator configuration
        
    Returns:
        List of generated Sigma rules
    """
    generator = LLMSigmaGenerator(config)
    
    tasks = [generator.generate_sigma_rule(ttp) for ttp in ttp_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions
    sigma_rules = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"Failed to generate rule for TTP {i+1}: {result}")
            # Use fallback
            sigma_rules.append(generator._generate_fallback_rule(ttp_list[i]))
        else:
            sigma_rules.append(result)
    
    return sigma_rules


# Example usage
if __name__ == "__main__":
    # Test with sample TTP data
    sample_ttp = {
        'ttp_id': 'test-123',
        'attack_id': 'T1059.001',
        'technique_name': 'PowerShell',
        'tactic': 'Execution',
        'description': 'Execution of PowerShell scripts',
        'confidence_score': 0.85,
        'context': {
            'threat_actor': 'APT28',
            'malware_used': ['Mimikatz'],
            'campaign': 'Test Campaign'
        },
        'tools': ['PowerShell', 'Empire'],
        'iocs': {
            'command_line': ['-encodedCommand', 'DownloadString'],
            'process_image': ['powershell.exe']
        }
    }
    
    async def test():
        config = {
            'api_key': os.getenv('GEMINI_API_KEY'),
            'model': 'gemini-2.0-flash-lite',
            'temperature': 0.3
        }
        
        generator = LLMSigmaGenerator(config)
        sigma_rule = await generator.generate_sigma_rule(sample_ttp)
        
        print("\n" + "="*80)
        print("Generated Sigma Rule:")
        print("="*80)
        print(json.dumps(sigma_rule, indent=2))
    
    asyncio.run(test())