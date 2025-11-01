"""
LLM-based Sigma Rule Generator using Gemini API (google-genai) - FIXED VERSION
Generates Sigma rules from TTP data using LLM
"""

import os
import json
import re
from typing import Dict, List, Any, Optional
from google import genai
from google.genai import types
from datetime import datetime
import uuid
import asyncio


class LLMSigmaGenerator:
    """Generate Sigma rules using LLM (Gemini) with google-genai SDK"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize LLM Sigma Generator
        
        Args:
            config: Configuration dict with:
                - api_key: Gemini API key
                - model: Model name (default: gemini-2.0-flash-exp)
                - temperature: Generation temperature
                - max_retries: Max retry attempts
        """
        self.config = config or {}
        
        # Get API key from config or environment
        self.api_key = self.config.get('api_key') or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key not found. Set GEMINI_API_KEY environment variable or pass in config")
        
        # Initialize google-genai client
        try:
            self.client = genai.Client(api_key=self.api_key)
            print(f"🔍 Debug: Gemini client initialized successfully")
        except Exception as e:
            print(f"🔍 Debug: Failed to initialize: {type(e).__name__}: {str(e)}")
            raise ValueError(f"Failed to initialize Gemini client: {str(e)}")
        
        # Model configuration
        self.model_name = self.config.get('model', 'gemini-2.0-flash-exp')
        self.temperature = self.config.get('temperature', 0.3)
        self.max_retries = self.config.get('max_retries', 3)
        
        print(f"✓ LLM Generator initialized with model: {self.model_name}")
    
    def _get_generation_config(self) -> types.GenerateContentConfig:
        """Create generation configuration object"""
        return types.GenerateContentConfig(
            temperature=self.temperature,
            top_p=0.95,
            top_k=40,
            max_output_tokens=4096,
            # Safety settings for security research content
            safety_settings=[
                types.SafetySetting(
                    category='HARM_CATEGORY_HARASSMENT',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_HATE_SPEECH',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_SEXUALLY_EXPLICIT',
                    threshold='BLOCK_NONE'
                ),
                types.SafetySetting(
                    category='HARM_CATEGORY_DANGEROUS_CONTENT',
                    threshold='BLOCK_NONE'
                ),
            ]
        )
    
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
        
        prompt = f"""You are a cybersecurity expert specializing in SIEM detection rules and Sigma rule creation.

Generate a high-quality Sigma detection rule for the following MITRE ATT&CK technique:

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
3. For phishing (T1566): Detect Office spawning processes, not generic "malicious.doc"
4. Use process relationships (ParentImage → Image) when relevant
5. Include both binary name AND command line patterns

Generate the Sigma rule now:"""
        
        return prompt
    
    async def generate_sigma_rule(self, ttp_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Sigma rule using LLM with google-genai
        
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
                
                # Generate response using google-genai
                response = await self._generate_with_client(prompt)
                
                # Extract JSON from response
                sigma_rule = self._extract_json_from_response(response)
                
                if sigma_rule:
                    # Validate and enhance
                    sigma_rule = self._validate_and_enhance(sigma_rule, ttp_data)
                    
                    print(f"   ✓ Generated: {sigma_rule.get('title', 'Untitled')}")
                    return sigma_rule
                else:
                    print(f"   ⚠️ Failed to extract valid JSON, retrying...")
                    
            except Exception as e:
                print(f"   ❌ Error: {type(e).__name__}: {str(e)}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    print(f"   ❌ Max retries reached, using fallback")
                    return self._generate_fallback_rule(ttp_data)
        
        return self._generate_fallback_rule(ttp_data)
    
    async def _generate_with_client(self, prompt: str) -> str:
        """Generate response using google-genai client"""
        def _generate_sync():
            config = self._get_generation_config()
            
            # CORRECT API CALL for google-genai
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config
            )
            
            # Extract text from response
            if hasattr(response, 'text') and response.text:
                return response.text
            
            # Fallback: extract from candidates/parts structure
            if hasattr(response, "candidates") and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content'):
                    content = candidate.content
                    if hasattr(content, "parts") and content.parts:
                        texts = []
                        for part in content.parts:
                            if hasattr(part, "text") and part.text:
                                texts.append(part.text)
                        if texts:
                            return ''.join(texts)
                
                # Direct text in candidate
                if hasattr(candidate, "text") and candidate.text:
                    return candidate.text
            
            print("🔍 Debug: No text found in response")
            return ""
        
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
            print(f"   ⚠️ Invalid detection section, using fallback")
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
            print(f"❌ Failed to generate rule for TTP {i+1}: {result}")
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
            'model': 'gemini-2.0-flash-exp',
            'temperature': 0.3
        }
        
        generator = LLMSigmaGenerator(config)
        sigma_rule = await generator.generate_sigma_rule(sample_ttp)
        
        print("\n" + "="*80)
        print("Generated Sigma Rule:")
        print("="*80)
        print(json.dumps(sigma_rule, indent=2))
    
    asyncio.run(test())