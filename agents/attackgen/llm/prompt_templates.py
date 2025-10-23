# agents/attackgen/llm/prompt_templates.py
"""
Prompt templates for AttackGen Agent LLM integration.
"""

from typing import Dict, Any
import json


class PromptTemplates:
    """
    Collection of prompt templates for attack command generation.
    """
    
    def get_command_generation_prompt(
        self, 
        ttp: Dict[str, Any], 
        attack_details: Dict[str, Any], 
        platform: str
    ) -> str:
        """Get main command generation prompt"""
        
        return f"""You are an expert cybersecurity red team researcher specialized in MITRE ATT&CK techniques.
Your task is to generate realistic attack commands for testing purposes in a controlled environment.

=== CONTEXT ===
Technique: {ttp['technique_name']} ({ttp['attack_id']})
Tactic: {ttp['tactic']}
Target Platform: {platform}
Description: {ttp.get('description', 'N/A')}
Confidence Score: {ttp.get('confidence_score', 'N/A')}

=== MITRE ATT&CK DETAILS ===
{self._format_attack_details(attack_details)}

=== TASK REQUIREMENTS ===
Generate 2-3 realistic attack commands that demonstrate this technique on {platform}:

1. Commands must be REALISTIC and technically accurate
2. Safe for testing environments (no actual damage)
3. Include clear explanations of what each command does
4. Provide expected indicators/artifacts that would be generated
5. Include prerequisites and cleanup instructions
6. Follow cybersecurity best practices for red team testing

=== OUTPUT FORMAT ===
Respond with valid JSON only:
{{
  "commands": [
    {{
      "name": "Descriptive name of the command",
      "command": "actual executable command or script",
      "explanation": "detailed explanation of what this does and how it relates to the technique",
      "indicators": ["list", "of", "expected", "detection", "artifacts"],
      "prerequisites": ["required", "conditions", "for", "execution"],
      "cleanup": "commands to clean up after testing",
      "platform_specific_notes": "any platform-specific considerations"
    }}
  ]
}}

=== EXAMPLE FOR T1059.001 (PowerShell) on Windows ===
{{
  "commands": [
    {{
      "name": "PowerShell Execution Policy Bypass",
      "command": "powershell.exe -ExecutionPolicy Bypass -Command \\"Get-Process | Where-Object {{\\$_.ProcessName -eq 'explorer'}}\\"",
      "explanation": "Executes PowerShell command while bypassing execution policy restrictions, demonstrating how attackers can run PowerShell scripts even when policies are restrictive",
      "indicators": ["PowerShell process creation", "ExecutionPolicy bypass parameter", "Process enumeration via WMI"],
      "prerequisites": ["PowerShell installed", "User privileges"],
      "cleanup": "No cleanup required for this read-only operation",
      "platform_specific_notes": "Works on Windows 7 and later"
    }}
  ]
}}

Generate commands for: {ttp['technique_name']} on {platform}"""

    def get_enhancement_prompt(self, base_command: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Get command enhancement prompt"""
        
        return f"""You are an expert red team operator improving attack commands.

=== EXISTING COMMAND ===
{json.dumps(base_command, indent=2)}

=== ADDITIONAL CONTEXT ===
{json.dumps(context, indent=2)}

=== ENHANCEMENT TASK ===
Improve this attack command by:
1. Making it more realistic and sophisticated
2. Adding evasion techniques if appropriate
3. Improving the explanation and indicators
4. Adding additional variants or options
5. Ensuring it aligns with real-world attacker behavior

=== OUTPUT FORMAT ===
{{
  "enhanced_command": "improved command",
  "additional_indicators": ["new", "indicators"],
  "evasion_techniques": ["techniques", "used"],
  "variants": [
    {{
      "name": "Variant name",
      "command": "variant command",
      "explanation": "why this variant is useful"
    }}
  ],
  "improvement_notes": "explanation of improvements made"
}}"""

    def get_script_generation_prompt(self, commands: list[Dict[str, Any]], platform: str) -> str:
        """Get script generation prompt for combining multiple commands"""
        
        return f"""You are an expert script developer creating comprehensive attack simulation scripts.

=== COMMANDS TO COMBINE ===
{json.dumps(commands, indent=2)}

=== TASK ===
Create a comprehensive {platform} script that:
1. Executes all provided commands in logical order
2. Includes error handling and logging
3. Has proper prerequisites checking
4. Includes cleanup functionality
5. Is well-documented with comments
6. Follows {platform} scripting best practices

=== OUTPUT FORMAT ===
{{
  "script_content": "complete executable script",
  "script_type": "powershell|bash|python",
  "execution_notes": "how to run this script",
  "safety_warnings": ["important", "safety", "considerations"]
}}"""

    def get_evasion_prompt(self, base_command: Dict[str, Any]) -> str:
        """Get evasion technique generation prompt"""
        
        return f"""You are a cybersecurity researcher studying defense evasion techniques.

=== BASE COMMAND ===
{json.dumps(base_command, indent=2)}

=== TASK ===
Generate evasion variants of this command that:
1. Achieve the same objective as the original
2. Use different methods to avoid detection
3. Are realistic techniques used by actual threat actors
4. Include explanations of the evasion methods

Common evasion techniques to consider:
- Process hiding/masquerading
- Registry/file system hiding
- Network traffic obfuscation
- Anti-analysis techniques
- Living-off-the-land techniques
- Timing/behavioral evasion

=== OUTPUT FORMAT ===
{{
  "evasive_variants": [
    {{
      "name": "Evasion technique name",
      "command": "evasive command",
      "explanation": "how this evades detection",
      "evasion_category": "process|network|filesystem|behavioral"
    }}
  ]
}}"""

    def _format_attack_details(self, attack_details: Dict[str, Any]) -> str:
        """Format MITRE ATT&CK details for prompt"""
        
        formatted = []
        
        # Basic info
        formatted.append(f"Name: {attack_details.get('name', 'N/A')}")
        formatted.append(f"Description: {attack_details.get('description', 'N/A')[:500]}...")
        
        # Tactics
        tactics = attack_details.get('tactics', [])
        if tactics:
            formatted.append(f"Tactics: {', '.join(tactics)}")
        
        # Platforms
        platforms = attack_details.get('platforms', [])
        if platforms:
            formatted.append(f"Platforms: {', '.join(platforms)}")
        
        # Related software
        software = attack_details.get('related_software', [])
        if software:
            software_names = [s.get('name', 'Unknown') for s in software[:3]]
            formatted.append(f"Related Software: {', '.join(software_names)}")
        
        # Data sources
        data_sources = attack_details.get('data_sources', [])
        if data_sources:
            formatted.append(f"Data Sources: {', '.join(data_sources[:3])}")
        
        return '\n'.join(formatted)

    def get_validation_prompt(self, command: str, platform: str) -> str:
        """Get command validation prompt"""
        
        return f"""You are a cybersecurity expert reviewing attack commands for safety and accuracy.

=== COMMAND TO VALIDATE ===
Platform: {platform}
Command: {command}

=== VALIDATION CRITERIA ===
1. SAFETY: Is this command safe for testing environments?
2. ACCURACY: Is this technically accurate and would it work?
3. REALISM: Would real attackers use similar commands?
4. DETECTABILITY: Would this generate useful detection indicators?

=== OUTPUT FORMAT ===
{{
  "is_safe": true/false,
  "is_accurate": true/false,
  "is_realistic": true/false,
  "is_detectable": true/false,
  "safety_concerns": ["list", "of", "safety", "issues"],
  "improvement_suggestions": ["suggestions", "for", "improvement"],
  "overall_score": 0-10
}}"""