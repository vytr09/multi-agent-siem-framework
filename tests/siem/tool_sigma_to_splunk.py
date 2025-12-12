# #!/usr/bin/env python3
# """
# Script để chuyển đổi Sigma rules thành Splunk queries
# """

# import json
# import re
# from typing import List, Dict, Any
# from pathlib import Path
# from datetime import datetime


# class SigmaToSplunkConverter:
#     """Converter chuyển đổi Sigma rules sang Splunk queries"""
    
#     def __init__(self):
#         # Mapping field names từ Sigma sang Splunk
#         # Hỗ trợ cả Traditional Sigma fields và ECS (Elastic Common Schema) fields
        
#         # Traditional Sigma to Splunk mapping
#         self.traditional_mapping = {
#             # Common fields
#             'EventID': 'EventCode',
            
#             # Sysmon fields (giữ nguyên)
#             'Image': 'Image',
#             'CommandLine': 'CommandLine',
#             'ParentImage': 'ParentImage',
#             'ParentCommandLine': 'ParentCommandLine',
#             'User': 'User',
#             'ProcessId': 'ProcessId',
#             'ParentProcessId': 'ParentProcessId',
#             'CurrentDirectory': 'Current_Directory',
#             'IntegrityLevel': 'Process_Integrity_Level',
#             'TargetFilename': 'TargetFilename',
#             'DestinationIp': 'DestinationIp',
#             'DestinationPort': 'DestinationPort',
#             'SourceIp': 'SourceIp',
#             'TargetObject': 'TargetObject',
            
#             # Windows Security Log fields (EventCode 4688)
#             'NewProcessName': 'New_Process_Name',
#             'Creator_Process_Name': 'Creator_Process_Name',
#             'SubjectUserName': 'Subject_User_Name',
#             'SubjectDomainName': 'Subject_Domain_Name',
#             'SubjectLogonId': 'Subject_Logon_Id',
#             'NewProcessId': 'New_Process_Id',
#             'TokenElevationType': 'Token_Elevation_Type',
#             'OriginalFileName': 'Original_File_Name',
#         }
        
#         # ECS (Elastic Common Schema) to Splunk mapping
#         self.ecs_mapping = {
#             # Process fields
#             'process.executable': 'New_Process_Name',
#             'process.command_line': 'Process_Command_Line',
#             'process.name': 'New_Process_Name',
#             'process.current_directory': 'Current_Directory',
#             'process.integrity_level': 'Process_Integrity_Level',
#             'process.creation_time': 'Process_Creation_Time',
#             'process.id': 'Process_ID',
#             'process.pid': 'Process_ID',
            
#             # Parent process fields
#             'process.parent.executable': 'Parent_Process_Name',
#             'process.parent.command_line': 'Parent_Process_Command_Line',
#             'process.parent.name': 'Parent_Process_Name',
#             'process.parent.id': 'Parent_Process_ID',
#             'process.parent.pid': 'Parent_Process_ID',
#             'process.parent.creation_time': 'Parent_Process_Creation_Time',
#             'process.parent.integrity_level': 'Parent_Process_Integrity_Level',
#             'process.parent.current_directory': 'Parent_Current_Directory',
            
#             # User fields
#             'user.name': 'Subject_User_Name',
#             'user.domain': 'Subject_Domain_Name',
#             'user.id': 'Subject_Logon_Id',
            
#             # File fields
#             'file.path': 'TargetFilename',
#             'file.name': 'TargetFilename',
#             'file.directory': 'Current_Directory',
            
#             # Network fields
#             'destination.ip': 'DestinationIp',
#             'destination.port': 'DestinationPort',
#             'source.ip': 'SourceIp',
#             'source.port': 'SourcePort',
#             'network.protocol': 'Protocol',
            
#             # Registry fields
#             'registry.path': 'TargetObject',
#             'registry.key': 'TargetObject',
#             'registry.value': 'Details',
            
#             # Event fields
#             'event.code': 'EventCode',
#             'event.id': 'EventCode',
#         }
        
#         # Combined mapping (ECS has priority over traditional)
#         self.field_mapping = {**self.traditional_mapping, **self.ecs_mapping}
        
#         # Context-aware mapping dựa trên log source
#         self.sysmon_fields = {
#             'Image', 'CommandLine', 'ParentImage', 'ParentCommandLine',
#             'User', 'ProcessId', 'ParentProcessId'
#         }
        
#         self.security_log_fields = {
#             'NewProcessName', 'Creator_Process_Name', 'SubjectUserName',
#             'SubjectDomainName', 'NewProcessId'
#         }
        
#         # Event ID to EventCode mapping
#         self.event_code_mapping = {
#             '1': '1',      # Sysmon - Process Creation
#             '3': '3',      # Sysmon - Network Connection
#             '7': '7',      # Sysmon - Image Loaded
#             '8': '8',      # Sysmon - CreateRemoteThread
#             '10': '10',    # Sysmon - Process Access
#             '11': '11',    # Sysmon - File Created
#             '12': '12',    # Sysmon - Registry Event
#             '13': '13',    # Sysmon - Registry Value Set
#             '4688': '4688' # Security - Process Creation
#         }
    
#     def convert_field_name(self, field: str, logsource: Dict = None) -> str:
#         """Chuyển đổi tên field từ Sigma sang Splunk với context awareness"""
        
#         # Check if it's an ECS field (contains dot notation)
#         if '.' in field:
#             # ECS field - use ECS mapping directly
#             splunk_field = self.ecs_mapping.get(field)
#             if splunk_field:
#                 return splunk_field
#             # If not found in mapping, return as-is
#             return field
        
#         # Traditional Sigma field
#         # For Windows logs, ALWAYS use normalized field names (với underscores)
        
#         # Process-related fields - map to Windows Security Log format
#         if field in ['Image', 'NewProcessName']:
#             return 'New_Process_Name'
#         elif field in ['CommandLine', 'ProcessCommandLine']:
#             return 'Process_Command_Line'
#         elif field in ['ParentImage', 'ParentProcessName', 'Creator_Process_Name']:
#             return 'Parent_Process_Name'
#         elif field in ['ParentCommandLine', 'ParentProcessCommandLine']:
#             return 'Parent_Process_Command_Line'
#         elif field in ['User', 'SubjectUserName']:
#             return 'Subject_User_Name'
#         elif field in ['ProcessId', 'NewProcessId']:
#             return 'Process_ID'
#         elif field in ['ParentProcessId']:
#             return 'Parent_Process_ID'
#         elif field in ['CurrentDirectory']:
#             return 'Current_Directory'
#         elif field in ['IntegrityLevel']:
#             return 'Process_Integrity_Level'
        
#         # Other fields
#         elif field in ['OriginalFileName']:
#             return 'Original_File_Name'
#         elif field in ['SubjectDomainName']:
#             return 'Subject_Domain_Name'
#         elif field in ['SubjectLogonId']:
#             return 'Subject_Logon_Id'
#         elif field in ['TokenElevationType']:
#             return 'Token_Elevation_Type'
        
#         # Keep these as-is or use mapping
#         return self.traditional_mapping.get(field, field)
    
#     def escape_splunk_value(self, value: str) -> str:
#         """Escape special characters trong giá trị Splunk"""
#         # Không cần escape dấu * vì nó là wildcard
#         if not isinstance(value, str):
#             value = str(value)
#         # Chỉ escape dấu ngoặc kép
#         value = value.replace('"', '\\"')
#         return value
    
#     def process_modifier(self, field: str, modifier: str, value: Any, logsource: Dict = None) -> str:
#         """Xử lý modifiers từ Sigma (contains, endswith, startswith, re, all)"""
#         splunk_field = self.convert_field_name(field, logsource)
        
#         if modifier == 'contains':
#             if isinstance(value, list):
#                 conditions = []
#                 for v in value:
#                     v = self.escape_splunk_value(v)
#                     conditions.append(f'{splunk_field}="*{v}*"')
#                 return f"({' OR '.join(conditions)})"
#             else:
#                 value = self.escape_splunk_value(value)
#                 return f'{splunk_field}="*{value}*"'
        
#         elif modifier == 'endswith':
#             if isinstance(value, list):
#                 conditions = []
#                 for v in value:
#                     v = self.escape_splunk_value(v)
#                     conditions.append(f'{splunk_field}="*{v}"')
#                 return f"({' OR '.join(conditions)})"
#             else:
#                 value = self.escape_splunk_value(value)
#                 return f'{splunk_field}="*{value}"'
        
#         elif modifier == 'startswith':
#             if isinstance(value, list):
#                 conditions = []
#                 for v in value:
#                     v = self.escape_splunk_value(v)
#                     conditions.append(f'{splunk_field}="{v}*"')
#                 return f"({' OR '.join(conditions)})"
#             else:
#                 value = self.escape_splunk_value(value)
#                 return f'{splunk_field}="{value}*"'
        
#         elif modifier == 're':
#             # Regex pattern - use regex command in Splunk
#             if isinstance(value, list):
#                 conditions = []
#                 for v in value:
#                     conditions.append(f'({splunk_field} LIKE "{v}")')
#                 return f"({' OR '.join(conditions)})"
#             else:
#                 return f'{splunk_field} LIKE "{value}"'
        
#         elif modifier == 'all':
#             # All values must be present
#             if isinstance(value, list):
#                 conditions = []
#                 for v in value:
#                     v = self.escape_splunk_value(v)
#                     conditions.append(f'{splunk_field}="*{v}*"')
#                 return f"({' AND '.join(conditions)})"
#             else:
#                 value = self.escape_splunk_value(value)
#                 return f'{splunk_field}="*{value}*"'
        
#         else:
#             # No modifier - exact or list match
#             if isinstance(value, list):
#                 conditions = []
#                 for v in value:
#                     v = self.escape_splunk_value(v)
#                     conditions.append(f'{splunk_field}="{v}"')
#                 return f"({' OR '.join(conditions)})"
#             else:
#                 value = self.escape_splunk_value(value)
#                 return f'{splunk_field}="{value}"'
    
#     def process_selection(self, selection: Dict, logsource: Dict = None) -> str:
#         """Xử lý selection block từ Sigma rule"""
#         conditions = []
        
#         for field_with_modifier, value in selection.items():
#             # Parse field and modifiers
#             if '|' in field_with_modifier:
#                 parts = field_with_modifier.split('|')
#                 base_field = parts[0]
#                 modifiers = parts[1:]
                
#                 # Get the main modifier (contains, endswith, startswith, re, all)
#                 main_modifier = None
#                 for mod in modifiers:
#                     if mod in ['contains', 'endswith', 'startswith', 're', 'all']:
#                         main_modifier = mod
#                         break
                
#                 condition = self.process_modifier(base_field, main_modifier, value, logsource)
#                 conditions.append(condition)
#             else:
#                 # No modifier - direct field match
#                 splunk_field = self.convert_field_name(field_with_modifier, logsource)
#                 if isinstance(value, list):
#                     or_conditions = []
#                     for v in value:
#                         v = self.escape_splunk_value(v)
#                         or_conditions.append(f'{splunk_field}="{v}"')
#                     conditions.append(f"({' OR '.join(or_conditions)})")
#                 else:
#                     value = self.escape_splunk_value(value)
#                     conditions.append(f'{splunk_field}="{value}"')
        
#         return ' AND '.join(conditions) if conditions else ""
    
#     def parse_condition_logic(self, condition: str, detection_blocks: Dict, logsource: Dict = None) -> str:
#         """Parse condition logic từ Sigma rule"""
#         condition = condition.strip().lower()
        
#         # Handle "selection and not filter" pattern
#         if 'not' in condition and 'and' in condition:
#             # Extract selection and filter parts
#             parts = re.split(r'\s+and\s+not\s+', condition, flags=re.IGNORECASE)
#             if len(parts) == 2:
#                 selection_part = parts[0].strip()
#                 filter_part = parts[1].strip()
                
#                 selection_query = ""
#                 filter_query = ""
                
#                 # Process selection (may have OR logic)
#                 if 'or' in selection_part:
#                     sel_parts = re.split(r'\s+or\s+', selection_part, flags=re.IGNORECASE)
#                     sel_queries = []
#                     for part in sel_parts:
#                         part = part.strip()
#                         if part in detection_blocks:
#                             sel_queries.append(f"({self.process_selection(detection_blocks[part], logsource)})")
#                     selection_query = ' OR '.join(sel_queries)
#                 else:
#                     if selection_part in detection_blocks:
#                         selection_query = self.process_selection(detection_blocks[selection_part], logsource)
                
#                 # Process filter
#                 if filter_part in detection_blocks:
#                     filter_query = self.process_selection(detection_blocks[filter_part], logsource)
                
#                 if selection_query and filter_query:
#                     return f"({selection_query}) NOT ({filter_query})"
#                 elif selection_query:
#                     return selection_query
        
#         # Handle "all of selection*" or "1 of selection*"
#         if 'all of selection' in condition or '1 of selection' in condition:
#             selection_queries = []
#             for key, value in detection_blocks.items():
#                 if key.startswith('selection'):
#                     query = self.process_selection(value, logsource)
#                     if query:
#                         selection_queries.append(f"({query})")
            
#             if 'all of' in condition:
#                 return ' AND '.join(selection_queries)
#             else:  # 1 of or any
#                 return ' OR '.join(selection_queries)
        
#         # Simple AND logic
#         if 'and' in condition:
#             parts = re.split(r'\s+and\s+', condition, flags=re.IGNORECASE)
#             queries = []
#             for part in parts:
#                 part = part.strip()
#                 if part in detection_blocks:
#                     query = self.process_selection(detection_blocks[part], logsource)
#                     if query:
#                         queries.append(f"({query})")
#             return ' AND '.join(queries)
        
#         # Simple OR logic
#         if 'or' in condition:
#             parts = re.split(r'\s+or\s+', condition, flags=re.IGNORECASE)
#             queries = []
#             for part in parts:
#                 part = part.strip()
#                 if part in detection_blocks:
#                     query = self.process_selection(detection_blocks[part], logsource)
#                     if query:
#                         queries.append(f"({query})")
#             return ' OR '.join(queries)
        
#         # Single condition
#         if condition in detection_blocks:
#             return self.process_selection(detection_blocks[condition], logsource)
        
#         return ""
    
#     def convert_sigma_to_splunk(self, sigma_rule: Dict) -> Dict[str, Any]:
#         """Chuyển đổi một Sigma rule thành Splunk query"""
#         detection = sigma_rule.get('detection', {})
#         logsource = sigma_rule.get('logsource', {})
        
#         # Build base search with index and sourcetype
#         base_parts = ['index=*']
        
#         # Determine sourcetype based on log source
#         product = logsource.get('product', '').lower()
#         service = logsource.get('service', '').lower()
#         category = logsource.get('category', '').lower()
        
#         # ALWAYS use Security log sourcetype for Windows process creation
#         # This ensures we get normalized field names
#         if product == 'windows' and (category == 'process_creation' or service in ['sysmon', 'security']):
#             base_parts.append('sourcetype="WinEventLog:Security"')
#             # Add EventCode 4688 for process creation
#             if category == 'process_creation':
#                 base_parts.append('EventCode=4688')
#         elif product == 'windows':
#             if service == 'sysmon':
#                 base_parts.append('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"')
#             elif service == 'security':
#                 base_parts.append('sourcetype="WinEventLog:Security"')
#         else:
#             # Generic fallback
#             base_parts.append('sourcetype="WinEventLog:Security"')
        
#         # Extract condition and detection blocks
#         condition = detection.get('condition', '')
#         detection_blocks = {k: v for k, v in detection.items() if k != 'condition'}
        
#         # Handle selection as list (implicit OR)
#         if 'selection' in detection_blocks and isinstance(detection_blocks['selection'], list):
#             selection_queries = []
#             for sel in detection_blocks['selection']:
#                 query = self.process_selection(sel, logsource)
#                 if query:
#                     selection_queries.append(f"({query})")
#             detection_logic = ' OR '.join(selection_queries)
#         else:
#             # Parse complex condition logic
#             if condition:
#                 detection_logic = self.parse_condition_logic(condition, detection_blocks, logsource)
#             else:
#                 # No condition specified, use simple AND of all blocks
#                 queries = []
#                 for key, value in detection_blocks.items():
#                     if isinstance(value, dict):
#                         query = self.process_selection(value, logsource)
#                         if query:
#                             queries.append(f"({query})")
#                 detection_logic = ' AND '.join(queries)
        
#         # Build the search command
#         if detection_logic:
#             search_command = f"| search {detection_logic}"
#         else:
#             search_command = ""
        
#         # Build final query
#         base_query = ' '.join(base_parts)
#         splunk_query = f"{base_query}{' ' + search_command if search_command else ''}"
        
#         # Add table command for output
#         output_fields = self._get_output_fields(detection_blocks, logsource)
#         table_command = f"| table _time, ComputerName, {', '.join(output_fields)}"
        
#         full_query = f"{splunk_query} {table_command}"
        
#         return {
#             'rule_id': sigma_rule.get('id', ''),
#             'title': sigma_rule.get('title', ''),
#             'description': sigma_rule.get('description', ''),
#             'author': sigma_rule.get('author', ''),
#             'level': sigma_rule.get('level', 'medium'),
#             'tags': sigma_rule.get('tags', []),
#             'logsource': logsource,
#             'splunk_query': full_query,
#             'splunk_query_no_table': splunk_query,
#             'metadata': sigma_rule.get('metadata', {}),
#             'falsepositives': sigma_rule.get('falsepositives', [])
#         }
    
#     def _get_output_fields(self, detection_blocks: Dict, logsource: Dict) -> List[str]:
#         """Xác định các field cần hiển thị trong output"""
#         fields = set()
        
#         # Extract fields from detection blocks
#         for block in detection_blocks.values():
#             if isinstance(block, dict):
#                 for field_with_mod in block.keys():
#                     base_field = field_with_mod.split('|')[0]
#                     splunk_field = self.convert_field_name(base_field, logsource)
#                     fields.add(splunk_field)
#             elif isinstance(block, list):
#                 for item in block:
#                     if isinstance(item, dict):
#                         for field_with_mod in item.keys():
#                             base_field = field_with_mod.split('|')[0]
#                             splunk_field = self.convert_field_name(base_field, logsource)
#                             fields.add(splunk_field)
        
#         # Always add standard Windows Security Log fields for process creation
#         category = logsource.get('category', '').lower()
        
#         if category == 'process_creation' or any(
#             field in ['New_Process_Name', 'Process_Command_Line', 'Image', 'CommandLine'] 
#             for field in fields
#         ):
#             # Windows Security Log standard fields
#             default_fields = [
#                 'New_Process_Name',
#                 'Process_Command_Line', 
#                 'Parent_Process_Name',
#                 'Subject_User_Name',
#                 'Process_ID'
#             ]
#         else:
#             # Minimal default fields
#             default_fields = ['New_Process_Name', 'Process_Command_Line', 'Subject_User_Name']
        
#         # Add default fields that aren't already in detected fields
#         for field in default_fields:
#             fields.add(field)
        
#         # Remove EventCode as it's in the base query
#         fields.discard('EventCode')
        
#         # Sort fields for consistent output
#         return sorted(list(fields))
    
#     def generate_savedsearches_conf(self, converted_rules: List[Dict]) -> str:
#         """Tạo file savedsearches.conf cho Splunk"""
#         conf_lines = []
#         conf_lines.append("# Splunk Saved Searches - Generated from Sigma Rules")
#         conf_lines.append(f"# Generated: {datetime.now().isoformat()}")
#         conf_lines.append("")
        
#         for rule in converted_rules:
#             title = rule['title'].replace(' ', '_').replace('/', '_').replace('(', '').replace(')', '')
#             conf_lines.append(f"[{title}]")
#             conf_lines.append(f"search = {rule['splunk_query_no_table']}")
#             conf_lines.append(f"description = {rule['description']}")
#             conf_lines.append(f"disabled = 0")
#             conf_lines.append(f"enableSched = 1")
#             conf_lines.append(f"cron_schedule = */5 * * * *")
#             conf_lines.append(f"dispatch.earliest_time = -15m")
#             conf_lines.append(f"dispatch.latest_time = now")
            
#             # Alert configuration
#             severity = self.map_severity(rule['level'])
#             conf_lines.append(f"alert.severity = {severity}")
#             conf_lines.append(f"alert.track = 1")
#             conf_lines.append(f"action.email = 1")
#             conf_lines.append(f"action.email.to = security@example.com")
#             conf_lines.append(f"action.email.subject = [Splunk Alert] {rule['title']}")
            
#             conf_lines.append("")
        
#         return '\n'.join(conf_lines)
    
#     def map_severity(self, level: str) -> int:
#         """Map Sigma level to Splunk severity"""
#         mapping = {
#             'informational': 1,
#             'low': 2,
#             'medium': 3,
#             'high': 4,
#             'critical': 5
#         }
#         return mapping.get(level.lower(), 3)


# def load_sigma_rules(file_path: str) -> List[Dict]:
#     """Load Sigma rules từ file JSON"""
#     with open(file_path, 'r', encoding='utf-8') as f:
#         data = json.load(f)
    
#     rules = []
#     for result in data.get('results', []):
#         if result.get('status') == 'success' and 'sigma_rule' in result:
#             rule = result['sigma_rule']
#             # Add metadata from result
#             if 'metadata' not in rule:
#                 rule['metadata'] = {}
#             rule['metadata']['ttp_id'] = result.get('ttp_id', '')
#             rule['metadata']['attack_id'] = result.get('attack_id', '')
#             rule['metadata']['technique_name'] = result.get('technique_name', '')
#             rule['metadata']['tactic'] = result.get('tactic', '')
#             rules.append(rule)
    
#     return rules


# def save_splunk_queries(queries: List[Dict], output_dir: Path):
#     """Lưu Splunk queries vào các file"""
#     output_dir.mkdir(parents=True, exist_ok=True)
    
#     # Save as JSON
#     json_file = output_dir / "splunk_queries.json"
#     with open(json_file, 'w', encoding='utf-8') as f:
#         json.dump(queries, f, indent=2, ensure_ascii=False)
#     print(f"✓ Đã lưu {len(queries)} queries vào {json_file}")
    
#     # Save as readable text
#     txt_file = output_dir / "splunk_queries.txt"
#     with open(txt_file, 'w', encoding='utf-8') as f:
#         f.write("="*100 + "\n")
#         f.write("SPLUNK QUERIES GENERATED FROM SIGMA RULES\n")
#         f.write(f"Generated: {datetime.now().isoformat()}\n")
#         f.write("="*100 + "\n\n")
        
#         for i, query in enumerate(queries, 1):
#             f.write(f"\n{'='*100}\n")
#             f.write(f"Query {i}: {query['title']}\n")
#             f.write(f"{'='*100}\n")
#             f.write(f"Rule ID: {query['rule_id']}\n")
#             f.write(f"MITRE ATT&CK: {query['metadata'].get('attack_id', 'N/A')} - {query['metadata'].get('technique_name', 'N/A')}\n")
#             f.write(f"Tactic: {query['metadata'].get('tactic', 'N/A')}\n")
#             f.write(f"Level: {query['level'].upper()}\n")
#             f.write(f"Tags: {', '.join(query['tags'])}\n")
#             f.write(f"\nDescription:\n{query['description']}\n")
            
#             if query.get('falsepositives'):
#                 f.write(f"\nFalse Positives:\n")
#                 for fp in query['falsepositives']:
#                     f.write(f"  - {fp}\n")
            
#             f.write(f"\n{'─'*100}\n")
#             f.write(f"Splunk Query:\n")
#             f.write(f"{'─'*100}\n")
#             f.write(f"{query['splunk_query']}\n")
#             f.write("\n")
    
#     print(f"✓ Đã lưu queries dạng text vào {txt_file}")
    
#     # Generate savedsearches.conf
#     converter = SigmaToSplunkConverter()
#     conf_content = converter.generate_savedsearches_conf(queries)
#     conf_file = output_dir / "savedsearches.conf"
#     with open(conf_file, 'w', encoding='utf-8') as f:
#         f.write(conf_content)
#     print(f"✓ Đã tạo Splunk savedsearches.conf: {conf_file}")
    
#     # Create test queries file (simplified queries for manual testing)
#     test_file = output_dir / "test_queries.txt"
#     with open(test_file, 'w', encoding='utf-8') as f:
#         f.write("# SIMPLIFIED TEST QUERIES\n")
#         f.write("# Copy and paste these into Splunk Search Bar\n")
#         f.write("# " + "="*90 + "\n\n")
        
#         for i, query in enumerate(queries, 1):
#             f.write(f"# Test {i}: {query['title']}\n")
#             f.write(f"# {query['metadata'].get('attack_id', '')} - {query['metadata'].get('technique_name', '')}\n")
#             f.write(f"{query['splunk_query']}\n\n")
    
#     print(f"✓ Đã tạo test queries: {test_file}")


# def print_summary(queries: List[Dict]):
#     """In tóm tắt về các queries"""
#     print("\n" + "="*80)
#     print("CONVERSION SUMMARY")
#     print("="*80)
    
#     print(f"\nTổng số Splunk queries: {len(queries)}")
    
#     # Thống kê theo level
#     levels = {}
#     for query in queries:
#         level = query['level']
#         levels[level] = levels.get(level, 0) + 1
    
#     print("\nTheo Severity Level:")
#     for level in ['low', 'medium', 'high', 'critical']:
#         count = levels.get(level, 0)
#         if count > 0:
#             print(f"  - {level.upper()}: {count} queries")
    
#     # Thống kê theo tactic
#     tactics = {}
#     for query in queries:
#         tactic = query['metadata'].get('tactic', 'Unknown')
#         tactics[tactic] = tactics.get(tactic, 0) + 1
    
#     print("\nTheo MITRE Tactic:")
#     for tactic, count in sorted(tactics.items()):
#         print(f"  - {tactic}: {count} queries")
    
#     # Thống kê theo MITRE technique
#     techniques = {}
#     for query in queries:
#         attack_id = query['metadata'].get('attack_id', 'UNKNOWN')
#         tech_name = query['metadata'].get('technique_name', 'Unknown')
#         tech_key = f"{attack_id} - {tech_name}"
#         techniques[tech_key] = techniques.get(tech_key, 0) + 1
    
#     print("\nTheo MITRE Technique:")
#     for tech, count in sorted(techniques.items()):
#         print(f"  - {tech}: {count} queries")


# def main():
#     # Đường dẫn file input
#     script_dir = Path(__file__).parent
#     project_root = script_dir.parent.parent
#     input_file = project_root / "data" / "generated_rules" / "rulegen_llm_test_output.json"
    
#     # Kiểm tra file tồn tại
#     if not input_file.exists():
#         print(f"❌ Không tìm thấy file: {input_file}")
#         print(f"   Script đang chạy từ: {script_dir}")
#         print(f"   Project root: {project_root}")
#         return
    
#     # Load Sigma rules
#     print(f"Đang đọc Sigma rules từ {input_file}...")
#     sigma_rules = load_sigma_rules(str(input_file))
#     print(f"✓ Đã load {len(sigma_rules)} Sigma rules")
    
#     # Convert to Splunk
#     print("\nĐang chuyển đổi sang Splunk queries...")
#     converter = SigmaToSplunkConverter()
#     splunk_queries = []
    
#     for i, rule in enumerate(sigma_rules, 1):
#         try:
#             converted = converter.convert_sigma_to_splunk(rule)
#             splunk_queries.append(converted)
#             print(f"  ✓ [{i}/{len(sigma_rules)}] {rule.get('title', 'Unknown')}")
#         except Exception as e:
#             print(f"  ✗ [{i}/{len(sigma_rules)}] Error: {e}")
#             import traceback
#             traceback.print_exc()
    
#     # Print summary
#     print_summary(splunk_queries)
    
#     # Save outputs
#     output_dir = script_dir / "splunk_queries"
#     print(f"\nĐang lưu outputs vào {output_dir}...")
#     save_splunk_queries(splunk_queries, output_dir)
    
#     print("\n" + "="*80)
#     print("✅ HOÀN THÀNH!")
#     print("="*80)
#     print(f"\nCác file đã được tạo trong thư mục '{output_dir.name}':")
#     print("  📄 splunk_queries.json       - Full queries với metadata")
#     print("  📄 splunk_queries.txt        - Queries với format dễ đọc")
#     print("  📄 test_queries.txt          - Queries đơn giản để test")
#     print("  ⚙️  savedsearches.conf       - Splunk saved searches config")
    
#     print("\n📝 HƯỚNG DẪN SỬ DỤNG:")
#     print("="*80)
#     print("1. Copy queries từ 'test_queries.txt' và paste vào Splunk Search")
#     print("2. Chạy attack commands từ extracted_commands/test_scripts/")
#     print("3. Kiểm tra detection trong Splunk")
#     print("4. Hoặc import 'savedsearches.conf' vào Splunk app để tạo alerts")
#     print("\n⚠️  LƯU Ý: Điều chỉnh 'index=' và 'sourcetype=' phù hợp với môi trường của bạn")


# if __name__ == "__main__":
#     main()



#!/usr/bin/env python3
"""
Script để chuyển đổi Sigma rules thành Splunk queries - VERSION FIXED
Sửa lỗi: EventCode trong search clause
"""

import json
import re
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime


class SigmaToSplunkConverter:
    """Converter chuyển đổi Sigma rules sang Splunk queries"""
    
    def __init__(self):
        self.traditional_mapping = {
            'EventID': 'EventCode',
            'Image': 'Image',
            'CommandLine': 'CommandLine',
            'ParentImage': 'ParentImage',
            'ParentCommandLine': 'ParentCommandLine',
            'User': 'User',
            'ProcessId': 'ProcessId',
            'ParentProcessId': 'ParentProcessId',
            'CurrentDirectory': 'Current_Directory',
            'IntegrityLevel': 'Process_Integrity_Level',
            'TargetFilename': 'TargetFilename',
            'DestinationIp': 'DestinationIp',
            'DestinationPort': 'DestinationPort',
            'SourceIp': 'SourceIp',
            'TargetObject': 'TargetObject',
            'NewProcessName': 'New_Process_Name',
            'Creator_Process_Name': 'Creator_Process_Name',
            'SubjectUserName': 'Subject_User_Name',
            'SubjectDomainName': 'Subject_Domain_Name',
            'SubjectLogonId': 'Subject_Logon_Id',
            'NewProcessId': 'New_Process_Id',
            'TokenElevationType': 'Token_Elevation_Type',
            'OriginalFileName': 'Original_File_Name',
        }
        
        self.ecs_mapping = {
            'process.executable': 'New_Process_Name',
            'process.command_line': 'Process_Command_Line',
            'process.name': 'New_Process_Name',
            'process.current_directory': 'Current_Directory',
            'process.integrity_level': 'Process_Integrity_Level',
            'process.creation_time': 'Process_Creation_Time',
            'process.id': 'Process_ID',
            'process.pid': 'Process_ID',
            'process.parent.executable': 'Parent_Process_Name',
            'process.parent.command_line': 'Parent_Process_Command_Line',
            'process.parent.name': 'Parent_Process_Name',
            'process.parent.id': 'Parent_Process_ID',
            'process.parent.pid': 'Parent_Process_ID',
            'process.parent.creation_time': 'Parent_Process_Creation_Time',
            'process.parent.integrity_level': 'Parent_Process_Integrity_Level',
            'process.parent.current_directory': 'Parent_Current_Directory',
            'user.name': 'Subject_User_Name',
            'user.domain': 'Subject_Domain_Name',
            'user.id': 'Subject_Logon_Id',
            'file.path': 'TargetFilename',
            'file.name': 'TargetFilename',
            'file.directory': 'Current_Directory',
            'destination.ip': 'DestinationIp',
            'destination.port': 'DestinationPort',
            'source.ip': 'SourceIp',
            'source.port': 'SourcePort',
            'network.protocol': 'Protocol',
            'registry.path': 'TargetObject',
            'registry.key': 'TargetObject',
            'registry.value': 'Details',
            'event.code': 'EventCode',
            'event.id': 'EventCode',
        }
        
        self.field_mapping = {**self.traditional_mapping, **self.ecs_mapping}
    
    def convert_field_name(self, field: str, logsource: Dict = None) -> str:
        """Chuyển đổi tên field từ Sigma sang Splunk với context awareness"""
        
        if '.' in field:
            splunk_field = self.ecs_mapping.get(field)
            if splunk_field:
                return splunk_field
            return field
        
        if field in ['Image', 'NewProcessName']:
            return 'New_Process_Name'
        elif field in ['CommandLine', 'ProcessCommandLine']:
            return 'Process_Command_Line'
        elif field in ['ParentImage', 'ParentProcessName', 'Creator_Process_Name']:
            return 'Parent_Process_Name'
        elif field in ['ParentCommandLine', 'ParentProcessCommandLine']:
            return 'Parent_Process_Command_Line'
        elif field in ['User', 'SubjectUserName']:
            return 'Subject_User_Name'
        elif field in ['ProcessId', 'NewProcessId']:
            return 'Process_ID'
        elif field in ['ParentProcessId']:
            return 'Parent_Process_ID'
        elif field in ['CurrentDirectory']:
            return 'Current_Directory'
        elif field in ['IntegrityLevel']:
            return 'Process_Integrity_Level'
        elif field in ['OriginalFileName']:
            return 'Original_File_Name'
        elif field in ['SubjectDomainName']:
            return 'Subject_Domain_Name'
        elif field in ['SubjectLogonId']:
            return 'Subject_Logon_Id'
        elif field in ['TokenElevationType']:
            return 'Token_Elevation_Type'
        
        return self.traditional_mapping.get(field, field)
    
    def escape_splunk_value(self, value: str) -> str:
        """Escape special characters trong giá trị Splunk"""
        if not isinstance(value, str):
            value = str(value)
        value = value.replace('"', '\\"')
        return value
    
    def process_modifier(self, field: str, modifier: str, value: Any, logsource: Dict = None) -> str:
        """Xử lý modifiers từ Sigma (contains, endswith, startswith, re, all)"""
        splunk_field = self.convert_field_name(field, logsource)
        
        if modifier == 'contains':
            if isinstance(value, list):
                conditions = []
                for v in value:
                    v = self.escape_splunk_value(v)
                    conditions.append(f'{splunk_field}="*{v}*"')
                return f"({' OR '.join(conditions)})"
            else:
                value = self.escape_splunk_value(value)
                return f'{splunk_field}="*{value}*"'
        
        elif modifier == 'endswith':
            if isinstance(value, list):
                conditions = []
                for v in value:
                    v = self.escape_splunk_value(v)
                    conditions.append(f'{splunk_field}="*{v}"')
                return f"({' OR '.join(conditions)})"
            else:
                value = self.escape_splunk_value(value)
                return f'{splunk_field}="*{value}"'
        
        elif modifier == 'startswith':
            if isinstance(value, list):
                conditions = []
                for v in value:
                    v = self.escape_splunk_value(v)
                    conditions.append(f'{splunk_field}="{v}*"')
                return f"({' OR '.join(conditions)})"
            else:
                value = self.escape_splunk_value(value)
                return f'{splunk_field}="{value}*"'
        
        elif modifier == 're':
            if isinstance(value, list):
                conditions = []
                for v in value:
                    conditions.append(f'({splunk_field} LIKE "{v}")')
                return f"({' OR '.join(conditions)})"
            else:
                return f'{splunk_field} LIKE "{value}"'
        
        elif modifier == 'all':
            if isinstance(value, list):
                conditions = []
                for v in value:
                    v = self.escape_splunk_value(v)
                    conditions.append(f'{splunk_field}="*{v}*"')
                return f"({' AND '.join(conditions)})"
            else:
                value = self.escape_splunk_value(value)
                return f'{splunk_field}="*{value}*"'
        
        else:
            if isinstance(value, list):
                conditions = []
                for v in value:
                    v = self.escape_splunk_value(v)
                    conditions.append(f'{splunk_field}="{v}"')
                return f"({' OR '.join(conditions)})"
            else:
                value = self.escape_splunk_value(value)
                return f'{splunk_field}="{value}"'
    
    def process_selection(self, selection: Dict, logsource: Dict = None) -> str:
        """Xử lý selection block từ Sigma rule - KHÔNGINCLUDE EventCode"""
        conditions = []
        
        for field_with_modifier, value in selection.items():
            # Skip EventCode/EventID vì nó sẽ được xử lý riêng trong base query
            if field_with_modifier.lower() in ['eventcode', 'eventid', 'event.code', 'event.id']:
                continue
            
            if '|' in field_with_modifier:
                parts = field_with_modifier.split('|')
                base_field = parts[0]
                modifiers = parts[1:]
                
                main_modifier = None
                for mod in modifiers:
                    if mod in ['contains', 'endswith', 'startswith', 're', 'all']:
                        main_modifier = mod
                        break
                
                condition = self.process_modifier(base_field, main_modifier, value, logsource)
                conditions.append(condition)
            else:
                splunk_field = self.convert_field_name(field_with_modifier, logsource)
                if isinstance(value, list):
                    or_conditions = []
                    for v in value:
                        v = self.escape_splunk_value(v)
                        or_conditions.append(f'{splunk_field}="{v}"')
                    conditions.append(f"({' OR '.join(or_conditions)})")
                else:
                    value = self.escape_splunk_value(value)
                    conditions.append(f'{splunk_field}="{value}"')
        
        return ' AND '.join(conditions) if conditions else ""
    

    def parse_condition_logic(self, condition: str, detection_blocks: Dict, logsource: Dict = None) -> str:
        """Parse condition logic từ Sigma rule"""
        condition = condition.strip().lower()
        
        if 'not' in condition and 'and' in condition:
            parts = re.split(r'\s+and\s+not\s+', condition, flags=re.IGNORECASE)
            if len(parts) == 2:
                selection_part = parts[0].strip()
                filter_part = parts[1].strip()
                
                selection_query = ""
                filter_query = ""
                
                if 'or' in selection_part:
                    sel_parts = re.split(r'\s+or\s+', selection_part, flags=re.IGNORECASE)
                    sel_queries = []
                    for part in sel_parts:
                        part = part.strip()
                        if part in detection_blocks:
                            sel_queries.append(f"({self.process_selection(detection_blocks[part], logsource)})")
                    selection_query = ' OR '.join(sel_queries)
                else:
                    if selection_part in detection_blocks:
                        selection_query = self.process_selection(detection_blocks[selection_part], logsource)
                
                if filter_part in detection_blocks:
                    filter_query = self.process_selection(detection_blocks[filter_part], logsource)
                
                if selection_query and filter_query:
                    return f"({selection_query}) NOT ({filter_query})"
                elif selection_query:
                    return selection_query
        
        if 'all of selection' in condition or '1 of selection' in condition:
            selection_queries = []
            for key, value in detection_blocks.items():
                if key.startswith('selection'):
                    query = self.process_selection(value, logsource)
                    if query:
                        selection_queries.append(f"({query})")
            
            if 'all of' in condition:
                return ' AND '.join(selection_queries)
            else:
                return ' OR '.join(selection_queries)
        
        if 'and' in condition:
            parts = re.split(r'\s+and\s+', condition, flags=re.IGNORECASE)
            queries = []
            for part in parts:
                part = part.strip()
                if part in detection_blocks:
                    query = self.process_selection(detection_blocks[part], logsource)
                    if query:
                        queries.append(f"({query})")
            return ' AND '.join(queries)
        
        if 'or' in condition:
            parts = re.split(r'\s+or\s+', condition, flags=re.IGNORECASE)
            queries = []
            for part in parts:
                part = part.strip()
                if part in detection_blocks:
                    query = self.process_selection(detection_blocks[part], logsource)
                    if query:
                        queries.append(f"({query})")
            return ' OR '.join(queries)
        
        if condition in detection_blocks:
            return self.process_selection(detection_blocks[condition], logsource)
        
        return ""
    
    def convert_sigma_to_splunk(self, sigma_rule: Dict) -> Dict[str, Any]:
        """Chuyển đổi một Sigma rule thành Splunk query"""
        detection = sigma_rule.get('detection', {})
        logsource = sigma_rule.get('logsource', {})
        
        # Build base search với index và sourcetype
        base_parts = ['index=*']
        
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        category = logsource.get('category', '').lower()
        
        # Xác định sourcetype
        if product == 'windows' and (category == 'process_creation' or service in ['sysmon', 'security']):
            base_parts.append('sourcetype="WinEventLog:Security"')
        elif product == 'windows':
            if service == 'sysmon':
                base_parts.append('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"')
            elif service == 'security':
                base_parts.append('sourcetype="WinEventLog:Security"')
        else:
            base_parts.append('sourcetype="WinEventLog:Security"')
        
        # Trích xuất detection blocks (không lấy EventCode vào base query)
        detection_blocks = {k: v for k, v in detection.items() if k != 'condition'}
        
        # Extract condition
        condition = detection.get('condition', '')
        
        # Parse detection logic (không bao gồm EventCode)
        if 'selection' in detection_blocks and isinstance(detection_blocks['selection'], list):
            selection_queries = []
            for sel in detection_blocks['selection']:
                query = self.process_selection(sel, logsource)
                if query:
                    selection_queries.append(f"({query})")
            detection_logic = ' OR '.join(selection_queries)
        else:
            if condition:
                detection_logic = self.parse_condition_logic(condition, detection_blocks, logsource)
            else:
                queries = []
                for key, value in detection_blocks.items():
                    if isinstance(value, dict):
                        query = self.process_selection(value, logsource)
                        if query:
                            queries.append(f"({query})")
                detection_logic = ' AND '.join(queries)
        
        # Build search command - CHỈ bao gồm detection_logic, KHÔNG bao gồm EventCode
        base_query = ' '.join(base_parts)
        
        if detection_logic:
            search_command = f"| search {detection_logic}"
        else:
            search_command = ""
        
        splunk_query = f"{base_query}{' ' + search_command if search_command else ''}"
        
        # Add table command
        output_fields = self._get_output_fields(detection_blocks, logsource)
        table_command = f"| table _time, ComputerName, {', '.join(output_fields)}"
        
        full_query = f"{splunk_query} {table_command}"
        
        return {
            'rule_id': sigma_rule.get('id', ''),
            'title': sigma_rule.get('title', ''),
            'description': sigma_rule.get('description', ''),
            'author': sigma_rule.get('author', ''),
            'level': sigma_rule.get('level', 'medium'),
            'tags': sigma_rule.get('tags', []),
            'logsource': logsource,
            'splunk_query': full_query,
            'splunk_query_no_table': splunk_query,
            'metadata': sigma_rule.get('metadata', {}),
            'falsepositives': sigma_rule.get('falsepositives', [])
        }
    
    def _get_output_fields(self, detection_blocks: Dict, logsource: Dict) -> List[str]:
        """Xác định các field cần hiển thị trong output"""
        fields = set()
        
        for block in detection_blocks.values():
            if isinstance(block, dict):
                for field_with_mod in block.keys():
                    # Skip EventCode
                    if field_with_mod.lower() in ['eventcode', 'eventid', 'event.code', 'event.id']:
                        continue
                    base_field = field_with_mod.split('|')[0]
                    splunk_field = self.convert_field_name(base_field, logsource)
                    fields.add(splunk_field)
            elif isinstance(block, list):
                for item in block:
                    if isinstance(item, dict):
                        for field_with_mod in item.keys():
                            if field_with_mod.lower() in ['eventcode', 'eventid', 'event.code', 'event.id']:
                                continue
                            base_field = field_with_mod.split('|')[0]
                            splunk_field = self.convert_field_name(base_field, logsource)
                            fields.add(splunk_field)
        
        category = logsource.get('category', '').lower()
        
        if category == 'process_creation' or any(
            field in ['New_Process_Name', 'Process_Command_Line', 'Image', 'CommandLine'] 
            for field in fields
        ):
            default_fields = [
                'New_Process_Name',
                'Process_Command_Line', 
                'Parent_Process_Name',
                'Subject_User_Name',
                'Process_ID'
            ]
        else:
            default_fields = ['New_Process_Name', 'Process_Command_Line', 'Subject_User_Name']
        
        for field in default_fields:
            fields.add(field)
        
        fields.discard('EventCode')
        
        return sorted(list(fields))
    
    def generate_savedsearches_conf(self, converted_rules: List[Dict]) -> str:
        """Tạo file savedsearches.conf cho Splunk"""
        conf_lines = []
        conf_lines.append("# Splunk Saved Searches - Generated from Sigma Rules")
        conf_lines.append(f"# Generated: {datetime.now().isoformat()}")
        conf_lines.append("")
        
        for rule in converted_rules:
            title = rule['title'].replace(' ', '_').replace('/', '_').replace('(', '').replace(')', '')
            conf_lines.append(f"[{title}]")
            conf_lines.append(f"search = {rule['splunk_query_no_table']}")
            conf_lines.append(f"description = {rule['description']}")
            conf_lines.append(f"disabled = 0")
            conf_lines.append(f"enableSched = 1")
            conf_lines.append(f"cron_schedule = */5 * * * *")
            conf_lines.append(f"dispatch.earliest_time = -15m")
            conf_lines.append(f"dispatch.latest_time = now")
            
            severity = self.map_severity(rule['level'])
            conf_lines.append(f"alert.severity = {severity}")
            conf_lines.append(f"alert.track = 1")
            conf_lines.append(f"action.email = 1")
            conf_lines.append(f"action.email.to = security@example.com")
            conf_lines.append(f"action.email.subject = [Splunk Alert] {rule['title']}")
            
            conf_lines.append("")
        
        return '\n'.join(conf_lines)
    
    def map_severity(self, level: str) -> int:
        """Map Sigma level to Splunk severity"""
        mapping = {
            'informational': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'critical': 5
        }
        return mapping.get(level.lower(), 3)


def load_sigma_rules(file_path: str) -> List[Dict]:
    """Load Sigma rules từ file JSON"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    rules = []
    for result in data.get('results', []):
        if result.get('status') == 'success' and 'sigma_rule' in result:
            rule = result['sigma_rule']
            if 'metadata' not in rule:
                rule['metadata'] = {}
            rule['metadata']['ttp_id'] = result.get('ttp_id', '')
            rule['metadata']['attack_id'] = result.get('attack_id', '')
            rule['metadata']['technique_name'] = result.get('technique_name', '')
            rule['metadata']['tactic'] = result.get('tactic', '')
            rules.append(rule)
    
    return rules


def save_splunk_queries(queries: List[Dict], output_dir: Path):
    """Lưu Splunk queries vào các file"""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    json_file = output_dir / "splunk_queries.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(queries, f, indent=2, ensure_ascii=False)
    print(f"✓ Đã lưu {len(queries)} queries vào {json_file}")
    
    txt_file = output_dir / "splunk_queries.txt"
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write("="*100 + "\n")
        f.write("SPLUNK QUERIES GENERATED FROM SIGMA RULES\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("="*100 + "\n\n")
        
        for i, query in enumerate(queries, 1):
            f.write(f"\n{'='*100}\n")
            f.write(f"Query {i}: {query['title']}\n")
            f.write(f"{'='*100}\n")
            f.write(f"Rule ID: {query['rule_id']}\n")
            f.write(f"MITRE ATT&CK: {query['metadata'].get('attack_id', 'N/A')} - {query['metadata'].get('technique_name', 'N/A')}\n")
            f.write(f"Tactic: {query['metadata'].get('tactic', 'N/A')}\n")
            f.write(f"Level: {query['level'].upper()}\n")
            f.write(f"Tags: {', '.join(query['tags'])}\n")
            f.write(f"\nDescription:\n{query['description']}\n")
            
            if query.get('falsepositives'):
                f.write(f"\nFalse Positives:\n")
                for fp in query['falsepositives']:
                    f.write(f"  - {fp}\n")
            
            f.write(f"\n{'─'*100}\n")
            f.write(f"Splunk Query:\n")
            f.write(f"{'─'*100}\n")
            f.write(f"{query['splunk_query']}\n")
            f.write("\n")
    
    print(f"✓ Đã lưu queries dạng text vào {txt_file}")
    
    converter = SigmaToSplunkConverter()
    conf_content = converter.generate_savedsearches_conf(queries)
    conf_file = output_dir / "savedsearches.conf"
    with open(conf_file, 'w', encoding='utf-8') as f:
        f.write(conf_content)
    print(f"✓ Đã tạo Splunk savedsearches.conf: {conf_file}")
    
    test_file = output_dir / "test_queries.txt"
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write("# SIMPLIFIED TEST QUERIES\n")
        f.write("# Copy and paste these into Splunk Search Bar\n")
        f.write("# " + "="*90 + "\n\n")
        
        for i, query in enumerate(queries, 1):
            f.write(f"# Test {i}: {query['title']}\n")
            f.write(f"# {query['metadata'].get('attack_id', '')} - {query['metadata'].get('technique_name', '')}\n")
            f.write(f"{query['splunk_query']}\n\n")
    
    print(f"✓ Đã tạo test queries: {test_file}")


def print_summary(queries: List[Dict]):
    """In tóm tắt về các queries"""
    print("\n" + "="*80)
    print("CONVERSION SUMMARY")
    print("="*80)
    
    print(f"\nTổng số Splunk queries: {len(queries)}")
    
    levels = {}
    for query in queries:
        level = query['level']
        levels[level] = levels.get(level, 0) + 1
    
    print("\nTheo Severity Level:")
    for level in ['low', 'medium', 'high', 'critical']:
        count = levels.get(level, 0)
        if count > 0:
            print(f"  - {level.upper()}: {count} queries")
    
    tactics = {}
    for query in queries:
        tactic = query['metadata'].get('tactic', 'Unknown')
        tactics[tactic] = tactics.get(tactic, 0) + 1
    
    print("\nTheo MITRE Tactic:")
    for tactic, count in sorted(tactics.items()):
        print(f"  - {tactic}: {count} queries")
    
    techniques = {}
    for query in queries:
        attack_id = query['metadata'].get('attack_id', 'UNKNOWN')
        tech_name = query['metadata'].get('technique_name', 'Unknown')
        tech_key = f"{attack_id} - {tech_name}"
        techniques[tech_key] = techniques.get(tech_key, 0) + 1
    
    print("\nTheo MITRE Technique:")
    for tech, count in sorted(techniques.items()):
        print(f"  - {tech}: {count} queries")


def main():
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent
    input_file = project_root / "data" / "generated_rules" / "rulegen_llm_test_output.json"
    
    if not input_file.exists():
        print(f"❌ Không tìm thấy file: {input_file}")
        print(f"   Script đang chạy từ: {script_dir}")
        print(f"   Project root: {project_root}")
        return
    
    print(f"Đang đọc Sigma rules từ {input_file}...")
    sigma_rules = load_sigma_rules(str(input_file))
    print(f"✓ Đã load {len(sigma_rules)} Sigma rules")
    
    print("\nĐang chuyển đổi sang Splunk queries...")
    converter = SigmaToSplunkConverter()
    splunk_queries = []
    
    for i, rule in enumerate(sigma_rules, 1):
        try:
            converted = converter.convert_sigma_to_splunk(rule)
            splunk_queries.append(converted)
            print(f"  ✓ [{i}/{len(sigma_rules)}] {rule.get('title', 'Unknown')}")
        except Exception as e:
            print(f"  ✗ [{i}/{len(sigma_rules)}] Error: {e}")
            import traceback
            traceback.print_exc()
    
    print_summary(splunk_queries)
    
    output_dir = project_root / "data" / "siem" / "splunk_queries"
    print(f"\nĐang lưu outputs vào {output_dir}...")
    save_splunk_queries(splunk_queries, output_dir)
    
    print("\n" + "="*80)
    print("✅ HOÀN THÀNH!")
    print("="*80)
    print(f"\nCác file đã được tạo trong thư mục '{output_dir.name}':")
    print("  📄 splunk_queries.json       - Full queries với metadata")
    print("  📄 splunk_queries.txt        - Queries với format dễ đọc")
    print("  📄 test_queries.txt          - Queries đơn giản để test")
    print("  ⚙️  savedsearches.conf       - Splunk saved searches config")
    
    print("\n📝 HƯỚNG DẪN SỬ DỤNG:")
    print("="*80)
    print("1. Copy queries từ 'test_queries.txt' và paste vào Splunk Search")
    print("2. Chạy attack commands từ extracted_commands/test_scripts/")
    print("3. Kiểm tra detection trong Splunk")
    print("4. Hoặc import 'savedsearches.conf' vào Splunk app để tạo alerts")
    print("\n⚠️  LƯU Ý: Điều chỉnh 'index=' và 'sourcetype=' phù hợp với môi trường của bạn")
    print("\n🔧 LƯU Ý VỀ CÁC SỬA CHỮA:")
    print("="*80)
    print("✓ EventCode HOÀN TOÀN bỏ qua khỏi query")
    print("✓ Query chỉ chứa các field thực tế cần search")
    print("✓ Cấu trúc query đơn giản và không phụ thuộc vào EventCode")
    print("✓ Tránh lỗi khi EventCode sai hoặc không khớp")
    print("✓ Query sẽ match trên toàn bộ events có patterns phù hợp")


if __name__ == "__main__":
    main()