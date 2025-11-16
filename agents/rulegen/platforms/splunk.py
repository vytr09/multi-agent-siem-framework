# agents/rulegen/platforms/splunk.py

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class SplunkConverter:
    """
    Converts Sigma rules to Splunk SPL (Search Processing Language)
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.syntax_type = "SPL"
        
        # Field mappings from Sigma to Splunk CIM
        self.field_mappings = {
            # Process events
            'CommandLine': 'process',
            'Image': 'process_name',
            'ParentImage': 'parent_process_name',
            'ParentCommandLine': 'parent_process',
            'User': 'user',
            'ProcessId': 'process_id',
            'ParentProcessId': 'parent_process_id',
            
            # File events
            'TargetFilename': 'file_path',
            'FileName': 'file_name',
            
            # Network events
            'DestinationIp': 'dest_ip',
            'DestinationPort': 'dest_port',
            'DestinationHostname': 'dest_host',
            'SourceIp': 'src_ip',
            'SourcePort': 'src_port',
            
            # Registry events
            'TargetObject': 'registry_path',
            'Details': 'registry_value_data',
            'EventType': 'registry_type',
        }
        
        # Log source to Splunk index mapping
        self.logsource_mappings = {
            'process_creation': {
                'index': 'windows',
                'sourcetype': 'WinEventLog:Security',
                'eventcode': '4688'
            },
            'network_connection': {
                'index': 'windows',
                'sourcetype': 'WinEventLog:Security',
                'eventcode': '5156'
            },
            'file_event': {
                'index': 'windows',
                'sourcetype': 'WinEventLog:Security',
                'eventcode': '4663'
            },
            'registry_event': {
                'index': 'windows',
                'sourcetype': 'WinEventLog:Security',
                'eventcode': '4657'
            }
        }
    
    async def initialize(self) -> None:
        """Initialize the converter"""
        logger.info("Splunk Converter initialized")
        
    # ADD THIS METHOD HERE
    def get_syntax_name(self) -> str:
        """Get the syntax name for this converter"""
        return self.syntax_type
    
    async def convert(self, sigma_rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Sigma rule to Splunk SPL
        
        Args:
            sigma_rule: Sigma rule dictionary
            
        Returns:
            Dictionary containing SPL query and metadata
        """
        logger.info(f"Converting Sigma rule to Splunk SPL: {sigma_rule.get('title', 'Unknown')}")
        
        try:
            logsource = sigma_rule.get('logsource', {})
            detection = sigma_rule.get('detection', {})
            
            # Build SPL query
            spl_query = self._build_spl_query(logsource, detection)
            
            # Build alert configuration
            alert_config = self._build_alert_config(sigma_rule)
            
            result = {
                'query': spl_query,
                'alert_config': alert_config,
                'metadata': {
                    'rule_name': sigma_rule.get('title'),
                    'rule_id': sigma_rule.get('id'),
                    'severity': sigma_rule.get('level', 'medium'),
                    'description': sigma_rule.get('description'),
                    'references': sigma_rule.get('references', []),
                    'tags': sigma_rule.get('tags', [])
                }
            }
            
            logger.info("Successfully converted to Splunk SPL")
            return result
            
        except Exception as e:
            logger.error(f"Error converting to Splunk SPL: {str(e)}")
            raise
    
    def _build_spl_query(self, logsource: Dict[str, Any], detection: Dict[str, Any]) -> str:
        """Build SPL query from Sigma rule"""
        query_parts = []
        
        # Add index and sourcetype
        category = logsource.get('category', 'process_creation')
        mapping = self.logsource_mappings.get(category, self.logsource_mappings['process_creation'])
        
        if mapping.get('index'):
            query_parts.append(f'index={mapping["index"]}')
        
        if mapping.get('sourcetype'):
            query_parts.append(f'sourcetype="{mapping["sourcetype"]}"')
        
        if mapping.get('eventcode'):
            query_parts.append(f'EventCode={mapping["eventcode"]}')
        
        # Build detection logic
        if detection:
            detection_spl = self._build_detection_spl(detection)
            if detection_spl:
                query_parts.append(detection_spl)
        
        # Combine base query
        base_query = ' '.join(query_parts)
        
        # Add table command for output
        spl_query = f"{base_query}\n| table _time, host, user, process_name, CommandLine, dest_ip, dest_port"
        
        return spl_query
    
    def _build_detection_spl(self, detection: Dict[str, Any]) -> str:
        """Build SPL detection logic"""
        condition = detection.get('condition', '')
        
        # Build selections
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                selections[key] = self._build_selection_spl(value)
        
        # Convert condition to SPL
        if condition:
            spl = self._convert_condition_to_spl(condition, selections)
        else:
            # Default: OR all selections
            if selections:
                spl = ' OR '.join([f"({s})" for s in selections.values()])
            else:
                spl = ""
        
        return spl
    
    def _build_selection_spl(self, selection: Dict[str, Any]) -> str:
        """Build SPL for a single selection"""
        conditions = []
        
        for field, value in selection.items():
            # Extract field and modifier
            field_parts = field.split('|')
            sigma_field = field_parts[0]
            modifier = field_parts[1] if len(field_parts) > 1 else None
            
            # Map to Splunk field
            splunk_field = self.field_mappings.get(sigma_field, sigma_field.lower())
            
            # Build condition
            condition = self._build_field_condition_spl(splunk_field, modifier, value)
            conditions.append(condition)
        
        # Combine with AND
        if len(conditions) == 1:
            return conditions[0]
        else:
            return "(" + " AND ".join(conditions) + ")"
    
    def _build_field_condition_spl(self, field: str, modifier: Optional[str], value: Any) -> str:
        """Build SPL condition for a field"""
        if isinstance(value, list):
            # Multiple values - use IN or OR
            if modifier in ['contains', 'startswith', 'endswith']:
                # Use OR for pattern matching
                sub_conditions = [self._build_single_condition_spl(field, modifier, v) for v in value]
                return "(" + " OR ".join(sub_conditions) + ")"
            else:
                # Use IN for exact matches
                quoted_values = [f'"{self._escape_spl_value(str(v))}"' for v in value]
                return f'{field} IN ({", ".join(quoted_values)})'
        else:
            return self._build_single_condition_spl(field, modifier, value)
    
    def _build_single_condition_spl(self, field: str, modifier: Optional[str], value: str) -> str:
        """Build SPL condition for a single value"""
        escaped_value = self._escape_spl_value(str(value))
        
        if modifier == 'contains':
            return f'{field}="*{escaped_value}*"'
        elif modifier == 'startswith':
            return f'{field}="{escaped_value}*"'
        elif modifier == 'endswith':
            return f'{field}="*{escaped_value}"'
        elif modifier == 're':
            # SPL regex
            return f'| regex {field}="{escaped_value}"'
        else:
            # Exact match or wildcard
            if '*' in escaped_value or '?' in escaped_value:
                return f'{field}="{escaped_value}"'
            else:
                return f'{field}="{escaped_value}"'
    
    def _escape_spl_value(self, value: str) -> str:
        """Escape special characters for SPL"""
        # Escape backslashes
        value = value.replace('\\', '\\\\')
        # Escape quotes
        value = value.replace('"', '\\"')
        return value
    
    def _convert_condition_to_spl(self, condition: str, selections: Dict[str, str]) -> str:
        """Convert Sigma condition to SPL"""
        spl_condition = condition
        
        # Replace selection names with actual SPL
        for selection_name, selection_spl in selections.items():
            spl_condition = spl_condition.replace(selection_name, f"({selection_spl})")
        
        # Convert boolean operators (SPL uses uppercase)
        spl_condition = spl_condition.replace(' and ', ' AND ')
        spl_condition = spl_condition.replace(' or ', ' OR ')
        spl_condition = spl_condition.replace(' not ', ' NOT ')
        
        return spl_condition
    
    def _build_alert_config(self, sigma_rule: Dict[str, Any]) -> Dict[str, Any]:
        """Build Splunk alert configuration"""
        severity_mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'informational': 'info'
        }
        
        alert_config = {
            'name': sigma_rule.get('title'),
            'description': sigma_rule.get('description'),
            'severity': severity_mapping.get(sigma_rule.get('level', 'medium'), 'medium'),
            'cron_schedule': '*/5 * * * *',  # Run every 5 minutes
            'earliest_time': '-10m@m',
            'latest_time': 'now',
            'alert_type': 'always',
            'alert_threshold': 0,
            'actions': 'email',
            'trigger_once': False,
            'throttle_period': '5m',
            'tags': sigma_rule.get('tags', []),
            'references': sigma_rule.get('references', [])
        }
        
        return alert_config
    
    async def validate(self, rule: Dict[str, Any]) -> bool:
        """
        Validate generated SPL query
        
        Args:
            rule: Dictionary containing SPL query
            
        Returns:
            True if valid, False otherwise
        """
        try:
            query = rule.get('query', '')
            
            if not query:
                logger.error("Empty query")
                return False
            
            # Basic SPL validation
            if not query.strip():
                logger.error("Query is empty or whitespace only")
                return False
            
            # Check for balanced quotes
            if query.count('"') % 2 != 0:
                logger.error("Unbalanced quotes in query")
                return False
            
            # Check for balanced parentheses
            if query.count('(') != query.count(')'):
                logger.error("Unbalanced parentheses in query")
                return False
            
            # Check for balanced brackets
            if query.count('[') != query.count(']'):
                logger.error("Unbalanced brackets in query")
                return False
            
            logger.info("SPL query validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            return False
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        logger.info("Splunk Converter shutdown")