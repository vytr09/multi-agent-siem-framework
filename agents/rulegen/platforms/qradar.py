# agents/rulegen/platforms/qradar.py

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class QRadarConverter:
    """
    Converts Sigma rules to IBM QRadar AQL (Ariel Query Language)
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.syntax_type = "AQL"
        
        # Field mappings from Sigma to QRadar
        self.field_mappings = {
            # Process events
            'CommandLine': 'Process CommandLine',
            'Image': 'Process Name',
            'ParentImage': 'Parent Process',
            'User': 'username',
            'ProcessId': 'Process ID',
            
            # File events
            'TargetFilename': 'Filename',
            'FileName': 'Filename',
            
            # Network events
            'DestinationIp': 'destinationip',
            'DestinationPort': 'destinationport',
            'DestinationHostname': 'destinationhost',
            'SourceIp': 'sourceip',
            'SourcePort': 'sourceport',
            
            # Generic fields
            'EventID': 'EventID',
            'LogName': 'Log Source'
        }
        
        # Log source mappings
        self.logsource_mappings = {
            'process_creation': {
                'category': 'Application',
                'logsourcetype': 'Microsoft Windows Security Event Log',
                'eventid': '4688'
            },
            'network_connection': {
                'category': 'Network',
                'logsourcetype': 'Microsoft Windows Security Event Log'
            },
            'file_event': {
                'category': 'File',
                'logsourcetype': 'Microsoft Windows Security Event Log'
            },
            'registry_event': {
                'category': 'Registry',
                'logsourcetype': 'Microsoft Windows Security Event Log'
            }
        }
    
    async def initialize(self) -> None:
        """Initialize the converter"""
        logger.info("QRadar Converter initialized")
    
    async def convert(self, sigma_rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Sigma rule to QRadar AQL
        
        Args:
            sigma_rule: Sigma rule dictionary
            
        Returns:
            Dictionary containing AQL query and metadata
        """
        logger.info(f"Converting Sigma rule to QRadar AQL: {sigma_rule.get('title', 'Unknown')}")
        
        try:
            logsource = sigma_rule.get('logsource', {})
            detection = sigma_rule.get('detection', {})
            
            # Build AQL query
            aql_query = self._build_aql_query(logsource, detection)
            
            # Build custom rule configuration
            rule_config = self._build_rule_config(sigma_rule)
            
            result = {
                'query': aql_query,
                'rule_config': rule_config,
                'metadata': {
                    'rule_name': sigma_rule.get('title'),
                    'rule_id': sigma_rule.get('id'),
                    'severity': sigma_rule.get('level', 'medium'),
                    'description': sigma_rule.get('description'),
                    'references': sigma_rule.get('references', []),
                    'tags': sigma_rule.get('tags', [])
                }
            }
            
            logger.info("Successfully converted to QRadar AQL")
            return result
            
        except Exception as e:
            logger.error(f"Error converting to QRadar AQL: {str(e)}")
            raise
    
    def _build_aql_query(self, logsource: Dict[str, Any], detection: Dict[str, Any]) -> str:
        """Build AQL query"""
        # Base query structure
        query_parts = [
            "SELECT",
            "  DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') as Time,",
            "  sourceip,",
            "  destinationip,",
            "  username,",
            "  QIDNAME(qid) as EventName,",
            "  category,",
            "  logsourcename(logsourceid) as LogSource",
            "FROM events"
        ]
        
        # Build WHERE clause
        where_conditions = []
        
        # Add logsource filters
        category = logsource.get('category', 'process_creation')
        mapping = self.logsource_mappings.get(category, {})
        
        if mapping.get('category'):
            where_conditions.append(f"category = '{mapping['category']}'")
        
        if mapping.get('eventid'):
            where_conditions.append(f"EventID = '{mapping['eventid']}'")
        
        # Build detection conditions
        if detection:
            detection_conditions = self._build_detection_aql(detection)
            if detection_conditions:
                where_conditions.append(detection_conditions)
        
        # Add WHERE clause
        if where_conditions:
            query_parts.append("WHERE")
            query_parts.append("  " + " AND ".join(where_conditions))
        
        # Add time window
        query_parts.append("LAST 24 HOURS")
        
        # Combine into final query
        aql_query = "\n".join(query_parts)
        
        return aql_query
    
    def _build_detection_aql(self, detection: Dict[str, Any]) -> str:
        """Build AQL detection conditions"""
        condition = detection.get('condition', '')
        
        # Build selections
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                selections[key] = self._build_selection_aql(value)
        
        # Convert condition to AQL
        if condition:
            aql = self._convert_condition_to_aql(condition, selections)
        else:
            # Default: OR all selections
            if selections:
                conditions = [f"({s})" for s in selections.values()]
                aql = " OR ".join(conditions)
            else:
                aql = ""
        
        return aql
    
    def _build_selection_aql(self, selection: Dict[str, Any]) -> str:
        """Build AQL for a single selection"""
        conditions = []
        
        for field, value in selection.items():
            # Extract field and modifier
            field_parts = field.split('|')
            sigma_field = field_parts[0]
            modifier = field_parts[1] if len(field_parts) > 1 else None
            
            # Map to QRadar field
            qradar_field = self.field_mappings.get(sigma_field, sigma_field)
            
            # Build condition
            condition = self._build_field_condition_aql(qradar_field, modifier, value)
            conditions.append(condition)
        
        # Combine with AND
        if len(conditions) == 1:
            return conditions[0]
        else:
            return "(" + " AND ".join(conditions) + ")"
    
    def _build_field_condition_aql(self, field: str, modifier: Optional[str], value: Any) -> str:
        """Build AQL condition for a field"""
        if isinstance(value, list):
            # Multiple values - use IN or OR
            if modifier in ['contains', 'startswith', 'endswith']:
                # Use OR for pattern matching
                sub_conditions = [self._build_single_condition_aql(field, modifier, v) for v in value]
                return "(" + " OR ".join(sub_conditions) + ")"
            else:
                # Use IN for exact matches
                quoted_values = [f"'{self._escape_aql_value(str(v))}'" for v in value]
                return f"{field} IN ({', '.join(quoted_values)})"
        else:
            return self._build_single_condition_aql(field, modifier, value)
    
    def _build_single_condition_aql(self, field: str, modifier: Optional[str], value: str) -> str:
        """Build AQL condition for a single value"""
        escaped_value = self._escape_aql_value(str(value))
        
        if modifier == 'contains':
            return f"{field} ILIKE '%{escaped_value}%'"
        elif modifier == 'startswith':
            return f"{field} ILIKE '{escaped_value}%'"
        elif modifier == 'endswith':
            return f"{field} ILIKE '%{escaped_value}'"
        elif modifier == 're':
            # AQL has limited regex support, use MATCHES
            return f"{field} MATCHES '{escaped_value}'"
        else:
            # Exact match or wildcard
            if '*' in escaped_value or '%' in escaped_value:
                # Convert * to % for SQL-like wildcards
                escaped_value = escaped_value.replace('*', '%')
                return f"{field} ILIKE '{escaped_value}'"
            else:
                return f"{field} = '{escaped_value}'"
    
    def _escape_aql_value(self, value: str) -> str:
        """Escape special characters for AQL"""
        # Escape single quotes
        value = value.replace("'", "''")
        return value
    
    def _convert_condition_to_aql(self, condition: str, selections: Dict[str, str]) -> str:
        """Convert Sigma condition to AQL"""
        aql_condition = condition
        
        # Replace selection names with actual AQL
        for selection_name, selection_aql in selections.items():
            aql_condition = aql_condition.replace(selection_name, f"({selection_aql})")
        
        # Convert boolean operators (AQL uses uppercase)
        aql_condition = aql_condition.replace(' and ', ' AND ')
        aql_condition = aql_condition.replace(' or ', ' OR ')
        aql_condition = aql_condition.replace(' not ', ' NOT ')
        
        return aql_condition
    
    def _build_rule_config(self, sigma_rule: Dict[str, Any]) -> Dict[str, Any]:
        """Build QRadar custom rule configuration"""
        severity_mapping = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'informational': 1
        }
        
        rule_config = {
            'name': sigma_rule.get('title'),
            'type': 'event',
            'enabled': True,
            'severity': severity_mapping.get(sigma_rule.get('level', 'medium'), 5),
            'description': sigma_rule.get('description'),
            'test_definitions': [
                {
                    'test_type': 'AQL',
                    'test_value': 'Generated automatically from Sigma rule'
                }
            ],
            'responses': [
                {
                    'type': 'offense',
                    'name': sigma_rule.get('title')
                }
            ],
            'notes': '\n'.join([
                'Generated from Sigma rule',
                f"Rule ID: {sigma_rule.get('id')}",
                f"References: {', '.join(sigma_rule.get('references', [])[:3])}"
            ])
        }
        
        return rule_config
    
    async def validate(self, rule: Dict[str, Any]) -> bool:
        """
        Validate generated AQL query
        
        Args:
            rule: Dictionary containing AQL query
            
        Returns:
            True if valid, False otherwise
        """
        try:
            query = rule.get('query', '')
            
            if not query:
                logger.error("Empty query")
                return False
            
            # Basic syntax validation
            required_keywords = ['SELECT', 'FROM']
            for keyword in required_keywords:
                if keyword not in query.upper():
                    logger.error(f"Missing required keyword: {keyword}")
                    return False
            
            # Check for balanced quotes
            if query.count("'") % 2 != 0:
                logger.error("Unbalanced quotes in query")
                return False
            
            # Check for balanced parentheses
            if query.count('(') != query.count(')'):
                logger.error("Unbalanced parentheses in query")
                return False
            
            logger.info("AQL query validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            return False
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        logger.info("QRadar Converter shutdown")