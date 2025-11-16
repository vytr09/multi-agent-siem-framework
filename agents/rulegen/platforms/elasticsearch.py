# agents/rulegen/platforms/elasticsearch.py

import logging
from typing import Dict, List, Any, Optional
import json

logger = logging.getLogger(__name__)


class ElasticsearchConverter:
    """
    Converts Sigma rules to Elasticsearch queries (KQL and DSL)
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.syntax_type = "KQL"  # Kibana Query Language
        self.use_dsl = config.get('use_dsl', False)  # Use Query DSL instead of KQL
        
        # Field mappings from Sigma to ECS (Elastic Common Schema)
        self.field_mappings = {
            # Process events
            'CommandLine': 'process.command_line',
            'Image': 'process.executable',
            'ParentImage': 'process.parent.executable',
            'ParentCommandLine': 'process.parent.command_line',
            'User': 'user.name',
            'ProcessId': 'process.pid',
            'ParentProcessId': 'process.parent.pid',
            
            # File events
            'TargetFilename': 'file.path',
            'FileName': 'file.name',
            
            # Network events
            'DestinationIp': 'destination.ip',
            'DestinationPort': 'destination.port',
            'DestinationHostname': 'destination.domain',
            'SourceIp': 'source.ip',
            'SourcePort': 'source.port',
            
            # Registry events
            'TargetObject': 'registry.path',
            'Details': 'registry.data.strings',
            'EventType': 'event.action',
        }
        
        # Logsource to index pattern mapping
        self.logsource_mappings = {
            'process_creation': {
                'index': 'winlogbeat-*',
                'event_category': 'process',
                'event_action': 'start'
            },
            'network_connection': {
                'index': 'winlogbeat-*',
                'event_category': 'network',
                'event_action': 'connection'
            },
            'file_event': {
                'index': 'winlogbeat-*',
                'event_category': 'file',
                'event_action': 'creation'
            },
            'registry_event': {
                'index': 'winlogbeat-*',
                'event_category': 'registry',
                'event_action': 'modification'
            }
        }
    
    async def initialize(self) -> None:
        """Initialize the converter"""
        logger.info("Elasticsearch Converter initialized")
        
    # ADD THIS METHOD HERE
    def get_syntax_name(self) -> str:
        """Get the syntax name for this converter"""
        return self.syntax_type
    
    async def convert(self, sigma_rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert Sigma rule to Elasticsearch query
        
        Args:
            sigma_rule: Sigma rule dictionary
            
        Returns:
            Dictionary containing KQL/DSL query and metadata
        """
        logger.info(f"Converting Sigma rule to Elasticsearch: {sigma_rule.get('title', 'Unknown')}")
        
        try:
            logsource = sigma_rule.get('logsource', {})
            detection = sigma_rule.get('detection', {})
            
            if self.use_dsl:
                # Generate Query DSL
                query = self._build_dsl_query(logsource, detection)
                query_type = "DSL"
            else:
                # Generate KQL query
                query = self._build_kql_query(logsource, detection)
                query_type = "KQL"
            
            # Build detection rule configuration
            rule_config = self._build_rule_config(sigma_rule, logsource)
            
            result = {
                'query': query,
                'query_type': query_type,
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
            
            logger.info(f"Successfully converted to Elasticsearch {query_type}")
            return result
            
        except Exception as e:
            logger.error(f"Error converting to Elasticsearch: {str(e)}")
            raise
    
    def _build_kql_query(self, logsource: Dict[str, Any], detection: Dict[str, Any]) -> str:
        """Build KQL query"""
        query_parts = []
        
        # Add logsource filters
        category = logsource.get('category', 'process_creation')
        mapping = self.logsource_mappings.get(category, self.logsource_mappings['process_creation'])
        
        if mapping.get('event_category'):
            query_parts.append(f'event.category:"{mapping["event_category"]}"')
        
        if mapping.get('event_action'):
            query_parts.append(f'event.action:"{mapping["event_action"]}"')
        
        # Build detection logic
        if detection:
            detection_kql = self._build_detection_kql(detection)
            if detection_kql:
                query_parts.append(detection_kql)
        
        # Combine with AND
        return " and ".join(query_parts) if query_parts else "*"
    
    def _build_detection_kql(self, detection: Dict[str, Any]) -> str:
        """Build KQL detection logic"""
        condition = detection.get('condition', '')
        
        # Build selections
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                selections[key] = self._build_selection_kql(value)
        
        # Convert condition to KQL
        if condition:
            kql = self._convert_condition_to_kql(condition, selections)
        else:
            # Default: OR all selections
            kql = " or ".join(f"({s})" for s in selections.values()) if selections else ""
        
        return kql
    
    def _build_selection_kql(self, selection: Dict[str, Any]) -> str:
        """Build KQL for a single selection"""
        conditions = []
        
        for field, value in selection.items():
            # Extract field and modifier
            field_parts = field.split('|')
            sigma_field = field_parts[0]
            modifier = field_parts[1] if len(field_parts) > 1 else None
            
            # Map to ECS field
            ecs_field = self.field_mappings.get(sigma_field, sigma_field.lower())
            
            # Build condition
            condition = self._build_field_condition_kql(ecs_field, modifier, value)
            conditions.append(condition)
        
        # Combine with AND
        if len(conditions) == 1:
            return conditions[0]
        else:
            return "(" + " and ".join(conditions) + ")"
    
    def _build_field_condition_kql(self, field: str, modifier: Optional[str], value: Any) -> str:
        """Build KQL condition for a field"""
        if isinstance(value, list):
            # Multiple values - use OR
            sub_conditions = [self._build_single_condition_kql(field, modifier, v) for v in value]
            return "(" + " or ".join(sub_conditions) + ")"
        else:
            return self._build_single_condition_kql(field, modifier, value)
    
    def _build_single_condition_kql(self, field: str, modifier: Optional[str], value: str) -> str:
        """Build KQL condition for a single value"""
        # Escape special characters
        escaped_value = self._escape_kql_value(str(value))
        
        if modifier == 'contains':
            return f'{field}:*{escaped_value}*'
        elif modifier == 'startswith':
            return f'{field}:{escaped_value}*'
        elif modifier == 'endswith':
            return f'{field}:*{escaped_value}'
        elif modifier == 're':
            # KQL doesn't support regex directly, convert to wildcard
            logger.warning(f"Regex not fully supported in KQL, converting to wildcard: {value}")
            return f'{field}:*{escaped_value}*'
        else:
            # Exact match or wildcard
            if '*' in escaped_value or '?' in escaped_value:
                return f'{field}:{escaped_value}'
            else:
                return f'{field}:"{escaped_value}"'
            
    def _escape_kql_value(self, value: str) -> str:
        """Escape special characters for KQL"""
        # Escape backslashes
        value = value.replace('\\', '\\\\')
        # Escape quotes
        value = value.replace('"', '\\"')
        # Preserve wildcards
        return value
    
    def _convert_condition_to_kql(self, condition: str, selections: Dict[str, str]) -> str:
        """Convert Sigma condition to KQL"""
        kql_condition = condition
        
        # Replace selection names with actual KQL
        for selection_name, selection_kql in selections.items():
            kql_condition = kql_condition.replace(selection_name, f"({selection_kql})")
        
        # Convert boolean operators (KQL uses lowercase)
        kql_condition = kql_condition.replace(' and ', ' and ')
        kql_condition = kql_condition.replace(' or ', ' or ')
        kql_condition = kql_condition.replace(' not ', ' not ')
        
        return kql_condition
    
    def _build_dsl_query(self, logsource: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
        """Build Elasticsearch Query DSL"""
        must_clauses = []
        
        # Add logsource filters
        category = logsource.get('category', 'process_creation')
        mapping = self.logsource_mappings.get(category, self.logsource_mappings['process_creation'])
        
        if mapping.get('event_category'):
            must_clauses.append({
                "match": {
                    "event.category": mapping['event_category']
                }
            })
        
        if mapping.get('event_action'):
            must_clauses.append({
                "match": {
                    "event.action": mapping['event_action']
                }
            })
        
        # Build detection logic
        if detection:
            detection_dsl = self._build_detection_dsl(detection)
            if detection_dsl:
                must_clauses.append(detection_dsl)
        
        # Build final query
        query = {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            }
        }
        
        return query
    
    def _build_detection_dsl(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """Build DSL detection logic"""
        condition = detection.get('condition', '')
        
        # Build selections
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                selections[key] = self._build_selection_dsl(value)
        
        # Convert condition to DSL
        if condition:
            dsl = self._convert_condition_to_dsl(condition, selections)
        else:
            # Default: OR all selections
            if selections:
                dsl = {
                    "bool": {
                        "should": list(selections.values()),
                        "minimum_should_match": 1
                    }
                }
            else:
                dsl = {"match_all": {}}
        
        return dsl
    
    def _build_selection_dsl(self, selection: Dict[str, Any]) -> Dict[str, Any]:
        """Build DSL for a single selection"""
        must_clauses = []
        
        for field, value in selection.items():
            # Extract field and modifier
            field_parts = field.split('|')
            sigma_field = field_parts[0]
            modifier = field_parts[1] if len(field_parts) > 1 else None
            
            # Map to ECS field
            ecs_field = self.field_mappings.get(sigma_field, sigma_field.lower())
            
            # Build clause
            clause = self._build_field_clause_dsl(ecs_field, modifier, value)
            must_clauses.append(clause)
        
        # Combine with AND
        if len(must_clauses) == 1:
            return must_clauses[0]
        else:
            return {
                "bool": {
                    "must": must_clauses
                }
            }
    
    def _build_field_clause_dsl(self, field: str, modifier: Optional[str], value: Any) -> Dict[str, Any]:
        """Build DSL clause for a field"""
        if isinstance(value, list):
            # Multiple values - use should (OR)
            should_clauses = [self._build_single_clause_dsl(field, modifier, v) for v in value]
            return {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            }
        else:
            return self._build_single_clause_dsl(field, modifier, value)
    
    def _build_single_clause_dsl(self, field: str, modifier: Optional[str], value: str) -> Dict[str, Any]:
        """Build DSL clause for a single value"""
        value_str = str(value)
        
        if modifier == 'contains':
            return {
                "wildcard": {
                    field: f"*{value_str}*"
                }
            }
        elif modifier == 'startswith':
            return {
                "wildcard": {
                    field: f"{value_str}*"
                }
            }
        elif modifier == 'endswith':
            return {
                "wildcard": {
                    field: f"*{value_str}"
                }
            }
        elif modifier == 're':
            return {
                "regexp": {
                    field: value_str
                }
            }
        else:
            # Exact match or wildcard
            if '*' in value_str or '?' in value_str:
                return {
                    "wildcard": {
                        field: value_str
                    }
                }
            else:
                return {
                    "match_phrase": {
                        field: value_str
                    }
                }
    
    def _convert_condition_to_dsl(self, condition: str, selections: Dict[str, Dict]) -> Dict[str, Any]:
        """Convert Sigma condition to DSL"""
        # Simple implementation - handles basic AND/OR/NOT
        condition_lower = condition.lower()
        
        if ' and ' in condition_lower:
            # Split by AND and build must clause
            parts = condition.split(' and ')
            must_clauses = []
            for part in parts:
                part = part.strip()
                if part in selections:
                    must_clauses.append(selections[part])
            
            return {
                "bool": {
                    "must": must_clauses
                }
            }
        
        elif ' or ' in condition_lower:
            # Split by OR and build should clause
            parts = condition.split(' or ')
            should_clauses = []
            for part in parts:
                part = part.strip()
                if part in selections:
                    should_clauses.append(selections[part])
            
            return {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            }
        
        elif ' not ' in condition_lower:
            # Handle NOT
            parts = condition.split(' not ')
            must_clause = selections.get(parts[0].strip())
            must_not_clause = selections.get(parts[1].strip())
            
            result = {"bool": {}}
            if must_clause:
                result["bool"]["must"] = [must_clause]
            if must_not_clause:
                result["bool"]["must_not"] = [must_not_clause]
            
            return result
        
        else:
            # Single selection
            return selections.get(condition.strip(), {"match_all": {}})
    
    def _build_rule_config(self, sigma_rule: Dict[str, Any], logsource: Dict[str, Any]) -> Dict[str, Any]:
        """Build Elasticsearch detection rule configuration"""
        severity_mapping = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25,
            'informational': 0
        }
        
        category = logsource.get('category', 'process_creation')
        mapping = self.logsource_mappings.get(category, self.logsource_mappings['process_creation'])
        
        rule_config = {
            'name': sigma_rule.get('title'),
            'description': sigma_rule.get('description'),
            'severity': sigma_rule.get('level', 'medium'),
            'risk_score': severity_mapping.get(sigma_rule.get('level', 'medium'), 50),
            'index': [mapping.get('index', 'winlogbeat-*')],
            'interval': '5m',
            'from': 'now-6m',
            'to': 'now',
            'max_signals': 100,
            'tags': sigma_rule.get('tags', []),
            'references': sigma_rule.get('references', []),
            'false_positives': sigma_rule.get('falsepositives', []),
            'threat': self._build_threat_mapping(sigma_rule),
            'type': 'query',
            'language': 'kuery' if not self.use_dsl else 'lucene',
            'enabled': True,
            'actions': []
        }
        
        return rule_config
    
    def _build_threat_mapping(self, sigma_rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build MITRE ATT&CK threat mapping"""
        threat_mapping = []
        
        tags = sigma_rule.get('tags', [])
        
        for tag in tags:
            if tag.startswith('attack.t'):
                # Extract technique ID
                technique_id = tag.replace('attack.', '').upper()
                
                threat_mapping.append({
                    'framework': 'MITRE ATT&CK',
                    'technique': {
                        'id': technique_id,
                        'name': sigma_rule.get('title', ''),
                        'reference': f'https://attack.mitre.org/techniques/{technique_id}/'
                    }
                })
        
        return threat_mapping
    
    async def validate(self, rule: Dict[str, Any]) -> bool:
        """
        Validate generated Elasticsearch query
        
        Args:
            rule: Dictionary containing query
            
        Returns:
            True if valid, False otherwise
        """
        try:
            query = rule.get('query')
            query_type = rule.get('query_type', 'KQL')
            
            if not query:
                logger.error("Empty query")
                return False
            
            if query_type == 'DSL':
                # Validate JSON structure
                if not isinstance(query, dict):
                    logger.error("DSL query must be a dictionary")
                    return False
                
                if 'query' not in query:
                    logger.error("DSL query missing 'query' field")
                    return False
                
                # Validate it's valid JSON
                try:
                    json.dumps(query)
                except:
                    logger.error("Invalid JSON in DSL query")
                    return False
            
            else:  # KQL
                # Basic KQL validation
                if not isinstance(query, str):
                    logger.error("KQL query must be a string")
                    return False
                
                # Check for balanced quotes
                if query.count('"') % 2 != 0:
                    logger.error("Unbalanced quotes in KQL query")
                    return False
                
                # Check for balanced parentheses
                if query.count('(') != query.count(')'):
                    logger.error("Unbalanced parentheses in KQL query")
                    return False
            
            logger.info("Elasticsearch query validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            return False
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        logger.info("Elasticsearch Converter shutdown")