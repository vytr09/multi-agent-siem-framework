# agents/rulegen/sigma/optimizer.py

import logging
from typing import Dict, List, Any, Set
import re

logger = logging.getLogger(__name__)


class RuleOptimizer:
    """
    Optimizes Sigma rules for better performance and accuracy
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enable_field_optimization = config.get('enable_field_optimization', True)
        self.enable_condition_optimization = config.get('enable_condition_optimization', True)
        self.enable_value_optimization = config.get('enable_value_optimization', True)
        
    async def optimize(self, sigma_rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optimize a Sigma rule
        
        Args:
            sigma_rule: Original Sigma rule
            
        Returns:
            Optimized Sigma rule with optimization metadata
        """
        logger.info(f"Optimizing rule: {sigma_rule.get('title', 'Unknown')}")
        
        optimized_rule = sigma_rule.copy()
        optimizations_applied = []
        
        # Optimize detection logic
        if 'detection' in optimized_rule:
            detection = optimized_rule['detection']
            
            # Field optimization
            if self.enable_field_optimization:
                detection, field_opts = self._optimize_fields(detection)
                optimizations_applied.extend(field_opts)
            
            # Condition optimization
            if self.enable_condition_optimization:
                detection, cond_opts = self._optimize_conditions(detection)
                optimizations_applied.extend(cond_opts)
            
            # Value optimization
            if self.enable_value_optimization:
                detection, value_opts = self._optimize_values(detection)
                optimizations_applied.extend(value_opts)
            
            optimized_rule['detection'] = detection
        
        # Add optimization metadata
        if not optimized_rule.get('metadata'):
            optimized_rule['metadata'] = {}
        
        optimized_rule['metadata']['optimizations'] = optimizations_applied
        optimized_rule['metadata']['optimization_count'] = len(optimizations_applied)
        
        logger.info(f"Applied {len(optimizations_applied)} optimizations")
        
        return optimized_rule
    
    def _optimize_fields(self, detection: Dict[str, Any]) -> tuple:
        """
        Optimize field selections for better performance
        
        Returns:
            (optimized_detection, list of optimizations)
        """
        optimizations = []
        optimized_detection = detection.copy()
        
        for key, value in detection.items():
            if key == 'condition':
                continue
            
            if isinstance(value, dict):
                optimized_selection, opts = self._optimize_selection_fields(value)
                optimized_detection[key] = optimized_selection
                optimizations.extend(opts)
        
        return optimized_detection, optimizations
    
    def _optimize_selection_fields(self, selection: Dict[str, Any]) -> tuple:
        """Optimize individual selection fields"""
        optimizations = []
        optimized_selection = {}
        
        for field, value in selection.items():
            # Extract field name and modifier
            field_parts = field.split('|')
            field_name = field_parts[0]
            modifier = field_parts[1] if len(field_parts) > 1 else None
            
            # Optimize field selection
            optimized_field, optimized_value, opt = self._optimize_field_value_pair(
                field_name, modifier, value
            )
            
            if opt:
                optimizations.append(opt)
            
            optimized_selection[optimized_field] = optimized_value
        
        return optimized_selection, optimizations
    
    def _optimize_field_value_pair(
        self, 
        field: str, 
        modifier: str, 
        value: Any
    ) -> tuple:
        """
        Optimize individual field-value pairs
        
        Returns:
            (optimized_field, optimized_value, optimization_description)
        """
        optimization = None
        
        # Choose best modifier for the value
        if modifier is None and isinstance(value, str):
            # Suggest better modifiers based on value patterns
            if '*' in value or '?' in value:
                # Value has wildcards, use contains or endswith
                if value.startswith('*') and value.endswith('*'):
                    field = f"{field}|contains"
                    value = value.strip('*')
                    optimization = f"Changed {field} to use 'contains' modifier"
                elif value.endswith('*'):
                    field = f"{field}|startswith"
                    value = value.rstrip('*')
                    optimization = f"Changed {field} to use 'startswith' modifier"
                elif value.startswith('*'):
                    field = f"{field}|endswith"
                    value = value.lstrip('*')
                    optimization = f"Changed {field} to use 'endswith' modifier"
            elif '\\' in value or '/' in value:
                # Path-like value
                if not modifier:
                    field = f"{field}|contains"
                    optimization = f"Added 'contains' modifier for path field"
        
        elif modifier and isinstance(value, list):
            # Optimize list values
            if len(value) == 1:
                value = value[0]
                optimization = f"Converted single-item list to scalar value"
        
        # Reconstruct field with modifier
        if modifier:
            optimized_field = f"{field}|{modifier}"
        else:
            optimized_field = field
        
        return optimized_field, value, optimization
    
    def _optimize_conditions(self, detection: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
        """
        Optimize condition logic
        
        Returns:
            (optimized_detection, list of optimizations)
        """
        optimizations = []
        optimized_detection = detection.copy()
        
        if 'condition' not in detection:
            return optimized_detection, optimizations
        
        condition = detection['condition']
        
        # Simplify redundant conditions
        if isinstance(condition, str):
            original_condition = condition
            
            # Remove redundant parentheses
            condition = self._remove_redundant_parentheses(condition)
            if condition != original_condition:
                optimizations.append("Removed redundant parentheses from condition")
            
            # Optimize boolean logic
            condition, opt = self._optimize_boolean_logic(condition)
            if opt:
                optimizations.append(opt)
            
            optimized_detection['condition'] = condition
        
        return optimized_detection, optimizations
    
    def _remove_redundant_parentheses(self, condition: str) -> str:
        """Remove unnecessary parentheses from condition"""
        # Simple implementation - can be enhanced
        while '( ' in condition:
            condition = condition.replace('( ', '(')
        while ' )' in condition:
            condition = condition.replace(' )', ')')
        
        # Remove outer parentheses if entire expression is wrapped
        if condition.startswith('(') and condition.endswith(')'):
            # Check if these are the matching outer parens
            depth = 0
            for i, char in enumerate(condition):
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                    if depth == 0 and i < len(condition) - 1:
                        # Found closing paren before end, not outer parens
                        break
            else:
                # Entire expression wrapped, remove outer parens
                condition = condition[1:-1].strip()
        
        return condition
    
    def _optimize_boolean_logic(self, condition: str) -> tuple[str, str]:
        """Optimize boolean logic in conditions"""
        optimization = None
        
        # Count operators
        and_count = condition.lower().count(' and ')
        or_count = condition.lower().count(' or ')
        
        # If many ORs, suggest reviewing for performance
        if or_count > 5:
            optimization = f"Condition has {or_count} OR operators - may impact performance"
        
        # Reorder for better performance (put most selective first)
        # This is a simplified heuristic
        if and_count > 1:
            parts = condition.split(' and ')
            # Prioritize selections with specific field matches
            scored_parts = []
            for part in parts:
                score = self._score_selection_selectivity(part.strip())
                scored_parts.append((score, part))
            
            # Sort by score (higher = more selective)
            scored_parts.sort(reverse=True)
            
            if scored_parts[0][1] != parts[0]:
                optimized_condition = ' and '.join([p[1] for p in scored_parts])
                optimization = "Reordered AND conditions for better performance"
                return optimized_condition, optimization
        
        return condition, optimization
    
    def _score_selection_selectivity(self, selection_name: str) -> int:
        """
        Score how selective a selection is likely to be
        Higher score = more selective (better to evaluate first)
        """
        score = 0
        
        # Selections with specific terms are more selective
        if 'process' in selection_name.lower():
            score += 3
        if 'file' in selection_name.lower():
            score += 3
        if 'network' in selection_name.lower():
            score += 2
        if 'registry' in selection_name.lower():
            score += 2
        
        return score
    
    def _optimize_values(self, detection: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
        """
        Optimize values in detection logic
        
        Returns:
            (optimized_detection, list of optimizations)
        """
        optimizations = []
        optimized_detection = detection.copy()
        
        for key, value in detection.items():
            if key == 'condition':
                continue
            
            if isinstance(value, dict):
                optimized_selection, opts = self._optimize_selection_values(value)
                optimized_detection[key] = optimized_selection
                optimizations.extend(opts)
        
        return optimized_detection, optimizations
    
    def _optimize_selection_values(self, selection: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
        """Optimize values in a selection"""
        optimizations = []
        optimized_selection = {}
        
        for field, value in selection.items():
            optimized_value = value
            
            if isinstance(value, str):
                # Normalize case for case-insensitive fields
                if self._is_case_insensitive_field(field):
                    if value != value.lower():
                        optimized_value = value.lower()
                        optimizations.append(f"Normalized {field} to lowercase")
                
                # Remove excessive wildcards
                if '**' in value or '***' in value:
                    optimized_value = re.sub(r'\*{2,}', '*', value)
                    optimizations.append(f"Removed excessive wildcards from {field}")
                
                # Optimize regex patterns if using re modifier
                if '|re' in field and isinstance(optimized_value, str):
                    optimized_value, opt = self._optimize_regex(optimized_value)
                    if opt:
                        optimizations.append(opt)
            
            elif isinstance(value, list):
                # Remove duplicates from lists
                if len(value) != len(set(value)):
                    optimized_value = list(set(value))
                    optimizations.append(f"Removed duplicate values from {field}")
                
                # Sort for consistency
                try:
                    optimized_value = sorted(optimized_value)
                except TypeError:
                    pass  # Can't sort mixed types
            
            optimized_selection[field] = optimized_value
        
        return optimized_selection, optimizations
    
    def _is_case_insensitive_field(self, field: str) -> bool:
        """Check if field is typically case-insensitive"""
        case_insensitive_fields = {
            'commandline', 'image', 'targetfilename', 
            'destinationhostname', 'parentimage'
        }
        
        field_name = field.split('|')[0].lower()
        return field_name in case_insensitive_fields
    
    def _optimize_regex(self, pattern: str) -> tuple[str, str]:
        """Optimize regex patterns"""
        optimization = None
        optimized_pattern = pattern
        
        # Remove unnecessary escaping
        unnecessary_escapes = [r'\.', r'\-', r'\_']
        for escape in unnecessary_escapes:
            if escape in pattern and not self._needs_escape(escape):
                optimized_pattern = optimized_pattern.replace(escape, escape[1])
                optimization = "Simplified regex pattern"
        
        # Suggest anchoring if pattern is very generic
        if not pattern.startswith('^') and not pattern.endswith('$'):
            if len(pattern) < 10 and '*' not in pattern:
                optimization = "Consider anchoring regex pattern for better performance"
        
        return optimized_pattern, optimization
    
    def _needs_escape(self, escape_seq: str) -> bool:
        """Check if escape sequence is necessary in regex context"""
        # Simplified check - in practice would need more context
        special_chars = {'.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '^', '$', '|', '\\'}
        return escape_seq[1] in special_chars
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        return {
            'field_optimization_enabled': self.enable_field_optimization,
            'condition_optimization_enabled': self.enable_condition_optimization,
            'value_optimization_enabled': self.enable_value_optimization
        }


# End of RuleOptimizer class