# agents/base/exceptions.py
"""
Custom exceptions for the Multi-Agent SIEM Framework.

This module defines all custom exceptions used throughout the framework
to provide better error handling and debugging capabilities.
"""

class AgentException(Exception):
    """Base exception for all agent-related errors"""
    
    def __init__(self, message: str, agent_name: str = None, agent_id: str = None):
        super().__init__(message)
        self.agent_name = agent_name
        self.agent_id = agent_id
        self.message = message
    
    def __str__(self):
        base_msg = self.message
        if self.agent_name:
            base_msg += f" (Agent: {self.agent_name})"
        if self.agent_id:
            base_msg += f" (ID: {self.agent_id})"
        return base_msg

class CollectorException(AgentException):
    """Exceptions specific to the Collector Agent"""
    pass

class CTISourceException(CollectorException):
    """Exceptions related to CTI source connections"""
    
    def __init__(self, message: str, source_type: str = None, source_url: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.source_type = source_type
        self.source_url = source_url
    
    def __str__(self):
        msg = super().__str__()
        if self.source_type:
            msg += f" (Source: {self.source_type})"
        if self.source_url:
            msg += f" (URL: {self.source_url})"
        return msg

class MISPConnectionException(CTISourceException):
    """MISP-specific connection errors"""
    pass

class TAXIIConnectionException(CTISourceException):
    """TAXII-specific connection errors"""
    pass

class DataNormalizationException(CollectorException):
    """Exceptions during data normalization process"""
    
    def __init__(self, message: str, data_format: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.data_format = data_format
    
    def __str__(self):
        msg = super().__str__()
        if self.data_format:
            msg += f" (Format: {self.data_format})"
        return msg

class ConfigurationException(AgentException):
    """Configuration-related exceptions"""
    
    def __init__(self, message: str, config_key: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.config_key = config_key
    
    def __str__(self):
        msg = super().__str__()
        if self.config_key:
            msg += f" (Config Key: {self.config_key})"
        return msg

class ValidationException(AgentException):
    """Data validation exceptions"""
    
    def __init__(self, message: str, validation_field: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.validation_field = validation_field
    
    def __str__(self):
        msg = super().__str__()
        if self.validation_field:
            msg += f" (Field: {self.validation_field})"
        return msg

class MessageQueueException(AgentException):
    """Message queue related exceptions"""
    pass

class DatabaseException(AgentException):
    """Database related exceptions"""
    pass

# Extractor Agent Exceptions (for future use)
class ExtractorException(AgentException):
    """Exceptions specific to the Extractor Agent"""
    pass

class LLMException(ExtractorException):
    """Large Language Model related exceptions"""
    pass

class NLPException(ExtractorException):
    """Natural Language Processing exceptions"""
    pass

class ATTACKMappingException(ExtractorException):
    """MITRE ATT&CK mapping exceptions"""
    pass

# RuleGen Agent Exceptions (for future use)
class RuleGenException(AgentException):
    """Exceptions specific to the Rule Generation Agent"""
    pass

class SigmaException(RuleGenException):
    """Sigma rule related exceptions"""
    pass

# Evaluator Agent Exceptions (for future use)
class EvaluatorException(AgentException):
    """Exceptions specific to the Evaluator Agent"""
    pass

class SIEMIntegrationException(EvaluatorException):
    """SIEM integration exceptions"""
    pass

class MetricsException(EvaluatorException):
    """Metrics calculation exceptions"""
    pass
