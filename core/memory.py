# core/memory.py
"""
Hybrid Memory Management using Custom Memory Implementation
Combines file-based persistence with in-memory caching
Replaces LangChain memory with custom implementation
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
from datetime import datetime
from core.logging import get_agent_logger


class CustomConversationMemory:
    """
    Custom conversation memory implementation to replace LangChain memory
    """
    def __init__(self, memory_key: str = "chat_history", return_messages: bool = True):
        self.memory_key = memory_key
        self.return_messages = return_messages
        self.chat_history: List[Dict[str, Any]] = []
    
    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]):
        """Save context to memory"""
        interaction = {
            "input": inputs.get("input", ""),
            "output": outputs.get("output", ""),
            "timestamp": datetime.utcnow().isoformat()
        }
        self.chat_history.append(interaction)
    
    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Load memory variables"""
        if self.return_messages:
            # Convert to message format
            messages = []
            for interaction in self.chat_history:
                messages.extend([
                    {"type": "HumanMessage", "content": interaction["input"]},
                    {"type": "AIMessage", "content": interaction["output"]}
                ])
            return {self.memory_key: messages}
        else:
            return {self.memory_key: self.chat_history}
    
    def clear(self):
        """Clear memory"""
        self.chat_history = []


class HybridMemoryManager:
    """
    Manages both short-term (in-memory) and long-term (file-based) memory
    Provides real-time agent communication with persistent storage
    """
    def __init__(self, 
                 memory_dir: str = "data/memory/",
                 persist_enabled: bool = True):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.persist_enabled = persist_enabled
        self.logger = get_agent_logger("memory_manager")
        
        # Short-term memory per agent (in-memory)
        self.agent_memories: Dict[str, CustomConversationMemory] = {}
        
    def get_agent_memory(self, agent_id: str) -> CustomConversationMemory:
        """Get or create memory for specific agent"""
        if agent_id not in self.agent_memories:
            memory = CustomConversationMemory(
                memory_key="chat_history",
                return_messages=True
            )
            
            # Load from file if exists
            if self.persist_enabled:
                self._load_from_file(agent_id, memory)
            
            self.agent_memories[agent_id] = memory
        
        return self.agent_memories[agent_id]
    
    def save_interaction(self, 
                        agent_id: str, 
                        input_data: Dict[str, Any], 
                        output_data: Dict[str, Any]):
        """Save agent interaction to memory"""
        memory = self.get_agent_memory(agent_id)
        
        # Save to custom memory
        memory.save_context(
            {"input": json.dumps(input_data)},
            {"output": json.dumps(output_data)}
        )
        
        # Persist to file
        if self.persist_enabled:
            self._persist_to_file(agent_id, memory)
    
    def get_history(self, agent_id: str, last_n: int = 10) -> List[Dict[str, Any]]:
        """Get conversation history"""
        memory = self.get_agent_memory(agent_id)
        variables = memory.load_memory_variables({})
        
        messages = variables.get("chat_history", [])
        return [self._message_to_dict(msg) for msg in messages[-last_n:]]
    
    def clear_agent_memory(self, agent_id: str):
        """Clear memory for specific agent"""
        if agent_id in self.agent_memories:
            self.agent_memories[agent_id].clear()
            
        # Delete file
        filepath = self.memory_dir / f"{agent_id}_memory.json"
        if filepath.exists():
            filepath.unlink()
    
    def _load_from_file(self, agent_id: str, memory: CustomConversationMemory):
        """Load memory from JSON file"""
        filepath = self.memory_dir / f"{agent_id}_memory.json"
        
        if not filepath.exists():
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Reconstruct messages
            for interaction in data.get("interactions", []):
                memory.save_context(
                    {"input": interaction["input"]},
                    {"output": interaction["output"]}
                )
            
            self.logger.info(f"Loaded {len(data.get('interactions', []))} interactions for {agent_id}")
        except Exception as e:
            self.logger.error(f"Failed to load memory for {agent_id}: {e}")
    
    def _persist_to_file(self, agent_id: str, memory: CustomConversationMemory):
        """Persist memory to JSON file"""
        filepath = self.memory_dir / f"{agent_id}_memory.json"
        
        try:
            variables = memory.load_memory_variables({})
            messages = variables.get("chat_history", [])
            
            # Convert to serializable format
            interactions = []
            for i in range(0, len(messages), 2):
                if i + 1 < len(messages):
                    msg1 = messages[i]
                    msg2 = messages[i+1]
                    
                    # Handle both dict and object formats
                    input_content = msg1.get("content", str(msg1)) if isinstance(msg1, dict) else getattr(msg1, "content", str(msg1))
                    output_content = msg2.get("content", str(msg2)) if isinstance(msg2, dict) else getattr(msg2, "content", str(msg2))
                    
                    interactions.append({
                        "input": input_content,
                        "output": output_content,
                        "timestamp": datetime.utcnow().isoformat()
                    })
            
            data = {
                "agent_id": agent_id,
                "last_updated": datetime.utcnow().isoformat(),
                "interaction_count": len(interactions),
                "interactions": interactions
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to persist memory for {agent_id}: {e}")
    
    @staticmethod
    def _message_to_dict(message) -> Dict[str, Any]:
        """Convert LangChain message to dict"""
        if isinstance(message, dict):
            return {
                "type": message.get("type", "Unknown"),
                "content": message.get("content", str(message)),
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            return {
                "type": message.__class__.__name__,
                "content": getattr(message, "content", str(message)),
                "timestamp": datetime.utcnow().isoformat()
            }

# Global memory manager instance
_memory_manager: Optional[HybridMemoryManager] = None

def get_memory_manager() -> HybridMemoryManager:
    """Get global memory manager instance"""
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = HybridMemoryManager()
    return _memory_manager
