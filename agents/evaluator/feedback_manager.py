# agents/evaluator/feedback_manager.py
"""
Feedback Manager với Custom Memory Integration
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
from datetime import datetime
from core.memory import get_memory_manager
from core.logging import get_agent_logger


class CustomConversationBufferWindowMemory:
    """
    Custom windowed conversation memory for feedback history
    Maintains limited history to prevent memory bloat
    """
    def __init__(self, k: int = 5, memory_key: str = "feedback_history", return_messages: bool = True):
        self.k = k  # Window size
        self.memory_key = memory_key
        self.return_messages = return_messages
        self.chat_history: List[Dict[str, Any]] = []
    
    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]):
        """Save context to memory with window limit"""
        interaction = {
            "input": inputs.get("evaluation", ""),
            "output": outputs.get("feedback", ""),
            "timestamp": datetime.utcnow().isoformat()
        }
        self.chat_history.append(interaction)
        
        # Maintain window size
        if len(self.chat_history) > self.k:
            self.chat_history = self.chat_history[-self.k:]
    
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


class FeedbackManager:
    """
    Manages feedback loop với memory support
    """
    def __init__(self, feedback_dir: str = "data/feedback/"):
        self.feedback_dir = Path(feedback_dir)
        self.feedback_dir.mkdir(parents=True, exist_ok=True)
        self.memory_manager = get_memory_manager()
        self.logger = get_agent_logger("feedback_manager")
        
        # Window memory cho recent feedback (chỉ giữ 5 iterations gần nhất)
        self.feedback_memory = CustomConversationBufferWindowMemory(
            k=5,
            memory_key="feedback_history",
            return_messages=True
        )
    
    def generate_feedback(self, 
                         evaluation: Dict[str, Any],
                         agent_id: str = "rulegen") -> Dict[str, Any]:
        """
        Generate feedback từ evaluation results
        Sử dụng history để identify patterns
        """
        # Load feedback history
        history = self.get_feedback_history(agent_id, last_n=3)
        
        feedback = {
            "timestamp": datetime.utcnow().isoformat(),
            "iteration": len(history) + 1,
            "evaluation_score": evaluation.get("overall_score", 0),
            "improvements_needed": [],
            "strengths": [],
            "patterns": self._identify_patterns(history),
            "actionable_suggestions": []
        }
        
        # Analyze metrics
        for metric_name, metric_value in evaluation.get("metrics", {}).items():
            if isinstance(metric_value, (int, float)):
                if metric_value < 0.7:
                    feedback["improvements_needed"].append({
                        "metric": metric_name,
                        "current_score": metric_value,
                        "target_score": 0.85,
                        "suggestion": self._get_improvement_suggestion(
                            metric_name, metric_value, history
                        )
                    })
                elif metric_value > 0.85:
                    feedback["strengths"].append(metric_name)
        
        # Generate actionable suggestions
        feedback["actionable_suggestions"] = self._generate_suggestions(
            evaluation, history
        )
        
        # Save to memory
        self.feedback_memory.save_context(
            {"evaluation": json.dumps(evaluation)},
            {"feedback": json.dumps(feedback)}
        )
        
        return feedback
    
    def write_feedback(self, agent_name: str, feedback: Dict[str, Any]):
        """Write feedback to file (backward compatible)"""
        filepath = self.feedback_dir / f"{agent_name}_feedback.json"
        
        # Load existing
        existing = []
        if filepath.exists():
            with open(filepath, 'r') as f:
                existing = json.load(f)
        
        # Append new
        existing.append(feedback)
        
        # Keep last 20 feedbacks
        if len(existing) > 20:
            existing = existing[-20:]
        
        # Write
        with open(filepath, 'w') as f:
            json.dump(existing, f, indent=2)
        
        self.logger.info(f"Feedback written for {agent_name}")
    
    def get_feedback_history(self, agent_id: str, last_n: int = 5) -> List[Dict]:
        """Get recent feedback history"""
        filepath = self.feedback_dir / f"{agent_id}_feedback.json"
        
        if not filepath.exists():
            return []
        
        with open(filepath, 'r') as f:
            all_feedback = json.load(f)
        
        return all_feedback[-last_n:]
    
    def _identify_patterns(self, history: List[Dict]) -> List[str]:
        """Identify recurring patterns in feedback history"""
        if len(history) < 2:
            return []
        
        patterns = []
        
        # Check for recurring issues
        recurring_issues = {}
        for fb in history:
            for improvement in fb.get("improvements_needed", []):
                metric = improvement["metric"]
                recurring_issues[metric] = recurring_issues.get(metric, 0) + 1
        
        for metric, count in recurring_issues.items():
            if count >= 2:
                patterns.append(f"Recurring issue with {metric} ({count} times)")
        
        # Check for score trends
        scores = [fb.get("evaluation_score", 0) for fb in history]
        if len(scores) >= 3:
            if all(scores[i] < scores[i-1] for i in range(1, len(scores))):
                patterns.append("Declining performance trend")
            elif all(scores[i] > scores[i-1] for i in range(1, len(scores))):
                patterns.append("Improving performance trend")
        
        return patterns
    
    def _get_improvement_suggestion(self, 
                                   metric_name: str, 
                                   score: float,
                                   history: List[Dict]) -> str:
        """Get improvement suggestion based on metric and history"""
        suggestions_map = {
            "accuracy": "Review detection logic and ensure coverage of edge cases",
            "false_positive_rate": "Tighten rule conditions to reduce false matches",
            "detection_coverage": "Expand rule patterns to cover more attack variants",
            "performance": "Optimize rule complexity and reduce regex overhead"
        }
        
        base_suggestion = suggestions_map.get(
            metric_name.lower(), 
            f"Focus on improving {metric_name}"
        )
        
        # Add context from history
        if history:
            last_feedback = history[-1]
            if metric_name in [i["metric"] for i in last_feedback.get("improvements_needed", [])]:
                base_suggestion += " (Note: This was also flagged in previous iteration)"
        
        return base_suggestion
    
    def _generate_suggestions(self, 
                             evaluation: Dict[str, Any],
                             history: List[Dict]) -> List[str]:
        """Generate actionable suggestions"""
        suggestions = []
        
        score = evaluation.get("overall_score", 0)
        
        if score < 0.5:
            suggestions.append("Consider revising the TTP extraction prompt")
            suggestions.append("Review MITRE ATT&CK technique mappings")
        elif score < 0.7:
            suggestions.append("Fine-tune rule generation parameters")
            suggestions.append("Add more context from CTI reports")
        else:
            suggestions.append("Maintain current approach")
            suggestions.append("Consider A/B testing minor variations")
        
        # Pattern-based suggestions
        patterns = self._identify_patterns(history)
        if "Recurring issue" in str(patterns):
            suggestions.append("PRIORITY: Address recurring issues first")
        
        return suggestions
