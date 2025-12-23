"""
Base Benchmark Framework for Multi-Agent SIEM Evaluation
Provides foundation for evaluating agent outputs using LLM-as-Judge
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import uuid


class MetricCategory(Enum):
    """Categories of evaluation metrics"""
    CORRECTNESS = "correctness"
    QUALITY = "quality"
    SAFETY = "safety"
    EFFECTIVENESS = "effectiveness"
    REALISM = "realism"
    DETECTABILITY = "detectability"


@dataclass
class BenchmarkMetric:
    """Individual benchmark metric"""
    name: str
    category: MetricCategory
    description: str
    weight: float = 1.0
    min_score: float = 0.0
    max_score: float = 1.0
    
    def normalize_score(self, score: float) -> float:
        """Normalize score to [0, 1] range"""
        if score < self.min_score:
            return 0.0
        if score > self.max_score:
            return 1.0
        return (score - self.min_score) / (self.max_score - self.min_score)


@dataclass
class EvaluationResult:
    """Result of a single evaluation"""
    metric_name: str
    score: float
    normalized_score: float
    explanation: str
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkResult:
    """Complete benchmark result for an item"""
    benchmark_id: str
    item_id: str
    item_type: str
    overall_score: float
    category_scores: Dict[str, float]
    metric_results: List[EvaluationResult]
    summary: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "benchmark_id": self.benchmark_id,
            "item_id": self.item_id,
            "item_type": self.item_type,
            "overall_score": self.overall_score,
            "category_scores": self.category_scores,
            "metric_results": [
                {
                    "metric_name": r.metric_name,
                    "score": r.score,
                    "normalized_score": r.normalized_score,
                    "explanation": r.explanation,
                    "confidence": r.confidence,
                    "timestamp": r.timestamp,
                    "metadata": r.metadata
                }
                for r in self.metric_results
            ],
            "summary": self.summary,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


class BaseBenchmark(ABC):
    """
    Abstract base class for benchmarks.
    
    All agent-specific benchmarks should inherit from this.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.benchmark_id = str(uuid.uuid4())
        self.metrics: List[BenchmarkMetric] = []
        self.results: List[BenchmarkResult] = []
        
        # LLM Judge configuration
        self.llm_judge_config = config.get("llm_judge", {})
        self.use_llm_judge = self.llm_judge_config.get("enabled", True)
        
        # Initialize metrics
        self._initialize_metrics()
    
    @abstractmethod
    def _initialize_metrics(self) -> None:
        """Initialize benchmark metrics - must be implemented by subclasses"""
        pass
    
    @abstractmethod
    async def evaluate_item(self, item: Dict[str, Any]) -> BenchmarkResult:
        """
        Evaluate a single item.
        
        Args:
            item: Item to evaluate
            
        Returns:
            BenchmarkResult with scores and analysis
        """
        pass
    
    async def evaluate_batch(self, items: List[Dict[str, Any]]) -> List[BenchmarkResult]:
        """
        Evaluate multiple items.
        
        Args:
            items: List of items to evaluate
            
        Returns:
            List of BenchmarkResults
        """
        results = []
        for item in items:
            result = await self.evaluate_item(item)
            results.append(result)
            self.results.append(result)
        
        return results
    
    def get_metric_by_name(self, name: str) -> Optional[BenchmarkMetric]:
        """Get metric by name"""
        for metric in self.metrics:
            if metric.name == name:
                return metric
        return None
    
    def calculate_overall_score(
        self, 
        metric_results: List[EvaluationResult]
    ) -> float:
        """
        Calculate weighted overall score from metric results.
        
        Args:
            metric_results: List of evaluation results
            
        Returns:
            Overall weighted score
        """
        total_weight = 0.0
        weighted_sum = 0.0
        
        for result in metric_results:
            metric = self.get_metric_by_name(result.metric_name)
            if metric:
                weighted_sum += result.normalized_score * metric.weight
                total_weight += metric.weight
        
        if total_weight == 0:
            return 0.0
        
        return weighted_sum / total_weight
    
    def calculate_category_scores(
        self, 
        metric_results: List[EvaluationResult]
    ) -> Dict[str, float]:
        """
        Calculate scores by category.
        
        Args:
            metric_results: List of evaluation results
            
        Returns:
            Dictionary mapping category to score
        """
        category_scores = {}
        category_weights = {}
        
        for result in metric_results:
            metric = self.get_metric_by_name(result.metric_name)
            if metric:
                category = metric.category.value
                
                if category not in category_scores:
                    category_scores[category] = 0.0
                    category_weights[category] = 0.0
                
                category_scores[category] += result.normalized_score * metric.weight
                category_weights[category] += metric.weight
        
        # Normalize by weights
        for category in category_scores:
            if category_weights[category] > 0:
                category_scores[category] /= category_weights[category]
        
        return category_scores
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get benchmark statistics"""
        if not self.results:
            return {
                "total_evaluations": 0,
                "average_score": 0.0,
                "category_averages": {},
                "metric_averages": {}
            }
        
        # Calculate averages
        total_score = sum(r.overall_score for r in self.results)
        avg_score = total_score / len(self.results)
        
        # Category averages
        category_totals = {}
        category_counts = {}
        
        for result in self.results:
            for category, score in result.category_scores.items():
                if category not in category_totals:
                    category_totals[category] = 0.0
                    category_counts[category] = 0
                
                category_totals[category] += score
                category_counts[category] += 1
        
        category_averages = {
            cat: category_totals[cat] / category_counts[cat]
            for cat in category_totals
        }
        
        # Metric averages
        metric_totals = {}
        metric_counts = {}
        
        for result in self.results:
            for metric_result in result.metric_results:
                name = metric_result.metric_name
                if name not in metric_totals:
                    metric_totals[name] = 0.0
                    metric_counts[name] = 0
                
                metric_totals[name] += metric_result.normalized_score
                metric_counts[name] += 1
        
        metric_averages = {
            name: metric_totals[name] / metric_counts[name]
            for name in metric_totals
        }
        
        return {
            "total_evaluations": len(self.results),
            "average_score": avg_score,
            "category_averages": category_averages,
            "metric_averages": metric_averages,
            "score_distribution": self._calculate_score_distribution()
        }
    
    def _calculate_score_distribution(self) -> Dict[str, int]:
        """Calculate distribution of scores"""
        distribution = {
            "excellent (>=0.9)": 0,
            "good (0.8-0.9)": 0,
            "fair (0.7-0.8)": 0,
            "poor (0.6-0.7)": 0,
            "failing (<0.6)": 0
        }
        
        for result in self.results:
            score = result.overall_score
            if score >= 0.9:
                distribution["excellent (>=0.9)"] += 1
            elif score >= 0.8:
                distribution["good (0.8-0.9)"] += 1
            elif score >= 0.7:
                distribution["fair (0.7-0.8)"] += 1
            elif score >= 0.6:
                distribution["poor (0.6-0.7)"] += 1
            else:
                distribution["failing (<0.6)"] += 1
        
        return distribution
    
    def export_results(self, filepath: str) -> None:
        """Export results to JSON file"""
        
        # Sanitize config to remove secrets
        sanitized_config = self._sanitize_config(self.config)
        
        output = {
            "benchmark_id": self.benchmark_id,
            "timestamp": datetime.utcnow().isoformat(),
            "config": sanitized_config,
            "statistics": self.get_statistics(),
            "results": [r.to_dict() for r in self.results]
        }
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)

    def _sanitize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize configuration dictionary"""
        if not isinstance(config, dict):
            return config
            
        clean_config = {}
        for k, v in config.items():
            if "api_key" in k.lower() or "secret" in k.lower() or "token" in k.lower():
                clean_config[k] = "<REDACTED>"
            elif isinstance(v, dict):
                clean_config[k] = self._sanitize_config(v)
            elif isinstance(v, list):
                clean_config[k] = [self._sanitize_config(i) if isinstance(i, dict) else i for i in v]
            else:
                clean_config[k] = v
                
        return clean_config
    
    def get_top_performers(self, n: int = 10) -> List[BenchmarkResult]:
        """Get top N performing items"""
        sorted_results = sorted(
            self.results, 
            key=lambda r: r.overall_score, 
            reverse=True
        )
        return sorted_results[:n]
    
    def get_bottom_performers(self, n: int = 10) -> List[BenchmarkResult]:
        """Get bottom N performing items"""
        sorted_results = sorted(
            self.results, 
            key=lambda r: r.overall_score
        )
        return sorted_results[:n]
    
    def get_results_by_category(
        self, 
        category: MetricCategory, 
        min_score: float = 0.0
    ) -> List[BenchmarkResult]:
        """Get results filtered by category score"""
        filtered = []
        
        for result in self.results:
            category_score = result.category_scores.get(category.value, 0.0)
            if category_score >= min_score:
                filtered.append(result)
        
        return sorted(filtered, key=lambda r: r.category_scores.get(category.value, 0.0), reverse=True)