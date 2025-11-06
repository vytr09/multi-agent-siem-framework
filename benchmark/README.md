# Benchmark Framework - Complete Guide

LLM-as-Judge evaluation framework for Multi-Agent SIEM outputs, inspired by academic research (CyberPal paper).

**Status:**
- **AttackGen Benchmark** - Fully implemented
- **RuleGen Benchmark** - Fully implemented

---

## Table of Contents

1. [Quick Start](#-quick-start)
2. [Overview](#-overview)
3. [Architecture](#-architecture)
4. [Evaluation Metrics](#-evaluation-metrics)
5. [Usage Examples](#-usage-examples)
6. [Configuration](#-configuration)
7. [Output Format](#-output-format)
8. [Advanced Features](#-advanced-features)
9. [Troubleshooting](#-troubleshooting)

---

## Quick Start

### 1. Setup

```bash
# Set your Gemini API key
export GEMINI_API_KEY='your-api-key-here'

# Or add to .env file
echo "GEMINI_API_KEY=your-api-key-here" >> .env
```

### 2. Run AttackGen Benchmark (Test Sample - Fast)

```bash
# Evaluate 3 sample commands (recommended for testing)
cd tests/benchmark
python run_attackgen_benchmark.py
```

**Output:**
- Evaluates 3 diverse commands
- Takes ~30-60 seconds
- Perfect for testing and development

### 3. Run Full AttackGen Benchmark

```bash
# Evaluate all 15 commands
USE_FULL_RESULTS=true python run_attackgen_benchmark.py
```

**Output:**
- Evaluates all commands
- Takes ~3-5 minutes
- Comprehensive statistics

### 4. Run RuleGen Benchmark

```bash
# Evaluate detection rules
cd tests/benchmark
python test_rulegen_benchmark.py
```

**Output:**
- Evaluates all generated detection rules
- Analyzes Sigma rules and platform conversions
- Takes ~2-4 minutes
- Provides actionable recommendations

---

## Overview

This benchmark framework evaluates agent-generated outputs across multiple dimensions:

### AttackGen Evaluation
- **Technical Correctness**: Syntax, logic, and accuracy
- **Quality**: Documentation, completeness, and clarity
- **Safety**: Testing safety and controlled impact
- **Effectiveness**: Operational viability and usefulness
- **Realism**: Resemblance to real-world techniques
- **Detectability**: Value for detection engineering

### RuleGen Evaluation
- **Correctness**: Sigma completeness, detection logic, platform syntax
- **Quality**: Detection specificity, sensitivity, metadata richness
- **Effectiveness**: Attack coverage, false positive resistance
- **Realism**: Operational deployability, performance efficiency
- **Detectability**: Evasion resistance, multi-stage detection

### Key Features

- **Hybrid Evaluation**: Combines LLM-as-Judge with rule-based checks
- **Multi-Dimensional**: 11 metrics (AttackGen) + 15 metrics (RuleGen)
- **Detailed Feedback**: Explanations, strengths, weaknesses
- **Confidence Scoring**: Reliability indicators
- **Comparative Analysis**: Side-by-side comparison
- **Export & Analytics**: JSON export with statistics
- **Actionable Recommendations**: Improvement suggestions for RuleGen

---

## Architecture

```
benchmark/
├── benchmark_base.py         # Base framework (abstract classes)
├── llm_judge.py               # LLM-as-Judge evaluator (Gemini)
├── attackgen_benchmark.py     # AttackGen-specific benchmark
└── rulegen_benchmark.py       # RuleGen-specific benchmark

tests/benchmark/
├── run_attackgen_benchmark.py # AttackGen test script
├── test_rulegen_benchmark.py  # RuleGen test script
└── debug_paths.py             # Path debugging tool

data/
├── attackgen/
│   ├── test_sample.json       # 3 commands for testing
│   └── real_attackgen_results.json  # Full results (15 commands)
├── generated_rules/
│   └── rulegen_llm_output.json # RuleGen agent output
└── benchmark_results/         # Exported results
```

### Components

**1. BaseBenchmark** - Abstract base class
- Metric management
- Score calculation
- Statistics tracking
- Result export

**2. LLMJudge** - Gemini-based evaluator
- Structured prompt engineering
- Multi-criteria evaluation
- Comparative analysis
- Confidence scoring

**3. AttackGenBenchmark** - AttackGen implementation
- 11 evaluation metrics
- Hybrid LLM + rule-based evaluation
- Detailed scoring breakdowns

**4. RuleGenBenchmark** - RuleGen implementation
- 15 evaluation metrics
- Sigma rule quality assessment
- Platform conversion validation
- Actionable recommendations

---

## Evaluation Metrics

### AttackGen Metrics (11 Total)

| Metric | Category | Weight | Type | Description |
|--------|----------|--------|------|-------------|
| **technical_correctness** | Correctness | 2.0 | LLM | Command syntax, logic, technical accuracy |
| **attack_alignment** | Correctness | 1.5 | LLM | Alignment with MITRE ATT&CK technique |
| **platform_compatibility** | Correctness | 1.5 | Rule | Compatibility with target platform |
| **operational_realism** | Realism | 2.0 | LLM | Resemblance to real-world attacks |
| **threat_actor_alignment** | Realism | 1.0 | LLM | Alignment with known threat actor TTPs |
| **testing_safety** | Safety | 2.5 | LLM | Safety for test environments |
| **controlled_impact** | Safety | 1.5 | Rule | Predictable and controllable effects |
| **detection_value** | Detectability | 1.5 | LLM | Value for detection rule creation |
| **artifact_generation** | Detectability | 1.0 | Rule | Quality of detection artifacts |
| **completeness** | Effectiveness | 1.5 | Rule | Implementation completeness |
| **documentation_quality** | Effectiveness | 1.0 | LLM | Documentation and explanation quality |

### RuleGen Metrics (15 Total)

| Metric | Category | Weight | Type | Description |
|--------|----------|--------|------|-------------|
| **sigma_completeness** | Correctness | 2.0 | Rule | All required Sigma fields present |
| **detection_logic_correctness** | Correctness | 3.0 | LLM | Detection logic correctly identifies TTP |
| **platform_syntax_correctness** | Correctness | 2.0 | Rule/LLM | Platform queries have valid syntax |
| **field_mapping_accuracy** | Correctness | 2.0 | LLM | Field mappings accurate for platforms |
| **detection_specificity** | Quality | 3.0 | LLM | Minimizes false positives |
| **detection_sensitivity** | Quality | 2.5 | LLM | Catches attack variations |
| **metadata_richness** | Quality | 1.5 | Rule/LLM | Comprehensive metadata included |
| **optimization_level** | Quality | 1.5 | LLM | Query performance optimization |
| **attack_coverage** | Effectiveness | 3.0 | LLM | Covers relevant attack techniques |
| **false_positive_resistance** | Effectiveness | 2.5 | LLM | Includes FP reduction filters |
| **contextual_awareness** | Effectiveness | 2.0 | LLM | Considers threat actor TTPs |
| **operational_deployability** | Realism | 2.5 | LLM | Ready for production SIEM |
| **performance_efficiency** | Realism | 2.0 | LLM | Efficient query execution |
| **analyst_actionability** | Realism | 2.0 | LLM | Provides actionable alerts |
| **evasion_resistance** | Detectability | 2.5 | LLM | Robust against evasion |
| **multi_stage_detection** | Detectability | 2.0 | LLM | Detects multiple attack stages |

### Scoring System

- **Raw Score**: 0-10 for each metric
- **Normalized Score**: 0-1 for weighted calculation
- **Overall Score**: Weighted average of all metrics
- **Category Scores**: Average by category

**Score Interpretation**:
- ≥0.9: Excellent (Production-ready)
- 0.8-0.9: Good (Minor improvements)
- 0.7-0.8: Fair (Needs work)
- 0.6-0.7: Poor (Significant issues)
- <0.6: Failing (Major problems)

---

## Usage Examples

### Example 1: Quick AttackGen Test

```bash
# Test with sample data (3 commands)
cd tests/benchmark
python run_attackgen_benchmark.py
```

### Example 2: RuleGen Evaluation

```bash
# Evaluate detection rules
cd tests/benchmark
python test_rulegen_benchmark.py
```

### Example 3: Programmatic AttackGen Evaluation

```python
import asyncio
from benchmark.attackgen_benchmark import AttackGenBenchmark

async def evaluate():
    # Configure
    config = {
        "llm_judge": {
            "enabled": True,
            "api_key": "your-key",
            "model": "gemini-2.0-flash-lite",
            "temperature": 0.3
        }
    }
    
    # Initialize
    benchmark = AttackGenBenchmark(config)
    
    # Evaluate single command
    command = {
        "command_id": "cmd-001",
        "name": "PowerShell Execution",
        "command": "powershell.exe -enc ...",
        "explanation": "Executes encoded PowerShell",
        "platform": "windows",
        "mitre_attack_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "indicators": ["PowerShell execution", "Network connection"],
        "prerequisites": ["PowerShell installed"],
        "cleanup": "Stop-Process -Name powershell",
        "confidence_score": 0.85,
        "source": "gemini_llm"
    }
    
    result = await benchmark.evaluate_item(command)
    benchmark.results.append(result)
    
    print(f"Overall Score: {result.overall_score:.3f}")
    print(f"Category Scores: {result.category_scores}")
    
    # Get statistics
    stats = benchmark.get_statistics()
    print(f"Average Score: {stats['average_score']:.3f}")

asyncio.run(evaluate())
```

### Example 4: Programmatic RuleGen Evaluation

```python
import asyncio
import json
from benchmark.rulegen_benchmark import RuleGenBenchmark

async def evaluate_rules():
    # Load rules
    with open("data/generated_rules/rulegen_llm_output.json") as f:
        data = json.load(f)
    
    rules = data["rule_generation_results"]
    
    # Configure
    config = {
        "platforms": ["splunk", "elasticsearch"],
        "evaluate_sigma": True,
        "evaluate_platforms": True,
        "syntactic_validation": True,
        "llm_judge": {
            "enabled": True,
            "api_key": "your-key",
            "model": "gemini-2.0-flash-lite",
            "temperature": 0.3
        }
    }
    
    # Initialize and evaluate
    benchmark = RuleGenBenchmark(config)
    results = await benchmark.evaluate_batch(rules)
    
    # Export with recommendations
    benchmark.export_results_with_recommendations(
        "results/rulegen_evaluation.json"
    )
    
    # Analyze
    stats = benchmark.get_statistics()
    print(f"Average Score: {stats['average_score']:.3f}")
    print(f"Recommendations: {len(benchmark._generate_aggregate_recommendations())}")

asyncio.run(evaluate_rules())
```

### Example 5: Batch Evaluation

```python
import json
from pathlib import Path

async def batch_evaluate():
    # Load commands
    with open("data/attackgen/test_sample.json") as f:
        data = json.load(f)
    
    commands = data["execution_result"]["attack_commands"]
    
    # Initialize benchmark
    benchmark = AttackGenBenchmark(config)
    
    # Evaluate all
    for command in commands:
        result = await benchmark.evaluate_item(command)
        benchmark.results.append(result)
    
    # Export results
    benchmark.export_results("results/my_benchmark.json")
    
    # Analyze
    stats = benchmark.get_statistics()
    top_5 = benchmark.get_top_performers(n=5)
    
    print(f"Average: {stats['average_score']:.3f}")
    for i, result in enumerate(top_5, 1):
        print(f"{i}. {result.metadata['technique_name']}: {result.overall_score:.3f}")

asyncio.run(batch_evaluate())
```

---

## Configuration

### Basic Configuration (AttackGen)

```python
config = {
    "llm_judge": {
        "enabled": True,
        "api_key": "...",
        "model": "gemini-2.0-flash-lite",
        "temperature": 0.3,
        "max_tokens": 2000,
        "persona": "expert cybersecurity researcher",
        "detailed_feedback": True,
        "confidence_scores": True
    }
}
```

### RuleGen Configuration

```python
config = {
    "platforms": ["splunk", "elasticsearch"],
    "evaluate_sigma": True,
    "evaluate_platforms": True,
    "syntactic_validation": True,
    "llm_judge": {
        "enabled": True,
        "api_key": "...",
        "model": "gemini-2.0-flash-lite",
        "temperature": 0.3,
        "max_tokens": 2000,
        "persona": "expert SIEM engineer and threat detection specialist",
        "detailed_feedback": True,
        "confidence_scores": True
    }
}
```

### Environment Variables

```bash
# Required
GEMINI_API_KEY=your-api-key

# Optional (for full AttackGen evaluation)
USE_FULL_RESULTS=true

# Optional model configuration
BENCHMARK_MODEL=gemini-2.0-flash-lite
BENCHMARK_TEMPERATURE=0.3
BENCHMARK_MAX_TOKENS=2000
```

### Advanced Configuration

See `config/benchmark_config.yaml` for full options:
- Custom metric weights
- Rate limiting
- Retry policies
- Export settings

---

## Output Format

### Console Output (AttackGen)

```
ATTACKGEN AGENT BENCHMARK
================================================================================

Using TEST SAMPLE file (3 commands)
Loaded 3 commands

Evaluating 3 commands...

[1/3] Mimikatz - Dump LSASS Credentials (Simulated)
Overall Score: 0.891

   Results:
      Overall Score: 0.891
      Category Scores:
         • correctness: 0.840
         • safety: 0.938
         • effectiveness: 1.000
         • realism: 0.800
         • detectability: 0.880

BENCHMARK STATISTICS
Total Evaluations: 3
Average Score: 0.842

Category Averages:
   • effectiveness: 0.973
   • safety: 0.979
   • correctness: 0.765
   • detectability: 0.760
   • realism: 0.700

TOP PERFORMERS:
1. OS Credential Dumping - Score: 0.891
```

### Console Output (RuleGen)

```
RULEGEN BENCHMARK EVALUATION
================================================================================

Loading RuleGen output: data/generated_rules/rulegen_llm_output.json
   Found 3 rules to evaluate

Initializing RuleGen Benchmark...
   - Initialized with 15 metrics
   - LLM Judge: Enabled

Starting evaluation...

EVALUATION RESULTS
================================================================================

Overall Statistics:
   Total Evaluations:     3
   Average Score:         0.886/1.0 (Good)

Category Averages:
   correctness          0.954 
   quality              0.300 

Metric Averages (Top 10):
   sigma_completeness              1.000 
   platform_syntax_correctness     1.000 
   detection_logic_correctness     0.800 
   metadata_richness               0.300 

Top 3 Rules:
   1. T1059.001     Score: 0.886 - PowerShell
   2. T1003         Score: 0.886 - OS Credential Dumping
   3. T1566.001     Score: 0.886 - Spearphishing Attachment

Bottom 3 Rules (Need Improvement):
   (All rules scored in Good range)

BENCHMARK COMPLETE
Detailed results saved to: data/benchmark/rulegen_benchmark_results.json
```

### JSON Export (AttackGen)

```json
{
  "benchmark_id": "uuid",
  "timestamp": "2025-11-03T23:00:00Z",
  "configuration": {
    "model": "gemini-2.0-flash-lite",
    "temperature": 0.3
  },
  "statistics": {
    "total_evaluations": 3,
    "average_score": 0.842,
    "category_averages": {
      "correctness": 0.765,
      "realism": 0.700,
      "safety": 0.979,
      "detectability": 0.760,
      "effectiveness": 0.973
    },
    "score_distribution": {
      "excellent (>=0.9)": 1,
      "good (0.8-0.9)": 1,
      "fair (0.7-0.8)": 1
    }
  },
  "results": [...]
}
```

### JSON Export (RuleGen)

```json
{
  "benchmark_id": "uuid",
  "timestamp": "2025-11-04T14:50:09.991236",
  "config": {
    "platforms": ["splunk", "elasticsearch"],
    "evaluate_sigma": true,
    "evaluate_platforms": true
  },
  "statistics": {
    "total_evaluations": 3,
    "average_score": 0.886,
    "category_averages": {
      "correctness": 0.954,
      "quality": 0.300
    },
    "metric_averages": {
      "sigma_completeness": 1.0,
      "detection_logic_correctness": 0.8,
      "metadata_richness": 0.3,
      "platform_syntax_correctness": 1.0
    }
  },
  "results": [...],
  "recommendations": [
    {
      "priority": "high",
      "metric": "metadata_richness",
      "issue": "Low average score (0.30) across all rules",
      "recommendation": "Include more context (threat actor, campaign, tools) in rule generation"
    }
  ]
}
```

---

## Advanced Features

### Comparative Evaluation

Compare two commands side-by-side:

```python
result = await benchmark.evaluate_comparison(
    command_a=cmd1,
    command_b=cmd2,
    criteria="overall quality"
)

print(result['preference'])  # "A", "B", or "neutral"
print(result['reasoning'])
```

### Top/Bottom Performers

```python
# Get best commands/rules
top_10 = benchmark.get_top_performers(n=10)

# Get worst commands/rules
bottom_10 = benchmark.get_bottom_performers(n=10)

# Filter by category
from benchmark.benchmark_base import MetricCategory

safe_commands = benchmark.get_results_by_category(
    category=MetricCategory.SAFETY,
    min_score=0.85
)
```

### Statistics & Analytics

```python
stats = benchmark.get_statistics()

print(f"Total: {stats['total_evaluations']}")
print(f"Average: {stats['average_score']:.3f}")
print(f"Categories: {stats['category_averages']}")
print(f"Distribution: {stats['score_distribution']}")
```

### RuleGen Recommendations

```python
# Export results with actionable recommendations
benchmark.export_results_with_recommendations(
    "results/rulegen_with_recommendations.json"
)

# Get recommendations programmatically
recommendations = benchmark._generate_aggregate_recommendations()
for rec in recommendations:
    print(f"[{rec['priority'].upper()}] {rec['metric']}")
    print(f"  Issue: {rec['issue']}")
    print(f"  Fix: {rec['recommendation']}")
```

---

## Evaluation Methodology

### Hybrid Approach

**1. LLM-as-Judge** (AttackGen: 6 metrics, RuleGen: 11 metrics)
- Structured prompts with detailed criteria
- Multi-dimensional scoring (0-10)
- Natural language explanations
- Confidence scoring (0-1)
- Strengths & weaknesses identification

**2. Rule-Based** (AttackGen: 4 metrics, RuleGen: 4 metrics)
- Deterministic checks (syntax, completeness)
- Platform-specific validation
- Safety pattern detection
- Artifact quality assessment

### LLM Judge Prompting

**AttackGen:**
```
You are an expert cybersecurity researcher evaluating attack commands.

Evaluate against these criteria:
1. Technical correctness: Syntax validity, logic flow, tool usage
2. Attack alignment: Matches MITRE ATT&CK technique
3. Operational realism: Resembles real-world attacks
4. Testing safety: Safe for test environments
5. Detection value: Generates useful artifacts

Provide:
- Score (0-10)
- Detailed explanation
- Strengths (list)
- Weaknesses (list)
- Confidence (0-1)
```

**RuleGen:**
```
You are an expert SIEM engineer and threat detection specialist evaluating detection rules.

Evaluate against these criteria:
1. Detection logic correctness: Accurately identifies the TTP
2. Detection specificity: Minimizes false positives
3. Detection sensitivity: Catches attack variations
4. Operational deployability: Ready for production
5. Evasion resistance: Robust against common evasions

Provide:
- Score (0-10)
- Detailed explanation
- Strengths (list)
- Weaknesses (list)
- Confidence (0-1)
```

---

## Troubleshooting

### "GEMINI_API_KEY not set"

```bash
# Set in environment
export GEMINI_API_KEY='your-key'

# Or add to .env file
echo "GEMINI_API_KEY=your-key" >> .env
```

### "No commands found in results" (AttackGen)

Check your JSON structure:

```python
# Commands should be in execution_result
{
  "execution_result": {
    "attack_commands": [...]
  }
}
```

The script handles both root-level and nested structures automatically.

### "Output file not found" (RuleGen)

```bash
# Make sure RuleGen agent has run first
python agents/rulegen_agent.py

# Check the expected output location
ls data/generated_rules/rulegen_llm_output.json
```

### "ModuleNotFoundError: No module named 'benchmark'"

```bash
# Run from project root
cd /path/to/multi-agent-siem-framework
python tests/benchmark/run_attackgen_benchmark.py
# or
python tests/benchmark/test_rulegen_benchmark.py
```

### Low metadata_richness scores (RuleGen)

This is expected when LLM Judge is disabled. The heuristic fallback only checks for:
- Threat actor information
- Tools information
- Campaign information
- References

Enable LLM Judge for more comprehensive metadata evaluation.

### Debug Tools

```bash
# Check paths and configuration
cd tests/benchmark
python debug_paths.py
```

---

## API Reference

### AttackGenBenchmark

```python
class AttackGenBenchmark(BaseBenchmark):
    """AttackGen-specific benchmark implementation"""
    
    async def evaluate_item(self, item: Dict) -> BenchmarkResult:
        """Evaluate single command"""
        
    async def evaluate_batch(self, items: List[Dict]) -> List[BenchmarkResult]:
        """Evaluate multiple commands"""
        
    async def evaluate_comparison(self, command_a: Dict, command_b: Dict, 
                                  criteria: str) -> Dict:
        """Compare two commands"""
        
    def get_statistics(self) -> Dict:
        """Get benchmark statistics"""
        
    def get_top_performers(self, n: int = 10) -> List[BenchmarkResult]:
        """Get top N commands"""
        
    def get_bottom_performers(self, n: int = 10) -> List[BenchmarkResult]:
        """Get bottom N commands"""
        
    def export_results(self, filepath: str):
        """Export results to JSON"""
```

### RuleGenBenchmark

```python
class RuleGenBenchmark(BaseBenchmark):
    """RuleGen-specific benchmark implementation"""
    
    async def evaluate_item(self, item: Dict) -> BenchmarkResult:
        """Evaluate single detection rule"""
        
    async def evaluate_batch(self, items: List[Dict]) -> List[BenchmarkResult]:
        """Evaluate multiple detection rules"""
        
    async def _evaluate_sigma_rule(self, sigma_rule: Dict, ttp_info: Dict) -> List[EvaluationResult]:
        """Evaluate Sigma rule quality"""
        
    async def _evaluate_platform_rules(self, platform_rules: Dict, sigma_rule: Dict, 
                                       ttp_info: Dict) -> List[EvaluationResult]:
        """Evaluate platform-specific conversions"""
        
    def _validate_syntax(self, platform_rules: Dict) -> List[EvaluationResult]:
        """Perform syntactic validation"""
        
    def get_statistics(self) -> Dict:
        """Get benchmark statistics"""
        
    def export_results_with_recommendations(self, filepath: str):
        """Export results with actionable recommendations"""
        
    def _generate_aggregate_recommendations(self) -> List[Dict]:
        """Generate improvement recommendations"""
```

---

## Future Work

### Planned Features

- [ ] Multi-model ensemble evaluation
- [ ] Ground truth comparison
- [ ] Temporal analysis (improvement over time)
- [ ] Cross-agent benchmarking
- [ ] Automated regression testing
- [ ] Interactive visualization dashboard
- [ ] Batch processing optimization
- [ ] Custom metric plugins
- [ ] Integration testing for rule deployments
- [ ] Real-world alert simulation
- [ ] Performance benchmarking on production SIEMs

---

## References

**Methodology inspired by:**
- CyberPal Paper: LLM-as-Judge for cybersecurity evaluation
- MITRE ATT&CK Framework: Technique alignment
- Red team best practices: Operational realism
- Detection engineering: Artifact quality
- Sigma Rule Specification: Detection rule standards

**Related Documentation:**
- `config/benchmark_config.yaml` - Full configuration options
- `data/benchmark_results/` - Example outputs
- `tests/benchmark/` - Test scripts and examples
- `benchmark/rulegen_benchmark.py` - RuleGen implementation

---

## Contributing

### To add new AttackGen metrics:

1. Define metric in `AttackGenBenchmark._initialize_metrics()`
2. Implement evaluation in `_evaluate_with_llm()` or `_evaluate_with_rules()`
3. Add explanation generators
4. Update documentation

### To add new RuleGen metrics:

1. Define metric in `RuleGenBenchmark._initialize_metrics()`
2. Implement evaluation in:
   - `_evaluate_sigma_rule()` for Sigma-specific metrics
   - `_evaluate_platform_rules()` for platform-specific metrics
   - `_validate_syntax()` for syntax validation
3. Add recommendation logic in `_get_metric_recommendation()`
4. Update documentation

---

## License

Part of Multi-Agent SIEM Framework project.

---

**Last Updated**: 2025-11-05  
**Version**: 1.1.0  
**Maintainer**: Multi-Agent SIEM Team