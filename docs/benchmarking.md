# Benchmarking Guide

This guide explains how to reproduce the experimental results from the thesis.

## Available Benchmarks

1. **TTP Extraction** (vs IntelEx baseline)
2. **Rule Quality** (LLM Judge evaluation)
3. **SIEM Detection Rate**

---

## 1. TTP Extraction Benchmark

Compares extraction performance against IntelEx ground truth dataset.

### Dataset

- **Source**: IntelEx CTI dataset (5 reports)
- **Location**: `data/datasets/intelex_gt/`
- **Ground Truth**: `data/datasets/intelex_gt/intelex_ground_truth.json`

### Run Benchmark

```bash
python scripts/run_intelex_benchmark.py
```

### Output

```
Precision: 0.96
Recall: 0.81
F1-Score: 0.87

Per-report results saved to: benchmark_results/intelex_comparison/
```

### Metrics Explanation

- **Precision**: TP / (TP + FP) - Accuracy of extracted TTPs
- **Recall**: TP / (TP + FN) - Coverage of ground truth TTPs
- **F1-Score**: Harmonic mean of precision and recall

---

## 2. Rule Quality Benchmark

Evaluates generated rules using LLM-as-a-Judge.

### Configuration

Edit `config/benchmark_config.yaml`:

```yaml
rule_quality:
  llm_judge_model: llama-3.3-70b
  criteria:
    - accuracy
    - completeness
    - efficiency
    - maintainability
```

### Run Benchmark

```bash
python scripts/benchmark_runner.py --config config/benchmark_config.yaml
```

### Results

```
Average Quality Score: 0.83/1.0

Criteria Breakdown:
- Accuracy: 0.87
- Completeness: 0.81
- Efficiency: 0.80
- Maintainability: 0.84
```

---

## 3. SIEM Detection Rate

Tests rule effectiveness in Splunk environment.

### Prerequisites

- Splunk Enterprise running
- SSH access to Windows test machine
- Configure credentials in `.env`

### Run Verification

```bash
python scripts/run_agents.py --report data/datasets/sample_report.txt --verify-siem
```

### Metrics

- **Detection Rate**: % of rules that successfully detected simulated attacks
- **False Positive Rate**: % of rules triggering on baseline traffic
- **Query Time**: Average SIEM query execution time

---

## Reproducing Published Results

### Full Benchmark Suite

```bash
# 1. TTP Extraction
python scripts/run_intelex_benchmark.py

# 2. Rule Generation
python scripts/benchmark_runner.py

# 3. Generate charts
python scripts/generate_thesis_charts.py

# 4. Aggregate statistics
python scripts/aggregate_thesis_data.py
```

**Output**: `benchmark_results/thesis_final/`

### Expected Results

| Metric | Value |
|--------|-------|
| TTP F1-Score | 0.87 |
| Rule Quality Score | 0.83 |
| SIEM Detection Rate | 92% |
| False Positive Rate | <5% |

---

## Custom Benchmarks

### Create Custom Dataset

```json
{
  "reports": [
    {
      "id": "custom_001",
      "content": "Report text...",
      "ground_truth_ttps": [
        {
          "technique_id": "T1003.001",
          "technique_name": "LSASS Memory"
        }
      ]
    }
  ]
}
```

### Run Custom Benchmark

```python
from benchmark.evaluator import BenchmarkEvaluator

evaluator = BenchmarkEvaluator()
results = await evaluator.run_benchmark(
    dataset_path="path/to/custom_dataset.json",
    output_dir="benchmark_results/custom/"
)
```

---

## Performance Profiling

### Enable Profiling

```bash
python -m cProfile -o profile.stats scripts/run_agents.py
```

### Analyze Results

```python
import pstats
stats = pstats.Stats('profile.stats')
stats.sort_stats('cumulative')
stats.print_stats(20)
```

---

## Troubleshooting Benchmarks

**Low recall on IntelEx dataset**
- Check NLP preprocessing configuration
- Verify MITRE ATT&CK database is v14.1
- Increase LLM temperature slightly

**SIEM verification failures**
- Ensure Splunk has indexed recent logs
- Check SSH connectivity to test machine
- Verify attack commands executed successfully

**Inconsistent results across runs**
- Set fixed random seed: `RANDOM_SEED=42`
- Use deterministic LLM settings (temperature=0)
- Clear ChromaDB cache between runs
