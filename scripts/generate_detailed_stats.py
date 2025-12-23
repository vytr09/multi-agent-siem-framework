import os
import json
import glob
from datetime import datetime

RESULTS_DIR = r"d:\UIT\Nam_4\KLTN\Project\multi-agent-siem-framework\data\benchmark_results"

def load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return None

def analyze_extraction_results():
    pattern = os.path.join(RESULTS_DIR, "result_*.json")
    files = glob.glob(pattern)
    
    stats = {
        "total_files": 0,
        "total_ttps": 0,
        "extraction_methods": {},
        "confidence_scores": [],
        "tactics": {}
    }
    
    for p in files:
        data = load_json(p)
        if not data: continue
        stats["total_files"] += 1
        
        results = data.get("extraction", {}).get("extraction_results", [])
        
        for rep in results:
            ttps = rep.get("extracted_ttps", [])
            stats["total_ttps"] += len(ttps)
            
            for ttp in ttps:
                method = ttp.get("extraction_method", "unknown")
                stats["extraction_methods"][method] = stats["extraction_methods"].get(method, 0) + 1
                
                conf = ttp.get("confidence_score")
                if conf is not None:
                    stats["confidence_scores"].append(conf)
                    
                tactic = ttp.get("tactic", "unknown")
                stats["tactics"][tactic] = stats["tactics"].get(tactic, 0) + 1

    return stats

def analyze_quality_reports(type_prefix):
    pattern = os.path.join(RESULTS_DIR, f"quality_report_{type_prefix}_*.json")
    files = glob.glob(pattern)
    
    stats = {
        "total_reports": 0,
        "pass_count": 0,
        "fail_count": 0,
        "total_score_accum": 0.0,
        "metric_accum": {}, # key: score_sum
        "metric_counts": {}, # key: count
        "category_accum": {}, # key: score_sum
        "category_counts": {}, # key: count
        "feedback_strengths": {}, # key: count
        "feedback_weaknesses": {} # key: count
    }
    
    for p in files:
        data = load_json(p)
        if not data: continue
        stats["total_reports"] += 1
        
        # 1. Overall Statistics
        summ = data.get("statistics", {})
        
        # Try finding average score in 'average_overall_score' then 'average_score'
        score = summ.get("average_overall_score")
        if score is None: 
            score = summ.get("average_score", 0.0)
            
        stats["total_score_accum"] += score
        if score >= 0.6:
            stats["pass_count"] += 1
        else:
            stats["fail_count"] += 1
            
        # 2. Metric Averages
        metrics = summ.get("metric_averages", {})
        for k, v in metrics.items():
            stats["metric_accum"][k] = stats["metric_accum"].get(k, 0.0) + v
            stats["metric_counts"][k] = stats["metric_counts"].get(k, 0) + 1
            
        # 3. Category Averages (NEW)
        cats = summ.get("category_averages", {})
        for k, v in cats.items():
            stats["category_accum"][k] = stats["category_accum"].get(k, 0.0) + v
            stats["category_counts"][k] = stats["category_counts"].get(k, 0) + 1

        # 4. Qualitative Feedback (NEW: Strengths & Weaknesses)
        results = data.get("results", [])
        for item in results:
            metric_results = item.get("metric_results", [])
            for m_res in metric_results:
                meta = m_res.get("metadata", {})
                
                # Count Strengths
                for s in meta.get("strengths", []):
                    s_clean = s.strip().lower() # Normalize
                    stats["feedback_strengths"][s_clean] = stats["feedback_strengths"].get(s_clean, 0) + 1
                
                # Count Weaknesses
                for w in meta.get("weaknesses", []):
                    w_clean = w.strip().lower() # Normalize
                    stats["feedback_weaknesses"][w_clean] = stats["feedback_weaknesses"].get(w_clean, 0) + 1
                    
    return stats

def analyze_pipeline_health_from_files():
    pattern = os.path.join(RESULTS_DIR, "result_*.json")
    files = glob.glob(pattern)
    
    stats = {
        "total_files": 0,
        "successful_pipeline": 0,
        "failed_pipeline": 0,
        "processing_times_ms": [],
        
        # Rule Statistics
        "total_rules_generated": 0,
        "rules_by_severity": {},
        
        # Attack Statistics
        "total_attacks_generated": 0,
        
        # Verification Statistics (Crucial)
        "verification_attempts": 0,
        "detected": 0,
        "missed": 0,
        "errors": 0,
        "detection_rate_per_file": []
    }
    
    for p in files:
        data = load_json(p)
        if not data: continue
        stats["total_files"] += 1
        
        # Pipeline Status
        if data.get("status") == "success":
            stats["successful_pipeline"] += 1
        else:
            stats["failed_pipeline"] += 1
            
        # Processing Time
        t = data.get("extraction", {}).get("extraction_summary", {}).get("processing_time_ms")
        if t is not None:
             stats["processing_times_ms"].append(t)

        # 1. Analyze Rules (Robust Parsing)
        rules_data = data.get("rules", [])
        rules = []
        if isinstance(rules_data, list):
            rules = rules_data
        elif isinstance(rules_data, dict):
            # Try all known keys for rules list
            if "generated_rules" in rules_data: rules = rules_data["generated_rules"]
            elif "rules" in rules_data: rules = rules_data["rules"]
            elif "rule_generation_results" in rules_data: rules = rules_data["rule_generation_results"]
        
        stats["total_rules_generated"] += len(rules)
        for r in rules:
            # Handle nested rule structure (some files have wrapper objects)
            rule_obj = r.get("rule", r) if isinstance(r, dict) else r
            
            if isinstance(rule_obj, dict):
                sev = rule_obj.get("severity", "unknown")
                stats["rules_by_severity"][sev] = stats["rules_by_severity"].get(sev, 0) + 1

        # 2. Analyze Attacks (Robust Parsing)
        attacks_data = data.get("attacks", [])
        attacks = []
        if isinstance(attacks_data, list):
             attacks = attacks_data
        elif isinstance(attacks_data, dict):
             if "generated_commands" in attacks_data: attacks = attacks_data["generated_commands"]
             elif "attacks" in attacks_data: attacks = attacks_data["attacks"]

        stats["total_attacks_generated"] += len(attacks)

        # 3. Analyze Verification
        ver_data = data.get("siem_verification", [])
        ver_results = []
        
        if isinstance(ver_data, list):
            ver_results = ver_data
        elif isinstance(ver_data, dict):
            ver_results = ver_data.get("results", [])
        
        file_detections = 0
        file_attempts = 0
        
        for ver in ver_results:
            stats["verification_attempts"] += 1
            file_attempts += 1
            
            is_detected = ver.get("detected", False)
            if is_detected:
                stats["detected"] += 1
                file_detections += 1
            else:
                stats["missed"] += 1
        
        if file_attempts > 0:
            stats["detection_rate_per_file"].append(file_detections / file_attempts)

    return stats

def print_stats():
    print("=== PIPELINE SUMMARY (Aggregated from Result Files) ===")
    summary = analyze_pipeline_health_from_files()
    print(f"Total Files Found: {summary['total_files']}")
    print(f"Successful Runs: {summary['successful_pipeline']}")
    print(f"Failed Runs: {summary['failed_pipeline']}")
    if summary['processing_times_ms']:
        avg_ms = sum(summary['processing_times_ms']) / len(summary['processing_times_ms'])
        print(f"Average Extraction Time: {avg_ms:.2f} ms ({avg_ms/1000:.2f} s)")
    else:
        print("Average Extraction Time: N/A")

    print("\n--- CONTENT GENERATION ---")
    print(f"Total Generated Rules: {summary['total_rules_generated']}")
    print(f"Rules by Severity: {json.dumps(summary['rules_by_severity'], indent=2)}")
    print(f"Total Generated Attacks: {summary['total_attacks_generated']}")
    
    print("\n--- SIEM VERIFICATION (CRITICAL) ---")
    print(f"Total Verification Attempts: {summary['verification_attempts']}")
    
    if summary['total_attacks_generated'] > 0:
        coverage = (summary['verification_attempts'] / summary['total_attacks_generated']) * 100
        print(f"Verification Coverage: {coverage:.2f}% ({summary['verification_attempts']} verified / {summary['total_attacks_generated']} generated)")
    
    print(f"Detected: {summary['detected']}")
    print(f"Missed: {summary['missed']}")
    print(f"Errors: {summary['errors']}")
    
    total_ver = summary['verification_attempts']
    if total_ver > 0:
        rate = (summary['detected'] / total_ver) * 100
        print(f"Overall Detection Rate: {rate:.2f}%")
    else:
        print("Overall Detection Rate: N/A")
        
    if summary['detection_rate_per_file']:
         avg_dr = sum(summary['detection_rate_per_file']) / len(summary['detection_rate_per_file'])
         print(f"Avg Detection Rate per File: {avg_dr*100:.2f}%")

    print("\n=== EXTRACTION STATISTICS (Detailed) ===")
    ext = analyze_extraction_results()
    print(f"Total Files Processed: {ext['total_files']}")
    print(f"Total TTPs Extracted: {ext['total_ttps']}")
    print(f"Extraction Methods: {json.dumps(ext['extraction_methods'], indent=2)}")
    if ext['confidence_scores']:
        print(f"Average Confidence: {sum(ext['confidence_scores']) / len(ext['confidence_scores']):.4f}")
    
    # Analyze Tactics
    print("Top Tactics:")
    sorted_tactics = sorted(ext['tactics'].items(), key=lambda x: x[1], reverse=True)[:5]
    for t, count in sorted_tactics:
        print(f"  - {t}: {count}")
    
    def print_quality_section(title, stats):
        print(f"\n=== {title} QUALITY STATISTICS ===")
        print(f"Total Reports: {stats['total_reports']}")
        
        avg_score = 0
        if stats['total_reports'] > 0:
            avg_score = stats['total_score_accum'] / stats['total_reports']
            
        print(f"Average Overall Score: {avg_score:.4f}")
        print(f"Pass/Fail: {stats['pass_count']} / {stats['fail_count']}")
        
        print("Category Averages:")
        for k, v in stats['category_accum'].items():
            count = stats['category_counts'].get(k, 1)
            print(f"  - {k}: {v/count:.4f}")

        print("Metric Averages:")
        for k, v in stats['metric_accum'].items():
            count = stats['metric_counts'].get(k, 1)
            print(f"  - {k}: {v/count:.4f}")
            
        print("Top Common Weaknesses:")
        sorted_weak = sorted(stats['feedback_weaknesses'].items(), key=lambda x: x[1], reverse=True)[:3]
        for w, c in sorted_weak:
             print(f"  - {w} ({c} occurrences)")

    rg = analyze_quality_reports("rulegen")
    print_quality_section("RULEGEN", rg)

    ag = analyze_quality_reports("attackgen")
    print_quality_section("ATTACKGEN", ag)
    
if __name__ == "__main__":
    print_stats()
