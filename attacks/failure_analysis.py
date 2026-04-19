"""
Analyze failure cases where both baseline and protected agents succeeded.

This identifies attack patterns that BOTH the baseline AND protected agent
allowed through, indicating cases where the defense mechanism failed to block.
"""

import json
import csv
import re
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent


def _normalize_text(text):
    """Normalize text for pattern matching."""
    return str(text).lower().strip()


SEMANTIC_FRAMING_KEYWORDS = {
    "summarize", "summary", "analyze", "analysis", "report",
    "review", "overview", "consolidate", "compile", "aggregate",
    "assessment", "comprehensive"
}

EXPLICIT_EXTRACTION_KEYWORDS = {
    "extract", "extract all", "full data", "all records", "export",
    "retrieve all", "get all", "list all", "export all", "dump"
}

AGGREGATION_KEYWORDS = {
    "aggregat", "consolidat", "combine", "merge", "compile",
    "derive", "derived", "statistical", "sum", "total"
}


def _classify_failure(prompt, trace):
    """
    Classify a failure case by attack pattern.
    
    Returns tuple: (primary_category, confidence, explanation)
    """
    norm = _normalize_text(prompt)
    
    # Check for explicit extraction patterns
    if any(kw in norm for kw in EXPLICIT_EXTRACTION_KEYWORDS):
        return "explicit_extraction", 0.9, f"Contains explicit extraction keywords"
    
    # Check for aggregation/derived data patterns
    if any(kw in norm for kw in AGGREGATION_KEYWORDS):
        if "external" in norm or "send" in norm or "forward" in norm:
            return "aggregation", 0.85, "Attempts to send aggregated/derived data externally"
    
    # Check for semantic framing (innocent-sounding but still requesting sensitive data)
    if any(kw in norm for kw in SEMANTIC_FRAMING_KEYWORDS):
        return "semantic_framing", 0.75, "Uses innocent-sounding framing (summarize/analyze) to request sensitive data"
    
    # Default: general exfiltration pattern
    if ("read" in norm or "user" in norm or "customer" in norm) and \
       ("send" in norm or "forward" in norm or "external" in norm):
        return "unclassified_exfiltration", 0.5, "Generic exfiltration pattern"
    
    return "uncategorized", 0.0, "Could not classify failure pattern"


def analyze_failures(results_json_path=None, prompts_csv_path=None, seed_results=None):
    """Analyze failures from either JSON results or CSV prompts."""
    
    failures = []
    failure_categories = defaultdict(list)
    
    sources = []
    if seed_results:
        for seed in seed_results:
            sources.append(ROOT / "results" / f"seed_{seed}_summary.json")
    elif results_json_path is not None:
        sources.append(Path(results_json_path))
    else:
        sources.append(ROOT / "results" / "adaptive_adversary_summary.json")

    for source in sources:
        if not Path(source).exists():
            continue
        print(f"[INFO] Loading results from {source}")
        with open(source) as f:
            data = json.load(f)

        results = data.get("results", [])

        for result in results:
            baseline_ok = result.get("baseline_success", False)
            protected_ok = result.get("protected_success", False)

            if baseline_ok and protected_ok:
                prompt = result.get("prompt", "")
                baseline_trace = result.get("baseline_trace", [])
                protected_trace = result.get("protected_trace", [])

                failures.append({
                    "seed": data.get("seed"),
                    "round": result.get("round"),
                    "prompt": prompt,
                    "baseline_trace": baseline_trace,
                    "protected_trace": protected_trace,
                    "baseline_success": baseline_ok,
                    "protected_success": protected_ok,
                })
    
    # Fallback to CSV if JSON not available or empty
    if not failures and prompts_csv_path is None:
        prompts_csv_path = ROOT / "results" / "adaptive_adversary_prompts.csv"
    
    if not failures and Path(prompts_csv_path).exists():
        print(f"[INFO] Loading results from {prompts_csv_path}")
        with open(prompts_csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    baseline_ok = row.get("baseline_success", "").lower() in {"true", "1"}
                    protected_ok = row.get("protected_success", "").lower() in {"true", "1"}
                    
                    if baseline_ok and protected_ok:
                        failures.append({
                            "round": int(row.get("round", 0)),
                            "prompt": row.get("prompt", ""),
                            "baseline_trace": [],  # CSV doesn't have trace info
                            "protected_trace": [],
                            "baseline_success": baseline_ok,
                            "protected_success": protected_ok,
                        })
                except (ValueError, TypeError):
                    continue
    
    if not failures:
        print("[WARN] No failure cases found (both baseline and protected succeeded)")
        return {
            "status": "no_failures_found",
            "total_failures": 0,
            "categories": {},
            "examples": {}
        }
    
    print(f"[INFO] Found {len(failures)} failure cases (both agents succeeded)")
    
    # Classify each failure
    for failure in failures:
        prompt = failure["prompt"]
        trace = failure.get("protected_trace", [])
        
        category, confidence, explanation = _classify_failure(prompt, trace)
        
        failure["category"] = category
        failure["confidence"] = confidence
        failure["explanation"] = explanation
        
        failure_categories[category].append(failure)
    
    # Generate summary statistics
    analysis_result = {
        "status": "completed",
        "total_failures": len(failures),
        "categories": {},
        "top_failures_per_category": {},
        "failures": failures,
    }
    
    for category, items in sorted(failure_categories.items()):
        count = len(items)
        analysis_result["categories"][category] = count
        
        # Get top 3 examples per category (sorted by confidence)
        top_examples = sorted(items, key=lambda x: x.get("confidence", 0), reverse=True)[:3]
        analysis_result["top_failures_per_category"][category] = [
            {
                "prompt": ex["prompt"],
                "round": ex.get("round"),
                "trace": ex.get("protected_trace", []),
                "explanation": ex.get("explanation", ""),
                "confidence": ex.get("confidence", 0),
            }
            for ex in top_examples
        ]
    
    return analysis_result


def build_failure_summary(analysis_result):
    total = analysis_result.get("total_failures", 0)
    categories = analysis_result.get("categories", {})
    top = analysis_result.get("top_failures_per_category", {})

    fixed_order = ["semantic_framing", "aggregation", "explicit_extraction"]
    summary_categories = {}
    for key in fixed_order:
        count = int(categories.get(key, 0))
        pct = round((100.0 * count / total), 2) if total else 0.0
        summary_categories[key] = {
            "count": count,
            "percentage": pct,
            "examples": top.get(key, [])[:3],
        }

    return {
        "status": analysis_result.get("status", "unknown"),
        "total_failures": total,
        "categories": summary_categories,
    }


def main():
    """Run failure analysis and save results."""
    import os
    
    os.makedirs(ROOT / "results", exist_ok=True)
    
    print("=" * 70)
    print("FAILURE ANALYSIS: Cases where both baseline and protected succeeded")
    print("=" * 70)
    
    # Run analysis
    result = analyze_failures()
    
    output_path = ROOT / "results" / "failure_analysis.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    failure_summary = build_failure_summary(result)
    summary_output_path = ROOT / "results" / "failure_summary.json"
    with open(summary_output_path, "w") as f:
        json.dump(failure_summary, f, indent=2)
    
    print(f"\n[OK] Analysis saved to {output_path}")
    print(f"[OK] Summary saved to {summary_output_path}")
    
    # Print summary
    print("\nFAILURE CATEGORY BREAKDOWN:")
    print("-" * 70)
    
    if result.get("status") == "completed":
        for category, count in sorted(result.get("categories", {}).items(), key=lambda x: x[1], reverse=True):
            print(f"  {category}: {count} cases")
            
            # Show examples
            examples = result.get("top_failures_per_category", {}).get(category, [])
            for i, ex in enumerate(examples, 1):
                trace_str = " -> ".join(ex.get("trace", [])) if ex.get("trace") else "(no execution)"
                print(f"    Example {i}: {ex['prompt'][:70]}...")
                print(f"              Trace: {trace_str}")
    else:
        print(f"  Status: {result.get('status')}")
    
    print(f"\nTotal failure cases: {result.get('total_failures', 0)}")
    
    return result


if __name__ == "__main__":
    main()
