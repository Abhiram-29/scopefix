import statistics
import datetime
from collections import defaultdict
from typing import List, Dict, Any
from radon.complexity import cc_visit
from radon.raw import analyze
from schema import *
from bandit_analysis import load_code, analyze_code

PRICING_PER_1M = {
    "gpt-4o": {"input": 5.00, "output": 15.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "alibaba-qwen3-32b": {"input": 0.50, "output": 1.50},
}

def calculate_attempt_cost(model: str, p_tokens: int, c_tokens: int) -> float:
    rates = PRICING_PER_1M.get(model, {"input": 0, "output": 0})
    cost = (p_tokens / 1_000_000 * rates["input"]) + \
           (c_tokens / 1_000_000 * rates["output"])
    return round(cost, 6)

def radon_analysis(code_str: str) -> Dict[str, Any]:
    try:
        blocks = cc_visit(code_str)
        if blocks:
            scores = [block.complexity for block in blocks]
            avg_complexity = statistics.mean(scores)
        else:
            avg_complexity = 0
            
        raw_metrics = analyze(code_str)
        return {
            "average_complexity": round(avg_complexity, 2),
            "sloc": raw_metrics.sloc,
        }
    except Exception as e:
        return {"average_complexity": 0.0, "sloc": 0}

def create_log(res: GraphState, file_name: str, duration: float) -> FileAuditLog:
    
    original_code = load_code(file_name)
    patched_code = res["code"]
    print("-------------------------------")
    print(patched_code)
    print("-------------------------------")
    
    stats_before = radon_analysis(original_code)
    stats_after = radon_analysis(patched_code)
    
    analysis_after = analyze_code(patched_code)
    vuln_cnt = len(analysis_after)
    
    raw_attempts = res.get("patch_results", [])
    
    grouped_attempts = defaultdict(list)
    for item in raw_attempts:
        data = item.model_dump() if hasattr(item, "model_dump") else item
        print(data)
        print()
        print()
        vid = data.get("vulnerability_id","UNKNOWN")
        grouped_attempts[vid].append(data)

    vulnerability_traces = []
    total_file_cost = 0.0
    fixed_count = 0

    for vid, attempts_data in grouped_attempts.items():
        trace_attempts = []
        vuln_cost = 0.0
        vuln_time = 0.0
        is_fixed = False
        fixed_at = None
        
        
        first_att = attempts_data[0]
        severity = first_att.get("severity", "UNKNOWN")
        confidence = first_att.get("confidence", "UNKNOWN")

        # Process each attempt for this specific vulnerability
        for att_data in attempts_data:
            # Cost Calculation
            t_usage = att_data.get("token_usage", {})
            p_tok = t_usage.get("prompt_tokens", 0)
            c_tok = t_usage.get("completion_tokens", 0)
            t_tok = t_usage.get("total_tokens", 0)
            
            cost = calculate_attempt_cost(att_data.get("model", ""), p_tok, c_tok)
            
            status_raw = att_data.get("status", "failed").upper()
            status_enum = "SUCCESS" if status_raw == "SUCCESS" else "FAILED"
            # Map syntax errors specifically if your raw log has them
            if "syntax" in str(att_data.get("finish_reason", "")).lower():
                status_enum = "SYNTAX_ERROR"

            patch_attempt = PatchAttempt(
                level=att_data.get("level_attempted", 1),
                model=att_data.get("model", "unknown"),
                status=status_enum,
                finish_reason=att_data.get("finish_reason"),
                duration_s=att_data.get("llm_time_taken", 0.0),
                cost_usd=cost,
                tokens=TokenUsage(
                    prompt_tokens=p_tok,
                    completion_tokens=c_tok,
                    total_tokens=t_tok
                )
            )
            
            trace_attempts.append(patch_attempt)
            
            # Aggregate per vuln
            vuln_cost += cost
            vuln_time += att_data.get("llm_time_taken", 0.0)
            
            # Check for success
            if status_enum == "SUCCESS":
                is_fixed = True
                fixed_at = att_data.get("level_attempted", 1)

        # Update Global Counters
        total_file_cost += vuln_cost
        if is_fixed:
            fixed_count += 1

        # Create the Trace Object
        trace = VulnerabilityTrace(
            test_id=vid,
            severity=severity,
            confidence_score=confidence,
            status="FIXED" if is_fixed else "FAILED",
            fixed_at_level=fixed_at,
            time_to_remediation_s=vuln_time,
            total_cost_usd=round(vuln_cost, 6),
            attempts=trace_attempts
        )
        vulnerability_traces.append(trace)

    init_vuln_cnt = fixed_count+len(res["processed_vulnerabilities"])

    return FileAuditLog(
        meta=MetaInfo(
            file_uid=file_name, 
            dataset="py_dst",
            implementation_version="v1.0.0",
            timestamp= datetime.now().isoformat(),
            total_pipeline_duration_s=duration
        ),
        input_stats=CodeStats(
            loc=stats_before["sloc"],
            avg_cyclomatic_complexity=stats_before["average_complexity"],
            vuln_count=init_vuln_cnt
        ),
        language="python",
        security_summary=SecuritySummary(
            fixed_count=fixed_count,
            # If init was 5 and we have 2 leftovers, new issues might be 0 unless explicitly detected
            new_issues_introduced=vuln_cnt-init_vuln_cnt+fixed_count, 
            final_code_stats=CodeStats(
                loc=stats_after["sloc"],
                avg_cyclomatic_complexity=stats_after["average_complexity"],
                vuln_count=vuln_cnt
            )
        ),
        total_cost_usd=round(total_file_cost, 6),
        vulnerabilities=vulnerability_traces
    )