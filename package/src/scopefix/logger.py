import statistics
import datetime
from collections import defaultdict
from typing import List, Dict, Any
from radon.complexity import cc_visit
from radon.raw import analyze
from schema import *
from bandit_analysis import load_code, analyze_code
import difflib
import ast
import io
import tokenize


PRICING_PER_1M = {
    "alibaba-qwen3-32b": {"input": 0.250, "output": 0.550},
    "deepseek-r1-distill-llama-70b": {"input": 0.990, "output": 0.990},
    "gemini-3-pro-preview": {"input": 2.00, "output": 12.00},
    "gemini-3-flash-preview": {"input": 0.50, "output": 3.00},
    "gpt-5.1": {"input": 1.25, "output": 10.00},
    "gpt-5.2": {"input": 1.75, "output": 14.00},
    "gpt-5-mini": {"input": 0.250, "output": 2.00}
}

def calculate_normalized_line_churn(original: str, patched: str) -> int:
    """
    Calculates line churn but performs 'normalization' first:
    1. Removes comments.
    2. Removes docstrings.
    3. Standardizes whitespace (ignores indentation changes).
    
    Returns: Number of LOGICAL lines changed.
    """
    def clean_code(code: str) -> list:
        """Parses code into a list of 'canonical' lines."""
        clean_lines = []
        try:
            tokens = tokenize.tokenize(io.BytesIO(code.encode('utf-8')).readline)
            current_line = []
            last_lineno = -1
            
            for tok in tokens:
                # Skip comments and non-code tokens
                if tok.type in (tokenize.COMMENT, tokenize.NL, tokenize.ENCODING):
                    continue
                # Docstrings are usually STRING tokens at the start of a block; 
                # simplifying here to keep all code strings
                
                if tok.type == tokenize.NEWLINE:
                    if current_line:
                        # Join tokens with space and strip to normalize
                        clean_lines.append(" ".join(current_line))
                        current_line = []
                elif tok.type in (tokenize.INDENT, tokenize.DEDENT):
                    continue
                else:
                    current_line.append(tok.string)
                    
            if current_line:
                clean_lines.append(" ".join(current_line))
                
        except tokenize.TokenError:
            # Fallback for severe syntax errors
            return [line.strip() for line in code.splitlines() if line.strip()]
            
        return clean_lines

    # 1. Get canonical lines (ignoring indentation/comments)
    lines_orig = clean_code(original)
    lines_pat = clean_code(patched)
    
    # 2. Diff the logical lines
    matcher = difflib.SequenceMatcher(None, lines_orig, lines_pat)
    churn = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'replace':
            churn += max(i2 - i1, j2 - j1) # Count the larger block as the churn cost
        elif tag == 'delete':
            churn += (i2 - i1)
        elif tag == 'insert':
            churn += (j2 - j1)
            
    return churn

def get_ast_linearization(code_str: str) -> list:
    """
    Parses code into a linear sequence of AST nodes.
    Captures structure (FunctionDef, If, Assign) and values (names, constants).
    Ignores formatting, whitespace, comments, and docstrings.
    """
    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        # Fallback for code that doesn't parse (e.g. partial snippets)
        return []

    linear_nodes = []
    
    for node in ast.walk(tree):
        # 1. Capture the Type of the node (e.g., 'If', 'Call', 'Name')
        node_type = type(node).__name__
        
        # 2. Capture specific values that matter for logic
        node_value = ""
        if isinstance(node, ast.Name):
            node_value = node.id
        elif isinstance(node, ast.Constant): # Literals like 1, "hello"
            node_value = str(node.value)
        elif isinstance(node, ast.Attribute):
            node_value = node.attr
        elif isinstance(node, ast.FunctionDef):
            node_value = node.name
            
        # Create a structural token: "Type:Value"
        # e.g., "Assign:", "Name:x", "Constant:1"
        token = f"{node_type}:{node_value}" if node_value else node_type
        linear_nodes.append(token)
        
    return linear_nodes

def calculate_ast_churn(original: str, patched: str) -> int:
    """
    Calculates the 'Structural Edit Distance' between two code snippets.
    Returns: Number of AST nodes inserted/deleted/replaced.
    """
    nodes_orig = get_ast_linearization(original)
    nodes_pat = get_ast_linearization(patched)
    
    # If parsing failed for either, return -1 or fallback length
    if not nodes_orig and original.strip(): return len(original.split()) 
    if not nodes_pat and patched.strip(): return len(patched.split())

    # Use SequenceMatcher on the AST nodes
    matcher = difflib.SequenceMatcher(None, nodes_orig, nodes_pat)
    
    churn = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'replace':
            churn += max(i2 - i1, j2 - j1)
        elif tag == 'delete':
            churn += (i2 - i1)
        elif tag == 'insert':
            churn += (j2 - j1)
            
    return churn

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
    # print("-------------------------------")
    # print(patched_code)
    # print("-------------------------------")
    
    stats_before = radon_analysis(original_code)
    stats_after = radon_analysis(patched_code)
    
    analysis_after = analyze_code(patched_code)
    vuln_cnt = len(analysis_after)

    normalized_loc_churn = calculate_normalized_line_churn(original_code, patched_code)
    ast_churn = calculate_ast_churn(original_code,patched_code)
    
    raw_attempts = res.get("patch_results", [])
    
    grouped_attempts = defaultdict(list)
    for item in raw_attempts:
        data = item.model_dump() if hasattr(item, "model_dump") else item
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
            dataset="cybernative_dst",
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
            new_issues_introduced=vuln_cnt-init_vuln_cnt+fixed_count, 
            final_code_stats=CodeStats(
                loc=stats_after["sloc"],
                avg_cyclomatic_complexity=stats_after["average_complexity"],
                vuln_count=vuln_cnt,
            ),
            normalized_loc_churn=normalized_loc_churn,
            ast_churn=ast_churn
        ),
        total_cost_usd=round(total_file_cost, 6),
        vulnerabilities=vulnerability_traces
    )

def append_log(log_entry: FileAuditLog, filepath: str):
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(log_entry.model_dump_json() + "\n")


def save_code_to_file(code_string: str, file_path: str):
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(code_string)