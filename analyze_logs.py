import pandas as pd
import json

def analyze_logs(log_file_path: str):
    data = []
    try:
        with open(log_file_path, "r") as f:
            for line in f:
                if line.strip(): data.append(json.loads(line))
    except FileNotFoundError:
        print(f"Error: File '{log_file_path}' not found.")
        return

    df_files = pd.json_normalize(data)
    
    initial_count = len(df_files)
    df_files = df_files[df_files['input_stats.vuln_count'] > 0]
    filtered_count = len(df_files)
    
    print(f"Dataset: Loaded {initial_count} files. Analyzed {filtered_count} (Excluded {initial_count - filtered_count} with 0 vulns).")
    
    if df_files.empty:
        print("No valid data to analyze.")
        return

    valid_file_ids = df_files['meta.file_uid'].unique()
    
    all_attempts = []
    all_vulns = []
    
    for entry in data:
        if entry['meta']['file_uid'] not in valid_file_ids: continue
            
        for v in entry['vulnerabilities']:
            all_vulns.append({
                "test_id": v['test_id'],
                "severity": v['severity'],
                "status": v['status']
            })
            for att in v['attempts']:
                all_attempts.append({
                    "level": att['level'],
                    "status": att['status'],
                    "total_tokens": att['tokens']['total_tokens']
                })
                
    df_attempts = pd.DataFrame(all_attempts)
    df_vulns = pd.DataFrame(all_vulns)

    total_detected = df_files['input_stats.vuln_count'].sum()
    total_fixed = df_files['security_summary.fixed_count'].sum()
    remediated_files = df_files[
        df_files['input_stats.vuln_count'] == df_files['security_summary.fixed_count']
    ]

    print(f"\n=== 1. OVERALL EFFECTIVENESS ===")
    print(f"Vulnerability Fix Rate:   {(total_fixed / total_detected * 100):.2f}% ({total_fixed}/{total_detected})")
    print(f"File Remediation Rate:    {(len(remediated_files) / len(df_files) * 100):.2f}% ({len(remediated_files)}/{len(df_files)} files clean)")

    print(f"\n=== 2. TIERED ARCHITECTURE EFFICIENCY ===")
    for level in [1, 2]:
        subset = df_attempts[df_attempts['level'] == level]
        if not subset.empty:
            success = len(subset[subset['status'] == 'SUCCESS'])
            print(f"Level {level} Success Rate:    {(success/len(subset)*100):.2f}% ({success}/{len(subset)})")
        else:
            print(f"Level {level} Success Rate:    N/A (No attempts)")

    avg_tokens = df_attempts[df_attempts['status'] == 'SUCCESS']['total_tokens'].mean()
    avg_cost_fix = df_files['total_cost_usd'].sum() / total_fixed if total_fixed > 0 else 0
    
    print(f"\n=== 3. COST METRICS ===")
    print(f"Avg Tokens per Fix:       {avg_tokens:.0f}")
    print(f"Avg Cost per Fix (CPF):   ${avg_cost_fix:.4f}")

    print(f"\n=== 4. PATCH QUALITY ===")
    
    if 'security_summary.normalized_loc_churn' in df_files.columns:
        avg_loc_churn = df_files['security_summary.normalized_loc_churn'].mean()
        print(f"Avg LOC Churn:            {avg_loc_churn:.2f} lines (Normalized)")
    else:
        print("Avg LOC Churn:            N/A")

    if 'security_summary.ast_churn' in df_files.columns:
        avg_ast_churn = df_files['security_summary.ast_churn'].mean()
        print(f"Avg AST Churn:            {avg_ast_churn:.2f} nodes (Structural)")
    else:
        print("Avg AST Churn:            N/A")
        
    avg_cc_delta = (
        df_files['security_summary.final_code_stats.avg_cyclomatic_complexity'] - 
        df_files['input_stats.avg_cyclomatic_complexity']
    ).mean()
    print(f"Avg Complexity Change:    {avg_cc_delta:+.2f}")

    print(f"\n=== 5. PERFORMANCE BY SEVERITY ===")
    if not df_vulns.empty:
        breakdown = df_vulns.groupby('severity')['status'].value_counts(normalize=True).unstack().fillna(0)
        if 'FIXED' in breakdown.columns:
            print((breakdown['FIXED'] * 100).round(2).to_string(float_format="%.2f%%"))
        else:
            print("No fixed vulnerabilities to display.")
    else:
        print("No vulnerability data found.")

    print(f"\n=== 6. DETAILED SUCCESS RATE BY VULNERABILITY ID ===")
    if not df_vulns.empty:
        df_vulns['is_fixed'] = (df_vulns['status'] == 'FIXED').astype(int)
        
        stats = df_vulns.groupby('test_id').agg(
            success_rate=('is_fixed', 'mean'),
            total_cases=('test_id', 'count')
        )
        
        stats['success_rate'] = (stats['success_rate'] * 100).round(1)
        stats = stats.sort_values(by=['total_cases', 'success_rate'], ascending=[False, False])
        
        print(f"{'TEST ID':<20} | {'RATE':<8} | {'CASES':<5}")
        print("-" * 40)
        for test_id, row in stats.iterrows():
            print(f"{test_id:<20} | {row['success_rate']}%   | {int(row['total_cases']):<5}")
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    analyze_logs("test_logs.jsonl")