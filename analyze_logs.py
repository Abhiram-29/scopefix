import pandas as pd
import json

def analyze_logs(log_file_path: str):
    data = []
    try:
        with open(log_file_path, "r") as f:
            for line in f:
                if line.strip(): data.append(json.loads(line))
    except FileNotFoundError:
        print(f" Error: File '{log_file_path}' not found.")
        return

    df_files = pd.json_normalize(data)
    
    initial_count = len(df_files)
    df_files = df_files[df_files['input_stats.vuln_count'] > 0]
    filtered_count = len(df_files)
    
    print(f"Dataset: Loaded {initial_count} files. Analyzed {filtered_count} (Excluded {initial_count - filtered_count} with 0 vulns).")
    
    if df_files.empty:
        print("No valid data to analyze.")
        return

    
    all_vulns = []
    for idx,entry in df_files.iterrows():
            
        for v in entry['vulnerabilities']:

            cum_tokens = sum(att['tokens']['total_tokens'] for att in v['attempts'])
            cum_cost = sum(att['cost_usd'] for att in v['attempts'])
            
            all_vulns.append({
                "test_id": v['test_id'],
                "severity": v['severity'],
                "status": v['status'],
                "fixed_at_level": v.get('fixed_at_level'), 
                "cumulative_tokens": cum_tokens,
                "cumulative_cost": cum_cost
            })
                
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
    

    l1_fixed = df_vulns[df_vulns['fixed_at_level'] == 1]
    l1_count = len(l1_fixed)
    l1_avg_cost = l1_fixed['cumulative_cost'].mean() if l1_count else 0
    l1_avg_tokens = l1_fixed['cumulative_tokens'].mean() if l1_count else 0
    l1_success_rate = (l1_count /len(df_vulns)) * 100 if len(df_vulns) else 0


    l2_fixed = df_vulns[df_vulns['fixed_at_level'] == 2]
    l2_count = len(l2_fixed)
    l2_avg_cost = l2_fixed['cumulative_cost'].mean() if l2_count else 0
    l2_avg_tokens = l2_fixed['cumulative_tokens'].mean() if l2_count else 0
    l2_success_rate = (l2_count /(len(df_vulns)-l1_count)) * 100 if len(df_vulns) else 0
 
    print(f"{'Level':<8} | {'Count':<5} | {'Avg Tokens (Cum)':<18} | {'Avg Cost (Cum)'}")
    print("-" * 55)
    print(f"{'Level 1':<8} | {l1_count:<5} | {l1_avg_tokens:<18.0f} | ${l1_avg_cost:.4f}")
    print(f"{'Level 2':<8} | {l2_count:<5} | {l2_avg_tokens:<18.0f} | ${l2_avg_cost:.4f}")
    print(f"\nSuccess Rates: Level 1: {l1_success_rate:.2f}%, Level 2: {l2_success_rate:.2f}%")
    if l2_count > 0:
        multiplier = l2_avg_cost / l1_avg_cost if l1_avg_cost > 0 else 0
        print(f"\nInsight: Level 2 fixes are {multiplier:.1f}x more expensive than Level 1 fixes.")

    total_experiment_cost = df_files['total_cost_usd'].sum()
    

    avg_file_cost = df_files['total_cost_usd'].mean()

    avg_cost_per_fix = total_experiment_cost / total_fixed if total_fixed > 0 else 0

    print(f"\n=== 3. FINANCIAL SUMMARY ===")
    print(f"Avg Total Cost per File:  ${avg_file_cost:.4f} (Sum of all vulns per file)")
    print(f"Avg Cost per Fix (CPF):   ${avg_cost_per_fix:.4f} (Total Spend / Total Fixes)")
    print(f"Total Experiment Cost:    ${total_experiment_cost:.4f}")

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

    avg_new_vulns_introduced = df_files['security_summary.new_issues_introduced'].mean()
    print(f"Avg New Vulns Introduced: {avg_new_vulns_introduced:.5f} per file")
    per_new_vuln_rate = df_files[df_files["security_summary.new_issues_introduced"] > 0].shape[0] / df_files.shape[0] * 100
    print(f"Percentage of files with New Vulns:     {per_new_vuln_rate:.2f}% ")
    print(df_files["security_summary.new_issues_introduced"].value_counts())

    print(f"\n=== 5. SUCCESS RATE BY VULNERABILITY ID ===")
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

# --- RUN ---
if __name__ == "__main__":
    # Update filename as needed
    analyze_logs("test_logs.jsonl")