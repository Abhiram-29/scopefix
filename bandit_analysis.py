import subprocess
import json
import logging

def analyze_code_with_bandit(file_path: str):
    try:
        result = subprocess.run(
            ["bandit", "-r", file_path, "-f", "json", "--exit-zero"], 
            capture_output=True, 
            text=True
        )
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logging.error("Failed to parse Bandit output. Make sure Bandit is installed.")
        return []

    extracted_issues = []

    if data.get("results"):
        for issue in data["results"]:
            extracted_issues.append({
                "issue_confidence": issue.get("issue_confidence"),
                "issue_severity": issue.get("issue_severity"),
                "issue_text": issue.get("issue_text"),
                "line_range": issue.get("line_range"),
                "test_id": issue.get("test_id"),
                "test_name": issue.get("test_name"),
                "more_info_url": issue.get("more_info"),
                "code_snippet": issue.get("code")
            })
            
    return extracted_issues