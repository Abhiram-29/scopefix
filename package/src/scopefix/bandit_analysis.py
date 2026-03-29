import subprocess
import json
import logging
import tempfile
import os
from pathlib import Path

def load_code(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")

def analyze_code(file_path: str):
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

def verify_patch(code_content: str, original_test_id: str) -> bool:
    is_patched = False
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
        temp_file.write(code_content)
        temp_path = temp_file.name
    try:
        cmd = ["bandit", "-r", temp_path, "-f", "json", "--exit-zero"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        try:
            data = json.loads(result.stdout)
            issues_found = [
                i.get("test_id") for i in data.get("results", []) 
                if i.get("test_id") == original_test_id
            ]
            if not issues_found:
                is_patched = True
            else:
                is_patched = False
                
        except json.JSONDecodeError:
            is_patched = False

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
    return is_patched