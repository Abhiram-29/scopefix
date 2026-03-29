from .fix_loop import fix_vuln
import argparse

def cli_fix():
    parser = argparse.ArgumentParser(description="Fix vulnerabilities in a Python file using ScopeFix.")
    parser.add_argument("file_path", type=str, help="Path to the Python file to be fixed.")
    args = parser.parse_args()
    
    result = fix_vuln(args.file_path)
    print(result)