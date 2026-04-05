from scopefix import fix_loop
import time
file = "datasets/cvefixes/sample_3.py"

start_time = time.perf_counter()
res = fix_loop.fix_vuln(file)
end_time = time.perf_counter()
total_time = end_time-start_time
print(f"Time taken to fix vulnerabilities: {total_time:.2f} seconds")
print(res["code"])