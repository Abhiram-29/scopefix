from fix_loop import fix_vuln
from logger import create_log, append_log, save_code_to_file
import time

test_files = [i for i in range(0,420,5)]
for file in test_files:
    file_path = f"py_dst/sample_{file}.py"
    start_time = time.perf_counter()
    res = fix_vuln(file_path)
    end_time = time.perf_counter()
    total_time = end_time-start_time
    log = create_log(res,file_path,total_time)
    append_log(log,"test_logs.jsonl")
    save_code_to_file(res["code"],f"fixed/sample_{file}.py")

    time.sleep(30)
    

