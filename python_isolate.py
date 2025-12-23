import pandas as pd
import re
import os

OUTPUT_DIR = "py_dst"

def clean_code(code: str) -> str:
    if not isinstance(code, str):
        return ""
    code = re.sub(r"^```(?:python)?\s*", "", code.strip())
    code = re.sub(r"\s*```$", "", code)
    return code

def write_bandit_files(df, code_column="chosen"):
    file_map = {} 
    for i, row in df.iterrows():
        code = clean_code(row[code_column])

        if not code.strip():
            continue

        filename = f"sample_{i}.py"
        path = os.path.join(OUTPUT_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            f.write(code)

        file_map[filename] = i

    return file_map

df = pd.read_json("cybernative_dst.json",lines=True)
py_df = df[df["lang"] == 'python'].reset_index()
print(write_bandit_files(py_df))