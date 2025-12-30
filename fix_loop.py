from bandit_analysis import analyze_code
from bandit_doc_scrape import scrape_bandit_docs
from strategist import vuln_strategist
from schema import GraphState
from langgraph.graph import StateGraph, START, END
from patchers import junior_patcher, senior_patcher
from dotenv import load_dotenv
import re
from pathlib import Path
from typing import Literal

curr_file = "py_dst/sample_35.py"

load_dotenv()
bandit_analysis = analyze_code(curr_file)
vuln_notes = []

def load_code(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")

def leftover_checker(state: GraphState) -> Literal["senior_patcher","end_workflow"]:
    leftovers = state.get("processed_vulnerabilities",[])
    if leftovers:
        return "senior_patcher"
    else:
        return "end_workflow"

for vuln in bandit_analysis:
    url = vuln['more_info_url']
    updt_bandit_url = re.sub(
    r"(?<=/en/)[0-9]+(?:\.[0-9]+)*",
    "latest",
    url
    )
    vuln.pop('more_info_url',None)
    vuln_notes.append({"scraped":scrape_bandit_docs(updt_bandit_url),"bandit_otpt":vuln})

workflow = StateGraph(GraphState)
workflow.add_node("vuln_strategist",vuln_strategist)
workflow.add_node("junior_patcher",junior_patcher)
workflow.add_node("senior_patcher",senior_patcher)
workflow.add_edge(START,"vuln_strategist")
workflow.add_edge("vuln_strategist","junior_patcher")
workflow.add_conditional_edges(
    "junior_patcher",
    leftover_checker,
    {"senior_patcher":"senior_patcher", "end_workflow":END}
    )
workflow.add_edge("senior_patcher",END)
app = workflow.compile()

py_code = load_code(curr_file)

res=app.invoke({"raw_vulnerabilities":vuln_notes, "code":py_code})

for strat in res["processed_vulnerabilities"]:
    print(strat)
print(res["code"])