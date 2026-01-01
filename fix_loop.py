from bandit_analysis import analyze_code, load_code
from bandit_doc_scrape import scrape_bandit_docs
from strategist import vuln_strategist
from schema import GraphState
from langgraph.graph import StateGraph, START, END
from patchers import junior_patcher, senior_patcher
from dotenv import load_dotenv
import re
from typing import Literal
import time
from logger import create_log

curr_file = "py_dst/sample_0.py"

load_dotenv()

def leftover_checker(state: GraphState) -> Literal["senior_patcher","end_workflow"]:
    leftovers = state.get("processed_vulnerabilities",[])
    if leftovers:
        return "senior_patcher"
    else:
        return "end_workflow"


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

def fix_vuln(file_path):
    bandit_analysis = analyze_code(file_path)
    vuln_notes = []
    for vuln in bandit_analysis:
        url = vuln['more_info_url']
        updt_bandit_url = re.sub(
        r"(?<=/en/)[0-9]+(?:\.[0-9]+)*",
        "latest",
        url
        )
        vuln.pop('more_info_url',None)
        vuln_notes.append({"scraped":scrape_bandit_docs(updt_bandit_url),"bandit_otpt":vuln})
    py_code = load_code(curr_file)
    res=app.invoke({"raw_vulnerabilities":vuln_notes, "code":py_code})
    
    return res

# start_time = time.perf_counter()
# res = fix_vuln(curr_file)
# end_time = time.perf_counter()
# total_time = end_time-start_time
# log = create_log(res,curr_file,total_time)
# print(log)

# for strat in res["processed_vulnerabilities"]:
#     print(strat)
# print(res["code"])
