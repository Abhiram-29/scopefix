from bandit_analysis import analyze_code_with_bandit
from bandit_doc_scrape import scrape_bandit_docs
from typing import TypedDict, List, Dict, Annotated
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv
import re
from pathlib import Path


load_dotenv()
bandit_analysis = analyze_code_with_bandit("py_dst/sample_0.py")
print(bandit_analysis)
vuln_notes = []

def load_python_code(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")

for vuln in bandit_analysis:
    url = vuln['more_info_url']
    updt_bandit_url = re.sub(
    r"(?<=/en/)[0-9]+(?:\.[0-9]+)*",
    "latest",
    url
    )
    vuln.pop('more_info_url',None)
    vuln_notes.append({"scraped":scrape_bandit_docs(updt_bandit_url),"bandit_otpt":bandit_analysis})


class GraphState(TypedDict):
    raw_vulnerabilities : List[Dict]
    code : str
    processed_vulnerabilities : List[str]

def vuln_strategist(state: GraphState):
    vulns = state["raw_vulnerabilities"]
    processed_vulns = []

    llm = ChatOpenAI(model="gpt-5-mini")
    strat_prompt = ChatPromptTemplate.from_template(
        """
        You are a Senior Cybersecurity analyst, you will be given a python code ,its vulnerability and the output of bandit code analyzer. 
        Your job is to guide the developer by providing the following:
        1. Brief explanation of the vulnerability and pinpoointing the line/function/module that is vulnerable
        2. A high level strategy on how to fix the vulnerability with minimum changes while preserving the original functionality, no need to give exact steps
        Don't write any code, your job is to collect and analyze all information and then tell the developer how to fix the vulnerability
        If there are multiple ways to fix a vulnerability, then choose the best option and give the developer a clear strategy, without any options.
        Keep everything short and technical, assume that the developer is skilled. Only give the minimum information and strategy needed to fix the vulnerablitiy, the developer will figure out the rest.
        
        Don't output anything unnecessay like explaination on why you choose a strategy or checklists.
        Vulnerability Info: {bandit_otpt}
        Documentation: {scraped}
        Vulnerable code: {code}
        """
    )
    
    chain = strat_prompt | llm | StrOutputParser()

    for vuln in vulns:
        strategy_text = chain.invoke({
            "bandit_otpt": vuln["bandit_otpt"],
            "scraped": vuln["scraped"],
            "code" : state["code"]
        })

        processed_vulns.append(strategy_text)
    
    return {"processed_vulnerabilities": processed_vulns}

workflow = StateGraph(GraphState)
workflow.add_node("vuln_strategist",vuln_strategist)
workflow.add_edge(START,"vuln_strategist")
workflow.add_edge("vuln_strategist",END)
app = workflow.compile()

py_code = load_python_code("py_dst/sample_0.py")

res=app.invoke({"raw_vulnerabilities":vuln_notes, "code":py_code})

for strat in res["processed_vulnerabilities"]:
    print(strat)
