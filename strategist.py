from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from slicing import CodeManager
from schema import GraphState

def vuln_strategist(state: GraphState):
    vulns = state["raw_vulnerabilities"]
    code = CodeManager(state["code"])
    processed_vulns = []

    llm = ChatGoogleGenerativeAI(model="gemini-3-flash-preview")
    strat_prompt = ChatPromptTemplate.from_template(
        """
        You are a Senior Cybersecurity analyst, you will be given a python code ,its vulnerability and the output of bandit code analyzer. 
        Your job is to guide the developer by providing the following:
        1. Brief explanation of the vulnerability and pinpoointing the line/function/module that is vulnerable
        2. A high level strategy on how to fix the vulnerability with minimum changes while preserving the original functionality, no need to give exact steps
        Don't write any code, your job is to collect and analyze all information and then tell the developer how to fix the vulnerability
        If there are multiple ways to fix a vulnerability, then choose the best option and give the developer a clear strategy, without any options.
        Try to replace insecure functions with secure options or change the logic (without affecting the output) rather than trying to do input validation.
        Keep everything short and technical, assume that the developer is skilled. Only give the minimum information and strategy needed to fix the vulnerablitiy, the developer will figure out the rest.
        
        Don't output anything unnecessay like explaination on why you choose a strategy or checklists.
        Vulnerability Info: {bandit_otpt}
        Documentation: {scraped}
        Vulnerable code: {code}
        """
    )
    
    chain = strat_prompt | llm | StrOutputParser()

    for vuln in vulns:
        # print(vuln["bandit_otpt"])
        line_num = vuln["bandit_otpt"]["line_range"][0]
        print(line_num)
        print(code.get_function_context(line_num))
        strategy_text = chain.invoke({
            "bandit_otpt": vuln["bandit_otpt"],
            "scraped": vuln["scraped"],
            "code" : code.get_function_context(line_num)
        })

        processed_vulns.append({"strategy" : strategy_text, "test_id" : vuln["bandit_otpt"]["test_id"], "line_num": line_num})
    return {"processed_vulnerabilities": processed_vulns}