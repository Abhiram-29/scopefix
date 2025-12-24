from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from bandit_analysis import verify_patch
from functools import partial
from schema import GraphState

def patching_logic(state: GraphState, model: str, level: int, patch_prompt: ChatPromptTemplate):
    vulnerabilities = state['processed_vulnerabilities']
    patch_results = state.get("patch_results",[])
    curr_code = state["code"]
    leftover_vulnerabilities = []    
    llm = ChatGoogleGenerativeAI(model=model)
   
    chain = patch_prompt | llm | StrOutputParser()
    
    print(f"Attempting Level {level} Patch (Small LLM) for {len(vulnerabilities)} issues")

    for vuln in vulnerabilities:
        strategy,test_id = vuln["strategy"],vuln["test_id"]
        print(test_id)
        try:
            fixed_code = chain.invoke({
                "code_snippet": curr_code,
                "fix_strategy": strategy
            })
            fixed_code = fixed_code.replace("```python", "").replace("```", "").strip()
            is_fixed = verify_patch(fixed_code, test_id)         
            if is_fixed:
                curr_code = fixed_code
            else:
                leftover_vulnerabilities.append(vuln)
            
            status = "success" if is_fixed else f"failed_level_{level}"
            print(f"Issue {test_id}: {status}")

            patch_results.append({
                "patched_code": fixed_code,
                "status": status,
                "level_attempted": level
            })
            
        except Exception as e:
            print(f"Error patching {test_id}: {e}")
            patch_results.append({
                "status": "error",
                "error_msg": str(e),
                "level": level
            })

    return {"patch_results": patch_results, "processed_vulnerabilities": leftover_vulnerabilities, "code": curr_code}



l1_patch_prompt = ChatPromptTemplate.from_template(
        """
        You are a cybersecurity specialist. Given a vulnerable code your job is to fix it without changing its functionality.
        You will be given an explaination of the vulnerability and a strategy to fix it, use the strategy as a guideline to fix the code.
        
        VULNERABLE CODE:
        {code_snippet}
        
        VULNERABILITY DETAILS AND FIXING STRATEGY:
        {fix_strategy}
      
        TASK:
        Rewrite the code snippet to be secure. 
        Output ONLY the valid Python code. No markdown, no explanations, No code comments.
        """
    )

junior_patcher = partial(patching_logic, model="gemini-3-flash-preview", level=1, patch_prompt=l1_patch_prompt)

l2_patch_prompt = ChatPromptTemplate.from_template(
    """
    You are a senior cybersecurity specialist. Your job is to patch vulnerable codes that your juniors failed to patch.
    You will be given a code, an explanation of the vulnerability and a strategy to fix it, patch the code without changing its functionality.
    Your juniors tried to patch the code using the same strategy but they failed, so think critically and use your own creativity, you can deviate from the strategy

    VULNERABLE CODE:
    {code_snippet}

    VULNERABILITY DETAILS AND FIXING STRATEGY:
    {fix_strategy}

    TASK:
    Rewrite the code snippet to be secure. 
    Output ONLY the valid Python code. No markdown, no explanations, No code comments.
    """
)

senior_patcher = partial(patching_logic, model="gemini-3-pro-preview", level=2, patch_prompt=l2_patch_prompt)