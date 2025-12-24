from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from bandit_analysis import verify_patch
from schema import GraphState

def small_patcher(state: GraphState):
    vulnerabilities = state['processed_vulnerabilities']
    print(vulnerabilities)
    patch_results = []    
    llm = ChatGoogleGenerativeAI(model="gemini-3-flash-preview")

    patch_prompt = ChatPromptTemplate.from_template(
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
    
    chain = patch_prompt | llm | StrOutputParser()
    
    print(f"--- Attempting Level 1 Patch (Small LLM) for {len(vulnerabilities)} issues ---")

    for vuln in vulnerabilities:
        # print(vuln)
        strategy,test_id = vuln["strategy"],vuln["test_id"]
        print(test_id)
        try:
            fixed_code = chain.invoke({
                "code_snippet": state['code'],
                "fix_strategy": strategy
            })
            
            # Clean up formatting (sometimes LLMs wrap in ```python ... ```)
            fixed_code = fixed_code.replace("```python", "").replace("```", "").strip()

            # 2. Verify Patch
            is_fixed = verify_patch(fixed_code, test_id)
            
            status = "success" if is_fixed else "failed_level_1"
            print(f"Issue {test_id}: {status}")

            patch_results.append({
                "patched_code": fixed_code,
                "status": status, # 'success' or 'failed_level_1'
                "level_attempted": 1
            })
            
        except Exception as e:
            print(f"Error patching {test_id}: {e}")
            patch_results.append({
                "status": "error",
                "error_msg": str(e)
            })

    return {"patch_results": patch_results}