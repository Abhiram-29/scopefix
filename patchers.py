from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_gradient import ChatGradient
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from slicing import CodeManager
from bandit_analysis import verify_patch
from functools import partial
from schema import GraphState, PatchResults
import os
import time

def patching_logic(state: GraphState, model: str, level: int, patch_prompt: ChatPromptTemplate):
    vulnerabilities = state['processed_vulnerabilities']
    patch_results = state.get("patch_results",[])
    curr_code = CodeManager(state["code"])
    leftover_vulnerabilities = []    
    # llm = ChatGoogleGenerativeAI(model=model,temperature=0)
    llm = ChatGradient(model= model,api_key=os.environ.get("DIGITALOCEAN_INFERENCE_KEY"))
   
    chain = patch_prompt | llm 
    
    print(f"Attempting Level {level} Patch (Small LLM) for {len(vulnerabilities)} issues")

    for vuln in vulnerabilities:
        strategy,test_id,line_num = vuln["strategy"],vuln["test_id"],vuln["line_num"]
        # print(test_id)
        affected_code_slice = curr_code.get_function_context(line_num)
        try:
            llm_start_time = time.perf_counter()
            llm_response = chain.invoke({
                "code_snippet": affected_code_slice["code"],
                "fix_strategy": strategy
            })
            llm_end_time = time.perf_counter()
            fixed_code_snippet = llm_response.content
            # print(fixed_code_snippet)
            fixed_code_snippet = fixed_code_snippet.replace("```python", "").replace("```", "").strip()
            curr_code.apply_patch(fixed_code_snippet,affected_code_slice["start_line"],affected_code_slice["end_line"])
            is_fixed = verify_patch(curr_code.full_code, test_id)         
            if is_fixed:
                pass
            else:
                leftover_vulnerabilities.append(vuln)
            
            status = "success" if is_fixed else f"failed_level_{level}"
            print(f"Issue {test_id}: {status}")
            # print(llm_response.response_metadata["token_usage"],type(llm_response.response_metadata["token_usage"]))
            patch_results.append(PatchResults(
                model= model,
                status= status,
                level_attempted= level,
                finish_reason= llm_response.response_metadata["finish_reason"],
                token_usage= llm_response.response_metadata["token_usage"],
                vulnerability_id= test_id,
                llm_time_taken=llm_end_time-llm_start_time,
                severity=vuln["severity"],
                confidence=vuln["confidence"]
            ))
            
        except Exception as e:
            print(f"Error patching {test_id}: {e}")
            patch_results.append(PatchResults(
                model= model,
                status= "error",
                level_attempted= level,
                finish_reason= str(e),  
                token_usage= {"total":0},
                vulnerability_id= test_id,
                llm_time_taken= 0,
                severity=vuln["severity"],
                confidence=vuln["confidence"]
            ))
    # print(patch_results)
    return {"patch_results": patch_results, "processed_vulnerabilities": leftover_vulnerabilities, "code": curr_code.full_code}



l1_patch_prompt = ChatPromptTemplate.from_template(
        """
        You are a cybersecurity specialist. Given a vulnerable code snippet your job is to fix it without changing its functionality.
        You will be given an explaination of the vulnerability and a strategy to fix it, use the strategy as a guideline to fix the code.
        Assume any external functions used are implemented correctly in the codebase
        
        VULNERABLE CODE:
        {code_snippet}
        
        VULNERABILITY DETAILS AND FIXING STRATEGY:
        {fix_strategy}
      
        TASK:
        Rewrite the code snippet to be secure. 
        Output ONLY the valid Python code. No markdown, no explanations, No code comments.
        """
    )

junior_patcher = partial(patching_logic, model="alibaba-qwen3-32b", level=1, patch_prompt=l1_patch_prompt)

l2_patch_prompt = ChatPromptTemplate.from_template(
    """
    You are a senior cybersecurity specialist. Your job is to patch vulnerable codes that your juniors failed to patch.
    You will be given a code snippet, an explanation of the vulnerability and a strategy to fix it, patch the code without changing its functionality.
    Your juniors tried to patch the code using the same strategy but they failed, so think critically and use your own creativity, you can deviate from the strategy
    Assume any external functions used are implemented correctly in the codebase
    VULNERABLE CODE:
    {code_snippet}

    VULNERABILITY DETAILS AND FIXING STRATEGY:
    {fix_strategy}

    TASK:
    Rewrite the code snippet to be secure. 
    Output ONLY the valid Python code. No markdown, no explanations, No code comments.
    """
)

senior_patcher = partial(patching_logic, model='deepseek-r1-distill-llama-70b', level=2, patch_prompt=l2_patch_prompt)