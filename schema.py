from typing import TypedDict, List, Dict, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class AttemptStatus(str, Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    failed = "FAILED"

class TokenUsage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

class PatchAttempt(BaseModel):
    """
    Represents a single call to an LLM to fix a specific bug.
    """
    level: int = Field(..., description="1 or 2")
    model: str

    status: str
    finish_reason: Optional[str] = None

    duration_s: float
    cost_usd: float
    tokens: TokenUsage

class VulnerabilityTrace(BaseModel):
    """
    Represents the full lifecycle of fixing ONE specific vulnerability.
    """
    test_id: str
    severity: str
    confidence_score: str
    status: str
    fixed_at_level: Optional[int] = None 
    time_to_remediation_s: float  
    total_cost_usd: float          
    attempts: List[PatchAttempt]


class VulnerabilityTrace(BaseModel):
    """
    Represents the full lifecycle of fixing ONE specific vulnerability.
    """
    # Identity (From your original VulnerabilityDetail)
    test_id: str
    severity: str
    confidence_score: str # Renamed from confidence for clarity
    
    # Final Outcome (For Questions #1 & #3)
    status: str
    fixed_at_level: Optional[int] = None # 1, 2, or None
    
    # Aggregated Metrics (For Question #5 - MTTR)
    time_to_remediation_s: float  # Sum of all attempts for this bug
    total_cost_usd: float         # Sum of all attempts for this bug
    
    # The History (For Question #4 - Syntax Error Rate)
    attempts: List[PatchAttempt]

class MetaInfo(BaseModel):
    file_uid: str
    dataset: str
    implementation_version: str
    timestamp: str 
    total_pipeline_duration_s: float

class CodeStats(BaseModel):
    loc: int
    avg_cyclomatic_complexity: float 
    vuln_count: int

class SecuritySummary(BaseModel):
    fixed_count: int
    new_issues_introduced: int
    final_code_stats: CodeStats 

class FileAuditLog(BaseModel):
    meta: MetaInfo
    input_stats: CodeStats
    language: str

    security_summary: SecuritySummary
    total_cost_usd: float
    vulnerabilities: List[VulnerabilityTrace]

# class Meta(BaseModel):
#     file_uid: str
#     dataset: str
#     implementation_version: str
#     total_duration_s: float

# class InputStats(BaseModel):
#     loc_original: int
#     avg_cyclomatic_complexity_original: float
#     vuln_count_initial: int
#     language: str

# class SecurityResults(BaseModel):
#     vuln_count_final: int
#     fixed_count: int
#     new_issues_introduced: int

# class VulnerabilityDetail(BaseModel):
#     test_id: str
#     severity: str
#     confidence: str
#     fixed_at_level: int
#     status: str
#     llm_time_s: int

# class CostMetrics(BaseModel):
#     model: str
#     level: int
#     test_id: str
#     status: str
#     completion_tokens: int
#     prompt_tokens: int
#     total_tokens: int
#     estimated_cost_usd: float

# class AuditLog(BaseModel):
#     meta: Meta
#     input_stats: InputStats
#     security_results: SecurityResults
#     vulnerability_details: List[VulnerabilityDetail]
#     cost_metrics: CostMetrics

class PatchResults(BaseModel):
    model: str
    status: str
    level_attempted: int
    finish_reason: str
    token_usage : dict
    vulnerability_id: str
    llm_time_taken: float
    confidence: str
    severity: str

class GraphState(TypedDict):
    raw_vulnerabilities : List[Dict]
    code : str 
    processed_vulnerabilities : List[Dict] 
    patch_results: List[PatchResults]