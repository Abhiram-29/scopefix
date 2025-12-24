from typing import TypedDict, List, Dict

class GraphState(TypedDict):
    raw_vulnerabilities : List[Dict]
    code : str
    processed_vulnerabilities : List[Dict]
    patch_results: List[Dict]