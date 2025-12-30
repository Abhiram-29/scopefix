import ast

class CodeManager:
    def __init__(self, code: str):
        self.full_code = code
        self.lines = code.splitlines(keepends=True)

    def get_function_context(self, line_number: int):
        try:
            tree = ast.parse(self.full_code)
        except SyntaxError:
            return self._get_sliding_window(line_number)
        target_node = None

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_lineno = node.lineno
                if node.decorator_list:
                    start_lineno = min(d.lineno for d in node.decorator_list)
                
                if start_lineno <= line_number <= node.end_lineno:
                    if target_node is None:
                        target_node = (node, start_lineno)
                    else:
                        prev_node, prev_start = target_node
                        if start_lineno >= prev_start and node.end_lineno <= prev_node.end_lineno:
                            target_node = (node, start_lineno)

        if target_node:
            node, start_lineno = target_node
            start_index = start_lineno - 1
            end_index = node.end_lineno
            
            return {
                "type": "function",
                "code": "".join(self.lines[start_index:end_index]),
                "start_line": start_lineno, # 1-based
                "end_line": node.end_lineno # 1-based
            }      
        return self._get_sliding_window(line_number)

    def _get_sliding_window(self, line_number, window=5):
        start = max(0, line_number - 1 - window)
        end = min(len(self.lines), line_number + window)
        return {
            "type": "window",
            "code": "".join(self.lines[start:end]),
            "start_line": start + 1,
            "end_line": end
        }

    def apply_patch(self, new_code_block: str, start_line: int, end_line: int):
        # 1. Convert 1-based lines to 0-based 
        start_index = start_line - 1
        end_index = end_line 
        
        if not new_code_block.endswith('\n'):
            new_code_block += '\n'
        pre_block = self.lines[:start_index]
        post_block = self.lines[end_index:]
        
        new_lines = pre_block + [new_code_block] + post_block
        self.lines = list(yield_lines(new_lines))
        self.full_code = "".join(self.lines)
        
        return self.full_code

def yield_lines(line_list):
    for item in line_list:
        if isinstance(item, list):
            yield from item
        else:
            yield item