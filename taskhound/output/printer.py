from typing import List

def print_results(lines: List[str]):
    if not lines:
        return
    print("\n".join(lines))
