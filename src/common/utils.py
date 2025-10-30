import json

def tolerant_load_file(path: str):
    """
    Accept full JSON (array or single object) OR JSONL.
    Returns a list of dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return []
    # Try full JSON first
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return obj
        elif isinstance(obj, dict):
            return [obj]
    except json.JSONDecodeError:
        pass
    # Fallback JSONL
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
