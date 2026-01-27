import os
import json
import ijson

# ========== CONFIG ==========
INPUT_FILE = r"F:\Downloads\json_logs.json\json_logs.json"
OUTPUT_DIR = r"F:\Desktop\DP-project\Json\max100"
CHUNK_SIZE = 100          # number of logs per file
MAX_FILES = None             # limit (set to None for full file)
# ============================

os.makedirs(OUTPUT_DIR, exist_ok=True)

def detect_format(file_path):
    """Detect if file is JSONL (newline JSON) or big array JSON."""
    with open(file_path, "rb") as f:
        first_non_ws = None
        while True:
            ch = f.read(1)
            if not ch:
                break
            if ch.strip():
                first_non_ws = ch
                break
    if first_non_ws == b'[':
        return "array"
    return "jsonl"

def split_jsonl(file_path):
    """Split newline-delimited JSON (JSONL) file."""
    file_count = 0
    line_count = 0
    buffer = []
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(file_path, "r", encoding="utf-8") as fin:
        for line in fin:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                buffer.append(data)
                line_count += 1
            except json.JSONDecodeError:
                continue

            if line_count >= CHUNK_SIZE:
                file_count += 1
                output_path = os.path.join(OUTPUT_DIR, f"part_{file_count:03d}.json")
                with open(output_path, "w", encoding="utf-8") as fout:
                    json.dump(buffer, fout, ensure_ascii=False, indent=2)
                print(f"✅ Created {output_path} ({len(buffer)} records)")
                buffer.clear()
                line_count = 0
                if MAX_FILES and file_count >= MAX_FILES:
                    break

    # save remaining
    if buffer:
        file_count += 1
        output_path = os.path.join(OUTPUT_DIR, f"part_{file_count:03d}.json")
        with open(output_path, "w", encoding="utf-8") as fout:
            json.dump(buffer, fout, ensure_ascii=False, indent=2)
        print(f"✅ Created {output_path} ({len(buffer)} records)")

def split_array(file_path):
    """Split large array JSON file."""
    file_count = 0
    record_count = 0
    buffer = []

    with open(file_path, "rb") as f:
        for obj in ijson.items(f, "item"):
            buffer.append(obj)
            record_count += 1

            if len(buffer) >= CHUNK_SIZE:
                file_count += 1
                output_path = os.path.join(OUTPUT_DIR, f"part_{file_count:03d}.json")
                with open(output_path, "w", encoding="utf-8") as fout:
                    json.dump(buffer, fout, ensure_ascii=False, indent=2)
                print(f"✅ Created {output_path} ({len(buffer)} records)")
                buffer.clear()
                if MAX_FILES and file_count >= MAX_FILES:
                    break

    # save remaining
    if buffer:
        file_count += 1
        output_path = os.path.join(OUTPUT_DIR, f"part_{file_count:03d}.json")
        with open(output_path, "w", encoding="utf-8") as fout:
            json.dump(buffer, fout, ensure_ascii=False, indent=2)
        print(f"✅ Created {output_path} ({len(buffer)} records)")

def main():
    fmt = detect_format(INPUT_FILE)
    print(f"Detected format: {fmt}")
    if fmt == "jsonl":
        split_jsonl(INPUT_FILE)
    else:
        split_array(INPUT_FILE)

if __name__ == "__main__":
    main()
