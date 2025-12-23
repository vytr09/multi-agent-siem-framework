import os
import json
import glob

RESULTS_DIR = r"d:\UIT\Nam_4\KLTN\Project\multi-agent-siem-framework\data"

def sanitize_obj(obj):
    """Recursively sanitize dictionary."""
    if isinstance(obj, dict):
        keys_to_redact = []
        for k, v in obj.items():
            if "api_key" in k.lower() or "secret" in k.lower():
                keys_to_redact.append(k)
            else:
                sanitize_obj(v)
        
        for k in keys_to_redact:
            obj[k] = "<REDACTED>"
            
    elif isinstance(obj, list):
        for item in obj:
            sanitize_obj(item)

def main():
    print(f"Scanning directory: {RESULTS_DIR}")
    # Python 3.10+ supports recursive glob with root_dir or we can use recursive=True
    pattern = os.path.join(RESULTS_DIR, "**", "**.json")
    files = glob.glob(pattern, recursive=True)
    print(f"Found {len(files)} files to check...")
    
    count = 0
    for file_path in files:
        changed = False
        try:
            # Skip verify database files if they are json? (usually not, but good to be careful)
            # Chroma db binary files unlikely to match .json
            
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON: {file_path}")
                    continue
            
            sanitize_obj(data)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            count += 1
            if count % 10 == 0:
                 print(f"Processed {count} files...")
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            
    print(f"\nCompleted! Sanitized {count} files.")

if __name__ == "__main__":
    main()
