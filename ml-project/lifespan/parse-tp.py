import re

def parse_file(file_path):
    with open(file_path, 'r') as file:
        data = {}
        current_key = None
        for line in file:
            line = line.strip()
            if not line:
                continue
            
            # Detect new chunk
            if ':' in line and not line.startswith(' '):
                current_key = line
                data[current_key] = []
            elif current_key:
                # Parameter line
                data[current_key].append(line)
        return data

def find_chunks_with_param(data, param_name):
    result = []
    for key, params in data.items():
        if any(param_name in param for param in params):
            result.append(key)
    return result

# Replace 'your_file_path.txt' with the actual file path
file_path = 'tp.txt'
parsed_data = parse_file(file_path)

# Example usage: find chunks that use a specific parameter
param_name = 'cred'  # Replace with the parameter you're looking for
chunks_with_param = find_chunks_with_param(parsed_data, param_name)

print(f"Chunks with parameter '{param_name}':")
for chunk in chunks_with_param:
    print(chunk, parsed_data[chunk])
