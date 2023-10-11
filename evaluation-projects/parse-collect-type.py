def parse_file(file_path):
    data_dict = {}
    third_lines = {}
    with open(file_path, 'r') as f:
        lines = f.readlines()
        
        stack = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # If the line is a number, it's the time value
            if line.isdigit():
                time_value = int(line)
                
                # Create a key from the stack
                key = '\n'.join(stack)
                
                # Initialize the array if the key doesn't exist
                if key not in data_dict:
                    data_dict[key] = []
                
                # Append the time value to the array
                data_dict[key].append(time_value)

                # Extract the third line from the stack and remove the +xxx part
                if len(stack) >= 3:
                    third_line = stack[2].split('+')[0]
                    # third_lines.add(third_line)
                    if key not in third_lines:
                        third_lines[key] = third_line
                
                # Clear the stack for the next set of lines
                stack.clear()
            else:
                # Otherwise, it's a part of the call stack
                stack.append(line)
    
    return data_dict, third_lines

if __name__ == "__main__":
    file_path = "collect-type.txt"  # Replace with the actual file path
    parsed_data, third_lines = parse_file(file_path)
    
    # Print the parsed data for verification
    for key, value in parsed_data.items():
        print(f"Key:\n{key}\n{third_lines[key]}\nValue:\n{value}\n")
