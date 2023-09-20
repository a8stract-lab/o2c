import subprocess

llvm_ir_path = '/home/ppw/Documents/ebpf-detector/linux-llvm-6.1/net/ipv6/'
llvm_analyze_path = '/home/ppw/Documents/ebpf-detector/hot_bpf_analyzer/src/lib/'

def execute_command_and_get_output(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8').strip().split('\n')
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
        return []

def main():
    input_file_path = 'ipv6-functions.txt'
    output_file_path = 'ipv6-structures.txt'
    
    with open(input_file_path, 'r') as infile:
        functions = infile.readlines()
    
    output_set = set()

    cnt = 1
    
    for function in functions:
        function = function.strip()
        if function:
            print(str(cnt) + '  ' + function)
            cnt = cnt + 1
            command = llvm_analyze_path + 'analyzer  -func2struct ' + function + f' `find {llvm_ir_path} -name "*.ll"`'
            output_list = execute_command_and_get_output(command)
            output_set.update(output_list)
            print(output_set)
    
    with open(output_file_path, 'w') as outfile:
        for item in output_set:
            outfile.write(f"{item}\n")

if __name__ == "__main__":
    main()