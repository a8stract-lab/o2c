import subprocess

llvm_ir_path = '/home/ppw/Documents/ebpf-detector/linux-llvm-6.1/net/ipv6/'
llvm_analyze_path = '/home/ppw/Documents/ebpf-detector/hot_bpf_analyzer/src/lib/'

def execute_command_and_get_output(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        l = output.decode('utf-8').strip().split('\n')
        ret = ''
        for x in l:
            ret = ret + x + ', '
        return ret
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
        return ''

def main():
    input_file_path = 'ipv6-structures.txt'
    output_file_path = 'ipv6-allocation-sites.txt'
    
    with open(input_file_path, 'r') as infile:
        structures = infile.readlines()
    
    output_csv = list()
    
    for st in structures:
        st = st.strip()
        if st:
            print(st)
            command = llvm_analyze_path + 'analyzer  -struct ' + st + f' `find {llvm_ir_path} -name "*.ll"`'
            output_ret = execute_command_and_get_output(command)
            output_csv.append(output_ret)
            print(output_csv)
    
    with open(output_file_path, 'w') as outfile:
        for item in output_csv:
            outfile.write(f"{item}\n")

if __name__ == "__main__":
    main()