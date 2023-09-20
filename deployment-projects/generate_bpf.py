import csv
import re
import bpf_templates



print(bpf_templates.headers)

target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/ipv6-functions.txt'
kprobe_list_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/kprobe_lists.txt'
target_funcs = set()
csv_file_path = '/home/ppw/Documents/on-the-fly-compartment/bin-project/result-0919.csv'

# def extract_register_and_offset(input_str):
#     match = re.match(r'\[(R[ABCD]X|R[BS]P|R[SD]I|R[89]|R1[0-5])\s*\+\s*0x([0-9a-fA-F]+)\]', input_str, re.IGNORECASE)
#     if match:
#         register, offset = match.groups()
#         register_lower = register.lower()
#         ctx_register = f"ctx->{register_lower[1:]}"
#         return ctx_register, f"0x{offset}"
#     else:
#         return None, None
def extract_register_and_offset(s):
    pattern = re.compile(r'\[(?:(R[ABCD]X|R[BS]P|R[SI]I|R[89]|R1[0-5])\s*\+\s*)?((?:0x)?[0-9a-fA-F]+)?\]')
    match = pattern.search(s)
    
    if match:
        register = match.group(1)
        offset = match.group(2)
        
        if register:
            register_output = f"ctx->{register.lower()}"
        else:
            register_output = "0"
        
        if offset:
            offset_output = offset
        else:
            offset_output = "0"
        
        return register_output, offset_output
    else:
        return "0", "0"

# print(bpf_templates.maps.format(map_name='map'))
cnt = 0
kprobes = set()
with open(kprobe_list_path, 'r') as infile:
    for func in infile.readlines():
        f = func[:-1]
        kprobes.add(f)

with open(target_funcs_path, 'r') as infile:
    for func in infile.readlines():
        f = func[:-1]
        if f not in kprobes:
            continue
        target_funcs.add(f)
        print(bpf_templates.function_entry.format(func=f, prog=str(cnt)))
        cnt = cnt + 1
        # print(bpf_templates.function_exit.format(func=f, prog=str(cnt)))
        # cnt = cnt + 1

# startup_64,0x31,0xffffffff810007b0,CALL 0xffffffff810007b0,direct call

with open(csv_file_path, 'r') as csvfile:
    csv_reader = csv.reader(csvfile)
    for row in csv_reader:
        if len(row) == 5:
            function_name, offset, target_addr, instruction, insttype = row

            if function_name not in target_funcs:
                continue
            if offset[0] == '-':
                continue
            # cnt = cnt + 1

            # print(function_name)
            match insttype:
                case 'write .data':
                    # print('write .data')
                    a,b = extract_register_and_offset(target_addr)
                    # print(a,b,instruction)
                    print(bpf_templates.mov_write.format(func=function_name, offset=offset, target_addr = "ctx->ax", prog=str(cnt)))
                    cnt = cnt + 1
                case 'write stack':
                    # print('write stack')
                    a,b = extract_register_and_offset(target_addr)
                    print(bpf_templates.mov_write.format(func=function_name, offset=offset, target_addr = "ctx->ax", prog=str(cnt)))
                    # print(a,b,instruction)
                    cnt = cnt + 1
                case 'write other [TODO]':
                    # print('write other [TODO]')
                    a,b = extract_register_and_offset(target_addr)
                    print(bpf_templates.mov_write.format(func=function_name, offset=offset, target_addr = "ctx->ax", prog=str(cnt)))
                    # print(a,b,instruction)
                    cnt = cnt + 1

# print(cnt)
