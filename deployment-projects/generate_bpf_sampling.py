import csv
import re
import bpf_templates



# modify here

# target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/ipv6-functions.txt'
# target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/netfilter-functions.txt'
target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/sched-functions.txt'



kprobe_list_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/kprobe_lists.txt'
target_funcs = set()
# csv_file_path = '/home/ppw/Documents/on-the-fly-compartment/bin-project/result.csv'
csv_file_path = '/home/ppw/Documents/on-the-fly-compartment/bin-project/optimized_result.csv'


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
        # print(bpf_templates.function_entry.format(func=f, prog=str(cnt)))
        # cnt = cnt + 1
        # print(bpf_templates.function_exit.format(func=f, prog=str(cnt)))
        # cnt = cnt + 1

print(len(target_funcs))

# startup_64,0x31,0xffffffff810007b0,CALL 0xffffffff810007b0,direct call

with open(csv_file_path, 'r') as csvfile:
    csv_reader = csv.reader(csvfile)
    for row in csv_reader:
        if len(row) == 6:
            function_name, offset, target_addr, instruction, insttype, ip = row
            # print(row)
            if function_name not in target_funcs:
                continue
            # if offset[0] == '-':
            #     continue
            # cnt = cnt + 1

            # print(function_name)
            match insttype:
                # case 'write .data':
                #     print('write .data')
                #     # a,b = extract_register_and_offset(target_addr)
                #     # print(a,b,instruction)
                #     # print(bpf_templates.mov_write.format(func=function_name, offset=offset, target_addr = "ctx->ax", prog=str(cnt)))
                #     cnt = cnt + 1
                # case 'write stack':
                #     print('write stack')
                #     # a,b = extract_register_and_offset(target_addr)
                #     # print(bpf_templates.mov_write.format(func=function_name, offset=offset, target_addr = "ctx->ax", prog=str(cnt)))
                #     # print(a,b,instruction)
                #     cnt = cnt + 1
                case 'write other [TODO]':
                    # print('write other [TODO]')
                    # a,b = extract_register_and_offset(target_addr)
                    # print(bpf_templates.mov_write.format(func=function_name, offset=offset, target_addr = "ctx->ax", prog=str(cnt)))
                    # print(a,b,instruction)
                    print(bpf_templates.sampling_mov_write.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt)))
                    cnt = cnt + 1

# print(cnt)
