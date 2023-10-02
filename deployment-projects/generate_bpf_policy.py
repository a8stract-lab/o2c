import csv
import re
import bpf_templates

skiplist = {'kfree', 'kfree_skb_reason', 'kmem_cache_alloc', 'kmem_cache_free','kvfree_call_rcu','kvfree','free_percpu','kmem_cache_free_bulk','kfree_skb_list_reason','__kfree_skb','kmem_cache_destroy',
            '_raw_read_lock', '_raw_read_unlock', '_raw_write_unlock','_raw_write_lock', 'migrate_disable', 'mutex_lock','mutex_unlock', 'synchronize_rcu', 
            '__check_object_size', 'memset', '__rcu_read_lock', '__mutex_init', 'strnlen', 'kmemdup',
             '__SCT__cond_resched', 'sprintf',  'capable', 'memcmp', 'static_key_enable',  '__local_bh_enable_ip',
             'memmove', 'memcpy', '__stack_chk_fail', 'bpf_iter_run_prog', '__rcu_read_unlock', 'seq_puts', 
             '_raw_spin_trylock', 'mod_timer', '_raw_spin_unlock', 'call_rcu', '__warn_printk', '_raw_spin_lock_bh',
             '_raw_spin_unlock_bh', 'lock_sock_nested', 'release_sock', 'rtnl_is_locked', '__get_user_4', '__get_user_2',
             '_printk', '_raw_read_unlock_bh', '_raw_read_lock_bh', '_raw_write_lock_bh', '_raw_write_unlock_bh', 
             '_raw_spin_lock', 'rtnl_lock', 'rtnl_unlock', 'jiffies_to_msecs', 'rtnl_trylock', 'strcmp', 'jiffies_to_clock_t',
             '_raw_spin_trylock_bh', 'sockopt_lock_sock', 'sockopt_release_sock','__copy_overflow', 'sock_release', '__static_key_slow_dec_deferred',
             '__static_key_deferred_flush', '__SCT__preempt_schedule', 'ns_to_timespec64', 'strlen','migrate_enable','static_key_slow_dec',
             'static_key_slow_inc', 'strncmp', 'seq_printf', 'skb_trim', 'mutex_is_locked','ktime_get',
             '_raw_spin_lock_irqsave','_raw_spin_unlock_irqrestore','__rtnl_unlock','refcount_dec_and_rtnl_lock',
             '__rtnl_lock', 'up_write', '__init_rwsem', 'fortify_panic'}

# modify here

target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/ipv6-functions.txt'
# target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/netfilter-functions.txt'
# target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/sched-functions.txt'


exported_func_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/exported_functions.txt'
exported_funcs = set()
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

print("target functions: ", len(target_funcs))


with open(exported_func_path, 'r') as infile:
    for func in infile.readlines():
        f = func[:-1]
        exported_funcs.add(f)



# startup_64,0x31,0xffffffff810007b0,CALL 0xffffffff810007b0,direct call
cnt_call = 0
cnt_stack = 0
cnt_write = 0
cnt_icall = 0


stk_switch_back = 0

used_set = dict()

with open(csv_file_path, 'r') as csvfile:
    csv_reader = csv.reader(csvfile)
    for row in csv_reader:
        if len(row) == 6:
            function_name, offset, target_addr, instruction, insttype, ip = row
            # print(row)
            if function_name not in target_funcs:
                continue

            match insttype:
                case 'in-direct call':
                    cnt_icall = cnt_icall + 1
                    print(bpf_templates.switch_gate.format(func=function_name, offset=offset, target_addr=target_addr,prog=str(cnt_icall)))
                case 'direct call':
                    if target_addr in exported_funcs and target_addr not in skiplist:
                        cnt_call = cnt_call + 1
                        stk_switch_back = 1
                        if target_addr in used_set.keys():
                            used_set[target_addr] = used_set[target_addr]+1
                        else:
                            used_set[target_addr] = 1
                        print(bpf_templates.switch_gate.format(func=function_name, offset=offset, prog=str(cnt_call)))
                        # print('call kernel function: ', target_addr)
                case 'call next':
                    if stk_switch_back == 1:
                        stk_switch_back = 0
                        print(bpf_templates.switch_gate.format(func=function_name, offset=offset, prog=str(cnt_call)))
                    # cnt_call = cnt_call + 1
                case 'write stack':
                    x = re.search('.*ctx.*ctx.*', target_addr)
                    if x:
                        cnt_stack = cnt_stack + 1
                        print(bpf_templates.mov_stk.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt_stack)))
                case 'write other [TODO]':
                    # print('write other [TODO]')
                    # a,b = extract_register_and_offset(target_addr)
                    # print(bpf_templates.mov_write.format(func=function_name, offset=offset, target_addr = "ctx->ax", prog=str(cnt)))
                    # print(a,b,instruction)
                    # print(bpf_templates.sampling_mov_write.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt)))
                    cnt_write = cnt_write + 1

# print(cnt)
print('call', cnt_call )
print('write stk', cnt_stack)
print('write', cnt_write)

# used_set = sorted(used_set, reverse=True)
sorted_x = sorted(used_set.items(), key=lambda kv: kv[1], reverse=True)
print(len(used_set))
for x in sorted_x:
    # print(x, sorted_x[x])
    print(x)
