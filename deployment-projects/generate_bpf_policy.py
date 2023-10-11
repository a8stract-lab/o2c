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

# cls_route.c
sched_file = {'exit_route4','init_route4','route4_bind_class','route4_change','route4_classify','route4_delete','route4_delete_filter_work',
            'route4_destroy','route4_dump','route4_get','route4_init','route4_reset_fastmap','route4_walk'}
# nf_tables_api
netfilter_file = {'jhash', 'nf_jiffies64_to_msecs', 'nf_msecs_to_jiffies64', '__nf_tables_abort', 'nf_tables_abort', 
                  'nf_tables_addchain.constprop.0', 'nf_tables_bind_check_setelem', 'nf_tables_bind_set', 'nf_tables_chain_destroy',
                    'nf_tables_chain_notify', 'nf_tables_check_loops', 'nf_tables_cleanup', 'nf_tables_commit', 'nf_tables_commit_audit_log',
                      '__nf_tables_commit_chain_free_rules_old', 'nf_tables_commit_chain_prepare_cancel', 'nf_tables_deactivate_flowtable', 
                      'nf_tables_deactivate_set', 'nf_tables_delchain', 'nf_tables_delflowtable', 'nf_tables_delobj', 'nf_tables_delrule', 
                      'nf_tables_delset', 'nf_tables_delsetelem', 'nf_tables_deltable', 'nf_tables_destroy_set', 'nf_tables_dump_chains', 
                      'nf_tables_dump_flowtable', 'nf_tables_dump_flowtable_done', 'nf_tables_dump_flowtable_start', 'nf_tables_dump_obj', 
                      'nf_tables_dump_obj_done', 'nf_tables_dump_obj_start', '__nf_tables_dump_rules', 'nf_tables_dump_rules', 
                      'nf_tables_dump_rules_done', 'nf_tables_dump_rules_start', 'nf_tables_dump_set', 'nf_tables_dump_set_done', 
                      'nf_tables_dump_setelem', 'nf_tables_dump_sets', 'nf_tables_dump_sets_done', 'nf_tables_dump_sets_start', 
                      'nf_tables_dump_set_start', 'nf_tables_dump_tables', 'nf_tables_exit_net', 'nf_tables_expr_parse', 
                      'nf_tables_fill_chain_info', 'nf_tables_fill_chain_info.cold', 'nf_tables_fill_expr_info', 
                      'nf_tables_fill_flowtable_info', 'nf_tables_fill_flowtable_info.cold', 'nf_tables_fill_gen_info', 
                      'nf_tables_fill_obj_info', 'nf_tables_fill_rule_info', 'nf_tables_fill_set', 'nf_tables_fill_setelem_info', 
                      'nf_tables_fill_setelem.isra.0', 'nf_tables_fill_table_info', 'nf_tables_flowtable_destroy', 
                      'nf_tables_flowtable_event', 'nf_tables_flowtable_notify', 'nf_tables_getchain', 'nf_tables_getflowtable', 
                      'nf_tables_getgen', 'nf_tables_getobj', 'nf_tables_getrule', 'nf_tables_getset', 'nf_tables_getsetelem', 
                      'nf_tables_gettable', 'nf_tables_init_net', 'nf_tables_loop_check_setelem', 'nf_tables_module_autoload_cleanup', 
                      'nf_tables_module_exit', 'nf_tables_module_init', 'nf_tables_newchain', 'nf_tables_newflowtable', 'nf_tables_newobj', 
                      'nf_tables_newrule', 'nf_tables_newset', 'nf_tables_newsetelem', 'nf_tables_newtable', 'nf_tables_parse_netdev_hooks',
                      'nf_tables_pre_exit_net', 'nf_tables_register_hook.part.0', 'nf_tables_rule_destroy', 'nf_tables_rule_notify', 
                      'nf_tables_rule_release', 'nf_tables_set_desc_parse', 'nf_tables_setelem_notify', 'nf_tables_set_notify.constprop.0', 
                      'nf_tables_table_destroy', 'nf_tables_table_notify', 'nf_tables_trans_destroy_flush_work', 'nf_tables_trans_destroy_work',
                        '__nf_tables_unregister_hook', 'nf_tables_validate', 'nf_tables_valid_genid', 'nft_add_set_elem', 'nft_chain_add', 
                        'nft_chain_del', 'nft_chain_hash', 'nft_chain_hash_cmp', 'nft_chain_hash_obj', 'nft_chain_lookup_byid', 
                        'nft_chain_lookup.part.0', 'nft_chain_parse_hook', 'nft_chain_release_hook', 'nft_chain_validate', 
                        'nft_chain_validate_dependency', 'nft_chain_validate_hooks', 'nft_data_dump', 'nft_data_hold', 'nft_data_init', 
                        'nft_data_release', 'nft_delchain', 'nft_delflowtable', 'nft_delobj', 'nft_delrule', 'nft_delrule_by_chain', 
                        'nft_delset', 'nft_del_setelem', 'nft_dump_register', 'nft_expr_clone', 'nft_expr_destroy', 'nft_expr_dump', 
                        'nft_expr_init', 'nft_flowtable_lookup', 'nft_flowtable_parse_hook', 'nft_flush_table', 'nft_get_set_elem', 
                        'nft_netdev_hook_alloc', 'nft_netdev_unregister_hooks', 'nft_obj_del', 'nft_obj_destroy', 'nft_obj_init', 
                        'nft_obj_lookup', 'nft_objname_hash', 'nft_objname_hash_cmp', 'nft_objname_hash_obj', 'nft_obj_notify', 
                        'nft_parse_register_load', 'nft_parse_register_store', 'nft_parse_u32_check', 'nft_rcv_nl_event', 
                        'nft_register_chain_type', 'nft_register_expr', 'nft_register_flowtable_net_hooks', 'nft_register_flowtable_type', 
                        'nft_register_obj', '__nft_reg_track_cancel', 'nft_reg_track_cancel', 'nft_reg_track_update', '__nft_release_basechain',
                          '__nft_release_hook', '__nft_release_table', 'nft_request_module', 'nft_request_module.cold', 
                          'nft_rule_expr_deactivate', 'nft_rule_lookup_byid', 'nft_set_catchall_bind_check', 'nft_set_catchall_dump', 
                          'nft_set_catchall_flush', 'nft_set_catchall_gc', 'nft_set_catchall_lookup', 'nft_set_destroy', 'nft_setelem_activate',
                            'nft_setelem_data_deactivate.constprop.0.isra.0', 'nft_set_elem_destroy', 'nft_set_elem_expr_alloc', 
                            'nft_set_elem_expr_clone', 'nft_set_elem_expr_destroy', 'nft_setelem_flush', 'nft_set_elem_init', 
                            'nft_setelem_remove', 'nft_set_ext_memcpy', 'nft_set_gc_batch_alloc', 'nft_set_gc_batch_release', 
                            'nft_set_lookup_global', 'nft_stats_alloc', 'nft_table_disable', 'nft_table_lookup.part.0', 'nft_table_validate', 
                            'nft_trans_alloc_gfp', 'nft_trans_rule_add', 'nft_unregister_chain_type', 'nft_unregister_expr', 
                            '__nft_unregister_flowtable_net_hooks', 'nft_unregister_flowtable_type', 'nft_unregister_obj', 
                            'nft_validate_register_store', 'nft_verdict_dump', 'nft_verdict_uninit', '__rhashtable_insert_fast.constprop.0', 
                            '__rhashtable_lookup', '__rhashtable_remove_fast_one', 'rht_key_get_hash.isra.'}

# ip6_output.c
ipv6_file = {'dst_output', 'ip6_append_data', '__ip6_append_data.isra.0', 'ip6_autoflowlabel', 'ip6_copy_metadata', 'ip6_cork_release', 
                'ip6_dst_lookup', 'ip6_dst_lookup_flow', 'ip6_dst_lookup_tail.constprop.0', 'ip6_dst_lookup_tunnel', 'ip6_finish_output', 
                'ip6_finish_output2', '__ip6_flush_pending_frames', 'ip6_flush_pending_frames', 'ip6_forward', 'ip6_forward_finish', 'ip6_frag_init', 'ip6_fraglist_init', 
                'ip6_fraglist_prepare', 'ip6_fragment', 'ip6_frag_next', '__ip6_make_skb', 'ip6_make_skb', 'ip6_output', 'ip6_push_pending_frames', 
                'ip6_send_skb', 'ip6_setup_cork', 'ip6_sk_dst_lookup_flow', 'ip6_xmit'}

# modify here

# target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/ipv6-functions.txt'
target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/netfilter-functions.txt'
# target_funcs_path = '/home/ppw/Documents/on-the-fly-compartment/deployment-projects/sched-functions.txt'

# target_policy_path = '/home/ppw/Documents/ebpf-detector/linux-6.1/samples/ebpf/comp_ipv6_sample_policy.csv'
target_policy_path = '/home/ppw/Documents/ebpf-detector/linux-6.1/samples/ebpf/comp_netfilter_sample_policy.csv'
# target_policy_path = '/home/ppw/Documents/ebpf-detector/linux-6.1/samples/ebpf/comp_sched_sample_policy.csv'

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

policy_dict = dict()
call_stk = set()
caches = set()
with open(target_policy_path, 'r') as infile:
    for line in infile.readlines():
        x = line.split(', ')
        if len(x) != 3:
            print("=====================")
            continue
        k = int('0x'+x[1], 16) - 1
        v1 = '0x'+x[2][:-1]
        if k in policy_dict:
            print('-------------------')
        else:
            policy_dict[str(hex(k))] = (x[0], int(v1, base=16))

# print(policy_dict)


# startup_64,0x31,0xffffffff810007b0,CALL 0xffffffff810007b0,direct call
cnt_call = 0
cnt_stack = 0
cnt_write = 0
cnt_icall = 0
cnt_stk = 0


stk_switch_back = 0
hotbpf_start = []

used_set = dict()

with open(csv_file_path, 'r') as csvfile:
    csv_reader = csv.reader(csvfile)
    for row in csv_reader:
        if len(row) == 6:
            function_name, offset, target_addr, instruction, insttype, ip = row
            # print(row)
            if function_name not in target_funcs:
                continue
            # if function_name not in sched_file:
            #     continue
            if function_name not in netfilter_file:
                continue
            # if function_name not in ipv6_file:
            #     continue

            match insttype:
                case 'in-direct call':
                    cnt_icall = cnt_icall + 1
                #     print(bpf_templates.icall.format(func=function_name, offset=offset, target_addr=target_addr,prog=str(cnt_icall)))
                case 'direct call':
                    if target_addr in exported_funcs and target_addr not in skiplist:
                        cnt_call = cnt_call + 1
                        stk_switch_back = 1
                        if target_addr in used_set.keys():
                            used_set[target_addr] = used_set[target_addr]+1
                        else:
                            used_set[target_addr] = 1
                        print(bpf_templates.switch_gate.format(func=function_name, offset=offset, prog=str(cnt_call)))
                    if target_addr == '__kmalloc' or target_addr == 'kmalloc_trace':
                        print(bpf_templates.hotbpf.format(func=function_name, offset=offset, prog=str(cnt_call)))
                        # print('call kernel function: ', target_addr)
                case 'call next':
                    cnt_call = cnt_call + 1
                    if stk_switch_back == 1:
                        stk_switch_back = 0
                        print(bpf_templates.switch_gate.format(func=function_name, offset=offset, prog=str(cnt_call)))
                    # if len(hotbpf_start) != 0:
                    #     print(bpf_templates.hotbpf.format(func=hotbpf_start[0], offset=hotbpf_start[1], prog=hotbpf_start[2], next_ip=ip))
                    #     hotbpf_start.clear()
                    # cnt_call = cnt_call + 1
                case 'write stack':
                    cnt_stk = cnt_stk + 1
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
                    if ip in policy_dict:
                        # print('++++++++', ip, policy_dict[ip])
                        if policy_dict[ip][0] == '0':
                            # slab general cache
                            print(bpf_templates.mov_slab.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt_write), target_cache='cache8k'))
                        elif policy_dict[ip][0] == '1':
                            # slab dedicate cache
                            print(bpf_templates.mov_slab.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt_write), target_cache=str(hex(policy_dict[ip][1]))))
                            caches.add(str(hex(policy_dict[ip][1])))
                        elif policy_dict[ip][0] == '2':
                            # buddy
                            print(bpf_templates.mov_buddy.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt_write)))
                            call_stk.add(str(hex(policy_dict[ip][1])))
                        elif policy_dict[ip][0] == '3':
                            # vmalloc
                            print(bpf_templates.mov_vmalloc.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt_write)))
                        elif policy_dict[ip][0] == '4':
                            # pages
                            print(bpf_templates.mov_page.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt_write)))
                        elif policy_dict[ip][0] == '5':
                            # unknown
                            continue
                    else:
                        print(bpf_templates.mov_general.format(func=function_name, offset=offset, target_addr=target_addr, prog=str(cnt_write)))




# // type:
#     // 0-> slab - generic cache
#     // 1-> slab - dedicate cache
#     // 2-> buddy
#     // 3-> vmalloc - caller
#     // 4-> pages
#     // 5-> undefined


# print(cnt)
print('call', cnt_call )
print('writestk', cnt_stack)
print('write', cnt_write)
print('icall', cnt_icall)
print('allwstk', cnt_stk)

# print('caches: ', caches)
# print('call stks: ', call_stk)

