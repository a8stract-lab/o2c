import csv

def classify_rows(file_path):
    classified_data = {}
    functions_by_struct = {}
    c = 0
    with open(file_path, newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) != 7:
                continue  # Skip rows that don't have exactly 7 columns

            struct_key = row[3]  # 'struct' is the fourth column
            function_name = row[1]  # 'function' is the second column

            if struct_key not in classified_data:
                classified_data[struct_key] = []

            if row not in classified_data[struct_key]:
                classified_data[struct_key].append(row)

            # c = c+1
            # if c > 100:
            #     break

            # Update functions_by_struct
            if struct_key not in functions_by_struct:
                functions_by_struct[struct_key] = set()
            functions_by_struct[struct_key].add(function_name)

    return classified_data, functions_by_struct

    return classified_data

# Replace 'your_file_path.csv' with the actual file path
file_path = 'results.txt'
data, functions_data  = classify_rows(file_path)

# Printing the classified data
# for struct, rows in data.items():
#     print(f"Struct: {struct}")
#     for row in rows:
#         print(f"  {row}")


# print("\nFunctions by Struct:")
# for struct, functions in functions_data.items():
#     print(f"Struct: {struct} - Functions: {', '.join(functions)}")


# get specific struct

def get_funcs_by_struct(st):
    if st in functions_data:
        return functions_data[st]
    return []

def get_funcs_by_struct_file(st, f):
    res = set()
    if st in data:
        for row in data[st]:
            ff = row[0]
            if f in ff:
                res.add(row[1])
        return res
    return []

# get cred
creds = get_funcs_by_struct('cred')
print(creds)

# print(get_funcs_by_struct_file('cred', 'kernel'))
ll = get_funcs_by_struct_file('cred', 'kernel')
print("\n\n\nsudo bpftrace -e '", end=' ')
for l in ll:
    print('kprobe:%s{ printf("%s\\n"); } '%(l, l), end=' ')
print('\'')



# sudo bpftrace -e ' kprobe:__sys_setresgid{ printf("__sys_setresgid\n"); }  kprobe:audit_receive{ printf("audit_receive\n"); }  kprobe:set_lookup{ printf("set_lookup\n"); }  kprobe:cp_stat64{ printf("cp_stat64\n"); }  kprobe:capable_wrt_inode_uidgid{ printf("capable_wrt_inode_uidgid\n"); }  kprobe:__send_signal_locked{ printf("__send_signal_locked\n"); }  kprobe:release_task{ printf("release_task\n"); }  kprobe:__sys_setreuid{ printf("__sys_setreuid\n"); }  kprobe:projid_m_show{ printf("projid_m_show\n"); }  kprobe:gid_m_show{ printf("gid_m_show\n"); }  kprobe:__sigqueue_alloc{ printf("__sigqueue_alloc\n"); }  kprobe:timens_install{ printf("timens_install\n"); }  kprobe:set_is_seen{ printf("set_is_seen\n"); }  kprobe:map_write{ printf("map_write\n"); }    kprobe:__do_sys_getgid{ printf("__do_sys_getgid\n"); }  kprobe:rdtgroup_mkdir{ printf("rdtgroup_mkdir\n"); }  kprobe:create_user_ns{ printf("create_user_ns\n"); }  kprobe:get_task_cred{ printf("get_task_cred\n"); }  kprobe:cgroup_addrm_files{ printf("cgroup_addrm_files\n"); }  kprobe:current_in_userns{ printf("current_in_userns\n"); }  kprobe:prctl_set_mm_map{ printf("prctl_set_mm_map\n"); }  kprobe:proc_projid_map_write{ printf("proc_projid_map_write\n"); }  kprobe:copy_pid_ns{ printf("copy_pid_ns\n"); }    kprobe:set_create_files_as{ printf("set_create_files_as\n"); }  kprobe:__do_sys_geteuid16{ printf("__do_sys_geteuid16\n"); }  kprobe:uid_m_show{ printf("uid_m_show\n"); }  kprobe:do_notify_parent{ printf("do_notify_parent\n"); }  kprobe:in_egroup_p{ printf("in_egroup_p\n"); }  kprobe:userns_install{ printf("userns_install\n"); }  kprobe:__do_sys_getegid16{ printf("__do_sys_getegid16\n"); }      kprobe:check_kill_permission{ printf("check_kill_permission\n"); }    kprobe:copy_namespaces{ printf("copy_namespaces\n"); }    kprobe:set_groups{ printf("set_groups\n"); }  kprobe:audit_data_to_entry{ printf("audit_data_to_entry\n"); }  kprobe:bpf_get_current_uid_gid{ printf("bpf_get_current_uid_gid\n"); }  kprobe:copy_utsname{ printf("copy_utsname\n"); }  kprobe:rdtgroup_add_files{ printf("rdtgroup_add_files\n"); }     kprobe:audit_set_loginuid{ printf("audit_set_loginuid\n"); }  kprobe:mkdir_mondata_all{ printf("mkdir_mondata_all\n"); }  kprobe:do_acct_process{ printf("do_acct_process\n"); }  kprobe:set_cred_ucounts{ printf("set_cred_ucounts\n"); }  kprobe:rdt_get_tree{ printf("rdt_get_tree\n"); }  kprobe:cgroup_mkdir{ printf("cgroup_mkdir\n"); }  kprobe:__sys_setuid{ printf("__sys_setuid\n"); }  kprobe:taskstats_user_cmd{ printf("taskstats_user_cmd\n"); }  kprobe:commit_creds{ printf("commit_creds\n"); }  kprobe:__ia32_sys_getgroups{ printf("__ia32_sys_getgroups\n"); }    kprobe:__sched_setscheduler{ printf("__sched_setscheduler\n"); }  kprobe:do_notify_parent_cldstop{ printf("do_notify_parent_cldstop\n"); }  kprobe:__sys_setregid{ printf("__sys_setregid\n"); }  kprobe:cgroupns_install{ printf("cgroupns_install\n"); }  kprobe:__sys_setresuid{ printf("__sys_setresuid\n"); }  kprobe:copy_time_ns{ printf("copy_time_ns\n"); }  kprobe:wait_consider_task{ printf("wait_consider_task\n"); }  kprobe:__ia32_sys_tgkill{ printf("__ia32_sys_tgkill\n"); }  kprobe:copy_process{ printf("copy_process\n"); }  kprobe:__sys_setgid{ printf("__sys_setgid\n"); }  kprobe:audit_signal_info{ printf("audit_signal_info\n"); }   kprobe:add_watch_to_object{ printf("add_watch_to_object\n"); }  kprobe:__x64_sys_getgroups16{ printf("__x64_sys_getgroups16\n"); }  kprobe:cred_fscmp{ printf("cred_fscmp\n"); }  kprobe:audit_filter{ printf("audit_filter\n"); }  kprobe:audit_signal_info_syscall{ printf("audit_signal_info_syscall\n"); }  kprobe:audit_log_uring{ printf("audit_log_uring\n"); }  kprobe:utsns_install{ printf("utsns_install\n"); } kprobe:perf_mmap{ printf("perf_mmap\n"); }  kprobe:__do_sys_geteuid{ printf("__do_sys_geteuid\n"); }  kprobe:set_current_groups{ printf("set_current_groups\n"); }  kprobe:audit_log_task_info{ printf("audit_log_task_info\n"); }  kprobe:bacct_add_tsk{ printf("bacct_add_tsk\n"); }  kprobe:__do_sys_getegid{ printf("__do_sys_getegid\n"); }  kprobe:proc_uid_map_write{ printf("proc_uid_map_write\n"); }  kprobe:may_setgroups{ printf("may_setgroups\n"); }    kprobe:audit_log_common_recv_msg{ printf("audit_log_common_recv_msg\n"); }  kprobe:userns_get{ printf("userns_get\n"); }    kprobe:do_seccomp{ printf("do_seccomp\n"); }  kprobe:copy_cgroup_ns{ printf("copy_cgroup_ns\n"); }  kprobe:mm_alloc{ printf("mm_alloc\n"); }    kprobe:prepare_kernel_cred{ printf("prepare_kernel_cred\n"); }  kprobe:free_watch{ printf("free_watch\n"); }  kprobe:pidns_install{ printf("pidns_install\n"); }  kprobe:__x64_sys_tgkill{ printf("__x64_sys_tgkill\n"); }  kprobe:revert_creds{ printf("revert_creds\n"); }  kprobe:unshare_nsproxy_namespaces{ printf("unshare_nsproxy_namespaces\n"); }    kprobe:__sys_bpf{ printf("__sys_bpf\n"); }  kprobe:mkdir_rdt_prepare{ printf("mkdir_rdt_prepare\n"); }  kprobe:rdtgroup_tasks_write{ printf("rdtgroup_tasks_write\n"); }   kprobe:add_del_listener{ printf("add_del_listener\n"); }  kprobe:__do_sys_getgid16{ printf("__do_sys_getgid16\n"); }  kprobe:__ia32_sys_getgroups16{ printf("__ia32_sys_getgroups16\n"); }  kprobe:kill_pid_usb_asyncio{ printf("kill_pid_usb_asyncio\n"); }  kprobe:__do_sys_getuid{ printf("__do_sys_getuid\n"); }  kprobe:__x64_sys_getgroups{ printf("__x64_sys_getgroups\n"); }    kprobe:set_one_prio{ printf("set_one_prio\n"); }  kprobe:in_group_p{ printf("in_group_p\n"); }  kprobe:sched_setaffinity{ printf("sched_setaffinity\n"); }  kprobe:__sys_setfsgid{ printf("__sys_setfsgid\n"); }  kprobe:mkdir_mondata_subdir{ printf("mkdir_mondata_subdir\n"); }  kprobe:get_signal{ printf("get_signal\n"); }  kprobe:__put_cred{ printf("__put_cred\n"); }  kprobe:proc_gid_map_write{ printf("proc_gid_map_write\n"); }  kprobe:__do_sys_getuid16{ printf("__do_sys_getuid16\n"); }  kprobe:audit_log_multicast{ printf("audit_log_multicast\n"); }  kprobe:__sys_setfsuid{ printf("__sys_setfsuid\n"); }  kprobe:copy_creds{ printf("copy_creds\n"); }    kprobe:prepare_exec_creds{ printf("prepare_exec_creds\n"); }  kprobe:abort_creds{ printf("abort_creds\n"); }  kprobe:send_signal_locked{ printf("send_signal_locked\n"); }  kprobe:exit_creds{ printf("exit_creds\n"); }  kprobe:ns_get_owner{ printf("ns_get_owner\n"); }  kprobe:audit_log_task{ printf("audit_log_task\n"); }  '