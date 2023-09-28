1777

SEC("kprobe/__nf_hook_entries_try_shrink+0xaf")
int BPF_KPROBE(do_mov_0)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_hook_entries_try_shrink+0xf5")
int BPF_KPROBE(do_mov_1)
{
    u64 addr = ctx->di + ctx->r11 * 0x1 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_hook_entries_try_shrink+0xfa")
int BPF_KPROBE(do_mov_2)
{
    u64 addr = ctx->di + ctx->r11 * 0x1 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_hook_entries_try_shrink+0xff")
int BPF_KPROBE(do_mov_3)
{
    u64 addr = ctx->si + ctx->r10 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_hook_entries_try_shrink+0x14e")
int BPF_KPROBE(do_mov_4)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x5d")
int BPF_KPROBE(do_mov_5)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x62")
int BPF_KPROBE(do_mov_6)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x65")
int BPF_KPROBE(do_mov_7)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x82")
int BPF_KPROBE(do_mov_8)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x85")
int BPF_KPROBE(do_mov_9)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x89")
int BPF_KPROBE(do_mov_10)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0xb8")
int BPF_KPROBE(do_mov_11)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0xbc")
int BPF_KPROBE(do_mov_12)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0xbf")
int BPF_KPROBE(do_mov_13)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0xc2")
int BPF_KPROBE(do_mov_14)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x1f")
int BPF_KPROBE(do_mov_15)
{
    u64 addr = ctx->di + 0xaa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x2a")
int BPF_KPROBE(do_mov_16)
{
    u64 addr = ctx->di + 0xaa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x35")
int BPF_KPROBE(do_mov_17)
{
    u64 addr = ctx->di + 0xab0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x40")
int BPF_KPROBE(do_mov_18)
{
    u64 addr = ctx->di + 0xab8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x4b")
int BPF_KPROBE(do_mov_19)
{
    u64 addr = ctx->di + 0xac0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x56")
int BPF_KPROBE(do_mov_20)
{
    u64 addr = ctx->di + 0xac8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x61")
int BPF_KPROBE(do_mov_21)
{
    u64 addr = ctx->di + 0xad0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x6c")
int BPF_KPROBE(do_mov_22)
{
    u64 addr = ctx->di + 0xad8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x77")
int BPF_KPROBE(do_mov_23)
{
    u64 addr = ctx->di + 0xae0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x82")
int BPF_KPROBE(do_mov_24)
{
    u64 addr = ctx->di + 0xae8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x8d")
int BPF_KPROBE(do_mov_25)
{
    u64 addr = ctx->di + 0xaf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x98")
int BPF_KPROBE(do_mov_26)
{
    u64 addr = ctx->di + 0xaf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xa3")
int BPF_KPROBE(do_mov_27)
{
    u64 addr = ctx->di + 0xb00;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xae")
int BPF_KPROBE(do_mov_28)
{
    u64 addr = ctx->di + 0xb08;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xb9")
int BPF_KPROBE(do_mov_29)
{
    u64 addr = ctx->di + 0xb10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xc4")
int BPF_KPROBE(do_mov_30)
{
    u64 addr = ctx->di + 0xb18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xcf")
int BPF_KPROBE(do_mov_31)
{
    u64 addr = ctx->di + 0xb20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xda")
int BPF_KPROBE(do_mov_32)
{
    u64 addr = ctx->di + 0xb28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xf1")
int BPF_KPROBE(do_mov_33)
{
    u64 addr = ctx->bx + 0xa38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_unregister_net_hook+0xa1")
int BPF_KPROBE(do_mov_34)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_unregister_net_hook+0xa9")
int BPF_KPROBE(do_mov_35)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_unregister_net_hook+0x11b")
int BPF_KPROBE(do_mov_36)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0xbb")
int BPF_KPROBE(do_mov_37)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0xde")
int BPF_KPROBE(do_mov_38)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0xea")
int BPF_KPROBE(do_mov_39)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0xf2")
int BPF_KPROBE(do_mov_40)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0x11d")
int BPF_KPROBE(do_mov_41)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0x131")
int BPF_KPROBE(do_mov_42)
{
    u64 addr = ctx->r8 + ctx->ax * 0x1 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0x136")
int BPF_KPROBE(do_mov_43)
{
    u64 addr = ctx->r8 + ctx->ax * 0x1 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0x185")
int BPF_KPROBE(do_mov_44)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0x192")
int BPF_KPROBE(do_mov_45)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0x19a")
int BPF_KPROBE(do_mov_46)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0x1c5")
int BPF_KPROBE(do_mov_47)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_delete_raw+0x3c")
int BPF_KPROBE(do_mov_48)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_delete_raw+0x44")
int BPF_KPROBE(do_mov_49)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_delete_raw+0x71")
int BPF_KPROBE(do_mov_50)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_insert_raw+0x5f")
int BPF_KPROBE(do_mov_51)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_insert_raw+0x89")
int BPF_KPROBE(do_mov_52)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_register_net_hook+0xb0")
int BPF_KPROBE(do_mov_53)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_register_net_hook+0x115")
int BPF_KPROBE(do_mov_54)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_next+0x10")
int BPF_KPROBE(do_mov_55)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_set+0x53")
int BPF_KPROBE(do_mov_56)
{
    u64 addr = ctx->r12 + ctx->ax * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_unset+0x44")
int BPF_KPROBE(do_mov_57)
{
    u64 addr = ctx->bx + ctx->dx * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_register+0x5f")
int BPF_KPROBE(do_mov_58)
{
    u64 addr =  - 0x7cccf6c0 + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_register+0xb0")
int BPF_KPROBE(do_mov_59)
{
    u64 addr =  - 0x7cccf6c0 + ctx->r12 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_bind_pf+0x49")
int BPF_KPROBE(do_mov_60)
{
    u64 addr = ctx->r13 + ctx->bx * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0x7c")
int BPF_KPROBE(do_mov_61)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0x9d")
int BPF_KPROBE(do_mov_62)
{
    u64 addr = ctx->r13 + 0xa98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0xe4")
int BPF_KPROBE(do_mov_63)
{
    u64 addr = ctx->r12 - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0xf2")
int BPF_KPROBE(do_mov_64)
{
    u64 addr = ctx->r12 - 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0xf7")
int BPF_KPROBE(do_mov_65)
{
    u64 addr = ctx->r12 - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0x100")
int BPF_KPROBE(do_mov_66)
{
    u64 addr = ctx->r12 - 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0x106")
int BPF_KPROBE(do_mov_67)
{
    u64 addr = ctx->r12 - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_unregister+0x47")
int BPF_KPROBE(do_mov_68)
{
    u64 addr =  - 0x7cccf6c0 + ctx->cx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_add+0x80")
int BPF_KPROBE(do_mov_69)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_add+0xa8")
int BPF_KPROBE(do_mov_70)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_open+0x24")
int BPF_KPROBE(do_mov_71)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_open+0x48")
int BPF_KPROBE(do_mov_72)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_proc_dostring+0xe8")
int BPF_KPROBE(do_mov_73)
{
    u64 addr = ctx->r14 + ctx->r9 * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_proc_dostring+0x1e4")
int BPF_KPROBE(do_mov_74)
{
    u64 addr = ctx->r14 + ctx->r9 * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_unbind_pf+0x37")
int BPF_KPROBE(do_mov_75)
{
    u64 addr = ctx->r12 + ctx->si * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xa7")
int BPF_KPROBE(do_mov_76)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xcf")
int BPF_KPROBE(do_mov_77)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xdc")
int BPF_KPROBE(do_mov_78)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xe2")
int BPF_KPROBE(do_mov_79)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xe7")
int BPF_KPROBE(do_mov_80)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xec")
int BPF_KPROBE(do_mov_81)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xf1")
int BPF_KPROBE(do_mov_82)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xf6")
int BPF_KPROBE(do_mov_83)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xfb")
int BPF_KPROBE(do_mov_84)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x100")
int BPF_KPROBE(do_mov_85)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x127")
int BPF_KPROBE(do_mov_86)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x13f")
int BPF_KPROBE(do_mov_87)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x1a9")
int BPF_KPROBE(do_mov_88)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x1ae")
int BPF_KPROBE(do_mov_89)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x1bb")
int BPF_KPROBE(do_mov_90)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x1c7")
int BPF_KPROBE(do_mov_91)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x1cf")
int BPF_KPROBE(do_mov_92)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x224")
int BPF_KPROBE(do_mov_93)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x22c")
int BPF_KPROBE(do_mov_94)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x234")
int BPF_KPROBE(do_mov_95)
{
    u64 addr = ctx->r12 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x240")
int BPF_KPROBE(do_mov_96)
{
    u64 addr = ctx->r12 + 0x74;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x293")
int BPF_KPROBE(do_mov_97)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x2d9")
int BPF_KPROBE(do_mov_98)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_register_sockopt+0x78")
int BPF_KPROBE(do_mov_99)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_register_sockopt+0x7f")
int BPF_KPROBE(do_mov_100)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_register_sockopt+0x82")
int BPF_KPROBE(do_mov_101)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_unregister_sockopt+0x27")
int BPF_KPROBE(do_mov_102)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_unregister_sockopt+0x2b")
int BPF_KPROBE(do_mov_103)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_unregister_sockopt+0x38")
int BPF_KPROBE(do_mov_104)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_unregister_sockopt+0x3f")
int BPF_KPROBE(do_mov_105)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ip_checksum+0xaa")
int BPF_KPROBE(do_mov_106)
{
    u64 addr = ctx->di + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ip_checksum+0xcb")
int BPF_KPROBE(do_mov_107)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ip_checksum+0xf1")
int BPF_KPROBE(do_mov_108)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ip6_checksum+0xa4")
int BPF_KPROBE(do_mov_109)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ip6_checksum+0x11f")
int BPF_KPROBE(do_mov_110)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_checksum_partial+0xbe")
int BPF_KPROBE(do_mov_111)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_checksum_partial+0x138")
int BPF_KPROBE(do_mov_112)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_subsys_unregister+0x2a")
int BPF_KPROBE(do_mov_113)
{
    u64 addr =  - 0x7c6f1140 + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_bind+0xb8")
int BPF_KPROBE(do_mov_114)
{
    u64 addr = ctx->r12 + 0xb38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_subsys_register+0x82")
int BPF_KPROBE(do_mov_115)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_net_init+0x7e")
int BPF_KPROBE(do_mov_116)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_unbind+0x7e")
int BPF_KPROBE(do_mov_117)
{
    u64 addr = ctx->r12 + 0xb38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0xda")
int BPF_KPROBE(do_mov_118)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x207")
int BPF_KPROBE(do_mov_119)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x20b")
int BPF_KPROBE(do_mov_120)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x214")
int BPF_KPROBE(do_mov_121)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x21f")
int BPF_KPROBE(do_mov_122)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x223")
int BPF_KPROBE(do_mov_123)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x22e")
int BPF_KPROBE(do_mov_124)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x239")
int BPF_KPROBE(do_mov_125)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x244")
int BPF_KPROBE(do_mov_126)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x24f")
int BPF_KPROBE(do_mov_127)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x25a")
int BPF_KPROBE(do_mov_128)
{
    u64 addr = ctx->ax + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x26c")
int BPF_KPROBE(do_mov_129)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x270")
int BPF_KPROBE(do_mov_130)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x31d")
int BPF_KPROBE(do_mov_131)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x322")
int BPF_KPROBE(do_mov_132)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x32f")
int BPF_KPROBE(do_mov_133)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x332")
int BPF_KPROBE(do_mov_134)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x3b9")
int BPF_KPROBE(do_mov_135)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x3bd")
int BPF_KPROBE(do_mov_136)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x3ca")
int BPF_KPROBE(do_mov_137)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x3ce")
int BPF_KPROBE(do_mov_138)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x438")
int BPF_KPROBE(do_mov_139)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x43d")
int BPF_KPROBE(do_mov_140)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x44a")
int BPF_KPROBE(do_mov_141)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x44e")
int BPF_KPROBE(do_mov_142)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x4b3")
int BPF_KPROBE(do_mov_143)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x4b8")
int BPF_KPROBE(do_mov_144)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x4c5")
int BPF_KPROBE(do_mov_145)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x4c8")
int BPF_KPROBE(do_mov_146)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x68f")
int BPF_KPROBE(do_mov_147)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x693")
int BPF_KPROBE(do_mov_148)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x6a0")
int BPF_KPROBE(do_mov_149)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x6a4")
int BPF_KPROBE(do_mov_150)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x7ce")
int BPF_KPROBE(do_mov_151)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x7d3")
int BPF_KPROBE(do_mov_152)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x7e0")
int BPF_KPROBE(do_mov_153)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x7e3")
int BPF_KPROBE(do_mov_154)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x88d")
int BPF_KPROBE(do_mov_155)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x892")
int BPF_KPROBE(do_mov_156)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x89f")
int BPF_KPROBE(do_mov_157)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x8a2")
int BPF_KPROBE(do_mov_158)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_fill_info.constprop.0+0x76")
int BPF_KPROBE(do_mov_159)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_fill_info.constprop.0+0x162")
int BPF_KPROBE(do_mov_160)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0xac")
int BPF_KPROBE(do_mov_161)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0xb3")
int BPF_KPROBE(do_mov_162)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x179")
int BPF_KPROBE(do_mov_163)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x19c")
int BPF_KPROBE(do_mov_164)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x19f")
int BPF_KPROBE(do_mov_165)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x1ae")
int BPF_KPROBE(do_mov_166)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x1b2")
int BPF_KPROBE(do_mov_167)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x1b6")
int BPF_KPROBE(do_mov_168)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x1b9")
int BPF_KPROBE(do_mov_169)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x1fd")
int BPF_KPROBE(do_mov_170)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x204")
int BPF_KPROBE(do_mov_171)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_start+0x84")
int BPF_KPROBE(do_mov_172)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_start+0x8e")
int BPF_KPROBE(do_mov_173)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_start+0x94")
int BPF_KPROBE(do_mov_174)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_net_init+0x2d")
int BPF_KPROBE(do_mov_175)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_net_init+0x30")
int BPF_KPROBE(do_mov_176)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_net_exit+0x70")
int BPF_KPROBE(do_mov_177)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_net_exit+0x74")
int BPF_KPROBE(do_mov_178)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_net_exit+0x7c")
int BPF_KPROBE(do_mov_179)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_dump+0xba")
int BPF_KPROBE(do_mov_180)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_dump+0xdb")
int BPF_KPROBE(do_mov_181)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_dump+0x111")
int BPF_KPROBE(do_mov_182)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0x99")
int BPF_KPROBE(do_mov_183)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0x9d")
int BPF_KPROBE(do_mov_184)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0xaa")
int BPF_KPROBE(do_mov_185)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0x109")
int BPF_KPROBE(do_mov_186)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0x10d")
int BPF_KPROBE(do_mov_187)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0x110")
int BPF_KPROBE(do_mov_188)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/instance_destroy_rcu+0x5b")
int BPF_KPROBE(do_mov_189)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/instance_destroy_rcu+0x5f")
int BPF_KPROBE(do_mov_190)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/instance_destroy_rcu+0x62")
int BPF_KPROBE(do_mov_191)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/instance_destroy_rcu+0x65")
int BPF_KPROBE(do_mov_192)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x2e9")
int BPF_KPROBE(do_mov_193)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x2f6")
int BPF_KPROBE(do_mov_194)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x2ff")
int BPF_KPROBE(do_mov_195)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x313")
int BPF_KPROBE(do_mov_196)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x31e")
int BPF_KPROBE(do_mov_197)
{
    u64 addr = ctx->r14 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x728")
int BPF_KPROBE(do_mov_198)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x736")
int BPF_KPROBE(do_mov_199)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x752")
int BPF_KPROBE(do_mov_200)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb2e")
int BPF_KPROBE(do_mov_201)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb31")
int BPF_KPROBE(do_mov_202)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb38")
int BPF_KPROBE(do_mov_203)
{
    u64 addr = ctx->r14 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb50")
int BPF_KPROBE(do_mov_204)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb57")
int BPF_KPROBE(do_mov_205)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb5b")
int BPF_KPROBE(do_mov_206)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb60")
int BPF_KPROBE(do_mov_207)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xcad")
int BPF_KPROBE(do_mov_208)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_bridge_adjust_segmented_data+0x39")
int BPF_KPROBE(do_mov_209)
{
    u64 addr = ctx->di + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_dev_event+0xb8")
int BPF_KPROBE(do_mov_210)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_dev_event+0xbc")
int BPF_KPROBE(do_mov_211)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_dev_event+0xc9")
int BPF_KPROBE(do_mov_212)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_dev_event+0xd0")
int BPF_KPROBE(do_mov_213)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_next+0x59")
int BPF_KPROBE(do_mov_214)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_queue_net_init+0x41")
int BPF_KPROBE(do_mov_215)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_queue_net_init+0x4a")
int BPF_KPROBE(do_mov_216)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_queue_net_init+0x6a")
int BPF_KPROBE(do_mov_217)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_nl_event+0x9d")
int BPF_KPROBE(do_mov_218)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_nl_event+0xa5")
int BPF_KPROBE(do_mov_219)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_nl_event+0xa9")
int BPF_KPROBE(do_mov_220)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0x72")
int BPF_KPROBE(do_mov_221)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0x80")
int BPF_KPROBE(do_mov_222)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0xe8")
int BPF_KPROBE(do_mov_223)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x132")
int BPF_KPROBE(do_mov_224)
{
    u64 addr = ctx->r11 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x136")
int BPF_KPROBE(do_mov_225)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x139")
int BPF_KPROBE(do_mov_226)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x13c")
int BPF_KPROBE(do_mov_227)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x14c")
int BPF_KPROBE(do_mov_228)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x14f")
int BPF_KPROBE(do_mov_229)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x156")
int BPF_KPROBE(do_mov_230)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x1a9")
int BPF_KPROBE(do_mov_231)
{
    u64 addr = ctx->dx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x1c4")
int BPF_KPROBE(do_mov_232)
{
    u64 addr = ctx->dx + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_enqueue_packet+0xe0")
int BPF_KPROBE(do_mov_233)
{
    u64 addr = ctx->bx + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_enqueue_packet+0x18d")
int BPF_KPROBE(do_mov_234)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_enqueue_packet+0x1d8")
int BPF_KPROBE(do_mov_235)
{
    u64 addr = ctx->r11 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_enqueue_packet+0x225")
int BPF_KPROBE(do_mov_236)
{
    u64 addr = ctx->bx + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_enqueue_packet+0x296")
int BPF_KPROBE(do_mov_237)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_enqueue_packet+0x2c5")
int BPF_KPROBE(do_mov_238)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x131")
int BPF_KPROBE(do_mov_239)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x135")
int BPF_KPROBE(do_mov_240)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x142")
int BPF_KPROBE(do_mov_241)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x14a")
int BPF_KPROBE(do_mov_242)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x257")
int BPF_KPROBE(do_mov_243)
{
    u64 addr = ctx->ax + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x25e")
int BPF_KPROBE(do_mov_244)
{
    u64 addr = ctx->ax + 0x9a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x2df")
int BPF_KPROBE(do_mov_245)
{
    u64 addr = ctx->dx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x2fb")
int BPF_KPROBE(do_mov_246)
{
    u64 addr = ctx->dx + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x45a")
int BPF_KPROBE(do_mov_247)
{
    u64 addr = ctx->r8 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x462")
int BPF_KPROBE(do_mov_248)
{
    u64 addr = ctx->r8 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x4b5")
int BPF_KPROBE(do_mov_249)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x1ed")
int BPF_KPROBE(do_mov_250)
{
    u64 addr = ctx->r8 + 0x36;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x200")
int BPF_KPROBE(do_mov_251)
{
    u64 addr = ctx->r8 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x23b")
int BPF_KPROBE(do_mov_252)
{
    u64 addr = ctx->r8 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x279")
int BPF_KPROBE(do_mov_253)
{
    u64 addr = ctx->r8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x313")
int BPF_KPROBE(do_mov_254)
{
    u64 addr = ctx->r8 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x31a")
int BPF_KPROBE(do_mov_255)
{
    u64 addr = ctx->r8 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x322")
int BPF_KPROBE(do_mov_256)
{
    u64 addr = ctx->r8 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x326")
int BPF_KPROBE(do_mov_257)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x32a")
int BPF_KPROBE(do_mov_258)
{
    u64 addr = ctx->r8 + 0x36;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x32f")
int BPF_KPROBE(do_mov_259)
{
    u64 addr = ctx->r8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x337")
int BPF_KPROBE(do_mov_260)
{
    u64 addr = ctx->r8 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x371")
int BPF_KPROBE(do_mov_261)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x375")
int BPF_KPROBE(do_mov_262)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x378")
int BPF_KPROBE(do_mov_263)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x380")
int BPF_KPROBE(do_mov_264)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x414")
int BPF_KPROBE(do_mov_265)
{
    u64 addr = ctx->r8 + 0x36;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x418")
int BPF_KPROBE(do_mov_266)
{
    u64 addr = ctx->r8 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x43c")
int BPF_KPROBE(do_mov_267)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x444")
int BPF_KPROBE(do_mov_268)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x460")
int BPF_KPROBE(do_mov_269)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_nf_hook_drop+0x98")
int BPF_KPROBE(do_mov_270)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_nf_hook_drop+0x9c")
int BPF_KPROBE(do_mov_271)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_nf_hook_drop+0x9f")
int BPF_KPROBE(do_mov_272)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_nf_hook_drop+0xa2")
int BPF_KPROBE(do_mov_273)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfulnl_send+0x5e")
int BPF_KPROBE(do_mov_274)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfulnl_send+0x65")
int BPF_KPROBE(do_mov_275)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_next+0x59")
int BPF_KPROBE(do_mov_276)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_log_net_init+0x45")
int BPF_KPROBE(do_mov_277)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_log_net_init+0x4e")
int BPF_KPROBE(do_mov_278)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_log_net_init+0x6e")
int BPF_KPROBE(do_mov_279)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0x4a")
int BPF_KPROBE(do_mov_280)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0x59")
int BPF_KPROBE(do_mov_281)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0xbb")
int BPF_KPROBE(do_mov_282)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__instance_destroy+0x17")
int BPF_KPROBE(do_mov_283)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__instance_destroy+0x1f")
int BPF_KPROBE(do_mov_284)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__instance_destroy+0x32")
int BPF_KPROBE(do_mov_285)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__instance_destroy+0x45")
int BPF_KPROBE(do_mov_286)
{
    u64 addr = ctx->r12 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x193")
int BPF_KPROBE(do_mov_287)
{
    u64 addr = ctx->r13 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x1a5")
int BPF_KPROBE(do_mov_288)
{
    u64 addr = ctx->r13 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x1cd")
int BPF_KPROBE(do_mov_289)
{
    u64 addr = ctx->r13 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x204")
int BPF_KPROBE(do_mov_290)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x22c")
int BPF_KPROBE(do_mov_291)
{
    u64 addr = ctx->r13 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x259")
int BPF_KPROBE(do_mov_292)
{
    u64 addr = ctx->r13 + 0x7a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x326")
int BPF_KPROBE(do_mov_293)
{
    u64 addr = ctx->r13 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x32a")
int BPF_KPROBE(do_mov_294)
{
    u64 addr = ctx->r13 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x3b8")
int BPF_KPROBE(do_mov_295)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x3d6")
int BPF_KPROBE(do_mov_296)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x3de")
int BPF_KPROBE(do_mov_297)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x3e6")
int BPF_KPROBE(do_mov_298)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x423")
int BPF_KPROBE(do_mov_299)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x427")
int BPF_KPROBE(do_mov_300)
{
    u64 addr = ctx->r13 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x42c")
int BPF_KPROBE(do_mov_301)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x433")
int BPF_KPROBE(do_mov_302)
{
    u64 addr = ctx->r13 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x438")
int BPF_KPROBE(do_mov_303)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x446")
int BPF_KPROBE(do_mov_304)
{
    u64 addr = ctx->r13 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x454")
int BPF_KPROBE(do_mov_305)
{
    u64 addr = ctx->r13 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x46b")
int BPF_KPROBE(do_mov_306)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x46f")
int BPF_KPROBE(do_mov_307)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x473")
int BPF_KPROBE(do_mov_308)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x47b")
int BPF_KPROBE(do_mov_309)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x1e1")
int BPF_KPROBE(do_mov_310)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x24b")
int BPF_KPROBE(do_mov_311)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x254")
int BPF_KPROBE(do_mov_312)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x258")
int BPF_KPROBE(do_mov_313)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x573")
int BPF_KPROBE(do_mov_314)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x57e")
int BPF_KPROBE(do_mov_315)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x5a1")
int BPF_KPROBE(do_mov_316)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x735")
int BPF_KPROBE(do_mov_317)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x8fe")
int BPF_KPROBE(do_mov_318)
{
    u64 addr = ctx->r15 + 0x74;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0xc22")
int BPF_KPROBE(do_mov_319)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0xcd7")
int BPF_KPROBE(do_mov_320)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0xcec")
int BPF_KPROBE(do_mov_321)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_match_one+0x108")
int BPF_KPROBE(do_mov_322)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_match_one+0x130")
int BPF_KPROBE(do_mov_323)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_remove_callback+0x88")
int BPF_KPROBE(do_mov_324)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_remove_callback+0x8c")
int BPF_KPROBE(do_mov_325)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_remove_callback+0x99")
int BPF_KPROBE(do_mov_326)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_add_callback+0x7e")
int BPF_KPROBE(do_mov_327)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_add_callback+0xe5")
int BPF_KPROBE(do_mov_328)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_add_callback+0xfc")
int BPF_KPROBE(do_mov_329)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_add_callback+0x103")
int BPF_KPROBE(do_mov_330)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_add_callback+0x106")
int BPF_KPROBE(do_mov_331)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x7a")
int BPF_KPROBE(do_mov_332)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x8b")
int BPF_KPROBE(do_mov_333)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x96")
int BPF_KPROBE(do_mov_334)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0xc6")
int BPF_KPROBE(do_mov_335)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x104")
int BPF_KPROBE(do_mov_336)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x14c")
int BPF_KPROBE(do_mov_337)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x155")
int BPF_KPROBE(do_mov_338)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_find+0xa7")
int BPF_KPROBE(do_mov_339)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_find+0xaf")
int BPF_KPROBE(do_mov_340)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_start+0x129")
int BPF_KPROBE(do_mov_341)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_start+0x130")
int BPF_KPROBE(do_mov_342)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_start+0x135")
int BPF_KPROBE(do_mov_343)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_start+0x13c")
int BPF_KPROBE(do_mov_344)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x9c")
int BPF_KPROBE(do_mov_345)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0xb3")
int BPF_KPROBE(do_mov_346)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0xb9")
int BPF_KPROBE(do_mov_347)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0xe8")
int BPF_KPROBE(do_mov_348)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x101")
int BPF_KPROBE(do_mov_349)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x3a0")
int BPF_KPROBE(do_mov_350)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x3b6")
int BPF_KPROBE(do_mov_351)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x3d0")
int BPF_KPROBE(do_mov_352)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump+0x85")
int BPF_KPROBE(do_mov_353)
{
    u64 addr = ctx->r15 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump+0xf1")
int BPF_KPROBE(do_mov_354)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump+0xfc")
int BPF_KPROBE(do_mov_355)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump+0x138")
int BPF_KPROBE(do_mov_356)
{
    u64 addr = ctx->r15 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x20")
int BPF_KPROBE(do_mov_357)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x24")
int BPF_KPROBE(do_mov_358)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x28")
int BPF_KPROBE(do_mov_359)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x31")
int BPF_KPROBE(do_mov_360)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x49")
int BPF_KPROBE(do_mov_361)
{
    u64 addr = ctx->ax + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x4d")
int BPF_KPROBE(do_mov_362)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x51")
int BPF_KPROBE(do_mov_363)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_hash_insert+0x59")
int BPF_KPROBE(do_mov_364)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_change_timeout+0x2b")
int BPF_KPROBE(do_mov_365)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x6")
int BPF_KPROBE(do_mov_366)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0xe")
int BPF_KPROBE(do_mov_367)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x15")
int BPF_KPROBE(do_mov_368)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x20")
int BPF_KPROBE(do_mov_369)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x28")
int BPF_KPROBE(do_mov_370)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x34")
int BPF_KPROBE(do_mov_371)
{
    u64 addr = ctx->di + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x4c")
int BPF_KPROBE(do_mov_372)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x4f")
int BPF_KPROBE(do_mov_373)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x5a")
int BPF_KPROBE(do_mov_374)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x5e")
int BPF_KPROBE(do_mov_375)
{
    u64 addr = ctx->di + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x6e")
int BPF_KPROBE(do_mov_376)
{
    u64 addr = ctx->di + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x7e")
int BPF_KPROBE(do_mov_377)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x86")
int BPF_KPROBE(do_mov_378)
{
    u64 addr = ctx->di + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x93")
int BPF_KPROBE(do_mov_379)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x97")
int BPF_KPROBE(do_mov_380)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_alloc_hashtable+0x35")
int BPF_KPROBE(do_mov_381)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_alloc_hashtable+0x60")
int BPF_KPROBE(do_mov_382)
{
    u64 addr = ctx->ax + ctx->dx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_port_nlattr_to_tuple+0x1b")
int BPF_KPROBE(do_mov_383)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_port_nlattr_to_tuple+0x33")
int BPF_KPROBE(do_mov_384)
{
    u64 addr = ctx->si + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tmpl_alloc+0x4e")
int BPF_KPROBE(do_mov_385)
{
    u64 addr = ctx->ax + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tmpl_alloc+0x55")
int BPF_KPROBE(do_mov_386)
{
    u64 addr = ctx->ax + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tmpl_alloc+0x60")
int BPF_KPROBE(do_mov_387)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tmpl_alloc+0x63")
int BPF_KPROBE(do_mov_388)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x2e")
int BPF_KPROBE(do_mov_389)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x37")
int BPF_KPROBE(do_mov_390)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x3f")
int BPF_KPROBE(do_mov_391)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x48")
int BPF_KPROBE(do_mov_392)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x51")
int BPF_KPROBE(do_mov_393)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x5a")
int BPF_KPROBE(do_mov_394)
{
    u64 addr = ctx->r12 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0xb4")
int BPF_KPROBE(do_mov_395)
{
    u64 addr = ctx->r12 + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0xb9")
int BPF_KPROBE(do_mov_396)
{
    u64 addr = ctx->r12 + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x133")
int BPF_KPROBE(do_mov_397)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x13d")
int BPF_KPROBE(do_mov_398)
{
    u64 addr = ctx->r12 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x18b")
int BPF_KPROBE(do_mov_399)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x18f")
int BPF_KPROBE(do_mov_400)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x19c")
int BPF_KPROBE(do_mov_401)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x1a1")
int BPF_KPROBE(do_mov_402)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x1c0")
int BPF_KPROBE(do_mov_403)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x1c7")
int BPF_KPROBE(do_mov_404)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_l4proto+0x31")
int BPF_KPROBE(do_mov_405)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_l4proto+0x89")
int BPF_KPROBE(do_mov_406)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_l4proto+0xe3")
int BPF_KPROBE(do_mov_407)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_attach+0x2d")
int BPF_KPROBE(do_mov_408)
{
    u64 addr = ctx->ax + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_refresh_acct+0x32")
int BPF_KPROBE(do_mov_409)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_insert_prepare+0x4c")
int BPF_KPROBE(do_mov_410)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_alter_reply+0x5f")
int BPF_KPROBE(do_mov_411)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_alter_reply+0x68")
int BPF_KPROBE(do_mov_412)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_alter_reply+0x71")
int BPF_KPROBE(do_mov_413)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_alter_reply+0x7a")
int BPF_KPROBE(do_mov_414)
{
    u64 addr = ctx->bx + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_alter_reply+0x83")
int BPF_KPROBE(do_mov_415)
{
    u64 addr = ctx->bx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_delete_from_lists+0xb9")
int BPF_KPROBE(do_mov_416)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_delete_from_lists+0xc0")
int BPF_KPROBE(do_mov_417)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_delete_from_lists+0xd2")
int BPF_KPROBE(do_mov_418)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_delete_from_lists+0xda")
int BPF_KPROBE(do_mov_419)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_delete_from_lists+0xe1")
int BPF_KPROBE(do_mov_420)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_delete_from_lists+0xff")
int BPF_KPROBE(do_mov_421)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x85")
int BPF_KPROBE(do_mov_422)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x9f")
int BPF_KPROBE(do_mov_423)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xa7")
int BPF_KPROBE(do_mov_424)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xaf")
int BPF_KPROBE(do_mov_425)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xb7")
int BPF_KPROBE(do_mov_426)
{
    u64 addr = ctx->r8 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xbf")
int BPF_KPROBE(do_mov_427)
{
    u64 addr = ctx->r8 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xca")
int BPF_KPROBE(do_mov_428)
{
    u64 addr = ctx->r8 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xd2")
int BPF_KPROBE(do_mov_429)
{
    u64 addr = ctx->r8 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xd9")
int BPF_KPROBE(do_mov_430)
{
    u64 addr = ctx->r8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xe1")
int BPF_KPROBE(do_mov_431)
{
    u64 addr = ctx->r8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xe8")
int BPF_KPROBE(do_mov_432)
{
    u64 addr = ctx->r8 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xf0")
int BPF_KPROBE(do_mov_433)
{
    u64 addr = ctx->r8 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xf8")
int BPF_KPROBE(do_mov_434)
{
    u64 addr = ctx->r8 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x100")
int BPF_KPROBE(do_mov_435)
{
    u64 addr = ctx->r8 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x108")
int BPF_KPROBE(do_mov_436)
{
    u64 addr = ctx->r8 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x10f")
int BPF_KPROBE(do_mov_437)
{
    u64 addr = ctx->r8 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x11b")
int BPF_KPROBE(do_mov_438)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x122")
int BPF_KPROBE(do_mov_439)
{
    u64 addr = ctx->r8 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x144")
int BPF_KPROBE(do_mov_440)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x256")
int BPF_KPROBE(do_mov_441)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x35a")
int BPF_KPROBE(do_mov_442)
{
    u64 addr = ctx->r15 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x386")
int BPF_KPROBE(do_mov_443)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x393")
int BPF_KPROBE(do_mov_444)
{
    u64 addr = ctx->r15 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x3a4")
int BPF_KPROBE(do_mov_445)
{
    u64 addr = ctx->r15 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x181")
int BPF_KPROBE(do_mov_446)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x1d3")
int BPF_KPROBE(do_mov_447)
{
    u64 addr = ctx->si + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x348")
int BPF_KPROBE(do_mov_448)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x34e")
int BPF_KPROBE(do_mov_449)
{
    u64 addr = ctx->bx + 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x357")
int BPF_KPROBE(do_mov_450)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x3ad")
int BPF_KPROBE(do_mov_451)
{
    u64 addr = ctx->bx + 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x3b1")
int BPF_KPROBE(do_mov_452)
{
    u64 addr = ctx->bx + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x3c6")
int BPF_KPROBE(do_mov_453)
{
    u64 addr = ctx->ax + 0x69;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x4d8")
int BPF_KPROBE(do_mov_454)
{
    u64 addr = ctx->ax + 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x4dc")
int BPF_KPROBE(do_mov_455)
{
    u64 addr = ctx->ax + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x4e0")
int BPF_KPROBE(do_mov_456)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_check_insert+0x3d6")
int BPF_KPROBE(do_mov_457)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_check_insert+0x47e")
int BPF_KPROBE(do_mov_458)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x50")
int BPF_KPROBE(do_mov_459)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x57")
int BPF_KPROBE(do_mov_460)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x5f")
int BPF_KPROBE(do_mov_461)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x67")
int BPF_KPROBE(do_mov_462)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x6f")
int BPF_KPROBE(do_mov_463)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x15a")
int BPF_KPROBE(do_mov_464)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x162")
int BPF_KPROBE(do_mov_465)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x16b")
int BPF_KPROBE(do_mov_466)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x174")
int BPF_KPROBE(do_mov_467)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x17d")
int BPF_KPROBE(do_mov_468)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_in+0x5e")
int BPF_KPROBE(do_mov_469)
{
    u64 addr = ctx->di + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_confirm+0x34e")
int BPF_KPROBE(do_mov_470)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_update+0x1b3")
int BPF_KPROBE(do_mov_471)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_update+0x1be")
int BPF_KPROBE(do_mov_472)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_cleanup_net+0x24")
int BPF_KPROBE(do_mov_473)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_cleanup_net+0x28")
int BPF_KPROBE(do_mov_474)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0xfd")
int BPF_KPROBE(do_mov_475)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x105")
int BPF_KPROBE(do_mov_476)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x109")
int BPF_KPROBE(do_mov_477)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x146")
int BPF_KPROBE(do_mov_478)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x14a")
int BPF_KPROBE(do_mov_479)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x14d")
int BPF_KPROBE(do_mov_480)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x155")
int BPF_KPROBE(do_mov_481)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_init_net+0x39")
int BPF_KPROBE(do_mov_482)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_init_net+0x44")
int BPF_KPROBE(do_mov_483)
{
    u64 addr = ctx->r12 + 0xb40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x15")
int BPF_KPROBE(do_mov_484)
{
    u64 addr = ctx->di + 0xb3e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x5a")
int BPF_KPROBE(do_mov_485)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x6c")
int BPF_KPROBE(do_mov_486)
{
    u64 addr = ctx->r12 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x7b")
int BPF_KPROBE(do_mov_487)
{
    u64 addr = ctx->r12 + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x8a")
int BPF_KPROBE(do_mov_488)
{
    u64 addr = ctx->r12 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x99")
int BPF_KPROBE(do_mov_489)
{
    u64 addr = ctx->r12 + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0xa8")
int BPF_KPROBE(do_mov_490)
{
    u64 addr = ctx->r12 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0xb7")
int BPF_KPROBE(do_mov_491)
{
    u64 addr = ctx->r12 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0xc6")
int BPF_KPROBE(do_mov_492)
{
    u64 addr = ctx->r12 + 0x708;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0xd5")
int BPF_KPROBE(do_mov_493)
{
    u64 addr = ctx->r12 + 0x748;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0xe4")
int BPF_KPROBE(do_mov_494)
{
    u64 addr = ctx->r12 + 0x648;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0xf3")
int BPF_KPROBE(do_mov_495)
{
    u64 addr = ctx->r12 + 0x688;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x102")
int BPF_KPROBE(do_mov_496)
{
    u64 addr = ctx->r12 + 0x6c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x111")
int BPF_KPROBE(do_mov_497)
{
    u64 addr = ctx->r12 + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x120")
int BPF_KPROBE(do_mov_498)
{
    u64 addr = ctx->r12 + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x12f")
int BPF_KPROBE(do_mov_499)
{
    u64 addr = ctx->r12 + 0x308;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x13e")
int BPF_KPROBE(do_mov_500)
{
    u64 addr = ctx->r12 + 0x348;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x14d")
int BPF_KPROBE(do_mov_501)
{
    u64 addr = ctx->r12 + 0x388;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x15c")
int BPF_KPROBE(do_mov_502)
{
    u64 addr = ctx->r12 + 0x3c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x16b")
int BPF_KPROBE(do_mov_503)
{
    u64 addr = ctx->r12 + 0x408;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x17a")
int BPF_KPROBE(do_mov_504)
{
    u64 addr = ctx->r12 + 0x448;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x189")
int BPF_KPROBE(do_mov_505)
{
    u64 addr = ctx->r12 + 0x488;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x198")
int BPF_KPROBE(do_mov_506)
{
    u64 addr = ctx->r12 + 0x4c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x1a7")
int BPF_KPROBE(do_mov_507)
{
    u64 addr = ctx->r12 + 0x548;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x1b6")
int BPF_KPROBE(do_mov_508)
{
    u64 addr = ctx->r12 + 0x588;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x1c5")
int BPF_KPROBE(do_mov_509)
{
    u64 addr = ctx->r12 + 0x608;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x1d4")
int BPF_KPROBE(do_mov_510)
{
    u64 addr = ctx->r12 + 0x5c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x1e3")
int BPF_KPROBE(do_mov_511)
{
    u64 addr = ctx->r12 + 0x508;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x1f2")
int BPF_KPROBE(do_mov_512)
{
    u64 addr = ctx->r12 + 0x788;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x201")
int BPF_KPROBE(do_mov_513)
{
    u64 addr = ctx->r12 + 0x7c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x210")
int BPF_KPROBE(do_mov_514)
{
    u64 addr = ctx->r12 + 0x808;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x21f")
int BPF_KPROBE(do_mov_515)
{
    u64 addr = ctx->r12 + 0x848;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x22e")
int BPF_KPROBE(do_mov_516)
{
    u64 addr = ctx->r12 + 0x888;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x23d")
int BPF_KPROBE(do_mov_517)
{
    u64 addr = ctx->r12 + 0x8c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x24c")
int BPF_KPROBE(do_mov_518)
{
    u64 addr = ctx->r12 + 0x9c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x25b")
int BPF_KPROBE(do_mov_519)
{
    u64 addr = ctx->r12 + 0x908;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x26a")
int BPF_KPROBE(do_mov_520)
{
    u64 addr = ctx->r12 + 0xa08;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x279")
int BPF_KPROBE(do_mov_521)
{
    u64 addr = ctx->r12 + 0x948;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x288")
int BPF_KPROBE(do_mov_522)
{
    u64 addr = ctx->r12 + 0xa48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x297")
int BPF_KPROBE(do_mov_523)
{
    u64 addr = ctx->r12 + 0x988;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2a6")
int BPF_KPROBE(do_mov_524)
{
    u64 addr = ctx->r12 + 0xa88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2b5")
int BPF_KPROBE(do_mov_525)
{
    u64 addr = ctx->r12 + 0xac8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2c4")
int BPF_KPROBE(do_mov_526)
{
    u64 addr = ctx->r12 + 0xb88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2d3")
int BPF_KPROBE(do_mov_527)
{
    u64 addr = ctx->r12 + 0xb08;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2e2")
int BPF_KPROBE(do_mov_528)
{
    u64 addr = ctx->r12 + 0xbc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2f1")
int BPF_KPROBE(do_mov_529)
{
    u64 addr = ctx->r12 + 0xb48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2f9")
int BPF_KPROBE(do_mov_530)
{
    u64 addr = ctx->r12 + 0xc08;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x319")
int BPF_KPROBE(do_mov_531)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x31f")
int BPF_KPROBE(do_mov_532)
{
    u64 addr = ctx->r12 + 0x154;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x328")
int BPF_KPROBE(do_mov_533)
{
    u64 addr = ctx->r12 + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x343")
int BPF_KPROBE(do_mov_534)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_alloc+0x23")
int BPF_KPROBE(do_mov_535)
{
    u64 addr = ctx->ax + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_alloc+0x27")
int BPF_KPROBE(do_mov_536)
{
    u64 addr = ctx->ax + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x29")
int BPF_KPROBE(do_mov_537)
{
    u64 addr = ctx->ax + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2f")
int BPF_KPROBE(do_mov_538)
{
    u64 addr = ctx->ax + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x39")
int BPF_KPROBE(do_mov_539)
{
    u64 addr = ctx->ax + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x41")
int BPF_KPROBE(do_mov_540)
{
    u64 addr = ctx->ax + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x49")
int BPF_KPROBE(do_mov_541)
{
    u64 addr = ctx->ax + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x4d")
int BPF_KPROBE(do_mov_542)
{
    u64 addr = ctx->ax + 0x46;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x61")
int BPF_KPROBE(do_mov_543)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x69")
int BPF_KPROBE(do_mov_544)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x6d")
int BPF_KPROBE(do_mov_545)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x71")
int BPF_KPROBE(do_mov_546)
{
    u64 addr = ctx->r11 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x96")
int BPF_KPROBE(do_mov_547)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x9e")
int BPF_KPROBE(do_mov_548)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0xf5")
int BPF_KPROBE(do_mov_549)
{
    u64 addr = ctx->ax + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0xfc")
int BPF_KPROBE(do_mov_550)
{
    u64 addr = ctx->ax + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x107")
int BPF_KPROBE(do_mov_551)
{
    u64 addr = ctx->ax + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x10b")
int BPF_KPROBE(do_mov_552)
{
    u64 addr = ctx->ax + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x123")
int BPF_KPROBE(do_mov_553)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x12c")
int BPF_KPROBE(do_mov_554)
{
    u64 addr = ctx->si + ctx->cx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x157")
int BPF_KPROBE(do_mov_555)
{
    u64 addr = ctx->r10 + ctx->r9 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x169")
int BPF_KPROBE(do_mov_556)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x16f")
int BPF_KPROBE(do_mov_557)
{
    u64 addr = ctx->di + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x179")
int BPF_KPROBE(do_mov_558)
{
    u64 addr = ctx->di + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x181")
int BPF_KPROBE(do_mov_559)
{
    u64 addr = ctx->di + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x189")
int BPF_KPROBE(do_mov_560)
{
    u64 addr = ctx->di + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x18d")
int BPF_KPROBE(do_mov_561)
{
    u64 addr = ctx->di + 0x46;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1a2")
int BPF_KPROBE(do_mov_562)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1ae")
int BPF_KPROBE(do_mov_563)
{
    u64 addr = ctx->ax + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1b6")
int BPF_KPROBE(do_mov_564)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1b9")
int BPF_KPROBE(do_mov_565)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1c0")
int BPF_KPROBE(do_mov_566)
{
    u64 addr = ctx->ax + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1c8")
int BPF_KPROBE(do_mov_567)
{
    u64 addr = ctx->ax + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1dc")
int BPF_KPROBE(do_mov_568)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1e4")
int BPF_KPROBE(do_mov_569)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1eb")
int BPF_KPROBE(do_mov_570)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1f9")
int BPF_KPROBE(do_mov_571)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x200")
int BPF_KPROBE(do_mov_572)
{
    u64 addr = ctx->si + ctx->cx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x228")
int BPF_KPROBE(do_mov_573)
{
    u64 addr = ctx->di + ctx->si * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x235")
int BPF_KPROBE(do_mov_574)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x242")
int BPF_KPROBE(do_mov_575)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x24a")
int BPF_KPROBE(do_mov_576)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x252")
int BPF_KPROBE(do_mov_577)
{
    u64 addr = ctx->r11 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x26d")
int BPF_KPROBE(do_mov_578)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x271")
int BPF_KPROBE(do_mov_579)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x27c")
int BPF_KPROBE(do_mov_580)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x280")
int BPF_KPROBE(do_mov_581)
{
    u64 addr = ctx->ax + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x28d")
int BPF_KPROBE(do_mov_582)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2a0")
int BPF_KPROBE(do_mov_583)
{
    u64 addr = ctx->si + ctx->dx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2aa")
int BPF_KPROBE(do_mov_584)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2b2")
int BPF_KPROBE(do_mov_585)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2bf")
int BPF_KPROBE(do_mov_586)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2c7")
int BPF_KPROBE(do_mov_587)
{
    u64 addr = ctx->di + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2cf")
int BPF_KPROBE(do_mov_588)
{
    u64 addr = ctx->r11 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2ee")
int BPF_KPROBE(do_mov_589)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2f6")
int BPF_KPROBE(do_mov_590)
{
    u64 addr = ctx->si + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x301")
int BPF_KPROBE(do_mov_591)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x307")
int BPF_KPROBE(do_mov_592)
{
    u64 addr = ctx->si + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0x76")
int BPF_KPROBE(do_mov_593)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0x7e")
int BPF_KPROBE(do_mov_594)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0x96")
int BPF_KPROBE(do_mov_595)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0xc4")
int BPF_KPROBE(do_mov_596)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0xc9")
int BPF_KPROBE(do_mov_597)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0xe2")
int BPF_KPROBE(do_mov_598)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x39a")
int BPF_KPROBE(do_mov_599)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3b2")
int BPF_KPROBE(do_mov_600)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3b7")
int BPF_KPROBE(do_mov_601)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3bb")
int BPF_KPROBE(do_mov_602)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3c4")
int BPF_KPROBE(do_mov_603)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3e9")
int BPF_KPROBE(do_mov_604)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3ee")
int BPF_KPROBE(do_mov_605)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3f3")
int BPF_KPROBE(do_mov_606)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3fb")
int BPF_KPROBE(do_mov_607)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_register+0x20")
int BPF_KPROBE(do_mov_608)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_register+0x28")
int BPF_KPROBE(do_mov_609)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_register+0x2b")
int BPF_KPROBE(do_mov_610)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_unregister+0x27")
int BPF_KPROBE(do_mov_611)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_unregister+0x2b")
int BPF_KPROBE(do_mov_612)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_unregister+0x38")
int BPF_KPROBE(do_mov_613)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_register+0x20")
int BPF_KPROBE(do_mov_614)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_register+0x28")
int BPF_KPROBE(do_mov_615)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_register+0x2b")
int BPF_KPROBE(do_mov_616)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_unregister+0x27")
int BPF_KPROBE(do_mov_617)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_unregister+0x2b")
int BPF_KPROBE(do_mov_618)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_unregister+0x38")
int BPF_KPROBE(do_mov_619)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_unregister+0x23")
int BPF_KPROBE(do_mov_620)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_unregister+0x2b")
int BPF_KPROBE(do_mov_621)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_unregister+0x47")
int BPF_KPROBE(do_mov_622)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x2a")
int BPF_KPROBE(do_mov_623)
{
    u64 addr = ctx->di - 0x46;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x32")
int BPF_KPROBE(do_mov_624)
{
    u64 addr = ctx->di - 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x3b")
int BPF_KPROBE(do_mov_625)
{
    u64 addr = ctx->di - 0x5e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x42")
int BPF_KPROBE(do_mov_626)
{
    u64 addr = ctx->di - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x4c")
int BPF_KPROBE(do_mov_627)
{
    u64 addr = ctx->di - 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x53")
int BPF_KPROBE(do_mov_628)
{
    u64 addr = ctx->di - 0x2e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x5b")
int BPF_KPROBE(do_mov_629)
{
    u64 addr = ctx->di - 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x63")
int BPF_KPROBE(do_mov_630)
{
    u64 addr = ctx->di - 0x66;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_ext_add+0x1b")
int BPF_KPROBE(do_mov_631)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_register+0x17c")
int BPF_KPROBE(do_mov_632)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_register+0x188")
int BPF_KPROBE(do_mov_633)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_register+0x18d")
int BPF_KPROBE(do_mov_634)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_register+0x191")
int BPF_KPROBE(do_mov_635)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_register+0x199")
int BPF_KPROBE(do_mov_636)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unhelp+0x6c")
int BPF_KPROBE(do_mov_637)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_try_assign_helper+0xa1")
int BPF_KPROBE(do_mov_638)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_try_assign_helper+0xc7")
int BPF_KPROBE(do_mov_639)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0x98")
int BPF_KPROBE(do_mov_640)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0xbc")
int BPF_KPROBE(do_mov_641)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0xf3")
int BPF_KPROBE(do_mov_642)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0x16c")
int BPF_KPROBE(do_mov_643)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0x195")
int BPF_KPROBE(do_mov_644)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0x1db")
int BPF_KPROBE(do_mov_645)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tcp_fixup+0x26")
int BPF_KPROBE(do_mov_646)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tcp_fixup+0x30")
int BPF_KPROBE(do_mov_647)
{
    u64 addr = ctx->di + 0xd4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_conntrack_local+0x4a")
int BPF_KPROBE(do_mov_648)
{
    u64 addr = ctx->di + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_put+0x75")
int BPF_KPROBE(do_mov_649)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_put+0x91")
int BPF_KPROBE(do_mov_650)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_put+0xc0")
int BPF_KPROBE(do_mov_651)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/generic_timeout_nlattr_to_obj+0x2b")
int BPF_KPROBE(do_mov_652)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/generic_timeout_nlattr_to_obj+0x37")
int BPF_KPROBE(do_mov_653)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_generic_init_net+0x6")
int BPF_KPROBE(do_mov_654)
{
    u64 addr = ctx->di + 0xb50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x20")
int BPF_KPROBE(do_mov_655)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x45")
int BPF_KPROBE(do_mov_656)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x5c")
int BPF_KPROBE(do_mov_657)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x73")
int BPF_KPROBE(do_mov_658)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x8a")
int BPF_KPROBE(do_mov_659)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xa1")
int BPF_KPROBE(do_mov_660)
{
    u64 addr = ctx->dx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xb8")
int BPF_KPROBE(do_mov_661)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xcf")
int BPF_KPROBE(do_mov_662)
{
    u64 addr = ctx->dx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xe6")
int BPF_KPROBE(do_mov_663)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xfd")
int BPF_KPROBE(do_mov_664)
{
    u64 addr = ctx->dx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x114")
int BPF_KPROBE(do_mov_665)
{
    u64 addr = ctx->dx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x12b")
int BPF_KPROBE(do_mov_666)
{
    u64 addr = ctx->dx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x12e")
int BPF_KPROBE(do_mov_667)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_to_nlattr+0xbd")
int BPF_KPROBE(do_mov_668)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0x88")
int BPF_KPROBE(do_mov_669)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0xa3")
int BPF_KPROBE(do_mov_670)
{
    u64 addr = ctx->bx + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0xb2")
int BPF_KPROBE(do_mov_671)
{
    u64 addr = ctx->bx + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0xcd")
int BPF_KPROBE(do_mov_672)
{
    u64 addr = ctx->bx + 0xdd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0xdc")
int BPF_KPROBE(do_mov_673)
{
    u64 addr = ctx->bx + 0xdd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0x12c")
int BPF_KPROBE(do_mov_674)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0x136")
int BPF_KPROBE(do_mov_675)
{
    u64 addr = ctx->bx + 0xdc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_options+0x7b")
int BPF_KPROBE(do_mov_676)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_options+0xec")
int BPF_KPROBE(do_mov_677)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x59")
int BPF_KPROBE(do_mov_678)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x64")
int BPF_KPROBE(do_mov_679)
{
    u64 addr = ctx->bx + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0xb6")
int BPF_KPROBE(do_mov_680)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0xc0")
int BPF_KPROBE(do_mov_681)
{
    u64 addr = ctx->bx + 0xdd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0xcb")
int BPF_KPROBE(do_mov_682)
{
    u64 addr = ctx->bx + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0xda")
int BPF_KPROBE(do_mov_683)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0xe2")
int BPF_KPROBE(do_mov_684)
{
    u64 addr = ctx->bx + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0xe8")
int BPF_KPROBE(do_mov_685)
{
    u64 addr = ctx->bx + 0xe3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x11e")
int BPF_KPROBE(do_mov_686)
{
    u64 addr = ctx->di + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x139")
int BPF_KPROBE(do_mov_687)
{
    u64 addr = ctx->di + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x18a")
int BPF_KPROBE(do_mov_688)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x194")
int BPF_KPROBE(do_mov_689)
{
    u64 addr = ctx->bx + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x1a9")
int BPF_KPROBE(do_mov_690)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x2f2")
int BPF_KPROBE(do_mov_691)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x31c")
int BPF_KPROBE(do_mov_692)
{
    u64 addr = ctx->r11 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x325")
int BPF_KPROBE(do_mov_693)
{
    u64 addr = ctx->r11 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x33c")
int BPF_KPROBE(do_mov_694)
{
    u64 addr = ctx->cx + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x344")
int BPF_KPROBE(do_mov_695)
{
    u64 addr = ctx->cx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x60c")
int BPF_KPROBE(do_mov_696)
{
    u64 addr = ctx->dx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x612")
int BPF_KPROBE(do_mov_697)
{
    u64 addr = ctx->dx + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x635")
int BPF_KPROBE(do_mov_698)
{
    u64 addr = ctx->dx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x644")
int BPF_KPROBE(do_mov_699)
{
    u64 addr = ctx->dx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x656")
int BPF_KPROBE(do_mov_700)
{
    u64 addr = ctx->r12 + 0xf3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x65e")
int BPF_KPROBE(do_mov_701)
{
    u64 addr = ctx->dx + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x67a")
int BPF_KPROBE(do_mov_702)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x685")
int BPF_KPROBE(do_mov_703)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x690")
int BPF_KPROBE(do_mov_704)
{
    u64 addr = ctx->ax + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x71a")
int BPF_KPROBE(do_mov_705)
{
    u64 addr = ctx->r12 + 0xf3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x89a")
int BPF_KPROBE(do_mov_706)
{
    u64 addr = ctx->r12 + 0xe3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x8a9")
int BPF_KPROBE(do_mov_707)
{
    u64 addr = ctx->r12 + 0xe1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x8bb")
int BPF_KPROBE(do_mov_708)
{
    u64 addr = ctx->r12 + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xaf7")
int BPF_KPROBE(do_mov_709)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xcc3")
int BPF_KPROBE(do_mov_710)
{
    u64 addr = ctx->r11 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xcd9")
int BPF_KPROBE(do_mov_711)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xd22")
int BPF_KPROBE(do_mov_712)
{
    u64 addr = ctx->r11 + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xd5e")
int BPF_KPROBE(do_mov_713)
{
    u64 addr = ctx->di + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xdb6")
int BPF_KPROBE(do_mov_714)
{
    u64 addr = ctx->r12 + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xdc4")
int BPF_KPROBE(do_mov_715)
{
    u64 addr = ctx->r12 + 0xe2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xdd3")
int BPF_KPROBE(do_mov_716)
{
    u64 addr = ctx->r12 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xde2")
int BPF_KPROBE(do_mov_717)
{
    u64 addr = ctx->r12 + 0xe4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xdea")
int BPF_KPROBE(do_mov_718)
{
    u64 addr = ctx->r12 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xed9")
int BPF_KPROBE(do_mov_719)
{
    u64 addr = ctx->r11 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xee0")
int BPF_KPROBE(do_mov_720)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xf00")
int BPF_KPROBE(do_mov_721)
{
    u64 addr = ctx->r11 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xf80")
int BPF_KPROBE(do_mov_722)
{
    u64 addr = ctx->r12 + ctx->dx * 0x4 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xf8d")
int BPF_KPROBE(do_mov_723)
{
    u64 addr = ctx->r12 + ctx->dx * 0x4 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x1079")
int BPF_KPROBE(do_mov_724)
{
    u64 addr = ctx->r11 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x1080")
int BPF_KPROBE(do_mov_725)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x10a0")
int BPF_KPROBE(do_mov_726)
{
    u64 addr = ctx->r11 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x10fa")
int BPF_KPROBE(do_mov_727)
{
    u64 addr = ctx->r12 + ctx->dx * 0x4 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x1107")
int BPF_KPROBE(do_mov_728)
{
    u64 addr = ctx->r12 + ctx->dx * 0x4 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x11ee")
int BPF_KPROBE(do_mov_729)
{
    u64 addr = ctx->r11 + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x11f5")
int BPF_KPROBE(do_mov_730)
{
    u64 addr = ctx->cx + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x125e")
int BPF_KPROBE(do_mov_731)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x1276")
int BPF_KPROBE(do_mov_732)
{
    u64 addr = ctx->cx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x163e")
int BPF_KPROBE(do_mov_733)
{
    u64 addr = ctx->r12 + 0xe1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x1646")
int BPF_KPROBE(do_mov_734)
{
    u64 addr = ctx->r12 + 0xe3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x1654")
int BPF_KPROBE(do_mov_735)
{
    u64 addr = ctx->r12 + 0xe4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x168e")
int BPF_KPROBE(do_mov_736)
{
    u64 addr = ctx->r12 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x169f")
int BPF_KPROBE(do_mov_737)
{
    u64 addr = ctx->r12 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x16c3")
int BPF_KPROBE(do_mov_738)
{
    u64 addr = ctx->r12 + 0xf2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x16fd")
int BPF_KPROBE(do_mov_739)
{
    u64 addr = ctx->r12 + 0xf2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x28c992")
int BPF_KPROBE(do_mov_740)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x28c9a4")
int BPF_KPROBE(do_mov_741)
{
    u64 addr = ctx->r12 + 0xe3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x28c9b3")
int BPF_KPROBE(do_mov_742)
{
    u64 addr = ctx->r12 + 0xe1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_init_net+0x15")
int BPF_KPROBE(do_mov_743)
{
    u64 addr = ctx->di + ctx->ax * 0x1 + 0xb54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_init_net+0x31")
int BPF_KPROBE(do_mov_744)
{
    u64 addr = ctx->di + 0xb54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_init_net+0x3b")
int BPF_KPROBE(do_mov_745)
{
    u64 addr = ctx->di + 0xb8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_timeout_nlattr_to_obj+0x1a")
int BPF_KPROBE(do_mov_746)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_timeout_nlattr_to_obj+0x25")
int BPF_KPROBE(do_mov_747)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_timeout_nlattr_to_obj+0x3c")
int BPF_KPROBE(do_mov_748)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_timeout_nlattr_to_obj+0x52")
int BPF_KPROBE(do_mov_749)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_udp_packet+0xee")
int BPF_KPROBE(do_mov_750)
{
    u64 addr = ctx->r13 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_udp_init_net+0x10")
int BPF_KPROBE(do_mov_751)
{
    u64 addr = ctx->di + 0xb94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_udp_init_net+0x17")
int BPF_KPROBE(do_mov_752)
{
    u64 addr = ctx->di + 0xb9c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_nlattr_to_tuple+0x1b")
int BPF_KPROBE(do_mov_753)
{
    u64 addr = ctx->si + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_nlattr_to_tuple+0x3d")
int BPF_KPROBE(do_mov_754)
{
    u64 addr = ctx->si + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_nlattr_to_tuple+0x54")
int BPF_KPROBE(do_mov_755)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_timeout_nlattr_to_obj+0x2b")
int BPF_KPROBE(do_mov_756)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_timeout_nlattr_to_obj+0x3c")
int BPF_KPROBE(do_mov_757)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_pkt_to_tuple+0x3d")
int BPF_KPROBE(do_mov_758)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_pkt_to_tuple+0x44")
int BPF_KPROBE(do_mov_759)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_pkt_to_tuple+0x4c")
int BPF_KPROBE(do_mov_760)
{
    u64 addr = ctx->bx + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmp_tuple+0x27")
int BPF_KPROBE(do_mov_761)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmp_tuple+0x39")
int BPF_KPROBE(do_mov_762)
{
    u64 addr = ctx->di + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmp_tuple+0x40")
int BPF_KPROBE(do_mov_763)
{
    u64 addr = ctx->di + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_inet_error+0x13b")
int BPF_KPROBE(do_mov_764)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_icmp_init_net+0x6")
int BPF_KPROBE(do_mov_765)
{
    u64 addr = ctx->di + 0xba0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0x8b")
int BPF_KPROBE(do_mov_766)
{
    u64 addr = ctx->dx + ctx->r15 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0x92")
int BPF_KPROBE(do_mov_767)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xa2")
int BPF_KPROBE(do_mov_768)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xa9")
int BPF_KPROBE(do_mov_769)
{
    u64 addr = ctx->r8 + ctx->cx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xc9")
int BPF_KPROBE(do_mov_770)
{
    u64 addr = ctx->r13 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xe1")
int BPF_KPROBE(do_mov_771)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xec")
int BPF_KPROBE(do_mov_772)
{
    u64 addr = ctx->r8 + ctx->cx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xf6")
int BPF_KPROBE(do_mov_773)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xfd")
int BPF_KPROBE(do_mov_774)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0x107")
int BPF_KPROBE(do_mov_775)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0x131")
int BPF_KPROBE(do_mov_776)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0x138")
int BPF_KPROBE(do_mov_777)
{
    u64 addr = ctx->r8 + ctx->cx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_acct_pernet_init+0xd")
int BPF_KPROBE(do_mov_778)
{
    u64 addr = ctx->di + 0xb3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seqadj_set+0x9a")
int BPF_KPROBE(do_mov_779)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seqadj_set+0xa0")
int BPF_KPROBE(do_mov_780)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seqadj_set+0xa3")
int BPF_KPROBE(do_mov_781)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seqadj_init+0x4e")
int BPF_KPROBE(do_mov_782)
{
    u64 addr = ctx->di + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seqadj_init+0x51")
int BPF_KPROBE(do_mov_783)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seq_adjust+0xfc")
int BPF_KPROBE(do_mov_784)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seq_adjust+0x169")
int BPF_KPROBE(do_mov_785)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seq_adjust+0x3d1")
int BPF_KPROBE(do_mov_786)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seq_adjust+0x3d5")
int BPF_KPROBE(do_mov_787)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_nlattr_to_tuple+0x1e")
int BPF_KPROBE(do_mov_788)
{
    u64 addr = ctx->si + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_nlattr_to_tuple+0x4a")
int BPF_KPROBE(do_mov_789)
{
    u64 addr = ctx->si + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_nlattr_to_tuple+0x61")
int BPF_KPROBE(do_mov_790)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_timeout_nlattr_to_obj+0x2b")
int BPF_KPROBE(do_mov_791)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_timeout_nlattr_to_obj+0x37")
int BPF_KPROBE(do_mov_792)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_pkt_to_tuple+0x3d")
int BPF_KPROBE(do_mov_793)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_pkt_to_tuple+0x44")
int BPF_KPROBE(do_mov_794)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_pkt_to_tuple+0x4c")
int BPF_KPROBE(do_mov_795)
{
    u64 addr = ctx->bx + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmpv6_tuple+0x32")
int BPF_KPROBE(do_mov_796)
{
    u64 addr = ctx->di + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmpv6_tuple+0x35")
int BPF_KPROBE(do_mov_797)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmpv6_tuple+0x3d")
int BPF_KPROBE(do_mov_798)
{
    u64 addr = ctx->di + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_icmpv6_error+0x108")
int BPF_KPROBE(do_mov_799)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_icmpv6_init_net+0x6")
int BPF_KPROBE(do_mov_800)
{
    u64 addr = ctx->di + 0xba4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_set_timeout+0x10f")
int BPF_KPROBE(do_mov_801)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_destroy_timeout+0x50")
int BPF_KPROBE(do_mov_802)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/untimeout+0x45")
int BPF_KPROBE(do_mov_803)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tstamp_pernet_init+0xd")
int BPF_KPROBE(do_mov_804)
{
    u64 addr = ctx->di + 0xb3d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_register_notifier+0x28")
int BPF_KPROBE(do_mov_805)
{
    u64 addr = ctx->bx + 0xb48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_unregister_notifier+0x20")
int BPF_KPROBE(do_mov_806)
{
    u64 addr = ctx->bx + 0xb48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ecache_ext_add+0x74")
int BPF_KPROBE(do_mov_807)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ecache_ext_add+0x79")
int BPF_KPROBE(do_mov_808)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_eventmask_report+0xc1")
int BPF_KPROBE(do_mov_809)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xc3")
int BPF_KPROBE(do_mov_810)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xca")
int BPF_KPROBE(do_mov_811)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xda")
int BPF_KPROBE(do_mov_812)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xe2")
int BPF_KPROBE(do_mov_813)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xe6")
int BPF_KPROBE(do_mov_814)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xee")
int BPF_KPROBE(do_mov_815)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0x17e")
int BPF_KPROBE(do_mov_816)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0x185")
int BPF_KPROBE(do_mov_817)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0x189")
int BPF_KPROBE(do_mov_818)
{
    u64 addr = ctx->di + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_work+0x56")
int BPF_KPROBE(do_mov_819)
{
    u64 addr = ctx->r12 + 0xb39;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_work+0x76")
int BPF_KPROBE(do_mov_820)
{
    u64 addr = ctx->r12 + 0xb39;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x46")
int BPF_KPROBE(do_mov_821)
{
    u64 addr = ctx->r12 + 0xb3b;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x58")
int BPF_KPROBE(do_mov_822)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x60")
int BPF_KPROBE(do_mov_823)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x64")
int BPF_KPROBE(do_mov_824)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x6c")
int BPF_KPROBE(do_mov_825)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x7a")
int BPF_KPROBE(do_mov_826)
{
    u64 addr = ctx->bx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x81")
int BPF_KPROBE(do_mov_827)
{
    u64 addr = ctx->bx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_new+0x47")
int BPF_KPROBE(do_mov_828)
{
    u64 addr = ctx->r9 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_new+0x57")
int BPF_KPROBE(do_mov_829)
{
    u64 addr = ctx->r9 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_new+0x5f")
int BPF_KPROBE(do_mov_830)
{
    u64 addr = ctx->r9 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_timeout_nlattr_to_obj+0x20")
int BPF_KPROBE(do_mov_831)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_timeout_nlattr_to_obj+0x46")
int BPF_KPROBE(do_mov_832)
{
    u64 addr = ctx->dx + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_timeout_nlattr_to_obj+0x56")
int BPF_KPROBE(do_mov_833)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_to_nlattr+0xb2")
int BPF_KPROBE(do_mov_834)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_dccp+0xa3")
int BPF_KPROBE(do_mov_835)
{
    u64 addr = ctx->bx + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_dccp+0xc0")
int BPF_KPROBE(do_mov_836)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_dccp+0xc6")
int BPF_KPROBE(do_mov_837)
{
    u64 addr = ctx->bx + 0xb9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_dccp+0xe6")
int BPF_KPROBE(do_mov_838)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x1e3")
int BPF_KPROBE(do_mov_839)
{
    u64 addr = ctx->r13 + ctx->ax * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x1ec")
int BPF_KPROBE(do_mov_840)
{
    u64 addr = ctx->r13 + ctx->cx * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x214")
int BPF_KPROBE(do_mov_841)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x22e")
int BPF_KPROBE(do_mov_842)
{
    u64 addr = ctx->r13 + 0xbb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x235")
int BPF_KPROBE(do_mov_843)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x23c")
int BPF_KPROBE(do_mov_844)
{
    u64 addr = ctx->r13 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x2fb")
int BPF_KPROBE(do_mov_845)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x31f")
int BPF_KPROBE(do_mov_846)
{
    u64 addr = ctx->r13 + ctx->cx * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x336")
int BPF_KPROBE(do_mov_847)
{
    u64 addr = ctx->r13 + ctx->ax * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x398")
int BPF_KPROBE(do_mov_848)
{
    u64 addr = ctx->r13 + 0xbb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x39f")
int BPF_KPROBE(do_mov_849)
{
    u64 addr = ctx->r13 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x3a6")
int BPF_KPROBE(do_mov_850)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x544")
int BPF_KPROBE(do_mov_851)
{
    u64 addr = ctx->r13 + 0xbb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x54f")
int BPF_KPROBE(do_mov_852)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_init_net+0x10")
int BPF_KPROBE(do_mov_853)
{
    u64 addr = ctx->di + 0xbac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_init_net+0x21")
int BPF_KPROBE(do_mov_854)
{
    u64 addr = ctx->di + 0xbb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_init_net+0x32")
int BPF_KPROBE(do_mov_855)
{
    u64 addr = ctx->di + 0xbbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_init_net+0x47")
int BPF_KPROBE(do_mov_856)
{
    u64 addr = ctx->di + 0xba8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_init_net+0x4e")
int BPF_KPROBE(do_mov_857)
{
    u64 addr = ctx->di + 0xbc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_timeout_nlattr_to_obj+0x20")
int BPF_KPROBE(do_mov_858)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_timeout_nlattr_to_obj+0x46")
int BPF_KPROBE(do_mov_859)
{
    u64 addr = ctx->dx + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_timeout_nlattr_to_obj+0x56")
int BPF_KPROBE(do_mov_860)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_to_nlattr+0xb6")
int BPF_KPROBE(do_mov_861)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_sctp+0x80")
int BPF_KPROBE(do_mov_862)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_sctp+0x8d")
int BPF_KPROBE(do_mov_863)
{
    u64 addr = ctx->bx + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_sctp+0x9a")
int BPF_KPROBE(do_mov_864)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x32")
int BPF_KPROBE(do_mov_865)
{
    u64 addr = ctx->di + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x3d")
int BPF_KPROBE(do_mov_866)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x62")
int BPF_KPROBE(do_mov_867)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x68")
int BPF_KPROBE(do_mov_868)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x124")
int BPF_KPROBE(do_mov_869)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x131")
int BPF_KPROBE(do_mov_870)
{
    u64 addr = ctx->bx + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x28b")
int BPF_KPROBE(do_mov_871)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x2b0")
int BPF_KPROBE(do_mov_872)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x2cc")
int BPF_KPROBE(do_mov_873)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x41f")
int BPF_KPROBE(do_mov_874)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x593")
int BPF_KPROBE(do_mov_875)
{
    u64 addr = ctx->bx + ctx->ax * 0x4 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x651")
int BPF_KPROBE(do_mov_876)
{
    u64 addr = ctx->bx + ctx->cx * 0x4 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x7f7")
int BPF_KPROBE(do_mov_877)
{
    u64 addr = ctx->bx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x84d")
int BPF_KPROBE(do_mov_878)
{
    u64 addr = ctx->bx + 0xc5;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x85d")
int BPF_KPROBE(do_mov_879)
{
    u64 addr = ctx->bx + ctx->di * 0x4 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x86d")
int BPF_KPROBE(do_mov_880)
{
    u64 addr = ctx->bx + ctx->ax * 0x4 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x8d3")
int BPF_KPROBE(do_mov_881)
{
    u64 addr = ctx->bx + 0xc5;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_init_net+0x10")
int BPF_KPROBE(do_mov_882)
{
    u64 addr = ctx->di + 0xbd4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_init_net+0x21")
int BPF_KPROBE(do_mov_883)
{
    u64 addr = ctx->di + 0xbdc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_init_net+0x32")
int BPF_KPROBE(do_mov_884)
{
    u64 addr = ctx->di + 0xbe4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_init_net+0x47")
int BPF_KPROBE(do_mov_885)
{
    u64 addr = ctx->di + 0xbec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_init_net+0x58")
int BPF_KPROBE(do_mov_886)
{
    u64 addr = ctx->di + 0xbf4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_timeout_nlattr_to_obj+0x1a")
int BPF_KPROBE(do_mov_887)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_timeout_nlattr_to_obj+0x25")
int BPF_KPROBE(do_mov_888)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_timeout_nlattr_to_obj+0x3c")
int BPF_KPROBE(do_mov_889)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_timeout_nlattr_to_obj+0x52")
int BPF_KPROBE(do_mov_890)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_destroy+0x73")
int BPF_KPROBE(do_mov_891)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_destroy+0x77")
int BPF_KPROBE(do_mov_892)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_destroy+0x7a")
int BPF_KPROBE(do_mov_893)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_destroy+0x94")
int BPF_KPROBE(do_mov_894)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x156")
int BPF_KPROBE(do_mov_895)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x15f")
int BPF_KPROBE(do_mov_896)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x168")
int BPF_KPROBE(do_mov_897)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x171")
int BPF_KPROBE(do_mov_898)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x17a")
int BPF_KPROBE(do_mov_899)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x17e")
int BPF_KPROBE(do_mov_900)
{
    u64 addr = ctx->r13 + ctx->r15 * 0x8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x1a7")
int BPF_KPROBE(do_mov_901)
{
    u64 addr = ctx->r8 + 0xc08;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x1ae")
int BPF_KPROBE(do_mov_902)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x1b1")
int BPF_KPROBE(do_mov_903)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x1b5")
int BPF_KPROBE(do_mov_904)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_pkt_to_tuple+0x60")
int BPF_KPROBE(do_mov_905)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_pkt_to_tuple+0x64")
int BPF_KPROBE(do_mov_906)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_pkt_to_tuple+0xd2")
int BPF_KPROBE(do_mov_907)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_pkt_to_tuple+0x13d")
int BPF_KPROBE(do_mov_908)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_gre_packet+0xd1")
int BPF_KPROBE(do_mov_909)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_gre_packet+0xdb")
int BPF_KPROBE(do_mov_910)
{
    u64 addr = ctx->r12 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_gre_init_net+0xd")
int BPF_KPROBE(do_mov_911)
{
    u64 addr = ctx->di + 0xc00;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_gre_init_net+0x14")
int BPF_KPROBE(do_mov_912)
{
    u64 addr = ctx->di + 0xc08;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_gre_init_net+0x28")
int BPF_KPROBE(do_mov_913)
{
    u64 addr = ctx->di + 0xc10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x46")
int BPF_KPROBE(do_mov_914)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x4d")
int BPF_KPROBE(do_mov_915)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x55")
int BPF_KPROBE(do_mov_916)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x5d")
int BPF_KPROBE(do_mov_917)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x65")
int BPF_KPROBE(do_mov_918)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x87")
int BPF_KPROBE(do_mov_919)
{
    u64 addr = ctx->r8 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x93")
int BPF_KPROBE(do_mov_920)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x96")
int BPF_KPROBE(do_mov_921)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x9f")
int BPF_KPROBE(do_mov_922)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xaa")
int BPF_KPROBE(do_mov_923)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xad")
int BPF_KPROBE(do_mov_924)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xb6")
int BPF_KPROBE(do_mov_925)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xbf")
int BPF_KPROBE(do_mov_926)
{
    u64 addr = ctx->r8 + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xc3")
int BPF_KPROBE(do_mov_927)
{
    u64 addr = ctx->r8 + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xce")
int BPF_KPROBE(do_mov_928)
{
    u64 addr = ctx->r8 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xd6")
int BPF_KPROBE(do_mov_929)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xdd")
int BPF_KPROBE(do_mov_930)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xe4")
int BPF_KPROBE(do_mov_931)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_xdp_ct_alloc+0x4f")
int BPF_KPROBE(do_mov_932)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_xdp_ct_lookup+0x4a")
int BPF_KPROBE(do_mov_933)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_skb_ct_alloc+0x59")
int BPF_KPROBE(do_mov_934)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_skb_ct_lookup+0x54")
int BPF_KPROBE(do_mov_935)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_ct_set_timeout+0x29")
int BPF_KPROBE(do_mov_936)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/change_seq_adj+0x57")
int BPF_KPROBE(do_mov_937)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/change_seq_adj+0x67")
int BPF_KPROBE(do_mov_938)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/change_seq_adj+0x78")
int BPF_KPROBE(do_mov_939)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_proto+0x78")
int BPF_KPROBE(do_mov_940)
{
    u64 addr = ctx->r13 + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x4f")
int BPF_KPROBE(do_mov_941)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x56")
int BPF_KPROBE(do_mov_942)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x5e")
int BPF_KPROBE(do_mov_943)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x66")
int BPF_KPROBE(do_mov_944)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x6e")
int BPF_KPROBE(do_mov_945)
{
    u64 addr = ctx->si + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0xaf")
int BPF_KPROBE(do_mov_946)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x17c")
int BPF_KPROBE(do_mov_947)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x180")
int BPF_KPROBE(do_mov_948)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x1cb")
int BPF_KPROBE(do_mov_949)
{
    u64 addr = ctx->r14 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x1d8")
int BPF_KPROBE(do_mov_950)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x1e2")
int BPF_KPROBE(do_mov_951)
{
    u64 addr = ctx->r14 + 0x3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x1e9")
int BPF_KPROBE(do_mov_952)
{
    u64 addr = ctx->bx + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x241")
int BPF_KPROBE(do_mov_953)
{
    u64 addr = ctx->bx + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x257")
int BPF_KPROBE(do_mov_954)
{
    u64 addr = ctx->r14 + 0x3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x25c")
int BPF_KPROBE(do_mov_955)
{
    u64 addr = ctx->bx + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x28c")
int BPF_KPROBE(do_mov_956)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x28f")
int BPF_KPROBE(do_mov_957)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x2aa")
int BPF_KPROBE(do_mov_958)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x2c2")
int BPF_KPROBE(do_mov_959)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x47")
int BPF_KPROBE(do_mov_960)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x65")
int BPF_KPROBE(do_mov_961)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x78")
int BPF_KPROBE(do_mov_962)
{
    u64 addr = ctx->r12 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x96")
int BPF_KPROBE(do_mov_963)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0xa5")
int BPF_KPROBE(do_mov_964)
{
    u64 addr = ctx->r12 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0xc2")
int BPF_KPROBE(do_mov_965)
{
    u64 addr = ctx->r12 + 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0xdf")
int BPF_KPROBE(do_mov_966)
{
    u64 addr = ctx->r12 + 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x12c")
int BPF_KPROBE(do_mov_967)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x148")
int BPF_KPROBE(do_mov_968)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x1cb")
int BPF_KPROBE(do_mov_969)
{
    u64 addr = ctx->r12 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_start+0x2b")
int BPF_KPROBE(do_mov_970)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_stat_cpu_dump+0xb9")
int BPF_KPROBE(do_mov_971)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_stat_cpu_dump+0x120")
int BPF_KPROBE(do_mov_972)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_stat_cpu_dump+0x12d")
int BPF_KPROBE(do_mov_973)
{
    u64 addr = ctx->r14 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_stat_cpu_dump+0x19f")
int BPF_KPROBE(do_mov_974)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_tuples_proto+0x94")
int BPF_KPROBE(do_mov_975)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_protoinfo+0x79")
int BPF_KPROBE(do_mov_976)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_ct_seq_adj+0xd2")
int BPF_KPROBE(do_mov_977)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_counters+0xd5")
int BPF_KPROBE(do_mov_978)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_tuples_ip+0x78")
int BPF_KPROBE(do_mov_979)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_ct_stat_cpu_dump+0xb6")
int BPF_KPROBE(do_mov_980)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_ct_stat_cpu_dump+0x11c")
int BPF_KPROBE(do_mov_981)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_ct_stat_cpu_dump+0x129")
int BPF_KPROBE(do_mov_982)
{
    u64 addr = ctx->r13 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_ct_stat_cpu_dump+0x2a1")
int BPF_KPROBE(do_mov_983)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_stat_ct+0xb1")
int BPF_KPROBE(do_mov_984)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_stat_ct+0x117")
int BPF_KPROBE(do_mov_985)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_change_synproxy+0x9a")
int BPF_KPROBE(do_mov_986)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_change_synproxy+0xa5")
int BPF_KPROBE(do_mov_987)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_change_synproxy+0xb1")
int BPF_KPROBE(do_mov_988)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_timestamp+0xd3")
int BPF_KPROBE(do_mov_989)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_ct_synproxy+0x104")
int BPF_KPROBE(do_mov_990)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_change_helper+0x11e")
int BPF_KPROBE(do_mov_991)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_glue_parse+0x130")
int BPF_KPROBE(do_mov_992)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0xd3")
int BPF_KPROBE(do_mov_993)
{
    u64 addr = ctx->r12 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x114")
int BPF_KPROBE(do_mov_994)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x119")
int BPF_KPROBE(do_mov_995)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x121")
int BPF_KPROBE(do_mov_996)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x126")
int BPF_KPROBE(do_mov_997)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x12e")
int BPF_KPROBE(do_mov_998)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x137")
int BPF_KPROBE(do_mov_999)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x140")
int BPF_KPROBE(do_mov_1000)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x149")
int BPF_KPROBE(do_mov_1001)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x152")
int BPF_KPROBE(do_mov_1002)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x15e")
int BPF_KPROBE(do_mov_1003)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x163")
int BPF_KPROBE(do_mov_1004)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x16d")
int BPF_KPROBE(do_mov_1005)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x21a")
int BPF_KPROBE(do_mov_1006)
{
    u64 addr = ctx->r12 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x226")
int BPF_KPROBE(do_mov_1007)
{
    u64 addr = ctx->r12 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x22e")
int BPF_KPROBE(do_mov_1008)
{
    u64 addr = ctx->r12 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x240")
int BPF_KPROBE(do_mov_1009)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_tuple+0x94")
int BPF_KPROBE(do_mov_1010)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_master+0xb9")
int BPF_KPROBE(do_mov_1011)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_helpinfo+0xea")
int BPF_KPROBE(do_mov_1012)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_secctx.isra.0+0xb9")
int BPF_KPROBE(do_mov_1013)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_glue_build+0x11e")
int BPF_KPROBE(do_mov_1014)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_glue_build+0x1b6")
int BPF_KPROBE(do_mov_1015)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_glue_build+0x34b")
int BPF_KPROBE(do_mov_1016)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_expect+0x1ba")
int BPF_KPROBE(do_mov_1017)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_expect+0x3fd")
int BPF_KPROBE(do_mov_1018)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_expect_event+0x11d")
int BPF_KPROBE(do_mov_1019)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_expect_event+0x127")
int BPF_KPROBE(do_mov_1020)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_expect_event+0x12d")
int BPF_KPROBE(do_mov_1021)
{
    u64 addr = ctx->r12 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_expect_event+0x15c")
int BPF_KPROBE(do_mov_1022)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_fill_info.constprop.0+0x5d")
int BPF_KPROBE(do_mov_1023)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_fill_info.constprop.0+0x67")
int BPF_KPROBE(do_mov_1024)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_fill_info.constprop.0+0x6d")
int BPF_KPROBE(do_mov_1025)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_fill_info.constprop.0+0x8d")
int BPF_KPROBE(do_mov_1026)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_ct_dump_table+0xdc")
int BPF_KPROBE(do_mov_1027)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_ct_dump_table+0xef")
int BPF_KPROBE(do_mov_1028)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_ct_dump_table+0xf9")
int BPF_KPROBE(do_mov_1029)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_ct_dump_table+0x123")
int BPF_KPROBE(do_mov_1030)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_table+0xa2")
int BPF_KPROBE(do_mov_1031)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_table+0xdd")
int BPF_KPROBE(do_mov_1032)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_table+0x10c")
int BPF_KPROBE(do_mov_1033)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_table+0x154")
int BPF_KPROBE(do_mov_1034)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x7d")
int BPF_KPROBE(do_mov_1035)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x8a")
int BPF_KPROBE(do_mov_1036)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x93")
int BPF_KPROBE(do_mov_1037)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x16e")
int BPF_KPROBE(do_mov_1038)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x20a")
int BPF_KPROBE(do_mov_1039)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x301")
int BPF_KPROBE(do_mov_1040)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_table+0x18e")
int BPF_KPROBE(do_mov_1041)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_table+0x1f6")
int BPF_KPROBE(do_mov_1042)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_table+0x279")
int BPF_KPROBE(do_mov_1043)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_table+0x43b")
int BPF_KPROBE(do_mov_1044)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_table+0x459")
int BPF_KPROBE(do_mov_1045)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_table+0x46e")
int BPF_KPROBE(do_mov_1046)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_new_expect+0x142")
int BPF_KPROBE(do_mov_1047)
{
    u64 addr = ctx->dx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_dying+0x38")
int BPF_KPROBE(do_mov_1048)
{
    u64 addr = ctx->si + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_dying+0xe7")
int BPF_KPROBE(do_mov_1049)
{
    u64 addr = ctx->r15 + 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_dying+0x120")
int BPF_KPROBE(do_mov_1050)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_dying+0x171")
int BPF_KPROBE(do_mov_1051)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x83")
int BPF_KPROBE(do_mov_1052)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x13a")
int BPF_KPROBE(do_mov_1053)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x26b")
int BPF_KPROBE(do_mov_1054)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x276")
int BPF_KPROBE(do_mov_1055)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x307")
int BPF_KPROBE(do_mov_1056)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x376")
int BPF_KPROBE(do_mov_1057)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x3ac")
int BPF_KPROBE(do_mov_1058)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_new_conntrack+0x372")
int BPF_KPROBE(do_mov_1059)
{
    u64 addr = ctx->r13 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x191")
int BPF_KPROBE(do_mov_1060)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x19c")
int BPF_KPROBE(do_mov_1061)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x1a5")
int BPF_KPROBE(do_mov_1062)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x2de")
int BPF_KPROBE(do_mov_1063)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x376")
int BPF_KPROBE(do_mov_1064)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x4d6")
int BPF_KPROBE(do_mov_1065)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_fill_info.constprop.0+0x77")
int BPF_KPROBE(do_mov_1066)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_fill_info.constprop.0+0x17a")
int BPF_KPROBE(do_mov_1067)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_fill_info.constprop.0+0x191")
int BPF_KPROBE(do_mov_1068)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x19a")
int BPF_KPROBE(do_mov_1069)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x1a0")
int BPF_KPROBE(do_mov_1070)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x1a8")
int BPF_KPROBE(do_mov_1071)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x1b6")
int BPF_KPROBE(do_mov_1072)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x1b9")
int BPF_KPROBE(do_mov_1073)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x1bd")
int BPF_KPROBE(do_mov_1074)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x1c2")
int BPF_KPROBE(do_mov_1075)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/untimeout+0x28")
int BPF_KPROBE(do_mov_1076)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/untimeout+0x45")
int BPF_KPROBE(do_mov_1077)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_default_get+0x131")
int BPF_KPROBE(do_mov_1078)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_default_get+0x1da")
int BPF_KPROBE(do_mov_1079)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_default_get+0x1ef")
int BPF_KPROBE(do_mov_1080)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_init+0x2f")
int BPF_KPROBE(do_mov_1081)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_init+0x32")
int BPF_KPROBE(do_mov_1082)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_init+0x36")
int BPF_KPROBE(do_mov_1083)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_init+0x3a")
int BPF_KPROBE(do_mov_1084)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x48")
int BPF_KPROBE(do_mov_1085)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x4c")
int BPF_KPROBE(do_mov_1086)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x53")
int BPF_KPROBE(do_mov_1087)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x5b")
int BPF_KPROBE(do_mov_1088)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x5f")
int BPF_KPROBE(do_mov_1089)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x63")
int BPF_KPROBE(do_mov_1090)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x6a")
int BPF_KPROBE(do_mov_1091)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_exit+0x9d")
int BPF_KPROBE(do_mov_1092)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_exit+0xa1")
int BPF_KPROBE(do_mov_1093)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_exit+0xa7")
int BPF_KPROBE(do_mov_1094)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_exit+0xab")
int BPF_KPROBE(do_mov_1095)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0x9e")
int BPF_KPROBE(do_mov_1096)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0xa2")
int BPF_KPROBE(do_mov_1097)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0xaf")
int BPF_KPROBE(do_mov_1098)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0x10c")
int BPF_KPROBE(do_mov_1099)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0x110")
int BPF_KPROBE(do_mov_1100)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0x11d")
int BPF_KPROBE(do_mov_1101)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_dump+0x34")
int BPF_KPROBE(do_mov_1102)
{
    u64 addr = ctx->si + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_dump+0xca")
int BPF_KPROBE(do_mov_1103)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_dump+0xd4")
int BPF_KPROBE(do_mov_1104)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x5b")
int BPF_KPROBE(do_mov_1105)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x63")
int BPF_KPROBE(do_mov_1106)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x6b")
int BPF_KPROBE(do_mov_1107)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x72")
int BPF_KPROBE(do_mov_1108)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x7a")
int BPF_KPROBE(do_mov_1109)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x8a")
int BPF_KPROBE(do_mov_1110)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x92")
int BPF_KPROBE(do_mov_1111)
{
    u64 addr = ctx->bx + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_del+0x124")
int BPF_KPROBE(do_mov_1112)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_del+0x128")
int BPF_KPROBE(do_mov_1113)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_del+0x12b")
int BPF_KPROBE(do_mov_1114)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_del+0x132")
int BPF_KPROBE(do_mov_1115)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x84")
int BPF_KPROBE(do_mov_1116)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x186")
int BPF_KPROBE(do_mov_1117)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x2ae")
int BPF_KPROBE(do_mov_1118)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x355")
int BPF_KPROBE(do_mov_1119)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x3b9")
int BPF_KPROBE(do_mov_1120)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_dump_table+0x3c")
int BPF_KPROBE(do_mov_1121)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_dump_table+0xb1")
int BPF_KPROBE(do_mov_1122)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_dump_table+0xbb")
int BPF_KPROBE(do_mov_1123)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_dump_table+0xc6")
int BPF_KPROBE(do_mov_1124)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x22d")
int BPF_KPROBE(do_mov_1125)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x24b")
int BPF_KPROBE(do_mov_1126)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x3de")
int BPF_KPROBE(do_mov_1127)
{
    u64 addr = ctx->bx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x3fc")
int BPF_KPROBE(do_mov_1128)
{
    u64 addr = ctx->bx - 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x49b")
int BPF_KPROBE(do_mov_1129)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x4a2")
int BPF_KPROBE(do_mov_1130)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x4cf")
int BPF_KPROBE(do_mov_1131)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x55f")
int BPF_KPROBE(do_mov_1132)
{
    u64 addr = ctx->r12 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x567")
int BPF_KPROBE(do_mov_1133)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x587")
int BPF_KPROBE(do_mov_1134)
{
    u64 addr = ctx->r12 + 0x9c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x59f")
int BPF_KPROBE(do_mov_1135)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5a8")
int BPF_KPROBE(do_mov_1136)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5b1")
int BPF_KPROBE(do_mov_1137)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5bf")
int BPF_KPROBE(do_mov_1138)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5ce")
int BPF_KPROBE(do_mov_1139)
{
    u64 addr = ctx->r12 + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5dd")
int BPF_KPROBE(do_mov_1140)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5e6")
int BPF_KPROBE(do_mov_1141)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5ef")
int BPF_KPROBE(do_mov_1142)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x5f8")
int BPF_KPROBE(do_mov_1143)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x601")
int BPF_KPROBE(do_mov_1144)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x614")
int BPF_KPROBE(do_mov_1145)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x63d")
int BPF_KPROBE(do_mov_1146)
{
    u64 addr = ctx->r12 + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x65d")
int BPF_KPROBE(do_mov_1147)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x66f")
int BPF_KPROBE(do_mov_1148)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x674")
int BPF_KPROBE(do_mov_1149)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x697")
int BPF_KPROBE(do_mov_1150)
{
    u64 addr = ctx->r12 + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_port+0x7c")
int BPF_KPROBE(do_mov_1151)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_number+0x1e")
int BPF_KPROBE(do_mov_1152)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_number+0x2b")
int BPF_KPROBE(do_mov_1153)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_number+0x56")
int BPF_KPROBE(do_mov_1154)
{
    u64 addr = ctx->cx + ctx->r10 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_number+0x7f")
int BPF_KPROBE(do_mov_1155)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_rfc959+0x57")
int BPF_KPROBE(do_mov_1156)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_rfc959+0x68")
int BPF_KPROBE(do_mov_1157)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_eprt+0x1e1")
int BPF_KPROBE(do_mov_1158)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x22f")
int BPF_KPROBE(do_mov_1159)
{
    u64 addr = ctx->cx + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x6aa")
int BPF_KPROBE(do_mov_1160)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x6ae")
int BPF_KPROBE(do_mov_1161)
{
    u64 addr = ctx->r12 + ctx->ax * 0x4 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x814")
int BPF_KPROBE(do_mov_1162)
{
    u64 addr = ctx->r12 + ctx->ax * 0x4 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x4e")
int BPF_KPROBE(do_mov_1163)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x56")
int BPF_KPROBE(do_mov_1164)
{
    u64 addr = ctx->ax + ctx->cx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x7d")
int BPF_KPROBE(do_mov_1165)
{
    u64 addr = ctx->r11 + ctx->r10 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xba")
int BPF_KPROBE(do_mov_1166)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xdf")
int BPF_KPROBE(do_mov_1167)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xef")
int BPF_KPROBE(do_mov_1168)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xfd")
int BPF_KPROBE(do_mov_1169)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x104")
int BPF_KPROBE(do_mov_1170)
{
    u64 addr = ctx->r9 + ctx->ax * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x12b")
int BPF_KPROBE(do_mov_1171)
{
    u64 addr = ctx->di + ctx->r9 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x137")
int BPF_KPROBE(do_mov_1172)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x13d")
int BPF_KPROBE(do_mov_1173)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x143")
int BPF_KPROBE(do_mov_1174)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x149")
int BPF_KPROBE(do_mov_1175)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x158")
int BPF_KPROBE(do_mov_1176)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x164")
int BPF_KPROBE(do_mov_1177)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/expect_h245+0x120")
int BPF_KPROBE(do_mov_1178)
{
    u64 addr = ctx->r11 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/expect_t120+0x125")
int BPF_KPROBE(do_mov_1179)
{
    u64 addr = ctx->r11 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x102")
int BPF_KPROBE(do_mov_1180)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x2 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x187")
int BPF_KPROBE(do_mov_1181)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x20b")
int BPF_KPROBE(do_mov_1182)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x20e")
int BPF_KPROBE(do_mov_1183)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x216")
int BPF_KPROBE(do_mov_1184)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x21b")
int BPF_KPROBE(do_mov_1185)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x2 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x299")
int BPF_KPROBE(do_mov_1186)
{
    u64 addr = ctx->r12 + ctx->r8 * 0x2 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/q931_help+0x7a8")
int BPF_KPROBE(do_mov_1187)
{
    u64 addr = ctx->r10 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x339")
int BPF_KPROBE(do_mov_1188)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x507")
int BPF_KPROBE(do_mov_1189)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x50f")
int BPF_KPROBE(do_mov_1190)
{
    u64 addr = ctx->r15 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x55d")
int BPF_KPROBE(do_mov_1191)
{
    u64 addr = ctx->bx + ctx->ax * 0x2 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x59e")
int BPF_KPROBE(do_mov_1192)
{
    u64 addr = ctx->bx + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x603")
int BPF_KPROBE(do_mov_1193)
{
    u64 addr = ctx->r15 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x71e")
int BPF_KPROBE(do_mov_1194)
{
    u64 addr = ctx->r15 + ctx->bx * 0x2 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x727")
int BPF_KPROBE(do_mov_1195)
{
    u64 addr = ctx->r15 + ctx->ax * 0x2 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x8ba")
int BPF_KPROBE(do_mov_1196)
{
    u64 addr = ctx->r13 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x8c7")
int BPF_KPROBE(do_mov_1197)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0xa0e")
int BPF_KPROBE(do_mov_1198)
{
    u64 addr = ctx->r13 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0xa1c")
int BPF_KPROBE(do_mov_1199)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0xb89")
int BPF_KPROBE(do_mov_1200)
{
    u64 addr = ctx->bx + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x2d")
int BPF_KPROBE(do_mov_1201)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x3f")
int BPF_KPROBE(do_mov_1202)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x59")
int BPF_KPROBE(do_mov_1203)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x5f")
int BPF_KPROBE(do_mov_1204)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x64")
int BPF_KPROBE(do_mov_1205)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bool+0x13")
int BPF_KPROBE(do_mov_1206)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bool+0x24")
int BPF_KPROBE(do_mov_1207)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bool+0x2d")
int BPF_KPROBE(do_mov_1208)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_oid+0x18")
int BPF_KPROBE(do_mov_1209)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_oid+0x1f")
int BPF_KPROBE(do_mov_1210)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_oid+0x30")
int BPF_KPROBE(do_mov_1211)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_oid+0x3e")
int BPF_KPROBE(do_mov_1212)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x21")
int BPF_KPROBE(do_mov_1213)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x3d")
int BPF_KPROBE(do_mov_1214)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x57")
int BPF_KPROBE(do_mov_1215)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x5d")
int BPF_KPROBE(do_mov_1216)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x76")
int BPF_KPROBE(do_mov_1217)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x89")
int BPF_KPROBE(do_mov_1218)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x98")
int BPF_KPROBE(do_mov_1219)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x9b")
int BPF_KPROBE(do_mov_1220)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0xa5")
int BPF_KPROBE(do_mov_1221)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0xad")
int BPF_KPROBE(do_mov_1222)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_numstr+0x65")
int BPF_KPROBE(do_mov_1223)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_numstr+0x73")
int BPF_KPROBE(do_mov_1224)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_numstr+0x79")
int BPF_KPROBE(do_mov_1225)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_numstr+0x98")
int BPF_KPROBE(do_mov_1226)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0x6a")
int BPF_KPROBE(do_mov_1227)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0x7c")
int BPF_KPROBE(do_mov_1228)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0x8b")
int BPF_KPROBE(do_mov_1229)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0xae")
int BPF_KPROBE(do_mov_1230)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0xc2")
int BPF_KPROBE(do_mov_1231)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0xc9")
int BPF_KPROBE(do_mov_1232)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x1b")
int BPF_KPROBE(do_mov_1233)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x22")
int BPF_KPROBE(do_mov_1234)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x3c")
int BPF_KPROBE(do_mov_1235)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x69")
int BPF_KPROBE(do_mov_1236)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x71")
int BPF_KPROBE(do_mov_1237)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x99")
int BPF_KPROBE(do_mov_1238)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0xd5")
int BPF_KPROBE(do_mov_1239)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0xec")
int BPF_KPROBE(do_mov_1240)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x7a")
int BPF_KPROBE(do_mov_1241)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x8e")
int BPF_KPROBE(do_mov_1242)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0xa0")
int BPF_KPROBE(do_mov_1243)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0xa7")
int BPF_KPROBE(do_mov_1244)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0xdc")
int BPF_KPROBE(do_mov_1245)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0xe3")
int BPF_KPROBE(do_mov_1246)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x104")
int BPF_KPROBE(do_mov_1247)
{
    u64 addr = ctx->dx + ctx->cx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x123")
int BPF_KPROBE(do_mov_1248)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x14a")
int BPF_KPROBE(do_mov_1249)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x151")
int BPF_KPROBE(do_mov_1250)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x16b")
int BPF_KPROBE(do_mov_1251)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x183")
int BPF_KPROBE(do_mov_1252)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x18a")
int BPF_KPROBE(do_mov_1253)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x1a2")
int BPF_KPROBE(do_mov_1254)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x47")
int BPF_KPROBE(do_mov_1255)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x50")
int BPF_KPROBE(do_mov_1256)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x62")
int BPF_KPROBE(do_mov_1257)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x69")
int BPF_KPROBE(do_mov_1258)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x7e")
int BPF_KPROBE(do_mov_1259)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x89")
int BPF_KPROBE(do_mov_1260)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0xa4")
int BPF_KPROBE(do_mov_1261)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0xb0")
int BPF_KPROBE(do_mov_1262)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0xe3")
int BPF_KPROBE(do_mov_1263)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0xec")
int BPF_KPROBE(do_mov_1264)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x12c")
int BPF_KPROBE(do_mov_1265)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x146")
int BPF_KPROBE(do_mov_1266)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x15e")
int BPF_KPROBE(do_mov_1267)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x16d")
int BPF_KPROBE(do_mov_1268)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x179")
int BPF_KPROBE(do_mov_1269)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x17f")
int BPF_KPROBE(do_mov_1270)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x1b1")
int BPF_KPROBE(do_mov_1271)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x1c1")
int BPF_KPROBE(do_mov_1272)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x1d6")
int BPF_KPROBE(do_mov_1273)
{
    u64 addr = ctx->r14 + ctx->si * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x1f0")
int BPF_KPROBE(do_mov_1274)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x1fe")
int BPF_KPROBE(do_mov_1275)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0xad")
int BPF_KPROBE(do_mov_1276)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0xec")
int BPF_KPROBE(do_mov_1277)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0xf3")
int BPF_KPROBE(do_mov_1278)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x10c")
int BPF_KPROBE(do_mov_1279)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x117")
int BPF_KPROBE(do_mov_1280)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x17c")
int BPF_KPROBE(do_mov_1281)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x183")
int BPF_KPROBE(do_mov_1282)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x1f1")
int BPF_KPROBE(do_mov_1283)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x1f8")
int BPF_KPROBE(do_mov_1284)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x226")
int BPF_KPROBE(do_mov_1285)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x247")
int BPF_KPROBE(do_mov_1286)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x24e")
int BPF_KPROBE(do_mov_1287)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x25c")
int BPF_KPROBE(do_mov_1288)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x270")
int BPF_KPROBE(do_mov_1289)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x277")
int BPF_KPROBE(do_mov_1290)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x289")
int BPF_KPROBE(do_mov_1291)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x29b")
int BPF_KPROBE(do_mov_1292)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x2b3")
int BPF_KPROBE(do_mov_1293)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0x2ba")
int BPF_KPROBE(do_mov_1294)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0xb8")
int BPF_KPROBE(do_mov_1295)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0xd2")
int BPF_KPROBE(do_mov_1296)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0xdf")
int BPF_KPROBE(do_mov_1297)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0xfa")
int BPF_KPROBE(do_mov_1298)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x106")
int BPF_KPROBE(do_mov_1299)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x125")
int BPF_KPROBE(do_mov_1300)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x162")
int BPF_KPROBE(do_mov_1301)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x16f")
int BPF_KPROBE(do_mov_1302)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x198")
int BPF_KPROBE(do_mov_1303)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x1dd")
int BPF_KPROBE(do_mov_1304)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x1e4")
int BPF_KPROBE(do_mov_1305)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x1fe")
int BPF_KPROBE(do_mov_1306)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x25b")
int BPF_KPROBE(do_mov_1307)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x26b")
int BPF_KPROBE(do_mov_1308)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x2ae")
int BPF_KPROBE(do_mov_1309)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0x2c2")
int BPF_KPROBE(do_mov_1310)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0xd5")
int BPF_KPROBE(do_mov_1311)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x133")
int BPF_KPROBE(do_mov_1312)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x14c")
int BPF_KPROBE(do_mov_1313)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x1b0")
int BPF_KPROBE(do_mov_1314)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x1bc")
int BPF_KPROBE(do_mov_1315)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x24d")
int BPF_KPROBE(do_mov_1316)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x26f")
int BPF_KPROBE(do_mov_1317)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x284")
int BPF_KPROBE(do_mov_1318)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x294")
int BPF_KPROBE(do_mov_1319)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x37f")
int BPF_KPROBE(do_mov_1320)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x390")
int BPF_KPROBE(do_mov_1321)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x3e0")
int BPF_KPROBE(do_mov_1322)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x3f4")
int BPF_KPROBE(do_mov_1323)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x41f")
int BPF_KPROBE(do_mov_1324)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x497")
int BPF_KPROBE(do_mov_1325)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x4ad")
int BPF_KPROBE(do_mov_1326)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x51a")
int BPF_KPROBE(do_mov_1327)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x52b")
int BPF_KPROBE(do_mov_1328)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x53f")
int BPF_KPROBE(do_mov_1329)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/DecodeQ931+0x6a")
int BPF_KPROBE(do_mov_1330)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x123")
int BPF_KPROBE(do_mov_1331)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x12b")
int BPF_KPROBE(do_mov_1332)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x133")
int BPF_KPROBE(do_mov_1333)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x13b")
int BPF_KPROBE(do_mov_1334)
{
    u64 addr = ctx->r15 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x143")
int BPF_KPROBE(do_mov_1335)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x154")
int BPF_KPROBE(do_mov_1336)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x15e")
int BPF_KPROBE(do_mov_1337)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x166")
int BPF_KPROBE(do_mov_1338)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x170")
int BPF_KPROBE(do_mov_1339)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x178")
int BPF_KPROBE(do_mov_1340)
{
    u64 addr = ctx->r15 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x183")
int BPF_KPROBE(do_mov_1341)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pptp_expectfn+0x3e")
int BPF_KPROBE(do_mov_1342)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/destroy_sibling_or_exp.constprop.0+0x58")
int BPF_KPROBE(do_mov_1343)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/exp_gre.isra.0+0x7b")
int BPF_KPROBE(do_mov_1344)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/exp_gre.isra.0+0xa3")
int BPF_KPROBE(do_mov_1345)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x35b")
int BPF_KPROBE(do_mov_1346)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x393")
int BPF_KPROBE(do_mov_1347)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x3a3")
int BPF_KPROBE(do_mov_1348)
{
    u64 addr = ctx->ax + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x3b4")
int BPF_KPROBE(do_mov_1349)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x3ed")
int BPF_KPROBE(do_mov_1350)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x404")
int BPF_KPROBE(do_mov_1351)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x56f")
int BPF_KPROBE(do_mov_1352)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x671")
int BPF_KPROBE(do_mov_1353)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x68d")
int BPF_KPROBE(do_mov_1354)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x6ac")
int BPF_KPROBE(do_mov_1355)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x6b3")
int BPF_KPROBE(do_mov_1356)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x6f5")
int BPF_KPROBE(do_mov_1357)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x772")
int BPF_KPROBE(do_mov_1358)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0xae9")
int BPF_KPROBE(do_mov_1359)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0xb56")
int BPF_KPROBE(do_mov_1360)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0xb5d")
int BPF_KPROBE(do_mov_1361)
{
    u64 addr = ctx->ax + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0xc40")
int BPF_KPROBE(do_mov_1362)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0xc55")
int BPF_KPROBE(do_mov_1363)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0xfc")
int BPF_KPROBE(do_mov_1364)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x11d")
int BPF_KPROBE(do_mov_1365)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x24d")
int BPF_KPROBE(do_mov_1366)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sip_parse_addr+0x2f")
int BPF_KPROBE(do_mov_1367)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sip_parse_addr+0x3c")
int BPF_KPROBE(do_mov_1368)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sip_parse_addr+0xc4")
int BPF_KPROBE(do_mov_1369)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skp_epaddr_len+0x49")
int BPF_KPROBE(do_mov_1370)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skp_epaddr_len+0x63")
int BPF_KPROBE(do_mov_1371)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x161")
int BPF_KPROBE(do_mov_1372)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x173")
int BPF_KPROBE(do_mov_1373)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x18c")
int BPF_KPROBE(do_mov_1374)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x192")
int BPF_KPROBE(do_mov_1375)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sdp_parse_addr+0x2c")
int BPF_KPROBE(do_mov_1376)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sdp_parse_addr+0x33")
int BPF_KPROBE(do_mov_1377)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sdp_parse_addr+0x6e")
int BPF_KPROBE(do_mov_1378)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_numerical_param+0xa5")
int BPF_KPROBE(do_mov_1379)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_numerical_param+0xc7")
int BPF_KPROBE(do_mov_1380)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_numerical_param+0xcb")
int BPF_KPROBE(do_mov_1381)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_address_param+0xcb")
int BPF_KPROBE(do_mov_1382)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_address_param+0xd8")
int BPF_KPROBE(do_mov_1383)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_sdp_header+0x106")
int BPF_KPROBE(do_mov_1384)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_sdp_header+0x16e")
int BPF_KPROBE(do_mov_1385)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_sdp_header+0x183")
int BPF_KPROBE(do_mov_1386)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_transport+0xad")
int BPF_KPROBE(do_mov_1387)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_transport+0xd3")
int BPF_KPROBE(do_mov_1388)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_header+0x1da")
int BPF_KPROBE(do_mov_1389)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_header+0x241")
int BPF_KPROBE(do_mov_1390)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_header+0x256")
int BPF_KPROBE(do_mov_1391)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x10f")
int BPF_KPROBE(do_mov_1392)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x11a")
int BPF_KPROBE(do_mov_1393)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x12d")
int BPF_KPROBE(do_mov_1394)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x179")
int BPF_KPROBE(do_mov_1395)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x1c4")
int BPF_KPROBE(do_mov_1396)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x1dc")
int BPF_KPROBE(do_mov_1397)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x21d")
int BPF_KPROBE(do_mov_1398)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_sip_msg+0x12c")
int BPF_KPROBE(do_mov_1399)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_register_request+0x1ec")
int BPF_KPROBE(do_mov_1400)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_register_request+0x2c7")
int BPF_KPROBE(do_mov_1401)
{
    u64 addr = ctx->r11 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_register_request+0x2cb")
int BPF_KPROBE(do_mov_1402)
{
    u64 addr = ctx->r11 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_register_request+0x2d9")
int BPF_KPROBE(do_mov_1403)
{
    u64 addr = ctx->r11 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_expected_rtp_rtcp+0x38e")
int BPF_KPROBE(do_mov_1404)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_expected_rtp_rtcp+0x391")
int BPF_KPROBE(do_mov_1405)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_invite_request+0x77")
int BPF_KPROBE(do_mov_1406)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_cleanup_conntrack+0x46")
int BPF_KPROBE(do_mov_1407)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_cleanup_conntrack+0x4e")
int BPF_KPROBE(do_mov_1408)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_cleanup_conntrack+0x5f")
int BPF_KPROBE(do_mov_1409)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x6d")
int BPF_KPROBE(do_mov_1410)
{
    u64 addr = ctx->r10 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x71")
int BPF_KPROBE(do_mov_1411)
{
    u64 addr = ctx->r10 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0xb1")
int BPF_KPROBE(do_mov_1412)
{
    u64 addr = ctx->r10 + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0xe4")
int BPF_KPROBE(do_mov_1413)
{
    u64 addr = ctx->r10 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0xe8")
int BPF_KPROBE(do_mov_1414)
{
    u64 addr = ctx->r10 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x127")
int BPF_KPROBE(do_mov_1415)
{
    u64 addr = ctx->r10 + 0x56;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x14f")
int BPF_KPROBE(do_mov_1416)
{
    u64 addr = ctx->r10 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x18e")
int BPF_KPROBE(do_mov_1417)
{
    u64 addr = ctx->r10 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x1bc")
int BPF_KPROBE(do_mov_1418)
{
    u64 addr = ctx->r10 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x1fb")
int BPF_KPROBE(do_mov_1419)
{
    u64 addr = ctx->r10 + 0x3a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x137")
int BPF_KPROBE(do_mov_1420)
{
    u64 addr = ctx->r14 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x13e")
int BPF_KPROBE(do_mov_1421)
{
    u64 addr = ctx->r14 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x145")
int BPF_KPROBE(do_mov_1422)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x14d")
int BPF_KPROBE(do_mov_1423)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x31d")
int BPF_KPROBE(do_mov_1424)
{
    u64 addr = ctx->r13 + ctx->cx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x456")
int BPF_KPROBE(do_mov_1425)
{
    u64 addr = ctx->r14 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x5a3")
int BPF_KPROBE(do_mov_1426)
{
    u64 addr = ctx->r14 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x717")
int BPF_KPROBE(do_mov_1427)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x71b")
int BPF_KPROBE(do_mov_1428)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_setup_info+0x7d5")
int BPF_KPROBE(do_mov_1429)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_proto_clean+0x89")
int BPF_KPROBE(do_mov_1430)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_proto_clean+0x91")
int BPF_KPROBE(do_mov_1431)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_proto_clean+0xa2")
int BPF_KPROBE(do_mov_1432)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_register_fn+0x147")
int BPF_KPROBE(do_mov_1433)
{
    u64 addr = ctx->r15 + ctx->dx * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_register_fn+0x167")
int BPF_KPROBE(do_mov_1434)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_unregister_fn+0x83")
int BPF_KPROBE(do_mov_1435)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_unregister_fn+0x116")
int BPF_KPROBE(do_mov_1436)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0xa0")
int BPF_KPROBE(do_mov_1437)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x18a")
int BPF_KPROBE(do_mov_1438)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x214")
int BPF_KPROBE(do_mov_1439)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x286")
int BPF_KPROBE(do_mov_1440)
{
    u64 addr = ctx->ax + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x28a")
int BPF_KPROBE(do_mov_1441)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x2e1")
int BPF_KPROBE(do_mov_1442)
{
    u64 addr = ctx->r9 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x31e")
int BPF_KPROBE(do_mov_1443)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x33b")
int BPF_KPROBE(do_mov_1444)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x341")
int BPF_KPROBE(do_mov_1445)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x3a8")
int BPF_KPROBE(do_mov_1446)
{
    u64 addr = ctx->r12 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x417")
int BPF_KPROBE(do_mov_1447)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x45d")
int BPF_KPROBE(do_mov_1448)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x46f")
int BPF_KPROBE(do_mov_1449)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x4fa")
int BPF_KPROBE(do_mov_1450)
{
    u64 addr = ctx->r12 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv6_manip_pkt+0xc8")
int BPF_KPROBE(do_mov_1451)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv6_manip_pkt+0xd1")
int BPF_KPROBE(do_mov_1452)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv6_manip_pkt+0xe2")
int BPF_KPROBE(do_mov_1453)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv6_manip_pkt+0xeb")
int BPF_KPROBE(do_mov_1454)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_icmpv6_reply_translation+0x1b7")
int BPF_KPROBE(do_mov_1455)
{
    u64 addr = ctx->r9 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_icmpv6_reply_translation+0x1e8")
int BPF_KPROBE(do_mov_1456)
{
    u64 addr = ctx->r9 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv6_in+0x99")
int BPF_KPROBE(do_mov_1457)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_manip_pkt+0xa2")
int BPF_KPROBE(do_mov_1458)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_manip_pkt+0xa8")
int BPF_KPROBE(do_mov_1459)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_manip_pkt+0xdd")
int BPF_KPROBE(do_mov_1460)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_manip_pkt+0xe4")
int BPF_KPROBE(do_mov_1461)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_icmp_reply_translation+0x1b6")
int BPF_KPROBE(do_mov_1462)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_icmp_reply_translation+0x1e1")
int BPF_KPROBE(do_mov_1463)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_xfrm_me_harder+0xb8")
int BPF_KPROBE(do_mov_1464)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_xfrm_me_harder+0xdc")
int BPF_KPROBE(do_mov_1465)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_pre_routing+0x9c")
int BPF_KPROBE(do_mov_1466)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_local_in+0xbb")
int BPF_KPROBE(do_mov_1467)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_local_in+0xc6")
int BPF_KPROBE(do_mov_1468)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x53")
int BPF_KPROBE(do_mov_1469)
{
    u64 addr = ctx->r10 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x6c")
int BPF_KPROBE(do_mov_1470)
{
    u64 addr = ctx->r10 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x7a")
int BPF_KPROBE(do_mov_1471)
{
    u64 addr = ctx->r10 + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0xa5")
int BPF_KPROBE(do_mov_1472)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0xd2")
int BPF_KPROBE(do_mov_1473)
{
    u64 addr = ctx->r10 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0xf1")
int BPF_KPROBE(do_mov_1474)
{
    u64 addr = ctx->r10 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x100")
int BPF_KPROBE(do_mov_1475)
{
    u64 addr = ctx->r10 + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x116")
int BPF_KPROBE(do_mov_1476)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mangle_contents+0xbb")
int BPF_KPROBE(do_mov_1477)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mangle_contents+0xc4")
int BPF_KPROBE(do_mov_1478)
{
    u64 addr = ctx->r12 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mangle_contents+0xf3")
int BPF_KPROBE(do_mov_1479)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mangle_contents+0x170")
int BPF_KPROBE(do_mov_1480)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_exp_find_port+0x61")
int BPF_KPROBE(do_mov_1481)
{
    u64 addr = ctx->r13 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_mangle_udp_packet+0xbf")
int BPF_KPROBE(do_mov_1482)
{
    u64 addr = ctx->r11 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_masquerade_ipv4+0xaa")
int BPF_KPROBE(do_mov_1483)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_masquerade_ipv6+0x82")
int BPF_KPROBE(do_mov_1484)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x3f")
int BPF_KPROBE(do_mov_1485)
{
    u64 addr = ctx->r9 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x4b")
int BPF_KPROBE(do_mov_1486)
{
    u64 addr = ctx->r9 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x59")
int BPF_KPROBE(do_mov_1487)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ftp+0x8a")
int BPF_KPROBE(do_mov_1488)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ftp+0x96")
int BPF_KPROBE(do_mov_1489)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ftp+0xa0")
int BPF_KPROBE(do_mov_1490)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x5a")
int BPF_KPROBE(do_mov_1491)
{
    u64 addr = ctx->r9 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x66")
int BPF_KPROBE(do_mov_1492)
{
    u64 addr = ctx->r9 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x74")
int BPF_KPROBE(do_mov_1493)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mangle_packet+0x69")
int BPF_KPROBE(do_mov_1494)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x9a")
int BPF_KPROBE(do_mov_1495)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x9d")
int BPF_KPROBE(do_mov_1496)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xa9")
int BPF_KPROBE(do_mov_1497)
{
    u64 addr = ctx->r15 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xb0")
int BPF_KPROBE(do_mov_1498)
{
    u64 addr = ctx->r15 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xbe")
int BPF_KPROBE(do_mov_1499)
{
    u64 addr = ctx->r15 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xc5")
int BPF_KPROBE(do_mov_1500)
{
    u64 addr = ctx->r15 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xce")
int BPF_KPROBE(do_mov_1501)
{
    u64 addr = ctx->r15 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xd2")
int BPF_KPROBE(do_mov_1502)
{
    u64 addr = ctx->r15 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xda")
int BPF_KPROBE(do_mov_1503)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xec")
int BPF_KPROBE(do_mov_1504)
{
    u64 addr = ctx->r12 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xf4")
int BPF_KPROBE(do_mov_1505)
{
    u64 addr = ctx->r12 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x109")
int BPF_KPROBE(do_mov_1506)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x111")
int BPF_KPROBE(do_mov_1507)
{
    u64 addr = ctx->r12 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x116")
int BPF_KPROBE(do_mov_1508)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x11b")
int BPF_KPROBE(do_mov_1509)
{
    u64 addr = ctx->r12 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x124")
int BPF_KPROBE(do_mov_1510)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x168")
int BPF_KPROBE(do_mov_1511)
{
    u64 addr = ctx->r15 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x18f")
int BPF_KPROBE(do_mov_1512)
{
    u64 addr = ctx->r12 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x206")
int BPF_KPROBE(do_mov_1513)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x20a")
int BPF_KPROBE(do_mov_1514)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x133")
int BPF_KPROBE(do_mov_1515)
{
    u64 addr = ctx->r13 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x147")
int BPF_KPROBE(do_mov_1516)
{
    u64 addr = ctx->r13 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x155")
int BPF_KPROBE(do_mov_1517)
{
    u64 addr = ctx->r13 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x159")
int BPF_KPROBE(do_mov_1518)
{
    u64 addr = ctx->r13 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x15d")
int BPF_KPROBE(do_mov_1519)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x165")
int BPF_KPROBE(do_mov_1520)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x16c")
int BPF_KPROBE(do_mov_1521)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip+0x867")
int BPF_KPROBE(do_mov_1522)
{
    u64 addr = ctx->dx + ctx->ax * 0x1 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x21")
int BPF_KPROBE(do_mov_1523)
{
    u64 addr = ctx->dx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x29")
int BPF_KPROBE(do_mov_1524)
{
    u64 addr = ctx->dx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x33")
int BPF_KPROBE(do_mov_1525)
{
    u64 addr = ctx->dx + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_init_timestamp_cookie+0x9")
int BPF_KPROBE(do_mov_1526)
{
    u64 addr = ctx->si + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_init_timestamp_cookie+0x3e")
int BPF_KPROBE(do_mov_1527)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_init_timestamp_cookie+0x47")
int BPF_KPROBE(do_mov_1528)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_init_timestamp_cookie+0x62")
int BPF_KPROBE(do_mov_1529)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_synproxy_ipv4_init+0x17")
int BPF_KPROBE(do_mov_1530)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_synproxy_ipv6_init+0x17")
int BPF_KPROBE(do_mov_1531)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x24")
int BPF_KPROBE(do_mov_1532)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x42")
int BPF_KPROBE(do_mov_1533)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x49")
int BPF_KPROBE(do_mov_1534)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x55")
int BPF_KPROBE(do_mov_1535)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x67")
int BPF_KPROBE(do_mov_1536)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x73")
int BPF_KPROBE(do_mov_1537)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0x4c")
int BPF_KPROBE(do_mov_1538)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0x5d")
int BPF_KPROBE(do_mov_1539)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0x78")
int BPF_KPROBE(do_mov_1540)
{
    u64 addr = ctx->r12 + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0x9e")
int BPF_KPROBE(do_mov_1541)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0xad")
int BPF_KPROBE(do_mov_1542)
{
    u64 addr = ctx->r12 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0xbe")
int BPF_KPROBE(do_mov_1543)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0xe7")
int BPF_KPROBE(do_mov_1544)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0x74")
int BPF_KPROBE(do_mov_1545)
{
    u64 addr = ctx->r11 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0x93")
int BPF_KPROBE(do_mov_1546)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0xa1")
int BPF_KPROBE(do_mov_1547)
{
    u64 addr = ctx->r12 + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0x16c")
int BPF_KPROBE(do_mov_1548)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0x18a")
int BPF_KPROBE(do_mov_1549)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0x1a4")
int BPF_KPROBE(do_mov_1550)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0x1af")
int BPF_KPROBE(do_mov_1551)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_parse_options+0x61")
int BPF_KPROBE(do_mov_1552)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_parse_options+0xe3")
int BPF_KPROBE(do_mov_1553)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_parse_options+0xf2")
int BPF_KPROBE(do_mov_1554)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_parse_options+0x10f")
int BPF_KPROBE(do_mov_1555)
{
    u64 addr = ctx->r12 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_parse_options+0x154")
int BPF_KPROBE(do_mov_1556)
{
    u64 addr = ctx->r12 + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_cpu_seq_start+0x65")
int BPF_KPROBE(do_mov_1557)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_cpu_seq_next+0x58")
int BPF_KPROBE(do_mov_1558)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_cpu_seq_next+0x86")
int BPF_KPROBE(do_mov_1559)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_net_init+0x85")
int BPF_KPROBE(do_mov_1560)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_net_init+0x98")
int BPF_KPROBE(do_mov_1561)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x7a")
int BPF_KPROBE(do_mov_1562)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x86")
int BPF_KPROBE(do_mov_1563)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x153")
int BPF_KPROBE(do_mov_1564)
{
    u64 addr = ctx->r15 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x161")
int BPF_KPROBE(do_mov_1565)
{
    u64 addr = ctx->r15 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x172")
int BPF_KPROBE(do_mov_1566)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x18d")
int BPF_KPROBE(do_mov_1567)
{
    u64 addr = ctx->r9 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x192")
int BPF_KPROBE(do_mov_1568)
{
    u64 addr = ctx->r9 + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x19e")
int BPF_KPROBE(do_mov_1569)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1a2")
int BPF_KPROBE(do_mov_1570)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1ae")
int BPF_KPROBE(do_mov_1571)
{
    u64 addr = ctx->r9 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1b5")
int BPF_KPROBE(do_mov_1572)
{
    u64 addr = ctx->r9 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1ca")
int BPF_KPROBE(do_mov_1573)
{
    u64 addr = ctx->r15 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1e9")
int BPF_KPROBE(do_mov_1574)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1f6")
int BPF_KPROBE(do_mov_1575)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1f9")
int BPF_KPROBE(do_mov_1576)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x201")
int BPF_KPROBE(do_mov_1577)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x20f")
int BPF_KPROBE(do_mov_1578)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x229")
int BPF_KPROBE(do_mov_1579)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x235")
int BPF_KPROBE(do_mov_1580)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x23d")
int BPF_KPROBE(do_mov_1581)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x244")
int BPF_KPROBE(do_mov_1582)
{
    u64 addr = ctx->ax + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x2a4")
int BPF_KPROBE(do_mov_1583)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x2bc")
int BPF_KPROBE(do_mov_1584)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x1f3")
int BPF_KPROBE(do_mov_1585)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x258")
int BPF_KPROBE(do_mov_1586)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x263")
int BPF_KPROBE(do_mov_1587)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x394")
int BPF_KPROBE(do_mov_1588)
{
    u64 addr = ctx->dx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3a2")
int BPF_KPROBE(do_mov_1589)
{
    u64 addr = ctx->dx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3b6")
int BPF_KPROBE(do_mov_1590)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3d0")
int BPF_KPROBE(do_mov_1591)
{
    u64 addr = ctx->r9 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3d9")
int BPF_KPROBE(do_mov_1592)
{
    u64 addr = ctx->r9 + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3e5")
int BPF_KPROBE(do_mov_1593)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3e9")
int BPF_KPROBE(do_mov_1594)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3f5")
int BPF_KPROBE(do_mov_1595)
{
    u64 addr = ctx->r9 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3fc")
int BPF_KPROBE(do_mov_1596)
{
    u64 addr = ctx->r9 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x411")
int BPF_KPROBE(do_mov_1597)
{
    u64 addr = ctx->dx + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x435")
int BPF_KPROBE(do_mov_1598)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x43c")
int BPF_KPROBE(do_mov_1599)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x444")
int BPF_KPROBE(do_mov_1600)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x44b")
int BPF_KPROBE(do_mov_1601)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x459")
int BPF_KPROBE(do_mov_1602)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x465")
int BPF_KPROBE(do_mov_1603)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x470")
int BPF_KPROBE(do_mov_1604)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x47b")
int BPF_KPROBE(do_mov_1605)
{
    u64 addr = ctx->ax + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5af")
int BPF_KPROBE(do_mov_1606)
{
    u64 addr = ctx->r15 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5bd")
int BPF_KPROBE(do_mov_1607)
{
    u64 addr = ctx->r15 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5d3")
int BPF_KPROBE(do_mov_1608)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5e6")
int BPF_KPROBE(do_mov_1609)
{
    u64 addr = ctx->r13 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5eb")
int BPF_KPROBE(do_mov_1610)
{
    u64 addr = ctx->r13 + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5f7")
int BPF_KPROBE(do_mov_1611)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5fb")
int BPF_KPROBE(do_mov_1612)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x607")
int BPF_KPROBE(do_mov_1613)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x60b")
int BPF_KPROBE(do_mov_1614)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x61d")
int BPF_KPROBE(do_mov_1615)
{
    u64 addr = ctx->r15 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x641")
int BPF_KPROBE(do_mov_1616)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x649")
int BPF_KPROBE(do_mov_1617)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x658")
int BPF_KPROBE(do_mov_1618)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x65f")
int BPF_KPROBE(do_mov_1619)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x666")
int BPF_KPROBE(do_mov_1620)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x671")
int BPF_KPROBE(do_mov_1621)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x679")
int BPF_KPROBE(do_mov_1622)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x68d")
int BPF_KPROBE(do_mov_1623)
{
    u64 addr = ctx->ax + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x7d6")
int BPF_KPROBE(do_mov_1624)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0xc0")
int BPF_KPROBE(do_mov_1625)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0xd0")
int BPF_KPROBE(do_mov_1626)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0xe7")
int BPF_KPROBE(do_mov_1627)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0xfe")
int BPF_KPROBE(do_mov_1628)
{
    u64 addr = ctx->r13 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x103")
int BPF_KPROBE(do_mov_1629)
{
    u64 addr = ctx->r13 + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x10f")
int BPF_KPROBE(do_mov_1630)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x113")
int BPF_KPROBE(do_mov_1631)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x11f")
int BPF_KPROBE(do_mov_1632)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x123")
int BPF_KPROBE(do_mov_1633)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x137")
int BPF_KPROBE(do_mov_1634)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x158")
int BPF_KPROBE(do_mov_1635)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x160")
int BPF_KPROBE(do_mov_1636)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x173")
int BPF_KPROBE(do_mov_1637)
{
    u64 addr = ctx->r15 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x17b")
int BPF_KPROBE(do_mov_1638)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x18d")
int BPF_KPROBE(do_mov_1639)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x1a6")
int BPF_KPROBE(do_mov_1640)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x1c6")
int BPF_KPROBE(do_mov_1641)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0xbe")
int BPF_KPROBE(do_mov_1642)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0xd6")
int BPF_KPROBE(do_mov_1643)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0xf6")
int BPF_KPROBE(do_mov_1644)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0xff")
int BPF_KPROBE(do_mov_1645)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x10e")
int BPF_KPROBE(do_mov_1646)
{
    u64 addr = ctx->r13 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x116")
int BPF_KPROBE(do_mov_1647)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x11a")
int BPF_KPROBE(do_mov_1648)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x11e")
int BPF_KPROBE(do_mov_1649)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x122")
int BPF_KPROBE(do_mov_1650)
{
    u64 addr = ctx->r13 + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x137")
int BPF_KPROBE(do_mov_1651)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x15c")
int BPF_KPROBE(do_mov_1652)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x164")
int BPF_KPROBE(do_mov_1653)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x17b")
int BPF_KPROBE(do_mov_1654)
{
    u64 addr = ctx->r15 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x183")
int BPF_KPROBE(do_mov_1655)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x195")
int BPF_KPROBE(do_mov_1656)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x1ae")
int BPF_KPROBE(do_mov_1657)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x1ce")
int BPF_KPROBE(do_mov_1658)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x77")
int BPF_KPROBE(do_mov_1659)
{
    u64 addr = ctx->r14 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x85")
int BPF_KPROBE(do_mov_1660)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x13e")
int BPF_KPROBE(do_mov_1661)
{
    u64 addr = ctx->dx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x151")
int BPF_KPROBE(do_mov_1662)
{
    u64 addr = ctx->dx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x169")
int BPF_KPROBE(do_mov_1663)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x170")
int BPF_KPROBE(do_mov_1664)
{
    u64 addr = ctx->cx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x17e")
int BPF_KPROBE(do_mov_1665)
{
    u64 addr = ctx->cx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x186")
int BPF_KPROBE(do_mov_1666)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x18a")
int BPF_KPROBE(do_mov_1667)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x18d")
int BPF_KPROBE(do_mov_1668)
{
    u64 addr = ctx->cx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1a6")
int BPF_KPROBE(do_mov_1669)
{
    u64 addr = ctx->dx + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1c0")
int BPF_KPROBE(do_mov_1670)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1c9")
int BPF_KPROBE(do_mov_1671)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1d6")
int BPF_KPROBE(do_mov_1672)
{
    u64 addr = ctx->r15 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1de")
int BPF_KPROBE(do_mov_1673)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1ed")
int BPF_KPROBE(do_mov_1674)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x206")
int BPF_KPROBE(do_mov_1675)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x212")
int BPF_KPROBE(do_mov_1676)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x21b")
int BPF_KPROBE(do_mov_1677)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x223")
int BPF_KPROBE(do_mov_1678)
{
    u64 addr = ctx->r15 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x289")
int BPF_KPROBE(do_mov_1679)
{
    u64 addr = ctx->r14 + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x2a1")
int BPF_KPROBE(do_mov_1680)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x19b")
int BPF_KPROBE(do_mov_1681)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x204")
int BPF_KPROBE(do_mov_1682)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x20f")
int BPF_KPROBE(do_mov_1683)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x367")
int BPF_KPROBE(do_mov_1684)
{
    u64 addr = ctx->dx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x37d")
int BPF_KPROBE(do_mov_1685)
{
    u64 addr = ctx->dx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3a7")
int BPF_KPROBE(do_mov_1686)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3aa")
int BPF_KPROBE(do_mov_1687)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3b9")
int BPF_KPROBE(do_mov_1688)
{
    u64 addr = ctx->cx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3c5")
int BPF_KPROBE(do_mov_1689)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3c9")
int BPF_KPROBE(do_mov_1690)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3cd")
int BPF_KPROBE(do_mov_1691)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3d0")
int BPF_KPROBE(do_mov_1692)
{
    u64 addr = ctx->cx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3e6")
int BPF_KPROBE(do_mov_1693)
{
    u64 addr = ctx->dx + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x418")
int BPF_KPROBE(do_mov_1694)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x41f")
int BPF_KPROBE(do_mov_1695)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x427")
int BPF_KPROBE(do_mov_1696)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x42e")
int BPF_KPROBE(do_mov_1697)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x43c")
int BPF_KPROBE(do_mov_1698)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x448")
int BPF_KPROBE(do_mov_1699)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x454")
int BPF_KPROBE(do_mov_1700)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x45f")
int BPF_KPROBE(do_mov_1701)
{
    u64 addr = ctx->ax + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x590")
int BPF_KPROBE(do_mov_1702)
{
    u64 addr = ctx->r15 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5a3")
int BPF_KPROBE(do_mov_1703)
{
    u64 addr = ctx->r15 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5ba")
int BPF_KPROBE(do_mov_1704)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5c0")
int BPF_KPROBE(do_mov_1705)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5cf")
int BPF_KPROBE(do_mov_1706)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5d5")
int BPF_KPROBE(do_mov_1707)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5d9")
int BPF_KPROBE(do_mov_1708)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5dc")
int BPF_KPROBE(do_mov_1709)
{
    u64 addr = ctx->dx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5f2")
int BPF_KPROBE(do_mov_1710)
{
    u64 addr = ctx->r15 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x615")
int BPF_KPROBE(do_mov_1711)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x61f")
int BPF_KPROBE(do_mov_1712)
{
    u64 addr = ctx->r13 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x62f")
int BPF_KPROBE(do_mov_1713)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x637")
int BPF_KPROBE(do_mov_1714)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x63f")
int BPF_KPROBE(do_mov_1715)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x64b")
int BPF_KPROBE(do_mov_1716)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x654")
int BPF_KPROBE(do_mov_1717)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x669")
int BPF_KPROBE(do_mov_1718)
{
    u64 addr = ctx->r13 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x7b6")
int BPF_KPROBE(do_mov_1719)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0xa")
int BPF_KPROBE(do_mov_1720)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0xe")
int BPF_KPROBE(do_mov_1721)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0x14")
int BPF_KPROBE(do_mov_1722)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0x22")
int BPF_KPROBE(do_mov_1723)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0x2a")
int BPF_KPROBE(do_mov_1724)
{
    u64 addr = ctx->di + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0x8a")
int BPF_KPROBE(do_mov_1725)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0x96")
int BPF_KPROBE(do_mov_1726)
{
    u64 addr = ctx->r12 + 0x800;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xb6")
int BPF_KPROBE(do_mov_1727)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xc4")
int BPF_KPROBE(do_mov_1728)
{
    u64 addr = ctx->r12 + 0x810;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xd4")
int BPF_KPROBE(do_mov_1729)
{
    u64 addr = ctx->r12 + 0x818;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xdc")
int BPF_KPROBE(do_mov_1730)
{
    u64 addr = ctx->r12 + 0x808;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xe4")
int BPF_KPROBE(do_mov_1731)
{
    u64 addr = ctx->r12 + 0x820;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xec")
int BPF_KPROBE(do_mov_1732)
{
    u64 addr = ctx->r12 + 0x828;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tree_gc_worker+0x190")
int BPF_KPROBE(do_mov_1733)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x2b3")
int BPF_KPROBE(do_mov_1734)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x2b7")
int BPF_KPROBE(do_mov_1735)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x2cb")
int BPF_KPROBE(do_mov_1736)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x2d2")
int BPF_KPROBE(do_mov_1737)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x323")
int BPF_KPROBE(do_mov_1738)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x32b")
int BPF_KPROBE(do_mov_1739)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x333")
int BPF_KPROBE(do_mov_1740)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x33b")
int BPF_KPROBE(do_mov_1741)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x343")
int BPF_KPROBE(do_mov_1742)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x34a")
int BPF_KPROBE(do_mov_1743)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x358")
int BPF_KPROBE(do_mov_1744)
{
    u64 addr = ctx->ax + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x366")
int BPF_KPROBE(do_mov_1745)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x36d")
int BPF_KPROBE(do_mov_1746)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x370")
int BPF_KPROBE(do_mov_1747)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x374")
int BPF_KPROBE(do_mov_1748)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x378")
int BPF_KPROBE(do_mov_1749)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x386")
int BPF_KPROBE(do_mov_1750)
{
    u64 addr = ctx->si + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x426")
int BPF_KPROBE(do_mov_1751)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x42e")
int BPF_KPROBE(do_mov_1752)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x436")
int BPF_KPROBE(do_mov_1753)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x43e")
int BPF_KPROBE(do_mov_1754)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x446")
int BPF_KPROBE(do_mov_1755)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x453")
int BPF_KPROBE(do_mov_1756)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x48a")
int BPF_KPROBE(do_mov_1757)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x494")
int BPF_KPROBE(do_mov_1758)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x498")
int BPF_KPROBE(do_mov_1759)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x49d")
int BPF_KPROBE(do_mov_1760)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4a9")
int BPF_KPROBE(do_mov_1761)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4b2")
int BPF_KPROBE(do_mov_1762)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4b7")
int BPF_KPROBE(do_mov_1763)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4bc")
int BPF_KPROBE(do_mov_1764)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4c0")
int BPF_KPROBE(do_mov_1765)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4c4")
int BPF_KPROBE(do_mov_1766)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4c9")
int BPF_KPROBE(do_mov_1767)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4d2")
int BPF_KPROBE(do_mov_1768)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4db")
int BPF_KPROBE(do_mov_1769)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4e4")
int BPF_KPROBE(do_mov_1770)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x534")
int BPF_KPROBE(do_mov_1771)
{
    u64 addr = ctx->r14 + ctx->si * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x53c")
int BPF_KPROBE(do_mov_1772)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x59a")
int BPF_KPROBE(do_mov_1773)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x5a3")
int BPF_KPROBE(do_mov_1774)
{
    u64 addr = ctx->r14 + ctx->si * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_do_netdev_egress+0x2e")
int BPF_KPROBE(do_mov_1775)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_do_netdev_egress+0x3b")
int BPF_KPROBE(do_mov_1776)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_dup_netdev_offload+0x34")
int BPF_KPROBE(do_mov_1777)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_dup_netdev_offload+0x49")
int BPF_KPROBE(do_mov_1778)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_dup_netdev_offload+0x4d")
int BPF_KPROBE(do_mov_1779)
{
    u64 addr = ctx->dx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_trace_packet+0x12")
int BPF_KPROBE(do_mov_1780)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_trace_packet+0x16")
int BPF_KPROBE(do_mov_1781)
{
    u64 addr = ctx->di + 0x3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_trace_verdict.isra.0+0x37")
int BPF_KPROBE(do_mov_1782)
{
    u64 addr = ctx->di + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_do_chain+0x2c0")
int BPF_KPROBE(do_mov_1783)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_do_chain+0x402")
int BPF_KPROBE(do_mov_1784)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x37")
int BPF_KPROBE(do_mov_1785)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x3e")
int BPF_KPROBE(do_mov_1786)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x46")
int BPF_KPROBE(do_mov_1787)
{
    u64 addr = ctx->cx + ctx->ax * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x76")
int BPF_KPROBE(do_mov_1788)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x7d")
int BPF_KPROBE(do_mov_1789)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x85")
int BPF_KPROBE(do_mov_1790)
{
    u64 addr = ctx->cx + ctx->ax * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_reg_track_cancel+0x16")
int BPF_KPROBE(do_mov_1791)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_reg_track_cancel+0x20")
int BPF_KPROBE(do_mov_1792)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_reg_track_cancel+0x2c")
int BPF_KPROBE(do_mov_1793)
{
    u64 addr = ctx->di + ctx->ax * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_chain_type+0x49")
int BPF_KPROBE(do_mov_1794)
{
    u64 addr =  - 0x7c6ee940 + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_chain_type+0x2a")
int BPF_KPROBE(do_mov_1795)
{
    u64 addr =  - 0x7c6ee940 + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_expr+0x28")
int BPF_KPROBE(do_mov_1796)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_expr+0x30")
int BPF_KPROBE(do_mov_1797)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_expr+0x34")
int BPF_KPROBE(do_mov_1798)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_expr+0x57")
int BPF_KPROBE(do_mov_1799)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_expr+0x5f")
int BPF_KPROBE(do_mov_1800)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_expr+0x6a")
int BPF_KPROBE(do_mov_1801)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_expr+0x24")
int BPF_KPROBE(do_mov_1802)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_expr+0x28")
int BPF_KPROBE(do_mov_1803)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_expr+0x35")
int BPF_KPROBE(do_mov_1804)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_obj+0x29")
int BPF_KPROBE(do_mov_1805)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_obj+0x31")
int BPF_KPROBE(do_mov_1806)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_obj+0x35")
int BPF_KPROBE(do_mov_1807)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_obj+0x24")
int BPF_KPROBE(do_mov_1808)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_obj+0x28")
int BPF_KPROBE(do_mov_1809)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_obj+0x35")
int BPF_KPROBE(do_mov_1810)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_type+0x1e")
int BPF_KPROBE(do_mov_1811)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_type+0x25")
int BPF_KPROBE(do_mov_1812)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_type+0x29")
int BPF_KPROBE(do_mov_1813)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_flowtable_type+0x23")
int BPF_KPROBE(do_mov_1814)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_flowtable_type+0x27")
int BPF_KPROBE(do_mov_1815)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_flowtable_type+0x34")
int BPF_KPROBE(do_mov_1816)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_destroy+0x6c")
int BPF_KPROBE(do_mov_1817)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_destroy+0x70")
int BPF_KPROBE(do_mov_1818)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_destroy+0x73")
int BPF_KPROBE(do_mov_1819)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x3d")
int BPF_KPROBE(do_mov_1820)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x41")
int BPF_KPROBE(do_mov_1821)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x44")
int BPF_KPROBE(do_mov_1822)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x47")
int BPF_KPROBE(do_mov_1823)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x40")
int BPF_KPROBE(do_mov_1824)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x5b")
int BPF_KPROBE(do_mov_1825)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x66")
int BPF_KPROBE(do_mov_1826)
{
    u64 addr = ctx->r10 + ctx->ax * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x7d")
int BPF_KPROBE(do_mov_1827)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x8b")
int BPF_KPROBE(do_mov_1828)
{
    u64 addr = ctx->r10 + ctx->r8 * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x9b")
int BPF_KPROBE(do_mov_1829)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0xa3")
int BPF_KPROBE(do_mov_1830)
{
    u64 addr = ctx->r10 + ctx->r8 * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_u32_check+0x12")
int BPF_KPROBE(do_mov_1831)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_netdev_unregister_hooks+0x4d")
int BPF_KPROBE(do_mov_1832)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_netdev_unregister_hooks+0x51")
int BPF_KPROBE(do_mov_1833)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_netdev_unregister_hooks+0x54")
int BPF_KPROBE(do_mov_1834)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_netdev_unregister_hooks+0x5b")
int BPF_KPROBE(do_mov_1835)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit_audit_log+0x5a")
int BPF_KPROBE(do_mov_1836)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit_audit_log+0x5e")
int BPF_KPROBE(do_mov_1837)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit_audit_log+0x6b")
int BPF_KPROBE(do_mov_1838)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit_audit_log+0x6f")
int BPF_KPROBE(do_mov_1839)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_netdev_hook_alloc+0x68")
int BPF_KPROBE(do_mov_1840)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x9b")
int BPF_KPROBE(do_mov_1841)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0xa0")
int BPF_KPROBE(do_mov_1842)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0xa3")
int BPF_KPROBE(do_mov_1843)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0xa7")
int BPF_KPROBE(do_mov_1844)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x102")
int BPF_KPROBE(do_mov_1845)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x106")
int BPF_KPROBE(do_mov_1846)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x109")
int BPF_KPROBE(do_mov_1847)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x10c")
int BPF_KPROBE(do_mov_1848)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets_start+0x25")
int BPF_KPROBE(do_mov_1849)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set_start+0x24")
int BPF_KPROBE(do_mov_1850)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x36")
int BPF_KPROBE(do_mov_1851)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x3d")
int BPF_KPROBE(do_mov_1852)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x45")
int BPF_KPROBE(do_mov_1853)
{
    u64 addr = ctx->di + ctx->ax * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x72")
int BPF_KPROBE(do_mov_1854)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x75")
int BPF_KPROBE(do_mov_1855)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x7d")
int BPF_KPROBE(do_mov_1856)
{
    u64 addr = ctx->di + ctx->ax * 0x8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_register_load+0x30")
int BPF_KPROBE(do_mov_1857)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_net_hooks+0x10e")
int BPF_KPROBE(do_mov_1858)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_net_hooks+0x112")
int BPF_KPROBE(do_mov_1859)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_net_hooks+0x11f")
int BPF_KPROBE(do_mov_1860)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_gc+0x64")
int BPF_KPROBE(do_mov_1861)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_gc+0x68")
int BPF_KPROBE(do_mov_1862)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_gc+0x6b")
int BPF_KPROBE(do_mov_1863)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj_start+0x52")
int BPF_KPROBE(do_mov_1864)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj_start+0x69")
int BPF_KPROBE(do_mov_1865)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj_start+0x6e")
int BPF_KPROBE(do_mov_1866)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_rules_start+0x52")
int BPF_KPROBE(do_mov_1867)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_rules_start+0x6e")
int BPF_KPROBE(do_mov_1868)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_rules_start+0x78")
int BPF_KPROBE(do_mov_1869)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable_start+0x4f")
int BPF_KPROBE(do_mov_1870)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable_start+0x58")
int BPF_KPROBE(do_mov_1871)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0x43")
int BPF_KPROBE(do_mov_1872)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0x4b")
int BPF_KPROBE(do_mov_1873)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xad")
int BPF_KPROBE(do_mov_1874)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xb9")
int BPF_KPROBE(do_mov_1875)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xe0")
int BPF_KPROBE(do_mov_1876)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xe6")
int BPF_KPROBE(do_mov_1877)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xec")
int BPF_KPROBE(do_mov_1878)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xf0")
int BPF_KPROBE(do_mov_1879)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xff")
int BPF_KPROBE(do_mov_1880)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0x148")
int BPF_KPROBE(do_mov_1881)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x5f")
int BPF_KPROBE(do_mov_1882)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x107")
int BPF_KPROBE(do_mov_1883)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x10a")
int BPF_KPROBE(do_mov_1884)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_stats_alloc+0xe6")
int BPF_KPROBE(do_mov_1885)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_stats_alloc+0xf9")
int BPF_KPROBE(do_mov_1886)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_cleanup+0x2b")
int BPF_KPROBE(do_mov_1887)
{
    u64 addr = ctx->bx + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x3d")
int BPF_KPROBE(do_mov_1888)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x44")
int BPF_KPROBE(do_mov_1889)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x48")
int BPF_KPROBE(do_mov_1890)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x4c")
int BPF_KPROBE(do_mov_1891)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x54")
int BPF_KPROBE(do_mov_1892)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x58")
int BPF_KPROBE(do_mov_1893)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x60")
int BPF_KPROBE(do_mov_1894)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x64")
int BPF_KPROBE(do_mov_1895)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x6d")
int BPF_KPROBE(do_mov_1896)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x76")
int BPF_KPROBE(do_mov_1897)
{
    u64 addr = ctx->bx + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit_chain_prepare_cancel+0x66")
int BPF_KPROBE(do_mov_1898)
{
    u64 addr = ctx->r13 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_init+0xcc")
int BPF_KPROBE(do_mov_1899)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_init+0x12c")
int BPF_KPROBE(do_mov_1900)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_init+0x19b")
int BPF_KPROBE(do_mov_1901)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_init+0x1a0")
int BPF_KPROBE(do_mov_1902)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x72")
int BPF_KPROBE(do_mov_1903)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x76")
int BPF_KPROBE(do_mov_1904)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x79")
int BPF_KPROBE(do_mov_1905)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x7c")
int BPF_KPROBE(do_mov_1906)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_validate+0x93")
int BPF_KPROBE(do_mov_1907)
{
    u64 addr = ctx->bx + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_register_store+0x48")
int BPF_KPROBE(do_mov_1908)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_register_store+0x8f")
int BPF_KPROBE(do_mov_1909)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_add+0x8c")
int BPF_KPROBE(do_mov_1910)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_add+0x90")
int BPF_KPROBE(do_mov_1911)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_add+0x94")
int BPF_KPROBE(do_mov_1912)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_add+0x97")
int BPF_KPROBE(do_mov_1913)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_remove+0x6a")
int BPF_KPROBE(do_mov_1914)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_remove+0x6e")
int BPF_KPROBE(do_mov_1915)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_remove+0x7b")
int BPF_KPROBE(do_mov_1916)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_del+0xa2")
int BPF_KPROBE(do_mov_1917)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_del+0xa6")
int BPF_KPROBE(do_mov_1918)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_del+0xb3")
int BPF_KPROBE(do_mov_1919)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_event+0x104")
int BPF_KPROBE(do_mov_1920)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_event+0x108")
int BPF_KPROBE(do_mov_1921)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_event+0x10b")
int BPF_KPROBE(do_mov_1922)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_request_module+0x10b")
int BPF_KPROBE(do_mov_1923)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_request_module+0x149")
int BPF_KPROBE(do_mov_1924)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_request_module+0x14d")
int BPF_KPROBE(do_mov_1925)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_request_module+0x150")
int BPF_KPROBE(do_mov_1926)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_request_module+0x154")
int BPF_KPROBE(do_mov_1927)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_expr_parse+0x171")
int BPF_KPROBE(do_mov_1928)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_expr_parse+0x175")
int BPF_KPROBE(do_mov_1929)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x27")
int BPF_KPROBE(do_mov_1930)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x2a")
int BPF_KPROBE(do_mov_1931)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x2e")
int BPF_KPROBE(do_mov_1932)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x36")
int BPF_KPROBE(do_mov_1933)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x3a")
int BPF_KPROBE(do_mov_1934)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x42")
int BPF_KPROBE(do_mov_1935)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x4a")
int BPF_KPROBE(do_mov_1936)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x52")
int BPF_KPROBE(do_mov_1937)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x5a")
int BPF_KPROBE(do_mov_1938)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x34")
int BPF_KPROBE(do_mov_1939)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x5c")
int BPF_KPROBE(do_mov_1940)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x64")
int BPF_KPROBE(do_mov_1941)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x68")
int BPF_KPROBE(do_mov_1942)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x6d")
int BPF_KPROBE(do_mov_1943)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x8e")
int BPF_KPROBE(do_mov_1944)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x35")
int BPF_KPROBE(do_mov_1945)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x60")
int BPF_KPROBE(do_mov_1946)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x68")
int BPF_KPROBE(do_mov_1947)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x6b")
int BPF_KPROBE(do_mov_1948)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x6f")
int BPF_KPROBE(do_mov_1949)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x99")
int BPF_KPROBE(do_mov_1950)
{
    u64 addr = ctx->r13 + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x31")
int BPF_KPROBE(do_mov_1951)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x5c")
int BPF_KPROBE(do_mov_1952)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x64")
int BPF_KPROBE(do_mov_1953)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x67")
int BPF_KPROBE(do_mov_1954)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x6b")
int BPF_KPROBE(do_mov_1955)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x92")
int BPF_KPROBE(do_mov_1956)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x150")
int BPF_KPROBE(do_mov_1957)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x154")
int BPF_KPROBE(do_mov_1958)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x193")
int BPF_KPROBE(do_mov_1959)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x19b")
int BPF_KPROBE(do_mov_1960)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delchain+0x57")
int BPF_KPROBE(do_mov_1961)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delchain+0x5f")
int BPF_KPROBE(do_mov_1962)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delchain+0x62")
int BPF_KPROBE(do_mov_1963)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delchain+0x66")
int BPF_KPROBE(do_mov_1964)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delchain+0xa6")
int BPF_KPROBE(do_mov_1965)
{
    u64 addr = ctx->si + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x43")
int BPF_KPROBE(do_mov_1966)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x47")
int BPF_KPROBE(do_mov_1967)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x4b")
int BPF_KPROBE(do_mov_1968)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x6c")
int BPF_KPROBE(do_mov_1969)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x74")
int BPF_KPROBE(do_mov_1970)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x77")
int BPF_KPROBE(do_mov_1971)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x7b")
int BPF_KPROBE(do_mov_1972)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0xa2")
int BPF_KPROBE(do_mov_1973)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xcf")
int BPF_KPROBE(do_mov_1974)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xd8")
int BPF_KPROBE(do_mov_1975)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xdc")
int BPF_KPROBE(do_mov_1976)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xe1")
int BPF_KPROBE(do_mov_1977)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xe4")
int BPF_KPROBE(do_mov_1978)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0x169")
int BPF_KPROBE(do_mov_1979)
{
    u64 addr = ctx->ax + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0x16f")
int BPF_KPROBE(do_mov_1980)
{
    u64 addr = ctx->ax + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x9f")
int BPF_KPROBE(do_mov_1981)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0xac")
int BPF_KPROBE(do_mov_1982)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x153")
int BPF_KPROBE(do_mov_1983)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x15b")
int BPF_KPROBE(do_mov_1984)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x1de")
int BPF_KPROBE(do_mov_1985)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x1e2")
int BPF_KPROBE(do_mov_1986)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x1e6")
int BPF_KPROBE(do_mov_1987)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x21b")
int BPF_KPROBE(do_mov_1988)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x21f")
int BPF_KPROBE(do_mov_1989)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x222")
int BPF_KPROBE(do_mov_1990)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x226")
int BPF_KPROBE(do_mov_1991)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x2da")
int BPF_KPROBE(do_mov_1992)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x2e3")
int BPF_KPROBE(do_mov_1993)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_init+0xbe")
int BPF_KPROBE(do_mov_1994)
{
    u64 addr = ctx->r13 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_init+0xa3")
int BPF_KPROBE(do_mov_1995)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_init+0xc6")
int BPF_KPROBE(do_mov_1996)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x223")
int BPF_KPROBE(do_mov_1997)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x227")
int BPF_KPROBE(do_mov_1998)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x264")
int BPF_KPROBE(do_mov_1999)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x26c")
int BPF_KPROBE(do_mov_2000)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_expr_info+0x92")
int BPF_KPROBE(do_mov_2001)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x261")
int BPF_KPROBE(do_mov_2002)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x265")
int BPF_KPROBE(do_mov_2003)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x301")
int BPF_KPROBE(do_mov_2004)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x305")
int BPF_KPROBE(do_mov_2005)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x30f")
int BPF_KPROBE(do_mov_2006)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x313")
int BPF_KPROBE(do_mov_2007)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x316")
int BPF_KPROBE(do_mov_2008)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x34c")
int BPF_KPROBE(do_mov_2009)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x354")
int BPF_KPROBE(do_mov_2010)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x358")
int BPF_KPROBE(do_mov_2011)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x35c")
int BPF_KPROBE(do_mov_2012)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x377")
int BPF_KPROBE(do_mov_2013)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x37b")
int BPF_KPROBE(do_mov_2014)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x37f")
int BPF_KPROBE(do_mov_2015)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x382")
int BPF_KPROBE(do_mov_2016)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3aa")
int BPF_KPROBE(do_mov_2017)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3ae")
int BPF_KPROBE(do_mov_2018)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3b1")
int BPF_KPROBE(do_mov_2019)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3b4")
int BPF_KPROBE(do_mov_2020)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3ec")
int BPF_KPROBE(do_mov_2021)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3f4")
int BPF_KPROBE(do_mov_2022)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3f8")
int BPF_KPROBE(do_mov_2023)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3fc")
int BPF_KPROBE(do_mov_2024)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x428")
int BPF_KPROBE(do_mov_2025)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x42c")
int BPF_KPROBE(do_mov_2026)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x430")
int BPF_KPROBE(do_mov_2027)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x433")
int BPF_KPROBE(do_mov_2028)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x45f")
int BPF_KPROBE(do_mov_2029)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x463")
int BPF_KPROBE(do_mov_2030)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x466")
int BPF_KPROBE(do_mov_2031)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x469")
int BPF_KPROBE(do_mov_2032)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x499")
int BPF_KPROBE(do_mov_2033)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x4a1")
int BPF_KPROBE(do_mov_2034)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_gen_info+0xc3")
int BPF_KPROBE(do_mov_2035)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_gen_info+0xd1")
int BPF_KPROBE(do_mov_2036)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_gen_info+0x168")
int BPF_KPROBE(do_mov_2037)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x35")
int BPF_KPROBE(do_mov_2038)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x5f")
int BPF_KPROBE(do_mov_2039)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x67")
int BPF_KPROBE(do_mov_2040)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x6b")
int BPF_KPROBE(do_mov_2041)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x70")
int BPF_KPROBE(do_mov_2042)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0xb8")
int BPF_KPROBE(do_mov_2043)
{
    u64 addr = ctx->r15 + 0x15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0xed")
int BPF_KPROBE(do_mov_2044)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x106")
int BPF_KPROBE(do_mov_2045)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x10a")
int BPF_KPROBE(do_mov_2046)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x117")
int BPF_KPROBE(do_mov_2047)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x11f")
int BPF_KPROBE(do_mov_2048)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x14b")
int BPF_KPROBE(do_mov_2049)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x14f")
int BPF_KPROBE(do_mov_2050)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x15c")
int BPF_KPROBE(do_mov_2051)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x164")
int BPF_KPROBE(do_mov_2052)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x62")
int BPF_KPROBE(do_mov_2053)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x231")
int BPF_KPROBE(do_mov_2054)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2a8")
int BPF_KPROBE(do_mov_2055)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2b0")
int BPF_KPROBE(do_mov_2056)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2b4")
int BPF_KPROBE(do_mov_2057)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2b9")
int BPF_KPROBE(do_mov_2058)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2e5")
int BPF_KPROBE(do_mov_2059)
{
    u64 addr = ctx->si + 0xed;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deltable+0x1f1")
int BPF_KPROBE(do_mov_2060)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deltable+0x1f5")
int BPF_KPROBE(do_mov_2061)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x1e3")
int BPF_KPROBE(do_mov_2062)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x1eb")
int BPF_KPROBE(do_mov_2063)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x207")
int BPF_KPROBE(do_mov_2064)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x20f")
int BPF_KPROBE(do_mov_2065)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x2ab")
int BPF_KPROBE(do_mov_2066)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x2b3")
int BPF_KPROBE(do_mov_2067)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x2c9")
int BPF_KPROBE(do_mov_2068)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x2d1")
int BPF_KPROBE(do_mov_2069)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delchain+0x10f")
int BPF_KPROBE(do_mov_2070)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delchain+0x117")
int BPF_KPROBE(do_mov_2071)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delchain+0x23c")
int BPF_KPROBE(do_mov_2072)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delchain+0x244")
int BPF_KPROBE(do_mov_2073)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delchain+0x261")
int BPF_KPROBE(do_mov_2074)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delchain+0x269")
int BPF_KPROBE(do_mov_2075)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_table_info+0xbc")
int BPF_KPROBE(do_mov_2076)
{
    u64 addr = ctx->bx + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_table_info+0xc0")
int BPF_KPROBE(do_mov_2077)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_table_info+0xc5")
int BPF_KPROBE(do_mov_2078)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_table_info+0x1c4")
int BPF_KPROBE(do_mov_2079)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xb6")
int BPF_KPROBE(do_mov_2080)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xbf")
int BPF_KPROBE(do_mov_2081)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xc3")
int BPF_KPROBE(do_mov_2082)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xc7")
int BPF_KPROBE(do_mov_2083)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xcc")
int BPF_KPROBE(do_mov_2084)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0x71")
int BPF_KPROBE(do_mov_2085)
{
    u64 addr = ctx->r12 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0xb3")
int BPF_KPROBE(do_mov_2086)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0xbc")
int BPF_KPROBE(do_mov_2087)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0xc5")
int BPF_KPROBE(do_mov_2088)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0xce")
int BPF_KPROBE(do_mov_2089)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0xd7")
int BPF_KPROBE(do_mov_2090)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0x169")
int BPF_KPROBE(do_mov_2091)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0x186")
int BPF_KPROBE(do_mov_2092)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_gettable+0x131")
int BPF_KPROBE(do_mov_2093)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_gettable+0x139")
int BPF_KPROBE(do_mov_2094)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0xc4")
int BPF_KPROBE(do_mov_2095)
{
    u64 addr = ctx->bx + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0xc8")
int BPF_KPROBE(do_mov_2096)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0xcd")
int BPF_KPROBE(do_mov_2097)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0x1f8")
int BPF_KPROBE(do_mov_2098)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0x247")
int BPF_KPROBE(do_mov_2099)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x104")
int BPF_KPROBE(do_mov_2100)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x108")
int BPF_KPROBE(do_mov_2101)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x10b")
int BPF_KPROBE(do_mov_2102)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x10f")
int BPF_KPROBE(do_mov_2103)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x7b")
int BPF_KPROBE(do_mov_2104)
{
    u64 addr = ctx->r14 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x148")
int BPF_KPROBE(do_mov_2105)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x181")
int BPF_KPROBE(do_mov_2106)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x189")
int BPF_KPROBE(do_mov_2107)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x191")
int BPF_KPROBE(do_mov_2108)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x199")
int BPF_KPROBE(do_mov_2109)
{
    u64 addr = ctx->r15 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x1a1")
int BPF_KPROBE(do_mov_2110)
{
    u64 addr = ctx->r15 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x24d")
int BPF_KPROBE(do_mov_2111)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getobj+0x189")
int BPF_KPROBE(do_mov_2112)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getobj+0x191")
int BPF_KPROBE(do_mov_2113)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getobj+0x286")
int BPF_KPROBE(do_mov_2114)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getobj+0x28e")
int BPF_KPROBE(do_mov_2115)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0xc2")
int BPF_KPROBE(do_mov_2116)
{
    u64 addr = ctx->r13 + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0xc7")
int BPF_KPROBE(do_mov_2117)
{
    u64 addr = ctx->r13 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0xcc")
int BPF_KPROBE(do_mov_2118)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0x308")
int BPF_KPROBE(do_mov_2119)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0x322")
int BPF_KPROBE(do_mov_2120)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0x338")
int BPF_KPROBE(do_mov_2121)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xc8")
int BPF_KPROBE(do_mov_2122)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xd0")
int BPF_KPROBE(do_mov_2123)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xd5")
int BPF_KPROBE(do_mov_2124)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xd8")
int BPF_KPROBE(do_mov_2125)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xdc")
int BPF_KPROBE(do_mov_2126)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x6b")
int BPF_KPROBE(do_mov_2127)
{
    u64 addr = ctx->r13 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0xf5")
int BPF_KPROBE(do_mov_2128)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0xfd")
int BPF_KPROBE(do_mov_2129)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x105")
int BPF_KPROBE(do_mov_2130)
{
    u64 addr = ctx->r14 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x10d")
int BPF_KPROBE(do_mov_2131)
{
    u64 addr = ctx->r14 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x115")
int BPF_KPROBE(do_mov_2132)
{
    u64 addr = ctx->r14 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x1a1")
int BPF_KPROBE(do_mov_2133)
{
    u64 addr = ctx->r14 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x1d5")
int BPF_KPROBE(do_mov_2134)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x1f6")
int BPF_KPROBE(do_mov_2135)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x1fb")
int BPF_KPROBE(do_mov_2136)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x200")
int BPF_KPROBE(do_mov_2137)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x222")
int BPF_KPROBE(do_mov_2138)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x22a")
int BPF_KPROBE(do_mov_2139)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x22e")
int BPF_KPROBE(do_mov_2140)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x233")
int BPF_KPROBE(do_mov_2141)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x278")
int BPF_KPROBE(do_mov_2142)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x280")
int BPF_KPROBE(do_mov_2143)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x3c8")
int BPF_KPROBE(do_mov_2144)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x3ea")
int BPF_KPROBE(do_mov_2145)
{
    u64 addr = ctx->r9 + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x3f1")
int BPF_KPROBE(do_mov_2146)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x3ff")
int BPF_KPROBE(do_mov_2147)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x43e")
int BPF_KPROBE(do_mov_2148)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x45a")
int BPF_KPROBE(do_mov_2149)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x4c2")
int BPF_KPROBE(do_mov_2150)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x4c7")
int BPF_KPROBE(do_mov_2151)
{
    u64 addr = ctx->r13 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x4f4")
int BPF_KPROBE(do_mov_2152)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x4fc")
int BPF_KPROBE(do_mov_2153)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x500")
int BPF_KPROBE(do_mov_2154)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x504")
int BPF_KPROBE(do_mov_2155)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x58a")
int BPF_KPROBE(do_mov_2156)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x58e")
int BPF_KPROBE(do_mov_2157)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x596")
int BPF_KPROBE(do_mov_2158)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x599")
int BPF_KPROBE(do_mov_2159)
{
    u64 addr = ctx->r9 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x5c7")
int BPF_KPROBE(do_mov_2160)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x5cf")
int BPF_KPROBE(do_mov_2161)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x69d")
int BPF_KPROBE(do_mov_2162)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x6a1")
int BPF_KPROBE(do_mov_2163)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0xc2")
int BPF_KPROBE(do_mov_2164)
{
    u64 addr = ctx->bx + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0xc6")
int BPF_KPROBE(do_mov_2165)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0xcb")
int BPF_KPROBE(do_mov_2166)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x1c4")
int BPF_KPROBE(do_mov_2167)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x3a1")
int BPF_KPROBE(do_mov_2168)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x407")
int BPF_KPROBE(do_mov_2169)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x54f")
int BPF_KPROBE(do_mov_2170)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x57b")
int BPF_KPROBE(do_mov_2171)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xbb")
int BPF_KPROBE(do_mov_2172)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xc4")
int BPF_KPROBE(do_mov_2173)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xc8")
int BPF_KPROBE(do_mov_2174)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xcc")
int BPF_KPROBE(do_mov_2175)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xd1")
int BPF_KPROBE(do_mov_2176)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0x6d")
int BPF_KPROBE(do_mov_2177)
{
    u64 addr = ctx->r12 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0xd6")
int BPF_KPROBE(do_mov_2178)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0xdf")
int BPF_KPROBE(do_mov_2179)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0xe8")
int BPF_KPROBE(do_mov_2180)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0xf1")
int BPF_KPROBE(do_mov_2181)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0xfa")
int BPF_KPROBE(do_mov_2182)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0x195")
int BPF_KPROBE(do_mov_2183)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0x1ca")
int BPF_KPROBE(do_mov_2184)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getchain+0x177")
int BPF_KPROBE(do_mov_2185)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getchain+0x17f")
int BPF_KPROBE(do_mov_2186)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getchain+0x198")
int BPF_KPROBE(do_mov_2187)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getchain+0x1a0")
int BPF_KPROBE(do_mov_2188)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x1ea")
int BPF_KPROBE(do_mov_2189)
{
    u64 addr = ctx->r13 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x1fa")
int BPF_KPROBE(do_mov_2190)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x222")
int BPF_KPROBE(do_mov_2191)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x22a")
int BPF_KPROBE(do_mov_2192)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x22e")
int BPF_KPROBE(do_mov_2193)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x233")
int BPF_KPROBE(do_mov_2194)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x287")
int BPF_KPROBE(do_mov_2195)
{
    u64 addr = ctx->r13 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x2f5")
int BPF_KPROBE(do_mov_2196)
{
    u64 addr = ctx->r15 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x32f")
int BPF_KPROBE(do_mov_2197)
{
    u64 addr = ctx->r15 + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x353")
int BPF_KPROBE(do_mov_2198)
{
    u64 addr = ctx->r15 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x391")
int BPF_KPROBE(do_mov_2199)
{
    u64 addr = ctx->r15 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x39c")
int BPF_KPROBE(do_mov_2200)
{
    u64 addr = ctx->r15 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x3ad")
int BPF_KPROBE(do_mov_2201)
{
    u64 addr = ctx->r15 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x3b7")
int BPF_KPROBE(do_mov_2202)
{
    u64 addr = ctx->r15 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x3c5")
int BPF_KPROBE(do_mov_2203)
{
    u64 addr = ctx->r15 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x3cc")
int BPF_KPROBE(do_mov_2204)
{
    u64 addr = ctx->r15 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x3da")
int BPF_KPROBE(do_mov_2205)
{
    u64 addr = ctx->r15 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x3e1")
int BPF_KPROBE(do_mov_2206)
{
    u64 addr = ctx->r15 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x404")
int BPF_KPROBE(do_mov_2207)
{
    u64 addr = ctx->r15 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x418")
int BPF_KPROBE(do_mov_2208)
{
    u64 addr = ctx->di + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x424")
int BPF_KPROBE(do_mov_2209)
{
    u64 addr = ctx->r15 + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x431")
int BPF_KPROBE(do_mov_2210)
{
    u64 addr = ctx->r15 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x4c8")
int BPF_KPROBE(do_mov_2211)
{
    u64 addr = ctx->si + 0xed;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x4f3")
int BPF_KPROBE(do_mov_2212)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x4fc")
int BPF_KPROBE(do_mov_2213)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x4ff")
int BPF_KPROBE(do_mov_2214)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x503")
int BPF_KPROBE(do_mov_2215)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x50a")
int BPF_KPROBE(do_mov_2216)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x50d")
int BPF_KPROBE(do_mov_2217)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x511")
int BPF_KPROBE(do_mov_2218)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x518")
int BPF_KPROBE(do_mov_2219)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x5de")
int BPF_KPROBE(do_mov_2220)
{
    u64 addr = ctx->r13 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x655")
int BPF_KPROBE(do_mov_2221)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x659")
int BPF_KPROBE(do_mov_2222)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x683")
int BPF_KPROBE(do_mov_2223)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x687")
int BPF_KPROBE(do_mov_2224)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x694")
int BPF_KPROBE(do_mov_2225)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x69c")
int BPF_KPROBE(do_mov_2226)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x19d")
int BPF_KPROBE(do_mov_2227)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1b3")
int BPF_KPROBE(do_mov_2228)
{
    u64 addr = ctx->cx + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1ba")
int BPF_KPROBE(do_mov_2229)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1c2")
int BPF_KPROBE(do_mov_2230)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1c6")
int BPF_KPROBE(do_mov_2231)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1d3")
int BPF_KPROBE(do_mov_2232)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x36e")
int BPF_KPROBE(do_mov_2233)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x372")
int BPF_KPROBE(do_mov_2234)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x37f")
int BPF_KPROBE(do_mov_2235)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x382")
int BPF_KPROBE(do_mov_2236)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x418")
int BPF_KPROBE(do_mov_2237)
{
    u64 addr = ctx->ax + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x420")
int BPF_KPROBE(do_mov_2238)
{
    u64 addr = ctx->ax - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x424")
int BPF_KPROBE(do_mov_2239)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x428")
int BPF_KPROBE(do_mov_2240)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x42d")
int BPF_KPROBE(do_mov_2241)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x443")
int BPF_KPROBE(do_mov_2242)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x447")
int BPF_KPROBE(do_mov_2243)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x44c")
int BPF_KPROBE(do_mov_2244)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x44f")
int BPF_KPROBE(do_mov_2245)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x477")
int BPF_KPROBE(do_mov_2246)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x47f")
int BPF_KPROBE(do_mov_2247)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x483")
int BPF_KPROBE(do_mov_2248)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x488")
int BPF_KPROBE(do_mov_2249)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x4b5")
int BPF_KPROBE(do_mov_2250)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x4b9")
int BPF_KPROBE(do_mov_2251)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x4c6")
int BPF_KPROBE(do_mov_2252)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x544")
int BPF_KPROBE(do_mov_2253)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x54c")
int BPF_KPROBE(do_mov_2254)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x590")
int BPF_KPROBE(do_mov_2255)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x598")
int BPF_KPROBE(do_mov_2256)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x5c0")
int BPF_KPROBE(do_mov_2257)
{
    u64 addr = ctx->r15 + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x5d7")
int BPF_KPROBE(do_mov_2258)
{
    u64 addr = ctx->r15 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x5e5")
int BPF_KPROBE(do_mov_2259)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x66a")
int BPF_KPROBE(do_mov_2260)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x66e")
int BPF_KPROBE(do_mov_2261)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x672")
int BPF_KPROBE(do_mov_2262)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x675")
int BPF_KPROBE(do_mov_2263)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x691")
int BPF_KPROBE(do_mov_2264)
{
    u64 addr = ctx->r15 + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x69b")
int BPF_KPROBE(do_mov_2265)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x70b")
int BPF_KPROBE(do_mov_2266)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x714")
int BPF_KPROBE(do_mov_2267)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x719")
int BPF_KPROBE(do_mov_2268)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x71e")
int BPF_KPROBE(do_mov_2269)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x743")
int BPF_KPROBE(do_mov_2270)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x74b")
int BPF_KPROBE(do_mov_2271)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x74f")
int BPF_KPROBE(do_mov_2272)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x754")
int BPF_KPROBE(do_mov_2273)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x75e")
int BPF_KPROBE(do_mov_2274)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x761")
int BPF_KPROBE(do_mov_2275)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x768")
int BPF_KPROBE(do_mov_2276)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x76b")
int BPF_KPROBE(do_mov_2277)
{
    u64 addr = ctx->cx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x79d")
int BPF_KPROBE(do_mov_2278)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x7a1")
int BPF_KPROBE(do_mov_2279)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x7a4")
int BPF_KPROBE(do_mov_2280)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x8a1")
int BPF_KPROBE(do_mov_2281)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x8a5")
int BPF_KPROBE(do_mov_2282)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x8a8")
int BPF_KPROBE(do_mov_2283)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_destroy+0x99")
int BPF_KPROBE(do_mov_2284)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_destroy+0x9d")
int BPF_KPROBE(do_mov_2285)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_destroy+0xa0")
int BPF_KPROBE(do_mov_2286)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x135")
int BPF_KPROBE(do_mov_2287)
{
    u64 addr = ctx->dx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x14a")
int BPF_KPROBE(do_mov_2288)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x154")
int BPF_KPROBE(do_mov_2289)
{
    u64 addr = ctx->dx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x158")
int BPF_KPROBE(do_mov_2290)
{
    u64 addr = ctx->dx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x198")
int BPF_KPROBE(do_mov_2291)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x19c")
int BPF_KPROBE(do_mov_2292)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1a0")
int BPF_KPROBE(do_mov_2293)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1a9")
int BPF_KPROBE(do_mov_2294)
{
    u64 addr = ctx->dx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1df")
int BPF_KPROBE(do_mov_2295)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1e3")
int BPF_KPROBE(do_mov_2296)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1e6")
int BPF_KPROBE(do_mov_2297)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1ea")
int BPF_KPROBE(do_mov_2298)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1f2")
int BPF_KPROBE(do_mov_2299)
{
    u64 addr = ctx->ax + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1f6")
int BPF_KPROBE(do_mov_2300)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x209")
int BPF_KPROBE(do_mov_2301)
{
    u64 addr = ctx->dx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x20c")
int BPF_KPROBE(do_mov_2302)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x217")
int BPF_KPROBE(do_mov_2303)
{
    u64 addr = ctx->dx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x232")
int BPF_KPROBE(do_mov_2304)
{
    u64 addr = ctx->dx + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x245")
int BPF_KPROBE(do_mov_2305)
{
    u64 addr = ctx->dx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x24c")
int BPF_KPROBE(do_mov_2306)
{
    u64 addr = ctx->dx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x284")
int BPF_KPROBE(do_mov_2307)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x289")
int BPF_KPROBE(do_mov_2308)
{
    u64 addr = ctx->dx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x28d")
int BPF_KPROBE(do_mov_2309)
{
    u64 addr = ctx->dx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x29c")
int BPF_KPROBE(do_mov_2310)
{
    u64 addr = ctx->r13 + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x2a3")
int BPF_KPROBE(do_mov_2311)
{
    u64 addr = ctx->dx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x2aa")
int BPF_KPROBE(do_mov_2312)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x302")
int BPF_KPROBE(do_mov_2313)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x30f")
int BPF_KPROBE(do_mov_2314)
{
    u64 addr = ctx->r8 + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x317")
int BPF_KPROBE(do_mov_2315)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x31b")
int BPF_KPROBE(do_mov_2316)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x32a")
int BPF_KPROBE(do_mov_2317)
{
    u64 addr = ctx->r13 + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x331")
int BPF_KPROBE(do_mov_2318)
{
    u64 addr = ctx->r8 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x335")
int BPF_KPROBE(do_mov_2319)
{
    u64 addr = ctx->r8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x35e")
int BPF_KPROBE(do_mov_2320)
{
    u64 addr = ctx->r8 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x399")
int BPF_KPROBE(do_mov_2321)
{
    u64 addr = ctx->r8 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x3b0")
int BPF_KPROBE(do_mov_2322)
{
    u64 addr = ctx->r8 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x3e0")
int BPF_KPROBE(do_mov_2323)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x3e7")
int BPF_KPROBE(do_mov_2324)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x3ee")
int BPF_KPROBE(do_mov_2325)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x49a")
int BPF_KPROBE(do_mov_2326)
{
    u64 addr = ctx->r8 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x4fd")
int BPF_KPROBE(do_mov_2327)
{
    u64 addr = ctx->si + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x513")
int BPF_KPROBE(do_mov_2328)
{
    u64 addr = ctx->r14 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x548")
int BPF_KPROBE(do_mov_2329)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x557")
int BPF_KPROBE(do_mov_2330)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x55a")
int BPF_KPROBE(do_mov_2331)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x55e")
int BPF_KPROBE(do_mov_2332)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x567")
int BPF_KPROBE(do_mov_2333)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x58d")
int BPF_KPROBE(do_mov_2334)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5b3")
int BPF_KPROBE(do_mov_2335)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5b7")
int BPF_KPROBE(do_mov_2336)
{
    u64 addr = ctx->dx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5ba")
int BPF_KPROBE(do_mov_2337)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5bd")
int BPF_KPROBE(do_mov_2338)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5c6")
int BPF_KPROBE(do_mov_2339)
{
    u64 addr = ctx->dx + 0x19;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5ca")
int BPF_KPROBE(do_mov_2340)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x640")
int BPF_KPROBE(do_mov_2341)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x64b")
int BPF_KPROBE(do_mov_2342)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x64e")
int BPF_KPROBE(do_mov_2343)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x652")
int BPF_KPROBE(do_mov_2344)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x656")
int BPF_KPROBE(do_mov_2345)
{
    u64 addr = ctx->dx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x68b")
int BPF_KPROBE(do_mov_2346)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x68f")
int BPF_KPROBE(do_mov_2347)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x692")
int BPF_KPROBE(do_mov_2348)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x695")
int BPF_KPROBE(do_mov_2349)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x756")
int BPF_KPROBE(do_mov_2350)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x75a")
int BPF_KPROBE(do_mov_2351)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x75d")
int BPF_KPROBE(do_mov_2352)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x760")
int BPF_KPROBE(do_mov_2353)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x7d2")
int BPF_KPROBE(do_mov_2354)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x7d6")
int BPF_KPROBE(do_mov_2355)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x7d9")
int BPF_KPROBE(do_mov_2356)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x7e0")
int BPF_KPROBE(do_mov_2357)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3a7")
int BPF_KPROBE(do_mov_2358)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3af")
int BPF_KPROBE(do_mov_2359)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3e2")
int BPF_KPROBE(do_mov_2360)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3e6")
int BPF_KPROBE(do_mov_2361)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3f3")
int BPF_KPROBE(do_mov_2362)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3fa")
int BPF_KPROBE(do_mov_2363)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x458")
int BPF_KPROBE(do_mov_2364)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x460")
int BPF_KPROBE(do_mov_2365)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x4c4")
int BPF_KPROBE(do_mov_2366)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x4c8")
int BPF_KPROBE(do_mov_2367)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x4e0")
int BPF_KPROBE(do_mov_2368)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x5c8")
int BPF_KPROBE(do_mov_2369)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x5d0")
int BPF_KPROBE(do_mov_2370)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x5ef")
int BPF_KPROBE(do_mov_2371)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x61c")
int BPF_KPROBE(do_mov_2372)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x624")
int BPF_KPROBE(do_mov_2373)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x627")
int BPF_KPROBE(do_mov_2374)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x62b")
int BPF_KPROBE(do_mov_2375)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x66b")
int BPF_KPROBE(do_mov_2376)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x673")
int BPF_KPROBE(do_mov_2377)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x68f")
int BPF_KPROBE(do_mov_2378)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x697")
int BPF_KPROBE(do_mov_2379)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x727")
int BPF_KPROBE(do_mov_2380)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x72b")
int BPF_KPROBE(do_mov_2381)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x77a")
int BPF_KPROBE(do_mov_2382)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x77e")
int BPF_KPROBE(do_mov_2383)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x7b0")
int BPF_KPROBE(do_mov_2384)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x7b4")
int BPF_KPROBE(do_mov_2385)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x7e2")
int BPF_KPROBE(do_mov_2386)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x7e6")
int BPF_KPROBE(do_mov_2387)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x828")
int BPF_KPROBE(do_mov_2388)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x82c")
int BPF_KPROBE(do_mov_2389)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x82f")
int BPF_KPROBE(do_mov_2390)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x832")
int BPF_KPROBE(do_mov_2391)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x89f")
int BPF_KPROBE(do_mov_2392)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x8a3")
int BPF_KPROBE(do_mov_2393)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x8a6")
int BPF_KPROBE(do_mov_2394)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x8a9")
int BPF_KPROBE(do_mov_2395)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_dump+0x53")
int BPF_KPROBE(do_mov_2396)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0xcb")
int BPF_KPROBE(do_mov_2397)
{
    u64 addr = ctx->bx + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0xcf")
int BPF_KPROBE(do_mov_2398)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0xd6")
int BPF_KPROBE(do_mov_2399)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0x2a6")
int BPF_KPROBE(do_mov_2400)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0x2c6")
int BPF_KPROBE(do_mov_2401)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xe5")
int BPF_KPROBE(do_mov_2402)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xee")
int BPF_KPROBE(do_mov_2403)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xf2")
int BPF_KPROBE(do_mov_2404)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xf6")
int BPF_KPROBE(do_mov_2405)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xfb")
int BPF_KPROBE(do_mov_2406)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x1e8")
int BPF_KPROBE(do_mov_2407)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x1f0")
int BPF_KPROBE(do_mov_2408)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x209")
int BPF_KPROBE(do_mov_2409)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x211")
int BPF_KPROBE(do_mov_2410)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x22a")
int BPF_KPROBE(do_mov_2411)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x232")
int BPF_KPROBE(do_mov_2412)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x4e")
int BPF_KPROBE(do_mov_2413)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x57")
int BPF_KPROBE(do_mov_2414)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x60")
int BPF_KPROBE(do_mov_2415)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x69")
int BPF_KPROBE(do_mov_2416)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x72")
int BPF_KPROBE(do_mov_2417)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x105")
int BPF_KPROBE(do_mov_2418)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x114")
int BPF_KPROBE(do_mov_2419)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x146")
int BPF_KPROBE(do_mov_2420)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_rules+0x7f")
int BPF_KPROBE(do_mov_2421)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_rules+0xb6")
int BPF_KPROBE(do_mov_2422)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0xd5")
int BPF_KPROBE(do_mov_2423)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0xd9")
int BPF_KPROBE(do_mov_2424)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0xe1")
int BPF_KPROBE(do_mov_2425)
{
    u64 addr = ctx->r14 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x29e")
int BPF_KPROBE(do_mov_2426)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x2cf")
int BPF_KPROBE(do_mov_2427)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x370")
int BPF_KPROBE(do_mov_2428)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x4a5")
int BPF_KPROBE(do_mov_2429)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x61e")
int BPF_KPROBE(do_mov_2430)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getset+0x208")
int BPF_KPROBE(do_mov_2431)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getset+0x210")
int BPF_KPROBE(do_mov_2432)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0xa9")
int BPF_KPROBE(do_mov_2433)
{
    u64 addr = ctx->r9 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0x1f4")
int BPF_KPROBE(do_mov_2434)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0x226")
int BPF_KPROBE(do_mov_2435)
{
    u64 addr = ctx->r9 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0x240")
int BPF_KPROBE(do_mov_2436)
{
    u64 addr = ctx->r9 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0x244")
int BPF_KPROBE(do_mov_2437)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xb3")
int BPF_KPROBE(do_mov_2438)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xbb")
int BPF_KPROBE(do_mov_2439)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xc0")
int BPF_KPROBE(do_mov_2440)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xc3")
int BPF_KPROBE(do_mov_2441)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xc7")
int BPF_KPROBE(do_mov_2442)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x1a")
int BPF_KPROBE(do_mov_2443)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x1e")
int BPF_KPROBE(do_mov_2444)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x2b")
int BPF_KPROBE(do_mov_2445)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x4d")
int BPF_KPROBE(do_mov_2446)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x51")
int BPF_KPROBE(do_mov_2447)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x54")
int BPF_KPROBE(do_mov_2448)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_clone+0x17")
int BPF_KPROBE(do_mov_2449)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x3ce")
int BPF_KPROBE(do_mov_2450)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x45c")
int BPF_KPROBE(do_mov_2451)
{
    u64 addr = ctx->r12 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x465")
int BPF_KPROBE(do_mov_2452)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x485")
int BPF_KPROBE(do_mov_2453)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x4b2")
int BPF_KPROBE(do_mov_2454)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x4c2")
int BPF_KPROBE(do_mov_2455)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x4ca")
int BPF_KPROBE(do_mov_2456)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x591")
int BPF_KPROBE(do_mov_2457)
{
    u64 addr = ctx->ax + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x640")
int BPF_KPROBE(do_mov_2458)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x648")
int BPF_KPROBE(do_mov_2459)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x66b")
int BPF_KPROBE(do_mov_2460)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x673")
int BPF_KPROBE(do_mov_2461)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x6e9")
int BPF_KPROBE(do_mov_2462)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x6ec")
int BPF_KPROBE(do_mov_2463)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x6f0")
int BPF_KPROBE(do_mov_2464)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x6f3")
int BPF_KPROBE(do_mov_2465)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x710")
int BPF_KPROBE(do_mov_2466)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7d2")
int BPF_KPROBE(do_mov_2467)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7d6")
int BPF_KPROBE(do_mov_2468)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7d9")
int BPF_KPROBE(do_mov_2469)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7dd")
int BPF_KPROBE(do_mov_2470)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x838")
int BPF_KPROBE(do_mov_2471)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x862")
int BPF_KPROBE(do_mov_2472)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x86a")
int BPF_KPROBE(do_mov_2473)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8a3")
int BPF_KPROBE(do_mov_2474)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8a6")
int BPF_KPROBE(do_mov_2475)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8aa")
int BPF_KPROBE(do_mov_2476)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8ad")
int BPF_KPROBE(do_mov_2477)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8c6")
int BPF_KPROBE(do_mov_2478)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8ce")
int BPF_KPROBE(do_mov_2479)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8eb")
int BPF_KPROBE(do_mov_2480)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8f3")
int BPF_KPROBE(do_mov_2481)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x915")
int BPF_KPROBE(do_mov_2482)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x918")
int BPF_KPROBE(do_mov_2483)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x91c")
int BPF_KPROBE(do_mov_2484)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x91f")
int BPF_KPROBE(do_mov_2485)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x93b")
int BPF_KPROBE(do_mov_2486)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x93f")
int BPF_KPROBE(do_mov_2487)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x942")
int BPF_KPROBE(do_mov_2488)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x946")
int BPF_KPROBE(do_mov_2489)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x96a")
int BPF_KPROBE(do_mov_2490)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x972")
int BPF_KPROBE(do_mov_2491)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x998")
int BPF_KPROBE(do_mov_2492)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x9a0")
int BPF_KPROBE(do_mov_2493)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x9c7")
int BPF_KPROBE(do_mov_2494)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x9cb")
int BPF_KPROBE(do_mov_2495)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_msecs_to_jiffies64+0x53")
int BPF_KPROBE(do_mov_2496)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x62a")
int BPF_KPROBE(do_mov_2497)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x632")
int BPF_KPROBE(do_mov_2498)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x84f")
int BPF_KPROBE(do_mov_2499)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x857")
int BPF_KPROBE(do_mov_2500)
{
    u64 addr = ctx->r13 + 0xff8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x897")
int BPF_KPROBE(do_mov_2501)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x89f")
int BPF_KPROBE(do_mov_2502)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x943")
int BPF_KPROBE(do_mov_2503)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0x9fe")
int BPF_KPROBE(do_mov_2504)
{
    u64 addr = ctx->di + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa05")
int BPF_KPROBE(do_mov_2505)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa09")
int BPF_KPROBE(do_mov_2506)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa14")
int BPF_KPROBE(do_mov_2507)
{
    u64 addr = ctx->di + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa1b")
int BPF_KPROBE(do_mov_2508)
{
    u64 addr = ctx->di + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa29")
int BPF_KPROBE(do_mov_2509)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa34")
int BPF_KPROBE(do_mov_2510)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa3f")
int BPF_KPROBE(do_mov_2511)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa4c")
int BPF_KPROBE(do_mov_2512)
{
    u64 addr = ctx->di + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa52")
int BPF_KPROBE(do_mov_2513)
{
    u64 addr = ctx->di + 0xca;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa5e")
int BPF_KPROBE(do_mov_2514)
{
    u64 addr = ctx->di + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa67")
int BPF_KPROBE(do_mov_2515)
{
    u64 addr = ctx->di + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa6d")
int BPF_KPROBE(do_mov_2516)
{
    u64 addr = ctx->di + 0xcb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa87")
int BPF_KPROBE(do_mov_2517)
{
    u64 addr = ctx->di + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa91")
int BPF_KPROBE(do_mov_2518)
{
    u64 addr = ctx->di + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa9b")
int BPF_KPROBE(do_mov_2519)
{
    u64 addr = ctx->di + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xaa6")
int BPF_KPROBE(do_mov_2520)
{
    u64 addr = ctx->di + 0x7e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xab1")
int BPF_KPROBE(do_mov_2521)
{
    u64 addr = ctx->di + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xabb")
int BPF_KPROBE(do_mov_2522)
{
    u64 addr = ctx->di + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xac2")
int BPF_KPROBE(do_mov_2523)
{
    u64 addr = ctx->di + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xaf8")
int BPF_KPROBE(do_mov_2524)
{
    u64 addr = ctx->di + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xb6f")
int BPF_KPROBE(do_mov_2525)
{
    u64 addr = ctx->di + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xba5")
int BPF_KPROBE(do_mov_2526)
{
    u64 addr = ctx->di + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xbaf")
int BPF_KPROBE(do_mov_2527)
{
    u64 addr = ctx->r14 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xbda")
int BPF_KPROBE(do_mov_2528)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc01")
int BPF_KPROBE(do_mov_2529)
{
    u64 addr = ctx->r14 + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc16")
int BPF_KPROBE(do_mov_2530)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc3b")
int BPF_KPROBE(do_mov_2531)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc44")
int BPF_KPROBE(do_mov_2532)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc47")
int BPF_KPROBE(do_mov_2533)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc4b")
int BPF_KPROBE(do_mov_2534)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc55")
int BPF_KPROBE(do_mov_2535)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc58")
int BPF_KPROBE(do_mov_2536)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc5c")
int BPF_KPROBE(do_mov_2537)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc68")
int BPF_KPROBE(do_mov_2538)
{
    u64 addr = ctx->di + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xdac")
int BPF_KPROBE(do_mov_2539)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xdd8")
int BPF_KPROBE(do_mov_2540)
{
    u64 addr = ctx->di + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xde9")
int BPF_KPROBE(do_mov_2541)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xdfc")
int BPF_KPROBE(do_mov_2542)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xeb8")
int BPF_KPROBE(do_mov_2543)
{
    u64 addr = ctx->cx + ctx->r13 * 0x1 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xf66")
int BPF_KPROBE(do_mov_2544)
{
    u64 addr = ctx->di + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xf6d")
int BPF_KPROBE(do_mov_2545)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xfdd")
int BPF_KPROBE(do_mov_2546)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x65")
int BPF_KPROBE(do_mov_2547)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x6e")
int BPF_KPROBE(do_mov_2548)
{
    u64 addr = ctx->bx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x108")
int BPF_KPROBE(do_mov_2549)
{
    u64 addr = ctx->bx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x11e")
int BPF_KPROBE(do_mov_2550)
{
    u64 addr = ctx->bx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_expr_clone+0x31")
int BPF_KPROBE(do_mov_2551)
{
    u64 addr = ctx->r13 + ctx->bx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_hold+0x4e")
int BPF_KPROBE(do_mov_2552)
{
    u64 addr = ctx->si + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_gc_batch_alloc+0x4b")
int BPF_KPROBE(do_mov_2553)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_del+0xa5")
int BPF_KPROBE(do_mov_2554)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_del+0xa9")
int BPF_KPROBE(do_mov_2555)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_del+0xb6")
int BPF_KPROBE(do_mov_2556)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_verdict_uninit+0x46")
int BPF_KPROBE(do_mov_2557)
{
    u64 addr = ctx->di + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x6cd")
int BPF_KPROBE(do_mov_2558)
{
    u64 addr = ctx->r12 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x7a7")
int BPF_KPROBE(do_mov_2559)
{
    u64 addr = ctx->si + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x7d8")
int BPF_KPROBE(do_mov_2560)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x802")
int BPF_KPROBE(do_mov_2561)
{
    u64 addr = ctx->cx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x95d")
int BPF_KPROBE(do_mov_2562)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xdd3")
int BPF_KPROBE(do_mov_2563)
{
    u64 addr = ctx->r9 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xdf8")
int BPF_KPROBE(do_mov_2564)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf26")
int BPF_KPROBE(do_mov_2565)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf57")
int BPF_KPROBE(do_mov_2566)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf5b")
int BPF_KPROBE(do_mov_2567)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf5e")
int BPF_KPROBE(do_mov_2568)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf62")
int BPF_KPROBE(do_mov_2569)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x107f")
int BPF_KPROBE(do_mov_2570)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x1082")
int BPF_KPROBE(do_mov_2571)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x108e")
int BPF_KPROBE(do_mov_2572)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x1092")
int BPF_KPROBE(do_mov_2573)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x1095")
int BPF_KPROBE(do_mov_2574)
{
    u64 addr = ctx->r12 + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x1eb")
int BPF_KPROBE(do_mov_2575)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x1f3")
int BPF_KPROBE(do_mov_2576)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x22d")
int BPF_KPROBE(do_mov_2577)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x231")
int BPF_KPROBE(do_mov_2578)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0x67")
int BPF_KPROBE(do_mov_2579)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0x7f")
int BPF_KPROBE(do_mov_2580)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0x9e")
int BPF_KPROBE(do_mov_2581)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0xa6")
int BPF_KPROBE(do_mov_2582)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0xaa")
int BPF_KPROBE(do_mov_2583)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0xaf")
int BPF_KPROBE(do_mov_2584)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0x9d")
int BPF_KPROBE(do_mov_2585)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xa7")
int BPF_KPROBE(do_mov_2586)
{
    u64 addr = ctx->bx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xd2")
int BPF_KPROBE(do_mov_2587)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xda")
int BPF_KPROBE(do_mov_2588)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xdd")
int BPF_KPROBE(do_mov_2589)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xe1")
int BPF_KPROBE(do_mov_2590)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x25d")
int BPF_KPROBE(do_mov_2591)
{
    u64 addr = ctx->ax + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x277")
int BPF_KPROBE(do_mov_2592)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x449")
int BPF_KPROBE(do_mov_2593)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x49a")
int BPF_KPROBE(do_mov_2594)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4c0")
int BPF_KPROBE(do_mov_2595)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4c8")
int BPF_KPROBE(do_mov_2596)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4cb")
int BPF_KPROBE(do_mov_2597)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4cf")
int BPF_KPROBE(do_mov_2598)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delsetelem+0x22f")
int BPF_KPROBE(do_mov_2599)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delsetelem+0x237")
int BPF_KPROBE(do_mov_2600)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delsetelem+0x2b0")
int BPF_KPROBE(do_mov_2601)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delsetelem+0x2b4")
int BPF_KPROBE(do_mov_2602)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_destroy+0xb2")
int BPF_KPROBE(do_mov_2603)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_destroy+0xb6")
int BPF_KPROBE(do_mov_2604)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_destroy+0xbd")
int BPF_KPROBE(do_mov_2605)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x5e")
int BPF_KPROBE(do_mov_2606)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x66")
int BPF_KPROBE(do_mov_2607)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x69")
int BPF_KPROBE(do_mov_2608)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0xc9")
int BPF_KPROBE(do_mov_2609)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0xcd")
int BPF_KPROBE(do_mov_2610)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0xd5")
int BPF_KPROBE(do_mov_2611)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0xd8")
int BPF_KPROBE(do_mov_2612)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x13d")
int BPF_KPROBE(do_mov_2613)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x141")
int BPF_KPROBE(do_mov_2614)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x144")
int BPF_KPROBE(do_mov_2615)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0x58")
int BPF_KPROBE(do_mov_2616)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0x5d")
int BPF_KPROBE(do_mov_2617)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0x6a")
int BPF_KPROBE(do_mov_2618)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0x71")
int BPF_KPROBE(do_mov_2619)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0xc7")
int BPF_KPROBE(do_mov_2620)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0xcb")
int BPF_KPROBE(do_mov_2621)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0xd8")
int BPF_KPROBE(do_mov_2622)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0xdc")
int BPF_KPROBE(do_mov_2623)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x122")
int BPF_KPROBE(do_mov_2624)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x126")
int BPF_KPROBE(do_mov_2625)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x12a")
int BPF_KPROBE(do_mov_2626)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x12d")
int BPF_KPROBE(do_mov_2627)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x18a")
int BPF_KPROBE(do_mov_2628)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x18e")
int BPF_KPROBE(do_mov_2629)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x197")
int BPF_KPROBE(do_mov_2630)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x19a")
int BPF_KPROBE(do_mov_2631)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x2e2")
int BPF_KPROBE(do_mov_2632)
{
    u64 addr = ctx->si + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x30e")
int BPF_KPROBE(do_mov_2633)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x312")
int BPF_KPROBE(do_mov_2634)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x315")
int BPF_KPROBE(do_mov_2635)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x359")
int BPF_KPROBE(do_mov_2636)
{
    u64 addr = ctx->si + 0x15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x409")
int BPF_KPROBE(do_mov_2637)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x40d")
int BPF_KPROBE(do_mov_2638)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x415")
int BPF_KPROBE(do_mov_2639)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x479")
int BPF_KPROBE(do_mov_2640)
{
    u64 addr = ctx->si + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x4ff")
int BPF_KPROBE(do_mov_2641)
{
    u64 addr = ctx->si + 0xed;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x54f")
int BPF_KPROBE(do_mov_2642)
{
    u64 addr = ctx->r15 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x57d")
int BPF_KPROBE(do_mov_2643)
{
    u64 addr = ctx->r15 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x5db")
int BPF_KPROBE(do_mov_2644)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x5df")
int BPF_KPROBE(do_mov_2645)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x5e2")
int BPF_KPROBE(do_mov_2646)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6cc")
int BPF_KPROBE(do_mov_2647)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6d0")
int BPF_KPROBE(do_mov_2648)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6d5")
int BPF_KPROBE(do_mov_2649)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6f2")
int BPF_KPROBE(do_mov_2650)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6f6")
int BPF_KPROBE(do_mov_2651)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6f9")
int BPF_KPROBE(do_mov_2652)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x794")
int BPF_KPROBE(do_mov_2653)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x798")
int BPF_KPROBE(do_mov_2654)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x79b")
int BPF_KPROBE(do_mov_2655)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x7a3")
int BPF_KPROBE(do_mov_2656)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x7d4")
int BPF_KPROBE(do_mov_2657)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x808")
int BPF_KPROBE(do_mov_2658)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x80c")
int BPF_KPROBE(do_mov_2659)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x810")
int BPF_KPROBE(do_mov_2660)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x813")
int BPF_KPROBE(do_mov_2661)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x87a")
int BPF_KPROBE(do_mov_2662)
{
    u64 addr = ctx->r15 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0xb0")
int BPF_KPROBE(do_mov_2663)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0xb5")
int BPF_KPROBE(do_mov_2664)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0xc2")
int BPF_KPROBE(do_mov_2665)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0xc9")
int BPF_KPROBE(do_mov_2666)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x1a1")
int BPF_KPROBE(do_mov_2667)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x1a5")
int BPF_KPROBE(do_mov_2668)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x1ac")
int BPF_KPROBE(do_mov_2669)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x1af")
int BPF_KPROBE(do_mov_2670)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x200")
int BPF_KPROBE(do_mov_2671)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x204")
int BPF_KPROBE(do_mov_2672)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x20b")
int BPF_KPROBE(do_mov_2673)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x20e")
int BPF_KPROBE(do_mov_2674)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xbb")
int BPF_KPROBE(do_mov_2675)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xbf")
int BPF_KPROBE(do_mov_2676)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xc2")
int BPF_KPROBE(do_mov_2677)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xc5")
int BPF_KPROBE(do_mov_2678)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rcv_nl_event+0xe8")
int BPF_KPROBE(do_mov_2679)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rcv_nl_event+0xec")
int BPF_KPROBE(do_mov_2680)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rcv_nl_event+0xf9")
int BPF_KPROBE(do_mov_2681)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_verdict_dump+0x93")
int BPF_KPROBE(do_mov_2682)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_dump+0x6c")
int BPF_KPROBE(do_mov_2683)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x243")
int BPF_KPROBE(do_mov_2684)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x351")
int BPF_KPROBE(do_mov_2685)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x63")
int BPF_KPROBE(do_mov_2686)
{
    u64 addr = ctx->r12 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x17a")
int BPF_KPROBE(do_mov_2687)
{
    u64 addr = ctx->r13 + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x17f")
int BPF_KPROBE(do_mov_2688)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x187")
int BPF_KPROBE(do_mov_2689)
{
    u64 addr = ctx->r13 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x296")
int BPF_KPROBE(do_mov_2690)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x2a9")
int BPF_KPROBE(do_mov_2691)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x2c5")
int BPF_KPROBE(do_mov_2692)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0xb0")
int BPF_KPROBE(do_mov_2693)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0xb4")
int BPF_KPROBE(do_mov_2694)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0xb8")
int BPF_KPROBE(do_mov_2695)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0x171")
int BPF_KPROBE(do_mov_2696)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0x188")
int BPF_KPROBE(do_mov_2697)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xc5")
int BPF_KPROBE(do_mov_2698)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xce")
int BPF_KPROBE(do_mov_2699)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xd2")
int BPF_KPROBE(do_mov_2700)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xd6")
int BPF_KPROBE(do_mov_2701)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xdb")
int BPF_KPROBE(do_mov_2702)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x122")
int BPF_KPROBE(do_mov_2703)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x129")
int BPF_KPROBE(do_mov_2704)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x12d")
int BPF_KPROBE(do_mov_2705)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x131")
int BPF_KPROBE(do_mov_2706)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x1e5")
int BPF_KPROBE(do_mov_2707)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x1f0")
int BPF_KPROBE(do_mov_2708)
{
    u64 addr = ctx->r15 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x2c1")
int BPF_KPROBE(do_mov_2709)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x2c5")
int BPF_KPROBE(do_mov_2710)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x2c8")
int BPF_KPROBE(do_mov_2711)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x2cc")
int BPF_KPROBE(do_mov_2712)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x3d9")
int BPF_KPROBE(do_mov_2713)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x3dd")
int BPF_KPROBE(do_mov_2714)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x3e0")
int BPF_KPROBE(do_mov_2715)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x3e4")
int BPF_KPROBE(do_mov_2716)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x43c")
int BPF_KPROBE(do_mov_2717)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x440")
int BPF_KPROBE(do_mov_2718)
{
    u64 addr = ctx->r14 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x45c")
int BPF_KPROBE(do_mov_2719)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x493")
int BPF_KPROBE(do_mov_2720)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x496")
int BPF_KPROBE(do_mov_2721)
{
    u64 addr = ctx->r14 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x4b2")
int BPF_KPROBE(do_mov_2722)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x4e6")
int BPF_KPROBE(do_mov_2723)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x54c")
int BPF_KPROBE(do_mov_2724)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x575")
int BPF_KPROBE(do_mov_2725)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5b5")
int BPF_KPROBE(do_mov_2726)
{
    u64 addr = ctx->si + 0x15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5de")
int BPF_KPROBE(do_mov_2727)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5e2")
int BPF_KPROBE(do_mov_2728)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5ef")
int BPF_KPROBE(do_mov_2729)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5f6")
int BPF_KPROBE(do_mov_2730)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x613")
int BPF_KPROBE(do_mov_2731)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6cd")
int BPF_KPROBE(do_mov_2732)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6d1")
int BPF_KPROBE(do_mov_2733)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6de")
int BPF_KPROBE(do_mov_2734)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6e6")
int BPF_KPROBE(do_mov_2735)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x74c")
int BPF_KPROBE(do_mov_2736)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x750")
int BPF_KPROBE(do_mov_2737)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x75d")
int BPF_KPROBE(do_mov_2738)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x765")
int BPF_KPROBE(do_mov_2739)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x8d3")
int BPF_KPROBE(do_mov_2740)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x8fc")
int BPF_KPROBE(do_mov_2741)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x900")
int BPF_KPROBE(do_mov_2742)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x903")
int BPF_KPROBE(do_mov_2743)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x90a")
int BPF_KPROBE(do_mov_2744)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x915")
int BPF_KPROBE(do_mov_2745)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x9ab")
int BPF_KPROBE(do_mov_2746)
{
    u64 addr = ctx->dx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x9de")
int BPF_KPROBE(do_mov_2747)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x9e2")
int BPF_KPROBE(do_mov_2748)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x9e6")
int BPF_KPROBE(do_mov_2749)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x9e9")
int BPF_KPROBE(do_mov_2750)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb2f")
int BPF_KPROBE(do_mov_2751)
{
    u64 addr = ctx->r13 - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb6b")
int BPF_KPROBE(do_mov_2752)
{
    u64 addr = ctx->r13 + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb92")
int BPF_KPROBE(do_mov_2753)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb96")
int BPF_KPROBE(do_mov_2754)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb99")
int BPF_KPROBE(do_mov_2755)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xbdc")
int BPF_KPROBE(do_mov_2756)
{
    u64 addr = ctx->si + 0xc9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xc3a")
int BPF_KPROBE(do_mov_2757)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xc3e")
int BPF_KPROBE(do_mov_2758)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xc46")
int BPF_KPROBE(do_mov_2759)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xcf5")
int BPF_KPROBE(do_mov_2760)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xcf9")
int BPF_KPROBE(do_mov_2761)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xd01")
int BPF_KPROBE(do_mov_2762)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xd5a")
int BPF_KPROBE(do_mov_2763)
{
    u64 addr = ctx->r13 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xde4")
int BPF_KPROBE(do_mov_2764)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xe65")
int BPF_KPROBE(do_mov_2765)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xe69")
int BPF_KPROBE(do_mov_2766)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xe76")
int BPF_KPROBE(do_mov_2767)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xecb")
int BPF_KPROBE(do_mov_2768)
{
    u64 addr = ctx->r13 + 0xed;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf40")
int BPF_KPROBE(do_mov_2769)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf44")
int BPF_KPROBE(do_mov_2770)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf51")
int BPF_KPROBE(do_mov_2771)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf58")
int BPF_KPROBE(do_mov_2772)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x1063")
int BPF_KPROBE(do_mov_2773)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x1076")
int BPF_KPROBE(do_mov_2774)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10c4")
int BPF_KPROBE(do_mov_2775)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10c8")
int BPF_KPROBE(do_mov_2776)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10e3")
int BPF_KPROBE(do_mov_2777)
{
    u64 addr = ctx->ax - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x118a")
int BPF_KPROBE(do_mov_2778)
{
    u64 addr = ctx->r13 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x11e7")
int BPF_KPROBE(do_mov_2779)
{
    u64 addr = ctx->r8 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getsetelem+0x254")
int BPF_KPROBE(do_mov_2780)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getsetelem+0x25c")
int BPF_KPROBE(do_mov_2781)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getsetelem+0x349")
int BPF_KPROBE(do_mov_2782)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getsetelem+0x34d")
int BPF_KPROBE(do_mov_2783)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_netdev_event+0x1ac")
int BPF_KPROBE(do_mov_2784)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_netdev_event+0x1b0")
int BPF_KPROBE(do_mov_2785)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_netdev_event+0x1bd")
int BPF_KPROBE(do_mov_2786)
{
    u64 addr = ctx->r10 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_notify+0xfe")
int BPF_KPROBE(do_mov_2787)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_notify+0x10e")
int BPF_KPROBE(do_mov_2788)
{
    u64 addr = ctx->ax + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_notify+0x119")
int BPF_KPROBE(do_mov_2789)
{
    u64 addr = ctx->r14 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_notify+0x4f4")
int BPF_KPROBE(do_mov_2790)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_notify+0x51e")
int BPF_KPROBE(do_mov_2791)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x2b")
int BPF_KPROBE(do_mov_2792)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x2f")
int BPF_KPROBE(do_mov_2793)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x3c")
int BPF_KPROBE(do_mov_2794)
{
    u64 addr = ctx->di + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x40")
int BPF_KPROBE(do_mov_2795)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x47")
int BPF_KPROBE(do_mov_2796)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x4e")
int BPF_KPROBE(do_mov_2797)
{
    u64 addr = ctx->di + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x8d")
int BPF_KPROBE(do_mov_2798)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x2a")
int BPF_KPROBE(do_mov_2799)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x43")
int BPF_KPROBE(do_mov_2800)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x58")
int BPF_KPROBE(do_mov_2801)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x60")
int BPF_KPROBE(do_mov_2802)
{
    u64 addr = ctx->ax + ctx->cx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x70")
int BPF_KPROBE(do_mov_2803)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x78")
int BPF_KPROBE(do_mov_2804)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x7e")
int BPF_KPROBE(do_mov_2805)
{
    u64 addr = ctx->ax + ctx->cx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x89")
int BPF_KPROBE(do_mov_2806)
{
    u64 addr = ctx->ax + ctx->cx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_init+0x91")
int BPF_KPROBE(do_mov_2807)
{
    u64 addr = ctx->bx + 0x19;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x29")
int BPF_KPROBE(do_mov_2808)
{
    u64 addr = ctx->cx + ctx->dx * 0x8 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x2e")
int BPF_KPROBE(do_mov_2809)
{
    u64 addr = ctx->cx + ctx->dx * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x42")
int BPF_KPROBE(do_mov_2810)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x65")
int BPF_KPROBE(do_mov_2811)
{
    u64 addr = ctx->di + ctx->ax * 0x1 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x80")
int BPF_KPROBE(do_mov_2812)
{
    u64 addr = ctx->di + ctx->ax * 0x1 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_eval+0x40")
int BPF_KPROBE(do_mov_2813)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_fast_init+0x87")
int BPF_KPROBE(do_mov_2814)
{
    u64 addr = ctx->bx + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_fast_init+0x90")
int BPF_KPROBE(do_mov_2815)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_fast_init+0x97")
int BPF_KPROBE(do_mov_2816)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0xe1")
int BPF_KPROBE(do_mov_2817)
{
    u64 addr = ctx->bx + ctx->r15 * 0x4 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x122")
int BPF_KPROBE(do_mov_2818)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x129")
int BPF_KPROBE(do_mov_2819)
{
    u64 addr = ctx->cx + ctx->dx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x14e")
int BPF_KPROBE(do_mov_2820)
{
    u64 addr = ctx->si + ctx->cx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x15e")
int BPF_KPROBE(do_mov_2821)
{
    u64 addr = ctx->bx + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x190")
int BPF_KPROBE(do_mov_2822)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x19a")
int BPF_KPROBE(do_mov_2823)
{
    u64 addr = ctx->cx + ctx->dx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x1c1")
int BPF_KPROBE(do_mov_2824)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x1c9")
int BPF_KPROBE(do_mov_2825)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x1cf")
int BPF_KPROBE(do_mov_2826)
{
    u64 addr = ctx->cx + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_init+0x72")
int BPF_KPROBE(do_mov_2827)
{
    u64 addr = ctx->bx + 0x1a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_init+0x78")
int BPF_KPROBE(do_mov_2828)
{
    u64 addr = ctx->bx + 0x19;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_cmp_offload+0xdf")
int BPF_KPROBE(do_mov_2829)
{
    u64 addr = ctx->r14 + ctx->ax * 0x2 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_range_eval+0x5c")
int BPF_KPROBE(do_mov_2830)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_range_init+0x137")
int BPF_KPROBE(do_mov_2831)
{
    u64 addr = ctx->bx + 0x2a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_range_init+0x140")
int BPF_KPROBE(do_mov_2832)
{
    u64 addr = ctx->bx + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_fast_offload+0x33")
int BPF_KPROBE(do_mov_2833)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_fast_reduce+0x4b")
int BPF_KPROBE(do_mov_2834)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_fast_reduce+0x59")
int BPF_KPROBE(do_mov_2835)
{
    u64 addr = ctx->di + ctx->dx * 0x8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_fast_reduce+0xa3")
int BPF_KPROBE(do_mov_2836)
{
    u64 addr = ctx->di + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_offload+0x77")
int BPF_KPROBE(do_mov_2837)
{
    u64 addr = ctx->cx + ctx->dx * 0x8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_offload+0x7c")
int BPF_KPROBE(do_mov_2838)
{
    u64 addr = ctx->cx + ctx->dx * 0x8 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_reduce+0x84")
int BPF_KPROBE(do_mov_2839)
{
    u64 addr = ctx->r12 + ctx->dx * 0x8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_reduce+0x152")
int BPF_KPROBE(do_mov_2840)
{
    u64 addr = ctx->r12 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_init+0x4b")
int BPF_KPROBE(do_mov_2841)
{
    u64 addr = ctx->bx + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_init+0x92")
int BPF_KPROBE(do_mov_2842)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_init+0x11a")
int BPF_KPROBE(do_mov_2843)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_eval+0x4a")
int BPF_KPROBE(do_mov_2844)
{
    u64 addr = ctx->r8 + ctx->dx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_eval+0x9f")
int BPF_KPROBE(do_mov_2845)
{
    u64 addr = ctx->r8 + ctx->si * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_eval+0xfc")
int BPF_KPROBE(do_mov_2846)
{
    u64 addr = ctx->r8 + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_fast_init+0xcb")
int BPF_KPROBE(do_mov_2847)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_fast_init+0xe9")
int BPF_KPROBE(do_mov_2848)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x5e")
int BPF_KPROBE(do_mov_2849)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x9d")
int BPF_KPROBE(do_mov_2850)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0xdf")
int BPF_KPROBE(do_mov_2851)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x10f")
int BPF_KPROBE(do_mov_2852)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x13d")
int BPF_KPROBE(do_mov_2853)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x16d")
int BPF_KPROBE(do_mov_2854)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_init+0x65")
int BPF_KPROBE(do_mov_2855)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_init+0x91")
int BPF_KPROBE(do_mov_2856)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_init+0xdb")
int BPF_KPROBE(do_mov_2857)
{
    u64 addr = ctx->bx + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x5a")
int BPF_KPROBE(do_mov_2858)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x71")
int BPF_KPROBE(do_mov_2859)
{
    u64 addr = ctx->dx - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x79")
int BPF_KPROBE(do_mov_2860)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0xde")
int BPF_KPROBE(do_mov_2861)
{
    u64 addr = ctx->r8 + ctx->cx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0xf3")
int BPF_KPROBE(do_mov_2862)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0xfe")
int BPF_KPROBE(do_mov_2863)
{
    u64 addr = ctx->cx + ctx->dx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x12f")
int BPF_KPROBE(do_mov_2864)
{
    u64 addr = ctx->dx + ctx->di * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x154")
int BPF_KPROBE(do_mov_2865)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x15c")
int BPF_KPROBE(do_mov_2866)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x188")
int BPF_KPROBE(do_mov_2867)
{
    u64 addr = ctx->dx + ctx->si * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x199")
int BPF_KPROBE(do_mov_2868)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x1ac")
int BPF_KPROBE(do_mov_2869)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x1c4")
int BPF_KPROBE(do_mov_2870)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x1d9")
int BPF_KPROBE(do_mov_2871)
{
    u64 addr = ctx->ax + ctx->si * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x1e8")
int BPF_KPROBE(do_mov_2872)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x1f0")
int BPF_KPROBE(do_mov_2873)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x1fb")
int BPF_KPROBE(do_mov_2874)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x202")
int BPF_KPROBE(do_mov_2875)
{
    u64 addr = ctx->ax + ctx->si * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_init+0x1a")
int BPF_KPROBE(do_mov_2876)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_init+0x26")
int BPF_KPROBE(do_mov_2877)
{
    u64 addr = ctx->si + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_init+0x38")
int BPF_KPROBE(do_mov_2878)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x31")
int BPF_KPROBE(do_mov_2879)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x3d")
int BPF_KPROBE(do_mov_2880)
{
    u64 addr = ctx->si + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x49")
int BPF_KPROBE(do_mov_2881)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x7b")
int BPF_KPROBE(do_mov_2882)
{
    u64 addr = ctx->bx + 0xd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x96")
int BPF_KPROBE(do_mov_2883)
{
    u64 addr = ctx->bx + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0xb6")
int BPF_KPROBE(do_mov_2884)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0x5b")
int BPF_KPROBE(do_mov_2885)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0x69")
int BPF_KPROBE(do_mov_2886)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0x6d")
int BPF_KPROBE(do_mov_2887)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0xaf")
int BPF_KPROBE(do_mov_2888)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0xbd")
int BPF_KPROBE(do_mov_2889)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0xc1")
int BPF_KPROBE(do_mov_2890)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x15a")
int BPF_KPROBE(do_mov_2891)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x168")
int BPF_KPROBE(do_mov_2892)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x16c")
int BPF_KPROBE(do_mov_2893)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x1ad")
int BPF_KPROBE(do_mov_2894)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x1bb")
int BPF_KPROBE(do_mov_2895)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x1bf")
int BPF_KPROBE(do_mov_2896)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x208")
int BPF_KPROBE(do_mov_2897)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x216")
int BPF_KPROBE(do_mov_2898)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x21a")
int BPF_KPROBE(do_mov_2899)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x256")
int BPF_KPROBE(do_mov_2900)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x297")
int BPF_KPROBE(do_mov_2901)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x2a5")
int BPF_KPROBE(do_mov_2902)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x2a9")
int BPF_KPROBE(do_mov_2903)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x2e5")
int BPF_KPROBE(do_mov_2904)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x2e9")
int BPF_KPROBE(do_mov_2905)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x324")
int BPF_KPROBE(do_mov_2906)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x332")
int BPF_KPROBE(do_mov_2907)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x336")
int BPF_KPROBE(do_mov_2908)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x372")
int BPF_KPROBE(do_mov_2909)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x380")
int BPF_KPROBE(do_mov_2910)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x384")
int BPF_KPROBE(do_mov_2911)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x3c0")
int BPF_KPROBE(do_mov_2912)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x3ce")
int BPF_KPROBE(do_mov_2913)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x3da")
int BPF_KPROBE(do_mov_2914)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x41b")
int BPF_KPROBE(do_mov_2915)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x459")
int BPF_KPROBE(do_mov_2916)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x467")
int BPF_KPROBE(do_mov_2917)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x473")
int BPF_KPROBE(do_mov_2918)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x4b4")
int BPF_KPROBE(do_mov_2919)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_payload_inner_offset+0x74")
int BPF_KPROBE(do_mov_2920)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_payload_inner_offset+0x7e")
int BPF_KPROBE(do_mov_2921)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_payload_inner_offset+0xb1")
int BPF_KPROBE(do_mov_2922)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x44")
int BPF_KPROBE(do_mov_2923)
{
    u64 addr = ctx->r14 + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0xb9")
int BPF_KPROBE(do_mov_2924)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x1eb")
int BPF_KPROBE(do_mov_2925)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x1fe")
int BPF_KPROBE(do_mov_2926)
{
    u64 addr = ctx->r14 + ctx->r9 * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x305")
int BPF_KPROBE(do_mov_2927)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x336")
int BPF_KPROBE(do_mov_2928)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x33e")
int BPF_KPROBE(do_mov_2929)
{
    u64 addr = ctx->r14 + ctx->dx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x351")
int BPF_KPROBE(do_mov_2930)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x361")
int BPF_KPROBE(do_mov_2931)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x369")
int BPF_KPROBE(do_mov_2932)
{
    u64 addr = ctx->r14 + ctx->r9 * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x37b")
int BPF_KPROBE(do_mov_2933)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x385")
int BPF_KPROBE(do_mov_2934)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x38c")
int BPF_KPROBE(do_mov_2935)
{
    u64 addr = ctx->r14 + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x39d")
int BPF_KPROBE(do_mov_2936)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x3a5")
int BPF_KPROBE(do_mov_2937)
{
    u64 addr = ctx->r14 + ctx->r9 * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x3b4")
int BPF_KPROBE(do_mov_2938)
{
    u64 addr = ctx->r14 + ctx->dx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_eval+0x146")
int BPF_KPROBE(do_mov_2939)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_eval+0x160")
int BPF_KPROBE(do_mov_2940)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_eval+0x166")
int BPF_KPROBE(do_mov_2941)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_eval+0x178")
int BPF_KPROBE(do_mov_2942)
{
    u64 addr = ctx->r15 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_eval+0x28a")
int BPF_KPROBE(do_mov_2943)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_eval+0x4ac")
int BPF_KPROBE(do_mov_2944)
{
    u64 addr = ctx->r15 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x109")
int BPF_KPROBE(do_mov_2945)
{
    u64 addr = ctx->cx + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x128")
int BPF_KPROBE(do_mov_2946)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x137")
int BPF_KPROBE(do_mov_2947)
{
    u64 addr = ctx->dx + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x15c")
int BPF_KPROBE(do_mov_2948)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x173")
int BPF_KPROBE(do_mov_2949)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x17b")
int BPF_KPROBE(do_mov_2950)
{
    u64 addr = ctx->dx + ctx->ax * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x190")
int BPF_KPROBE(do_mov_2951)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x1a8")
int BPF_KPROBE(do_mov_2952)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x1ae")
int BPF_KPROBE(do_mov_2953)
{
    u64 addr = ctx->dx + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_init+0xac")
int BPF_KPROBE(do_mov_2954)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_init+0xd3")
int BPF_KPROBE(do_mov_2955)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_init+0xdf")
int BPF_KPROBE(do_mov_2956)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_eval+0xa3")
int BPF_KPROBE(do_mov_2957)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_eval+0x120")
int BPF_KPROBE(do_mov_2958)
{
    u64 addr = ctx->r15 + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_new+0xcb")
int BPF_KPROBE(do_mov_2959)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_dump+0x1d8")
int BPF_KPROBE(do_mov_2960)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x9c")
int BPF_KPROBE(do_mov_2961)
{
    u64 addr = ctx->r13 + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0xf7")
int BPF_KPROBE(do_mov_2962)
{
    u64 addr = ctx->r13 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x1f1")
int BPF_KPROBE(do_mov_2963)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x1f8")
int BPF_KPROBE(do_mov_2964)
{
    u64 addr = ctx->r13 + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x21d")
int BPF_KPROBE(do_mov_2965)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x225")
int BPF_KPROBE(do_mov_2966)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x22f")
int BPF_KPROBE(do_mov_2967)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x239")
int BPF_KPROBE(do_mov_2968)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x24c")
int BPF_KPROBE(do_mov_2969)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x25e")
int BPF_KPROBE(do_mov_2970)
{
    u64 addr = ctx->r13 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x262")
int BPF_KPROBE(do_mov_2971)
{
    u64 addr = ctx->r13 + 0x1b;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x26b")
int BPF_KPROBE(do_mov_2972)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x2bd")
int BPF_KPROBE(do_mov_2973)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x2cf")
int BPF_KPROBE(do_mov_2974)
{
    u64 addr = ctx->r13 + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x2d3")
int BPF_KPROBE(do_mov_2975)
{
    u64 addr = ctx->r13 + 0x1f;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x2e8")
int BPF_KPROBE(do_mov_2976)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x2fa")
int BPF_KPROBE(do_mov_2977)
{
    u64 addr = ctx->r13 + 0x17;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x2fe")
int BPF_KPROBE(do_mov_2978)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x304")
int BPF_KPROBE(do_mov_2979)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x309")
int BPF_KPROBE(do_mov_2980)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x32d")
int BPF_KPROBE(do_mov_2981)
{
    u64 addr = ctx->r12 + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x336")
int BPF_KPROBE(do_mov_2982)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x35e")
int BPF_KPROBE(do_mov_2983)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x42a")
int BPF_KPROBE(do_mov_2984)
{
    u64 addr = ctx->r13 + ctx->cx * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x437")
int BPF_KPROBE(do_mov_2985)
{
    u64 addr = ctx->r13 + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x500")
int BPF_KPROBE(do_mov_2986)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x517")
int BPF_KPROBE(do_mov_2987)
{
    u64 addr = ctx->r13 + 0x19;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x51f")
int BPF_KPROBE(do_mov_2988)
{
    u64 addr = ctx->r13 + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x528")
int BPF_KPROBE(do_mov_2989)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x550")
int BPF_KPROBE(do_mov_2990)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x565")
int BPF_KPROBE(do_mov_2991)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x569")
int BPF_KPROBE(do_mov_2992)
{
    u64 addr = ctx->r13 + 0x1d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x572")
int BPF_KPROBE(do_mov_2993)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x5fb")
int BPF_KPROBE(do_mov_2994)
{
    u64 addr = ctx->r13 + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_cgroup+0x4e")
int BPF_KPROBE(do_mov_2995)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_eval+0x2f")
int BPF_KPROBE(do_mov_2996)
{
    u64 addr = ctx->dx + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_eval+0x37")
int BPF_KPROBE(do_mov_2997)
{
    u64 addr = ctx->dx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_eval+0x54")
int BPF_KPROBE(do_mov_2998)
{
    u64 addr = ctx->dx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_eval+0x5c")
int BPF_KPROBE(do_mov_2999)
{
    u64 addr = ctx->dx + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_eval+0x93")
int BPF_KPROBE(do_mov_3000)
{
    u64 addr = ctx->dx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_secmark_obj_eval+0x12")
int BPF_KPROBE(do_mov_3001)
{
    u64 addr = ctx->ax + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_skugid+0xdb")
int BPF_KPROBE(do_mov_3002)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_skugid+0x108")
int BPF_KPROBE(do_mov_3003)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0x54")
int BPF_KPROBE(do_mov_3004)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0x98")
int BPF_KPROBE(do_mov_3005)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0xa3")
int BPF_KPROBE(do_mov_3006)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0xcb")
int BPF_KPROBE(do_mov_3007)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_init+0x14")
int BPF_KPROBE(do_mov_3008)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_init+0x51")
int BPF_KPROBE(do_mov_3009)
{
    u64 addr = ctx->ax + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_init+0x1a")
int BPF_KPROBE(do_mov_3010)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_init+0x39")
int BPF_KPROBE(do_mov_3011)
{
    u64 addr = ctx->bx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x4d")
int BPF_KPROBE(do_mov_3012)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x5b")
int BPF_KPROBE(do_mov_3013)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x5f")
int BPF_KPROBE(do_mov_3014)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x73")
int BPF_KPROBE(do_mov_3015)
{
    u64 addr = ctx->di + ctx->dx * 0x8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x9e")
int BPF_KPROBE(do_mov_3016)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0xac")
int BPF_KPROBE(do_mov_3017)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0xb5")
int BPF_KPROBE(do_mov_3018)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0xc7")
int BPF_KPROBE(do_mov_3019)
{
    u64 addr = ctx->di + ctx->dx * 0x8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0xfd")
int BPF_KPROBE(do_mov_3020)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x106")
int BPF_KPROBE(do_mov_3021)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x10e")
int BPF_KPROBE(do_mov_3022)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x120")
int BPF_KPROBE(do_mov_3023)
{
    u64 addr = ctx->di + ctx->dx * 0x8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x14a")
int BPF_KPROBE(do_mov_3024)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x158")
int BPF_KPROBE(do_mov_3025)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x15c")
int BPF_KPROBE(do_mov_3026)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x173")
int BPF_KPROBE(do_mov_3027)
{
    u64 addr = ctx->di + ctx->dx * 0x8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_secmark_compute_secid+0x5a")
int BPF_KPROBE(do_mov_3028)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_secmark_obj_init+0x29")
int BPF_KPROBE(do_mov_3029)
{
    u64 addr = ctx->bx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_rtclassid.isra.0+0x13")
int BPF_KPROBE(do_mov_3030)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0x60")
int BPF_KPROBE(do_mov_3031)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0x8b")
int BPF_KPROBE(do_mov_3032)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0xd3")
int BPF_KPROBE(do_mov_3033)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0xe9")
int BPF_KPROBE(do_mov_3034)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x53")
int BPF_KPROBE(do_mov_3035)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x88")
int BPF_KPROBE(do_mov_3036)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0xaa")
int BPF_KPROBE(do_mov_3037)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0xb2")
int BPF_KPROBE(do_mov_3038)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0xd4")
int BPF_KPROBE(do_mov_3039)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0xe4")
int BPF_KPROBE(do_mov_3040)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0xf7")
int BPF_KPROBE(do_mov_3041)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x10d")
int BPF_KPROBE(do_mov_3042)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x115")
int BPF_KPROBE(do_mov_3043)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x125")
int BPF_KPROBE(do_mov_3044)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x138")
int BPF_KPROBE(do_mov_3045)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x165")
int BPF_KPROBE(do_mov_3046)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x16d")
int BPF_KPROBE(do_mov_3047)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x17f")
int BPF_KPROBE(do_mov_3048)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x1c8")
int BPF_KPROBE(do_mov_3049)
{
    u64 addr = ctx->si + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x1d0")
int BPF_KPROBE(do_mov_3050)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x210")
int BPF_KPROBE(do_mov_3051)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x282")
int BPF_KPROBE(do_mov_3052)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x28a")
int BPF_KPROBE(do_mov_3053)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x47")
int BPF_KPROBE(do_mov_3054)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x5d")
int BPF_KPROBE(do_mov_3055)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x65")
int BPF_KPROBE(do_mov_3056)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x7a")
int BPF_KPROBE(do_mov_3057)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x95")
int BPF_KPROBE(do_mov_3058)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0xc9")
int BPF_KPROBE(do_mov_3059)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x10b")
int BPF_KPROBE(do_mov_3060)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x10f")
int BPF_KPROBE(do_mov_3061)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_init+0x1d")
int BPF_KPROBE(do_mov_3062)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_init+0x3a")
int BPF_KPROBE(do_mov_3063)
{
    u64 addr = ctx->si + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_init+0x3e")
int BPF_KPROBE(do_mov_3064)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_init+0xe9")
int BPF_KPROBE(do_mov_3065)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_init+0xf1")
int BPF_KPROBE(do_mov_3066)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_init+0xf7")
int BPF_KPROBE(do_mov_3067)
{
    u64 addr = ctx->bx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_init+0xfd")
int BPF_KPROBE(do_mov_3068)
{
    u64 addr = ctx->bx + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_init+0x103")
int BPF_KPROBE(do_mov_3069)
{
    u64 addr = ctx->bx + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_init+0xf0")
int BPF_KPROBE(do_mov_3070)
{
    u64 addr = ctx->r12 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_init+0xf8")
int BPF_KPROBE(do_mov_3071)
{
    u64 addr = ctx->r12 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_init+0xfe")
int BPF_KPROBE(do_mov_3072)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_init+0x106")
int BPF_KPROBE(do_mov_3073)
{
    u64 addr = ctx->r12 + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_init+0x10e")
int BPF_KPROBE(do_mov_3074)
{
    u64 addr = ctx->r12 + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv6_eval+0x44")
int BPF_KPROBE(do_mov_3075)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv6_eval+0xa8")
int BPF_KPROBE(do_mov_3076)
{
    u64 addr = ctx->r15 + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv6_eval+0xc5")
int BPF_KPROBE(do_mov_3077)
{
    u64 addr = ctx->r12 + ctx->r14 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv6_eval+0xd0")
int BPF_KPROBE(do_mov_3078)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0xce")
int BPF_KPROBE(do_mov_3079)
{
    u64 addr = ctx->r13 + ctx->r14 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0xd7")
int BPF_KPROBE(do_mov_3080)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0x120")
int BPF_KPROBE(do_mov_3081)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0x13d")
int BPF_KPROBE(do_mov_3082)
{
    u64 addr = ctx->r15 + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0x16b")
int BPF_KPROBE(do_mov_3083)
{
    u64 addr = ctx->r13 + ctx->r14 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0x174")
int BPF_KPROBE(do_mov_3084)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv4_eval+0x3c")
int BPF_KPROBE(do_mov_3085)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv4_eval+0x165")
int BPF_KPROBE(do_mov_3086)
{
    u64 addr = ctx->r14 + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv4_eval+0x1a6")
int BPF_KPROBE(do_mov_3087)
{
    u64 addr = ctx->r15 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv4_eval+0x1ae")
int BPF_KPROBE(do_mov_3088)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_eval+0xc5")
int BPF_KPROBE(do_mov_3089)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_eval+0x149")
int BPF_KPROBE(do_mov_3090)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_eval+0x189")
int BPF_KPROBE(do_mov_3091)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0xe2")
int BPF_KPROBE(do_mov_3092)
{
    u64 addr = ctx->r10 + ctx->r8 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x102")
int BPF_KPROBE(do_mov_3093)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x10e")
int BPF_KPROBE(do_mov_3094)
{
    u64 addr = ctx->r10 + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x11f")
int BPF_KPROBE(do_mov_3095)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x146")
int BPF_KPROBE(do_mov_3096)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x15f")
int BPF_KPROBE(do_mov_3097)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x174")
int BPF_KPROBE(do_mov_3098)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x17c")
int BPF_KPROBE(do_mov_3099)
{
    u64 addr = ctx->r10 + ctx->ax * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x192")
int BPF_KPROBE(do_mov_3100)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x199")
int BPF_KPROBE(do_mov_3101)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x1a0")
int BPF_KPROBE(do_mov_3102)
{
    u64 addr = ctx->r10 + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x63")
int BPF_KPROBE(do_mov_3103)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x79")
int BPF_KPROBE(do_mov_3104)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x18e")
int BPF_KPROBE(do_mov_3105)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x1a6")
int BPF_KPROBE(do_mov_3106)
{
    u64 addr = ctx->ax + ctx->r14 * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x1c4")
int BPF_KPROBE(do_mov_3107)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x1d2")
int BPF_KPROBE(do_mov_3108)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x1ee")
int BPF_KPROBE(do_mov_3109)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x1f8")
int BPF_KPROBE(do_mov_3110)
{
    u64 addr = ctx->ax + ctx->r14 * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_eval+0x23")
int BPF_KPROBE(do_mov_3111)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_eval+0x2d")
int BPF_KPROBE(do_mov_3112)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_dump+0xa0")
int BPF_KPROBE(do_mov_3113)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_init+0x53")
int BPF_KPROBE(do_mov_3114)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_init+0x7d")
int BPF_KPROBE(do_mov_3115)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_init+0x81")
int BPF_KPROBE(do_mov_3116)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_clone+0x27")
int BPF_KPROBE(do_mov_3117)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_do_init+0x7a")
int BPF_KPROBE(do_mov_3118)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_do_init+0x9d")
int BPF_KPROBE(do_mov_3119)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_do_init+0xaa")
int BPF_KPROBE(do_mov_3120)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_fetch+0x1d")
int BPF_KPROBE(do_mov_3121)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_fetch+0x24")
int BPF_KPROBE(do_mov_3122)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_clone+0x5c")
int BPF_KPROBE(do_mov_3123)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_clone+0x64")
int BPF_KPROBE(do_mov_3124)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_clone+0x70")
int BPF_KPROBE(do_mov_3125)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_init_seqcount+0x23")
int BPF_KPROBE(do_mov_3126)
{
    u64 addr = ctx->dx + ctx->bx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x5b")
int BPF_KPROBE(do_mov_3127)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x5f")
int BPF_KPROBE(do_mov_3128)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x63")
int BPF_KPROBE(do_mov_3129)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x68")
int BPF_KPROBE(do_mov_3130)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x6c")
int BPF_KPROBE(do_mov_3131)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x77")
int BPF_KPROBE(do_mov_3132)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0xd5")
int BPF_KPROBE(do_mov_3133)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0xd9")
int BPF_KPROBE(do_mov_3134)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0xde")
int BPF_KPROBE(do_mov_3135)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0xe2")
int BPF_KPROBE(do_mov_3136)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0xe6")
int BPF_KPROBE(do_mov_3137)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_unbind+0x11b")
int BPF_KPROBE(do_mov_3138)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_unbind+0x11f")
int BPF_KPROBE(do_mov_3139)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_unbind+0x122")
int BPF_KPROBE(do_mov_3140)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_unbind+0x126")
int BPF_KPROBE(do_mov_3141)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_block_offload_cmd+0xe3")
int BPF_KPROBE(do_mov_3142)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_block_offload_cmd+0xe7")
int BPF_KPROBE(do_mov_3143)
{
    u64 addr = ctx->r12 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_block_offload_cmd+0xef")
int BPF_KPROBE(do_mov_3144)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_block_offload_cmd+0xf2")
int BPF_KPROBE(do_mov_3145)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0xd8")
int BPF_KPROBE(do_mov_3146)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0xdc")
int BPF_KPROBE(do_mov_3147)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0xf1")
int BPF_KPROBE(do_mov_3148)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0xf8")
int BPF_KPROBE(do_mov_3149)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0x100")
int BPF_KPROBE(do_mov_3150)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0x104")
int BPF_KPROBE(do_mov_3151)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0x10e")
int BPF_KPROBE(do_mov_3152)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0x112")
int BPF_KPROBE(do_mov_3153)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0x116")
int BPF_KPROBE(do_mov_3154)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_offload_cmd+0x121")
int BPF_KPROBE(do_mov_3155)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_offload_cmd+0x125")
int BPF_KPROBE(do_mov_3156)
{
    u64 addr = ctx->r12 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_offload_cmd+0x12d")
int BPF_KPROBE(do_mov_3157)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_offload_cmd+0x130")
int BPF_KPROBE(do_mov_3158)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_set_addr_type+0x1d")
int BPF_KPROBE(do_mov_3159)
{
    u64 addr = ctx->di + 0x56;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_set_addr_type+0x21")
int BPF_KPROBE(do_mov_3160)
{
    u64 addr = ctx->di + 0xae;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_set_addr_type+0x28")
int BPF_KPROBE(do_mov_3161)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_set_addr_type+0x2b")
int BPF_KPROBE(do_mov_3162)
{
    u64 addr = ctx->di + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0xb3")
int BPF_KPROBE(do_mov_3163)
{
    u64 addr = ctx->bx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0xcc")
int BPF_KPROBE(do_mov_3164)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0xdd")
int BPF_KPROBE(do_mov_3165)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0xec")
int BPF_KPROBE(do_mov_3166)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x10d")
int BPF_KPROBE(do_mov_3167)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x111")
int BPF_KPROBE(do_mov_3168)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x197")
int BPF_KPROBE(do_mov_3169)
{
    u64 addr = ctx->bx + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1aa")
int BPF_KPROBE(do_mov_3170)
{
    u64 addr = ctx->bx + 0xdc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1b6")
int BPF_KPROBE(do_mov_3171)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1c1")
int BPF_KPROBE(do_mov_3172)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1c8")
int BPF_KPROBE(do_mov_3173)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1cf")
int BPF_KPROBE(do_mov_3174)
{
    u64 addr = ctx->bx + 0xe4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1d6")
int BPF_KPROBE(do_mov_3175)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1da")
int BPF_KPROBE(do_mov_3176)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1e6")
int BPF_KPROBE(do_mov_3177)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x264")
int BPF_KPROBE(do_mov_3178)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x270")
int BPF_KPROBE(do_mov_3179)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x274")
int BPF_KPROBE(do_mov_3180)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x27f")
int BPF_KPROBE(do_mov_3181)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x282")
int BPF_KPROBE(do_mov_3182)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x289")
int BPF_KPROBE(do_mov_3183)
{
    u64 addr = ctx->bx + 0xdc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_offload_set_dependency+0x6")
int BPF_KPROBE(do_mov_3184)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_offload_update_dependency+0x1d")
int BPF_KPROBE(do_mov_3185)
{
    u64 addr = ctx->di + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_offload_update_dependency+0x20")
int BPF_KPROBE(do_mov_3186)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_offload_update_dependency+0x31")
int BPF_KPROBE(do_mov_3187)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_offload_update_dependency+0x37")
int BPF_KPROBE(do_mov_3188)
{
    u64 addr = ctx->di + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_estimate+0x10")
int BPF_KPROBE(do_mov_3189)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_estimate+0x19")
int BPF_KPROBE(do_mov_3190)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_remove+0x17")
int BPF_KPROBE(do_mov_3191)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_remove+0x1f")
int BPF_KPROBE(do_mov_3192)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_remove+0x2d")
int BPF_KPROBE(do_mov_3193)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_walk+0x77")
int BPF_KPROBE(do_mov_3194)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_walk+0x84")
int BPF_KPROBE(do_mov_3195)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_destroy+0x3c")
int BPF_KPROBE(do_mov_3196)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_destroy+0x48")
int BPF_KPROBE(do_mov_3197)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_destroy+0x5b")
int BPF_KPROBE(do_mov_3198)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_destroy+0x63")
int BPF_KPROBE(do_mov_3199)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_lookup+0xa4")
int BPF_KPROBE(do_mov_3200)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_fast_estimate+0x73")
int BPF_KPROBE(do_mov_3201)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_fast_estimate+0x80")
int BPF_KPROBE(do_mov_3202)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xc1")
int BPF_KPROBE(do_mov_3203)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xc4")
int BPF_KPROBE(do_mov_3204)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xc8")
int BPF_KPROBE(do_mov_3205)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xd2")
int BPF_KPROBE(do_mov_3206)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xe9")
int BPF_KPROBE(do_mov_3207)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_deactivate+0x9e")
int BPF_KPROBE(do_mov_3208)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_flush+0x4b")
int BPF_KPROBE(do_mov_3209)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_init+0x91")
int BPF_KPROBE(do_mov_3210)
{
    u64 addr = ctx->r12 + 0x178;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_init+0xad")
int BPF_KPROBE(do_mov_3211)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_init+0xb5")
int BPF_KPROBE(do_mov_3212)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_init+0xc1")
int BPF_KPROBE(do_mov_3213)
{
    u64 addr = ctx->r12 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_walk+0x5f")
int BPF_KPROBE(do_mov_3214)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_walk+0xb6")
int BPF_KPROBE(do_mov_3215)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_walk+0xca")
int BPF_KPROBE(do_mov_3216)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_lookup_fast+0xb2")
int BPF_KPROBE(do_mov_3217)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x1f8")
int BPF_KPROBE(do_mov_3218)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x1fb")
int BPF_KPROBE(do_mov_3219)
{
    u64 addr = ctx->cx + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x289")
int BPF_KPROBE(do_mov_3220)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x28c")
int BPF_KPROBE(do_mov_3221)
{
    u64 addr = ctx->cx + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_init+0x4f")
int BPF_KPROBE(do_mov_3222)
{
    u64 addr = ctx->di + 0xf4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_lookup+0x185")
int BPF_KPROBE(do_mov_3223)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_estimate+0x73")
int BPF_KPROBE(do_mov_3224)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_estimate+0x80")
int BPF_KPROBE(do_mov_3225)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_update+0x1fe")
int BPF_KPROBE(do_mov_3226)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_insert+0x97")
int BPF_KPROBE(do_mov_3227)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_remove+0x58")
int BPF_KPROBE(do_mov_3228)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_remove+0x5c")
int BPF_KPROBE(do_mov_3229)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_remove+0x69")
int BPF_KPROBE(do_mov_3230)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_walk+0x6d")
int BPF_KPROBE(do_mov_3231)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_walk+0x7a")
int BPF_KPROBE(do_mov_3232)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_init+0x12")
int BPF_KPROBE(do_mov_3233)
{
    u64 addr = ctx->di + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_init+0x19")
int BPF_KPROBE(do_mov_3234)
{
    u64 addr = ctx->di + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_init+0x41")
int BPF_KPROBE(do_mov_3235)
{
    u64 addr = ctx->di + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_estimate+0x24")
int BPF_KPROBE(do_mov_3236)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_estimate+0x37")
int BPF_KPROBE(do_mov_3237)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0x7c")
int BPF_KPROBE(do_mov_3238)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0x80")
int BPF_KPROBE(do_mov_3239)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0x85")
int BPF_KPROBE(do_mov_3240)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0x8a")
int BPF_KPROBE(do_mov_3241)
{
    u64 addr = ctx->bx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0xa3")
int BPF_KPROBE(do_mov_3242)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_estimate+0x35")
int BPF_KPROBE(do_mov_3243)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_estimate+0x38")
int BPF_KPROBE(do_mov_3244)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_flush+0x4b")
int BPF_KPROBE(do_mov_3245)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x28")
int BPF_KPROBE(do_mov_3246)
{
    u64 addr = ctx->di + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x3d")
int BPF_KPROBE(do_mov_3247)
{
    u64 addr = ctx->di - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x41")
int BPF_KPROBE(do_mov_3248)
{
    u64 addr = ctx->di - 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x49")
int BPF_KPROBE(do_mov_3249)
{
    u64 addr = ctx->di - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x51")
int BPF_KPROBE(do_mov_3250)
{
    u64 addr = ctx->di - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x58")
int BPF_KPROBE(do_mov_3251)
{
    u64 addr = ctx->di - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x5c")
int BPF_KPROBE(do_mov_3252)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_walk+0x6c")
int BPF_KPROBE(do_mov_3253)
{
    u64 addr = ctx->r15 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_walk+0xbd")
int BPF_KPROBE(do_mov_3254)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0xef")
int BPF_KPROBE(do_mov_3255)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0xf4")
int BPF_KPROBE(do_mov_3256)
{
    u64 addr = ctx->r12 + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x114")
int BPF_KPROBE(do_mov_3257)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x119")
int BPF_KPROBE(do_mov_3258)
{
    u64 addr = ctx->r12 + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x24f")
int BPF_KPROBE(do_mov_3259)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x25e")
int BPF_KPROBE(do_mov_3260)
{
    u64 addr = ctx->r12 + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x215")
int BPF_KPROBE(do_mov_3261)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x218")
int BPF_KPROBE(do_mov_3262)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x220")
int BPF_KPROBE(do_mov_3263)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x228")
int BPF_KPROBE(do_mov_3264)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x455")
int BPF_KPROBE(do_mov_3265)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_lookup+0x16c")
int BPF_KPROBE(do_mov_3266)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_lookup+0x1e9")
int BPF_KPROBE(do_mov_3267)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_get.constprop.0+0x16e")
int BPF_KPROBE(do_mov_3268)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_get.constprop.0+0x17a")
int BPF_KPROBE(do_mov_3269)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_gc_init+0xd")
int BPF_KPROBE(do_mov_3270)
{
    u64 addr = ctx->di + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0xb8")
int BPF_KPROBE(do_mov_3271)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0xbd")
int BPF_KPROBE(do_mov_3272)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0xcc")
int BPF_KPROBE(do_mov_3273)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0xd4")
int BPF_KPROBE(do_mov_3274)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0x37b")
int BPF_KPROBE(do_mov_3275)
{
    u64 addr = ctx->r9 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_resize+0x199")
int BPF_KPROBE(do_mov_3276)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_resize+0x1a5")
int BPF_KPROBE(do_mov_3277)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_resize+0x1a9")
int BPF_KPROBE(do_mov_3278)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_resize+0x1b2")
int BPF_KPROBE(do_mov_3279)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_estimate+0x6c")
int BPF_KPROBE(do_mov_3280)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_estimate+0xa1")
int BPF_KPROBE(do_mov_3281)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_estimate+0xc0")
int BPF_KPROBE(do_mov_3282)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_estimate+0xcd")
int BPF_KPROBE(do_mov_3283)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_gc+0x73")
int BPF_KPROBE(do_mov_3284)
{
    u64 addr = ctx->si + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_gc+0x76")
int BPF_KPROBE(do_mov_3285)
{
    u64 addr = ctx->si + ctx->ax * 0x8 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_gc+0xe6")
int BPF_KPROBE(do_mov_3286)
{
    u64 addr = ctx->r12 + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_gc+0x13c")
int BPF_KPROBE(do_mov_3287)
{
    u64 addr = ctx->r12 + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_walk+0x98")
int BPF_KPROBE(do_mov_3288)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_walk+0xf2")
int BPF_KPROBE(do_mov_3289)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_realloc_scratch+0xa7")
int BPF_KPROBE(do_mov_3290)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_realloc_scratch+0xbf")
int BPF_KPROBE(do_mov_3291)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_insert+0x28")
int BPF_KPROBE(do_mov_3292)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x4f")
int BPF_KPROBE(do_mov_3293)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x56")
int BPF_KPROBE(do_mov_3294)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x5f")
int BPF_KPROBE(do_mov_3295)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x7b")
int BPF_KPROBE(do_mov_3296)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x9e")
int BPF_KPROBE(do_mov_3297)
{
    u64 addr = ctx->cx + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0xde")
int BPF_KPROBE(do_mov_3298)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x106")
int BPF_KPROBE(do_mov_3299)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x10d")
int BPF_KPROBE(do_mov_3300)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x115")
int BPF_KPROBE(do_mov_3301)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x11d")
int BPF_KPROBE(do_mov_3302)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x125")
int BPF_KPROBE(do_mov_3303)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x150")
int BPF_KPROBE(do_mov_3304)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x168")
int BPF_KPROBE(do_mov_3305)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x1a2")
int BPF_KPROBE(do_mov_3306)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x6e")
int BPF_KPROBE(do_mov_3307)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x72")
int BPF_KPROBE(do_mov_3308)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x7f")
int BPF_KPROBE(do_mov_3309)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0xa2")
int BPF_KPROBE(do_mov_3310)
{
    u64 addr = ctx->cx + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0xd6")
int BPF_KPROBE(do_mov_3311)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0xf9")
int BPF_KPROBE(do_mov_3312)
{
    u64 addr = ctx->cx + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x122")
int BPF_KPROBE(do_mov_3313)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x14b")
int BPF_KPROBE(do_mov_3314)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x15b")
int BPF_KPROBE(do_mov_3315)
{
    u64 addr = ctx->dx - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x166")
int BPF_KPROBE(do_mov_3316)
{
    u64 addr = ctx->dx - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x16e")
int BPF_KPROBE(do_mov_3317)
{
    u64 addr = ctx->dx - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x176")
int BPF_KPROBE(do_mov_3318)
{
    u64 addr = ctx->dx - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x17e")
int BPF_KPROBE(do_mov_3319)
{
    u64 addr = ctx->dx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x186")
int BPF_KPROBE(do_mov_3320)
{
    u64 addr = ctx->dx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x18e")
int BPF_KPROBE(do_mov_3321)
{
    u64 addr = ctx->bx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x1a2")
int BPF_KPROBE(do_mov_3322)
{
    u64 addr = ctx->bx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x1b1")
int BPF_KPROBE(do_mov_3323)
{
    u64 addr = ctx->bx + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x1b8")
int BPF_KPROBE(do_mov_3324)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_commit+0x6e")
int BPF_KPROBE(do_mov_3325)
{
    u64 addr = ctx->bx + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_commit+0x83")
int BPF_KPROBE(do_mov_3326)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_commit+0x9f")
int BPF_KPROBE(do_mov_3327)
{
    u64 addr = ctx->bx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_destroy+0xbb")
int BPF_KPROBE(do_mov_3328)
{
    u64 addr = ctx->r12 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_destroy+0x185")
int BPF_KPROBE(do_mov_3329)
{
    u64 addr = ctx->r12 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_refill+0x95")
int BPF_KPROBE(do_mov_3330)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_refill+0xba")
int BPF_KPROBE(do_mov_3331)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_lookup+0x17a")
int BPF_KPROBE(do_mov_3332)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_lookup+0x1a3")
int BPF_KPROBE(do_mov_3333)
{
    u64 addr = ctx->gs + 0x30798;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_lookup+0x2b1")
int BPF_KPROBE(do_mov_3334)
{
    u64 addr = ctx->gs + 0x30798;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x10c")
int BPF_KPROBE(do_mov_3335)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x1fc")
int BPF_KPROBE(do_mov_3336)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x219")
int BPF_KPROBE(do_mov_3337)
{
    u64 addr = ctx->r13 + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x2a0")
int BPF_KPROBE(do_mov_3338)
{
    u64 addr = ctx->di + ctx->si * 0x8 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x319")
int BPF_KPROBE(do_mov_3339)
{
    u64 addr = ctx->bx + ctx->si * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x57b")
int BPF_KPROBE(do_mov_3340)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x5e0")
int BPF_KPROBE(do_mov_3341)
{
    u64 addr = ctx->si + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x5e7")
int BPF_KPROBE(do_mov_3342)
{
    u64 addr = ctx->si + ctx->dx * 0x8 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x627")
int BPF_KPROBE(do_mov_3343)
{
    u64 addr = ctx->dx + ctx->cx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x668")
int BPF_KPROBE(do_mov_3344)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_remove+0x2a7")
int BPF_KPROBE(do_mov_3345)
{
    u64 addr = ctx->si + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_remove+0x2b3")
int BPF_KPROBE(do_mov_3346)
{
    u64 addr = ctx->si - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_remove+0x31b")
int BPF_KPROBE(do_mov_3347)
{
    u64 addr = ctx->bx + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_fill+0x79")
int BPF_KPROBE(do_mov_3348)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_fill+0x95")
int BPF_KPROBE(do_mov_3349)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_refill+0x8f")
int BPF_KPROBE(do_mov_3350)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_refill+0xf3")
int BPF_KPROBE(do_mov_3351)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_refill+0x15b")
int BPF_KPROBE(do_mov_3352)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_refill+0x1bf")
int BPF_KPROBE(do_mov_3353)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_estimate+0x94")
int BPF_KPROBE(do_mov_3354)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_estimate+0xd4")
int BPF_KPROBE(do_mov_3355)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_estimate+0xe6")
int BPF_KPROBE(do_mov_3356)
{
    u64 addr = ctx->r10 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_estimate+0x106")
int BPF_KPROBE(do_mov_3357)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_lookup+0x3ea")
int BPF_KPROBE(do_mov_3358)
{
    u64 addr = ctx->gs + 0x30799;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_lookup+0x583")
int BPF_KPROBE(do_mov_3359)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_clone+0x28")
int BPF_KPROBE(do_mov_3360)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_clone+0x3e")
int BPF_KPROBE(do_mov_3361)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_clone+0x47")
int BPF_KPROBE(do_mov_3362)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_do_init+0x61")
int BPF_KPROBE(do_mov_3363)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_do_init+0x71")
int BPF_KPROBE(do_mov_3364)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_do_init+0x75")
int BPF_KPROBE(do_mov_3365)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_eval+0x81")
int BPF_KPROBE(do_mov_3366)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_eval+0x8b")
int BPF_KPROBE(do_mov_3367)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_inc_eval+0x37")
int BPF_KPROBE(do_mov_3368)
{
    u64 addr = ctx->si + ctx->r10 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_random_init+0x16")
int BPF_KPROBE(do_mov_3369)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_random_init+0x22")
int BPF_KPROBE(do_mov_3370)
{
    u64 addr = ctx->si + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_random_eval+0x32")
int BPF_KPROBE(do_mov_3371)
{
    u64 addr = ctx->r12 + ctx->r14 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_inc_init+0x29")
int BPF_KPROBE(do_mov_3372)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_inc_init+0x36")
int BPF_KPROBE(do_mov_3373)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_inc_init+0x62")
int BPF_KPROBE(do_mov_3374)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ng_inc_init+0x84")
int BPF_KPROBE(do_mov_3375)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_notrack_eval+0x2a")
int BPF_KPROBE(do_mov_3376)
{
    u64 addr = ctx->ax + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_init+0xc")
int BPF_KPROBE(do_mov_3377)
{
    u64 addr = ctx->si + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_init+0x12")
int BPF_KPROBE(do_mov_3378)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_init+0x4c")
int BPF_KPROBE(do_mov_3379)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_init+0x90")
int BPF_KPROBE(do_mov_3380)
{
    u64 addr = ctx->dx + 0xb3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_init+0xaf")
int BPF_KPROBE(do_mov_3381)
{
    u64 addr = ctx->bx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x2d")
int BPF_KPROBE(do_mov_3382)
{
    u64 addr = ctx->dx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x48")
int BPF_KPROBE(do_mov_3383)
{
    u64 addr = ctx->dx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x57")
int BPF_KPROBE(do_mov_3384)
{
    u64 addr = ctx->dx + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x65")
int BPF_KPROBE(do_mov_3385)
{
    u64 addr = ctx->dx + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x73")
int BPF_KPROBE(do_mov_3386)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x81")
int BPF_KPROBE(do_mov_3387)
{
    u64 addr = ctx->dx + 0x8d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_helper_obj_init+0x4a")
int BPF_KPROBE(do_mov_3388)
{
    u64 addr = ctx->dx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_helper_obj_init+0xd1")
int BPF_KPROBE(do_mov_3389)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_helper_obj_init+0xd8")
int BPF_KPROBE(do_mov_3390)
{
    u64 addr = ctx->bx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_dump+0xc5")
int BPF_KPROBE(do_mov_3391)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_init+0x67")
int BPF_KPROBE(do_mov_3392)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_init+0x13e")
int BPF_KPROBE(do_mov_3393)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_init+0x147")
int BPF_KPROBE(do_mov_3394)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_init+0x15f")
int BPF_KPROBE(do_mov_3395)
{
    u64 addr = ctx->ax + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_zone_eval+0x79")
int BPF_KPROBE(do_mov_3396)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_zone_eval+0x88")
int BPF_KPROBE(do_mov_3397)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_zone_eval+0xe1")
int BPF_KPROBE(do_mov_3398)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_tmpl_put_pcpu+0x30")
int BPF_KPROBE(do_mov_3399)
{
    u64 addr = ctx->ax + ctx->r12 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_init+0x2e")
int BPF_KPROBE(do_mov_3400)
{
    u64 addr = ctx->si + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_init+0x3b")
int BPF_KPROBE(do_mov_3401)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_init+0x74")
int BPF_KPROBE(do_mov_3402)
{
    u64 addr = ctx->r12 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_init+0x115")
int BPF_KPROBE(do_mov_3403)
{
    u64 addr = ctx->r12 + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_init+0x1cf")
int BPF_KPROBE(do_mov_3404)
{
    u64 addr = ctx->dx + ctx->r15 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_helper_obj_eval+0x7f")
int BPF_KPROBE(do_mov_3405)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_eval+0x31")
int BPF_KPROBE(do_mov_3406)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_eval+0x111")
int BPF_KPROBE(do_mov_3407)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_eval+0x127")
int BPF_KPROBE(do_mov_3408)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_eval+0x86")
int BPF_KPROBE(do_mov_3409)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_eval+0xca")
int BPF_KPROBE(do_mov_3410)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_eval+0xdb")
int BPF_KPROBE(do_mov_3411)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_eval+0xa9")
int BPF_KPROBE(do_mov_3412)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_eval+0xc3")
int BPF_KPROBE(do_mov_3413)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_eval+0x135")
int BPF_KPROBE(do_mov_3414)
{
    u64 addr = ctx->r12 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x49")
int BPF_KPROBE(do_mov_3415)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x94")
int BPF_KPROBE(do_mov_3416)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x116")
int BPF_KPROBE(do_mov_3417)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x128")
int BPF_KPROBE(do_mov_3418)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x145")
int BPF_KPROBE(do_mov_3419)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x16d")
int BPF_KPROBE(do_mov_3420)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x17c")
int BPF_KPROBE(do_mov_3421)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x1b9")
int BPF_KPROBE(do_mov_3422)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x1bd")
int BPF_KPROBE(do_mov_3423)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x1d9")
int BPF_KPROBE(do_mov_3424)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x1e1")
int BPF_KPROBE(do_mov_3425)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x1f5")
int BPF_KPROBE(do_mov_3426)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x269")
int BPF_KPROBE(do_mov_3427)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x271")
int BPF_KPROBE(do_mov_3428)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x280")
int BPF_KPROBE(do_mov_3429)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x288")
int BPF_KPROBE(do_mov_3430)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x318")
int BPF_KPROBE(do_mov_3431)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x31c")
int BPF_KPROBE(do_mov_3432)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x344")
int BPF_KPROBE(do_mov_3433)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x348")
int BPF_KPROBE(do_mov_3434)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x366")
int BPF_KPROBE(do_mov_3435)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x36e")
int BPF_KPROBE(do_mov_3436)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x38d")
int BPF_KPROBE(do_mov_3437)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x395")
int BPF_KPROBE(do_mov_3438)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x3da")
int BPF_KPROBE(do_mov_3439)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x3e2")
int BPF_KPROBE(do_mov_3440)
{
    u64 addr = ctx->r14 + ctx->cx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x40c")
int BPF_KPROBE(do_mov_3441)
{
    u64 addr = ctx->di + ctx->cx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x455")
int BPF_KPROBE(do_mov_3442)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x45d")
int BPF_KPROBE(do_mov_3443)
{
    u64 addr = ctx->r14 + ctx->cx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x487")
int BPF_KPROBE(do_mov_3444)
{
    u64 addr = ctx->di + ctx->cx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x4b4")
int BPF_KPROBE(do_mov_3445)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x4dd")
int BPF_KPROBE(do_mov_3446)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x4ed")
int BPF_KPROBE(do_mov_3447)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x4f4")
int BPF_KPROBE(do_mov_3448)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x54c")
int BPF_KPROBE(do_mov_3449)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x55c")
int BPF_KPROBE(do_mov_3450)
{
    u64 addr = ctx->r14 + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x5a9")
int BPF_KPROBE(do_mov_3451)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x5b0")
int BPF_KPROBE(do_mov_3452)
{
    u64 addr = ctx->r14 + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0x62")
int BPF_KPROBE(do_mov_3453)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0x81")
int BPF_KPROBE(do_mov_3454)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0xa9")
int BPF_KPROBE(do_mov_3455)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0xe2")
int BPF_KPROBE(do_mov_3456)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0xf1")
int BPF_KPROBE(do_mov_3457)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0xf5")
int BPF_KPROBE(do_mov_3458)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0x108")
int BPF_KPROBE(do_mov_3459)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0x111")
int BPF_KPROBE(do_mov_3460)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0x118")
int BPF_KPROBE(do_mov_3461)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0x142")
int BPF_KPROBE(do_mov_3462)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_pkts_init+0x32")
int BPF_KPROBE(do_mov_3463)
{
    u64 addr = ctx->bx + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_init+0x2c")
int BPF_KPROBE(do_mov_3464)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_bytes_eval+0x58")
int BPF_KPROBE(do_mov_3465)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_bytes_eval+0x72")
int BPF_KPROBE(do_mov_3466)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_bytes_eval+0x90")
int BPF_KPROBE(do_mov_3467)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_bytes_eval+0xa6")
int BPF_KPROBE(do_mov_3468)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x1d")
int BPF_KPROBE(do_mov_3469)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x25")
int BPF_KPROBE(do_mov_3470)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x2d")
int BPF_KPROBE(do_mov_3471)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x35")
int BPF_KPROBE(do_mov_3472)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x3c")
int BPF_KPROBE(do_mov_3473)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x48")
int BPF_KPROBE(do_mov_3474)
{
    u64 addr = ctx->di + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x57")
int BPF_KPROBE(do_mov_3475)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x60")
int BPF_KPROBE(do_mov_3476)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x6e")
int BPF_KPROBE(do_mov_3477)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x77")
int BPF_KPROBE(do_mov_3478)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x1d")
int BPF_KPROBE(do_mov_3479)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x25")
int BPF_KPROBE(do_mov_3480)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x2d")
int BPF_KPROBE(do_mov_3481)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x34")
int BPF_KPROBE(do_mov_3482)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x40")
int BPF_KPROBE(do_mov_3483)
{
    u64 addr = ctx->di + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x4f")
int BPF_KPROBE(do_mov_3484)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x58")
int BPF_KPROBE(do_mov_3485)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x66")
int BPF_KPROBE(do_mov_3486)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x6f")
int BPF_KPROBE(do_mov_3487)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_eval+0x39")
int BPF_KPROBE(do_mov_3488)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_eval+0x50")
int BPF_KPROBE(do_mov_3489)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_eval+0x68")
int BPF_KPROBE(do_mov_3490)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_eval+0x7b")
int BPF_KPROBE(do_mov_3491)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_pkts_eval+0x45")
int BPF_KPROBE(do_mov_3492)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_pkts_eval+0x5f")
int BPF_KPROBE(do_mov_3493)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_pkts_eval+0x7d")
int BPF_KPROBE(do_mov_3494)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_pkts_eval+0x93")
int BPF_KPROBE(do_mov_3495)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_eval+0x49")
int BPF_KPROBE(do_mov_3496)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_eval+0x60")
int BPF_KPROBE(do_mov_3497)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_eval+0x78")
int BPF_KPROBE(do_mov_3498)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_eval+0x8b")
int BPF_KPROBE(do_mov_3499)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_init+0x53")
int BPF_KPROBE(do_mov_3500)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_init+0x9d")
int BPF_KPROBE(do_mov_3501)
{
    u64 addr = ctx->r12 + 0xd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_init+0x13c")
int BPF_KPROBE(do_mov_3502)
{
    u64 addr = ctx->r12 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_init+0x195")
int BPF_KPROBE(do_mov_3503)
{
    u64 addr = ctx->r12 + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_init+0x1a5")
int BPF_KPROBE(do_mov_3504)
{
    u64 addr = ctx->r12 + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_eval+0xa2")
int BPF_KPROBE(do_mov_3505)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_objref_init+0x51")
int BPF_KPROBE(do_mov_3506)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_objref_map_init+0x85")
int BPF_KPROBE(do_mov_3507)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_objref_map_init+0x93")
int BPF_KPROBE(do_mov_3508)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_objref_map_eval+0xa5")
int BPF_KPROBE(do_mov_3509)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_sreg_eval+0x25")
int BPF_KPROBE(do_mov_3510)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_init+0x18")
int BPF_KPROBE(do_mov_3511)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_init+0x2d")
int BPF_KPROBE(do_mov_3512)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_init+0x58")
int BPF_KPROBE(do_mov_3513)
{
    u64 addr = ctx->cx + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_init+0x6c")
int BPF_KPROBE(do_mov_3514)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_sreg_init+0x39")
int BPF_KPROBE(do_mov_3515)
{
    u64 addr = ctx->r12 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_eval+0x60")
int BPF_KPROBE(do_mov_3516)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_obj_update+0xd")
int BPF_KPROBE(do_mov_3517)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_obj_update+0x1f")
int BPF_KPROBE(do_mov_3518)
{
    u64 addr = ctx->di + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_clone+0x23")
int BPF_KPROBE(do_mov_3519)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_clone+0x2c")
int BPF_KPROBE(do_mov_3520)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_do_init+0xa4")
int BPF_KPROBE(do_mov_3521)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_do_init+0xae")
int BPF_KPROBE(do_mov_3522)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_do_init+0xb3")
int BPF_KPROBE(do_mov_3523)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_do_init+0xb7")
int BPF_KPROBE(do_mov_3524)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_obj_eval+0x3e")
int BPF_KPROBE(do_mov_3525)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_eval+0x33")
int BPF_KPROBE(do_mov_3526)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reject_init+0x1a")
int BPF_KPROBE(do_mov_3527)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reject_init+0x49")
int BPF_KPROBE(do_mov_3528)
{
    u64 addr = ctx->si + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reject_inet_eval+0x39")
int BPF_KPROBE(do_mov_3529)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reject_netdev_eval+0xa8")
int BPF_KPROBE(do_mov_3530)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_init+0x1d")
int BPF_KPROBE(do_mov_3531)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_init+0x42")
int BPF_KPROBE(do_mov_3532)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_init+0x51")
int BPF_KPROBE(do_mov_3533)
{
    u64 addr = ctx->si + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_init+0x74")
int BPF_KPROBE(do_mov_3534)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0x84")
int BPF_KPROBE(do_mov_3535)
{
    u64 addr = ctx->si + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0x93")
int BPF_KPROBE(do_mov_3536)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0xb5")
int BPF_KPROBE(do_mov_3537)
{
    u64 addr = ctx->si + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0xbc")
int BPF_KPROBE(do_mov_3538)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0xd1")
int BPF_KPROBE(do_mov_3539)
{
    u64 addr = ctx->si + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0xd8")
int BPF_KPROBE(do_mov_3540)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x1e0")
int BPF_KPROBE(do_mov_3541)
{
    u64 addr = ctx->ax + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x1e8")
int BPF_KPROBE(do_mov_3542)
{
    u64 addr = ctx->ax + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x1f3")
int BPF_KPROBE(do_mov_3543)
{
    u64 addr = ctx->ax + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x1fe")
int BPF_KPROBE(do_mov_3544)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x209")
int BPF_KPROBE(do_mov_3545)
{
    u64 addr = ctx->ax + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x214")
int BPF_KPROBE(do_mov_3546)
{
    u64 addr = ctx->ax + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x21f")
int BPF_KPROBE(do_mov_3547)
{
    u64 addr = ctx->ax + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x22a")
int BPF_KPROBE(do_mov_3548)
{
    u64 addr = ctx->ax + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x235")
int BPF_KPROBE(do_mov_3549)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x240")
int BPF_KPROBE(do_mov_3550)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x263")
int BPF_KPROBE(do_mov_3551)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x28c")
int BPF_KPROBE(do_mov_3552)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x40f")
int BPF_KPROBE(do_mov_3553)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x419")
int BPF_KPROBE(do_mov_3554)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x429")
int BPF_KPROBE(do_mov_3555)
{
    u64 addr = ctx->bx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x4e4")
int BPF_KPROBE(do_mov_3556)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x552")
int BPF_KPROBE(do_mov_3557)
{
    u64 addr = ctx->r14 + 0x3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x561")
int BPF_KPROBE(do_mov_3558)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x570")
int BPF_KPROBE(do_mov_3559)
{
    u64 addr = ctx->r14 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x579")
int BPF_KPROBE(do_mov_3560)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x634")
int BPF_KPROBE(do_mov_3561)
{
    u64 addr = ctx->bx + 0x9a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x640")
int BPF_KPROBE(do_mov_3562)
{
    u64 addr = ctx->bx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x64b")
int BPF_KPROBE(do_mov_3563)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x655")
int BPF_KPROBE(do_mov_3564)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x67a")
int BPF_KPROBE(do_mov_3565)
{
    u64 addr = ctx->bx + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_dump+0x10c")
int BPF_KPROBE(do_mov_3566)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_dump+0x26c")
int BPF_KPROBE(do_mov_3567)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_dump+0x39f")
int BPF_KPROBE(do_mov_3568)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_dump+0x494")
int BPF_KPROBE(do_mov_3569)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x19")
int BPF_KPROBE(do_mov_3570)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x45")
int BPF_KPROBE(do_mov_3571)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x66")
int BPF_KPROBE(do_mov_3572)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x81")
int BPF_KPROBE(do_mov_3573)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x96")
int BPF_KPROBE(do_mov_3574)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0xd2")
int BPF_KPROBE(do_mov_3575)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0xfd")
int BPF_KPROBE(do_mov_3576)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x13e")
int BPF_KPROBE(do_mov_3577)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x159")
int BPF_KPROBE(do_mov_3578)
{
    u64 addr = ctx->bx + 0xd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x1c1")
int BPF_KPROBE(do_mov_3579)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_masq_init+0x25")
int BPF_KPROBE(do_mov_3580)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_masq_init+0x7e")
int BPF_KPROBE(do_mov_3581)
{
    u64 addr = ctx->bx + 0xd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_masq_ipv4_eval+0x85")
int BPF_KPROBE(do_mov_3582)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_masq_ipv6_eval+0x82")
int BPF_KPROBE(do_mov_3583)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_redir_init+0x5c")
int BPF_KPROBE(do_mov_3584)
{
    u64 addr = ctx->r12 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_redir_init+0x84")
int BPF_KPROBE(do_mov_3585)
{
    u64 addr = ctx->r12 + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_redir_ipv4_eval+0x79")
int BPF_KPROBE(do_mov_3586)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_redir_ipv6_eval+0x8b")
int BPF_KPROBE(do_mov_3587)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_symhash_init+0x26")
int BPF_KPROBE(do_mov_3588)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_symhash_init+0x32")
int BPF_KPROBE(do_mov_3589)
{
    u64 addr = ctx->si + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_symhash_eval+0x34")
int BPF_KPROBE(do_mov_3590)
{
    u64 addr = ctx->r13 + ctx->dx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_jhash_init+0x66")
int BPF_KPROBE(do_mov_3591)
{
    u64 addr = ctx->si + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_jhash_init+0x8a")
int BPF_KPROBE(do_mov_3592)
{
    u64 addr = ctx->r13 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_jhash_init+0xa8")
int BPF_KPROBE(do_mov_3593)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_jhash_init+0xca")
int BPF_KPROBE(do_mov_3594)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_init+0x33")
int BPF_KPROBE(do_mov_3595)
{
    u64 addr = ctx->si + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_init+0x65")
int BPF_KPROBE(do_mov_3596)
{
    u64 addr = ctx->r8 + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_store_result+0x35")
int BPF_KPROBE(do_mov_3597)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_store_result+0x46")
int BPF_KPROBE(do_mov_3598)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_netdev_eval+0x66")
int BPF_KPROBE(do_mov_3599)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_init+0x31")
int BPF_KPROBE(do_mov_3600)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_init+0x55")
int BPF_KPROBE(do_mov_3601)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_init+0x8f")
int BPF_KPROBE(do_mov_3602)
{
    u64 addr = ctx->si + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_sock_get_eval_cgroupv2.constprop.0+0x4e")
int BPF_KPROBE(do_mov_3603)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0xbf")
int BPF_KPROBE(do_mov_3604)
{
    u64 addr = ctx->r14 + ctx->r8 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0xfc")
int BPF_KPROBE(do_mov_3605)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0x13a")
int BPF_KPROBE(do_mov_3606)
{
    u64 addr = ctx->r14 + ctx->r8 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0x142")
int BPF_KPROBE(do_mov_3607)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0x185")
int BPF_KPROBE(do_mov_3608)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0x1d0")
int BPF_KPROBE(do_mov_3609)
{
    u64 addr = ctx->r14 + ctx->r8 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0x20e")
int BPF_KPROBE(do_mov_3610)
{
    u64 addr = ctx->r14 + ctx->r8 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_osf_init+0x21")
int BPF_KPROBE(do_mov_3611)
{
    u64 addr = ctx->si + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_osf_init+0x36")
int BPF_KPROBE(do_mov_3612)
{
    u64 addr = ctx->si + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_osf_eval+0x37")
int BPF_KPROBE(do_mov_3613)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_osf_eval+0xc3")
int BPF_KPROBE(do_mov_3614)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_osf_eval+0xcc")
int BPF_KPROBE(do_mov_3615)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tproxy_init+0x34")
int BPF_KPROBE(do_mov_3616)
{
    u64 addr = ctx->r12 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tproxy_eval+0x61")
int BPF_KPROBE(do_mov_3617)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tproxy_eval+0x33e")
int BPF_KPROBE(do_mov_3618)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tproxy_eval+0x342")
int BPF_KPROBE(do_mov_3619)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_init+0x3e")
int BPF_KPROBE(do_mov_3620)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_init+0x66")
int BPF_KPROBE(do_mov_3621)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_init+0x82")
int BPF_KPROBE(do_mov_3622)
{
    u64 addr = ctx->si + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_init+0x89")
int BPF_KPROBE(do_mov_3623)
{
    u64 addr = ctx->si + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x34")
int BPF_KPROBE(do_mov_3624)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x77")
int BPF_KPROBE(do_mov_3625)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x7a")
int BPF_KPROBE(do_mov_3626)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x86")
int BPF_KPROBE(do_mov_3627)
{
    u64 addr = ctx->dx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x8e")
int BPF_KPROBE(do_mov_3628)
{
    u64 addr = ctx->dx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x96")
int BPF_KPROBE(do_mov_3629)
{
    u64 addr = ctx->dx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0xa9")
int BPF_KPROBE(do_mov_3630)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0xac")
int BPF_KPROBE(do_mov_3631)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0xb8")
int BPF_KPROBE(do_mov_3632)
{
    u64 addr = ctx->dx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_eval+0x1b")
int BPF_KPROBE(do_mov_3633)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_obj_update+0xc")
int BPF_KPROBE(do_mov_3634)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_init+0x4f")
int BPF_KPROBE(do_mov_3635)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_init+0x62")
int BPF_KPROBE(do_mov_3636)
{
    u64 addr = ctx->r15 + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_init+0x82")
int BPF_KPROBE(do_mov_3637)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x45")
int BPF_KPROBE(do_mov_3638)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x91")
int BPF_KPROBE(do_mov_3639)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x168")
int BPF_KPROBE(do_mov_3640)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x261")
int BPF_KPROBE(do_mov_3641)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x2bf")
int BPF_KPROBE(do_mov_3642)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_netdev_eval+0x2f")
int BPF_KPROBE(do_mov_3643)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_netdev_eval+0x4e")
int BPF_KPROBE(do_mov_3644)
{
    u64 addr = ctx->dx + 0x83;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_netdev_eval+0x63")
int BPF_KPROBE(do_mov_3645)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_netdev_eval+0x70")
int BPF_KPROBE(do_mov_3646)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_neigh_init+0x30")
int BPF_KPROBE(do_mov_3647)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_neigh_eval+0x4d")
int BPF_KPROBE(do_mov_3648)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_neigh_eval+0xee")
int BPF_KPROBE(do_mov_3649)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_neigh_eval+0x189")
int BPF_KPROBE(do_mov_3650)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_neigh_eval+0x18f")
int BPF_KPROBE(do_mov_3651)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x2e")
int BPF_KPROBE(do_mov_3652)
{
    u64 addr = ctx->r9 + 0x3a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x5e")
int BPF_KPROBE(do_mov_3653)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x62")
int BPF_KPROBE(do_mov_3654)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x6e")
int BPF_KPROBE(do_mov_3655)
{
    u64 addr = ctx->r9 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x72")
int BPF_KPROBE(do_mov_3656)
{
    u64 addr = ctx->r9 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x87")
int BPF_KPROBE(do_mov_3657)
{
    u64 addr = ctx->si + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x9b")
int BPF_KPROBE(do_mov_3658)
{
    u64 addr = ctx->si + 0x31;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0xc9")
int BPF_KPROBE(do_mov_3659)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0xd1")
int BPF_KPROBE(do_mov_3660)
{
    u64 addr = ctx->ax + 0x2a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0xdb")
int BPF_KPROBE(do_mov_3661)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0xe3")
int BPF_KPROBE(do_mov_3662)
{
    u64 addr = ctx->r9 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_teardown+0x6a")
int BPF_KPROBE(do_mov_3663)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_teardown+0x76")
int BPF_KPROBE(do_mov_3664)
{
    u64 addr = ctx->dx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_teardown+0x80")
int BPF_KPROBE(do_mov_3665)
{
    u64 addr = ctx->dx + 0xd4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_refresh+0x41")
int BPF_KPROBE(do_mov_3666)
{
    u64 addr = ctx->si + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_dnat_port+0x31")
int BPF_KPROBE(do_mov_3667)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_dnat_port+0xa4")
int BPF_KPROBE(do_mov_3668)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_dnat_port+0xcb")
int BPF_KPROBE(do_mov_3669)
{
    u64 addr = ctx->bx + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x28")
int BPF_KPROBE(do_mov_3670)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x3d")
int BPF_KPROBE(do_mov_3671)
{
    u64 addr = ctx->di - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x41")
int BPF_KPROBE(do_mov_3672)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x49")
int BPF_KPROBE(do_mov_3673)
{
    u64 addr = ctx->di - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x67")
int BPF_KPROBE(do_mov_3674)
{
    u64 addr = ctx->bx + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x75")
int BPF_KPROBE(do_mov_3675)
{
    u64 addr = ctx->bx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0xcc")
int BPF_KPROBE(do_mov_3676)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0xd0")
int BPF_KPROBE(do_mov_3677)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0xd3")
int BPF_KPROBE(do_mov_3678)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_pernet_init+0x20")
int BPF_KPROBE(do_mov_3679)
{
    u64 addr = ctx->bx + 0xc28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0xb8")
int BPF_KPROBE(do_mov_3680)
{
    u64 addr = ctx->r13 + ctx->dx * 0x8 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0xe3")
int BPF_KPROBE(do_mov_3681)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x107")
int BPF_KPROBE(do_mov_3682)
{
    u64 addr = ctx->ax + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x112")
int BPF_KPROBE(do_mov_3683)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x181")
int BPF_KPROBE(do_mov_3684)
{
    u64 addr = ctx->si + 0x3a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1a1")
int BPF_KPROBE(do_mov_3685)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1a8")
int BPF_KPROBE(do_mov_3686)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1b8")
int BPF_KPROBE(do_mov_3687)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1be")
int BPF_KPROBE(do_mov_3688)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1c5")
int BPF_KPROBE(do_mov_3689)
{
    u64 addr = ctx->si + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1cb")
int BPF_KPROBE(do_mov_3690)
{
    u64 addr = ctx->si + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1ed")
int BPF_KPROBE(do_mov_3691)
{
    u64 addr = ctx->cx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x2d4")
int BPF_KPROBE(do_mov_3692)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x2e2")
int BPF_KPROBE(do_mov_3693)
{
    u64 addr = ctx->r13 + ctx->ax * 0x8 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_route_init+0x3a")
int BPF_KPROBE(do_mov_3694)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_snat_port+0x32")
int BPF_KPROBE(do_mov_3695)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_snat_port+0xa5")
int BPF_KPROBE(do_mov_3696)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_snat_port+0xcb")
int BPF_KPROBE(do_mov_3697)
{
    u64 addr = ctx->bx + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_alloc+0x51")
int BPF_KPROBE(do_mov_3698)
{
    u64 addr = ctx->r12 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_add+0x53")
int BPF_KPROBE(do_mov_3699)
{
    u64 addr = ctx->r12 + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_add+0xc1")
int BPF_KPROBE(do_mov_3700)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_free+0x44")
int BPF_KPROBE(do_mov_3701)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_free+0x48")
int BPF_KPROBE(do_mov_3702)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_free+0x55")
int BPF_KPROBE(do_mov_3703)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_free+0x5d")
int BPF_KPROBE(do_mov_3704)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_tuple_encap+0x21")
int BPF_KPROBE(do_mov_3705)
{
    u64 addr = ctx->si + 0x2a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_tuple_encap+0x2c")
int BPF_KPROBE(do_mov_3706)
{
    u64 addr = ctx->si + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_tuple_encap+0x65")
int BPF_KPROBE(do_mov_3707)
{
    u64 addr = ctx->cx + ctx->dx * 0x4 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_tuple_encap+0x71")
int BPF_KPROBE(do_mov_3708)
{
    u64 addr = ctx->cx + ctx->dx * 0x4 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0x76")
int BPF_KPROBE(do_mov_3709)
{
    u64 addr = ctx->bx + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0x98")
int BPF_KPROBE(do_mov_3710)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0xc7")
int BPF_KPROBE(do_mov_3711)
{
    u64 addr = ctx->bx + 0x82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0xe1")
int BPF_KPROBE(do_mov_3712)
{
    u64 addr = ctx->bx + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0xed")
int BPF_KPROBE(do_mov_3713)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0x112")
int BPF_KPROBE(do_mov_3714)
{
    u64 addr = ctx->bx + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0x119")
int BPF_KPROBE(do_mov_3715)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_xmit_xfrm+0x22")
int BPF_KPROBE(do_mov_3716)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_xmit_xfrm+0x2b")
int BPF_KPROBE(do_mov_3717)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_xmit_xfrm+0x60")
int BPF_KPROBE(do_mov_3718)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_xmit_xfrm+0x6b")
int BPF_KPROBE(do_mov_3719)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_skb_encap_protocol.constprop.0+0x75")
int BPF_KPROBE(do_mov_3720)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_nat_ipv6_l4proto.constprop.0.isra.0+0x8c")
int BPF_KPROBE(do_mov_3721)
{
    u64 addr = ctx->bx + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_nat_ip_l4proto.isra.0+0x9a")
int BPF_KPROBE(do_mov_3722)
{
    u64 addr = ctx->bx + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_queue_xmit+0x29")
int BPF_KPROBE(do_mov_3723)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x3a1")
int BPF_KPROBE(do_mov_3724)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x3b0")
int BPF_KPROBE(do_mov_3725)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x4fd")
int BPF_KPROBE(do_mov_3726)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x538")
int BPF_KPROBE(do_mov_3727)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x549")
int BPF_KPROBE(do_mov_3728)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x5a8")
int BPF_KPROBE(do_mov_3729)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x5e7")
int BPF_KPROBE(do_mov_3730)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x686")
int BPF_KPROBE(do_mov_3731)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x6c9")
int BPF_KPROBE(do_mov_3732)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x6f3")
int BPF_KPROBE(do_mov_3733)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x706")
int BPF_KPROBE(do_mov_3734)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x71a")
int BPF_KPROBE(do_mov_3735)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x723")
int BPF_KPROBE(do_mov_3736)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x731")
int BPF_KPROBE(do_mov_3737)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x740")
int BPF_KPROBE(do_mov_3738)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x74a")
int BPF_KPROBE(do_mov_3739)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x364")
int BPF_KPROBE(do_mov_3740)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x4a7")
int BPF_KPROBE(do_mov_3741)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x4fa")
int BPF_KPROBE(do_mov_3742)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x50c")
int BPF_KPROBE(do_mov_3743)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x575")
int BPF_KPROBE(do_mov_3744)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x579")
int BPF_KPROBE(do_mov_3745)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x62f")
int BPF_KPROBE(do_mov_3746)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x633")
int BPF_KPROBE(do_mov_3747)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x677")
int BPF_KPROBE(do_mov_3748)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x67b")
int BPF_KPROBE(do_mov_3749)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6a5")
int BPF_KPROBE(do_mov_3750)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6a9")
int BPF_KPROBE(do_mov_3751)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6c3")
int BPF_KPROBE(do_mov_3752)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6cc")
int BPF_KPROBE(do_mov_3753)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6d5")
int BPF_KPROBE(do_mov_3754)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6e4")
int BPF_KPROBE(do_mov_3755)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6ef")
int BPF_KPROBE(do_mov_3756)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_redirect+0x48")
int BPF_KPROBE(do_mov_3757)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_redirect+0x61")
int BPF_KPROBE(do_mov_3758)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_redirect+0x68")
int BPF_KPROBE(do_mov_3759)
{
    u64 addr = ctx->dx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_mangle+0x5")
int BPF_KPROBE(do_mov_3760)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_mangle+0xb")
int BPF_KPROBE(do_mov_3761)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_mangle+0xe")
int BPF_KPROBE(do_mov_3762)
{
    u64 addr = ctx->di + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_mangle+0x15")
int BPF_KPROBE(do_mov_3763)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_mangle+0x1d")
int BPF_KPROBE(do_mov_3764)
{
    u64 addr = ctx->di + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_tuple+0x110")
int BPF_KPROBE(do_mov_3765)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_tuple+0x11a")
int BPF_KPROBE(do_mov_3766)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_tuple+0x125")
int BPF_KPROBE(do_mov_3767)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_tuple+0x12d")
int BPF_KPROBE(do_mov_3768)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_tuple+0x135")
int BPF_KPROBE(do_mov_3769)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x47")
int BPF_KPROBE(do_mov_3770)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x55")
int BPF_KPROBE(do_mov_3771)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x59")
int BPF_KPROBE(do_mov_3772)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x5d")
int BPF_KPROBE(do_mov_3773)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x61")
int BPF_KPROBE(do_mov_3774)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x65")
int BPF_KPROBE(do_mov_3775)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x69")
int BPF_KPROBE(do_mov_3776)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x3c")
int BPF_KPROBE(do_mov_3777)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x40")
int BPF_KPROBE(do_mov_3778)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x60")
int BPF_KPROBE(do_mov_3779)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x65")
int BPF_KPROBE(do_mov_3780)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x6a")
int BPF_KPROBE(do_mov_3781)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x6e")
int BPF_KPROBE(do_mov_3782)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x71")
int BPF_KPROBE(do_mov_3783)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x75")
int BPF_KPROBE(do_mov_3784)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_port_dnat.constprop.0+0x2c")
int BPF_KPROBE(do_mov_3785)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_port_snat.constprop.0+0x2c")
int BPF_KPROBE(do_mov_3786)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x50")
int BPF_KPROBE(do_mov_3787)
{
    u64 addr = ctx->r12 + 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x61")
int BPF_KPROBE(do_mov_3788)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x74")
int BPF_KPROBE(do_mov_3789)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x85")
int BPF_KPROBE(do_mov_3790)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0xaf")
int BPF_KPROBE(do_mov_3791)
{
    u64 addr = ctx->r12 + 0x36;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0xba")
int BPF_KPROBE(do_mov_3792)
{
    u64 addr = ctx->r12 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0xca")
int BPF_KPROBE(do_mov_3793)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0xd4")
int BPF_KPROBE(do_mov_3794)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0xfc")
int BPF_KPROBE(do_mov_3795)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x107")
int BPF_KPROBE(do_mov_3796)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x185")
int BPF_KPROBE(do_mov_3797)
{
    u64 addr = ctx->r12 + 0x52;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x18b")
int BPF_KPROBE(do_mov_3798)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x199")
int BPF_KPROBE(do_mov_3799)
{
    u64 addr = ctx->r12 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x1a5")
int BPF_KPROBE(do_mov_3800)
{
    u64 addr = ctx->r12 + 0x74;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x1aa")
int BPF_KPROBE(do_mov_3801)
{
    u64 addr = ctx->r12 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x1af")
int BPF_KPROBE(do_mov_3802)
{
    u64 addr = ctx->r12 + 0xf4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x1c3")
int BPF_KPROBE(do_mov_3803)
{
    u64 addr = ctx->r12 + 0xfc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x1cf")
int BPF_KPROBE(do_mov_3804)
{
    u64 addr = ctx->r12 + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x1d7")
int BPF_KPROBE(do_mov_3805)
{
    u64 addr = ctx->r12 + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x1e3")
int BPF_KPROBE(do_mov_3806)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x208")
int BPF_KPROBE(do_mov_3807)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x20c")
int BPF_KPROBE(do_mov_3808)
{
    u64 addr = ctx->r12 + 0xca;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x21a")
int BPF_KPROBE(do_mov_3809)
{
    u64 addr = ctx->r12 + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x286")
int BPF_KPROBE(do_mov_3810)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2af")
int BPF_KPROBE(do_mov_3811)
{
    u64 addr = ctx->r12 + 0x6e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2b7")
int BPF_KPROBE(do_mov_3812)
{
    u64 addr = ctx->r12 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2cf")
int BPF_KPROBE(do_mov_3813)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2d8")
int BPF_KPROBE(do_mov_3814)
{
    u64 addr = ctx->r12 + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2e1")
int BPF_KPROBE(do_mov_3815)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2e9")
int BPF_KPROBE(do_mov_3816)
{
    u64 addr = ctx->r12 + 0x62;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2f0")
int BPF_KPROBE(do_mov_3817)
{
    u64 addr = ctx->r12 + 0xda;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2ff")
int BPF_KPROBE(do_mov_3818)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x337")
int BPF_KPROBE(do_mov_3819)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x372")
int BPF_KPROBE(do_mov_3820)
{
    u64 addr = ctx->r12 + 0x36;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x378")
int BPF_KPROBE(do_mov_3821)
{
    u64 addr = ctx->r12 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x37e")
int BPF_KPROBE(do_mov_3822)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x383")
int BPF_KPROBE(do_mov_3823)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x3be")
int BPF_KPROBE(do_mov_3824)
{
    u64 addr = ctx->r12 + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x3c4")
int BPF_KPROBE(do_mov_3825)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x3cd")
int BPF_KPROBE(do_mov_3826)
{
    u64 addr = ctx->r12 + 0x10c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x3d9")
int BPF_KPROBE(do_mov_3827)
{
    u64 addr = ctx->r12 + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x402")
int BPF_KPROBE(do_mov_3828)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x40a")
int BPF_KPROBE(do_mov_3829)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x41a")
int BPF_KPROBE(do_mov_3830)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x422")
int BPF_KPROBE(do_mov_3831)
{
    u64 addr = ctx->r12 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x438")
int BPF_KPROBE(do_mov_3832)
{
    u64 addr = ctx->r12 + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x444")
int BPF_KPROBE(do_mov_3833)
{
    u64 addr = ctx->r12 + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x460")
int BPF_KPROBE(do_mov_3834)
{
    u64 addr = ctx->r12 + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x46c")
int BPF_KPROBE(do_mov_3835)
{
    u64 addr = ctx->r12 + 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x486")
int BPF_KPROBE(do_mov_3836)
{
    u64 addr = ctx->r12 + 0x5a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x49e")
int BPF_KPROBE(do_mov_3837)
{
    u64 addr = ctx->r12 + 0x52;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x4a9")
int BPF_KPROBE(do_mov_3838)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x4b2")
int BPF_KPROBE(do_mov_3839)
{
    u64 addr = ctx->r12 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x4be")
int BPF_KPROBE(do_mov_3840)
{
    u64 addr = ctx->r12 + 0x74;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x4c6")
int BPF_KPROBE(do_mov_3841)
{
    u64 addr = ctx->r12 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x4d2")
int BPF_KPROBE(do_mov_3842)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x4fc")
int BPF_KPROBE(do_mov_3843)
{
    u64 addr = ctx->r12 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x50a")
int BPF_KPROBE(do_mov_3844)
{
    u64 addr = ctx->r12 + 0x134;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x517")
int BPF_KPROBE(do_mov_3845)
{
    u64 addr = ctx->r12 + 0x136;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x520")
int BPF_KPROBE(do_mov_3846)
{
    u64 addr = ctx->r12 + 0xbe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x529")
int BPF_KPROBE(do_mov_3847)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x53c")
int BPF_KPROBE(do_mov_3848)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x565")
int BPF_KPROBE(do_mov_3849)
{
    u64 addr = ctx->r12 + 0x66;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x56d")
int BPF_KPROBE(do_mov_3850)
{
    u64 addr = ctx->r12 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x57d")
int BPF_KPROBE(do_mov_3851)
{
    u64 addr = ctx->r12 + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x586")
int BPF_KPROBE(do_mov_3852)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x591")
int BPF_KPROBE(do_mov_3853)
{
    u64 addr = ctx->r12 + 0x9c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x59d")
int BPF_KPROBE(do_mov_3854)
{
    u64 addr = ctx->r12 + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x5ad")
int BPF_KPROBE(do_mov_3855)
{
    u64 addr = ctx->r12 + 0x114;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x5cd")
int BPF_KPROBE(do_mov_3856)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x5f6")
int BPF_KPROBE(do_mov_3857)
{
    u64 addr = ctx->r12 + 0x66;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x5fe")
int BPF_KPROBE(do_mov_3858)
{
    u64 addr = ctx->r12 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0xbe")
int BPF_KPROBE(do_mov_3859)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0xe3")
int BPF_KPROBE(do_mov_3860)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x1a3")
int BPF_KPROBE(do_mov_3861)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x1b7")
int BPF_KPROBE(do_mov_3862)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x2be")
int BPF_KPROBE(do_mov_3863)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x2d8")
int BPF_KPROBE(do_mov_3864)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x323")
int BPF_KPROBE(do_mov_3865)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x35f")
int BPF_KPROBE(do_mov_3866)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x36c")
int BPF_KPROBE(do_mov_3867)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x3be")
int BPF_KPROBE(do_mov_3868)
{
    u64 addr = ctx->r9 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x3cc")
int BPF_KPROBE(do_mov_3869)
{
    u64 addr = ctx->r9 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x3d7")
int BPF_KPROBE(do_mov_3870)
{
    u64 addr = ctx->r9 + 0x42;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x54c")
int BPF_KPROBE(do_mov_3871)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x565")
int BPF_KPROBE(do_mov_3872)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x57f")
int BPF_KPROBE(do_mov_3873)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x598")
int BPF_KPROBE(do_mov_3874)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x59f")
int BPF_KPROBE(do_mov_3875)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0x81")
int BPF_KPROBE(do_mov_3876)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0x9a")
int BPF_KPROBE(do_mov_3877)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0xb6")
int BPF_KPROBE(do_mov_3878)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0xfe")
int BPF_KPROBE(do_mov_3879)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0x11c")
int BPF_KPROBE(do_mov_3880)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0x197")
int BPF_KPROBE(do_mov_3881)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_work_handler+0x272")
int BPF_KPROBE(do_mov_3882)
{
    u64 addr = ctx->dx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv6+0xc0")
int BPF_KPROBE(do_mov_3883)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv6+0x138")
int BPF_KPROBE(do_mov_3884)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x172")
int BPF_KPROBE(do_mov_3885)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x176")
int BPF_KPROBE(do_mov_3886)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x179")
int BPF_KPROBE(do_mov_3887)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x17d")
int BPF_KPROBE(do_mov_3888)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x28e")
int BPF_KPROBE(do_mov_3889)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x292")
int BPF_KPROBE(do_mov_3890)
{
    u64 addr = ctx->bx + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x299")
int BPF_KPROBE(do_mov_3891)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x29c")
int BPF_KPROBE(do_mov_3892)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_target+0x42")
int BPF_KPROBE(do_mov_3893)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_target+0x46")
int BPF_KPROBE(do_mov_3894)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_target+0x4e")
int BPF_KPROBE(do_mov_3895)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_target+0x53")
int BPF_KPROBE(do_mov_3896)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_target+0x41")
int BPF_KPROBE(do_mov_3897)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_target+0x48")
int BPF_KPROBE(do_mov_3898)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_target+0x55")
int BPF_KPROBE(do_mov_3899)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_target+0x5d")
int BPF_KPROBE(do_mov_3900)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_match+0x42")
int BPF_KPROBE(do_mov_3901)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_match+0x46")
int BPF_KPROBE(do_mov_3902)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_match+0x4e")
int BPF_KPROBE(do_mov_3903)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_match+0x53")
int BPF_KPROBE(do_mov_3904)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_match+0x41")
int BPF_KPROBE(do_mov_3905)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_match+0x48")
int BPF_KPROBE(do_mov_3906)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_match+0x55")
int BPF_KPROBE(do_mov_3907)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_match+0x5d")
int BPF_KPROBE(do_mov_3908)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/target_revfn+0x85")
int BPF_KPROBE(do_mov_3909)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/match_revfn+0x85")
int BPF_KPROBE(do_mov_3910)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_find_revision+0x48")
int BPF_KPROBE(do_mov_3911)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_find_revision+0x64")
int BPF_KPROBE(do_mov_3912)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_find_revision+0x7e")
int BPF_KPROBE(do_mov_3913)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_add_offset+0x50")
int BPF_KPROBE(do_mov_3914)
{
    u64 addr = ctx->dx + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_add_offset+0x5b")
int BPF_KPROBE(do_mov_3915)
{
    u64 addr = ctx->ax + ctx->dx * 0x8 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_flush_offsets+0x51")
int BPF_KPROBE(do_mov_3916)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_flush_offsets+0x59")
int BPF_KPROBE(do_mov_3917)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_init_offsets+0x77")
int BPF_KPROBE(do_mov_3918)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_init_offsets+0x82")
int BPF_KPROBE(do_mov_3919)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_init_offsets+0x88")
int BPF_KPROBE(do_mov_3920)
{
    u64 addr = ctx->bx + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_from_user+0x63")
int BPF_KPROBE(do_mov_3921)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_from_user+0x6b")
int BPF_KPROBE(do_mov_3922)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_from_user+0x74")
int BPF_KPROBE(do_mov_3923)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_from_user+0x82")
int BPF_KPROBE(do_mov_3924)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_from_user+0xa2")
int BPF_KPROBE(do_mov_3925)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_from_user+0x63")
int BPF_KPROBE(do_mov_3926)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_from_user+0x6b")
int BPF_KPROBE(do_mov_3927)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_from_user+0x74")
int BPF_KPROBE(do_mov_3928)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_from_user+0x82")
int BPF_KPROBE(do_mov_3929)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_from_user+0xa2")
int BPF_KPROBE(do_mov_3930)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_alloc_table_info+0x3c")
int BPF_KPROBE(do_mov_3931)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_alloc_table_info+0x47")
int BPF_KPROBE(do_mov_3932)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_alloc_table_info+0x5d")
int BPF_KPROBE(do_mov_3933)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_net_init+0x35")
int BPF_KPROBE(do_mov_3934)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_net_init+0x38")
int BPF_KPROBE(do_mov_3935)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_table+0x3d")
int BPF_KPROBE(do_mov_3936)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_table+0x41")
int BPF_KPROBE(do_mov_3937)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_table+0x4e")
int BPF_KPROBE(do_mov_3938)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_table+0x56")
int BPF_KPROBE(do_mov_3939)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_template+0x9d")
int BPF_KPROBE(do_mov_3940)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_template+0xa4")
int BPF_KPROBE(do_mov_3941)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_template+0xb1")
int BPF_KPROBE(do_mov_3942)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_template+0xb9")
int BPF_KPROBE(do_mov_3943)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x29")
int BPF_KPROBE(do_mov_3944)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x32")
int BPF_KPROBE(do_mov_3945)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x45")
int BPF_KPROBE(do_mov_3946)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x4d")
int BPF_KPROBE(do_mov_3947)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x6a")
int BPF_KPROBE(do_mov_3948)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/textify_hooks.constprop.0+0x45")
int BPF_KPROBE(do_mov_3949)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x4c")
int BPF_KPROBE(do_mov_3950)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x62")
int BPF_KPROBE(do_mov_3951)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x85")
int BPF_KPROBE(do_mov_3952)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x89")
int BPF_KPROBE(do_mov_3953)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x9d")
int BPF_KPROBE(do_mov_3954)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0xf6")
int BPF_KPROBE(do_mov_3955)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0xfa")
int BPF_KPROBE(do_mov_3956)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x104")
int BPF_KPROBE(do_mov_3957)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_target_seq_start+0x14")
int BPF_KPROBE(do_mov_3958)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_to_user+0xbc")
int BPF_KPROBE(do_mov_3959)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_to_user+0xbc")
int BPF_KPROBE(do_mov_3960)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x12a")
int BPF_KPROBE(do_mov_3961)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x132")
int BPF_KPROBE(do_mov_3962)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x145")
int BPF_KPROBE(do_mov_3963)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x149")
int BPF_KPROBE(do_mov_3964)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x150")
int BPF_KPROBE(do_mov_3965)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x153")
int BPF_KPROBE(do_mov_3966)
{
    u64 addr = ctx->bx - 0x7c6ee740;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_match_seq_start+0x14")
int BPF_KPROBE(do_mov_3967)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_hook_ops_alloc+0x76")
int BPF_KPROBE(do_mov_3968)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_hook_ops_alloc+0x79")
int BPF_KPROBE(do_mov_3969)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_hook_ops_alloc+0x80")
int BPF_KPROBE(do_mov_3970)
{
    u64 addr = ctx->dx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_hook_ops_alloc+0x88")
int BPF_KPROBE(do_mov_3971)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_matches+0x80")
int BPF_KPROBE(do_mov_3972)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_matches+0x87")
int BPF_KPROBE(do_mov_3973)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_matches+0x8a")
int BPF_KPROBE(do_mov_3974)
{
    u64 addr = ctx->r13 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_matches+0x91")
int BPF_KPROBE(do_mov_3975)
{
    u64 addr = ctx->r13 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_matches+0x58")
int BPF_KPROBE(do_mov_3976)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_matches+0x5c")
int BPF_KPROBE(do_mov_3977)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_matches+0x64")
int BPF_KPROBE(do_mov_3978)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_matches+0x68")
int BPF_KPROBE(do_mov_3979)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_targets+0x80")
int BPF_KPROBE(do_mov_3980)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_targets+0x87")
int BPF_KPROBE(do_mov_3981)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_targets+0x8a")
int BPF_KPROBE(do_mov_3982)
{
    u64 addr = ctx->r13 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_targets+0x91")
int BPF_KPROBE(do_mov_3983)
{
    u64 addr = ctx->r13 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_targets+0x58")
int BPF_KPROBE(do_mov_3984)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_targets+0x5c")
int BPF_KPROBE(do_mov_3985)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_targets+0x64")
int BPF_KPROBE(do_mov_3986)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_targets+0x68")
int BPF_KPROBE(do_mov_3987)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0x4c")
int BPF_KPROBE(do_mov_3988)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0x96")
int BPF_KPROBE(do_mov_3989)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0xf0")
int BPF_KPROBE(do_mov_3990)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0xf8")
int BPF_KPROBE(do_mov_3991)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0x1bd")
int BPF_KPROBE(do_mov_3992)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0x1df")
int BPF_KPROBE(do_mov_3993)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x13c")
int BPF_KPROBE(do_mov_3994)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x158")
int BPF_KPROBE(do_mov_3995)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x173")
int BPF_KPROBE(do_mov_3996)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x177")
int BPF_KPROBE(do_mov_3997)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x17c")
int BPF_KPROBE(do_mov_3998)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x180")
int BPF_KPROBE(do_mov_3999)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xc8")
int BPF_KPROBE(do_mov_4000)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xd0")
int BPF_KPROBE(do_mov_4001)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xd9")
int BPF_KPROBE(do_mov_4002)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xe1")
int BPF_KPROBE(do_mov_4003)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xe9")
int BPF_KPROBE(do_mov_4004)
{
    u64 addr = ctx->cx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xf2")
int BPF_KPROBE(do_mov_4005)
{
    u64 addr = ctx->cx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xf9")
int BPF_KPROBE(do_mov_4006)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0x110")
int BPF_KPROBE(do_mov_4007)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0x118")
int BPF_KPROBE(do_mov_4008)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0x121")
int BPF_KPROBE(do_mov_4009)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0x12a")
int BPF_KPROBE(do_mov_4010)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0x133")
int BPF_KPROBE(do_mov_4011)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0x13c")
int BPF_KPROBE(do_mov_4012)
{
    u64 addr = ctx->cx + 0x1f;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_mt+0x1b5")
int BPF_KPROBE(do_mov_4013)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_mt+0xbd")
int BPF_KPROBE(do_mov_4014)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mark_tg+0x1b")
int BPF_KPROBE(do_mov_4015)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/connmark_tg_shift+0x72")
int BPF_KPROBE(do_mov_4016)
{
    u64 addr = ctx->si + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/connmark_tg_shift+0xd9")
int BPF_KPROBE(do_mov_4017)
{
    u64 addr = ctx->dx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/connmark_tg_shift+0x11e")
int BPF_KPROBE(do_mov_4018)
{
    u64 addr = ctx->si + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/compat_flags+0x6")
int BPF_KPROBE(do_mov_4019)
{
    u64 addr = ctx->di + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/compat_flags+0x35")
int BPF_KPROBE(do_mov_4020)
{
    u64 addr = ctx->di + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_target_v3+0x192")
int BPF_KPROBE(do_mov_4021)
{
    u64 addr = ctx->r13 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_target_v3+0x1a1")
int BPF_KPROBE(do_mov_4022)
{
    u64 addr = ctx->r13 + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_target_v3+0x1ce")
int BPF_KPROBE(do_mov_4023)
{
    u64 addr = ctx->r13 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/classify_tg+0xf")
int BPF_KPROBE(do_mov_4024)
{
    u64 addr = ctx->di + 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/connsecmark_tg+0x36")
int BPF_KPROBE(do_mov_4025)
{
    u64 addr = ctx->di + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/connsecmark_tg+0x62")
int BPF_KPROBE(do_mov_4026)
{
    u64 addr = ctx->ax + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_destroy+0x35")
int BPF_KPROBE(do_mov_4027)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_destroy+0x39")
int BPF_KPROBE(do_mov_4028)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_destroy+0x46")
int BPF_KPROBE(do_mov_4029)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_destroy+0x4e")
int BPF_KPROBE(do_mov_4030)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0x71")
int BPF_KPROBE(do_mov_4031)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0xae")
int BPF_KPROBE(do_mov_4032)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0xbc")
int BPF_KPROBE(do_mov_4033)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0xca")
int BPF_KPROBE(do_mov_4034)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0xfa")
int BPF_KPROBE(do_mov_4035)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0x109")
int BPF_KPROBE(do_mov_4036)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0x10e")
int BPF_KPROBE(do_mov_4037)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_put+0x46")
int BPF_KPROBE(do_mov_4038)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_put+0x4e")
int BPF_KPROBE(do_mov_4039)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_put+0x60")
int BPF_KPROBE(do_mov_4040)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_put+0x68")
int BPF_KPROBE(do_mov_4041)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_net_init+0x45")
int BPF_KPROBE(do_mov_4042)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_net_init+0x4f")
int BPF_KPROBE(do_mov_4043)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0xa8")
int BPF_KPROBE(do_mov_4044)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x189")
int BPF_KPROBE(do_mov_4045)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x192")
int BPF_KPROBE(do_mov_4046)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1a2")
int BPF_KPROBE(do_mov_4047)
{
    u64 addr = ctx->r12 + 0x39;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1bf")
int BPF_KPROBE(do_mov_4048)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1e5")
int BPF_KPROBE(do_mov_4049)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1ef")
int BPF_KPROBE(do_mov_4050)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1f3")
int BPF_KPROBE(do_mov_4051)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1f9")
int BPF_KPROBE(do_mov_4052)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/secmark_tg_check+0x72")
int BPF_KPROBE(do_mov_4053)
{
    u64 addr = ctx->bx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/secmark_tg_check+0x89")
int BPF_KPROBE(do_mov_4054)
{
    u64 addr = ctx->bx + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/secmark_tg_v1+0x1d")
int BPF_KPROBE(do_mov_4055)
{
    u64 addr = ctx->di + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/secmark_tg_v0+0x19")
int BPF_KPROBE(do_mov_4056)
{
    u64 addr = ctx->di + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/secmark_tg_check_v0+0x65")
int BPF_KPROBE(do_mov_4057)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/secmark_tg_check_v0+0x7b")
int BPF_KPROBE(do_mov_4058)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x13a")
int BPF_KPROBE(do_mov_4059)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x142")
int BPF_KPROBE(do_mov_4060)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x25e")
int BPF_KPROBE(do_mov_4061)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x268")
int BPF_KPROBE(do_mov_4062)
{
    u64 addr = ctx->bx + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x293")
int BPF_KPROBE(do_mov_4063)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_tg6+0xa1")
int BPF_KPROBE(do_mov_4064)
{
    u64 addr = ctx->cx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_tg6+0xe0")
int BPF_KPROBE(do_mov_4065)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_tg4+0x77")
int BPF_KPROBE(do_mov_4066)
{
    u64 addr = ctx->si + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_tg4+0x86")
int BPF_KPROBE(do_mov_4067)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy_v1+0x4a")
int BPF_KPROBE(do_mov_4068)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy_v1+0x4e")
int BPF_KPROBE(do_mov_4069)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy_v1+0x5b")
int BPF_KPROBE(do_mov_4070)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy_v1+0x5e")
int BPF_KPROBE(do_mov_4071)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy+0x4a")
int BPF_KPROBE(do_mov_4072)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy+0x4e")
int BPF_KPROBE(do_mov_4073)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy+0x5b")
int BPF_KPROBE(do_mov_4074)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy+0x5e")
int BPF_KPROBE(do_mov_4075)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x8e")
int BPF_KPROBE(do_mov_4076)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x17f")
int BPF_KPROBE(do_mov_4077)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x19e")
int BPF_KPROBE(do_mov_4078)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x1ce")
int BPF_KPROBE(do_mov_4079)
{
    u64 addr = ctx->bx + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x1ef")
int BPF_KPROBE(do_mov_4080)
{
    u64 addr = ctx->di + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x202")
int BPF_KPROBE(do_mov_4081)
{
    u64 addr = ctx->ax + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x240")
int BPF_KPROBE(do_mov_4082)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x244")
int BPF_KPROBE(do_mov_4083)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x247")
int BPF_KPROBE(do_mov_4084)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x270")
int BPF_KPROBE(do_mov_4085)
{
    u64 addr = ctx->ax + 0xfc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x27b")
int BPF_KPROBE(do_mov_4086)
{
    u64 addr = ctx->ax + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x28a")
int BPF_KPROBE(do_mov_4087)
{
    u64 addr = ctx->ax + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x29d")
int BPF_KPROBE(do_mov_4088)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x2a4")
int BPF_KPROBE(do_mov_4089)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x2b0")
int BPF_KPROBE(do_mov_4090)
{
    u64 addr = ctx->ax + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x2e7")
int BPF_KPROBE(do_mov_4091)
{
    u64 addr = ctx->ax + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x73")
int BPF_KPROBE(do_mov_4092)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x107")
int BPF_KPROBE(do_mov_4093)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x125")
int BPF_KPROBE(do_mov_4094)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x153")
int BPF_KPROBE(do_mov_4095)
{
    u64 addr = ctx->bx + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x173")
int BPF_KPROBE(do_mov_4096)
{
    u64 addr = ctx->di + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x185")
int BPF_KPROBE(do_mov_4097)
{
    u64 addr = ctx->ax + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x1bf")
int BPF_KPROBE(do_mov_4098)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x1c3")
int BPF_KPROBE(do_mov_4099)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x1c8")
int BPF_KPROBE(do_mov_4100)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x1f5")
int BPF_KPROBE(do_mov_4101)
{
    u64 addr = ctx->ax + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x203")
int BPF_KPROBE(do_mov_4102)
{
    u64 addr = ctx->ax + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x215")
int BPF_KPROBE(do_mov_4103)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x21c")
int BPF_KPROBE(do_mov_4104)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x227")
int BPF_KPROBE(do_mov_4105)
{
    u64 addr = ctx->ax + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xbc")
int BPF_KPROBE(do_mov_4106)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xc4")
int BPF_KPROBE(do_mov_4107)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xcb")
int BPF_KPROBE(do_mov_4108)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xd5")
int BPF_KPROBE(do_mov_4109)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xf4")
int BPF_KPROBE(do_mov_4110)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xfc")
int BPF_KPROBE(do_mov_4111)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_check_v1+0x73")
int BPF_KPROBE(do_mov_4112)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_check_v1+0xf8")
int BPF_KPROBE(do_mov_4113)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_cluster_mt+0xc8")
int BPF_KPROBE(do_mov_4114)
{
    u64 addr = ctx->ax + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/connlimit_mt_check+0x33")
int BPF_KPROBE(do_mov_4115)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/connlimit_mt+0xe4")
int BPF_KPROBE(do_mov_4116)
{
    u64 addr = ctx->r13 + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_mt+0x220")
int BPF_KPROBE(do_mov_4117)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_mt+0x273")
int BPF_KPROBE(do_mov_4118)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/esp_mt+0x101")
int BPF_KPROBE(do_mov_4119)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/helper_mt_check+0x25")
int BPF_KPROBE(do_mov_4120)
{
    u64 addr = ctx->r13 + 0x21;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/comp_mt+0x10b")
int BPF_KPROBE(do_mov_4121)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x47")
int BPF_KPROBE(do_mov_4122)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x51")
int BPF_KPROBE(do_mov_4123)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x5d")
int BPF_KPROBE(do_mov_4124)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x65")
int BPF_KPROBE(do_mov_4125)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x69")
int BPF_KPROBE(do_mov_4126)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_check+0x89")
int BPF_KPROBE(do_mov_4127)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_check+0x8d")
int BPF_KPROBE(do_mov_4128)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_check+0xb1")
int BPF_KPROBE(do_mov_4129)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_check+0xbf")
int BPF_KPROBE(do_mov_4130)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_check+0xdc")
int BPF_KPROBE(do_mov_4131)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiport_mt+0x1f1")
int BPF_KPROBE(do_mov_4132)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfacct_mt_checkentry+0x1f")
int BPF_KPROBE(do_mov_4133)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v2+0x3f")
int BPF_KPROBE(do_mov_4134)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v2+0x5e")
int BPF_KPROBE(do_mov_4135)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v2+0x6f")
int BPF_KPROBE(do_mov_4136)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v1+0x3f")
int BPF_KPROBE(do_mov_4137)
{
    u64 addr = ctx->bx + 0x1008;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v1+0x5e")
int BPF_KPROBE(do_mov_4138)
{
    u64 addr = ctx->bx + 0x1008;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v1+0x6f")
int BPF_KPROBE(do_mov_4139)
{
    u64 addr = ctx->bx + 0x1008;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/quota_mt+0x3a")
int BPF_KPROBE(do_mov_4140)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/quota_mt_check+0x2c")
int BPF_KPROBE(do_mov_4141)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/quota_mt_check+0x35")
int BPF_KPROBE(do_mov_4142)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/quota_mt_check+0x43")
int BPF_KPROBE(do_mov_4143)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_mt_checkentry+0x55")
int BPF_KPROBE(do_mov_4144)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_mt_checkentry+0x59")
int BPF_KPROBE(do_mov_4145)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_seq_start+0x2b")
int BPF_KPROBE(do_mov_4146)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_seq_start+0x6c")
int BPF_KPROBE(do_mov_4147)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_seq_next+0x5d")
int BPF_KPROBE(do_mov_4148)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_seq_open+0x2d")
int BPF_KPROBE(do_mov_4149)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_net_init+0x2b")
int BPF_KPROBE(do_mov_4150)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_net_init+0x2f")
int BPF_KPROBE(do_mov_4151)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_net_init+0x67")
int BPF_KPROBE(do_mov_4152)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_net_exit+0x57")
int BPF_KPROBE(do_mov_4153)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x63")
int BPF_KPROBE(do_mov_4154)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x67")
int BPF_KPROBE(do_mov_4155)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x72")
int BPF_KPROBE(do_mov_4156)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x75")
int BPF_KPROBE(do_mov_4157)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x79")
int BPF_KPROBE(do_mov_4158)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x7d")
int BPF_KPROBE(do_mov_4159)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x80")
int BPF_KPROBE(do_mov_4160)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x84")
int BPF_KPROBE(do_mov_4161)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x257")
int BPF_KPROBE(do_mov_4162)
{
    u64 addr = ctx->r15 + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x262")
int BPF_KPROBE(do_mov_4163)
{
    u64 addr = ctx->r15 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x270")
int BPF_KPROBE(do_mov_4164)
{
    u64 addr = ctx->r15 + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x277")
int BPF_KPROBE(do_mov_4165)
{
    u64 addr = ctx->r15 + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x2bc")
int BPF_KPROBE(do_mov_4166)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x2d5")
int BPF_KPROBE(do_mov_4167)
{
    u64 addr = ctx->r15 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x2dc")
int BPF_KPROBE(do_mov_4168)
{
    u64 addr = ctx->r15 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x2fd")
int BPF_KPROBE(do_mov_4169)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x300")
int BPF_KPROBE(do_mov_4170)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x390")
int BPF_KPROBE(do_mov_4171)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x39c")
int BPF_KPROBE(do_mov_4172)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x39f")
int BPF_KPROBE(do_mov_4173)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x3a3")
int BPF_KPROBE(do_mov_4174)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x3e2")
int BPF_KPROBE(do_mov_4175)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x3f2")
int BPF_KPROBE(do_mov_4176)
{
    u64 addr = ctx->si + ctx->dx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x40d")
int BPF_KPROBE(do_mov_4177)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x448")
int BPF_KPROBE(do_mov_4178)
{
    u64 addr = ctx->r15 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x498")
int BPF_KPROBE(do_mov_4179)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x4a5")
int BPF_KPROBE(do_mov_4180)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x4ba")
int BPF_KPROBE(do_mov_4181)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check_v0+0x5b")
int BPF_KPROBE(do_mov_4182)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_destroy+0xb1")
int BPF_KPROBE(do_mov_4183)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_destroy+0xb5")
int BPF_KPROBE(do_mov_4184)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_destroy+0xc2")
int BPF_KPROBE(do_mov_4185)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_destroy+0xca")
int BPF_KPROBE(do_mov_4186)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x62")
int BPF_KPROBE(do_mov_4187)
{
    u64 addr = ctx->ax + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x70")
int BPF_KPROBE(do_mov_4188)
{
    u64 addr = ctx->ax + 0x33;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x74")
int BPF_KPROBE(do_mov_4189)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x7d")
int BPF_KPROBE(do_mov_4190)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x88")
int BPF_KPROBE(do_mov_4191)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x92")
int BPF_KPROBE(do_mov_4192)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x96")
int BPF_KPROBE(do_mov_4193)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x10a")
int BPF_KPROBE(do_mov_4194)
{
    u64 addr = ctx->dx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x119")
int BPF_KPROBE(do_mov_4195)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x11c")
int BPF_KPROBE(do_mov_4196)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x120")
int BPF_KPROBE(do_mov_4197)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x135")
int BPF_KPROBE(do_mov_4198)
{
    u64 addr = ctx->bx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x13c")
int BPF_KPROBE(do_mov_4199)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x140")
int BPF_KPROBE(do_mov_4200)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x144")
int BPF_KPROBE(do_mov_4201)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x224")
int BPF_KPROBE(do_mov_4202)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x22e")
int BPF_KPROBE(do_mov_4203)
{
    u64 addr = ctx->cx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x235")
int BPF_KPROBE(do_mov_4204)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x239")
int BPF_KPROBE(do_mov_4205)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x254")
int BPF_KPROBE(do_mov_4206)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x258")
int BPF_KPROBE(do_mov_4207)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x277")
int BPF_KPROBE(do_mov_4208)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x27a")
int BPF_KPROBE(do_mov_4209)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x27e")
int BPF_KPROBE(do_mov_4210)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x282")
int BPF_KPROBE(do_mov_4211)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x285")
int BPF_KPROBE(do_mov_4212)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x289")
int BPF_KPROBE(do_mov_4213)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x18c")
int BPF_KPROBE(do_mov_4214)
{
    u64 addr = ctx->di + 0x33;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x192")
int BPF_KPROBE(do_mov_4215)
{
    u64 addr = ctx->di + ctx->ax * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x19d")
int BPF_KPROBE(do_mov_4216)
{
    u64 addr = ctx->di + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1b4")
int BPF_KPROBE(do_mov_4217)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1b8")
int BPF_KPROBE(do_mov_4218)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1bf")
int BPF_KPROBE(do_mov_4219)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1c3")
int BPF_KPROBE(do_mov_4220)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1c7")
int BPF_KPROBE(do_mov_4221)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1cb")
int BPF_KPROBE(do_mov_4222)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1e3")
int BPF_KPROBE(do_mov_4223)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x228")
int BPF_KPROBE(do_mov_4224)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x22c")
int BPF_KPROBE(do_mov_4225)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x24b")
int BPF_KPROBE(do_mov_4226)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x24e")
int BPF_KPROBE(do_mov_4227)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x252")
int BPF_KPROBE(do_mov_4228)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x256")
int BPF_KPROBE(do_mov_4229)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x259")
int BPF_KPROBE(do_mov_4230)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x25d")
int BPF_KPROBE(do_mov_4231)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x195")
int BPF_KPROBE(do_mov_4232)
{
    u64 addr = ctx->bx + 0x33;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x19b")
int BPF_KPROBE(do_mov_4233)
{
    u64 addr = ctx->bx + ctx->ax * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1bd")
int BPF_KPROBE(do_mov_4234)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1c1")
int BPF_KPROBE(do_mov_4235)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1cb")
int BPF_KPROBE(do_mov_4236)
{
    u64 addr = ctx->r15 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1d2")
int BPF_KPROBE(do_mov_4237)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1d6")
int BPF_KPROBE(do_mov_4238)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1da")
int BPF_KPROBE(do_mov_4239)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1e2")
int BPF_KPROBE(do_mov_4240)
{
    u64 addr = ctx->bx + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x2e8")
int BPF_KPROBE(do_mov_4241)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x2ec")
int BPF_KPROBE(do_mov_4242)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x30a")
int BPF_KPROBE(do_mov_4243)
{
    u64 addr = ctx->ax - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x30e")
int BPF_KPROBE(do_mov_4244)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x312")
int BPF_KPROBE(do_mov_4245)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x316")
int BPF_KPROBE(do_mov_4246)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x319")
int BPF_KPROBE(do_mov_4247)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x31c")
int BPF_KPROBE(do_mov_4248)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x33b")
int BPF_KPROBE(do_mov_4249)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x33f")
int BPF_KPROBE(do_mov_4250)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x35e")
int BPF_KPROBE(do_mov_4251)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x362")
int BPF_KPROBE(do_mov_4252)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x365")
int BPF_KPROBE(do_mov_4253)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x369")
int BPF_KPROBE(do_mov_4254)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x36c")
int BPF_KPROBE(do_mov_4255)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x370")
int BPF_KPROBE(do_mov_4256)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x38d")
int BPF_KPROBE(do_mov_4257)
{
    u64 addr = ctx->r15 + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x427")
int BPF_KPROBE(do_mov_4258)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x442")
int BPF_KPROBE(do_mov_4259)
{
    u64 addr = ctx->r14 + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_mt+0x17c")
int BPF_KPROBE(do_mov_4260)
{
    u64 addr = ctx->bx + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/statistic_mt_check+0x38")
int BPF_KPROBE(do_mov_4261)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/statistic_mt_check+0x44")
int BPF_KPROBE(do_mov_4262)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/string_mt_check+0x66")
int BPF_KPROBE(do_mov_4263)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mt+0x8d")
int BPF_KPROBE(do_mov_4264)
{
    u64 addr = ctx->r14 + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_set_and_id+0x1b")
int BPF_KPROBE(do_mov_4265)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_set_and_id+0x76")
int BPF_KPROBE(do_mov_4266)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_register+0x56")
int BPF_KPROBE(do_mov_4267)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_register+0x5e")
int BPF_KPROBE(do_mov_4268)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_register+0x68")
int BPF_KPROBE(do_mov_4269)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_unregister+0x4a")
int BPF_KPROBE(do_mov_4270)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_unregister+0x4e")
int BPF_KPROBE(do_mov_4271)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_unregister+0x5b")
int BPF_KPROBE(do_mov_4272)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_init_comment+0x86")
int BPF_KPROBE(do_mov_4273)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_init_comment+0x8a")
int BPF_KPROBE(do_mov_4274)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_init_comment+0xc0")
int BPF_KPROBE(do_mov_4275)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_init_comment+0xc9")
int BPF_KPROBE(do_mov_4276)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_comment_free+0x39")
int BPF_KPROBE(do_mov_4277)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_comment_free+0x43")
int BPF_KPROBE(do_mov_4278)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_elem_len+0x6a")
int BPF_KPROBE(do_mov_4279)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0xd7")
int BPF_KPROBE(do_mov_4280)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x114")
int BPF_KPROBE(do_mov_4281)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x144")
int BPF_KPROBE(do_mov_4282)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x178")
int BPF_KPROBE(do_mov_4283)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x181")
int BPF_KPROBE(do_mov_4284)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x19d")
int BPF_KPROBE(do_mov_4285)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x1c3")
int BPF_KPROBE(do_mov_4286)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x1fd")
int BPF_KPROBE(do_mov_4287)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_minmax+0x3c")
int BPF_KPROBE(do_mov_4288)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_minmax+0x44")
int BPF_KPROBE(do_mov_4289)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_minmax+0x93")
int BPF_KPROBE(do_mov_4290)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_minmax+0xa3")
int BPF_KPROBE(do_mov_4291)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_get+0x53")
int BPF_KPROBE(do_mov_4292)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_done+0x56")
int BPF_KPROBE(do_mov_4293)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/call_ad+0x1c3")
int BPF_KPROBE(do_mov_4294)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/call_ad+0x242")
int BPF_KPROBE(do_mov_4295)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_match_extensions+0x45")
int BPF_KPROBE(do_mov_4296)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_match_extensions+0x49")
int BPF_KPROBE(do_mov_4297)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_ipaddr4+0x65")
int BPF_KPROBE(do_mov_4298)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_put_byindex+0x61")
int BPF_KPROBE(do_mov_4299)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_init+0x45")
int BPF_KPROBE(do_mov_4300)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_init+0x55")
int BPF_KPROBE(do_mov_4301)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_init+0x6f")
int BPF_KPROBE(do_mov_4302)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_init+0x73")
int BPF_KPROBE(do_mov_4303)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_init+0x7d")
int BPF_KPROBE(do_mov_4304)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_exit+0x30")
int BPF_KPROBE(do_mov_4305)
{
    u64 addr = ctx->r12 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_exit+0x59")
int BPF_KPROBE(do_mov_4306)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_nfnl_put+0x6e")
int BPF_KPROBE(do_mov_4307)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_byname+0xbd")
int BPF_KPROBE(do_mov_4308)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_ipaddr6+0x6c")
int BPF_KPROBE(do_mov_4309)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_ipaddr6+0x6f")
int BPF_KPROBE(do_mov_4310)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_start+0x95")
int BPF_KPROBE(do_mov_4311)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_start+0xc2")
int BPF_KPROBE(do_mov_4312)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_start+0xdb")
int BPF_KPROBE(do_mov_4313)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_start+0xdf")
int BPF_KPROBE(do_mov_4314)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_destroy+0x131")
int BPF_KPROBE(do_mov_4315)
{
    u64 addr = ctx->bx + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_destroy+0x162")
int BPF_KPROBE(do_mov_4316)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_destroy+0x17f")
int BPF_KPROBE(do_mov_4317)
{
    u64 addr = ctx->bx + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_destroy+0x19c")
int BPF_KPROBE(do_mov_4318)
{
    u64 addr = ctx->ax + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_swap+0x13c")
int BPF_KPROBE(do_mov_4319)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_swap+0x143")
int BPF_KPROBE(do_mov_4320)
{
    u64 addr = ctx->r12 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_swap+0x14c")
int BPF_KPROBE(do_mov_4321)
{
    u64 addr = ctx->ax + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_swap+0x158")
int BPF_KPROBE(do_mov_4322)
{
    u64 addr = ctx->ax + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_protocol+0xa9")
int BPF_KPROBE(do_mov_4323)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_protocol+0x102")
int BPF_KPROBE(do_mov_4324)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_byname+0x12e")
int BPF_KPROBE(do_mov_4325)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_byname+0x1b9")
int BPF_KPROBE(do_mov_4326)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x219")
int BPF_KPROBE(do_mov_4327)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x248")
int BPF_KPROBE(do_mov_4328)
{
    u64 addr = ctx->r13 + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x270")
int BPF_KPROBE(do_mov_4329)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x27f")
int BPF_KPROBE(do_mov_4330)
{
    u64 addr = ctx->r13 + 0x2b;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x2a2")
int BPF_KPROBE(do_mov_4331)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x2b9")
int BPF_KPROBE(do_mov_4332)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_create+0x111")
int BPF_KPROBE(do_mov_4333)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_create+0x160")
int BPF_KPROBE(do_mov_4334)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_create+0x171")
int BPF_KPROBE(do_mov_4335)
{
    u64 addr = ctx->r12 + 0x41;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_create+0x34a")
int BPF_KPROBE(do_mov_4336)
{
    u64 addr = ctx->ax + ctx->bx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_create+0x43b")
int BPF_KPROBE(do_mov_4337)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_create+0x44d")
int BPF_KPROBE(do_mov_4338)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_byindex+0x12a")
int BPF_KPROBE(do_mov_4339)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_byindex+0x19e")
int BPF_KPROBE(do_mov_4340)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_header+0x104")
int BPF_KPROBE(do_mov_4341)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_header+0x203")
int BPF_KPROBE(do_mov_4342)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type+0x10f")
int BPF_KPROBE(do_mov_4343)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type+0x1dc")
int BPF_KPROBE(do_mov_4344)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x1c1")
int BPF_KPROBE(do_mov_4345)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x1d3")
int BPF_KPROBE(do_mov_4346)
{
    u64 addr = ctx->bx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x1f6")
int BPF_KPROBE(do_mov_4347)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x2b6")
int BPF_KPROBE(do_mov_4348)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x2d0")
int BPF_KPROBE(do_mov_4349)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x2de")
int BPF_KPROBE(do_mov_4350)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x381")
int BPF_KPROBE(do_mov_4351)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x435")
int BPF_KPROBE(do_mov_4352)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x531")
int BPF_KPROBE(do_mov_4353)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x691")
int BPF_KPROBE(do_mov_4354)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_port+0x68")
int BPF_KPROBE(do_mov_4355)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_port+0x6c")
int BPF_KPROBE(do_mov_4356)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_port+0xc7")
int BPF_KPROBE(do_mov_4357)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_ip4_port+0x5f")
int BPF_KPROBE(do_mov_4358)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_range_to_cidr+0x4e")
int BPF_KPROBE(do_mov_4359)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_range_to_cidr+0x55")
int BPF_KPROBE(do_mov_4360)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_close+0x14")
int BPF_KPROBE(do_mov_4361)
{
    u64 addr = ctx->di + ctx->ax * 0x1 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_resolve_clash+0x1bf")
int BPF_KPROBE(do_mov_4362)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_resolve_clash+0x1ca")
int BPF_KPROBE(do_mov_4363)
{
    u64 addr = ctx->r13 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x166")
int BPF_KPROBE(do_mov_4364)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x176")
int BPF_KPROBE(do_mov_4365)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x17e")
int BPF_KPROBE(do_mov_4366)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x18f")
int BPF_KPROBE(do_mov_4367)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x193")
int BPF_KPROBE(do_mov_4368)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x19a")
int BPF_KPROBE(do_mov_4369)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x1a3")
int BPF_KPROBE(do_mov_4370)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x4c")
int BPF_KPROBE(do_mov_4371)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x55")
int BPF_KPROBE(do_mov_4372)
{
    u64 addr = ctx->bx + 0xa094;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x63")
int BPF_KPROBE(do_mov_4373)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x7c")
int BPF_KPROBE(do_mov_4374)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0xa1")
int BPF_KPROBE(do_mov_4375)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0xaf")
int BPF_KPROBE(do_mov_4376)
{
    u64 addr = ctx->bx + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0xc1")
int BPF_KPROBE(do_mov_4377)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}

