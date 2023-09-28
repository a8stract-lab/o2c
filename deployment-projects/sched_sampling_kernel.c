797

SEC("kprobe/netif_freeze_queues+0x4b")
int BPF_KPROBE(do_mov_0)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netif_freeze_queues+0x5a")
int BPF_KPROBE(do_mov_1)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/noop_enqueue+0x9")
int BPF_KPROBE(do_mov_2)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/noop_enqueue+0x14")
int BPF_KPROBE(do_mov_3)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/noqueue_init+0x8")
int BPF_KPROBE(do_mov_4)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_graft_qdisc+0x37")
int BPF_KPROBE(do_mov_5)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_graft_qdisc+0x3c")
int BPF_KPROBE(do_mov_6)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_block_init+0x6")
int BPF_KPROBE(do_mov_7)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_block_init+0xa")
int BPF_KPROBE(do_mov_8)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_dequeue+0xa6")
int BPF_KPROBE(do_mov_9)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_dequeue+0x143")
int BPF_KPROBE(do_mov_10)
{
    u64 addr = ctx->r11 + ctx->si * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_dequeue+0x15b")
int BPF_KPROBE(do_mov_11)
{
    u64 addr = ctx->r8 + ctx->dx * 0x1 + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_dequeue+0x1b7")
int BPF_KPROBE(do_mov_12)
{
    u64 addr = ctx->dx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_swap+0x3a")
int BPF_KPROBE(do_mov_13)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_swap+0x42")
int BPF_KPROBE(do_mov_14)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_swap+0x4f")
int BPF_KPROBE(do_mov_15)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_swap+0x63")
int BPF_KPROBE(do_mov_16)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0xa")
int BPF_KPROBE(do_mov_17)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x1a")
int BPF_KPROBE(do_mov_18)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x26")
int BPF_KPROBE(do_mov_19)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x2e")
int BPF_KPROBE(do_mov_20)
{
    u64 addr = ctx->di + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x37")
int BPF_KPROBE(do_mov_21)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x3b")
int BPF_KPROBE(do_mov_22)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x3f")
int BPF_KPROBE(do_mov_23)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x6")
int BPF_KPROBE(do_mov_24)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0xe")
int BPF_KPROBE(do_mov_25)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x15")
int BPF_KPROBE(do_mov_26)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x24")
int BPF_KPROBE(do_mov_27)
{
    u64 addr = ctx->di + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x2c")
int BPF_KPROBE(do_mov_28)
{
    u64 addr = ctx->di + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x3b")
int BPF_KPROBE(do_mov_29)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x42")
int BPF_KPROBE(do_mov_30)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x4c")
int BPF_KPROBE(do_mov_31)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x5b")
int BPF_KPROBE(do_mov_32)
{
    u64 addr = ctx->di + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x6a")
int BPF_KPROBE(do_mov_33)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x86")
int BPF_KPROBE(do_mov_34)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0xa0")
int BPF_KPROBE(do_mov_35)
{
    u64 addr = ctx->ax + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0xa7")
int BPF_KPROBE(do_mov_36)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0x113")
int BPF_KPROBE(do_mov_37)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0x117")
int BPF_KPROBE(do_mov_38)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0x12b")
int BPF_KPROBE(do_mov_39)
{
    u64 addr = ctx->ax + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__netdev_watchdog_up+0x60")
int BPF_KPROBE(do_mov_40)
{
    u64 addr = ctx->di + 0x4f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0x77")
int BPF_KPROBE(do_mov_41)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0x8b")
int BPF_KPROBE(do_mov_42)
{
    u64 addr = ctx->bx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0x9d")
int BPF_KPROBE(do_mov_43)
{
    u64 addr = ctx->bx - 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0xa1")
int BPF_KPROBE(do_mov_44)
{
    u64 addr = ctx->bx - 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0xa8")
int BPF_KPROBE(do_mov_45)
{
    u64 addr = ctx->bx - 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0xaf")
int BPF_KPROBE(do_mov_46)
{
    u64 addr = ctx->bx - 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0xb9")
int BPF_KPROBE(do_mov_47)
{
    u64 addr = ctx->bx - 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0xc3")
int BPF_KPROBE(do_mov_48)
{
    u64 addr = ctx->bx - 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0xf1")
int BPF_KPROBE(do_mov_49)
{
    u64 addr = ctx->r15 + ctx->ax * 0x1 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x6")
int BPF_KPROBE(do_mov_50)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x9")
int BPF_KPROBE(do_mov_51)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x1f")
int BPF_KPROBE(do_mov_52)
{
    u64 addr = ctx->di + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x31")
int BPF_KPROBE(do_mov_53)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x49")
int BPF_KPROBE(do_mov_54)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x52")
int BPF_KPROBE(do_mov_55)
{
    u64 addr = ctx->di + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0xa2")
int BPF_KPROBE(do_mov_56)
{
    u64 addr = ctx->bx + ctx->r14 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x11b")
int BPF_KPROBE(do_mov_57)
{
    u64 addr = ctx->bx + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x175")
int BPF_KPROBE(do_mov_58)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1a0")
int BPF_KPROBE(do_mov_59)
{
    u64 addr = ctx->r15 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1b2")
int BPF_KPROBE(do_mov_60)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1ba")
int BPF_KPROBE(do_mov_61)
{
    u64 addr = ctx->r15 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1c1")
int BPF_KPROBE(do_mov_62)
{
    u64 addr = ctx->r15 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1cc")
int BPF_KPROBE(do_mov_63)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1cf")
int BPF_KPROBE(do_mov_64)
{
    u64 addr = ctx->ax + ctx->r12 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x201")
int BPF_KPROBE(do_mov_65)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x282")
int BPF_KPROBE(do_mov_66)
{
    u64 addr = ctx->dx + ctx->cx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x293")
int BPF_KPROBE(do_mov_67)
{
    u64 addr = ctx->r15 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x2a4")
int BPF_KPROBE(do_mov_68)
{
    u64 addr = ctx->r15 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_reset+0x68")
int BPF_KPROBE(do_mov_69)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_reset+0xca")
int BPF_KPROBE(do_mov_70)
{
    u64 addr = ctx->cx + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_reset+0x107")
int BPF_KPROBE(do_mov_71)
{
    u64 addr = ctx->dx + ctx->cx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_reset+0x117")
int BPF_KPROBE(do_mov_72)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_reset+0x126")
int BPF_KPROBE(do_mov_73)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0x4d")
int BPF_KPROBE(do_mov_74)
{
    u64 addr = ctx->bx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0x5a")
int BPF_KPROBE(do_mov_75)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0x61")
int BPF_KPROBE(do_mov_76)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0x69")
int BPF_KPROBE(do_mov_77)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0x6d")
int BPF_KPROBE(do_mov_78)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xac")
int BPF_KPROBE(do_mov_79)
{
    u64 addr = ctx->bx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xb9")
int BPF_KPROBE(do_mov_80)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xc0")
int BPF_KPROBE(do_mov_81)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xc8")
int BPF_KPROBE(do_mov_82)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xcc")
int BPF_KPROBE(do_mov_83)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xe0")
int BPF_KPROBE(do_mov_84)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xea")
int BPF_KPROBE(do_mov_85)
{
    u64 addr = ctx->bx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x127")
int BPF_KPROBE(do_mov_86)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x153")
int BPF_KPROBE(do_mov_87)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x211")
int BPF_KPROBE(do_mov_88)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x214")
int BPF_KPROBE(do_mov_89)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x218")
int BPF_KPROBE(do_mov_90)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x220")
int BPF_KPROBE(do_mov_91)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x22e")
int BPF_KPROBE(do_mov_92)
{
    u64 addr = ctx->r12 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x2f4")
int BPF_KPROBE(do_mov_93)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x2f7")
int BPF_KPROBE(do_mov_94)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x2fb")
int BPF_KPROBE(do_mov_95)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x303")
int BPF_KPROBE(do_mov_96)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x311")
int BPF_KPROBE(do_mov_97)
{
    u64 addr = ctx->r12 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0xd6")
int BPF_KPROBE(do_mov_98)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0xf2")
int BPF_KPROBE(do_mov_99)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x1fd")
int BPF_KPROBE(do_mov_100)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x20a")
int BPF_KPROBE(do_mov_101)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x24f")
int BPF_KPROBE(do_mov_102)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x252")
int BPF_KPROBE(do_mov_103)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x256")
int BPF_KPROBE(do_mov_104)
{
    u64 addr = ctx->r12 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x25e")
int BPF_KPROBE(do_mov_105)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x26c")
int BPF_KPROBE(do_mov_106)
{
    u64 addr = ctx->r12 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x3a1")
int BPF_KPROBE(do_mov_107)
{
    u64 addr = ctx->r12 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x3b1")
int BPF_KPROBE(do_mov_108)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x3b9")
int BPF_KPROBE(do_mov_109)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x3c1")
int BPF_KPROBE(do_mov_110)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x3c5")
int BPF_KPROBE(do_mov_111)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x46a")
int BPF_KPROBE(do_mov_112)
{
    u64 addr = ctx->r12 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x47a")
int BPF_KPROBE(do_mov_113)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x482")
int BPF_KPROBE(do_mov_114)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x48a")
int BPF_KPROBE(do_mov_115)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x48e")
int BPF_KPROBE(do_mov_116)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x57")
int BPF_KPROBE(do_mov_117)
{
    u64 addr = ctx->r15 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x62")
int BPF_KPROBE(do_mov_118)
{
    u64 addr = ctx->r15 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x69")
int BPF_KPROBE(do_mov_119)
{
    u64 addr = ctx->r15 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x77")
int BPF_KPROBE(do_mov_120)
{
    u64 addr = ctx->r15 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x7e")
int BPF_KPROBE(do_mov_121)
{
    u64 addr = ctx->r15 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x85")
int BPF_KPROBE(do_mov_122)
{
    u64 addr = ctx->r15 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x98")
int BPF_KPROBE(do_mov_123)
{
    u64 addr = ctx->r15 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xa7")
int BPF_KPROBE(do_mov_124)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xaf")
int BPF_KPROBE(do_mov_125)
{
    u64 addr = ctx->r15 + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xba")
int BPF_KPROBE(do_mov_126)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xc1")
int BPF_KPROBE(do_mov_127)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xc5")
int BPF_KPROBE(do_mov_128)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xc9")
int BPF_KPROBE(do_mov_129)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xdc")
int BPF_KPROBE(do_mov_130)
{
    u64 addr = ctx->r15 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x138")
int BPF_KPROBE(do_mov_131)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x14b")
int BPF_KPROBE(do_mov_132)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x17b")
int BPF_KPROBE(do_mov_133)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0x19d")
int BPF_KPROBE(do_mov_134)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create_dflt+0x4f")
int BPF_KPROBE(do_mov_135)
{
    u64 addr = ctx->ax + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create_dflt+0xf3")
int BPF_KPROBE(do_mov_136)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_activate+0x15b")
int BPF_KPROBE(do_mov_137)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_activate+0x1a7")
int BPF_KPROBE(do_mov_138)
{
    u64 addr = ctx->r12 + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_activate+0x252")
int BPF_KPROBE(do_mov_139)
{
    u64 addr = ctx->r12 + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_deactivate_many+0x59")
int BPF_KPROBE(do_mov_140)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_deactivate_many+0x8f")
int BPF_KPROBE(do_mov_141)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_deactivate+0x24")
int BPF_KPROBE(do_mov_142)
{
    u64 addr = ctx->di + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_deactivate+0x28")
int BPF_KPROBE(do_mov_143)
{
    u64 addr = ctx->di + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_deactivate+0x44")
int BPF_KPROBE(do_mov_144)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_deactivate+0x48")
int BPF_KPROBE(do_mov_145)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_qdisc_change_tx_queue_len+0xc0")
int BPF_KPROBE(do_mov_146)
{
    u64 addr = ctx->r13 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_qdisc_change_tx_queue_len+0xc4")
int BPF_KPROBE(do_mov_147)
{
    u64 addr = ctx->r13 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_qdisc_change_tx_queue_len+0xdd")
int BPF_KPROBE(do_mov_148)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_qdisc_change_tx_queue_len+0xe1")
int BPF_KPROBE(do_mov_149)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_init_scheduler+0xf")
int BPF_KPROBE(do_mov_150)
{
    u64 addr = ctx->di + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_init_scheduler+0x31")
int BPF_KPROBE(do_mov_151)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_init_scheduler+0x3c")
int BPF_KPROBE(do_mov_152)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_init_scheduler+0x58")
int BPF_KPROBE(do_mov_153)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_init_scheduler+0x60")
int BPF_KPROBE(do_mov_154)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_shutdown+0x36")
int BPF_KPROBE(do_mov_155)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_shutdown+0x3e")
int BPF_KPROBE(do_mov_156)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_shutdown+0x6e")
int BPF_KPROBE(do_mov_157)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_shutdown+0x76")
int BPF_KPROBE(do_mov_158)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_shutdown+0x90")
int BPF_KPROBE(do_mov_159)
{
    u64 addr = ctx->r12 + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_dump_class+0x2e")
int BPF_KPROBE(do_mov_160)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_dump_class+0x43")
int BPF_KPROBE(do_mov_161)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_walk+0x23")
int BPF_KPROBE(do_mov_162)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_walk+0x3f")
int BPF_KPROBE(do_mov_163)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_walk+0x66")
int BPF_KPROBE(do_mov_164)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_dump+0x3c")
int BPF_KPROBE(do_mov_165)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_dump+0x52")
int BPF_KPROBE(do_mov_166)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_dump+0x5e")
int BPF_KPROBE(do_mov_167)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_dump+0x66")
int BPF_KPROBE(do_mov_168)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_attach+0x8d")
int BPF_KPROBE(do_mov_169)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_graft+0x73")
int BPF_KPROBE(do_mov_170)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_init+0x47")
int BPF_KPROBE(do_mov_171)
{
    u64 addr = ctx->r15 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_init+0x69")
int BPF_KPROBE(do_mov_172)
{
    u64 addr = ctx->dx + ctx->r13 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x40")
int BPF_KPROBE(do_mov_173)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x48")
int BPF_KPROBE(do_mov_174)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x51")
int BPF_KPROBE(do_mov_175)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x5a")
int BPF_KPROBE(do_mov_176)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x63")
int BPF_KPROBE(do_mov_177)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x67")
int BPF_KPROBE(do_mov_178)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x73")
int BPF_KPROBE(do_mov_179)
{
    u64 addr = ctx->ax + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x93")
int BPF_KPROBE(do_mov_180)
{
    u64 addr = ctx->ax + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0xaa")
int BPF_KPROBE(do_mov_181)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0xb1")
int BPF_KPROBE(do_mov_182)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0xd3")
int BPF_KPROBE(do_mov_183)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0xdc")
int BPF_KPROBE(do_mov_184)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0xe5")
int BPF_KPROBE(do_mov_185)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0xa2")
int BPF_KPROBE(do_mov_186)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0xbe")
int BPF_KPROBE(do_mov_187)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0xec")
int BPF_KPROBE(do_mov_188)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0xf5")
int BPF_KPROBE(do_mov_189)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0xfe")
int BPF_KPROBE(do_mov_190)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x106")
int BPF_KPROBE(do_mov_191)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x10f")
int BPF_KPROBE(do_mov_192)
{
    u64 addr = ctx->r12 + 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x132")
int BPF_KPROBE(do_mov_193)
{
    u64 addr = ctx->r12 + 0x82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x176")
int BPF_KPROBE(do_mov_194)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x191")
int BPF_KPROBE(do_mov_195)
{
    u64 addr = ctx->r12 + 0x9a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x19a")
int BPF_KPROBE(do_mov_196)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x1dd")
int BPF_KPROBE(do_mov_197)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_fragment+0xfc")
int BPF_KPROBE(do_mov_198)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_fragment+0x125")
int BPF_KPROBE(do_mov_199)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_fragment+0x1bb")
int BPF_KPROBE(do_mov_200)
{
    u64 addr = ctx->r12 + 0x3e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_fragment+0x1dd")
int BPF_KPROBE(do_mov_201)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x7")
int BPF_KPROBE(do_mov_202)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x13")
int BPF_KPROBE(do_mov_203)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x3a")
int BPF_KPROBE(do_mov_204)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x43")
int BPF_KPROBE(do_mov_205)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x47")
int BPF_KPROBE(do_mov_206)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x4b")
int BPF_KPROBE(do_mov_207)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_remove+0xe")
int BPF_KPROBE(do_mov_208)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_remove+0x19")
int BPF_KPROBE(do_mov_209)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_remove+0x28")
int BPF_KPROBE(do_mov_210)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_remove+0x30")
int BPF_KPROBE(do_mov_211)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xbc")
int BPF_KPROBE(do_mov_212)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xc4")
int BPF_KPROBE(do_mov_213)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xd8")
int BPF_KPROBE(do_mov_214)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xe4")
int BPF_KPROBE(do_mov_215)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xf8")
int BPF_KPROBE(do_mov_216)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_calculate_pkt_len+0x43")
int BPF_KPROBE(do_mov_217)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_offload_graft_helper+0x96")
int BPF_KPROBE(do_mov_218)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_watchdog_init_clockid+0x22")
int BPF_KPROBE(do_mov_219)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_watchdog_init_clockid+0x26")
int BPF_KPROBE(do_mov_220)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_watchdog_init+0x25")
int BPF_KPROBE(do_mov_221)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_watchdog_init+0x29")
int BPF_KPROBE(do_mov_222)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0x2a")
int BPF_KPROBE(do_mov_223)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xa6")
int BPF_KPROBE(do_mov_224)
{
    u64 addr = ctx->cx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xb9")
int BPF_KPROBE(do_mov_225)
{
    u64 addr = ctx->cx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xc3")
int BPF_KPROBE(do_mov_226)
{
    u64 addr = ctx->cx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xcb")
int BPF_KPROBE(do_mov_227)
{
    u64 addr = ctx->cx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xd3")
int BPF_KPROBE(do_mov_228)
{
    u64 addr = ctx->cx + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xdb")
int BPF_KPROBE(do_mov_229)
{
    u64 addr = ctx->cx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_qdisc+0x71")
int BPF_KPROBE(do_mov_230)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_qdisc+0x74")
int BPF_KPROBE(do_mov_231)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_add+0x53")
int BPF_KPROBE(do_mov_232)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_add+0x57")
int BPF_KPROBE(do_mov_233)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_add+0x5b")
int BPF_KPROBE(do_mov_234)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_add+0x63")
int BPF_KPROBE(do_mov_235)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_del+0x35")
int BPF_KPROBE(do_mov_236)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_del+0x3d")
int BPF_KPROBE(do_mov_237)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_del+0x41")
int BPF_KPROBE(do_mov_238)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_put_rtab+0x54")
int BPF_KPROBE(do_mov_239)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_put_stab+0x1c")
int BPF_KPROBE(do_mov_240)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_put_stab+0x20")
int BPF_KPROBE(do_mov_241)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_put_stab+0x30")
int BPF_KPROBE(do_mov_242)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_put_stab+0x38")
int BPF_KPROBE(do_mov_243)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_watchdog_schedule_range_ns+0x39")
int BPF_KPROBE(do_mov_244)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass+0xd6")
int BPF_KPROBE(do_mov_245)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x9f")
int BPF_KPROBE(do_mov_246)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x14c")
int BPF_KPROBE(do_mov_247)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x15b")
int BPF_KPROBE(do_mov_248)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x164")
int BPF_KPROBE(do_mov_249)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x16d")
int BPF_KPROBE(do_mov_250)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x190")
int BPF_KPROBE(do_mov_251)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x1a0")
int BPF_KPROBE(do_mov_252)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x1a5")
int BPF_KPROBE(do_mov_253)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x228")
int BPF_KPROBE(do_mov_254)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x24c")
int BPF_KPROBE(do_mov_255)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x270")
int BPF_KPROBE(do_mov_256)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0xa8")
int BPF_KPROBE(do_mov_257)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0xef")
int BPF_KPROBE(do_mov_258)
{
    u64 addr = ctx->r12 + 0x418;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x103")
int BPF_KPROBE(do_mov_259)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x10a")
int BPF_KPROBE(do_mov_260)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x113")
int BPF_KPROBE(do_mov_261)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x11f")
int BPF_KPROBE(do_mov_262)
{
    u64 addr = ctx->r12 + 0x404;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x13d")
int BPF_KPROBE(do_mov_263)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x154")
int BPF_KPROBE(do_mov_264)
{
    u64 addr = ctx->r12 + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x1d8")
int BPF_KPROBE(do_mov_265)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x23e")
int BPF_KPROBE(do_mov_266)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x26")
int BPF_KPROBE(do_mov_267)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x2d")
int BPF_KPROBE(do_mov_268)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x34")
int BPF_KPROBE(do_mov_269)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x3c")
int BPF_KPROBE(do_mov_270)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x44")
int BPF_KPROBE(do_mov_271)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x4c")
int BPF_KPROBE(do_mov_272)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x59")
int BPF_KPROBE(do_mov_273)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x65")
int BPF_KPROBE(do_mov_274)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0xa4")
int BPF_KPROBE(do_mov_275)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0xbd")
int BPF_KPROBE(do_mov_276)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0xc1")
int BPF_KPROBE(do_mov_277)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0xc8")
int BPF_KPROBE(do_mov_278)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0xcf")
int BPF_KPROBE(do_mov_279)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0x232")
int BPF_KPROBE(do_mov_280)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0x327")
int BPF_KPROBE(do_mov_281)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_qdisc_root+0x17e")
int BPF_KPROBE(do_mov_282)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_qdisc+0x16a")
int BPF_KPROBE(do_mov_283)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_qdisc+0x16f")
int BPF_KPROBE(do_mov_284)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_qdisc+0x1f2")
int BPF_KPROBE(do_mov_285)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0xeb")
int BPF_KPROBE(do_mov_286)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0xf4")
int BPF_KPROBE(do_mov_287)
{
    u64 addr = ctx->r10 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0xf8")
int BPF_KPROBE(do_mov_288)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0xfb")
int BPF_KPROBE(do_mov_289)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0x10d")
int BPF_KPROBE(do_mov_290)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0x110")
int BPF_KPROBE(do_mov_291)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0x114")
int BPF_KPROBE(do_mov_292)
{
    u64 addr = ctx->r14 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0xb7")
int BPF_KPROBE(do_mov_293)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0xd7")
int BPF_KPROBE(do_mov_294)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0xde")
int BPF_KPROBE(do_mov_295)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0xe5")
int BPF_KPROBE(do_mov_296)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0xe8")
int BPF_KPROBE(do_mov_297)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0x1bf")
int BPF_KPROBE(do_mov_298)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x2cb")
int BPF_KPROBE(do_mov_299)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x2f6")
int BPF_KPROBE(do_mov_300)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x2fe")
int BPF_KPROBE(do_mov_301)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x384")
int BPF_KPROBE(do_mov_302)
{
    u64 addr = ctx->r15 + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x53a")
int BPF_KPROBE(do_mov_303)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x565")
int BPF_KPROBE(do_mov_304)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create+0x8c")
int BPF_KPROBE(do_mov_305)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create+0xb2")
int BPF_KPROBE(do_mov_306)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create+0x21e")
int BPF_KPROBE(do_mov_307)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create+0x230")
int BPF_KPROBE(do_mov_308)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create+0x2d7")
int BPF_KPROBE(do_mov_309)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create+0x43a")
int BPF_KPROBE(do_mov_310)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_tclass+0x541")
int BPF_KPROBE(do_mov_311)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_tclass+0x565")
int BPF_KPROBE(do_mov_312)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0xf6")
int BPF_KPROBE(do_mov_313)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x298")
int BPF_KPROBE(do_mov_314)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x310")
int BPF_KPROBE(do_mov_315)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x332")
int BPF_KPROBE(do_mov_316)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x354")
int BPF_KPROBE(do_mov_317)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x380")
int BPF_KPROBE(do_mov_318)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x3a2")
int BPF_KPROBE(do_mov_319)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x3c8")
int BPF_KPROBE(do_mov_320)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x1bf")
int BPF_KPROBE(do_mov_321)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x39b")
int BPF_KPROBE(do_mov_322)
{
    u64 addr = ctx->r10 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x4d7")
int BPF_KPROBE(do_mov_323)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x52f")
int BPF_KPROBE(do_mov_324)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x56b")
int BPF_KPROBE(do_mov_325)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x60f")
int BPF_KPROBE(do_mov_326)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x6c4")
int BPF_KPROBE(do_mov_327)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x6e6")
int BPF_KPROBE(do_mov_328)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x72c")
int BPF_KPROBE(do_mov_329)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x752")
int BPF_KPROBE(do_mov_330)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x777")
int BPF_KPROBE(do_mov_331)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x77b")
int BPF_KPROBE(do_mov_332)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x788")
int BPF_KPROBE(do_mov_333)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x790")
int BPF_KPROBE(do_mov_334)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x7b6")
int BPF_KPROBE(do_mov_335)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x7f4")
int BPF_KPROBE(do_mov_336)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x82e")
int BPF_KPROBE(do_mov_337)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x854")
int BPF_KPROBE(do_mov_338)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x87a")
int BPF_KPROBE(do_mov_339)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x8a5")
int BPF_KPROBE(do_mov_340)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/blackhole_enqueue+0x9")
int BPF_KPROBE(do_mov_341)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/blackhole_enqueue+0x14")
int BPF_KPROBE(do_mov_342)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_head_change_dflt+0x9")
int BPF_KPROBE(do_mov_343)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x40")
int BPF_KPROBE(do_mov_344)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x5c")
int BPF_KPROBE(do_mov_345)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x6a")
int BPF_KPROBE(do_mov_346)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x89")
int BPF_KPROBE(do_mov_347)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_tcf_proto_ops+0x68")
int BPF_KPROBE(do_mov_348)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_tcf_proto_ops+0x70")
int BPF_KPROBE(do_mov_349)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_tcf_proto_ops+0x74")
int BPF_KPROBE(do_mov_350)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_tcf_proto_ops+0x91")
int BPF_KPROBE(do_mov_351)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_tcf_proto_ops+0x95")
int BPF_KPROBE(do_mov_352)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_tcf_proto_ops+0xa2")
int BPF_KPROBE(do_mov_353)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_tcf_proto_ops+0xa5")
int BPF_KPROBE(do_mov_354)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_queue_work+0x10")
int BPF_KPROBE(do_mov_355)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_queue_work+0x17")
int BPF_KPROBE(do_mov_356)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_queue_work+0x1b")
int BPF_KPROBE(do_mov_357)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_queue_work+0x25")
int BPF_KPROBE(do_mov_358)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_get_next_chain+0x58")
int BPF_KPROBE(do_mov_359)
{
    u64 addr = ctx->r12 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_net_init+0x35")
int BPF_KPROBE(do_mov_360)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_net_init+0x3b")
int BPF_KPROBE(do_mov_361)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_net_init+0x41")
int BPF_KPROBE(do_mov_362)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_net_init+0x49")
int BPF_KPROBE(do_mov_363)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain0_head_change_cb_del+0x7b")
int BPF_KPROBE(do_mov_364)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain0_head_change_cb_del+0x7f")
int BPF_KPROBE(do_mov_365)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain0_head_change_cb_del+0x8c")
int BPF_KPROBE(do_mov_366)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain0_head_change_cb_del+0x94")
int BPF_KPROBE(do_mov_367)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_owner_del+0x37")
int BPF_KPROBE(do_mov_368)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_owner_del+0x3e")
int BPF_KPROBE(do_mov_369)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_owner_del+0x4b")
int BPF_KPROBE(do_mov_370)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_owner_del+0x52")
int BPF_KPROBE(do_mov_371)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_destroy+0x29")
int BPF_KPROBE(do_mov_372)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_validate_ex+0x107")
int BPF_KPROBE(do_mov_373)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_validate_ex+0x10d")
int BPF_KPROBE(do_mov_374)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_validate_ex+0x11a")
int BPF_KPROBE(do_mov_375)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_validate_ex+0x121")
int BPF_KPROBE(do_mov_376)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_validate_ex+0x18f")
int BPF_KPROBE(do_mov_377)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_lookup_ops+0x81")
int BPF_KPROBE(do_mov_378)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0x8a")
int BPF_KPROBE(do_mov_379)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0x8e")
int BPF_KPROBE(do_mov_380)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0x94")
int BPF_KPROBE(do_mov_381)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xa6")
int BPF_KPROBE(do_mov_382)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xaa")
int BPF_KPROBE(do_mov_383)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xb0")
int BPF_KPROBE(do_mov_384)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xd6")
int BPF_KPROBE(do_mov_385)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_signal_destroying.isra.0+0x4f")
int BPF_KPROBE(do_mov_386)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_signal_destroying.isra.0+0x53")
int BPF_KPROBE(do_mov_387)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_signal_destroying.isra.0+0x57")
int BPF_KPROBE(do_mov_388)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_signal_destroying.isra.0+0x5f")
int BPF_KPROBE(do_mov_389)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x3e")
int BPF_KPROBE(do_mov_390)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x43")
int BPF_KPROBE(do_mov_391)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x48")
int BPF_KPROBE(do_mov_392)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x5c")
int BPF_KPROBE(do_mov_393)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x65")
int BPF_KPROBE(do_mov_394)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x6a")
int BPF_KPROBE(do_mov_395)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x6f")
int BPF_KPROBE(do_mov_396)
{
    u64 addr = ctx->r12 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x7d")
int BPF_KPROBE(do_mov_397)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_netif_keep_dst+0x14")
int BPF_KPROBE(do_mov_398)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_validate_change+0x3e")
int BPF_KPROBE(do_mov_399)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_validate_change+0x65")
int BPF_KPROBE(do_mov_400)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_replace+0xa4")
int BPF_KPROBE(do_mov_401)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_replace+0xb8")
int BPF_KPROBE(do_mov_402)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_dump+0xee")
int BPF_KPROBE(do_mov_403)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_change+0x12")
int BPF_KPROBE(do_mov_404)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_change+0x19")
int BPF_KPROBE(do_mov_405)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_change+0x21")
int BPF_KPROBE(do_mov_406)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_change+0x29")
int BPF_KPROBE(do_mov_407)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_find+0x46")
int BPF_KPROBE(do_mov_408)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_find+0x4c")
int BPF_KPROBE(do_mov_409)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_find+0x67")
int BPF_KPROBE(do_mov_410)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_find+0x6c")
int BPF_KPROBE(do_mov_411)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_block_find+0x6d")
int BPF_KPROBE(do_mov_412)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_block_find+0x98")
int BPF_KPROBE(do_mov_413)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0x95")
int BPF_KPROBE(do_mov_414)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0x9c")
int BPF_KPROBE(do_mov_415)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0xbd")
int BPF_KPROBE(do_mov_416)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0xc8")
int BPF_KPROBE(do_mov_417)
{
    u64 addr = ctx->r14 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0x158")
int BPF_KPROBE(do_mov_418)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0x1a9")
int BPF_KPROBE(do_mov_419)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_get+0xa4")
int BPF_KPROBE(do_mov_420)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x3a")
int BPF_KPROBE(do_mov_421)
{
    u64 addr = ctx->bx + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x59")
int BPF_KPROBE(do_mov_422)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x7b")
int BPF_KPROBE(do_mov_423)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x7f")
int BPF_KPROBE(do_mov_424)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x8f")
int BPF_KPROBE(do_mov_425)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x128")
int BPF_KPROBE(do_mov_426)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x12c")
int BPF_KPROBE(do_mov_427)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x134")
int BPF_KPROBE(do_mov_428)
{
    u64 addr = ctx->ax + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x1c4")
int BPF_KPROBE(do_mov_429)
{
    u64 addr = ctx->bx + 0x4d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_destroy+0x7e")
int BPF_KPROBE(do_mov_430)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_destroy+0x86")
int BPF_KPROBE(do_mov_431)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_destroy+0x8a")
int BPF_KPROBE(do_mov_432)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_flush+0x44")
int BPF_KPROBE(do_mov_433)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_flush+0x57")
int BPF_KPROBE(do_mov_434)
{
    u64 addr = ctx->r12 + 0x4d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_flush+0x8a")
int BPF_KPROBE(do_mov_435)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_flush+0xa4")
int BPF_KPROBE(do_mov_436)
{
    u64 addr = ctx->r12 + 0x4d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_delete_empty+0x9e")
int BPF_KPROBE(do_mov_437)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_delete_empty+0xc4")
int BPF_KPROBE(do_mov_438)
{
    u64 addr = ctx->r15 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_playback_offloads+0xda")
int BPF_KPROBE(do_mov_439)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_unbind+0x83")
int BPF_KPROBE(do_mov_440)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_unbind+0x87")
int BPF_KPROBE(do_mov_441)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_unbind+0x94")
int BPF_KPROBE(do_mov_442)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_unbind+0x99")
int BPF_KPROBE(do_mov_443)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0xd5")
int BPF_KPROBE(do_mov_444)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0xd9")
int BPF_KPROBE(do_mov_445)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0xee")
int BPF_KPROBE(do_mov_446)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0xf5")
int BPF_KPROBE(do_mov_447)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0xfd")
int BPF_KPROBE(do_mov_448)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0x101")
int BPF_KPROBE(do_mov_449)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0x10b")
int BPF_KPROBE(do_mov_450)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0x10f")
int BPF_KPROBE(do_mov_451)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0x113")
int BPF_KPROBE(do_mov_452)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x120")
int BPF_KPROBE(do_mov_453)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x124")
int BPF_KPROBE(do_mov_454)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x135")
int BPF_KPROBE(do_mov_455)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x141")
int BPF_KPROBE(do_mov_456)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x1aa")
int BPF_KPROBE(do_mov_457)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x1ae")
int BPF_KPROBE(do_mov_458)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x1b3")
int BPF_KPROBE(do_mov_459)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x1b6")
int BPF_KPROBE(do_mov_460)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_offload_cmd.isra.0+0xd4")
int BPF_KPROBE(do_mov_461)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_offload_unbind+0x6a")
int BPF_KPROBE(do_mov_462)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x78")
int BPF_KPROBE(do_mov_463)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x7c")
int BPF_KPROBE(do_mov_464)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x87")
int BPF_KPROBE(do_mov_465)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x8b")
int BPF_KPROBE(do_mov_466)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x95")
int BPF_KPROBE(do_mov_467)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0xa1")
int BPF_KPROBE(do_mov_468)
{
    u64 addr = ctx->r13 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0xd7")
int BPF_KPROBE(do_mov_469)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0xdf")
int BPF_KPROBE(do_mov_470)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x146")
int BPF_KPROBE(do_mov_471)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x14a")
int BPF_KPROBE(do_mov_472)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x14d")
int BPF_KPROBE(do_mov_473)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x151")
int BPF_KPROBE(do_mov_474)
{
    u64 addr = ctx->r13 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x270")
int BPF_KPROBE(do_mov_475)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x274")
int BPF_KPROBE(do_mov_476)
{
    u64 addr = ctx->r13 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x278")
int BPF_KPROBE(do_mov_477)
{
    u64 addr = ctx->r13 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x283")
int BPF_KPROBE(do_mov_478)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x287")
int BPF_KPROBE(do_mov_479)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x292")
int BPF_KPROBE(do_mov_480)
{
    u64 addr = ctx->r13 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x299")
int BPF_KPROBE(do_mov_481)
{
    u64 addr = ctx->r13 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x2a7")
int BPF_KPROBE(do_mov_482)
{
    u64 addr = ctx->r13 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x2ae")
int BPF_KPROBE(do_mov_483)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x2b2")
int BPF_KPROBE(do_mov_484)
{
    u64 addr = ctx->r13 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x2b9")
int BPF_KPROBE(do_mov_485)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x2c6")
int BPF_KPROBE(do_mov_486)
{
    u64 addr = ctx->r13 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x3a7")
int BPF_KPROBE(do_mov_487)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x3ab")
int BPF_KPROBE(do_mov_488)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x3ae")
int BPF_KPROBE(do_mov_489)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x3b2")
int BPF_KPROBE(do_mov_490)
{
    u64 addr = ctx->r13 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x3e5")
int BPF_KPROBE(do_mov_491)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x40b")
int BPF_KPROBE(do_mov_492)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x452")
int BPF_KPROBE(do_mov_493)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x47a")
int BPF_KPROBE(do_mov_494)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_init+0x1f")
int BPF_KPROBE(do_mov_495)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_init+0x26")
int BPF_KPROBE(do_mov_496)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_init+0x2e")
int BPF_KPROBE(do_mov_497)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_init+0x36")
int BPF_KPROBE(do_mov_498)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_init+0x61")
int BPF_KPROBE(do_mov_499)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_chain+0x29e")
int BPF_KPROBE(do_mov_500)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_chain+0x348")
int BPF_KPROBE(do_mov_501)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0xa3")
int BPF_KPROBE(do_mov_502)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0xc0")
int BPF_KPROBE(do_mov_503)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0xcc")
int BPF_KPROBE(do_mov_504)
{
    u64 addr = ctx->r14 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0xde")
int BPF_KPROBE(do_mov_505)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0x19b")
int BPF_KPROBE(do_mov_506)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0x1fd")
int BPF_KPROBE(do_mov_507)
{
    u64 addr = ctx->ax + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0x213")
int BPF_KPROBE(do_mov_508)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x12e")
int BPF_KPROBE(do_mov_509)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x13a")
int BPF_KPROBE(do_mov_510)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x16d")
int BPF_KPROBE(do_mov_511)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x1b8")
int BPF_KPROBE(do_mov_512)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x1c0")
int BPF_KPROBE(do_mov_513)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x1c8")
int BPF_KPROBE(do_mov_514)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x1d0")
int BPF_KPROBE(do_mov_515)
{
    u64 addr = ctx->r15 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x1d8")
int BPF_KPROBE(do_mov_516)
{
    u64 addr = ctx->r15 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x22c")
int BPF_KPROBE(do_mov_517)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tfilter+0x2a0")
int BPF_KPROBE(do_mov_518)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tfilter+0x357")
int BPF_KPROBE(do_mov_519)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x1cc")
int BPF_KPROBE(do_mov_520)
{
    u64 addr = ctx->r14 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x1de")
int BPF_KPROBE(do_mov_521)
{
    u64 addr = ctx->r14 + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x225")
int BPF_KPROBE(do_mov_522)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x303")
int BPF_KPROBE(do_mov_523)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x333")
int BPF_KPROBE(do_mov_524)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x430")
int BPF_KPROBE(do_mov_525)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x434")
int BPF_KPROBE(do_mov_526)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x49e")
int BPF_KPROBE(do_mov_527)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x52c")
int BPF_KPROBE(do_mov_528)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x553")
int BPF_KPROBE(do_mov_529)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x582")
int BPF_KPROBE(do_mov_530)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x5e1")
int BPF_KPROBE(do_mov_531)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x5ff")
int BPF_KPROBE(do_mov_532)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x63c")
int BPF_KPROBE(do_mov_533)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x65f")
int BPF_KPROBE(do_mov_534)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_destroy+0xeb")
int BPF_KPROBE(do_mov_535)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_destroy+0xff")
int BPF_KPROBE(do_mov_536)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x438")
int BPF_KPROBE(do_mov_537)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x4b6")
int BPF_KPROBE(do_mov_538)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x502")
int BPF_KPROBE(do_mov_539)
{
    u64 addr = ctx->r13 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x52e")
int BPF_KPROBE(do_mov_540)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x5a9")
int BPF_KPROBE(do_mov_541)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x615")
int BPF_KPROBE(do_mov_542)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x63c")
int BPF_KPROBE(do_mov_543)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x663")
int BPF_KPROBE(do_mov_544)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x68a")
int BPF_KPROBE(do_mov_545)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x6a8")
int BPF_KPROBE(do_mov_546)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x6d7")
int BPF_KPROBE(do_mov_547)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x719")
int BPF_KPROBE(do_mov_548)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x75d")
int BPF_KPROBE(do_mov_549)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x7af")
int BPF_KPROBE(do_mov_550)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_terse_dump+0x7a")
int BPF_KPROBE(do_mov_551)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x376")
int BPF_KPROBE(do_mov_552)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x41d")
int BPF_KPROBE(do_mov_553)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x444")
int BPF_KPROBE(do_mov_554)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x46b")
int BPF_KPROBE(do_mov_555)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x48f")
int BPF_KPROBE(do_mov_556)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x4c4")
int BPF_KPROBE(do_mov_557)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x4e1")
int BPF_KPROBE(do_mov_558)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x512")
int BPF_KPROBE(do_mov_559)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x53c")
int BPF_KPROBE(do_mov_560)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x563")
int BPF_KPROBE(do_mov_561)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x580")
int BPF_KPROBE(do_mov_562)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x1ed")
int BPF_KPROBE(do_mov_563)
{
    u64 addr = ctx->di + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x43a")
int BPF_KPROBE(do_mov_564)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x4ca")
int BPF_KPROBE(do_mov_565)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x652")
int BPF_KPROBE(do_mov_566)
{
    u64 addr = ctx->r9 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x674")
int BPF_KPROBE(do_mov_567)
{
    u64 addr = ctx->r9 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x67c")
int BPF_KPROBE(do_mov_568)
{
    u64 addr = ctx->r9 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x687")
int BPF_KPROBE(do_mov_569)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x68b")
int BPF_KPROBE(do_mov_570)
{
    u64 addr = ctx->r9 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x696")
int BPF_KPROBE(do_mov_571)
{
    u64 addr = ctx->r9 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x69e")
int BPF_KPROBE(do_mov_572)
{
    u64 addr = ctx->r9 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x7fd")
int BPF_KPROBE(do_mov_573)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x824")
int BPF_KPROBE(do_mov_574)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x874")
int BPF_KPROBE(do_mov_575)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x89d")
int BPF_KPROBE(do_mov_576)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x8ec")
int BPF_KPROBE(do_mov_577)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x91f")
int BPF_KPROBE(do_mov_578)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xa76")
int BPF_KPROBE(do_mov_579)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xaa1")
int BPF_KPROBE(do_mov_580)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xace")
int BPF_KPROBE(do_mov_581)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xb27")
int BPF_KPROBE(do_mov_582)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xb51")
int BPF_KPROBE(do_mov_583)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xb9f")
int BPF_KPROBE(do_mov_584)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xbe5")
int BPF_KPROBE(do_mov_585)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_set_ctrlact+0xd")
int BPF_KPROBE(do_mov_586)
{
    u64 addr = ctx->di + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_set_ctrlact+0x13")
int BPF_KPROBE(do_mov_587)
{
    u64 addr = ctx->di + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_pernet_del_id_list+0x4c")
int BPF_KPROBE(do_mov_588)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_pernet_del_id_list+0x50")
int BPF_KPROBE(do_mov_589)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_pernet_del_id_list+0x5d")
int BPF_KPROBE(do_mov_590)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_pernet_del_id_list+0x64")
int BPF_KPROBE(do_mov_591)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0x5f")
int BPF_KPROBE(do_mov_592)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0x7e")
int BPF_KPROBE(do_mov_593)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0x98")
int BPF_KPROBE(do_mov_594)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0xba")
int BPF_KPROBE(do_mov_595)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_unregister_action+0x68")
int BPF_KPROBE(do_mov_596)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_unregister_action+0x6c")
int BPF_KPROBE(do_mov_597)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_unregister_action+0x79")
int BPF_KPROBE(do_mov_598)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_unregister_action+0x80")
int BPF_KPROBE(do_mov_599)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_exec+0xd6")
int BPF_KPROBE(do_mov_600)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_exec+0x102")
int BPF_KPROBE(do_mov_601)
{
    u64 addr = ctx->di + 0x82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_cmd.constprop.0+0x30")
int BPF_KPROBE(do_mov_602)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_cmd.constprop.0+0x59")
int BPF_KPROBE(do_mov_603)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_add_ex+0x98")
int BPF_KPROBE(do_mov_604)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_add_ex+0x9b")
int BPF_KPROBE(do_mov_605)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_add_ex+0xa5")
int BPF_KPROBE(do_mov_606)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_add_ex+0x1db")
int BPF_KPROBE(do_mov_607)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_add_ex+0x1e5")
int BPF_KPROBE(do_mov_608)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0x7a")
int BPF_KPROBE(do_mov_609)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0xa4")
int BPF_KPROBE(do_mov_610)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0x10e")
int BPF_KPROBE(do_mov_611)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0x121")
int BPF_KPROBE(do_mov_612)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0xdd")
int BPF_KPROBE(do_mov_613)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0xef")
int BPF_KPROBE(do_mov_614)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0xf6")
int BPF_KPROBE(do_mov_615)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0xfa")
int BPF_KPROBE(do_mov_616)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0x18a")
int BPF_KPROBE(do_mov_617)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0x191")
int BPF_KPROBE(do_mov_618)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0x195")
int BPF_KPROBE(do_mov_619)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x4f")
int BPF_KPROBE(do_mov_620)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x5f")
int BPF_KPROBE(do_mov_621)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0xc6")
int BPF_KPROBE(do_mov_622)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x10f")
int BPF_KPROBE(do_mov_623)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x11c")
int BPF_KPROBE(do_mov_624)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x147")
int BPF_KPROBE(do_mov_625)
{
    u64 addr = ctx->r12 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x153")
int BPF_KPROBE(do_mov_626)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x15c")
int BPF_KPROBE(do_mov_627)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x168")
int BPF_KPROBE(do_mov_628)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x174")
int BPF_KPROBE(do_mov_629)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x17c")
int BPF_KPROBE(do_mov_630)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x1c1")
int BPF_KPROBE(do_mov_631)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x1cf")
int BPF_KPROBE(do_mov_632)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x1d3")
int BPF_KPROBE(do_mov_633)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x221")
int BPF_KPROBE(do_mov_634)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x235")
int BPF_KPROBE(do_mov_635)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_search+0x5a")
int BPF_KPROBE(do_mov_636)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_update_hw_stats+0xeb")
int BPF_KPROBE(do_mov_637)
{
    u64 addr = ctx->bx + 0xc6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_update_hw_stats+0xf2")
int BPF_KPROBE(do_mov_638)
{
    u64 addr = ctx->bx + 0xc5;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_del_ex+0x110")
int BPF_KPROBE(do_mov_639)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_destroy+0x55")
int BPF_KPROBE(do_mov_640)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_action_load_ops+0x96")
int BPF_KPROBE(do_mov_641)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_action_load_ops+0x161")
int BPF_KPROBE(do_mov_642)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_action_load_ops+0x17e")
int BPF_KPROBE(do_mov_643)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x6d")
int BPF_KPROBE(do_mov_644)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x119")
int BPF_KPROBE(do_mov_645)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x12f")
int BPF_KPROBE(do_mov_646)
{
    u64 addr = ctx->r10 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x1fa")
int BPF_KPROBE(do_mov_647)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x22f")
int BPF_KPROBE(do_mov_648)
{
    u64 addr = ctx->ax + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x2b3")
int BPF_KPROBE(do_mov_649)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init+0xbc")
int BPF_KPROBE(do_mov_650)
{
    u64 addr = ctx->r15 + ctx->r13 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init+0x21c")
int BPF_KPROBE(do_mov_651)
{
    u64 addr = ctx->ax + ctx->r15 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init+0x29e")
int BPF_KPROBE(do_mov_652)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init+0x2c9")
int BPF_KPROBE(do_mov_653)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_dump_1+0xfa")
int BPF_KPROBE(do_mov_654)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0xdb")
int BPF_KPROBE(do_mov_655)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0x1bd")
int BPF_KPROBE(do_mov_656)
{
    u64 addr = ctx->ax + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0x1df")
int BPF_KPROBE(do_mov_657)
{
    u64 addr = ctx->cx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0x3c9")
int BPF_KPROBE(do_mov_658)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0x3fe")
int BPF_KPROBE(do_mov_659)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0xab")
int BPF_KPROBE(do_mov_660)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0xc9")
int BPF_KPROBE(do_mov_661)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x144")
int BPF_KPROBE(do_mov_662)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x159")
int BPF_KPROBE(do_mov_663)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x1e6")
int BPF_KPROBE(do_mov_664)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x1f1")
int BPF_KPROBE(do_mov_665)
{
    u64 addr = ctx->si + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x1f4")
int BPF_KPROBE(do_mov_666)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x20d")
int BPF_KPROBE(do_mov_667)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x2d5")
int BPF_KPROBE(do_mov_668)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x2fb")
int BPF_KPROBE(do_mov_669)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0xe5")
int BPF_KPROBE(do_mov_670)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x17c")
int BPF_KPROBE(do_mov_671)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x21c")
int BPF_KPROBE(do_mov_672)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x246")
int BPF_KPROBE(do_mov_673)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x29e")
int BPF_KPROBE(do_mov_674)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x2c4")
int BPF_KPROBE(do_mov_675)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x2e1")
int BPF_KPROBE(do_mov_676)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_dump+0x56")
int BPF_KPROBE(do_mov_677)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_get_fill.constprop.0+0x6c")
int BPF_KPROBE(do_mov_678)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_get_fill.constprop.0+0xc7")
int BPF_KPROBE(do_mov_679)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_get_fill.constprop.0+0xde")
int BPF_KPROBE(do_mov_680)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x1eb")
int BPF_KPROBE(do_mov_681)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x243")
int BPF_KPROBE(do_mov_682)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x313")
int BPF_KPROBE(do_mov_683)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x394")
int BPF_KPROBE(do_mov_684)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x43b")
int BPF_KPROBE(do_mov_685)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x52a")
int BPF_KPROBE(do_mov_686)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x568")
int BPF_KPROBE(do_mov_687)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x585")
int BPF_KPROBE(do_mov_688)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_add+0x16c")
int BPF_KPROBE(do_mov_689)
{
    u64 addr = ctx->r13 + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_add+0x1b7")
int BPF_KPROBE(do_mov_690)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_action+0x124")
int BPF_KPROBE(do_mov_691)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_action+0x14a")
int BPF_KPROBE(do_mov_692)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x20")
int BPF_KPROBE(do_mov_693)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x27")
int BPF_KPROBE(do_mov_694)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x30")
int BPF_KPROBE(do_mov_695)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x3b")
int BPF_KPROBE(do_mov_696)
{
    u64 addr = ctx->si + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x4d")
int BPF_KPROBE(do_mov_697)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x54")
int BPF_KPROBE(do_mov_698)
{
    u64 addr = ctx->si + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x60")
int BPF_KPROBE(do_mov_699)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x68")
int BPF_KPROBE(do_mov_700)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x25")
int BPF_KPROBE(do_mov_701)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x2c")
int BPF_KPROBE(do_mov_702)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x35")
int BPF_KPROBE(do_mov_703)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x46")
int BPF_KPROBE(do_mov_704)
{
    u64 addr = ctx->si + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x50")
int BPF_KPROBE(do_mov_705)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x57")
int BPF_KPROBE(do_mov_706)
{
    u64 addr = ctx->si + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x63")
int BPF_KPROBE(do_mov_707)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x6b")
int BPF_KPROBE(do_mov_708)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_set_limit+0x59")
int BPF_KPROBE(do_mov_709)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_set_limit+0x67")
int BPF_KPROBE(do_mov_710)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_init+0x42")
int BPF_KPROBE(do_mov_711)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_init+0x58")
int BPF_KPROBE(do_mov_712)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_init+0xd9")
int BPF_KPROBE(do_mov_713)
{
    u64 addr = ctx->ax + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x22")
int BPF_KPROBE(do_mov_714)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x29")
int BPF_KPROBE(do_mov_715)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x32")
int BPF_KPROBE(do_mov_716)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x3c")
int BPF_KPROBE(do_mov_717)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x4e")
int BPF_KPROBE(do_mov_718)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x55")
int BPF_KPROBE(do_mov_719)
{
    u64 addr = ctx->si + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x7b")
int BPF_KPROBE(do_mov_720)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x81")
int BPF_KPROBE(do_mov_721)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x8d")
int BPF_KPROBE(do_mov_722)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xa0")
int BPF_KPROBE(do_mov_723)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xa3")
int BPF_KPROBE(do_mov_724)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xb9")
int BPF_KPROBE(do_mov_725)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xc0")
int BPF_KPROBE(do_mov_726)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xc3")
int BPF_KPROBE(do_mov_727)
{
    u64 addr = ctx->di + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xdf")
int BPF_KPROBE(do_mov_728)
{
    u64 addr = ctx->di + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xf3")
int BPF_KPROBE(do_mov_729)
{
    u64 addr = ctx->di + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xfa")
int BPF_KPROBE(do_mov_730)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x103")
int BPF_KPROBE(do_mov_731)
{
    u64 addr = ctx->di + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_hd_init+0x23")
int BPF_KPROBE(do_mov_732)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_hd_init+0x71")
int BPF_KPROBE(do_mov_733)
{
    u64 addr = ctx->ax + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fifo_hd_init+0x8a")
int BPF_KPROBE(do_mov_734)
{
    u64 addr = ctx->ax + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_deactivate_class+0x3c")
int BPF_KPROBE(do_mov_735)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_deactivate_class+0x40")
int BPF_KPROBE(do_mov_736)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_deactivate_class+0x58")
int BPF_KPROBE(do_mov_737)
{
    u64 addr = ctx->r8 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_deactivate_class+0x61")
int BPF_KPROBE(do_mov_738)
{
    u64 addr = ctx->r8 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_sync_defmap+0x3c")
int BPF_KPROBE(do_mov_739)
{
    u64 addr = ctx->dx + ctx->cx * 0x8 + 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_sync_defmap+0xd6")
int BPF_KPROBE(do_mov_740)
{
    u64 addr = ctx->dx + ctx->r8 * 0x8 + 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x1f")
int BPF_KPROBE(do_mov_741)
{
    u64 addr = ctx->di + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x2b")
int BPF_KPROBE(do_mov_742)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x3d")
int BPF_KPROBE(do_mov_743)
{
    u64 addr = ctx->di + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x4a")
int BPF_KPROBE(do_mov_744)
{
    u64 addr = ctx->di + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x5a")
int BPF_KPROBE(do_mov_745)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x68")
int BPF_KPROBE(do_mov_746)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x6f")
int BPF_KPROBE(do_mov_747)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x80")
int BPF_KPROBE(do_mov_748)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_stats+0x1a")
int BPF_KPROBE(do_mov_749)
{
    u64 addr = ctx->ax + 0x2f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x18")
int BPF_KPROBE(do_mov_750)
{
    u64 addr = ctx->di - 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x1f")
int BPF_KPROBE(do_mov_751)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x26")
int BPF_KPROBE(do_mov_752)
{
    u64 addr = ctx->di - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x2e")
int BPF_KPROBE(do_mov_753)
{
    u64 addr = ctx->di - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x3b")
int BPF_KPROBE(do_mov_754)
{
    u64 addr = ctx->r13 + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x52")
int BPF_KPROBE(do_mov_755)
{
    u64 addr = ctx->r13 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x65")
int BPF_KPROBE(do_mov_756)
{
    u64 addr = ctx->r13 + 0x3e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x70")
int BPF_KPROBE(do_mov_757)
{
    u64 addr = ctx->r13 + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0xc1")
int BPF_KPROBE(do_mov_758)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0xc9")
int BPF_KPROBE(do_mov_759)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0xd4")
int BPF_KPROBE(do_mov_760)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0xdf")
int BPF_KPROBE(do_mov_761)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0xea")
int BPF_KPROBE(do_mov_762)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class_stats+0x53")
int BPF_KPROBE(do_mov_763)
{
    u64 addr = ctx->si + 0x11c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class_stats+0x64")
int BPF_KPROBE(do_mov_764)
{
    u64 addr = ctx->si + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class_stats+0x81")
int BPF_KPROBE(do_mov_765)
{
    u64 addr = ctx->bx + 0xf4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class_stats+0x9a")
int BPF_KPROBE(do_mov_766)
{
    u64 addr = ctx->bx + 0x11c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_walk+0x56")
int BPF_KPROBE(do_mov_767)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_walk+0x83")
int BPF_KPROBE(do_mov_768)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_opt_parse+0x65")
int BPF_KPROBE(do_mov_769)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_opt_parse+0x8b")
int BPF_KPROBE(do_mov_770)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_fopt.isra.0+0x36")
int BPF_KPROBE(do_mov_771)
{
    u64 addr = ctx->r12 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_fopt.isra.0+0x73")
int BPF_KPROBE(do_mov_772)
{
    u64 addr = ctx->r12 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_fopt.isra.0+0x87")
int BPF_KPROBE(do_mov_773)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_wrr.isra.0+0x10")
int BPF_KPROBE(do_mov_774)
{
    u64 addr = ctx->di + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_wrr.isra.0+0x1b")
int BPF_KPROBE(do_mov_775)
{
    u64 addr = ctx->di + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_wrr.isra.0+0x6b")
int BPF_KPROBE(do_mov_776)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_wrr.isra.0+0x6e")
int BPF_KPROBE(do_mov_777)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_wrr.isra.0+0x79")
int BPF_KPROBE(do_mov_778)
{
    u64 addr = ctx->di + 0x21;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_destroy+0x1e")
int BPF_KPROBE(do_mov_779)
{
    u64 addr = ctx->di + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_destroy+0x57")
int BPF_KPROBE(do_mov_780)
{
    u64 addr = ctx->r12 + 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_graft+0x6c")
int BPF_KPROBE(do_mov_781)
{
    u64 addr = ctx->r14 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_graft+0xef")
int BPF_KPROBE(do_mov_782)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x16b")
int BPF_KPROBE(do_mov_783)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x183")
int BPF_KPROBE(do_mov_784)
{
    u64 addr = ctx->di + 0xaa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x1e6")
int BPF_KPROBE(do_mov_785)
{
    u64 addr = ctx->r13 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x217")
int BPF_KPROBE(do_mov_786)
{
    u64 addr = ctx->bx + ctx->ax * 0x4 + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x2dd")
int BPF_KPROBE(do_mov_787)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x2f5")
int BPF_KPROBE(do_mov_788)
{
    u64 addr = ctx->bx + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x305")
int BPF_KPROBE(do_mov_789)
{
    u64 addr = ctx->bx + 0x3f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x310")
int BPF_KPROBE(do_mov_790)
{
    u64 addr = ctx->bx + 0x400;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x320")
int BPF_KPROBE(do_mov_791)
{
    u64 addr = ctx->bx + 0x400;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x333")
int BPF_KPROBE(do_mov_792)
{
    u64 addr = ctx->ax + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x347")
int BPF_KPROBE(do_mov_793)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x80")
int BPF_KPROBE(do_mov_794)
{
    u64 addr = ctx->bx + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x104")
int BPF_KPROBE(do_mov_795)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x112")
int BPF_KPROBE(do_mov_796)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x118")
int BPF_KPROBE(do_mov_797)
{
    u64 addr = ctx->bx + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x124")
int BPF_KPROBE(do_mov_798)
{
    u64 addr = ctx->bx + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x146")
int BPF_KPROBE(do_mov_799)
{
    u64 addr = ctx->bx + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x14d")
int BPF_KPROBE(do_mov_800)
{
    u64 addr = ctx->bx + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x16f")
int BPF_KPROBE(do_mov_801)
{
    u64 addr = ctx->bx + 0x230;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x176")
int BPF_KPROBE(do_mov_802)
{
    u64 addr = ctx->bx + 0x238;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x183")
int BPF_KPROBE(do_mov_803)
{
    u64 addr = ctx->bx + 0x202;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x18a")
int BPF_KPROBE(do_mov_804)
{
    u64 addr = ctx->bx + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x190")
int BPF_KPROBE(do_mov_805)
{
    u64 addr = ctx->bx + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x197")
int BPF_KPROBE(do_mov_806)
{
    u64 addr = ctx->bx + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x1a2")
int BPF_KPROBE(do_mov_807)
{
    u64 addr = ctx->bx + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x1b1")
int BPF_KPROBE(do_mov_808)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x1c6")
int BPF_KPROBE(do_mov_809)
{
    u64 addr = ctx->bx + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x1fc")
int BPF_KPROBE(do_mov_810)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x20a")
int BPF_KPROBE(do_mov_811)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x244")
int BPF_KPROBE(do_mov_812)
{
    u64 addr = ctx->dx + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x25d")
int BPF_KPROBE(do_mov_813)
{
    u64 addr = ctx->bx + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x281")
int BPF_KPROBE(do_mov_814)
{
    u64 addr = ctx->r15 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x29b")
int BPF_KPROBE(do_mov_815)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x44")
int BPF_KPROBE(do_mov_816)
{
    u64 addr = ctx->r14 + 0x3f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x9d")
int BPF_KPROBE(do_mov_817)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0xb3")
int BPF_KPROBE(do_mov_818)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0xbf")
int BPF_KPROBE(do_mov_819)
{
    u64 addr = ctx->ax + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x159")
int BPF_KPROBE(do_mov_820)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x1e6")
int BPF_KPROBE(do_mov_821)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x225")
int BPF_KPROBE(do_mov_822)
{
    u64 addr = ctx->r14 + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x230")
int BPF_KPROBE(do_mov_823)
{
    u64 addr = ctx->ax + 0x470;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x2eb")
int BPF_KPROBE(do_mov_824)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x2f0")
int BPF_KPROBE(do_mov_825)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x391")
int BPF_KPROBE(do_mov_826)
{
    u64 addr = ctx->r15 + 0xa9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x3b6")
int BPF_KPROBE(do_mov_827)
{
    u64 addr = ctx->r13 + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x3c2")
int BPF_KPROBE(do_mov_828)
{
    u64 addr = ctx->r13 + 0xa9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x3ef")
int BPF_KPROBE(do_mov_829)
{
    u64 addr = ctx->ax + ctx->dx * 0x8 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x423")
int BPF_KPROBE(do_mov_830)
{
    u64 addr = ctx->di + ctx->ax * 0x8 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x434")
int BPF_KPROBE(do_mov_831)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x438")
int BPF_KPROBE(do_mov_832)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x457")
int BPF_KPROBE(do_mov_833)
{
    u64 addr = ctx->ax + ctx->si * 0x8 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x47f")
int BPF_KPROBE(do_mov_834)
{
    u64 addr = ctx->ax + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x489")
int BPF_KPROBE(do_mov_835)
{
    u64 addr = ctx->ax + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x4a6")
int BPF_KPROBE(do_mov_836)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x501")
int BPF_KPROBE(do_mov_837)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x517")
int BPF_KPROBE(do_mov_838)
{
    u64 addr = ctx->r13 + 0xa9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x52e")
int BPF_KPROBE(do_mov_839)
{
    u64 addr = ctx->r13 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x546")
int BPF_KPROBE(do_mov_840)
{
    u64 addr = ctx->di + 0x470;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x59d")
int BPF_KPROBE(do_mov_841)
{
    u64 addr = ctx->di + 0x470;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5ba")
int BPF_KPROBE(do_mov_842)
{
    u64 addr = ctx->r14 + 0x3f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5c1")
int BPF_KPROBE(do_mov_843)
{
    u64 addr = ctx->r14 + 0x400;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5e0")
int BPF_KPROBE(do_mov_844)
{
    u64 addr = ctx->r14 + 0x408;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5f6")
int BPF_KPROBE(do_mov_845)
{
    u64 addr = ctx->r14 + ctx->cx * 0x8 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x656")
int BPF_KPROBE(do_mov_846)
{
    u64 addr = ctx->ax + ctx->dx * 0x8 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x69b")
int BPF_KPROBE(do_mov_847)
{
    u64 addr = ctx->si + ctx->ax * 0x8 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x6ac")
int BPF_KPROBE(do_mov_848)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x6b0")
int BPF_KPROBE(do_mov_849)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x727")
int BPF_KPROBE(do_mov_850)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x7ac")
int BPF_KPROBE(do_mov_851)
{
    u64 addr = ctx->r14 + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump+0x64")
int BPF_KPROBE(do_mov_852)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class+0x27")
int BPF_KPROBE(do_mov_853)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class+0x38")
int BPF_KPROBE(do_mov_854)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class+0x45")
int BPF_KPROBE(do_mov_855)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class+0x8a")
int BPF_KPROBE(do_mov_856)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0xd0")
int BPF_KPROBE(do_mov_857)
{
    u64 addr = ctx->r12 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0xee")
int BPF_KPROBE(do_mov_858)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0xf1")
int BPF_KPROBE(do_mov_859)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x12f")
int BPF_KPROBE(do_mov_860)
{
    u64 addr = ctx->r12 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x1a0")
int BPF_KPROBE(do_mov_861)
{
    u64 addr = ctx->r12 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x288")
int BPF_KPROBE(do_mov_862)
{
    u64 addr = ctx->r12 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x2e4")
int BPF_KPROBE(do_mov_863)
{
    u64 addr = ctx->dx + ctx->ax * 0x8 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x2f9")
int BPF_KPROBE(do_mov_864)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x2fd")
int BPF_KPROBE(do_mov_865)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x390")
int BPF_KPROBE(do_mov_866)
{
    u64 addr = ctx->r12 + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x3db")
int BPF_KPROBE(do_mov_867)
{
    u64 addr = ctx->r12 + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x3ed")
int BPF_KPROBE(do_mov_868)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x156")
int BPF_KPROBE(do_mov_869)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x257")
int BPF_KPROBE(do_mov_870)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x29c")
int BPF_KPROBE(do_mov_871)
{
    u64 addr = ctx->r12 + ctx->dx * 0x4 + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x35e")
int BPF_KPROBE(do_mov_872)
{
    u64 addr = ctx->r12 + 0x47c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x3b5")
int BPF_KPROBE(do_mov_873)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x3ea")
int BPF_KPROBE(do_mov_874)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x4b0")
int BPF_KPROBE(do_mov_875)
{
    u64 addr = ctx->si + ctx->ax * 0x8 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x4c5")
int BPF_KPROBE(do_mov_876)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x4c9")
int BPF_KPROBE(do_mov_877)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x5b9")
int BPF_KPROBE(do_mov_878)
{
    u64 addr = ctx->r11 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x5d7")
int BPF_KPROBE(do_mov_879)
{
    u64 addr = ctx->r11 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x604")
int BPF_KPROBE(do_mov_880)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x60d")
int BPF_KPROBE(do_mov_881)
{
    u64 addr = ctx->r11 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x614")
int BPF_KPROBE(do_mov_882)
{
    u64 addr = ctx->r11 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x623")
int BPF_KPROBE(do_mov_883)
{
    u64 addr = ctx->r11 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x627")
int BPF_KPROBE(do_mov_884)
{
    u64 addr = ctx->r11 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x636")
int BPF_KPROBE(do_mov_885)
{
    u64 addr = ctx->r11 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x65c")
int BPF_KPROBE(do_mov_886)
{
    u64 addr = ctx->r11 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x6ab")
int BPF_KPROBE(do_mov_887)
{
    u64 addr = ctx->r11 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x6b9")
int BPF_KPROBE(do_mov_888)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x6c7")
int BPF_KPROBE(do_mov_889)
{
    u64 addr = ctx->r11 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x6d7")
int BPF_KPROBE(do_mov_890)
{
    u64 addr = ctx->r11 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x6e2")
int BPF_KPROBE(do_mov_891)
{
    u64 addr = ctx->r10 + 0xaa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x728")
int BPF_KPROBE(do_mov_892)
{
    u64 addr = ctx->r11 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x769")
int BPF_KPROBE(do_mov_893)
{
    u64 addr = ctx->r11 + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x77c")
int BPF_KPROBE(do_mov_894)
{
    u64 addr = ctx->r11 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x790")
int BPF_KPROBE(do_mov_895)
{
    u64 addr = ctx->r11 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x7ee")
int BPF_KPROBE(do_mov_896)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x88c")
int BPF_KPROBE(do_mov_897)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x8ba")
int BPF_KPROBE(do_mov_898)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x952")
int BPF_KPROBE(do_mov_899)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x964")
int BPF_KPROBE(do_mov_900)
{
    u64 addr = ctx->r11 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x981")
int BPF_KPROBE(do_mov_901)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x9a8")
int BPF_KPROBE(do_mov_902)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x9b9")
int BPF_KPROBE(do_mov_903)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x9e3")
int BPF_KPROBE(do_mov_904)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0xa86")
int BPF_KPROBE(do_mov_905)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0x75")
int BPF_KPROBE(do_mov_906)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0xa2")
int BPF_KPROBE(do_mov_907)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0xb3")
int BPF_KPROBE(do_mov_908)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0xb7")
int BPF_KPROBE(do_mov_909)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0xf7")
int BPF_KPROBE(do_mov_910)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0xfa")
int BPF_KPROBE(do_mov_911)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0x10f")
int BPF_KPROBE(do_mov_912)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0x13d")
int BPF_KPROBE(do_mov_913)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0x10")
int BPF_KPROBE(do_mov_914)
{
    u64 addr = ctx->si + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0x2b")
int BPF_KPROBE(do_mov_915)
{
    u64 addr = ctx->si + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0x40")
int BPF_KPROBE(do_mov_916)
{
    u64 addr = ctx->r8 + ctx->cx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0x8e")
int BPF_KPROBE(do_mov_917)
{
    u64 addr = ctx->si + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0x95")
int BPF_KPROBE(do_mov_918)
{
    u64 addr = ctx->si + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0xa0")
int BPF_KPROBE(do_mov_919)
{
    u64 addr = ctx->si + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0xab")
int BPF_KPROBE(do_mov_920)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class_stats+0xe0")
int BPF_KPROBE(do_mov_921)
{
    u64 addr = ctx->bx + 0xcc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class_stats+0x104")
int BPF_KPROBE(do_mov_922)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class_stats+0x13d")
int BPF_KPROBE(do_mov_923)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class_stats+0x144")
int BPF_KPROBE(do_mov_924)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_walk+0x56")
int BPF_KPROBE(do_mov_925)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_walk+0x83")
int BPF_KPROBE(do_mov_926)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class+0x3f")
int BPF_KPROBE(do_mov_927)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class+0x44")
int BPF_KPROBE(do_mov_928)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class+0x5d")
int BPF_KPROBE(do_mov_929)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class+0x182")
int BPF_KPROBE(do_mov_930)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x52")
int BPF_KPROBE(do_mov_931)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x5d")
int BPF_KPROBE(do_mov_932)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x6b")
int BPF_KPROBE(do_mov_933)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x72")
int BPF_KPROBE(do_mov_934)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x156")
int BPF_KPROBE(do_mov_935)
{
    u64 addr = ctx->bx + 0x8f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x165")
int BPF_KPROBE(do_mov_936)
{
    u64 addr = ctx->bx + 0x8f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x199")
int BPF_KPROBE(do_mov_937)
{
    u64 addr = ctx->bx + 0x1b4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x1b5")
int BPF_KPROBE(do_mov_938)
{
    u64 addr = ctx->bx + 0x19c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x1bf")
int BPF_KPROBE(do_mov_939)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x1e5")
int BPF_KPROBE(do_mov_940)
{
    u64 addr = ctx->dx + ctx->r14 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x2bc")
int BPF_KPROBE(do_mov_941)
{
    u64 addr = ctx->bx + 0x8fc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x2e4")
int BPF_KPROBE(do_mov_942)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x308")
int BPF_KPROBE(do_mov_943)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_attach+0xb6")
int BPF_KPROBE(do_mov_944)
{
    u64 addr = ctx->r12 + 0x8f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0xd4")
int BPF_KPROBE(do_mov_945)
{
    u64 addr = ctx->dx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0xdb")
int BPF_KPROBE(do_mov_946)
{
    u64 addr = ctx->dx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0xe6")
int BPF_KPROBE(do_mov_947)
{
    u64 addr = ctx->dx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0xf1")
int BPF_KPROBE(do_mov_948)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0x201")
int BPF_KPROBE(do_mov_949)
{
    u64 addr = ctx->dx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0x208")
int BPF_KPROBE(do_mov_950)
{
    u64 addr = ctx->dx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0x213")
int BPF_KPROBE(do_mov_951)
{
    u64 addr = ctx->dx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0x21e")
int BPF_KPROBE(do_mov_952)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump+0x3d")
int BPF_KPROBE(do_mov_953)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump+0x59")
int BPF_KPROBE(do_mov_954)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump+0x100")
int BPF_KPROBE(do_mov_955)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x4d")
int BPF_KPROBE(do_mov_956)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x58")
int BPF_KPROBE(do_mov_957)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x77")
int BPF_KPROBE(do_mov_958)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0xb0")
int BPF_KPROBE(do_mov_959)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x103")
int BPF_KPROBE(do_mov_960)
{
    u64 addr = ctx->r12 + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x10f")
int BPF_KPROBE(do_mov_961)
{
    u64 addr = ctx->r12 + 0x8e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x12f")
int BPF_KPROBE(do_mov_962)
{
    u64 addr = ctx->r12 + 0x290;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x13b")
int BPF_KPROBE(do_mov_963)
{
    u64 addr = ctx->r12 + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x147")
int BPF_KPROBE(do_mov_964)
{
    u64 addr = ctx->r12 + 0x2a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x154")
int BPF_KPROBE(do_mov_965)
{
    u64 addr = ctx->r12 + 0x2a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x17d")
int BPF_KPROBE(do_mov_966)
{
    u64 addr = ctx->r12 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x189")
int BPF_KPROBE(do_mov_967)
{
    u64 addr = ctx->r12 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x195")
int BPF_KPROBE(do_mov_968)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_deactivate_prios+0xd0")
int BPF_KPROBE(do_mov_969)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_deactivate_prios+0x131")
int BPF_KPROBE(do_mov_970)
{
    u64 addr = ctx->cx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_deactivate_prios+0x13c")
int BPF_KPROBE(do_mov_971)
{
    u64 addr = ctx->cx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_deactivate_prios+0x22a")
int BPF_KPROBE(do_mov_972)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_deactivate_prios+0x25a")
int BPF_KPROBE(do_mov_973)
{
    u64 addr = ctx->r11 + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class_mode+0x87")
int BPF_KPROBE(do_mov_974)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class_mode+0xad")
int BPF_KPROBE(do_mov_975)
{
    u64 addr = ctx->r12 + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class_mode+0xe3")
int BPF_KPROBE(do_mov_976)
{
    u64 addr = ctx->r12 + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class_mode+0xf5")
int BPF_KPROBE(do_mov_977)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_qlen_notify+0x26")
int BPF_KPROBE(do_mov_978)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dequeue+0x42")
int BPF_KPROBE(do_mov_979)
{
    u64 addr = ctx->di + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dequeue+0x52")
int BPF_KPROBE(do_mov_980)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dequeue+0xed")
int BPF_KPROBE(do_mov_981)
{
    u64 addr = ctx->bx + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dequeue+0x44f")
int BPF_KPROBE(do_mov_982)
{
    u64 addr = ctx->di + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_graft+0x76")
int BPF_KPROBE(do_mov_983)
{
    u64 addr = ctx->r15 + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_graft+0xee")
int BPF_KPROBE(do_mov_984)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x45")
int BPF_KPROBE(do_mov_985)
{
    u64 addr = ctx->bx + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x4c")
int BPF_KPROBE(do_mov_986)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x5b")
int BPF_KPROBE(do_mov_987)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x88")
int BPF_KPROBE(do_mov_988)
{
    u64 addr = ctx->bx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x8f")
int BPF_KPROBE(do_mov_989)
{
    u64 addr = ctx->bx + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x9a")
int BPF_KPROBE(do_mov_990)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0xa6")
int BPF_KPROBE(do_mov_991)
{
    u64 addr = ctx->bx + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0xb0")
int BPF_KPROBE(do_mov_992)
{
    u64 addr = ctx->bx + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0xc9")
int BPF_KPROBE(do_mov_993)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x137")
int BPF_KPROBE(do_mov_994)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy_class_offload+0x31a")
int BPF_KPROBE(do_mov_995)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy_class_offload+0x3c2")
int BPF_KPROBE(do_mov_996)
{
    u64 addr = ctx->dx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy_class_offload+0x3c6")
int BPF_KPROBE(do_mov_997)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy_class_offload+0x3d2")
int BPF_KPROBE(do_mov_998)
{
    u64 addr = ctx->si + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy_class_offload+0x3dd")
int BPF_KPROBE(do_mov_999)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy+0x98")
int BPF_KPROBE(do_mov_1000)
{
    u64 addr = ctx->bx + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy+0x379")
int BPF_KPROBE(do_mov_1001)
{
    u64 addr = ctx->r12 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy+0x385")
int BPF_KPROBE(do_mov_1002)
{
    u64 addr = ctx->r12 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy+0x391")
int BPF_KPROBE(do_mov_1003)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_delete+0x2bd")
int BPF_KPROBE(do_mov_1004)
{
    u64 addr = ctx->r14 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_delete+0x2e9")
int BPF_KPROBE(do_mov_1005)
{
    u64 addr = ctx->r14 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0xe6")
int BPF_KPROBE(do_mov_1006)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0xe9")
int BPF_KPROBE(do_mov_1007)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x20d")
int BPF_KPROBE(do_mov_1008)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x214")
int BPF_KPROBE(do_mov_1009)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x21d")
int BPF_KPROBE(do_mov_1010)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x22e")
int BPF_KPROBE(do_mov_1011)
{
    u64 addr = ctx->bx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x25a")
int BPF_KPROBE(do_mov_1012)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x25d")
int BPF_KPROBE(do_mov_1013)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x2b3")
int BPF_KPROBE(do_mov_1014)
{
    u64 addr = ctx->r12 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x32b")
int BPF_KPROBE(do_mov_1015)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x333")
int BPF_KPROBE(do_mov_1016)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x342")
int BPF_KPROBE(do_mov_1017)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x349")
int BPF_KPROBE(do_mov_1018)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x37d")
int BPF_KPROBE(do_mov_1019)
{
    u64 addr = ctx->si + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x39f")
int BPF_KPROBE(do_mov_1020)
{
    u64 addr = ctx->ax + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x3b7")
int BPF_KPROBE(do_mov_1021)
{
    u64 addr = ctx->cx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x3c9")
int BPF_KPROBE(do_mov_1022)
{
    u64 addr = ctx->si + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x3d5")
int BPF_KPROBE(do_mov_1023)
{
    u64 addr = ctx->si + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x54a")
int BPF_KPROBE(do_mov_1024)
{
    u64 addr = ctx->si + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x583")
int BPF_KPROBE(do_mov_1025)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x5b1")
int BPF_KPROBE(do_mov_1026)
{
    u64 addr = ctx->ax + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x72b")
int BPF_KPROBE(do_mov_1027)
{
    u64 addr = ctx->cx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x746")
int BPF_KPROBE(do_mov_1028)
{
    u64 addr = ctx->cx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x754")
int BPF_KPROBE(do_mov_1029)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x76e")
int BPF_KPROBE(do_mov_1030)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x867")
int BPF_KPROBE(do_mov_1031)
{
    u64 addr = ctx->cx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x877")
int BPF_KPROBE(do_mov_1032)
{
    u64 addr = ctx->cx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x885")
int BPF_KPROBE(do_mov_1033)
{
    u64 addr = ctx->cx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x894")
int BPF_KPROBE(do_mov_1034)
{
    u64 addr = ctx->cx + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x8a3")
int BPF_KPROBE(do_mov_1035)
{
    u64 addr = ctx->cx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x8b4")
int BPF_KPROBE(do_mov_1036)
{
    u64 addr = ctx->cx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x8cb")
int BPF_KPROBE(do_mov_1037)
{
    u64 addr = ctx->cx + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x8d5")
int BPF_KPROBE(do_mov_1038)
{
    u64 addr = ctx->cx + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x936")
int BPF_KPROBE(do_mov_1039)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x964")
int BPF_KPROBE(do_mov_1040)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xb4b")
int BPF_KPROBE(do_mov_1041)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xc0a")
int BPF_KPROBE(do_mov_1042)
{
    u64 addr = ctx->bx + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xc32")
int BPF_KPROBE(do_mov_1043)
{
    u64 addr = ctx->bx + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xc37")
int BPF_KPROBE(do_mov_1044)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xc46")
int BPF_KPROBE(do_mov_1045)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xdc3")
int BPF_KPROBE(do_mov_1046)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xdf0")
int BPF_KPROBE(do_mov_1047)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0x38")
int BPF_KPROBE(do_mov_1048)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0x59")
int BPF_KPROBE(do_mov_1049)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0x8d")
int BPF_KPROBE(do_mov_1050)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0xab")
int BPF_KPROBE(do_mov_1051)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0xd2")
int BPF_KPROBE(do_mov_1052)
{
    u64 addr = ctx->si + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0xf4")
int BPF_KPROBE(do_mov_1053)
{
    u64 addr = ctx->si + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0x89")
int BPF_KPROBE(do_mov_1054)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0x9b")
int BPF_KPROBE(do_mov_1055)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xb1")
int BPF_KPROBE(do_mov_1056)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xce")
int BPF_KPROBE(do_mov_1057)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xe1")
int BPF_KPROBE(do_mov_1058)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xe4")
int BPF_KPROBE(do_mov_1059)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xf7")
int BPF_KPROBE(do_mov_1060)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xfa")
int BPF_KPROBE(do_mov_1061)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0x102")
int BPF_KPROBE(do_mov_1062)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0x10a")
int BPF_KPROBE(do_mov_1063)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x43")
int BPF_KPROBE(do_mov_1064)
{
    u64 addr = ctx->bx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x55")
int BPF_KPROBE(do_mov_1065)
{
    u64 addr = ctx->bx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x60")
int BPF_KPROBE(do_mov_1066)
{
    u64 addr = ctx->bx + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x6b")
int BPF_KPROBE(do_mov_1067)
{
    u64 addr = ctx->bx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x76")
int BPF_KPROBE(do_mov_1068)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x81")
int BPF_KPROBE(do_mov_1069)
{
    u64 addr = ctx->bx + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x8c")
int BPF_KPROBE(do_mov_1070)
{
    u64 addr = ctx->bx + 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x97")
int BPF_KPROBE(do_mov_1071)
{
    u64 addr = ctx->bx + 0x148;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xa2")
int BPF_KPROBE(do_mov_1072)
{
    u64 addr = ctx->bx + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xad")
int BPF_KPROBE(do_mov_1073)
{
    u64 addr = ctx->bx + 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xb8")
int BPF_KPROBE(do_mov_1074)
{
    u64 addr = ctx->bx + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xc3")
int BPF_KPROBE(do_mov_1075)
{
    u64 addr = ctx->bx + 0x2e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xcd")
int BPF_KPROBE(do_mov_1076)
{
    u64 addr = ctx->bx + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xd8")
int BPF_KPROBE(do_mov_1077)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xe3")
int BPF_KPROBE(do_mov_1078)
{
    u64 addr = ctx->bx + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x105")
int BPF_KPROBE(do_mov_1079)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x110")
int BPF_KPROBE(do_mov_1080)
{
    u64 addr = ctx->bx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x11b")
int BPF_KPROBE(do_mov_1081)
{
    u64 addr = ctx->bx + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x129")
int BPF_KPROBE(do_mov_1082)
{
    u64 addr = ctx->bx + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x137")
int BPF_KPROBE(do_mov_1083)
{
    u64 addr = ctx->bx + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x145")
int BPF_KPROBE(do_mov_1084)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x153")
int BPF_KPROBE(do_mov_1085)
{
    u64 addr = ctx->bx + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x161")
int BPF_KPROBE(do_mov_1086)
{
    u64 addr = ctx->bx + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x173")
int BPF_KPROBE(do_mov_1087)
{
    u64 addr = ctx->bx + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x17e")
int BPF_KPROBE(do_mov_1088)
{
    u64 addr = ctx->bx + 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x189")
int BPF_KPROBE(do_mov_1089)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x197")
int BPF_KPROBE(do_mov_1090)
{
    u64 addr = ctx->bx + 0x278;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x1a5")
int BPF_KPROBE(do_mov_1091)
{
    u64 addr = ctx->bx + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x1b3")
int BPF_KPROBE(do_mov_1092)
{
    u64 addr = ctx->bx + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x1c1")
int BPF_KPROBE(do_mov_1093)
{
    u64 addr = ctx->bx + 0x290;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x1cf")
int BPF_KPROBE(do_mov_1094)
{
    u64 addr = ctx->bx + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x1e1")
int BPF_KPROBE(do_mov_1095)
{
    u64 addr = ctx->bx + 0x2a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x1ec")
int BPF_KPROBE(do_mov_1096)
{
    u64 addr = ctx->bx + 0x2a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x1f7")
int BPF_KPROBE(do_mov_1097)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x205")
int BPF_KPROBE(do_mov_1098)
{
    u64 addr = ctx->bx + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x213")
int BPF_KPROBE(do_mov_1099)
{
    u64 addr = ctx->bx + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x221")
int BPF_KPROBE(do_mov_1100)
{
    u64 addr = ctx->bx + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x22f")
int BPF_KPROBE(do_mov_1101)
{
    u64 addr = ctx->bx + 0x2d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x23d")
int BPF_KPROBE(do_mov_1102)
{
    u64 addr = ctx->bx + 0x2d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0x262")
int BPF_KPROBE(do_mov_1103)
{
    u64 addr = ctx->r13 + 0x498;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x5b")
int BPF_KPROBE(do_mov_1104)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x86")
int BPF_KPROBE(do_mov_1105)
{
    u64 addr = ctx->r12 + 0x498;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0xc5")
int BPF_KPROBE(do_mov_1106)
{
    u64 addr = ctx->r12 + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0xd4")
int BPF_KPROBE(do_mov_1107)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0xe1")
int BPF_KPROBE(do_mov_1108)
{
    u64 addr = ctx->r12 + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x10e")
int BPF_KPROBE(do_mov_1109)
{
    u64 addr = ctx->r12 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x11a")
int BPF_KPROBE(do_mov_1110)
{
    u64 addr = ctx->r12 + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x122")
int BPF_KPROBE(do_mov_1111)
{
    u64 addr = ctx->r12 + 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x12e")
int BPF_KPROBE(do_mov_1112)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x154")
int BPF_KPROBE(do_mov_1113)
{
    u64 addr = ctx->r12 + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dump_class_stats+0x75")
int BPF_KPROBE(do_mov_1114)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_walk+0x56")
int BPF_KPROBE(do_mov_1115)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_walk+0x83")
int BPF_KPROBE(do_mov_1116)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_destroy_qdisc+0x48")
int BPF_KPROBE(do_mov_1117)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x4b")
int BPF_KPROBE(do_mov_1118)
{
    u64 addr = ctx->bx + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x59")
int BPF_KPROBE(do_mov_1119)
{
    u64 addr = ctx->bx + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x67")
int BPF_KPROBE(do_mov_1120)
{
    u64 addr = ctx->bx + 0x230;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x75")
int BPF_KPROBE(do_mov_1121)
{
    u64 addr = ctx->bx + 0x238;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x83")
int BPF_KPROBE(do_mov_1122)
{
    u64 addr = ctx->bx + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x91")
int BPF_KPROBE(do_mov_1123)
{
    u64 addr = ctx->bx + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x9f")
int BPF_KPROBE(do_mov_1124)
{
    u64 addr = ctx->bx + 0x250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0xad")
int BPF_KPROBE(do_mov_1125)
{
    u64 addr = ctx->bx + 0x258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0xc4")
int BPF_KPROBE(do_mov_1126)
{
    u64 addr = ctx->bx + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0xcf")
int BPF_KPROBE(do_mov_1127)
{
    u64 addr = ctx->bx + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0xef")
int BPF_KPROBE(do_mov_1128)
{
    u64 addr = ctx->bx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x105")
int BPF_KPROBE(do_mov_1129)
{
    u64 addr = ctx->bx + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x141")
int BPF_KPROBE(do_mov_1130)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x148")
int BPF_KPROBE(do_mov_1131)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x153")
int BPF_KPROBE(do_mov_1132)
{
    u64 addr = ctx->bx + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x15e")
int BPF_KPROBE(do_mov_1133)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0x3b")
int BPF_KPROBE(do_mov_1134)
{
    u64 addr = ctx->bx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0x4d")
int BPF_KPROBE(do_mov_1135)
{
    u64 addr = ctx->bx + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0x9d")
int BPF_KPROBE(do_mov_1136)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0xa7")
int BPF_KPROBE(do_mov_1137)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0xb2")
int BPF_KPROBE(do_mov_1138)
{
    u64 addr = ctx->bx + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0xbd")
int BPF_KPROBE(do_mov_1139)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x50")
int BPF_KPROBE(do_mov_1140)
{
    u64 addr = ctx->bx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x85")
int BPF_KPROBE(do_mov_1141)
{
    u64 addr = ctx->bx + 0x2ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0xa0")
int BPF_KPROBE(do_mov_1142)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0xc0")
int BPF_KPROBE(do_mov_1143)
{
    u64 addr = ctx->r13 + 0x148;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x112")
int BPF_KPROBE(do_mov_1144)
{
    u64 addr = ctx->r13 + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x142")
int BPF_KPROBE(do_mov_1145)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x158")
int BPF_KPROBE(do_mov_1146)
{
    u64 addr = ctx->bx + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x166")
int BPF_KPROBE(do_mov_1147)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x1bc")
int BPF_KPROBE(do_mov_1148)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x1c6")
int BPF_KPROBE(do_mov_1149)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x1d1")
int BPF_KPROBE(do_mov_1150)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x1dc")
int BPF_KPROBE(do_mov_1151)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x221")
int BPF_KPROBE(do_mov_1152)
{
    u64 addr = ctx->bx + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x27b")
int BPF_KPROBE(do_mov_1153)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x285")
int BPF_KPROBE(do_mov_1154)
{
    u64 addr = ctx->bx + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x290")
int BPF_KPROBE(do_mov_1155)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x29b")
int BPF_KPROBE(do_mov_1156)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x2ca")
int BPF_KPROBE(do_mov_1157)
{
    u64 addr = ctx->r13 + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x2e9")
int BPF_KPROBE(do_mov_1158)
{
    u64 addr = ctx->bx + 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x2f8")
int BPF_KPROBE(do_mov_1159)
{
    u64 addr = ctx->bx + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x306")
int BPF_KPROBE(do_mov_1160)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x312")
int BPF_KPROBE(do_mov_1161)
{
    u64 addr = ctx->r13 + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x322")
int BPF_KPROBE(do_mov_1162)
{
    u64 addr = ctx->r13 + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x3d")
int BPF_KPROBE(do_mov_1163)
{
    u64 addr = ctx->bx + 0x2ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x70")
int BPF_KPROBE(do_mov_1164)
{
    u64 addr = ctx->bx + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0xca")
int BPF_KPROBE(do_mov_1165)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0xd4")
int BPF_KPROBE(do_mov_1166)
{
    u64 addr = ctx->bx + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0xdf")
int BPF_KPROBE(do_mov_1167)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0xea")
int BPF_KPROBE(do_mov_1168)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x116")
int BPF_KPROBE(do_mov_1169)
{
    u64 addr = ctx->r14 + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x18d")
int BPF_KPROBE(do_mov_1170)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x1bc")
int BPF_KPROBE(do_mov_1171)
{
    u64 addr = ctx->bx + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x1cd")
int BPF_KPROBE(do_mov_1172)
{
    u64 addr = ctx->bx + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x1e0")
int BPF_KPROBE(do_mov_1173)
{
    u64 addr = ctx->bx + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x1e6")
int BPF_KPROBE(do_mov_1174)
{
    u64 addr = ctx->bx + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x226")
int BPF_KPROBE(do_mov_1175)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x22d")
int BPF_KPROBE(do_mov_1176)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x238")
int BPF_KPROBE(do_mov_1177)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x243")
int BPF_KPROBE(do_mov_1178)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x296")
int BPF_KPROBE(do_mov_1179)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x29d")
int BPF_KPROBE(do_mov_1180)
{
    u64 addr = ctx->bx + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x2a8")
int BPF_KPROBE(do_mov_1181)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x2b3")
int BPF_KPROBE(do_mov_1182)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x306")
int BPF_KPROBE(do_mov_1183)
{
    u64 addr = ctx->bx + 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x32b")
int BPF_KPROBE(do_mov_1184)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x332")
int BPF_KPROBE(do_mov_1185)
{
    u64 addr = ctx->ax + 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_qdisc+0x4c")
int BPF_KPROBE(do_mov_1186)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_graft_class+0x78")
int BPF_KPROBE(do_mov_1187)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_graft_class+0xf8")
int BPF_KPROBE(do_mov_1188)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_delete_class+0x7e")
int BPF_KPROBE(do_mov_1189)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_delete_class+0x82")
int BPF_KPROBE(do_mov_1190)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_delete_class+0x94")
int BPF_KPROBE(do_mov_1191)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_delete_class+0x9d")
int BPF_KPROBE(do_mov_1192)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_delete_class+0xd9")
int BPF_KPROBE(do_mov_1193)
{
    u64 addr = ctx->r8 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0xc4")
int BPF_KPROBE(do_mov_1194)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0xd2")
int BPF_KPROBE(do_mov_1195)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0xda")
int BPF_KPROBE(do_mov_1196)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0xe2")
int BPF_KPROBE(do_mov_1197)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0xe6")
int BPF_KPROBE(do_mov_1198)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0x1b3")
int BPF_KPROBE(do_mov_1199)
{
    u64 addr = ctx->r14 + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0x273")
int BPF_KPROBE(do_mov_1200)
{
    u64 addr = ctx->ax + 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dump_class+0x37")
int BPF_KPROBE(do_mov_1201)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dump_class+0x3c")
int BPF_KPROBE(do_mov_1202)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dump_class+0x50")
int BPF_KPROBE(do_mov_1203)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dump_class+0xc0")
int BPF_KPROBE(do_mov_1204)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x273")
int BPF_KPROBE(do_mov_1205)
{
    u64 addr = ctx->r12 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x28b")
int BPF_KPROBE(do_mov_1206)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2a3")
int BPF_KPROBE(do_mov_1207)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2b3")
int BPF_KPROBE(do_mov_1208)
{
    u64 addr = ctx->r12 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2bb")
int BPF_KPROBE(do_mov_1209)
{
    u64 addr = ctx->r12 + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2c3")
int BPF_KPROBE(do_mov_1210)
{
    u64 addr = ctx->r12 + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2cb")
int BPF_KPROBE(do_mov_1211)
{
    u64 addr = ctx->r12 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2d3")
int BPF_KPROBE(do_mov_1212)
{
    u64 addr = ctx->r12 + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2db")
int BPF_KPROBE(do_mov_1213)
{
    u64 addr = ctx->r12 + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2e3")
int BPF_KPROBE(do_mov_1214)
{
    u64 addr = ctx->r12 + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2eb")
int BPF_KPROBE(do_mov_1215)
{
    u64 addr = ctx->r12 + 0x230;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2f3")
int BPF_KPROBE(do_mov_1216)
{
    u64 addr = ctx->r12 + 0x238;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x2fb")
int BPF_KPROBE(do_mov_1217)
{
    u64 addr = ctx->r12 + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x303")
int BPF_KPROBE(do_mov_1218)
{
    u64 addr = ctx->r12 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x30b")
int BPF_KPROBE(do_mov_1219)
{
    u64 addr = ctx->r12 + 0x250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x313")
int BPF_KPROBE(do_mov_1220)
{
    u64 addr = ctx->r12 + 0x258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x320")
int BPF_KPROBE(do_mov_1221)
{
    u64 addr = ctx->r12 + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x32c")
int BPF_KPROBE(do_mov_1222)
{
    u64 addr = ctx->r12 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x33d")
int BPF_KPROBE(do_mov_1223)
{
    u64 addr = ctx->r12 + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x378")
int BPF_KPROBE(do_mov_1224)
{
    u64 addr = ctx->r12 + 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x388")
int BPF_KPROBE(do_mov_1225)
{
    u64 addr = ctx->r12 + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x390")
int BPF_KPROBE(do_mov_1226)
{
    u64 addr = ctx->r12 + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x3a0")
int BPF_KPROBE(do_mov_1227)
{
    u64 addr = ctx->r12 + 0x278;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x3b0")
int BPF_KPROBE(do_mov_1228)
{
    u64 addr = ctx->r12 + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x3c0")
int BPF_KPROBE(do_mov_1229)
{
    u64 addr = ctx->r12 + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x3d0")
int BPF_KPROBE(do_mov_1230)
{
    u64 addr = ctx->r12 + 0x290;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x3e0")
int BPF_KPROBE(do_mov_1231)
{
    u64 addr = ctx->r12 + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x413")
int BPF_KPROBE(do_mov_1232)
{
    u64 addr = ctx->r12 + 0x2a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x41b")
int BPF_KPROBE(do_mov_1233)
{
    u64 addr = ctx->r12 + 0x2a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x42b")
int BPF_KPROBE(do_mov_1234)
{
    u64 addr = ctx->r12 + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x43b")
int BPF_KPROBE(do_mov_1235)
{
    u64 addr = ctx->r12 + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x44b")
int BPF_KPROBE(do_mov_1236)
{
    u64 addr = ctx->r12 + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x45b")
int BPF_KPROBE(do_mov_1237)
{
    u64 addr = ctx->r12 + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x46b")
int BPF_KPROBE(do_mov_1238)
{
    u64 addr = ctx->r12 + 0x2d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x47b")
int BPF_KPROBE(do_mov_1239)
{
    u64 addr = ctx->r12 + 0x2d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x6c5")
int BPF_KPROBE(do_mov_1240)
{
    u64 addr = ctx->r10 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x6de")
int BPF_KPROBE(do_mov_1241)
{
    u64 addr = ctx->r10 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x6f7")
int BPF_KPROBE(do_mov_1242)
{
    u64 addr = ctx->r10 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x705")
int BPF_KPROBE(do_mov_1243)
{
    u64 addr = ctx->r10 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x70c")
int BPF_KPROBE(do_mov_1244)
{
    u64 addr = ctx->r10 + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x713")
int BPF_KPROBE(do_mov_1245)
{
    u64 addr = ctx->r10 + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x71a")
int BPF_KPROBE(do_mov_1246)
{
    u64 addr = ctx->r10 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x721")
int BPF_KPROBE(do_mov_1247)
{
    u64 addr = ctx->r10 + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x728")
int BPF_KPROBE(do_mov_1248)
{
    u64 addr = ctx->r10 + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x72f")
int BPF_KPROBE(do_mov_1249)
{
    u64 addr = ctx->r10 + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x736")
int BPF_KPROBE(do_mov_1250)
{
    u64 addr = ctx->r10 + 0x230;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x73d")
int BPF_KPROBE(do_mov_1251)
{
    u64 addr = ctx->r10 + 0x238;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x744")
int BPF_KPROBE(do_mov_1252)
{
    u64 addr = ctx->r10 + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x74b")
int BPF_KPROBE(do_mov_1253)
{
    u64 addr = ctx->r10 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x752")
int BPF_KPROBE(do_mov_1254)
{
    u64 addr = ctx->r10 + 0x250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x759")
int BPF_KPROBE(do_mov_1255)
{
    u64 addr = ctx->r10 + 0x258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x765")
int BPF_KPROBE(do_mov_1256)
{
    u64 addr = ctx->r10 + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x770")
int BPF_KPROBE(do_mov_1257)
{
    u64 addr = ctx->r10 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x7ba")
int BPF_KPROBE(do_mov_1258)
{
    u64 addr = ctx->r10 + 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x7c8")
int BPF_KPROBE(do_mov_1259)
{
    u64 addr = ctx->r10 + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x7cf")
int BPF_KPROBE(do_mov_1260)
{
    u64 addr = ctx->r10 + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x7dd")
int BPF_KPROBE(do_mov_1261)
{
    u64 addr = ctx->r10 + 0x278;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x7eb")
int BPF_KPROBE(do_mov_1262)
{
    u64 addr = ctx->r10 + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x7f9")
int BPF_KPROBE(do_mov_1263)
{
    u64 addr = ctx->r10 + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x807")
int BPF_KPROBE(do_mov_1264)
{
    u64 addr = ctx->r10 + 0x290;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x815")
int BPF_KPROBE(do_mov_1265)
{
    u64 addr = ctx->r10 + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x84c")
int BPF_KPROBE(do_mov_1266)
{
    u64 addr = ctx->r10 + 0x2a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x857")
int BPF_KPROBE(do_mov_1267)
{
    u64 addr = ctx->r10 + 0x2a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x865")
int BPF_KPROBE(do_mov_1268)
{
    u64 addr = ctx->r10 + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x873")
int BPF_KPROBE(do_mov_1269)
{
    u64 addr = ctx->r10 + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x881")
int BPF_KPROBE(do_mov_1270)
{
    u64 addr = ctx->r10 + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x88f")
int BPF_KPROBE(do_mov_1271)
{
    u64 addr = ctx->r10 + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x89d")
int BPF_KPROBE(do_mov_1272)
{
    u64 addr = ctx->r10 + 0x2d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x8ab")
int BPF_KPROBE(do_mov_1273)
{
    u64 addr = ctx->r10 + 0x2d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x8b9")
int BPF_KPROBE(do_mov_1274)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x8c2")
int BPF_KPROBE(do_mov_1275)
{
    u64 addr = ctx->r10 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x8d0")
int BPF_KPROBE(do_mov_1276)
{
    u64 addr = ctx->r10 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x8e4")
int BPF_KPROBE(do_mov_1277)
{
    u64 addr = ctx->r10 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x912")
int BPF_KPROBE(do_mov_1278)
{
    u64 addr = ctx->r10 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x91d")
int BPF_KPROBE(do_mov_1279)
{
    u64 addr = ctx->r10 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x924")
int BPF_KPROBE(do_mov_1280)
{
    u64 addr = ctx->r10 + 0xd8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x92f")
int BPF_KPROBE(do_mov_1281)
{
    u64 addr = ctx->r10 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x97e")
int BPF_KPROBE(do_mov_1282)
{
    u64 addr = ctx->r12 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x986")
int BPF_KPROBE(do_mov_1283)
{
    u64 addr = ctx->r10 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x98a")
int BPF_KPROBE(do_mov_1284)
{
    u64 addr = ctx->r10 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x991")
int BPF_KPROBE(do_mov_1285)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x9cf")
int BPF_KPROBE(do_mov_1286)
{
    u64 addr = ctx->r12 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0xa21")
int BPF_KPROBE(do_mov_1287)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0xb17")
int BPF_KPROBE(do_mov_1288)
{
    u64 addr = ctx->r10 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_enqueue+0xaa")
int BPF_KPROBE(do_mov_1289)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_enqueue+0xad")
int BPF_KPROBE(do_mov_1290)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_dump_class+0x18")
int BPF_KPROBE(do_mov_1291)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_dequeue+0x80")
int BPF_KPROBE(do_mov_1292)
{
    u64 addr = ctx->bx + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_reset+0x19")
int BPF_KPROBE(do_mov_1293)
{
    u64 addr = ctx->bx + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_reset+0x24")
int BPF_KPROBE(do_mov_1294)
{
    u64 addr = ctx->bx + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_reset+0x2f")
int BPF_KPROBE(do_mov_1295)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_dump+0x1b1")
int BPF_KPROBE(do_mov_1296)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_walk+0x31")
int BPF_KPROBE(do_mov_1297)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_walk+0x3a")
int BPF_KPROBE(do_mov_1298)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x63")
int BPF_KPROBE(do_mov_1299)
{
    u64 addr = ctx->si + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x91")
int BPF_KPROBE(do_mov_1300)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x12d")
int BPF_KPROBE(do_mov_1301)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x170")
int BPF_KPROBE(do_mov_1302)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x173")
int BPF_KPROBE(do_mov_1303)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x188")
int BPF_KPROBE(do_mov_1304)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x197")
int BPF_KPROBE(do_mov_1305)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x1d3")
int BPF_KPROBE(do_mov_1306)
{
    u64 addr = ctx->bx + 0x2e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x267")
int BPF_KPROBE(do_mov_1307)
{
    u64 addr = ctx->bx + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x277")
int BPF_KPROBE(do_mov_1308)
{
    u64 addr = ctx->bx + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x329")
int BPF_KPROBE(do_mov_1309)
{
    u64 addr = ctx->bx + 0x2e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_graft+0x5e")
int BPF_KPROBE(do_mov_1310)
{
    u64 addr = ctx->r12 + 0x310;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_graft+0xfd")
int BPF_KPROBE(do_mov_1311)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x18b")
int BPF_KPROBE(do_mov_1312)
{
    u64 addr = ctx->r14 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x192")
int BPF_KPROBE(do_mov_1313)
{
    u64 addr = ctx->r14 + 0x185;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x19d")
int BPF_KPROBE(do_mov_1314)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x1fa")
int BPF_KPROBE(do_mov_1315)
{
    u64 addr = ctx->r14 + 0x310;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x227")
int BPF_KPROBE(do_mov_1316)
{
    u64 addr = ctx->r14 + 0x1dd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x22e")
int BPF_KPROBE(do_mov_1317)
{
    u64 addr = ctx->r14 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x240")
int BPF_KPROBE(do_mov_1318)
{
    u64 addr = ctx->r14 + 0x1de;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x247")
int BPF_KPROBE(do_mov_1319)
{
    u64 addr = ctx->r14 + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x257")
int BPF_KPROBE(do_mov_1320)
{
    u64 addr = ctx->r14 + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x27a")
int BPF_KPROBE(do_mov_1321)
{
    u64 addr = ctx->r14 + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x2af")
int BPF_KPROBE(do_mov_1322)
{
    u64 addr = ctx->r11 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x2be")
int BPF_KPROBE(do_mov_1323)
{
    u64 addr = ctx->r14 + 0x1dc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x2d0")
int BPF_KPROBE(do_mov_1324)
{
    u64 addr = ctx->r14 + 0x1d4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x2de")
int BPF_KPROBE(do_mov_1325)
{
    u64 addr = ctx->r14 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x2e5")
int BPF_KPROBE(do_mov_1326)
{
    u64 addr = ctx->r14 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x30e")
int BPF_KPROBE(do_mov_1327)
{
    u64 addr = ctx->r14 + 0x1df;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x32b")
int BPF_KPROBE(do_mov_1328)
{
    u64 addr = ctx->r14 + 0x2d7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x332")
int BPF_KPROBE(do_mov_1329)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x335")
int BPF_KPROBE(do_mov_1330)
{
    u64 addr = ctx->r14 + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x347")
int BPF_KPROBE(do_mov_1331)
{
    u64 addr = ctx->r14 + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x442")
int BPF_KPROBE(do_mov_1332)
{
    u64 addr = ctx->r14 + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x4e9")
int BPF_KPROBE(do_mov_1333)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x510")
int BPF_KPROBE(do_mov_1334)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_init+0x38")
int BPF_KPROBE(do_mov_1335)
{
    u64 addr = ctx->di + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_init+0x46")
int BPF_KPROBE(do_mov_1336)
{
    u64 addr = ctx->di + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x43")
int BPF_KPROBE(do_mov_1337)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x51")
int BPF_KPROBE(do_mov_1338)
{
    u64 addr = ctx->r10 + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x6b")
int BPF_KPROBE(do_mov_1339)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x72")
int BPF_KPROBE(do_mov_1340)
{
    u64 addr = ctx->r10 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x7a")
int BPF_KPROBE(do_mov_1341)
{
    u64 addr = ctx->r10 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x91")
int BPF_KPROBE(do_mov_1342)
{
    u64 addr = ctx->r10 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xa4")
int BPF_KPROBE(do_mov_1343)
{
    u64 addr = ctx->r10 + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xb4")
int BPF_KPROBE(do_mov_1344)
{
    u64 addr = ctx->r10 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xbf")
int BPF_KPROBE(do_mov_1345)
{
    u64 addr = ctx->r10 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xe1")
int BPF_KPROBE(do_mov_1346)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xea")
int BPF_KPROBE(do_mov_1347)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xf1")
int BPF_KPROBE(do_mov_1348)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xfd")
int BPF_KPROBE(do_mov_1349)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x109")
int BPF_KPROBE(do_mov_1350)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x10f")
int BPF_KPROBE(do_mov_1351)
{
    u64 addr = ctx->dx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x11e")
int BPF_KPROBE(do_mov_1352)
{
    u64 addr = ctx->dx + 0x15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x124")
int BPF_KPROBE(do_mov_1353)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x128")
int BPF_KPROBE(do_mov_1354)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x143")
int BPF_KPROBE(do_mov_1355)
{
    u64 addr = ctx->r10 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x3d")
int BPF_KPROBE(do_mov_1356)
{
    u64 addr = ctx->ax + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x48")
int BPF_KPROBE(do_mov_1357)
{
    u64 addr = ctx->ax + 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x53")
int BPF_KPROBE(do_mov_1358)
{
    u64 addr = ctx->ax + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x5d")
int BPF_KPROBE(do_mov_1359)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x89")
int BPF_KPROBE(do_mov_1360)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x94")
int BPF_KPROBE(do_mov_1361)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x9f")
int BPF_KPROBE(do_mov_1362)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dequeue+0x2c")
int BPF_KPROBE(do_mov_1363)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dequeue+0x3c")
int BPF_KPROBE(do_mov_1364)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dequeue+0xaa")
int BPF_KPROBE(do_mov_1365)
{
    u64 addr = ctx->r13 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dequeue+0xd1")
int BPF_KPROBE(do_mov_1366)
{
    u64 addr = ctx->di + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dequeue+0x105")
int BPF_KPROBE(do_mov_1367)
{
    u64 addr = ctx->di + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dequeue+0x11e")
int BPF_KPROBE(do_mov_1368)
{
    u64 addr = ctx->r13 + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_apply+0x5c")
int BPF_KPROBE(do_mov_1369)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0xd6")
int BPF_KPROBE(do_mov_1370)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0xf6")
int BPF_KPROBE(do_mov_1371)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0x116")
int BPF_KPROBE(do_mov_1372)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0x136")
int BPF_KPROBE(do_mov_1373)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0x159")
int BPF_KPROBE(do_mov_1374)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x88")
int BPF_KPROBE(do_mov_1375)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x9a")
int BPF_KPROBE(do_mov_1376)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0xc0")
int BPF_KPROBE(do_mov_1377)
{
    u64 addr = ctx->r13 + ctx->bx * 0x8 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x3a0")
int BPF_KPROBE(do_mov_1378)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x3de")
int BPF_KPROBE(do_mov_1379)
{
    u64 addr = ctx->si + 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x3ec")
int BPF_KPROBE(do_mov_1380)
{
    u64 addr = ctx->si + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x523")
int BPF_KPROBE(do_mov_1381)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x67b")
int BPF_KPROBE(do_mov_1382)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x7be")
int BPF_KPROBE(do_mov_1383)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x7d5")
int BPF_KPROBE(do_mov_1384)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x82")
int BPF_KPROBE(do_mov_1385)
{
    u64 addr = ctx->bx + 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x91")
int BPF_KPROBE(do_mov_1386)
{
    u64 addr = ctx->bx + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0xd0")
int BPF_KPROBE(do_mov_1387)
{
    u64 addr = ctx->bx + 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0xe4")
int BPF_KPROBE(do_mov_1388)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0xf3")
int BPF_KPROBE(do_mov_1389)
{
    u64 addr = ctx->r12 + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x126")
int BPF_KPROBE(do_mov_1390)
{
    u64 addr = ctx->bx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x184")
int BPF_KPROBE(do_mov_1391)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x18d")
int BPF_KPROBE(do_mov_1392)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x1cc")
int BPF_KPROBE(do_mov_1393)
{
    u64 addr = ctx->r13 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x2df")
int BPF_KPROBE(do_mov_1394)
{
    u64 addr = ctx->bx + 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x2ef")
int BPF_KPROBE(do_mov_1395)
{
    u64 addr = ctx->bx + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x2ff")
int BPF_KPROBE(do_mov_1396)
{
    u64 addr = ctx->bx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x32b")
int BPF_KPROBE(do_mov_1397)
{
    u64 addr = ctx->bx + 0x154;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x390")
int BPF_KPROBE(do_mov_1398)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x398")
int BPF_KPROBE(do_mov_1399)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x39b")
int BPF_KPROBE(do_mov_1400)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x3c9")
int BPF_KPROBE(do_mov_1401)
{
    u64 addr = ctx->bx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x3d8")
int BPF_KPROBE(do_mov_1402)
{
    u64 addr = ctx->bx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x444")
int BPF_KPROBE(do_mov_1403)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x44c")
int BPF_KPROBE(do_mov_1404)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x457")
int BPF_KPROBE(do_mov_1405)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x46c")
int BPF_KPROBE(do_mov_1406)
{
    u64 addr = ctx->r12 + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x48f")
int BPF_KPROBE(do_mov_1407)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x498")
int BPF_KPROBE(do_mov_1408)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x4f9")
int BPF_KPROBE(do_mov_1409)
{
    u64 addr = ctx->bx + 0x154;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x504")
int BPF_KPROBE(do_mov_1410)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x50c")
int BPF_KPROBE(do_mov_1411)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x519")
int BPF_KPROBE(do_mov_1412)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x521")
int BPF_KPROBE(do_mov_1413)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0xbd")
int BPF_KPROBE(do_mov_1414)
{
    u64 addr = ctx->r12 + 0x20c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0xc8")
int BPF_KPROBE(do_mov_1415)
{
    u64 addr = ctx->r12 + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0xd5")
int BPF_KPROBE(do_mov_1416)
{
    u64 addr = ctx->r12 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x139")
int BPF_KPROBE(do_mov_1417)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x2e0")
int BPF_KPROBE(do_mov_1418)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x30a")
int BPF_KPROBE(do_mov_1419)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x334")
int BPF_KPROBE(do_mov_1420)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x35e")
int BPF_KPROBE(do_mov_1421)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_init+0x7f")
int BPF_KPROBE(do_mov_1422)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_init+0xae")
int BPF_KPROBE(do_mov_1423)
{
    u64 addr = ctx->r12 + 0x230;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_init+0x10d")
int BPF_KPROBE(do_mov_1424)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x23f")
int BPF_KPROBE(do_mov_1425)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x2f2")
int BPF_KPROBE(do_mov_1426)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x341")
int BPF_KPROBE(do_mov_1427)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x360")
int BPF_KPROBE(do_mov_1428)
{
    u64 addr = ctx->r15 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x364")
int BPF_KPROBE(do_mov_1429)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x375")
int BPF_KPROBE(do_mov_1430)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x380")
int BPF_KPROBE(do_mov_1431)
{
    u64 addr = ctx->r15 + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x3a6")
int BPF_KPROBE(do_mov_1432)
{
    u64 addr = ctx->r15 + 0x49;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x3b1")
int BPF_KPROBE(do_mov_1433)
{
    u64 addr = ctx->r15 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x3c0")
int BPF_KPROBE(do_mov_1434)
{
    u64 addr = ctx->r15 + 0x4a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x3c8")
int BPF_KPROBE(do_mov_1435)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x3cc")
int BPF_KPROBE(do_mov_1436)
{
    u64 addr = ctx->r15 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x3f1")
int BPF_KPROBE(do_mov_1437)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x42b")
int BPF_KPROBE(do_mov_1438)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x43b")
int BPF_KPROBE(do_mov_1439)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x449")
int BPF_KPROBE(do_mov_1440)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x454")
int BPF_KPROBE(do_mov_1441)
{
    u64 addr = ctx->r15 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x458")
int BPF_KPROBE(do_mov_1442)
{
    u64 addr = ctx->r15 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x478")
int BPF_KPROBE(do_mov_1443)
{
    u64 addr = ctx->r15 + 0x4b;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x48f")
int BPF_KPROBE(do_mov_1444)
{
    u64 addr = ctx->r15 + 0x143;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x496")
int BPF_KPROBE(do_mov_1445)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x499")
int BPF_KPROBE(do_mov_1446)
{
    u64 addr = ctx->r15 + 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x4a8")
int BPF_KPROBE(do_mov_1447)
{
    u64 addr = ctx->r15 + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x5ae")
int BPF_KPROBE(do_mov_1448)
{
    u64 addr = ctx->r12 + ctx->r9 * 0x8 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x5d5")
int BPF_KPROBE(do_mov_1449)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x5f3")
int BPF_KPROBE(do_mov_1450)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x736")
int BPF_KPROBE(do_mov_1451)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x75d")
int BPF_KPROBE(do_mov_1452)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ingress_ingress_block_set+0x6")
int BPF_KPROBE(do_mov_1453)
{
    u64 addr = ctx->di + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_ingress_block_set+0x6")
int BPF_KPROBE(do_mov_1454)
{
    u64 addr = ctx->di + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_egress_block_set+0x6")
int BPF_KPROBE(do_mov_1455)
{
    u64 addr = ctx->di + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0x54")
int BPF_KPROBE(do_mov_1456)
{
    u64 addr = ctx->r12 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0x64")
int BPF_KPROBE(do_mov_1457)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0x70")
int BPF_KPROBE(do_mov_1458)
{
    u64 addr = ctx->r12 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0xaf")
int BPF_KPROBE(do_mov_1459)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0xcd")
int BPF_KPROBE(do_mov_1460)
{
    u64 addr = ctx->r12 + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0xd9")
int BPF_KPROBE(do_mov_1461)
{
    u64 addr = ctx->r12 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ingress_init+0x4d")
int BPF_KPROBE(do_mov_1462)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ingress_init+0x5b")
int BPF_KPROBE(do_mov_1463)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ingress_init+0x65")
int BPF_KPROBE(do_mov_1464)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ingress_dump+0x47")
int BPF_KPROBE(do_mov_1465)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_walk+0x39")
int BPF_KPROBE(do_mov_1466)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_walk+0x81")
int BPF_KPROBE(do_mov_1467)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_delete+0x28")
int BPF_KPROBE(do_mov_1468)
{
    u64 addr = ctx->ax + ctx->si * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_delete+0x34")
int BPF_KPROBE(do_mov_1469)
{
    u64 addr = ctx->ax + ctx->si * 0x1 - 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dump_class+0xad")
int BPF_KPROBE(do_mov_1470)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dump_class+0xbc")
int BPF_KPROBE(do_mov_1471)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dump_class+0x143")
int BPF_KPROBE(do_mov_1472)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x123")
int BPF_KPROBE(do_mov_1473)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x14d")
int BPF_KPROBE(do_mov_1474)
{
    u64 addr = ctx->ax + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x158")
int BPF_KPROBE(do_mov_1475)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x16f")
int BPF_KPROBE(do_mov_1476)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x17e")
int BPF_KPROBE(do_mov_1477)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x196")
int BPF_KPROBE(do_mov_1478)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x1dc")
int BPF_KPROBE(do_mov_1479)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_change+0xd9")
int BPF_KPROBE(do_mov_1480)
{
    u64 addr = ctx->ax + ctx->dx * 0x2 - 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_change+0xfb")
int BPF_KPROBE(do_mov_1481)
{
    u64 addr = ctx->dx + ctx->cx * 0x2 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x5d")
int BPF_KPROBE(do_mov_1482)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x6c")
int BPF_KPROBE(do_mov_1483)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x74")
int BPF_KPROBE(do_mov_1484)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x7d")
int BPF_KPROBE(do_mov_1485)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x81")
int BPF_KPROBE(do_mov_1486)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x175")
int BPF_KPROBE(do_mov_1487)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x1f1")
int BPF_KPROBE(do_mov_1488)
{
    u64 addr = ctx->cx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x212")
int BPF_KPROBE(do_mov_1489)
{
    u64 addr = ctx->cx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dump+0xa7")
int BPF_KPROBE(do_mov_1490)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_graft+0x59")
int BPF_KPROBE(do_mov_1491)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_graft+0xdc")
int BPF_KPROBE(do_mov_1492)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x5b")
int BPF_KPROBE(do_mov_1493)
{
    u64 addr = ctx->r12 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0xfb")
int BPF_KPROBE(do_mov_1494)
{
    u64 addr = ctx->r12 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x229")
int BPF_KPROBE(do_mov_1495)
{
    u64 addr = ctx->r12 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x263")
int BPF_KPROBE(do_mov_1496)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x26c")
int BPF_KPROBE(do_mov_1497)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x291")
int BPF_KPROBE(do_mov_1498)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x29a")
int BPF_KPROBE(do_mov_1499)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x349")
int BPF_KPROBE(do_mov_1500)
{
    u64 addr = ctx->r12 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x35b")
int BPF_KPROBE(do_mov_1501)
{
    u64 addr = ctx->r12 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_zero_all_buckets+0xd")
int BPF_KPROBE(do_mov_1502)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_zero_all_buckets+0x15")
int BPF_KPROBE(do_mov_1503)
{
    u64 addr = ctx->di + 0x410;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_reset+0x2c")
int BPF_KPROBE(do_mov_1504)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_dump+0x80")
int BPF_KPROBE(do_mov_1505)
{
    u64 addr = ctx->bx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_dump+0xd7")
int BPF_KPROBE(do_mov_1506)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_walk+0x31")
int BPF_KPROBE(do_mov_1507)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_walk+0x3a")
int BPF_KPROBE(do_mov_1508)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_dequeue+0x96")
int BPF_KPROBE(do_mov_1509)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_dequeue+0xcd")
int BPF_KPROBE(do_mov_1510)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_graft+0x59")
int BPF_KPROBE(do_mov_1511)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_graft+0xd8")
int BPF_KPROBE(do_mov_1512)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x150")
int BPF_KPROBE(do_mov_1513)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x15f")
int BPF_KPROBE(do_mov_1514)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x16f")
int BPF_KPROBE(do_mov_1515)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x17a")
int BPF_KPROBE(do_mov_1516)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x188")
int BPF_KPROBE(do_mov_1517)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x193")
int BPF_KPROBE(do_mov_1518)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x19d")
int BPF_KPROBE(do_mov_1519)
{
    u64 addr = ctx->bx + 0x1b4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1a7")
int BPF_KPROBE(do_mov_1520)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1b1")
int BPF_KPROBE(do_mov_1521)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1bb")
int BPF_KPROBE(do_mov_1522)
{
    u64 addr = ctx->bx + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1c5")
int BPF_KPROBE(do_mov_1523)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1cb")
int BPF_KPROBE(do_mov_1524)
{
    u64 addr = ctx->bx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1d8")
int BPF_KPROBE(do_mov_1525)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1e1")
int BPF_KPROBE(do_mov_1526)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_init+0x3e")
int BPF_KPROBE(do_mov_1527)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x17b")
int BPF_KPROBE(do_mov_1528)
{
    u64 addr = ctx->r14 + ctx->r15 * 0x4 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x1af")
int BPF_KPROBE(do_mov_1529)
{
    u64 addr = ctx->di + 0x1f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x20e")
int BPF_KPROBE(do_mov_1530)
{
    u64 addr = ctx->di + 0x1f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x233")
int BPF_KPROBE(do_mov_1531)
{
    u64 addr = ctx->r14 + ctx->dx * 0x4 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x2e7")
int BPF_KPROBE(do_mov_1532)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x379")
int BPF_KPROBE(do_mov_1533)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x39c")
int BPF_KPROBE(do_mov_1534)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x39f")
int BPF_KPROBE(do_mov_1535)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x43a")
int BPF_KPROBE(do_mov_1536)
{
    u64 addr = ctx->bx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x440")
int BPF_KPROBE(do_mov_1537)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x485")
int BPF_KPROBE(do_mov_1538)
{
    u64 addr = ctx->si + 0x1d9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x4d5")
int BPF_KPROBE(do_mov_1539)
{
    u64 addr = ctx->r14 + ctx->dx * 0x4 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x4fa")
int BPF_KPROBE(do_mov_1540)
{
    u64 addr = ctx->di + 0x1f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x554")
int BPF_KPROBE(do_mov_1541)
{
    u64 addr = ctx->di + 0x1f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x623")
int BPF_KPROBE(do_mov_1542)
{
    u64 addr = ctx->bx + 0x1d9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x630")
int BPF_KPROBE(do_mov_1543)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x6a6")
int BPF_KPROBE(do_mov_1544)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x6b2")
int BPF_KPROBE(do_mov_1545)
{
    u64 addr = ctx->bx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x711")
int BPF_KPROBE(do_mov_1546)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x715")
int BPF_KPROBE(do_mov_1547)
{
    u64 addr = ctx->dx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x78c")
int BPF_KPROBE(do_mov_1548)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x7b4")
int BPF_KPROBE(do_mov_1549)
{
    u64 addr = ctx->r14 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x67")
int BPF_KPROBE(do_mov_1550)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x6a")
int BPF_KPROBE(do_mov_1551)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x6e")
int BPF_KPROBE(do_mov_1552)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x76")
int BPF_KPROBE(do_mov_1553)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0xba")
int BPF_KPROBE(do_mov_1554)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0xe0")
int BPF_KPROBE(do_mov_1555)
{
    u64 addr = ctx->r11 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0xf8")
int BPF_KPROBE(do_mov_1556)
{
    u64 addr = ctx->r11 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x127")
int BPF_KPROBE(do_mov_1557)
{
    u64 addr = ctx->dx + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x12c")
int BPF_KPROBE(do_mov_1558)
{
    u64 addr = ctx->dx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x130")
int BPF_KPROBE(do_mov_1559)
{
    u64 addr = ctx->ax + ctx->r9 * 0x4 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x155")
int BPF_KPROBE(do_mov_1560)
{
    u64 addr = ctx->dx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x16d")
int BPF_KPROBE(do_mov_1561)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x170")
int BPF_KPROBE(do_mov_1562)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x186")
int BPF_KPROBE(do_mov_1563)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x18a")
int BPF_KPROBE(do_mov_1564)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x190")
int BPF_KPROBE(do_mov_1565)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x198")
int BPF_KPROBE(do_mov_1566)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x1b8")
int BPF_KPROBE(do_mov_1567)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x21c")
int BPF_KPROBE(do_mov_1568)
{
    u64 addr = ctx->ax + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x259")
int BPF_KPROBE(do_mov_1569)
{
    u64 addr = ctx->di + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x26a")
int BPF_KPROBE(do_mov_1570)
{
    u64 addr = ctx->di + ctx->r8 * 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_destroy+0x20")
int BPF_KPROBE(do_mov_1571)
{
    u64 addr = ctx->bx + 0x3f4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_walk+0x30")
int BPF_KPROBE(do_mov_1572)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_walk+0x6e")
int BPF_KPROBE(do_mov_1573)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x92")
int BPF_KPROBE(do_mov_1574)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x95")
int BPF_KPROBE(do_mov_1575)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x145")
int BPF_KPROBE(do_mov_1576)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x16f")
int BPF_KPROBE(do_mov_1577)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x1c2")
int BPF_KPROBE(do_mov_1578)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x1c5")
int BPF_KPROBE(do_mov_1579)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x1e7")
int BPF_KPROBE(do_mov_1580)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x207")
int BPF_KPROBE(do_mov_1581)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x216")
int BPF_KPROBE(do_mov_1582)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x21e")
int BPF_KPROBE(do_mov_1583)
{
    u64 addr = ctx->r14 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x238")
int BPF_KPROBE(do_mov_1584)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x23b")
int BPF_KPROBE(do_mov_1585)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x243")
int BPF_KPROBE(do_mov_1586)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x246")
int BPF_KPROBE(do_mov_1587)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x27d")
int BPF_KPROBE(do_mov_1588)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x299")
int BPF_KPROBE(do_mov_1589)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x2af")
int BPF_KPROBE(do_mov_1590)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x2c1")
int BPF_KPROBE(do_mov_1591)
{
    u64 addr = ctx->r12 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x2e9")
int BPF_KPROBE(do_mov_1592)
{
    u64 addr = ctx->r15 + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x2ee")
int BPF_KPROBE(do_mov_1593)
{
    u64 addr = ctx->r15 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x2f3")
int BPF_KPROBE(do_mov_1594)
{
    u64 addr = ctx->r12 + ctx->cx * 0x4 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x315")
int BPF_KPROBE(do_mov_1595)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x333")
int BPF_KPROBE(do_mov_1596)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x411")
int BPF_KPROBE(do_mov_1597)
{
    u64 addr = ctx->r14 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x41e")
int BPF_KPROBE(do_mov_1598)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x42b")
int BPF_KPROBE(do_mov_1599)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x433")
int BPF_KPROBE(do_mov_1600)
{
    u64 addr = ctx->r14 + 0x1a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x45a")
int BPF_KPROBE(do_mov_1601)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x467")
int BPF_KPROBE(do_mov_1602)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x4c1")
int BPF_KPROBE(do_mov_1603)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x4fd")
int BPF_KPROBE(do_mov_1604)
{
    u64 addr = ctx->r14 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x55d")
int BPF_KPROBE(do_mov_1605)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x560")
int BPF_KPROBE(do_mov_1606)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x567")
int BPF_KPROBE(do_mov_1607)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x56e")
int BPF_KPROBE(do_mov_1608)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x58f")
int BPF_KPROBE(do_mov_1609)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x594")
int BPF_KPROBE(do_mov_1610)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x5a5")
int BPF_KPROBE(do_mov_1611)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x5a8")
int BPF_KPROBE(do_mov_1612)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x5b0")
int BPF_KPROBE(do_mov_1613)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x5b3")
int BPF_KPROBE(do_mov_1614)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x64b")
int BPF_KPROBE(do_mov_1615)
{
    u64 addr = ctx->r14 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x654")
int BPF_KPROBE(do_mov_1616)
{
    u64 addr = ctx->r14 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x46")
int BPF_KPROBE(do_mov_1617)
{
    u64 addr = ctx->di + 0x428;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x85")
int BPF_KPROBE(do_mov_1618)
{
    u64 addr = ctx->dx - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x8d")
int BPF_KPROBE(do_mov_1619)
{
    u64 addr = ctx->dx - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xa6")
int BPF_KPROBE(do_mov_1620)
{
    u64 addr = ctx->r13 + 0x189;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xae")
int BPF_KPROBE(do_mov_1621)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xb9")
int BPF_KPROBE(do_mov_1622)
{
    u64 addr = ctx->r13 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xc1")
int BPF_KPROBE(do_mov_1623)
{
    u64 addr = ctx->r13 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xcc")
int BPF_KPROBE(do_mov_1624)
{
    u64 addr = ctx->r13 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xe7")
int BPF_KPROBE(do_mov_1625)
{
    u64 addr = ctx->r13 + 0x3f4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xf2")
int BPF_KPROBE(do_mov_1626)
{
    u64 addr = ctx->r13 + 0x3f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xff")
int BPF_KPROBE(do_mov_1627)
{
    u64 addr = ctx->r13 + 0x1a2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x225")
int BPF_KPROBE(do_mov_1628)
{
    u64 addr = ctx->r13 + 0x3f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x232")
int BPF_KPROBE(do_mov_1629)
{
    u64 addr = ctx->r13 + 0x1a2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x242")
int BPF_KPROBE(do_mov_1630)
{
    u64 addr = ctx->r13 + 0x3f4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x25b")
int BPF_KPROBE(do_mov_1631)
{
    u64 addr = ctx->r13 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x271")
int BPF_KPROBE(do_mov_1632)
{
    u64 addr = ctx->r13 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x27d")
int BPF_KPROBE(do_mov_1633)
{
    u64 addr = ctx->r13 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x29f")
int BPF_KPROBE(do_mov_1634)
{
    u64 addr = ctx->r13 + 0x189;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2ba")
int BPF_KPROBE(do_mov_1635)
{
    u64 addr = ctx->r13 + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2e2")
int BPF_KPROBE(do_mov_1636)
{
    u64 addr = ctx->r11 + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2e8")
int BPF_KPROBE(do_mov_1637)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2f8")
int BPF_KPROBE(do_mov_1638)
{
    u64 addr = ctx->r11 + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2ff")
int BPF_KPROBE(do_mov_1639)
{
    u64 addr = ctx->r11 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x303")
int BPF_KPROBE(do_mov_1640)
{
    u64 addr = ctx->r11 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x32c")
int BPF_KPROBE(do_mov_1641)
{
    u64 addr = ctx->di + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x35b")
int BPF_KPROBE(do_mov_1642)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x368")
int BPF_KPROBE(do_mov_1643)
{
    u64 addr = ctx->di + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x375")
int BPF_KPROBE(do_mov_1644)
{
    u64 addr = ctx->di + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x378")
int BPF_KPROBE(do_mov_1645)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x382")
int BPF_KPROBE(do_mov_1646)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x392")
int BPF_KPROBE(do_mov_1647)
{
    u64 addr = ctx->r13 + 0x1a1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x39d")
int BPF_KPROBE(do_mov_1648)
{
    u64 addr = ctx->r13 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x46e")
int BPF_KPROBE(do_mov_1649)
{
    u64 addr = ctx->r13 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x497")
int BPF_KPROBE(do_mov_1650)
{
    u64 addr = ctx->r13 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x4d1")
int BPF_KPROBE(do_mov_1651)
{
    u64 addr = ctx->dx + ctx->cx * 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x508")
int BPF_KPROBE(do_mov_1652)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x51c")
int BPF_KPROBE(do_mov_1653)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x54c")
int BPF_KPROBE(do_mov_1654)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x554")
int BPF_KPROBE(do_mov_1655)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x55c")
int BPF_KPROBE(do_mov_1656)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x564")
int BPF_KPROBE(do_mov_1657)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x56c")
int BPF_KPROBE(do_mov_1658)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x574")
int BPF_KPROBE(do_mov_1659)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x577")
int BPF_KPROBE(do_mov_1660)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x5a9")
int BPF_KPROBE(do_mov_1661)
{
    u64 addr = ctx->r9 + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x5ae")
int BPF_KPROBE(do_mov_1662)
{
    u64 addr = ctx->r9 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x5b3")
int BPF_KPROBE(do_mov_1663)
{
    u64 addr = ctx->r13 + ctx->cx * 0x4 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x5e5")
int BPF_KPROBE(do_mov_1664)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x607")
int BPF_KPROBE(do_mov_1665)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x611")
int BPF_KPROBE(do_mov_1666)
{
    u64 addr = ctx->r13 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x6f")
int BPF_KPROBE(do_mov_1667)
{
    u64 addr = ctx->r13 - 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x76")
int BPF_KPROBE(do_mov_1668)
{
    u64 addr = ctx->r13 - 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x15b")
int BPF_KPROBE(do_mov_1669)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x164")
int BPF_KPROBE(do_mov_1670)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x167")
int BPF_KPROBE(do_mov_1671)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x170")
int BPF_KPROBE(do_mov_1672)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x18f")
int BPF_KPROBE(do_mov_1673)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x192")
int BPF_KPROBE(do_mov_1674)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x196")
int BPF_KPROBE(do_mov_1675)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x19e")
int BPF_KPROBE(do_mov_1676)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x1d6")
int BPF_KPROBE(do_mov_1677)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x1f8")
int BPF_KPROBE(do_mov_1678)
{
    u64 addr = ctx->r9 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x211")
int BPF_KPROBE(do_mov_1679)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x240")
int BPF_KPROBE(do_mov_1680)
{
    u64 addr = ctx->r10 + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x245")
int BPF_KPROBE(do_mov_1681)
{
    u64 addr = ctx->r10 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x24a")
int BPF_KPROBE(do_mov_1682)
{
    u64 addr = ctx->r12 + ctx->r8 * 0x4 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x28f")
int BPF_KPROBE(do_mov_1683)
{
    u64 addr = ctx->r12 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x2d3")
int BPF_KPROBE(do_mov_1684)
{
    u64 addr = ctx->cx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x2ed")
int BPF_KPROBE(do_mov_1685)
{
    u64 addr = ctx->cx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x2fe")
int BPF_KPROBE(do_mov_1686)
{
    u64 addr = ctx->ax + ctx->dx * 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x315")
int BPF_KPROBE(do_mov_1687)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x363")
int BPF_KPROBE(do_mov_1688)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x36a")
int BPF_KPROBE(do_mov_1689)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x372")
int BPF_KPROBE(do_mov_1690)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x376")
int BPF_KPROBE(do_mov_1691)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x3de")
int BPF_KPROBE(do_mov_1692)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x3e1")
int BPF_KPROBE(do_mov_1693)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x3e9")
int BPF_KPROBE(do_mov_1694)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x3ef")
int BPF_KPROBE(do_mov_1695)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x421")
int BPF_KPROBE(do_mov_1696)
{
    u64 addr = ctx->si + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x431")
int BPF_KPROBE(do_mov_1697)
{
    u64 addr = ctx->si + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x46e")
int BPF_KPROBE(do_mov_1698)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x48a")
int BPF_KPROBE(do_mov_1699)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x4a0")
int BPF_KPROBE(do_mov_1700)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x4b2")
int BPF_KPROBE(do_mov_1701)
{
    u64 addr = ctx->r12 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x4d9")
int BPF_KPROBE(do_mov_1702)
{
    u64 addr = ctx->dx + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x4dd")
int BPF_KPROBE(do_mov_1703)
{
    u64 addr = ctx->dx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x4e1")
int BPF_KPROBE(do_mov_1704)
{
    u64 addr = ctx->r12 + ctx->cx * 0x4 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x503")
int BPF_KPROBE(do_mov_1705)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x55c")
int BPF_KPROBE(do_mov_1706)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x577")
int BPF_KPROBE(do_mov_1707)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x5ce")
int BPF_KPROBE(do_mov_1708)
{
    u64 addr = ctx->si + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x5da")
int BPF_KPROBE(do_mov_1709)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x5e8")
int BPF_KPROBE(do_mov_1710)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x5f0")
int BPF_KPROBE(do_mov_1711)
{
    u64 addr = ctx->si + 0x1a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x6ea")
int BPF_KPROBE(do_mov_1712)
{
    u64 addr = ctx->si + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x716")
int BPF_KPROBE(do_mov_1713)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x24")
int BPF_KPROBE(do_mov_1714)
{
    u64 addr = ctx->dx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x6a")
int BPF_KPROBE(do_mov_1715)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x6d")
int BPF_KPROBE(do_mov_1716)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x71")
int BPF_KPROBE(do_mov_1717)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x79")
int BPF_KPROBE(do_mov_1718)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0xb5")
int BPF_KPROBE(do_mov_1719)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0xdb")
int BPF_KPROBE(do_mov_1720)
{
    u64 addr = ctx->r10 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0xf3")
int BPF_KPROBE(do_mov_1721)
{
    u64 addr = ctx->r10 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x122")
int BPF_KPROBE(do_mov_1722)
{
    u64 addr = ctx->ax + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x127")
int BPF_KPROBE(do_mov_1723)
{
    u64 addr = ctx->ax + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x12b")
int BPF_KPROBE(do_mov_1724)
{
    u64 addr = ctx->dx + ctx->r9 * 0x4 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x150")
int BPF_KPROBE(do_mov_1725)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x1b4")
int BPF_KPROBE(do_mov_1726)
{
    u64 addr = ctx->ax + ctx->di * 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x1cd")
int BPF_KPROBE(do_mov_1727)
{
    u64 addr = ctx->dx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x225")
int BPF_KPROBE(do_mov_1728)
{
    u64 addr = ctx->dx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x269")
int BPF_KPROBE(do_mov_1729)
{
    u64 addr = ctx->dx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dump_class+0x18")
int BPF_KPROBE(do_mov_1730)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_reset+0x25")
int BPF_KPROBE(do_mov_1731)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_reset+0x33")
int BPF_KPROBE(do_mov_1732)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_reset+0x41")
int BPF_KPROBE(do_mov_1733)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_walk+0x31")
int BPF_KPROBE(do_mov_1734)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_walk+0x3a")
int BPF_KPROBE(do_mov_1735)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_enqueue+0x48")
int BPF_KPROBE(do_mov_1736)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_enqueue+0x51")
int BPF_KPROBE(do_mov_1737)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_enqueue+0xbc")
int BPF_KPROBE(do_mov_1738)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_enqueue+0xc3")
int BPF_KPROBE(do_mov_1739)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dump+0x1b0")
int BPF_KPROBE(do_mov_1740)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_graft+0x5e")
int BPF_KPROBE(do_mov_1741)
{
    u64 addr = ctx->r12 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_graft+0xf3")
int BPF_KPROBE(do_mov_1742)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0xe7")
int BPF_KPROBE(do_mov_1743)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0xf4")
int BPF_KPROBE(do_mov_1744)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0xfb")
int BPF_KPROBE(do_mov_1745)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x103")
int BPF_KPROBE(do_mov_1746)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x107")
int BPF_KPROBE(do_mov_1747)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x191")
int BPF_KPROBE(do_mov_1748)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x19d")
int BPF_KPROBE(do_mov_1749)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x1a4")
int BPF_KPROBE(do_mov_1750)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x2ae")
int BPF_KPROBE(do_mov_1751)
{
    u64 addr = ctx->r14 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x2c1")
int BPF_KPROBE(do_mov_1752)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x2da")
int BPF_KPROBE(do_mov_1753)
{
    u64 addr = ctx->r14 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x2e1")
int BPF_KPROBE(do_mov_1754)
{
    u64 addr = ctx->r14 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x2fc")
int BPF_KPROBE(do_mov_1755)
{
    u64 addr = ctx->r14 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x303")
int BPF_KPROBE(do_mov_1756)
{
    u64 addr = ctx->r14 + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x30a")
int BPF_KPROBE(do_mov_1757)
{
    u64 addr = ctx->r14 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x318")
int BPF_KPROBE(do_mov_1758)
{
    u64 addr = ctx->r14 + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x31f")
int BPF_KPROBE(do_mov_1759)
{
    u64 addr = ctx->r14 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x32d")
int BPF_KPROBE(do_mov_1760)
{
    u64 addr = ctx->r14 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x33b")
int BPF_KPROBE(do_mov_1761)
{
    u64 addr = ctx->r14 + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x349")
int BPF_KPROBE(do_mov_1762)
{
    u64 addr = ctx->r14 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x354")
int BPF_KPROBE(do_mov_1763)
{
    u64 addr = ctx->r14 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_init+0x27")
int BPF_KPROBE(do_mov_1764)
{
    u64 addr = ctx->r12 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_init+0x46")
int BPF_KPROBE(do_mov_1765)
{
    u64 addr = ctx->r12 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x3f")
int BPF_KPROBE(do_mov_1766)
{
    u64 addr = ctx->di + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x46")
int BPF_KPROBE(do_mov_1767)
{
    u64 addr = ctx->di + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x4d")
int BPF_KPROBE(do_mov_1768)
{
    u64 addr = ctx->di + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x54")
int BPF_KPROBE(do_mov_1769)
{
    u64 addr = ctx->di + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0xd8")
int BPF_KPROBE(do_mov_1770)
{
    u64 addr = ctx->cx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x13b")
int BPF_KPROBE(do_mov_1771)
{
    u64 addr = ctx->di + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x149")
int BPF_KPROBE(do_mov_1772)
{
    u64 addr = ctx->ax + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x154")
int BPF_KPROBE(do_mov_1773)
{
    u64 addr = ctx->di + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x162")
int BPF_KPROBE(do_mov_1774)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x16f")
int BPF_KPROBE(do_mov_1775)
{
    u64 addr = ctx->cx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x190")
int BPF_KPROBE(do_mov_1776)
{
    u64 addr = ctx->cx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x19a")
int BPF_KPROBE(do_mov_1777)
{
    u64 addr = ctx->cx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_open+0x86")
int BPF_KPROBE(do_mov_1778)
{
    u64 addr = ctx->dx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_open+0x9e")
int BPF_KPROBE(do_mov_1779)
{
    u64 addr = ctx->cx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_stats64+0xd")
int BPF_KPROBE(do_mov_1780)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_stats64+0x1c")
int BPF_KPROBE(do_mov_1781)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_stats64+0x27")
int BPF_KPROBE(do_mov_1782)
{
    u64 addr = ctx->si + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_stats64+0x32")
int BPF_KPROBE(do_mov_1783)
{
    u64 addr = ctx->si + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_mtu+0x3e")
int BPF_KPROBE(do_mov_1784)
{
    u64 addr = ctx->di + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0x38")
int BPF_KPROBE(do_mov_1785)
{
    u64 addr = ctx->di + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0x45")
int BPF_KPROBE(do_mov_1786)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0x4d")
int BPF_KPROBE(do_mov_1787)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0x54")
int BPF_KPROBE(do_mov_1788)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0x58")
int BPF_KPROBE(do_mov_1789)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0xac")
int BPF_KPROBE(do_mov_1790)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0xe3")
int BPF_KPROBE(do_mov_1791)
{
    u64 addr = ctx->dx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_destroy+0x46")
int BPF_KPROBE(do_mov_1792)
{
    u64 addr = ctx->dx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_destroy+0x6a")
int BPF_KPROBE(do_mov_1793)
{
    u64 addr = ctx->cx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_destroy+0x84")
int BPF_KPROBE(do_mov_1794)
{
    u64 addr = ctx->cx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x21")
int BPF_KPROBE(do_mov_1795)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x29")
int BPF_KPROBE(do_mov_1796)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x43")
int BPF_KPROBE(do_mov_1797)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x46")
int BPF_KPROBE(do_mov_1798)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x4a")
int BPF_KPROBE(do_mov_1799)
{
    u64 addr = ctx->si + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x51")
int BPF_KPROBE(do_mov_1800)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x5e")
int BPF_KPROBE(do_mov_1801)
{
    u64 addr = ctx->si + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x1a6")
int BPF_KPROBE(do_mov_1802)
{
    u64 addr = ctx->r10 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x2ae")
int BPF_KPROBE(do_mov_1803)
{
    u64 addr = ctx->si + 0xa78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x332")
int BPF_KPROBE(do_mov_1804)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x361")
int BPF_KPROBE(do_mov_1805)
{
    u64 addr = ctx->gs + 0x3253a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x389")
int BPF_KPROBE(do_mov_1806)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x391")
int BPF_KPROBE(do_mov_1807)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x3b6")
int BPF_KPROBE(do_mov_1808)
{
    u64 addr = ctx->bx + 0xa78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x3e3")
int BPF_KPROBE(do_mov_1809)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x434")
int BPF_KPROBE(do_mov_1810)
{
    u64 addr = ctx->r14 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x447")
int BPF_KPROBE(do_mov_1811)
{
    u64 addr = ctx->r14 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_xmit+0x4af")
int BPF_KPROBE(do_mov_1812)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_dequeue+0x53")
int BPF_KPROBE(do_mov_1813)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_dequeue+0x60")
int BPF_KPROBE(do_mov_1814)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_dequeue+0x67")
int BPF_KPROBE(do_mov_1815)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_dequeue+0x6f")
int BPF_KPROBE(do_mov_1816)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_dequeue+0x73")
int BPF_KPROBE(do_mov_1817)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_dump_class+0x1b")
int BPF_KPROBE(do_mov_1818)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x11f")
int BPF_KPROBE(do_mov_1819)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x123")
int BPF_KPROBE(do_mov_1820)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x135")
int BPF_KPROBE(do_mov_1821)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x139")
int BPF_KPROBE(do_mov_1822)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_walk+0x31")
int BPF_KPROBE(do_mov_1823)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_walk+0x56")
int BPF_KPROBE(do_mov_1824)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_graft+0x62")
int BPF_KPROBE(do_mov_1825)
{
    u64 addr = ctx->r13 + ctx->ax * 0x8 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_graft+0x104")
int BPF_KPROBE(do_mov_1826)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0xfb")
int BPF_KPROBE(do_mov_1827)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0x10a")
int BPF_KPROBE(do_mov_1828)
{
    u64 addr = ctx->r14 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0x115")
int BPF_KPROBE(do_mov_1829)
{
    u64 addr = ctx->r14 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0x1a6")
int BPF_KPROBE(do_mov_1830)
{
    u64 addr = ctx->r14 + ctx->ax * 0x8 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_dequeue+0x2f")
int BPF_KPROBE(do_mov_1831)
{
    u64 addr = ctx->bx + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_dump_class+0x1f")
int BPF_KPROBE(do_mov_1832)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_reset+0x40")
int BPF_KPROBE(do_mov_1833)
{
    u64 addr = ctx->r12 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_enqueue+0x64")
int BPF_KPROBE(do_mov_1834)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_enqueue+0x68")
int BPF_KPROBE(do_mov_1835)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_walk+0x39")
int BPF_KPROBE(do_mov_1836)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_walk+0x62")
int BPF_KPROBE(do_mov_1837)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_tune+0x56")
int BPF_KPROBE(do_mov_1838)
{
    u64 addr = ctx->si + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_tune+0xbf")
int BPF_KPROBE(do_mov_1839)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_tune+0xee")
int BPF_KPROBE(do_mov_1840)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_tune+0x159")
int BPF_KPROBE(do_mov_1841)
{
    u64 addr = ctx->r14 + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_tune+0x242")
int BPF_KPROBE(do_mov_1842)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_init+0x5")
int BPF_KPROBE(do_mov_1843)
{
    u64 addr = ctx->di + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_init+0x64")
int BPF_KPROBE(do_mov_1844)
{
    u64 addr = ctx->r12 + 0x182;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_init+0x79")
int BPF_KPROBE(do_mov_1845)
{
    u64 addr = ctx->r12 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_init+0x9e")
int BPF_KPROBE(do_mov_1846)
{
    u64 addr = ctx->ax + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_graft+0x61")
int BPF_KPROBE(do_mov_1847)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_graft+0xdc")
int BPF_KPROBE(do_mov_1848)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dump_class+0x28")
int BPF_KPROBE(do_mov_1849)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_reset+0x8e")
int BPF_KPROBE(do_mov_1850)
{
    u64 addr = ctx->r12 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_reset+0x9a")
int BPF_KPROBE(do_mov_1851)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_reset+0xdb")
int BPF_KPROBE(do_mov_1852)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_reset+0xe7")
int BPF_KPROBE(do_mov_1853)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_reset+0xf3")
int BPF_KPROBE(do_mov_1854)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_walk+0x31")
int BPF_KPROBE(do_mov_1855)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_walk+0x3a")
int BPF_KPROBE(do_mov_1856)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_dist_table+0x5f")
int BPF_KPROBE(do_mov_1857)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_dist_table+0x9b")
int BPF_KPROBE(do_mov_1858)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x92")
int BPF_KPROBE(do_mov_1859)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x16d")
int BPF_KPROBE(do_mov_1860)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x179")
int BPF_KPROBE(do_mov_1861)
{
    u64 addr = ctx->bx + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x189")
int BPF_KPROBE(do_mov_1862)
{
    u64 addr = ctx->bx + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x195")
int BPF_KPROBE(do_mov_1863)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1a0")
int BPF_KPROBE(do_mov_1864)
{
    u64 addr = ctx->bx + 0x20c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1aa")
int BPF_KPROBE(do_mov_1865)
{
    u64 addr = ctx->bx + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1b5")
int BPF_KPROBE(do_mov_1866)
{
    u64 addr = ctx->bx + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1c0")
int BPF_KPROBE(do_mov_1867)
{
    u64 addr = ctx->bx + 0x214;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1ca")
int BPF_KPROBE(do_mov_1868)
{
    u64 addr = ctx->bx + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1e5")
int BPF_KPROBE(do_mov_1869)
{
    u64 addr = ctx->bx + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1f0")
int BPF_KPROBE(do_mov_1870)
{
    u64 addr = ctx->bx + 0x23c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x1fb")
int BPF_KPROBE(do_mov_1871)
{
    u64 addr = ctx->bx + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x206")
int BPF_KPROBE(do_mov_1872)
{
    u64 addr = ctx->bx + 0x244;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x211")
int BPF_KPROBE(do_mov_1873)
{
    u64 addr = ctx->bx + 0x250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x21c")
int BPF_KPROBE(do_mov_1874)
{
    u64 addr = ctx->bx + 0x24c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x231")
int BPF_KPROBE(do_mov_1875)
{
    u64 addr = ctx->bx + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x23a")
int BPF_KPROBE(do_mov_1876)
{
    u64 addr = ctx->bx + 0x258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x245")
int BPF_KPROBE(do_mov_1877)
{
    u64 addr = ctx->bx + 0x254;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x257")
int BPF_KPROBE(do_mov_1878)
{
    u64 addr = ctx->bx + 0x21c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x260")
int BPF_KPROBE(do_mov_1879)
{
    u64 addr = ctx->bx + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x26b")
int BPF_KPROBE(do_mov_1880)
{
    u64 addr = ctx->bx + 0x25c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x27d")
int BPF_KPROBE(do_mov_1881)
{
    u64 addr = ctx->bx + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x287")
int BPF_KPROBE(do_mov_1882)
{
    u64 addr = ctx->bx + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x290")
int BPF_KPROBE(do_mov_1883)
{
    u64 addr = ctx->bx + 0x22c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x299")
int BPF_KPROBE(do_mov_1884)
{
    u64 addr = ctx->bx + 0x238;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x2a7")
int BPF_KPROBE(do_mov_1885)
{
    u64 addr = ctx->bx + 0x230;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x2e1")
int BPF_KPROBE(do_mov_1886)
{
    u64 addr = ctx->bx + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x309")
int BPF_KPROBE(do_mov_1887)
{
    u64 addr = ctx->bx + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x331")
int BPF_KPROBE(do_mov_1888)
{
    u64 addr = ctx->bx + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x344")
int BPF_KPROBE(do_mov_1889)
{
    u64 addr = ctx->bx + 0x204;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x35b")
int BPF_KPROBE(do_mov_1890)
{
    u64 addr = ctx->bx + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x366")
int BPF_KPROBE(do_mov_1891)
{
    u64 addr = ctx->bx + 0x2a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x371")
int BPF_KPROBE(do_mov_1892)
{
    u64 addr = ctx->bx + 0x2a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x382")
int BPF_KPROBE(do_mov_1893)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x38d")
int BPF_KPROBE(do_mov_1894)
{
    u64 addr = ctx->bx + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x398")
int BPF_KPROBE(do_mov_1895)
{
    u64 addr = ctx->bx + 0x2a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x3b1")
int BPF_KPROBE(do_mov_1896)
{
    u64 addr = ctx->bx + 0x2ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x3c7")
int BPF_KPROBE(do_mov_1897)
{
    u64 addr = ctx->bx + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x3cd")
int BPF_KPROBE(do_mov_1898)
{
    u64 addr = ctx->bx + 0x2cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x3fa")
int BPF_KPROBE(do_mov_1899)
{
    u64 addr = ctx->bx + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x407")
int BPF_KPROBE(do_mov_1900)
{
    u64 addr = ctx->bx + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x42f")
int BPF_KPROBE(do_mov_1901)
{
    u64 addr = ctx->bx + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x514")
int BPF_KPROBE(do_mov_1902)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x51e")
int BPF_KPROBE(do_mov_1903)
{
    u64 addr = ctx->bx + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x528")
int BPF_KPROBE(do_mov_1904)
{
    u64 addr = ctx->bx + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x531")
int BPF_KPROBE(do_mov_1905)
{
    u64 addr = ctx->bx + 0x284;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x53a")
int BPF_KPROBE(do_mov_1906)
{
    u64 addr = ctx->bx + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x543")
int BPF_KPROBE(do_mov_1907)
{
    u64 addr = ctx->bx + 0x28c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x54c")
int BPF_KPROBE(do_mov_1908)
{
    u64 addr = ctx->bx + 0x290;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x57e")
int BPF_KPROBE(do_mov_1909)
{
    u64 addr = ctx->bx + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x585")
int BPF_KPROBE(do_mov_1910)
{
    u64 addr = ctx->bx + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x58c")
int BPF_KPROBE(do_mov_1911)
{
    u64 addr = ctx->bx + 0x284;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x593")
int BPF_KPROBE(do_mov_1912)
{
    u64 addr = ctx->bx + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x59a")
int BPF_KPROBE(do_mov_1913)
{
    u64 addr = ctx->bx + 0x28c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x5a0")
int BPF_KPROBE(do_mov_1914)
{
    u64 addr = ctx->bx + 0x290;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x5a7")
int BPF_KPROBE(do_mov_1915)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x5b8")
int BPF_KPROBE(do_mov_1916)
{
    u64 addr = ctx->bx + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x5c9")
int BPF_KPROBE(do_mov_1917)
{
    u64 addr = ctx->bx + 0x230;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x5e6")
int BPF_KPROBE(do_mov_1918)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x5f0")
int BPF_KPROBE(do_mov_1919)
{
    u64 addr = ctx->bx + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x5fa")
int BPF_KPROBE(do_mov_1920)
{
    u64 addr = ctx->bx + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x603")
int BPF_KPROBE(do_mov_1921)
{
    u64 addr = ctx->bx + 0x284;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x60c")
int BPF_KPROBE(do_mov_1922)
{
    u64 addr = ctx->bx + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x615")
int BPF_KPROBE(do_mov_1923)
{
    u64 addr = ctx->bx + 0x28c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_init+0x35")
int BPF_KPROBE(do_mov_1924)
{
    u64 addr = ctx->r12 + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dump+0x252")
int BPF_KPROBE(do_mov_1925)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dump+0x287")
int BPF_KPROBE(do_mov_1926)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_graft+0x4b")
int BPF_KPROBE(do_mov_1927)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_graft+0xcd")
int BPF_KPROBE(do_mov_1928)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_slot_next+0x3e")
int BPF_KPROBE(do_mov_1929)
{
    u64 addr = ctx->bx + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_slot_next+0x45")
int BPF_KPROBE(do_mov_1930)
{
    u64 addr = ctx->bx + 0x148;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x43")
int BPF_KPROBE(do_mov_1931)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x4f")
int BPF_KPROBE(do_mov_1932)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0xb6")
int BPF_KPROBE(do_mov_1933)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x160")
int BPF_KPROBE(do_mov_1934)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x168")
int BPF_KPROBE(do_mov_1935)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x178")
int BPF_KPROBE(do_mov_1936)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x196")
int BPF_KPROBE(do_mov_1937)
{
    u64 addr = ctx->bx + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x1a1")
int BPF_KPROBE(do_mov_1938)
{
    u64 addr = ctx->bx + 0x2cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x271")
int BPF_KPROBE(do_mov_1939)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x281")
int BPF_KPROBE(do_mov_1940)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x30")
int BPF_KPROBE(do_mov_1941)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x203")
int BPF_KPROBE(do_mov_1942)
{
    u64 addr = ctx->r14 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x240")
int BPF_KPROBE(do_mov_1943)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x249")
int BPF_KPROBE(do_mov_1944)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x251")
int BPF_KPROBE(do_mov_1945)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x259")
int BPF_KPROBE(do_mov_1946)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x2a5")
int BPF_KPROBE(do_mov_1947)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x2ac")
int BPF_KPROBE(do_mov_1948)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x37c")
int BPF_KPROBE(do_mov_1949)
{
    u64 addr = ctx->r14 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x387")
int BPF_KPROBE(do_mov_1950)
{
    u64 addr = ctx->r15 + 0x20c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x392")
int BPF_KPROBE(do_mov_1951)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x3ae")
int BPF_KPROBE(do_mov_1952)
{
    u64 addr = ctx->r15 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x41e")
int BPF_KPROBE(do_mov_1953)
{
    u64 addr = ctx->r15 + 0x214;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x42e")
int BPF_KPROBE(do_mov_1954)
{
    u64 addr = ctx->r15 + 0x214;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x4cd")
int BPF_KPROBE(do_mov_1955)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x4d4")
int BPF_KPROBE(do_mov_1956)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x5c7")
int BPF_KPROBE(do_mov_1957)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x5ca")
int BPF_KPROBE(do_mov_1958)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x638")
int BPF_KPROBE(do_mov_1959)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x63b")
int BPF_KPROBE(do_mov_1960)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x6a1")
int BPF_KPROBE(do_mov_1961)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x6cf")
int BPF_KPROBE(do_mov_1962)
{
    u64 addr = ctx->r15 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x76b")
int BPF_KPROBE(do_mov_1963)
{
    u64 addr = ctx->r15 + 0x24c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x7ae")
int BPF_KPROBE(do_mov_1964)
{
    u64 addr = ctx->r15 + 0x25c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x7e0")
int BPF_KPROBE(do_mov_1965)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x7fb")
int BPF_KPROBE(do_mov_1966)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x88a")
int BPF_KPROBE(do_mov_1967)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x8b5")
int BPF_KPROBE(do_mov_1968)
{
    u64 addr = ctx->r14 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x960")
int BPF_KPROBE(do_mov_1969)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x973")
int BPF_KPROBE(do_mov_1970)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x97a")
int BPF_KPROBE(do_mov_1971)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x9f8")
int BPF_KPROBE(do_mov_1972)
{
    u64 addr = ctx->di + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xa00")
int BPF_KPROBE(do_mov_1973)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xa61")
int BPF_KPROBE(do_mov_1974)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xa65")
int BPF_KPROBE(do_mov_1975)
{
    u64 addr = ctx->dx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xabf")
int BPF_KPROBE(do_mov_1976)
{
    u64 addr = ctx->r15 + 0x244;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xb10")
int BPF_KPROBE(do_mov_1977)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xb29")
int BPF_KPROBE(do_mov_1978)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xb6b")
int BPF_KPROBE(do_mov_1979)
{
    u64 addr = ctx->r15 + 0x254;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbac")
int BPF_KPROBE(do_mov_1980)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbaf")
int BPF_KPROBE(do_mov_1981)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbd2")
int BPF_KPROBE(do_mov_1982)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbe1")
int BPF_KPROBE(do_mov_1983)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbe4")
int BPF_KPROBE(do_mov_1984)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xc2e")
int BPF_KPROBE(do_mov_1985)
{
    u64 addr = ctx->r15 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_qlen_notify+0xe")
int BPF_KPROBE(do_mov_1986)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_qlen_notify+0x15")
int BPF_KPROBE(do_mov_1987)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_qlen_notify+0x22")
int BPF_KPROBE(do_mov_1988)
{
    u64 addr = ctx->si + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_qlen_notify+0x2a")
int BPF_KPROBE(do_mov_1989)
{
    u64 addr = ctx->si + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_reset_qdisc+0x69")
int BPF_KPROBE(do_mov_1990)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_reset_qdisc+0x6d")
int BPF_KPROBE(do_mov_1991)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_reset_qdisc+0x74")
int BPF_KPROBE(do_mov_1992)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_reset_qdisc+0x78")
int BPF_KPROBE(do_mov_1993)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x3c")
int BPF_KPROBE(do_mov_1994)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x43")
int BPF_KPROBE(do_mov_1995)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x47")
int BPF_KPROBE(do_mov_1996)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x51")
int BPF_KPROBE(do_mov_1997)
{
    u64 addr = ctx->r14 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x58")
int BPF_KPROBE(do_mov_1998)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x5b")
int BPF_KPROBE(do_mov_1999)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x5f")
int BPF_KPROBE(do_mov_2000)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x9a")
int BPF_KPROBE(do_mov_2001)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0xca")
int BPF_KPROBE(do_mov_2002)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0xd9")
int BPF_KPROBE(do_mov_2003)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0xe1")
int BPF_KPROBE(do_mov_2004)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0xea")
int BPF_KPROBE(do_mov_2005)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0xee")
int BPF_KPROBE(do_mov_2006)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x126")
int BPF_KPROBE(do_mov_2007)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x12a")
int BPF_KPROBE(do_mov_2008)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x137")
int BPF_KPROBE(do_mov_2009)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x13e")
int BPF_KPROBE(do_mov_2010)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_walk+0x56")
int BPF_KPROBE(do_mov_2011)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_walk+0x83")
int BPF_KPROBE(do_mov_2012)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_init_qdisc+0x52")
int BPF_KPROBE(do_mov_2013)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_init_qdisc+0x5c")
int BPF_KPROBE(do_mov_2014)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_tcf_block+0x35")
int BPF_KPROBE(do_mov_2015)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dump_class+0x2a")
int BPF_KPROBE(do_mov_2016)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dump_class+0x33")
int BPF_KPROBE(do_mov_2017)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dump_class+0x42")
int BPF_KPROBE(do_mov_2018)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dump_class+0x98")
int BPF_KPROBE(do_mov_2019)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_graft_class+0x54")
int BPF_KPROBE(do_mov_2020)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_graft_class+0xd0")
int BPF_KPROBE(do_mov_2021)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0xf5")
int BPF_KPROBE(do_mov_2022)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x17c")
int BPF_KPROBE(do_mov_2023)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x17f")
int BPF_KPROBE(do_mov_2024)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x18f")
int BPF_KPROBE(do_mov_2025)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x225")
int BPF_KPROBE(do_mov_2026)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x25e")
int BPF_KPROBE(do_mov_2027)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x2af")
int BPF_KPROBE(do_mov_2028)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x321")
int BPF_KPROBE(do_mov_2029)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x422")
int BPF_KPROBE(do_mov_2030)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x445")
int BPF_KPROBE(do_mov_2031)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0xf0")
int BPF_KPROBE(do_mov_2032)
{
    u64 addr = ctx->r12 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0xf8")
int BPF_KPROBE(do_mov_2033)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0xfc")
int BPF_KPROBE(do_mov_2034)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0x100")
int BPF_KPROBE(do_mov_2035)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0x106")
int BPF_KPROBE(do_mov_2036)
{
    u64 addr = ctx->bx + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0x15e")
int BPF_KPROBE(do_mov_2037)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0x161")
int BPF_KPROBE(do_mov_2038)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_init+0x6")
int BPF_KPROBE(do_mov_2039)
{
    u64 addr = ctx->di + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_init+0x11")
int BPF_KPROBE(do_mov_2040)
{
    u64 addr = ctx->di + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_init+0x1e")
int BPF_KPROBE(do_mov_2041)
{
    u64 addr = ctx->di + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_init+0x38")
int BPF_KPROBE(do_mov_2042)
{
    u64 addr = ctx->di + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_init+0x41")
int BPF_KPROBE(do_mov_2043)
{
    u64 addr = ctx->di + 0x181;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x37")
int BPF_KPROBE(do_mov_2044)
{
    u64 addr = ctx->di + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x41")
int BPF_KPROBE(do_mov_2045)
{
    u64 addr = ctx->di + 0x181;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x5d")
int BPF_KPROBE(do_mov_2046)
{
    u64 addr = ctx->di + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x7b")
int BPF_KPROBE(do_mov_2047)
{
    u64 addr = ctx->di + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x85")
int BPF_KPROBE(do_mov_2048)
{
    u64 addr = ctx->di + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x8d")
int BPF_KPROBE(do_mov_2049)
{
    u64 addr = ctx->di + 0x181;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x94")
int BPF_KPROBE(do_mov_2050)
{
    u64 addr = ctx->di + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x9d")
int BPF_KPROBE(do_mov_2051)
{
    u64 addr = ctx->di + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0xad")
int BPF_KPROBE(do_mov_2052)
{
    u64 addr = ctx->di + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0xb4")
int BPF_KPROBE(do_mov_2053)
{
    u64 addr = ctx->di + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_dequeue+0x2c")
int BPF_KPROBE(do_mov_2054)
{
    u64 addr = ctx->di + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_dequeue+0x48")
int BPF_KPROBE(do_mov_2055)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_dequeue+0x54")
int BPF_KPROBE(do_mov_2056)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_dequeue+0x94")
int BPF_KPROBE(do_mov_2057)
{
    u64 addr = ctx->di + 0x181;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_dequeue+0x9f")
int BPF_KPROBE(do_mov_2058)
{
    u64 addr = ctx->di + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x31")
int BPF_KPROBE(do_mov_2059)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x38")
int BPF_KPROBE(do_mov_2060)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x41")
int BPF_KPROBE(do_mov_2061)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x52")
int BPF_KPROBE(do_mov_2062)
{
    u64 addr = ctx->si + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x6f")
int BPF_KPROBE(do_mov_2063)
{
    u64 addr = ctx->si + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x76")
int BPF_KPROBE(do_mov_2064)
{
    u64 addr = ctx->si + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x82")
int BPF_KPROBE(do_mov_2065)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x8a")
int BPF_KPROBE(do_mov_2066)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_qlen_notify+0x3e")
int BPF_KPROBE(do_mov_2067)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_qlen_notify+0x42")
int BPF_KPROBE(do_mov_2068)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_qlen_notify+0x4f")
int BPF_KPROBE(do_mov_2069)
{
    u64 addr = ctx->di + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_qlen_notify+0x5a")
int BPF_KPROBE(do_mov_2070)
{
    u64 addr = ctx->di + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_offload_change+0xec")
int BPF_KPROBE(do_mov_2071)
{
    u64 addr = ctx->cx - 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_offload_change+0xfb")
int BPF_KPROBE(do_mov_2072)
{
    u64 addr = ctx->cx - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_reset+0x6a")
int BPF_KPROBE(do_mov_2073)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_reset+0x6e")
int BPF_KPROBE(do_mov_2074)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_reset+0x71")
int BPF_KPROBE(do_mov_2075)
{
    u64 addr = ctx->ax + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_reset+0x78")
int BPF_KPROBE(do_mov_2076)
{
    u64 addr = ctx->ax + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_walk+0x31")
int BPF_KPROBE(do_mov_2077)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_walk+0x56")
int BPF_KPROBE(do_mov_2078)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_tcf_block+0x35")
int BPF_KPROBE(do_mov_2079)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x17c")
int BPF_KPROBE(do_mov_2080)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x17f")
int BPF_KPROBE(do_mov_2081)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x194")
int BPF_KPROBE(do_mov_2082)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x197")
int BPF_KPROBE(do_mov_2083)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x1a6")
int BPF_KPROBE(do_mov_2084)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x1ad")
int BPF_KPROBE(do_mov_2085)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x1b1")
int BPF_KPROBE(do_mov_2086)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x1b6")
int BPF_KPROBE(do_mov_2087)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x1be")
int BPF_KPROBE(do_mov_2088)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x6b")
int BPF_KPROBE(do_mov_2089)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x78")
int BPF_KPROBE(do_mov_2090)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x7f")
int BPF_KPROBE(do_mov_2091)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x87")
int BPF_KPROBE(do_mov_2092)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x8b")
int BPF_KPROBE(do_mov_2093)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x154")
int BPF_KPROBE(do_mov_2094)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x15e")
int BPF_KPROBE(do_mov_2095)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x162")
int BPF_KPROBE(do_mov_2096)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x16c")
int BPF_KPROBE(do_mov_2097)
{
    u64 addr = ctx->r13 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x173")
int BPF_KPROBE(do_mov_2098)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x177")
int BPF_KPROBE(do_mov_2099)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x17c")
int BPF_KPROBE(do_mov_2100)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x1dd")
int BPF_KPROBE(do_mov_2101)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x203")
int BPF_KPROBE(do_mov_2102)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x210")
int BPF_KPROBE(do_mov_2103)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x217")
int BPF_KPROBE(do_mov_2104)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x21f")
int BPF_KPROBE(do_mov_2105)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x223")
int BPF_KPROBE(do_mov_2106)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x266")
int BPF_KPROBE(do_mov_2107)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x26a")
int BPF_KPROBE(do_mov_2108)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x26d")
int BPF_KPROBE(do_mov_2109)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x275")
int BPF_KPROBE(do_mov_2110)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_dump+0x46")
int BPF_KPROBE(do_mov_2111)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_dump+0x71")
int BPF_KPROBE(do_mov_2112)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_dump+0x80")
int BPF_KPROBE(do_mov_2113)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_dump+0xc7")
int BPF_KPROBE(do_mov_2114)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x189")
int BPF_KPROBE(do_mov_2115)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x294")
int BPF_KPROBE(do_mov_2116)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x34d")
int BPF_KPROBE(do_mov_2117)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x406")
int BPF_KPROBE(do_mov_2118)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x453")
int BPF_KPROBE(do_mov_2119)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x45a")
int BPF_KPROBE(do_mov_2120)
{
    u64 addr = ctx->si + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x461")
int BPF_KPROBE(do_mov_2121)
{
    u64 addr = ctx->si + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x468")
int BPF_KPROBE(do_mov_2122)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x472")
int BPF_KPROBE(do_mov_2123)
{
    u64 addr = ctx->si + 0x1dc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x4e0")
int BPF_KPROBE(do_mov_2124)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x4e4")
int BPF_KPROBE(do_mov_2125)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x4ec")
int BPF_KPROBE(do_mov_2126)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x4f0")
int BPF_KPROBE(do_mov_2127)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x56d")
int BPF_KPROBE(do_mov_2128)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x577")
int BPF_KPROBE(do_mov_2129)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x57e")
int BPF_KPROBE(do_mov_2130)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x5ba")
int BPF_KPROBE(do_mov_2131)
{
    u64 addr = ctx->dx - 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x5e4")
int BPF_KPROBE(do_mov_2132)
{
    u64 addr = ctx->bx + ctx->ax * 0x1 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x682")
int BPF_KPROBE(do_mov_2133)
{
    u64 addr = ctx->r12 - 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x68b")
int BPF_KPROBE(do_mov_2134)
{
    u64 addr = ctx->r12 - 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x694")
int BPF_KPROBE(do_mov_2135)
{
    u64 addr = ctx->r12 - 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x6a2")
int BPF_KPROBE(do_mov_2136)
{
    u64 addr = ctx->r12 - 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x6ab")
int BPF_KPROBE(do_mov_2137)
{
    u64 addr = ctx->r12 - 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x6b4")
int BPF_KPROBE(do_mov_2138)
{
    u64 addr = ctx->r12 - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x727")
int BPF_KPROBE(do_mov_2139)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x731")
int BPF_KPROBE(do_mov_2140)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x738")
int BPF_KPROBE(do_mov_2141)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x767")
int BPF_KPROBE(do_mov_2142)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x774")
int BPF_KPROBE(do_mov_2143)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x779")
int BPF_KPROBE(do_mov_2144)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x80a")
int BPF_KPROBE(do_mov_2145)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x82d")
int BPF_KPROBE(do_mov_2146)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x850")
int BPF_KPROBE(do_mov_2147)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x877")
int BPF_KPROBE(do_mov_2148)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x8af")
int BPF_KPROBE(do_mov_2149)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x8d6")
int BPF_KPROBE(do_mov_2150)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x8fd")
int BPF_KPROBE(do_mov_2151)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_init+0x42")
int BPF_KPROBE(do_mov_2152)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_init+0x5a")
int BPF_KPROBE(do_mov_2153)
{
    u64 addr = ctx->r12 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_init+0x62")
int BPF_KPROBE(do_mov_2154)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_init+0x65")
int BPF_KPROBE(do_mov_2155)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dump+0x180")
int BPF_KPROBE(do_mov_2156)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dump+0x201")
int BPF_KPROBE(do_mov_2157)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dump+0x218")
int BPF_KPROBE(do_mov_2158)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_graft+0x67")
int BPF_KPROBE(do_mov_2159)
{
    u64 addr = ctx->ax + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_graft+0xed")
int BPF_KPROBE(do_mov_2160)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x102")
int BPF_KPROBE(do_mov_2161)
{
    u64 addr = ctx->r12 + ctx->ax * 0x1 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x1f6")
int BPF_KPROBE(do_mov_2162)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x202")
int BPF_KPROBE(do_mov_2163)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x20a")
int BPF_KPROBE(do_mov_2164)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x224")
int BPF_KPROBE(do_mov_2165)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x246")
int BPF_KPROBE(do_mov_2166)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x268")
int BPF_KPROBE(do_mov_2167)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x293")
int BPF_KPROBE(do_mov_2168)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_walk+0x27")
int BPF_KPROBE(do_mov_2169)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_walk+0x4a")
int BPF_KPROBE(do_mov_2170)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_walk+0x76")
int BPF_KPROBE(do_mov_2171)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_walk+0xc3")
int BPF_KPROBE(do_mov_2172)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_attach+0x8d")
int BPF_KPROBE(do_mov_2173)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump_class+0x66")
int BPF_KPROBE(do_mov_2174)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump_class+0x74")
int BPF_KPROBE(do_mov_2175)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump_class+0x7d")
int BPF_KPROBE(do_mov_2176)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_graft+0x59")
int BPF_KPROBE(do_mov_2177)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0xab")
int BPF_KPROBE(do_mov_2178)
{
    u64 addr = ctx->r15 + 0x15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x134")
int BPF_KPROBE(do_mov_2179)
{
    u64 addr = ctx->r14 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x154")
int BPF_KPROBE(do_mov_2180)
{
    u64 addr = ctx->r14 + 0x18a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x1b6")
int BPF_KPROBE(do_mov_2181)
{
    u64 addr = ctx->r14 + ctx->si * 0x8 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x216")
int BPF_KPROBE(do_mov_2182)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x23c")
int BPF_KPROBE(do_mov_2183)
{
    u64 addr = ctx->dx + ctx->r13 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x485")
int BPF_KPROBE(do_mov_2184)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x4e1")
int BPF_KPROBE(do_mov_2185)
{
    u64 addr = ctx->r14 + ctx->cx * 0x8 + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x53b")
int BPF_KPROBE(do_mov_2186)
{
    u64 addr = ctx->r14 + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x55c")
int BPF_KPROBE(do_mov_2187)
{
    u64 addr = ctx->r12 + ctx->ax * 0x1 + 0x8e2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x649")
int BPF_KPROBE(do_mov_2188)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x82")
int BPF_KPROBE(do_mov_2189)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0xa0")
int BPF_KPROBE(do_mov_2190)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0xb0")
int BPF_KPROBE(do_mov_2191)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0xbb")
int BPF_KPROBE(do_mov_2192)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x18d")
int BPF_KPROBE(do_mov_2193)
{
    u64 addr = ctx->r14 + ctx->ax * 0x2 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x19c")
int BPF_KPROBE(do_mov_2194)
{
    u64 addr = ctx->r14 + ctx->ax * 0x2 + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x20d")
int BPF_KPROBE(do_mov_2195)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x40b")
int BPF_KPROBE(do_mov_2196)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x43d")
int BPF_KPROBE(do_mov_2197)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_change+0x13")
int BPF_KPROBE(do_mov_2198)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x1a")
int BPF_KPROBE(do_mov_2199)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x1d")
int BPF_KPROBE(do_mov_2200)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x25")
int BPF_KPROBE(do_mov_2201)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x38")
int BPF_KPROBE(do_mov_2202)
{
    u64 addr = ctx->r8 + 0x780;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x43")
int BPF_KPROBE(do_mov_2203)
{
    u64 addr = ctx->r8 + 0xc78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x63")
int BPF_KPROBE(do_mov_2204)
{
    u64 addr = ctx->r8 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x6b")
int BPF_KPROBE(do_mov_2205)
{
    u64 addr = ctx->r8 + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x85")
int BPF_KPROBE(do_mov_2206)
{
    u64 addr = ctx->r8 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x51")
int BPF_KPROBE(do_mov_2207)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x5b")
int BPF_KPROBE(do_mov_2208)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x62")
int BPF_KPROBE(do_mov_2209)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x6a")
int BPF_KPROBE(do_mov_2210)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x6e")
int BPF_KPROBE(do_mov_2211)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0xcb")
int BPF_KPROBE(do_mov_2212)
{
    u64 addr = ctx->r10 + 0x784;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x122")
int BPF_KPROBE(do_mov_2213)
{
    u64 addr = ctx->ax + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x138")
int BPF_KPROBE(do_mov_2214)
{
    u64 addr = ctx->ax + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x74")
int BPF_KPROBE(do_mov_2215)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x77")
int BPF_KPROBE(do_mov_2216)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x8a")
int BPF_KPROBE(do_mov_2217)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x8d")
int BPF_KPROBE(do_mov_2218)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x91")
int BPF_KPROBE(do_mov_2219)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x95")
int BPF_KPROBE(do_mov_2220)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0xab")
int BPF_KPROBE(do_mov_2221)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x102")
int BPF_KPROBE(do_mov_2222)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x10d")
int BPF_KPROBE(do_mov_2223)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x114")
int BPF_KPROBE(do_mov_2224)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x11c")
int BPF_KPROBE(do_mov_2225)
{
    u64 addr = ctx->r11 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x120")
int BPF_KPROBE(do_mov_2226)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x131")
int BPF_KPROBE(do_mov_2227)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x134")
int BPF_KPROBE(do_mov_2228)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x14f")
int BPF_KPROBE(do_mov_2229)
{
    u64 addr = ctx->si + 0x784;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x186")
int BPF_KPROBE(do_mov_2230)
{
    u64 addr = ctx->ax + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x196")
int BPF_KPROBE(do_mov_2231)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x199")
int BPF_KPROBE(do_mov_2232)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x19d")
int BPF_KPROBE(do_mov_2233)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x1a1")
int BPF_KPROBE(do_mov_2234)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x1bb")
int BPF_KPROBE(do_mov_2235)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x1db")
int BPF_KPROBE(do_mov_2236)
{
    u64 addr = ctx->ax + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x1eb")
int BPF_KPROBE(do_mov_2237)
{
    u64 addr = ctx->ax + 0xc82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x242")
int BPF_KPROBE(do_mov_2238)
{
    u64 addr = ctx->ax + 0xc82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x260")
int BPF_KPROBE(do_mov_2239)
{
    u64 addr = ctx->ax + 0xc82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x26d")
int BPF_KPROBE(do_mov_2240)
{
    u64 addr = ctx->ax + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_walk+0x2f")
int BPF_KPROBE(do_mov_2241)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_walk+0x4d")
int BPF_KPROBE(do_mov_2242)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_destroy+0x2a")
int BPF_KPROBE(do_mov_2243)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_destroy+0x34")
int BPF_KPROBE(do_mov_2244)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_destroy+0x3b")
int BPF_KPROBE(do_mov_2245)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_destroy+0x43")
int BPF_KPROBE(do_mov_2246)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_destroy+0x47")
int BPF_KPROBE(do_mov_2247)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x2c")
int BPF_KPROBE(do_mov_2248)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x36")
int BPF_KPROBE(do_mov_2249)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x3d")
int BPF_KPROBE(do_mov_2250)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x45")
int BPF_KPROBE(do_mov_2251)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x49")
int BPF_KPROBE(do_mov_2252)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x73")
int BPF_KPROBE(do_mov_2253)
{
    u64 addr = ctx->r13 + 0x780;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x7e")
int BPF_KPROBE(do_mov_2254)
{
    u64 addr = ctx->r13 + 0xc78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x9c")
int BPF_KPROBE(do_mov_2255)
{
    u64 addr = ctx->r13 + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_reset+0x1e")
int BPF_KPROBE(do_mov_2256)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_reset+0x6b")
int BPF_KPROBE(do_mov_2257)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_reset+0x76")
int BPF_KPROBE(do_mov_2258)
{
    u64 addr = ctx->bx + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_reset+0x81")
int BPF_KPROBE(do_mov_2259)
{
    u64 addr = ctx->bx + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_reset+0x8c")
int BPF_KPROBE(do_mov_2260)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_dump+0xe4")
int BPF_KPROBE(do_mov_2261)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x2e")
int BPF_KPROBE(do_mov_2262)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x5f")
int BPF_KPROBE(do_mov_2263)
{
    u64 addr = ctx->si + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x75")
int BPF_KPROBE(do_mov_2264)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x9b")
int BPF_KPROBE(do_mov_2265)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0xa4")
int BPF_KPROBE(do_mov_2266)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x145")
int BPF_KPROBE(do_mov_2267)
{
    u64 addr = ctx->bx + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x15b")
int BPF_KPROBE(do_mov_2268)
{
    u64 addr = ctx->bx + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x1f9")
int BPF_KPROBE(do_mov_2269)
{
    u64 addr = ctx->ax + ctx->dx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x213")
int BPF_KPROBE(do_mov_2270)
{
    u64 addr = ctx->bx + 0x2e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x268")
int BPF_KPROBE(do_mov_2271)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x2a7")
int BPF_KPROBE(do_mov_2272)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x2de")
int BPF_KPROBE(do_mov_2273)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x31a")
int BPF_KPROBE(do_mov_2274)
{
    u64 addr = ctx->bx + 0x2b4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x3a7")
int BPF_KPROBE(do_mov_2275)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x3e8")
int BPF_KPROBE(do_mov_2276)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x3ec")
int BPF_KPROBE(do_mov_2277)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x424")
int BPF_KPROBE(do_mov_2278)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x42d")
int BPF_KPROBE(do_mov_2279)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x467")
int BPF_KPROBE(do_mov_2280)
{
    u64 addr = ctx->bx + 0x2b4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x483")
int BPF_KPROBE(do_mov_2281)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x4de")
int BPF_KPROBE(do_mov_2282)
{
    u64 addr = ctx->si + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x55e")
int BPF_KPROBE(do_mov_2283)
{
    u64 addr = ctx->bx + 0x2e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x597")
int BPF_KPROBE(do_mov_2284)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_dequeue+0x2f")
int BPF_KPROBE(do_mov_2285)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_dequeue+0x5f")
int BPF_KPROBE(do_mov_2286)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_dequeue+0xca")
int BPF_KPROBE(do_mov_2287)
{
    u64 addr = ctx->bx + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x1ce")
int BPF_KPROBE(do_mov_2288)
{
    u64 addr = ctx->r15 + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x1ee")
int BPF_KPROBE(do_mov_2289)
{
    u64 addr = ctx->r10 + ctx->cx * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x204")
int BPF_KPROBE(do_mov_2290)
{
    u64 addr = ctx->r15 + 0x2e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x20b")
int BPF_KPROBE(do_mov_2291)
{
    u64 addr = ctx->r15 + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x21a")
int BPF_KPROBE(do_mov_2292)
{
    u64 addr = ctx->r15 + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x221")
int BPF_KPROBE(do_mov_2293)
{
    u64 addr = ctx->r15 + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x234")
int BPF_KPROBE(do_mov_2294)
{
    u64 addr = ctx->r15 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x23f")
int BPF_KPROBE(do_mov_2295)
{
    u64 addr = ctx->r15 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x25d")
int BPF_KPROBE(do_mov_2296)
{
    u64 addr = ctx->r15 + 0x1ad;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x267")
int BPF_KPROBE(do_mov_2297)
{
    u64 addr = ctx->r15 + 0x1ae;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x270")
int BPF_KPROBE(do_mov_2298)
{
    u64 addr = ctx->r15 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x282")
int BPF_KPROBE(do_mov_2299)
{
    u64 addr = ctx->r15 + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x292")
int BPF_KPROBE(do_mov_2300)
{
    u64 addr = ctx->r15 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x2b5")
int BPF_KPROBE(do_mov_2301)
{
    u64 addr = ctx->r15 + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x2df")
int BPF_KPROBE(do_mov_2302)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x2ec")
int BPF_KPROBE(do_mov_2303)
{
    u64 addr = ctx->r15 + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x2fe")
int BPF_KPROBE(do_mov_2304)
{
    u64 addr = ctx->r15 + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x30c")
int BPF_KPROBE(do_mov_2305)
{
    u64 addr = ctx->r15 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x313")
int BPF_KPROBE(do_mov_2306)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x33c")
int BPF_KPROBE(do_mov_2307)
{
    u64 addr = ctx->r15 + 0x1af;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x359")
int BPF_KPROBE(do_mov_2308)
{
    u64 addr = ctx->r15 + 0x2a7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x360")
int BPF_KPROBE(do_mov_2309)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x363")
int BPF_KPROBE(do_mov_2310)
{
    u64 addr = ctx->r15 + 0x2b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x375")
int BPF_KPROBE(do_mov_2311)
{
    u64 addr = ctx->r15 + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x389")
int BPF_KPROBE(do_mov_2312)
{
    u64 addr = ctx->r15 + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x3c8")
int BPF_KPROBE(do_mov_2313)
{
    u64 addr = ctx->r15 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_slot_scan+0x34")
int BPF_KPROBE(do_mov_2314)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_slot_scan+0x38")
int BPF_KPROBE(do_mov_2315)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x5e")
int BPF_KPROBE(do_mov_2316)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0xc2")
int BPF_KPROBE(do_mov_2317)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0xc6")
int BPF_KPROBE(do_mov_2318)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0xca")
int BPF_KPROBE(do_mov_2319)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0xce")
int BPF_KPROBE(do_mov_2320)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x10b")
int BPF_KPROBE(do_mov_2321)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x158")
int BPF_KPROBE(do_mov_2322)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x160")
int BPF_KPROBE(do_mov_2323)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x16e")
int BPF_KPROBE(do_mov_2324)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x175")
int BPF_KPROBE(do_mov_2325)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x1dc")
int BPF_KPROBE(do_mov_2326)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x1e6")
int BPF_KPROBE(do_mov_2327)
{
    u64 addr = ctx->r15 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x252")
int BPF_KPROBE(do_mov_2328)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x261")
int BPF_KPROBE(do_mov_2329)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x265")
int BPF_KPROBE(do_mov_2330)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x2af")
int BPF_KPROBE(do_mov_2331)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x1f")
int BPF_KPROBE(do_mov_2332)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x27")
int BPF_KPROBE(do_mov_2333)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x2b")
int BPF_KPROBE(do_mov_2334)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x34")
int BPF_KPROBE(do_mov_2335)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x45")
int BPF_KPROBE(do_mov_2336)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x53")
int BPF_KPROBE(do_mov_2337)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x74")
int BPF_KPROBE(do_mov_2338)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0x54")
int BPF_KPROBE(do_mov_2339)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0x5d")
int BPF_KPROBE(do_mov_2340)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0x7e")
int BPF_KPROBE(do_mov_2341)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0x82")
int BPF_KPROBE(do_mov_2342)
{
    u64 addr = ctx->r13 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0x86")
int BPF_KPROBE(do_mov_2343)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xa0")
int BPF_KPROBE(do_mov_2344)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xa8")
int BPF_KPROBE(do_mov_2345)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xac")
int BPF_KPROBE(do_mov_2346)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xb4")
int BPF_KPROBE(do_mov_2347)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xcc")
int BPF_KPROBE(do_mov_2348)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xd5")
int BPF_KPROBE(do_mov_2349)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xe0")
int BPF_KPROBE(do_mov_2350)
{
    u64 addr = ctx->r13 + 0x1d58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xe7")
int BPF_KPROBE(do_mov_2351)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0x148")
int BPF_KPROBE(do_mov_2352)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0x5a")
int BPF_KPROBE(do_mov_2353)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0x64")
int BPF_KPROBE(do_mov_2354)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0x7c")
int BPF_KPROBE(do_mov_2355)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0x8b")
int BPF_KPROBE(do_mov_2356)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0xd6")
int BPF_KPROBE(do_mov_2357)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0xdf")
int BPF_KPROBE(do_mov_2358)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0xe3")
int BPF_KPROBE(do_mov_2359)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0xe6")
int BPF_KPROBE(do_mov_2360)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0x123")
int BPF_KPROBE(do_mov_2361)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_walk+0x56")
int BPF_KPROBE(do_mov_2362)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_walk+0x83")
int BPF_KPROBE(do_mov_2363)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0x7b")
int BPF_KPROBE(do_mov_2364)
{
    u64 addr = ctx->bx + 0x1ed0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0x84")
int BPF_KPROBE(do_mov_2365)
{
    u64 addr = ctx->bx + 0x1ed4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0x99")
int BPF_KPROBE(do_mov_2366)
{
    u64 addr = ctx->dx - 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0x9f")
int BPF_KPROBE(do_mov_2367)
{
    u64 addr = ctx->dx - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0xb3")
int BPF_KPROBE(do_mov_2368)
{
    u64 addr = ctx->dx - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0xc1")
int BPF_KPROBE(do_mov_2369)
{
    u64 addr = ctx->dx - 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0xd7")
int BPF_KPROBE(do_mov_2370)
{
    u64 addr = ctx->bx + 0x1ed8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x24")
int BPF_KPROBE(do_mov_2371)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x48")
int BPF_KPROBE(do_mov_2372)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x55")
int BPF_KPROBE(do_mov_2373)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x63")
int BPF_KPROBE(do_mov_2374)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x6a")
int BPF_KPROBE(do_mov_2375)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x134")
int BPF_KPROBE(do_mov_2376)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x144")
int BPF_KPROBE(do_mov_2377)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x149")
int BPF_KPROBE(do_mov_2378)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x1bc")
int BPF_KPROBE(do_mov_2379)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x1cb")
int BPF_KPROBE(do_mov_2380)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x200")
int BPF_KPROBE(do_mov_2381)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x20a")
int BPF_KPROBE(do_mov_2382)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0x13")
int BPF_KPROBE(do_mov_2383)
{
    u64 addr = ctx->si + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0x22")
int BPF_KPROBE(do_mov_2384)
{
    u64 addr = ctx->si + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0x6b")
int BPF_KPROBE(do_mov_2385)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0x76")
int BPF_KPROBE(do_mov_2386)
{
    u64 addr = ctx->si + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0xc6")
int BPF_KPROBE(do_mov_2387)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0xd2")
int BPF_KPROBE(do_mov_2388)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0xd6")
int BPF_KPROBE(do_mov_2389)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_add_to_agg+0x17")
int BPF_KPROBE(do_mov_2390)
{
    u64 addr = ctx->dx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_add_to_agg+0x42")
int BPF_KPROBE(do_mov_2391)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_add_to_agg+0x47")
int BPF_KPROBE(do_mov_2392)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_add_to_agg+0x4b")
int BPF_KPROBE(do_mov_2393)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_add_to_agg+0x4f")
int BPF_KPROBE(do_mov_2394)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dump_class+0x2a")
int BPF_KPROBE(do_mov_2395)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dump_class+0x33")
int BPF_KPROBE(do_mov_2396)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dump_class+0x42")
int BPF_KPROBE(do_mov_2397)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dump_class+0xc4")
int BPF_KPROBE(do_mov_2398)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_qdisc+0x94")
int BPF_KPROBE(do_mov_2399)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_reset_qdisc+0x8d")
int BPF_KPROBE(do_mov_2400)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_reset_qdisc+0x91")
int BPF_KPROBE(do_mov_2401)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_reset_qdisc+0x98")
int BPF_KPROBE(do_mov_2402)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_reset_qdisc+0x9c")
int BPF_KPROBE(do_mov_2403)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_qlen_notify+0x11")
int BPF_KPROBE(do_mov_2404)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_qlen_notify+0x15")
int BPF_KPROBE(do_mov_2405)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_qlen_notify+0x22")
int BPF_KPROBE(do_mov_2406)
{
    u64 addr = ctx->si + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_qlen_notify+0x2a")
int BPF_KPROBE(do_mov_2407)
{
    u64 addr = ctx->si + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0xea")
int BPF_KPROBE(do_mov_2408)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0xf7")
int BPF_KPROBE(do_mov_2409)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0xfe")
int BPF_KPROBE(do_mov_2410)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x106")
int BPF_KPROBE(do_mov_2411)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x10a")
int BPF_KPROBE(do_mov_2412)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x15f")
int BPF_KPROBE(do_mov_2413)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x166")
int BPF_KPROBE(do_mov_2414)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x178")
int BPF_KPROBE(do_mov_2415)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x186")
int BPF_KPROBE(do_mov_2416)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x194")
int BPF_KPROBE(do_mov_2417)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x1a6")
int BPF_KPROBE(do_mov_2418)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x1e2")
int BPF_KPROBE(do_mov_2419)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x203")
int BPF_KPROBE(do_mov_2420)
{
    u64 addr = ctx->r13 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x219")
int BPF_KPROBE(do_mov_2421)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x21d")
int BPF_KPROBE(do_mov_2422)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x22a")
int BPF_KPROBE(do_mov_2423)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x232")
int BPF_KPROBE(do_mov_2424)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x24b")
int BPF_KPROBE(do_mov_2425)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x265")
int BPF_KPROBE(do_mov_2426)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x2a7")
int BPF_KPROBE(do_mov_2427)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x2ab")
int BPF_KPROBE(do_mov_2428)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x2b8")
int BPF_KPROBE(do_mov_2429)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x2bd")
int BPF_KPROBE(do_mov_2430)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x2c1")
int BPF_KPROBE(do_mov_2431)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x2c5")
int BPF_KPROBE(do_mov_2432)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_graft_class+0x54")
int BPF_KPROBE(do_mov_2433)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_graft_class+0xd0")
int BPF_KPROBE(do_mov_2434)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_delete_class+0xe7")
int BPF_KPROBE(do_mov_2435)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x1ad")
int BPF_KPROBE(do_mov_2436)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x20f")
int BPF_KPROBE(do_mov_2437)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x281")
int BPF_KPROBE(do_mov_2438)
{
    u64 addr = ctx->r13 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x293")
int BPF_KPROBE(do_mov_2439)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x2b0")
int BPF_KPROBE(do_mov_2440)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3a6")
int BPF_KPROBE(do_mov_2441)
{
    u64 addr = ctx->r14 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3aa")
int BPF_KPROBE(do_mov_2442)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3b6")
int BPF_KPROBE(do_mov_2443)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3bf")
int BPF_KPROBE(do_mov_2444)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3cb")
int BPF_KPROBE(do_mov_2445)
{
    u64 addr = ctx->r12 + 0x1ed8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3d3")
int BPF_KPROBE(do_mov_2446)
{
    u64 addr = ctx->r14 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3d7")
int BPF_KPROBE(do_mov_2447)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3db")
int BPF_KPROBE(do_mov_2448)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x43c")
int BPF_KPROBE(do_mov_2449)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x440")
int BPF_KPROBE(do_mov_2450)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x44d")
int BPF_KPROBE(do_mov_2451)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x455")
int BPF_KPROBE(do_mov_2452)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x477")
int BPF_KPROBE(do_mov_2453)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x19d")
int BPF_KPROBE(do_mov_2454)
{
    u64 addr = ctx->r9 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x1a6")
int BPF_KPROBE(do_mov_2455)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x1ab")
int BPF_KPROBE(do_mov_2456)
{
    u64 addr = ctx->r9 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x1af")
int BPF_KPROBE(do_mov_2457)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x1b3")
int BPF_KPROBE(do_mov_2458)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x282")
int BPF_KPROBE(do_mov_2459)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x286")
int BPF_KPROBE(do_mov_2460)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x28e")
int BPF_KPROBE(do_mov_2461)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x293")
int BPF_KPROBE(do_mov_2462)
{
    u64 addr = ctx->r9 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x297")
int BPF_KPROBE(do_mov_2463)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x29b")
int BPF_KPROBE(do_mov_2464)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x2b2")
int BPF_KPROBE(do_mov_2465)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x2b5")
int BPF_KPROBE(do_mov_2466)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x39a")
int BPF_KPROBE(do_mov_2467)
{
    u64 addr = ctx->r9 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x476")
int BPF_KPROBE(do_mov_2468)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x47a")
int BPF_KPROBE(do_mov_2469)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x481")
int BPF_KPROBE(do_mov_2470)
{
    u64 addr = ctx->r9 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x489")
int BPF_KPROBE(do_mov_2471)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4d0")
int BPF_KPROBE(do_mov_2472)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4d4")
int BPF_KPROBE(do_mov_2473)
{
    u64 addr = ctx->ax + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4df")
int BPF_KPROBE(do_mov_2474)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4e8")
int BPF_KPROBE(do_mov_2475)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4f3")
int BPF_KPROBE(do_mov_2476)
{
    u64 addr = ctx->r15 + 0x1ed8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4fa")
int BPF_KPROBE(do_mov_2477)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4fd")
int BPF_KPROBE(do_mov_2478)
{
    u64 addr = ctx->ax + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x501")
int BPF_KPROBE(do_mov_2479)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x51d")
int BPF_KPROBE(do_mov_2480)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x520")
int BPF_KPROBE(do_mov_2481)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x26")
int BPF_KPROBE(do_mov_2482)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x37")
int BPF_KPROBE(do_mov_2483)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x3f")
int BPF_KPROBE(do_mov_2484)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x42")
int BPF_KPROBE(do_mov_2485)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x62")
int BPF_KPROBE(do_mov_2486)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x69")
int BPF_KPROBE(do_mov_2487)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x7f")
int BPF_KPROBE(do_mov_2488)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x88")
int BPF_KPROBE(do_mov_2489)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0x6")
int BPF_KPROBE(do_mov_2490)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0xd")
int BPF_KPROBE(do_mov_2491)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0x18")
int BPF_KPROBE(do_mov_2492)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_reset+0x45")
int BPF_KPROBE(do_mov_2493)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_reset+0x50")
int BPF_KPROBE(do_mov_2494)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_reset+0x5b")
int BPF_KPROBE(do_mov_2495)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_dump+0x136")
int BPF_KPROBE(do_mov_2496)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0x94")
int BPF_KPROBE(do_mov_2497)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0xb1")
int BPF_KPROBE(do_mov_2498)
{
    u64 addr = ctx->bx + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0xce")
int BPF_KPROBE(do_mov_2499)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0xe4")
int BPF_KPROBE(do_mov_2500)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0x114")
int BPF_KPROBE(do_mov_2501)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0x153")
int BPF_KPROBE(do_mov_2502)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0x159")
int BPF_KPROBE(do_mov_2503)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0x165")
int BPF_KPROBE(do_mov_2504)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x2a")
int BPF_KPROBE(do_mov_2505)
{
    u64 addr = ctx->di - 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x2e")
int BPF_KPROBE(do_mov_2506)
{
    u64 addr = ctx->di - 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x38")
int BPF_KPROBE(do_mov_2507)
{
    u64 addr = ctx->di - 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x3f")
int BPF_KPROBE(do_mov_2508)
{
    u64 addr = ctx->di - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x43")
int BPF_KPROBE(do_mov_2509)
{
    u64 addr = ctx->di - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x50")
int BPF_KPROBE(do_mov_2510)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x6a")
int BPF_KPROBE(do_mov_2511)
{
    u64 addr = ctx->bx + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x94")
int BPF_KPROBE(do_mov_2512)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x43")
int BPF_KPROBE(do_mov_2513)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x53")
int BPF_KPROBE(do_mov_2514)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x8d")
int BPF_KPROBE(do_mov_2515)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x11d")
int BPF_KPROBE(do_mov_2516)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x144")
int BPF_KPROBE(do_mov_2517)
{
    u64 addr = ctx->bx + 0x19e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x192")
int BPF_KPROBE(do_mov_2518)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x1a2")
int BPF_KPROBE(do_mov_2519)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x1c1")
int BPF_KPROBE(do_mov_2520)
{
    u64 addr = ctx->bx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x1d3")
int BPF_KPROBE(do_mov_2521)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x217")
int BPF_KPROBE(do_mov_2522)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x21e")
int BPF_KPROBE(do_mov_2523)
{
    u64 addr = ctx->bx + 0x19c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x253")
int BPF_KPROBE(do_mov_2524)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x26f")
int BPF_KPROBE(do_mov_2525)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x27d")
int BPF_KPROBE(do_mov_2526)
{
    u64 addr = ctx->bx + 0x19c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x3a8")
int BPF_KPROBE(do_mov_2527)
{
    u64 addr = ctx->di + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x3bf")
int BPF_KPROBE(do_mov_2528)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x421")
int BPF_KPROBE(do_mov_2529)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x431")
int BPF_KPROBE(do_mov_2530)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x450")
int BPF_KPROBE(do_mov_2531)
{
    u64 addr = ctx->bx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x462")
int BPF_KPROBE(do_mov_2532)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x4b1")
int BPF_KPROBE(do_mov_2533)
{
    u64 addr = ctx->bx + 0x19c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x4e4")
int BPF_KPROBE(do_mov_2534)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x4f2")
int BPF_KPROBE(do_mov_2535)
{
    u64 addr = ctx->bx + 0x19e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x4f9")
int BPF_KPROBE(do_mov_2536)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x506")
int BPF_KPROBE(do_mov_2537)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x511")
int BPF_KPROBE(do_mov_2538)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x560")
int BPF_KPROBE(do_mov_2539)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x5a4")
int BPF_KPROBE(do_mov_2540)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x5b7")
int BPF_KPROBE(do_mov_2541)
{
    u64 addr = ctx->di + 0x19c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x5c3")
int BPF_KPROBE(do_mov_2542)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x5ce")
int BPF_KPROBE(do_mov_2543)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x661")
int BPF_KPROBE(do_mov_2544)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x6b3")
int BPF_KPROBE(do_mov_2545)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x706")
int BPF_KPROBE(do_mov_2546)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x711")
int BPF_KPROBE(do_mov_2547)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x721")
int BPF_KPROBE(do_mov_2548)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x736")
int BPF_KPROBE(do_mov_2549)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dequeue_func+0x19")
int BPF_KPROBE(do_mov_2550)
{
    u64 addr = ctx->di - 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dequeue_func+0x20")
int BPF_KPROBE(do_mov_2551)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0x6")
int BPF_KPROBE(do_mov_2552)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0xd")
int BPF_KPROBE(do_mov_2553)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0x18")
int BPF_KPROBE(do_mov_2554)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x18")
int BPF_KPROBE(do_mov_2555)
{
    u64 addr = ctx->di + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x1f")
int BPF_KPROBE(do_mov_2556)
{
    u64 addr = ctx->di + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x2d")
int BPF_KPROBE(do_mov_2557)
{
    u64 addr = ctx->di + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x34")
int BPF_KPROBE(do_mov_2558)
{
    u64 addr = ctx->di + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x6a")
int BPF_KPROBE(do_mov_2559)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x75")
int BPF_KPROBE(do_mov_2560)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x79")
int BPF_KPROBE(do_mov_2561)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0xa3")
int BPF_KPROBE(do_mov_2562)
{
    u64 addr = ctx->r13 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_walk+0x30")
int BPF_KPROBE(do_mov_2563)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_walk+0x78")
int BPF_KPROBE(do_mov_2564)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dump+0x1e5")
int BPF_KPROBE(do_mov_2565)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x90")
int BPF_KPROBE(do_mov_2566)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x94")
int BPF_KPROBE(do_mov_2567)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0xf3")
int BPF_KPROBE(do_mov_2568)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x114")
int BPF_KPROBE(do_mov_2569)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x117")
int BPF_KPROBE(do_mov_2570)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x11f")
int BPF_KPROBE(do_mov_2571)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x157")
int BPF_KPROBE(do_mov_2572)
{
    u64 addr = ctx->r13 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x176")
int BPF_KPROBE(do_mov_2573)
{
    u64 addr = ctx->r12 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x182")
int BPF_KPROBE(do_mov_2574)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x229")
int BPF_KPROBE(do_mov_2575)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x230")
int BPF_KPROBE(do_mov_2576)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x240")
int BPF_KPROBE(do_mov_2577)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x249")
int BPF_KPROBE(do_mov_2578)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x285")
int BPF_KPROBE(do_mov_2579)
{
    u64 addr = ctx->r12 + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x2a9")
int BPF_KPROBE(do_mov_2580)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x33a")
int BPF_KPROBE(do_mov_2581)
{
    u64 addr = ctx->r12 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x342")
int BPF_KPROBE(do_mov_2582)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x346")
int BPF_KPROBE(do_mov_2583)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x34a")
int BPF_KPROBE(do_mov_2584)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x35e")
int BPF_KPROBE(do_mov_2585)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x366")
int BPF_KPROBE(do_mov_2586)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x9f")
int BPF_KPROBE(do_mov_2587)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0xf4")
int BPF_KPROBE(do_mov_2588)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0xfc")
int BPF_KPROBE(do_mov_2589)
{
    u64 addr = ctx->r14 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x20d")
int BPF_KPROBE(do_mov_2590)
{
    u64 addr = ctx->r13 + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x224")
int BPF_KPROBE(do_mov_2591)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x230")
int BPF_KPROBE(do_mov_2592)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x234")
int BPF_KPROBE(do_mov_2593)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x23e")
int BPF_KPROBE(do_mov_2594)
{
    u64 addr = ctx->bx + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x245")
int BPF_KPROBE(do_mov_2595)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x249")
int BPF_KPROBE(do_mov_2596)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x24d")
int BPF_KPROBE(do_mov_2597)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x29d")
int BPF_KPROBE(do_mov_2598)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x2f0")
int BPF_KPROBE(do_mov_2599)
{
    u64 addr = ctx->r13 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x303")
int BPF_KPROBE(do_mov_2600)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x307")
int BPF_KPROBE(do_mov_2601)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x30a")
int BPF_KPROBE(do_mov_2602)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x30e")
int BPF_KPROBE(do_mov_2603)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x327")
int BPF_KPROBE(do_mov_2604)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x32b")
int BPF_KPROBE(do_mov_2605)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x335")
int BPF_KPROBE(do_mov_2606)
{
    u64 addr = ctx->bx + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x33c")
int BPF_KPROBE(do_mov_2607)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x340")
int BPF_KPROBE(do_mov_2608)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x344")
int BPF_KPROBE(do_mov_2609)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x386")
int BPF_KPROBE(do_mov_2610)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x3ab")
int BPF_KPROBE(do_mov_2611)
{
    u64 addr = ctx->r13 + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x3fe")
int BPF_KPROBE(do_mov_2612)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x447")
int BPF_KPROBE(do_mov_2613)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x44b")
int BPF_KPROBE(do_mov_2614)
{
    u64 addr = ctx->r13 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x4b9")
int BPF_KPROBE(do_mov_2615)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x4ff")
int BPF_KPROBE(do_mov_2616)
{
    u64 addr = ctx->r13 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x530")
int BPF_KPROBE(do_mov_2617)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x538")
int BPF_KPROBE(do_mov_2618)
{
    u64 addr = ctx->r13 + 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x541")
int BPF_KPROBE(do_mov_2619)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x556")
int BPF_KPROBE(do_mov_2620)
{
    u64 addr = ctx->r13 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x55f")
int BPF_KPROBE(do_mov_2621)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x5de")
int BPF_KPROBE(do_mov_2622)
{
    u64 addr = ctx->r13 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x5f6")
int BPF_KPROBE(do_mov_2623)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x603")
int BPF_KPROBE(do_mov_2624)
{
    u64 addr = ctx->bx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x6eb")
int BPF_KPROBE(do_mov_2625)
{
    u64 addr = ctx->bx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x717")
int BPF_KPROBE(do_mov_2626)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x76c")
int BPF_KPROBE(do_mov_2627)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x792")
int BPF_KPROBE(do_mov_2628)
{
    u64 addr = ctx->bx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x6e")
int BPF_KPROBE(do_mov_2629)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0xec")
int BPF_KPROBE(do_mov_2630)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x109")
int BPF_KPROBE(do_mov_2631)
{
    u64 addr = ctx->bx + 0x1b4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x11c")
int BPF_KPROBE(do_mov_2632)
{
    u64 addr = ctx->bx + 0x1c1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x12f")
int BPF_KPROBE(do_mov_2633)
{
    u64 addr = ctx->bx + 0x1c2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x14c")
int BPF_KPROBE(do_mov_2634)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x162")
int BPF_KPROBE(do_mov_2635)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x17f")
int BPF_KPROBE(do_mov_2636)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x19c")
int BPF_KPROBE(do_mov_2637)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x1b8")
int BPF_KPROBE(do_mov_2638)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x210")
int BPF_KPROBE(do_mov_2639)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x28c")
int BPF_KPROBE(do_mov_2640)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x22")
int BPF_KPROBE(do_mov_2641)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x29")
int BPF_KPROBE(do_mov_2642)
{
    u64 addr = ctx->di + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x33")
int BPF_KPROBE(do_mov_2643)
{
    u64 addr = ctx->di + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x4f")
int BPF_KPROBE(do_mov_2644)
{
    u64 addr = ctx->di + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x59")
int BPF_KPROBE(do_mov_2645)
{
    u64 addr = ctx->di + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x66")
int BPF_KPROBE(do_mov_2646)
{
    u64 addr = ctx->di + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x6d")
int BPF_KPROBE(do_mov_2647)
{
    u64 addr = ctx->di + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x7b")
int BPF_KPROBE(do_mov_2648)
{
    u64 addr = ctx->di + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x82")
int BPF_KPROBE(do_mov_2649)
{
    u64 addr = ctx->di + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x93")
int BPF_KPROBE(do_mov_2650)
{
    u64 addr = ctx->di + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x9a")
int BPF_KPROBE(do_mov_2651)
{
    u64 addr = ctx->di + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0xa4")
int BPF_KPROBE(do_mov_2652)
{
    u64 addr = ctx->di + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0xab")
int BPF_KPROBE(do_mov_2653)
{
    u64 addr = ctx->di + 0x1c2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0xc2")
int BPF_KPROBE(do_mov_2654)
{
    u64 addr = ctx->di + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x113")
int BPF_KPROBE(do_mov_2655)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x123")
int BPF_KPROBE(do_mov_2656)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x136")
int BPF_KPROBE(do_mov_2657)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x163")
int BPF_KPROBE(do_mov_2658)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x188")
int BPF_KPROBE(do_mov_2659)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x1bf")
int BPF_KPROBE(do_mov_2660)
{
    u64 addr = ctx->di - 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x1c3")
int BPF_KPROBE(do_mov_2661)
{
    u64 addr = ctx->di - 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x1ec")
int BPF_KPROBE(do_mov_2662)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_get_tcpopt+0x6f")
int BPF_KPROBE(do_mov_2663)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_calc_overhead+0x25")
int BPF_KPROBE(do_mov_2664)
{
    u64 addr = ctx->di + 0x410c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_calc_overhead+0x37")
int BPF_KPROBE(do_mov_2665)
{
    u64 addr = ctx->cx + 0x4110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_calc_overhead+0x6f")
int BPF_KPROBE(do_mov_2666)
{
    u64 addr = ctx->cx + 0x410e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_calc_overhead+0x81")
int BPF_KPROBE(do_mov_2667)
{
    u64 addr = ctx->cx + 0x4112;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_heap_swap+0x40")
int BPF_KPROBE(do_mov_2668)
{
    u64 addr = ctx->ax + ctx->di * 0x2 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_heap_swap+0x4c")
int BPF_KPROBE(do_mov_2669)
{
    u64 addr = ctx->ax + ctx->si * 0x2 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_heap_swap+0x6d")
int BPF_KPROBE(do_mov_2670)
{
    u64 addr = ctx->cx + ctx->si * 0x2 + 0x16000;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_heap_swap+0x8d")
int BPF_KPROBE(do_mov_2671)
{
    u64 addr = ctx->ax + ctx->dx * 0x2 + 0x16000;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_advance_shaper+0x5a")
int BPF_KPROBE(do_mov_2672)
{
    u64 addr = ctx->si + 0x19868;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_advance_shaper+0x85")
int BPF_KPROBE(do_mov_2673)
{
    u64 addr = ctx->si + 0x19868;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue_one+0x3e")
int BPF_KPROBE(do_mov_2674)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue_one+0x46")
int BPF_KPROBE(do_mov_2675)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x1e")
int BPF_KPROBE(do_mov_2676)
{
    u64 addr = ctx->di + 0x19800;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x29")
int BPF_KPROBE(do_mov_2677)
{
    u64 addr = ctx->r9 + 0x19810;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x37")
int BPF_KPROBE(do_mov_2678)
{
    u64 addr = ctx->r9 + 0x19870;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x4c")
int BPF_KPROBE(do_mov_2679)
{
    u64 addr = ctx->r9 + 0x19878;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x53")
int BPF_KPROBE(do_mov_2680)
{
    u64 addr = ctx->r9 + 0x19880;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x5b")
int BPF_KPROBE(do_mov_2681)
{
    u64 addr = ctx->r9 + 0x19808;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x62")
int BPF_KPROBE(do_mov_2682)
{
    u64 addr = ctx->r9 + 0x19818;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x69")
int BPF_KPROBE(do_mov_2683)
{
    u64 addr = ctx->r9 + 0x19820;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0xa4")
int BPF_KPROBE(do_mov_2684)
{
    u64 addr = ctx->di + 0x19800;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x8d")
int BPF_KPROBE(do_mov_2685)
{
    u64 addr = ctx->di + 0x4248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x98")
int BPF_KPROBE(do_mov_2686)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0xa6")
int BPF_KPROBE(do_mov_2687)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x108")
int BPF_KPROBE(do_mov_2688)
{
    u64 addr = ctx->r12 + 0x19882;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x15e")
int BPF_KPROBE(do_mov_2689)
{
    u64 addr = ctx->bx + 0x41f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x166")
int BPF_KPROBE(do_mov_2690)
{
    u64 addr = ctx->bx + 0x41f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x193")
int BPF_KPROBE(do_mov_2691)
{
    u64 addr = ctx->bx + 0x41f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x1b2")
int BPF_KPROBE(do_mov_2692)
{
    u64 addr = ctx->ax + ctx->r13 * 0x1 + 0x19818;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x1db")
int BPF_KPROBE(do_mov_2693)
{
    u64 addr = ctx->bx + 0x41b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x1eb")
int BPF_KPROBE(do_mov_2694)
{
    u64 addr = ctx->bx + 0x41a6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x235")
int BPF_KPROBE(do_mov_2695)
{
    u64 addr = ctx->bx + 0x41e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x259")
int BPF_KPROBE(do_mov_2696)
{
    u64 addr = ctx->bx + 0x41e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x288")
int BPF_KPROBE(do_mov_2697)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x28f")
int BPF_KPROBE(do_mov_2698)
{
    u64 addr = ctx->di + 0x4248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x29a")
int BPF_KPROBE(do_mov_2699)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x2fc")
int BPF_KPROBE(do_mov_2700)
{
    u64 addr = ctx->r12 + 0x19882;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x356")
int BPF_KPROBE(do_mov_2701)
{
    u64 addr = ctx->bx + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x360")
int BPF_KPROBE(do_mov_2702)
{
    u64 addr = ctx->bx + 0x4248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x36b")
int BPF_KPROBE(do_mov_2703)
{
    u64 addr = ctx->bx + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x3f7")
int BPF_KPROBE(do_mov_2704)
{
    u64 addr = ctx->ax + 0x19882;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x405")
int BPF_KPROBE(do_mov_2705)
{
    u64 addr = ctx->ax + 0x33152;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x413")
int BPF_KPROBE(do_mov_2706)
{
    u64 addr = ctx->ax + 0x4ca22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x439")
int BPF_KPROBE(do_mov_2707)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x441")
int BPF_KPROBE(do_mov_2708)
{
    u64 addr = ctx->di + 0x4248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x44c")
int BPF_KPROBE(do_mov_2709)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x516")
int BPF_KPROBE(do_mov_2710)
{
    u64 addr = ctx->ax + 0x19882;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x525")
int BPF_KPROBE(do_mov_2711)
{
    u64 addr = ctx->ax + 0x33152;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x534")
int BPF_KPROBE(do_mov_2712)
{
    u64 addr = ctx->ax + 0x4ca22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x543")
int BPF_KPROBE(do_mov_2713)
{
    u64 addr = ctx->ax + 0x662f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x566")
int BPF_KPROBE(do_mov_2714)
{
    u64 addr = ctx->di + 0x4248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x571")
int BPF_KPROBE(do_mov_2715)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x57b")
int BPF_KPROBE(do_mov_2716)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x593")
int BPF_KPROBE(do_mov_2717)
{
    u64 addr = ctx->r12 + 0x19882;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_walk+0x81")
int BPF_KPROBE(do_mov_2718)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_walk+0xc4")
int BPF_KPROBE(do_mov_2719)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reset+0x1e")
int BPF_KPROBE(do_mov_2720)
{
    u64 addr = ctx->bx + 0x41f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reset+0x26")
int BPF_KPROBE(do_mov_2721)
{
    u64 addr = ctx->bx + 0x41f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reset+0x53")
int BPF_KPROBE(do_mov_2722)
{
    u64 addr = ctx->bx + 0x41f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump+0x334")
int BPF_KPROBE(do_mov_2723)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump_stats+0x629")
int BPF_KPROBE(do_mov_2724)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump_stats+0x65c")
int BPF_KPROBE(do_mov_2725)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump_stats+0x673")
int BPF_KPROBE(do_mov_2726)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x6c")
int BPF_KPROBE(do_mov_2727)
{
    u64 addr = ctx->bx + 0x419d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x83")
int BPF_KPROBE(do_mov_2728)
{
    u64 addr = ctx->bx + 0x419d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0xad")
int BPF_KPROBE(do_mov_2729)
{
    u64 addr = ctx->bx + 0x41c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0xc3")
int BPF_KPROBE(do_mov_2730)
{
    u64 addr = ctx->bx + 0x419c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0xe7")
int BPF_KPROBE(do_mov_2731)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x10c")
int BPF_KPROBE(do_mov_2732)
{
    u64 addr = ctx->bx + 0x419d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x121")
int BPF_KPROBE(do_mov_2733)
{
    u64 addr = ctx->bx + 0x419f;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x13b")
int BPF_KPROBE(do_mov_2734)
{
    u64 addr = ctx->bx + 0x41ca;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x14c")
int BPF_KPROBE(do_mov_2735)
{
    u64 addr = ctx->bx + 0x428c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x16c")
int BPF_KPROBE(do_mov_2736)
{
    u64 addr = ctx->bx + 0x428c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x17f")
int BPF_KPROBE(do_mov_2737)
{
    u64 addr = ctx->bx + 0x41cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x19e")
int BPF_KPROBE(do_mov_2738)
{
    u64 addr = ctx->bx + 0x41d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x1bd")
int BPF_KPROBE(do_mov_2739)
{
    u64 addr = ctx->bx + 0x41d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x1e2")
int BPF_KPROBE(do_mov_2740)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x207")
int BPF_KPROBE(do_mov_2741)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x21a")
int BPF_KPROBE(do_mov_2742)
{
    u64 addr = ctx->bx + 0x419e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x22c")
int BPF_KPROBE(do_mov_2743)
{
    u64 addr = ctx->bx + 0x41ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x250")
int BPF_KPROBE(do_mov_2744)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x265")
int BPF_KPROBE(do_mov_2745)
{
    u64 addr = ctx->bx + 0x41a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x273")
int BPF_KPROBE(do_mov_2746)
{
    u64 addr = ctx->bx + 0x41a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x302")
int BPF_KPROBE(do_mov_2747)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x311")
int BPF_KPROBE(do_mov_2748)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x320")
int BPF_KPROBE(do_mov_2749)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x32f")
int BPF_KPROBE(do_mov_2750)
{
    u64 addr = ctx->bx + 0x41c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x2f")
int BPF_KPROBE(do_mov_2751)
{
    u64 addr = ctx->di - 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x36")
int BPF_KPROBE(do_mov_2752)
{
    u64 addr = ctx->di - 0x41e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x40")
int BPF_KPROBE(do_mov_2753)
{
    u64 addr = ctx->di - 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x48")
int BPF_KPROBE(do_mov_2754)
{
    u64 addr = ctx->di - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x50")
int BPF_KPROBE(do_mov_2755)
{
    u64 addr = ctx->di - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x58")
int BPF_KPROBE(do_mov_2756)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0xc1")
int BPF_KPROBE(do_mov_2757)
{
    u64 addr = ctx->cx + ctx->cx * 0x1 - 0x7c6f2580;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0xea")
int BPF_KPROBE(do_mov_2758)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x125")
int BPF_KPROBE(do_mov_2759)
{
    u64 addr = ctx->r10 + 0x19830;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x131")
int BPF_KPROBE(do_mov_2760)
{
    u64 addr = ctx->r10 + 0x19838;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x138")
int BPF_KPROBE(do_mov_2761)
{
    u64 addr = ctx->r10 + 0x19840;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x146")
int BPF_KPROBE(do_mov_2762)
{
    u64 addr = ctx->r10 + 0x19848;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x14d")
int BPF_KPROBE(do_mov_2763)
{
    u64 addr = ctx->r10 + 0x19850;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x15b")
int BPF_KPROBE(do_mov_2764)
{
    u64 addr = ctx->r10 + 0x19858;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x162")
int BPF_KPROBE(do_mov_2765)
{
    u64 addr = ctx->r10 + 0x1982c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x16d")
int BPF_KPROBE(do_mov_2766)
{
    u64 addr = ctx->r10 + 0x19860;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x19f")
int BPF_KPROBE(do_mov_2767)
{
    u64 addr = ctx->dx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1a6")
int BPF_KPROBE(do_mov_2768)
{
    u64 addr = ctx->r10 + ctx->r8 * 0x2 + 0x16000;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1c4")
int BPF_KPROBE(do_mov_2769)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1d2")
int BPF_KPROBE(do_mov_2770)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1d5")
int BPF_KPROBE(do_mov_2771)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1dd")
int BPF_KPROBE(do_mov_2772)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1e1")
int BPF_KPROBE(do_mov_2773)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1e9")
int BPF_KPROBE(do_mov_2774)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x28b")
int BPF_KPROBE(do_mov_2775)
{
    u64 addr =  - 0x7c6f25c0 + ctx->cx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x2bd")
int BPF_KPROBE(do_mov_2776)
{
    u64 addr = ctx->bx + 0x4290;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x2c7")
int BPF_KPROBE(do_mov_2777)
{
    u64 addr = ctx->bx + 0x4278;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump_class_stats+0x250")
int BPF_KPROBE(do_mov_2778)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x62a")
int BPF_KPROBE(do_mov_2779)
{
    u64 addr = ctx->bx + ctx->r10 * 0x4 + 0x15000;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x6aa")
int BPF_KPROBE(do_mov_2780)
{
    u64 addr = ctx->bx + ctx->cx * 0x4 + 0x16800;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x6df")
int BPF_KPROBE(do_mov_2781)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x75a")
int BPF_KPROBE(do_mov_2782)
{
    u64 addr = ctx->bx + ctx->cx * 0x4 + 0x16804;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x790")
int BPF_KPROBE(do_mov_2783)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 + 0x4a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x836")
int BPF_KPROBE(do_mov_2784)
{
    u64 addr = ctx->bx + ctx->r10 * 0x4 + 0x15000;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_handle_diffserv+0x16d")
int BPF_KPROBE(do_mov_2785)
{
    u64 addr = ctx->dx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_handle_diffserv+0x18f")
int BPF_KPROBE(do_mov_2786)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_overhead+0x70")
int BPF_KPROBE(do_mov_2787)
{
    u64 addr = ctx->di + 0x4108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_ack_filter.isra.0+0x509")
int BPF_KPROBE(do_mov_2788)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_ack_filter.isra.0+0x513")
int BPF_KPROBE(do_mov_2789)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa1")
int BPF_KPROBE(do_mov_2790)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa4")
int BPF_KPROBE(do_mov_2791)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x1ba")
int BPF_KPROBE(do_mov_2792)
{
    u64 addr = ctx->r13 + 0x19868;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x21b")
int BPF_KPROBE(do_mov_2793)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x224")
int BPF_KPROBE(do_mov_2794)
{
    u64 addr = ctx->r15 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x240")
int BPF_KPROBE(do_mov_2795)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x243")
int BPF_KPROBE(do_mov_2796)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x247")
int BPF_KPROBE(do_mov_2797)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x2e7")
int BPF_KPROBE(do_mov_2798)
{
    u64 addr = ctx->r12 + 0x4258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x310")
int BPF_KPROBE(do_mov_2799)
{
    u64 addr = ctx->r12 + 0x4268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x361")
int BPF_KPROBE(do_mov_2800)
{
    u64 addr = ctx->r13 + 0x19840;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x368")
int BPF_KPROBE(do_mov_2801)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x36c")
int BPF_KPROBE(do_mov_2802)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x378")
int BPF_KPROBE(do_mov_2803)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x37b")
int BPF_KPROBE(do_mov_2804)
{
    u64 addr = ctx->r13 + ctx->ax * 0x1 + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x3fc")
int BPF_KPROBE(do_mov_2805)
{
    u64 addr = ctx->r13 + ctx->cx * 0x1 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x413")
int BPF_KPROBE(do_mov_2806)
{
    u64 addr = ctx->r12 + 0x41e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x484")
int BPF_KPROBE(do_mov_2807)
{
    u64 addr = ctx->r12 + 0x4198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x4c8")
int BPF_KPROBE(do_mov_2808)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x4d6")
int BPF_KPROBE(do_mov_2809)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x502")
int BPF_KPROBE(do_mov_2810)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x509")
int BPF_KPROBE(do_mov_2811)
{
    u64 addr = ctx->ax + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x50d")
int BPF_KPROBE(do_mov_2812)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x511")
int BPF_KPROBE(do_mov_2813)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x51b")
int BPF_KPROBE(do_mov_2814)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x5b0")
int BPF_KPROBE(do_mov_2815)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x5b3")
int BPF_KPROBE(do_mov_2816)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x646")
int BPF_KPROBE(do_mov_2817)
{
    u64 addr = ctx->ax + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x64a")
int BPF_KPROBE(do_mov_2818)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x656")
int BPF_KPROBE(do_mov_2819)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x6a2")
int BPF_KPROBE(do_mov_2820)
{
    u64 addr = ctx->ax + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x70c")
int BPF_KPROBE(do_mov_2821)
{
    u64 addr = ctx->r12 + 0x4270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x718")
int BPF_KPROBE(do_mov_2822)
{
    u64 addr = ctx->r12 + 0x4258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x727")
int BPF_KPROBE(do_mov_2823)
{
    u64 addr = ctx->r12 + 0x4198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x878")
int BPF_KPROBE(do_mov_2824)
{
    u64 addr = ctx->r12 + 0x4270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x884")
int BPF_KPROBE(do_mov_2825)
{
    u64 addr = ctx->r12 + 0x4260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x8bd")
int BPF_KPROBE(do_mov_2826)
{
    u64 addr = ctx->r12 + 0x4278;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x8e2")
int BPF_KPROBE(do_mov_2827)
{
    u64 addr = ctx->r12 + 0x41c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x905")
int BPF_KPROBE(do_mov_2828)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x909")
int BPF_KPROBE(do_mov_2829)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x973")
int BPF_KPROBE(do_mov_2830)
{
    u64 addr = ctx->r12 + 0x41e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x9b3")
int BPF_KPROBE(do_mov_2831)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa32")
int BPF_KPROBE(do_mov_2832)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa44")
int BPF_KPROBE(do_mov_2833)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa51")
int BPF_KPROBE(do_mov_2834)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa64")
int BPF_KPROBE(do_mov_2835)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa71")
int BPF_KPROBE(do_mov_2836)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa74")
int BPF_KPROBE(do_mov_2837)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa78")
int BPF_KPROBE(do_mov_2838)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xab8")
int BPF_KPROBE(do_mov_2839)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xb46")
int BPF_KPROBE(do_mov_2840)
{
    u64 addr = ctx->r13 + 0x19834;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xb57")
int BPF_KPROBE(do_mov_2841)
{
    u64 addr = ctx->r12 + 0x41b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xb5f")
int BPF_KPROBE(do_mov_2842)
{
    u64 addr = ctx->r12 + 0x41a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xbce")
int BPF_KPROBE(do_mov_2843)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xbd6")
int BPF_KPROBE(do_mov_2844)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x100")
int BPF_KPROBE(do_mov_2845)
{
    u64 addr = ctx->r15 + 0x41f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x16f")
int BPF_KPROBE(do_mov_2846)
{
    u64 addr = ctx->r15 + 0x41f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x22b")
int BPF_KPROBE(do_mov_2847)
{
    u64 addr = ctx->bx + 0x35;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x234")
int BPF_KPROBE(do_mov_2848)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x24e")
int BPF_KPROBE(do_mov_2849)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x2ce")
int BPF_KPROBE(do_mov_2850)
{
    u64 addr = ctx->bx + 0x35;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x2dd")
int BPF_KPROBE(do_mov_2851)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x2ef")
int BPF_KPROBE(do_mov_2852)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x30b")
int BPF_KPROBE(do_mov_2853)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x314")
int BPF_KPROBE(do_mov_2854)
{
    u64 addr = ctx->bx + 0x35;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x31d")
int BPF_KPROBE(do_mov_2855)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x351")
int BPF_KPROBE(do_mov_2856)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x3bd")
int BPF_KPROBE(do_mov_2857)
{
    u64 addr = ctx->r12 + 0x198a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x3f4")
int BPF_KPROBE(do_mov_2858)
{
    u64 addr = ctx->r12 + 0x198b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x426")
int BPF_KPROBE(do_mov_2859)
{
    u64 addr = ctx->r12 + 0x198b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x471")
int BPF_KPROBE(do_mov_2860)
{
    u64 addr = ctx->r15 + 0x4198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x489")
int BPF_KPROBE(do_mov_2861)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x510")
int BPF_KPROBE(do_mov_2862)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x524")
int BPF_KPROBE(do_mov_2863)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x53a")
int BPF_KPROBE(do_mov_2864)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x5ab")
int BPF_KPROBE(do_mov_2865)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x5c3")
int BPF_KPROBE(do_mov_2866)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x60f")
int BPF_KPROBE(do_mov_2867)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x66b")
int BPF_KPROBE(do_mov_2868)
{
    u64 addr = ctx->r15 + 0x41f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x687")
int BPF_KPROBE(do_mov_2869)
{
    u64 addr = ctx->r15 + 0x41f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x6ce")
int BPF_KPROBE(do_mov_2870)
{
    u64 addr = ctx->r12 + 0x19884;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x75f")
int BPF_KPROBE(do_mov_2871)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x763")
int BPF_KPROBE(do_mov_2872)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x776")
int BPF_KPROBE(do_mov_2873)
{
    u64 addr = ctx->r12 + 0x19850;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x77e")
int BPF_KPROBE(do_mov_2874)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x781")
int BPF_KPROBE(do_mov_2875)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x785")
int BPF_KPROBE(do_mov_2876)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x816")
int BPF_KPROBE(do_mov_2877)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x820")
int BPF_KPROBE(do_mov_2878)
{
    u64 addr = ctx->dx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x9da")
int BPF_KPROBE(do_mov_2879)
{
    u64 addr = ctx->bx + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa1b")
int BPF_KPROBE(do_mov_2880)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa1f")
int BPF_KPROBE(do_mov_2881)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa25")
int BPF_KPROBE(do_mov_2882)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa5a")
int BPF_KPROBE(do_mov_2883)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa62")
int BPF_KPROBE(do_mov_2884)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa6d")
int BPF_KPROBE(do_mov_2885)
{
    u64 addr = ctx->r12 + 0x19860;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa75")
int BPF_KPROBE(do_mov_2886)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa79")
int BPF_KPROBE(do_mov_2887)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa7c")
int BPF_KPROBE(do_mov_2888)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa96")
int BPF_KPROBE(do_mov_2889)
{
    u64 addr = ctx->bx + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb0e")
int BPF_KPROBE(do_mov_2890)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb36")
int BPF_KPROBE(do_mov_2891)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb3a")
int BPF_KPROBE(do_mov_2892)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb41")
int BPF_KPROBE(do_mov_2893)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb47")
int BPF_KPROBE(do_mov_2894)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb66")
int BPF_KPROBE(do_mov_2895)
{
    u64 addr = ctx->bx + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb95")
int BPF_KPROBE(do_mov_2896)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xbb9")
int BPF_KPROBE(do_mov_2897)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xbe8")
int BPF_KPROBE(do_mov_2898)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xbfb")
int BPF_KPROBE(do_mov_2899)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xc13")
int BPF_KPROBE(do_mov_2900)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xc8d")
int BPF_KPROBE(do_mov_2901)
{
    u64 addr = ctx->bx + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xd11")
int BPF_KPROBE(do_mov_2902)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xd18")
int BPF_KPROBE(do_mov_2903)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xd1c")
int BPF_KPROBE(do_mov_2904)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xd54")
int BPF_KPROBE(do_mov_2905)
{
    u64 addr = ctx->r15 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xe0e")
int BPF_KPROBE(do_mov_2906)
{
    u64 addr = ctx->r12 + 0x19884;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_flow_purge+0x54")
int BPF_KPROBE(do_mov_2907)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_flow_purge+0x5d")
int BPF_KPROBE(do_mov_2908)
{
    u64 addr = ctx->r13 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x63")
int BPF_KPROBE(do_mov_2909)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0xda")
int BPF_KPROBE(do_mov_2910)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0xe6")
int BPF_KPROBE(do_mov_2911)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x19c")
int BPF_KPROBE(do_mov_2912)
{
    u64 addr = ctx->r15 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x1c7")
int BPF_KPROBE(do_mov_2913)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x1cb")
int BPF_KPROBE(do_mov_2914)
{
    u64 addr = ctx->r8 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x1d9")
int BPF_KPROBE(do_mov_2915)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x201")
int BPF_KPROBE(do_mov_2916)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x250")
int BPF_KPROBE(do_mov_2917)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x25a")
int BPF_KPROBE(do_mov_2918)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x262")
int BPF_KPROBE(do_mov_2919)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x26a")
int BPF_KPROBE(do_mov_2920)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x320")
int BPF_KPROBE(do_mov_2921)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x328")
int BPF_KPROBE(do_mov_2922)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x341")
int BPF_KPROBE(do_mov_2923)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x348")
int BPF_KPROBE(do_mov_2924)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x350")
int BPF_KPROBE(do_mov_2925)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x354")
int BPF_KPROBE(do_mov_2926)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x35c")
int BPF_KPROBE(do_mov_2927)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x38e")
int BPF_KPROBE(do_mov_2928)
{
    u64 addr = ctx->r8 + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x39a")
int BPF_KPROBE(do_mov_2929)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x39d")
int BPF_KPROBE(do_mov_2930)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x3a1")
int BPF_KPROBE(do_mov_2931)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x44e")
int BPF_KPROBE(do_mov_2932)
{
    u64 addr = ctx->r8 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x475")
int BPF_KPROBE(do_mov_2933)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x48b")
int BPF_KPROBE(do_mov_2934)
{
    u64 addr = ctx->r15 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x495")
int BPF_KPROBE(do_mov_2935)
{
    u64 addr = ctx->r12 + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x524")
int BPF_KPROBE(do_mov_2936)
{
    u64 addr = ctx->r8 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x540")
int BPF_KPROBE(do_mov_2937)
{
    u64 addr = ctx->r8 + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x566")
int BPF_KPROBE(do_mov_2938)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x56f")
int BPF_KPROBE(do_mov_2939)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x5b3")
int BPF_KPROBE(do_mov_2940)
{
    u64 addr = ctx->r8 + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x5f5")
int BPF_KPROBE(do_mov_2941)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x5fd")
int BPF_KPROBE(do_mov_2942)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x60a")
int BPF_KPROBE(do_mov_2943)
{
    u64 addr = ctx->r12 + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x620")
int BPF_KPROBE(do_mov_2944)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x67e")
int BPF_KPROBE(do_mov_2945)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x6ca")
int BPF_KPROBE(do_mov_2946)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x6ce")
int BPF_KPROBE(do_mov_2947)
{
    u64 addr = ctx->r8 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x6d5")
int BPF_KPROBE(do_mov_2948)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x6e2")
int BPF_KPROBE(do_mov_2949)
{
    u64 addr = ctx->r8 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0x1c")
int BPF_KPROBE(do_mov_2950)
{
    u64 addr = ctx->di - 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0x26")
int BPF_KPROBE(do_mov_2951)
{
    u64 addr = ctx->di - 0xfc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0xa6")
int BPF_KPROBE(do_mov_2952)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0xb1")
int BPF_KPROBE(do_mov_2953)
{
    u64 addr = ctx->r13 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0xbc")
int BPF_KPROBE(do_mov_2954)
{
    u64 addr = ctx->r13 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0xc7")
int BPF_KPROBE(do_mov_2955)
{
    u64 addr = ctx->r13 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0xd2")
int BPF_KPROBE(do_mov_2956)
{
    u64 addr = ctx->r13 + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dump+0x2da")
int BPF_KPROBE(do_mov_2957)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x71")
int BPF_KPROBE(do_mov_2958)
{
    u64 addr = ctx->r14 + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x78")
int BPF_KPROBE(do_mov_2959)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0xe7")
int BPF_KPROBE(do_mov_2960)
{
    u64 addr = ctx->r14 + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x101")
int BPF_KPROBE(do_mov_2961)
{
    u64 addr = ctx->r14 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x127")
int BPF_KPROBE(do_mov_2962)
{
    u64 addr = ctx->r14 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x137")
int BPF_KPROBE(do_mov_2963)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x13b")
int BPF_KPROBE(do_mov_2964)
{
    u64 addr = ctx->r14 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x142")
int BPF_KPROBE(do_mov_2965)
{
    u64 addr = ctx->bx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x185")
int BPF_KPROBE(do_mov_2966)
{
    u64 addr = ctx->r14 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x18e")
int BPF_KPROBE(do_mov_2967)
{
    u64 addr = ctx->r14 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x20a")
int BPF_KPROBE(do_mov_2968)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x20e")
int BPF_KPROBE(do_mov_2969)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x240")
int BPF_KPROBE(do_mov_2970)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x247")
int BPF_KPROBE(do_mov_2971)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x24f")
int BPF_KPROBE(do_mov_2972)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x257")
int BPF_KPROBE(do_mov_2973)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x273")
int BPF_KPROBE(do_mov_2974)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x28f")
int BPF_KPROBE(do_mov_2975)
{
    u64 addr = ctx->r14 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x2f9")
int BPF_KPROBE(do_mov_2976)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x300")
int BPF_KPROBE(do_mov_2977)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x315")
int BPF_KPROBE(do_mov_2978)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x319")
int BPF_KPROBE(do_mov_2979)
{
    u64 addr = ctx->r14 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x320")
int BPF_KPROBE(do_mov_2980)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x32d")
int BPF_KPROBE(do_mov_2981)
{
    u64 addr = ctx->r14 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x347")
int BPF_KPROBE(do_mov_2982)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x35b")
int BPF_KPROBE(do_mov_2983)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x3bd")
int BPF_KPROBE(do_mov_2984)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x3c1")
int BPF_KPROBE(do_mov_2985)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x3e8")
int BPF_KPROBE(do_mov_2986)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x452")
int BPF_KPROBE(do_mov_2987)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x482")
int BPF_KPROBE(do_mov_2988)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x4a6")
int BPF_KPROBE(do_mov_2989)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x5e0")
int BPF_KPROBE(do_mov_2990)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x5e4")
int BPF_KPROBE(do_mov_2991)
{
    u64 addr = ctx->dx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x607")
int BPF_KPROBE(do_mov_2992)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x638")
int BPF_KPROBE(do_mov_2993)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x660")
int BPF_KPROBE(do_mov_2994)
{
    u64 addr = ctx->r15 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x19b")
int BPF_KPROBE(do_mov_2995)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x1a2")
int BPF_KPROBE(do_mov_2996)
{
    u64 addr = ctx->bx + 0x279;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x203")
int BPF_KPROBE(do_mov_2997)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x20d")
int BPF_KPROBE(do_mov_2998)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x216")
int BPF_KPROBE(do_mov_2999)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x21f")
int BPF_KPROBE(do_mov_3000)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_change+0xc2")
int BPF_KPROBE(do_mov_3001)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_change+0xd5")
int BPF_KPROBE(do_mov_3002)
{
    u64 addr = ctx->r14 + 0x24c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_change+0xfa")
int BPF_KPROBE(do_mov_3003)
{
    u64 addr = ctx->r14 + 0x240;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_change+0x110")
int BPF_KPROBE(do_mov_3004)
{
    u64 addr = ctx->r14 + 0x244;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_change+0x335")
int BPF_KPROBE(do_mov_3005)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x23")
int BPF_KPROBE(do_mov_3006)
{
    u64 addr = ctx->di - 0x2c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x30")
int BPF_KPROBE(do_mov_3007)
{
    u64 addr = ctx->di - 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x4c")
int BPF_KPROBE(do_mov_3008)
{
    u64 addr = ctx->di - 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x62")
int BPF_KPROBE(do_mov_3009)
{
    u64 addr = ctx->di - 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x74")
int BPF_KPROBE(do_mov_3010)
{
    u64 addr = ctx->di - 0x5e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x7a")
int BPF_KPROBE(do_mov_3011)
{
    u64 addr = ctx->di - 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x85")
int BPF_KPROBE(do_mov_3012)
{
    u64 addr = ctx->di - 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x95")
int BPF_KPROBE(do_mov_3013)
{
    u64 addr = ctx->di - 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xa3")
int BPF_KPROBE(do_mov_3014)
{
    u64 addr = ctx->di - 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xb1")
int BPF_KPROBE(do_mov_3015)
{
    u64 addr = ctx->di - 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xba")
int BPF_KPROBE(do_mov_3016)
{
    u64 addr = ctx->di - 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xc5")
int BPF_KPROBE(do_mov_3017)
{
    u64 addr = ctx->di - 0x148;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xd0")
int BPF_KPROBE(do_mov_3018)
{
    u64 addr = ctx->di - 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xdb")
int BPF_KPROBE(do_mov_3019)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xe2")
int BPF_KPROBE(do_mov_3020)
{
    u64 addr = ctx->di - 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xed")
int BPF_KPROBE(do_mov_3021)
{
    u64 addr = ctx->di - 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xf5")
int BPF_KPROBE(do_mov_3022)
{
    u64 addr = ctx->di - 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x4e")
int BPF_KPROBE(do_mov_3023)
{
    u64 addr = ctx->ax - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x52")
int BPF_KPROBE(do_mov_3024)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0xb5")
int BPF_KPROBE(do_mov_3025)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0xbc")
int BPF_KPROBE(do_mov_3026)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0xbf")
int BPF_KPROBE(do_mov_3027)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0xc2")
int BPF_KPROBE(do_mov_3028)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x111")
int BPF_KPROBE(do_mov_3029)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x118")
int BPF_KPROBE(do_mov_3030)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x11c")
int BPF_KPROBE(do_mov_3031)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x126")
int BPF_KPROBE(do_mov_3032)
{
    u64 addr = ctx->dx + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x12d")
int BPF_KPROBE(do_mov_3033)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x130")
int BPF_KPROBE(do_mov_3034)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x134")
int BPF_KPROBE(do_mov_3035)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x156")
int BPF_KPROBE(do_mov_3036)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x15a")
int BPF_KPROBE(do_mov_3037)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_destroy+0x90")
int BPF_KPROBE(do_mov_3038)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_destroy+0x94")
int BPF_KPROBE(do_mov_3039)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_destroy+0x97")
int BPF_KPROBE(do_mov_3040)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_destroy+0x9b")
int BPF_KPROBE(do_mov_3041)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dump+0x185")
int BPF_KPROBE(do_mov_3042)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0xee")
int BPF_KPROBE(do_mov_3043)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0xf2")
int BPF_KPROBE(do_mov_3044)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0xff")
int BPF_KPROBE(do_mov_3045)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x107")
int BPF_KPROBE(do_mov_3046)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x184")
int BPF_KPROBE(do_mov_3047)
{
    u64 addr = ctx->di + ctx->cx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x1d3")
int BPF_KPROBE(do_mov_3048)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x1fe")
int BPF_KPROBE(do_mov_3049)
{
    u64 addr = ctx->di + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x224")
int BPF_KPROBE(do_mov_3050)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x22f")
int BPF_KPROBE(do_mov_3051)
{
    u64 addr = ctx->cx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x239")
int BPF_KPROBE(do_mov_3052)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x26c")
int BPF_KPROBE(do_mov_3053)
{
    u64 addr = ctx->r15 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2c6")
int BPF_KPROBE(do_mov_3054)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2cd")
int BPF_KPROBE(do_mov_3055)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2e9")
int BPF_KPROBE(do_mov_3056)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2ec")
int BPF_KPROBE(do_mov_3057)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x33c")
int BPF_KPROBE(do_mov_3058)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x347")
int BPF_KPROBE(do_mov_3059)
{
    u64 addr = ctx->dx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x366")
int BPF_KPROBE(do_mov_3060)
{
    u64 addr = ctx->r15 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x384")
int BPF_KPROBE(do_mov_3061)
{
    u64 addr = ctx->r15 + 0x250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x38b")
int BPF_KPROBE(do_mov_3062)
{
    u64 addr = ctx->r15 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x399")
int BPF_KPROBE(do_mov_3063)
{
    u64 addr = ctx->r15 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3a0")
int BPF_KPROBE(do_mov_3064)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3b1")
int BPF_KPROBE(do_mov_3065)
{
    u64 addr = ctx->r15 + ctx->dx * 0x8 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3c2")
int BPF_KPROBE(do_mov_3066)
{
    u64 addr = ctx->cx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3dc")
int BPF_KPROBE(do_mov_3067)
{
    u64 addr = ctx->r15 + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3e3")
int BPF_KPROBE(do_mov_3068)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3ea")
int BPF_KPROBE(do_mov_3069)
{
    u64 addr = ctx->r15 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3f1")
int BPF_KPROBE(do_mov_3070)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x452")
int BPF_KPROBE(do_mov_3071)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x45a")
int BPF_KPROBE(do_mov_3072)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x4d8")
int BPF_KPROBE(do_mov_3073)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x4dc")
int BPF_KPROBE(do_mov_3074)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x4e5")
int BPF_KPROBE(do_mov_3075)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x4ea")
int BPF_KPROBE(do_mov_3076)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x4ee")
int BPF_KPROBE(do_mov_3077)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x4f2")
int BPF_KPROBE(do_mov_3078)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0xcc")
int BPF_KPROBE(do_mov_3079)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0xd3")
int BPF_KPROBE(do_mov_3080)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0xda")
int BPF_KPROBE(do_mov_3081)
{
    u64 addr = ctx->bx + 0x274;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0xe9")
int BPF_KPROBE(do_mov_3082)
{
    u64 addr = ctx->bx + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0x100")
int BPF_KPROBE(do_mov_3083)
{
    u64 addr = ctx->bx + 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0x112")
int BPF_KPROBE(do_mov_3084)
{
    u64 addr = ctx->bx + 0x26c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0x129")
int BPF_KPROBE(do_mov_3085)
{
    u64 addr = ctx->bx + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x34")
int BPF_KPROBE(do_mov_3086)
{
    u64 addr = ctx->di - 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x4e")
int BPF_KPROBE(do_mov_3087)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x5e")
int BPF_KPROBE(do_mov_3088)
{
    u64 addr = ctx->r12 + 0x248;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x66")
int BPF_KPROBE(do_mov_3089)
{
    u64 addr = ctx->r12 + 0x250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x6e")
int BPF_KPROBE(do_mov_3090)
{
    u64 addr = ctx->r12 + 0x258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x76")
int BPF_KPROBE(do_mov_3091)
{
    u64 addr = ctx->r12 + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x88")
int BPF_KPROBE(do_mov_3092)
{
    u64 addr = ctx->r12 + 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x9a")
int BPF_KPROBE(do_mov_3093)
{
    u64 addr = ctx->r12 + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0xe3")
int BPF_KPROBE(do_mov_3094)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x107")
int BPF_KPROBE(do_mov_3095)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x10a")
int BPF_KPROBE(do_mov_3096)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x127")
int BPF_KPROBE(do_mov_3097)
{
    u64 addr = ctx->r12 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x133")
int BPF_KPROBE(do_mov_3098)
{
    u64 addr = ctx->r12 + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x153")
int BPF_KPROBE(do_mov_3099)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x173")
int BPF_KPROBE(do_mov_3100)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x18f")
int BPF_KPROBE(do_mov_3101)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x1a9")
int BPF_KPROBE(do_mov_3102)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x1b1")
int BPF_KPROBE(do_mov_3103)
{
    u64 addr = ctx->r12 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x1c1")
int BPF_KPROBE(do_mov_3104)
{
    u64 addr = ctx->r12 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x1c9")
int BPF_KPROBE(do_mov_3105)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x2c")
int BPF_KPROBE(do_mov_3106)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x106")
int BPF_KPROBE(do_mov_3107)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x118")
int BPF_KPROBE(do_mov_3108)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x13e")
int BPF_KPROBE(do_mov_3109)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x142")
int BPF_KPROBE(do_mov_3110)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x145")
int BPF_KPROBE(do_mov_3111)
{
    u64 addr = ctx->di + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x171")
int BPF_KPROBE(do_mov_3112)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x179")
int BPF_KPROBE(do_mov_3113)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x181")
int BPF_KPROBE(do_mov_3114)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x189")
int BPF_KPROBE(do_mov_3115)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x191")
int BPF_KPROBE(do_mov_3116)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x19f")
int BPF_KPROBE(do_mov_3117)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x1ee")
int BPF_KPROBE(do_mov_3118)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x205")
int BPF_KPROBE(do_mov_3119)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x21d")
int BPF_KPROBE(do_mov_3120)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_drop_early+0x93")
int BPF_KPROBE(do_mov_3121)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_drop_early+0xec")
int BPF_KPROBE(do_mov_3122)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x35")
int BPF_KPROBE(do_mov_3123)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x49")
int BPF_KPROBE(do_mov_3124)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x7c")
int BPF_KPROBE(do_mov_3125)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0xa5")
int BPF_KPROBE(do_mov_3126)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0xc9")
int BPF_KPROBE(do_mov_3127)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0xd5")
int BPF_KPROBE(do_mov_3128)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0xf3")
int BPF_KPROBE(do_mov_3129)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0xfc")
int BPF_KPROBE(do_mov_3130)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x108")
int BPF_KPROBE(do_mov_3131)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x119")
int BPF_KPROBE(do_mov_3132)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x127")
int BPF_KPROBE(do_mov_3133)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x13e")
int BPF_KPROBE(do_mov_3134)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x14f")
int BPF_KPROBE(do_mov_3135)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_dequeue+0x22")
int BPF_KPROBE(do_mov_3136)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_dequeue+0x2e")
int BPF_KPROBE(do_mov_3137)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_dequeue+0x9b")
int BPF_KPROBE(do_mov_3138)
{
    u64 addr = ctx->di + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x20")
int BPF_KPROBE(do_mov_3139)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x2b")
int BPF_KPROBE(do_mov_3140)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x36")
int BPF_KPROBE(do_mov_3141)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x41")
int BPF_KPROBE(do_mov_3142)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x4c")
int BPF_KPROBE(do_mov_3143)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x6f")
int BPF_KPROBE(do_mov_3144)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x7a")
int BPF_KPROBE(do_mov_3145)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x85")
int BPF_KPROBE(do_mov_3146)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_destroy+0xd")
int BPF_KPROBE(do_mov_3147)
{
    u64 addr = ctx->di - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_dump+0x1a9")
int BPF_KPROBE(do_mov_3148)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x73")
int BPF_KPROBE(do_mov_3149)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x82")
int BPF_KPROBE(do_mov_3150)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x8b")
int BPF_KPROBE(do_mov_3151)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x13a")
int BPF_KPROBE(do_mov_3152)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x15e")
int BPF_KPROBE(do_mov_3153)
{
    u64 addr = ctx->r13 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x1bc")
int BPF_KPROBE(do_mov_3154)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x1c0")
int BPF_KPROBE(do_mov_3155)
{
    u64 addr = ctx->ax + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x1f5")
int BPF_KPROBE(do_mov_3156)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x1fd")
int BPF_KPROBE(do_mov_3157)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x206")
int BPF_KPROBE(do_mov_3158)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x210")
int BPF_KPROBE(do_mov_3159)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x22e")
int BPF_KPROBE(do_mov_3160)
{
    u64 addr = ctx->bx + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x239")
int BPF_KPROBE(do_mov_3161)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x240")
int BPF_KPROBE(do_mov_3162)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x252")
int BPF_KPROBE(do_mov_3163)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x94")
int BPF_KPROBE(do_mov_3164)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0xac")
int BPF_KPROBE(do_mov_3165)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0xc2")
int BPF_KPROBE(do_mov_3166)
{
    u64 addr = ctx->bx + 0x1cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0xc8")
int BPF_KPROBE(do_mov_3167)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0xd7")
int BPF_KPROBE(do_mov_3168)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0xe9")
int BPF_KPROBE(do_mov_3169)
{
    u64 addr = ctx->bx + 0x1d4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0xfb")
int BPF_KPROBE(do_mov_3170)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x10d")
int BPF_KPROBE(do_mov_3171)
{
    u64 addr = ctx->bx + 0x1d9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x11f")
int BPF_KPROBE(do_mov_3172)
{
    u64 addr = ctx->bx + 0x1da;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x13d")
int BPF_KPROBE(do_mov_3173)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x17c")
int BPF_KPROBE(do_mov_3174)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x182")
int BPF_KPROBE(do_mov_3175)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x18e")
int BPF_KPROBE(do_mov_3176)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x1a")
int BPF_KPROBE(do_mov_3177)
{
    u64 addr = ctx->di + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x3c")
int BPF_KPROBE(do_mov_3178)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x4e")
int BPF_KPROBE(do_mov_3179)
{
    u64 addr = ctx->r12 + 0x1da;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x5c")
int BPF_KPROBE(do_mov_3180)
{
    u64 addr = ctx->r12 + 0x1cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x74")
int BPF_KPROBE(do_mov_3181)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x80")
int BPF_KPROBE(do_mov_3182)
{
    u64 addr = ctx->r12 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x8f")
int BPF_KPROBE(do_mov_3183)
{
    u64 addr = ctx->r12 + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0xa1")
int BPF_KPROBE(do_mov_3184)
{
    u64 addr = ctx->r12 + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0xab")
int BPF_KPROBE(do_mov_3185)
{
    u64 addr = ctx->r12 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0xb4")
int BPF_KPROBE(do_mov_3186)
{
    u64 addr = ctx->r12 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0xc0")
int BPF_KPROBE(do_mov_3187)
{
    u64 addr = ctx->r12 + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0xcc")
int BPF_KPROBE(do_mov_3188)
{
    u64 addr = ctx->r12 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0xd8")
int BPF_KPROBE(do_mov_3189)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0xc")
int BPF_KPROBE(do_mov_3190)
{
    u64 addr = ctx->di + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x13")
int BPF_KPROBE(do_mov_3191)
{
    u64 addr = ctx->di + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x21")
int BPF_KPROBE(do_mov_3192)
{
    u64 addr = ctx->di + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x28")
int BPF_KPROBE(do_mov_3193)
{
    u64 addr = ctx->di + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x7a")
int BPF_KPROBE(do_mov_3194)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x82")
int BPF_KPROBE(do_mov_3195)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x86")
int BPF_KPROBE(do_mov_3196)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x8e")
int BPF_KPROBE(do_mov_3197)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x92")
int BPF_KPROBE(do_mov_3198)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x9a")
int BPF_KPROBE(do_mov_3199)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0xa2")
int BPF_KPROBE(do_mov_3200)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0xaa")
int BPF_KPROBE(do_mov_3201)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_destroy+0x20")
int BPF_KPROBE(do_mov_3202)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x53")
int BPF_KPROBE(do_mov_3203)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x5c")
int BPF_KPROBE(do_mov_3204)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0xdf")
int BPF_KPROBE(do_mov_3205)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0xe6")
int BPF_KPROBE(do_mov_3206)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0xe9")
int BPF_KPROBE(do_mov_3207)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0xec")
int BPF_KPROBE(do_mov_3208)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x129")
int BPF_KPROBE(do_mov_3209)
{
    u64 addr = ctx->dx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x12f")
int BPF_KPROBE(do_mov_3210)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x133")
int BPF_KPROBE(do_mov_3211)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x13d")
int BPF_KPROBE(do_mov_3212)
{
    u64 addr = ctx->si + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x144")
int BPF_KPROBE(do_mov_3213)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x147")
int BPF_KPROBE(do_mov_3214)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x14b")
int BPF_KPROBE(do_mov_3215)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x15f")
int BPF_KPROBE(do_mov_3216)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x163")
int BPF_KPROBE(do_mov_3217)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_dump+0x245")
int BPF_KPROBE(do_mov_3218)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x8d")
int BPF_KPROBE(do_mov_3219)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x91")
int BPF_KPROBE(do_mov_3220)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0xff")
int BPF_KPROBE(do_mov_3221)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x1cd")
int BPF_KPROBE(do_mov_3222)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x1d8")
int BPF_KPROBE(do_mov_3223)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x1e1")
int BPF_KPROBE(do_mov_3224)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x203")
int BPF_KPROBE(do_mov_3225)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x229")
int BPF_KPROBE(do_mov_3226)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x27b")
int BPF_KPROBE(do_mov_3227)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x27e")
int BPF_KPROBE(do_mov_3228)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x286")
int BPF_KPROBE(do_mov_3229)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x2a2")
int BPF_KPROBE(do_mov_3230)
{
    u64 addr = ctx->r13 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x2a8")
int BPF_KPROBE(do_mov_3231)
{
    u64 addr = ctx->r13 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x303")
int BPF_KPROBE(do_mov_3232)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x30d")
int BPF_KPROBE(do_mov_3233)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x324")
int BPF_KPROBE(do_mov_3234)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x32b")
int BPF_KPROBE(do_mov_3235)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x32f")
int BPF_KPROBE(do_mov_3236)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x333")
int BPF_KPROBE(do_mov_3237)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x343")
int BPF_KPROBE(do_mov_3238)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x431")
int BPF_KPROBE(do_mov_3239)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x435")
int BPF_KPROBE(do_mov_3240)
{
    u64 addr = ctx->ax + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x9c")
int BPF_KPROBE(do_mov_3241)
{
    u64 addr = ctx->bx + 0x1cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0xa2")
int BPF_KPROBE(do_mov_3242)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0xbf")
int BPF_KPROBE(do_mov_3243)
{
    u64 addr = ctx->bx + 0x1e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0xea")
int BPF_KPROBE(do_mov_3244)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x102")
int BPF_KPROBE(do_mov_3245)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x114")
int BPF_KPROBE(do_mov_3246)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x126")
int BPF_KPROBE(do_mov_3247)
{
    u64 addr = ctx->bx + 0x1d4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x138")
int BPF_KPROBE(do_mov_3248)
{
    u64 addr = ctx->bx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x14a")
int BPF_KPROBE(do_mov_3249)
{
    u64 addr = ctx->bx + 0x1ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x15c")
int BPF_KPROBE(do_mov_3250)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x16e")
int BPF_KPROBE(do_mov_3251)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x180")
int BPF_KPROBE(do_mov_3252)
{
    u64 addr = ctx->bx + 0x1d9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x192")
int BPF_KPROBE(do_mov_3253)
{
    u64 addr = ctx->bx + 0x1da;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x2c5")
int BPF_KPROBE(do_mov_3254)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x2cd")
int BPF_KPROBE(do_mov_3255)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x2d6")
int BPF_KPROBE(do_mov_3256)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x2f1")
int BPF_KPROBE(do_mov_3257)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x337")
int BPF_KPROBE(do_mov_3258)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x19")
int BPF_KPROBE(do_mov_3259)
{
    u64 addr = ctx->di + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x3a")
int BPF_KPROBE(do_mov_3260)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x50")
int BPF_KPROBE(do_mov_3261)
{
    u64 addr = ctx->bx + 0x1da;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x57")
int BPF_KPROBE(do_mov_3262)
{
    u64 addr = ctx->bx + 0x1cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x6b")
int BPF_KPROBE(do_mov_3263)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x77")
int BPF_KPROBE(do_mov_3264)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x87")
int BPF_KPROBE(do_mov_3265)
{
    u64 addr = ctx->bx + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xa4")
int BPF_KPROBE(do_mov_3266)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xab")
int BPF_KPROBE(do_mov_3267)
{
    u64 addr = ctx->bx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xbb")
int BPF_KPROBE(do_mov_3268)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xc9")
int BPF_KPROBE(do_mov_3269)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xd0")
int BPF_KPROBE(do_mov_3270)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xde")
int BPF_KPROBE(do_mov_3271)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xe5")
int BPF_KPROBE(do_mov_3272)
{
    u64 addr = ctx->bx + 0x1ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xef")
int BPF_KPROBE(do_mov_3273)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x135")
int BPF_KPROBE(do_mov_3274)
{
    u64 addr = ctx->bx + 0x1e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x16f")
int BPF_KPROBE(do_mov_3275)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1af")
int BPF_KPROBE(do_mov_3276)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1b7")
int BPF_KPROBE(do_mov_3277)
{
    u64 addr = ctx->ax + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1bb")
int BPF_KPROBE(do_mov_3278)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1c3")
int BPF_KPROBE(do_mov_3279)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1c7")
int BPF_KPROBE(do_mov_3280)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1cf")
int BPF_KPROBE(do_mov_3281)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1d7")
int BPF_KPROBE(do_mov_3282)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dump_class+0x28")
int BPF_KPROBE(do_mov_3283)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_set_port_rate+0x42")
int BPF_KPROBE(do_mov_3284)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_disable_offload+0x39")
int BPF_KPROBE(do_mov_3285)
{
    u64 addr = ctx->si + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_disable_offload+0x44")
int BPF_KPROBE(do_mov_3286)
{
    u64 addr = ctx->si + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_enqueue_soft+0x54")
int BPF_KPROBE(do_mov_3287)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_enqueue_soft+0x78")
int BPF_KPROBE(do_mov_3288)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dequeue_soft+0x79")
int BPF_KPROBE(do_mov_3289)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dequeue_soft+0x120")
int BPF_KPROBE(do_mov_3290)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dequeue_soft+0x150")
int BPF_KPROBE(do_mov_3291)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dequeue_soft+0x197")
int BPF_KPROBE(do_mov_3292)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dequeue_soft+0x1b9")
int BPF_KPROBE(do_mov_3293)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_destroy+0x65")
int BPF_KPROBE(do_mov_3294)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_destroy+0x69")
int BPF_KPROBE(do_mov_3295)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_destroy+0x76")
int BPF_KPROBE(do_mov_3296)
{
    u64 addr = ctx->bx + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_destroy+0x81")
int BPF_KPROBE(do_mov_3297)
{
    u64 addr = ctx->bx + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dump+0xf7")
int BPF_KPROBE(do_mov_3298)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0xe1")
int BPF_KPROBE(do_mov_3299)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0xec")
int BPF_KPROBE(do_mov_3300)
{
    u64 addr = ctx->bx + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0xfb")
int BPF_KPROBE(do_mov_3301)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x105")
int BPF_KPROBE(do_mov_3302)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x11d")
int BPF_KPROBE(do_mov_3303)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x136")
int BPF_KPROBE(do_mov_3304)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x1a4")
int BPF_KPROBE(do_mov_3305)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x1c4")
int BPF_KPROBE(do_mov_3306)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x1e2")
int BPF_KPROBE(do_mov_3307)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0x3d")
int BPF_KPROBE(do_mov_3308)
{
    u64 addr = ctx->r12 + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0x77")
int BPF_KPROBE(do_mov_3309)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0x7b")
int BPF_KPROBE(do_mov_3310)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0x83")
int BPF_KPROBE(do_mov_3311)
{
    u64 addr = ctx->r12 + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0xc0")
int BPF_KPROBE(do_mov_3312)
{
    u64 addr = ctx->r12 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0xd4")
int BPF_KPROBE(do_mov_3313)
{
    u64 addr = ctx->r12 + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0xe4")
int BPF_KPROBE(do_mov_3314)
{
    u64 addr = ctx->r12 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0x125")
int BPF_KPROBE(do_mov_3315)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_walk+0x31")
int BPF_KPROBE(do_mov_3316)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_walk+0x3a")
int BPF_KPROBE(do_mov_3317)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_graft+0x54")
int BPF_KPROBE(do_mov_3318)
{
    u64 addr = ctx->bx + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_graft+0xd3")
int BPF_KPROBE(do_mov_3319)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/report_sock_error+0x60")
int BPF_KPROBE(do_mov_3320)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/report_sock_error+0x6f")
int BPF_KPROBE(do_mov_3321)
{
    u64 addr = ctx->r13 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/report_sock_error+0x74")
int BPF_KPROBE(do_mov_3322)
{
    u64 addr = ctx->r13 + 0x46;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/report_sock_error+0x78")
int BPF_KPROBE(do_mov_3323)
{
    u64 addr = ctx->r13 + 0x47;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/report_sock_error+0x7d")
int BPF_KPROBE(do_mov_3324)
{
    u64 addr = ctx->r13 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dump+0xc8")
int BPF_KPROBE(do_mov_3325)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x60")
int BPF_KPROBE(do_mov_3326)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x69")
int BPF_KPROBE(do_mov_3327)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0xf0")
int BPF_KPROBE(do_mov_3328)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0xf4")
int BPF_KPROBE(do_mov_3329)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0xfd")
int BPF_KPROBE(do_mov_3330)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x106")
int BPF_KPROBE(do_mov_3331)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x10e")
int BPF_KPROBE(do_mov_3332)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x173")
int BPF_KPROBE(do_mov_3333)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x17b")
int BPF_KPROBE(do_mov_3334)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x184")
int BPF_KPROBE(do_mov_3335)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x18d")
int BPF_KPROBE(do_mov_3336)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0xb4")
int BPF_KPROBE(do_mov_3337)
{
    u64 addr = ctx->r12 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0xcb")
int BPF_KPROBE(do_mov_3338)
{
    u64 addr = ctx->r12 + 0x18c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0xd7")
int BPF_KPROBE(do_mov_3339)
{
    u64 addr = ctx->r12 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0xe8")
int BPF_KPROBE(do_mov_3340)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0xf4")
int BPF_KPROBE(do_mov_3341)
{
    u64 addr = ctx->r12 + 0x181;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x10f")
int BPF_KPROBE(do_mov_3342)
{
    u64 addr = ctx->r12 + 0x182;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x13e")
int BPF_KPROBE(do_mov_3343)
{
    u64 addr = ctx->r12 + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x1dc")
int BPF_KPROBE(do_mov_3344)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x244")
int BPF_KPROBE(do_mov_3345)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x279")
int BPF_KPROBE(do_mov_3346)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x29b")
int BPF_KPROBE(do_mov_3347)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x2c1")
int BPF_KPROBE(do_mov_3348)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x2e3")
int BPF_KPROBE(do_mov_3349)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x305")
int BPF_KPROBE(do_mov_3350)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x327")
int BPF_KPROBE(do_mov_3351)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/timesortedlist_remove+0x2c")
int BPF_KPROBE(do_mov_3352)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/timesortedlist_remove+0x3e")
int BPF_KPROBE(do_mov_3353)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/timesortedlist_remove+0x4b")
int BPF_KPROBE(do_mov_3354)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/timesortedlist_remove+0x5b")
int BPF_KPROBE(do_mov_3355)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/timesortedlist_remove+0xa5")
int BPF_KPROBE(do_mov_3356)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_reset+0x52")
int BPF_KPROBE(do_mov_3357)
{
    u64 addr = ctx->r13 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_reset+0x90")
int BPF_KPROBE(do_mov_3358)
{
    u64 addr = ctx->r13 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_reset+0xb7")
int BPF_KPROBE(do_mov_3359)
{
    u64 addr = ctx->r13 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_reset+0xc2")
int BPF_KPROBE(do_mov_3360)
{
    u64 addr = ctx->r13 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_reset+0xcd")
int BPF_KPROBE(do_mov_3361)
{
    u64 addr = ctx->r13 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0xcc")
int BPF_KPROBE(do_mov_3362)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0xdf")
int BPF_KPROBE(do_mov_3363)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0xee")
int BPF_KPROBE(do_mov_3364)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0x102")
int BPF_KPROBE(do_mov_3365)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0x115")
int BPF_KPROBE(do_mov_3366)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0x162")
int BPF_KPROBE(do_mov_3367)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump_class+0x2e")
int BPF_KPROBE(do_mov_3368)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump_class+0x43")
int BPF_KPROBE(do_mov_3369)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_walk+0x24")
int BPF_KPROBE(do_mov_3370)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_walk+0x45")
int BPF_KPROBE(do_mov_3371)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_walk+0x6f")
int BPF_KPROBE(do_mov_3372)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_free_sched_cb+0x3d")
int BPF_KPROBE(do_mov_3373)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_free_sched_cb+0x41")
int BPF_KPROBE(do_mov_3374)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_free_sched_cb+0x44")
int BPF_KPROBE(do_mov_3375)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_free_sched_cb+0x47")
int BPF_KPROBE(do_mov_3376)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_set_picos_per_byte+0x46")
int BPF_KPROBE(do_mov_3377)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_graft+0x7c")
int BPF_KPROBE(do_mov_3378)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_graft+0x86")
int BPF_KPROBE(do_mov_3379)
{
    u64 addr = ctx->ax + ctx->bx * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_graft+0xe2")
int BPF_KPROBE(do_mov_3380)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0xb3")
int BPF_KPROBE(do_mov_3381)
{
    u64 addr = ctx->bx + ctx->ax * 0x1 + 0x258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0xc9")
int BPF_KPROBE(do_mov_3382)
{
    u64 addr = ctx->bx + ctx->ax * 0x1 + 0x218;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x201")
int BPF_KPROBE(do_mov_3383)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x223")
int BPF_KPROBE(do_mov_3384)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x245")
int BPF_KPROBE(do_mov_3385)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x26c")
int BPF_KPROBE(do_mov_3386)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x292")
int BPF_KPROBE(do_mov_3387)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x29e")
int BPF_KPROBE(do_mov_3388)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x2a2")
int BPF_KPROBE(do_mov_3389)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_attach+0xcc")
int BPF_KPROBE(do_mov_3390)
{
    u64 addr = ctx->r15 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x4e")
int BPF_KPROBE(do_mov_3391)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x71")
int BPF_KPROBE(do_mov_3392)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x188")
int BPF_KPROBE(do_mov_3393)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x193")
int BPF_KPROBE(do_mov_3394)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x201")
int BPF_KPROBE(do_mov_3395)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x208")
int BPF_KPROBE(do_mov_3396)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x21f")
int BPF_KPROBE(do_mov_3397)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x226")
int BPF_KPROBE(do_mov_3398)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x57")
int BPF_KPROBE(do_mov_3399)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x77")
int BPF_KPROBE(do_mov_3400)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x97")
int BPF_KPROBE(do_mov_3401)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x180")
int BPF_KPROBE(do_mov_3402)
{
    u64 addr = ctx->r11 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1b4")
int BPF_KPROBE(do_mov_3403)
{
    u64 addr = ctx->r11 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1c4")
int BPF_KPROBE(do_mov_3404)
{
    u64 addr = ctx->r11 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1de")
int BPF_KPROBE(do_mov_3405)
{
    u64 addr = ctx->r11 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1ee")
int BPF_KPROBE(do_mov_3406)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1f2")
int BPF_KPROBE(do_mov_3407)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1f5")
int BPF_KPROBE(do_mov_3408)
{
    u64 addr = ctx->r11 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1f9")
int BPF_KPROBE(do_mov_3409)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x21a")
int BPF_KPROBE(do_mov_3410)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x248")
int BPF_KPROBE(do_mov_3411)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x27c")
int BPF_KPROBE(do_mov_3412)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x2a2")
int BPF_KPROBE(do_mov_3413)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x2c9")
int BPF_KPROBE(do_mov_3414)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x2f0")
int BPF_KPROBE(do_mov_3415)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x315")
int BPF_KPROBE(do_mov_3416)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x34d")
int BPF_KPROBE(do_mov_3417)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x367")
int BPF_KPROBE(do_mov_3418)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_offload_alloc+0x38")
int BPF_KPROBE(do_mov_3419)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_disable_offload+0x48")
int BPF_KPROBE(do_mov_3420)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_disable_offload+0x64")
int BPF_KPROBE(do_mov_3421)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_disable_offload+0x8f")
int BPF_KPROBE(do_mov_3422)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_disable_offload+0xb3")
int BPF_KPROBE(do_mov_3423)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_destroy+0x33")
int BPF_KPROBE(do_mov_3424)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_destroy+0x37")
int BPF_KPROBE(do_mov_3425)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_destroy+0x44")
int BPF_KPROBE(do_mov_3426)
{
    u64 addr = ctx->di + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_destroy+0x4c")
int BPF_KPROBE(do_mov_3427)
{
    u64 addr = ctx->di + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_destroy+0xa0")
int BPF_KPROBE(do_mov_3428)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc7")
int BPF_KPROBE(do_mov_3429)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x107")
int BPF_KPROBE(do_mov_3430)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x237")
int BPF_KPROBE(do_mov_3431)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x242")
int BPF_KPROBE(do_mov_3432)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x370")
int BPF_KPROBE(do_mov_3433)
{
    u64 addr = ctx->r12 + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x378")
int BPF_KPROBE(do_mov_3434)
{
    u64 addr = ctx->r12 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x42b")
int BPF_KPROBE(do_mov_3435)
{
    u64 addr = ctx->r13 + ctx->ax * 0x1 + 0x8e1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x4e9")
int BPF_KPROBE(do_mov_3436)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x4f0")
int BPF_KPROBE(do_mov_3437)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x4f8")
int BPF_KPROBE(do_mov_3438)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x500")
int BPF_KPROBE(do_mov_3439)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x53b")
int BPF_KPROBE(do_mov_3440)
{
    u64 addr = ctx->ax + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x541")
int BPF_KPROBE(do_mov_3441)
{
    u64 addr = ctx->ax + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x5bb")
int BPF_KPROBE(do_mov_3442)
{
    u64 addr = ctx->r15 + ctx->ax * 0x4 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x5e6")
int BPF_KPROBE(do_mov_3443)
{
    u64 addr = ctx->cx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x5f2")
int BPF_KPROBE(do_mov_3444)
{
    u64 addr = ctx->cx + ctx->ax * 0x1 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x627")
int BPF_KPROBE(do_mov_3445)
{
    u64 addr = ctx->r12 + 0x19c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x68d")
int BPF_KPROBE(do_mov_3446)
{
    u64 addr = ctx->r12 + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x713")
int BPF_KPROBE(do_mov_3447)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x743")
int BPF_KPROBE(do_mov_3448)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x7c8")
int BPF_KPROBE(do_mov_3449)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x7ef")
int BPF_KPROBE(do_mov_3450)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x81f")
int BPF_KPROBE(do_mov_3451)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x8d5")
int BPF_KPROBE(do_mov_3452)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x919")
int BPF_KPROBE(do_mov_3453)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x943")
int BPF_KPROBE(do_mov_3454)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x994")
int BPF_KPROBE(do_mov_3455)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x9b7")
int BPF_KPROBE(do_mov_3456)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x9e8")
int BPF_KPROBE(do_mov_3457)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xa2f")
int BPF_KPROBE(do_mov_3458)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xa53")
int BPF_KPROBE(do_mov_3459)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xa8c")
int BPF_KPROBE(do_mov_3460)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xa9e")
int BPF_KPROBE(do_mov_3461)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xaaf")
int BPF_KPROBE(do_mov_3462)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xab2")
int BPF_KPROBE(do_mov_3463)
{
    u64 addr = ctx->r12 + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xb1e")
int BPF_KPROBE(do_mov_3464)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xba1")
int BPF_KPROBE(do_mov_3465)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xbf2")
int BPF_KPROBE(do_mov_3466)
{
    u64 addr = ctx->r12 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc1a")
int BPF_KPROBE(do_mov_3467)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc51")
int BPF_KPROBE(do_mov_3468)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc78")
int BPF_KPROBE(do_mov_3469)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xcc0")
int BPF_KPROBE(do_mov_3470)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xcf4")
int BPF_KPROBE(do_mov_3471)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd07")
int BPF_KPROBE(do_mov_3472)
{
    u64 addr = ctx->r12 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd33")
int BPF_KPROBE(do_mov_3473)
{
    u64 addr = ctx->r12 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd42")
int BPF_KPROBE(do_mov_3474)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd76")
int BPF_KPROBE(do_mov_3475)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd99")
int BPF_KPROBE(do_mov_3476)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xdbc")
int BPF_KPROBE(do_mov_3477)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x38")
int BPF_KPROBE(do_mov_3478)
{
    u64 addr = ctx->di - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x52")
int BPF_KPROBE(do_mov_3479)
{
    u64 addr = ctx->r15 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x5d")
int BPF_KPROBE(do_mov_3480)
{
    u64 addr = ctx->r15 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x64")
int BPF_KPROBE(do_mov_3481)
{
    u64 addr = ctx->r15 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x6f")
int BPF_KPROBE(do_mov_3482)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x7a")
int BPF_KPROBE(do_mov_3483)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x83")
int BPF_KPROBE(do_mov_3484)
{
    u64 addr = ctx->r15 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x8a")
int BPF_KPROBE(do_mov_3485)
{
    u64 addr = ctx->r15 + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0xc0")
int BPF_KPROBE(do_mov_3486)
{
    u64 addr = ctx->r15 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0xf5")
int BPF_KPROBE(do_mov_3487)
{
    u64 addr = ctx->dx + ctx->r12 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x19d")
int BPF_KPROBE(do_mov_3488)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x1bd")
int BPF_KPROBE(do_mov_3489)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x92")
int BPF_KPROBE(do_mov_3490)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x9b")
int BPF_KPROBE(do_mov_3491)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x2e1")
int BPF_KPROBE(do_mov_3492)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x2f4")
int BPF_KPROBE(do_mov_3493)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x335")
int BPF_KPROBE(do_mov_3494)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x37b")
int BPF_KPROBE(do_mov_3495)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x382")
int BPF_KPROBE(do_mov_3496)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x407")
int BPF_KPROBE(do_mov_3497)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue+0xa4")
int BPF_KPROBE(do_mov_3498)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue+0xb7")
int BPF_KPROBE(do_mov_3499)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue+0x12d")
int BPF_KPROBE(do_mov_3500)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue+0x136")
int BPF_KPROBE(do_mov_3501)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_schedule+0x1ad")
int BPF_KPROBE(do_mov_3502)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_schedule+0x276")
int BPF_KPROBE(do_mov_3503)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x92")
int BPF_KPROBE(do_mov_3504)
{
    u64 addr = ctx->bx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x96")
int BPF_KPROBE(do_mov_3505)
{
    u64 addr = ctx->bx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0xba")
int BPF_KPROBE(do_mov_3506)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0xc7")
int BPF_KPROBE(do_mov_3507)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0xcb")
int BPF_KPROBE(do_mov_3508)
{
    u64 addr = ctx->bx - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0xd7")
int BPF_KPROBE(do_mov_3509)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0xdb")
int BPF_KPROBE(do_mov_3510)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x109")
int BPF_KPROBE(do_mov_3511)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x138")
int BPF_KPROBE(do_mov_3512)
{
    u64 addr = ctx->bx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x141")
int BPF_KPROBE(do_mov_3513)
{
    u64 addr = ctx->bx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump+0x1b7")
int BPF_KPROBE(do_mov_3514)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump+0x26a")
int BPF_KPROBE(do_mov_3515)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump+0x281")
int BPF_KPROBE(do_mov_3516)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_walk+0x81")
int BPF_KPROBE(do_mov_3517)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_walk+0xa5")
int BPF_KPROBE(do_mov_3518)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_reset_fastmap+0x1d")
int BPF_KPROBE(do_mov_3519)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_reset_fastmap+0x26")
int BPF_KPROBE(do_mov_3520)
{
    u64 addr = ctx->bx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_dump+0x3e")
int BPF_KPROBE(do_mov_3521)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_dump+0xe0")
int BPF_KPROBE(do_mov_3522)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_init+0x28")
int BPF_KPROBE(do_mov_3523)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_destroy+0x7a")
int BPF_KPROBE(do_mov_3524)
{
    u64 addr = ctx->r13 + ctx->r12 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_destroy+0xd3")
int BPF_KPROBE(do_mov_3525)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_destroy+0x11b")
int BPF_KPROBE(do_mov_3526)
{
    u64 addr = ctx->si + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_destroy+0x132")
int BPF_KPROBE(do_mov_3527)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0x82")
int BPF_KPROBE(do_mov_3528)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0xaa")
int BPF_KPROBE(do_mov_3529)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0xe2")
int BPF_KPROBE(do_mov_3530)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0x13b")
int BPF_KPROBE(do_mov_3531)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0x195")
int BPF_KPROBE(do_mov_3532)
{
    u64 addr = ctx->r13 + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0xdf")
int BPF_KPROBE(do_mov_3533)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0xf3")
int BPF_KPROBE(do_mov_3534)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x10c")
int BPF_KPROBE(do_mov_3535)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x129")
int BPF_KPROBE(do_mov_3536)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x139")
int BPF_KPROBE(do_mov_3537)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x140")
int BPF_KPROBE(do_mov_3538)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x14b")
int BPF_KPROBE(do_mov_3539)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x14f")
int BPF_KPROBE(do_mov_3540)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x157")
int BPF_KPROBE(do_mov_3541)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x15e")
int BPF_KPROBE(do_mov_3542)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x166")
int BPF_KPROBE(do_mov_3543)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x226")
int BPF_KPROBE(do_mov_3544)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x37f")
int BPF_KPROBE(do_mov_3545)
{
    u64 addr = ctx->ax + ctx->r12 * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x388")
int BPF_KPROBE(do_mov_3546)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x39c")
int BPF_KPROBE(do_mov_3547)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x3a8")
int BPF_KPROBE(do_mov_3548)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x3ac")
int BPF_KPROBE(do_mov_3549)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x3b0")
int BPF_KPROBE(do_mov_3550)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x3c4")
int BPF_KPROBE(do_mov_3551)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x4cf")
int BPF_KPROBE(do_mov_3552)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x4d2")
int BPF_KPROBE(do_mov_3553)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x566")
int BPF_KPROBE(do_mov_3554)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x5c4")
int BPF_KPROBE(do_mov_3555)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x619")
int BPF_KPROBE(do_mov_3556)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x641")
int BPF_KPROBE(do_mov_3557)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x654")
int BPF_KPROBE(do_mov_3558)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x6da")
int BPF_KPROBE(do_mov_3559)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x114")
int BPF_KPROBE(do_mov_3560)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x118")
int BPF_KPROBE(do_mov_3561)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x175")
int BPF_KPROBE(do_mov_3562)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x179")
int BPF_KPROBE(do_mov_3563)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x1ea")
int BPF_KPROBE(do_mov_3564)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x1ee")
int BPF_KPROBE(do_mov_3565)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x216")
int BPF_KPROBE(do_mov_3566)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x21a")
int BPF_KPROBE(do_mov_3567)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x28b")
int BPF_KPROBE(do_mov_3568)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x28f")
int BPF_KPROBE(do_mov_3569)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x298")
int BPF_KPROBE(do_mov_3570)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x2f7")
int BPF_KPROBE(do_mov_3571)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x2fb")
int BPF_KPROBE(do_mov_3572)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x2ff")
int BPF_KPROBE(do_mov_3573)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_walk+0x45")
int BPF_KPROBE(do_mov_3574)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_walk+0x66")
int BPF_KPROBE(do_mov_3575)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_classify+0x65")
int BPF_KPROBE(do_mov_3576)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_classify+0x69")
int BPF_KPROBE(do_mov_3577)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_classify+0xd3")
int BPF_KPROBE(do_mov_3578)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_classify+0xdb")
int BPF_KPROBE(do_mov_3579)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_dump+0x3e")
int BPF_KPROBE(do_mov_3580)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_dump+0xe9")
int BPF_KPROBE(do_mov_3581)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_destroy+0x40")
int BPF_KPROBE(do_mov_3582)
{
    u64 addr = ctx->r13 + ctx->r12 * 0x8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_destroy+0x90")
int BPF_KPROBE(do_mov_3583)
{
    u64 addr = ctx->r15 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_destroy+0xe7")
int BPF_KPROBE(do_mov_3584)
{
    u64 addr = ctx->r15 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_delete+0x6d")
int BPF_KPROBE(do_mov_3585)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_delete+0x8d")
int BPF_KPROBE(do_mov_3586)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_delete+0xa9")
int BPF_KPROBE(do_mov_3587)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_delete+0xef")
int BPF_KPROBE(do_mov_3588)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x6e")
int BPF_KPROBE(do_mov_3589)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x153")
int BPF_KPROBE(do_mov_3590)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x263")
int BPF_KPROBE(do_mov_3591)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x26a")
int BPF_KPROBE(do_mov_3592)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x26e")
int BPF_KPROBE(do_mov_3593)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x299")
int BPF_KPROBE(do_mov_3594)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x2a0")
int BPF_KPROBE(do_mov_3595)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x2a4")
int BPF_KPROBE(do_mov_3596)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0xe7")
int BPF_KPROBE(do_mov_3597)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0xf3")
int BPF_KPROBE(do_mov_3598)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0xf7")
int BPF_KPROBE(do_mov_3599)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x104")
int BPF_KPROBE(do_mov_3600)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x10c")
int BPF_KPROBE(do_mov_3601)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x114")
int BPF_KPROBE(do_mov_3602)
{
    u64 addr = ctx->r13 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x118")
int BPF_KPROBE(do_mov_3603)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x121")
int BPF_KPROBE(do_mov_3604)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x14c")
int BPF_KPROBE(do_mov_3605)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x19d")
int BPF_KPROBE(do_mov_3606)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x1a1")
int BPF_KPROBE(do_mov_3607)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x204")
int BPF_KPROBE(do_mov_3608)
{
    u64 addr = ctx->r15 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x227")
int BPF_KPROBE(do_mov_3609)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x2ac")
int BPF_KPROBE(do_mov_3610)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x2c1")
int BPF_KPROBE(do_mov_3611)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x2dc")
int BPF_KPROBE(do_mov_3612)
{
    u64 addr = ctx->r10 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x2e9")
int BPF_KPROBE(do_mov_3613)
{
    u64 addr = ctx->r10 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x2f7")
int BPF_KPROBE(do_mov_3614)
{
    u64 addr = ctx->r10 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x313")
int BPF_KPROBE(do_mov_3615)
{
    u64 addr = ctx->r10 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x350")
int BPF_KPROBE(do_mov_3616)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x353")
int BPF_KPROBE(do_mov_3617)
{
    u64 addr = ctx->bx + ctx->ax * 0x8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x362")
int BPF_KPROBE(do_mov_3618)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x3e5")
int BPF_KPROBE(do_mov_3619)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x3e7")
int BPF_KPROBE(do_mov_3620)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_register+0x62")
int BPF_KPROBE(do_mov_3621)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_register+0x74")
int BPF_KPROBE(do_mov_3622)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_register+0x78")
int BPF_KPROBE(do_mov_3623)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_unregister+0x28")
int BPF_KPROBE(do_mov_3624)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_unregister+0x2c")
int BPF_KPROBE(do_mov_3625)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_unregister+0x39")
int BPF_KPROBE(do_mov_3626)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_unregister+0x41")
int BPF_KPROBE(do_mov_3627)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x25")
int BPF_KPROBE(do_mov_3628)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x2c")
int BPF_KPROBE(do_mov_3629)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x93")
int BPF_KPROBE(do_mov_3630)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0xad")
int BPF_KPROBE(do_mov_3631)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x163")
int BPF_KPROBE(do_mov_3632)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x170")
int BPF_KPROBE(do_mov_3633)
{
    u64 addr = ctx->cx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x179")
int BPF_KPROBE(do_mov_3634)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x17d")
int BPF_KPROBE(do_mov_3635)
{
    u64 addr = ctx->cx + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x222")
int BPF_KPROBE(do_mov_3636)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x2b1")
int BPF_KPROBE(do_mov_3637)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x2b5")
int BPF_KPROBE(do_mov_3638)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x2fd")
int BPF_KPROBE(do_mov_3639)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x320")
int BPF_KPROBE(do_mov_3640)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_dump+0x104")
int BPF_KPROBE(do_mov_3641)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_dump+0x1fe")
int BPF_KPROBE(do_mov_3642)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_dump+0x212")
int BPF_KPROBE(do_mov_3643)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/shutdown_scheduler_queue+0xe")
int BPF_KPROBE(do_mov_3644)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/shutdown_scheduler_queue+0x12")
int BPF_KPROBE(do_mov_3645)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/attach_one_default_qdisc+0x5e")
int BPF_KPROBE(do_mov_3646)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}

