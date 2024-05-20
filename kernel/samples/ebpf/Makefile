# SPDX-License-Identifier: GPL-2.0

BPF_SAMPLES_PATH ?= $(abspath $(srctree)/$(src))
TOOLS_PATH := $(BPF_SAMPLES_PATH)/../../tools

pound := \#

# List of programs to build
tprogs-y += unittest0
tprogs-y += unittest1
tprogs-y += perm_pt
tprogs-y += perm_pks
tprogs-y += perm_standalone
tprogs-y += comp_model
tprogs-y += comp_unittest0
tprogs-y += comp_test1
tprogs-y += comp_test2
tprogs-y += comp_ipv6_sample
tprogs-y += comp_netfilter_sample
tprogs-y += comp_sched_sample
tprogs-y += comp_working_ipv6_x
tprogs-y += comp_working_ipv6
tprogs-y += comp_working_netfilter_x
tprogs-y += comp_working_netfilter
tprogs-y += comp_working_sched_x
tprogs-y += comp_working_sched
tprogs-y += comp_working_ipv6_x1
tprogs-y += comp_working_ipv61
tprogs-y += comp_working_sched_x1
tprogs-y += comp_working_sched1
tprogs-y += comp_working_netfilter_x1
tprogs-y += comp_working_netfilter1
tprogs-y += comp_working_scale
tprogs-y += comp_working_scale1



# Libbpf dependencies
LIBBPF_SRC = $(TOOLS_PATH)/lib/bpf
LIBBPF_OUTPUT = $(abspath $(BPF_SAMPLES_PATH))/libbpf
LIBBPF_DESTDIR = $(LIBBPF_OUTPUT)
LIBBPF_INCLUDE = $(LIBBPF_DESTDIR)/include
LIBBPF = $(LIBBPF_OUTPUT)/libbpf.a

CGROUP_HELPERS := ../../tools/testing/selftests/bpf/cgroup_helpers.o
TRACE_HELPERS := ../../tools/testing/selftests/bpf/trace_helpers.o
XDP_SAMPLE := xdp_sample_user.o

unittest0-objs := unittest0_user.o
unittest1-objs := unittest1_user.o
perm_pt-objs := perm_pt_user.o
perm_pks-objs := perm_pks_user.o
perm_standalone-objs := perm_standalone_user.o
comp_model-objs := comp_model_user.o trace_helpers.o
comp_unittest0-objs := comp_unittest0_user.o
comp_test1-objs := comp_test1_user.o trace_helpers.o
comp_test2-objs := comp_test2_user.o trace_helpers.o
comp_ipv6_sample-objs := comp_ipv6_sample_user.o trace_helpers.o
comp_netfilter_sample-objs := comp_netfilter_sample_user.o trace_helpers.o
comp_sched_sample-objs := comp_sched_sample_user.o trace_helpers.o
comp_working_ipv6_x-objs := comp_working_ipv6_x_user.o trace_helpers.o
comp_working_ipv6-objs := comp_working_ipv6_user.o trace_helpers.o
comp_working_netfilter_x-objs := comp_working_netfilter_x_user.o trace_helpers.o
comp_working_netfilter-objs := comp_working_netfilter_user.o trace_helpers.o
comp_working_sched_x-objs := comp_working_sched_x_user.o trace_helpers.o
comp_working_sched-objs := comp_working_sched_user.o trace_helpers.o
comp_working_ipv6_x1-objs := comp_working_ipv6_x1_user.o trace_helpers.o
comp_working_ipv61-objs := comp_working_ipv61_user.o trace_helpers.o
comp_working_sched_x1-objs := comp_working_sched_x1_user.o trace_helpers.o
comp_working_sched1-objs := comp_working_sched1_user.o trace_helpers.o
comp_working_netfilter_x1-objs := comp_working_netfilter_x1_user.o trace_helpers.o
comp_working_netfilter1-objs := comp_working_netfilter1_user.o trace_helpers.o
comp_working_scale-objs := comp_working_scale_user.o trace_helpers.o
comp_working_scale1-objs := comp_working_scale1_user.o trace_helpers.o




# Tell kbuild to always build the programs
always-y := $(tprogs-y)
always-y += unittest0_kern.o
always-y += unittest1_kern.o
always-y += perm_pt_kern.o
always-y += perm_pks_kern.o
always-y += perm_standalone_kern.o
always-y += comp_model_kern.o
always-y += comp_unittest0_kern.o
always-y += comp_test1_kern.o
always-y += comp_test2_kern.o
always-y += comp_ipv6_sample_kern.o
always-y += comp_netfilter_sample_kern.o
always-y += comp_sched_sample_kern.o
always-y += comp_working_ipv6_x_kern.o
always-y += comp_working_ipv6_kern.o
always-y += comp_working_netfilter_x_kern.o
always-y += comp_working_netfilter_kern.o
always-y += comp_working_netfilter_x1_kern.o
always-y += comp_working_netfilter1_kern.o
always-y += comp_working_sched_x_kern.o
always-y += comp_working_sched_kern.o
always-y += comp_working_ipv6_x1_kern.o
always-y += comp_working_ipv61_kern.o
always-y += comp_working_sched_x1_kern.o
always-y += comp_working_sched1_kern.o
always-y += comp_working_scale_kern.o
always-y += comp_working_scale1_kern.o



ifeq ($(ARCH), arm)
# Strip all except -D__LINUX_ARM_ARCH__ option needed to handle linux
# headers when arm instruction set identification is requested.
ARM_ARCH_SELECTOR := $(filter -D__LINUX_ARM_ARCH__%, $(KBUILD_CFLAGS))
BPF_EXTRA_CFLAGS := $(ARM_ARCH_SELECTOR)
TPROGS_CFLAGS += $(ARM_ARCH_SELECTOR)
endif

ifeq ($(ARCH), mips)
TPROGS_CFLAGS += -D__SANE_USERSPACE_TYPES__
ifdef CONFIG_MACH_LOONGSON64
BPF_EXTRA_CFLAGS += -I$(srctree)/arch/mips/include/asm/mach-loongson64
BPF_EXTRA_CFLAGS += -I$(srctree)/arch/mips/include/asm/mach-generic
endif
endif

TPROGS_CFLAGS += -Wall -O2
TPROGS_CFLAGS += -Wmissing-prototypes
TPROGS_CFLAGS += -Wstrict-prototypes

TPROGS_CFLAGS += -I$(objtree)/usr/include
TPROGS_CFLAGS += -I$(srctree)/tools/testing/selftests/bpf/
TPROGS_CFLAGS += -I$(LIBBPF_INCLUDE)
TPROGS_CFLAGS += -I$(srctree)/tools/include
TPROGS_CFLAGS += -I$(srctree)/tools/perf
TPROGS_CFLAGS += -I$(srctree)/samples/ebpf
TPROGS_CFLAGS += -DHAVE_ATTR_TEST=0
TPROGS_CFLAGS += -lpthread

ifdef SYSROOT
TPROGS_CFLAGS += --sysroot=$(SYSROOT)
TPROGS_LDFLAGS := -L$(SYSROOT)/usr/lib
endif

TPROGS_LDLIBS			+= $(LIBBPF) -lelf -lz
TPROGLDLIBS_xdp_monitor		+= -lm
TPROGLDLIBS_xdp_redirect	+= -lm
TPROGLDLIBS_xdp_redirect_cpu	+= -lm
TPROGLDLIBS_xdp_redirect_map	+= -lm
TPROGLDLIBS_xdp_redirect_map_multi += -lm
TPROGLDLIBS_xdp_router_ipv4	+= -lm -pthread
TPROGLDLIBS_tracex4		+= -lrt
TPROGLDLIBS_trace_output	+= -lrt
TPROGLDLIBS_map_perf_test	+= -lrt
TPROGLDLIBS_test_overhead	+= -lrt

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
# make M=samples/bpf LLC=~/git/llvm-project/llvm/build/bin/llc CLANG=~/git/llvm-project/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang
OPT ?= opt
LLVM_DIS ?= llvm-dis
LLVM_OBJCOPY ?= llvm-objcopy
LLVM_READELF ?= llvm-readelf
BTF_PAHOLE ?= pahole

# Detect that we're cross compiling and use the cross compiler
ifdef CROSS_COMPILE
CLANG_ARCH_ARGS = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif

# Don't evaluate probes and warnings if we need to run make recursively
ifneq ($(src),)
HDR_PROBE := $(shell printf "$(pound)include <linux/types.h>\n struct list_head { int a; }; int main() { return 0; }" | \
	$(CC) $(TPROGS_CFLAGS) $(TPROGS_LDFLAGS) -x c - \
	-o /dev/null 2>/dev/null && echo okay)

ifeq ($(HDR_PROBE),)
$(warning WARNING: Detected possible issues with include path.)
$(warning WARNING: Please install kernel headers locally (make headers_install).)
endif

BTF_LLC_PROBE := $(shell $(LLC) -march=bpf -mattr=help 2>&1 | grep dwarfris)
BTF_PAHOLE_PROBE := $(shell $(BTF_PAHOLE) --help 2>&1 | grep BTF)
BTF_OBJCOPY_PROBE := $(shell $(LLVM_OBJCOPY) --help 2>&1 | grep -i 'usage.*llvm')
BTF_LLVM_PROBE := $(shell echo "int main() { return 0; }" | \
			  $(CLANG) -target bpf -O2 -g -c -x c - -o ./llvm_btf_verify.o; \
			  $(LLVM_READELF) -S ./llvm_btf_verify.o | grep BTF; \
			  /bin/rm -f ./llvm_btf_verify.o)

BPF_EXTRA_CFLAGS += -fno-stack-protector
ifneq ($(BTF_LLVM_PROBE),)
	BPF_EXTRA_CFLAGS += -g
else
ifneq ($(and $(BTF_LLC_PROBE),$(BTF_PAHOLE_PROBE),$(BTF_OBJCOPY_PROBE)),)
	BPF_EXTRA_CFLAGS += -g
	LLC_FLAGS += -mattr=dwarfris
	DWARF2BTF = y
endif
endif
endif

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C ../../ M=$(CURDIR) BPF_SAMPLES_PATH=$(CURDIR)

clean:
	$(MAKE) -C ../../ M=$(CURDIR) clean
	@find $(CURDIR) -type f -name '*~' -delete
	@$(RM) -r $(CURDIR)/libbpf $(CURDIR)/bpftool

$(LIBBPF): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OUTPUT)
# Fix up variables inherited from Kbuild that tools/ build system won't like
	$(MAKE) -C $(LIBBPF_SRC) RM='rm -rf' EXTRA_CFLAGS="$(TPROGS_CFLAGS)" \
		LDFLAGS=$(TPROGS_LDFLAGS) srctree=$(BPF_SAMPLES_PATH)/../../ \
		O= OUTPUT=$(LIBBPF_OUTPUT)/ DESTDIR=$(LIBBPF_DESTDIR) prefix= \
		$@ install_headers

BPFTOOLDIR := $(TOOLS_PATH)/bpf/bpftool
BPFTOOL_OUTPUT := $(abspath $(BPF_SAMPLES_PATH))/bpftool
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool
$(BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) | $(BPFTOOL_OUTPUT)
	$(MAKE) -C $(BPFTOOLDIR) srctree=$(BPF_SAMPLES_PATH)/../../ 		\
		OUTPUT=$(BPFTOOL_OUTPUT)/ bootstrap

$(LIBBPF_OUTPUT) $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(obj)/syscall_nrs.h:	$(obj)/syscall_nrs.s FORCE
	$(call filechk,offsets,__SYSCALL_NRS_H__)

targets += syscall_nrs.s
clean-files += syscall_nrs.h

FORCE:


# Verify LLVM compiler tools are available and bpf target is supported by llc
.PHONY: verify_cmds verify_target_bpf $(CLANG) $(LLC)

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

$(BPF_SAMPLES_PATH)/*.c: verify_target_bpf $(LIBBPF)
$(src)/*.c: verify_target_bpf $(LIBBPF)

libbpf_hdrs: $(LIBBPF)
$(obj)/$(TRACE_HELPERS) $(obj)/$(CGROUP_HELPERS) $(obj)/$(XDP_SAMPLE): | libbpf_hdrs

.PHONY: libbpf_hdrs

$(obj)/xdp_redirect_cpu_user.o: $(obj)/xdp_redirect_cpu.skel.h
$(obj)/xdp_redirect_map_multi_user.o: $(obj)/xdp_redirect_map_multi.skel.h
$(obj)/xdp_redirect_map_user.o: $(obj)/xdp_redirect_map.skel.h
$(obj)/xdp_redirect_user.o: $(obj)/xdp_redirect.skel.h
$(obj)/xdp_monitor_user.o: $(obj)/xdp_monitor.skel.h
$(obj)/xdp_router_ipv4_user.o: $(obj)/xdp_router_ipv4.skel.h

$(obj)/tracex5_kern.o: $(obj)/syscall_nrs.h
$(obj)/hbm_out_kern.o: $(src)/hbm.h $(src)/hbm_kern.h
$(obj)/hbm.o: $(src)/hbm.h
$(obj)/hbm_edt_kern.o: $(src)/hbm.h $(src)/hbm_kern.h

# Override includes for xdp_sample_user.o because $(srctree)/usr/include in
# TPROGS_CFLAGS causes conflicts
XDP_SAMPLE_CFLAGS += -Wall -O2 \
		     -I$(src)/../../tools/include \
		     -I$(src)/../../tools/include/uapi \
		     -I$(LIBBPF_INCLUDE) \
		     -I$(src)/../../tools/testing/selftests/bpf

$(obj)/$(XDP_SAMPLE): TPROGS_CFLAGS = $(XDP_SAMPLE_CFLAGS)
$(obj)/$(XDP_SAMPLE): $(src)/xdp_sample_user.h $(src)/xdp_sample_shared.h

-include $(BPF_SAMPLES_PATH)/Makefile.target

VMLINUX_BTF_PATHS ?= $(abspath $(if $(O),$(O)/vmlinux))				\
		     $(abspath $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux))	\
		     $(abspath ./vmlinux)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))

$(obj)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL)
ifeq ($(VMLINUX_H),)
ifeq ($(VMLINUX_BTF),)
	$(error Cannot find a vmlinux for VMLINUX_BTF at any of "$(VMLINUX_BTF_PATHS)",\
		build the kernel or set VMLINUX_BTF or VMLINUX_H variable)
endif
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(Q)cp "$(VMLINUX_H)" $@
endif

clean-files += vmlinux.h

# Get Clang's default includes on this system, as opposed to those seen by
# '-target bpf'. This fixes "missing" files on some architectures/distros,
# such as asm/byteorder.h, asm/socket.h, asm/sockios.h, sys/cdefs.h etc.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
define get_sys_includes
$(shell $(1) -v -E - </dev/null 2>&1 \
        | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) -dM -E - </dev/null | grep '#define __riscv_xlen ' | sed 's/#define /-D/' | sed 's/ /=/')
endef

CLANG_SYS_INCLUDES = $(call get_sys_includes,$(CLANG))

$(obj)/xdp_redirect_cpu.bpf.o: $(obj)/xdp_sample.bpf.o
$(obj)/xdp_redirect_map_multi.bpf.o: $(obj)/xdp_sample.bpf.o
$(obj)/xdp_redirect_map.bpf.o: $(obj)/xdp_sample.bpf.o
$(obj)/xdp_redirect.bpf.o: $(obj)/xdp_sample.bpf.o
$(obj)/xdp_monitor.bpf.o: $(obj)/xdp_sample.bpf.o
$(obj)/xdp_router_ipv4.bpf.o: $(obj)/xdp_sample.bpf.o

$(obj)/%.bpf.o: $(src)/%.bpf.c $(obj)/vmlinux.h $(src)/xdp_sample.bpf.h $(src)/xdp_sample_shared.h
	@echo "  CLANG-BPF " $@
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(SRCARCH) \
		-Wno-compare-distinct-pointer-types -I$(srctree)/include -I$(srctree)/samples/ebpf \
		-I$(srctree)/samples/bpf -I$(srctree)/tools/include \
		-I$(LIBBPF_INCLUDE) $(CLANG_SYS_INCLUDES) \
		-c $(filter %.bpf.c,$^) -o $@

LINKED_SKELS := xdp_redirect_cpu.skel.h xdp_redirect_map_multi.skel.h \
		xdp_redirect_map.skel.h xdp_redirect.skel.h xdp_monitor.skel.h \
		xdp_router_ipv4.skel.h
clean-files += $(LINKED_SKELS)

xdp_redirect_cpu.skel.h-deps := xdp_redirect_cpu.bpf.o xdp_sample.bpf.o
xdp_redirect_map_multi.skel.h-deps := xdp_redirect_map_multi.bpf.o xdp_sample.bpf.o
xdp_redirect_map.skel.h-deps := xdp_redirect_map.bpf.o xdp_sample.bpf.o
xdp_redirect.skel.h-deps := xdp_redirect.bpf.o xdp_sample.bpf.o
xdp_monitor.skel.h-deps := xdp_monitor.bpf.o xdp_sample.bpf.o
xdp_router_ipv4.skel.h-deps := xdp_router_ipv4.bpf.o xdp_sample.bpf.o

LINKED_BPF_SRCS := $(patsubst %.bpf.o,%.bpf.c,$(foreach skel,$(LINKED_SKELS),$($(skel)-deps)))

BPF_SRCS_LINKED := $(notdir $(wildcard $(src)/*.bpf.c))
BPF_OBJS_LINKED := $(patsubst %.bpf.c,$(obj)/%.bpf.o, $(BPF_SRCS_LINKED))
BPF_SKELS_LINKED := $(addprefix $(obj)/,$(LINKED_SKELS))

$(BPF_SKELS_LINKED): $(BPF_OBJS_LINKED) $(BPFTOOL)
	@echo "  BPF GEN-OBJ " $(@:.skel.h=)
	$(Q)$(BPFTOOL) gen object $(@:.skel.h=.lbpf.o) $(addprefix $(obj)/,$($(@F)-deps))
	@echo "  BPF GEN-SKEL" $(@:.skel.h=)
	$(Q)$(BPFTOOL) gen skeleton $(@:.skel.h=.lbpf.o) name $(notdir $(@:.skel.h=)) > $@

# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
# below we use long chain of commands, clang | opt | llvm-dis | llc,
# to generate final object file. 'clang' compiles the source into IR
# with native target, e.g., x64, arm64, etc. 'opt' does bpf CORE IR builtin
# processing (llvm12) and IR optimizations. 'llvm-dis' converts
# 'opt' output to IR, and finally 'llc' generates bpf byte code.
$(obj)/%.o: $(src)/%.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(BPF_EXTRA_CFLAGS) \
		-I$(obj) -I$(srctree)/tools/testing/selftests/bpf/ \
		-I$(LIBBPF_INCLUDE) \
		-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(SRCARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-fno-asynchronous-unwind-tables \
		-I$(srctree)/samples/bpf/ -I$(srctree)/samples/ebpf/ -include asm_goto_workaround.h \
		-O2 -emit-llvm -Xclang -disable-llvm-passes -c $< -o - | \
		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
		$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@
ifeq ($(DWARF2BTF),y)
	$(BTF_PAHOLE) -J $@
endif
