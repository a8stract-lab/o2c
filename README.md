# on-the-fly-compartment

https://docs.google.com/presentation/d/1fVZlfJtHDvP3GEj31bMvFD9OVvtb9nGEMj6EDqXMRcI/edit#slide=id.p

## Insight: 

on-the-fly kernel compartmentalization can quickly remediate the 0-day hotspots (i.e. 0-day Vulnerability Highly Exposed Areas), 2 research questions are solved,

1. what happened in the past, before the compartmentalization, nothing is recorded for the runtime check, we design a ML-heuristic audition to solve it.
2. what for runtime check, cannot accurately decide the legal access range of an instruction, we use an conservative legal access set

it can work on the fly, and no need special hardware features as other solution did.

## Introduction

On-the-fly security has become an essential requirement in the realm of hotpatching and vulnerability prevention, as it allows for the swift rectification of n-day security issues while maintaining service functionality. As security threats escalate in severity, it is imperative that countermeasures against 0-day threats also adopt an on-the-fly approach.

On-the-fly kernel compartmentalization serves as a potent tool to promptly address vulnerabilities in 0-day hotspots (i.e., areas highly exposed to 0-day vulnerabilities), ensuring the system continues to operate correctly. However, this approach presents three significant challenges that need to be addressed:

- Integrating the compartmentalization framework during runtime.
- Determining the parameters for runtime checks. Typically, the framework scrutinizes the target addresses or object types of memory access instructions. However, runtime binaries often lack the necessary type information to accurately determine the legal access range of an instruction, while previous solutions have relied on hardware features or compile-time instrumentation.
- Understanding the context before the compartmentalization, as no records pertaining to kernel objects are available for runtime checks.


To address these challenges, we propose the following solution:

- Utilization of eBPF, an in-kernel virtual machine, to establish a Software Fault Isolation (SFI) framework. Because eBPF allows for efficient and safe code insertion into the kernel.
- Adoption of a conservative access range for runtime checks parameters, encompassing potential types and ranges of functions or compartments.
- Implementation of two distinct compartment policies for both the initialization and working phases:
    - During the initialization phase, the compartmentalization is newly implemented. The lifecycle of the original data is still ongoing. We use a machine learning heuristic method. This method deduces the type of original data from its content in the kernel memory. It helps in making informed decisions about memory access.
    - As the lifecycle of the original data ends, the framework logs all allocated memory details. The compartment then moves to the working phase. In this phase, the machine learning heuristic method is not needed. Memory access evaluations are done directly using the recorded data.

It's important to note that an object's lifecycle is generally short-lived (> 96% shorter than 1s), meaning the initialization phase will not last long.






## ML heuristic method: 

- data set collection: in [ebpf-project](./ebpf-project/README.md), a eBPF program to dump allocation site and content
- ML alogrithms and Model training: ?


**毫无疑问，object在kfree时内容是最全面的，但是大概率和函数使用中的内容是不同的，既然已经打算做log&audition，不如在函数指令访问的时候只记录一个log，在object释放的时候，因为已经知道了具体的类型再进行audition （解决了不同阶段采样数据不同的问题）**

- **how to get all accessed buddy memory in the function? static analysis seems cannot do that**



<!-- 其中static/dynamic analyzer负责对内核代码和内核运行时binary进行静态和动态分析,该模块负责1.提炼出需要部署compartment策略的指令，2.提炼出对应指令所需的安全策略，3. 提炼出安全策略的优化提升系统性能。

ML sampler借助了analyzer提炼出的指令集合，在内核中采样ML模型需要的训练数据及标签，经过训练生成ML model。

policy generator将analyzer输出的工作阶段的安全策略和ML model产生的审计策略转化为eBPF 程序，并传递给phase0和1隔离不可信compartment


phase0 是整个系统的过渡阶段，此时compartment策略已经安装进内核，但系统中仍有生命周期未结束的原始数据，这个阶段是之前工作无法实现on-the-fly compartment的主要原因。

在这个阶段，\sys framework同时采用了两种compartment策略，首先working policy生效，检测当前使用数据是否合法，如非法则可能是载入前分配的未记录数据，此时\sys framework执行ML heuristic audition安全策略，dump出当前访问数据对象的内容，识别该访问是否合法。

phase1阶段是正常工作阶段，此时\sys载入前分配的数据生命周期结束，因此系统中使用的数据对象都已被记录，故\sys关闭ML audition安全策略，仅保留working policy -->


<!-- outline

----------------------------------------
已经有了三类指令，我们需要使用静态分析三类指令分配指定的安全检查。静态分析使用了当下较为成熟的LLVMIR静态分析

对于第二类内存访问指令，\sys需要知道当前访问的目标地址是否合法，首先compart毫无疑问能够自由访问自己的代码、数据、堆和栈
内核堆的使用类型较为复杂，而且compart和内核存在共享的heap object，我们借助分治方案进行逐一解决

内核及compart使用的object主要由buddy,slab,vmalloc三种堆分配器分配
首先，buddy分配器管理了系统所有物理内存，以页为粒度分配和释放内存，compart的私有堆没有单独的buddy alloctor，而是用BPF hash table标记分配的页的地址，在运行时进行判断。
因此\sys 需要使用静态分析确定compart使用的buddy object类型和分配地址
其次，slab分配器负责分配小于页大小的内存object，它由若干个slab cache组成，每个slab cache从buddy分配器中拿到多个页的内存，并划分为相同大小的object进行分配。
内核中通常包括单独分配一种类型object的专用slab cache，和分配相同大小类型不同的general slab cache。
Comparts的私有栈包括属于compart数据结构类型的专用slab cache，和compart其他数据对象使用的general slab cache，与原本内核的slab cache进行区分
\sys 运行时主要检查当前object所在的cache是否属于compart或是kernel与compart的共享cache。
因此\sys需要使用静态分析确定使用的slab object类型和分配地址
最后，vmalloc分配器用于分配大块的地址空间连续的内存，同样从buddy分配器获取内存，但是通过构建页表在vmalloc区域分配地址空间连续的内存。由于vmalloc由专门数据对象记录object地址和分配函数，
因此compart只需要在运行时检查分配该地址是否由compart分配即可。
因此\sys只需要使用静态分析确定compart使用的vmalloc的分配地址即可


总而言之，我们借助了typm,xxx~\cite{}的静态分析技术,分析compart使用的object类型和分配地址，值得注意的是，对于某些类型不明确的buffer object，我们将其额外赋予一个类型帮助运行时检查。
对于vmalloc，我们使用了一个dummy llvm pass找到调用函数，并在kernel runtime binary中确定地址。
对于任意一个给定的内存访问，检查的过程如listing所示，runtime分别判断访问目标地址是否属于buddy，slab，vmalloc，stack和global，对于后三者，因为静态分析可以得到确定结果，如果判断失败则说明发生了攻击行为
对于buddy和slab object，因为存在C3,即存在compartmentalization载入前分配的未被记录的object，因此需要section~\ref{}的机器学习算法进行判断 -->




<!-- 我们针对eBPF framework的不支持浮点计算、不支持过多指令的缺点，选取合适的机器学习算法，并将该模型修改为eBPF程序植入内核中 -->

<!-- the goal of object profiler is to collect labeled data from running kernel.
we construct an eBPF program to achieve the goal.
However, there are 2 challenges, 1. how to get the object type on-the-fly, 2. when to profile the object content, because there are multiple memory accesses in the period from the data object allocation to free.
below are solutions.

the type of the data object serves as the label of training data, we can derive the type from the caller (call trace) of the object allocation site.
after object allocation, the caller usually assign the specific type for the memory object.
we can reuse the object static analysis from code analyzer to deduce the object type from the caller function.
Once we have the object type, we can judge if the type can be accessed by the compart according to the analyze result in section~\ref{sec:analyzer}.

there are multiple memory access in the object's lifetime, we decide to collect the object's content only once at the free site.
Because when the object is just allocated and accessed, the content of the object is all 0 or mostly 0, can not be distinguished from other objects.
And in the whole life cycle, the object's content keeps changing, it is difficult to use only one model to predict one object's type but at the different access site.
only at the free site, the content of the object is the most complete and no longer change, and be able to distinguish with other objects, and proper to train a stable machine learning model.

In summary, we synthesize the insights above, and generate a eBPF program to hooking the memory allocation and free sites, like \Code{kmalloc/kfree}, \Code{mm_page_alloc/free}.
in the object allocation sites, we record the address and caller of the allocation object.
in the object free sites, we find the caller according to the object address, dump the content of the object, and record the object's type and content for futher training.
According to the experiments results, a 5-minute sample, which can collect about 6.5 million data objects, about 4GB in total, is enough for training.
Note that for the label balance, during the sampling there should be enough compart related objects, we can get them by executing a set of benchmark programs generated by object-oriented fuzzing techniques, we will discuss it section~\ref{sec:discussion} -->


<!-- In this section, we present a series of analysis and experiments to evaluate the security of the compartmentalization, the ML model, and the effectivness of the system and compare to the related work.


To evaluate the effective of the compartmentalization, we first analyze the compartmentalization's countermeasures against the attack vectors assumed in the security model. 
after that we collect about 170 publically available vulnerabilities in ipv6, sched, netfilter modules from CVEs and syzkaller, and evaluate the \sys's effectiveness facing the real world vulnerablities.

For control flow integrity, attackers may exploit vulnerablities in the compartment to hijack the control flow, and corrupt the entire system by launching code reuse attacks in the kernel.
To hijack the control flow, attackers can either change the indirect call/jump target(ICT), or manipulating the return value in the kernel call stack to launch return-orientied programming(ROP) attacks.
\sys provides SFI framework and compartmentalization policy, all the target addresses of call indirect calls and jumps will be checked before executing.
also, all the memory write instructions are under the montior, the return value in the kernel call stack cannot be modified.
in summary, attackers cannot break the control flow integrity, and corrupt the kernel.

For data integrity, attackers may directly modify the kernel code, global data, stack, and sensitive objects to launch data only attacks, which can also corrupt the entire kernel.
Compartmentalization in \sys have a complete solution to all these cases, because all the memory writes are under monitor, and their access range is limited.
in detail, for kernel code, apparently they are protected by WxorX access control policy, compartments are not allowed to break through the protection by modifying the CPU working status or the page table.
for kernel gloabl data, compartments are only allow to write their own global data. 
For kernel stack, \sys provides each compartment a private stack, compartments can only use their own stack, no access is allowed for the kernel stack.
For kernel sensitive objects, compartments mainly use their own private heap, and the access to the shared object is strictly limited.
in summary, attackers cannot break the data integrity.

for argument when the compartments call kernel functions, and return values when the compartment return to the kernel. 
\sys provides a flexible and simple framework, system administrator can check on any functions according to the annotations for the arguments or return value.
malicious compartment cannot break the kernel.

For the real world vulnerabilities and exploitations, according to our anlysis to the 170 samples, currently attacks mainly focus on the memory related, especially kernel heap vulnerabilities, e.g. CVE-xxxx-xxxx, overlapping the vulnerable and payload objects, and construct a control flow hijack attack.
or dirtycred, launching data-only attack to modify the privilege level of attacking process.
\sys compartmentalization can monitor all the memory access and indirect control flow target, 
attackers can neither bypass the contorl flow integrity or modify the sensitive kernel objects.
so \sys can fully defend the real world vulnerabilties. -->





performance overhead.

In this section, we are aiming to evaluate the performance overhead of \sys.
We have designed a series experiments to answer the following research questions,
1. what is the performance overhead to the system when isolating untrusted kernel modules into compartments, do quality of functions in the compartment effect?
2. what is the performance overhead to the compartment module, do the quality of functions in the compartment effect? How does it compare to related work?
3. how long should the phase 0 machine learning audition lasted?

experiment setup

Frist of all, we choose 3 modules for evaluating \sys, 
They come from the net subsystem, the most vulnerable subsystem in the kernel, accounting for more than 20% of all vulnerabilities
more than 100 recent 3 year vulnerabilities have been found in these modules,
they are ipv6 modules for parsing IP protocal version 6 in the linux net stack, 
netfilter modules for filtering network packets and performing network address translation (NAT),
and sched for network packet scheduling and traffic control (QoS, Quality of Service).

For the first research question, we want to find the performance overhead to the system caused by \sys, so we design experiments by running kernel benchmarks alongside with different compartments, and compare the overhead with vanilla/stock kernel
For benchmark programs, we choose the classic LMBench to evaluate the kernel core operations.
We also choose phoronix test suites to evaluate the real world applications, include, perf, apache/nginx-ipv4, git, sqlite, redis, xz compression, and kernel compilation.
For the compartments, We've chosen three modules, and for each of them we've built two separate compartments, one that isolates just one of the module's vulnerable files, and one that isolates the entire module.
the vulnerable files are ip6_output.c in ipv6, nf_tables_api.c in netfilter, cls_route.c in sched, they include, x, y, z eBPF hooks.
and the module ipv6, netfilter, sched, their compartment include x1, y1, z1 eBPF hooks.
Because in phase 0, there is addtional ML audition in \sys compartmentalizaiton, 
so we test each compartment when are using ML audition and not using ML audition.

For the second research question, we want to find the performance overhead to the comparted modules, so we design experiments by testing the its main ser ice's performance loss.
So we choose apache Bench to test the ipv6 compartment's performance loss on request per second and transfer rate.
and like the first experiment, we test 2 compartments, when using the ML audition and not using it.