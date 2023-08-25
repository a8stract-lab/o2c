# on-the-fly-compartment

<!-- To compartment a part of the kernel, developers have to add runtime checks in the source code, recompile and reboot the system.

However, an on-the-fly-compartment is needed, not only for the on demond security, but systems are running cloud native services with very complex dependencies and hardly accept an interrupt to even one services.

The main challenge to compartment a running part of code is that developers have no idea about the system context and status before the compartmentalization is loaded in the system.

So the compartment policies cannot judge the access to origin data is legal or not.

To conquer the problem, we present a on-the-fly compartmentalization framework with eBPF and PKS. based on that, we provided 2 compartment policies for the initialization and working phase.

In the initialization phase, the comparmentalization is just loaded and the life cycle of the origin data is not end, we provided a ML heuristic method to infer the type of origin data according to its content dumped from kernel memory. The method helps system to judge the memory access.

When the life cycle of origin data is end and the framework has record all the allocated memory, the compartment switchs to the working phase, ML heuristic method is not needed, all the memory access can be directly judged by the recorded information.

Noted that the life cycle of an object is normally very short, the heavy ML logging phase will finished sooner or later. -->

To compartmentalize a portion of the kernel, developers must insert runtime checks into the source code, followed by recompilation and a system reboot.

However, the need for on-the-fly compartmentalization is pressing, especially for systems running cloud-native services with intricate dependencies. These systems can scarcely afford an interruption to even a single service. On-demand security is not just a preference; it's a requirement.

The primary challenge in compartmentalizing a running segment of code lies in the developers' lack of insight into the system's context and status before the compartmentalization is implemented. Consequently, the compartment policies are unable to determine whether access to the original data is legitimate.

To overcome this obstacle, we introduce an on-the-fly compartmentalization framework utilizing eBPF and PKS. Within this framework, we have devised two distinct compartment policies for both the initialization and working phases.

During the initialization phase, the compartmentalization is newly loaded, and the lifecycle of the original data has not yet concluded. We employ a machine learning heuristic method to infer the type of original data based on its content extracted from kernel memory. This method enables the system to make informed judgments about memory access.

Once the lifecycle of the original data ends and the framework has recorded all allocated memory, the compartment switches to the working phase. In this stage, the machine learning heuristic method becomes unnecessary, as all memory access can be directly assessed using the recorded information.

It's important to note that the lifecycle of an object is typically brief, meaning the resource-intensive machine learning logging phase will eventually conclude.

## ML heuristic method: 

- data set collection: in [ebpf-project](./ebpf-project/README.md), a eBPF program to dump allocation site and content
- ML alogrithms and Model training: ?


**毫无疑问，object在kfree时内容是最全面的，但是大概率和函数使用中的内容是不同的，既然已经打算做log&audition，不如在函数指令访问的时候只记录一个log，在object释放的时候，因为已经知道了具体的类型再进行audition （解决了不同阶段采样数据不同的问题）**