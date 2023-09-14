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