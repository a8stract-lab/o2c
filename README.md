# on-the-fly-compartment


**Add introduction here!**

## directories
- bin-project: identify instructions for compartmentalization enforcement
- deployment-projects: scripts for eBPF program generation
- ebpf-project: other eBPF programs for statistics
- evaluation-project: performance evaluation
- ml-project: sample ML training
- kernel: modified kernel for on-the-fly compartmentalization, eBPF programs see kernel/samples/eBPF.
    - comp_*_sample, dump the objects from running kernel
    - comp_*_working, compartmentalize the untrusted driver
    - comp_*_working1, compartmentalizes part of untrusted driver, rather than the entire driver.


<!-- `!!!!!!!!!!!!  git push new-origin lss !!!!!!!!!!!!!` -->
<!-- origin will push to the on-the-fly-compartment.git -->