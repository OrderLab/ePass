# Configuration Management

## Core Framework Options (could be access by the kernel)

Should be more customizable.

## libbpf Option Interface

Should be safer, limited.

`enable_passes`: What passes to enable

`epass config`: some flag.

Full option as a string.

Example:

```
enable_passes=adding_couner(limit=1000),masking(opt=xxx,opt2=xxc)
epass_config=debug,enable_coalesce,print=bpf
```
