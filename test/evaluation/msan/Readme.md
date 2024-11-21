# Memory Sanitizer

Wrap the memory access. Only allow reading the written area.

## Evaluation Metric:
- How many bugs in real world projects and online code do you find using the msan?
- What is the runtime overhead?

## Expectation:
- Base: Collected + handcraft 5 programs pass the verifier but the bug was captured during runtime
- Good: Collected + handcraft 10 program pass the verifier but the bug was captured during runtime
- Ideal: Collected + handcraft 15 program pass the verifier but the bug was captured during runtime, runtime overhead lower comparing to other work
