# Instruction Counter

Leverage the verifier’s insn_processed to allow complex programs to pass the verifier.

## Evaluation Metric:
- How many existing programs could pass the verifier with this pass? Do they throw an exception during runtime?
- How many instructions are added? (Overhead)
- What are different modes (performance mode/accurate mode) and their trade-offs?

## Expectation:

- Base: Collected + handcraft 5 programs with exceeding instruction limit. <30% overhead on average.
- Good: Collected + handcraft 10 program <10% overhead on average. Performance mode should be <5%.
- Ideal: Collected + handcraft 15 program <5% overhead on average, performance mode <2%.
