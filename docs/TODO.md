# TODOs

- [ ] Huge tests in falco
- [ ] bpf-to-bpf calls
- [ ] Full test suite

- SSA construction was missing fallthrough predecessors (phis lost their entry-edge operand).
- Liveness live_out_at_statement didn't stop at the defining statement — the critical fix that made register allocation converge.