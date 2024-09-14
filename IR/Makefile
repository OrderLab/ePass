
format:
	./scripts/format.sh

genctor:
	./scripts/gen_insn_ctor.py
	./scripts/format.sh

build: genctor
	cmake --build build

kernel: build
	./scripts/gen_kernel.sh

.PHONY: build format kernel
