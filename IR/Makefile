build: format
	cmake --build build

buildall: genctor
	cmake --build build

format:
	./scripts/format.sh

genctor:
	./scripts/gen_insn_ctor.py
	./scripts/format.sh

kernel: build
	./scripts/gen_kernel.sh

.PHONY: build format kernel
