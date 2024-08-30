build:
	cmake --build build

kernel: build
	./scripts/gen_kernel.sh

format:
	./scripts/format.sh

.PHONY: build format
