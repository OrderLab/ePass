
format:
	./scripts/format.sh

build: format
	cmake --build build

kernel: build
	./scripts/gen_kernel.sh

.PHONY: build format kernel
