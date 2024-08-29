build:
	cmake --build build

run: build
	build/read tests/${NAME}.o

kernel: build
	./scripts/gen_kernel.sh

format:
	./scripts/format.sh

.PHONY: build run format
