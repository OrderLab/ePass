build:
	cmake --build build

run: build
	build/read tests/${NAME}.o

format:
	./scripts/format.sh

.PHONY: build run format
