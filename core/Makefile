build: format
	cmake --build build

buildall: genctor
	cmake --build build

format:
	rm -f tests/vmlinux.h
	./scripts/format.sh

genctor:
	./scripts/gen_insn_ctor.py
	./scripts/format.sh

kernel: build
	./scripts/gen_kernel.sh

read: build
	build/read tests/output/${NAME}.o prog

readlog: build
	build/readlog tests/log/${NAME}.txt

test_kern: build
	build/test_kern

.PHONY: build format kernel readlog read genctor
