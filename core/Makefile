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
	epasstool -m read -p tests/output/${NAME}.o -s prog --gopt verbose=3

readlog: build
	epasstool -m readlog -p tests/log/${NAME}.txt --gopt verbose=3

test: build
	./build/test_list
	./build/test_hashtable

.PHONY: build format kernel readlog read genctor test
