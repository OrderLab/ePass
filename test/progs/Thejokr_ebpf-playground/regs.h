#pragma once
#ifndef OBSERVER_BPF_REGS_H
#define OBSERVER_BPF_REGS_H

#include <linux/ptrace.h>

// Mapping of Linux's struct pt_regs* to Go's ABIInternal registers (https://go.dev/s/regabi)
#if defined(__TARGET_ARCH_x86) && !defined(__i386__)
#define GOABI_R0(x) ((x)->rax)
#define GOABI_R1(x) ((x)->rbx)
#define GOABI_R2(x) ((x)->rcx)
#define GOABI_R3(x) ((x)->rdi)
#define GOABI_R4(x) ((x)->rsi)
#define GOABI_R5(x) ((x)->r8)
#define GOABI_R6(x) ((x)->r9)
#define GOABI_R7(x) ((x)->r10)
#define GOABI_R8(x) ((x)->r11)

#elif defined(__TARGET_ARCH_arm64)
#define AARCH64_REG(x, N) (((const struct user_pt_regs *)(x))->regs[N])
#define GOABI_R0(x) AARCH64_REG(x, 0)
#define GOABI_R1(x) AARCH64_REG(x, 1)
#define GOABI_R2(x) AARCH64_REG(x, 2)
#define GOABI_R3(x) AARCH64_REG(x, 3)
#define GOABI_R4(x) AARCH64_REG(x, 4)
#define GOABI_R5(x) AARCH64_REG(x, 5)
#define GOABI_R6(x) AARCH64_REG(x, 6)
#define GOABI_R7(x) AARCH64_REG(x, 7)
#define GOABI_R8(x) AARCH64_REG(x, 8)

#else
#error this example only supports x86-64 and arm64
#endif

#endif  // OBSERVER_BPF_REGS_H