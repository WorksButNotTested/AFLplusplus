#include "frida-gumjs.h"

#include "debug.h"

#include "ctx.h"

#if defined(__x86_64__)

  #define X86_REG_8L(LABEL, REG)  \
    case LABEL: {                 \
                                  \
      return REG & GUM_INT8_MASK; \
                                  \
    }

  #define X86_REG_8H(LABEL, REG)          \
    case LABEL: {                         \
                                          \
      return (REG & GUM_INT16_MASK) >> 8; \
                                          \
    }

  #define X86_REG_16(LABEL, REG)     \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT16_MASK); \
                                     \
    }

  #define X86_REG_32(LABEL, REG)     \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT32_MASK); \
                                     \
    }

  #define X86_REG_64(LABEL, REG) \
    case LABEL: {                \
                                 \
      return (REG);              \
                                 \
    }

  #define X86_REG_REG(LABEL, REG) \
    case LABEL: {                 \
                                  \
      return (REG);               \
                                  \
    }

gsize ctx_read_reg(GumX64CpuContext *ctx, x86_reg reg) {

  switch (reg) {

    X86_REG_8L(X86_REG_AL, ctx->rax)
    X86_REG_8L(X86_REG_BL, ctx->rbx)
    X86_REG_8L(X86_REG_CL, ctx->rcx)
    X86_REG_8L(X86_REG_DL, ctx->rdx)
    X86_REG_8L(X86_REG_SPL, ctx->rsp)
    X86_REG_8L(X86_REG_BPL, ctx->rbp)
    X86_REG_8L(X86_REG_SIL, ctx->rsi)
    X86_REG_8L(X86_REG_DIL, ctx->rdi)
    X86_REG_8L(X86_REG_R8B, ctx->r8)
    X86_REG_8L(X86_REG_R9B, ctx->r9)
    X86_REG_8L(X86_REG_R10B, ctx->r10)
    X86_REG_8L(X86_REG_R11B, ctx->r11)
    X86_REG_8L(X86_REG_R12B, ctx->r12)
    X86_REG_8L(X86_REG_R13B, ctx->r13)
    X86_REG_8L(X86_REG_R14B, ctx->r14)
    X86_REG_8L(X86_REG_R15B, ctx->r15)

    X86_REG_8H(X86_REG_AH, ctx->rax)
    X86_REG_8H(X86_REG_BH, ctx->rbx)
    X86_REG_8H(X86_REG_CH, ctx->rcx)
    X86_REG_8H(X86_REG_DH, ctx->rdx)

    X86_REG_16(X86_REG_AX, ctx->rax)
    X86_REG_16(X86_REG_BX, ctx->rbx)
    X86_REG_16(X86_REG_CX, ctx->rcx)
    X86_REG_16(X86_REG_DX, ctx->rdx)
    X86_REG_16(X86_REG_SP, ctx->rsp)
    X86_REG_16(X86_REG_BP, ctx->rbp)
    X86_REG_16(X86_REG_DI, ctx->rdi)
    X86_REG_16(X86_REG_SI, ctx->rsi)
    X86_REG_16(X86_REG_R8W, ctx->r8)
    X86_REG_16(X86_REG_R9W, ctx->r9)
    X86_REG_16(X86_REG_R10W, ctx->r10)
    X86_REG_16(X86_REG_R11W, ctx->r11)
    X86_REG_16(X86_REG_R12W, ctx->r12)
    X86_REG_16(X86_REG_R13W, ctx->r13)
    X86_REG_16(X86_REG_R14W, ctx->r14)
    X86_REG_16(X86_REG_R15W, ctx->r15)

    X86_REG_32(X86_REG_EAX, ctx->rax)
    X86_REG_32(X86_REG_EBX, ctx->rbx)
    X86_REG_32(X86_REG_ECX, ctx->rcx)
    X86_REG_32(X86_REG_EDX, ctx->rdx)
    X86_REG_32(X86_REG_ESP, ctx->rsp)
    X86_REG_32(X86_REG_EBP, ctx->rbp)
    X86_REG_32(X86_REG_ESI, ctx->rsi)
    X86_REG_32(X86_REG_EDI, ctx->rdi)
    X86_REG_32(X86_REG_R8D, ctx->r8)
    X86_REG_32(X86_REG_R9D, ctx->r9)
    X86_REG_32(X86_REG_R10D, ctx->r10)
    X86_REG_32(X86_REG_R11D, ctx->r11)
    X86_REG_32(X86_REG_R12D, ctx->r12)
    X86_REG_32(X86_REG_R13D, ctx->r13)
    X86_REG_32(X86_REG_R14D, ctx->r14)
    X86_REG_32(X86_REG_R15D, ctx->r15)
    X86_REG_32(X86_REG_EIP, ctx->rip)

    X86_REG_64(X86_REG_RAX, ctx->rax)
    X86_REG_64(X86_REG_RCX, ctx->rcx)
    X86_REG_64(X86_REG_RDX, ctx->rdx)
    X86_REG_64(X86_REG_RBX, ctx->rbx)
    X86_REG_64(X86_REG_RSP, ctx->rsp)
    X86_REG_64(X86_REG_RBP, ctx->rbp)
    X86_REG_64(X86_REG_RSI, ctx->rsi)
    X86_REG_64(X86_REG_RDI, ctx->rdi)
    X86_REG_64(X86_REG_R8, ctx->r8)
    X86_REG_64(X86_REG_R9, ctx->r9)
    X86_REG_64(X86_REG_R10, ctx->r10)
    X86_REG_64(X86_REG_R11, ctx->r11)
    X86_REG_64(X86_REG_R12, ctx->r12)
    X86_REG_64(X86_REG_R13, ctx->r13)
    X86_REG_64(X86_REG_R14, ctx->r14)
    X86_REG_64(X86_REG_R15, ctx->r15)
    X86_REG_64(X86_REG_RIP, ctx->rip)

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

GumCpuReg ctx_get_reg(x86_reg reg) {

  switch (reg) {

    X86_REG_REG(X86_REG_AL, GUM_REG_RAX)
    X86_REG_REG(X86_REG_BL, GUM_REG_RBX)
    X86_REG_REG(X86_REG_CL, GUM_REG_RCX)
    X86_REG_REG(X86_REG_DL, GUM_REG_RDX)
    X86_REG_REG(X86_REG_SPL, GUM_REG_RSP)
    X86_REG_REG(X86_REG_BPL, GUM_REG_RBP)
    X86_REG_REG(X86_REG_SIL, GUM_REG_RSI)
    X86_REG_REG(X86_REG_DIL, GUM_REG_RDI)
    X86_REG_REG(X86_REG_R8B, GUM_REG_R8)
    X86_REG_REG(X86_REG_R9B, GUM_REG_R9)
    X86_REG_REG(X86_REG_R10B, GUM_REG_R10)
    X86_REG_REG(X86_REG_R11B, GUM_REG_R11)
    X86_REG_REG(X86_REG_R12B, GUM_REG_R12)
    X86_REG_REG(X86_REG_R13B, GUM_REG_R13)
    X86_REG_REG(X86_REG_R14B, GUM_REG_R14)
    X86_REG_REG(X86_REG_R15B, GUM_REG_R15)

    X86_REG_REG(X86_REG_AH, GUM_REG_RAX)
    X86_REG_REG(X86_REG_BH, GUM_REG_RBX)
    X86_REG_REG(X86_REG_CH, GUM_REG_RCX)
    X86_REG_REG(X86_REG_DH, GUM_REG_RDX)

    X86_REG_REG(X86_REG_AX, GUM_REG_RAX)
    X86_REG_REG(X86_REG_BX, GUM_REG_RBX)
    X86_REG_REG(X86_REG_CX, GUM_REG_RCX)
    X86_REG_REG(X86_REG_DX, GUM_REG_RDX)
    X86_REG_REG(X86_REG_SP, GUM_REG_RSP)
    X86_REG_REG(X86_REG_BP, GUM_REG_RBP)
    X86_REG_REG(X86_REG_DI, GUM_REG_RDI)
    X86_REG_REG(X86_REG_SI, GUM_REG_RSI)
    X86_REG_REG(X86_REG_R8W, GUM_REG_R8)
    X86_REG_REG(X86_REG_R9W, GUM_REG_R9)
    X86_REG_REG(X86_REG_R10W, GUM_REG_R10)
    X86_REG_REG(X86_REG_R11W, GUM_REG_R11)
    X86_REG_REG(X86_REG_R12W, GUM_REG_R12)
    X86_REG_REG(X86_REG_R13W, GUM_REG_R13)
    X86_REG_REG(X86_REG_R14W, GUM_REG_R14)
    X86_REG_REG(X86_REG_R15W, GUM_REG_R15)

    X86_REG_REG(X86_REG_EAX, GUM_REG_RAX)
    X86_REG_REG(X86_REG_EBX, GUM_REG_RBX)
    X86_REG_REG(X86_REG_ECX, GUM_REG_RCX)
    X86_REG_REG(X86_REG_EDX, GUM_REG_RDX)
    X86_REG_REG(X86_REG_ESP, GUM_REG_RSP)
    X86_REG_REG(X86_REG_EBP, GUM_REG_RBP)
    X86_REG_REG(X86_REG_ESI, GUM_REG_RSI)
    X86_REG_REG(X86_REG_EDI, GUM_REG_RDI)
    X86_REG_REG(X86_REG_R8D, GUM_REG_R8)
    X86_REG_REG(X86_REG_R9D, GUM_REG_R9)
    X86_REG_REG(X86_REG_R10D, GUM_REG_R10)
    X86_REG_REG(X86_REG_R11D, GUM_REG_R11)
    X86_REG_REG(X86_REG_R12D, GUM_REG_R12)
    X86_REG_REG(X86_REG_R13D, GUM_REG_R13)
    X86_REG_REG(X86_REG_R14D, GUM_REG_R14)
    X86_REG_REG(X86_REG_R15D, GUM_REG_R15)
    X86_REG_REG(X86_REG_EIP, GUM_REG_RIP)

    X86_REG_REG(X86_REG_RAX, GUM_REG_RAX)
    X86_REG_REG(X86_REG_RCX, GUM_REG_RCX)
    X86_REG_REG(X86_REG_RDX, GUM_REG_RDX)
    X86_REG_REG(X86_REG_RBX, GUM_REG_RBX)
    X86_REG_REG(X86_REG_RSP, GUM_REG_RSP)
    X86_REG_REG(X86_REG_RBP, GUM_REG_RBP)
    X86_REG_REG(X86_REG_RSI, GUM_REG_RSI)
    X86_REG_REG(X86_REG_RDI, GUM_REG_RDI)
    X86_REG_REG(X86_REG_R8, GUM_REG_R8)
    X86_REG_REG(X86_REG_R9, GUM_REG_R9)
    X86_REG_REG(X86_REG_R10, GUM_REG_R10)
    X86_REG_REG(X86_REG_R11, GUM_REG_R11)
    X86_REG_REG(X86_REG_R12, GUM_REG_R12)
    X86_REG_REG(X86_REG_R13, GUM_REG_R13)
    X86_REG_REG(X86_REG_R14, GUM_REG_R14)
    X86_REG_REG(X86_REG_R15, GUM_REG_R15)
    X86_REG_REG(X86_REG_RIP, GUM_REG_RIP)

    X86_REG_REG(X86_REG_INVALID, GUM_REG_NONE)

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

gsize ctx_get_shift(x86_reg reg) {

  switch (reg) {

    case X86_REG_AL:
    case X86_REG_BL:
    case X86_REG_CL:
    case X86_REG_DL:
    case X86_REG_SPL:
    case X86_REG_BPL:
    case X86_REG_SIL:
    case X86_REG_DIL:
    case X86_REG_R8B:
    case X86_REG_R9B:
    case X86_REG_R10B:
    case X86_REG_R11B:
    case X86_REG_R12B:
    case X86_REG_R13B:
    case X86_REG_R14B:
    case X86_REG_R15B:
      return 0;

    case X86_REG_AH:
    case X86_REG_BH:
    case X86_REG_CH:
    case X86_REG_DH:
      return 8;

    case X86_REG_AX:
    case X86_REG_BX:
    case X86_REG_CX:
    case X86_REG_DX:
    case X86_REG_SP:
    case X86_REG_BP:
    case X86_REG_DI:
    case X86_REG_SI:
    case X86_REG_R8W:
    case X86_REG_R9W:
    case X86_REG_R10W:
    case X86_REG_R11W:
    case X86_REG_R12W:
    case X86_REG_R13W:
    case X86_REG_R14W:
    case X86_REG_R15W:
      return 0;

    case X86_REG_EAX:
    case X86_REG_EBX:
    case X86_REG_ECX:
    case X86_REG_EDX:
    case X86_REG_ESP:
    case X86_REG_EBP:
    case X86_REG_ESI:
    case X86_REG_EDI:
    case X86_REG_R8D:
    case X86_REG_R9D:
    case X86_REG_R10D:
    case X86_REG_R11D:
    case X86_REG_R12D:
    case X86_REG_R13D:
    case X86_REG_R14D:
    case X86_REG_R15D:
    case X86_REG_EIP:
      return 0;

    case X86_REG_RAX:
    case X86_REG_RCX:
    case X86_REG_RDX:
    case X86_REG_RBX:
    case X86_REG_RSP:
    case X86_REG_RBP:
    case X86_REG_RSI:
    case X86_REG_RDI:
    case X86_REG_R8:
    case X86_REG_R9:
    case X86_REG_R10:
    case X86_REG_R11:
    case X86_REG_R12:
    case X86_REG_R13:
    case X86_REG_R14:
    case X86_REG_R15:
    case X86_REG_RIP:
      return 0;

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

gsize ctx_get_mask(x86_reg reg) {

  switch (reg) {

    case X86_REG_AL:
    case X86_REG_BL:
    case X86_REG_CL:
    case X86_REG_DL:
    case X86_REG_SPL:
    case X86_REG_BPL:
    case X86_REG_SIL:
    case X86_REG_DIL:
    case X86_REG_R8B:
    case X86_REG_R9B:
    case X86_REG_R10B:
    case X86_REG_R11B:
    case X86_REG_R12B:
    case X86_REG_R13B:
    case X86_REG_R14B:
    case X86_REG_R15B:
      return GUM_INT8_MASK;

    case X86_REG_AH:
    case X86_REG_BH:
    case X86_REG_CH:
    case X86_REG_DH:
      return GUM_INT8_MASK;

    case X86_REG_AX:
    case X86_REG_BX:
    case X86_REG_CX:
    case X86_REG_DX:
    case X86_REG_SP:
    case X86_REG_BP:
    case X86_REG_DI:
    case X86_REG_SI:
    case X86_REG_R8W:
    case X86_REG_R9W:
    case X86_REG_R10W:
    case X86_REG_R11W:
    case X86_REG_R12W:
    case X86_REG_R13W:
    case X86_REG_R14W:
    case X86_REG_R15W:
      return GUM_INT16_MASK;

    case X86_REG_EAX:
    case X86_REG_EBX:
    case X86_REG_ECX:
    case X86_REG_EDX:
    case X86_REG_ESP:
    case X86_REG_EBP:
    case X86_REG_ESI:
    case X86_REG_EDI:
    case X86_REG_R8D:
    case X86_REG_R9D:
    case X86_REG_R10D:
    case X86_REG_R11D:
    case X86_REG_R12D:
    case X86_REG_R13D:
    case X86_REG_R14D:
    case X86_REG_R15D:
    case X86_REG_EIP:
      return GUM_INT32_MASK;

    case X86_REG_RAX:
    case X86_REG_RCX:
    case X86_REG_RDX:
    case X86_REG_RBX:
    case X86_REG_RSP:
    case X86_REG_RBP:
    case X86_REG_RSI:
    case X86_REG_RDI:
    case X86_REG_R8:
    case X86_REG_R9:
    case X86_REG_R10:
    case X86_REG_R11:
    case X86_REG_R12:
    case X86_REG_R13:
    case X86_REG_R14:
    case X86_REG_R15:
    case X86_REG_RIP:
      return 0;

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

#endif

