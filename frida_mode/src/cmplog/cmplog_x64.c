#include "frida-gumjs.h"

#include "debug.h"
#include "cmplog.h"

#include "ctx.h"
#include "frida_cmplog.h"
#include "util.h"

#if defined(__x86_64__)

typedef struct {

  x86_op_type type;
  uint8_t     size;

  union {

    x86_op_mem mem;
    x86_reg    reg;
    int64_t    imm;

  };

} cmplog_ctx_t;

typedef struct {

  cmplog_ctx_t operand1;
  cmplog_ctx_t operand2;

} cmplog_pair_ctx_t;

static void cmplog_cmp_sub_update_inst_func(GumStalkerOutput *output,
                                            gboolean          is_call) {

  g_assert(offsetof(struct cmp_map, headers) == 0);
  g_assert(sizeof(struct cmp_header) == 8);
  g_assert(CMP_MAP_W == 65536);
  g_assert(CMP_MAP_H == 32);
  g_assert(sizeof(struct cmp_operands) == 32);
  g_assert(offsetof(struct cmp_operands, v0) == 0);

  // RDI = op1, RSI = op2, RDX = address, RCX = size
  GumX86Writer *cw = output->writer.x86;

  gum_x86_writer_put_push_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RBX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R8);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R9);

  //   register uintptr_t k = (uintptr_t)address;

  //   k = (k >> 4) ^ (k << 8);
  //   k &= CMP_MAP_W - 1;
  // RAX = k

  gum_x86_writer_put_mov_reg_reg(cw, GUM_REG_RAX, GUM_REG_RDX);
  gum_x86_writer_put_shr_reg_u8(cw, GUM_REG_RAX, 4);
  gum_x86_writer_put_mov_reg_reg(cw, GUM_REG_RBX, GUM_REG_RDX);
  gum_x86_writer_put_shl_reg_u8(cw, GUM_REG_RBX, 8);
  gum_x86_writer_put_xor_reg_reg(cw, GUM_REG_RAX, GUM_REG_RBX);
  if (is_call) {

    gum_x86_writer_put_and_reg_u32(cw, GUM_REG_RAX, CMP_MAP_W - 7);

  } else {

    gum_x86_writer_put_and_reg_u32(cw, GUM_REG_RAX, CMP_MAP_W - 1);

  }

  // // r8 = &__afl_cmp_map->headers[k];
  // // rbx = __afl_cmp_map->headers[k];

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_R8,
                                     GUM_ADDRESS(__afl_cmp_map));
  gum_x86_writer_put_mov_reg_reg(cw, GUM_REG_RBX, GUM_REG_RAX);
  /* 8 bytes */
  gum_x86_writer_put_shl_reg_u8(cw, GUM_REG_RBX, 3);
  gum_x86_writer_put_add_reg_reg(cw, GUM_REG_R8, GUM_REG_RBX);
  gum_x86_writer_put_mov_reg_reg_ptr(cw, GUM_REG_RBX, GUM_REG_R8);

  //   __afl_cmp_map->headers[k].type = CMP_TYPE_INS;
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX,
                                     GUM_ADDRESS(0xFF9FFFFFFFFFFFFF));
  gum_x86_writer_put_and_reg_reg(cw, GUM_REG_RBX, GUM_REG_RDX);

  if (is_call) {

    gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX,
                                       GUM_ADDRESS(0x40000000000000));

  } else {

    gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX,
                                       GUM_ADDRESS(0x20000000000000));

  }

  gum_x86_writer_put_add_reg_reg(cw, GUM_REG_RBX, GUM_REG_RDX);

  //   __afl_cmp_map->headers[k].shape = (size - 1);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX,
                                     GUM_ADDRESS(0xFFE0FFFFFFFFFFFF));
  gum_x86_writer_put_and_reg_reg(cw, GUM_REG_RBX, GUM_REG_RDX);

  gum_x86_writer_put_mov_reg_reg(cw, GUM_REG_R9, GUM_REG_RCX);
  gum_x86_writer_put_dec_reg(cw, GUM_REG_R9);
  gum_x86_writer_put_shl_reg_u8(cw, GUM_REG_R9, 48);
  gum_x86_writer_put_add_reg_reg(cw, GUM_REG_RBX, GUM_REG_R9);

  //   u32 hits = __afl_cmp_map->headers[k].hits;
  //   __afl_cmp_map->headers[k].hits = hits + 1;

  // rdx = hits
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX, GUM_ADDRESS(0xFFFFFF));
  gum_x86_writer_put_and_reg_reg(cw, GUM_REG_RDX, GUM_REG_RBX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDX);
  gum_x86_writer_put_inc_reg(cw, GUM_REG_RDX);

  gum_x86_writer_put_push_reg(cw, GUM_REG_RDX);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX,
                                     GUM_ADDRESS(0xFFFFFFFFFF000000));
  gum_x86_writer_put_and_reg_reg(cw, GUM_REG_RBX, GUM_REG_RDX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDX);

  gum_x86_writer_put_add_reg_reg(cw, GUM_REG_RBX, GUM_REG_RDX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDX);

  gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_REG_R8, GUM_REG_RBX);

  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_R8,
                                     GUM_ADDRESS(__afl_cmp_map->log));

  if (is_call) {

    // hits &= CMP_MAP_RTN_H - 1;
    gum_x86_writer_put_and_reg_u32(cw, GUM_REG_RDX, CMP_MAP_RTN_H - 1);
    /* (2^4) 16 elements per row */
    gum_x86_writer_put_shl_reg_u8(cw, GUM_REG_RAX, 4);
    gum_x86_writer_put_add_reg_reg(cw, GUM_REG_RAX, GUM_REG_RDX);
    /* (2 ^ 6) 64 bytes each */
    gum_x86_writer_put_shl_reg_u8(cw, GUM_REG_RAX, 6);
    gum_x86_writer_put_add_reg_reg(cw, GUM_REG_R8, GUM_REG_RAX);

    // gum_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v0,
    // ptr1,
    //            32);
    // gum_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v1,
    // ptr2,
    //            32);

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RDI, 0);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 0, GUM_REG_RBX);

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RDI, 8);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 8, GUM_REG_RBX);

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RDI, 16);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 16, GUM_REG_RBX);

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RDI, 24);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 24, GUM_REG_RBX);

    gum_x86_writer_put_add_reg_imm(cw, GUM_REG_R8,
                                   offsetof(struct cmpfn_operands, v1));

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RSI, 0);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 0, GUM_REG_RBX);

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RSI, 8);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 8, GUM_REG_RBX);

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RSI, 16);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 16, GUM_REG_RBX);

    gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_REG_RBX, GUM_REG_RSI, 24);
    gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_REG_R8, 24, GUM_REG_RBX);

  } else {

    //   hits &= CMP_MAP_H - 1;
    gum_x86_writer_put_and_reg_u32(cw, GUM_REG_RDX, CMP_MAP_H - 1);

    /* (2^5) 32 elements per row */
    gum_x86_writer_put_shl_reg_u8(cw, GUM_REG_RAX, 5);
    gum_x86_writer_put_add_reg_reg(cw, GUM_REG_RAX, GUM_REG_RDX);
    /* (2 ^ 5) 32 bytes each */
    gum_x86_writer_put_shl_reg_u8(cw, GUM_REG_RAX, 5);
    gum_x86_writer_put_add_reg_reg(cw, GUM_REG_R8, GUM_REG_RAX);

    //   __afl_cmp_map->log[k][hits].v0 = operand1;
    //   __afl_cmp_map->log[k][hits].v1 = operand2;
    gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_REG_R8, GUM_REG_RDI);
    gum_x86_writer_put_add_reg_imm(cw, GUM_REG_R8,
                                   offsetof(struct cmp_operands, v1));
    gum_x86_writer_put_mov_reg_ptr_reg(cw, GUM_REG_R8, GUM_REG_RSI);

  }

  gum_x86_writer_put_pop_reg(cw, GUM_REG_R9);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_R8);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RBX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_ret(cw);

}

static void cmplog_cmp_sub_update_inst(GumStalkerOutput *output,
                                       uint64_t address, uint8_t size) {

  static GumAddress current_cmp_sub_update_impl = GUM_ADDRESS(0);
  static GumAddress current_call_update_impl = GUM_ADDRESS(0);
  GumX86Writer *    cw = output->writer.x86;
  GumAddress *      target = NULL;
  if (size == 32) {

    target = &current_call_update_impl;

  } else {

    target = &current_cmp_sub_update_impl;

  }

  if (*target == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc, *target) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128, *target)) {

    gconstpointer after_readable_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_readable_impl);

    *target = cw->pc;
    cmplog_cmp_sub_update_inst_func(output, size == 32);

    gum_x86_writer_put_label(cw, after_readable_impl);

  }

  gum_x86_writer_put_push_reg(cw, GUM_REG_RDX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RCX);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDX, GUM_ADDRESS(address));
  gum_x86_writer_put_mov_reg_u32(cw, GUM_REG_ECX, size);
  gum_x86_writer_put_call_address(cw, GUM_ADDRESS(*target));
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RCX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDX);

}

static void cmplog_write_is_readable_func(GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  gum_x86_writer_put_push_reg(cw, GUM_REG_RCX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R8);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R9);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R10);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R11);

  gum_x86_writer_put_call_address(cw, GUM_ADDRESS(cmplog_is_readable));

  gum_x86_writer_put_pop_reg(cw, GUM_REG_R11);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_R10);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_R9);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_R8);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDX);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RCX);
  gum_x86_writer_put_ret(cw);

}

static void cmplog_write_is_readable(GumStalkerOutput *output,
                                     GumCpuReg location, uint8_t size) {

  static GumAddress current_readable_impl = GUM_ADDRESS(0);
  GumX86Writer *    cw = output->writer.x86;
  if (current_readable_impl == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc,
                                                  current_readable_impl) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128,
                                                  current_readable_impl)) {

    gconstpointer after_readable_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_readable_impl);

    current_readable_impl = cw->pc;
    cmplog_write_is_readable_func(output);

    gum_x86_writer_put_label(cw, after_readable_impl);

  }

  if (GUM_REG_RDI != location) {

    gum_x86_writer_put_mov_reg_reg(cw, GUM_REG_RDI, location);

  }

  gum_x86_writer_put_mov_reg_u32(cw, GUM_REG_ESI, size);
  gum_x86_writer_put_call_address(cw, GUM_ADDRESS(current_readable_impl));

}

static void call_inst(GumStalkerOutput *output, uint64_t address) {

  GumX86Writer *cw = output->writer.x86;

  gconstpointer done = cw->code + 1;

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RSI);

  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RSI);
  cmplog_write_is_readable(output, GUM_REG_RSI, 32);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RSI);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_test_reg_reg(cw, GUM_REG_RAX, GUM_REG_RAX);
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, done, GUM_UNLIKELY);

  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RSI);
  cmplog_write_is_readable(output, GUM_REG_RDI, 32);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RSI);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_test_reg_reg(cw, GUM_REG_RAX, GUM_REG_RAX);
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, done, GUM_UNLIKELY);

  cmplog_cmp_sub_update_inst(output, address, 32);

  gum_x86_writer_put_label(cw, done);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RSI);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_popfx(cw);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void cmplog_instrument_call(const cs_insn *     instr,
                                   GumStalkerIterator *iterator,
                                   GumStalkerOutput *  output) {

  UNUSED_PARAMETER(iterator);

  cs_x86     x86 = instr->detail->x86;
  cs_x86_op *operand;

  if (instr->id != X86_INS_CALL) return;

  if (x86.op_count != 1) return;

  operand = &x86.operands[0];

  if (operand->type == X86_OP_INVALID) return;
  if (operand->type == X86_OP_MEM && operand->mem.segment != X86_REG_INVALID)
    return;

  call_inst(output, instr->address);

}

static void cmp_read_imm_inst(GumStalkerOutput *output, int64_t imm,
                              GumCpuReg reg) {

  GumX86Writer *cw = output->writer.x86;
  gum_x86_writer_put_mov_reg_u64(cw, reg, imm);
  gum_x86_writer_put_mov_reg_u32(cw, GUM_REG_RAX, 1);

}

static void cmp_read_reg_inst(GumStalkerOutput *output, x86_reg src_reg,
                              GumCpuReg dst_reg) {

  GumX86Writer *cw = output->writer.x86;
  GumCpuReg     gum_src_reg = ctx_get_reg(src_reg);
  gsize         shift = ctx_get_shift(src_reg);
  gsize         mask = ctx_get_mask(src_reg);

  if (gum_src_reg != dst_reg) {

    gum_x86_writer_put_mov_reg_reg(cw, dst_reg, gum_src_reg);

  }

  if (shift != 0) { gum_x86_writer_put_shr_reg_u8(cw, dst_reg, shift); }
  if (mask != 0) { gum_x86_writer_put_and_reg_u32(cw, dst_reg, mask); }

  gum_x86_writer_put_mov_reg_u32(cw, GUM_REG_RAX, 1);

}

static void cmplog_read_mem_inst(GumStalkerOutput *output, uint8_t size,
                                 x86_op_mem *mem, GumCpuReg dst_reg) {

  g_assert(dst_reg != GUM_REG_NONE);

  GumX86Writer *cw = output->writer.x86;
  GumCpuReg     scratch = GUM_REG_NONE;
  GumCpuReg candidates[] = {GUM_REG_RAX, GUM_REG_RCX, GUM_REG_RDX, GUM_REG_RBX,
                            GUM_REG_RSI, GUM_REG_RDI, GUM_REG_R8,  GUM_REG_R9,
                            GUM_REG_R10, GUM_REG_R11, GUM_REG_R12, GUM_REG_R13,
                            GUM_REG_R14, GUM_REG_R15};

  GumCpuReg base_reg = ctx_get_reg(mem->base);
  GumCpuReg index_reg = ctx_get_reg(mem->index);

  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {

    if (candidates[i] == base_reg) { continue; }
    if (candidates[i] == index_reg) { continue; }
    if (candidates[i] == dst_reg) { continue; }
    scratch = candidates[i];

  }

  if (base_reg != GUM_REG_NONE && base_reg != GUM_REG_RAX &&
      base_reg != dst_reg) {

    gum_x86_writer_put_push_reg(cw, base_reg);

  }

  if (index_reg != GUM_REG_NONE && index_reg != GUM_REG_RAX &&
      index_reg != dst_reg && base_reg != index_reg) {

    gum_x86_writer_put_push_reg(cw, index_reg);

  }

  if (index_reg != GUM_REG_NONE) {

    cmp_read_reg_inst(output, mem->index, index_reg);

    if (base_reg == index_reg) {

      if (scratch == GUM_REG_NONE) { FATAL("Failed to find scratch register"); }

      gum_x86_writer_put_push_reg(cw, scratch);
      gum_x86_writer_put_mov_reg_reg(cw, scratch, index_reg);

    }

    switch (mem->scale) {

      case 1:
        break;
      case 2:
        gum_x86_writer_put_shl_reg_u8(cw, index_reg, 1);
        break;
      case 4:
        gum_x86_writer_put_shl_reg_u8(cw, index_reg, 2);
        break;
      case 8:
        gum_x86_writer_put_shl_reg_u8(cw, index_reg, 3);
        break;
      default:
        FATAL("Unsupported scale: %d", mem->scale);

    }

    if (base_reg == index_reg) {

      gum_x86_writer_put_add_reg_reg(cw, index_reg, scratch);
      gum_x86_writer_put_pop_reg(cw, scratch);

    }

  }

  if (base_reg != GUM_REG_NONE && base_reg != index_reg) {

    cmp_read_reg_inst(output, mem->base, base_reg);

  }

  if (dst_reg == index_reg) {

    if (base_reg != GUM_REG_NONE && base_reg != index_reg) {

      gum_x86_writer_put_add_reg_reg(cw, dst_reg, base_reg);

    }

    if (mem->disp != 0) {

      gum_x86_writer_put_add_reg_imm(cw, dst_reg, mem->disp);

    }

  } else if (dst_reg == base_reg) {

    if (index_reg != GUM_REG_NONE) {

      gum_x86_writer_put_add_reg_reg(cw, dst_reg, index_reg);

    }

    if (mem->disp != 0) {

      gum_x86_writer_put_add_reg_imm(cw, dst_reg, mem->disp);

    }

  } else {

    gum_x86_writer_put_xor_reg_reg(cw, dst_reg, dst_reg);

    if (index_reg != GUM_REG_NONE) {

      gum_x86_writer_put_mov_reg_reg(cw, dst_reg, index_reg);

    }

    if (base_reg != GUM_REG_NONE && base_reg != index_reg) {

      gum_x86_writer_put_add_reg_reg(cw, dst_reg, base_reg);

    }

    if (mem->disp != 0) {

      gum_x86_writer_put_add_reg_imm(cw, dst_reg, mem->disp);

    }

  }

  gum_x86_writer_put_push_reg(cw, dst_reg);
  cmplog_write_is_readable(output, dst_reg, size);
  gum_x86_writer_put_pop_reg(cw, dst_reg);

  gum_x86_writer_put_test_reg_reg(cw, GUM_REG_RAX, GUM_REG_RAX);
  gconstpointer done = cw->code + 1;
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, done, GUM_UNLIKELY);

  gum_x86_writer_put_mov_reg_reg_ptr(cw, dst_reg, dst_reg);
  switch (size) {

    case 1:
      gum_x86_writer_put_and_reg_u32(cw, dst_reg, GUM_INT8_MASK);
      break;
    case 2:
      gum_x86_writer_put_and_reg_u32(cw, dst_reg, GUM_INT16_MASK);
      break;
    case 4:
      gum_x86_writer_put_and_reg_u32(cw, dst_reg, GUM_INT32_MASK);
    case 8:
      break;
    default:
      FATAL("Unsupported scale: %d", mem->scale);

  }

  gum_x86_writer_put_label(cw, done);

  if (index_reg != GUM_REG_NONE && index_reg != GUM_REG_RAX &&
      index_reg != dst_reg && base_reg != index_reg) {

    gum_x86_writer_put_pop_reg(cw, index_reg);

  }

  if (base_reg != GUM_REG_NONE && base_reg != GUM_REG_RAX &&
      base_reg != dst_reg) {

    gum_x86_writer_put_pop_reg(cw, base_reg);

  }

}

static void cmp_read_operand_inst(GumStalkerOutput *output, cs_x86_op *operand,
                                  GumCpuReg dst_reg) {

  switch (operand->type) {

    case X86_OP_REG:
      cmp_read_reg_inst(output, operand->reg, dst_reg);
      break;
    case X86_OP_IMM:
      cmp_read_imm_inst(output, operand->imm, dst_reg);
      break;
    case X86_OP_MEM:
      cmplog_read_mem_inst(output, operand->size, &operand->mem, dst_reg);
      break;
    default:
      FATAL("Invalid operand type: %d\n", operand->type);

  }

}

static void cmp_sub_inst(GumStalkerOutput *output, uint64_t address,
                         cs_x86_op *operand1, cs_x86_op *operand2) {

  GumX86Writer *cw = output->writer.x86;

  gconstpointer done = cw->code + 1;

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -(GUM_RED_ZONE_SIZE));

  gum_x86_writer_put_pushfx(cw);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RSI);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R8);
  gum_x86_writer_put_push_reg(cw, GUM_REG_R9);

  cmp_read_operand_inst(output, operand1, GUM_REG_RDI);
  gum_x86_writer_put_test_reg_reg(cw, GUM_REG_RAX, GUM_REG_RAX);
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, done, GUM_UNLIKELY);

  cmp_read_operand_inst(output, operand2, GUM_REG_RSI);
  gum_x86_writer_put_test_reg_reg(cw, GUM_REG_RAX, GUM_REG_RAX);
  gum_x86_writer_put_jcc_near_label(cw, X86_INS_JE, done, GUM_UNLIKELY);

  cmplog_cmp_sub_update_inst(output, address, operand1->size);

  gum_x86_writer_put_label(cw, done);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_R9);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_R8);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RSI);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RAX);
  gum_x86_writer_put_popfx(cw);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        (GUM_RED_ZONE_SIZE));

}

static void cmplog_instrument_cmp_sub(const cs_insn *     instr,
                                      GumStalkerIterator *iterator,
                                      GumStalkerOutput *  output) {

  UNUSED_PARAMETER(iterator);
  cs_x86     x86 = instr->detail->x86;
  cs_x86_op *operand1;
  cs_x86_op *operand2;

  switch (instr->id) {

    case X86_INS_CMP:
    case X86_INS_SUB:
    case X86_INS_SCASB:
    case X86_INS_SCASD:
    case X86_INS_SCASQ:
    case X86_INS_SCASW:
    case X86_INS_CMPSB:
    case X86_INS_CMPSD:
    case X86_INS_CMPSQ:
    case X86_INS_CMPSS:
    case X86_INS_CMPSW:
      break;
    default:
      return;

  }

  if (x86.op_count != 2) return;

  operand1 = &x86.operands[0];
  operand2 = &x86.operands[1];

  if (operand1->type == X86_OP_INVALID) return;
  if (operand2->type == X86_OP_INVALID) return;

  /* Both operands are the same size */
  if (operand1->size == 1) { return; }

  cmp_sub_inst(output, instr->address, operand1, operand2);

}

void cmplog_instrument(const cs_insn *instr, GumStalkerIterator *iterator,
                       GumStalkerOutput *output) {

  if (__afl_cmp_map == NULL) return;

  cmplog_instrument_call(instr, iterator, output);
  cmplog_instrument_cmp_sub(instr, iterator, output);

}

#endif

