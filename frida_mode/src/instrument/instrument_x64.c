#include "frida-gumjs.h"

#include "config.h"

#include "instrument.h"

#if defined(__x86_64__)

static GumAddress current_log_impl = GUM_ADDRESS(0);

static const guint8 afl_log_code[] = {

    0x9c,                                                         /* pushfq */
    0x51,                                                       /* push rcx */
    0x52,                                                       /* push rdx */

    0x48, 0x8b, 0x0d, 0x26,
    0x00, 0x00, 0x00,                          /* mov rcx, sym.&previous_pc */
    0x48, 0x8b, 0x11,                               /* mov rdx, qword [rcx] */
    0x48, 0x31, 0xfa,                                       /* xor rdx, rdi */

    0x48, 0x03, 0x15, 0x11,
    0x00, 0x00, 0x00,                     /* add rdx, sym._afl_area_ptr_ptr */

    0x80, 0x02, 0x01,                              /* add byte ptr [rdx], 1 */
    0x80, 0x12, 0x00,                              /* adc byte ptr [rdx], 0 */
    0x66, 0xd1, 0xcf,                                          /* ror di, 1 */
    0x48, 0x89, 0x39,                               /* mov qword [rcx], rdi */

    0x5a,                                                        /* pop rdx */
    0x59,                                                        /* pop rcx */
    0x9d,                                                          /* popfq */

    0xc3,                                                            /* ret */

    0x90

    /* Read-only data goes here: */
    /* uint8_t* __afl_area_ptr */
    /* uint64_t* &previous_pc */

};

static const guint8 afl_log_code_bigmap[] = {

    // 0xcc,

    0x9c,                                                         /* pushfq */
    0x51,                                                       /* push rcx */
    0x52,                                                       /* push rdx */
    0x56,                                                       /* push rsi */

    /* edge = current_pc ^ instrument_previous_pc; */
    0x48, 0x8b, 0x0d, 0x4b, 0x00, 0x00, 0x00,  /* mov rcx, sym.&previous_pc */
    0x48, 0x8b, 0x11,                               /* mov rdx, qword [rcx] */
    0x48, 0x31, 0xfa,                                       /* xor rdx, rdi */

    /* edge_cnt = index_map[edge] */
    0x48, 0x8b, 0x35, 0x46, 0x00, 0x00,
    0x00,                             /* mov rsi, sym.&instrument_index_map */
    0x48, 0x8d, 0x34, 0x56,                     /* mov rsi, [rsi + rdx * 2] */
    0x48, 0x0F, 0xB7, 0x16,                    /* movzx rdx, word ptr [rsi] */
    0x66, 0x83, 0xfa, 0xff,                               /* cmp dx, 0xffff */

    0x75, 0x18,                                                 /* jne used */

    0x53,                                                       /* push rbx */
    0x48, 0x8b, 0x1d, 0x38, 0x00, 0x00,
    0x00,                            /* mov rbx, sym.&instrument_bigmap_cnt */
    0x66, 0x83, 0x03, 0x01,                        /* add word ptr [rbx], 1 */
    0x66, 0x83, 0x13, 0x00,                        /* adc word ptr [rbx], 0 */
    0x48, 0x0f, 0xb7, 0x13,                    /* movzx rdx, word ptr [rbx] */
    0x66, 0x89, 0x16,                             /* mov word ptr [rsi], dx */
    0x5b,                                                        /* pop rbx */

    /* used: */

    /* __afl_area_ptr[edge]++ */
    0x48, 0x03, 0x15, 0x29, 0x00, 0x00,
    0x00,                                 /* add rdx, sym._afl_area_ptr_ptr */

    0x80, 0x02, 0x01,                              /* add byte ptr [rdx], 1 */
    0x80, 0x12, 0x00,                              /* adc byte ptr [rdx], 0 */

    /* instrument_previous_pc = ror16 (current_pc) */
    0x66, 0xd1, 0xcf,                                          /* ror di, 1 */
    0x48, 0x89, 0x39,                               /* mov qword [rcx], rdi */

    0x5e,                                                        /* pop rsi */
    0x5a,                                                        /* pop rdx */
    0x59,                                                        /* pop rcx */
    0x9d,                                                          /* popfq */

    0xc3,                                                            /* ret */

    /* Read-only data goes here: */
    /* uint64_t* &previous_pc */
    /* uint16_t* instrument_index_map */
    /* uint16_t* &instrument_bigmap_cnt */
    /* uint8_t* __afl_area_ptr */

};

gboolean instrument_is_coverage_optimize_supported(void) {

  return true;

}

static guint8 align_pad[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

static void instrument_coverate_write_function(GumStalkerOutput *output) {

  guint64       misalign = 0;
  GumX86Writer *cw = output->writer.x86;

  if (current_log_impl == 0 ||
      !gum_x86_writer_can_branch_directly_between(cw->pc, current_log_impl) ||
      !gum_x86_writer_can_branch_directly_between(cw->pc + 128,
                                                  current_log_impl)) {

    gconstpointer after_log_impl = cw->code + 1;

    gum_x86_writer_put_jmp_near_label(cw, after_log_impl);

    if (instrument_bigmap) {

      misalign = ((cw->pc + sizeof(afl_log_code_bigmap)) & 0x7);

    } else {

      misalign = ((cw->pc + sizeof(afl_log_code)) & 0x7);

    }

    if (misalign != 0) {

      gum_x86_writer_put_bytes(cw, align_pad, 8 - misalign);

    }

    current_log_impl = cw->pc;
    if (instrument_bigmap) {

      gum_x86_writer_put_bytes(cw, afl_log_code_bigmap,
                               sizeof(afl_log_code_bigmap));

    } else {

      gum_x86_writer_put_bytes(cw, afl_log_code, sizeof(afl_log_code));

    }

    uint64_t *afl_prev_loc_ptr = &instrument_previous_pc;

    if (instrument_bigmap) {

      uint16_t *instrument_bigmap_cnt_ptr = &instrument_bigmap_cnt;
      gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                               sizeof(afl_prev_loc_ptr));
      gum_x86_writer_put_bytes(cw, (const guint8 *)&instrument_index_map,
                               sizeof(instrument_index_map));
      gum_x86_writer_put_bytes(cw, (const guint8 *)&instrument_bigmap_cnt_ptr,
                               sizeof(instrument_bigmap_cnt_ptr));
      gum_x86_writer_put_bytes(cw, (const guint8 *)&__afl_area_ptr,
                               sizeof(__afl_area_ptr));

    } else {

      gum_x86_writer_put_bytes(cw, (const guint8 *)&__afl_area_ptr,
                               sizeof(__afl_area_ptr));
      gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                               sizeof(afl_prev_loc_ptr));

    }

    gum_x86_writer_put_label(cw, after_log_impl);

  }

}

void instrument_coverage_optimize(const cs_insn *   instr,
                                  GumStalkerOutput *output) {

  GumX86Writer *cw = output->writer.x86;
  guint64 area_offset = instrument_get_offset_hash(GUM_ADDRESS(instr->address));
  instrument_coverate_write_function(output);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDI, area_offset);
  gum_x86_writer_put_call_address(cw, current_log_impl);
  gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                        GUM_RED_ZONE_SIZE);

}

void instrument_flush(GumStalkerOutput *output) {

  gum_x86_writer_flush(output->writer.x86);

}

gpointer instrument_cur(GumStalkerOutput *output) {

  return gum_x86_writer_cur(output->writer.x86);

}

#endif

