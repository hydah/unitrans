/*
 *  i386 emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"
#include "exec.h"
#include "disas.h"
#include "qemu-barrier.h"
#include "stdlib.h"

#include "ind-prof.h"
#include "retrans-ind.h"

#if !defined(CONFIG_SOFTMMU)
#undef EAX
#undef ECX
#undef EDX
#undef EBX
#undef ESP
#undef EBP
#undef ESI
#undef EDI
#undef EIP
#include <signal.h>
#ifdef __linux__
#include <sys/ucontext.h>
#endif
#endif

struct CPUX86State *env;
#define tcg_qemu_tb_exec(tb_ptr) ((long REGPARM (*)(void *))code_gen_prologue)(tb_ptr)
int tb_invalidated_flag;

//#define CONFIG_DEBUG_EXEC
//#define DEBUG_SIGNAL

void cpu_loop_exit(void)
{
    env->current_tb = NULL;
    longjmp(env->jmp_env, 1);
}

void cpu_x86_fsave(CPUX86State *s, target_ulong ptr, int data32)
{
    /* dummy */
    abort();
}

#if 0
/* only works if protected mode and not VM86. seg_reg must be != R_CS */
void helper_load_seg(CPUX86State *env, int seg_reg, int selector)
{
    uint32_t e1, e2;
    int cpl, dpl, rpl;
    SegmentCache *dt;
    int index;
    target_ulong ptr;

    selector &= 0xffff;
    cpl = env->hflags & HF_CPL_MASK;
    if ((selector & 0xfffc) == 0) {
        /* null selector case */
        if (seg_reg == R_SS
#ifdef TARGET_X86_64
                && (!(env->hflags & HF_CS64_MASK) || cpl == 3)
#endif
           ) {
            raise_exception_err(env, EXCP0D_GPF, 0);
        }
        cpu_x86_load_seg_cache(env, seg_reg, selector, 0, 0, 0);
    } else {

        if (selector & 0x4) {
            dt = &env->ldt;
        } else {
            dt = &env->gdt;
        }
        index = selector & ~7;
        if ((index + 7) > dt->limit) {
            raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
        }
        ptr = dt->base + index;
        e1 = cpu_ldl_kernel(env, ptr);
        e2 = cpu_ldl_kernel(env, ptr + 4);

        if (!(e2 & DESC_S_MASK)) {
            raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
        }
        rpl = selector & 3;
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        if (seg_reg == R_SS) {
            /* must be writable segment */
            if ((e2 & DESC_CS_MASK) || !(e2 & DESC_W_MASK)) {
                raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
            }
            if (rpl != cpl || dpl != cpl) {
                raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
            }
        } else {
            /* must be readable segment */
            if ((e2 & (DESC_CS_MASK | DESC_R_MASK)) == DESC_CS_MASK) {
                raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
            }

            if (!(e2 & DESC_CS_MASK) || !(e2 & DESC_C_MASK)) {
                /* if not conforming code, test rights */
                if (dpl < cpl || dpl < rpl) {
                    raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
                }
            }
        }

        if (!(e2 & DESC_P_MASK)) {
            if (seg_reg == R_SS) {
                raise_exception_err(env, EXCP0C_STACK, selector & 0xfffc);
            } else {
                raise_exception_err(env, EXCP0B_NOSEG, selector & 0xfffc);
            }
        }

        /* set the access bit if not already set */
        if (!(e2 & DESC_A_MASK)) {
            e2 |= DESC_A_MASK;
            cpu_stl_kernel(env, ptr + 4, e2);
        }

        cpu_x86_load_seg_cache(env, seg_reg, selector,
                get_seg_base(e1, e2),
                get_seg_limit(e1, e2),
                e2);
#if 0
        qemu_log("load_seg: sel=0x%04x base=0x%08lx limit=0x%08lx flags=%08x\n",
                selector, (unsigned long)sc->base, sc->limit, sc->flags);
#endif
    }
}

#endif



void cpu_x86_load_seg(CPUX86State *s, int seg_reg, int selector)
{
#if 0
    if (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK)) {
        selector &= 0xffff;
        cpu_x86_load_seg_cache(env, seg_reg, selector,
                (selector << 4), 0xffff, 0);
    } else {
        helper_load_seg(env, seg_reg, selector);
    }
#else
    /* dummy */
    abort();
#endif
}
void cpu_x86_frstor(CPUX86State *s, target_ulong ptr, int data32)
{
    /* dummy */
    abort();
}
int cpu_signal_handler(int host_signum, void *pinfo, void *puc)
{
    /* dummy */
    abort();
    return 0;
}

static TranslationBlock *tb_find_slow(target_ulong pc, target_ulong tb_tag)
{
    TranslationBlock *tb, **ptb1;
    unsigned int h;

    tb_invalidated_flag = 0;

    /* find translated block using physical mappings */
    h = tb_phys_hash_func(pc);
    ptb1 = &tb_phys_hash[h];
    for(;;) {
        tb = *ptb1;
        if (!tb)
            goto not_found;

        if (tb->pc == pc && tb->tb_tag == tb_tag) goto found;
        ptb1 = &tb->phys_hash_next;
    }
 not_found:
    return NULL;
 found:
    /* we add the TB in the virtual pc hash table */
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;
    return tb;
}

inline TranslationBlock *tb_find_fast(uint32_t pc, uint32_t tb_tag)
{
    TranslationBlock *tb;

    tb = env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)];
    if (unlikely(!tb || tb->pc != pc || tb_tag != tb->tb_tag)) {
        tb = tb_find_slow(pc, tb_tag);
    }
    return tb;
}


static TranslationBlock *get_next_tb(CPUX86State *env, uint32_t cur_pc,
                                     TranslationBlock *prev_tb)
{
    TranslationBlock *tb;
    uint32_t tb_tag;

    tb_tag = NORMAL_TB_TAG;

    tb = tb_find_fast(cur_pc, tb_tag);

    if (tb == NULL) {
        /* tb doesn't exist */
        ///fprintf(stderr, "ind tb_tag: 0x%x\n", tb_tag);
        /* if no translated code available, then translate it now */
        if (env->ind_type != NOT_IND && env->ind_type != TYPE_SYSCALL) {
            switch(env->ind_type) {
              case IND_TYPE_CALL:
              case IND_TYPE_CALL_SP:
                tb = make_tb(env, cur_pc, cur_pc, tb_tag);
                break;
              case IND_TYPE_JMP:
              case IND_TYPE_JMP_SP:
                tb = make_tb(env, cur_pc, env->ind_dest, tb_tag);
                break;
              case IND_TYPE_RET:
              case IND_TYPE_RET_SP:
                tb = make_tb(env, cur_pc, cur_pc, tb_tag);
                break;
              case IND_TYPE_RECUR:
                tb = make_tb(env, cur_pc, env->ind_dest, tb_tag);
                break;
              default:
                tb = make_tb(env, cur_pc, 0, tb_tag);
                fprintf(stderr, "default tb_tag: 0x%x\n", tb_tag);
                break;
            }
        } else {
            if(prev_tb != NULL) {
                if (cur_pc == 0x814fd8e)
                    fprintf(stderr, "*************0x814fd8e***************\n");
                tb = make_tb(env, cur_pc, prev_tb->func_addr, tb_tag);
            } else {
                tb = make_tb(env, cur_pc, 0, tb_tag);
                fprintf(stderr, "unexpected path: 0x%x\n", cur_pc);
            }
        }
        (void)cpu_gen_code(env, tb);
    } else if (tb->tc_ptr == (uint8_t *)NOT_TRANS_YET) {
        /* tb exists, but not translated yes */
        (void)cpu_gen_code(env, tb);
    }

    return tb;
}

#ifdef IND_OPT
static void patch_jmp_target(TranslationBlock *tb, 
                             uint32_t src_addr, uint32_t dest_addr)
{
     int jmp_index;

     //fprintf(stderr, "src:0x%x tgt:0x%x dest:0x%x\n", tb->pc, src_addr, dest_addr);
     jmp_index = tb->jmp_ind_index;
     *(uint32_t *)(tb->jind_src_addr[jmp_index]) = -src_addr;
     *(uint32_t *)(tb->jind_dest_addr[jmp_index]) =
          dest_addr - tb->jind_dest_addr[jmp_index] - 4;
     tb->jmp_ind = 0;
     tb->jmp_ind_index++;
}

static void patch_ind_opt(TranslationBlock *prev_tb, TranslationBlock *tb)
{
    uint32_t tgt_addr;

    tgt_addr = env->eip;

    if(prev_tb->jmp_ind_index < IND_SLOT_MAX) {
        patch_jmp_target(prev_tb, tgt_addr, (uint32_t)tb->tc_ptr);
    } else {
        /* jmp_target was already filled, add enter_sieve now */
        ind_patch_sieve(env, prev_tb->ind_enter_sieve);
    }
}
#endif

int prolog_count = 0;

void handle_syscall(int trapnr)
{
    abi_ulong pc;
    //fprintf(stderr, "this is %s\n", __FUNCTION__);
    switch(trapnr) {
        case 0x80:
            /* linux syscall from int $0x80 */
            env->regs[R_EAX] = do_syscall(env,
                    env->regs[R_EAX],
                    env->regs[R_EBX],
                    env->regs[R_ECX],
                    env->regs[R_EDX],
                    env->regs[R_ESI],
                    env->regs[R_EDI],
                    env->regs[R_EBP]);
            break;
        default:
            pc = env->segs[R_CS].base + env->eip;
            fprintf(stderr, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                    (long)pc, trapnr);
            abort();
    }
}

int cpu_exec(CPUState *env1)
{
    int ret;
    TranslationBlock *tb;
    uint8_t *tc_ptr;
    uint32_t prev_tb;
    int new_tb_count;

    env = env1;
    env->tb_tag = 0;
    prev_tb = 0; /* force lookup of first TB */
    new_tb_count = -500;

#ifdef RETRANS_IND
    env->has_ind = false;
#endif

    for(;;) {
        prolog_count++;

        tb = get_next_tb(env, env->eip, (TranslationBlock *)prev_tb);

        if(env->ind_type != NOT_IND) {
            /* from {ret, ind_jmp, ind_call} */
            if(prev_tb == 0) {
				/* from sieve */
				add_sieve_entry(env, tb, env->ind_type);
				env->ind_type = NOT_IND;
            } else {
                if (env->ind_type == TYPE_SYSCALL) {
                    prev_tb = 0;
                } else {
#ifdef IND_OPT
                    patch_ind_opt((TranslationBlock *)prev_tb, tb);
                    prev_tb = 0;
#endif
                }
            }
        }

#ifdef CONFIG_DEBUG_EXEC
        qemu_log_mask(CPU_LOG_EXEC, "Trace 0x%08lx [" TARGET_FMT_lx "] %s\n",
                     (long)tb->tc_ptr, tb->pc,
                     lookup_symbol(tb->pc));
#endif

        /* link tb */
        if(prev_tb != 0 && (uint32_t)tb != prev_tb) {
            tb_add_jump((TranslationBlock *)prev_tb, env->patch_num, tb);
        }

#ifdef RETRANS_IND
        if(env->has_ind == true) {
            chg_tbs_tag((TranslationBlock *)(env->ind_tb), NORMAL_TB_TAG);
            env->has_ind = false;
        }
#endif

        /* clear env */
        env->current_tb = tb;
        tc_ptr = tb->tc_ptr;
        env->target_tc = (uint32_t)tc_ptr;
        env->ret_tb = 0;
        env->trapnr = -1;
        env->ind_type = NOT_IND;
       
        /* enter code cache */
        prev_tb = tcg_qemu_tb_exec(tc_ptr);
        
        if (env->ind_type == TYPE_SYSCALL) {
            //fprintf(stderr, "env->trapnr is %d\n", env->trapnr);
            handle_syscall(env->trapnr); 
        }

        //fprintf(stderr, "prev_tb = 0x%x pc = 0x%x\n", prev_tb, env->eip);

        env->current_tb = NULL;
    } /* for(;;) */

    return ret;
}

