/*
 * internal execution defines for qemu
 *
 *  Copyright (c) 2003 Fabrice Bellard
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

#ifndef _EXEC_ALL_H_
#define _EXEC_ALL_H_

#include "opt-def.h"
#include "qemu-common.h"

/* allow to see translation results - the slowdown should be negligible, so we leave it */
#define DEBUG_DISAS

/* Page tracking code uses ram addresses in system mode, and virtual
   addresses in userspace mode.  Define tb_page_addr_t to be an appropriate
   type.  */
#if defined(CONFIG_USER_ONLY)
typedef abi_ulong tb_page_addr_t;
#else
typedef ram_addr_t tb_page_addr_t;
#endif

/* is_jmp field values */
#define DISAS_NEXT    0 /* next instruction can be analyzed */
#define DISAS_JUMP    1 /* only pc was modified dynamically */
#define DISAS_UPDATE  2 /* cpu state was modified dynamically */
#define DISAS_TB_JUMP 3 /* only pc was modified statically */

typedef struct TranslationBlock TranslationBlock;
extern uint8_t *tb_ret_addr;
void codecache_prologue_init(CPUX86State *env);

/* XXX: make safe guess about sizes */
#define MAX_OP_PER_INSTR 96

#if HOST_LONG_BITS == 32
#define MAX_OPC_PARAM_PER_ARG 2
#else
#define MAX_OPC_PARAM_PER_ARG 1
#endif
#define MAX_OPC_PARAM_IARGS 4
#define MAX_OPC_PARAM_OARGS 1
#define MAX_OPC_PARAM_ARGS (MAX_OPC_PARAM_IARGS + MAX_OPC_PARAM_OARGS)

/* A Call op needs up to 4 + 2N parameters on 32-bit archs,
 * and up to 4 + N parameters on 64-bit archs
 * (N = number of input arguments + output arguments).  */
#define MAX_OPC_PARAM (4 + (MAX_OPC_PARAM_PER_ARG * MAX_OPC_PARAM_ARGS))
#define OPC_BUF_SIZE 640
#define OPC_MAX_SIZE (OPC_BUF_SIZE - MAX_OP_PER_INSTR)

/* Maximum size a TCG op can expand to.  This is complicated because a
   single op may require several host instructions and register reloads.
   For now take a wild guess at 192 bytes, which should allow at least
   a couple of fixup instructions per argument.  */
#define TCG_MAX_OP_SIZE 192

#define OPPARAM_BUF_SIZE (OPC_BUF_SIZE * MAX_OPC_PARAM)

extern target_ulong gen_opc_pc[OPC_BUF_SIZE];
extern uint8_t gen_opc_instr_start[OPC_BUF_SIZE];
extern uint16_t gen_opc_icount[OPC_BUF_SIZE];

#include "qemu-log.h"


void gen_target_code(CPUState *env, struct TranslationBlock *tb);
void gen_pc_load(CPUState *env, struct TranslationBlock *tb,
                 unsigned long searched_pc, int pc_pos, void *puc);

void cpu_gen_init(void);
int cpu_gen_code(CPUState *env, struct TranslationBlock *tb);
int cpu_restore_state(struct TranslationBlock *tb,
                      CPUState *env, unsigned long searched_pc,
                      void *puc);
void cpu_resume_from_signal(CPUState *env1, void *puc);
void cpu_io_recompile(CPUState *env, void *retaddr);
TranslationBlock *tb_gen_code(CPUState *env, target_ulong pc);
void cpu_exec_init(CPUState *env);
void QEMU_NORETURN cpu_loop_exit(void);
int page_unprotect(target_ulong address, unsigned long pc, void *puc);
void tb_invalidate_phys_page_range(tb_page_addr_t start, tb_page_addr_t end,
                                   int is_cpu_write_access);
void tb_invalidate_page_range(target_ulong start, target_ulong end);
void tlb_flush_page(CPUState *env, target_ulong addr);
void tlb_flush(CPUState *env, int flush_global);

#define CODE_GEN_ALIGN           16 /* must be >= of the size of a icache line */

#define CODE_GEN_PHYS_HASH_BITS     15
#define CODE_GEN_PHYS_HASH_SIZE     (1 << CODE_GEN_PHYS_HASH_BITS)

#define MIN_CODE_GEN_BUFFER_SIZE     (1024 * 1024)

/* estimated block size for TB allocation */
/* XXX: use a per code average code fragment size and modulate it
   according to the host CPU */
#if defined(CONFIG_SOFTMMU)
#define CODE_GEN_AVG_BLOCK_SIZE 128
#else
#define CODE_GEN_AVG_BLOCK_SIZE 64
#endif

#if defined(_ARCH_PPC) || defined(__x86_64__) || defined(__arm__) || defined(__i386__)
#define USE_DIRECT_JUMP
#endif

#define DEFAULT_CODE_GEN_BUFFER_SIZE (256 * 1024 * 1024)
#define DEFAULT_SIEVE_BUFFER_SIZE (64 * 1024 * 1024)

#ifdef SWITCH_OPT
#define DEFAULT_SWITCH_CASE_BUFFER_SIZE (256 * 1024 * 1024)
#endif

#define NOT_TRANS_YET	0xdeadbeaf
#define CONT_TRANS_TAG	(PATCH_MAX - 1)
#define PATCH_MAX	8

#define IND_TGT_SIZE		128
#define IND_TGT_NODE_MAX	(1024*16*16)
#define IND_HASH(a)	((a >> 4) & (IND_TGT_SIZE - 1))

typedef struct ind_tgt_stat {
    uint32_t tgt_count[IND_TGT_SIZE];
} ind_tgt_stat;
extern ind_tgt_stat ind_tgt_nodes[];

struct TranslationBlock {
    target_ulong pc;   /* simulated PC corresponding to this block (EIP + CS base) */
    uint16_t size;      /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    uint32_t func_addr;
    uint32_t tb_tag;
    uint16_t hcode_size;      /* size of host code for this block */
    uint32_t insn_count;
    uint32_t icount;
    uint32_t ind_miss_count;
	uint32_t ind_replace_count;

    uint8_t *tc_ptr;    /* pointer to the translated code */
    /* next matching tb for physical address. */
    struct TranslationBlock *phys_hash_next;

    /* the following data are used to directly call another TB from
       the code of this one. */
    uint32_t patch_num;
    uint16_t tb_jmp_offset[PATCH_MAX]; /* offset of jump instruction */
    struct TranslationBlock *jmp_next[PATCH_MAX];

    /* indicated which tbs are jumped into this tb, 
       and from which of their jmp_stub */
    struct TranslationBlock *jmp_from[TB_FROM_MAX];
    uint8_t jmp_from_num[TB_FROM_MAX]; /* */
    uint32_t jmp_from_index;

    uint32_t prof_pos;
#ifdef IND_OPT
    uint32_t type;

    uint32_t jind_src_addr[IND_SLOT_MAX];
    uint32_t jind_dest_addr[IND_SLOT_MAX];
	/* add for mru */
	uint32_t mru_src;
	uint32_t mru_dest;
    uint32_t jmp_ind;
    uint32_t jmp_ind_index;
    uint8_t *retrans_patch_ptr;
    uint8_t *ind_enter_sieve;
#ifdef SWITCH_OPT
	uint32_t sa_base;
	uint32_t shadow_base;
	uint32_t sa_entry_sum;
#endif

    bool     has_ind;
    bool     retransed;
    uint32_t retrans_count;
    uint32_t retrans_count_max;

    ind_tgt_stat *ind_tgt;
#endif
} __attribute__ ((aligned (32)));

static inline unsigned int tb_jmp_cache_hash_page(target_ulong pc)
{
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK;
}

static inline unsigned int tb_jmp_cache_hash_func(target_ulong pc)
{
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (((tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK)
	    | (tmp & TB_JMP_ADDR_MASK));
}

static inline unsigned int tb_phys_hash_func(tb_page_addr_t pc)
{
    return pc & (CODE_GEN_PHYS_HASH_SIZE - 1);
}

void tb_add_jmp_from(TranslationBlock *tb, TranslationBlock *next_tb, int n);
TranslationBlock *make_tb(CPUX86State *env, target_ulong pc, 
                          uint32_t func_addr, uint32_t recur_addr);
void map_exec(void *addr, long size);
TranslationBlock *tb_alloc(target_ulong pc);
void tb_free(TranslationBlock *tb);
void tb_flush(CPUState *env);
void tb_link_page(TranslationBlock *tb,
                  tb_page_addr_t phys_pc, tb_page_addr_t phys_page2);
void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);

extern TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];

#if defined(USE_DIRECT_JUMP)

#if defined(_ARCH_PPC)
extern void ppc_tb_set_jmp_target(unsigned long jmp_addr, unsigned long addr);
#define tb_set_jmp_target1 ppc_tb_set_jmp_target
#elif defined(__i386__) || defined(__x86_64__)
static inline void tb_set_jmp_target1(unsigned long jmp_addr, unsigned long addr)
{
    /* patch the branch destination */
    *(uint32_t *)jmp_addr = addr - (jmp_addr + 4);
    /* no need to flush icache explicitly */
}
#elif defined(__arm__)
static inline void tb_set_jmp_target1(unsigned long jmp_addr, unsigned long addr)
{
#if QEMU_GNUC_PREREQ(4, 1)
    void __clear_cache(char *beg, char *end);
#else
    register unsigned long _beg __asm ("a1");
    register unsigned long _end __asm ("a2");
    register unsigned long _flg __asm ("a3");
#endif

    /* we could use a ldr pc, [pc, #-4] kind of branch and avoid the flush */
    *(uint32_t *)jmp_addr =
        (*(uint32_t *)jmp_addr & ~0xffffff)
        | (((addr - (jmp_addr + 8)) >> 2) & 0xffffff);

#if QEMU_GNUC_PREREQ(4, 1)
    __clear_cache((char *) jmp_addr, (char *) jmp_addr + 4);
#else
    /* flush icache */
    _beg = jmp_addr;
    _end = jmp_addr + 4;
    _flg = 0;
    __asm __volatile__ ("swi 0x9f0002" : : "r" (_beg), "r" (_end), "r" (_flg));
#endif
}
#endif

static inline void tb_set_jmp_target(TranslationBlock *tb,
                                     int n, unsigned long addr)
{
    unsigned long offset;

    offset = tb->tb_jmp_offset[n];
    tb_set_jmp_target1((unsigned long)(tb->tc_ptr + offset), addr);
}

#endif

static inline void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next)
{
    /* patch the native jump address */
    tb_set_jmp_target(tb, n, ((unsigned long)tb_next->tc_ptr));

    tb_add_jmp_from(tb, tb_next, n);
}

TranslationBlock *tb_find_pc(unsigned long pc_ptr);

#include "qemu-lock.h"

/* cpu-exec.c */
extern volatile sig_atomic_t exit_request;

/* jianing */
TranslationBlock *tb_find_fast(uint32_t pc, uint32_t recur_addr);
/* ningjia */

#endif
