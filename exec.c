/*
 *  virtual page mapping and translated block handling
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
#include "config.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

#include "cpu.h"
#include "exec-all.h"
#include "qemu-common.h"
#include "osdep.h"
#include "qemu-timer.h"
#include "disas.h"
#if defined(CONFIG_USER_ONLY)
#include <qemu.h>
#include <signal.h>
#endif

//#define DEBUG_TB_INVALIDATE
//#define DEBUG_FLUSH
//#define DEBUG_TLB
//#define DEBUG_UNASSIGNED

/* make various TB consistency checks */
//#define DEBUG_TB_CHECK
//#define DEBUG_TLB_CHECK

//#define DEBUG_IOPORT
//#define DEBUG_SUBPAGE

#if !defined(CONFIG_USER_ONLY)
/* TB consistency checks only implemented for usermode emulation.  */
#undef DEBUG_TB_CHECK
#endif

#define SMC_BITMAP_USE_THRESHOLD 10

TranslationBlock *tbs;
int nb_tbs;
int nb_tb_jmp_reg = 0;

ind_tgt_stat ind_tgt_nodes[IND_TGT_NODE_MAX];
int nb_ind_tgt_nodes;

static int code_gen_max_blocks;
TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];
/* any access to the tbs or the page table must use this lock */

#if defined(__arm__) || defined(__sparc_v9__)
/* The prologue must be reachable with a direct jump. ARM and Sparc64
 have limited branch ranges (possibly also PPC) so place it in a
 section close to code segment. */
#define code_gen_section                                \
    __attribute__((__section__(".gen_code")))           \
    __attribute__((aligned (32)))
#else
#define code_gen_section                                \
    __attribute__((aligned (32)))
#endif

uint8_t code_gen_prologue[2048] code_gen_section;
uint8_t *code_gen_buffer;
uint8_t *sieve_buffer;
uint8_t *switch_case_buffer;

static unsigned long code_gen_buffer_size;
/* threshold to flush the translated code buffer */
static unsigned long code_gen_buffer_max_size;
uint8_t *code_gen_ptr;

CPUState *first_cpu;
/* current CPU in the current thread. It is only valid inside
   cpu_exec() */
CPUState *cpu_single_env;
/* 0 = Do not count executed instructions.
   1 = Precise instruction counting.
   2 = Adaptive rate instruction counting.  */
int use_icount = 0;
/* Current instruction counter.  While executing translated code this may
   include some instructions that have not yet been executed.  */
int64_t qemu_icount;

typedef struct PageDesc {
    /* list of TBs intersecting this ram page */
    TranslationBlock *first_tb;
    /* in order to optimize self modifying code, we count the number
       of lookups we do to a given page to use a bitmap */
    unsigned int code_write_count;
    uint8_t *code_bitmap;
#if defined(CONFIG_USER_ONLY)
    unsigned long flags;
#endif
} PageDesc;

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
# define L1_MAP_ADDR_SPACE_BITS  TARGET_VIRT_ADDR_SPACE_BITS

/* Size of the L2 (and L3, etc) page tables.  */
#define L2_BITS 10
#define L2_SIZE (1 << L2_BITS)

/* The bits remaining after N lower levels of page tables.  */
#define P_L1_BITS_REM \
    ((TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % L2_BITS)
#define V_L1_BITS_REM \
    ((L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % L2_BITS)

/* Size of the L1 page table.  Avoid silly small sizes.  */
#if P_L1_BITS_REM < 4
#define P_L1_BITS  (P_L1_BITS_REM + L2_BITS)
#else
#define P_L1_BITS  P_L1_BITS_REM
#endif

#if V_L1_BITS_REM < 4
#define V_L1_BITS  (V_L1_BITS_REM + L2_BITS)
#else
#define V_L1_BITS  V_L1_BITS_REM
#endif

#define P_L1_SIZE  ((target_phys_addr_t)1 << P_L1_BITS)
#define V_L1_SIZE  ((target_ulong)1 << V_L1_BITS)

#define P_L1_SHIFT (TARGET_PHYS_ADDR_SPACE_BITS - TARGET_PAGE_BITS - P_L1_BITS)
#define V_L1_SHIFT (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - V_L1_BITS)

unsigned long qemu_real_host_page_size;
unsigned long qemu_host_page_bits;
unsigned long qemu_host_page_size;
unsigned long qemu_host_page_mask;

/* This is a multi-level map on the virtual address space.
   The bottom level has pointers to PageDesc.  */
static void *l1_map[V_L1_SIZE];

/* log support */
static const char *logfilename = "/tmp/qemu.log";
FILE *logfile;
int loglevel;
static int log_append = 0;

/* statistics */
static int tb_flush_count;

void map_exec(void *addr, long size)
{
    unsigned long start, end, page_size;
    
    page_size = getpagesize();
    start = (unsigned long)addr;
    start &= ~(page_size - 1);
    
    end = (unsigned long)addr + size;
    end += page_size - 1;
    end &= ~(page_size - 1);
    
    mprotect((void *)start, end - start,
             PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void page_init(void)
{
    /* NOTE: we can always suppose that qemu_host_page_size >=
       TARGET_PAGE_SIZE */
    qemu_real_host_page_size = getpagesize();
    if (qemu_host_page_size == 0)
        qemu_host_page_size = qemu_real_host_page_size;
    if (qemu_host_page_size < TARGET_PAGE_SIZE)
        qemu_host_page_size = TARGET_PAGE_SIZE;
    qemu_host_page_bits = 0;
    while ((1 << qemu_host_page_bits) < qemu_host_page_size)
        qemu_host_page_bits++;
    qemu_host_page_mask = ~(qemu_host_page_size - 1);
}

#if defined(CONFIG_USER_ONLY)
/* Currently it is not recommended to allocate big chunks of data in
   user mode. It will change when a dedicated libc will be used */
#define USE_STATIC_CODE_GEN_BUFFER
#endif

#ifdef USE_STATIC_CODE_GEN_BUFFER
static uint8_t static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE]
               __attribute__((aligned (CODE_GEN_ALIGN)));
static uint8_t static_sieve_buffer[DEFAULT_SIEVE_BUFFER_SIZE]
               __attribute__((aligned (CODE_GEN_ALIGN)));
#endif

#ifdef SWITCH_OPT 
static uint8_t static_switch_case_buffer[DEFAULT_SWITCH_CASE_BUFFER_SIZE]
               __attribute__((aligned (CODE_GEN_ALIGN)));
#endif

static void code_gen_alloc(unsigned long tb_size)
{
    code_gen_buffer = static_code_gen_buffer;
    code_gen_buffer_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
    map_exec(code_gen_buffer, code_gen_buffer_size);

    sieve_buffer = static_sieve_buffer;
    map_exec(sieve_buffer, DEFAULT_SIEVE_BUFFER_SIZE);

#ifdef SWITCH_OPT
	switch_case_buffer = static_switch_case_buffer;
	map_exec(switch_case_buffer, DEFAULT_SWITCH_CASE_BUFFER_SIZE);
#endif

    map_exec(code_gen_prologue, sizeof(code_gen_prologue));
    code_gen_buffer_max_size = code_gen_buffer_size - 
        (TCG_MAX_OP_SIZE * OPC_MAX_SIZE);
    code_gen_max_blocks = code_gen_buffer_size / CODE_GEN_AVG_BLOCK_SIZE;
    tbs = qemu_malloc(code_gen_max_blocks * sizeof(TranslationBlock));
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void cpu_exec_init_all(unsigned long tb_size)
{
    code_gen_alloc(tb_size);
    code_gen_ptr = code_gen_buffer;
    page_init();
}

/* flush all the translation blocks */
/* XXX: tb_flush is currently not thread safe */
void tb_flush(CPUState *env1)
{
    printf("qemu: tb flush\n");
    abort();
    CPUState *env;
#if defined(DEBUG_FLUSH)
    printf("qemu: flush code_size=%ld nb_tbs=%d avg_tb_size=%ld\n",
           (unsigned long)(code_gen_ptr - code_gen_buffer),
           nb_tbs, nb_tbs > 0 ?
           ((unsigned long)(code_gen_ptr - code_gen_buffer)) / nb_tbs : 0);
#endif
    if ((unsigned long)(code_gen_ptr - code_gen_buffer) > code_gen_buffer_size)
        cpu_abort(env1, "Internal error: code buffer overflow\n");

    nb_tbs = 0;

    for(env = first_cpu; env != NULL; env = env->next_cpu) {
        memset (env->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof (void *));
    }

    memset (tb_phys_hash, 0, CODE_GEN_PHYS_HASH_SIZE * sizeof (void *));
    ///page_flush_tb();

    code_gen_ptr = code_gen_buffer;
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    tb_flush_count++;
}

void tb_add_jmp_from(TranslationBlock *tb, TranslationBlock *next_tb, int n)
{
    ///fprintf(stderr, "0x%p->0x%p %d\n", tb->tc_ptr, next_tb->tc_ptr, n);
    /* ningjia: add jump_from support */
    next_tb->jmp_from[next_tb->jmp_from_index] = tb;
    next_tb->jmp_from_num[next_tb->jmp_from_index] = n;
    next_tb->jmp_from_index++;

    /* record how many tbs has more than one entries */
    if (next_tb->is_jmp_reg == 1 && next_tb->jmp_reg_mto == 0 && next_tb->jmp_from_index >= 2)
    {
        next_tb->jmp_reg_mto = 1;
        nb_tb_jmp_reg++;
    }
        
    
    if(next_tb->jmp_from_index == TB_FROM_MAX) {
        next_tb->jmp_from_index = 0;
        ///fprintf(stderr, "jmp_from_index overflow\n");
    }
}

TranslationBlock *make_tb(CPUState *env, target_ulong pc, 
                          uint32_t func_addr, uint32_t tb_tag)
{
    TranslationBlock *tb;
    uint8_t *tc_ptr;
    tb_page_addr_t phys_pc, phys_page2;
    int i;

    tb_tag = 0; //FIXME

    phys_pc = pc;
    tb = tb_alloc(pc);
    if (!tb) {
        /* flush must be done */
        tb_flush(env);
        /* cannot fail at this point */
        tb = tb_alloc(pc);
    }
    tc_ptr = (uint8_t *)NOT_TRANS_YET;
    tb->tc_ptr = tc_ptr;
    tb->insn_count = 0;
    tb->func_addr = func_addr;
    tb->tb_tag = tb_tag;

#ifdef SHA_RODATA
    tb->is_jmp_reg = 0;
    tb->jmp_reg_mto = 0;
#endif

    for(i = 0; i < PATCH_MAX; i++) {
        tb->tb_jmp_offset[i] = 0;
    }
    tb->jmp_from_index = 0;
#ifdef IND_OPT
    tb->jmp_ind_index = 0;
	tb->ind_miss_count = 0;
	tb->ind_replace_count = 0;
    tb->retransed = false;
#endif
    tb->patch_num = 0;
    tb_link_page(tb, phys_pc, phys_page2);
    env->tb_jmp_cache[tb_jmp_cache_hash_func(pc)] = tb;

#ifdef STATIC_PROF
    memset(tb->path, 0, sizeof(tb->path));
#endif
    return tb;
}

TranslationBlock *tb_gen_code(CPUState *env, target_ulong pc)
{
    TranslationBlock *tb;

    tb = make_tb(env, pc, 0, 0);
    cpu_gen_code(env, tb);

    return tb;
}

#if 1
int cpu_gen_code(CPUState *env, TranslationBlock *tb)
{
    int gen_code_size;

#if 0
    if(tb->tb_tag != 0)
        fprintf(stderr, "gen recur:0x%x pc:0x%x\n", tb->tb_tag, tb->pc);
#endif

    tb->tc_ptr = code_gen_ptr;
    gen_target_code(env, tb);
    gen_code_size = tb->hcode_size;

#if 0
    /* generate machine code */
    tb->tb_next_offset[0] = 0xffff;
    tb->tb_next_offset[1] = 0xffff;
#endif

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM)) {
        qemu_log("OUT: [size=%d]\n", gen_code_size);
        log_disas(tb->tc_ptr, gen_code_size);
        qemu_log("\n");
        qemu_log_flush();
    }
#endif
    return 0;
}
#endif

/* Allocate a new translation block. Flush the translation buffer if
   too many translation blocks or too much generated code. */
TranslationBlock *tb_alloc(target_ulong pc)
{
    TranslationBlock *tb;

    if (nb_tbs >= code_gen_max_blocks ||
        (code_gen_ptr - code_gen_buffer) >= code_gen_buffer_max_size)
        return NULL;
    tb = &tbs[nb_tbs++];
    tb->pc = pc;
    return tb;
}

void tb_free(TranslationBlock *tb)
{
    /* In practice this is mostly used for single use temporary TB
       Ignore the hard cases and just back up if this TB happens to
       be the last one generated.  */
    if (nb_tbs > 0 && tb == &tbs[nb_tbs - 1]) {
        code_gen_ptr = tb->tc_ptr;
        nb_tbs--;
    }
}

/* add a new TB and link it to the physical page tables. phys_page2 is
   (-1) to indicate that only one page contains the TB. */
void tb_link_page(TranslationBlock *tb,
                  tb_page_addr_t phys_pc, tb_page_addr_t phys_page2)
{
    unsigned int h;
    TranslationBlock **ptb;

    /* Grab the mmap lock to stop another thread invalidating this TB
       before we are done.  */
    ///mmap_lock();
    /* add in the physical hash table */
    h = tb_phys_hash_func(phys_pc);
    ptb = &tb_phys_hash[h];
    tb->phys_hash_next = *ptb;
    *ptb = tb;

#if 0 /* ningjia */
    /* add in the page list */
    tb_alloc_page(tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (phys_page2 != -1)
        tb_alloc_page(tb, 1, phys_page2);
    else
        tb->page_addr[1] = -1;
    tb->page_addr[1] = -1;

    tb->jmp_first = (TranslationBlock *)((long)tb | 2);
    tb->jmp_next[0] = NULL;
    tb->jmp_next[1] = NULL;

    /* init original jump addresses */
    if (tb->tb_next_offset[0] != 0xffff)
        tb_reset_jump(tb, 0);
    if (tb->tb_next_offset[1] != 0xffff)
        tb_reset_jump(tb, 1);
#endif

#ifdef DEBUG_TB_CHECK
    tb_page_check();
#endif
}

/* enable or disable low levels log */
void cpu_set_log(int log_flags)
{
    loglevel = log_flags;
    if (loglevel && !logfile) {
        logfile = fopen(logfilename, log_append ? "a" : "w");
        if (!logfile) {
            perror(logfilename);
            _exit(1);
        }
#if !defined(CONFIG_SOFTMMU)
        /* must avoid mmap() usage of glibc by setting a buffer "by hand" */
        {
            static char logfile_buf[4096];
            setvbuf(logfile, logfile_buf, _IOLBF, sizeof(logfile_buf));
        }
#elif !defined(_WIN32)
        /* Win32 doesn't support line-buffering and requires size >= 2 */
        setvbuf(logfile, NULL, _IOLBF, 0);
#endif
        log_append = 1;
    }
    if (!loglevel && logfile) {
        fclose(logfile);
        logfile = NULL;
    }
}

void cpu_set_log_filename(const char *filename)
{
    logfilename = strdup(filename);
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    cpu_set_log(loglevel);
}



const CPULogItem cpu_log_items[] = {
    { CPU_LOG_TB_OUT_ASM, "out_asm",
      "show generated host assembly code for each compiled TB" },
    { CPU_LOG_TB_IN_ASM, "in_asm",
      "show target assembly code for each compiled TB" },
    { CPU_LOG_TB_OP, "op",
      "show micro ops for each compiled TB" },
    { CPU_LOG_TB_OP_OPT, "op_opt",
      "show micro ops "
#ifdef TARGET_I386
      "before eflags optimization and "
#endif
      "after liveness analysis" },
    { CPU_LOG_INT, "int",
      "show interrupts/exceptions in short format" },
    { CPU_LOG_EXEC, "exec",
      "show trace before each executed TB (lots of logs)" },
    { CPU_LOG_TB_CPU, "cpu",
      "show CPU state before block translation" },
#ifdef TARGET_I386
    { CPU_LOG_PCALL, "pcall",
      "show protected mode far calls/returns/exceptions" },
    { CPU_LOG_RESET, "cpu_reset",
      "show CPU state before CPU resets" },
#endif
#ifdef DEBUG_IOPORT
    { CPU_LOG_IOPORT, "ioport",
      "show all i/o ports accesses" },
#endif
    { 0, NULL, NULL },
};


static int cmp1(const char *s1, int n, const char *s2)
{
    if (strlen(s2) != n)
        return 0;
    return memcmp(s1, s2, n) == 0;
}

/* takes a comma separated list of log masks. Return 0 if error. */
int cpu_str_to_log_mask(const char *str)
{
    const CPULogItem *item;
    int mask;
    const char *p, *p1;

    p = str;
    mask = 0;
    for(;;) {
        p1 = strchr(p, ',');
        if (!p1)
            p1 = p + strlen(p);
	if(cmp1(p,p1-p,"all")) {
		for(item = cpu_log_items; item->mask != 0; item++) {
			mask |= item->mask;
		}
	} else {
        for(item = cpu_log_items; item->mask != 0; item++) {
            if (cmp1(p, p1 - p, item->name))
                goto found;
        }
        return 0;
	}
    found:
        mask |= item->mask;
        if (*p1 != ',')
            break;
        p = p1 + 1;
    }
    return mask;
}

void cpu_abort(CPUState *env, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "qemu: fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
#ifdef TARGET_I386
    cpu_dump_state(env, stderr, fprintf, X86_DUMP_FPU | X86_DUMP_CCOP);
#else
    cpu_dump_state(env, stderr, fprintf, 0);
#endif
    if (qemu_log_enabled()) {
        qemu_log("qemu: fatal: ");
        qemu_log_vprintf(fmt, ap2);
        qemu_log("\n");
#ifdef TARGET_I386
        log_cpu_state(env, X86_DUMP_FPU | X86_DUMP_CCOP);
#else
        log_cpu_state(env, 0);
#endif
        qemu_log_flush();
        qemu_log_close();
    }
    va_end(ap2);
    va_end(ap);
#if defined(CONFIG_USER_ONLY)
    {
        struct sigaction act;
        sigfillset(&act.sa_mask);
        act.sa_handler = SIG_DFL;
        sigaction(SIGABRT, &act, NULL);
    }
#endif
    abort();
}

/* dummy func */
CPUState *cpu_copy(CPUState *env)
{
    abort();
    return env;
}

static void tb_invalidate_phys_page(tb_page_addr_t addr,
                                    unsigned long pc, void *puc)
{
    abort();
}
void cpu_exit(CPUState *env)
{
    abort();
}

void cpu_interrupt(CPUState *env, int mask)
{
    abort();
}

void cpu_breakpoint_remove_all(CPUState *env, int mask)
{
    abort();
}

void cpu_watchpoint_remove_all(CPUState *env, int mask)
{
    abort();
}


void tlb_flush(CPUState *env, int flush_global)
{
}

void tlb_flush_page(CPUState *env, target_ulong addr)
{
}

/*
 * Walks guest process memory "regions" one by one
 * and calls callback function 'fn' for each region.
 */

struct walk_memory_regions_data
{
    walk_memory_regions_fn fn;
    void *priv;
    unsigned long start;
    int prot;
};

static int walk_memory_regions_end(struct walk_memory_regions_data *data,
                                   abi_ulong end, int new_prot)
{
    if (data->start != -1ul) {
        int rc = data->fn(data->priv, data->start, end, data->prot);
        if (rc != 0) {
            return rc;
        }
    }

    data->start = (new_prot ? end : -1ul);
    data->prot = new_prot;

    return 0;
}

static int walk_memory_regions_1(struct walk_memory_regions_data *data,
                                 abi_ulong base, int level, void **lp)
{
    abi_ulong pa;
    int i, rc;

    if (*lp == NULL) {
        return walk_memory_regions_end(data, base, 0);
    }

    if (level == 0) {
        PageDesc *pd = *lp;
        for (i = 0; i < L2_SIZE; ++i) {
            int prot = pd[i].flags;

            pa = base | (i << TARGET_PAGE_BITS);
            if (prot != data->prot) {
                rc = walk_memory_regions_end(data, pa, prot);
                if (rc != 0) {
                    return rc;
                }
            }
        }
    } else {
        void **pp = *lp;
        for (i = 0; i < L2_SIZE; ++i) {
            pa = base | ((abi_ulong)i <<
                (TARGET_PAGE_BITS + L2_BITS * level));
            rc = walk_memory_regions_1(data, pa, level - 1, pp + i);
            if (rc != 0) {
                return rc;
            }
        }
    }

    return 0;
}

int walk_memory_regions(void *priv, walk_memory_regions_fn fn)
{
    struct walk_memory_regions_data data;
    unsigned long i;

    data.fn = fn;
    data.priv = priv;
    data.start = -1ul;
    data.prot = 0;

    for (i = 0; i < V_L1_SIZE; i++) {
        int rc = walk_memory_regions_1(&data, (abi_ulong)i << V_L1_SHIFT,
                                       V_L1_SHIFT / L2_BITS - 1, l1_map + i);
        if (rc != 0) {
            return rc;
        }
    }

    return walk_memory_regions_end(&data, 0, 0);
}

static int dump_region(void *priv, abi_ulong start,
    abi_ulong end, unsigned long prot)
{
    FILE *f = (FILE *)priv;

    (void) fprintf(f, TARGET_ABI_FMT_lx"-"TARGET_ABI_FMT_lx
        " "TARGET_ABI_FMT_lx" %c%c%c\n",
        start, end, end - start,
        ((prot & PAGE_READ) ? 'r' : '-'),
        ((prot & PAGE_WRITE) ? 'w' : '-'),
        ((prot & PAGE_EXEC) ? 'x' : '-'));

    return (0);
}

static PageDesc *page_find_alloc(tb_page_addr_t index, int alloc)
{
    PageDesc *pd;
    void **lp;
    int i;

    /* We can't use qemu_malloc because it may recurse into a locked mutex. */
# define ALLOC(P, SIZE)                                 \
    do {                                                \
        P = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,    \
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   \
    } while (0)

    /* Level 1.  Always allocated.  */
    lp = l1_map + ((index >> V_L1_SHIFT) & (V_L1_SIZE - 1));

    /* Level 2..N-1.  */
    for (i = V_L1_SHIFT / L2_BITS - 1; i > 0; i--) {
        void **p = *lp;

        if (p == NULL) {
            if (!alloc) {
                return NULL;
            }
            ALLOC(p, sizeof(void *) * L2_SIZE);
            *lp = p;
        }

        lp = p + ((index >> (i * L2_BITS)) & (L2_SIZE - 1));
    }

    pd = *lp;
    if (pd == NULL) {
        if (!alloc) {
            return NULL;
        }
        ALLOC(pd, sizeof(PageDesc) * L2_SIZE);
        *lp = pd;
    }

#undef ALLOC

    return pd + (index & (L2_SIZE - 1));
}

static inline PageDesc *page_find(tb_page_addr_t index)
{
    return page_find_alloc(index, 0);
}

/* dump memory mappings */
void page_dump(FILE *f)
{
    (void) fprintf(f, "%-8s %-8s %-8s %s\n",
            "start", "end", "size", "prot");
    walk_memory_regions(f, dump_region);
}

int page_get_flags(target_ulong address)
{
    PageDesc *p;

    p = page_find(address >> TARGET_PAGE_BITS);
    if (!p)
        return 0;
    return p->flags;
}

/* Modify the flags of a page and invalidate the code if necessary.
   The flag PAGE_WRITE_ORG is positioned automatically depending
   on PAGE_WRITE.  The mmap_lock should already be held.  */
void page_set_flags(target_ulong start, target_ulong end, int flags)
{
    target_ulong addr, len;

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(end < ((abi_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif
    assert(start < end);

    start = start & TARGET_PAGE_MASK;
    end = TARGET_PAGE_ALIGN(end);

    if (flags & PAGE_WRITE) {
        flags |= PAGE_WRITE_ORG;
    }

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
        PageDesc *p = page_find_alloc(addr >> TARGET_PAGE_BITS, 1);

        /* If the write protection bit is set, then we invalidate
           the code inside.  */
        if (!(p->flags & PAGE_WRITE) &&
            (flags & PAGE_WRITE) &&
            p->first_tb) {
            tb_invalidate_phys_page(addr, 0, NULL);
        }
        p->flags = flags;
    }
}

int page_check_range(target_ulong start, target_ulong len, int flags)
{
    PageDesc *p;
    target_ulong end;
    target_ulong addr;

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(start < ((abi_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif

    if (len == 0) {
        return 0;
    }
    if (start + len - 1 < start) {
        /* We've wrapped around.  */
        return -1;
    }

    end = TARGET_PAGE_ALIGN(start+len); /* must do before we loose bits in the next step */
    start = start & TARGET_PAGE_MASK;

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
        p = page_find(addr >> TARGET_PAGE_BITS);
        if( !p )
            return -1;
        if( !(p->flags & PAGE_VALID) )
            return -1;

        if ((flags & PAGE_READ) && !(p->flags & PAGE_READ))
            return -1;
        if (flags & PAGE_WRITE) {
            if (!(p->flags & PAGE_WRITE_ORG))
                return -1;
            /* unprotect the page if it was put read-only because it
               contains translated code */
            if (!(p->flags & PAGE_WRITE)) {
                if (!page_unprotect(addr, 0, NULL))
                    return -1;
            }
            return 0;
        }
    }
    return 0;
}

/* called from signal handler: invalidate the code and unprotect the
   page. Return TRUE if the fault was successfully handled. */
int page_unprotect(target_ulong address, unsigned long pc, void *puc)
{
    unsigned int prot;
    PageDesc *p;
    target_ulong host_start, host_end, addr;

    /* Technically this isn't safe inside a signal handler.  However we
       know this only ever happens in a synchronous SEGV handler, so in
       practice it seems to be ok.  */
    mmap_lock();

    p = page_find(address >> TARGET_PAGE_BITS);
    if (!p) {
        mmap_unlock();
        return 0;
    }

    /* if the page was really writable, then we change its
       protection back to writable */
    if ((p->flags & PAGE_WRITE_ORG) && !(p->flags & PAGE_WRITE)) {
        host_start = address & qemu_host_page_mask;
        host_end = host_start + qemu_host_page_size;

        prot = 0;
        for (addr = host_start ; addr < host_end ; addr += TARGET_PAGE_SIZE) {
            p = page_find(addr >> TARGET_PAGE_BITS);
            p->flags |= PAGE_WRITE;
            prot |= p->flags;

            /* and since the content will be modified, we must invalidate
               the corresponding translated code. */
            tb_invalidate_phys_page(addr, pc, puc);
#ifdef DEBUG_TB_CHECK
            tb_invalidate_check(addr);
#endif
        }
        mprotect((void *)g2h(host_start), qemu_host_page_size,
                 prot & PAGE_BITS);

        mmap_unlock();
        return 1;
    }
    mmap_unlock();
    return 0;
}

/* physical memory access (slow version, mainly for debug) */
int cpu_memory_rw_debug(CPUState *env, target_ulong addr,
                        uint8_t *buf, int len, int is_write)
{
    int l, flags;
    target_ulong page;
    void * p;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        flags = page_get_flags(page);

        if (!(flags & PAGE_VALID))
            return -1;
        if (is_write) {
            if (!(flags & PAGE_WRITE))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_WRITE, addr, l, 0)))
                return -1;
            memcpy(p, buf, l);
            unlock_user(p, addr, l);
        } else {
            if (!(flags & PAGE_READ))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_READ, addr, l, 1)))
                return -1;
            memcpy(buf, p, l);
            unlock_user(p, addr, 0);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

