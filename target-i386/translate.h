#ifndef _TRANSLATE_H_
#define _TRANSLATE_H_

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <asm/unistd.h>

#include "cpu.h"
#include "exec-all.h"
#include "disas.h"

#include "decode.h"
#include "emit.h"

#ifdef SHA_RODATA
	#define IS_JMP 0
	#define IS_CALL 1

	#define CANNOT_OPT 0 
	#define CAN_OPT 1
	
	#define DISP_MEM 1 
	#define REG_MEM 2
	#define MEM 3
	#define REG 4 
    #define INCL_RING(c)\
    do {\
        c = (c + 1) % 6;\
    } while(0)
#endif

extern uint8_t *code_gen_ptr;
extern uint8_t *code_gen_buffer;
extern uint8_t *sieve_buffer;
extern uint8_t *switch_case_buffer;
extern uint8_t code_gen_prologue[];
extern int prolog_count;
extern int nb_tbs;
extern int jmp_reg_tb;
extern int nb_tb_jmp_reg;
extern int nb_ind_tgt_nodes;
extern TranslationBlock *tbs;


#ifdef COUNT_PROF
    #define INCL_COUNT(c) \
    do { \
        cemit_incl_mem64(env, (uint32_t)&cgc->c); \
    } while(0)
#else
    #define INCL_COUNT(c)
#endif

#define ABORT_IF(cond, msg) \
    do { \
        if(cond) { \
            fprintf(stderr, msg); \
            abort(); \
        } \
    } while(0)

#ifdef COUNT_INSN
    #define ADD_INSNS_COUNT(mem, v) \
    do { \
        /* incl insn_count */ \
        cemit_add_mem64(env, (uint32_t)&(mem), (uint32_t)(v)); \
    } while(0)
#else
    #define ADD_INSNS_COUNT(mem, v)
#endif

#ifdef PROF_PREV_TB
    #define SAVE_PREV_TB(env, mem, v) \
    do { \
        /* movl $v, (mem) */ \
        code_emit8(env->code_ptr, 0xc7); \
        code_emit8(env->code_ptr, 0x05); /* ModRM = 00 000 101b */ \
        code_emit32(env->code_ptr, (uint32_t)&(mem)); \
        code_emit32(env->code_ptr, (v)); \
    } while(0)
#else
    #define SAVE_PREV_TB(env, mem, v)
#endif

#ifdef PROF_PATH
    #define PUSH_PATH(env, is_ind) \
    do { \
        cemit_push_path(env, is_ind); \
    } while(0)
#else
    #define PUSH_PATH(env, is_ind)
#endif

typedef struct SuperTransBlock {
    uint32_t pc_start;
    uint32_t pc_end;
    uint32_t tc_ptr;
#ifdef PATCH_IN_TB
    uint32_t insn_offset[OFF_MAX];
#endif
} SuperTransBlock;

typedef struct stat_node {
    uint32_t src_addr;
    uint32_t path[PATH_DEPTH + 1];
    /* restore the targets and the hit count of each target */
    uint32_t tgt_addr[STAT_TGT_MAX];
    uint64_t tgt_addr_hit[STAT_TGT_MAX];
    uint64_t tgt_dyn_count;
    uint32_t tgt_count;
    uint32_t tgt_recent_addr[IND_SLOT_MAX];
    uint64_t tgt_recent_hit;
    uint64_t recent_index;
    int	     profed;
    struct stat_node *next;
} stat_node;

typedef struct ind_info_node {
    uint32_t src_addr;
    uint32_t tgt_addr[IND_SLOT_MAX];
    uint32_t path[PATH_DEPTH + 1];
} ind_info_node;

typedef struct code_gen_context {
    uint8_t *tb_ret_addr;
    uint32_t pc_ptr;
    uint32_t pc_start;
    uint32_t insn_len;

    SuperTransBlock stbs[STB_MAX];
#ifdef PATCH_IN_TB
    SuperTransBlock *stbs_recent[STB_DEPTH];
    uint32_t stb_recent_num;
#endif
    uint32_t stb_count;

    /* static insns count */
    uint32_t jmp_count;
    uint32_t jcond_count;
    uint32_t jothercond_count;
    uint32_t call_count;
    uint32_t call_ind_count;
    uint32_t ret_count;
    uint32_t retIw_count;
    uint32_t j_ind_count;
    uint32_t patch_in_tb_count;
    uint32_t find_dest_count;
    uint32_t s_code_size;
#ifdef SIEVE_OPT
    uint32_t sieve_stat[SIEVE_SIZE];
#endif

    /* stb end type */
    uint32_t end_by_transnext;
#ifdef COUNT_PROF
    /* dynamic insns count */
    uint64_t insn_dyn_count;
    uint64_t ret_dyn_count;
    uint64_t ras_dyn_count;
    uint64_t ras_miss_count;
    uint64_t rc_miss_count;
    uint32_t sv_miss_count;
    uint32_t recur_dyn_count;
    uint64_t rc_ind_nothit_count;
    uint64_t rc_ind_dyn_count;
    uint64_t sv_travel_count;

    uint64_t cind_nothit_count;
    uint64_t jind_nothit_count;
    uint64_t jind_dyn_count;
    uint64_t cind_dyn_count;
#ifdef SHA_RODATA
	uint64_t jind_disp_mem;
	uint64_t jind_reg_mem;
	uint64_t jind_mem;
	uint64_t jind_reg;
	uint64_t opt_jind_nothit_count;
	uint64_t opt_jind_dyn_count;
	uint64_t opt_failed_jind_dyn_count;
	
	uint64_t cind_disp_mem;
	uint64_t cind_reg_mem;
	uint64_t cind_mem;
	uint64_t cind_reg;
	uint64_t opt_cind_nothit_count;
	uint64_t opt_cind_dyn_count;
	uint64_t opt_failed_cind_dyn_count;
#endif
#endif
    stat_node stat_nodes[STAT_NODE_MAX];
    uint32_t stat_node_count;

    ind_info_node info_nodes[STAT_NODE_MAX];
    int info_node_num;

#ifdef RETRANS_IND
    uint32_t retrans_tb_count;
#endif

    FILE *fp_db;
} code_gen_context;

extern code_gen_context *cgc;
extern TranslationBlock *cur_tb;
extern FILE *fout;
void rebuild_profed_tb(CPUX86State *env, TranslationBlock *tb);
void add_sieve_entry(CPUX86State *env, TranslationBlock *tb, int type);
void ind_patch_sieve(CPUX86State *env, uint8_t* enter_sieve_ptr);
void lazy_patch(CPUX86State *env);
void note_patch(CPUX86State *env, uint8_t *at, uint8_t *to, uint8_t *tb, 
                uint32_t func_addr, uint32_t tb_tag);

#ifdef SWITCH_OPT
typedef struct sa_ptn {
	 int flag;
	 int scale;
	 int reg;
	 long displacement;
	 uint32_t t_sum;
} sa_ptn;
extern sa_ptn *cur_ptn;
extern int sa_num;
extern int call_table;
#endif

#endif
