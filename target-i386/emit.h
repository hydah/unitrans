#ifndef EMIT_H
#define EMIT_H


#define NEED_PATCH_32	0x5a5a
#define NEED_PATCH_8	0x5a
#define MAX_INSNS	1024 * 8

#define code_emit8(code_emit_ptr, val) do{ \
        *(code_emit_ptr)++ = val; \
} while(0)

#define code_emit16(code_emit_ptr, val) do{ \
        *(uint16_t *)(code_emit_ptr) = (val); \
        (code_emit_ptr) += 2; \
} while(0)

#define code_emit32(code_emit_ptr, val) do{ \
        *(uint32_t *)(code_emit_ptr) = (val); \
        (code_emit_ptr) += 4; \
} while(0)

bool inline emit_normal(CPUX86State *loc_env, decode_t *ds);
bool emit_int(CPUX86State *loc_env, decode_t *ds);
bool emit_sysenter(CPUX86State *loc_env, decode_t *ds);

bool emit_jcond(CPUX86State *loc_env, decode_t *ds);
bool emit_other_jcond(CPUX86State *loc_env, decode_t *ds);
bool emit_jmp(CPUX86State *loc_env, decode_t *ds);
bool emit_jmp_near_mem(CPUX86State *loc_env, decode_t *ds);

bool emit_call_disp(CPUX86State *loc_env, decode_t *ds);
bool emit_call_near_mem(CPUX86State *loc_env, decode_t *ds);

bool emit_ret(CPUX86State *loc_env, decode_t *ds);
bool emit_ret_Iw(CPUX86State *loc_env, decode_t *ds);

#endif

