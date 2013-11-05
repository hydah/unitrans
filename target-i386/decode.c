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

#define READ_IN_NEXT_BYTE(ds)             \
      do {ds->b = ldub_code(ds->decode_eip);  \
      (ds->decode_eip)++; } while(0)
#define READ_IN_NEXT_WORD(ds)             \
      do {ds->b = lduw_code(ds->decode_eip);  \
      (ds->decode_eip) += 2; } while(0)
#define READ_IN_NEXT_LONG(ds)             \
      do {ds->b = ldl_code(ds->decode_eip);  \
      (ds->decode_eip) += 4; } while(0)


uint32_t simple_disas_insn(decode_t *ds, target_ulong pc)
{
    //unsigned i;
    CONST_TABLE OpCode *table = nopbyte0;
    CONST_TABLE OpCode *pEntry = 0;
    int wierd = 0;

    ds->decode_eip = pc;
    ds->attr = 0;
    ds->emitfn = 0;
    ds->modrm_regs = 0;      /* registers sourced by this instruction */
    ds->need_sib = 0;
    ds->dispBytes = 0;
    ds->no_of_prefixes = 0;
    ds->Group1_Prefix=0;
    ds->Group2_Prefix=0;
    ds->Group3_Prefix=0;
    ds->Group4_Prefix=0;
    ds->flags = 0;
    ds->opstate = OPSTATE_DATA32 | OPSTATE_ADDR32;

    for(;;){
        ds->b = ldub_code(ds->decode_eip);
        if (IS_IFAULT(ds->b))
            goto handle_ifault;

        ds->attr = table[ds->b].attr;

        if ((ds->attr & DF_PREFIX) == 0)
            break;

        ds->no_of_prefixes ++; 

        switch(ds->b) {
            case HD_PREFIX_LOCK:
            case HD_PREFIX_REPZ:
            case HD_PREFIX_REPNZ:
                ds->flags |= DSFL_GROUP1_PREFIX;
                ds->Group1_Prefix = ds->b;
                break;

            case HD_PREFIX_CS:
            case HD_PREFIX_DS:
            case HD_PREFIX_ES:
            case HD_PREFIX_FS:
            case HD_PREFIX_GS:
            case HD_PREFIX_SS:
                ds->flags |= DSFL_GROUP2_PREFIX;
                ds->Group2_Prefix = ds->b;
                break;

            case HD_PREFIX_OPSZ:
                ds->flags |= DSFL_GROUP3_PREFIX;
                ds->opstate ^= OPSTATE_DATA32;
                ds->Group3_Prefix = ds->b;
                break;

            case HD_PREFIX_ADDRSZ:
                ds->flags |= DSFL_GROUP4_PREFIX;
                ds->opstate ^= OPSTATE_ADDR32;
                ds->Group4_Prefix = ds->b;
                break;
        }
        (ds->decode_eip)++;
    }

    /* Pick off the instruction bytes */
    ds->instr = (unsigned char *)(ds->decode_eip);

    for(;;) {
        ds->b = ldub_code(ds->decode_eip);
        if (IS_IFAULT(ds->b))
            goto handle_ifault;
        pEntry = &table[ds->b];
        ds->attr = pEntry->attr;
        (ds->decode_eip)++;

        if (ds->attr & DF_TABLE) {
            table = pEntry->ptr;
            //ds->attr &= ~DF_TABLE;
            continue;
        }

        if (ds->attr & DF_FLOAT) {
            wierd = 1;
            table = pEntry->ptr;
            ds->b = ldub_code(ds->decode_eip);
            if (IS_IFAULT(ds->b))
                goto handle_ifault;
            (ds->decode_eip)++;
            ds->modrm.byte = ds->b;
            if (ds->modrm.parts.mod == 0x3u) {
                pEntry = &table[ds->modrm.parts.reg + 8];
                ds->attr = pEntry->attr;
                if (ds->attr & DF_ONE_MORE_LEVEL) {
                    table = pEntry->ptr;
                    pEntry = &table[ds->modrm.parts.rm];
                    ds->attr = pEntry->attr;
                }
            }
            else {
                pEntry = &table[ds->modrm.parts.reg];
                ds->attr = pEntry->attr;
            }
        }
        break;
    }

    /* If needed, fetch the modR/M byte: */
    if (!wierd) {
        /* i.e., If we have not already eaten up the modR/M byte because of Escape opcodes */
        if (ds->attr & (DF_MODRM|DF_GROUP)) {
            READ_IN_NEXT_BYTE(ds);
        }
    }

    /* If attr now contains DF_GROUP, then the last byte fetched (the
     * current value of b) was the modrm byte and we need to do one more
     * round of table processing to pick off the proper opcode. */

    if (ds->attr & DF_GROUP) {
        ds->modrm.byte = ds->b;
        pEntry = pEntry->ptr;
        pEntry += ds->modrm.parts.reg;
        ds->attr |= pEntry->attr;
    }

    /* Note that if opcode requires modrm processing then ds->b
     * currently holds the modrm byte.
     */
    if (ds->attr & (DF_MODRM))
        ds->modrm.byte = ds->b;

    /* /attr/ now contains accumulated attributes. /pEntry/ points to
     * last located entry, which specifies what we are going to do in
     * the end. Finish copying modrm arguments and immediate values, if
     * any. 
     */
    if (ds->attr & (DF_MODRM|DF_GROUP)) {
        if (ds->opstate & OPSTATE_ADDR32) {
            /* ds->mod of 00b, 01b, 10b  are the register-indirect cases,
               except that ds->rm == 100b implies a sib byte and (ds->mod,
               ds->rm) of (00b, 101b) is disp32. */
            if ((ds->modrm.parts.mod != 0x3u) && (ds->modrm.parts.rm == 4u))
                ds->need_sib = 1;    /* scaled index mode */

            if (ds->modrm.parts.mod == 0u && ds->modrm.parts.rm == 5u)
                ds->dispBytes = 4;    /* memory absolute */
            else if (ds->modrm.parts.mod == 1u)
                ds->dispBytes = 1;
            else if (ds->modrm.parts.mod == 2u)
                ds->dispBytes = 4;
        }
        else {  
            /* No SIB byte to consider, but pick off 
               (ds->mod, ds->rm) == (00b,110b) since that is disp16 */
            if (ds->modrm.parts.mod == 0u && ds->modrm.parts.rm == 6u)
                ds->dispBytes = 2;    /* memory absolute */
            else if (ds->modrm.parts.mod == 1u)
                ds->dispBytes = 1;
            else if (ds->modrm.parts.mod == 2u)
                ds->dispBytes = 2;
        }

        if (ds->need_sib) {
            READ_IN_NEXT_BYTE(ds);
            ds->sib.byte = ds->b;
            if ((ds->sib.parts.base == GP_REG_EBP) && (ds->modrm.parts.mod == 0u))
                ds->dispBytes = 4;
        }

        if (ds->dispBytes) {
            if(ds->dispBytes > 2){
                READ_IN_NEXT_LONG(ds);
                ds->displacement = ds->b;
            }else if(ds->dispBytes > 1){
                READ_IN_NEXT_WORD(ds);
                ds->displacement = ds->b;
            } else{
                READ_IN_NEXT_BYTE(ds);
                ds->displacement = ds->b;
            }
        }
    }

    /* At this point we have everything except the immediates (or
       offsets, depending on the instruction. Of the instructions that
       take such, only one (ENTER) takes more than one. Iw mode is in
       fact used only by ENTER, RET, and LRET. We therefore proceed by
       handling Iw as a special case. */

    if (ds->attr & DF_Iw) {
        READ_IN_NEXT_WORD(ds);
        ds->imm16 = ds->b;
    }

    if ((ds->attr & DF_Ib) || (ds->attr & DF_Jb)) {
        READ_IN_NEXT_BYTE(ds);
        signed char sc = ds->b;    /* for sign extension */
        ds->immediate = sc;
    }

    if (ds->attr & DF_Iv) {
        if (ds->opstate & OPSTATE_DATA32) {
            READ_IN_NEXT_LONG(ds);
            ds->immediate = ds->b;
        }
        else{
            READ_IN_NEXT_WORD(ds);
            ds->immediate = ds->b;
        }
    }

    if ((ds->attr & DF_Ov) || (ds->attr & DF_Ob)) {
        if (ds->opstate & OPSTATE_ADDR32) {
            READ_IN_NEXT_LONG(ds);
            ds->immediate = ds->b;
        }
        else{
            READ_IN_NEXT_WORD(ds);
            ds->immediate = ds->b;
        }
    }

    if (ds->attr & (DF_Jv|DF_Ap)) {
        if (ds->opstate & OPSTATE_DATA32) {
            READ_IN_NEXT_LONG(ds);
            ds->immediate = ds->b;
        }
        else{
            READ_IN_NEXT_WORD(ds);
            ds->immediate = ds->b;
        }
    }

    if (ds->attr & DF_Ap) {
        READ_IN_NEXT_WORD(ds);
        ds->imm16 = ds->b;
    }

    ds->pInstr = (unsigned char *)ldub_code(ds->decode_eip);

    ds->emitfn = pEntry->ptr;
    ds->pEntry = pEntry;

    if (ds->attr & DF_UNDEFINED) {
        //DEBUG(decode)
        //    printf ("\nUndefined opcode: %2X %2X at %08X\n", ds->instr[0], ds->instr[1], ds->decode_eip);
        return false;
    }

    if (pEntry->ptr == 0)
        return false;

    ds->inst_type = pEntry->inst_type;
    return true;

handle_ifault:
    /* We took an instruction fetch fault of some form on this byte. */
    ds->pInstr = (unsigned char *)ldub_code(ds->decode_eip);

    //ds->emitfn = pEntry->ptr;
    ds->pEntry = pEntry;

    return false;

}
