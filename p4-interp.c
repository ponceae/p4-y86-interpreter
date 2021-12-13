/*
 * CS 261 PA4: Mini-ELF interpreter
 *
 * Name: Adrien Ponce
 */

#include "p4-interp.h"
void write_back_reg(y86_regnum_t reg, y86_t *cpu, y86_reg_t valX);
bool get_mov_cnd(y86_cmov_t mov, y86_t *cpu);
bool get_jmp_cnd(y86_jump_t jmp, y86_t *cpu);
y86_reg_t set_op_cc(y86_reg_t valB, y86_reg_t *valA, y86_inst_t ins, y86_t *cpu);

/**********************************************************************
 *                         REQUIRED FUNCTIONS
 *********************************************************************/

y86_reg_t decode_execute (y86_t *cpu, y86_inst_t inst, bool *cnd, y86_reg_t *valA)
{
    // brief error checking for NULL values
    if (valA == NULL) {
        cpu->stat = INS;
    }

    // initialize registers
    y86_reg_t valE, valB = 0;

    // y86 decode stages
    switch (inst.icode) {
        case CMOV:
            *valA = cpu->reg[inst.ra];
            break;
        case RMMOVQ:
            *valA = cpu->reg[inst.ra];
            valB = cpu->reg[inst.rb];
            break;
        case MRMOVQ:
            valB = cpu->reg[inst.rb];
            break;
        case OPQ:
            *valA = cpu->reg[inst.ra];
            valB = cpu->reg[inst.rb];
            break;
        case CALL:
            valB = cpu->reg[RSP];
            break;
        case RET:
            *valA = cpu->reg[RSP];
            valB = cpu->reg[RSP];
            break;
        case PUSHQ:
            *valA = cpu->reg[inst.ra];
            valB = cpu->reg[RSP];
            break;
        case POPQ:
            *valA = cpu->reg[RSP];
            valB = cpu->reg[RSP];
            break;
        case INVALID:
            cpu->stat = INS;
            break;
        default:
            break;
    }

    // y86 execute stages
    switch (inst.icode) {
        // clear all sign bits on halt
        case HALT:
            cpu->stat = HLT;
            cpu->of = false;
            cpu-> sf = false;
            cpu->zf = false;
            break;
        case CMOV:
            valE = *valA;
            *cnd = get_mov_cnd(inst.ifun.cmov, cpu);
            break;
        case IRMOVQ:
            valE = inst.valC.v;
            break;
        case RMMOVQ:
            valE = (int64_t) (valB + inst.valC.d);
            break;
        case MRMOVQ:
            valE = (int64_t) (valB + inst.valC.d);
            break;
        case OPQ:
            valE = set_op_cc(valB, valA, inst, cpu);
            break;
        case JUMP:
            *cnd = get_jmp_cnd(inst.ifun.jump, cpu);
            break;
        case CALL:
            valE = (int64_t) (valB - 8);
            break;
        case RET:
            valE = (int64_t) (valB + 8);
            break;
        case PUSHQ:
            valE = (int64_t) (valB - 8);
            break;
        case POPQ:
            valE = (int64_t) (valB + 8);
            break;
        case INVALID:
            cpu->stat = INS;
            break;
        default:
            break;
    }

    return valE;
}

void memory_wb_pc (y86_t *cpu, y86_inst_t inst, byte_t *memory,
                   bool cnd, y86_reg_t valA, y86_reg_t valE)
{
    // initialize register
    y86_reg_t valM = 0;

    // pointer to eight bytes of memory
    uint64_t *m8 = 0;

    // y86 memory stages
    switch (inst.icode) {
        case RMMOVQ:
            // eight bytes of memory at address valE
            m8 = (uint64_t*) &memory[valE];
            *m8 = valA;
            break;
        case MRMOVQ:
            // check for valid valE
            if (valE >= MEMSIZE) {
                cpu->stat = ADR;
                break;
            }
            m8 = (uint64_t*) &memory[valE];
            valM = *m8;
            break;
        case CALL:
            m8 = (uint64_t*) &memory[valE];
            *m8 = inst.valP;
            break;
        case RET:
            // eight bytes of memory at address valA
            m8 = (uint64_t*) &memory[valA];
            valM = *m8;
            break;
        case PUSHQ:
            m8 = (uint64_t*) &memory[valE];
            *m8 = valA;
            break;
        case POPQ:
            m8 = (uint64_t*) &memory[valA];
            valM = *m8;
            break;
        case INVALID:
            cpu->stat = INS;
            break;
        default:
            break;
    }

    // y86 write back stages
    switch (inst.icode) {
        case CMOV:
            // only write to reg if conditions are met
            if (cnd) {
                write_back_reg(inst.rb, cpu, valE);
            }
            break;
        case IRMOVQ:
            cpu->reg[inst.rb] = valE;
            break;
        case MRMOVQ:
            if (valE >= MEMSIZE) {
                cpu->stat = ADR;
                break;
            }
            // write value from valM back to rA
            write_back_reg(inst.ra, cpu, valM);
            break;
        case OPQ:
            cpu->reg[inst.rb] = valE;
            break;
        case CALL:
            cpu->reg[RSP] = valE;
            break;
        case RET:
            cpu->reg[RSP] = valE;
            break;
        case PUSHQ:
            cpu->reg[RSP] = valE;
            break;
        case POPQ:
            cpu->reg[RSP] = valE;
            write_back_reg(inst.ra, cpu, valM);
            break;
        case INVALID:
            cpu->stat = INS;
            break;
        default:
            break;
    }

    // y86 pc update stages
    switch (inst.icode) {
        case JUMP:
            cpu->pc = inst.valC.dest;
            break;
        case CALL:
            cpu->pc = inst.valC.dest;
            break;
        case RET:
            cpu->pc = valM;
            break;
        case INVALID:
            cpu->stat = INS;
            break;
        default:
            cpu->pc = inst.valP;
            break;
    }
}

/**********************************************************************
 *                         OPTIONAL FUNCTIONS
 *********************************************************************/

void usage_p4 (char **argv)
{
    printf("Usage: %s <option(s)> mini-elf-file\n", argv[0]);
    printf(" Options are:\n");
    printf("  -h      Display usage\n");
    printf("  -H      Show the Mini-ELF header\n");
    printf("  -a      Show all with brief memory\n");
    printf("  -f      Show all with full memory\n");
    printf("  -s      Show the program headers\n");
    printf("  -m      Show the memory contents (brief)\n");
    printf("  -M      Show the memory contents (full)\n");
    printf("  -d      Disassemble code contents\n");
    printf("  -D      Disassemble data contents\n");
    printf("  -e      Execute program\n");
    printf("  -E      Execute program (trace mode)\n");
}

bool parse_command_line_p4 (int argc, char **argv,
                            bool *header, bool *segments, bool *membrief, bool *memfull,
                            bool *disas_code, bool *disas_data,
                            bool *exec_normal, bool *exec_trace, char **filename)
{
    // brief error checking for NULL
    if (argv == NULL || header == NULL || segments == NULL
            || membrief == NULL || memfull == NULL
            || disas_code == NULL || disas_data == NULL
            || exec_normal == NULL || exec_trace == NULL
            || filename == NULL) {
        return false;
    }

    int c;
    while ((c = getopt(argc, argv, "hHafsmMdDeE")) != -1) {
        switch (c) {
            case 'h':                   // display usage
                usage_p4(argv);
                return true;
            case 'H':                   // display Mini-Elf header
                *header = true;
                break;
            case 'a':                   // display H, s, m flags
                *header = true;
                *segments = true;
                *membrief = true;
                break;
            case 'f':                   // display H, s, M flags
                *header = true;
                *segments = true;
                *memfull = true;
                break;
            case 's':                   // display program headers
                *segments = true;
                break;
            case 'm':                   // display brief memory contents
                *membrief = true;
                break;
            case 'M':                   // display full memory contents
                *memfull = true;
                break;
            case 'd':                   // dissasemble code
                *disas_code = true;
                break;
            case 'D':                   // dissasemble data
                *disas_data = true;
                break;
            case 'e':                   // execute program
                *exec_normal = true;
                break;
            case 'E':                   // execute program in trace mode
                *exec_trace = true;
                break;
            default:                    // display usage (default)
                usage_p4(argv);
                return false;
        }
    }

    if (optind != argc-1) {
        // no filename (or extraneous input)
        usage_p4(argv);
        return false;
    }

    *filename = argv[optind];   // save filename

    return true;
}

void dump_cpu_state (y86_t cpu)
{
    printf("Y86 CPU state:\n");
    // print instruction pointer
    printf("  %%rip: %016lx   flags: Z%d S%d O%d     ", cpu.pc, cpu.zf, cpu.sf, cpu.of);

    // check which status is active
    switch (cpu.stat) {
        case AOK:
            printf("AOK\n");
            break;
        case HLT:
            printf("HLT\n");
            break;
        case ADR:
            printf("ADR\n");
            break;
        case INS:
            printf("INS\n");
            break;
    }

    // register prints
    printf("  %%rax: %016lx    %%rcx: %016lx\n", cpu.reg[RAX], cpu.reg[RCX]);
    printf("  %%rdx: %016lx    %%rbx: %016lx\n", cpu.reg[RDX], cpu.reg[RBX]);
    printf("  %%rsp: %016lx    %%rbp: %016lx\n", cpu.reg[RSP], cpu.reg[RBP]);
    printf("  %%rsi: %016lx    %%rdi: %016lx\n", cpu.reg[RSI], cpu.reg[RDI]);
    printf("   %%r8: %016lx     %%r9: %016lx\n", cpu.reg[R8], cpu.reg[R9]);
    printf("  %%r10: %016lx    %%r11: %016lx\n", cpu.reg[R10], cpu.reg[R11]);
    printf("  %%r12: %016lx    %%r13: %016lx\n", cpu.reg[R12], cpu.reg[R13]);
    printf("  %%r14: %016lx\n",                  cpu.reg[R14]);
}

/*
 *  Helper method to modify valX based on the value of reg and
 *  updates it to the CPU.
 */
void write_back_reg(y86_regnum_t reg, y86_t *cpu, y86_reg_t valX)
{
    switch (reg) {
        case RAX:
            cpu->reg[RAX] = valX;
            break;
        case RCX:
            cpu->reg[RCX] = valX;
            break;
        case RDX:
            cpu->reg[RDX] = valX;
            break;
        case RBX:
            cpu->reg[RBX] = valX;
            break;
        case RSP:
            cpu->reg[RSP] = valX;
            break;
        case RBP:
            cpu->reg[RBP] = valX;
            break;
        case RSI:
            cpu->reg[RSI] = valX;
            break;
        case RDI:
            cpu->reg[RDI] = valX;
            break;
        case R8:
            cpu->reg[R8]  = valX;
            break;
        case R9:
            cpu->reg[R9]  = valX;
            break;
        case R10:
            cpu->reg[R10] = valX;
            break;
        case R11:
            cpu->reg[R11] = valX;
            break;
        case R12:
            cpu->reg[R12] = valX;
            break;
        case R13:
            cpu->reg[R13] = valX;
            break;
        case R14:
            cpu->reg[R14] = valX;
            break;
        case NOREG:
            cpu->stat = INS;
            break;
    }
}

/*
 * Helper method to determine if a mov should occur based on its CC.
 */
bool get_mov_cnd(y86_cmov_t mov, y86_t *cpu)
{
    bool cnd = false;

    switch (mov) {
        case RRMOVQ:
            cnd = true;
            break;
        case CMOVLE:
            if (cpu->zf || ((!cpu->sf && cpu->of) || (cpu->sf && !cpu->of))) {
                cnd = true;
            }
            break;
        case CMOVL:
            if (((!cpu->sf && cpu->of) || (cpu->sf && !cpu->of))) {
                cnd = true;
            }
            break;
        case CMOVE:
            if (cpu->zf) {
                cnd = true;
            }
            break;
        case CMOVNE:
            if (!cpu->zf) {
                cnd = true;
            }
            break;
        case CMOVGE:
            if (cpu->of == cpu->sf) {
                cnd = true;
            }
            break;
        case CMOVG:
            if (!cpu->zf && cpu->of == cpu->sf) {
                cnd = true;
            }
            break;
        case BADCMOV:
            cpu->stat = INS;
            break;
    }

    return cnd;
}

/*
 * Helper method to determine if a jmp should occur based on its CC.
 */
bool get_jmp_cnd(y86_jump_t jmp, y86_t *cpu)
{
    bool cnd = false;
    switch (jmp) {
        case JMP:
            cnd = true;
            break;
        case JLE:
            if (cpu->zf || ((!cpu->sf && cpu->of) || (cpu->sf && !cpu->of))) {
                cnd = true;
            }
            break;
        case JL:
            if ((!cpu->sf && cpu->of) || (cpu->sf && !cpu->of)) {
                cnd = true;
            }
            break;
        case JE:
            if (cpu->zf) {
                cnd = true;
            }
            break;
        case JNE:
            if (!cpu->zf) {
                cnd = true;
            }
            break;
        case JGE:
            if (cpu->of == cpu->sf) {
                cnd = true;
            }
            break;
        case JG:
            if (!cpu->zf && (cpu->of == cpu->sf)) {
                cnd = true;
            }
            break;
        case BADJUMP:
            cpu->stat = INS;
            break;
        default:
            cpu->stat = INS;
            break;
    }

    return cnd;
}

y86_reg_t set_op_cc(y86_reg_t valB, y86_reg_t *valA, y86_inst_t ins, y86_t *cpu)
{
    y86_reg_t valE = 0;

    switch (ins.ifun.op) {
        case ADD:
            cpu->of = (valB < 0 && *valA < 0 && valE > 0)
                      || (valB > 0 && *valA > 0 && valE < 0);
            valE = (int64_t) (valB + *valA);
            break;
        case SUB:
            cpu->of = ((valB < 0 && *valA > 0 && valE > 0)
                       || (valB > 0 && *valA < 0 && valE < 0));
            valE = (int64_t) (valB - *valA);
            break;
        case AND:
            valE = (int64_t) (valB & *valA);
            break;
        case XOR:
            valE = (int64_t) (valB ^ *valA);
            break;
        case BADOP:
            cpu->stat = INS;
            return valE;
            break;
    }

    // clear bits for all cases regardless
    cpu->sf = (valE >> 63) == 1;
    cpu->zf = (valE == 0);

    return valE;
}
