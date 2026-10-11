/* A small stack-machine interpreter: the classic big-switch dispatch loop. */
#include <string.h>
#include "features.h"

enum opcode {
    OP_PUSH, OP_POP, OP_DUP, OP_SWAP, OP_ADD, OP_SUB, OP_MUL, OP_DIV,
    OP_MOD, OP_NEG, OP_AND, OP_OR, OP_XOR, OP_SHL, OP_SHR, OP_EQ,
    OP_LT, OP_JMP, OP_JZ, OP_JNZ, OP_LOAD, OP_STORE, OP_INC, OP_HALT,
};

struct vm {
    int64_t stack[64];
    int64_t vars[8];
    int sp;
    uint32_t steps;
};

static int64_t vm_run(struct vm *m, const int32_t *code, int len)
{
    int pc = 0;
    m->sp = 0;
    m->steps = 0;
    while (pc >= 0 && pc < len && m->steps < 100000) {
        int32_t op = code[pc++];
        int64_t a, b;
        m->steps++;
        switch (op) {
        case OP_PUSH: m->stack[m->sp++] = code[pc++]; break;
        case OP_POP: m->sp--; break;
        case OP_DUP: m->stack[m->sp] = m->stack[m->sp - 1]; m->sp++; break;
        case OP_SWAP:
            a = m->stack[m->sp - 1];
            m->stack[m->sp - 1] = m->stack[m->sp - 2];
            m->stack[m->sp - 2] = a;
            break;
#define BINOP(name, expr) \
        case name: b = m->stack[--m->sp]; a = m->stack[m->sp - 1]; m->stack[m->sp - 1] = (expr); break;
        BINOP(OP_ADD, a + b)
        BINOP(OP_SUB, a - b)
        BINOP(OP_MUL, a * b)
        BINOP(OP_DIV, b ? a / b : 0)
        BINOP(OP_MOD, b ? a % b : 0)
        BINOP(OP_AND, a & b)
        BINOP(OP_OR, a | b)
        BINOP(OP_XOR, a ^ b)
        BINOP(OP_SHL, a << (b & 63))
        BINOP(OP_SHR, a >> (b & 63))
        BINOP(OP_EQ, a == b)
        BINOP(OP_LT, a < b)
#undef BINOP
        case OP_NEG: m->stack[m->sp - 1] = -m->stack[m->sp - 1]; break;
        case OP_JMP: pc = code[pc]; break;
        case OP_JZ: pc = m->stack[--m->sp] == 0 ? code[pc] : pc + 1; break;
        case OP_JNZ: pc = m->stack[--m->sp] != 0 ? code[pc] : pc + 1; break;
        case OP_LOAD: m->stack[m->sp++] = m->vars[code[pc++] & 7]; break;
        case OP_STORE: m->vars[code[pc++] & 7] = m->stack[--m->sp]; break;
        case OP_INC: m->vars[code[pc] & 7] += code[pc + 1]; pc += 2; break;
        case OP_HALT: return m->sp ? m->stack[m->sp - 1] : 0;
        default: return -1;
        }
        if (m->sp < 0 || m->sp >= 63)
            return -2;
    }
    return -3;
}

uint32_t run_vm(int n)
{
    /* sum = 0; for (i = 0; i < n; i++) sum += i * i ^ 5; return sum */
    const int32_t prog[] = {
        OP_PUSH, 0, OP_STORE, 0,           /* 0: sum = 0 */
        OP_PUSH, 0, OP_STORE, 1,           /* 4: i = 0 */
        OP_LOAD, 1, OP_PUSH, n, OP_LT,     /* 8: i < n */
        OP_JZ, 33,                         /* 13 */
        OP_LOAD, 1, OP_DUP, OP_MUL,        /* 15: i*i */
        OP_PUSH, 5, OP_XOR,                /* 19: ^5 */
        OP_LOAD, 0, OP_ADD, OP_STORE, 0,   /* 22: sum += */
        OP_INC, 1, 1,                      /* 27: i++ */
        OP_JMP, 8,                         /* 30 */
        OP_NEG,                            /* 32: (unreached) */
        OP_LOAD, 0, OP_HALT,               /* 33 */
    };
    struct vm m;
    memset(&m, 0, sizeof(m));
    int64_t r = vm_run(&m, prog, (int)(sizeof(prog) / sizeof(prog[0])));
    return (uint32_t)r ^ (m.steps << 8);
}
