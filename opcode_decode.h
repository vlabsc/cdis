#ifndef OPCODE_DECODE_H_INCLUDED
#define OPCODE_DECODE_H_INCLUDED



#endif // OPCODE_DECODE_H_INCLUDED

int opcode_type(unsigned char op1);
char *opcode_final(unsigned char op1);
int opcode_build();
int opcode_decode(unsigned char opcode[], int index, int code_section_address_of_entry_point, unsigned char *finalstr);


    // G The reg field of the ModR/M byte selects a general register (for example, AX (000)).
    // E A ModR/M byte follows the opcode and specifies the operand. The operand is either a general-purpose
    //  register or a memory address. If it is a memory address, the address is computed from a segment register
    //  and any of the following values: a base register, an index register, a scaling factor, a displacement.
    //
    // v Word, doubleword or quadword (in 64-bit mode), depending on operand-size attribute.

    enum OpCodeType {NIL=0, DIRECT, MODRM, MODRMIMM8, Ib, Iz, Iv, Eb, Ev, GbEb, GvEv, EvGv, EbGb, EbIb, EvIb, EvIz, GvM, ALIb, \
    YvXv, rAXIz, OvrAX, SHORT_DISPLACEMENT_JUMP_ON_CONDITION, LONG_DISPLACEMENT_JUMP_ON_CONDITION, SHORT_JUMP, OPCODE_EXTENSION_GROUP5, \
    OPCODE_EXTENSION_IMMEDIATEGROUP1, OPCODE_EXTENSION_GROUP11, OPCODE_EXTENSION_UNARY_GROUP3, JMP_32BIT, CALL_32BIT, TWOBYTE_OPCODE, \
    MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER, REP_REPE_XRELEASE, BYTE_SET_ON_CONDITION};

    enum Immediate {imm0=0, imm8, imm21, imm32};

    typedef struct opCode_t opCode_t;
    typedef struct opCode_t{
        int value;
        enum OpCodeType type;
        enum OpCodeType subtype;
        enum Immediate imm;
        char *ins_string;
        char *regs;         // incase direct
    };

    opCode_t *OPCode[255];
    opCode_t *OPCode_2Byte[255];
