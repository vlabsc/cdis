//printf(" mod: %.2X,  reg: %.2X  rm: %.2X \n", mod_val, reg_val, rm_val);
//printf(" sib_base: %.2X,  sib_scale: %.2X  sib_index: %.2X \n", sib_base, sib_scale, sib_index);

#include "opcode_decode.h"

#define DUMPINT(varname) fprintf(stderr, "%s = %u", #varname, varname);

int breakhere = 0;
int make_rmstr(unsigned char opcode[], int *ind, unsigned char *rm_str, unsigned char *sib_str, int bittype);
int make_sibstr(unsigned char opcode[], int *ind, unsigned char *rm_str, unsigned char *sib_str, int bittype);

unsigned char *regs[8];
unsigned char *regs_8bit[8];


    unsigned char *modrm_rm[4][8] = {
        {"[EAX]", "[ECX]", "[EDX]", "[EBX]", "0", "[%.8X]", "[ESI]", "[EDI]"},
        {"EAX", "ECX", "EDX", "EBX", "%.2X", "EBP", "ESI", "EDI"},
        {"EAX", "ECX", "EDX", "EBX", "%.8X", "EBP", "ESI", "EDI"},
        {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"},
    };

    unsigned char *modrm_rm_8bit[4][8] = {
        {"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"},
        {"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"},
        {"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"},
        {"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"},
    };



    unsigned char *OpCodeExtension_Group1[8] = {"ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP"};
    unsigned char *OpCodeExtension_Group3[8] = {"TEST", "0", "NOT", "NEG", "MUL", "IMUL", "DIV", "IDIV"};
    unsigned char *OpCodeExtension_Group5[8] = {"INC", "DEC", "CALL", "CALL", "JMP", "JMP", "PUSH", "0"};
    unsigned char *OpCodeExtension_Group11[8] = {"MOV", "", "", "", "", "", "", ""};


    unsigned char *sib_rm[4][8] = {
        {"EAX", "ECX", "EDX", "EBX", "0", "%.8X", "ESI", "EDI"},
        {"EAX*2", "ECX*2", "EDX*2", "EBX*2", "0", "EBP*2", "ESI*2", "EDI*2"},
        {"EAX*4", "ECX*4", "EDX*4", "EBX*4", "0", "EBP*4", "ESI*4", "EDI*4"},
        {"EAX*8", "ECX*8", "EDX*8", "EBX*8", "0", "EBP*8", "ESI*8", "EDI*8"},
    };

int initialize(void)
{
    regs[0] = "EAX";
    regs[1] = "ECX";
    regs[2] = "EDX";
    regs[3] = "EBX";
    regs[4] = "ESP";
    regs[5] = "EBP";
    regs[6] = "ESI";
    regs[7] = "EDI";

    regs_8bit[0] = "AL";
    regs_8bit[1] = "CL";
    regs_8bit[2] = "DL";
    regs_8bit[3] = "BL";
    regs_8bit[4] = "AH";
    regs_8bit[5] = "CH";
    regs_8bit[6] = "DH";
    regs_8bit[7] = "BH";
}

int opcode_type(unsigned char op1)
{
    return OPCode[op1]->type;
}

char *opcode_final(unsigned char op1)
{


}
int opcode_build()
{
    int i = 0;
    // the following loop creates the first 255 nodes.
    for(i = 0x0; i <= 0xff; ++i){
        OPCode[i] = (opCode_t *) malloc(sizeof (opCode_t));
        OPCode[i]->value = i;
        OPCode[i]->type = NIL;
        OPCode[i]->imm = imm0;

        OPCode[i]->ins_string = (char *) malloc(15);
        memset(OPCode[i]->ins_string, 0, 15);
        OPCode[i]->regs = (char *) malloc(3);
        memset(OPCode[i]->ins_string, 0, 3);


        OPCode_2Byte[i] = (opCode_t *) malloc(sizeof (opCode_t));
        OPCode_2Byte[i]->value = i;
        OPCode_2Byte[i]->type = NIL;
        OPCode_2Byte[i]->imm = imm0;

        OPCode_2Byte[i]->ins_string = (char *) malloc(15);
        memset(OPCode_2Byte[i]->ins_string, 0, 15);
        OPCode_2Byte[i]->regs = (char *) malloc(3);
        memset(OPCode_2Byte[i]->ins_string, 0, 3);
    }

    /*
     G The reg field of the ModR/M byte selects a general register (for example, AX (000)).
     E A ModR/M byte follows the opcode and specifies the operand. The operand is either a general-purpose
      register or a memory address. If it is a memory address, the address is computed from a segment register
      and any of the following values: a base register, an index register, a scaling factor, a displacement.

     v Word, doubleword or quadword (in 64-bit mode), depending on operand-size attribute.

     enum OpCodeType {NIL=0, DIRECT, MODRM, MODRMIMM8, Ib, Iz, GvEv, EvGv, EbGb, EvIb, EvIz, GvM, OvrAX, \
    SHORT_DISPLACEMENT_JUMP_ON_CONDITION, SHORT_JUMP, OPCODE_EXTENSION_GROUP5, OPCODE_EXTENSION_GROUP1IMMEDIATE, \
    OPCODE_EXTENSION_GROUP11, JMP_32BIT, CALL_32BIT, TWOBYTE_OPCODE};
    enum Immediate {imm0=0, imm8, imm21, imm32};
     */

    OPCode[0x03]->type = GvEv;
    OPCode[0x05]->type = rAXIz;
    OPCode[0x09]->type = EvGv;
    OPCode[0x0F]->type = TWOBYTE_OPCODE;

    OPCode[0x1B]->type = GvEv;

    OPCode[0x21]->type = EvGv;
    OPCode[0x2B]->type = GvEv;

    OPCode[0x33]->type = GvEv;
    OPCode[0x39]->type = EvGv;


    OPCode[0x3B]->type = GvEv;
    OPCode[0x3C]->type = ALIb;
    OPCode[0x3D]->type = rAXIz;

    OPCode[0x40]->type = DIRECT;
    OPCode[0x41]->type = DIRECT;
    OPCode[0x42]->type = DIRECT;
    OPCode[0x43]->type = DIRECT;
    OPCode[0x44]->type = DIRECT;
    OPCode[0x45]->type = DIRECT;
    OPCode[0x46]->type = DIRECT;
    OPCode[0x47]->type = DIRECT;
    OPCode[0x48]->type = DIRECT;
    OPCode[0x49]->type = DIRECT;
    OPCode[0x4A]->type = DIRECT;
    OPCode[0x4B]->type = DIRECT;
    OPCode[0x4C]->type = DIRECT;
    OPCode[0x4D]->type = DIRECT;
    OPCode[0x4E]->type = DIRECT;
    OPCode[0x4F]->type = DIRECT;

    OPCode[0x50]->type = DIRECT;
    OPCode[0x51]->type = DIRECT;
    OPCode[0x52]->type = DIRECT;
    OPCode[0x53]->type = DIRECT;
    OPCode[0x55]->type = DIRECT;
    OPCode[0x56]->type = DIRECT;
    OPCode[0x57]->type = DIRECT;
    OPCode[0x58]->type = DIRECT;
    OPCode[0x59]->type = DIRECT;
    OPCode[0x5A]->type = DIRECT;
    OPCode[0x5B]->type = DIRECT;
    OPCode[0x5D]->type = DIRECT;
    OPCode[0x5E]->type = DIRECT;
    OPCode[0x5F]->type = DIRECT;

    OPCode[0x68]->type = Iz;
    OPCode[0x6A]->type = Ib;

    OPCode[0x72]->type = SHORT_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode[0x74]->type = SHORT_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode[0x75]->type = SHORT_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode[0x76]->type = SHORT_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode[0x7C]->type = SHORT_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode[0x7D]->type = SHORT_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode[0x7E]->type = SHORT_DISPLACEMENT_JUMP_ON_CONDITION;

    OPCode[0x80]->type = OPCODE_EXTENSION_IMMEDIATEGROUP1;
    OPCode[0x80]->subtype = EvIb;
    OPCode[0x81]->type = OPCODE_EXTENSION_IMMEDIATEGROUP1;
    OPCode[0x81]->subtype = EvIz;
    OPCode[0x83]->type = OPCODE_EXTENSION_IMMEDIATEGROUP1;
    OPCode[0x83]->subtype = EvIb;

    OPCode[0x84]->type = EbGb;
    OPCode[0x85]->type = EvGv;
    OPCode[0x88]->type = EbGb;
    OPCode[0x89]->type = EvGv;
    OPCode[0x8A]->type = GbEb;
    OPCode[0x8B]->type = GvEv;
    OPCode[0x8D]->type = GvM;

    OPCode[0x99]->type = DIRECT;

    OPCode[0xA3]->type = OvrAX;
    OPCode[0xA5]->type = YvXv;

    OPCode[0xC1]->type = EvIb;

    OPCode[0xB8]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;
    OPCode[0xB9]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;
    OPCode[0xBA]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;
    OPCode[0xBB]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;
    OPCode[0xBC]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;
    OPCode[0xBD]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;
    OPCode[0xBE]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;
    OPCode[0xBF]->type = MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER;


    OPCode[0xC1]->type = EvIb;
    OPCode[0xC3]->type = DIRECT;
    OPCode[0xC6]->type = OPCODE_EXTENSION_GROUP11;
    OPCode[0xC6]->subtype = EbIb;
    OPCode[0xC7]->type = OPCODE_EXTENSION_GROUP11;
    OPCode[0xC7]->subtype = EvIz;
    OPCode[0xC9]->type = DIRECT;

    OPCode[0xE8]->type = CALL_32BIT;
    OPCode[0xE9]->type = JMP_32BIT;
    OPCode[0xEB]->type = SHORT_JUMP;

    OPCode[0xF3]->type = REP_REPE_XRELEASE;
    OPCode[0xFF]->type = OPCODE_EXTENSION_GROUP5;

    OPCode[0xF6]->type = OPCODE_EXTENSION_UNARY_GROUP3;
    OPCode[0xF6]->subtype = Eb;
    OPCode[0xF7]->type = OPCODE_EXTENSION_UNARY_GROUP3;
    OPCode[0xF7]->subtype = Ev;



    strcpy(OPCode[0x40]->regs, "EAX");
    strcpy(OPCode[0x41]->regs, "ECX");
    strcpy(OPCode[0x42]->regs, "EDX");
    strcpy(OPCode[0x43]->regs, "EBX");
    strcpy(OPCode[0x44]->regs, "ESP");
    strcpy(OPCode[0x45]->regs, "EBP");
    strcpy(OPCode[0x46]->regs, "ESI");
    strcpy(OPCode[0x47]->regs, "EDI");

    strcpy(OPCode[0x48]->regs, "EAX");
    strcpy(OPCode[0x49]->regs, "ECX");
    strcpy(OPCode[0x4A]->regs, "EDX");
    strcpy(OPCode[0x4B]->regs, "EBX");
    strcpy(OPCode[0x4C]->regs, "ESP");
    strcpy(OPCode[0x4D]->regs, "EBP");
    strcpy(OPCode[0x4E]->regs, "ESI");
    strcpy(OPCode[0x4F]->regs, "EDI");


    strcpy(OPCode[0x50]->regs, "EAX");
    strcpy(OPCode[0x51]->regs, "ECX");
    strcpy(OPCode[0x52]->regs, "EDX");
    strcpy(OPCode[0x53]->regs, "EBX");
    strcpy(OPCode[0x55]->regs, "EBP");
    strcpy(OPCode[0x56]->regs, "ESI");
    strcpy(OPCode[0x57]->regs, "EDI");
    strcpy(OPCode[0x58]->regs, "EAX");
    strcpy(OPCode[0x59]->regs, "ECX");
    strcpy(OPCode[0x5A]->regs, "EDX");
    strcpy(OPCode[0x5B]->regs, "EBX");
    strcpy(OPCode[0x5D]->regs, "EBP");
    strcpy(OPCode[0x5E]->regs, "ESI");
    strcpy(OPCode[0x5F]->regs, "EDI");

    strcpy(OPCode[0x99]->regs, "");

    strcpy(OPCode[0xA5]->regs, "ES:[EDI], DS:[ESI]");

    strcpy(OPCode[0xC3]->regs, "");

    strcpy(OPCode[0x03]->ins_string, "ADD");
    strcpy(OPCode[0x05]->ins_string, "ADD");
    strcpy(OPCode[0x09]->ins_string, "OR");

    strcpy(OPCode[0x18]->ins_string, "SBB");
    strcpy(OPCode[0x19]->ins_string, "SBB");
    strcpy(OPCode[0x1A]->ins_string, "SBB");
    strcpy(OPCode[0x1B]->ins_string, "SBB");
    strcpy(OPCode[0x1C]->ins_string, "SBB");
    strcpy(OPCode[0x1D]->ins_string, "SBB");

    strcpy(OPCode[0x21]->ins_string, "ADD");

    strcpy(OPCode[0x28]->ins_string, "SUB");
    strcpy(OPCode[0x29]->ins_string, "SUB");
    strcpy(OPCode[0x2A]->ins_string, "SUB");
    strcpy(OPCode[0x2B]->ins_string, "SUB");
    strcpy(OPCode[0x2C]->ins_string, "SUB");
    strcpy(OPCode[0x2D]->ins_string, "SUB");

    strcpy(OPCode[0x33]->ins_string, "XOR");

    strcpy(OPCode[0x38]->ins_string, "CMP");
    strcpy(OPCode[0x39]->ins_string, "CMP");
    strcpy(OPCode[0x3A]->ins_string, "CMP");
    strcpy(OPCode[0x3B]->ins_string, "CMP");
    strcpy(OPCode[0x3C]->ins_string, "CMP");
    strcpy(OPCode[0x3D]->ins_string, "CMP");

    strcpy(OPCode[0x40]->ins_string, "INC");
    strcpy(OPCode[0x41]->ins_string, "INC");
    strcpy(OPCode[0x42]->ins_string, "INC");
    strcpy(OPCode[0x43]->ins_string, "INC");
    strcpy(OPCode[0x44]->ins_string, "INC");
    strcpy(OPCode[0x45]->ins_string, "INC");
    strcpy(OPCode[0x46]->ins_string, "INC");
    strcpy(OPCode[0x47]->ins_string, "INC");

    strcpy(OPCode[0x48]->ins_string, "DEC");
    strcpy(OPCode[0x49]->ins_string, "DEC");
    strcpy(OPCode[0x4A]->ins_string, "DEC");
    strcpy(OPCode[0x4B]->ins_string, "DEC");
    strcpy(OPCode[0x4C]->ins_string, "DEC");
    strcpy(OPCode[0x4D]->ins_string, "DEC");
    strcpy(OPCode[0x4E]->ins_string, "DEC");
    strcpy(OPCode[0x4F]->ins_string, "DEC");

    strcpy(OPCode[0x50]->ins_string, "PUSH");
    strcpy(OPCode[0x51]->ins_string, "PUSH");
    strcpy(OPCode[0x52]->ins_string, "PUSH");
    strcpy(OPCode[0x53]->ins_string, "PUSH");
    strcpy(OPCode[0x54]->ins_string, "PUSH");
    strcpy(OPCode[0x55]->ins_string, "PUSH");
    strcpy(OPCode[0x56]->ins_string, "PUSH");
    strcpy(OPCode[0x57]->ins_string, "PUSH");

    strcpy(OPCode[0x58]->ins_string, "POP");
    strcpy(OPCode[0x59]->ins_string, "POP");
    strcpy(OPCode[0x5A]->ins_string, "POP");
    strcpy(OPCode[0x5B]->ins_string, "POP");
    strcpy(OPCode[0x5C]->ins_string, "POP");
    strcpy(OPCode[0x5D]->ins_string, "POP");
    strcpy(OPCode[0x5E]->ins_string, "POP");
    strcpy(OPCode[0x5F]->ins_string, "POP");

    strcpy(OPCode[0x61]->ins_string, "PUSH");
    strcpy(OPCode[0x68]->ins_string, "PUSH");
    strcpy(OPCode[0x6A]->ins_string, "PUSH");

    strcpy(OPCode[0x72]->ins_string, "JB");
    strcpy(OPCode[0x74]->ins_string, "JE");
    strcpy(OPCode[0x75]->ins_string, "JNZ");
    strcpy(OPCode[0x76]->ins_string, "JBE");
    strcpy(OPCode[0x7C]->ins_string, "JL");
    strcpy(OPCode[0x7D]->ins_string, "JGE");
    strcpy(OPCode[0x7E]->ins_string, "JLE");

    strcpy(OPCode[0x83]->ins_string, "ADD");
    strcpy(OPCode[0x84]->ins_string, "TEST");
    strcpy(OPCode[0x85]->ins_string, "TEST");
    strcpy(OPCode[0x88]->ins_string, "MOV");
    strcpy(OPCode[0x89]->ins_string, "MOV");
    strcpy(OPCode[0x8A]->ins_string, "MOV");
    strcpy(OPCode[0x8B]->ins_string, "MOV");
    strcpy(OPCode[0x8D]->ins_string, "LEA");

    strcpy(OPCode[0x99]->ins_string, "CDQ");

    strcpy(OPCode[0xA3]->ins_string, "MOVS");
    strcpy(OPCode[0xA5]->ins_string, "MOV");

    strcpy(OPCode[0xB0]->ins_string, "MOV");
    strcpy(OPCode[0xB1]->ins_string, "MOV");
    strcpy(OPCode[0xB2]->ins_string, "MOV");
    strcpy(OPCode[0xB3]->ins_string, "MOV");
    strcpy(OPCode[0xB4]->ins_string, "MOV");
    strcpy(OPCode[0xB5]->ins_string, "MOV");
    strcpy(OPCode[0xB6]->ins_string, "MOV");
    strcpy(OPCode[0xB7]->ins_string, "MOV");
    strcpy(OPCode[0xB8]->ins_string, "MOV");
    strcpy(OPCode[0xB9]->ins_string, "MOV");
    strcpy(OPCode[0xBA]->ins_string, "MOV");
    strcpy(OPCode[0xBB]->ins_string, "MOV");
    strcpy(OPCode[0xBC]->ins_string, "MOV");
    strcpy(OPCode[0xBD]->ins_string, "MOV");
    strcpy(OPCode[0xBE]->ins_string, "MOV");
    strcpy(OPCode[0xBF]->ins_string, "MOV");

    strcpy(OPCode[0xC1]->ins_string, "SHL");
    strcpy(OPCode[0xC3]->ins_string, "RETN");
    strcpy(OPCode[0xC9]->ins_string, "LEAVE");

    strcpy(OPCode[0xE8]->ins_string, "CALL");
    strcpy(OPCode[0xE9]->ins_string, "JMP");
    strcpy(OPCode[0xEB]->ins_string, "JB");

    strcpy(OPCode[0xF3]->ins_string, "REP");

    OPCode[0x68]->imm = imm32;
    OPCode[0x6A]->imm = imm8;

    OPCode[0x74]->imm = imm8;
    OPCode[0x75]->imm = imm8;
    OPCode[0x7C]->imm = imm8;
    OPCode[0x7D]->imm = imm8;

    OPCode[0x81]->imm = imm8;
    OPCode[0x83]->imm = imm8;

    OPCode[0xB9]->imm = imm32;

    OPCode[0xC1]->imm = imm8;

    OPCode[0xE8]->imm = imm32;
    OPCode[0xE9]->imm = imm32;
    OPCode[0xEB]->imm = imm8;




    //OPCode_2Byte[0x85]->type = JMP_32BIT;
    OPCode_2Byte[0x84]->type = LONG_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode_2Byte[0x85]->type = LONG_DISPLACEMENT_JUMP_ON_CONDITION;
    OPCode_2Byte[0x8C]->type = LONG_DISPLACEMENT_JUMP_ON_CONDITION;

    OPCode_2Byte[0x95]->type = BYTE_SET_ON_CONDITION;


    strcpy(OPCode_2Byte[0x84]->ins_string, "JE");
    strcpy(OPCode_2Byte[0x85]->ins_string, "JNZ");
    strcpy(OPCode_2Byte[0x8C]->ins_string, "JL");

    strcpy(OPCode_2Byte[0x95]->ins_string, "SETNE");



    OPCode_2Byte[0x84]->imm = imm32;
    OPCode_2Byte[0x85]->imm = imm32;
    OPCode_2Byte[0x8C]->imm = imm32;

}


int opcode_decode(unsigned char opcode[], int index, int code_section_address_of_entry_point, unsigned char *finalstr)
{
    unsigned char op1 = 0, op2 = 0, op3 = 0;
    unsigned char mod_val = 0, reg_val = 0, rm_val = 0;
    unsigned char sib_scale = 0, sib_index = 0, sib_base = 0;
    unsigned char opcode_extension = 0;
    unsigned char direction;
    unsigned char *reg_str = (unsigned char *) malloc(16);
    unsigned char *rm_str = (unsigned char *) malloc(16);
    unsigned char *sib_str = (unsigned char *) malloc(16);
    unsigned char *tstr = (unsigned char *) malloc(16);
    unsigned char unsignedByte = 0;
    unsigned char signed32[4] = {0};
    unsigned long signed32val = 0;
    unsigned long addr = 0;
    char signedByte = 0;

    op1 = opcode[index++];
    printf("%.2X", op1);

    // G The reg field of the ModR/M byte selects a general register (for example, AX (000)).
    // E A ModR/M byte follows the opcode and specifies the operand. The operand is either a general-purpose
    //  register or a memory address. If it is a memory address, the address is computed from a segment register
    //  and any of the following values: a base register, an index register, a scaling factor, a displacement.
    //
    // v Word, doubleword or quadword (in 64-bit mode), depending on operand-size attribute.

    if(OPCode[op1]->type == NIL){
            puts("!!!!!");
            exit(0);
    }


    if(OPCode[op1]->type == DIRECT){
        //printf(" %s %s", OPCode[op1]->ins_string, OPCode[op1]->regs);
        sprintf(finalstr, "%s %s", OPCode[op1]->ins_string, OPCode[op1]->regs);
    }

    if(OPCode[op1]->type == MODRMIMM8){           // immdiate 8b or 32b constant is present, so diff logic
        op2 = opcode[index++];
        printf(" %.2X", op2);

        mod_val = (op2 & 0xC0) >> 6;    // first two bit
        reg_val = (op2 & 0x38) >> 3; // middle 3 bit
        rm_val = (op2 & 0x07);    // first two bit

        unsignedByte = opcode[index++];
        printf(" %x", unsignedByte);

        sprintf(OPCode[op1]->regs, "%s", regs[rm_val]);
        sprintf(finalstr,"%s %s, %.2X", OPCode[op1]->ins_string, OPCode[op1]->regs, unsignedByte);
    }

    if(OPCode[op1]->type == SHORT_DISPLACEMENT_JUMP_ON_CONDITION) {
            op2 = opcode[index++];
            printf(" %.2X", op2);
            addr = 0;
            addr += (((int)op2 * 0x00000001));

            sprintf(finalstr,"%s %.8Xh", OPCode[op1]->ins_string, code_section_address_of_entry_point + addr + 2);
    }
    else if(OPCode[op1]->type == SHORT_JUMP) {
            op2 = opcode[index++];
            printf(" %.2X", op2);
            addr = 0;
            addr += (((int)op2 * 0x00000001));

            sprintf(finalstr,"%s %.8Xh", OPCode[op1]->ins_string, code_section_address_of_entry_point + addr + 2);
    }
    else if(OPCode[op1]->type == Ib) {
            op2 = opcode[index++];
            printf(" %.2X", op2);
            addr = 0;
            addr += (((int)op2 * 0x00000001));

            sprintf(finalstr,"%s %.2Xh", OPCode[op1]->ins_string, op2);
    }

    if(OPCode[op1]->type == rAXIz){
        signed32[0] = opcode[index++];
        signed32[1] = opcode[index++];
        signed32[2] = opcode[index++];
        signed32[3] = opcode[index++];
        printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

        signed32val = (((int)signed32[3] * 0x01000000));
        signed32val += (((int)signed32[2] * 0x00010000));
        signed32val += (((int)signed32[1] * 0x00000100));
        signed32val += (((int)signed32[0] * 0x00000001));
        sprintf(finalstr,"%s EAX, %.8X", OPCode[op1]->ins_string, signed32val);
    }

    else if(OPCode[op1]->type == Iz) {
            signed32[0] = opcode[index++];
            signed32[1] = opcode[index++];
            signed32[2] = opcode[index++];
            signed32[3] = opcode[index++];
            printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

            signed32val = (((int)signed32[3] * 0x01000000));
            signed32val += (((int)signed32[2] * 0x00010000));
            signed32val += (((int)signed32[1] * 0x00000100));
            signed32val += (((int)signed32[0] * 0x00000001));
            sprintf(finalstr,"%s %.8X", OPCode[op1]->ins_string, signed32val);
    }

    else if(OPCode[op1]->type == CALL_32BIT || OPCode[op1]->type == JMP_32BIT) {
            signed32[0] = opcode[index++];
            signed32[1] = opcode[index++];
            signed32[2] = opcode[index++];
            signed32[3] = opcode[index++];
            printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

            signed32val = (((int)signed32[3] * 0x01000000));
            signed32val += (((int)signed32[2] * 0x00010000));
            signed32val += (((int)signed32[1] * 0x00000100));
            signed32val += (((int)signed32[0] * 0x00000001));
            sprintf(finalstr,"%s %.8X", OPCode[op1]->ins_string, code_section_address_of_entry_point + signed32val + 5);
    }


    if(OPCode[op1]->type == MOV_IMMEDIATE_WORD_OR_DOUBLE_INTO_WORD_DOUBLE_OR_QUAD_REGISTER) {
            signed32[0] = opcode[index++];
            signed32[1] = opcode[index++];
            signed32[2] = opcode[index++];
            signed32[3] = opcode[index++];
            printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

            signed32val = (((int)signed32[3] * 0x01000000));
            signed32val += (((int)signed32[2] * 0x00010000));
            signed32val += (((int)signed32[1] * 0x00000100));
            signed32val += (((int)signed32[0] * 0x00000001));
            sprintf(finalstr,"%s %s, %.8X", OPCode[op1]->ins_string, regs[op1-0xB8], signed32val);
        }


    if(OPCode[op1]->type == OvrAX) {
            signed32[0] = opcode[index++];
            signed32[1] = opcode[index++];
            signed32[2] = opcode[index++];
            signed32[3] = opcode[index++];
            printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

            signed32val = (((int)signed32[3] * 0x01000000));
            signed32val += (((int)signed32[2] * 0x00010000));
            signed32val += (((int)signed32[1] * 0x00000100));
            signed32val += (((int)signed32[0] * 0x00000001));
            sprintf(finalstr,"%s [%.8X], eax", OPCode[op1]->ins_string, signed32val);
    }

    if(OPCode[op1]->type == ALIb) {
            signedByte = opcode[index++];
            printf(" %.2X", (unsigned char) signedByte);
            sprintf(finalstr,"%s AL, %.2X", OPCode[op1]->ins_string, (unsigned char) signedByte);
    }

    if(OPCode[op1]->type == EvIb){
        if(OPCode[op1]->type == SHORT_DISPLACEMENT_JUMP_ON_CONDITION) {
            op2 = opcode[index++];
            printf(" %.2X", op2);
            addr = 0;
            addr += (((int)op2 * 0x00000001));

            sprintf(finalstr,"%s %.2Xh", OPCode[op1]->ins_string, code_section_address_of_entry_point + addr + 2);
        }
        else {
            op2 = opcode[index++];
            printf(" %.2X", op2);
            op3 = opcode[index++];
            printf(" %.2x", op3);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit
            //sprintf(rm_str, "%s", modrm_rm[mod_val][rm_val]);
            sprintf(rm_str, "%s", regs[rm_val]);
            sprintf(finalstr,"%s %s, %.2Xh", OPCode[op1]->ins_string, rm_str, op3);
        }
    }


    if(OPCode[op1]->type == EvGv) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit

            sprintf(reg_str, "%s", regs[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 32);
            sprintf(OPCode[op1]->regs, "%s, %s", rm_str, reg_str);
            sprintf(finalstr,"%s %s", OPCode[op1]->ins_string, OPCode[op1]->regs);
    }


    if(OPCode[op1]->type == EbGb) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit

            sprintf(reg_str, "%s", regs_8bit[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 8);
            sprintf(OPCode[op1]->regs, "%s, %s", rm_str, reg_str);
            sprintf(finalstr,"%s %s", OPCode[op1]->ins_string, OPCode[op1]->regs);
    }


    if(OPCode[op1]->type == GbEb) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit
            //printf(" mod: %.2X,  reg: %.2X  rm: %.2X \n", mod_val, reg_val, rm_val);

            sprintf(reg_str, "%s", regs_8bit[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 8);
            sprintf(OPCode[op1]->regs, "%s, %s", reg_str, rm_str);
            sprintf(finalstr,"%s %s", OPCode[op1]->ins_string, OPCode[op1]->regs);
    }

    if(OPCode[op1]->type == GvEv) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit
            //printf(" mod: %.2X,  reg: %.2X  rm: %.2X \n", mod_val, reg_val, rm_val);

            sprintf(reg_str, "%s", regs[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 32);
            sprintf(OPCode[op1]->regs, "%s, %s", reg_str, rm_str);
            sprintf(finalstr,"%s %s", OPCode[op1]->ins_string, OPCode[op1]->regs);
    }



    if(OPCode[op1]->type == GvM) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit

            sprintf(reg_str, "%s", regs[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 32);
            sprintf(OPCode[op1]->regs, "%s, %s", reg_str, rm_str);
            sprintf(finalstr,"%s %s", OPCode[op1]->ins_string, OPCode[op1]->regs);
    }

    if(OPCode[op1]->type == REP_REPE_XRELEASE) {
            op2 = opcode[index++];
            printf(" %.2X", op2);

            sprintf(finalstr,"%s %s %s", OPCode[op1]->ins_string, OPCode[op2]->ins_string, OPCode[op2]->regs);
            //breakhere = 1;
    }


    if(OPCode[op1]->type == OPCODE_EXTENSION_GROUP5) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            opcode_extension = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit

            sprintf(reg_str, "%s", regs[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 32);

            sprintf(OPCode[op1]->regs, "%s", rm_str);
            sprintf(finalstr,"%s %s", OpCodeExtension_Group5[opcode_extension], OPCode[op1]->regs);
    }

    else if(OPCode[op1]->type == OPCODE_EXTENSION_IMMEDIATEGROUP1) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            opcode_extension = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit

            sprintf(reg_str, "%s", regs[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 32);
            sprintf(OPCode[op1]->regs, "%s", rm_str);

            if(OPCode[op1]->subtype == EvIb){
                unsignedByte = opcode[index++];
                printf(" %.2X", unsignedByte);
                sprintf(finalstr,"%s %s, %.2X", OpCodeExtension_Group1[opcode_extension], OPCode[op1]->regs, unsignedByte);
            }
            else if(OPCode[op1]->subtype == EvIz){
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));
                sprintf(finalstr,"%s %s, %.2X", OpCodeExtension_Group1[opcode_extension], OPCode[op1]->regs, signed32val);
            }
    }


    else if(OPCode[op1]->type == OPCODE_EXTENSION_GROUP11) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            opcode_extension = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit
            //printf(" mod: %.2X,  reg: %.2X  rm: %.2X \n", mod_val, reg_val, rm_val);

            sprintf(reg_str, "%s", regs[reg_val]);
            make_rmstr(opcode, &index, rm_str, sib_str, 32);
            sprintf(OPCode[op1]->regs, "%s", rm_str);

            if(OPCode[op1]->subtype == EvIz){
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));
                sprintf(finalstr,"%s %s, %.2X", OpCodeExtension_Group11[opcode_extension], OPCode[op1]->regs, signed32val);
            }
            else if(OPCode[op1]->subtype == EbIb){
                unsignedByte = opcode[index++];
                printf(" %.2X", unsignedByte);
                sprintf(finalstr,"%s %s, %.2X", OpCodeExtension_Group11[opcode_extension], OPCode[op1]->regs, signed32val);
            }
    }

    else if(OPCode[op1]->type == OPCODE_EXTENSION_UNARY_GROUP3) {
            op2 = opcode[index];
            printf(" %.2X", op2);

            mod_val = (op2 & 0xC0) >> 6;    // first two bit
            reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
            opcode_extension = (op2 & 0x38) >> 3;    // middle 3 bit
            rm_val = (op2 & 0x07);          // first two bit
            //printf(" mod: %.2X,  reg: %.2X  rm: %.2X \n", mod_val, reg_val, rm_val);
            //sprintf(reg_str, "%s", regs[reg_val]);

            make_rmstr(opcode, &index, rm_str, sib_str, 32);
            sprintf(OPCode[op1]->regs, "%s", rm_str);
            sprintf(finalstr,"%s %s", OpCodeExtension_Group3[opcode_extension], rm_str);
    }



    if(OPCode[op1]->type == TWOBYTE_OPCODE) {

            op1 = opcode[index++];
            printf(" %.2X", op1);
            //puts("Two Byte opcode detected !");

            if(OPCode_2Byte[op1]->type == SHORT_DISPLACEMENT_JUMP_ON_CONDITION) {
                    op2 = opcode[index++];
                    printf(" %.2X", op2);
                    addr = 0;
                    addr += (((int)op2 * 0x00000001));

                    sprintf(finalstr,"%s %.8Xh", OPCode_2Byte[op1]->ins_string, code_section_address_of_entry_point + addr + 2);
            }
            else if(OPCode_2Byte[op1]->type == LONG_DISPLACEMENT_JUMP_ON_CONDITION){
                    signed32[0] = opcode[index++];
                    signed32[1] = opcode[index++];
                    signed32[2] = opcode[index++];
                    signed32[3] = opcode[index++];
                    printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                    signed32val = (((int)signed32[3] * 0x01000000));
                    signed32val += (((int)signed32[2] * 0x00010000));
                    signed32val += (((int)signed32[1] * 0x00000100));
                    signed32val += (((int)signed32[0] * 0x00000001));
                    sprintf(finalstr,"%s %.2X", OPCode_2Byte[op1]->ins_string, code_section_address_of_entry_point + signed32val + 5);
            }
            else if(OPCode_2Byte[op1]->type == SHORT_JUMP) {
                    op2 = opcode[index++];
                    printf(" %.2X", op2);
                    addr = 0;
                    addr += (((int)op2 * 0x00000001));

                    sprintf(finalstr,"%s %.8Xh", OPCode_2Byte[op1]->ins_string, code_section_address_of_entry_point + addr + 2);
            }
            else if(OPCode_2Byte[op1]->type == Ib) {
                    op2 = opcode[index++];
                    printf(" %.2X", op2);
                    addr = 0;
                    addr += (((int)op2 * 0x00000001));

                    sprintf(finalstr,"%s %.2Xh", OPCode_2Byte[op1]->ins_string, op2);
            }
            else if(OPCode_2Byte[op1]->type == Iz) {
                    signed32[0] = opcode[index++];
                    signed32[1] = opcode[index++];
                    signed32[2] = opcode[index++];
                    signed32[3] = opcode[index++];
                    printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                    signed32val = (((int)signed32[3] * 0x01000000));
                    signed32val += (((int)signed32[2] * 0x00010000));
                    signed32val += (((int)signed32[1] * 0x00000100));
                    signed32val += (((int)signed32[0] * 0x00000001));
                    sprintf(finalstr,"%s %.8X", OPCode_2Byte[op1]->ins_string, signed32val);
            }
            else if(OPCode_2Byte[op1]->type == CALL_32BIT || OPCode_2Byte[op1]->type == JMP_32BIT) {
                    signed32[0] = opcode[index++];
                    signed32[1] = opcode[index++];
                    signed32[2] = opcode[index++];
                    signed32[3] = opcode[index++];
                    printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                    signed32val = (((int)signed32[3] * 0x01000000));
                    signed32val += (((int)signed32[2] * 0x00010000));
                    signed32val += (((int)signed32[1] * 0x00000100));
                    signed32val += (((int)signed32[0] * 0x00000001));
                    sprintf(finalstr,"%s %.8X", OPCode_2Byte[op1]->ins_string, code_section_address_of_entry_point + 6 + signed32val);
            }
            else if(OPCode_2Byte[op1]->type == BYTE_SET_ON_CONDITION) {
                    op2 = opcode[index];
                    printf(" %.2X", op2);
                    make_rmstr(opcode, &index, rm_str, sib_str, 8);
                    sprintf(finalstr,"%s %s", OPCode_2Byte[op1]->ins_string, rm_str);
            }

            else{
                puts("nothing found!");
                breakhere = 1;
            }

    }





    return index;
}


int make_rmstr(unsigned char opcode[], int *ind, unsigned char *rm_str, unsigned char *sib_str, int bittype)
{
    unsigned char op1 = 0, op2 = 0, op3 = 0;
    unsigned char mod_val = 0, reg_val = 0, rm_val = 0;
    unsigned char sib_scale = 0, sib_index = 0, sib_base = 0;
    unsigned char unsignedByte = 0;
    unsigned char signed32[4] = {0};
    unsigned long signed32val = 0;
    char signedByte = 0;
    //unsigned long addr = 0;

    int index = *ind;

    if(bittype == 32) {
        op2 = opcode[index++];
        //printf(" %.2X", op2);

        mod_val = (op2 & 0xC0) >> 6;    // first two bit
        reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
        rm_val = (op2 & 0x07);          // first two bit


        if(mod_val == 0) {
            if(rm_val == 0x04){     // 100 in MODRM
                make_sibstr(opcode, &index, rm_str, sib_str, bittype);
                sprintf(rm_str, "[%s]", sib_str);
                //puts(sib_str);
            }
            else if(rm_val == 0x05){     // 101 in MODRM
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2X%.2X%.2X%.2X" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));
                sprintf(rm_str, "[%.8Xh]", signed32val);
            }
            else {
                sprintf(rm_str, "[%s]", regs[rm_val]);
            }
        }
        else if(mod_val == 1){
            if(rm_val == 0x04){     // 100 in MODRM
                /*
                op3 = opcode[index++];
                printf(" %.2X", op3);
                signedByte = opcode[index++];
                printf(" %.2X", (unsigned char) signedByte);

                sib_scale = (op3 & 0xC0) >> 6;    // first two bit
                sib_index = (op3 & 0x38) >> 3; // middle 3 bit
                sib_base = (op3 & 0x07);    // first two bit

                if(sib_index == 0x04)     // 100 in SIB
                    sprintf(rm_str, "[%s%s%.2X]", regs[sib_base], (signedByte > -1) ? "+":"", signedByte);
                else
                //sprintf(rm_str, "[%s+%s+%.2X]", regs[sib_base], sib_rm[sib_scale][sib_index], unsignedByte);
                sprintf(rm_str, "[%s+%s%s%d]", regs[sib_base], sib_rm[sib_scale][sib_index], (signedByte > -1) ? "+":"" , signedByte);
                */


                make_sibstr(opcode, &index, rm_str, sib_str, bittype);
                signedByte = opcode[index++];
                printf(" %.2X", (unsigned char) signedByte);

                sprintf(rm_str, "[%s%s%.2X]", sib_str, (signedByte > -1) ? "+":"" , signedByte);
            }
            else {
                signedByte = opcode[index++];
                printf(" %.2X", (unsigned char) signedByte);
                sprintf(rm_str, "[%s%s%d]", regs[rm_val], (signedByte > -1) ? "+":"" , signedByte);
            }
        }
        else if(mod_val == 2){
            if(rm_val == 0x04){     // 100 in MODRM
                printf("yet to 4");
            }
            else {
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));
                sprintf(rm_str, "[%s+%.8Xh]", regs[rm_val], signed32val);
            }
        }
        else if(mod_val == 3) {
            sprintf(rm_str, "%s", regs[rm_val]);
        }
    } // if(bittype == 32)

    else if(bittype == 8) {
        op2 = opcode[index++];
        //printf(" %.2X", op2);

        mod_val = (op2 & 0xC0) >> 6;    // first two bit
        reg_val = (op2 & 0x38) >> 3;    // middle 3 bit
        rm_val = (op2 & 0x07);          // first two bit


        if(mod_val == 0) {
            if(rm_val == 0x04){     // 100 in MODRM
                op3 = opcode[index++];
                printf(" %.2X", op3);

                sib_scale = (op3 & 0xC0) >> 6;    // first two bit
                sib_index = (op3 & 0x38) >> 3; // middle 3 bit
                sib_base = (op3 & 0x07);    // first two bit

                if(sib_index == 0x04)     // 100 in SIB
                    sprintf(rm_str, "[%s+%.2X]", regs[sib_base], unsignedByte);
                else
                    sprintf(rm_str, "[%s+%s]", regs[sib_base], sib_rm[sib_scale][sib_index]);
            }
            else if(rm_val == 0x05){     // 101 in MODRM
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));
                sprintf(rm_str, "[%.8X]", signedByte);
                breakhere = 1;
            }
            else {
                sprintf(rm_str, "BYTE [%s]", regs[rm_val]);
            }
        }
        else if(mod_val == 1){
            if(rm_val == 0x04){     // 100 in MODRM
                op3 = opcode[index++];
                printf(" %.2X", op3);
                signedByte = opcode[index++];
                printf(" %.2X", (unsigned char) signedByte);

                sib_scale = (op3 & 0xC0) >> 6;    // first two bit
                sib_index = (op3 & 0x38) >> 3; // middle 3 bit
                sib_base = (op3 & 0x07);    // first two bit

                if(sib_index == 0x04)     // 100 in SIB
                    sprintf(rm_str, "[%s%s%.2X]", regs[sib_base], (signedByte > -1) ? "+":"", signedByte);
                else
                    sprintf(rm_str, "[%s+%s%s%d]", regs[sib_base], sib_rm[sib_scale][sib_index], (signedByte > -1) ? "+":"" , signedByte);
            }
            else {
                signedByte = opcode[index++];
                printf(" %.2X", (unsigned char) signedByte);
                sprintf(rm_str, "BYTE [%s%s%d]", regs[rm_val], (signedByte > -1) ? "+":"" , signedByte);
            }
        }
        else if(mod_val == 2) {
            if(rm_val == 0x04){     // 100 in MODRM
                printf("yet to 4");
            }
            else {
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));
                //sprintf(rm_str, modrm_rm_8bit[mod_val][rm_val], signed32val);
                //sprintf(rm_str, "[%s+%.8Xh]", modrm_rm_8bit[mod_val][rm_val], signed32val);
                sprintf(rm_str, "[%s+%.8Xh]", regs_8bit[rm_val], signed32val);
                breakhere = 1;
            }
        }
        else if(mod_val == 3){
            //sprintf(rm_str, "%s", modrm_rm_8bit[mod_val][rm_val]);
            sprintf(rm_str, "%s", regs_8bit[rm_val]);
        }
    } // if(bittype == 8)

    *ind = index;

}


int make_sibstr(unsigned char opcode[], int *ind, unsigned char *rm_str, unsigned char *sib_str, int bittype)
{
    unsigned char op3 = 0;
    unsigned char sib_scale = 0, sib_index = 0, sib_base = 0;
    unsigned char signed32[4] = {0};
    unsigned long signed32val = 0;

    int index = *ind;

    op3 = opcode[index++];
    printf(" %.2X", op3);

    sib_scale = (op3 & 0xC0) >> 6;    // first two bit
    sib_index = (op3 & 0x38) >> 3; // middle 3 bit
    sib_base = (op3 & 0x07);    // first two bit

    if(bittype == 32) {
        if(sib_scale == 0) {
            if(sib_index == 0x04)
                sprintf(sib_str, "%s", regs[sib_base]);
            else
                sprintf(sib_str, "%s+%s", regs[sib_base], regs[sib_index]);
        }
        else if(sib_scale == 1){
            if(sib_index == 0x04)
                sprintf(sib_str, "%s", regs[sib_base]);
            else
                sprintf(sib_str, "%s+%s*2", regs[sib_base], regs[sib_index]);
        }
        else if(sib_scale == 2){
            if(sib_index == 0x04)
                sprintf(sib_str, "%s", regs[sib_base]);
            else
                sprintf(sib_str, "%s+%s*4", regs[sib_base], regs[sib_index]);
        }
        else if(sib_scale == 3) {
            if(sib_index == 0x04 && sib_base == 0x05) {
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));

                sprintf(sib_str, "%.8X", signed32val);
            }
            else if(sib_index != 0x04 && sib_base == 0x05) {
                signed32[0] = opcode[index++];
                signed32[1] = opcode[index++];
                signed32[2] = opcode[index++];
                signed32[3] = opcode[index++];
                printf(" %.2x%.2x%.2x%.2x" , signed32[0], signed32[1], signed32[2], signed32[3]);

                signed32val = (((int)signed32[3] * 0x01000000));
                signed32val += (((int)signed32[2] * 0x00010000));
                signed32val += (((int)signed32[1] * 0x00000100));
                signed32val += (((int)signed32[0] * 0x00000001));

                sprintf(sib_str, "%s*8+%.8X", regs[sib_index], signed32val);
            }
            else if(sib_index == 0x04 && sib_base != 0x05) {

                sprintf(sib_str, "%s", regs[sib_base]);
            }

            else if(sib_index != 0x04 && sib_base != 0x05) {

                sprintf(sib_str, "%s+%s*8", regs[sib_base], regs[sib_index]);
            }
        }
    } // if(bittype == 32)



    *ind = index;

}
