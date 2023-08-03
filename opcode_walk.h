#ifndef OPCODEWALK_H_INCLUDED
#define OPCODEWALK_H_INCLUDED



#endif // OPCODEWALK_H_INCLUDED

    int index = 0, no_of_opcodes_processed = 0;
    long addr = 0;

    char signed_displacement_1byte = 0;
    unsigned char op1 = 0, op2 = 0, op3 = 0, op4 = 0;
    unsigned char signed_displacement_4byte[4] = {0,0,0,0};


    int code_section_address_of_entry_point;
    int code_section_address_of_entry_point_rfa;
    HANDLE hFile;
    int ret, out;
    int per_screen = 45;

    //int size_of_raw_data = Code_SectionHeader->SizeOfRawData;
    //int addr_rfa = code_section_address_of_entry_point_rfa;
    //int addr_rva = code_section_address_of_entry_point;
    //DUMP(code_section_address_of_entry_point_rfa);
    //DUMP(code_section_address_of_entry_point);



    enum OpCodeType {NIL=0, DIRECT, MODRM, MODRMIMM8, Ib, GvEv, EvGv, EvIb, GvM, SHORT_DISPLACEMENT_JUMP_ON_CONDITION, \
    OPCODE_EXTENSION_GROUP5, OPCODE_EXTENSION_GROUP1IMMEDIATE, CALL_32BIT};
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

    //opCode_t *OPNode[255];

