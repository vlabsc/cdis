#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include "opcode_walk.h"

//#include "opcode_single_opcodes.h"
//#include "opcode_8d.h"


#define DUMP(varname) fprintf(stderr, "\n%s = 0x%x\n", #varname, varname);
#define DUMPINT(varname) fprintf(stderr, "%s = %u", #varname, varname);
#define re return

int opcode_type(unsigned char op1);
char *opcode_final(unsigned char op1);
int opcode_build();
int opcode_decode(unsigned char opcode[], int index, int code_section_address_of_entry_point, unsigned char *finalstr);


int opcode_walk(char *FileName, int max, int from_entrypoint, IMAGE_NT_HEADERS *NTHeader, IMAGE_SECTION_HEADER *Code_SectionHeader);
int initialize();




int opcode_walk(char *FileName, int max, int from_entrypoint, IMAGE_NT_HEADERS *NTHeader, IMAGE_SECTION_HEADER *Code_SectionHeader)
{
    char opcodetype = 0;
    unsigned char *finalstr = (unsigned char *) malloc(64);
    initialize();

    if(from_entrypoint){
        code_section_address_of_entry_point = (NTHeader->OptionalHeader.ImageBase + NTHeader->OptionalHeader.AddressOfEntryPoint);

        code_section_address_of_entry_point_rfa = Code_SectionHeader->PointerToRawData + \
                (NTHeader->OptionalHeader.AddressOfEntryPoint - NTHeader->OptionalHeader.BaseOfCode);

        SetColor(6);
        printf("\n------------------- OPCODE analysis START (first %d bytes from entry point)-------------------\n", max);

    }
    else {
        code_section_address_of_entry_point = (NTHeader->OptionalHeader.ImageBase + Code_SectionHeader->VirtualAddress);
        code_section_address_of_entry_point_rfa = Code_SectionHeader->PointerToRawData;
        SetColor(6);
        printf("\n------------------- OPCODE analysis START (first %d bytes from beginning of code base)-------------------\n", max);
    }


    SetColor(11);

    hFile = CreateFile(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("error in opening the file \n");
        return -1;
    }

    ret = SetFilePointer(hFile, code_section_address_of_entry_point_rfa, NULL, FILE_BEGIN);

    //unsigned char *opcode = (unsigned char *) malloc (700);
    //ret = ReadFile(hFile, opcode, 700, &out, NULL);

    unsigned char *opcode = (unsigned char *) malloc (max+1);
    memset(opcode, 0, max+1);
    ret = ReadFile(hFile, opcode, max, &out, NULL);
    if (ret != TRUE) {
        printf("ReadFile error! \n");
    }
    //            printf("\n\n brk !!!\n\n"); break;





    int i =0, j =0, k =0, ret = 0;


    opcode_build();

    extern int breakhere;

    for(index = 0; index < 5214; ++no_of_opcodes_processed) {
        printf("%.8X:  ", code_section_address_of_entry_point+index);

        ret = opcode_decode(opcode, index, code_section_address_of_entry_point+index, finalstr);

        if((ret - index) == 1)
            printf(":\t\t\t\t%s", finalstr);
        else if((ret - index) == 2)
            printf(":\t\t\t%s ", finalstr);
        else if((ret - index) == 3)
            printf(":\t\t\t%s", finalstr);
        else if((ret - index) == 4)
            printf(":\t\t\t%s", finalstr);
        else if((ret - index) == 5)
            printf(":\t\t\t%s", finalstr);
        else if((ret - index) == 10)
            printf(":\t%s", finalstr);
        else
            printf(":\t\t%s", finalstr);


        memset(finalstr, 0, 64);
        index = ret;
        printf("\n");
        if(breakhere){
            //puts(rm_str);
            puts("break here to test");
            exit(0);
        }
    }





    printf("");
    DUMP(no_of_opcodes_processed);
    printf("\n\n");


    CloseHandle(hFile);
}


