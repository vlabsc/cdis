#include <stdio.h>
#include <windows.h>
#include <winnt.h>

#define DUMP(varname) fprintf(stderr, "\n%s = 0x%x\n", #varname, varname);
#define DUMPINT(varname) fprintf(stderr, "\n%s = %u\n", #varname, varname);
//#define FileName "goat3.2.exe"

int peheader(char *FileName, int probe_iat, IMAGE_DOS_HEADER *DosHeader, IMAGE_NT_HEADERS *NTHeader, IMAGE_SECTION_HEADER *SectionHeader, \
             IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor, IMAGE_SECTION_HEADER *Code_SectionHeader, \
             IMAGE_SECTION_HEADER *Data_SectionHeader, int *runtime_data);

/*
int Import_Table_rfa = 0;       // Import table begin address at the file
int Import_Table_rva = 0;       // Import table begin address at memory
int Import_Table_Section_size = 0;       // Size of the section that contain Import table

int Import_Directory_Table_rfa = 0;       // Import table begin address at memory
int Import_Directory_Table_rva = 0;       // Import table begin address at memory

int Import_Name_Table_rfa = 0;              // the address of the thunk data at the file

int Import_Directory_Table_DLLName_rfa = 0;    // this holds the offset within the file for fetching name of dll file
int ImportDescriptor_Valid_Walk = 0;    // this is used as boolean while walking through the ImportDescriptor table
                                        // the table reaches the end when all the values OriginalFirstThunk;
                                        // ForwarderChain; Name; FirstThunk are set to 0
*/

unsigned int Import_Table_rfa = 0;       // Import table begin address at the file
unsigned int Import_Table_rva = 0;       // Import table begin address at memory
unsigned int Import_Table_Section_size = 0;       // Size of the section that contain Import table

unsigned int Import_Directory_Table_rfa = 0;       // Import table begin address at memory
unsigned int Import_Directory_Table_rva = 0;       // Import table begin address at memory

unsigned int Import_Name_Table_rfa = 0;              // the address of the thunk data at the file

unsigned int Import_Directory_Table_DLLName_rfa = 0;    // this holds the offset within the file for fetching name of dll file
unsigned int ImportDescriptor_Valid_Walk = 0;    // this is used as boolean while walking through the ImportDescriptor table
                                        // the table reaches the end when all the values OriginalFirstThunk;
                                        // ForwarderChain; Name; FirstThunk are set to 0



int peheader(char *FileName, int probe_iat, IMAGE_DOS_HEADER *DosHeader, IMAGE_NT_HEADERS *NTHeader, IMAGE_SECTION_HEADER *SectionHeader, \
             IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor, IMAGE_SECTION_HEADER *Code_SectionHeader, \
             IMAGE_SECTION_HEADER *Data_SectionHeader, int *runtime_data)
{
    // declaration area - BEGIN
    HANDLE hFile;

    // this will be used as map file
    // to print the IMAGE DATA DIRECTORY information when parsing the optional header
    char *IMAGE_DATA_DIRECTORY_Table[16] = {"Export table\0", "Import table\0", "Resource table\0", "Exception table\0",
    "Certificate table\0", "Base relocation table\0", "Debugging information starting\0", "Architecture-specific data\0",
    "Global pointer register relative virtual address\0", "Thread local storage (TLS) table\0", "Load configuration table\0",
    "Bound import table\0", "Import address table\0", "Delay import descriptor\0", "The CLR header\0", "Reserved\0"};

    int ret = 0;            // used to check function return values
    int out = 0;            // used as an argument in ReadFile function
    int check = 0;          // used to check while fetching character values from file
    int directory_table_index = 1, name_table_row = 0;     // used in iteration
    int check_addr = 0;     // this is used during iteration through walk through, iterate till value 0 occurs
    int i = 0;

    char *ImportDLL_Name, *Function_Name;
    IMAGE_IMPORT_BY_NAME *ImportByName;

    // declaration area - END

    ImportByName = (struct IMAGE_IMPORT_BY_NAME *) malloc(sizeof(IMAGE_IMPORT_BY_NAME));
    memset(ImportByName, 0, sizeof(IMAGE_IMPORT_BY_NAME));

    ImportDLL_Name = (char *) malloc(257);
    Function_Name = (char *) malloc(257);
    memset(ImportDLL_Name, 0, 257);
    memset(Function_Name, 0, 257);

    printf("analysing the file: %s\n", FileName);

    hFile = CreateFile(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("error in opening the file \n");
        return -1;
    }

    // ************************** IMAGE_DOS_HEADER BEGIN **************************

    ret = ReadFile(hFile, DosHeader, sizeof(IMAGE_DOS_HEADER), &out, NULL);
    if (ret != TRUE) {
        printf("ReadFile error! \n");
    }

    SetColor(6);
    printf("\n------------------- IMAGE_DOS_HEADER PROBE START ------------------- \n");
    SetColor(2);
    printf("The IMAGE_DOS_HEADER begins at file offset: 0x%.8X\n", 0);
    printf("DOS Signature: 0x%X   -> [DOS Signature 'MZ']\n", DosHeader->e_magic);
    printf("lfanew: 0x%.8X   -> [pointer to the PE header]\n", DosHeader->e_lfanew);
    printf("e_cs: 0x%.2X   -> [code segment value in DOS mode]\n", DosHeader->e_cs);
    printf("e_ip: 0x%.2X   -> [instruction pointer value in DOS mode]\n", DosHeader->e_ip);
    printf("e_ss: 0x%.2X   -> [stack segment value in DOS mode]\n", DosHeader->e_ss);
    printf("e_sp: 0x%.2X   -> [stack pointer value in DOS mode]\n", DosHeader->e_sp);
    SetColor(6);
    printf("------------------- IMAGE_DOS_HEADER PROBE END ------------------- \n");

    // ************************** IMAGE_DOS_HEADER END **************************


    // ************************** IMAGE_NT_HEADERS BEGIN **************************

    ret = SetFilePointer(hFile, DosHeader->e_lfanew, NULL, FILE_BEGIN);
    if (ret == INVALID_SET_FILE_POINTER) {
        printf("Error in SetFilePointer\n");
        return -1;
    }

    ret = ReadFile(hFile, NTHeader, sizeof(IMAGE_NT_HEADERS), &out, NULL);

    SetColor(6);
    printf("\n------------------- IMAGE_NT_HEADERS PROBE START ------------------- \n");
    SetColor(2);
    printf("The IMAGE_NT_HEADER begins at file offset: 0x%.8X\n", DosHeader->e_lfanew);
    printf("Signature: 0x%.8X   -> [PE Signature 'PE']\n", NTHeader->Signature);

    // ************* FileHeader PROBE BEGIN *************
    SetColor(6);
    printf("  --- IMAGE_NT_HEADERS -> FileHeader PROBE START --- \n");
    SetColor(2);
    printf("   The FileHeader begins at: 0x%.8X\n", (DosHeader->e_lfanew + 4));
    printf("   FileHeader.Machine: 0x%.4X -> ", NTHeader->FileHeader.Machine);
    switch(NTHeader->FileHeader.Machine) {
    case 0x14c:
        printf("x86");
        break;
    case 0x0200:
        printf("Intel Itanium");
        break;
    case 0x8664:
        printf("x64");
        break;
    default:
        break;
    }
    printf("   -> [supported machine architecture] \n");

    printf("   FileHeader.Number of Sections: 0x%.4X\n", NTHeader->FileHeader.NumberOfSections);
    printf("   FileHeader.PointerToSymbolTable: 0x%.8X\n", NTHeader->FileHeader.PointerToSymbolTable);
    printf("   FileHeader.NumberOfSymbols: 0x%.8X\n", NTHeader->FileHeader.NumberOfSymbols);
    printf("   FileHeader.SizeOfOptionalHeader: 0x%.4X\n", NTHeader->FileHeader.SizeOfOptionalHeader);
    printf("   FileHeader.Characteristics: 0x%.4X   -> ", NTHeader->FileHeader.Characteristics);
    if ((NTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
        printf("[IMAGE_FILE_EXECUTABLE_IMAGE = EXE File]");
    if ((NTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
        printf("[IMAGE_FILE_DLL = DLL File]");

    printf("\n");
    SetColor(6);
    printf("  --- IMAGE_NT_HEADERS -> FileHeader PROBE END  --- \n");

    // ************* FileHeader PROBE END *************


    // ************* IMAGE_OPTIONAL_HEADER BEGIN *************

    SetColor(6);
    printf("  --- IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER PROBE START  --- \n");
    SetColor(2);
    printf("   The IMAGE_OPTIONAL_HEADER begins at: 0x%.8X\n", (DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER)));
    printf("   ImageBase: 0x%.8X\n", NTHeader->OptionalHeader.ImageBase);
    printf("   Base of Code: 0x%.8X, Base of Data: 0x%.8X\n", NTHeader->OptionalHeader.BaseOfCode, NTHeader->OptionalHeader.BaseOfData);
    printf("   AddressOfEntryPoint: 0x%.8X\n", NTHeader->OptionalHeader.AddressOfEntryPoint);
    printf("   SizeOfCode: 0x%.8X\n", NTHeader->OptionalHeader.SizeOfCode);

    SetColor(6);
    printf("   Walking through the DataDirectory table ...\n");
    SetColor(3);

    for(i = 0; i < 16; ++i){
            printf("   DataDirectory[%d].VirtualAddress: 0x%.8X (%s)", i, NTHeader->OptionalHeader.DataDirectory[i].VirtualAddress, IMAGE_DATA_DIRECTORY_Table[i]);
            if(i == IMAGE_DIRECTORY_ENTRY_IMPORT){
                Import_Directory_Table_rva = NTHeader->OptionalHeader.DataDirectory[i].VirtualAddress;
                printf("   -> [ Location of the Import Table within the memory ]");
            }
            printf("\n");
    }


    SetColor(6);
    printf("  --- IMAGE_NT_HEADERS -> IMAGE_OPTIONAL_HEADER PROBE END  --- \n");

    SetColor(6);
    printf("------------------- IMAGE_NT_HEADERS PROBE END ------------------- \n");

    // ************* IMAGE_OPTIONAL_HEADER  EGIN *************

    // ************************** IMAGE_NT_HEADERS END **************************




    // ************************** Section table BEGIN **************************


    SetColor(6);
    printf("\n------------------- Section table PROBE BEGIN ------------------- \n");
    SetColor(2);

    for(i = 0; i < NTHeader->FileHeader.NumberOfSections; i++) {

        ret = SetFilePointer(hFile, (DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i)), NULL, FILE_BEGIN);
        if (ret == INVALID_SET_FILE_POINTER) {
            printf("Error in SetFilePointer\n");
            return -1;
        }

        memset(SectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
        ret = ReadFile(hFile, SectionHeader, sizeof(IMAGE_SECTION_HEADER), &out, NULL);

        SetColor(3);
        printf("Section name: %s  -  at file offset: 0x%X\n", SectionHeader->Name, (DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i)));

        SetColor(2);
        printf(" VirtualAddress: 0x%.8X, ", SectionHeader->VirtualAddress);
        printf(" PointerToRawData: 0x%.8X\n", SectionHeader->PointerToRawData);
        printf(" VirtualSize: 0x%.8X, ", SectionHeader->Misc.VirtualSize);
        printf(" SizeOfRawData: 0x%.8X\n", SectionHeader->SizeOfRawData);
        printf(" Charactersitics: ");

        if ((SectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE)    printf("IMAGE_SCN_CNT_CODE  ");
        if ((SectionHeader->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ) printf("IMAGE_SCN_MEM_READ  ");
        if ((SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE) printf("IMAGE_SCN_MEM_WRITE  ");
        if ((SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)    printf("IMAGE_SCN_MEM_EXECUTE  ");
        if ((SectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA) printf("IMAGE_SCN_CNT_INITIALIZED_DATA ");
        if ((SectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf("IMAGE_SCN_CNT_UNINITIALIZED_DATA  ");
        if ((SectionHeader->Characteristics & IMAGE_DIRECTORY_ENTRY_IMPORT) == IMAGE_DIRECTORY_ENTRY_IMPORT) printf("IMAGE_DIRECTORY_ENTRY_IMPORT  ");

        /*
        much accurate one is coded below
        if (((SectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE) && \
            ((SectionHeader->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ) && \
            ((SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)) {
            memset(Code_SectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
            memcpy(Code_SectionHeader, SectionHeader, sizeof(IMAGE_SECTION_HEADER));
            SetColor(3);
            printf("\n [ This is a code section ! ]");
        }
        */

        // much accurate one
        if (NTHeader->OptionalHeader.BaseOfCode == SectionHeader->VirtualAddress) {
            memset(Code_SectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
            memcpy(Code_SectionHeader, SectionHeader, sizeof(IMAGE_SECTION_HEADER));
            SetColor(3);
            printf("\n [ This is a code section ! ]");
        }


        if(strncmp(SectionHeader->Name, ".data", strlen(SectionHeader->Name)-1) == 0){
            if (((SectionHeader->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ)) {
                memset(Data_SectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
                memcpy(Data_SectionHeader, SectionHeader, sizeof(IMAGE_SECTION_HEADER));
                SetColor(3);
                printf("\n [ This is a data section ! ]");
            }
        }

        // tweaked if code - see below comments
        if(Import_Directory_Table_rva >= SectionHeader->VirtualAddress && \
           (Import_Directory_Table_rva <= (SectionHeader->VirtualAddress + SectionHeader->SizeOfRawData))) {

               Import_Table_rfa = SectionHeader->PointerToRawData;
               Import_Table_rva = SectionHeader->VirtualAddress;
               Import_Table_Section_size = SectionHeader->SizeOfRawData;

               // Import_Directory_Table_rva is already computed before
               Import_Directory_Table_rfa = Import_Table_rfa + (Import_Directory_Table_rva - Import_Table_rva);

               SetColor(3);
               printf("\n [ This section %s contains Import data ] ", SectionHeader->Name);
           }

        printf("\n");
    }

    /*
    // DEBUG
    printf("\n--- Import_Table_rva: 0x%.8X \n", Import_Table_rva);
    printf("\n--- Import_Table_rfa: 0x%.8X \n", Import_Table_rfa);
    printf("\n--- Import_Directory_Table_rva: 0x%.8X \n", Import_Directory_Table_rva);
    printf("\n--- Import_Directory_Table_rfa: 0x%.8X \n", Import_Directory_Table_rfa);
    //printf("\n--- Import_Directory_Table_rfa_addr: 0x%.8X \n", Import_Directory_Table_rfa_addr);
    return 0;
    */


    SetColor(6);
    printf("------------------- Section table PROBE ENDDDDDDDDDDDDDDDDDDDDDDD ------------------- \n\n");

    // ************************** Section table END **************************

    if(!probe_iat){
        CloseHandle(hFile);
        printf(" iat: %d \n", probe_iat);
        return 0;
    }
    getch();


    printf("------------------- Import data PROBE START -------------------\n");
    SetColor(2);

    directory_table_index = 0;
    ImportDescriptor_Valid_Walk = 1;
    printf("Import Directory Table at file offset: 0x%X\n", Import_Directory_Table_rfa);

    while(ImportDescriptor_Valid_Walk){

        // ImageDescriptor = Image Directory Table
        memset(ImportDescriptor, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

        ret = SetFilePointer(hFile, (Import_Directory_Table_rfa +(sizeof(IMAGE_IMPORT_DESCRIPTOR) * directory_table_index)), NULL, FILE_BEGIN);
        if (ret == INVALID_SET_FILE_POINTER) {
            printf("Error in SetFilePointer during Import_Directory_Table_offset\n");
            return -1;
        }
        ReadFile(hFile, ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), &out, NULL);

        ImportDescriptor_Valid_Walk = (ImportDescriptor->OriginalFirstThunk | ImportDescriptor->Name | ImportDescriptor->FirstThunk);
        if (ImportDescriptor_Valid_Walk) {
            char c = 1;
            printf("OriginalFirstThunk: 0x%.8X, ", ImportDescriptor->OriginalFirstThunk);
            printf("FirstThunk: 0x%.8X \n", ImportDescriptor->FirstThunk);
            printf("Name RVA: 0x%.8X -> ", ImportDescriptor->Name);


            //Import_Directory_Table_DLLName_rfa = ImportDescriptor->Name - Import_Table_rva;
            Import_Directory_Table_DLLName_rfa = Import_Table_rfa + (ImportDescriptor->Name - Import_Table_rva);

            ret = SetFilePointer(hFile, Import_Directory_Table_DLLName_rfa, NULL, FILE_BEGIN);

            // tweaked code 2
            ReadFile(hFile, ImportDLL_Name, 256, &out, NULL);
            printf("%s\n", ImportDLL_Name);

            if(strlen(ImportDLL_Name) == 11){
                if(strncmp(ImportDLL_Name, "mscoree.dll", 11) == 0){
                    printf("Microsoft .NET runtime detected\n");
                    *runtime_data = 2;
                }
            }
            if(strlen(ImportDLL_Name) == 10){
                if(strncmp(ImportDLL_Name, "msvcrt.dll", 10) == 0){
                    printf("Microsoft Visual C runtime detected\n");
                    *runtime_data = 1;
                }
            }

            printf("enumerating all the functions \n");

            check_addr = 1;
            name_table_row = 0;
            while(check_addr) {
                    Import_Name_Table_rfa = name_table_row + Import_Table_rfa + \
                                (ImportDescriptor->OriginalFirstThunk - Import_Table_rva);

                    ret = SetFilePointer(hFile, Import_Name_Table_rfa, NULL, FILE_BEGIN);
                    IMAGE_THUNK_DATA32 *ThunkData;
                    ThunkData = (struct IMAGE_THUNK_DATA32 *) malloc(sizeof(IMAGE_THUNK_DATA32 ));
                    ReadFile(hFile, ThunkData, sizeof(IMAGE_THUNK_DATA32), &out, NULL);

                    // check_addr = 0x00000000 - end of imports
                    check_addr = ThunkData->u1.AddressOfData;


                    Import_Name_Table_rfa = Import_Table_rfa + (ThunkData->u1.AddressOfData - Import_Table_rva);

                    // first fetch the Hint value = 2 bytes
                    ret = SetFilePointer(hFile, Import_Name_Table_rfa, NULL, FILE_BEGIN);
                    ReadFile(hFile, ImportByName, sizeof(IMAGE_IMPORT_BY_NAME), &out, NULL);

                    // after reading hint = length of hint = 2 so increment Import_Name_Table_rfa += 2;
                    Import_Name_Table_rfa += 2;

                    if(check_addr) { // check_addr = 0x00000000 - end of imports
                        // .NET runtime function _CorExeMain starts with hint 0000
                        // so we should be careful here
                        if(ImportByName->Hint || *runtime_data == 2){

                            if(Import_Name_Table_rfa > (Import_Table_rva+Import_Table_Section_size)) {
                                printf("\tOrdinal: 0x%.4X\n", ImportByName->Hint);
                            }

                            else if(Import_Name_Table_rfa < (Import_Table_rva+Import_Table_Section_size)) {

                                // fetch the function name
                                memset(Function_Name, 0, 256);
                                ret = SetFilePointer(hFile, Import_Name_Table_rfa, NULL, FILE_BEGIN);
                                ReadFile(hFile, Function_Name, 256, &out, NULL);

                                printf("\tHintS: 0x%.4X, Name: ", ImportByName->Hint);
                                printf("%s\n", Function_Name);
                            }

                        }
                    }
                    name_table_row += 4;
            }
            printf("\n");
        }
        ++directory_table_index;
        getch();
    }
    SetColor(6);
    printf("------------------- Import data PROBE END -------------------\n");

    CloseHandle(hFile);
    return 0;
}
