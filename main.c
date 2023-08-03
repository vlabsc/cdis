#include <stdio.h>
#include <windows.h>
#include <winnt.h>

#define DUMP(varname) fprintf(stderr, "%s = 0x%x", #varname, varname);
#define DUMPINT(varname) fprintf(stderr, "%s = %u", #varname, varname);
//#define FileName "goat1.1.exe"



int initialize();
int single_mode_scan();
int peheader(char *FileName, int probe_iat, IMAGE_DOS_HEADER *DosHeader, IMAGE_NT_HEADERS *NTHeader, IMAGE_SECTION_HEADER *SectionHeader, \
             IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor, IMAGE_SECTION_HEADER *Code_SectionHeader, \
             IMAGE_SECTION_HEADER *Data_SectionHeader, int *runtime_data);

int opcode_walk(char *FileName, int max, int from_entrypoint, IMAGE_NT_HEADERS *NTHeader, IMAGE_SECTION_HEADER *Code_SectionHeader);
int hex_walk(char *FileName, int max, IMAGE_NT_HEADERS *NTHeader, IMAGE_SECTION_HEADER *Data_SectionHeader);


HANDLE hConsole;
HANDLE hFile;


IMAGE_SECTION_HEADER *Code_SectionHeader;    // this will hold the Header information of the .text / .code .bss ;etc
IMAGE_SECTION_HEADER *Data_SectionHeader;    // this will hold the Header information of the .data section

IMAGE_DOS_HEADER *DosHeader;            // this will hold the DOS or MZ Header information
IMAGE_NT_HEADERS *NTHeader;             // this will hold the new PE header information
IMAGE_SECTION_HEADER *SectionHeader;    // this will hold the Header information of each section .text .code .bss ;etc
IMAGE_IMPORT_DESCRIPTOR *ImportDescriptor;  // this will hold the ImportDescriptor -> OriginalFirstThunk, Name, FirstThunk ;etc


                                        // rfa - relative file address -> file pointer
                                        // rva - relative virtual address -> memory pointer


char *current_working_dir;
char *scan_file;
int runtime_data = 0;

int main()
{
    single_mode_scan();
    //start_scan();

    CloseHandle(hFile);
}


int single_mode_scan()
{    // 1 - msvcrt, 2 - .NET runtime
    runtime_data = 0;
    char *scan_file = "goat1.2.exe";

    // initialization area - BEGIN

    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);     // create the console, this will be helpful for colour printing

    //DosHeader = (struct IMAGE_DOS_HEADER *) malloc(sizeof(IMAGE_DOS_HEADER));
    DosHeader = malloc(sizeof(IMAGE_DOS_HEADER));
    memset(DosHeader, 0, sizeof(IMAGE_DOS_HEADER));

    NTHeader = (struct IMAGE_NT_HEADERS*) malloc(sizeof(IMAGE_NT_HEADERS ));
    memset(NTHeader, 0, sizeof(IMAGE_NT_HEADERS));

    SectionHeader = (struct IMAGE_SECTION_HEADER *) malloc(sizeof(IMAGE_SECTION_HEADER));
    ImportDescriptor = (struct IMAGE_IMPORT_DESCRIPTOR *) malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));

    Code_SectionHeader = (struct IMAGE_SECTION_HEADER *) malloc(sizeof(IMAGE_SECTION_HEADER));
    Data_SectionHeader = (struct IMAGE_SECTION_HEADER *) malloc(sizeof(IMAGE_SECTION_HEADER));
    memset(SectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    memset(Code_SectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    memset(Data_SectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));

    // initialization area - END


    peheader(scan_file, 1, DosHeader, NTHeader, SectionHeader, ImportDescriptor, Code_SectionHeader, Data_SectionHeader, &runtime_data);
    //peheader(scan_file, 0, DosHeader, NTHeader, SectionHeader, ImportDescriptor, Code_SectionHeader, Data_SectionHeader, &runtime_data);


    opcode_walk(scan_file, NTHeader->OptionalHeader.SizeOfCode, 0, NTHeader, Code_SectionHeader);
    //opcode_walk(scan_file, 15, 1, NTHeader, Code_SectionHeader);

    //hex_walk(scan_file, 18, NTHeader, Data_SectionHeader);

    printf("scanned file: %s \n", scan_file);
}


int SetColor(int color)
{
        SetConsoleTextAttribute(hConsole, color);
}

int start_scan()
{
    current_working_dir = (char *) malloc(256);
    scan_file = (char *) malloc(256);

    memset(current_working_dir, 0, 256);

    GetCurrentDirectory(256, current_working_dir);
    printf("current directory is: %s \n", current_working_dir);


    SetCurrentDirectory("\\Vlabs");

    scan();

}

int scan()
{
    int ret = 0, hFind = 0;
    WIN32_FIND_DATA *FindData;
    FindData = (WIN32_FIND_DATA *) malloc (sizeof(WIN32_FIND_DATA));

    hFind = FindFirstFile("*.*", FindData);
    ret = 1;
    if(hFind != INVALID_HANDLE_VALUE) {

        while(ret) {
            if(FindData->dwFileAttributes == 16){
                if(strncmp(FindData->cFileName, "..", 2) == 0 || strncmp(FindData->cFileName, ".", 1) == 0) {
                    // do nothing
                }
                else {
                    //printf("Dir: %s, ", FindData->cFileName);
                    //printf("attr: %d \n", FindData->dwFileAttributes);
                    SetCurrentDirectory(FindData->cFileName);
                    scan();
                    SetCurrentDirectory("..");
                }
            }
            else if(FindData->dwFileAttributes == 32) {
                if(strstr(FindData->cFileName, ".exe")) {
                    //printf("File: %s, ", FindData->cFileName);
                    //printf("attr: %d \n", FindData->dwFileAttributes);
                    GetCurrentDirectory(256, current_working_dir);
                    sprintf(scan_file, "%s\\%s", current_working_dir, FindData->cFileName);
                    peheader(scan_file, 1, DosHeader, NTHeader, SectionHeader, ImportDescriptor, Code_SectionHeader, Data_SectionHeader, &runtime_data);
                    printf("scanned file: %s \n", scan_file);
                    getch();
                }
            }

            ret = FindNextFile(hFind, FindData);
        }
    }

    free(FindData);
}


