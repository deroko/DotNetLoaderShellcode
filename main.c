#include        "defs.h"


int __cdecl wmain(int argc, wchar_t **argv){
        HANDLE  hFile;
        DWORD   dwWritten;
        PVOID   shellcode;
        ULONG   shellcode_len;
        
        shellcode = ExportShellcode(&shellcode_len);
        
        hFile = CreateFile(argv[1], GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0,0);
        WriteFile(hFile, shellcode, shellcode_len, &dwWritten, 0);
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        
        printf("Dumped file : %S\n", argv[1]);
}