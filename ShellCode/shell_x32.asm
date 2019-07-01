bits 32
%include "shell_x32.inc"

Init:
    push    TEB_PPEB_OFFSET
    pop     eax
    fs mov  edx, dword [eax]
    mov     edx, dword [edx + PEB_PLDR_OFFSET]
    mov     edx, dword [edx + LDR_PIN_ORDER_MOD_LIST_OFFSET]
    mov     esi, edx
    lodsd
    xchg    eax, esi
    lodsd
    mov     ebp, dword [eax + LDR_MODULE_BASE_OFFSET]
    mov     eax, dword [ebp + IMAGE_DOS_HEADER_LFANEW_OFFSET]
    mov     ebx, dword [ebp + eax + IMAGE_NT_HEADER_ENTRY_EXPORT_OFFSET]
    add     ebx, ebp
    mov     esi, [ebx + EXPORT_TABLE_ADDR_OF_NAMES_OFFSET]
    add     esi, ebp
    xor     ecx, ecx
FindGetProcAddr:
    inc     ecx
    lodsd   
    add     eax, ebp
    cmp     dword [eax], STRING_OF_GETP
    jnz     FindGetProcAddr
    cmp     dword [eax + 0x4], STRING_OF_ROCA
    jnz     FindGetProcAddr
    cmp     dword [eax + 0x8], STRING_OF_DDRE
    jnz     FindGetProcAddr
    mov     esi, [ebx + EXPORT_TABLE_ADDR_OF_ORDINALS_OFFSET]
    add     esi, ebp
    mov     cx, [esi + ecx*2]
    dec     ecx
    mov     esi, [ebx + EXPORT_TABLE_ADDR_OF_FUNCTIONS_OFFSET]
    add     esi, ebp
    mov     edi, [esi + ecx*4]
    add     edi, ebp
    mov     esi, edx
    mov     ebp, dword [esi + LDR_MODULE_BASE_OFFSET]
    jmp     GetApisArray
ApisArray:
    pop     ebx
ApisArrayLoop:
    xor     edx, edx
    cmp     byte [ebx], dl
    je      ApisArrayLoopEnd
LdrLoop:
    mov     esi, [esi]
    mov     ecx, dword [esi + LDR_MODULE_BASE_OFFSET]
    test    ecx, ecx
    jz      FatalExit
    push    ebx
    push    ecx
    call    edi
    test    eax, eax
    jz      LdrLoop
    xor     edx, edx
GetThunkLoop:
    inc     ebx
    cmp     byte [ebx], dl
    jnz     GetThunkLoop
    inc     ebx
    mov     edx, [ebx]
    add     edx, ebp
    mov     dword [edx], eax
    add     ebx, 4h
LdrLoopEnd:
    jmp     ApisArrayLoop
ApisArrayLoopEnd:
    pop     ebp
    sub     ebp, 5h
    mov     dword [ebp], FIRST_ORIGINAL_FOUR_BYTES
    mov     byte [ebp + 4], FIFTH_ORIGINAL_BYTE
    jmp     ebp
FatalExit:
    int3
GetApisArray:  
    call    ApisArray