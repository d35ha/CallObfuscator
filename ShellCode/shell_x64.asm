bits 64
%include "shell_x64.inc"

Init:
    pop     r15
    sub     r15, 5h
    push    TEB_PPEB_OFFSET
    pop     rax
    gs mov  rdx, [rax]
    mov     rdx, [rdx + PEB_PLDR_OFFSET]
    mov     rdx, [rdx + LDR_PIN_ORDER_MOD_LIST_OFFSET]
    push    rdx
    pop     rsi
    lodsq
    xchg    rax, rsi
    lodsq
    mov     rbp, [rax + LDR_MODULE_BASE_OFFSET]
    mov     eax, [rbp + IMAGE_DOS_HEADER_LFANEW_OFFSET]
    mov     ebx, [rbp + rax + IMAGE_NT_HEADER_ENTRY_EXPORT_OFFSET]
    add     rbx, rbp
    mov     esi, [rbx + EXPORT_TABLE_ADDR_OF_NAMES_OFFSET]
    add     rsi, rbp
    xor     rcx, rcx
FindGetProcAddr:
    inc     rcx
    lodsd   
    add     rax, rbp
    cmp     dword [rax], STRING_OF_GETP
    jnz     FindGetProcAddr
    cmp     dword [rax + 0x4], STRING_OF_ROCA
    jnz     FindGetProcAddr
    cmp     dword [rax + 0x8], STRING_OF_DDRE
    jnz     FindGetProcAddr
    mov     esi, [rbx + EXPORT_TABLE_ADDR_OF_ORDINALS_OFFSET]
    add     rsi, rbp
    mov     cx, [rsi + rcx*2]
    dec     rcx
    mov     esi, [rbx + EXPORT_TABLE_ADDR_OF_FUNCTIONS_OFFSET]
    add     rsi, rbp
    mov     edi, [rsi + rcx*4]
    add     rdi, rbp
    push    rdx
    pop     rsi
    mov     rbp, qword [rsi + LDR_MODULE_BASE_OFFSET]
    jmp     GetApisArray
ApisArray:
    pop     rbx
ApisArrayLoop:
    xor     rdx, rdx
    cmp     byte [rbx], dl
    je      ApisArrayLoopEnd
LdrLoop:
    mov     rsi, [rsi]
    mov     rcx, qword [rsi + LDR_MODULE_BASE_OFFSET]
    test    rcx, rcx
    jz      FatalExit
    push    rbx
    pop     rdx
    call    rdi
    test    rax, rax
    jz      LdrLoop
    xor     rdx, rdx
GetThunkLoop:
    inc     rbx
    cmp     byte [rbx], dl
    jnz     GetThunkLoop
    inc     rbx
    mov     edx, [rbx]
    add     rdx, rbp
    mov     qword [rdx], rax
    add     rbx, 4h
LdrLoopEnd:
    jmp     ApisArrayLoop
ApisArrayLoopEnd:
    mov     dword [r15], FIRST_ORIGINAL_FOUR_BYTES
    mov     byte [r15 + 4], FIFTH_ORIGINAL_BYTE
    jmp     r15
FatalExit:
    int3
GetApisArray:  
    call    ApisArray