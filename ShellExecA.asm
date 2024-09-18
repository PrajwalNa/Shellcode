uwu:
    ; create a new stack frame
    push ebp
    mov ebp, esp
    sub esp, 0x78           ; Allocate space for local variables (80 bytes)

    ; store "SHELL32.dll" to search
    xor eax, eax
    push eax
    push 0x6c6c64
    push 0x2e32334c
    push 0x4c454853
    mov [ebp - 0x04], esp   ; Pointer to "SHELL32.dll" in var 4

    ; store function name ("ShellExecuteA")
    xor eax, eax
    push eax
    push 0x41
    push 0x65747563
    push 0x6578456c
    push 0x6c656853
    mov [ebp - 0x08], esp   ; Pointer to "ShellExecuteA\x00" in var 8

    ; look for shell32.dll base address
    xor eax, eax
    mov ebx, [fs:0x30 + eax]    ; PEB
    mov ebx, [ebx + 0x0C]       ; PEB_LDR_DATA
    mov ebx, [ebx + 0x14]       ; InMemoryOrderModuleList (first entry)
    mov ebx, [ebx]              ; Flink (ntdll.dll)
    mov ebx, [ebx]              ; Flink (kernel32.dll)

    .search:
        mov ebx, [ebx]          ; Flink (next entry)
        mov edi, [ebx + 0x20]   ; Get FullDllName from LDR_DATA_TABLE_ENTRY, !it is in unicode!
        add edi, 0x28           ; skip "C:\\Windows\\System32\\"
        mov esi, [ebp - 0x04]   ; Move pointer to "shell32.dll" into esi
        xor ecx, ecx            ; clear out counter
        add cx, 0x0B            ; add num of bytes to compare, 11 characters of "SHELL32.dll"
        cld

        .compare:
            lodsb               ; load a byte into al
            mov dx, word [edi]  ; get two bytes into dx
            add edi, 0x02       ; move edi up by 2 (current character + current character null byte)
            cmp al, dl          ; compare the two character bytes only
            jne uwu.search      ; if not equal, move to next entry
            loop uwu.compare    ; loop until cx value is exhausted

    mov ebx, [ebx + 0x10]       ; BaseAddress
    
    mov [ebp - 0xC], ebx    ; Store SHELL32.dll base address in var C
    
    ; look for address of Address Table, Name Pointer Table & Ordinal Table in SHELL32.dll
    mov eax, [ebx + 0x3C]   ; PE Signature RVA (base + 0x3C)
    add eax, ebx            ; PE Signature addr.
    mov eax, [eax + 0x78]   ; Export Table RVA (PE addr. + 0x78)
    add eax, ebx            ; Export Table addr.

    mov edx, [eax + 0x14]   ; Number of exported functions
    
    mov ecx, [eax + 0x1C]   ; RVA of Address Table (Export Table addr. + 0x1C)
    add ecx, ebx            ; Addr. of Address Table
    mov [ebp - 0x10], ecx   ; Store Address Table addr. in var 10
    
    mov ecx, [eax + 0x20]   ; RVA of Name Pointer Table (Export Table addr. + 0x20)
    add ecx, ebx            ; Addr. of Name Pointer Table
    mov [ebp - 0x14], ecx   ; Store Name Pointer Table addr. in var 14
    
    mov ecx, [eax + 0x24]   ; RVA of Ordinal Table (Export Table addr. + 0x24)
    add ecx, ebx            ; Addr. of Ordinal Table
    mov [ebp - 0x18], ecx   ; Store Ordinal Table addr. in var 18
    
    xor eax, eax            ; counter for keeping track of position

    ; look for the string
    .scan:
        mov edi, [ebp - 0x14]   ; Name Pointer Table addr.
        mov esi, [ebp - 0x08]   ; String "ShellExecuteA"
        xor ecx, ecx            ; clearing the character counter
        cld                     ; clear direction flag to read strings left to right
        
        ; since we're moving the base address of Name Pointer Table in edi every turn,
        ; and each entry is 4 bytes, just increment by the position (eax) * 4 bytes
        ; that gets us the RVA of n'th entry
        mov edi, [edi + eax * 0x04]
        add edi, ebx    ; get addr. of n'th entry

        add cx, 0x0D    ; Num of bytes to be compared in "ShellExecuteA"
        repe cmpsb      ; repeat until equal, compare esi and edi byte by byte
        jz uwu.good     ; if match is found (ZF=1), jump to the label 'good'
        
        inc eax         ; increment counter
        cmp eax, edx    ; compare if we reached the last exported function
        jb uwu.scan     ; if eax < edx, continue loop
        
        jmp uwu.fin
    
    ; if the string is found
    .good:
        mov edx, [ebp - 0x18]   ; Addr. of Ordinal Table
        mov ecx, [ebp - 0x10]   ; Addr. of Address Table
        
        ; move the Ordinal Number into eax (Ordinal Base + Position * Bytes in Each Entry)
        movzx eax, word [edx + eax * 0x02]
        ; move the RVA into eax (Address Table base + Ordinal Number * Bytes in Each Entry)
        mov eax, [ecx + eax * 0x04]
        add eax, ebx            ; get actual address of function by adding to shell32 base
        
        ; call the function with args '/c echo "Hello from shellcode!!!" > file.txt'
        ; don't worry about unescaped characters, they'll be normalised when pushing into stack anyways
        xor edx, edx
        push edx
        push 0x7478742e
        push 0x656c6966
        push 0x203e2022
        push 0x21212165
        push 0x646f636c
        push 0x6c656873
        push 0x206d6f72
        push 0x66206f6c
        push 0x6c654822
        push 0x206f6863
        push 0x6520632f

        mov esi, esp        ; esi -> '/c echo "Hello from shellcode!!" > file.txt'
        
        push edx
        push 0x657865
        push 0x2e646d63
        mov edi, esp        ; edi -> "cmd.exe" 
        
        push edx
        push 0x6e65706f
        mov edx, esp        ; edx -> "open"
        
        xor ecx, ecx
        push ecx            ; Visibility (nShowCmd) [0]
        push ecx            ; Directory (lpDirectory) [Null]
        push esi            ; Arguments (lpParameters) ["/c echo "Hello from shellcode!!" > file.txt"]
        push edi            ; File (lpFile) ["cmd.exe"]
        push edx            ; Operation (lpOperation) ["open"]
        push ecx            ; Handle (hwnd) [NULL]
        call eax            ; Invoke ShellExecuteA

    ; cleanup    
    .fin:
        add esp, 0x58
        pop ebp
        ret
