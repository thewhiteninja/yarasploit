
    rule executex64_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::executex64::start"
    
        /*
            55                   | U                    | push ebp
            89E5                 | ..                   | mov ebp, esp
            56                   | V                    | push esi
            57                   | W                    | push edi
            8B7508               | .u.                  | mov esi, [ebp+8]
            8B4D0C               | .M.                  | mov ecx, [ebp+12]
            E800000000           | .....                | call delta
        */
    
        strings:
            $a   = { 55 89 e5 56 57 8b 75 08 8b 4d 0c e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule executex64_delta_x86
    {
        meta:
            desc = "Metasploit::windows::x86::executex64::delta"
    
        /*
            58                   | X                    | pop eax
            83C02A               | ..*                  | add eax, (native_x64-delta)
            83EC08               | ...                  | sub esp, 8
            89E2                 | ..                   | mov edx, esp
            C7420433000000       | .B.3...              | mov dword [edx+4], x64_code_segment
            8902                 | ..                   | mov dword [edx], eax
            E80E000000           | .....                | call go_all_native
            668CD8               | f..                  | mov ax, ds
            8ED0                 | ..                   | mov ss, ax
            83C414               | ...                  | add esp, (8+4+8)
            5F                   | _                    | pop edi
            5E                   | ^                    | pop esi
            5D                   | ]                    | pop ebp
            C20800               | ...                  | retn (4*2)
        */
    
        strings:
            $a   = { 58 83 c0 2a 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 0e 00 00 00 66 8c d8 8e d0 83 c4 14 5f 5e 5d c2 08 00 }
    
        condition:
            any of them
    }
    
    
    rule executex64_go_all_native_x86
    {
        meta:
            desc = "Metasploit::windows::x86::executex64::go_all_native"
    
        /*
            8B3C24               | .<$                  | mov edi, [esp]
            FF2A                 | .*                   | jmp dword far [edx]
        */
    
        strings:
            $a   = { 8b 3c 24 ff 2a }
    
        condition:
            any of them
    }
    
    
    rule executex64_native_x64_x86
    {
        meta:
            desc = "Metasploit::windows::x86::executex64::native_x64"
    
        /*
            48                   | H                    | xor rax, rax
            31C0                 | 1.                   | push rdi
            57                   | W                    | call rsi
            FFD6                 | ..                   | pop rdi
            5F                   | _                    | push rax
            50                   | P                    | mov dword [rsp+4], wow64_code_segment
            C744240423000000     | .D$.#...             | mov dword [rsp], edi
            893C24               | .<$                  | jmp dword far [rsp]
        */
    
        strings:
            $a   = { 48 31 c0 57 ff d6 5f 50 c7 44 24 04 23 00 00 00 89 3c 24 }
    
        condition:
            any of them
    }
    
    