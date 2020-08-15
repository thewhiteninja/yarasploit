
    rule passivex__start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::_start"
    
        /*
            FC                   | .                    | cld
            E877000000           | .w...                | call get_find_function
        */
    
        strings:
            $a   = { fc e8 77 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule passivex_find_function_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::find_function"
    
        /*
            60                   | `                    | pushad
            8B6C2424             | .l$$                 | mov ebp, [esp + 0x24]
            8B453C               | .E<                  | mov eax, [ebp + 0x3c]
            8B7C0578             | .|.x                 | mov edi, [ebp + eax + 0x78]
            01EF                 | ..                   | add edi, ebp
            8B4F18               | .O.                  | mov ecx, [edi + 0x18]
            8B5F20               | ._                   | mov ebx, [edi + 0x20]
            01EB                 | ..                   | add ebx, ebp
        */
    
        strings:
            $a   = { 60 8b 6c 24 24 8b 45 3c 8b 7c 05 78 01 ef 8b 4f 18 8b 5f 20 01 eb }
    
        condition:
            any of them
    }
    
    
    rule passivex_find_function_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::find_function_loop"
    
        /*
            E332                 | .2                   | jecxz find_function_finished
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi, [ebx + ecx * 4]
            01EE                 | ..                   | add esi, ebp
        */
    
        strings:
            $a   = { e3 32 49 8b 34 8b 01 ee }
    
        condition:
            any of them
    }
    
    
    rule passivex_compute_hash_again_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::compute_hash_again"
    
        /*
            AC                   | .                    | lodsb
            84C0                 | ..                   | test al, al
            7407                 | t.                   | jz compute_hash_finished
            C1CA0D               | ...                  | ror edx, 0xd
            01C2                 | ..                   | add edx, eax
            EBF4                 | ..                   | jmp compute_hash_again
        */
    
        strings:
            $a   = { ac 84 c0 74 07 c1 ca 0d 01 c2 eb f4 }
    
        condition:
            any of them
    }
    
    
    rule passivex_find_function_compare_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::find_function_compare"
    
        /*
            3B542428             | ;T$(                 | cmp edx, [esp + 0x28]
            75E3                 | u.                   | jnz find_function_loop
            8B5F24               | ._$                  | mov ebx, [edi + 0x24]
            01EB                 | ..                   | add ebx, ebp
            668B0C4B             | f..K                 | mov cx, [ebx + 2 * ecx]
            8B5F1C               | ._.                  | mov ebx, [edi + 0x1c]
            01EB                 | ..                   | add ebx, ebp
            8B048B               | ...                  | mov eax, [ebx + 4 * ecx]
            01E8                 | ..                   | add eax, ebp
            8944241C             | .D$.                 | mov [esp + 0x1c], eax
        */
    
        strings:
            $a   = { 3b 54 24 28 75 e3 8b 5f 24 01 eb 66 8b 0c 4b 8b 5f 1c 01 eb 8b 04 8b 01 e8 89 44 24 1c }
    
        condition:
            any of them
    }
    
    
    rule passivex_find_kernel32_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::find_kernel32"
    
        /*
            31D2                 | 1.                   | xor edx, edx
            648B4230             | d.B0                 | mov eax, [fs:edx+0x30]
            85C0                 | ..                   | test eax, eax
            780C                 | x.                   | js find_kernel32_9x
        */
    
        strings:
            $a   = { 31 d2 64 8b 42 30 85 c0 78 0c }
    
        condition:
            any of them
    }
    
    
    rule passivex_find_kernel32_nt_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::find_kernel32_nt"
    
        /*
            8B400C               | .@.                  | mov eax, [eax + 0x0c]
            8B701C               | .p.                  | mov esi, [eax + 0x1c]
            AD                   | .                    | lodsd
            8B4008               | .@.                  | mov eax, [eax + 0x8]
            EB09                 | ..                   | jmp short find_kernel32_finished
        */
    
        strings:
            $a   = { 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 }
    
        condition:
            any of them
    }
    
    
    rule passivex_find_kernel32_9x_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::find_kernel32_9x"
    
        /*
            8B4034               | .@4                  | mov eax, [eax + 0x34]
            83C07C               | ..|                  | add eax, byte 0x7c
            8B403C               | .@<                  | mov eax, [eax + 0x3c]
        */
    
        strings:
            $a   = { 8b 40 34 83 c0 7c 8b 40 3c }
    
        condition:
            any of them
    }
    
    
    rule passivex_find_kernel32_symbols_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::find_kernel32_symbols"
    
        /*
            687ED8E273           | h~..s                | push 0x73e2d87e
            50                   | P                    | push eax
            6872FEB316           | hr...                | push 0x16b3fe72
            50                   | P                    | push eax
            688E4E0EEC           | h.N..                | push 0xec0e4e8e
            50                   | P                    | push eax
            FFD7                 | ..                   | call edi
            96                   | .                    | xchg eax, esi
            FFD7                 | ..                   | call edi
            894500               | .E.                  | mov [ebp], eax
            FFD7                 | ..                   | call edi
            894504               | .E.                  | mov [ebp + 0x4], eax
        */
    
        strings:
            $a   = { 68 7e d8 e2 73 50 68 72 fe b3 16 50 68 8e 4e 0e ec 50 ff d7 96 ff d7 89 45 00 ff d7 89 45 04 }
    
        condition:
            any of them
    }
    
    
    rule passivex_load_advapi32_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::load_advapi32"
    
        /*
            52                   | R                    | push edx
            6870693332           | hpi32                | push 0x32336970
            6861647661           | hadva                | push 0x61766461
            54                   | T                    | push esp
            FFD6                 | ..                   | call esi
        */
    
        strings:
            $a   = { 52 68 70 69 33 32 68 61 64 76 61 54 ff d6 }
    
        condition:
            any of them
    }
    
    
    rule passivex_resolve_advapi32_symbols_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::resolve_advapi32_symbols"
    
        /*
            68A92B9202           | h.+..                | push 0x02922ba9
            50                   | P                    | push eax
            68DD9A1C2D           | h...-                | push 0x2d1c9add
            50                   | P                    | push eax
            FFD7                 | ..                   | call edi
            894508               | .E.                  | mov [ebp + 0x8], eax
            FFD7                 | ..                   | call edi
            97                   | .                    | xchg eax, edi
            87F3                 | ..                   | xchg esi, ebx
        */
    
        strings:
            $a   = { 68 a9 2b 92 02 50 68 dd 9a 1c 2d 50 ff d7 89 45 08 ff d7 97 87 f3 }
    
        condition:
            any of them
    }
    
    
    rule passivex_open_key_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::open_key"
    
        /*
            54                   | T                    | push esp
            56                   | V                    | push esi
            6801000080           | h....                | push 0x80000001
            FFD7                 | ..                   | call edi
            5B                   | [                    | pop ebx
            83C644               | ..D                  | add esi, byte (reg_values - strings)
            50                   | P                    | push eax
            89E7                 | ..                   | mov edi, esp
        */
    
        strings:
            $a   = { 54 56 68 01 00 00 80 ff d7 5b 83 c6 44 50 89 e7 }
    
        condition:
            any of them
    }
    
    
    rule passivex_set_values_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::set_values"
    
        /*
            803E63               | .>c                  | cmp byte [esi], 'c'
            741B                 | t.                   | jz initialize_structs
            50                   | P                    | push eax
            AD                   | .                    | lodsd
            50                   | P                    | push eax
            89E0                 | ..                   | mov eax, esp
            6A04                 | j.                   | push byte 0x4
            57                   | W                    | push edi
            6A04                 | j.                   | push byte 0x4
            6A00                 | j.                   | push byte 0x0
            50                   | P                    | push eax
            53                   | S                    | push ebx
            FF5508               | .U.                  | call [ebp + 0x8]
            EBE8                 | ..                   | jmp set_values
        */
    
        strings:
            $a   = { 80 3e 63 74 1b 50 ad 50 89 e0 6a 04 57 6a 04 6a 00 50 53 ff 55 08 eb e8 }
    
        condition:
            any of them
    }
    
    
    rule passivex_fixup_drive_letter_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::fixup_drive_letter"
    
        /*
            8A0D3000FE7F         | ..0...               | mov cl, byte [0x7ffe0030]
            880E                 | ..                   | mov byte [esi], cl
        */
    
        strings:
            $a   = { 8a 0d 30 00 fe 7f 88 0e }
    
        condition:
            any of them
    }
    
    
    rule passivex_initialize_structs_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::initialize_structs"
    
        /*
            6A54                 | jT                   | push byte 0x54
            59                   | Y                    | pop ecx
            29CC                 | ).                   | sub esp, ecx
            89E7                 | ..                   | mov edi, esp
            57                   | W                    | push edi
            F3AA                 | ..                   | rep stosb
            5F                   | _                    | pop edi
            C60744               | ..D                  | mov byte [edi], 0x44
            FE472C               | .G,                  | inc byte [edi + 0x2c]
            FE472D               | .G-                  | inc byte [edi + 0x2d]
            68756C7400           | hult.                | push 0x00746c75
            6844656661           | hDefa                | push 0x61666544
            687461305C           | hta0\                | push 0x5c306174
            6857696E53           | hWinS                | push 0x536e6957
            896708               | .g.                  | mov [edi + 8], esp
        */
    
        strings:
            $a   = { 6a 54 59 29 cc 89 e7 57 f3 aa 5f c6 07 44 fe 47 2c fe 47 2d 68 75 6c 74 00 68 44 65 66 61 68 74 61 30 5c 68 57 69 6e 53 89 67 08 }
    
        condition:
            any of them
    }
    
    
    rule passivex_execute_process_x86
    {
        meta:
            desc = "Metasploit::windows::x86::passivex::execute_process"
    
        /*
            8D5F44               | ._D                  | lea ebx, [edi + 0x44]
            53                   | S                    | push ebx
            57                   | W                    | push edi
            50                   | P                    | push eax
            50                   | P                    | push eax
            6A10                 | j.                   | push byte 0x10
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            56                   | V                    | push esi
            50                   | P                    | push eax
            FF5500               | .U.                  | call [ebp]
        */
    
        strings:
            $a   = { 8d 5f 44 53 57 50 50 6a 10 50 50 50 56 50 ff 55 00 }
    
        condition:
            any of them
    }
    
    