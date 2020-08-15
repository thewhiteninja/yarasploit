
    rule w32_speaking_shellcode_find_hash_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::find_hash"
    
        /*
            31F6                 | 1.                   | xor esi, esi
            648B7630             | d.v0                 | mov esi, [fs:esi + 0x30]
            8B760C               | .v.                  | mov esi, [esi + 0x0c]
            8B761C               | .v.                  | mov esi, [esi + 0x1c]
            56                   | V                    | push esi
            66BEAA1A             | f...                 | mov si, hash_kernel32_loadlibrarya
        */
    
        strings:
            $a   = { 31 f6 64 8b 76 30 8b 76 0c 8b 76 1c 56 66 be aa 1a }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_next_module_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::next_module"
    
        /*
            5F                   | _                    | pop edi
            8B6F08               | .o.                  | mov ebp, [edi + 0x08]
            FF37                 | .7                   | push dword [edi]
        */
    
        strings:
            $a   = { 5f 8b 6f 08 ff 37 }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_get_proc_address_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::get_proc_address_loop"
    
        /*
            8B5D3C               | .]<                  | mov ebx, [ebp + 0x3c]
            8B5C1D78             | .\.x                 | mov ebx, [ebp + ebx + 0x78]
            01EB                 | ..                   | add ebx, ebp
            8B4B18               | .K.                  | mov ecx, [ebx + 0x18]
            67E3EB               | g..                  | jcxz next_module
        */
    
        strings:
            $a   = { 8b 5d 3c 8b 5c 1d 78 01 eb 8b 4b 18 67 e3 eb }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_next_function_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::next_function_loop"
    
        /*
            8B7B20               | .{                   | mov edi, [ebx + 0x20]
            01EF                 | ..                   | add edi, ebp
            8B7C8FFC             | .|..                 | mov edi, [edi + ecx * 4 - 4]
            01EF                 | ..                   | add edi, ebp
            31C0                 | 1.                   | xor eax, eax
            99                   | .                    | cdq
        */
    
        strings:
            $a   = { 8b 7b 20 01 ef 8b 7c 8f fc 01 ef 31 c0 99 }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_hash_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::hash_loop"
    
        /*
            3217                 | 2.                   | xor dl, [edi]
            66C1CA01             | f...                 | ror dx, byte hash_ror_value
            AE                   | .                    | scasb
            75F7                 | u.                   | jne hash_loop
            49                   | I                    | dec ecx
            6639F2               | f9.                  | cmp dx, si
            7405                 | t.                   | je found_function
            67E3CB               | g..                  | jcxz next_module
            EBDE                 | ..                   | jmp next_function_loop
        */
    
        strings:
            $a   = { 32 17 66 c1 ca 01 ae 75 f7 49 66 39 f2 74 05 67 e3 cb eb de }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_found_function_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::found_function"
    
        /*
            8B7324               | .s$                  | mov esi, [ebx + 0x24]
            01EE                 | ..                   | add esi, ebp
            0FB7344E             | ..4N                 | movzx esi, word [esi + 2 * ecx]
            8B431C               | .C.                  | mov eax, [ebx + 0x1c]
            01E8                 | ..                   | add eax, ebp
            8B3CB0               | .<.                  | mov edi, [eax + 4 * esi]
            01EF                 | ..                   | add edi, ebp
            31F6                 | 1.                   | xor esi, esi
            6681FADAF0           | f....                | cmp dx, hash_ole32_coinitialize
            7418                 | t.                   | je ole32_coinitialize
            6681FA6927           | f..i'                | cmp dx, hash_ole32_cocreateinstance
            741A                 | t.                   | je ole32_cocreateinstance
        */
    
        strings:
            $a   = { 8b 73 24 01 ee 0f b7 34 4e 8b 43 1c 01 e8 8b 3c b0 01 ef 31 f6 66 81 fa da f0 74 18 66 81 fa 69 27 74 1a }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_kernel32_loadlibrary_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::kernel32_loadlibrary"
    
        /*
            6A32                 | j2                   | push byte '2'
            686F6C6533           | hole3                | push ((('3') << 24) + (('e') << 16) + (('l') << 8) + ('o'))
            54                   | T                    | push esp
            FFD7                 | ..                   | call edi
            95                   | .                    | xchg eax, ebp
            66BEDAF0             | f...                 | mov si, hash_ole32_coinitialize
            EB9B                 | ..                   | jmp get_proc_address_loop
        */
    
        strings:
            $a   = { 6a 32 68 6f 6c 65 33 54 ff d7 95 66 be da f0 eb 9b }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_ole32_coinitialize_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::ole32_coinitialize"
    
        /*
            56                   | V                    | push esi
            FFD7                 | ..                   | call edi
            66BE6927             | f.i'                 | mov si, hash_ole32_cocreateinstance
            EB92                 | ..                   | jmp get_proc_address_loop
        */
    
        strings:
            $a   = { 56 ff d7 66 be 69 27 eb 92 }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_ole32_cocreateinstance_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::ole32_cocreateinstance"
    
        /*
            686E0422D4           | hn.".                | push 0xd422046e
            68A1ECEF99           | h....                | push 0x99efeca1
            68B9729249           | h.r.I                | push 0x499272b9
            6874DF446C           | ht.Dl                | push 0x6c44df74
            89E0                 | ..                   | mov eax, esp
            684F797396           | hOys.                | push 0x9673794f
            689EE301C0           | h....                | push 0xc001e39e
            FF4C2402             | .L$.                 | dec dword [esp+2]
            689133D211           | h.3..                | push 0x11d23391
            6877937496           | hw.t.                | push 0x96749377
            89E3                 | ..                   | mov ebx, esp
            56                   | V                    | push esi
            54                   | T                    | push esp
            50                   | P                    | push eax
            6A17                 | j.                   | push byte 0x17
            56                   | V                    | push esi
            53                   | S                    | push ebx
            FFD7                 | ..                   | call edi
            5B                   | [                    | pop ebx
            686F672075           | hog u                | push ((('u') << 24) + ((' ') << 16) + (('g') << 8) + ('o'))
            686F702074           | hop t                | push ((('t') << 24) + ((' ') << 16) + (('p') << 8) + ('o'))
            6821646E68           | h!dnh                | push ((('h') << 24) + (('n') << 16) + (('d') << 8) + ('!'))
            96                   | .                    | xchg eax, esi
            89E6                 | ..                   | mov esi, esp
            50                   | P                    | push eax
        */
    
        strings:
            $a   = { 68 6e 04 22 d4 68 a1 ec ef 99 68 b9 72 92 49 68 74 df 44 6c 89 e0 68 4f 79 73 96 68 9e e3 01 c0 ff 4c 24 02 68 91 33 d2 11 68 77 93 74 96 89 e3 56 54 50 6a 17 56 53 ff d7 5b 68 6f 67 20 75 68 6f 70 20 74 68 21 64 6e 68 96 89 e6 50 }
    
        condition:
            any of them
    }
    
    
    rule w32_speaking_shellcode_unicode_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::w32-speaking-shellcode::unicode_loop"
    
        /*
            AC                   | .                    | lodsb
            6650                 | fP                   | push ax
            3C75                 | <u                   | cmp al, 'u'
            75F9                 | u.                   | jne unicode_loop
            89E1                 | ..                   | mov ecx, esp
            31C0                 | 1.                   | xor eax, eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            53                   | S                    | push ebx
            8B13                 | ..                   | mov edx, [ebx]
            8B4A50               | .JP                  | mov ecx, [edx+0x50]
            FFD1                 | ..                   | call ecx
            CC                   | .                    | int3
        */
    
        strings:
            $a   = { ac 66 50 3c 75 75 f9 89 e1 31 c0 50 50 51 53 8b 13 8b 4a 50 ff d1 cc }
    
        condition:
            any of them
    }
    
    