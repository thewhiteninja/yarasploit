
    rule midstager__start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::_start"
    
        /*
            FC                   | .                    | cld
            31DB                 | 1.                   | xor ebx, ebx
            648B4330             | d.C0                 | mov eax, [fs:ebx+0x30]
            8B400C               | .@.                  | mov eax, [eax+0xc]
            8B501C               | .P.                  | mov edx, [eax+0x1c]
            8B12                 | ..                   | mov edx, [edx]
            8B7220               | .r                   | mov esi, [edx+0x20]
            AD                   | .                    | lodsd
            AD                   | .                    | lodsd
            4E                   | N                    | dec esi
            0306                 | ..                   | add eax, [esi]
            3D32335F32           | =23_2                | cmp eax, 0x325f3332
            0F85EBFFFFFF         | ......               | jnz 0x0d
            8B6A08               | .j.                  | mov ebp, [edx+0x8]
            8B453C               | .E<                  | mov eax, [ebp+0x3c]
            8B4C0578             | .L.x                 | mov ecx, [ebp+eax+0x78]
            8B4C0D1C             | .L..                 | mov ecx, [ebp+ecx+0x1c]
            01E9                 | ..                   | add ecx, ebp
            8B713C               | .q<                  | mov esi, [ecx+0x3c]
            01EE                 | ..                   | add esi, ebp
            60                   | `                    | pushad
            648B5B30             | d.[0                 | mov ebx, [fs:ebx+0x30]
            8B5B0C               | .[.                  | mov ebx, [ebx+0x0c]
            8B5B14               | .[.                  | mov ebx, [ebx+0x14]
        */
    
        strings:
            $a   = { fc 31 db 64 8b 43 30 8b 40 0c 8b 50 1c 8b 12 8b 72 20 ad ad 4e 03 06 3d 32 33 5f 32 0f 85 eb ff ff ff 8b 6a 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 01 e9 8b 71 3c 01 ee 60 64 8b 5b 30 8b 5b 0c 8b 5b 14 }
    
        condition:
            any of them
    }
    
    
    rule midstager_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::next_mod"
    
        /*
            8B7328               | .s(                  | mov esi, [ebx+0x28]
            6A18                 | j.                   | push byte 24
            59                   | Y                    | pop ecx
            31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 8b 73 28 6a 18 59 31 ff }
    
        condition:
            any of them
    }
    
    
    rule midstager_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::loop_modname"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            3C61                 | <a                   | cmp al, 'a'
            7C02                 | |.                   | jl not_lowercase
            2C20                 | ,                    | sub al, 0x20
        */
    
        strings:
            $a   = { 31 c0 ac 3c 61 7c 02 2c 20 }
    
        condition:
            any of them
    }
    
    
    rule midstager_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::not_lowercase"
    
        /*
            C1CF0D               | ...                  | ror edi, 13
            01C7                 | ..                   | add edi, eax
            E2F0                 | ..                   | loop loop_modname
            81FF5BBC4A6A         | ..[.Jj               | cmp edi, 0x6a4abc5b
            8B6B10               | .k.                  | mov ebp, [ebx+0x10]
            8B1B                 | ..                   | mov ebx, [ebx]
            75DB                 | u.                   | jne next_mod
            8B453C               | .E<                  | mov eax, [ebp+0x3c]
            8B7C0578             | .|.x                 | mov edi, [ebp+eax+0x78]
            01EF                 | ..                   | add edi, ebp
            8B4F18               | .O.                  | mov ecx, [edi+0x18]
            8B5F20               | ._                   | mov ebx, [edi+0x20]
            01EB                 | ..                   | add ebx, ebp
        */
    
        strings:
            $a   = { c1 cf 0d 01 c7 e2 f0 81 ff 5b bc 4a 6a 8b 6b 10 8b 1b 75 db 8b 45 3c 8b 7c 05 78 01 ef 8b 4f 18 8b 5f 20 01 eb }
    
        condition:
            any of them
    }
    
    
    rule midstager_next_entry_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::next_entry"
    
        /*
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi, [ebx+ecx*4]
            01EE                 | ..                   | add esi, ebp
            31C0                 | 1.                   | xor eax, eax
            99                   | .                    | cdq
        */
    
        strings:
            $a   = { 49 8b 34 8b 01 ee 31 c0 99 }
    
        condition:
            any of them
    }
    
    
    rule midstager_next_byte_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::next_byte"
    
        /*
            AC                   | .                    | lodsb
            84C0                 | ..                   | test al, al
            7407                 | t.                   | jz hash_complete
            C1CA0D               | ...                  | ror edx, 0x0d
            01C2                 | ..                   | add edx, eax
            EBF4                 | ..                   | jmp short next_byte
        */
    
        strings:
            $a   = { ac 84 c0 74 07 c1 ca 0d 01 c2 eb f4 }
    
        condition:
            any of them
    }
    
    
    rule midstager_hash_complete_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::hash_complete"
    
        /*
            81FA54CAAF91         | ..T...               | cmp edx, 0x91afca54
            75E3                 | u.                   | jnz next_entry
            8B5F24               | ._$                  | mov ebx, [edi+0x24]
            01EB                 | ..                   | add ebx, ebp
            668B0C4B             | f..K                 | mov cx, [ebx+ecx*2]
            8B5F1C               | ._.                  | mov ebx, [edi+0x1c]
            01EB                 | ..                   | add ebx, ebp
            8B1C8B               | ...                  | mov ebx, [ebx+ecx*4]
            01EB                 | ..                   | add ebx, ebp
            895C2408             | .\$.                 | mov [esp+0x8], ebx
            61                   | a                    | popad
            89E3                 | ..                   | mov ebx, esp
            6A00                 | j.                   | push byte +0x0
            6A04                 | j.                   | push byte +0x4
            53                   | S                    | push ebx
            57                   | W                    | push edi
            FFD6                 | ..                   | call esi
            8B1B                 | ..                   | mov ebx, [ebx]
            6A40                 | j@                   | push 0x40
            6800300000           | h.0..                | push 0x3000
            53                   | S                    | push ebx
            6A00                 | j.                   | push 0x00000000
            FFD5                 | ..                   | call ebp
            89C5                 | ..                   | mov ebp, eax
            55                   | U                    | push ebp
        */
    
        strings:
            $a   = { 81 fa 54 ca af 91 75 e3 8b 5f 24 01 eb 66 8b 0c 4b 8b 5f 1c 01 eb 8b 1c 8b 01 eb 89 5c 24 08 61 89 e3 6a 00 6a 04 53 57 ff d6 8b 1b 6a 40 68 00 30 00 00 53 6a 00 ff d5 89 c5 55 }
    
        condition:
            any of them
    }
    
    
    rule midstager_read_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::midstager::read_more"
    
        /*
            6A00                 | j.                   | push byte +0x0
            53                   | S                    | push ebx
            55                   | U                    | push ebp
            57                   | W                    | push edi
            FFD6                 | ..                   | call esi
            01C5                 | ..                   | add ebp, eax
            29C3                 | ).                   | sub ebx, eax
            85DB                 | ..                   | test ebx, ebx
            75F1                 | u.                   | jnz read_more
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 6a 00 53 55 57 ff d6 01 c5 29 c3 85 db 75 f1 c3 }
    
        condition:
            any of them
    }
    
    