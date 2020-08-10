
    rule single_create_remote_process___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::__start0__"
    
        /*
            FC                   | .                    | cld
        E882000000           | .....                | call start
        */
    
        strings:
            $a   = { fc e8 82 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::api_call"
    
        /*
            60                   | `                    | pushad
        89E5                 | ..                   | mov ebp, esp
        31C0                 | 1.                   | xor eax, eax
        648B5030             | d.P0                 | mov edx, [fs:eax+48]
        8B520C               | .R.                  | mov edx, [edx+12]
        8B5214               | .R.                  | mov edx, [edx+20]
        */
    
        strings:
            $a   = { 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::next_mod"
    
        /*
            8B7228               | .r(                  | mov esi, [edx+40]
        0FB74A26             | ..J&                 | movzx ecx, word [edx+38]
        31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 8b 72 28 0f b7 4a 26 31 ff }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::loop_modname"
    
        /*
            AC                   | .                    | lodsb
        3C61                 | <a                   | cmp al, 'a'
        7C02                 | |.                   | jl not_lowercase
        2C20                 | ,                    | sub al, 0x20
        */
    
        strings:
            $a   = { ac 3c 61 7c 02 2c 20 }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::not_lowercase"
    
        /*
            C1CF0D               | ...                  | ror edi, 13
        01C7                 | ..                   | add edi, eax
        E2F2                 | ..                   | loop loop_modname
        52                   | R                    | push edx
        57                   | W                    | push edi
        8B5210               | .R.                  | mov edx, [edx+16]
        8B4A3C               | .J<                  | mov ecx, [edx+60]
        8B4C1178             | .L.x                 | mov ecx, [ecx+edx+120]
        E348                 | .H                   | jecxz get_next_mod1
        01D1                 | ..                   | add ecx, edx
        51                   | Q                    | push ecx
        8B5920               | .Y                   | mov ebx, [ecx+32]
        01D3                 | ..                   | add ebx, edx
        8B4918               | .I.                  | mov ecx, [ecx+24]
        */
    
        strings:
            $a   = { c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48 01 d1 51 8b 59 20 01 d3 8b 49 18 }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::get_next_func"
    
        /*
            E33A                 | .:                   | jecxz get_next_mod
        49                   | I                    | dec ecx
        8B348B               | .4.                  | mov esi, [ebx+ecx*4]
        01D6                 | ..                   | add esi, edx
        31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { e3 3a 49 8b 34 8b 01 d6 31 ff }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::loop_funcname"
    
        /*
            AC                   | .                    | lodsb
        C1CF0D               | ...                  | ror edi, 13
        01C7                 | ..                   | add edi, eax
        38E0                 | 8.                   | cmp al, ah
        75F6                 | u.                   | jne loop_funcname
        037DF8               | .}.                  | add edi, [ebp-8]
        3B7D24               | ;}$                  | cmp edi, [ebp+36]
        75E4                 | u.                   | jnz get_next_func
        58                   | X                    | pop eax
        8B5824               | .X$                  | mov ebx, [eax+36]
        01D3                 | ..                   | add ebx, edx
        668B0C4B             | f..K                 | mov cx, [ebx+2*ecx]
        8B581C               | .X.                  | mov ebx, [eax+28]
        01D3                 | ..                   | add ebx, edx
        8B048B               | ...                  | mov eax, [ebx+4*ecx]
        01D0                 | ..                   | add eax, edx
        */
    
        strings:
            $a   = { ac c1 cf 0d 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::finish"
    
        /*
            89442424             | .D$$                 | mov [esp+36], eax
        5B                   | [                    | pop ebx
        5B                   | [                    | pop ebx
        61                   | a                    | popad
        59                   | Y                    | pop ecx
        5A                   | Z                    | pop edx
        51                   | Q                    | push ecx
        FFE0                 | ..                   | jmp eax
        */
    
        strings:
            $a   = { 89 44 24 24 5b 5b 61 59 5a 51 ff e0 }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::get_next_mod1"
    
        /*
            5F                   | _                    | pop edi
        5A                   | Z                    | pop edx
        8B12                 | ..                   | mov edx, [edx]
        EB8D                 | ..                   | jmp short next_mod
        */
    
        strings:
            $a   = { 5f 5a 8b 12 eb 8d }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::start"
    
        /*
            5D                   | ]                    | pop ebp
        31FF                 | 1.                   | xor edi, edi
        6A04                 | j.                   | push 0x00000004
        6800100000           | h....                | push 0x00001000
        6A54                 | jT                   | push 0x00000054
        57                   | W                    | push edi
        6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
        FFD5                 | ..                   | call ebp
        C70044000000         | ..D...               | mov dword [eax], 0x44
        8D7044               | .pD                  | lea esi, [eax+0x44]
        57                   | W                    | push edi
        682E657865           | h.exe                | push 0x6578652e
        686C6C3332           | hll32                | push 0x32336c6c
        6872756E64           | hrund                | push 0x646e7572
        89E1                 | ..                   | mov ecx, esp
        56                   | V                    | push esi
        50                   | P                    | push eax
        57                   | W                    | push edi
        57                   | W                    | push edi
        6A44                 | jD                   | push 0x00000044
        57                   | W                    | push edi
        57                   | W                    | push edi
        57                   | W                    | push edi
        51                   | Q                    | push ecx
        57                   | W                    | push edi
        6879CC3F86           | hy.?.                | push 0x863fcc79	; CreateProcessA
        FFD5                 | ..                   | call ebp
        8B0E                 | ..                   | mov ecx, [esi]
        6A40                 | j@                   | push 0x00000040
        6800100000           | h....                | push 0x00001000
        6800100000           | h....                | push 0x00001000
        57                   | W                    | push edi
        51                   | Q                    | push ecx
        68AE87923F           | h...?                | push 0x3f9287ae	; VirtualAllocEx
        FFD5                 | ..                   | call ebp
        E800000000           | .....                | call me2
        */
    
        strings:
            $a   = { 5d 31 ff 6a 04 68 00 10 00 00 6a 54 57 68 58 a4 53 e5 ff d5 c7 00 44 00 00 00 8d 70 44 57 68 2e 65 78 65 68 6c 6c 33 32 68 72 75 6e 64 89 e1 56 50 57 57 6a 44 57 57 57 51 57 68 79 cc 3f 86 ff d5 8b 0e 6a 40 68 00 10 00 00 68 00 10 00 00 57 51 68 ae 87 92 3f ff d5 e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_create_remote_process_me2_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_create_remote_process::me2"
    
        /*
            5A                   | Z                    | pop edx
        89C7                 | ..                   | mov edi, eax
        8B0E                 | ..                   | mov ecx, [esi]
        81C247221100         | ..G"..               | add dword edx, 0x112247
        54                   | T                    | push esp
        6800100000           | h....                | push 0x00001000
        52                   | R                    | push edx
        50                   | P                    | push eax
        51                   | Q                    | push ecx
        68C5D8BDE7           | h....                | push 0xe7bdd8c5	; WriteProcessMemory
        FFD5                 | ..                   | call ebp
        31C0                 | 1.                   | xor eax, eax
        8B0E                 | ..                   | mov ecx, [esi]
        50                   | P                    | push eax
        50                   | P                    | push eax
        50                   | P                    | push eax
        57                   | W                    | push edi
        50                   | P                    | push eax
        50                   | P                    | push eax
        51                   | Q                    | push ecx
        68C6AC9A79           | h...y                | push 0x799aacc6	; CreateRemoteThread
        FFD5                 | ..                   | call ebp
        8B0E                 | ..                   | mov ecx, [esi]
        51                   | Q                    | push ecx
        68C6968752           | h...R                | push 0x528796c6	; CloseHandle
        FFD5                 | ..                   | call ebp
        8B4E04               | .N.                  | mov ecx, [esi+0x4]
        51                   | Q                    | push ecx
        68C6968752           | h...R                | push 0x528796c6	; CloseHandle
        FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 5a 89 c7 8b 0e 81 c2 47 22 11 00 54 68 00 10 00 00 52 50 51 68 c5 d8 bd e7 ff d5 31 c0 8b 0e 50 50 50 57 50 50 51 68 c6 ac 9a 79 ff d5 8b 0e 51 68 c6 96 87 52 ff d5 8b 4e 04 51 68 c6 96 87 52 ff d5 }
    
        condition:
            any of them
    }
    
    