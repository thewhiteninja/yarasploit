
    rule apc___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::__start0__"
    
        /*
            FC                   | .                    | cld
            8B742404             | .t$.                 | mov esi, [esp+4]
            55                   | U                    | push ebp
            89E5                 | ..                   | mov ebp, esp
            E88C000000           | .....                | call start
        */
    
        strings:
            $a   = { fc 8b 74 24 04 55 89 e5 e8 8c 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule apc_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::api_call"
    
        /*
            60                   | `                    | pushad
            89E5                 | ..                   | mov ebp, esp
            31D2                 | 1.                   | xor edx, edx
            648B5230             | d.R0                 | mov edx, [fs:edx+0x30]
            8B520C               | .R.                  | mov edx, [edx+0xc]
            8B5214               | .R.                  | mov edx, [edx+0x14]
        */
    
        strings:
            $a   = { 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 }
    
        condition:
            any of them
    }
    
    
    rule apc_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::next_mod"
    
        /*
            8B7228               | .r(                  | mov esi, [edx+0x28]
            0FB74A26             | ..J&                 | movzx ecx, word [edx+0x26]
            31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 8b 72 28 0f b7 4a 26 31 ff }
    
        condition:
            any of them
    }
    
    
    rule apc_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::loop_modname"
    
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
    
    
    rule apc_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::not_lowercase"
    
        /*
            C1CF0D               | ...                  | ror edi, 0xd
            01C7                 | ..                   | add edi, eax
            49                   | I                    | dec ecx
            75EF                 | u.                   | jnz loop_modname
            52                   | R                    | push edx
            57                   | W                    | push edi
            8B5210               | .R.                  | mov edx, [edx+0x10]
            8B423C               | .B<                  | mov eax, [edx+0x3c]
            01D0                 | ..                   | add eax, edx
            8B4078               | .@x                  | mov eax, [eax+0x78]
            85C0                 | ..                   | test eax, eax
            744C                 | tL                   | jz get_next_mod1
            01D0                 | ..                   | add eax, edx
            50                   | P                    | push eax
            8B4818               | .H.                  | mov ecx, [eax+0x18]
            8B5820               | .X                   | mov ebx, [eax+0x20]
            01D3                 | ..                   | add ebx, edx
        */
    
        strings:
            $a   = { c1 cf 0d 01 c7 49 75 ef 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4c 01 d0 50 8b 48 18 8b 58 20 01 d3 }
    
        condition:
            any of them
    }
    
    
    rule apc_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::get_next_func"
    
        /*
            85C9                 | ..                   | test ecx, ecx
            743C                 | t<                   | jz get_next_mod
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi, [ebx+ecx*4]
            01D6                 | ..                   | add esi, edx
            31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 85 c9 74 3c 49 8b 34 8b 01 d6 31 ff }
    
        condition:
            any of them
    }
    
    
    rule apc_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::loop_funcname"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            C1CF0D               | ...                  | ror edi, 0xd
            01C7                 | ..                   | add edi, eax
            38E0                 | 8.                   | cmp al, ah
            75F4                 | u.                   | jne loop_funcname
            037DF8               | .}.                  | add edi, [ebp-8]
            3B7D24               | ;}$                  | cmp edi, [ebp+0x24]
            75E0                 | u.                   | jnz get_next_func
            58                   | X                    | pop eax
            8B5824               | .X$                  | mov ebx, [eax+0x24]
            01D3                 | ..                   | add ebx, edx
            668B0C4B             | f..K                 | mov cx, [ebx+2*ecx]
            8B581C               | .X.                  | mov ebx, [eax+0x1c]
            01D3                 | ..                   | add ebx, edx
            8B048B               | ...                  | mov eax, [ebx+4*ecx]
            01D0                 | ..                   | add eax, edx
        */
    
        strings:
            $a   = { 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e0 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 }
    
        condition:
            any of them
    }
    
    
    rule apc_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::finish"
    
        /*
            89442424             | .D$$                 | mov [esp+0x24], eax
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
    
    
    rule apc_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::get_next_mod1"
    
        /*
            5F                   | _                    | pop edi
            5A                   | Z                    | pop edx
            8B12                 | ..                   | mov edx, [edx]
            EB83                 | ..                   | jmp next_mod
        */
    
        strings:
            $a   = { 5f 5a 8b 12 eb 83 }
    
        condition:
            any of them
    }
    
    
    rule apc_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::start"
    
        /*
            5B                   | [                    | pop ebx
            807E1000             | .~..                 | cmp byte [esi+16], 0
            753B                 | u;                   | jne cleanup
            C6461001             | .F..                 | mov byte [esi+16], 1
            68A695BD9D           | h....                | push 0x9dbd95a6	; GetVersion
            FFD3                 | ..                   | call ebx
            3C06                 | <.                   | cmp al, byte 6
            7C1A                 | |.                   | jl short continue
            31C9                 | 1.                   | xor ecx, ecx
            648B4118             | d.A.                 | mov eax, [fs:ecx+24]
            3988A8010000         | 9.....               | cmp dword [eax+424], ecx
            750C                 | u.                   | jne continue
            8D93D2000000         | ......               | lea edx, [ebx+context-delta]
            8990A8010000         | ......               | mov dword [eax+424], edx
        */
    
        strings:
            $a   = { 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a 31 c9 64 8b 41 18 39 88 a8 01 00 00 75 0c 8d 93 d2 00 00 00 89 90 a8 01 00 00 }
    
        condition:
            any of them
    }
    
    
    rule apc_continue_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::continue"
    
        /*
            31C9                 | 1.                   | xor ecx, ecx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            FF7608               | .v.                  | push dword [esi+8]
            FF36                 | .6                   | push dword [esi]
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            6838680D16           | h8h..                | push 0x160d6838	; CreateThread
            FFD3                 | ..                   | call ebx
        */
    
        strings:
            $a   = { 31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 }
    
        condition:
            any of them
    }
    
    