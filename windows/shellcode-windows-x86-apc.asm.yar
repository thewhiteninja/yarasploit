
    rule apc___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::__start0__"
    
        /*
            FC                   | .                    | cld
            8B742404             | .t$.                 | mov esi, [esp+4]
            55                   | U                    | push ebp
            89E5                 | ..                   | mov ebp, esp
            E882000000           | .....                | call start
        */
    
        strings:
            $a   = { fc 8b 74 24 04 55 89 e5 e8 82 00 00 00 }
    
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
    
    
    rule apc_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::next_mod"
    
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
    
    
    rule apc_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::loop_modname"
    
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
    
    
    rule apc_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::not_lowercase"
    
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
    
    
    rule apc_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::get_next_func"
    
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
    
    
    rule apc_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::loop_funcname"
    
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
    
    
    rule apc_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::finish"
    
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
    
    
    rule apc_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::apc::get_next_mod1"
    
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
            8D93C8000000         | ......               | lea edx, [ebx+context-delta]
            8990A8010000         | ......               | mov dword [eax+424], edx
        */
    
        strings:
            $a   = { 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a 31 c9 64 8b 41 18 39 88 a8 01 00 00 75 0c 8d 93 c8 00 00 00 89 90 a8 01 00 00 }
    
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
    
    