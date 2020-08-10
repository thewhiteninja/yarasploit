
    rule single_loadlibrary___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::__start0__"
    
        /*
            FC                   | .                    | cld
        E882000000           | .....                | call start
        */
    
        strings:
            $a   = { fc e8 82 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_loadlibrary_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::api_call"
    
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
    
    
    rule single_loadlibrary_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::next_mod"
    
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
    
    
    rule single_loadlibrary_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::loop_modname"
    
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
    
    
    rule single_loadlibrary_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::not_lowercase"
    
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
    
    
    rule single_loadlibrary_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::get_next_func"
    
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
    
    
    rule single_loadlibrary_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::loop_funcname"
    
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
    
    
    rule single_loadlibrary_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::finish"
    
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
    
    
    rule single_loadlibrary_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::get_next_mod1"
    
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
    
    
    rule single_loadlibrary_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::start"
    
        /*
            5D                   | ]                    | pop ebp
        8D85B0000000         | ......               | lea eax, [ebp+libpath-delta]
        50                   | P                    | push eax
        684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
        FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 5d 8d 85 b0 00 00 00 50 68 4c 77 26 07 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule single_loadlibrary_exitfunk_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::exitfunk"
    
        /*
            BBE01D2A0A           | ...*.                | mov ebx, 0x0a2a1de0
        68A695BD9D           | h....                | push 0x9dbd95a6	; GetVersion
        FFD5                 | ..                   | call ebp
        3C06                 | <.                   | cmp al, byte 6
        7C0A                 | |.                   | jl short goodbye
        80FBE0               | ...                  | cmp bl, 0xe0
        7505                 | u.                   | jne short goodbye
        BB4713726F           | .G.ro                | mov ebx, 0x6f721347
        */
    
        strings:
            $a   = { bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5 3c 06 7c 0a 80 fb e0 75 05 bb 47 13 72 6f }
    
        condition:
            any of them
    }
    
    
    rule single_loadlibrary_goodbye_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_loadlibrary::goodbye"
    
        /*
            6A00                 | j.                   | push byte 0
        53                   | S                    | push ebx
        FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 6a 00 53 ff d5 }
    
        condition:
            any of them
    }
    
    