
    rule migrate___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::__start0__"
    
        /*
            FC                   | .                    | cld
            8B742404             | .t$.                 | mov esi, [esp+4]
            81EC00200000         | ... ..               | sub esp, 0x2000
            E882000000           | .....                | call start
        */
    
        strings:
            $a   = { fc 8b 74 24 04 81 ec 00 20 00 00 e8 82 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule migrate_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::api_call"
    
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
    
    
    rule migrate_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::next_mod"
    
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
    
    
    rule migrate_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::loop_modname"
    
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
    
    
    rule migrate_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::not_lowercase"
    
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
    
    
    rule migrate_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::get_next_func"
    
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
    
    
    rule migrate_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::loop_funcname"
    
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
    
    
    rule migrate_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::finish"
    
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
    
    
    rule migrate_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::get_next_mod1"
    
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
    
    
    rule migrate_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::migrate::start"
    
        /*
            5D                   | ]                    | pop ebp
            6833320000           | h32..                | push 0x00003233
            687773325F           | hws2_                | push 0x5f327377
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
            B890010000           | .....                | mov eax, 0x0190
            29C4                 | ).                   | sub esp, eax
            54                   | T                    | push esp
            50                   | P                    | push eax
            6829806B00           | h).k.                | push 0x006b8029	; WSAStartup
            FFD5                 | ..                   | call ebp
            50                   | P                    | push eax
            50                   | P                    | push eax
            8D5E10               | .^.                  | lea ebx, [esi+16]
            53                   | S                    | push ebx
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            68EA0FDFE0           | h....                | push 0xe0df0fea	; WSASocketA
            FFD5                 | ..                   | call ebp
            97                   | .                    | xchg edi, eax
            FF36                 | .6                   | push dword [esi]
            681D9F2635           | h..&5                | push 0x35269f1d	; SetEvent
            FFD5                 | ..                   | call ebp
            FF5608               | .V.                  | call dword [esi+8]
        */
    
        strings:
            $a   = { 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 8d 5e 10 53 50 40 50 40 50 68 ea 0f df e0 ff d5 97 ff 36 68 1d 9f 26 35 ff d5 ff 56 08 }
    
        condition:
            any of them
    }
    
    