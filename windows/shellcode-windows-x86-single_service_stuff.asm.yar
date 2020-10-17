
    rule single_service_stuff___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::__start0__"
    
        /*
            FC                   | .                    | cld
            E88C000000           | .....                | call start
        */
    
        strings:
            $a   = { fc e8 8c 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_service_stuff_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::api_call"
    
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
    
    
    rule single_service_stuff_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::next_mod"
    
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
    
    
    rule single_service_stuff_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::loop_modname"
    
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
    
    
    rule single_service_stuff_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::not_lowercase"
    
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
    
    
    rule single_service_stuff_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::get_next_func"
    
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
    
    
    rule single_service_stuff_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::loop_funcname"
    
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
    
    
    rule single_service_stuff_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::finish"
    
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
    
    
    rule single_service_stuff_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::get_next_mod1"
    
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
    
    
    rule single_service_stuff_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::start"
    
        /*
            5D                   | ]                    | pop ebp
            6A00                 | j.                   | push byte 0x0
            6870693332           | hpi32                | push 0x32336970
            6861647661           | hadva                | push 0x61766461
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
            6849434500           | hICE.                | push 0x00454349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            8D85D0000000         | ......               | lea eax, [ebp+0xd0]
            6A00                 | j.                   | push 0x00000000
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            89E0                 | ..                   | mov eax,esp
            6A00                 | j.                   | push 0x00000000
            50                   | P                    | push eax
            68FAF772CB           | h..r.                | push 0xcb72f7fa	; StartServiceCtrlDispatcherA
            FFD5                 | ..                   | call ebp
            6A00                 | j.                   | push 0x00000000
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            31C0                 | 1.                   | xor eax,eax
            C3                   | .                    | ret
            FC                   | .                    | cld
            E800000000           | .....                | call me
        */
    
        strings:
            $a   = { 5d 6a 00 68 70 69 33 32 68 61 64 76 61 54 68 4c 77 26 07 ff d5 68 49 43 45 00 68 53 45 52 56 89 e1 8d 85 d0 00 00 00 6a 00 50 51 89 e0 6a 00 50 68 fa f7 72 cb ff d5 6a 00 68 f0 b5 a2 56 ff d5 58 58 58 58 31 c0 c3 fc e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_service_stuff_me_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::me"
    
        /*
            5D                   | ]                    | pop ebp
            81EDD6000000         | ......               | sub ebp, 0xd6
            6849434600           | hICF.                | push 0x00464349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            8D85C9000000         | ......               | lea eax, [ebp+0xc9]
            6A00                 | j.                   | push 0x00000000
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            680BAA4452           | h..DR                | push 0x5244aa0b	; RegisterServiceCtrlHandlerExA
            FFD5                 | ..                   | call ebp
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A04                 | j.                   | push 0x00000004
            6A10                 | j.                   | push 0x00000010
            89E1                 | ..                   | mov ecx, esp
            6A00                 | j.                   | push 0x00000000
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            68C655377D           | h.U7}                | push 0x7d3755c6	; SetServiceStatus
            FFD5                 | ..                   | call ebp
            683F000F00           | h?...                | push 0x000f003f
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6867F03676           | hg.6v                | push 0x7636f067	; OpenSCManagerA
            FFD5                 | ..                   | call ebp
            89C7                 | ..                   | mov edi, eax
            6849434600           | hICF.                | push 0x00464349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            68FF010F00           | h....                | push 0x000f01ff
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            6856284B40           | hV(K@                | push 0x404b2856	; OpenServiceA
            FFD5                 | ..                   | call ebp
            89C6                 | ..                   | mov esi, eax
            6849434600           | hICF.                | push 0x00464349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            6A00                 | j.                   | push 0x00000000
            51                   | Q                    | push ecx
            89E1                 | ..                   | mov ecx, esp
            51                   | Q                    | push ecx
            6A01                 | j.                   | push 0x00000001
            50                   | P                    | push eax
            6887B035ED           | h..5.                | push 0xed35b087	; ChangeServiceConfig2A
            FFD5                 | ..                   | call ebp
            56                   | V                    | push esi
            68DEEA77AD           | h..w.                | push 0xad77eade	; CloseServiceHandle
            FFD5                 | ..                   | call ebp
            57                   | W                    | push edi
            68DEEA77AD           | h..w.                | push 0xad77eade	; CloseServiceHandle
            FFD5                 | ..                   | call ebp
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
            $a   = { 5d 81 ed d6 00 00 00 68 49 43 46 00 68 53 45 52 56 89 e1 8d 85 c9 00 00 00 6a 00 50 51 68 0b aa 44 52 ff d5 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 04 6a 10 89 e1 6a 00 51 50 68 c6 55 37 7d ff d5 68 3f 00 0f 00 6a 00 6a 00 68 67 f0 36 76 ff d5 89 c7 68 49 43 46 00 68 53 45 52 56 89 e1 68 ff 01 0f 00 51 50 68 56 28 4b 40 ff d5 89 c6 68 49 43 46 00 68 53 45 52 56 89 e1 6a 00 51 89 e1 51 6a 01 50 68 87 b0 35 ed ff d5 56 68 de ea 77 ad ff d5 57 68 de ea 77 ad ff d5 31 ff 6a 04 68 00 10 00 00 6a 54 57 68 58 a4 53 e5 ff d5 c7 00 44 00 00 00 8d 70 44 57 68 2e 65 78 65 68 6c 6c 33 32 68 72 75 6e 64 89 e1 56 50 57 57 6a 44 57 57 57 51 57 68 79 cc 3f 86 ff d5 8b 0e 6a 40 68 00 10 00 00 68 00 10 00 00 57 51 68 ae 87 92 3f ff d5 e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_service_stuff_me2_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::me2"
    
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
            E800000000           | .....                | call me3
        */
    
        strings:
            $a   = { 5a 89 c7 8b 0e 81 c2 47 22 11 00 54 68 00 10 00 00 52 50 51 68 c5 d8 bd e7 ff d5 31 c0 8b 0e 50 50 50 57 50 50 51 68 c6 ac 9a 79 ff d5 8b 0e 51 68 c6 96 87 52 ff d5 8b 4e 04 51 68 c6 96 87 52 ff d5 e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_service_stuff_me3_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_service_stuff::me3"
    
        /*
            5F                   | _                    | pop edi
            E9E4FDFFFF           | .....                | jmp 0x7
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            31C0                 | 1.                   | xor eax,eax
            C3                   | .                    | ret
            6849434600           | hICF.                | push 0x00464349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            8D4703               | .G.                  | lea eax, [edi+0x3]
            6A00                 | j.                   | push 0x00000000
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            680BAA4452           | h..DR                | push 0x5244aa0b	; RegisterServiceCtrlHandlerExA
            FFD5                 | ..                   | call ebp
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6A01                 | j.                   | push 0x00000001
            6A10                 | j.                   | push 0x00000010
            89E1                 | ..                   | mov ecx, esp
            6A00                 | j.                   | push 0x00000000
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            68C655377D           | h.U7}                | push 0x7d3755c6	; SetServiceStatus
            FFD5                 | ..                   | call ebp
            6A00                 | j.                   | push 0x0
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
            57                   | W                    | push edi
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 5f e9 e4 fd ff ff 58 58 58 58 31 c0 c3 68 49 43 46 00 68 53 45 52 56 89 e1 8d 47 03 6a 00 50 51 68 0b aa 44 52 ff d5 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 01 6a 10 89 e1 6a 00 51 50 68 c6 55 37 7d ff d5 6a 00 68 f0 b5 a2 56 ff d5 57 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    