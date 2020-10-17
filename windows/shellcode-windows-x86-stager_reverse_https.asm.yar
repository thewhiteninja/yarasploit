
    rule stager_reverse_https___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::__start0__"
    
        /*
            FC                   | .                    | cld
            E88C000000           | .....                | call start
        */
    
        strings:
            $a   = { fc e8 8c 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::api_call"
    
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
    
    
    rule stager_reverse_https_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::next_mod"
    
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
    
    
    rule stager_reverse_https_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::loop_modname"
    
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
    
    
    rule stager_reverse_https_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::not_lowercase"
    
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
    
    
    rule stager_reverse_https_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::get_next_func"
    
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
    
    
    rule stager_reverse_https_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::loop_funcname"
    
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
    
    
    rule stager_reverse_https_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::finish"
    
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
    
    
    rule stager_reverse_https_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::get_next_mod1"
    
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
    
    
    rule stager_reverse_https_load_wininet_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::load_wininet"
    
        /*
            686E657400           | hnet.                | push 0x0074656e
            6877696E69           | hwini                | push 0x696e6977
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_set_retry_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::set_retry"
    
        /*
            6A08                 | j.                   | push byte 8
            5F                   | _                    | pop edi
            31DB                 | 1.                   | xor ebx, ebx
            89F9                 | ..                   | mov ecx, edi
        */
    
        strings:
            $a   = { 6a 08 5f 31 db 89 f9 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_internetopen_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::internetopen"
    
        /*
            683A5679A7           | h:Vy.                | push 0xa779563a	; InternetOpenA
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 3a 56 79 a7 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_internetconnect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::internetconnect"
    
        /*
            6A03                 | j.                   | push byte 3
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            68????0000           | h\...                | push dword 4444	; Port
            E886000000           | .....                | call got_server_uri
        */
    
        strings:
            $a   = { 6a 03 53 53 68 ?? ?? 00 00 e8 86 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_got_server_host_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::got_server_host"
    
        /*
            50                   | P                    | push eax
            6857899FC6           | hW...                | push 0xc69f8957	; InternetConnectA
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 50 68 57 89 9f c6 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_httpopenrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::httpopenrequest"
    
        /*
            680032E084           | h.2..                | push ( 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 | 0x00800000 | 0x00002000 | 0x00001000 )
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            57                   | W                    | push edi
            53                   | S                    | push ebx
            50                   | P                    | push eax
            68EB552E3B           | h.U.;                | push 0x3b2e55eb	; HttpOpenRequestA
            FFD5                 | ..                   | call ebp
            96                   | .                    | xchg esi, eax
        */
    
        strings:
            $a   = { 68 00 32 e0 84 53 53 53 57 53 50 68 eb 55 2e 3b ff d5 96 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_set_security_options_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::set_security_options"
    
        /*
            6880330000           | h.3..                | push 0x00003380
            89E0                 | ..                   | mov eax, esp
            6A04                 | j.                   | push byte 4
            50                   | P                    | push eax
            6A1F                 | j.                   | push byte 31
            56                   | V                    | push esi
            6875469E86           | huF..                | push 0x869e4675	; InternetSetOptionA
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 80 33 00 00 89 e0 6a 04 50 6a 1f 56 68 75 46 9e 86 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_httpsendrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::httpsendrequest"
    
        /*
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            56                   | V                    | push esi
            682D06187B           | h-..{                | push 0x7b18062d	; HttpSendRequestA
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            750A                 | u.                   | jnz short allocate_memory
        */
    
        strings:
            $a   = { 53 53 53 53 56 68 2d 06 18 7b ff d5 85 c0 75 0a }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_failure_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::failure"
    
        /*
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_allocate_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::allocate_memory"
    
        /*
            6A40                 | j@                   | push byte 0x40
            6800100000           | h....                | push 0x1000
            6800004000           | h..@.                | push 0x00400000
            53                   | S                    | push ebx
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 6a 40 68 00 10 00 00 68 00 00 40 00 53 68 58 a4 53 e5 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_download_prep_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::download_prep"
    
        /*
            93                   | .                    | xchg eax, ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            89E7                 | ..                   | mov edi, esp
        */
    
        strings:
            $a   = { 93 53 53 89 e7 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_download_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::download_more"
    
        /*
            57                   | W                    | push edi
            6800200000           | h. ..                | push 8192
            53                   | S                    | push ebx
            56                   | V                    | push esi
            68129689E2           | h....                | push 0xe2899612	; InternetReadFile
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            74CD                 | t.                   | jz failure
            8B07                 | ..                   | mov eax, [edi]
            01C3                 | ..                   | add ebx, eax
            85C0                 | ..                   | test eax,eax
            75E5                 | u.                   | jnz download_more
            58                   | X                    | pop eax
        */
    
        strings:
            $a   = { 57 68 00 20 00 00 53 56 68 12 96 89 e2 ff d5 85 c0 74 cd 8b 07 01 c3 85 c0 75 e5 58 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_https_got_server_uri_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_https::got_server_uri"
    
        /*
            5F                   | _                    | pop edi
            E87BFFFFFF           | .{...                | call got_server_host
        */
    
        strings:
            $a   = { 5f e8 7b ff ff ff }
    
        condition:
            any of them
    }
    
    