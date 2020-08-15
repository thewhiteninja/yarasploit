
    rule block_reverse_https_proxy_load_wininet_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::load_wininet"
    
        /*
            686E657400           | hnet.                | push 0x0074656e
            6877696E69           | hwini                | push 0x696e6977
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
            E80F000000           | .....                | call internetopen
        */
    
        strings:
            $a   = { 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 e8 0f 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_internetopen_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::internetopen"
    
        /*
            59                   | Y                    | pop ecx
            31FF                 | 1.                   | xor edi,edi
            57                   | W                    | push edi
            54                   | T                    | push esp
            51                   | Q                    | push ecx
            6A03                 | j.                   | push byte 3
            6A00                 | j.                   | push byte 0
            683A5679A7           | h:Vy.                | push 0xa779563a	; InternetOpenA
            FFD5                 | ..                   | call ebp
            E9C4000000           | .....                | jmp dbl_get_server_host
        */
    
        strings:
            $a   = { 59 31 ff 57 54 51 6a 03 6a 00 68 3a 56 79 a7 ff d5 e9 c4 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_internetconnect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::internetconnect"
    
        /*
            5B                   | [                    | pop ebx
            31C9                 | 1.                   | xor ecx, ecx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            6A03                 | j.                   | push byte 3
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            68????0000           | h\...                | push dword 4444	; Port
            53                   | S                    | push ebx
            50                   | P                    | push eax
            6857899FC6           | hW...                | push 0xc69f8957	; InternetConnectA
            FFD5                 | ..                   | call ebp
            89C6                 | ..                   | mov esi,eax
            70726F78795F617574685F7374617274 | proxy_auth_start     | #ommited# db "proxy_auth_start"
            E80F000000           | .....                | call set_proxy_username
        */
    
        strings:
            $a   = { 5b 31 c9 51 51 6a 03 51 51 68 ?? ?? 00 00 53 50 68 57 89 9f c6 ff d5 89 c6 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 0f 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_set_proxy_username_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::set_proxy_username"
    
        /*
            59                   | Y                    | pop ecx
            6A0F                 | j.                   | push dword 15
            51                   | Q                    | push ecx
            6A2B                 | j+                   | push byte 43
            56                   | V                    | push esi
            6875469E86           | huF..                | push 0x869e4675	; InternetSetOptionA
            FFD5                 | ..                   | call ebp
            E80F000000           | .....                | call set_proxy_password
        */
    
        strings:
            $a   = { 59 6a 0f 51 6a 2b 56 68 75 46 9e 86 ff d5 e8 0f 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_set_proxy_password_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::set_proxy_password"
    
        /*
            59                   | Y                    | pop ecx
            6A0F                 | j.                   | push dword 15
            51                   | Q                    | push ecx
            6A2C                 | j,                   | push byte 44
            56                   | V                    | push esi
            6875469E86           | huF..                | push 0x869e4675	; InternetSetOptionA
            FFD5                 | ..                   | call ebp
            70726F78795F617574685F73746F70 | proxy_auth_stop      | #ommited# db "proxy_auth_stop"
            EB48                 | .H                   | jmp get_server_uri
        */
    
        strings:
            $a   = { 59 6a 0f 51 6a 2c 56 68 75 46 9e 86 ff d5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb 48 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_httpopenrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::httpopenrequest"
    
        /*
            59                   | Y                    | pop ecx
            31D2                 | 1.                   | xor edx, edx
            52                   | R                    | push edx
            680032A084           | h.2..                | push (0x80000000 | 0x04000000 | 0x00800000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200)
            52                   | R                    | push edx
            52                   | R                    | push edx
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            56                   | V                    | push esi
            68EB552E3B           | h.U.;                | push 0x3b2e55eb	; HttpOpenRequestA
            FFD5                 | ..                   | call ebp
            89C6                 | ..                   | mov esi, eax
        */
    
        strings:
            $a   = { 59 31 d2 52 68 00 32 a0 84 52 52 52 51 52 56 68 eb 55 2e 3b ff d5 89 c6 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_set_security_options_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::set_security_options"
    
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
    
    
    rule block_reverse_https_proxy_httpsendrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::httpsendrequest"
    
        /*
            31FF                 | 1.                   | xor edi, edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            56                   | V                    | push esi
            682D06187B           | h-..{                | push 0x7b18062d	; HttpSendRequestA
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            751A                 | u.                   | jnz short allocate_memory
        */
    
        strings:
            $a   = { 31 ff 57 57 57 57 56 68 2d 06 18 7b ff d5 85 c0 75 1a }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_try_it_again_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::try_it_again"
    
        /*
            4B                   | K                    | dec ebx
            7410                 | t.                   | jz failure
            EBD5                 | ..                   | jmp short set_security_options
        */
    
        strings:
            $a   = { 4b 74 10 eb d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_failure_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::failure"
    
        /*
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_allocate_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::allocate_memory"
    
        /*
            6A40                 | j@                   | push byte 0x40
            6800100000           | h....                | push 0x1000
            6800004000           | h..@.                | push 0x00400000
            57                   | W                    | push edi
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 6a 40 68 00 10 00 00 68 00 00 40 00 57 68 58 a4 53 e5 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_proxy_download_prep_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::download_prep"
    
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
    
    
    rule block_reverse_https_proxy_download_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_https_proxy::download_more"
    
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
    
    