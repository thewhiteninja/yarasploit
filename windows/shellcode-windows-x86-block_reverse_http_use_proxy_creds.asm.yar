
    rule block_reverse_http_use_proxy_creds_load_wininet_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::load_wininet"
    
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
    
    
    rule block_reverse_http_use_proxy_creds_internetopen_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::internetopen"
    
        /*
            31FF                 | 1.                   | xor edi,edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            6A00                 | j.                   | push byte 0
            54                   | T                    | push esp
            683A5679A7           | h:Vy.                | push 0xa779563a	; InternetOpenA
            FFD5                 | ..                   | call ebp
            EB4B                 | .K                   | jmp short dbl_get_server_host
        */
    
        strings:
            $a   = { 31 ff 57 57 57 57 6a 00 54 68 3a 56 79 a7 ff d5 eb 4b }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_use_proxy_creds_internetconnect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::internetconnect"
    
        /*
            5B                   | [                    | pop ebx
            31FF                 | 1.                   | xor edi, edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            6A03                 | j.                   | push byte 3
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            68????0000           | h\...                | push dword 4444	; Port
            53                   | S                    | push ebx
            50                   | P                    | push eax
            6857899FC6           | hW...                | push 0xc69f8957	; InternetConnectA
            FFD5                 | ..                   | call ebp
            EB34                 | .4                   | jmp get_server_uri
        */
    
        strings:
            $a   = { 5b 31 ff 57 57 6a 03 51 52 68 ?? ?? 00 00 53 50 68 57 89 9f c6 ff d5 eb 34 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_use_proxy_creds_httpopenrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::httpopenrequest"
    
        /*
            59                   | Y                    | pop ecx
            31D2                 | 1.                   | xor edx, edx
            52                   | R                    | push edx
            6800022084           | h.. .                | push (0x80000000 | 0x04000000 | 0x00200000 | 0x00000200)
            52                   | R                    | push edx
            52                   | R                    | push edx
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            50                   | P                    | push eax
            68EB552E3B           | h.U.;                | push 0x3b2e55eb	; HttpOpenRequestA
            FFD5                 | ..                   | call ebp
            89C6                 | ..                   | mov esi, eax
        */
    
        strings:
            $a   = { 59 31 d2 52 68 00 02 20 84 52 52 52 51 52 50 68 eb 55 2e 3b ff d5 89 c6 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_use_proxy_creds_httpsendrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::httpsendrequest"
    
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
    
    
    rule block_reverse_http_use_proxy_creds_try_it_again_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::try_it_again"
    
        /*
            4B                   | K                    | dec ebx
            7410                 | t.                   | jz failure
            EBE9                 | ..                   | jmp short httpsendrequest
        */
    
        strings:
            $a   = { 4b 74 10 eb e9 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_use_proxy_creds_failure_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::failure"
    
        /*
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_use_proxy_creds_allocate_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::allocate_memory"
    
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
    
    
    rule block_reverse_http_use_proxy_creds_download_prep_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::download_prep"
    
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
    
    
    rule block_reverse_http_use_proxy_creds_download_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::download_more"
    
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
    
    
    rule block_reverse_http_use_proxy_creds_get_proxy_auth_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http_use_proxy_creds::get_proxy_auth"
    
        /*
            5E                   | ^                    | pop esi
            5E                   | ^                    | pop esi
            5E                   | ^                    | pop esi
            59                   | Y                    | pop ecx
            5A                   | Z                    | pop edx
            E860FFFFFF           | .`...                | call internetconnect
        */
    
        strings:
            $a   = { 5e 5e 5e 59 5a e8 60 ff ff ff }
    
        condition:
            any of them
    }
    
    