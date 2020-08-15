
    rule block_reverse_http_load_wininet_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::load_wininet"
    
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
    
    
    rule block_reverse_http_set_retry_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::set_retry"
    
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
    
    
    rule block_reverse_http_internetopen_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::internetopen"
    
        /*
            683A5679A7           | h:Vy.                | push 0xa779563a	; InternetOpenA
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 3a 56 79 a7 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_internetconnect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::internetconnect"
    
        /*
            6A03                 | j.                   | push byte 3
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            68????0000           | h\...                | push dword 4444	; Port
            E872000000           | .r...                | call got_server_uri
        */
    
        strings:
            $a   = { 6a 03 53 53 68 ?? ?? 00 00 e8 72 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_got_server_host_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::got_server_host"
    
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
    
    
    rule block_reverse_http_httpopenrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::httpopenrequest"
    
        /*
            6800026084           | h..`.                | push ( 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 )
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
            $a   = { 68 00 02 60 84 53 53 53 57 53 50 68 eb 55 2e 3b ff d5 96 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_httpsendrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::httpsendrequest"
    
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
    
    
    rule block_reverse_http_failure_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::failure"
    
        /*
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_http_allocate_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::allocate_memory"
    
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
    
    
    rule block_reverse_http_download_prep_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::download_prep"
    
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
    
    
    rule block_reverse_http_download_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::download_more"
    
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
    
    
    rule block_reverse_http_got_server_uri_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_http::got_server_uri"
    
        /*
            5F                   | _                    | pop edi
            E88FFFFFFF           | .....                | call got_server_host
        */
    
        strings:
            $a   = { 5f e8 8f ff ff ff }
    
        condition:
            any of them
    }
    
    