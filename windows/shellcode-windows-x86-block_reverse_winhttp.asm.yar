
    rule block_reverse_winhttp_load_winhttp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::load_winhttp"
    
        /*
            6874747000           | http.                | push 0x00707474
            6877696E68           | hwinh                | push 0x686e6977
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 74 74 70 00 68 77 69 6e 68 54 68 4c 77 26 07 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_set_retry_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::set_retry"
    
        /*
            6A06                 | j.                   | push byte 6
            5F                   | _                    | pop edi
            31DB                 | 1.                   | xor ebx, ebx
            89F9                 | ..                   | mov ecx, edi
        */
    
        strings:
            $a   = { 6a 06 5f 31 db 89 f9 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_winhttpopen_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::winhttpopen"
    
        /*
            68041F9DBB           | h....                | push 0xbb9d1f04	; WinHttpOpen
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 04 1f 9d bb ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_winhttpconnect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::winhttpconnect"
    
        /*
            53                   | S                    | push ebx
            68????0000           | h\...                | push dword 4444	; Port
            E888000000           | .....                | call got_server_uri
        */
    
        strings:
            $a   = { 53 68 ?? ?? 00 00 e8 88 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_got_server_host_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::got_server_host"
    
        /*
            50                   | P                    | push eax
            68469B1EC2           | hF...                | push 0xc21e9b46	; WinHttpConnect
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 50 68 46 9b 1e c2 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_winhttpopenrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::winhttpopenrequest"
    
        /*
            6800010000           | h....                | push 0x00000100
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            57                   | W                    | push edi
            53                   | S                    | push ebx
            50                   | P                    | push eax
            689810B35B           | h...[                | push 0x5bb31098	; WinHttpOpenRequest
            FFD5                 | ..                   | call ebp
            96                   | .                    | xchg esi, eax
        */
    
        strings:
            $a   = { 68 00 01 00 00 53 53 53 57 53 50 68 98 10 b3 5b ff d5 96 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_winhttpsendrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::winhttpsendrequest"
    
        /*
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            56                   | V                    | push esi
            689558BB91           | h.X..                | push 0x91bb5895	; WinHttpSendRequest
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            750A                 | u.                   | jnz short receive_response
        */
    
        strings:
            $a   = { 53 53 53 53 53 53 56 68 95 58 bb 91 ff d5 85 c0 75 0a }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_failure_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::failure"
    
        /*
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_receive_response_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::receive_response"
    
        /*
            53                   | S                    | push ebx
            56                   | V                    | push esi
            6805889D70           | h...p                | push 0x709d8805	; WinHttpReceiveResponse
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            74EC                 | t.                   | jz failure
        */
    
        strings:
            $a   = { 53 56 68 05 88 9d 70 ff d5 85 c0 74 ec }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_allocate_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::allocate_memory"
    
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
    
    
    rule block_reverse_winhttp_download_prep_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::download_prep"
    
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
    
    
    rule block_reverse_winhttp_download_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::download_more"
    
        /*
            57                   | W                    | push edi
            6800200000           | h. ..                | push 8192
            53                   | S                    | push ebx
            56                   | V                    | push esi
            686C29247E           | hl)$~                | push 0x7e24296c	; WinHttpReadData
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            74C0                 | t.                   | jz failure
            8B07                 | ..                   | mov eax, [edi]
            01C3                 | ..                   | add ebx, eax
            85C0                 | ..                   | test eax,eax
            75E5                 | u.                   | jnz download_more
            58                   | X                    | pop eax
        */
    
        strings:
            $a   = { 57 68 00 20 00 00 53 56 68 6c 29 24 7e ff d5 85 c0 74 c0 8b 07 01 c3 85 c0 75 e5 58 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_winhttp_got_server_uri_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_winhttp::got_server_uri"
    
        /*
            5F                   | _                    | pop edi
            E880FFFFFF           | .....                | call got_server_host
        */
    
        strings:
            $a   = { 5f e8 80 ff ff ff }
    
        condition:
            any of them
    }
    
    