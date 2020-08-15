
    rule block_reverse_ipv6_tcp_reverse_ipv6_tcp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_ipv6_tcp::reverse_ipv6_tcp"
    
        /*
            6833320000           | h32..                | push 0x00003233
            687773325F           | hws2_                | push 0x5f327377
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
            B804020000           | .....                | mov eax, 0x0204
            29C4                 | ).                   | sub esp, eax
            48                   | H                    | dec eax
            48                   | H                    | dec eax
            54                   | T                    | push esp
            50                   | P                    | push eax
            6829806B00           | h).k.                | push 0x006b8029	; WSAStartup
            FFD5                 | ..                   | call ebp
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            6A06                 | j.                   | push byte 6
            40                   | @                    | inc eax
            50                   | P                    | push eax
            6A17                 | j.                   | push byte 23
            68EA0FDFE0           | h....                | push 0xe0df0fea	; WSASocketA
            FFD5                 | ..                   | call ebp
            89C7                 | ..                   | mov edi, eax
            6A1C                 | j.                   | push byte 28
            E81C000000           | .....                | call ipv6_connect
            1700                 | ..                   | #ommited# dw 0x0017
            115C                 | .\                   | #ommited# dw 0x5c11
            00000000             | ....                 | #ommited# dd 0x00000000
            B1BBBBBBBBBBBBBB     | ........             | #ommited# dq 0xbbbbbbbbbbbbbbb1
            C1CCCCCCCCCCCCCC     | ........             | #ommited# dq 0xccccccccccccccc1
            A1AAAAAA             | ....                 | #ommited# dd 0xaaaaaaa1
        */
    
        strings:
            $a   = { 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 04 02 00 00 29 c4 48 48 54 50 68 29 80 6b 00 ff d5 50 50 50 6a 06 40 50 6a 17 68 ea 0f df e0 ff d5 89 c7 6a 1c e8 1c 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_ipv6_tcp_ipv6_connect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_ipv6_tcp::ipv6_connect"
    
        /*
            57                   | W                    | push edi
            6899A57461           | h..ta                | push 0x6174a599	; connect
            FFD5                 | ..                   | call ebp
            89E6                 | ..                   | mov esi, esp
        */
    
        strings:
            $a   = { 57 68 99 a5 74 61 ff d5 89 e6 }
    
        condition:
            any of them
    }
    
    