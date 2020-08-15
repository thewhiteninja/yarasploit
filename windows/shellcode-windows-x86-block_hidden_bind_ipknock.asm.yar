
    rule block_hidden_bind_ipknock_bind_tcp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_hidden_bind_ipknock::bind_tcp"
    
        /*
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
            50                   | P                    | push eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            68EA0FDFE0           | h....                | push 0xe0df0fea	; WSASocketA
            FFD5                 | ..                   | call ebp
            97                   | .                    | xchg edi, eax
            31DB                 | 1.                   | xor ebx, ebx
            53                   | S                    | push ebx
            680200????           | h...\                | push 0x5c110002	; Port
            89E6                 | ..                   | mov esi, esp
            6A10                 | j.                   | push byte 16
            56                   | V                    | push esi
            57                   | W                    | push edi
            68C2DB3767           | h..7g                | push 0x6737dbc2	; bind
            FFD5                 | ..                   | call ebp
            6A01                 | j.                   | push 0x1
            54                   | T                    | push esp
            6802300000           | h.0..                | push 0x3002
            68FFFF0000           | h....                | push 0xffff
            57                   | W                    | push edi
            68F1A27729           | h..w)                | push 0x2977a2f1	; setsockopt
            FFD5                 | ..                   | call ebp
            53                   | S                    | push ebx
            57                   | W                    | push edi
            68B7E938FF           | h..8.                | push 0xff38e9b7	; listen
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 31 db 53 68 02 00 ?? ?? 89 e6 6a 10 56 57 68 c2 db 37 67 ff d5 6a 01 54 68 02 30 00 00 68 ff ff 00 00 57 68 f1 a2 77 29 ff d5 53 57 68 b7 e9 38 ff ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_hidden_bind_ipknock_condition_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_hidden_bind_ipknock::condition"
    
        /*
            53                   | S                    | push ebx
            E81A000000           | .....                | call wsaaccept
            8B442404             | .D$.                 | mov eax, dword [esp+4]
            8B4004               | .@.                  | mov eax, dword [eax+4]
            8B4004               | .@.                  | mov eax, dword [eax+4]
            2DC0A80121           | -...!                | sub eax, 0x2101a8c0
            7403                 | t.                   | jz equal
            31C0                 | 1.                   | xor eax, eax
            40                   | @                    | inc eax
        */
    
        strings:
            $a   = { 53 e8 1a 00 00 00 8b 44 24 04 8b 40 04 8b 40 04 2d c0 a8 01 21 74 03 31 c0 40 }
    
        condition:
            any of them
    }
    
    
    rule block_hidden_bind_ipknock_equal_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_hidden_bind_ipknock::equal"
    
        /*
            894554               | .ET                  | mov dword [ebp+84], eax
            C22000               | . .                  | retn 0x20
        */
    
        strings:
            $a   = { 89 45 54 c2 20 00 }
    
        condition:
            any of them
    }
    
    
    rule block_hidden_bind_ipknock_wsaaccept_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_hidden_bind_ipknock::wsaaccept"
    
        /*
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            57                   | W                    | push edi
            6894ACBE33           | h...3                | push 0x33beac94	; WSAAccept
            FFD5                 | ..                   | call ebp
            837C240400           | .|$..                | cmp dword [esp+4], 0
            75CF                 | u.                   | jnz condition
            40                   | @                    | inc eax
            7506                 | u.                   | jnz connection
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            EBE8                 | ..                   | jmp wsaaccept
            74C6                 | t.                   | jz condition
        */
    
        strings:
            $a   = { 53 53 57 68 94 ac be 33 ff d5 83 7c 24 04 00 75 cf 40 75 06 53 53 eb e8 74 c6 }
    
        condition:
            any of them
    }
    
    
    rule block_hidden_bind_ipknock_connection_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_hidden_bind_ipknock::connection"
    
        /*
            48                   | H                    | dec eax
            57                   | W                    | push edi
            97                   | .                    | xchg edi, eax
            68756E4D61           | hunMa                | push 0x614d6e75	; closesocket
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 48 57 97 68 75 6e 4d 61 ff d5 }
    
        condition:
            any of them
    }
    
    