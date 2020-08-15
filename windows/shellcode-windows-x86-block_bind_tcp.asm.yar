
    rule block_bind_tcp_bind_tcp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_bind_tcp::bind_tcp"
    
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
            6A08                 | j.                   | push byte 8
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 6a 08 59 }
    
        condition:
            any of them
    }
    
    
    rule block_bind_tcp_push_8_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_bind_tcp::push_8_loop"
    
        /*
            50                   | P                    | push eax
            E2FD                 | ..                   | loop push_8_loop
            40                   | @                    | inc eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            68EA0FDFE0           | h....                | push 0xe0df0fea	; WSASocketA
            FFD5                 | ..                   | call ebp
            97                   | .                    | xchg edi, eax
            680200????           | h...\                | push 0x5c110002	; Port
            89E6                 | ..                   | mov esi, esp
            6A10                 | j.                   | push byte 16
            56                   | V                    | push esi
            57                   | W                    | push edi
            68C2DB3767           | h..7g                | push 0x6737dbc2	; bind
            FFD5                 | ..                   | call ebp
            57                   | W                    | push edi
            68B7E938FF           | h..8.                | push 0xff38e9b7	; listen
            FFD5                 | ..                   | call ebp
            57                   | W                    | push edi
            6874EC3BE1           | ht.;.                | push 0xe13bec74	; accept
            FFD5                 | ..                   | call ebp
            57                   | W                    | push edi
            97                   | .                    | xchg edi, eax
            68756E4D61           | hunMa                | push 0x614d6e75	; closesocket
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 50 e2 fd 40 50 40 50 68 ea 0f df e0 ff d5 97 68 02 00 ?? ?? 89 e6 6a 10 56 57 68 c2 db 37 67 ff d5 57 68 b7 e9 38 ff ff d5 57 68 74 ec 3b e1 ff d5 57 97 68 75 6e 4d 61 ff d5 }
    
        condition:
            any of them
    }
    
    