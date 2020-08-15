
    rule block_reverse_tcp_allports_reverse_tcp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_tcp_allports::reverse_tcp"
    
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
        */
    
        strings:
            $a   = { 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_tcp_allports_set_address_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_tcp_allports::set_address"
    
        /*
            68????????           | h....                | push 0x0100007f	; Host
            680200????           | h...\                | push 0x5c110002	; Port
            89E6                 | ..                   | mov esi, esp
        */
    
        strings:
            $a   = { 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e6 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_tcp_allports_try_connect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_tcp_allports::try_connect"
    
        /*
            6A10                 | j.                   | push byte 16
            56                   | V                    | push esi
            57                   | W                    | push edi
            6899A57461           | h..ta                | push 0x6174a599	; connect
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            740F                 | t.                   | jz short connected
        */
    
        strings:
            $a   = { 6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 0f }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_tcp_allports_port_bump_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_reverse_tcp_allports::port_bump"
    
        /*
            668B4602             | f.F.                 | mov word ax, [esi+2]
            86E0                 | ..                   | xchg ah,al
            40                   | @                    | inc eax
            86E0                 | ..                   | xchg ah,al
            66894602             | f.F.                 | mov word [esi+2], ax
            EBE2                 | ..                   | jmp short try_connect
        */
    
        strings:
            $a   = { 66 8b 46 02 86 e0 40 86 e0 66 89 46 02 eb e2 }
    
        condition:
            any of them
    }
    
    