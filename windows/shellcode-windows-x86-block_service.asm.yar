
    rule block_service___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_service::__start0__"
    
        /*
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
            $a   = { 6a 00 68 70 69 33 32 68 61 64 76 61 54 68 4c 77 26 07 ff d5 68 49 43 45 00 68 53 45 52 56 89 e1 8d 85 d0 00 00 00 6a 00 50 51 89 e0 6a 00 50 68 fa f7 72 cb ff d5 6a 00 68 f0 b5 a2 56 ff d5 58 58 58 58 31 c0 c3 fc e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_service_me_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_service::me"
    
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
        */
    
        strings:
            $a   = { 5d 81 ed d6 00 00 00 68 49 43 46 00 68 53 45 52 56 89 e1 8d 85 c9 00 00 00 6a 00 50 51 68 0b aa 44 52 ff d5 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 04 6a 10 89 e1 6a 00 51 50 68 c6 55 37 7d ff d5 }
    
        condition:
            any of them
    }
    
    