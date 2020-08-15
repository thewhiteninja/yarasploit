
    rule block_service_stopped_me3_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_service_stopped::me3"
    
        /*
            5F                   | _                    | pop edi
            E9FCFFFFFF           | .....                | jmp 0x7
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            58                   | X                    | pop eax
            31C0                 | 1.                   | xor eax,eax
            C3                   | .                    | ret
            6849434600           | hICF.                | push 0x00464349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            8D4703               | .G.                  | lea eax, [edi+0x3]
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
            6A01                 | j.                   | push 0x00000001
            6A10                 | j.                   | push 0x00000010
            89E1                 | ..                   | mov ecx, esp
            6A00                 | j.                   | push 0x00000000
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            68C655377D           | h.U7}                | push 0x7d3755c6	; SetServiceStatus
            FFD5                 | ..                   | call ebp
            6A00                 | j.                   | push 0x0
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 5f e9 fc ff ff ff 58 58 58 58 31 c0 c3 68 49 43 46 00 68 53 45 52 56 89 e1 8d 47 03 6a 00 50 51 68 0b aa 44 52 ff d5 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 01 6a 10 89 e1 6a 00 51 50 68 c6 55 37 7d ff d5 6a 00 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    