
    rule block_service_change_description___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_service_change_description::__start0__"
    
        /*
            683F000F00           | h?...                | push 0x000f003f
            6A00                 | j.                   | push 0x00000000
            6A00                 | j.                   | push 0x00000000
            6867F03676           | hg.6v                | push 0x7636f067	; OpenSCManagerA
            FFD5                 | ..                   | call ebp
            89C7                 | ..                   | mov edi, eax
            6849434600           | hICF.                | push 0x00464349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            68FF010F00           | h....                | push 0x000f01ff
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            6856284B40           | hV(K@                | push 0x404b2856	; OpenServiceA
            FFD5                 | ..                   | call ebp
            89C6                 | ..                   | mov esi, eax
            6849434600           | hICF.                | push 0x00464349
            6853455256           | hSERV                | push 0x56524553
            89E1                 | ..                   | mov ecx, esp
            6A00                 | j.                   | push 0x00000000
            51                   | Q                    | push ecx
            89E1                 | ..                   | mov ecx, esp
            51                   | Q                    | push ecx
            6A01                 | j.                   | push 0x00000001
            50                   | P                    | push eax
            6887B035ED           | h..5.                | push 0xed35b087	; ChangeServiceConfig2A
            FFD5                 | ..                   | call ebp
            56                   | V                    | push esi
            68DEEA77AD           | h..w.                | push 0xad77eade	; CloseServiceHandle
            FFD5                 | ..                   | call ebp
            57                   | W                    | push edi
            68DEEA77AD           | h..w.                | push 0xad77eade	; CloseServiceHandle
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 3f 00 0f 00 6a 00 6a 00 68 67 f0 36 76 ff d5 89 c7 68 49 43 46 00 68 53 45 52 56 89 e1 68 ff 01 0f 00 51 50 68 56 28 4b 40 ff d5 89 c6 68 49 43 46 00 68 53 45 52 56 89 e1 6a 00 51 89 e1 51 6a 01 50 68 87 b0 35 ed ff d5 56 68 de ea 77 ad ff d5 57 68 de ea 77 ad ff d5 }
    
        condition:
            any of them
    }
    
    