
    rule block_recv_recv_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_recv::recv"
    
        /*
            6A00                 | j.                   | push byte 0
            6A04                 | j.                   | push byte 4
            56                   | V                    | push esi
            57                   | W                    | push edi
            6802D9C85F           | h..._                | push 0x5fc8d902	; recv
            FFD5                 | ..                   | call ebp
            8B36                 | .6                   | mov esi, [esi]
            6A40                 | j@                   | push byte 0x40
            6800100000           | h....                | push 0x1000
            56                   | V                    | push esi
            6A00                 | j.                   | push byte 0
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
            93                   | .                    | xchg ebx, eax
            53                   | S                    | push ebx
        */
    
        strings:
            $a   = { 6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5 8b 36 6a 40 68 00 10 00 00 56 6a 00 68 58 a4 53 e5 ff d5 93 53 }
    
        condition:
            any of them
    }
    
    
    rule block_recv_read_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_recv::read_more"
    
        /*
            6A00                 | j.                   | push byte 0
            56                   | V                    | push esi
            53                   | S                    | push ebx
            57                   | W                    | push edi
            6802D9C85F           | h..._                | push 0x5fc8d902	; recv
            FFD5                 | ..                   | call ebp
            01C3                 | ..                   | add ebx, eax
            29C6                 | ).                   | sub esi, eax
            75EE                 | u.                   | jnz read_more
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 6a 00 56 53 57 68 02 d9 c8 5f ff d5 01 c3 29 c6 75 ee c3 }
    
        condition:
            any of them
    }
    
    