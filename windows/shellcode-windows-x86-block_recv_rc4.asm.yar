
    rule block_recv_rc4_recv_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_recv_rc4::recv"
    
        /*
            6A00                 | j.                   | push byte 0
            6A04                 | j.                   | push byte 4
            56                   | V                    | push esi
            57                   | W                    | push edi
            6802D9C85F           | h..._                | push 0x5fc8d902	; recv
            FFD5                 | ..                   | call ebp
            8B36                 | .6                   | mov esi, [esi]
            81F6786F726B         | ..xork               | xor esi, "xork"
            8D0E                 | ..                   | lea ecx, [esi+0x00]
            6A40                 | j@                   | push byte 0x40
            6800100000           | h....                | push 0x1000
            51                   | Q                    | push ecx
            6A00                 | j.                   | push byte 0
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
            8D9800010000         | ......               | lea ebx, [eax+0x100]
            53                   | S                    | push ebx
            56                   | V                    | push esi
            50                   | P                    | push eax
        */
    
        strings:
            $a   = { 6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5 8b 36 81 f6 78 6f 72 6b 8d 0e 6a 40 68 00 10 00 00 51 6a 00 68 58 a4 53 e5 ff d5 8d 98 00 01 00 00 53 56 50 }
    
        condition:
            any of them
    }
    
    
    rule block_recv_rc4_read_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_recv_rc4::read_more"
    
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
            5B                   | [                    | pop ebx
            59                   | Y                    | pop ecx
            5D                   | ]                    | pop ebp
            55                   | U                    | push ebp
            57                   | W                    | push edi
            89DF                 | ..                   | mov edi, ebx
            E810000000           | .....                | call after_key
            7263346B65796D65746173706C6F6974 | rc4keymetasploit     | #ommited# db "rc4keymetasploit"
        */
    
        strings:
            $a   = { 6a 00 56 53 57 68 02 d9 c8 5f ff d5 01 c3 29 c6 75 ee 5b 59 5d 55 57 89 df e8 10 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_recv_rc4_init_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_recv_rc4::init"
    
        /*
            AA                   | .                    | stosb
            FEC0                 | ..                   | inc al
            75FB                 | u.                   | jnz init
            81EF00010000         | ......               | sub edi, 0x100
            31DB                 | 1.                   | xor ebx, ebx
        */
    
        strings:
            $a   = { aa fe c0 75 fb 81 ef 00 01 00 00 31 db }
    
        condition:
            any of them
    }
    
    
    rule block_recv_rc4_permute_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_recv_rc4::permute"
    
        /*
            021C07               | ...                  | add bl, [edi+eax]
            89C2                 | ..                   | mov edx, eax
            80E20F               | ...                  | and dl, 0xf
            021C16               | ...                  | add bl, [esi+edx]
            8A1407               | ...                  | mov dl, [edi+eax]
            86141F               | ...                  | xchg dl, [edi+ebx]
            881407               | ...                  | mov [edi+eax], dl
            FEC0                 | ..                   | inc al
            75E8                 | u.                   | jnz permute
            31DB                 | 1.                   | xor ebx, ebx
        */
    
        strings:
            $a   = { 02 1c 07 89 c2 80 e2 0f 02 1c 16 8a 14 07 86 14 1f 88 14 07 fe c0 75 e8 31 db }
    
        condition:
            any of them
    }
    
    
    rule block_recv_rc4_decrypt_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_recv_rc4::decrypt"
    
        /*
            FEC0                 | ..                   | inc al
            021C07               | ...                  | add bl, [edi+eax]
            8A1407               | ...                  | mov dl, [edi+eax]
            86141F               | ...                  | xchg dl, [edi+ebx]
            881407               | ...                  | mov [edi+eax], dl
            02141F               | ...                  | add dl, [edi+ebx]
            8A1417               | ...                  | mov dl, [edi+edx]
            305500               | 0U.                  | xor [ebp], dl
            45                   | E                    | inc ebp
            49                   | I                    | dec ecx
            75E5                 | u.                   | jnz decrypt
            5F                   | _                    | pop edi
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { fe c0 02 1c 07 8a 14 07 86 14 1f 88 14 07 02 14 1f 8a 14 17 30 55 00 45 49 75 e5 5f c3 }
    
        condition:
            any of them
    }
    
    