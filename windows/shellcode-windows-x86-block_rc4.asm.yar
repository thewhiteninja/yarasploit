
    rule block_rc4_init_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_rc4::init"
    
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
    
    
    rule block_rc4_permute_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_rc4::permute"
    
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
    
    
    rule block_rc4_decrypt_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_rc4::decrypt"
    
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
        */
    
        strings:
            $a   = { fe c0 02 1c 07 8a 14 07 86 14 1f 88 14 07 02 14 1f 8a 14 17 30 55 00 45 49 75 e5 }
    
        condition:
            any of them
    }
    
    