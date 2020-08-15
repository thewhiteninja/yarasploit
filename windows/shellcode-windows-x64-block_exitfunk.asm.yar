
    rule block_exitfunk_exitfunk_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_exitfunk::exitfunk"
    
        /*
            BBE01D2A0A           | ...*.                | mov ebx, 0x0a2a1de0
            41BAA695BD9D         | A.....               | mov r10d, 0x9dbd95a6
            FFD5                 | ..                   | call rbp
            4883C428             | H..(                 | add rsp, 40
            3C06                 | <.                   | cmp al, byte 6
            7C0A                 | |.                   | jl short goodbye
            80FBE0               | ...                  | cmp bl, 0xe0
            7505                 | u.                   | jne short goodbye
            BB4713726F           | .G.ro                | mov ebx, 0x6f721347
        */
    
        strings:
            $a   = { bb e0 1d 2a 0a 41 ba a6 95 bd 9d ff d5 48 83 c4 28 3c 06 7c 0a 80 fb e0 75 05 bb 47 13 72 6f }
    
        condition:
            any of them
    }
    
    
    rule block_exitfunk_goodbye_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_exitfunk::goodbye"
    
        /*
            6A00                 | j.                   | push byte 0
            59                   | Y                    | pop rcx
            4189DA               | A..                  | mov r10d, ebx
            FFD5                 | ..                   | call rbp
        */
    
        strings:
            $a   = { 6a 00 59 41 89 da ff d5 }
    
        condition:
            any of them
    }
    
    