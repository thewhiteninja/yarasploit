
    rule block_recv_recv_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_recv::recv"
    
        /*
            4883EC10             | H...                 | sub rsp, 16
            4889E2               | H..                  | mov rdx, rsp
            4D31C9               | M1.                  | xor r9, r9
            6A04                 | j.                   | push byte 4
            4158                 | AX                   | pop r8
            4889F9               | H..                  | mov rcx, rdi
            41BA02D9C85F         | A...._               | mov r10d, 0x5fc8d902
            FFD5                 | ..                   | call rbp
            4883C420             | H..                  | add rsp, 32
            5E                   | ^                    | pop rsi
            89F6                 | ..                   | mov esi, esi
            6A40                 | j@                   | push byte 0x40
            4159                 | AY                   | pop r9
            6800100000           | h....                | push 0x1000
            4158                 | AX                   | pop r8
            4889F2               | H..                  | mov rdx, rsi
            4831C9               | H1.                  | xor rcx, rcx
            41BA58A453E5         | A.X.S.               | mov r10d, 0xe553a458
            FFD5                 | ..                   | call rbp
            4889C3               | H..                  | mov rbx, rax
            4989C7               | I..                  | mov r15, rax
        */
    
        strings:
            $a   = { 48 83 ec 10 48 89 e2 4d 31 c9 6a 04 41 58 48 89 f9 41 ba 02 d9 c8 5f ff d5 48 83 c4 20 5e 89 f6 6a 40 41 59 68 00 10 00 00 41 58 48 89 f2 48 31 c9 41 ba 58 a4 53 e5 ff d5 48 89 c3 49 89 c7 }
    
        condition:
            any of them
    }
    
    
    rule block_recv_read_more_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_recv::read_more"
    
        /*
            4D31C9               | M1.                  | xor r9, r9
            4989F0               | I..                  | mov r8, rsi
            4889DA               | H..                  | mov rdx, rbx
            4889F9               | H..                  | mov rcx, rdi
            41BA02D9C85F         | A...._               | mov r10d, 0x5fc8d902
            FFD5                 | ..                   | call rbp
            4801C3               | H..                  | add rbx, rax
            4829C6               | H).                  | sub rsi, rax
            4885F6               | H..                  | test rsi, rsi
            75E1                 | u.                   | jnz short read_more
            41FFE7               | A..                  | jmp r15
        */
    
        strings:
            $a   = { 4d 31 c9 49 89 f0 48 89 da 48 89 f9 41 ba 02 d9 c8 5f ff d5 48 01 c3 48 29 c6 48 85 f6 75 e1 41 ff e7 }
    
        condition:
            any of them
    }
    
    