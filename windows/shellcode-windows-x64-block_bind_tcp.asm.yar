
    rule block_bind_tcp_bind_tcp_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_bind_tcp::bind_tcp"
    
        /*
            49BE7773325F33320000 | I.ws2_32..           | mov r14, 'ws2_32'
            4156                 | AV                   | push r14
            4989E6               | I..                  | mov r14, rsp
            4881ECA0010000       | H......              | sub rsp, 408+8
            4989E5               | I..                  | mov r13, rsp
            41BC0200115C         | A....\               | mov r12, 0x000000005c110002
            4154                 | AT                   | push r12
            4989E4               | I..                  | mov r12, rsp
            4C89F1               | L..                  | mov rcx, r14
            41BA4C772607         | A.Lw&.               | mov r10d, 0x0726774c
            FFD5                 | ..                   | call rbp
            4C89EA               | L..                  | mov rdx, r13
            6801010000           | h....                | push 0x0101
            59                   | Y                    | pop rcx
            41BA29806B00         | A.).k.               | mov r10d, 0x006b8029
            FFD5                 | ..                   | call rbp
            50                   | P                    | push rax
            50                   | P                    | push rax
            4D31C9               | M1.                  | xor r9, r9
            4D31C0               | M1.                  | xor r8, r8
            48FFC0               | H..                  | inc rax
            4889C2               | H..                  | mov rdx, rax
            48FFC0               | H..                  | inc rax
            4889C1               | H..                  | mov rcx, rax
            41BAEA0FDFE0         | A.....               | mov r10d, 0xe0df0fea
            FFD5                 | ..                   | call rbp
            4889C7               | H..                  | mov rdi, rax
            6A10                 | j.                   | push byte 16
            4158                 | AX                   | pop r8
            4C89E2               | L..                  | mov rdx, r12
            4889F9               | H..                  | mov rcx, rdi
            41BAC2DB3767         | A...7g               | mov r10d, 0x6737dbc2
            FFD5                 | ..                   | call rbp
            4831D2               | H1.                  | xor rdx, rdx
            4889F9               | H..                  | mov rcx, rdi
            41BAB7E938FF         | A...8.               | mov r10d, 0xff38e9b7
            FFD5                 | ..                   | call rbp
            4D31C0               | M1.                  | xor r8, r8
            4831D2               | H1.                  | xor rdx, rdx
            4889F9               | H..                  | mov rcx, rdi
            41BA74EC3BE1         | A.t.;.               | mov r10d, 0xe13bec74
            FFD5                 | ..                   | call rbp
            4889F9               | H..                  | mov rcx, rdi
            4889C7               | H..                  | mov rdi, rax
            41BA756E4D61         | A.unMa               | mov r10d, 0x614d6e75
            FFD5                 | ..                   | call rbp
            4881C4A0020000       | H......              | add rsp, ( (408+8) + (8*4) + (32*7) )
        */
    
        strings:
            $a   = { 49 be 77 73 32 5f 33 32 00 00 41 56 49 89 e6 48 81 ec a0 01 00 00 49 89 e5 41 bc 02 00 11 5c 41 54 49 89 e4 4c 89 f1 41 ba 4c 77 26 07 ff d5 4c 89 ea 68 01 01 00 00 59 41 ba 29 80 6b 00 ff d5 50 50 4d 31 c9 4d 31 c0 48 ff c0 48 89 c2 48 ff c0 48 89 c1 41 ba ea 0f df e0 ff d5 48 89 c7 6a 10 41 58 4c 89 e2 48 89 f9 41 ba c2 db 37 67 ff d5 48 31 d2 48 89 f9 41 ba b7 e9 38 ff ff d5 4d 31 c0 48 31 d2 48 89 f9 41 ba 74 ec 3b e1 ff d5 48 89 f9 48 89 c7 41 ba 75 6e 4d 61 ff d5 48 81 c4 a0 02 00 00 }
    
        condition:
            any of them
    }
    
    