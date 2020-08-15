
    rule block_shell_shell_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_shell::shell"
    
        /*
            41B8636D6400         | A.cmd.               | mov r8, 'cmd'
            4150                 | AP                   | push r8
            4150                 | AP                   | push r8
            4889E2               | H..                  | mov rdx, rsp
            57                   | W                    | push rdi
            57                   | W                    | push rdi
            57                   | W                    | push rdi
            4D31C0               | M1.                  | xor r8, r8
            6A0D                 | j.                   | push byte 13
            59                   | Y                    | pop rcx
        */
    
        strings:
            $a   = { 41 b8 63 6d 64 00 41 50 41 50 48 89 e2 57 57 57 4d 31 c0 6a 0d 59 }
    
        condition:
            any of them
    }
    
    
    rule block_shell_push_loop_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_shell::push_loop"
    
        /*
            4150                 | AP                   | push r8
            E2FC                 | ..                   | loop push_loop
            66C74424540101       | f.D$T..              | mov word [rsp+84], 0x0101
            488D442418           | H.D$.                | lea rax, [rsp+24]
            C60068               | ..h                  | mov byte [rax], 104
            4889E6               | H..                  | mov rsi, rsp
            56                   | V                    | push rsi
            50                   | P                    | push rax
            4150                 | AP                   | push r8
            4150                 | AP                   | push r8
            4150                 | AP                   | push r8
            49FFC0               | I..                  | inc r8
            4150                 | AP                   | push r8
            49FFC8               | I..                  | dec r8
            4D89C1               | M..                  | mov r9, r8
            4C89C1               | L..                  | mov rcx, r8
            41BA79CC3F86         | A.y.?.               | mov r10d, 0x863fcc79
            FFD5                 | ..                   | call rbp
            4831D2               | H1.                  | xor rdx, rdx
            48FFCA               | H..                  | dec rdx
            8B0E                 | ..                   | mov ecx, dword [rsi]
            41BA08871D60         | A....`               | mov r10d, 0x601d8708
            FFD5                 | ..                   | call rbp
        */
    
        strings:
            $a   = { 41 50 e2 fc 66 c7 44 24 54 01 01 48 8d 44 24 18 c6 00 68 48 89 e6 56 50 41 50 41 50 41 50 49 ff c0 41 50 49 ff c8 4d 89 c1 4c 89 c1 41 ba 79 cc 3f 86 ff d5 48 31 d2 48 ff ca 8b 0e 41 ba 08 87 1d 60 ff d5 }
    
        condition:
            any of them
    }
    
    