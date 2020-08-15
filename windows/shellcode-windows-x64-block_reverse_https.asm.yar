
    rule block_reverse_https_load_wininet_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::load_wininet"
    
        /*
            6A00                 | j.                   | push byte 0
            49BE77696E696E657400 | I.wininet.           | mov r14, 'wininet'
            4156                 | AV                   | push r14
            4989E6               | I..                  | mov r14, rsp
            4C89F1               | L..                  | mov rcx, r14
            41BA4C772607         | A.Lw&.               | mov r10, 0x0726774c
            FFD5                 | ..                   | call rbp
        */
    
        strings:
            $a   = { 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 4c 77 26 07 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_internetopen_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::internetopen"
    
        /*
            6A00                 | j.                   | push byte 0
            6A00                 | j.                   | push byte 0
            4889E1               | H..                  | mov rcx, rsp
            4831D2               | H1.                  | xor rdx, rdx
            4D31C0               | M1.                  | xor r8, r8
            4D31C9               | M1.                  | xor r9, r9
            4150                 | AP                   | push r8
            4150                 | AP                   | push r8
            41BA3A5679A7         | A.:Vy.               | mov r10, 0xa779563a
            FFD5                 | ..                   | call rbp
            E981000000           | .....                | jmp dbl_get_server_host
        */
    
        strings:
            $a   = { 6a 00 6a 00 48 89 e1 48 31 d2 4d 31 c0 4d 31 c9 41 50 41 50 41 ba 3a 56 79 a7 ff d5 e9 81 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_internetconnect_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::internetconnect"
    
        /*
            5A                   | Z                    | pop rdx
            4889C1               | H..                  | mov rcx, rax
            41B8????0000         | A.\...               | mov r8, 4444	; Port
            4D31C9               | M1.                  | xor r9, r9
            4151                 | AQ                   | push r9
            4151                 | AQ                   | push r9
            6A03                 | j.                   | push 3
            4151                 | AQ                   | push r9
            41BA57899FC6         | A.W...               | mov r10, 0xc69f8957
            FFD5                 | ..                   | call rbp
            EB64                 | .d                   | jmp get_server_uri
        */
    
        strings:
            $a   = { 5a 48 89 c1 41 B8 ?? ?? 00 00 4d 31 c9 41 51 41 51 6a 03 41 51 41 ba 57 89 9f c6 ff d5 eb 64 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_httpopenrequest_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::httpopenrequest"
    
        /*
            4889C1               | H..                  | mov rcx, rax
            4831D2               | H1.                  | xor rdx, rdx
            4158                 | AX                   | pop r8
            4D31C9               | M1.                  | xor r9, r9
            52                   | R                    | push rdx
            680032A084           | h.2..                | push qword (0x0000000080000000 | 0x0000000004000000 | 0x0000000000800000 | 0x0000000000200000 | 0x0000000000001000 |0x0000000000002000 |0x0000000000000200)
            52                   | R                    | push rdx
            52                   | R                    | push rdx
            41BAEB552E3B         | A..U.;               | mov r10, 0x3b2e55eb
            FFD5                 | ..                   | call rbp
            4889C6               | H..                  | mov rsi, rax
        */
    
        strings:
            $a   = { 48 89 c1 48 31 d2 41 58 4d 31 c9 52 68 00 32 a0 84 52 52 41 ba eb 55 2e 3b ff d5 48 89 c6 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_internetsetoption_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::internetsetoption"
    
        /*
            4889F1               | H..                  | mov rcx, rsi
            BA1F000000           | .....                | mov rdx, 31
            6A00                 | j.                   | push byte 0
            6880330000           | h.3..                | push qword 0x00003380
            4989E0               | I..                  | mov r8, rsp
            41B904000000         | A.....               | mov r9, 4
            41BA75469E86         | A.uF..               | mov r10, 0x869e4675
            FFD5                 | ..                   | call rbp
        */
    
        strings:
            $a   = { 48 89 f1 ba 1f 00 00 00 6a 00 68 80 33 00 00 49 89 e0 41 b9 04 00 00 00 41 ba 75 46 9e 86 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_httpsendrequest_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::httpsendrequest"
    
        /*
            4889F1               | H..                  | mov rcx, rsi
            4831D2               | H1.                  | xor rdx, rdx
            4D31C0               | M1.                  | xor r8, r8
            4D31C9               | M1.                  | xor r9, r9
            52                   | R                    | push rdx
            52                   | R                    | push rdx
            41BA2D06187B         | A.-..{               | mov r10, 0x7b18062d
            FFD5                 | ..                   | call rbp
            85C0                 | ..                   | test eax,eax
            751D                 | u.                   | jnz short allocate_memory
        */
    
        strings:
            $a   = { 48 89 f1 48 31 d2 4d 31 c0 4d 31 c9 52 52 41 ba 2d 06 18 7b ff d5 85 c0 75 1d }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_try_it_again_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::try_it_again"
    
        /*
            48FFCF               | H..                  | dec rdi
            7410                 | t.                   | jz failure
            EBBF                 | ..                   | jmp short internetsetoption
        */
    
        strings:
            $a   = { 48 ff cf 74 10 eb bf }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_failure_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::failure"
    
        /*
            41BEF0B5A256         | A....V               | mov r14, 0x56a2b5f0
            FFD5                 | ..                   | call rbp
        */
    
        strings:
            $a   = { 41 be f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_allocate_memory_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::allocate_memory"
    
        /*
            4831C9               | H1.                  | xor rcx, rcx
            BA00004000           | ...@.                | mov rdx, 0x00400000
            41B800100000         | A.....               | mov r8, 0x1000
            41B940000000         | A.@...               | mov r9, 0x40
            41BA58A453E5         | A.X.S.               | mov r10, 0xe553a458
            FFD5                 | ..                   | call rbp
        */
    
        strings:
            $a   = { 48 31 c9 ba 00 00 40 00 41 b8 00 10 00 00 41 b9 40 00 00 00 41 ba 58 a4 53 e5 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_download_prep_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::download_prep"
    
        /*
            4893                 | H.                   | xchg rax, rbx
            53                   | S                    | push rbx
            53                   | S                    | push rbx
            4889E7               | H..                  | mov rdi, rsp
        */
    
        strings:
            $a   = { 48 93 53 53 48 89 e7 }
    
        condition:
            any of them
    }
    
    
    rule block_reverse_https_download_more_x64
    {
        meta:
            desc = "Metasploit::windows::x64::block_reverse_https::download_more"
    
        /*
            4889F1               | H..                  | mov rcx, rsi
            4889DA               | H..                  | mov rdx, rbx
            41B800200000         | A.. ..               | mov r8, 8192
            4989F9               | I..                  | mov r9, rdi
            41BA129689E2         | A.....               | mov r10, 0xe2899612
            FFD5                 | ..                   | call rbp
            4883C420             | H..                  | add rsp, 32
            85C0                 | ..                   | test eax,eax
            74B6                 | t.                   | jz failure
            66678B07             | fg..                 | mov ax, word [edi]
            4801C3               | H..                  | add rbx, rax
            4885C0               | H..                  | test rax,rax
            75D5                 | u.                   | jnz download_more
            58                   | X                    | pop rax
            58                   | X                    | pop rax
        */
    
        strings:
            $a   = { 48 89 f1 48 89 da 41 b8 00 20 00 00 49 89 f9 41 ba 12 96 89 e2 ff d5 48 83 c4 20 85 c0 74 b6 66 67 8b 07 48 01 c3 48 85 c0 75 d5 58 58 }
    
        condition:
            any of them
    }
    
    