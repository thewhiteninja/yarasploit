
    rule stager_reverse_tcp_nx___start0___x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::__start0__"
    
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
    
    
    rule stager_reverse_tcp_nx_api_call_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::api_call"
    
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
    
    
    rule stager_reverse_tcp_nx_next_mod_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::next_mod"
    
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
    
    
    rule stager_reverse_tcp_nx_loop_modname_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::loop_modname"
    
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
    
    
    rule stager_reverse_tcp_nx_not_lowercase_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::not_lowercase"
    
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
    
    
    rule stager_reverse_tcp_nx_get_next_func_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::get_next_func"
    
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
    
    
    rule stager_reverse_tcp_nx_loop_funcname_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::loop_funcname"
    
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
    
    
    rule stager_reverse_tcp_nx_finish_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::finish"
    
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
    
    
    rule stager_reverse_tcp_nx_get_next_mod1_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::get_next_mod1"
    
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
    
    
    rule stager_reverse_tcp_nx_reverse_tcp_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::reverse_tcp"
    
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
    
    
    rule stager_reverse_tcp_nx_recv_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::recv"
    
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
    
    
    rule stager_reverse_tcp_nx_read_more_x64
    {
        meta:
            desc = "Metasploit::windows::x64::stager_reverse_tcp_nx::read_more"
    
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
    
    