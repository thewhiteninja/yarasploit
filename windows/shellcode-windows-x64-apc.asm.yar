
    rule apc___start0___x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::__start0__"
    
        /*
            FC                   | .                    | cld
            80791000             | .y..                 | cmp byte [rcx+16], 0
            0F8513010000         | ......               | jne cleanup
            C6411001             | .A..                 | mov byte [rcx+16], 1
            4883EC78             | H..x                 | sub rsp, 120
            E8C8000000           | .....                | call start
        */
    
        strings:
            $a   = { fc 80 79 10 00 0f 85 13 01 00 00 c6 41 10 01 48 83 ec 78 e8 c8 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule apc_api_call_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::api_call"
    
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
    
    
    rule apc_next_mod_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::next_mod"
    
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
    
    
    rule apc_loop_modname_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::loop_modname"
    
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
    
    
    rule apc_not_lowercase_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::not_lowercase"
    
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
    
    
    rule apc_get_next_func_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::get_next_func"
    
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
    
    
    rule apc_loop_funcname_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::loop_funcname"
    
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
    
    
    rule apc_finish_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::finish"
    
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
    
    
    rule apc_get_next_mod1_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::get_next_mod1"
    
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
    
    
    rule apc_start_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::start"
    
        /*
            5D                   | ]                    | pop rbp
            4831D2               | H1.                  | xor rdx, rdx
            65488B4230           | eH.B0                | mov rax, [gs:rdx+48]
            483990C8020000       | H9.....              | cmp qword [rax+712], rdx
            750E                 | u.                   | jne continue
            488D9507010000       | H......              | lea rdx, [rbp+context-delta]
            488990C8020000       | H......              | mov qword [rax+712], rdx
        */
    
        strings:
            $a   = { 5d 48 31 d2 65 48 8b 42 30 48 39 90 c8 02 00 00 75 0e 48 8d 95 07 01 00 00 48 89 90 c8 02 00 00 }
    
        condition:
            any of them
    }
    
    
    rule apc_continue_x64
    {
        meta:
            desc = "Metasploit::windows::x64::apc::continue"
    
        /*
            4C8B01               | L..                  | mov r8, [rcx]
            4C8B4908             | L.I.                 | mov r9, [rcx+8]
            4831C9               | H1.                  | xor rcx, rcx
            4831D2               | H1.                  | xor rdx, rdx
            51                   | Q                    | push rcx
            51                   | Q                    | push rcx
            41BA38680D16         | A.8h..               | mov r10d, 0x160d6838
            FFD5                 | ..                   | call rbp
            4881C4A8000000       | H......              | add rsp, (120 + 32 + (8*2))
        */
    
        strings:
            $a   = { 4c 8b 01 4c 8b 49 08 48 31 c9 48 31 d2 51 51 41 ba 38 68 0d 16 ff d5 48 81 c4 a8 00 00 00 }
    
        condition:
            any of them
    }
    
    