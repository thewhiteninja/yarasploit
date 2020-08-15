
    rule single_find_tcp_shell_initialize_stack_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_find_tcp_shell::initialize_stack"
    
        /*
            53                   | S                    | push ebx
            89E6                 | ..                   | mov esi, esp
            6A40                 | j@                   | push byte 0x40
            B70A                 | ..                   | mov bh, 0xa
            53                   | S                    | push ebx
            56                   | V                    | push esi
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            86FB                 | ..                   | xchg bh, bl
        */
    
        strings:
            $a   = { 53 89 e6 6a 40 b7 0a 53 56 53 89 e1 86 fb }
    
        condition:
            any of them
    }
    
    
    rule single_find_tcp_shell_findtag_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_find_tcp_shell::findtag"
    
        /*
            66FF01               | f..                  | inc word [ecx]
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            813E6D736621         | .>msf!               | cmp dword [esi], 0x2166736d
            75F0                 | u.                   | jnz findtag
            5F                   | _                    | pop edi
        */
    
        strings:
            $a   = { 66 ff 01 6a 66 58 cd 80 81 3e 6d 73 66 21 75 f0 5f }
    
        condition:
            any of them
    }
    
    
    rule single_find_tcp_shell_dup_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_find_tcp_shell::dup"
    
        /*
            89FB                 | ..                   | mov ebx, edi
            6A02                 | j.                   | push byte 0x2
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { 89 fb 6a 02 59 }
    
        condition:
            any of them
    }
    
    
    rule single_find_tcp_shell_dup_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_find_tcp_shell::dup_loop"
    
        /*
            6A3F                 | j?                   | push byte 0x3f
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            49                   | I                    | dec ecx
            79F8                 | y.                   | jns dup_loop
        */
    
        strings:
            $a   = { 6a 3f 58 cd 80 49 79 f8 }
    
        condition:
            any of them
    }
    
    
    rule single_find_tcp_shell_execve_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_find_tcp_shell::execve"
    
        /*
            6A0B                 | j.                   | push byte 0xb
            58                   | X                    | pop eax
            99                   | .                    | cdq
            52                   | R                    | push edx
            682F2F7368           | h//sh                | push dword 0x68732f2f
            682F62696E           | h/bin                | push dword 0x6e69622f
            89E3                 | ..                   | mov ebx, esp
            52                   | R                    | push edx
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 6a 0b 58 99 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 53 89 e1 cd 80 }
    
        condition:
            any of them
    }
    
    