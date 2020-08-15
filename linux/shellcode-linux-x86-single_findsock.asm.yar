
    rule single_findsock_main_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_findsock::main"
    
        /*
            31D2                 | 1.                   | xor edx, edx
            52                   | R                    | push edx
            89E5                 | ..                   | mov ebp, esp
            6A07                 | j.                   | push byte 0x07
            5B                   | [                    | pop ebx
            6A10                 | j.                   | push byte 0x10
            54                   | T                    | push esp
            55                   | U                    | push ebp
            52                   | R                    | push edx
            89E1                 | ..                   | mov ecx, esp
        */
    
        strings:
            $a   = { 31 d2 52 89 e5 6a 07 5b 6a 10 54 55 52 89 e1 }
    
        condition:
            any of them
    }
    
    
    rule single_findsock_getpeername_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_findsock::getpeername_loop"
    
        /*
            FF01                 | ..                   | inc dword [ecx]
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            66817D02115C         | f.}..\               | cmp word [ebp + 2], 0x5c11
            75F1                 | u.                   | jne getpeername_loop
            5B                   | [                    | pop ebx
            6A02                 | j.                   | push byte 0x02
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { ff 01 6a 66 58 cd 80 66 81 7d 02 11 5c 75 f1 5b 6a 02 59 }
    
        condition:
            any of them
    }
    
    
    rule single_findsock_dup2_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_findsock::dup2_loop"
    
        /*
            B03F                 | .?                   | mov al, 0x3f
            CD80                 | ..                   | int 0x80
            49                   | I                    | dec ecx
            79F9                 | y.                   | jns dup2_loop
            52                   | R                    | push edx
            682F2F7368           | h//sh                | push dword 0x68732f2f
            682F62696E           | h/bin                | push dword 0x6e69622f
            89E3                 | ..                   | mov ebx, esp
            52                   | R                    | push edx
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            B00B                 | ..                   | mov al, 0x0b
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { b0 3f cd 80 49 79 f9 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 53 89 e1 b0 0b cd 80 }
    
        condition:
            any of them
    }
    
    