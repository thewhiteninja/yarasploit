
    rule single_shell_bind_tcp_random_port__start_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_shell_bind_tcp_random_port::_start"
    
        /*
            31DB                 | 1.                   | xor ebx, ebx
            F7E3                 | ..                   | mul ebx
            B066                 | .f                   | mov al, 102
            43                   | C                    | inc ebx
            52                   | R                    | push edx
            53                   | S                    | push ebx
            6A02                 | j.                   | push 2
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
            52                   | R                    | push edx
            50                   | P                    | push eax
            89E1                 | ..                   | mov ecx, esp
            B066                 | .f                   | mov al, 102
            B304                 | ..                   | mov bl, 4
            CD80                 | ..                   | int 0x80
            B066                 | .f                   | mov al, 102
            43                   | C                    | inc ebx
            CD80                 | ..                   | int 0x80
            59                   | Y                    | pop ecx
            93                   | .                    | xchg ebx, eax
        */
    
        strings:
            $a   = { 31 db f7 e3 b0 66 43 52 53 6a 02 89 e1 cd 80 52 50 89 e1 b0 66 b3 04 cd 80 b0 66 43 cd 80 59 93 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_bind_tcp_random_port_dup_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_shell_bind_tcp_random_port::dup_loop"
    
        /*
            6A3F                 | j?                   | push 63
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            49                   | I                    | dec ecx
            79F8                 | y.                   | jns dup_loop
            B00B                 | ..                   | mov al, 11
            682F2F7368           | h//sh                | push 0x68732f2f
            682F62696E           | h/bin                | push 0x6e69622f
            89E3                 | ..                   | mov ebx, esp
            41                   | A                    | inc ecx
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 6a 3f 58 cd 80 49 79 f8 b0 0b 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 41 cd 80 }
    
        condition:
            any of them
    }
    
    