
    rule single_reverse_tcp_shell_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_tcp_shell::socket"
    
        /*
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            6A02                 | j.                   | push byte 0x2
            89E1                 | ..                   | mov ecx, esp
            B066                 | .f                   | mov al, 0x66
            CD80                 | ..                   | int 0x80
            93                   | .                    | xchg eax, ebx
        */
    
        strings:
            $a   = { 53 43 53 6a 02 89 e1 b0 66 cd 80 93 }
    
        condition:
            any of them
    }
    
    
    rule single_reverse_tcp_shell_dup_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_tcp_shell::dup_loop"
    
        /*
            B03F                 | .?                   | mov al, 0x3f
            CD80                 | ..                   | int 0x80
            49                   | I                    | dec ecx
            79F9                 | y.                   | jns dup_loop
        */
    
        strings:
            $a   = { b0 3f cd 80 49 79 f9 }
    
        condition:
            any of them
    }
    
    
    rule single_reverse_tcp_shell_connect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_tcp_shell::connect"
    
        /*
            68????????           | h....                | push dword 0x0100007f	; Host
            680200BFBF           | h....                | push 0xbfbf0002
            89E1                 | ..                   | mov ecx, esp
            B066                 | .f                   | mov al, 0x66
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            53                   | S                    | push ebx
            B303                 | ..                   | mov bl, 0x3
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 68 ?? ?? ?? ?? 68 02 00 bf bf 89 e1 b0 66 50 51 53 b3 03 89 e1 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule single_reverse_tcp_shell_execve_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_tcp_shell::execve"
    
        /*
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
            $a   = { 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 53 89 e1 b0 0b cd 80 }
    
        condition:
            any of them
    }
    
    