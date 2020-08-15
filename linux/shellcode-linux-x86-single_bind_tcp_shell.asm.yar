
    rule single_bind_tcp_shell_mprotect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_bind_tcp_shell::mprotect"
    
        /*
            6A7D                 | j}                   | push byte 0x7d
            58                   | X                    | pop eax
            99                   | .                    | cdq
            B207                 | ..                   | mov dl, 0x7
            B900100000           | .....                | mov ecx, 0x1000
            89E3                 | ..                   | mov ebx, esp
            6681E300F0           | f....                | and bx, 0xf000
            CD80                 | ..                   | int 0x80
            31DB                 | 1.                   | xor ebx, ebx
            F7E3                 | ..                   | mul ebx
        */
    
        strings:
            $a   = { 6a 7d 58 99 b2 07 b9 00 10 00 00 89 e3 66 81 e3 00 f0 cd 80 31 db f7 e3 }
    
        condition:
            any of them
    }
    
    
    rule single_bind_tcp_shell_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_bind_tcp_shell::socket"
    
        /*
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            6A02                 | j.                   | push byte 0x2
            89E1                 | ..                   | mov ecx, esp
            B066                 | .f                   | mov al, 0x66
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 53 43 53 6a 02 89 e1 b0 66 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule single_bind_tcp_shell_bind_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_bind_tcp_shell::bind"
    
        /*
            5B                   | [                    | pop ebx
            5E                   | ^                    | pop esi
            52                   | R                    | push edx
            680200BFBF           | h....                | push 0xbfbf0002
            6A10                 | j.                   | push byte 0x10
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            89E1                 | ..                   | mov ecx, esp
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 5b 5e 52 68 02 00 bf bf 6a 10 51 50 89 e1 6a 66 58 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule single_bind_tcp_shell_listen_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_bind_tcp_shell::listen"
    
        /*
            D1E3                 | ..                   | shl ebx, 1
            B066                 | .f                   | mov al, 0x66
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { d1 e3 b0 66 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule single_bind_tcp_shell_accept_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_bind_tcp_shell::accept"
    
        /*
            43                   | C                    | inc ebx
            B066                 | .f                   | mov al, 0x66
            895104               | .Q.                  | mov [ecx+4], edx
            CD80                 | ..                   | int 0x80
            93                   | .                    | xchg eax, ebx
        */
    
        strings:
            $a   = { 43 b0 66 89 51 04 cd 80 93 }
    
        condition:
            any of them
    }
    
    
    rule single_bind_tcp_shell_dup_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_bind_tcp_shell::dup_loop"
    
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
    
    
    rule single_bind_tcp_shell_execve_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_bind_tcp_shell::execve"
    
        /*
            B00B                 | ..                   | mov al, 0xb
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
            $a   = { b0 0b 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 53 89 e1 cd 80 }
    
        condition:
            any of them
    }
    
    