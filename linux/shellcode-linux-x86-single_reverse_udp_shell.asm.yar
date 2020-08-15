
    rule single_reverse_udp_shell_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_udp_shell::socket"
    
        /*
            53                   | S                    | push ebx
            6A02                 | j.                   | push byte 0x2
            6A02                 | j.                   | push byte 0x2
            43                   | C                    | inc ebx
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
            93                   | .                    | xchg eax, ebx
        */
    
        strings:
            $a   = { 53 6a 02 6a 02 43 6a 66 58 89 e1 cd 80 93 }
    
        condition:
            any of them
    }
    
    
    rule single_reverse_udp_shell_dup_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_udp_shell::dup_loop"
    
        /*
            B03F                 | .?                   | mov al, 0x3f
            CD80                 | ..                   | int 0x80
            49                   | I                    | dec ecx,
            79F9                 | y.                   | jns dup_loop
        */
    
        strings:
            $a   = { b0 3f cd 80 49 79 f9 }
    
        condition:
            any of them
    }
    
    
    rule single_reverse_udp_shell_connect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_udp_shell::connect"
    
        /*
            5B                   | [                    | pop ebx
            5A                   | Z                    | pop edx
            68????????           | h....                | push dword 0x0100007f	; Host
            6668BFBF             | fh..                 | push word 0xbfbf
            6653                 | fS                   | push word bx
            89E1                 | ..                   | mov ecx, esp
            6A10                 | j.                   | push byte 0x10
            51                   | Q                    | push ecx
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            43                   | C                    | inc ebx
            B066                 | .f                   | mov al, 0x66
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 5b 5a 68 ?? ?? ?? ?? 66 68 bf bf 66 53 89 e1 6a 10 51 53 89 e1 43 b0 66 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule single_reverse_udp_shell_execve_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_reverse_udp_shell::execve"
    
        /*
            6A0B                 | j.                   | push byte 0xb
            58                   | X                    | pop eax
            52                   | R                    | push edx
            66682D69             | fh-i                 | push word 0x692d
            89E1                 | ..                   | mov ecx, esp
            6A67                 | jg                   | push byte 0x67
            6668696E             | fhin                 | push word 0x6e69
            6865646974           | hedit                | push dword 0x74696465
            682D2D6E6F           | h--no                | push dword 0x6f6e2d2d
            89E7                 | ..                   | mov edi, esp
            52                   | R                    | push edx
            682F2F7368           | h//sh                | push dword 0x68732f2f
            682F62696E           | h/bin                | push dword 0x6e69622f
            89E3                 | ..                   | mov ebx, esp
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 6a 0b 58 52 66 68 2d 69 89 e1 6a 67 66 68 69 6e 68 65 64 69 74 68 2d 2d 6e 6f 89 e7 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 51 57 53 89 e1 cd 80 }
    
        condition:
            any of them
    }
    
    