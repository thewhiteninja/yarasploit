
    rule stager_sock_bind_icmp_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind_icmp::socket"
    
        /*
            6A01                 | j.                   | push byte 0x1
            5B                   | [                    | pop ebx
            53                   | S                    | push ebx
            6A03                 | j.                   | push byte 0x3
            6A02                 | j.                   | push byte 0x2
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            99                   | .                    | cdq
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
            93                   | .                    | xchg eax, ebx
        */
    
        strings:
            $a   = { 6a 01 5b 53 6a 03 6a 02 6a 66 58 99 89 e1 cd 80 93 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_bind_icmp_read_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind_icmp::read"
    
        /*
            B003                 | ..                   | mov al, 0x3
            B60C                 | ..                   | mov dh, 0xc
            CD80                 | ..                   | int 0x80
            6A1C                 | j.                   | push byte 0x1c
            5A                   | Z                    | pop edx
            01D1                 | ..                   | add ecx, edx
            FFE1                 | ..                   | jmp ecx
        */
    
        strings:
            $a   = { b0 03 b6 0c cd 80 6a 1c 5a 01 d1 ff e1 }
    
        condition:
            any of them
    }
    
    