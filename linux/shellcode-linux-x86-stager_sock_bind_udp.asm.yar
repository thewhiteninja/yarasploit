
    rule stager_sock_bind_udp_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind_udp::socket"
    
        /*
            53                   | S                    | push ebx
            6A02                 | j.                   | push byte 0x2
            6A02                 | j.                   | push byte 0x2
            43                   | C                    | inc ebx
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            99                   | .                    | cdq
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
            96                   | .                    | xchg eax, esi
        */
    
        strings:
            $a   = { 53 6a 02 6a 02 43 6a 66 58 99 89 e1 cd 80 96 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_bind_udp_bind_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind_udp::bind"
    
        /*
            5B                   | [                    | pop ebx
            52                   | R                    | push edx
            6668BFBF             | fh..                 | push word 0xbfbf
            6653                 | fS                   | push bx
            89E1                 | ..                   | mov ecx, esp
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            56                   | V                    | push esi
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 5b 52 66 68 bf bf 66 53 89 e1 6a 66 58 50 51 56 89 e1 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_bind_udp_recv_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind_udp::recv"
    
        /*
            5B                   | [                    | pop ebx
            B60C                 | ..                   | mov dh, 0xc
            B003                 | ..                   | mov al, 0x3
            CD80                 | ..                   | int 0x80
            89DF                 | ..                   | mov edi, ebx
            FFE1                 | ..                   | jmp ecx
        */
    
        strings:
            $a   = { 5b b6 0c b0 03 cd 80 89 df ff e1 }
    
        condition:
            any of them
    }
    
    