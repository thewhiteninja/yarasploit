
    rule stager_sock_reverse_udp_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp::socket"
    
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
            97                   | .                    | xchg eax, edi
        */
    
        strings:
            $a   = { 53 6a 02 6a 02 43 6a 66 58 99 89 e1 cd 80 97 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_udp_connect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp::connect"
    
        /*
            5B                   | [                    | pop ebx
            68????????           | h....                | push dword 0x0100007f	; Host
            6668BFBF             | fh..                 | push word 0xbfbf
            6653                 | fS                   | push word bx
            89E1                 | ..                   | mov ecx, esp
            6A10                 | j.                   | push byte 0x10
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            89E1                 | ..                   | mov ecx, esp
            B066                 | .f                   | mov al, 0x66
            43                   | C                    | inc ebx
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 5b 68 ?? ?? ?? ?? 66 68 bf bf 66 53 89 e1 6a 10 51 57 89 e1 b0 66 43 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_udp_write_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp::write"
    
        /*
            5B                   | [                    | pop ebx
            686D736621           | hmsf!                | push dword 0x2166736d
            89E1                 | ..                   | mov ecx, esp
            B204                 | ..                   | mov dl, 0x4
            B004                 | ..                   | mov al, 0x4
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 5b 68 6d 73 66 21 89 e1 b2 04 b0 04 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_udp_recv_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp::recv"
    
        /*
            B60C                 | ..                   | mov dh, 0xc
            B003                 | ..                   | mov al, 0x3
            CD80                 | ..                   | int 0x80
            FFE1                 | ..                   | jmp ecx
        */
    
        strings:
            $a   = { b6 0c b0 03 cd 80 ff e1 }
    
        condition:
            any of them
    }
    
    