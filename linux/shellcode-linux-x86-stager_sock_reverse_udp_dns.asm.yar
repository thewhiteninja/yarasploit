
    rule stager_sock_reverse_udp_dns_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp_dns::socket"
    
        /*
            53                   | S                    | push ebx
            6A02                 | j.                   | push byte 0x2
            6A02                 | j.                   | push byte 0x2
            43                   | C                    | inc ebx
            B066                 | .f                   | mov al, 0x66
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
            97                   | .                    | xchg eax, edi
        */
    
        strings:
            $a   = { 53 6a 02 6a 02 43 b0 66 89 e1 cd 80 97 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_udp_dns_connect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp_dns::connect"
    
        /*
            5B                   | [                    | pop ebx
            68????????           | h....                | push dword 0x0100007f	; Host
            B635                 | .5                   | mov dh, 0x35
            6652                 | fR                   | push dx
            6653                 | fS                   | push bx
            89E1                 | ..                   | mov ecx, esp
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            89E1                 | ..                   | mov ecx, esp
            43                   | C                    | inc ebx
            CD80                 | ..                   | int 0x80
            99                   | .                    | cdq
        */
    
        strings:
            $a   = { 5b 68 ?? ?? ?? ?? b6 35 66 52 66 53 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 99 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_udp_dns_write_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp_dns::write"
    
        /*
            5B                   | [                    | pop ebx
            42                   | B                    | inc edx
            6652                 | fR                   | push dx
            6652                 | fR                   | push dx
            4A                   | J                    | dec edx
            6652                 | fR                   | push dx
            6803636F6D           | h.com                | push dword 0x6d6f6303
            B103                 | ..                   | mov cl, 0x3
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            FEC6                 | ..                   | inc dh
            52                   | R                    | push edx
            B604                 | ..                   | mov dh, 0x4
            6652                 | fR                   | push dx
            86C6                 | ..                   | xchg al, dh
            6656                 | fV                   | push si
            89E1                 | ..                   | mov ecx, esp
            B219                 | ..                   | mov dl, 0x19
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 5b 42 66 52 66 52 4a 66 52 68 03 63 6f 6d b1 03 51 52 fe c6 52 b6 04 66 52 86 c6 66 56 89 e1 b2 19 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_udp_dns_read_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_udp_dns::read"
    
        /*
            B60C                 | ..                   | mov dh, 0xc
            B003                 | ..                   | mov al, 0x3
            CD80                 | ..                   | int 0x80
            83C10D               | ...                  | add ecx, byte 0xd
            FFE1                 | ..                   | jmp ecx
        */
    
        strings:
            $a   = { b6 0c b0 03 cd 80 83 c1 0d ff e1 }
    
        condition:
            any of them
    }
    
    