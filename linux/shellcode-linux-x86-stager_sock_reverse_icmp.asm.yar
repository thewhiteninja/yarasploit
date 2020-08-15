
    rule stager_sock_reverse_icmp_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_icmp::socket"
    
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
    
    
    rule stager_sock_reverse_icmp_sendto_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_icmp::sendto"
    
        /*
            59                   | Y                    | pop ecx
            68????????           | h....                | push dword 0x0100007f	; Host
            51                   | Q                    | push ecx
            89E1                 | ..                   | mov ecx, esp
            52                   | R                    | push edx
            52                   | R                    | push edx
            666AF7               | fj.                  | push word 0xfff7
            666A08               | fj.                  | o16 push byte 0x8
            89E7                 | ..                   | mov edi, esp
            6A10                 | j.                   | push byte 0x10
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            6A09                 | j.                   | push byte 0x9
            57                   | W                    | push edi
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            6A0B                 | j.                   | push byte 0xb
            5B                   | [                    | pop ebx
            B066                 | .f                   | mov al, 0x66
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 59 68 ?? ?? ?? ?? 51 89 e1 52 52 66 6a f7 66 6a 08 89 e7 6a 10 51 52 6a 09 57 53 89 e1 6a 0b 5b b0 66 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_icmp_read_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse_icmp::read"
    
        /*
            5B                   | [                    | pop ebx
            B003                 | ..                   | mov al, 0x3
            B60C                 | ..                   | mov dh, 0xc
            CD80                 | ..                   | int 0x80
            6A1C                 | j.                   | push byte 0x1c
            5A                   | Z                    | pop edx
            01D1                 | ..                   | add ecx, edx
            FFE1                 | ..                   | jmp ecx
        */
    
        strings:
            $a   = { 5b b0 03 b6 0c cd 80 6a 1c 5a 01 d1 ff e1 }
    
        condition:
            any of them
    }
    
    