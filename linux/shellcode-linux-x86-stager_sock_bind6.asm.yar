
    rule stager_sock_bind6_mprotect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind6::mprotect"
    
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
    
    
    rule stager_sock_bind6_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind6::socket"
    
        /*
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            6A0A                 | j.                   | push byte 0xa
            89E1                 | ..                   | mov ecx, esp
            B066                 | .f                   | mov al, 0x66
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 53 43 53 6a 0a 89 e1 b0 66 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_bind6_bind_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind6::bind"
    
        /*
            43                   | C                    | inc ebx
            52                   | R                    | push edx
            52                   | R                    | push edx
            52                   | R                    | push edx
            52                   | R                    | push edx
            52                   | R                    | push edx
            52                   | R                    | push edx
            680A00BFBF           | h....                | push 0xbfbf000a
            89E1                 | ..                   | mov ecx, esp
            6A1C                 | j.                   | push byte 0x1c
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            89E1                 | ..                   | mov ecx, esp
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 43 52 52 52 52 52 52 68 0a 00 bf bf 89 e1 6a 1c 51 50 89 e1 6a 66 58 cd 80 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_bind6_listen_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind6::listen"
    
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
    
    
    rule stager_sock_bind6_accept_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind6::accept"
    
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
    
    
    rule stager_sock_bind6_recv_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_bind6::recv"
    
        /*
            B60C                 | ..                   | mov dh, 0xc
            B003                 | ..                   | mov al, 0x3
            CD80                 | ..                   | int 0x80
            89DF                 | ..                   | mov edi, ebx
            FFE1                 | ..                   | jmp ecx
        */
    
        strings:
            $a   = { b6 0c b0 03 cd 80 89 df ff e1 }
    
        condition:
            any of them
    }
    
    