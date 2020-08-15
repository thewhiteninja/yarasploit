
    rule stager_sock_reverse_create_socket_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse::create_socket"
    
        /*
            31DB                 | 1.                   | xor ebx, ebx
            F7E3                 | ..                   | mul ebx
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            6A02                 | j.                   | push byte 0x2
            B066                 | .f                   | mov al, 0x66
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
            97                   | .                    | xchg eax, edi
        */
    
        strings:
            $a   = { 31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_set_address_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse::set_address"
    
        /*
            5B                   | [                    | pop ebx
            68????????           | h....                | push dword 0x0100007f	; Host
            680200BFBF           | h....                | push 0xbfbf0002
            89E1                 | ..                   | mov ecx, esp
        */
    
        strings:
            $a   = { 5b 68 ?? ?? ?? ?? 68 02 00 bf bf 89 e1 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_try_connect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse::try_connect"
    
        /*
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            89E1                 | ..                   | mov ecx, esp
            43                   | C                    | inc ebx
            CD80                 | ..                   | int 0x80
            85C0                 | ..                   | test eax, eax
            7919                 | y.                   | jns mprotect
        */
    
        strings:
            $a   = { 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_handle_failure_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse::handle_failure"
    
        /*
            68A2000000           | h....                | push 0xa2
            58                   | X                    | pop eax
            6A00                 | j.                   | push 0x0
            6A05                 | j.                   | push 0x5
            89E3                 | ..                   | mov ebx, esp
            31C9                 | 1.                   | xor ecx, ecx
            CD80                 | ..                   | int 0x80
            85C0                 | ..                   | test eax, eax
            782C                 | x,                   | js failed
            4E                   | N                    | dec esi
            75BD                 | u.                   | jnz create_socket
            EB27                 | .'                   | jmp failed
        */
    
        strings:
            $a   = { 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 78 2c 4e 75 bd eb 27 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_mprotect_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse::mprotect"
    
        /*
            B207                 | ..                   | mov dl, 0x7
            B900100000           | .....                | mov ecx, 0x1000
            89E3                 | ..                   | mov ebx, esp
            C1EB0C               | ...                  | shr ebx, 12
            C1E30C               | ...                  | shl ebx, 12
            B07D                 | .}                   | mov al, 0x7d
            CD80                 | ..                   | int 0x80
            85C0                 | ..                   | test eax, eax
            7810                 | x.                   | js failed
        */
    
        strings:
            $a   = { b2 07 b9 00 10 00 00 89 e3 c1 eb 0c c1 e3 0c b0 7d cd 80 85 c0 78 10 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_recv_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse::recv"
    
        /*
            5B                   | [                    | pop ebx
            89E1                 | ..                   | mov ecx, esp
            99                   | .                    | cdq
            B60C                 | ..                   | mov dh, 0xc
            B003                 | ..                   | mov al, 0x3
            CD80                 | ..                   | int 0x80
            85C0                 | ..                   | test eax, eax
            7802                 | x.                   | js failed
            FFE1                 | ..                   | jmp ecx
        */
    
        strings:
            $a   = { 5b 89 e1 99 b6 0c b0 03 cd 80 85 c0 78 02 ff e1 }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_reverse_failed_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_reverse::failed"
    
        /*
            B801000000           | .....                | mov eax, 0x1
            BB01000000           | .....                | mov ebx, 0x1
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { b8 01 00 00 00 bb 01 00 00 00 cd 80 }
    
        condition:
            any of them
    }
    
    