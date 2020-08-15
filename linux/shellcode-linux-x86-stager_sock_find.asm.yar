
    rule stager_sock_find_initialize_stack_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_find::initialize_stack"
    
        /*
            53                   | S                    | push ebx
            89E6                 | ..                   | mov esi, esp
            6A40                 | j@                   | push byte 0x40
            B70A                 | ..                   | mov bh, 0xa
            53                   | S                    | push ebx
            56                   | V                    | push esi
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            86FB                 | ..                   | xchg bh, bl
        */
    
        strings:
            $a   = { 53 89 e6 6a 40 b7 0a 53 56 53 89 e1 86 fb }
    
        condition:
            any of them
    }
    
    
    rule stager_sock_find_findtag_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_sock_find::findtag"
    
        /*
            66FF01               | f..                  | inc word [ecx]
            6A66                 | jf                   | push byte 0x66
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            813E6D736621         | .>msf!               | cmp dword [esi], 0x2166736d
            75F0                 | u.                   | jnz findtag
            5F                   | _                    | pop edi
        */
    
        strings:
            $a   = { 66 ff 01 6a 66 58 cd 80 81 3e 6d 73 66 21 75 f0 5f }
    
        condition:
            any of them
    }
    
    