
    rule stager_egghunt_loop_check_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_egghunt::loop_check"
    
        /*
            6A43                 | jC                   | push byte 0x43
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            3CF2                 | <.                   | cmp al, 0xf2
            74F1                 | t.                   | je loop_inc_page
        */
    
        strings:
            $a   = { 6a 43 58 cd 80 3c f2 74 f1 }
    
        condition:
            any of them
    }
    
    
    rule stager_egghunt_is_egg_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stager_egghunt::is_egg"
    
        /*
            B890509050           | ..P.P                | mov eax, 0x50905090
            89CF                 | ..                   | mov edi, ecx
            AF                   | .                    | scasd
            75EC                 | u.                   | jnz loop_inc_one
            AF                   | .                    | scasd
            75E9                 | u.                   | jnz loop_inc_one
            FFE7                 | ..                   | jmp edi
        */
    
        strings:
            $a   = { b8 90 50 90 50 89 cf af 75 ec af 75 e9 ff e7 }
    
        condition:
            any of them
    }
    
    