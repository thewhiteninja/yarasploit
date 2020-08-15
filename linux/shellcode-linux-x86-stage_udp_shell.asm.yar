
    rule stage_udp_shell_dup_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stage_udp_shell::dup"
    
        /*
            89FB                 | ..                   | mov ebx, edi
            6A02                 | j.                   | push byte 0x2
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { 89 fb 6a 02 59 }
    
        condition:
            any of them
    }
    
    
    rule stage_udp_shell_dup_loop_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stage_udp_shell::dup_loop"
    
        /*
            6A3F                 | j?                   | push byte 0x3f
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            49                   | I                    | dec ecx
            79F8                 | y.                   | jns dup_loop
        */
    
        strings:
            $a   = { 6a 3f 58 cd 80 49 79 f8 }
    
        condition:
            any of them
    }
    
    
    rule stage_udp_shell_execve_x86
    {
        meta:
            desc = "Metasploit::linux::x86::stage_udp_shell::execve"
    
        /*
            6A0B                 | j.                   | push byte 0xb
            58                   | X                    | pop eax
            99                   | .                    | cdq
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
            $a   = { 6a 0b 58 99 52 66 68 2d 69 89 e1 6a 67 66 68 69 6e 68 65 64 69 74 68 2d 2d 6e 6f 89 e7 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 51 57 53 89 e1 cd 80 }
    
        condition:
            any of them
    }
    
    