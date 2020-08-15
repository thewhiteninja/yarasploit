
    rule single_exec__start_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_exec::_start"
    
        /*
            6A0B                 | j.                   | push byte 0xb
            58                   | X                    | pop eax
            99                   | .                    | cdq
            52                   | R                    | push edx
            66682D63             | fh-c                 | push word 0x632d
            89E7                 | ..                   | mov edi, esp
            682F736800           | h/sh.                | push dword 0x0068732f
            682F62696E           | h/bin                | push dword 0x6e69622f
            89E3                 | ..                   | mov ebx, esp
            52                   | R                    | push edx
            E809000000           | .....                | call getstr
            6563686F206D303000   | echo m00.            | #ommited# db "echo m00", 0x00
        */
    
        strings:
            $a   = { 6a 0b 58 99 52 66 68 2d 63 89 e7 68 2f 73 68 00 68 2f 62 69 6e 89 e3 52 e8 09 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_exec_getstr_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_exec::getstr"
    
        /*
            57                   | W                    | push edi
            53                   | S                    | push ebx
            89E1                 | ..                   | mov ecx, esp
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 57 53 89 e1 cd 80 }
    
        condition:
            any of them
    }
    
    