
    rule single_adduser_setreuid_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_adduser::setreuid"
    
        /*
            31C9                 | 1.                   | xor ecx, ecx
            89CB                 | ..                   | mov ebx, ecx
            6A46                 | jF                   | push byte 0x46
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            6A05                 | j.                   | push byte 0x05
            58                   | X                    | pop eax
            31C9                 | 1.                   | xor ecx, ecx
            51                   | Q                    | push ecx
            6873737764           | hsswd                | push dword 0x64777373
            682F2F7061           | h//pa                | push dword 0x61702f2f
            682F657463           | h/etc                | push dword 0x6374652f
            89E3                 | ..                   | mov ebx, esp
            41                   | A                    | inc ecx
            B504                 | ..                   | mov ch, 0x04
            CD80                 | ..                   | int 0x80
            93                   | .                    | xchg eax, ebx
            E820000000           | . ...                | call getstr
            6162633A61616E76336D33357662632F673A303A303A3A2F3A2F62696E2F7368 | abc:aanv3m35vbc/g:0:0::/:/bin/sh | #ommited# db "abc:aanv3m35vbc/g:0:0::/:/bin/sh"
        */
    
        strings:
            $a   = { 31 c9 89 cb 6a 46 58 cd 80 6a 05 58 31 c9 51 68 73 73 77 64 68 2f 2f 70 61 68 2f 65 74 63 89 e3 41 b5 04 cd 80 93 e8 20 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_adduser_getstr_x86
    {
        meta:
            desc = "Metasploit::linux::x86::single_adduser::getstr"
    
        /*
            59                   | Y                    | pop ecx
            8B51FC               | .Q.                  | mov edx, [ecx-4]
            6A04                 | j.                   | push byte 0x04
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
            6A01                 | j.                   | push byte 0x01
            58                   | X                    | pop eax
            CD80                 | ..                   | int 0x80
        */
    
        strings:
            $a   = { 59 8b 51 fc 6a 04 58 cd 80 6a 01 58 cd 80 }
    
        condition:
            any of them
    }
    
    