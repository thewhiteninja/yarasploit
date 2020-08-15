
    rule win32_stage_shell_lsetcommand_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_shell::lsetcommand"
    
        /*
            68636D6400           | hcmd.                | push "cmd"
            89E3                 | ..                   | mov ebx, esp
        */
    
        strings:
            $a   = { 68 63 6d 64 00 89 e3 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_shell_lcreateprocessstructs_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_shell::lcreateprocessstructs"
    
        /*
            87FA                 | ..                   | xchg edi, edx
            31C0                 | 1.                   | xor eax,eax
            8D7C24AC             | .|$.                 | lea edi, [esp-84]
            6A15                 | j.                   | push byte 21
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { 87 fa 31 c0 8d 7c 24 ac 6a 15 59 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_shell_lcreatestructs_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_shell::lcreatestructs"
    
        /*
            83EC54               | ..T                  | sub esp, 84
            C644241044           | .D$.D                | mov byte [esp + 16], 68
            66C744243C0101       | f.D$<..              | mov word [esp + 60], 0x0101
            897C2448             | .|$H                 | mov [esp + 16 + 56], edi
            897C244C             | .|$L                 | mov [esp + 16 + 60], edi
            897C2450             | .|$P                 | mov [esp + 16 + 64], edi
            8D442410             | .D$.                 | lea eax, [esp + 16]
            54                   | T                    | push esp
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            41                   | A                    | inc ecx
            51                   | Q                    | push ecx
            49                   | I                    | dec ecx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            53                   | S                    | push ebx
            51                   | Q                    | push ecx
        */
    
        strings:
            $a   = { 83 ec 54 c6 44 24 10 44 66 c7 44 24 3c 01 01 89 7c 24 48 89 7c 24 4c 89 7c 24 50 8d 44 24 10 54 50 51 51 51 41 51 49 51 51 53 51 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_shell_lcreateprocessa_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_shell::lcreateprocessa"
    
        /*
            FF7500               | .u.                  | push dword [ebp]
            6872FEB316           | hr...                | push 0x16b3fe72
            FF5504               | .U.                  | call [ebp + 4]
            FFD0                 | ..                   | call eax
            89E6                 | ..                   | mov esi, esp
        */
    
        strings:
            $a   = { ff 75 00 68 72 fe b3 16 ff 55 04 ff d0 89 e6 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_shell_lwaitforsingleobject_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_shell::lwaitforsingleobject"
    
        /*
            FF7500               | .u.                  | push dword [ebp]
            68ADD905CE           | h....                | push 0xce05d9ad
            FF5504               | .U.                  | call [ebp + 4]
            89C3                 | ..                   | mov ebx, eax
            6AFF                 | j.                   | push 0xffffffff
            FF36                 | .6                   | push dword [esi]
            FFD3                 | ..                   | call ebx
        */
    
        strings:
            $a   = { ff 75 00 68 ad d9 05 ce ff 55 04 89 c3 6a ff ff 36 ff d3 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_shell_ldeathbecomesyou_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_shell::ldeathbecomesyou"
    
        /*
            FF7500               | .u.                  | push dword [ebp]
            687ED8E273           | h~..s                | push 0x73e2d87e
            FF5504               | .U.                  | call [ebp + 4]
            31DB                 | 1.                   | xor ebx, ebx
            53                   | S                    | push ebx
            FFD0                 | ..                   | call eax
        */
    
        strings:
            $a   = { ff 75 00 68 7e d8 e2 73 ff 55 04 31 db 53 ff d0 }
    
        condition:
            any of them
    }
    
    