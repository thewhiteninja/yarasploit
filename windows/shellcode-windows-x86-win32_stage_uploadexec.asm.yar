
    rule win32_stage_uploadexec_lloadfileapi_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lloadfileapi"
    
        /*
            FF7500               | .u.                  | push dword [ebp]
            68A517007C           | h...|                | push 0x7c0017a5
            FF5504               | .U.                  | call [ebp + 4]
            894564               | .Ed                  | mov [ebp+100], eax
            FF7500               | .u.                  | push dword [ebp]
            681F790AE8           | h.y..                | push 0xe80a791f
            FF5504               | .U.                  | call [ebp + 4]
            894568               | .Eh                  | mov [ebp+104], eax
            FF7500               | .u.                  | push dword [ebp]
            68FB97FD0F           | h....                | push 0x0ffd97fb
            FF5504               | .U.                  | call [ebp + 4]
            89456C               | .El                  | mov [ebp+108], eax
        */
    
        strings:
            $a   = { ff 75 00 68 a5 17 00 7c ff 55 04 89 45 64 ff 75 00 68 1f 79 0a e8 ff 55 04 89 45 68 ff 75 00 68 fb 97 fd 0f ff 55 04 89 45 6c }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_uploadexec_lreadfilelength_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lreadfilelength"
    
        /*
            8D4578               | .Ex                  | lea eax, [ebp+120]
            6A00                 | j.                   | push byte 0x00
            6A04                 | j.                   | push 4
            50                   | P                    | push eax
            57                   | W                    | push dword edi
            FF5518               | .U.                  | call [ebp + 24]
            8B4578               | .Ex                  | mov eax, [ebp+120]
            E812000000           | .....                | call lgetfilename
            633A5C6D65746173706C6F69742E65786500 | c:\metasploit.exe.   | #ommited# db "c:\metasploit.exe", 0x00
        */
    
        strings:
            $a   = { 8d 45 78 6a 00 6a 04 50 57 ff 55 18 8b 45 78 e8 12 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_uploadexec_lcreatefile_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lcreatefile"
    
        /*
            6A00                 | j.                   | push byte 0
            6A06                 | j.                   | push byte 6
            6A04                 | j.                   | push byte 4
            6A00                 | j.                   | push byte 0
            6A07                 | j.                   | push byte 7
            68000000E0           | h....                | push 0xe0000000
            51                   | Q                    | push ecx
            FF5564               | .Ud                  | call [ebp+100]
            89C3                 | ..                   | mov ebx, eax
        */
    
        strings:
            $a   = { 6a 00 6a 06 6a 04 6a 00 6a 07 68 00 00 00 e0 51 ff 55 64 89 c3 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_uploadexec_lconfigbuffer_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lconfigbuffer"
    
        /*
            81EC58FFFFFF         | ..X...               | sub esp, 32 - 200
            896574               | .et                  | mov [ebp+116], esp
        */
    
        strings:
            $a   = { 81 ec 58 ff ff ff 89 65 74 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_uploadexec_lreadsocket_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lreadsocket"
    
        /*
            8B4574               | .Et                  | mov eax, [ebp+116]
            6A00                 | j.                   | push byte 0x00
            6A20                 | j                    | push 32
            50                   | P                    | push eax
            57                   | W                    | push dword edi
            FF5518               | .U.                  | call [ebp + 24]
            8B4D78               | .Mx                  | mov ecx, [ebp+120]
            29C1                 | ).                   | sub ecx, eax
            894D78               | .Mx                  | mov [ebp+120], ecx
        */
    
        strings:
            $a   = { 8b 45 74 6a 00 6a 20 50 57 ff 55 18 8b 4d 78 29 c1 89 4d 78 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_uploadexec_lwritefile_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lwritefile"
    
        /*
            54                   | T                    | push esp
            89E1                 | ..                   | mov ecx, esp
            6A00                 | j.                   | push byte 0
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            FF7574               | .ut                  | push dword [ebp+116]
            53                   | S                    | push ebx
            FF5568               | .Uh                  | call [ebp+104]
            59                   | Y                    | pop ecx
            8B4578               | .Ex                  | mov eax, [ebp+120]
            85C0                 | ..                   | test eax, eax
            75D6                 | u.                   | jnz lreadsocket
        */
    
        strings:
            $a   = { 54 89 e1 6a 00 51 50 ff 75 74 53 ff 55 68 59 8b 45 78 85 c0 75 d6 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_uploadexec_lcreateprocessstructs_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lcreateprocessstructs"
    
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
    
    
    rule win32_stage_uploadexec_lcreatestructs_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lcreatestructs"
    
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
            FF7570               | .up                  | push dword [ebp+112]
            51                   | Q                    | push ecx
        */
    
        strings:
            $a   = { 83 ec 54 c6 44 24 10 44 66 c7 44 24 3c 01 01 89 7c 24 48 89 7c 24 4c 89 7c 24 50 8d 44 24 10 54 50 51 51 51 41 51 49 51 51 ff 75 70 51 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_uploadexec_lcreateprocessa_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lcreateprocessa"
    
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
    
    
    rule win32_stage_uploadexec_lwaitforsingleobject_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::lwaitforsingleobject"
    
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
    
    
    rule win32_stage_uploadexec_ldeathbecomesyou_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_uploadexec::ldeathbecomesyou"
    
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
    
    