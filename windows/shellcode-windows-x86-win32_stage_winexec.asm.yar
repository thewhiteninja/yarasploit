
    rule win32_stage_winexec_lgetprocaddress_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::lgetprocaddress"
    
        /*
            53                   | S                    | push ebx
            55                   | U                    | push ebp
            56                   | V                    | push esi
            57                   | W                    | push edi
            8B6C2418             | .l$.                 | mov ebp, [esp + 24]
            8B453C               | .E<                  | mov eax, [ebp + 0x3c]
            8B540578             | .T.x                 | mov edx, [ebp + eax + 120]
            01EA                 | ..                   | add edx, ebp
            8B4A18               | .J.                  | mov ecx, [edx + 24]
            8B5A20               | .Z                   | mov ebx, [edx + 32]
            01EB                 | ..                   | add ebx, ebp
        */
    
        strings:
            $a   = { 53 55 56 57 8b 6c 24 18 8b 45 3c 8b 54 05 78 01 ea 8b 4a 18 8b 5a 20 01 eb }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_lfnlp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::lfnlp"
    
        /*
            E332                 | .2                   | jecxz lntfnd
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi, [ebx + ecx * 4]
            01EE                 | ..                   | add esi, ebp
            31FF                 | 1.                   | xor edi, edi
            FC                   | .                    | cld
        */
    
        strings:
            $a   = { e3 32 49 8b 34 8b 01 ee 31 ff fc }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_lhshlp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::lhshlp"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            38E0                 | 8.                   | cmp al, ah
            7407                 | t.                   | je lfnd
            C1CF0D               | ...                  | ror edi, 13
            01C7                 | ..                   | add edi, eax
            EBF2                 | ..                   | jmp short lhshlp
        */
    
        strings:
            $a   = { 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_lfnd_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::lfnd"
    
        /*
            3B7C2414             | ;|$.                 | cmp edi, [esp + 20]
            75E1                 | u.                   | jnz lfnlp
            8B5A24               | .Z$                  | mov ebx, [edx + 36]
            01EB                 | ..                   | add ebx, ebp
            668B0C4B             | f..K                 | mov cx, [ebx + 2 * ecx]
            8B5A1C               | .Z.                  | mov ebx, [edx + 28]
            01EB                 | ..                   | add ebx, ebp
            8B048B               | ...                  | mov eax, [ebx + 4 * ecx]
            01E8                 | ..                   | add eax, ebp
            EB02                 | ..                   | jmp short ldone
        */
    
        strings:
            $a   = { 3b 7c 24 14 75 e1 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 eb 02 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_ldone_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::ldone"
    
        /*
            5F                   | _                    | pop edi
            5E                   | ^                    | pop esi
            5D                   | ]                    | pop ebp
            5B                   | [                    | pop ebx
            C20800               | ...                  | ret 8
        */
    
        strings:
            $a   = { 5f 5e 5d 5b c2 08 00 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_lkernel32base_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::lkernel32base"
    
        /*
            5E                   | ^                    | pop esi
            6A30                 | j0                   | push byte 0x30
            59                   | Y                    | pop ecx
            648B19               | d..                  | mov ebx, [fs:ecx]
            8B5B0C               | .[.                  | mov ebx, [ebx + 0x0c]
            8B5B1C               | .[.                  | mov ebx, [ebx + 0x1c]
            8B1B                 | ..                   | mov ebx, [ebx]
            8B5B08               | .[.                  | mov ebx, [ebx + 0x08]
            53                   | S                    | push ebx
            688E4E0EEC           | h.N..                | push 0xec0e4e8e
            FFD6                 | ..                   | call esi
            89C7                 | ..                   | mov edi, eax
            53                   | S                    | push ebx
            6854CAAF91           | hT...                | push 0x91afca54
            FFD6                 | ..                   | call esi
            EB18                 | ..                   | jmp short getcmd
        */
    
        strings:
            $a   = { 5e 6a 30 59 64 8b 19 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08 53 68 8e 4e 0e ec ff d6 89 c7 53 68 54 ca af 91 ff d6 eb 18 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_winexec_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::winexec"
    
        /*
            53                   | S                    | push ebx
            6898FE8A0E           | h....                | push 0x0e8afe98
            FFD6                 | ..                   | call esi
            FFD0                 | ..                   | call eax
        */
    
        strings:
            $a   = { 53 68 98 fe 8a 0e ff d6 ff d0 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_exitprocess_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::exitprocess"
    
        /*
            53                   | S                    | push ebx
            687ED8E273           | h~..s                | push 0x73e2d87e
            FFD6                 | ..                   | call esi
            6A00                 | j.                   | push byte 0
            FFD0                 | ..                   | call eax
            FFD0                 | ..                   | call eax
        */
    
        strings:
            $a   = { 53 68 7e d8 e2 73 ff d6 6a 00 ff d0 ff d0 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_winexec_getcmd_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_winexec::getcmd"
    
        /*
            6A00                 | j.                   | push byte 0
            E8E1FFFFFF           | .....                | call winexec
        */
    
        strings:
            $a   = { 6a 00 e8 e1 ff ff ff }
    
        condition:
            any of them
    }
    
    