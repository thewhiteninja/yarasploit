
    rule stager_sysenter_hook_ring0_migrate_patch_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_sysenter_hook::ring0_migrate_patch"
    
        /*
            5E                   | ^                    | pop esi
            6876010000           | hv...                | push 0x176
            59                   | Y                    | pop ecx
            0F32                 | .2                   | rdmsr
            89465D               | .F]                  | mov dword [ esi + ( ring0_stager_data - ring0_stager_start ) + 0 ], eax
            8B7E61               | .~a                  | mov edi, dword [ esi + ( ring0_stager_data - ring0_stager_start ) + 4 ]
            89F8                 | ..                   | mov eax, edi
            0F30                 | .0                   | wrmsr
            B941414141           | .AAAA                | mov ecx, 0x41414141
            F3A4                 | ..                   | rep movsb
            FB                   | .                    | sti
        */
    
        strings:
            $a   = { 5e 68 76 01 00 00 59 0f 32 89 46 5d 8b 7e 61 89 f8 0f 30 b9 41 41 41 41 f3 a4 fb }
    
        condition:
            any of them
    }
    
    
    rule stager_sysenter_hook_ring0_stager_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_sysenter_hook::ring0_stager_start"
    
        /*
            6A00                 | j.                   | push byte 0
            9C                   | .                    | pushfd
            60                   | `                    | pushad
            E800000000           | .....                | call ring0_stager_eip
        */
    
        strings:
            $a   = { 6a 00 9c 60 e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule stager_sysenter_hook_ring0_stager_eip_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_sysenter_hook::ring0_stager_eip"
    
        /*
            58                   | X                    | pop eax
            8B5854               | .XT                  | mov ebx, dword [ eax + ( ring0_stager_data - ring0_stager_eip ) + 0 ]
            895C2424             | .\$$                 | mov [ esp + 36 ], ebx
            81F9DEC0ADDE         | ......               | cmp ecx, 0xdeadc0de
            7510                 | u.                   | jne ring0_stager_hook
            6876010000           | hv...                | push 0x176
            59                   | Y                    | pop ecx
            89D8                 | ..                   | mov eax, ebx
            31D2                 | 1.                   | xor edx, edx
            0F30                 | .0                   | wrmsr
            31C0                 | 1.                   | xor eax, eax
            EB31                 | .1                   | jmp short ring0_stager_finish
        */
    
        strings:
            $a   = { 58 8b 58 54 89 5c 24 24 81 f9 de c0 ad de 75 10 68 76 01 00 00 59 89 d8 31 d2 0f 30 31 c0 eb 31 }
    
        condition:
            any of them
    }
    
    
    rule stager_sysenter_hook_ring0_stager_hook_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_sysenter_hook::ring0_stager_hook"
    
        /*
            8B32                 | .2                   | mov esi, [ edx ]
            0FB61E               | ...                  | movzx ebx, byte [ esi ]
            6681FBC300           | f....                | cmp bx, 0xc3
            7525                 | u%                   | jne short ring0_stager_finish
            8B585C               | .X\                  | mov ebx, dword [ eax + ( ring0_stager_data - ring0_stager_eip ) + 8 ]
            8D5B69               | .[i                  | lea ebx, [ ebx + ring3_start - ring0_stager_start ]
            891A                 | ..                   | mov [ edx ], ebx
            B801000080           | .....                | mov eax, 0x80000001
            0FA2                 | ..                   | cpuid
            81E200001000         | ......               | and edx, 0x00100000
            740E                 | t.                   | jz short ring0_stager_finish
            BA45454545           | .EEEE                | mov edx, 0x45454545
            83C204               | ...                  | add edx, 4
            8122FFFFFF7F         | ."....               | and dword [ edx ], 0x7fffffff
        */
    
        strings:
            $a   = { 8b 32 0f b6 1e 66 81 fb c3 00 75 25 8b 58 5c 8d 5b 69 89 1a b8 01 00 00 80 0f a2 81 e2 00 00 10 00 74 0e ba 45 45 45 45 83 c2 04 81 22 ff ff ff 7f }
    
        condition:
            any of them
    }
    
    
    rule stager_sysenter_hook_ring3_start_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_sysenter_hook::ring3_start"
    
        /*
            60                   | `                    | pushad
            6A30                 | j0                   | push byte 0x30
            58                   | X                    | pop eax
            99                   | .                    | cdq
            648B18               | d..                  | mov ebx, [ fs : eax ]
            39530C               | 9S.                  | cmp [ ebx + 0xc ], edx
            742B                 | t+                   | jz ring3_finish
            8B4310               | .C.                  | mov eax, [ ebx + 0x10 ]
            8B403C               | .@<                  | mov eax, [ eax + 0x3c ]
            83C028               | ..(                  | add eax, byte 0x28
            8B08                 | ..                   | mov ecx, [ eax ]
            034803               | .H.                  | add ecx, [ eax + 0x3 ]
            81F944444444         | ..DDDD               | cmp ecx, 0x44444444
            7515                 | u.                   | jne ring3_finish
            E807000000           | .....                | call ring3_cleanup
            E80D000000           | .....                | call ring3_stager
            EB09                 | ..                   | jmp ring3_finish
        */
    
        strings:
            $a   = { 60 6a 30 58 99 64 8b 18 39 53 0c 74 2b 8b 43 10 8b 40 3c 83 c0 28 8b 08 03 48 03 81 f9 44 44 44 44 75 15 e8 07 00 00 00 e8 0d 00 00 00 eb 09 }
    
        condition:
            any of them
    }
    
    
    rule stager_sysenter_hook_ring3_cleanup_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_sysenter_hook::ring3_cleanup"
    
        /*
            B9DEC0ADDE           | .....                | mov ecx, 0xdeadc0de
            89E2                 | ..                   | mov edx, esp
            0F34                 | .4                   | sysenter
        */
    
        strings:
            $a   = { b9 de c0 ad de 89 e2 0f 34 }
    
        condition:
            any of them
    }
    
    