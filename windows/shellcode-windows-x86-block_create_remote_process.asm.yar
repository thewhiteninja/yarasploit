
    rule block_create_remote_process___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_create_remote_process::__start0__"
    
        /*
            31FF                 | 1.                   | xor edi, edi
            6A04                 | j.                   | push 0x00000004
            6800100000           | h....                | push 0x00001000
            6A54                 | jT                   | push 0x00000054
            57                   | W                    | push edi
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
            C70044000000         | ..D...               | mov dword [eax], 0x44
            8D7044               | .pD                  | lea esi, [eax+0x44]
            57                   | W                    | push edi
            682E657865           | h.exe                | push 0x6578652e
            686C6C3332           | hll32                | push 0x32336c6c
            6872756E64           | hrund                | push 0x646e7572
            89E1                 | ..                   | mov ecx, esp
            56                   | V                    | push esi
            50                   | P                    | push eax
            57                   | W                    | push edi
            57                   | W                    | push edi
            6A44                 | jD                   | push 0x00000044
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            6879CC3F86           | hy.?.                | push 0x863fcc79	; CreateProcessA
            FFD5                 | ..                   | call ebp
            8B0E                 | ..                   | mov ecx, [esi]
            6A40                 | j@                   | push 0x00000040
            6800100000           | h....                | push 0x00001000
            6800100000           | h....                | push 0x00001000
            57                   | W                    | push edi
            51                   | Q                    | push ecx
            68AE87923F           | h...?                | push 0x3f9287ae	; VirtualAllocEx
            FFD5                 | ..                   | call ebp
            E800000000           | .....                | call me2
        */
    
        strings:
            $a   = { 31 ff 6a 04 68 00 10 00 00 6a 54 57 68 58 a4 53 e5 ff d5 c7 00 44 00 00 00 8d 70 44 57 68 2e 65 78 65 68 6c 6c 33 32 68 72 75 6e 64 89 e1 56 50 57 57 6a 44 57 57 57 51 57 68 79 cc 3f 86 ff d5 8b 0e 6a 40 68 00 10 00 00 68 00 10 00 00 57 51 68 ae 87 92 3f ff d5 e8 00 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule block_create_remote_process_me2_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_create_remote_process::me2"
    
        /*
            5A                   | Z                    | pop edx
            89C7                 | ..                   | mov edi, eax
            8B0E                 | ..                   | mov ecx, [esi]
            81C247221100         | ..G"..               | add dword edx, 0x112247
            54                   | T                    | push esp
            6800100000           | h....                | push 0x00001000
            52                   | R                    | push edx
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            68C5D8BDE7           | h....                | push 0xe7bdd8c5	; WriteProcessMemory
            FFD5                 | ..                   | call ebp
            31C0                 | 1.                   | xor eax, eax
            8B0E                 | ..                   | mov ecx, [esi]
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            57                   | W                    | push edi
            50                   | P                    | push eax
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            68C6AC9A79           | h...y                | push 0x799aacc6	; CreateRemoteThread
            FFD5                 | ..                   | call ebp
            8B0E                 | ..                   | mov ecx, [esi]
            51                   | Q                    | push ecx
            68C6968752           | h...R                | push 0x528796c6	; CloseHandle
            FFD5                 | ..                   | call ebp
            8B4E04               | .N.                  | mov ecx, [esi+0x4]
            51                   | Q                    | push ecx
            68C6968752           | h...R                | push 0x528796c6	; CloseHandle
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 5a 89 c7 8b 0e 81 c2 47 22 11 00 54 68 00 10 00 00 52 50 51 68 c5 d8 bd e7 ff d5 31 c0 8b 0e 50 50 50 57 50 50 51 68 c6 ac 9a 79 ff d5 8b 0e 51 68 c6 96 87 52 ff d5 8b 4e 04 51 68 c6 96 87 52 ff d5 }
    
        condition:
            any of them
    }
    
    