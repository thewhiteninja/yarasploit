
    rule block_shell_shell_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_shell::shell"
    
        /*
            68636D6400           | hcmd.                | push 0x00646d63
            89E3                 | ..                   | mov ebx, esp
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            31F6                 | 1.                   | xor esi, esi
            6A12                 | j.                   | push byte 18
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { 68 63 6d 64 00 89 e3 57 57 57 31 f6 6a 12 59 }
    
        condition:
            any of them
    }
    
    
    rule block_shell_push_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_shell::push_loop"
    
        /*
            56                   | V                    | push esi
            E2FD                 | ..                   | loop push_loop
            66C744243C0101       | f.D$<..              | mov word [esp + 60], 0x0101
            8D442410             | .D$.                 | lea eax, [esp + 16]
            C60044               | ..D                  | mov byte [eax], 68
            54                   | T                    | push esp
            50                   | P                    | push eax
            56                   | V                    | push esi
            56                   | V                    | push esi
            56                   | V                    | push esi
            46                   | F                    | inc esi
            56                   | V                    | push esi
            4E                   | N                    | dec esi
            56                   | V                    | push esi
            56                   | V                    | push esi
            53                   | S                    | push ebx
            56                   | V                    | push esi
            6879CC3F86           | hy.?.                | push 0x863fcc79	; CreateProcessA
            FFD5                 | ..                   | call ebp
            89E0                 | ..                   | mov eax, esp
            4E                   | N                    | dec esi
            56                   | V                    | push esi
            46                   | F                    | inc esi
            FF30                 | .0                   | push dword [eax]
            6808871D60           | h...`                | push 0x601d8708	; WaitForSingleObject
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 56 e2 fd 66 c7 44 24 3c 01 01 8d 44 24 10 c6 00 44 54 50 56 56 56 46 56 4e 56 56 53 56 68 79 cc 3f 86 ff d5 89 e0 4e 56 46 ff 30 68 08 87 1d 60 ff d5 }
    
        condition:
            any of them
    }
    
    