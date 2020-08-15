
    rule stager_find_tag___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_find_tag::__start0__"
    
        /*
            FC                   | .                    | cld
            31FF                 | 1.                   | xor edi,edi
            648B4730             | d.G0                 | mov eax,[fs:edi+0x30]
            8B400C               | .@.                  | mov eax,[eax+0xc]
            8B581C               | .X.                  | mov ebx,[eax+0x1c]
            8B1B                 | ..                   | mov ebx,[ebx]
            8B7320               | .s                   | mov esi,[ebx+0x20]
            AD                   | .                    | lodsd
            AD                   | .                    | lodsd
            4E                   | N                    | dec esi
            0306                 | ..                   | add eax,[esi]
            3D32335F32           | =23_2                | cmp eax,0x325f3332
            0F85EBFFFFFF         | ......               | jnz 0xd
            8B6B08               | .k.                  | mov ebp,[ebx+0x8]
            8B453C               | .E<                  | mov eax,[ebp+0x3c]
            8B4C0578             | .L.x                 | mov ecx,[ebp+eax+0x78]
            8B4C0D1C             | .L..                 | mov ecx,[ebp+ecx+0x1c]
            8B5C293C             | .\)<                 | mov ebx,[ecx+ebp+0x3c]
            01EB                 | ..                   | add ebx,ebp
            036C2924             | .l)$                 | add ebp,[ecx+ebp+0x24]
            57                   | W                    | push edi
            6647                 | fG                   | inc di
            89E6                 | ..                   | mov esi,esp
            56                   | V                    | push esi
            687F660440           | h.f.@                | push dword 0x4004667f
            57                   | W                    | push edi
            FFD5                 | ..                   | call ebp
            AD                   | .                    | lodsd
            85C0                 | ..                   | test eax,eax
            0F84E6FFFFFF         | ......               | jz 0x37
            99                   | .                    | cdq
            52                   | R                    | push edx
            B60C                 | ..                   | mov dh,0xc
            52                   | R                    | push edx
            56                   | V                    | push esi
            57                   | W                    | push edi
            FFD3                 | ..                   | call ebx
            AD                   | .                    | lodsd
            3D734B7A33           | =sKz3                | cmp eax,0x337a4b73
            0F85D1FFFFFF         | ......               | jnz 0x37
            FFE6                 | ..                   | jmp esi
            636D64               | cmd                  | arpl [ebp+0x64],bp
            650F8856000000       | e..V...              | gs js 0xc8
            202F                 |  /                   | and [edi],ch
            6320                 | c                    | arpl [eax],sp
            6E                   | n                    | outsb
            650F840D000000       | e......              | gs jz 0x8b
            0F855C000000         | ..\...               | jnz 0xe0
            650F8205000000       | e......              | gs jc 0x90
            6D                   | m                    | insd
            650F8442000000       | e..B...              | gs jz 0xd5
            0F834D000000         | ..M...               | jnc 0xe6
            6C                   | l                    | insb
            6F                   | o                    | outsd
            6970202F414444       | ip /ADD              | imul esi,[eax+0x20],dword 0x4444412f
            2026                 |  &                   | and [esi],ah
            26206E65             | & ne                 | and [es:esi+0x65],ch
            0F84FAFFFFFF         | ......               | jz 0xa8
            6C                   | l                    | insb
            6F                   | o                    | outsd
            63616C               | cal                  | arpl [ecx+0x6c],sp
            670F8245000000       | g..E...              | a16 jc 0xff
            0F8542000000         | ..B...               | jnz 0x102
            204164               |  Ad                  | and [ecx+0x64],al
            6D                   | m                    | insd
            696E6973747261       | inistra              | imul ebp,[esi+0x69],dword 0x61727473
            0F843D000000         | ..=...               | jz 0x10e
            0F823D000000         | ..=...               | jc 0x114
            206D65               |  me                  | and [ebp+0x65],ch
            0F8427000000         | ..'...               | jz 0x107
            0F8332000000         | ..2...               | jnc 0x118
            6C                   | l                    | insb
            6F                   | o                    | outsd
            69702F41444400       | ip/ADD.              | imul esi,[eax+0x2f],dword 0x444441
        */
    
        strings:
            $a   = { fc 31 ff 64 8b 47 30 8b 40 0c 8b 58 1c 8b 1b 8b 73 20 ad ad 4e 03 06 3d 32 33 5f 32 0f 85 eb ff ff ff 8b 6b 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 8b 5c 29 3c 01 eb 03 6c 29 24 57 66 47 89 e6 56 68 7f 66 04 40 57 ff d5 ad 85 c0 0f 84 e6 ff ff ff 99 52 b6 0c 52 56 57 ff d3 ad 3d 73 4b 7a 33 0f 85 d1 ff ff ff ff e6 63 6d 64 65 0f 88 56 00 00 00 20 2f 63 20 6e 65 0f 84 0d 00 00 00 0f 85 5c 00 00 00 65 0f 82 05 00 00 00 6d 65 0f 84 42 00 00 00 0f 83 4d 00 00 00 6c 6f 69 70 20 2f 41 44 44 20 26 26 20 6e 65 0f 84 fa ff ff ff 6c 6f 63 61 6c 67 0f 82 45 00 00 00 0f 85 42 00 00 00 20 41 64 6d 69 6e 69 73 74 72 61 0f 84 3d 00 00 00 0f 82 3d 00 00 00 20 6d 65 0f 84 27 00 00 00 0f 83 32 00 00 00 6c 6f 69 70 2f 41 44 44 00 }
    
        condition:
            any of them
    }
    
    