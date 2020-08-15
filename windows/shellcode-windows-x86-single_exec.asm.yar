
    rule single_exec___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_exec::__start0__"
    
        /*
            FC                   | .                    | cld
            E844000000           | .D...                | call startup
            8B453C               | .E<                  | mov eax,[ebp+0x3c]
            8B7C0578             | .|.x                 | mov edi,[ebp+eax+0x78]
            01EF                 | ..                   | add edi,ebp
            8B4F18               | .O.                  | mov ecx,[edi+0x18]
            8B5F20               | ._                   | mov ebx,[edi+0x20]
            01EB                 | ..                   | add ebx,ebp
        */
    
        strings:
            $a   = { fc e8 44 00 00 00 8b 45 3c 8b 7c 05 78 01 ef 8b 4f 18 8b 5f 20 01 eb }
    
        condition:
            any of them
    }
    
    
    rule single_exec_next_export_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_exec::next_export"
    
        /*
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi,[ebx+ecx*4]
            01EE                 | ..                   | add esi,ebp
            31C0                 | 1.                   | xor eax,eax
            99                   | .                    | cdq
        */
    
        strings:
            $a   = { 49 8b 34 8b 01 ee 31 c0 99 }
    
        condition:
            any of them
    }
    
    
    rule single_exec_next_byte_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_exec::next_byte"
    
        /*
            AC                   | .                    | lodsb
            84C0                 | ..                   | test al,al
            740D                 | t.                   | jz hash_complete
            C1CA0D               | ...                  | ror edx,0xd
            01C2                 | ..                   | add edx,eax
            EBF4                 | ..                   | jmp short next_byte
            3B542404             | ;T$.                 | cmp edx,[esp+0x4]
            75E5                 | u.                   | jnz next_export
        */
    
        strings:
            $a   = { ac 84 c0 74 0d c1 ca 0d 01 c2 eb f4 3b 54 24 04 75 e5 }
    
        condition:
            any of them
    }
    
    
    rule single_exec_hash_complete_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_exec::hash_complete"
    
        /*
            8B5F24               | ._$                  | mov ebx,[edi+0x24]
            01EB                 | ..                   | add ebx,ebp
            668B0C4B             | f..K                 | mov cx,[ebx+ecx*2]
            8B5F1C               | ._.                  | mov ebx,[edi+0x1c]
            01EB                 | ..                   | add ebx,ebp
            8B1C8B               | ...                  | mov ebx,[ebx+ecx*4]
            01EB                 | ..                   | add ebx,ebp
            895C2404             | .\$.                 | mov [esp+0x4],ebx
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 8b 5f 24 01 eb 66 8b 0c 4b 8b 5f 1c 01 eb 8b 1c 8b 01 eb 89 5c 24 04 c3 }
    
        condition:
            any of them
    }
    
    
    rule single_exec_startup_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_exec::startup"
    
        /*
            5F                   | _                    | pop edi
            31F6                 | 1.                   | xor esi,esi
            60                   | `                    | pusha
            56                   | V                    | push esi
            648B4630             | d.F0                 | mov eax,[fs:esi+0x30]
            8B400C               | .@.                  | mov eax,[eax+0xc]
            8B701C               | .p.                  | mov esi,[eax+0x1c]
            AD                   | .                    | lodsd
            8B6808               | .h.                  | mov ebp,[eax+0x8]
            89F8                 | ..                   | mov eax,edi
            83C06A               | ..j                  | add eax,byte +0x6a
            50                   | P                    | push eax
            68F08A045F           | h..._                | push dword 0x5f048af0
            6898FE8A0E           | h....                | push dword 0xe8afe98
            57                   | W                    | push edi
            FFE7                 | ..                   | jmp edi
            636F6D6D616E6420737472696E67 | command string       | #ommited# db "command string"
        */
    
        strings:
            $a   = { 5f 31 f6 60 56 64 8b 46 30 8b 40 0c 8b 70 1c ad 8b 68 08 89 f8 83 c0 6a 50 68 f0 8a 04 5f 68 98 fe 8a 0e 57 ff e7 }
    
        condition:
            any of them
    }
    
    