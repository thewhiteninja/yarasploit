
    rule block_get_pstore_creds_alloc_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::alloc_memory"
    
        /*
            6A40                 | j@                   | push byte 0x40
            6800100000           | h....                | push 0x1000
            6800100000           | h....                | push 0x1000
            6A00                 | j.                   | push 0
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 68 58 a4 53 e5 ff d5 c3 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_alloc_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::alloc_loop"
    
        /*
            E8E3FFFFFF           | .....                | call alloc_memory
            50                   | P                    | push eax
            FECB                 | ..                   | dec bl
            75F6                 | u.                   | jnz alloc_loop
        */
    
        strings:
            $a   = { e8 e3 ff ff ff 50 fe cb 75 f6 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_load_pstorec_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::load_pstorec"
    
        /*
            6872656300           | hrec.                | push 0x00636572
            687073746F           | hpsto                | push 0x6f747370
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
            5A                   | Z                    | pop edx
            5A                   | Z                    | pop edx
        */
    
        strings:
            $a   = { 68 72 65 63 00 68 70 73 74 6f 54 68 4c 77 26 07 ff d5 5a 5a }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_pstorecreateinstance_pstore_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::pstorecreateinstance_pstore"
    
        /*
            5F                   | _                    | pop edi
            57                   | W                    | push edi
            6A00                 | j.                   | push 0
            6A00                 | j.                   | push 0
            6A00                 | j.                   | push 0
            57                   | W                    | push edi
            68DBBD6426           | h..d&                | push 0x2664bddb	; PStoreCreateInstance
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 5f 57 6a 00 6a 00 6a 00 57 68 db bd 64 26 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_pstore_enumtypes_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::pstore.enumtypes"
    
        /*
            58                   | X                    | pop eax
            5A                   | Z                    | pop edx
            52                   | R                    | push edx
            50                   | P                    | push eax
            52                   | R                    | push edx
            6A00                 | j.                   | push 0
            6A00                 | j.                   | push 0
            8B00                 | ..                   | mov eax, [eax]
            50                   | P                    | push eax
            8B10                 | ..                   | mov edx, [eax]
            8B5238               | .R8                  | mov edx, [edx+0x38]
            FFD2                 | ..                   | call edx
            BF00817E5E           | ...~^                | mov edi, 0x5e7e8100
        */
    
        strings:
            $a   = { 58 5a 52 50 52 6a 00 6a 00 8b 00 50 8b 10 8b 52 38 ff d2 bf 00 81 7e 5e }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_enumpstoretypes_raw_next_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::enumpstoretypes.raw_next"
    
        /*
            58                   | X                    | pop eax
            5A                   | Z                    | pop edx
            59                   | Y                    | pop ecx
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            50                   | P                    | push eax
            6A00                 | j.                   | push 0
            51                   | Q                    | push ecx
            6A01                 | j.                   | push 1
            8B12                 | ..                   | mov edx, [edx]
            52                   | R                    | push edx
            8B12                 | ..                   | mov edx, [edx]
            8B520C               | .R.                  | mov edx, [edx+0x0c]
            FFD2                 | ..                   | call edx
            8B442408             | .D$.                 | mov eax, [esp+8]
            8B00                 | ..                   | mov eax, [eax]
            85C0                 | ..                   | test eax, eax
            0F84B1000000         | ......               | jz no_auth
            39C7                 | 9.                   | cmp edi, eax
            75D9                 | u.                   | jne enumpstoretypes.raw_next
        */
    
        strings:
            $a   = { 58 5a 59 51 52 50 6a 00 51 6a 01 8b 12 52 8b 12 8b 52 0c ff d2 8b 44 24 08 8b 00 85 c0 0f 84 b1 00 00 00 39 c7 75 d9 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_pstore_enumsubtypes_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::pstore.enumsubtypes"
    
        /*
            58                   | X                    | pop eax
            5A                   | Z                    | pop edx
            59                   | Y                    | pop ecx
            5F                   | _                    | pop edi
            57                   | W                    | push edi
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            50                   | P                    | push eax
            57                   | W                    | push edi
            6A00                 | j.                   | push 0
            51                   | Q                    | push ecx
            6A00                 | j.                   | push 0
            8B00                 | ..                   | mov eax, [eax]
            50                   | P                    | push eax
            8B10                 | ..                   | mov edx, [eax]
            8B523C               | .R<                  | mov edx, [edx+0x3c]
            FFD2                 | ..                   | call edx
        */
    
        strings:
            $a   = { 58 5a 59 5f 57 51 52 50 57 6a 00 51 6a 00 8b 00 50 8b 10 8b 52 3c ff d2 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_enumsubtypes_raw_next_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::enumsubtypes.raw_next"
    
        /*
            8B44240C             | .D$.                 | mov eax, [esp+0x0c]
            8B542410             | .T$.                 | mov edx, [esp+0x10]
            6A00                 | j.                   | push 0
            52                   | R                    | push edx
            6A01                 | j.                   | push 1
            8B00                 | ..                   | mov eax, [eax]
            50                   | P                    | push eax
            8B10                 | ..                   | mov edx, [eax]
            8B520C               | .R.                  | mov edx, [edx+0x0c]
            FFD2                 | ..                   | call edx
        */
    
        strings:
            $a   = { 8b 44 24 0c 8b 54 24 10 6a 00 52 6a 01 8b 00 50 8b 10 8b 52 0c ff d2 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_pstore_enumitems_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::pstore.enumitems"
    
        /*
            58                   | X                    | pop eax
            59                   | Y                    | pop ecx
            5A                   | Z                    | pop edx
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            50                   | P                    | push eax
            8B4C2410             | .L$.                 | mov ecx, [esp+0x10]
            8B7C2414             | .|$.                 | mov edi, [esp+0x14]
            57                   | W                    | push edi
            6A00                 | j.                   | push 0
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            6A00                 | j.                   | push 0
            8B00                 | ..                   | mov eax, [eax]
            50                   | P                    | push eax
            8B10                 | ..                   | mov edx, [eax]
            8B5254               | .RT                  | mov edx, [edx+0x54]
            FFD2                 | ..                   | call edx
        */
    
        strings:
            $a   = { 58 59 5a 52 51 50 8b 4c 24 10 8b 7c 24 14 57 6a 00 51 52 6a 00 8b 00 50 8b 10 8b 52 54 ff d2 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_spenumitems_raw_next_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::spenumitems.raw_next"
    
        /*
            8B442414             | .D$.                 | mov eax, [esp+0x14]
            8B4C2418             | .L$.                 | mov ecx, [esp+0x18]
            6A00                 | j.                   | push 0
            51                   | Q                    | push ecx
            6A01                 | j.                   | push 1
            8B00                 | ..                   | mov eax, [eax]
            50                   | P                    | push eax
            8B10                 | ..                   | mov edx, [eax]
            8B520C               | .R.                  | mov edx, [edx+0x0c]
            FFD2                 | ..                   | call edx
        */
    
        strings:
            $a   = { 8b 44 24 14 8b 4c 24 18 6a 00 51 6a 01 8b 00 50 8b 10 8b 52 0c ff d2 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_pstore_readitem_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::pstore.readitem"
    
        /*
            58                   | X                    | pop eax
            50                   | P                    | push eax
            6A00                 | j.                   | push 0
            6A00                 | j.                   | push 0
            8B4C2424             | .L$$                 | mov ecx, [esp+0x24]
            51                   | Q                    | push ecx
            8B4C242C             | .L$,                 | mov ecx, [esp+0x2c]
            51                   | Q                    | push ecx
            8B4C2428             | .L$(                 | mov ecx, [esp+0x28]
            8B09                 | ..                   | mov ecx, [ecx]
            51                   | Q                    | push ecx
            8B4C2424             | .L$$                 | mov ecx, [esp+0x24]
            51                   | Q                    | push ecx
            8B4C2420             | .L$                  | mov ecx, [esp+0x20]
            51                   | Q                    | push ecx
            6A00                 | j.                   | push 0
            8B00                 | ..                   | mov eax, [eax]
            50                   | P                    | push eax
            8B10                 | ..                   | mov edx, [eax]
            8B5244               | .RD                  | mov edx, [edx+0x44]
            FFD2                 | ..                   | call edx
        */
    
        strings:
            $a   = { 58 50 6a 00 6a 00 8b 4c 24 24 51 8b 4c 24 2c 51 8b 4c 24 28 8b 09 51 8b 4c 24 24 51 8b 4c 24 20 51 6a 00 8b 00 50 8b 10 8b 52 44 ff d2 }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_split_user_pass_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::split_user_pass"
    
        /*
            8B44241C             | .D$.                 | mov eax, [esp+0x1c]
            8B00                 | ..                   | mov eax, [eax]
            50                   | P                    | push eax
            B13A                 | .:                   | mov cl, byte 0x3a
            8A10                 | ..                   | mov dl, byte [eax]
            38D1                 | 8.                   | cmp cl, dl
            740C                 | t.                   | jz no_auth
        */
    
        strings:
            $a   = { 8b 44 24 1c 8b 00 50 b1 3a 8a 10 38 d1 74 0c }
    
        condition:
            any of them
    }
    
    
    rule block_get_pstore_creds_loop_split_x86
    {
        meta:
            desc = "Metasploit::windows::x86::block_get_pstore_creds::loop_split"
    
        /*
            40                   | @                    | inc eax
            8A10                 | ..                   | mov dl, byte [eax]
            38D1                 | 8.                   | cmp cl, dl
            75F9                 | u.                   | jnz loop_split
            C60000               | ...                  | mov [eax], byte 0x00
            40                   | @                    | inc eax
            50                   | P                    | push eax
        */
    
        strings:
            $a   = { 40 8a 10 38 d1 75 f9 c6 00 00 40 50 }
    
        condition:
            any of them
    }
    
    