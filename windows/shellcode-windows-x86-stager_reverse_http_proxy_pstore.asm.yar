
    rule stager_reverse_http_proxy_pstore___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::__start0__"
    
        /*
            FC                   | .                    | cld
            E88C000000           | .....                | call start
        */
    
        strings:
            $a   = { fc e8 8c 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::api_call"
    
        /*
            60                   | `                    | pushad
            89E5                 | ..                   | mov ebp, esp
            31D2                 | 1.                   | xor edx, edx
            648B5230             | d.R0                 | mov edx, [fs:edx+0x30]
            8B520C               | .R.                  | mov edx, [edx+0xc]
            8B5214               | .R.                  | mov edx, [edx+0x14]
        */
    
        strings:
            $a   = { 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::next_mod"
    
        /*
            8B7228               | .r(                  | mov esi, [edx+0x28]
            0FB74A26             | ..J&                 | movzx ecx, word [edx+0x26]
            31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 8b 72 28 0f b7 4a 26 31 ff }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::loop_modname"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            3C61                 | <a                   | cmp al, 'a'
            7C02                 | |.                   | jl not_lowercase
            2C20                 | ,                    | sub al, 0x20
        */
    
        strings:
            $a   = { 31 c0 ac 3c 61 7c 02 2c 20 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::not_lowercase"
    
        /*
            C1CF0D               | ...                  | ror edi, 0xd
            01C7                 | ..                   | add edi, eax
            49                   | I                    | dec ecx
            75EF                 | u.                   | jnz loop_modname
            52                   | R                    | push edx
            57                   | W                    | push edi
            8B5210               | .R.                  | mov edx, [edx+0x10]
            8B423C               | .B<                  | mov eax, [edx+0x3c]
            01D0                 | ..                   | add eax, edx
            8B4078               | .@x                  | mov eax, [eax+0x78]
            85C0                 | ..                   | test eax, eax
            744C                 | tL                   | jz get_next_mod1
            01D0                 | ..                   | add eax, edx
            50                   | P                    | push eax
            8B4818               | .H.                  | mov ecx, [eax+0x18]
            8B5820               | .X                   | mov ebx, [eax+0x20]
            01D3                 | ..                   | add ebx, edx
        */
    
        strings:
            $a   = { c1 cf 0d 01 c7 49 75 ef 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4c 01 d0 50 8b 48 18 8b 58 20 01 d3 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::get_next_func"
    
        /*
            85C9                 | ..                   | test ecx, ecx
            743C                 | t<                   | jz get_next_mod
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi, [ebx+ecx*4]
            01D6                 | ..                   | add esi, edx
            31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 85 c9 74 3c 49 8b 34 8b 01 d6 31 ff }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::loop_funcname"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            C1CF0D               | ...                  | ror edi, 0xd
            01C7                 | ..                   | add edi, eax
            38E0                 | 8.                   | cmp al, ah
            75F4                 | u.                   | jne loop_funcname
            037DF8               | .}.                  | add edi, [ebp-8]
            3B7D24               | ;}$                  | cmp edi, [ebp+0x24]
            75E0                 | u.                   | jnz get_next_func
            58                   | X                    | pop eax
            8B5824               | .X$                  | mov ebx, [eax+0x24]
            01D3                 | ..                   | add ebx, edx
            668B0C4B             | f..K                 | mov cx, [ebx+2*ecx]
            8B581C               | .X.                  | mov ebx, [eax+0x1c]
            01D3                 | ..                   | add ebx, edx
            8B048B               | ...                  | mov eax, [ebx+4*ecx]
            01D0                 | ..                   | add eax, edx
        */
    
        strings:
            $a   = { 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e0 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::finish"
    
        /*
            89442424             | .D$$                 | mov [esp+0x24], eax
            5B                   | [                    | pop ebx
            5B                   | [                    | pop ebx
            61                   | a                    | popad
            59                   | Y                    | pop ecx
            5A                   | Z                    | pop edx
            51                   | Q                    | push ecx
            FFE0                 | ..                   | jmp eax
        */
    
        strings:
            $a   = { 89 44 24 24 5b 5b 61 59 5a 51 ff e0 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::get_next_mod1"
    
        /*
            5F                   | _                    | pop edi
            5A                   | Z                    | pop edx
            8B12                 | ..                   | mov edx, [edx]
            EB83                 | ..                   | jmp next_mod
        */
    
        strings:
            $a   = { 5f 5a 8b 12 eb 83 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_alloc_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::alloc_memory"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_alloc_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::alloc_loop"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_load_pstorec_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::load_pstorec"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_pstorecreateinstance_pstore_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::pstorecreateinstance_pstore"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_pstore_enumtypes_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::pstore.enumtypes"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_enumpstoretypes_raw_next_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::enumpstoretypes.raw_next"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_pstore_enumsubtypes_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::pstore.enumsubtypes"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_enumsubtypes_raw_next_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::enumsubtypes.raw_next"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_pstore_enumitems_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::pstore.enumitems"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_spenumitems_raw_next_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::spenumitems.raw_next"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_pstore_readitem_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::pstore.readitem"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_split_user_pass_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::split_user_pass"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_loop_split_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::loop_split"
    
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
    
    
    rule stager_reverse_http_proxy_pstore_load_wininet_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::load_wininet"
    
        /*
            686E657400           | hnet.                | push 0x0074656e
            6877696E69           | hwini                | push 0x696e6977
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_internetopen_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::internetopen"
    
        /*
            31FF                 | 1.                   | xor edi,edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            6A00                 | j.                   | push byte 0
            54                   | T                    | push esp
            683A5679A7           | h:Vy.                | push 0xa779563a	; InternetOpenA
            FFD5                 | ..                   | call ebp
            EB4B                 | .K                   | jmp short dbl_get_server_host
        */
    
        strings:
            $a   = { 31 ff 57 57 57 57 6a 00 54 68 3a 56 79 a7 ff d5 eb 4b }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_internetconnect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::internetconnect"
    
        /*
            5B                   | [                    | pop ebx
            31FF                 | 1.                   | xor edi, edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            6A03                 | j.                   | push byte 3
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            68????0000           | h\...                | push dword 4444	; Port
            53                   | S                    | push ebx
            50                   | P                    | push eax
            6857899FC6           | hW...                | push 0xc69f8957	; InternetConnectA
            FFD5                 | ..                   | call ebp
            EB34                 | .4                   | jmp get_server_uri
        */
    
        strings:
            $a   = { 5b 31 ff 57 57 6a 03 51 52 68 ?? ?? 00 00 53 50 68 57 89 9f c6 ff d5 eb 34 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_httpopenrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::httpopenrequest"
    
        /*
            59                   | Y                    | pop ecx
            31D2                 | 1.                   | xor edx, edx
            52                   | R                    | push edx
            6800022084           | h.. .                | push (0x80000000 | 0x04000000 | 0x00200000 | 0x00000200)
            52                   | R                    | push edx
            52                   | R                    | push edx
            52                   | R                    | push edx
            51                   | Q                    | push ecx
            52                   | R                    | push edx
            50                   | P                    | push eax
            68EB552E3B           | h.U.;                | push 0x3b2e55eb	; HttpOpenRequestA
            FFD5                 | ..                   | call ebp
            89C6                 | ..                   | mov esi, eax
        */
    
        strings:
            $a   = { 59 31 d2 52 68 00 02 20 84 52 52 52 51 52 50 68 eb 55 2e 3b ff d5 89 c6 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_httpsendrequest_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::httpsendrequest"
    
        /*
            31FF                 | 1.                   | xor edi, edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            56                   | V                    | push esi
            682D06187B           | h-..{                | push 0x7b18062d	; HttpSendRequestA
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            751A                 | u.                   | jnz short allocate_memory
        */
    
        strings:
            $a   = { 31 ff 57 57 57 57 56 68 2d 06 18 7b ff d5 85 c0 75 1a }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_try_it_again_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::try_it_again"
    
        /*
            4B                   | K                    | dec ebx
            7410                 | t.                   | jz failure
            EBE9                 | ..                   | jmp short httpsendrequest
        */
    
        strings:
            $a   = { 4b 74 10 eb e9 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_failure_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::failure"
    
        /*
            68F0B5A256           | h...V                | push 0x56a2b5f0	; ExitProcess
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 f0 b5 a2 56 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_allocate_memory_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::allocate_memory"
    
        /*
            6A40                 | j@                   | push byte 0x40
            6800100000           | h....                | push 0x1000
            6800004000           | h..@.                | push 0x00400000
            57                   | W                    | push edi
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 6a 40 68 00 10 00 00 68 00 00 40 00 57 68 58 a4 53 e5 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_download_prep_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::download_prep"
    
        /*
            93                   | .                    | xchg eax, ebx
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            89E7                 | ..                   | mov edi, esp
        */
    
        strings:
            $a   = { 93 53 53 89 e7 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_download_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::download_more"
    
        /*
            57                   | W                    | push edi
            6800200000           | h. ..                | push 8192
            53                   | S                    | push ebx
            56                   | V                    | push esi
            68129689E2           | h....                | push 0xe2899612	; InternetReadFile
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            74CD                 | t.                   | jz failure
            8B07                 | ..                   | mov eax, [edi]
            01C3                 | ..                   | add ebx, eax
            85C0                 | ..                   | test eax,eax
            75E5                 | u.                   | jnz download_more
            58                   | X                    | pop eax
        */
    
        strings:
            $a   = { 57 68 00 20 00 00 53 56 68 12 96 89 e2 ff d5 85 c0 74 cd 8b 07 01 c3 85 c0 75 e5 58 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_http_proxy_pstore_get_proxy_auth_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_http_proxy_pstore::get_proxy_auth"
    
        /*
            5E                   | ^                    | pop esi
            5E                   | ^                    | pop esi
            5E                   | ^                    | pop esi
            59                   | Y                    | pop ecx
            5A                   | Z                    | pop edx
            E860FFFFFF           | .`...                | call internetconnect
        */
    
        strings:
            $a   = { 5e 5e 5e 59 5a e8 60 ff ff ff }
    
        condition:
            any of them
    }
    
    