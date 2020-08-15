
    rule win32_stage_revert_lavdatasegment_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_revert::lavdatasegment"
    
        /*
            616476617069333200   | advapi32.            | #ommited# db "advapi32", 0x00
            FF5508               | .U.                  | call [ebp + 8]
            50                   | P                    | push eax
            682AC8DE50           | h*..P                | push 0x50dec82a
            FF5504               | .U.                  | call [ebp + 4]
            FFD0                 | ..                   | call eax
        */
    
        strings:
            $a   = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ff 55 08 50 68 2a c8 de 50 ff 55 04 ff d0 }
    
        condition:
            any of them
    }
    
    