rule RomulusLoader_Shellcode
{
    meta:
        description = "Detects RomulusLoader shellcode based on specific code patterns"
        author = "proofpoint"
        date = "2026-03-26"
    strings:
        $code_block_1 = {
            44 89 ?? 24 20          // mov [rsp+20h], r9d
            4C 89 ?? 24 18          // mov [rsp+18h], r8
            89 ?? 24 10             // mov [rsp+10h], edx
            48 89 ?? 24 08          // mov [rsp+8], rcx
            48 81 EC 38 01 00 00    // sub rsp, 138h
            48 63 ?? 24 58 01 00 00 // movsxd rax, [rsp+158h]
            4C 8B ??                // mov r8, rax
            48 8B ?? 24 50 01 00 00 // mov rdx, [rsp+150h]
            48 8D ?? 24 20          // lea rcx, [rsp+20h]
            E8 ?? ?? ?? ??          // call sub_CC0
        }
        $code_block_2 = {
            48 63 ?? 24 48 01 00 00 // movsxd rax, [rsp+148h]
            4C 8B ??                // mov r8, rax
            48 8B ?? 24 40 01 00 00 // mov rdx, [rsp+140h]
            48 8D ?? 24 20          // lea rcx, [rsp+20h]
            E8 ?? ?? ?? ??          // call sub_DD8
            90                      // nop
            48 81 C4 38 01 00 00    // add rsp, 138h
        }
        // ntdll.dll string construction
        $code_block_3 = {
            48 83 EC 38             // sub rsp, 38h
            B9 8D 10 B7 F8          // mov ecx, 0F8B7108Dh (LoadLibraryA hash)
            C7 44 24 20 6E 74 64 6C // mov dword ptr [rsp+20h], 'ldtn'
            C7 44 24 24 6C 2E 64 6C // mov dword ptr [rsp+24h], 'ld.l'
            66 C7 44 24 28 6C 00    // mov word ptr [rsp+28h], 6Ch
            E8 ?? ?? ?? ??          // call sub_100
            48 8D ?? 24 20          // lea rcx, [rsp+20h]
            FF D0                   // call rax
            48 83 C4 38             // add rsp, 38h
            C3                      // retn
        }
        // GetProcAddress wrapper
        $code_block_4 = {
            48 89 ?? 24 08          // mov [rsp+8], rbx
            57                      // push rdi
            48 83 EC 20             // sub rsp, 20h
            48 8B ??                // mov rdi, rcx
            48 8B ??                // mov rbx, rdx
            B9 91 B8 F6 88          // mov ecx, 88F6B891h (GetProcAddress hash)
            E8 ?? ?? ?? ??          // call sub_100
            48 8B ??                // mov rdx, rbx
            48 8B ??                // mov rcx, rdi
            48 8B ?? 24 30          // mov rbx, [rsp+30h]
            48 83 C4 20             // add rsp, 20h
            5F                      // pop rdi
            48 FF E0                // jmp rax
        }
    condition:
        ( filesize < 400000 and filesize > 200000 ) and
        2 of ($code_block_*)
}