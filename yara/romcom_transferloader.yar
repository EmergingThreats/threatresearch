rule TA829_SlipScreen_Shellcode
{
    meta:
        author = "Proofpoint"
        category = "malware"
        description = "track shellcode loaded by RomCom first stage loaders called SlipScreen based on stack strings and registry checks"
        date = "2025-02-27"
        version = "1.0"


    strings:
         $reg_recent_docs_stack = {
            c7 85 ?? f? ff ff 53 4f 46 54  // mov     dword [ebp-0x45b {var_45f}], 'SOFT'
            c7 85 ?? f? ff ff 57 41 52 45  // mov     dword [ebp-0x457 {var_45b}], 'WARE'
            c7 85 ?? f? ff ff 5c 4d 69 63  // mov     dword [ebp-0x453 {var_457}], '\\Mic'
            c7 85 ?? f? ff ff 72 6f 73 6f  // mov     dword [ebp-0x44f {var_453}], 'roso'
            c7 85 ?? f? ff ff 66 74 5c 57  // mov     dword [ebp-0x44b {var_44f}], 'ft\\W'
            c7 85 ?? f? ff ff 69 6e 64 6f  // mov     dword [ebp-0x447 {var_44b}], 'indo'
            c7 85 ?? f? ff ff 77 73 5c 43  // mov     dword [ebp-0x443 {var_447}], 'ws\\C'
            c7 85 ?? f? ff ff 75 72 72 65  // mov     dword [ebp-0x43f {var_443}], 'urre'
            c7 85 ?? f? ff ff 6e 74 56 65  // mov     dword [ebp-0x43b {var_43f}], 'ntVe'
            c7 85 ?? f? ff ff 72 73 69 6f  // mov     dword [ebp-0x437 {var_43b}], 'rsio'
            c7 85 ?? f? ff ff 6e 5c 45 78  // mov     dword [ebp-0x433 {var_437}], 'n\\Ex'
            c7 85 ?? f? ff ff 70 6c 6f 72  // mov     dword [ebp-0x42f {var_433}], 'plor'
            c7 85 ?? f? ff ff [20-35]
            66 c7 85 ?? f? ff ff (63 73 | 73 00)

        }

         $reg_vals_check = {
             c7 44 24 0c 19 00 02 00  // mov     dword [esp+0xc {var_4a0_2}], 0x20019
             [0-5]                    // mov     dword [esp+0x8 {var_4a4_2}], edx  {0x0}
             89 ?4 24 04              // mov     dword [esp+0x4 {var_4a8_2}], eax {var_45f}
             c7 04 24 01 00 00 80     // mov     dword [esp {var_4ac_2}], 0x80000001  {0x80000001}
             [0-8]                    // mov     eax, dword [ebp-0x620 {var_624}]
             ff ??                    // call    ebx
             83 ec 14                 // sub     esp, 0x14

        }

          $stack_internetOpenA = {
             c7 45 ?? 49 6e 74 65  // mov     dword [ebp-0x56 {var_5a}], 0x65746e49
             c7 45 ?? 72 6e 65 74  // mov     dword [ebp-0x52 {var_56}], 0x74656e72
             c7 45 ?? 4f 70 65 6e  // mov     dword [ebp-0x4e], 0x6e65704f
             66 c7 45 ?? 41        // mov     word [ebp-0x4a], 0x41
        }

        $precheck = {
             //31 ??                 // xor     ecx, ecx  {0x0}
             c7 44 24 0c 40 00 00 00  // mov     dword [esp+0xc {var_ec_2}], 0x40
             c7 44 24 08 00 30 00 00  // mov     dword [esp+0x8 {var_f0_1}], 0x3000
             c7 44 24 04 ?? 0b 00 00  // mov     dword [esp+0x4 {var_f4_1}], 0xb74
             89 0c 24                 // mov     dword [esp {var_f8_1}], ecx  {0x0}
             ff 55 ??                 // call    dword [ebp+0x10 {arg3}]
             83 ec 10                 // sub     esp, 0x10
        }

        $stack_readFile = {
             c7 45 ?? 52 65 61 64  // mov     dword [ebp-0x4e], 0x64616552
             [0-4]
             c7 45 ?? 46 69 6c 65  // mov     dword [ebp-0x4a], 0x656c6946

        }

    condition:
        2 of ($reg*) or 3 of them
}

rule TA829_SingleCamper_Backdoor
{
    meta:
        author = "Proofpoint"
        description = "detect SingleCamper backdoor in memory"
        date = "2025-04-30"
        version = "1.0"
        category = "malware"
        hash = "54a94c7ec259104478b40fd0e6325d1f5364351e6ce1adfd79369d6438ed6ed9"

    strings:
        $a_c2_format_str = {40 40 65 78 69 73 74 [16-40] 3a 34 33 37 3a 63 2e 34 3a 30}
        $a_command_execution = "cmd.exe /U /C %s" wide
        $a_mutex = "Global\\srvmutex"
        $a_dllname = "message_module.dll"

        $error1 = "ERROR_SUCCESS" ascii
        $error2 = "ERROR_INIT_FAILED" ascii
        $error3 = "ERROR_PROXY_CONFIG" ascii
        $error4 = "ERROR_CONNECT_FAILED" ascii
        $error5 = "ERROR_REQUEST_FAILED" ascii
        $error6 = "ERROR_RESPONSE_FAILED" ascii
        $error7 = "ERROR_MEMORY_ALLOCATE" ascii
        $error8 = "ERROR_QUERY_DATA_AVAILABLE" ascii
        $error9 = "ERROR_READ_DATA" ascii
        $error10 = "ERROR_IPFS_GATEWAY_THE_SAME" ascii
        $error11 = "ERROR_GATEWAY_BUFFER_EMPTY" ascii
        $error12 = "ERROR_HTTPS_OPEN" ascii
        $error13 = "ERROR_HTTPS_CONNECT" ascii
        $error14 = "ERROR_OPEN_REQUEST" ascii
        $error15 = "ERROR_SEND_REQUEST" ascii
        $error16 = "ERROR_WRITE_DATA" ascii
        $error17 = "ERROR_REQUEST_HEADER" ascii
        $error18 = "ERROR_GEN_GUIID" ascii
        $error19 = "ERROR_CREATE_PIPE" ascii
        $error20 = "ERROR_CREATE_PROCESS" ascii
        $error21 = "ERROR_WRITE_TO_PIPE" ascii
        $error22 = "ERROR_INVALID_PARAMETER" ascii
        $error23 = "ERROR_UNKNOWN_COMMAND" ascii
        $error24 = "ERROR_CREATE_FILE" ascii
        $error25 = "ERROR_GET_COMPUTER_NAME" ascii
        $error26 = "ERROR_GET_ADAPTER_INFO" ascii
        $error27 = "ERROR_GET_MAC_ADDRESS" ascii
        $error28 = "ERROR_SAVE_FILE" ascii
        $error29 = "ERROR_LOAD_FILE" ascii
        $error30 = "ERROR_WIN_HTTP_READ_DATA" ascii
        $error31 = "ERROR_SEND_DATA" ascii
        $error32 = "ERROR_UNSUCCESSFUL" ascii
        $error33 = "ERROR_CREATE_EVENT" ascii
        $error34 = "ERROR_SET_CALLBACK" ascii
        $error35 = "ERROR_SET_OPTION" ascii
        $error36 = "ERROR_GET_FILE_SIZE" ascii
        $error37 = "ERROR_READ_FILE" ascii
        $error38 = "ERROR_INIT_BRYPT_HANDLE" ascii
        $error39 = "ERROR_COPY_FILE" ascii
        $error40 = "ERROR_DOMAIN_NOT_FOUND" ascii
        $error41 = "ERROR_CONVERT_STR_TO_WSTR" ascii


    condition:
        2 of ($a*) or 30 of ($error*)
}

rule TA829_Shared_Equity_Decode_Routine
{
    meta:
        author = "Proofpoint"
        description = "detect shared API resolution and string decryption code consistent across SingleCamper, DustyHammock samples"
        date = "2025-04-30"
        version = "1.0"
        category = "malware"
        hash = "07b9e353239c4c057115e8871adc3cfb42467998c6b737b28435ecc9405001c9"
        hash = "7fc65b23e0a85f548e4268b77b66a3c9f3d08b9c1817c99bc1336d51d36e1ec6"
        hash = "8f3b065e6aa6bc220867cdcb1c250c69b2d46422c51f66f25091f6cab5d043de"

    strings:
        $string_decode_routine = {
            //48 c1 c8 20  // ror     rax, 0x20
            //4d 0f af c1  // imul    r8, r9
            //49 8b d0     // mov     rdx, r8
            49 c1 e0 1f  // shl     r8, 0x1f
            48 c1 ea 21  // shr     rdx, 0x21
            49 0b d0     // or      rdx, r8
            48 03 c2     // add     rax, rdx
            48 8b c8     // mov     rcx, rax
            48 c1 e0 21  // shl     rax, 0x21
            48 c1 e9 1f  // shr     rcx, 0x1f
            48 0b c8     // or      rcx, rax
            0f b6 c1     // movzx   eax, cl

            }
        $resolve_api_algos = {
            //69 d1 8f 30 e4 a9  // imul    edx, ecx, 0xa9e4308f
            //45 8d 52 01        // lea     r10d, [r10+0x1]
            c1 ca 11           // ror     edx, 0x11
            81 c2 ?? ?? ?? ??  // add     edx, 0xa9e4308f
            03 c2              // add     eax, edx
            c1 c8 0f           // ror     eax, 0xf
            41 0f af c0        // imul    eax, r8d
            47 0f be 04 0a     // movsx   r8d, byte [r10+r9]
            03 c0              // add     eax, eax
            8b d0              // mov     edx, eax
            c1 c8 0e           // ror     eax, 0xe
            c1 ca 10           // ror     edx, 0x10

            }
    condition:
        1 of them
}

rule TA829_DustyHammock_Components_Memory
{
    meta:
        author = "Proofpoint"
        description = "track TA829's DustyHammock modules based on leftover path names and beaconing strigns"
        date = "2025-04-30"
        version = "1.0"
        hash = "6d5226cba687d99ce14eda8de290edd470e79436625618559c8db1458a53666c"
        hash = "7e51eb44cfd945f4a155707f773fae3207ebfb59d45ea866ba69bd9bc28dfc32"
        hash = "f5f2761278163a1a813356666cb305fe37806f5f633b2a5475997f10d24fb3d4"
        hash = "cd526475391c375e8e40f0146146672928db9bbf210acb41e0fd41381cd5eb9a"
        category = "malware"

    strings:
        $ = "src\\bot" ascii wide
        $ = "@@exists" ascii wide
    condition:
        all of them
}
