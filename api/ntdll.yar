
rule ntdll_A_SHAFinal
{
    meta:
        desc = "Metasploit::API::ntdll::A_SHAFinal"

    /*
        68C3C007B2           | push 0xb207c0c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 c0 07 b2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_A_SHAInit
{
    meta:
        desc = "Metasploit::API::ntdll::A_SHAInit"

    /*
        6810D460FE           | push 0xfe60d410
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 d4 60 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_A_SHAUpdate
{
    meta:
        desc = "Metasploit::API::ntdll::A_SHAUpdate"

    /*
        68BF14A10D           | push 0x0da114bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 14 a1 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcAdjustCompletionListConcurrencyCount
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcAdjustCompletionListConcurrencyCount"

    /*
        6837534F62           | push 0x624f5337
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 53 4f 62 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcFreeCompletionListMessage
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcFreeCompletionListMessage"

    /*
        6850607B41           | push 0x417b6050
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 60 7b 41 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcGetCompletionListLastMessageInformation
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcGetCompletionListLastMessageInformation"

    /*
        689DC5EED0           | push 0xd0eec59d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d c5 ee d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcGetCompletionListMessageAttributes
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcGetCompletionListMessageAttributes"

    /*
        687F3EEE59           | push 0x59ee3e7f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 3e ee 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcGetHeaderSize
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcGetHeaderSize"

    /*
        68012F349B           | push 0x9b342f01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 2f 34 9b ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcGetMessageAttribute
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcGetMessageAttribute"

    /*
        6891D0C78D           | push 0x8dc7d091
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 d0 c7 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcGetMessageFromCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcGetMessageFromCompletionList"

    /*
        6851A37A1F           | push 0x1f7aa351
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 a3 7a 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcGetOutstandingCompletionListMessageCount
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcGetOutstandingCompletionListMessageCount"

    /*
        685CA83558           | push 0x5835a85c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c a8 35 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcInitializeMessageAttribute
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcInitializeMessageAttribute"

    /*
        68D87373A4           | push 0xa47373d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 73 73 a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcMaxAllowedMessageLength
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcMaxAllowedMessageLength"

    /*
        682100EB34           | push 0x34eb0021
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 00 eb 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcRegisterCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcRegisterCompletionList"

    /*
        68524328FC           | push 0xfc284352
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 43 28 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcRegisterCompletionListWorkerThread
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcRegisterCompletionListWorkerThread"

    /*
        68CC7BD5CB           | push 0xcbd57bcc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 7b d5 cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcRundownCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcRundownCompletionList"

    /*
        686D890002           | push 0x0200896d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 89 00 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcUnregisterCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcUnregisterCompletionList"

    /*
        68AAE9A3B9           | push 0xb9a3e9aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa e9 a3 b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_AlpcUnregisterCompletionListWorkerThread
{
    meta:
        desc = "Metasploit::API::ntdll::AlpcUnregisterCompletionListWorkerThread"

    /*
        6848E18FA3           | push 0xa38fe148
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 e1 8f a3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ApiSetQueryApiSetPresence
{
    meta:
        desc = "Metasploit::API::ntdll::ApiSetQueryApiSetPresence"

    /*
        68BFCF0CFB           | push 0xfb0ccfbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf cf 0c fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ApiSetQueryApiSetPresenceEx
{
    meta:
        desc = "Metasploit::API::ntdll::ApiSetQueryApiSetPresenceEx"

    /*
        68BE44085F           | push 0x5f0844be
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 44 08 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrAllocateCaptureBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::CsrAllocateCaptureBuffer"

    /*
        688D7F408E           | push 0x8e407f8d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 7f 40 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrAllocateMessagePointer
{
    meta:
        desc = "Metasploit::API::ntdll::CsrAllocateMessagePointer"

    /*
        682EE30224           | push 0x2402e32e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e e3 02 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrCaptureMessageBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::CsrCaptureMessageBuffer"

    /*
        685607B272           | push 0x72b20756
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 07 b2 72 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrCaptureMessageMultiUnicodeStringsInPlace
{
    meta:
        desc = "Metasploit::API::ntdll::CsrCaptureMessageMultiUnicodeStringsInPlace"

    /*
        68301F7241           | push 0x41721f30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 1f 72 41 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrCaptureMessageString
{
    meta:
        desc = "Metasploit::API::ntdll::CsrCaptureMessageString"

    /*
        6895C99EF8           | push 0xf89ec995
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 c9 9e f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrCaptureTimeout
{
    meta:
        desc = "Metasploit::API::ntdll::CsrCaptureTimeout"

    /*
        688A34C4B8           | push 0xb8c4348a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 34 c4 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrClientCallServer
{
    meta:
        desc = "Metasploit::API::ntdll::CsrClientCallServer"

    /*
        68D19AEDAB           | push 0xabed9ad1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 9a ed ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrClientConnectToServer
{
    meta:
        desc = "Metasploit::API::ntdll::CsrClientConnectToServer"

    /*
        68E35B8343           | push 0x43835be3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 5b 83 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrFreeCaptureBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::CsrFreeCaptureBuffer"

    /*
        68D8C79010           | push 0x1090c7d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 c7 90 10 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrGetProcessId
{
    meta:
        desc = "Metasploit::API::ntdll::CsrGetProcessId"

    /*
        6838B81BB5           | push 0xb51bb838
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 b8 1b b5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrIdentifyAlertableThread
{
    meta:
        desc = "Metasploit::API::ntdll::CsrIdentifyAlertableThread"

    /*
        686FC29BA8           | push 0xa89bc26f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f c2 9b a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrSetPriorityClass
{
    meta:
        desc = "Metasploit::API::ntdll::CsrSetPriorityClass"

    /*
        688AF30795           | push 0x9507f38a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a f3 07 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_CsrVerifyRegion
{
    meta:
        desc = "Metasploit::API::ntdll::CsrVerifyRegion"

    /*
        68E7CB2715           | push 0x1527cbe7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 cb 27 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgBreakPoint
{
    meta:
        desc = "Metasploit::API::ntdll::DbgBreakPoint"

    /*
        6848C5BE1D           | push 0x1dbec548
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 c5 be 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgPrint
{
    meta:
        desc = "Metasploit::API::ntdll::DbgPrint"

    /*
        68385FDD59           | push 0x59dd5f38
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 5f dd 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgPrintEx
{
    meta:
        desc = "Metasploit::API::ntdll::DbgPrintEx"

    /*
        68D5222C13           | push 0x132c22d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 22 2c 13 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgPrintReturnControlC
{
    meta:
        desc = "Metasploit::API::ntdll::DbgPrintReturnControlC"

    /*
        6833C4FF23           | push 0x23ffc433
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 c4 ff 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgPrompt
{
    meta:
        desc = "Metasploit::API::ntdll::DbgPrompt"

    /*
        686950837F           | push 0x7f835069
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 50 83 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgQueryDebugFilterState
{
    meta:
        desc = "Metasploit::API::ntdll::DbgQueryDebugFilterState"

    /*
        681C03D08D           | push 0x8dd0031c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 03 d0 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgSetDebugFilterState
{
    meta:
        desc = "Metasploit::API::ntdll::DbgSetDebugFilterState"

    /*
        68671A589E           | push 0x9e581a67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 1a 58 9e ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiConnectToDbg
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiConnectToDbg"

    /*
        68D2F66DC6           | push 0xc66df6d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 f6 6d c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiContinue
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiContinue"

    /*
        68DF2052C5           | push 0xc55220df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 20 52 c5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiConvertStateChangeStructure
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiConvertStateChangeStructure"

    /*
        680050285B           | push 0x5b285000
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 50 28 5b ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiConvertStateChangeStructureEx
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiConvertStateChangeStructureEx"

    /*
        68D654E865           | push 0x65e854d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 54 e8 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiDebugActiveProcess
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiDebugActiveProcess"

    /*
        685617845E           | push 0x5e841756
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 17 84 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiGetThreadDebugObject
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiGetThreadDebugObject"

    /*
        68833707EE           | push 0xee073783
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 37 07 ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiIssueRemoteBreakin
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiIssueRemoteBreakin"

    /*
        68A2DB1EF4           | push 0xf41edba2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 db 1e f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiRemoteBreakin
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiRemoteBreakin"

    /*
        6889971E9A           | push 0x9a1e9789
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 97 1e 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiSetThreadDebugObject
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiSetThreadDebugObject"

    /*
        68843707AE           | push 0xae073784
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 37 07 ae ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiStopDebugging
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiStopDebugging"

    /*
        68BA7D75D6           | push 0xd6757dba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 7d 75 d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUiWaitStateChange
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUiWaitStateChange"

    /*
        68F8A72802           | push 0x0228a7f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 a7 28 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_DbgUserBreakPoint
{
    meta:
        desc = "Metasploit::API::ntdll::DbgUserBreakPoint"

    /*
        68A51BB815           | push 0x15b81ba5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 1b b8 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwCheckCoverage
{
    meta:
        desc = "Metasploit::API::ntdll::EtwCheckCoverage"

    /*
        68C999352B           | push 0x2b3599c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 99 35 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwCreateTraceInstanceId
{
    meta:
        desc = "Metasploit::API::ntdll::EtwCreateTraceInstanceId"

    /*
        68173BDBB8           | push 0xb8db3b17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 3b db b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwDeliverDataBlock
{
    meta:
        desc = "Metasploit::API::ntdll::EtwDeliverDataBlock"

    /*
        68F2630FF5           | push 0xf50f63f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 63 0f f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEnumerateProcessRegGuids
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEnumerateProcessRegGuids"

    /*
        6872A2DE0E           | push 0x0edea272
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 a2 de 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventActivityIdControl
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventActivityIdControl"

    /*
        6888C1282C           | push 0x2c28c188
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 c1 28 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventEnabled
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventEnabled"

    /*
        68D29DE92B           | push 0x2be99dd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 9d e9 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventProviderEnabled
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventProviderEnabled"

    /*
        6828C25FB8           | push 0xb85fc228
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 c2 5f b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventRegister
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventRegister"

    /*
        68EEF06121           | push 0x2161f0ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee f0 61 21 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventSetInformation
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventSetInformation"

    /*
        682E9304C6           | push 0xc604932e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 93 04 c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventUnregister
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventUnregister"

    /*
        6803C0F142           | push 0x42f1c003
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 c0 f1 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWrite
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWrite"

    /*
        688D190B5E           | push 0x5e0b198d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 19 0b 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWriteEndScenario
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWriteEndScenario"

    /*
        6824ADB5FF           | push 0xffb5ad24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 ad b5 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWriteEx
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWriteEx"

    /*
        6816B89A1E           | push 0x1e9ab816
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 b8 9a 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWriteFull
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWriteFull"

    /*
        684674223C           | push 0x3c227446
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 74 22 3c ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWriteNoRegistration
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWriteNoRegistration"

    /*
        6878FF30C5           | push 0xc530ff78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 ff 30 c5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWriteStartScenario
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWriteStartScenario"

    /*
        6805AE0144           | push 0x4401ae05
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 ae 01 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWriteString
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWriteString"

    /*
        68CDD01D1E           | push 0x1e1dd0cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd d0 1d 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwEventWriteTransfer
{
    meta:
        desc = "Metasploit::API::ntdll::EtwEventWriteTransfer"

    /*
        6809E0D4A1           | push 0xa1d4e009
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 e0 d4 a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwGetTraceEnableFlags
{
    meta:
        desc = "Metasploit::API::ntdll::EtwGetTraceEnableFlags"

    /*
        68E823AAE3           | push 0xe3aa23e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 23 aa e3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwGetTraceEnableLevel
{
    meta:
        desc = "Metasploit::API::ntdll::EtwGetTraceEnableLevel"

    /*
        686BB3710D           | push 0x0d71b36b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b b3 71 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwGetTraceLoggerHandle
{
    meta:
        desc = "Metasploit::API::ntdll::EtwGetTraceLoggerHandle"

    /*
        681B389A99           | push 0x999a381b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 38 9a 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwLogTraceEvent
{
    meta:
        desc = "Metasploit::API::ntdll::EtwLogTraceEvent"

    /*
        686612EE95           | push 0x95ee1266
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 12 ee 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwNotificationRegister
{
    meta:
        desc = "Metasploit::API::ntdll::EtwNotificationRegister"

    /*
        68EAD36615           | push 0x1566d3ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea d3 66 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwNotificationUnregister
{
    meta:
        desc = "Metasploit::API::ntdll::EtwNotificationUnregister"

    /*
        68007F2A44           | push 0x442a7f00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 7f 2a 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwProcessPrivateLoggerRequest
{
    meta:
        desc = "Metasploit::API::ntdll::EtwProcessPrivateLoggerRequest"

    /*
        68C6D8B021           | push 0x21b0d8c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 d8 b0 21 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwRegisterSecurityProvider
{
    meta:
        desc = "Metasploit::API::ntdll::EtwRegisterSecurityProvider"

    /*
        6816EAC945           | push 0x45c9ea16
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 ea c9 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwRegisterTraceGuidsA
{
    meta:
        desc = "Metasploit::API::ntdll::EtwRegisterTraceGuidsA"

    /*
        688958D589           | push 0x89d55889
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 58 d5 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwRegisterTraceGuidsW
{
    meta:
        desc = "Metasploit::API::ntdll::EtwRegisterTraceGuidsW"

    /*
        688958858A           | push 0x8a855889
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 58 85 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwReplyNotification
{
    meta:
        desc = "Metasploit::API::ntdll::EtwReplyNotification"

    /*
        68006826A7           | push 0xa7266800
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 68 26 a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwSendNotification
{
    meta:
        desc = "Metasploit::API::ntdll::EtwSendNotification"

    /*
        682213D4EB           | push 0xebd41322
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 13 d4 eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwSetMark
{
    meta:
        desc = "Metasploit::API::ntdll::EtwSetMark"

    /*
        687BAE8EBC           | push 0xbc8eae7b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b ae 8e bc ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwTraceEventInstance
{
    meta:
        desc = "Metasploit::API::ntdll::EtwTraceEventInstance"

    /*
        6829FB67C1           | push 0xc167fb29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 fb 67 c1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwTraceMessage
{
    meta:
        desc = "Metasploit::API::ntdll::EtwTraceMessage"

    /*
        684A58C606           | push 0x06c6584a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 58 c6 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwTraceMessageVa
{
    meta:
        desc = "Metasploit::API::ntdll::EtwTraceMessageVa"

    /*
        68C16BB24C           | push 0x4cb26bc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 6b b2 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwUnregisterTraceGuids
{
    meta:
        desc = "Metasploit::API::ntdll::EtwUnregisterTraceGuids"

    /*
        6843507AC7           | push 0xc77a5043
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 50 7a c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwWriteUMSecurityEvent
{
    meta:
        desc = "Metasploit::API::ntdll::EtwWriteUMSecurityEvent"

    /*
        6860D5F194           | push 0x94f1d560
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 d5 f1 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwpCreateEtwThread
{
    meta:
        desc = "Metasploit::API::ntdll::EtwpCreateEtwThread"

    /*
        688EE2ED71           | push 0x71ede28e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e e2 ed 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EtwpGetCpuSpeed
{
    meta:
        desc = "Metasploit::API::ntdll::EtwpGetCpuSpeed"

    /*
        68DBB5A8EC           | push 0xeca8b5db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db b5 a8 ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_EvtIntReportAuthzEventAndSourceAsync
{
    meta:
        desc = "Metasploit::API::ntdll::EvtIntReportAuthzEventAndSourceAsync"

    /*
        688D923249           | push 0x4932928d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 92 32 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_EvtIntReportEventAndSourceAsync
{
    meta:
        desc = "Metasploit::API::ntdll::EvtIntReportEventAndSourceAsync"

    /*
        6887F0D577           | push 0x77d5f087
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 f0 d5 77 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ExpInterlockedPopEntrySListEnd
{
    meta:
        desc = "Metasploit::API::ntdll::ExpInterlockedPopEntrySListEnd"

    /*
        680088F736           | push 0x36f78800
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 88 f7 36 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ExpInterlockedPopEntrySListFault
{
    meta:
        desc = "Metasploit::API::ntdll::ExpInterlockedPopEntrySListFault"

    /*
        68CD8E95FB           | push 0xfb958ecd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 8e 95 fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ExpInterlockedPopEntrySListResume
{
    meta:
        desc = "Metasploit::API::ntdll::ExpInterlockedPopEntrySListResume"

    /*
        686CDDE70F           | push 0x0fe7dd6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c dd e7 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_KiRaiseUserExceptionDispatcher
{
    meta:
        desc = "Metasploit::API::ntdll::KiRaiseUserExceptionDispatcher"

    /*
        680B7788CE           | push 0xce88770b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 77 88 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_KiUserApcDispatcher
{
    meta:
        desc = "Metasploit::API::ntdll::KiUserApcDispatcher"

    /*
        68901EB362           | push 0x62b31e90
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 1e b3 62 ff d5 }

    condition:
        any of them
}

    
rule ntdll_KiUserCallbackDispatcher
{
    meta:
        desc = "Metasploit::API::ntdll::KiUserCallbackDispatcher"

    /*
        687BF895A6           | push 0xa695f87b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b f8 95 a6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_KiUserExceptionDispatcher
{
    meta:
        desc = "Metasploit::API::ntdll::KiUserExceptionDispatcher"

    /*
        68C7054E5D           | push 0x5d4e05c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 05 4e 5d ff d5 }

    condition:
        any of them
}

    
rule ntdll_KiUserInvertedFunctionTable
{
    meta:
        desc = "Metasploit::API::ntdll::KiUserInvertedFunctionTable"

    /*
        68C7ACF5A2           | push 0xa2f5acc7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 ac f5 a2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrAccessResource
{
    meta:
        desc = "Metasploit::API::ntdll::LdrAccessResource"

    /*
        68A231482C           | push 0x2c4831a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 31 48 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrAddDllDirectory
{
    meta:
        desc = "Metasploit::API::ntdll::LdrAddDllDirectory"

    /*
        68C5394B71           | push 0x714b39c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 39 4b 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrAddLoadAsDataTable
{
    meta:
        desc = "Metasploit::API::ntdll::LdrAddLoadAsDataTable"

    /*
        68861A1D2A           | push 0x2a1d1a86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 1a 1d 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrAddRefDll
{
    meta:
        desc = "Metasploit::API::ntdll::LdrAddRefDll"

    /*
        68DEAB1230           | push 0x3012abde
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de ab 12 30 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrAppxHandleIntegrityFailure
{
    meta:
        desc = "Metasploit::API::ntdll::LdrAppxHandleIntegrityFailure"

    /*
        68939681EA           | push 0xea819693
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 96 81 ea ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrCallEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::LdrCallEnclave"

    /*
        68DA940B64           | push 0x640b94da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 94 0b 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrControlFlowGuardEnforced
{
    meta:
        desc = "Metasploit::API::ntdll::LdrControlFlowGuardEnforced"

    /*
        688C87402C           | push 0x2c40878c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c 87 40 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrCreateEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::LdrCreateEnclave"

    /*
        68E66C1CCD           | push 0xcd1c6ce6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 6c 1c cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrDeleteEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::LdrDeleteEnclave"

    /*
        68176CAACD           | push 0xcdaa6c17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 6c aa cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrDisableThreadCalloutsForDll
{
    meta:
        desc = "Metasploit::API::ntdll::LdrDisableThreadCalloutsForDll"

    /*
        683A440569           | push 0x6905443a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 44 05 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrEnumResources
{
    meta:
        desc = "Metasploit::API::ntdll::LdrEnumResources"

    /*
        6832BEAFD2           | push 0xd2afbe32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 be af d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrEnumerateLoadedModules
{
    meta:
        desc = "Metasploit::API::ntdll::LdrEnumerateLoadedModules"

    /*
        682790D5FE           | push 0xfed59027
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 90 d5 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrFastFailInLoaderCallout
{
    meta:
        desc = "Metasploit::API::ntdll::LdrFastFailInLoaderCallout"

    /*
        680F67455C           | push 0x5c45670f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 67 45 5c ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrFindEntryForAddress
{
    meta:
        desc = "Metasploit::API::ntdll::LdrFindEntryForAddress"

    /*
        6843249715           | push 0x15972443
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 24 97 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrFindResourceDirectory_U
{
    meta:
        desc = "Metasploit::API::ntdll::LdrFindResourceDirectory_U"

    /*
        6866D5E0AE           | push 0xaee0d566
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 d5 e0 ae ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrFindResourceEx_U
{
    meta:
        desc = "Metasploit::API::ntdll::LdrFindResourceEx_U"

    /*
        685D5EE853           | push 0x53e85e5d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 5e e8 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrFindResource_U
{
    meta:
        desc = "Metasploit::API::ntdll::LdrFindResource_U"

    /*
        688CB6CC75           | push 0x75ccb68c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c b6 cc 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrFlushAlternateResourceModules
{
    meta:
        desc = "Metasploit::API::ntdll::LdrFlushAlternateResourceModules"

    /*
        682B44A6D0           | push 0xd0a6442b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 44 a6 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetDllDirectory
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetDllDirectory"

    /*
        68C53D4B39           | push 0x394b3dc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 3d 4b 39 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetDllFullName
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetDllFullName"

    /*
        682FA7E7BE           | push 0xbee7a72f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f a7 e7 be ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetDllHandle
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetDllHandle"

    /*
        6897D4B6B0           | push 0xb0b6d497
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 d4 b6 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetDllHandleByMapping
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetDllHandleByMapping"

    /*
        6839904974           | push 0x74499039
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 90 49 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetDllHandleByName
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetDllHandleByName"

    /*
        683FDBF079           | push 0x79f0db3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f db f0 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetDllHandleEx
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetDllHandleEx"

    /*
        68AB7A89C9           | push 0xc9897aab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 7a 89 c9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetDllPath
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetDllPath"

    /*
        68586B7660           | push 0x60766b58
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 6b 76 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetFailureData
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetFailureData"

    /*
        68E9F0E2A4           | push 0xa4e2f0e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 f0 e2 a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetFileNameFromLoadAsDataTable
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetFileNameFromLoadAsDataTable"

    /*
        68D75CFFD5           | push 0xd5ff5cd7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 5c ff d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetKnownDllSectionHandle
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetKnownDllSectionHandle"

    /*
        689EC9173F           | push 0x3f17c99e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e c9 17 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetProcedureAddress
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetProcedureAddress"

    /*
        68B541D95E           | push 0x5ed941b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 41 d9 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetProcedureAddressEx
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetProcedureAddressEx"

    /*
        6817C22452           | push 0x5224c217
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 c2 24 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrGetProcedureAddressForCaller
{
    meta:
        desc = "Metasploit::API::ntdll::LdrGetProcedureAddressForCaller"

    /*
        6802609203           | push 0x03926002
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 60 92 03 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrInitShimEngineDynamic
{
    meta:
        desc = "Metasploit::API::ntdll::LdrInitShimEngineDynamic"

    /*
        68B517FD0F           | push 0x0ffd17b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 17 fd 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrInitializeEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::LdrInitializeEnclave"

    /*
        68266ECD5C           | push 0x5ccd6e26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 6e cd 5c ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrInitializeThunk
{
    meta:
        desc = "Metasploit::API::ntdll::LdrInitializeThunk"

    /*
        68BCE4553F           | push 0x3f55e4bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc e4 55 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrIsModuleSxsRedirected
{
    meta:
        desc = "Metasploit::API::ntdll::LdrIsModuleSxsRedirected"

    /*
        68749CCD92           | push 0x92cd9c74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 9c cd 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrLoadAlternateResourceModule
{
    meta:
        desc = "Metasploit::API::ntdll::LdrLoadAlternateResourceModule"

    /*
        68DC9DEAD6           | push 0xd6ea9ddc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 9d ea d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrLoadAlternateResourceModuleEx
{
    meta:
        desc = "Metasploit::API::ntdll::LdrLoadAlternateResourceModuleEx"

    /*
        68F5CB7B56           | push 0x567bcbf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 cb 7b 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrLoadDll
{
    meta:
        desc = "Metasploit::API::ntdll::LdrLoadDll"

    /*
        68139CBFBD           | push 0xbdbf9c13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 9c bf bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrLoadEnclaveModule
{
    meta:
        desc = "Metasploit::API::ntdll::LdrLoadEnclaveModule"

    /*
        6894E83643           | push 0x4336e894
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 e8 36 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrLockLoaderLock
{
    meta:
        desc = "Metasploit::API::ntdll::LdrLockLoaderLock"

    /*
        687AAD49FB           | push 0xfb49ad7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a ad 49 fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrOpenImageFileOptionsKey
{
    meta:
        desc = "Metasploit::API::ntdll::LdrOpenImageFileOptionsKey"

    /*
        6899954109           | push 0x09419599
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 95 41 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrProcessInitializationComplete
{
    meta:
        desc = "Metasploit::API::ntdll::LdrProcessInitializationComplete"

    /*
        68322A5E12           | push 0x125e2a32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 2a 5e 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrProcessRelocationBlock
{
    meta:
        desc = "Metasploit::API::ntdll::LdrProcessRelocationBlock"

    /*
        680568A9B9           | push 0xb9a96805
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 68 a9 b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrProcessRelocationBlockEx
{
    meta:
        desc = "Metasploit::API::ntdll::LdrProcessRelocationBlockEx"

    /*
        682D562E06           | push 0x062e562d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 56 2e 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrQueryImageFileExecutionOptions
{
    meta:
        desc = "Metasploit::API::ntdll::LdrQueryImageFileExecutionOptions"

    /*
        68F75FDB1E           | push 0x1edb5ff7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 5f db 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrQueryImageFileExecutionOptionsEx
{
    meta:
        desc = "Metasploit::API::ntdll::LdrQueryImageFileExecutionOptionsEx"

    /*
        68C752AC52           | push 0x52ac52c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 52 ac 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrQueryImageFileKeyOption
{
    meta:
        desc = "Metasploit::API::ntdll::LdrQueryImageFileKeyOption"

    /*
        68645E311B           | push 0x1b315e64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 5e 31 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrQueryModuleServiceTags
{
    meta:
        desc = "Metasploit::API::ntdll::LdrQueryModuleServiceTags"

    /*
        688DB499CF           | push 0xcf99b48d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d b4 99 cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrQueryOptionalDelayLoadedAPI
{
    meta:
        desc = "Metasploit::API::ntdll::LdrQueryOptionalDelayLoadedAPI"

    /*
        68E8A97571           | push 0x7175a9e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 a9 75 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrQueryProcessModuleInformation
{
    meta:
        desc = "Metasploit::API::ntdll::LdrQueryProcessModuleInformation"

    /*
        68BF6F774E           | push 0x4e776fbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 6f 77 4e ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrRegisterDllNotification
{
    meta:
        desc = "Metasploit::API::ntdll::LdrRegisterDllNotification"

    /*
        682C5A7A8A           | push 0x8a7a5a2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 5a 7a 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrRemoveDllDirectory
{
    meta:
        desc = "Metasploit::API::ntdll::LdrRemoveDllDirectory"

    /*
        68D9656D73           | push 0x736d65d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 65 6d 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrRemoveLoadAsDataTable
{
    meta:
        desc = "Metasploit::API::ntdll::LdrRemoveLoadAsDataTable"

    /*
        68DF5E2152           | push 0x52215edf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 5e 21 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrResFindResource
{
    meta:
        desc = "Metasploit::API::ntdll::LdrResFindResource"

    /*
        688D485E07           | push 0x075e488d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 48 5e 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrResFindResourceDirectory
{
    meta:
        desc = "Metasploit::API::ntdll::LdrResFindResourceDirectory"

    /*
        688798892C           | push 0x2c899887
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 98 89 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrResGetRCConfig
{
    meta:
        desc = "Metasploit::API::ntdll::LdrResGetRCConfig"

    /*
        68DF0B5C94           | push 0x945c0bdf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 0b 5c 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrResRelease
{
    meta:
        desc = "Metasploit::API::ntdll::LdrResRelease"

    /*
        68DABC431F           | push 0x1f43bcda
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da bc 43 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrResSearchResource
{
    meta:
        desc = "Metasploit::API::ntdll::LdrResSearchResource"

    /*
        68B3E9E329           | push 0x29e3e9b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 e9 e3 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrResolveDelayLoadedAPI
{
    meta:
        desc = "Metasploit::API::ntdll::LdrResolveDelayLoadedAPI"

    /*
        68BC259E3F           | push 0x3f9e25bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 25 9e 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrResolveDelayLoadsFromDll
{
    meta:
        desc = "Metasploit::API::ntdll::LdrResolveDelayLoadsFromDll"

    /*
        68BB76C232           | push 0x32c276bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 76 c2 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrRscIsTypeExist
{
    meta:
        desc = "Metasploit::API::ntdll::LdrRscIsTypeExist"

    /*
        68EEB24F49           | push 0x494fb2ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee b2 4f 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrSetAppCompatDllRedirectionCallback
{
    meta:
        desc = "Metasploit::API::ntdll::LdrSetAppCompatDllRedirectionCallback"

    /*
        68455FE18E           | push 0x8ee15f45
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 5f e1 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrSetDefaultDllDirectories
{
    meta:
        desc = "Metasploit::API::ntdll::LdrSetDefaultDllDirectories"

    /*
        682A291EF7           | push 0xf71e292a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 29 1e f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrSetDllDirectory
{
    meta:
        desc = "Metasploit::API::ntdll::LdrSetDllDirectory"

    /*
        68C73D4BB9           | push 0xb94b3dc7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 3d 4b b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrSetDllManifestProber
{
    meta:
        desc = "Metasploit::API::ntdll::LdrSetDllManifestProber"

    /*
        680560ED02           | push 0x02ed6005
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 60 ed 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrSetImplicitPathOptions
{
    meta:
        desc = "Metasploit::API::ntdll::LdrSetImplicitPathOptions"

    /*
        68257B3DE9           | push 0xe93d7b25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 7b 3d e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrSetMUICacheType
{
    meta:
        desc = "Metasploit::API::ntdll::LdrSetMUICacheType"

    /*
        68EF338704           | push 0x048733ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 33 87 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrShutdownProcess
{
    meta:
        desc = "Metasploit::API::ntdll::LdrShutdownProcess"

    /*
        68CED0BF6A           | push 0x6abfd0ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce d0 bf 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrShutdownThread
{
    meta:
        desc = "Metasploit::API::ntdll::LdrShutdownThread"

    /*
        685B2B62F9           | push 0xf9622b5b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 2b 62 f9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrStandardizeSystemPath
{
    meta:
        desc = "Metasploit::API::ntdll::LdrStandardizeSystemPath"

    /*
        68B9354E96           | push 0x964e35b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 35 4e 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrSystemDllInitBlock
{
    meta:
        desc = "Metasploit::API::ntdll::LdrSystemDllInitBlock"

    /*
        6889C57E9C           | push 0x9c7ec589
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 c5 7e 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrUnloadAlternateResourceModule
{
    meta:
        desc = "Metasploit::API::ntdll::LdrUnloadAlternateResourceModule"

    /*
        68E916B76E           | push 0x6eb716e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 16 b7 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrUnloadAlternateResourceModuleEx
{
    meta:
        desc = "Metasploit::API::ntdll::LdrUnloadAlternateResourceModuleEx"

    /*
        681B0F9A49           | push 0x499a0f1b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 0f 9a 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrUnloadDll
{
    meta:
        desc = "Metasploit::API::ntdll::LdrUnloadDll"

    /*
        68DC2C873A           | push 0x3a872cdc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 2c 87 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrUnlockLoaderLock
{
    meta:
        desc = "Metasploit::API::ntdll::LdrUnlockLoaderLock"

    /*
        68AAC63B94           | push 0x943bc6aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa c6 3b 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrUnregisterDllNotification
{
    meta:
        desc = "Metasploit::API::ntdll::LdrUnregisterDllNotification"

    /*
        68F3D6431B           | push 0x1b43d6f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 d6 43 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrUpdatePackageSearchPath
{
    meta:
        desc = "Metasploit::API::ntdll::LdrUpdatePackageSearchPath"

    /*
        689E7B410C           | push 0x0c417b9e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 7b 41 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrVerifyImageMatchesChecksum
{
    meta:
        desc = "Metasploit::API::ntdll::LdrVerifyImageMatchesChecksum"

    /*
        68D08BCAEB           | push 0xebca8bd0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 8b ca eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrVerifyImageMatchesChecksumEx
{
    meta:
        desc = "Metasploit::API::ntdll::LdrVerifyImageMatchesChecksumEx"

    /*
        68FA48778E           | push 0x8e7748fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 48 77 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrpResGetMappingSize
{
    meta:
        desc = "Metasploit::API::ntdll::LdrpResGetMappingSize"

    /*
        6820FD2935           | push 0x3529fd20
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 fd 29 35 ff d5 }

    condition:
        any of them
}

    
rule ntdll_LdrpResGetResourceDirectory
{
    meta:
        desc = "Metasploit::API::ntdll::LdrpResGetResourceDirectory"

    /*
        684D24400E           | push 0x0e40244d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 24 40 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_MD4Final
{
    meta:
        desc = "Metasploit::API::ntdll::MD4Final"

    /*
        6833C8D06B           | push 0x6bd0c833
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 c8 d0 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_MD4Init
{
    meta:
        desc = "Metasploit::API::ntdll::MD4Init"

    /*
        6849CB4E1F           | push 0x1f4ecb49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 cb 4e 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_MD4Update
{
    meta:
        desc = "Metasploit::API::ntdll::MD4Update"

    /*
        6808E31E49           | push 0x491ee308
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 e3 1e 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_MD5Final
{
    meta:
        desc = "Metasploit::API::ntdll::MD5Final"

    /*
        6833C8D46B           | push 0x6bd4c833
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 c8 d4 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_MD5Init
{
    meta:
        desc = "Metasploit::API::ntdll::MD5Init"

    /*
        684ACB4E9F           | push 0x9f4ecb4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a cb 4e 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_MD5Update
{
    meta:
        desc = "Metasploit::API::ntdll::MD5Update"

    /*
        6828E31E49           | push 0x491ee328
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 e3 1e 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NlsAnsiCodePage
{
    meta:
        desc = "Metasploit::API::ntdll::NlsAnsiCodePage"

    /*
        68593BB882           | push 0x82b83b59
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 3b b8 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NlsMbCodePageTag
{
    meta:
        desc = "Metasploit::API::ntdll::NlsMbCodePageTag"

    /*
        680C7CB537           | push 0x37b57c0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 7c b5 37 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NlsMbOemCodePageTag
{
    meta:
        desc = "Metasploit::API::ntdll::NlsMbOemCodePageTag"

    /*
        68538CB41E           | push 0x1eb48c53
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 8c b4 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAcceptConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAcceptConnectPort"

    /*
        681AEAB905           | push 0x05b9ea1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a ea b9 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAccessCheck
{
    meta:
        desc = "Metasploit::API::ntdll::NtAccessCheck"

    /*
        68EADD49DA           | push 0xda49ddea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea dd 49 da ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAccessCheckAndAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtAccessCheckAndAuditAlarm"

    /*
        68E487F298           | push 0x98f287e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 87 f2 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAccessCheckByType
{
    meta:
        desc = "Metasploit::API::ntdll::NtAccessCheckByType"

    /*
        684BE23DCF           | push 0xcf3de24b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b e2 3d cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAccessCheckByTypeAndAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtAccessCheckByTypeAndAuditAlarm"

    /*
        68E6016DC9           | push 0xc96d01e6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 01 6d c9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAccessCheckByTypeResultList
{
    meta:
        desc = "Metasploit::API::ntdll::NtAccessCheckByTypeResultList"

    /*
        68BD1D1B2D           | push 0x2d1b1dbd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 1d 1b 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAccessCheckByTypeResultListAndAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtAccessCheckByTypeResultListAndAuditAlarm"

    /*
        6884F09B82           | push 0x829bf084
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 f0 9b 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAccessCheckByTypeResultListAndAuditAlarmByHandle
{
    meta:
        desc = "Metasploit::API::ntdll::NtAccessCheckByTypeResultListAndAuditAlarmByHandle"

    /*
        6879232D02           | push 0x022d2379
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 23 2d 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAcquireProcessActivityReference
{
    meta:
        desc = "Metasploit::API::ntdll::NtAcquireProcessActivityReference"

    /*
        685B5BC3B9           | push 0xb9c35b5b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 5b c3 b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAddAtom
{
    meta:
        desc = "Metasploit::API::ntdll::NtAddAtom"

    /*
        6862BB989F           | push 0x9f98bb62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 bb 98 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAddAtomEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtAddAtomEx"

    /*
        68672D0382           | push 0x82032d67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 2d 03 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAddBootEntry
{
    meta:
        desc = "Metasploit::API::ntdll::NtAddBootEntry"

    /*
        68FC6D0456           | push 0x56046dfc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 6d 04 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAddDriverEntry
{
    meta:
        desc = "Metasploit::API::ntdll::NtAddDriverEntry"

    /*
        68FE720B55           | push 0x550b72fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 72 0b 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAdjustGroupsToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtAdjustGroupsToken"

    /*
        682C2055A6           | push 0xa655202c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 20 55 a6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAdjustPrivilegesToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtAdjustPrivilegesToken"

    /*
        684D7EC91D           | push 0x1dc97e4d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 7e c9 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAdjustTokenClaimsAndDeviceGroups
{
    meta:
        desc = "Metasploit::API::ntdll::NtAdjustTokenClaimsAndDeviceGroups"

    /*
        68E4B58B75           | push 0x758bb5e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 b5 8b 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlertResumeThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlertResumeThread"

    /*
        68B56F4D32           | push 0x324d6fb5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 6f 4d 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlertThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlertThread"

    /*
        689F8D96A6           | push 0xa6968d9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 8d 96 a6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlertThreadByThreadId
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlertThreadByThreadId"

    /*
        68672C8B79           | push 0x798b2c67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 2c 8b 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAllocateLocallyUniqueId
{
    meta:
        desc = "Metasploit::API::ntdll::NtAllocateLocallyUniqueId"

    /*
        681651BF15           | push 0x15bf5116
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 51 bf 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAllocateReserveObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtAllocateReserveObject"

    /*
        6848646A53           | push 0x536a6448
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 64 6a 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAllocateUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::ntdll::NtAllocateUserPhysicalPages"

    /*
        68893C623D           | push 0x3d623c89
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 3c 62 3d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAllocateUuids
{
    meta:
        desc = "Metasploit::API::ntdll::NtAllocateUuids"

    /*
        68E07D2A98           | push 0x982a7de0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 7d 2a 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAllocateVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtAllocateVirtualMemory"

    /*
        682DB18894           | push 0x9488b12d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d b1 88 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAllocateVirtualMemoryEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtAllocateVirtualMemoryEx"

    /*
        6824A000BE           | push 0xbe00a024
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 a0 00 be ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcAcceptConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcAcceptConnectPort"

    /*
        68F1AF5ACB           | push 0xcb5aaff1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 af 5a cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcCancelMessage
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcCancelMessage"

    /*
        6828C32AF1           | push 0xf12ac328
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 c3 2a f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcConnectPort"

    /*
        686E69CAA8           | push 0xa8ca696e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e 69 ca a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcConnectPortEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcConnectPortEx"

    /*
        6869B06ECE           | push 0xce6eb069
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 b0 6e ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcCreatePort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcCreatePort"

    /*
        6842DB277E           | push 0x7e27db42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 db 27 7e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcCreatePortSection
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcCreatePortSection"

    /*
        6809FC5D87           | push 0x875dfc09
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 fc 5d 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcCreateResourceReserve
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcCreateResourceReserve"

    /*
        6832FEAF55           | push 0x55affe32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 fe af 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcCreateSectionView
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcCreateSectionView"

    /*
        684CA4D187           | push 0x87d1a44c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c a4 d1 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcCreateSecurityContext
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcCreateSecurityContext"

    /*
        682D754BA8           | push 0xa84b752d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 75 4b a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcDeletePortSection
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcDeletePortSection"

    /*
        68120C5167           | push 0x67510c12
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 0c 51 67 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcDeleteResourceReserve
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcDeleteResourceReserve"

    /*
        68318CB086           | push 0x86b08c31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 8c b0 86 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcDeleteSectionView
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcDeleteSectionView"

    /*
        6855B4C467           | push 0x67c4b455
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 b4 c4 67 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcDeleteSecurityContext
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcDeleteSecurityContext"

    /*
        682C034CD9           | push 0xd94c032c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 03 4c d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcDisconnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcDisconnectPort"

    /*
        6867B3C6D5           | push 0xd5c6b367
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 b3 c6 d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcImpersonateClientContainerOfPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcImpersonateClientContainerOfPort"

    /*
        68A0ED365A           | push 0x5a36eda0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 ed 36 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcImpersonateClientOfPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcImpersonateClientOfPort"

    /*
        6891B2BA20           | push 0x20bab291
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 b2 ba 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcOpenSenderProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcOpenSenderProcess"

    /*
        680CB972AD           | push 0xad72b90c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c b9 72 ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcOpenSenderThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcOpenSenderThread"

    /*
        68B2F36956           | push 0x5669f3b2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 f3 69 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcQueryInformation
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcQueryInformation"

    /*
        688F29E88A           | push 0x8ae8298f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 29 e8 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcQueryInformationMessage
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcQueryInformationMessage"

    /*
        68F2B21F0F           | push 0x0f1fb2f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 b2 1f 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcRevokeSecurityContext
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcRevokeSecurityContext"

    /*
        68E416D3DB           | push 0xdbd316e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 16 d3 db ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcSendWaitReceivePort
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcSendWaitReceivePort"

    /*
        68AF033D1E           | push 0x1e3d03af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 03 3d 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAlpcSetInformation
{
    meta:
        desc = "Metasploit::API::ntdll::NtAlpcSetInformation"

    /*
        684DF08C08           | push 0x088cf04d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d f0 8c 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtApphelpCacheControl
{
    meta:
        desc = "Metasploit::API::ntdll::NtApphelpCacheControl"

    /*
        6884F51382           | push 0x8213f584
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 f5 13 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAreMappedFilesTheSame
{
    meta:
        desc = "Metasploit::API::ntdll::NtAreMappedFilesTheSame"

    /*
        68AB7CCF68           | push 0x68cf7cab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 7c cf 68 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAssignProcessToJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtAssignProcessToJobObject"

    /*
        683FEAC009           | push 0x09c0ea3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f ea c0 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtAssociateWaitCompletionPacket
{
    meta:
        desc = "Metasploit::API::ntdll::NtAssociateWaitCompletionPacket"

    /*
        684CC37BA7           | push 0xa77bc34c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c c3 7b a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCallEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::NtCallEnclave"

    /*
        68FA640A59           | push 0x590a64fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 64 0a 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCallbackReturn
{
    meta:
        desc = "Metasploit::API::ntdll::NtCallbackReturn"

    /*
        684A9C0342           | push 0x42039c4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 9c 03 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCancelIoFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtCancelIoFile"

    /*
        6853F4B0B4           | push 0xb4b0f453
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 f4 b0 b4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCancelIoFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtCancelIoFileEx"

    /*
        68AC6911C8           | push 0xc81169ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac 69 11 c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCancelSynchronousIoFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtCancelSynchronousIoFile"

    /*
        6856EEDE42           | push 0x42deee56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 ee de 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCancelTimer
{
    meta:
        desc = "Metasploit::API::ntdll::NtCancelTimer"

    /*
        68B2446AE8           | push 0xe86a44b2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 44 6a e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCancelTimer2
{
    meta:
        desc = "Metasploit::API::ntdll::NtCancelTimer2"

    /*
        68D06547AB           | push 0xab4765d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 65 47 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCancelWaitCompletionPacket
{
    meta:
        desc = "Metasploit::API::ntdll::NtCancelWaitCompletionPacket"

    /*
        6890675AC5           | push 0xc55a6790
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 67 5a c5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtClearEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtClearEvent"

    /*
        680304F5B3           | push 0xb3f50403
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 04 f5 b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtClose
{
    meta:
        desc = "Metasploit::API::ntdll::NtClose"

    /*
        68F1FD98A1           | push 0xa198fdf1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 fd 98 a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCloseObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtCloseObjectAuditAlarm"

    /*
        685CBA3784           | push 0x8437ba5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c ba 37 84 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCommitComplete
{
    meta:
        desc = "Metasploit::API::ntdll::NtCommitComplete"

    /*
        6861B52949           | push 0x4929b561
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 b5 29 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCommitEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtCommitEnlistment"

    /*
        68793E3DE5           | push 0xe53d3e79
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 3e 3d e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCommitRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtCommitRegistryTransaction"

    /*
        68EEF9DD9C           | push 0x9cddf9ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee f9 dd 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCommitTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtCommitTransaction"

    /*
        6824E33176           | push 0x7631e324
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 e3 31 76 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCompactKeys
{
    meta:
        desc = "Metasploit::API::ntdll::NtCompactKeys"

    /*
        6846614C65           | push 0x654c6146
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 61 4c 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCompareObjects
{
    meta:
        desc = "Metasploit::API::ntdll::NtCompareObjects"

    /*
        685C317367           | push 0x6773315c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 31 73 67 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCompareSigningLevels
{
    meta:
        desc = "Metasploit::API::ntdll::NtCompareSigningLevels"

    /*
        68D8649831           | push 0x319864d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 64 98 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCompareTokens
{
    meta:
        desc = "Metasploit::API::ntdll::NtCompareTokens"

    /*
        68BDCEE7E1           | push 0xe1e7cebd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd ce e7 e1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCompleteConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtCompleteConnectPort"

    /*
        6893D4AD66           | push 0x66add493
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 d4 ad 66 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCompressKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtCompressKey"

    /*
        6865DE86B1           | push 0xb186de65
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 de 86 b1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtConnectPort"

    /*
        6806B85477           | push 0x7754b806
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 b8 54 77 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtContinue
{
    meta:
        desc = "Metasploit::API::ntdll::NtContinue"

    /*
        68BD7284E2           | push 0xe28472bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 72 84 e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
{
    meta:
        desc = "Metasploit::API::ntdll::NtConvertBetweenAuxiliaryCounterAndPerformanceCounter"

    /*
        68A9D78DD9           | push 0xd98dd7a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 d7 8d d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateCrossVmEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateCrossVmEvent"

    /*
        689FF58405           | push 0x0584f59f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f f5 84 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateDebugObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateDebugObject"

    /*
        68AF157CBA           | push 0xba7c15af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 15 7c ba ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateDirectoryObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateDirectoryObject"

    /*
        684E51CF7B           | push 0x7bcf514e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 51 cf 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateDirectoryObjectEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateDirectoryObjectEx"

    /*
        685EA8A88F           | push 0x8fa8a85e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e a8 a8 8f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateEnclave"

    /*
        68E374D00C           | push 0x0cd074e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 74 d0 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateEnlistment"

    /*
        682A1F1F3F           | push 0x3f1f1f2a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 1f 1f 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateEvent"

    /*
        68CFD05E96           | push 0x965ed0cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf d0 5e 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateEventPair"

    /*
        680C37C74F           | push 0x4fc7370c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 37 c7 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateFile"

    /*
        68933382BB           | push 0xbb823393
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 33 82 bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateIRTimer
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateIRTimer"

    /*
        681C41C8A4           | push 0xa4c8411c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 41 c8 a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateIoCompletion"

    /*
        6884B94A07           | push 0x074ab984
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 b9 4a 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateJobObject"

    /*
        6823FD5C50           | push 0x505cfd23
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 fd 5c 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateJobSet
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateJobSet"

    /*
        68B1A15058           | push 0x5850a1b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 a1 50 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateKey"

    /*
        6887A58A4C           | push 0x4c8aa587
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 a5 8a 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateKeyTransacted
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateKeyTransacted"

    /*
        6823220C10           | push 0x100c2223
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 22 0c 10 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateKeyedEvent"

    /*
        689466E34B           | push 0x4be36694
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 66 e3 4b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateLowBoxToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateLowBoxToken"

    /*
        682A0F0114           | push 0x14010f2a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 0f 01 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateMailslotFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateMailslotFile"

    /*
        6895C0EF0C           | push 0x0cefc095
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 c0 ef 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateMutant
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateMutant"

    /*
        68F4C35D74           | push 0x745dc3f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 c3 5d 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateNamedPipeFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateNamedPipeFile"

    /*
        6809E36D2A           | push 0x2a6de309
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 e3 6d 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreatePagingFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreatePagingFile"

    /*
        68A6469081           | push 0x819046a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 46 90 81 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreatePartition
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreatePartition"

    /*
        6826D2C1CA           | push 0xcac1d226
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 d2 c1 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreatePort
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreatePort"

    /*
        6813D5FAC7           | push 0xc7fad513
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 d5 fa c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreatePrivateNamespace
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreatePrivateNamespace"

    /*
        685B6C531E           | push 0x1e536c5b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 6c 53 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateProcess"

    /*
        6889E54F15           | push 0x154fe589
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 e5 4f 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateProcessEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateProcessEx"

    /*
        6844B7CDEF           | push 0xefcdb744
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 b7 cd ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateProfile
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateProfile"

    /*
        68C913E01C           | push 0x1ce013c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 13 e0 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateProfileEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateProfileEx"

    /*
        684647D9D3           | push 0xd3d94746
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 47 d9 d3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateRegistryTransaction"

    /*
        68BD7CE3AB           | push 0xabe37cbd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 7c e3 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateResourceManager"

    /*
        68F54CAAB3           | push 0xb3aa4cf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 4c aa b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateSection
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateSection"

    /*
        68E3F4F41C           | push 0x1cf4f4e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 f4 f4 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateSectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateSectionEx"

    /*
        68C68D11D9           | push 0xd9118dc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 8d 11 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateSemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateSemaphore"

    /*
        684A2A2D5A           | push 0x5a2d2a4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 2a 2d 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateSymbolicLinkObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateSymbolicLinkObject"

    /*
        68B7FAF9F5           | push 0xf5f9fab7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 fa f9 f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateThread"

    /*
        68ADA0F9FB           | push 0xfbf9a0ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad a0 f9 fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateThreadEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateThreadEx"

    /*
        683E803C9A           | push 0x9a3c803e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 80 3c 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateTimer
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateTimer"

    /*
        6896FE4D26           | push 0x264dfe96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 fe 4d 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateTimer2
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateTimer2"

    /*
        68EE54697A           | push 0x7a6954ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 54 69 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateToken"

    /*
        68965E2E22           | push 0x222e5e96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 5e 2e 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateTokenEx"

    /*
        6887FA6B27           | push 0x276bfa87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 fa 6b 27 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateTransaction"

    /*
        6833B2B47B           | push 0x7bb4b233
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 b2 b4 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateTransactionManager"

    /*
        68EEA607B5           | push 0xb507a6ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee a6 07 b5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateUserProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateUserProcess"

    /*
        68D9BE21B8           | push 0xb821bed9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 be 21 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateWaitCompletionPacket
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateWaitCompletionPacket"

    /*
        68CDDE164D           | push 0x4d16decd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd de 16 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateWaitablePort
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateWaitablePort"

    /*
        686EA15C87           | push 0x875ca16e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e a1 5c 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateWnfStateName
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateWnfStateName"

    /*
        680D781DBE           | push 0xbe1d780d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 78 1d be ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtCreateWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::NtCreateWorkerFactory"

    /*
        680AC95EDD           | push 0xdd5ec90a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a c9 5e dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDebugActiveProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtDebugActiveProcess"

    /*
        68CDABD0E5           | push 0xe5d0abcd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd ab d0 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDebugContinue
{
    meta:
        desc = "Metasploit::API::ntdll::NtDebugContinue"

    /*
        6821E14985           | push 0x8549e121
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 e1 49 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDelayExecution
{
    meta:
        desc = "Metasploit::API::ntdll::NtDelayExecution"

    /*
        68D7BE3001           | push 0x0130bed7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 be 30 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteAtom
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteAtom"

    /*
        68D37CC118           | push 0x18c17cd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 7c c1 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteBootEntry
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteBootEntry"

    /*
        68B4CE9812           | push 0x1298ceb4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 ce 98 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteDriverEntry
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteDriverEntry"

    /*
        682DA1237A           | push 0x7a23a12d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d a1 23 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteFile"

    /*
        6813CC8102           | push 0x0281cc13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 cc 81 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteKey"

    /*
        6867AE9A3F           | push 0x3f9aae67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 ae 9a 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteObjectAuditAlarm"

    /*
        689CF34889           | push 0x8948f39c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c f3 48 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeletePrivateNamespace
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeletePrivateNamespace"

    /*
        6860F44C8E           | push 0x8e4cf460
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 f4 4c 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteValueKey"

    /*
        68D6CBB463           | push 0x63b4cbd6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 cb b4 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteWnfStateData"

    /*
        6865D9433E           | push 0x3e43d965
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 d9 43 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeleteWnfStateName
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeleteWnfStateName"

    /*
        68A577643E           | push 0x3e6477a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 77 64 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDeviceIoControlFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtDeviceIoControlFile"

    /*
        6895375E28           | push 0x285e3795
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 37 5e 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDisableLastKnownGood
{
    meta:
        desc = "Metasploit::API::ntdll::NtDisableLastKnownGood"

    /*
        68A679E193           | push 0x93e179a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 79 e1 93 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDisplayString
{
    meta:
        desc = "Metasploit::API::ntdll::NtDisplayString"

    /*
        68E0981059           | push 0x591098e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 98 10 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDrawText
{
    meta:
        desc = "Metasploit::API::ntdll::NtDrawText"

    /*
        68DF23C751           | push 0x51c723df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 23 c7 51 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDuplicateObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtDuplicateObject"

    /*
        6832C2C7FA           | push 0xfac7c232
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 c2 c7 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtDuplicateToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtDuplicateToken"

    /*
        68635E4F76           | push 0x764f5e63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 5e 4f 76 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtEnableLastKnownGood
{
    meta:
        desc = "Metasploit::API::ntdll::NtEnableLastKnownGood"

    /*
        6871308E92           | push 0x928e3071
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 30 8e 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtEnumerateBootEntries
{
    meta:
        desc = "Metasploit::API::ntdll::NtEnumerateBootEntries"

    /*
        68883C5A32           | push 0x325a3c88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 3c 5a 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtEnumerateDriverEntries
{
    meta:
        desc = "Metasploit::API::ntdll::NtEnumerateDriverEntries"

    /*
        6861492123           | push 0x23214961
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 49 21 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtEnumerateKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtEnumerateKey"

    /*
        687733CDB9           | push 0xb9cd3377
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 33 cd b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtEnumerateSystemEnvironmentValuesEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtEnumerateSystemEnvironmentValuesEx"

    /*
        680D7C0810           | push 0x10087c0d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 7c 08 10 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtEnumerateTransactionObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtEnumerateTransactionObject"

    /*
        6860864583           | push 0x83458660
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 86 45 83 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtEnumerateValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtEnumerateValueKey"

    /*
        685E0ECEA0           | push 0xa0ce0e5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 0e ce a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtExtendSection
{
    meta:
        desc = "Metasploit::API::ntdll::NtExtendSection"

    /*
        6844C5121D           | push 0x1d12c544
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 c5 12 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFilterBootOption
{
    meta:
        desc = "Metasploit::API::ntdll::NtFilterBootOption"

    /*
        68D6B3FC72           | push 0x72fcb3d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 b3 fc 72 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFilterToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtFilterToken"

    /*
        68B49468F5           | push 0xf56894b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 94 68 f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFilterTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtFilterTokenEx"

    /*
        68FC81F9F5           | push 0xf5f981fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 81 f9 f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFindAtom
{
    meta:
        desc = "Metasploit::API::ntdll::NtFindAtom"

    /*
        6875F0C1F1           | push 0xf1c1f075
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 f0 c1 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushBuffersFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushBuffersFile"

    /*
        6874AD5D09           | push 0x095dad74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 ad 5d 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushBuffersFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushBuffersFileEx"

    /*
        6801B23FF3           | push 0xf33fb201
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 b2 3f f3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushInstallUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushInstallUILanguage"

    /*
        68AEE3021C           | push 0x1c02e3ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae e3 02 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushInstructionCache
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushInstructionCache"

    /*
        68AFB15C94           | push 0x945cb1af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af b1 5c 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushKey"

    /*
        685C5E4020           | push 0x20405e5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 5e 40 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushProcessWriteBuffers
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushProcessWriteBuffers"

    /*
        6830F926D8           | push 0xd826f930
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 f9 26 d8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushVirtualMemory"

    /*
        68A34B7C80           | push 0x807c4ba3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 4b 7c 80 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFlushWriteBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::NtFlushWriteBuffer"

    /*
        68B5C33151           | push 0x5131c3b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 c3 31 51 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFreeUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::ntdll::NtFreeUserPhysicalPages"

    /*
        6801327641           | push 0x41763201
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 32 76 41 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFreeVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtFreeVirtualMemory"

    /*
        686CF2F8EB           | push 0xebf8f26c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c f2 f8 eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFreezeRegistry
{
    meta:
        desc = "Metasploit::API::ntdll::NtFreezeRegistry"

    /*
        6821B72138           | push 0x3821b721
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 b7 21 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFreezeTransactions
{
    meta:
        desc = "Metasploit::API::ntdll::NtFreezeTransactions"

    /*
        682418149A           | push 0x9a141824
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 18 14 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtFsControlFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtFsControlFile"

    /*
        681BE80D2D           | push 0x2d0de81b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b e8 0d 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetCachedSigningLevel
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetCachedSigningLevel"

    /*
        68AB047BF6           | push 0xf67b04ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 04 7b f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetCompleteWnfStateSubscription
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetCompleteWnfStateSubscription"

    /*
        68A116B1FD           | push 0xfdb116a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 16 b1 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetContextThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetContextThread"

    /*
        68FE60395B           | push 0x5b3960fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 60 39 5b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetCurrentProcessorNumber
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetCurrentProcessorNumber"

    /*
        688343456F           | push 0x6f454383
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 43 45 6f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetCurrentProcessorNumberEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetCurrentProcessorNumberEx"

    /*
        689B35256D           | push 0x6d25359b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 35 25 6d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetDevicePowerState
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetDevicePowerState"

    /*
        6811698C2B           | push 0x2b8c6911
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 69 8c 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetMUIRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetMUIRegistryInfo"

    /*
        68FD5B628A           | push 0x8a625bfd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 5b 62 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetNextProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetNextProcess"

    /*
        68AF516FF5           | push 0xf56f51af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 51 6f f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetNextThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetNextThread"

    /*
        68B15C7EE9           | push 0xe97e5cb1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 5c 7e e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetNlsSectionPtr
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetNlsSectionPtr"

    /*
        6889258762           | push 0x62872589
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 25 87 62 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetNotificationResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetNotificationResourceManager"

    /*
        680F472E6C           | push 0x6c2e470f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 47 2e 6c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetTickCount
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetTickCount"

    /*
        68DF0BBB51           | push 0x51bb0bdf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 0b bb 51 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtGetWriteWatch
{
    meta:
        desc = "Metasploit::API::ntdll::NtGetWriteWatch"

    /*
        682BB5E1B8           | push 0xb8e1b52b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b b5 e1 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtImpersonateAnonymousToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtImpersonateAnonymousToken"

    /*
        68B7F20843           | push 0x4308f2b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 f2 08 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtImpersonateClientOfPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtImpersonateClientOfPort"

    /*
        680E9C5F09           | push 0x095f9c0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 9c 5f 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtImpersonateThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtImpersonateThread"

    /*
        68069E6158           | push 0x58619e06
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 9e 61 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtInitializeEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::NtInitializeEnclave"

    /*
        6821424D9D           | push 0x9d4d4221
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 42 4d 9d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtInitializeNlsFiles
{
    meta:
        desc = "Metasploit::API::ntdll::NtInitializeNlsFiles"

    /*
        68958C058E           | push 0x8e058c95
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 8c 05 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtInitializeRegistry
{
    meta:
        desc = "Metasploit::API::ntdll::NtInitializeRegistry"

    /*
        68062F0622           | push 0x22062f06
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 2f 06 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtInitiatePowerAction
{
    meta:
        desc = "Metasploit::API::ntdll::NtInitiatePowerAction"

    /*
        684A59D670           | push 0x70d6594a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 59 d6 70 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtIsProcessInJob
{
    meta:
        desc = "Metasploit::API::ntdll::NtIsProcessInJob"

    /*
        68BE623337           | push 0x373362be
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 62 33 37 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtIsSystemResumeAutomatic
{
    meta:
        desc = "Metasploit::API::ntdll::NtIsSystemResumeAutomatic"

    /*
        68B8D28901           | push 0x0189d2b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 d2 89 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtIsUILanguageComitted
{
    meta:
        desc = "Metasploit::API::ntdll::NtIsUILanguageComitted"

    /*
        689F4F83A8           | push 0xa8834f9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 4f 83 a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtListenPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtListenPort"

    /*
        687A8FBE95           | push 0x95be8f7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 8f be 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLoadDriver
{
    meta:
        desc = "Metasploit::API::ntdll::NtLoadDriver"

    /*
        683C4A2C91           | push 0x912c4a3c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 4a 2c 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLoadEnclaveData
{
    meta:
        desc = "Metasploit::API::ntdll::NtLoadEnclaveData"

    /*
        68775D0123           | push 0x23015d77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 5d 01 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLoadKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtLoadKey"

    /*
        6840EA26CE           | push 0xce26ea40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 ea 26 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLoadKey2
{
    meta:
        desc = "Metasploit::API::ntdll::NtLoadKey2"

    /*
        68B593B6D7           | push 0xd7b693b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 93 b6 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLoadKey3
{
    meta:
        desc = "Metasploit::API::ntdll::NtLoadKey3"

    /*
        68B593BED7           | push 0xd7be93b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 93 be d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLoadKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtLoadKeyEx"

    /*
        68F2E48E25           | push 0x258ee4f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 e4 8e 25 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLockFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtLockFile"

    /*
        6879405661           | push 0x61564079
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 40 56 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLockProductActivationKeys
{
    meta:
        desc = "Metasploit::API::ntdll::NtLockProductActivationKeys"

    /*
        684D59525A           | push 0x5a52594d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 59 52 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLockRegistryKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtLockRegistryKey"

    /*
        686BCCD635           | push 0x35d6cc6b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b cc d6 35 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtLockVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtLockVirtualMemory"

    /*
        689C0AF6AB           | push 0xabf60a9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 0a f6 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtMakePermanentObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtMakePermanentObject"

    /*
        68163F108E           | push 0x8e103f16
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 3f 10 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtMakeTemporaryObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtMakeTemporaryObject"

    /*
        68E71FAC0F           | push 0x0fac1fe7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 1f ac 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtManageHotPatch
{
    meta:
        desc = "Metasploit::API::ntdll::NtManageHotPatch"

    /*
        6820B144E5           | push 0xe544b120
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 b1 44 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtManagePartition
{
    meta:
        desc = "Metasploit::API::ntdll::NtManagePartition"

    /*
        68278E270F           | push 0x0f278e27
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 8e 27 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtMapCMFModule
{
    meta:
        desc = "Metasploit::API::ntdll::NtMapCMFModule"

    /*
        6833D0C134           | push 0x34c1d033
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 d0 c1 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtMapUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::ntdll::NtMapUserPhysicalPages"

    /*
        6866298DEA           | push 0xea8d2966
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 29 8d ea ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtMapUserPhysicalPagesScatter
{
    meta:
        desc = "Metasploit::API::ntdll::NtMapUserPhysicalPagesScatter"

    /*
        6815BE1F2A           | push 0x2a1fbe15
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 be 1f 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtMapViewOfSection
{
    meta:
        desc = "Metasploit::API::ntdll::NtMapViewOfSection"

    /*
        68FBBF401B           | push 0x1b40bffb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb bf 40 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtMapViewOfSectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtMapViewOfSectionEx"

    /*
        68C653046C           | push 0x6c0453c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 53 04 6c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtModifyBootEntry
{
    meta:
        desc = "Metasploit::API::ntdll::NtModifyBootEntry"

    /*
        68FAF67C2E           | push 0x2e7cf6fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa f6 7c 2e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtModifyDriverEntry
{
    meta:
        desc = "Metasploit::API::ntdll::NtModifyDriverEntry"

    /*
        68B4B22D73           | push 0x732db2b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 b2 2d 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtNotifyChangeDirectoryFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtNotifyChangeDirectoryFile"

    /*
        68754DB675           | push 0x75b64d75
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 4d b6 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtNotifyChangeDirectoryFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtNotifyChangeDirectoryFileEx"

    /*
        681CB26709           | push 0x0967b21c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c b2 67 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtNotifyChangeKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtNotifyChangeKey"

    /*
        680B6A64FD           | push 0xfd646a0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 6a 64 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtNotifyChangeMultipleKeys
{
    meta:
        desc = "Metasploit::API::ntdll::NtNotifyChangeMultipleKeys"

    /*
        68D579A009           | push 0x09a079d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 79 a0 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtNotifyChangeSession
{
    meta:
        desc = "Metasploit::API::ntdll::NtNotifyChangeSession"

    /*
        68F92F3DB9           | push 0xb93d2ff9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 2f 3d b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenDirectoryObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenDirectoryObject"

    /*
        6806A3DD95           | push 0x95dda306
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 a3 dd 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenEnlistment"

    /*
        689AC23B73           | push 0x733bc29a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a c2 3b 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenEvent"

    /*
        68AF1798FE           | push 0xfe9817af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 17 98 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenEventPair"

    /*
        688F3D35E4           | push 0xe4353d8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 3d 35 e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenFile"

    /*
        689A405EE4           | push 0xe45e409a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 40 5e e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenIoCompletion"

    /*
        689195730E           | push 0x0e739591
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 95 73 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenJobObject"

    /*
        68A603CBE4           | push 0xe4cb03a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 03 cb e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenKey"

    /*
        68A28A2BCE           | push 0xce2b8aa2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 8a 2b ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenKeyEx"

    /*
        6872FDB626           | push 0x26b6fd72
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 fd b6 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenKeyTransacted
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenKeyTransacted"

    /*
        686A5B74F0           | push 0xf0745b6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 5b 74 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenKeyTransactedEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenKeyTransactedEx"

    /*
        687B2FEBB8           | push 0xb8eb2f7b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b 2f eb b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenKeyedEvent"

    /*
        68040A0080           | push 0x80000a04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 0a 00 80 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenMutant
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenMutant"

    /*
        68BE0561AB           | push 0xab6105be
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 05 61 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenObjectAuditAlarm"

    /*
        680A3C10A7           | push 0xa7103c0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 3c 10 a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenPartition
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenPartition"

    /*
        68AAD82F5F           | push 0x5f2fd8aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa d8 2f 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenPrivateNamespace
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenPrivateNamespace"

    /*
        68CE3C14AC           | push 0xac143cce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce 3c 14 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenProcess"

    /*
        68A39DA123           | push 0x23a19da3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 9d a1 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenProcessToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenProcessToken"

    /*
        68E4E3948A           | push 0x8a94e3e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 e3 94 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenProcessTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenProcessTokenEx"

    /*
        68E24D0D41           | push 0x410d4de2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 4d 0d 41 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenRegistryTransaction"

    /*
        685EFEFE90           | push 0x90fefe5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e fe fe 90 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenResourceManager"

    /*
        68AD9EB8CD           | push 0xcdb89ead
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 9e b8 cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenSection
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenSection"

    /*
        68FDAC462B           | push 0x2b46acfd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd ac 46 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenSemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenSemaphore"

    /*
        68CD309BEE           | push 0xee9b30cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 30 9b ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenSession
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenSession"

    /*
        68059D462B           | push 0x2b469d05
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 9d 46 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenSymbolicLinkObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenSymbolicLinkObject"

    /*
        685B172E66           | push 0x662e175b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 17 2e 66 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenThread"

    /*
        6877E2FC32           | push 0x32fce277
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 e2 fc 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenThreadToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenThreadToken"

    /*
        684E864292           | push 0x9242864e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 86 42 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenThreadTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenThreadTokenEx"

    /*
        6863E8752C           | push 0x2c75e863
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 e8 75 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenTimer
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenTimer"

    /*
        687745878E           | push 0x8e874577
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 45 87 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenTransaction"

    /*
        6818533697           | push 0x97365318
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 53 36 97 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtOpenTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtOpenTransactionManager"

    /*
        6891C33B25           | push 0x253bc391
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 c3 3b 25 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPlugPlayControl
{
    meta:
        desc = "Metasploit::API::ntdll::NtPlugPlayControl"

    /*
        68AC3C56DC           | push 0xdc563cac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac 3c 56 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPowerInformation
{
    meta:
        desc = "Metasploit::API::ntdll::NtPowerInformation"

    /*
        686A98ACAB           | push 0xabac986a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 98 ac ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPrePrepareComplete
{
    meta:
        desc = "Metasploit::API::ntdll::NtPrePrepareComplete"

    /*
        6823E529F8           | push 0xf829e523
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 e5 29 f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPrePrepareEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtPrePrepareEnlistment"

    /*
        68252F49A5           | push 0xa5492f25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 2f 49 a5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPrepareComplete
{
    meta:
        desc = "Metasploit::API::ntdll::NtPrepareComplete"

    /*
        68FEFB3704           | push 0x0437fbfe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe fb 37 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPrepareEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtPrepareEnlistment"

    /*
        68E8E5CEA8           | push 0xa8cee5e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 e5 ce a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPrivilegeCheck
{
    meta:
        desc = "Metasploit::API::ntdll::NtPrivilegeCheck"

    /*
        68CA63CBEC           | push 0xeccb63ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 63 cb ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPrivilegeObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtPrivilegeObjectAuditAlarm"

    /*
        680219C804           | push 0x04c81902
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 19 c8 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPrivilegedServiceAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::NtPrivilegedServiceAuditAlarm"

    /*
        6851F33D85           | push 0x853df351
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 f3 3d 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPropagationComplete
{
    meta:
        desc = "Metasploit::API::ntdll::NtPropagationComplete"

    /*
        684FB9EBBE           | push 0xbeebb94f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f b9 eb be ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPropagationFailed
{
    meta:
        desc = "Metasploit::API::ntdll::NtPropagationFailed"

    /*
        689B7B9238           | push 0x38927b9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 7b 92 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtProtectVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtProtectVirtualMemory"

    /*
        681979E6AA           | push 0xaae67919
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 79 e6 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtPulseEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtPulseEvent"

    /*
        68464EC1FA           | push 0xfac14e46
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 4e c1 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryAttributesFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryAttributesFile"

    /*
        68A2611C03           | push 0x031c61a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 61 1c 03 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryAuxiliaryCounterFrequency
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryAuxiliaryCounterFrequency"

    /*
        687DD071B8           | push 0xb871d07d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d d0 71 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryBootEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryBootEntryOrder"

    /*
        6837835BF6           | push 0xf65b8337
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 83 5b f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryBootOptions
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryBootOptions"

    /*
        6845E45243           | push 0x4352e445
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 e4 52 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryDebugFilterState
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryDebugFilterState"

    /*
        6850BF4F8B           | push 0x8b4fbf50
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 bf 4f 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryDefaultLocale
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryDefaultLocale"

    /*
        682BEF6F88           | push 0x886fef2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b ef 6f 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryDefaultUILanguage"

    /*
        68B0154E8A           | push 0x8a4e15b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 15 4e 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryDirectoryFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryDirectoryFile"

    /*
        68D18E1DA1           | push 0xa11d8ed1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 8e 1d a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryDirectoryFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryDirectoryFileEx"

    /*
        68270938E3           | push 0xe3380927
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 09 38 e3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryDirectoryObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryDirectoryObject"

    /*
        68A4F03B63           | push 0x633bf0a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 f0 3b 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryDriverEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryDriverEntryOrder"

    /*
        6806C9AB32           | push 0x32abc906
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 c9 ab 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryEaFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryEaFile"

    /*
        68FED07F6E           | push 0x6e7fd0fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe d0 7f 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryEvent"

    /*
        68264E1134           | push 0x34114e26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 4e 11 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryFullAttributesFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryFullAttributesFile"

    /*
        68F7A782B1           | push 0xb182a7f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 a7 82 b1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationAtom
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationAtom"

    /*
        6849069F5D           | push 0x5d9f0649
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 06 9f 5d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationByName
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationByName"

    /*
        6819E1FF6A           | push 0x6affe119
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 e1 ff 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationEnlistment"

    /*
        689E4EF5C6           | push 0xc6f54e9e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 4e f5 c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationFile"

    /*
        6889555F47           | push 0x475f5589
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 55 5f 47 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationJobObject"

    /*
        681D8E4B16           | push 0x164b8e1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 8e 4b 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationPort"

    /*
        6809F7D753           | push 0x53d7f709
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 f7 d7 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationProcess"

    /*
        68CD9F6700           | push 0x00679fcd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 9f 67 00 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationResourceManager"

    /*
        68AF6495F7           | push 0xf79564af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 64 95 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationThread"

    /*
        68101E42F3           | push 0xf3421e10
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 1e 42 f3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationToken"

    /*
        687FBDDA31           | push 0x31dabd7f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f bd da 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationTransaction"

    /*
        68E4F058F7           | push 0xf758f0e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 f0 58 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationTransactionManager"

    /*
        681D7D8F29           | push 0x298f7d1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 7d 8f 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInformationWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInformationWorkerFactory"

    /*
        6869756EC6           | push 0xc66e7569
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 75 6e c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryInstallUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryInstallUILanguage"

    /*
        68D9614720           | push 0x204761d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 61 47 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryIntervalProfile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryIntervalProfile"

    /*
        68CB516D06           | push 0x066d51cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 51 6d 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryIoCompletion"

    /*
        6878649ABD           | push 0xbd9a6478
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 64 9a bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryKey"

    /*
        687C6F01AB           | push 0xab016f7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 6f 01 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryLicenseValue
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryLicenseValue"

    /*
        6889E62844           | push 0x4428e689
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 e6 28 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryMultipleValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryMultipleValueKey"

    /*
        6843BBB301           | push 0x01b3bb43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 bb b3 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryMutant
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryMutant"

    /*
        6888B11A5F           | push 0x5f1ab188
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 b1 1a 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryObject"

    /*
        68BE0E22E7           | push 0xe7220ebe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 0e 22 e7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryOpenSubKeys
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryOpenSubKeys"

    /*
        687CB77E69           | push 0x697eb77c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c b7 7e 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryOpenSubKeysEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryOpenSubKeysEx"

    /*
        68D93382FB           | push 0xfb8233d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 33 82 fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryPerformanceCounter
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryPerformanceCounter"

    /*
        6828DF7939           | push 0x3979df28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 df 79 39 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryPortInformationProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryPortInformationProcess"

    /*
        68DCFAC9C4           | push 0xc4c9fadc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc fa c9 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryQuotaInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryQuotaInformationFile"

    /*
        68C74B87DE           | push 0xde874bc7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 4b 87 de ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySection
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySection"

    /*
        68CB4A9489           | push 0x89944acb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 4a 94 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySecurityAttributesToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySecurityAttributesToken"

    /*
        68C5092AAB           | push 0xab2a09c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 09 2a ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySecurityObject"

    /*
        68EC1EC5B2           | push 0xb2c51eec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 1e c5 b2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySecurityPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySecurityPolicy"

    /*
        68F23EF13A           | push 0x3af13ef2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 3e f1 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySemaphore"

    /*
        6825A40282           | push 0x8202a425
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 a4 02 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySymbolicLinkObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySymbolicLinkObject"

    /*
        68F6D3C8A1           | push 0xa1c8d3f6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 d3 c8 a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySystemEnvironmentValue
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySystemEnvironmentValue"

    /*
        6825E03B7E           | push 0x7e3be025
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 e0 3b 7e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySystemEnvironmentValueEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySystemEnvironmentValueEx"

    /*
        681E5ECC2A           | push 0x2acc5e1e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 5e cc 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySystemInformation
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySystemInformation"

    /*
        685D3E5195           | push 0x95513e5d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 3e 51 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySystemInformationEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySystemInformationEx"

    /*
        6824EC23F0           | push 0xf023ec24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 ec 23 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQuerySystemTime
{
    meta:
        desc = "Metasploit::API::ntdll::NtQuerySystemTime"

    /*
        68F526471C           | push 0x1c4726f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 26 47 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryTimer
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryTimer"

    /*
        68EE7B00C4           | push 0xc4007bee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 7b 00 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryTimerResolution
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryTimerResolution"

    /*
        6867421E6A           | push 0x6a1e4267
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 42 1e 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryValueKey"

    /*
        68602C6819           | push 0x19682c60
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 2c 68 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryVirtualMemory"

    /*
        68EB8F2C63           | push 0x632c8feb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 8f 2c 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryVolumeInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryVolumeInformationFile"

    /*
        68FAE970E6           | push 0xe670e9fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa e9 70 e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryWnfStateData"

    /*
        68C1844C74           | push 0x744c84c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 84 4c 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueryWnfStateNameInformation
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueryWnfStateNameInformation"

    /*
        68421DBF9C           | push 0x9cbf1d42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 1d bf 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueueApcThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueueApcThread"

    /*
        689CAECC78           | push 0x78ccae9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c ae cc 78 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtQueueApcThreadEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtQueueApcThreadEx"

    /*
        68DDFBFFCE           | push 0xcefffbdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd fb ff ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRaiseException
{
    meta:
        desc = "Metasploit::API::ntdll::NtRaiseException"

    /*
        6860F65C7F           | push 0x7f5cf660
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 f6 5c 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRaiseHardError
{
    meta:
        desc = "Metasploit::API::ntdll::NtRaiseHardError"

    /*
        682AF078FA           | push 0xfa78f02a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a f0 78 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReadFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtReadFile"

    /*
        68353F4EE7           | push 0xe74e3f35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 3f 4e e7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReadFileScatter
{
    meta:
        desc = "Metasploit::API::ntdll::NtReadFileScatter"

    /*
        68F57742C2           | push 0xc24277f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 77 42 c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReadOnlyEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtReadOnlyEnlistment"

    /*
        6835AEE566           | push 0x66e5ae35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 ae e5 66 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReadRequestData
{
    meta:
        desc = "Metasploit::API::ntdll::NtReadRequestData"

    /*
        68FDA50F2C           | push 0x2c0fa5fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd a5 0f 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReadVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtReadVirtualMemory"

    /*
        68CCEEEB6B           | push 0x6bebeecc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc ee eb 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRecoverEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtRecoverEnlistment"

    /*
        6828E15B73           | push 0x735be128
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 e1 5b 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRecoverResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtRecoverResourceManager"

    /*
        68F4ADC8CD           | push 0xcdc8adf4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 ad c8 cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRecoverTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtRecoverTransactionManager"

    /*
        68B0E33BB3           | push 0xb33be3b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 e3 3b b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRegisterProtocolAddressInformation
{
    meta:
        desc = "Metasploit::API::ntdll::NtRegisterProtocolAddressInformation"

    /*
        688F68D15B           | push 0x5bd1688f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 68 d1 5b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRegisterThreadTerminatePort
{
    meta:
        desc = "Metasploit::API::ntdll::NtRegisterThreadTerminatePort"

    /*
        68A81C4A23           | push 0x234a1ca8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 1c 4a 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReleaseKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtReleaseKeyedEvent"

    /*
        6873018695           | push 0x95860173
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 01 86 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReleaseMutant
{
    meta:
        desc = "Metasploit::API::ntdll::NtReleaseMutant"

    /*
        681D5E5222           | push 0x22525e1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 5e 52 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReleaseSemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::NtReleaseSemaphore"

    /*
        687E1389AD           | push 0xad89137e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 13 89 ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReleaseWorkerFactoryWorker
{
    meta:
        desc = "Metasploit::API::ntdll::NtReleaseWorkerFactoryWorker"

    /*
        6827C65275           | push 0x7552c627
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 c6 52 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRemoveIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::NtRemoveIoCompletion"

    /*
        681EC112CB           | push 0xcb12c11e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e c1 12 cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRemoveIoCompletionEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtRemoveIoCompletionEx"

    /*
        68729C8460           | push 0x60849c72
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 9c 84 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRemoveProcessDebug
{
    meta:
        desc = "Metasploit::API::ntdll::NtRemoveProcessDebug"

    /*
        686873FB34           | push 0x34fb7368
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 73 fb 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRenameKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtRenameKey"

    /*
        68A31E8BBF           | push 0xbf8b1ea3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 1e 8b bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRenameTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtRenameTransactionManager"

    /*
        6812B66743           | push 0x4367b612
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 b6 67 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReplaceKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtReplaceKey"

    /*
        6836BBD74A           | push 0x4ad7bb36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 bb d7 4a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReplacePartitionUnit
{
    meta:
        desc = "Metasploit::API::ntdll::NtReplacePartitionUnit"

    /*
        68BE3F8059           | push 0x59803fbe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 3f 80 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReplyPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtReplyPort"

    /*
        6829D28D07           | push 0x078dd229
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 d2 8d 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReplyWaitReceivePort
{
    meta:
        desc = "Metasploit::API::ntdll::NtReplyWaitReceivePort"

    /*
        6824B3F398           | push 0x98f3b324
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 b3 f3 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReplyWaitReceivePortEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtReplyWaitReceivePortEx"

    /*
        68E51DC1D8           | push 0xd8c11de5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 1d c1 d8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtReplyWaitReplyPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtReplyWaitReplyPort"

    /*
        6874A736A8           | push 0xa836a774
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 a7 36 a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRequestPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtRequestPort"

    /*
        6803D0B2FE           | push 0xfeb2d003
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 d0 b2 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRequestWaitReplyPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtRequestWaitReplyPort"

    /*
        682D7725D0           | push 0xd025772d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 77 25 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtResetEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtResetEvent"

    /*
        6887CCFC81           | push 0x81fccc87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 cc fc 81 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtResetWriteWatch
{
    meta:
        desc = "Metasploit::API::ntdll::NtResetWriteWatch"

    /*
        689C7B554F           | push 0x4f557b9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 7b 55 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRestoreKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtRestoreKey"

    /*
        683DBC0FCE           | push 0xce0fbc3d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d bc 0f ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtResumeProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtResumeProcess"

    /*
        68BEACEB1C           | push 0x1cebacbe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be ac eb 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtResumeThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtResumeThread"

    /*
        68A141E074           | push 0x74e041a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 41 e0 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRevertContainerImpersonation
{
    meta:
        desc = "Metasploit::API::ntdll::NtRevertContainerImpersonation"

    /*
        684079D37A           | push 0x7ad37940
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 79 d3 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRollbackComplete
{
    meta:
        desc = "Metasploit::API::ntdll::NtRollbackComplete"

    /*
        684E14163B           | push 0x3b16144e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 14 16 3b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRollbackEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtRollbackEnlistment"

    /*
        68F6F95460           | push 0x6054f9f6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 f9 54 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRollbackRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtRollbackRegistryTransaction"

    /*
        68C7DDB95A           | push 0x5ab9ddc7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 dd b9 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRollbackTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtRollbackTransaction"

    /*
        68E2BB1552           | push 0x5215bbe2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 bb 15 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtRollforwardTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtRollforwardTransactionManager"

    /*
        680F3B09FC           | push 0xfc093b0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 3b 09 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSaveKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtSaveKey"

    /*
        682BFBEE4D           | push 0x4deefb2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b fb ee 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSaveKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtSaveKeyEx"

    /*
        68921F9317           | push 0x17931f92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 1f 93 17 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSaveMergedKeys
{
    meta:
        desc = "Metasploit::API::ntdll::NtSaveMergedKeys"

    /*
        68246E6771           | push 0x71676e24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 6e 67 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSecureConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtSecureConnectPort"

    /*
        68BA29BC06           | push 0x06bc29ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 29 bc 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSerializeBoot
{
    meta:
        desc = "Metasploit::API::ntdll::NtSerializeBoot"

    /*
        68D63E8F38           | push 0x388f3ed6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 3e 8f 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetBootEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetBootEntryOrder"

    /*
        689F7CE715           | push 0x15e77c9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 7c e7 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetBootOptions
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetBootOptions"

    /*
        6854984F09           | push 0x094f9854
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 98 4f 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetCachedSigningLevel
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetCachedSigningLevel"

    /*
        68AB0481F6           | push 0xf68104ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 04 81 f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetCachedSigningLevel2
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetCachedSigningLevel2"

    /*
        6886D60FAB           | push 0xab0fd686
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 d6 0f ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetContextThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetContextThread"

    /*
        68FE60455B           | push 0x5b4560fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 60 45 5b ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetDebugFilterState
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetDebugFilterState"

    /*
        6858194E6E           | push 0x6e4e1958
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 19 4e 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetDefaultHardErrorPort
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetDefaultHardErrorPort"

    /*
        682283730D           | push 0x0d738322
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 83 73 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetDefaultLocale
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetDefaultLocale"

    /*
        681CF39C07           | push 0x079cf31c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c f3 9c 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetDefaultUILanguage"

    /*
        68A32D8D5A           | push 0x5a8d2da3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 2d 8d 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetDriverEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetDriverEntryOrder"

    /*
        680E23AA15           | push 0x15aa230e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 23 aa 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetEaFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetEaFile"

    /*
        681D3979FA           | push 0xfa79391d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 39 79 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetEvent"

    /*
        68A63F1561           | push 0x61153fa6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 3f 15 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetEventBoostPriority
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetEventBoostPriority"

    /*
        68684780F3           | push 0xf3804768
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 47 80 f3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetHighEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetHighEventPair"

    /*
        68C1408C54           | push 0x548c40c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 40 8c 54 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetHighWaitLowEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetHighWaitLowEventPair"

    /*
        682F5A7BAB           | push 0xab7b5a2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 5a 7b ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetIRTimer
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetIRTimer"

    /*
        68CFF66352           | push 0x5263f6cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf f6 63 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationDebugObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationDebugObject"

    /*
        685AE03F9E           | push 0x9e3fe05a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a e0 3f 9e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationEnlistment"

    /*
        68A27B74B8           | push 0xb8747ba2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 7b 74 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationFile"

    /*
        68E851A012           | push 0x12a051e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 51 a0 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationJobObject"

    /*
        684D0CECFB           | push 0xfbec0c4d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 0c ec fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationKey"

    /*
        686A505510           | push 0x1055506a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 50 55 10 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationObject"

    /*
        6880B6ECC3           | push 0xc3ecb680
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 b6 ec c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationProcess"

    /*
        68C621FEBF           | push 0xbffe21c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 21 fe bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationResourceManager"

    /*
        6831FB54F0           | push 0xf054fb31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 fb 54 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationSymbolicLink
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationSymbolicLink"

    /*
        688CEF8EDE           | push 0xde8eef8c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c ef 8e de ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationThread"

    /*
        68033681C3           | push 0xc3813603
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 36 81 c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationToken
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationToken"

    /*
        688717D914           | push 0x14d91787
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 17 d9 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationTransaction"

    /*
        68DE7C785F           | push 0x5f787cde
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 7c 78 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationTransactionManager"

    /*
        684AFC802D           | push 0x2d80fc4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a fc 80 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationVirtualMemory"

    /*
        68268881FC           | push 0xfc818826
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 88 81 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetInformationWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetInformationWorkerFactory"

    /*
        68C37351CE           | push 0xce5173c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 73 51 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetIntervalProfile
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetIntervalProfile"

    /*
        682B4EAED1           | push 0xd1ae4e2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 4e ae d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetIoCompletion"

    /*
        685E94185E           | push 0x5e18945e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 94 18 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetIoCompletionEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetIoCompletionEx"

    /*
        68566CF921           | push 0x21f96c56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 6c f9 21 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetLdtEntries
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetLdtEntries"

    /*
        68D74F5E74           | push 0x745e4fd7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 4f 5e 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetLowEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetLowEventPair"

    /*
        68C2013DD7           | push 0xd73d01c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 01 3d d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetLowWaitHighEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetLowWaitHighEventPair"

    /*
        6874937519           | push 0x19759374
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 93 75 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetQuotaInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetQuotaInformationFile"

    /*
        68F7C927C4           | push 0xc427c9f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 c9 27 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetSecurityObject"

    /*
        68541851D2           | push 0xd2511854
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 18 51 d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetSystemEnvironmentValue
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetSystemEnvironmentValue"

    /*
        681E6C5BE6           | push 0xe65b6c1e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 6c 5b e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetSystemEnvironmentValueEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetSystemEnvironmentValueEx"

    /*
        68785CAF32           | push 0x32af5c78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 5c af 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetSystemInformation
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetSystemInformation"

    /*
        6850569065           | push 0x65905650
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 56 90 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetSystemPowerState
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetSystemPowerState"

    /*
        6834752BB1           | push 0xb12b7534
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 75 2b b1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetSystemTime
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetSystemTime"

    /*
        68B51FC9B2           | push 0xb2c91fb5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 1f c9 b2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetThreadExecutionState
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetThreadExecutionState"

    /*
        689785C8C2           | push 0xc2c88597
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 85 c8 c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetTimer
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetTimer"

    /*
        686D6D04F1           | push 0xf1046d6d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 6d 04 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetTimer2
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetTimer2"

    /*
        68A1AA1FF1           | push 0xf11faaa1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 aa 1f f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetTimerEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetTimerEx"

    /*
        683BB0EFDC           | push 0xdcefb03b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b b0 ef dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetTimerResolution
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetTimerResolution"

    /*
        68C63E5F35           | push 0x355f3ec6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 3e 5f 35 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetUuidSeed
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetUuidSeed"

    /*
        68BB160DCA           | push 0xca0d16bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 16 0d ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetValueKey"

    /*
        684334C217           | push 0x17c23443
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 34 c2 17 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetVolumeInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetVolumeInformationFile"

    /*
        68FE16F0D7           | push 0xd7f016fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 16 f0 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSetWnfProcessNotificationEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtSetWnfProcessNotificationEvent"

    /*
        683CD9D0E9           | push 0xe9d0d93c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c d9 d0 e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtShutdownSystem
{
    meta:
        desc = "Metasploit::API::ntdll::NtShutdownSystem"

    /*
        68043A90D7           | push 0xd7903a04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 3a 90 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtShutdownWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::NtShutdownWorkerFactory"

    /*
        68D2D2AF87           | push 0x87afd2d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 d2 af 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSignalAndWaitForSingleObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtSignalAndWaitForSingleObject"

    /*
        685EE40907           | push 0x0709e45e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e e4 09 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSinglePhaseReject
{
    meta:
        desc = "Metasploit::API::ntdll::NtSinglePhaseReject"

    /*
        68F2259714           | push 0x149725f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 25 97 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtStartProfile
{
    meta:
        desc = "Metasploit::API::ntdll::NtStartProfile"

    /*
        68D0697D84           | push 0x847d69d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 69 7d 84 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtStopProfile
{
    meta:
        desc = "Metasploit::API::ntdll::NtStopProfile"

    /*
        68E41B3A2D           | push 0x2d3a1be4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 1b 3a 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSubscribeWnfStateChange
{
    meta:
        desc = "Metasploit::API::ntdll::NtSubscribeWnfStateChange"

    /*
        6893F7F231           | push 0x31f2f793
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 f7 f2 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSuspendProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtSuspendProcess"

    /*
        689F31B3ED           | push 0xedb3319f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 31 b3 ed ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSuspendThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtSuspendThread"

    /*
        68BA5B7C65           | push 0x657c5bba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 5b 7c 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtSystemDebugControl
{
    meta:
        desc = "Metasploit::API::ntdll::NtSystemDebugControl"

    /*
        68DBA740BB           | push 0xbb40a7db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db a7 40 bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTerminateEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::NtTerminateEnclave"

    /*
        68F66FB615           | push 0x15b66ff6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 6f b6 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTerminateJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtTerminateJobObject"

    /*
        68E5C1DB89           | push 0x89dbc1e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 c1 db 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTerminateProcess
{
    meta:
        desc = "Metasploit::API::ntdll::NtTerminateProcess"

    /*
        689CE0351E           | push 0x1e35e09c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c e0 35 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTerminateThread
{
    meta:
        desc = "Metasploit::API::ntdll::NtTerminateThread"

    /*
        68CA015CBB           | push 0xbb5c01ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 01 5c bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTestAlert
{
    meta:
        desc = "Metasploit::API::ntdll::NtTestAlert"

    /*
        686DA2AFF3           | push 0xf3afa26d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d a2 af f3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtThawRegistry
{
    meta:
        desc = "Metasploit::API::ntdll::NtThawRegistry"

    /*
        68FD65DA78           | push 0x78da65fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 65 da 78 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtThawTransactions
{
    meta:
        desc = "Metasploit::API::ntdll::NtThawTransactions"

    /*
        682FCC0125           | push 0x2501cc2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f cc 01 25 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTraceControl
{
    meta:
        desc = "Metasploit::API::ntdll::NtTraceControl"

    /*
        68FFD0A507           | push 0x07a5d0ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff d0 a5 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTraceEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtTraceEvent"

    /*
        684734C1EF           | push 0xefc13447
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 34 c1 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtTranslateFilePath
{
    meta:
        desc = "Metasploit::API::ntdll::NtTranslateFilePath"

    /*
        682CC74843           | push 0x4348c72c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c c7 48 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUmsThreadYield
{
    meta:
        desc = "Metasploit::API::ntdll::NtUmsThreadYield"

    /*
        68F5B9CBA9           | push 0xa9cbb9f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 b9 cb a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnloadDriver
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnloadDriver"

    /*
        68B48221CB           | push 0xcb2182b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 82 21 cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnloadKey
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnloadKey"

    /*
        685D26C3C8           | push 0xc8c3265d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 26 c3 c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnloadKey2
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnloadKey2"

    /*
        6897689EB8           | push 0xb89e6897
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 68 9e b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnloadKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnloadKeyEx"

    /*
        6831EC9DCC           | push 0xcc9dec31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 ec 9d cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnlockFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnlockFile"

    /*
        685B153E42           | push 0x423e155b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 15 3e 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnlockVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnlockVirtualMemory"

    /*
        68A3199DEA           | push 0xea9d19a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 19 9d ea ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnmapViewOfSection
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnmapViewOfSection"

    /*
        68D0A721FD           | push 0xfd21a7d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 a7 21 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnmapViewOfSectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnmapViewOfSectionEx"

    /*
        68FE483EE4           | push 0xe43e48fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 48 3e e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUnsubscribeWnfStateChange
{
    meta:
        desc = "Metasploit::API::ntdll::NtUnsubscribeWnfStateChange"

    /*
        6830F20F6E           | push 0x6e0ff230
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 f2 0f 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtUpdateWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::NtUpdateWnfStateData"

    /*
        68BDD97BC2           | push 0xc27bd9bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd d9 7b c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtVdmControl
{
    meta:
        desc = "Metasploit::API::ntdll::NtVdmControl"

    /*
        689CA0A815           | push 0x15a8a09c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c a0 a8 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitForAlertByThreadId
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitForAlertByThreadId"

    /*
        68D6809963           | push 0x639980d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 80 99 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitForDebugEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitForDebugEvent"

    /*
        68593F2851           | push 0x51283f59
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 3f 28 51 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitForKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitForKeyedEvent"

    /*
        685A3D1C28           | push 0x281c3d5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 3d 1c 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitForMultipleObjects
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitForMultipleObjects"

    /*
        68A5843BF6           | push 0xf63b84a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 84 3b f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitForMultipleObjects32
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitForMultipleObjects32"

    /*
        68BC798528           | push 0x288579bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 79 85 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitForSingleObject
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitForSingleObject"

    /*
        6885872F4C           | push 0x4c2f8785
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 87 2f 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitForWorkViaWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitForWorkViaWorkerFactory"

    /*
        68A4EE7E05           | push 0x057eeea4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 ee 7e 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitHighEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitHighEventPair"

    /*
        68D9DB1ADE           | push 0xde1adbd9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 db 1a de ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWaitLowEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::NtWaitLowEventPair"

    /*
        68F412A0AA           | push 0xaaa012f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 12 a0 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWorkerFactoryWorkerReady
{
    meta:
        desc = "Metasploit::API::ntdll::NtWorkerFactoryWorkerReady"

    /*
        68AD20F1FA           | push 0xfaf120ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 20 f1 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWriteFile
{
    meta:
        desc = "Metasploit::API::ntdll::NtWriteFile"

    /*
        68BF573508           | push 0x083557bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 57 35 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWriteFileGather
{
    meta:
        desc = "Metasploit::API::ntdll::NtWriteFileGather"

    /*
        682D971095           | push 0x9510972d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 97 10 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWriteRequestData
{
    meta:
        desc = "Metasploit::API::ntdll::NtWriteRequestData"

    /*
        6842B7F248           | push 0x48f2b742
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 b7 f2 48 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtWriteVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::NtWriteVirtualMemory"

    /*
        68D33FB0A4           | push 0xa4b03fd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 3f b0 a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtYieldExecution
{
    meta:
        desc = "Metasploit::API::ntdll::NtYieldExecution"

    /*
        68621247C3           | push 0xc3471262
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 12 47 c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtdllDefWindowProc_A
{
    meta:
        desc = "Metasploit::API::ntdll::NtdllDefWindowProc_A"

    /*
        6822D32CA4           | push 0xa42cd322
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 d3 2c a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtdllDefWindowProc_W
{
    meta:
        desc = "Metasploit::API::ntdll::NtdllDefWindowProc_W"

    /*
        6822D3DCA4           | push 0xa4dcd322
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 d3 dc a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtdllDialogWndProc_A
{
    meta:
        desc = "Metasploit::API::ntdll::NtdllDialogWndProc_A"

    /*
        68107AB8E0           | push 0xe0b87a10
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 7a b8 e0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_NtdllDialogWndProc_W
{
    meta:
        desc = "Metasploit::API::ntdll::NtdllDialogWndProc_W"

    /*
        68107A68E1           | push 0xe1687a10
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 7a 68 e1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PfxFindPrefix
{
    meta:
        desc = "Metasploit::API::ntdll::PfxFindPrefix"

    /*
        68BADC9326           | push 0x2693dcba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba dc 93 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PfxInitialize
{
    meta:
        desc = "Metasploit::API::ntdll::PfxInitialize"

    /*
        68F37A6067           | push 0x67607af3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 7a 60 67 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PfxInsertPrefix
{
    meta:
        desc = "Metasploit::API::ntdll::PfxInsertPrefix"

    /*
        680055817E           | push 0x7e815500
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 55 81 7e ff d5 }

    condition:
        any of them
}

    
rule ntdll_PfxRemovePrefix
{
    meta:
        desc = "Metasploit::API::ntdll::PfxRemovePrefix"

    /*
        68AEA36F02           | push 0x026fa3ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae a3 6f 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtCaptureSnapshot
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtCaptureSnapshot"

    /*
        68E20CE99C           | push 0x9ce90ce2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 0c e9 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtDuplicateSnapshot
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtDuplicateSnapshot"

    /*
        68CA6EBBE9           | push 0xe9bb6eca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 6e bb e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtFreeRemoteSnapshot
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtFreeRemoteSnapshot"

    /*
        6862554736           | push 0x36475562
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 55 47 36 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtFreeSnapshot
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtFreeSnapshot"

    /*
        6810D82042           | push 0x4220d810
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 d8 20 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtFreeWalkMarker
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtFreeWalkMarker"

    /*
        682D28429C           | push 0x9c42282d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 28 42 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtQuerySnapshot
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtQuerySnapshot"

    /*
        68161488E4           | push 0xe4881416
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 14 88 e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtValidateDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtValidateDescriptor"

    /*
        68DC6B6E70           | push 0x706e6bdc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 6b 6e 70 ff d5 }

    condition:
        any of them
}

    
rule ntdll_PssNtWalkSnapshot
{
    meta:
        desc = "Metasploit::API::ntdll::PssNtWalkSnapshot"

    /*
        682109FF01           | push 0x01ff0921
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 09 ff 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAbortRXact
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAbortRXact"

    /*
        68C9D5EADE           | push 0xdeead5c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 d5 ea de ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAbsoluteToSelfRelativeSD
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAbsoluteToSelfRelativeSD"

    /*
        68E9C3CBD5           | push 0xd5cbc3e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 c3 cb d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAcquirePebLock
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAcquirePebLock"

    /*
        6809986D79           | push 0x796d9809
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 98 6d 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAcquirePrivilege
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAcquirePrivilege"

    /*
        687AF04AF8           | push 0xf84af07a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a f0 4a f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAcquireReleaseSRWLockExclusive
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAcquireReleaseSRWLockExclusive"

    /*
        68251B9549           | push 0x49951b25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 1b 95 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAcquireResourceExclusive
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAcquireResourceExclusive"

    /*
        68B40621FF           | push 0xff2106b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 06 21 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAcquireResourceShared
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAcquireResourceShared"

    /*
        68BCE5C2F9           | push 0xf9c2e5bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc e5 c2 f9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAcquireSRWLockExclusive
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAcquireSRWLockExclusive"

    /*
        683F3F8449           | push 0x49843f3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 3f 84 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAcquireSRWLockShared
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAcquireSRWLockShared"

    /*
        68E12A5F2B           | push 0x2b5f2ae1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 2a 5f 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlActivateActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlActivateActivationContext"

    /*
        68BCEF84BD           | push 0xbd84efbc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc ef 84 bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlActivateActivationContextEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlActivateActivationContextEx"

    /*
        68EE4310FD           | push 0xfd1043ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 43 10 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlActivateActivationContextUnsafeFast
{
    meta:
        desc = "Metasploit::API::ntdll::RtlActivateActivationContextUnsafeFast"

    /*
        6893C69498           | push 0x9894c693
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 c6 94 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAccessAllowedAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAccessAllowedAce"

    /*
        68DEF78A5E           | push 0x5e8af7de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de f7 8a 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAccessAllowedAceEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAccessAllowedAceEx"

    /*
        68564C923E           | push 0x3e924c56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 4c 92 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAccessAllowedObjectAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAccessAllowedObjectAce"

    /*
        68A4609AC6           | push 0xc69a60a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 60 9a c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAccessDeniedAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAccessDeniedAce"

    /*
        689E0BA40D           | push 0x0da40b9e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 0b a4 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAccessDeniedAceEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAccessDeniedAceEx"

    /*
        68823CD704           | push 0x04d73c82
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 3c d7 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAccessDeniedObjectAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAccessDeniedObjectAce"

    /*
        68081D9D15           | push 0x159d1d08
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 1d 9d 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAccessFilterAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAccessFilterAce"

    /*
        685EFBD011           | push 0x11d0fb5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e fb d0 11 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAce"

    /*
        68C10DCF38           | push 0x38cf0dc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 0d cf 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddActionToRXact
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddActionToRXact"

    /*
        687070AA72           | push 0x72aa7070
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 70 aa 72 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAtomToAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAtomToAtomTable"

    /*
        68750A76E4           | push 0xe4760a75
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 0a 76 e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAttributeActionToRXact
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAttributeActionToRXact"

    /*
        68171A14CA           | push 0xca141a17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 1a 14 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAuditAccessAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAuditAccessAce"

    /*
        682069179F           | push 0x9f176920
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 69 17 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAuditAccessAceEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAuditAccessAceEx"

    /*
        68E79CAE61           | push 0x61ae9ce7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 9c ae 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddAuditAccessObjectAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddAuditAccessObjectAce"

    /*
        68D662A38B           | push 0x8ba362d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 62 a3 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddCompoundAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddCompoundAce"

    /*
        6820F39AA8           | push 0xa89af320
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 f3 9a a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddFunctionTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddFunctionTable"

    /*
        682F2FA3F1           | push 0xf1a32f2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 2f a3 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddGrowableFunctionTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddGrowableFunctionTable"

    /*
        681730457F           | push 0x7f453017
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 30 45 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddIntegrityLabelToBoundaryDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddIntegrityLabelToBoundaryDescriptor"

    /*
        6836BEBD0F           | push 0x0fbdbe36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 be bd 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddMandatoryAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddMandatoryAce"

    /*
        685C87380E           | push 0x0e38875c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 87 38 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddProcessTrustLabelAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddProcessTrustLabelAce"

    /*
        685E44CDA0           | push 0xa0cd445e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 44 cd a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddRefActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddRefActivationContext"

    /*
        68C159355A           | push 0x5a3559c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 59 35 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddRefMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddRefMemoryStream"

    /*
        68074BF283           | push 0x83f24b07
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 4b f2 83 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddResourceAttributeAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddResourceAttributeAce"

    /*
        68D667A687           | push 0x87a667d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 67 a6 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddSIDToBoundaryDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddSIDToBoundaryDescriptor"

    /*
        6860AF3893           | push 0x9338af60
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 af 38 93 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddScopedPolicyIDAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddScopedPolicyIDAce"

    /*
        686A6FA9B5           | push 0xb5a96f6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 6f a9 b5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddVectoredContinueHandler
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddVectoredContinueHandler"

    /*
        68C915B327           | push 0x27b315c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 15 b3 27 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddVectoredExceptionHandler
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddVectoredExceptionHandler"

    /*
        682AFE5A82           | push 0x825afe2a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a fe 5a 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAddressInSectionTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAddressInSectionTable"

    /*
        688FB8E333           | push 0x33e3b88f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f b8 e3 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAdjustPrivilege
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAdjustPrivilege"

    /*
        687A19776A           | push 0x6a77197a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 19 77 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateActivationContextStack
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateActivationContextStack"

    /*
        68FC20EA42           | push 0x42ea20fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 20 ea 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateAndInitializeSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateAndInitializeSid"

    /*
        68DDF6D1EA           | push 0xead1f6dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd f6 d1 ea ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateAndInitializeSidEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateAndInitializeSidEx"

    /*
        683A0C5250           | push 0x50520c3a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 0c 52 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateHandle
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateHandle"

    /*
        6897343F76           | push 0x763f3497
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 34 3f 76 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateHeap"

    /*
        681808CC67           | push 0x67cc0818
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 08 cc 67 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateMemoryBlockLookaside"

    /*
        68A5067A5F           | push 0x5f7a06a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 06 7a 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateMemoryZone
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateMemoryZone"

    /*
        68B577B4B0           | push 0xb0b477b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 77 b4 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAllocateWnfSerializationGroup
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAllocateWnfSerializationGroup"

    /*
        68BBA09B74           | push 0x749ba0bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb a0 9b 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAnsiCharToUnicodeChar
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAnsiCharToUnicodeChar"

    /*
        688940B7CA           | push 0xcab74089
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 40 b7 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAnsiStringToUnicodeSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAnsiStringToUnicodeSize"

    /*
        684E76DEB8           | push 0xb8de764e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 76 de b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAnsiStringToUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAnsiStringToUnicodeString"

    /*
        68B372E95A           | push 0x5ae972b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 72 e9 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAppendAsciizToString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAppendAsciizToString"

    /*
        683D20619A           | push 0x9a61203d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 20 61 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAppendPathElement
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAppendPathElement"

    /*
        68163007A9           | push 0xa9073016
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 30 07 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAppendStringToString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAppendStringToString"

    /*
        682ED1E0DA           | push 0xdae0d12e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e d1 e0 da ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAppendUnicodeStringToString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAppendUnicodeStringToString"

    /*
        68C8E2E799           | push 0x99e7e2c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 e2 e7 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAppendUnicodeToString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAppendUnicodeToString"

    /*
        6865FECD66           | push 0x66cdfe65
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 fe cd 66 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlApplicationVerifierStop
{
    meta:
        desc = "Metasploit::API::ntdll::RtlApplicationVerifierStop"

    /*
        68C53C24EB           | push 0xeb243cc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 3c 24 eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlApplyRXact
{
    meta:
        desc = "Metasploit::API::ntdll::RtlApplyRXact"

    /*
        680945FFDF           | push 0xdfff4509
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 45 ff df ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlApplyRXactNoFlush
{
    meta:
        desc = "Metasploit::API::ntdll::RtlApplyRXactNoFlush"

    /*
        6847B5425A           | push 0x5a42b547
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 b5 42 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAppxIsFileOwnedByTrustedInstaller
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAppxIsFileOwnedByTrustedInstaller"

    /*
        68B4F5A020           | push 0x20a0f5b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 f5 a0 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAreAllAccessesGranted
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAreAllAccessesGranted"

    /*
        682D754170           | push 0x7041752d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 75 41 70 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAreAnyAccessesGranted
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAreAnyAccessesGranted"

    /*
        683D754E70           | push 0x704e753d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 75 4e 70 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAreBitsClear
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAreBitsClear"

    /*
        6865E2E4AD           | push 0xade4e265
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 e2 e4 ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAreBitsSet
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAreBitsSet"

    /*
        685A00C1B8           | push 0xb8c1005a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 00 c1 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAreLongPathsEnabled
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAreLongPathsEnabled"

    /*
        6802DDC5FF           | push 0xffc5dd02
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 dd c5 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAssert
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAssert"

    /*
        6889014801           | push 0x01480189
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 01 48 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAvlInsertNodeEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAvlInsertNodeEx"

    /*
        689C7F652B           | push 0x2b657f9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 7f 65 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlAvlRemoveNode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlAvlRemoveNode"

    /*
        68E5FD4D30           | push 0x304dfde5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 fd 4d 30 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlBarrier
{
    meta:
        desc = "Metasploit::API::ntdll::RtlBarrier"

    /*
        681DF9B801           | push 0x01b8f91d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d f9 b8 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlBarrierForDelete
{
    meta:
        desc = "Metasploit::API::ntdll::RtlBarrierForDelete"

    /*
        68DBA8E9F2           | push 0xf2e9a8db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db a8 e9 f2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCallEnclaveReturn
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCallEnclaveReturn"

    /*
        68C8290602           | push 0x020629c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 29 06 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCancelTimer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCancelTimer"

    /*
        68328C6BFB           | push 0xfb6b8c32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 8c 6b fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCanonicalizeDomainName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCanonicalizeDomainName"

    /*
        6802254F61           | push 0x614f2502
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 25 4f 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCapabilityCheck
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCapabilityCheck"

    /*
        6884AC91E4           | push 0xe491ac84
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 ac 91 e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCapabilityCheckForSingleSessionSku
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCapabilityCheckForSingleSessionSku"

    /*
        6865027AFC           | push 0xfc7a0265
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 02 7a fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCaptureContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCaptureContext"

    /*
        68A223DE64           | push 0x64de23a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 23 de 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCaptureStackBackTrace
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCaptureStackBackTrace"

    /*
        682F76533D           | push 0x3d53762f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 76 53 3d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCharToInteger
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCharToInteger"

    /*
        6895E080A3           | push 0xa380e095
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 e0 80 a3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckBootStatusIntegrity
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckBootStatusIntegrity"

    /*
        6825CFEE8E           | push 0x8eeecf25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 cf ee 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckForOrphanedCriticalSections
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckForOrphanedCriticalSections"

    /*
        689B19C139           | push 0x39c1199b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 19 c1 39 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckPortableOperatingSystem
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckPortableOperatingSystem"

    /*
        68EC650F7C           | push 0x7c0f65ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 65 0f 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckRegistryKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckRegistryKey"

    /*
        685F49A6D2           | push 0xd2a6495f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 49 a6 d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckSandboxedToken
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckSandboxedToken"

    /*
        68D7828B7D           | push 0x7d8b82d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 82 8b 7d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckSystemBootStatusIntegrity
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckSystemBootStatusIntegrity"

    /*
        68F7793BFD           | push 0xfd3b79f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 79 3b fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckTokenCapability
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckTokenCapability"

    /*
        68FC9F73D0           | push 0xd0739ffc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 9f 73 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckTokenMembership
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckTokenMembership"

    /*
        68632D38CB           | push 0xcb382d63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 2d 38 cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCheckTokenMembershipEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCheckTokenMembershipEx"

    /*
        68B2ADDF69           | push 0x69dfadb2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 ad df 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCleanUpTEBLangLists
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCleanUpTEBLangLists"

    /*
        680B16FEDE           | push 0xdefe160b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 16 fe de ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlClearAllBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlClearAllBits"

    /*
        68FA38C33E           | push 0x3ec338fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 38 c3 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlClearBit
{
    meta:
        desc = "Metasploit::API::ntdll::RtlClearBit"

    /*
        685DBF7C8B           | push 0x8b7cbf5d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d bf 7c 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlClearBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlClearBits"

    /*
        68647EA482           | push 0x82a47e64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 7e a4 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlClearThreadWorkOnBehalfTicket
{
    meta:
        desc = "Metasploit::API::ntdll::RtlClearThreadWorkOnBehalfTicket"

    /*
        68B339AB17           | push 0x17ab39b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 39 ab 17 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCloneMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCloneMemoryStream"

    /*
        68007E110E           | push 0x0e117e00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 7e 11 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCloneUserProcess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCloneUserProcess"

    /*
        682200F394           | push 0x94f30022
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 00 f3 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCmDecodeMemIoResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCmDecodeMemIoResource"

    /*
        6825FE45D9           | push 0xd945fe25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 fe 45 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCmEncodeMemIoResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCmEncodeMemIoResource"

    /*
        68250086DB           | push 0xdb860025
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 00 86 db ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCommitDebugInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCommitDebugInfo"

    /*
        68D9B32CB1           | push 0xb12cb3d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 b3 2c b1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCommitMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCommitMemoryStream"

    /*
        68625B7BEB           | push 0xeb7b5b62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 5b 7b eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompactHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompactHeap"

    /*
        68C6723578           | push 0x783572c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 72 35 78 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompareAltitudes
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompareAltitudes"

    /*
        68E1F808EE           | push 0xee08f8e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 f8 08 ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompareMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompareMemory"

    /*
        68BDCF4DB6           | push 0xb64dcfbd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd cf 4d b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompareMemoryUlong
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompareMemoryUlong"

    /*
        6831CFB2DB           | push 0xdbb2cf31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 cf b2 db ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompareString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompareString"

    /*
        68C41ED629           | push 0x29d61ec4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 1e d6 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompareUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompareUnicodeString"

    /*
        68055694FA           | push 0xfa945605
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 56 94 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompareUnicodeStrings
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompareUnicodeStrings"

    /*
        6820F7E737           | push 0x37e7f720
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 f7 e7 37 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompleteProcessCloning
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompleteProcessCloning"

    /*
        68BBD280AB           | push 0xab80d2bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb d2 80 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCompressBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCompressBuffer"

    /*
        68B4DC103B           | push 0x3b10dcb4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 dc 10 3b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlComputeCrc32
{
    meta:
        desc = "Metasploit::API::ntdll::RtlComputeCrc32"

    /*
        6807A7A8B3           | push 0xb3a8a707
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 a7 a8 b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlComputeImportTableHash
{
    meta:
        desc = "Metasploit::API::ntdll::RtlComputeImportTableHash"

    /*
        684EF4D4CA           | push 0xcad4f44e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e f4 d4 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlComputePrivatizedDllName_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlComputePrivatizedDllName_U"

    /*
        6884005148           | push 0x48510084
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 00 51 48 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConnectToSm
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConnectToSm"

    /*
        68C6371E8A           | push 0x8a1e37c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 37 1e 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConsoleMultiByteToUnicodeN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConsoleMultiByteToUnicodeN"

    /*
        68E1AC9F38           | push 0x389face1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 ac 9f 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConstructCrossVmEventPath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConstructCrossVmEventPath"

    /*
        68E18B009A           | push 0x9a008be1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 8b 00 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlContractHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlContractHashTable"

    /*
        683251A29D           | push 0x9da25132
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 51 a2 9d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConvertDeviceFamilyInfoToString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConvertDeviceFamilyInfoToString"

    /*
        68424D6EFC           | push 0xfc6e4d42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 4d 6e fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConvertExclusiveToShared
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConvertExclusiveToShared"

    /*
        688C591472           | push 0x7214598c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c 59 14 72 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConvertLCIDToString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConvertLCIDToString"

    /*
        6888D81F60           | push 0x601fd888
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 d8 1f 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConvertSRWLockExclusiveToShared
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConvertSRWLockExclusiveToShared"

    /*
        6844772713           | push 0x13277744
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 77 27 13 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConvertSharedToExclusive
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConvertSharedToExclusive"

    /*
        68D09346FC           | push 0xfc4693d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 93 46 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConvertSidToUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConvertSidToUnicodeString"

    /*
        68BF77CF44           | push 0x44cf77bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 77 cf 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlConvertToAutoInheritSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlConvertToAutoInheritSecurityObject"

    /*
        68124F243C           | push 0x3c244f12
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 4f 24 3c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyBitMap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyBitMap"

    /*
        6835FE04B7           | push 0xb704fe35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 fe 04 b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyContext"

    /*
        68C34C8881           | push 0x81884cc3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 4c 88 81 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyExtendedContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyExtendedContext"

    /*
        6827175229           | push 0x29521727
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 17 52 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyLuid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyLuid"

    /*
        68C95F26F1           | push 0xf1265fc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 5f 26 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyLuidAndAttributesArray
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyLuidAndAttributesArray"

    /*
        6813825D26           | push 0x265d8213
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 82 5d 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyMappedMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyMappedMemory"

    /*
        68DDFC2741           | push 0x4127fcdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd fc 27 41 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyMemory"

    /*
        68739278FB           | push 0xfb789273
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 92 78 fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyMemoryNonTemporal
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyMemoryNonTemporal"

    /*
        6840169E32           | push 0x329e1640
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 16 9e 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyMemoryStreamTo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyMemoryStreamTo"

    /*
        687D299D15           | push 0x159d297d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 29 9d 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyOutOfProcessMemoryStreamTo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyOutOfProcessMemoryStreamTo"

    /*
        68AF1D3105           | push 0x05311daf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 1d 31 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopySecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopySecurityDescriptor"

    /*
        6842214CA7           | push 0xa74c2142
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 21 4c a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopySid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopySid"

    /*
        683C6A81D5           | push 0xd5816a3c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 6a 81 d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopySidAndAttributesArray
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopySidAndAttributesArray"

    /*
        68D69816C3           | push 0xc31698d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 98 16 c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyString"

    /*
        687BE1006F           | push 0x6f00e17b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b e1 00 6f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCopyUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCopyUnicodeString"

    /*
        68CEACEC9F           | push 0x9fecacce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce ac ec 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCrc32
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCrc32"

    /*
        68B152E1D9           | push 0xd9e152b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 52 e1 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCrc64
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCrc64"

    /*
        687153F1D9           | push 0xd9f15371
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 53 f1 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateAcl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateAcl"

    /*
        6824AA6E38           | push 0x386eaa24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 aa 6e 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateActivationContext"

    /*
        68FAF7354A           | push 0x4a35f7fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa f7 35 4a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateAndSetSD
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateAndSetSD"

    /*
        6804C78AA5           | push 0xa58ac704
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 c7 8a a5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateAtomTable"

    /*
        682C2AD463           | push 0x63d42a2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 2a d4 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateBootStatusDataFile
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateBootStatusDataFile"

    /*
        68971B0194           | push 0x94011b97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 1b 01 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateBoundaryDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateBoundaryDescriptor"

    /*
        689E91F3CF           | push 0xcff3919e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 91 f3 cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateEnvironment
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateEnvironment"

    /*
        68DC35FF0C           | push 0x0cff35dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 35 ff 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateEnvironmentEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateEnvironmentEx"

    /*
        6802CCA1DB           | push 0xdba1cc02
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 cc a1 db ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateHashTable"

    /*
        68AC62C050           | push 0x50c062ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac 62 c0 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateHashTableEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateHashTableEx"

    /*
        68D3FFECCB           | push 0xcbecffd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 ff ec cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateHeap"

    /*
        683353CADC           | push 0xdcca5333
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 53 ca dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateMemoryBlockLookaside"

    /*
        68A37B95AA           | push 0xaa957ba3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 7b 95 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateMemoryZone
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateMemoryZone"

    /*
        68AE4B22DD           | push 0xdd224bae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 4b 22 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateProcessParameters
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateProcessParameters"

    /*
        68C673B2E5           | push 0xe5b273c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 73 b2 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateProcessParametersEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateProcessParametersEx"

    /*
        6878467108           | push 0x08714678
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 46 71 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateProcessParametersWithTemplate
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateProcessParametersWithTemplate"

    /*
        682F0ED8CB           | push 0xcbd80e2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 0e d8 cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateProcessReflection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateProcessReflection"

    /*
        6866946A61           | push 0x616a9466
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 94 6a 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateQueryDebugBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateQueryDebugBuffer"

    /*
        689F83D028           | push 0x28d0839f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 83 d0 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateRegistryKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateRegistryKey"

    /*
        68BC7B5599           | push 0x99557bbc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 7b 55 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateSecurityDescriptor"

    /*
        686FC921B8           | push 0xb821c96f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f c9 21 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateServiceSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateServiceSid"

    /*
        6844FBF629           | push 0x29f6fb44
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 fb f6 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateSystemVolumeInformationFolder
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateSystemVolumeInformationFolder"

    /*
        6813DCE7B6           | push 0xb6e7dc13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 dc e7 b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateTagHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateTagHeap"

    /*
        688A1144D5           | push 0xd544118a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 11 44 d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateTimer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateTimer"

    /*
        6816464F39           | push 0x394f4616
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 46 4f 39 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateTimerQueue
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateTimerQueue"

    /*
        681C1C2489           | push 0x89241c1c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 1c 24 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUmsCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUmsCompletionList"

    /*
        68DA94B4F4           | push 0xf4b494da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 94 b4 f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUmsThreadContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUmsThreadContext"

    /*
        68CB92F587           | push 0x87f592cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 92 f5 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUnicodeString"

    /*
        6828FD97C1           | push 0xc197fd28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 fd 97 c1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUnicodeStringFromAsciiz
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUnicodeStringFromAsciiz"

    /*
        68F17837E5           | push 0xe53778f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 78 37 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUserFiberShadowStack
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUserFiberShadowStack"

    /*
        68A2CF2A4A           | push 0x4a2acfa2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 cf 2a 4a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUserProcess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUserProcess"

    /*
        68DE0A22D6           | push 0xd6220ade
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 0a 22 d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUserProcessEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUserProcessEx"

    /*
        68740C5724           | push 0x24570c74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 0c 57 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUserSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUserSecurityObject"

    /*
        68960C1F39           | push 0x391f0c96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 0c 1f 39 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUserStack
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUserStack"

    /*
        68ABF619E1           | push 0xe119f6ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab f6 19 e1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateUserThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateUserThread"

    /*
        68C838A440           | push 0x40a438c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 38 a4 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCreateVirtualAccountSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCreateVirtualAccountSid"

    /*
        6857C643DA           | push 0xda43c657
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 c6 43 da ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCultureNameToLCID
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCultureNameToLCID"

    /*
        68C5BFD32B           | push 0x2bd3bfc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 bf d3 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCustomCPToUnicodeN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCustomCPToUnicodeN"

    /*
        68844237E8           | push 0xe8374284
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 42 37 e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlCutoverTimeToSystemTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlCutoverTimeToSystemTime"

    /*
        6817E002CE           | push 0xce02e017
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 e0 02 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeCommitDebugInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeCommitDebugInfo"

    /*
        685E9AA6D7           | push 0xd7a69a5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 9a a6 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeNormalizeProcessParams
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeNormalizeProcessParams"

    /*
        68AFC7FAC6           | push 0xc6fac7af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af c7 fa c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeactivateActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeactivateActivationContext"

    /*
        685E692307           | push 0x0723695e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 69 23 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeactivateActivationContextUnsafeFast
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeactivateActivationContextUnsafeFast"

    /*
        68FB64FC2A           | push 0x2afc64fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 64 fc 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDebugPrintTimes
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDebugPrintTimes"

    /*
        6887FDC74D           | push 0x4dc7fd87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 fd c7 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDecodePointer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDecodePointer"

    /*
        683FF10974           | push 0x7409f13f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f f1 09 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDecodeRemotePointer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDecodeRemotePointer"

    /*
        68A4E1B554           | push 0x54b5e1a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 e1 b5 54 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDecodeSystemPointer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDecodeSystemPointer"

    /*
        68E56A419D           | push 0x9d416ae5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 6a 41 9d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDecompressBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDecompressBuffer"

    /*
        688401E277           | push 0x77e20184
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 01 e2 77 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDecompressBufferEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDecompressBufferEx"

    /*
        68DDB55494           | push 0x9454b5dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd b5 54 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDecompressFragment
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDecompressFragment"

    /*
        68BD3F21FE           | push 0xfe213fbd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 3f 21 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDefaultNpAcl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDefaultNpAcl"

    /*
        681A1AA031           | push 0x31a01a1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 1a a0 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDelete
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDelete"

    /*
        680292DB00           | push 0x00db9202
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 92 db 00 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteAce"

    /*
        6804B3462B           | push 0x2b46b304
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 b3 46 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteAtomFromAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteAtomFromAtomTable"

    /*
        6849EBDDD1           | push 0xd1ddeb49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 eb dd d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteBarrier
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteBarrier"

    /*
        6881AFE45D           | push 0x5de4af81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 af e4 5d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteBoundaryDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteBoundaryDescriptor"

    /*
        68BA9255CE           | push 0xce5592ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 92 55 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteCriticalSection"

    /*
        68598444CF           | push 0xcf448459
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 84 44 cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteElementGenericTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteElementGenericTable"

    /*
        68DF288672           | push 0x728628df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 28 86 72 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteElementGenericTableAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteElementGenericTableAvl"

    /*
        68F20C62E4           | push 0xe4620cf2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 0c 62 e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteElementGenericTableAvlEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteElementGenericTableAvlEx"

    /*
        68789157B4           | push 0xb4579178
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 91 57 b4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteFunctionTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteFunctionTable"

    /*
        68801841AE           | push 0xae411880
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 18 41 ae ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteGrowableFunctionTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteGrowableFunctionTable"

    /*
        6800CE01D0           | push 0xd001ce00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 ce 01 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteHashTable"

    /*
        68EC2E4074           | push 0x74402eec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 2e 40 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteNoSplay
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteNoSplay"

    /*
        68F18F54E4           | push 0xe4548ff1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 8f 54 e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteRegistryValue
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteRegistryValue"

    /*
        6823125F53           | push 0x535f1223
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 12 5f 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteResource"

    /*
        6862CE57AD           | push 0xad57ce62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 ce 57 ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteSecurityObject"

    /*
        68B648D63A           | push 0x3ad648b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 48 d6 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteTimer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteTimer"

    /*
        68137E51FD           | push 0xfd517e13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 7e 51 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteTimerQueue
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteTimerQueue"

    /*
        681A3825EB           | push 0xeb25381a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 38 25 eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteTimerQueueEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteTimerQueueEx"

    /*
        687A5B2265           | push 0x65225b7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 5b 22 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteUmsCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteUmsCompletionList"

    /*
        68A614D834           | push 0x34d814a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 14 d8 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeleteUmsThreadContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeleteUmsThreadContext"

    /*
        68CF1AEFF7           | push 0xf7ef1acf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 1a ef f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDequeueUmsCompletionListItems
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDequeueUmsCompletionListItems"

    /*
        68CADE6E69           | push 0x696edeca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca de 6e 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeregisterSecureMemoryCacheCallback
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeregisterSecureMemoryCacheCallback"

    /*
        680EE784F1           | push 0xf184e70e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e e7 84 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeregisterWait
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeregisterWait"

    /*
        68201296EC           | push 0xec961220
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 12 96 ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeregisterWaitEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeregisterWaitEx"

    /*
        68FADC58C1           | push 0xc158dcfa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa dc 58 c1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDeriveCapabilitySidsFromName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDeriveCapabilitySidsFromName"

    /*
        688741FF6A           | push 0x6aff4187
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 41 ff 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyAtomTable"

    /*
        6805D3A2B3           | push 0xb3a2d305
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 d3 a2 b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyEnvironment
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyEnvironment"

    /*
        68306CA900           | push 0x00a96c30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 6c a9 00 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyHandleTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyHandleTable"

    /*
        68E06A0EB5           | push 0xb50e6ae0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 6a 0e b5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyHeap"

    /*
        68E6A4677C           | push 0x7c67a4e6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 a4 67 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyMemoryBlockLookaside"

    /*
        68401B48FC           | push 0xfc481b40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 1b 48 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyMemoryZone
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyMemoryZone"

    /*
        6823CAEC23           | push 0x23ecca23
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 ca ec 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyProcessParameters
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyProcessParameters"

    /*
        686F4202BF           | push 0xbf02426f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 42 02 bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDestroyQueryDebugBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDestroyQueryDebugBuffer"

    /*
        68C99EA522           | push 0x22a59ec9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 9e a5 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDetectHeapLeaks
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDetectHeapLeaks"

    /*
        686B6CAE3A           | push 0x3aae6c6b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 6c ae 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDetermineDosPathNameType_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDetermineDosPathNameType_U"

    /*
        681889C5F0           | push 0xf0c58918
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 89 c5 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDisableThreadProfiling
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDisableThreadProfiling"

    /*
        68D2E1D1A7           | push 0xa7d1e1d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 e1 d1 a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDllShutdownInProgress
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDllShutdownInProgress"

    /*
        680B992EBA           | push 0xba2e990b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 99 2e ba ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDnsHostNameToComputerName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDnsHostNameToComputerName"

    /*
        68BAD07E0A           | push 0x0a7ed0ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba d0 7e 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDoesFileExists_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDoesFileExists_U"

    /*
        6832E68825           | push 0x2588e632
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 e6 88 25 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDoesNameContainWildCards
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDoesNameContainWildCards"

    /*
        68934F5915           | push 0x15594f93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 4f 59 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosApplyFileIsolationRedirection_Ustr
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosApplyFileIsolationRedirection_Ustr"

    /*
        68FC864882           | push 0x824886fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 86 48 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosLongPathNameToNtPathName_U_WithStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosLongPathNameToNtPathName_U_WithStatus"

    /*
        68A7EE43CF           | push 0xcf43eea7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 ee 43 cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosLongPathNameToRelativeNtPathName_U_WithStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosLongPathNameToRelativeNtPathName_U_WithStatus"

    /*
        68406EB1D1           | push 0xd1b16e40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 6e b1 d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosPathNameToNtPathName_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosPathNameToNtPathName_U"

    /*
        687B2DA760           | push 0x60a72d7b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b 2d a7 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosPathNameToNtPathName_U_WithStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosPathNameToNtPathName_U_WithStatus"

    /*
        68FADD9D8C           | push 0x8c9dddfa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa dd 9d 8c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosPathNameToRelativeNtPathName_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosPathNameToRelativeNtPathName_U"

    /*
        6863F9C1D5           | push 0xd5c1f963
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 f9 c1 d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosPathNameToRelativeNtPathName_U_WithStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosPathNameToRelativeNtPathName_U_WithStatus"

    /*
        682FC86E24           | push 0x246ec82f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f c8 6e 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosSearchPath_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosSearchPath_U"

    /*
        6831D1C404           | push 0x04c4d131
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 d1 c4 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDosSearchPath_Ustr
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDosSearchPath_Ustr"

    /*
        68C389B6ED           | push 0xedb689c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 89 b6 ed ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDowncaseUnicodeChar
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDowncaseUnicodeChar"

    /*
        6821CD55ED           | push 0xed55cd21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 cd 55 ed ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDowncaseUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDowncaseUnicodeString"

    /*
        6880B700DF           | push 0xdf00b780
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 b7 00 df ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDrainNonVolatileFlush
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDrainNonVolatileFlush"

    /*
        68F079832B           | push 0x2b8379f0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 79 83 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDumpResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDumpResource"

    /*
        684DE184B0           | push 0xb084e14d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d e1 84 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlDuplicateUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlDuplicateUnicodeString"

    /*
        68E342D99C           | push 0x9cd942e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 42 d9 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEmptyAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEmptyAtomTable"

    /*
        6816765B73           | push 0x735b7616
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 76 5b 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnableEarlyCriticalSectionEventCreation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnableEarlyCriticalSectionEventCreation"

    /*
        6824B9F74D           | push 0x4df7b924
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 b9 f7 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnableThreadProfiling
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnableThreadProfiling"

    /*
        686FC0BFC8           | push 0xc8bfc06f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f c0 bf c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnclaveCallDispatch
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnclaveCallDispatch"

    /*
        6826181A9F           | push 0x9f1a1826
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 18 1a 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnclaveCallDispatchReturn
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnclaveCallDispatchReturn"

    /*
        6802F6B6B0           | push 0xb0b6f602
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 f6 b6 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEncodePointer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEncodePointer"

    /*
        68CFF18974           | push 0x7489f1cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf f1 89 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEncodeRemotePointer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEncodeRemotePointer"

    /*
        68A4E3F556           | push 0x56f5e3a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 e3 f5 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEncodeSystemPointer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEncodeSystemPointer"

    /*
        68E56C819F           | push 0x9f816ce5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 6c 81 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEndEnumerationHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEndEnumerationHashTable"

    /*
        68BCE8D679           | push 0x79d6e8bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc e8 d6 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEndStrongEnumerationHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEndStrongEnumerationHashTable"

    /*
        6857520736           | push 0x36075257
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 52 07 36 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEndWeakEnumerationHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEndWeakEnumerationHashTable"

    /*
        68138EA14C           | push 0x4ca18e13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 8e a1 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnterCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnterCriticalSection"

    /*
        68FF35E5CE           | push 0xcee535ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 35 e5 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnterUmsSchedulingMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnterUmsSchedulingMode"

    /*
        68114A739A           | push 0x9a734a11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 4a 73 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnumProcessHeaps
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnumProcessHeaps"

    /*
        685E2AB33F           | push 0x3fb32a5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 2a b3 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnumerateEntryHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnumerateEntryHashTable"

    /*
        680FE73316           | push 0x1633e70f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f e7 33 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnumerateGenericTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnumerateGenericTable"

    /*
        68110DF956           | push 0x56f90d11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 0d f9 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnumerateGenericTableAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnumerateGenericTableAvl"

    /*
        68BBF22A48           | push 0x482af2bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb f2 2a 48 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnumerateGenericTableLikeADirectory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnumerateGenericTableLikeADirectory"

    /*
        6863E121FC           | push 0xfc21e163
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 e1 21 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnumerateGenericTableWithoutSplaying
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnumerateGenericTableWithoutSplaying"

    /*
        6861FA7886           | push 0x8678fa61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 fa 78 86 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEnumerateGenericTableWithoutSplayingAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEnumerateGenericTableWithoutSplayingAvl"

    /*
        6895F289E8           | push 0xe889f295
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 f2 89 e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualComputerName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualComputerName"

    /*
        68D013B0CC           | push 0xccb013d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 13 b0 cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualDomainName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualDomainName"

    /*
        68B164B462           | push 0x62b464b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 64 b4 62 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualLuid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualLuid"

    /*
        68A12D2D9F           | push 0x9f2d2da1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 2d 2d 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualPrefixSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualPrefixSid"

    /*
        686D5C1395           | push 0x95135c6d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 5c 13 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualSid"

    /*
        68FD5F3CAF           | push 0xaf3c5ffd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 5f 3c af ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualString"

    /*
        686657B4F0           | push 0xf0b45766
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 57 b4 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualUnicodeString"

    /*
        683E6A5BD6           | push 0xd65b6a3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 6a 5b d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEqualWnfChangeStamps
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEqualWnfChangeStamps"

    /*
        685A637C50           | push 0x507c635a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 63 7c 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEraseUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEraseUnicodeString"

    /*
        68484E4716           | push 0x16474e48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 4e 47 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEthernetAddressToStringA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEthernetAddressToStringA"

    /*
        6811A9B4AF           | push 0xafb4a911
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 a9 b4 af ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEthernetAddressToStringW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEthernetAddressToStringW"

    /*
        6811A964B0           | push 0xb064a911
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 a9 64 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEthernetStringToAddressA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEthernetStringToAddressA"

    /*
        68BB7EEFC6           | push 0xc6ef7ebb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 7e ef c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlEthernetStringToAddressW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlEthernetStringToAddressW"

    /*
        68BB7E9FC7           | push 0xc79f7ebb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 7e 9f c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExecuteUmsThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExecuteUmsThread"

    /*
        68FC48C309           | push 0x09c348fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 48 c3 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExitUserProcess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExitUserProcess"

    /*
        684D811BAA           | push 0xaa1b814d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 81 1b aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExitUserThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExitUserThread"

    /*
        684713726F           | push 0x6f721347
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 13 72 6f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExpandEnvironmentStrings
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExpandEnvironmentStrings"

    /*
        688E9D6C8D           | push 0x8d6c9d8e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 9d 6c 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExpandEnvironmentStrings_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExpandEnvironmentStrings_U"

    /*
        68E2BEE3F5           | push 0xf5e3bee2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 be e3 f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExpandHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExpandHashTable"

    /*
        68AC7A3456           | push 0x56347aac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac 7a 34 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExtendCorrelationVector
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExtendCorrelationVector"

    /*
        68F0532EA0           | push 0xa02e53f0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 53 2e a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExtendMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExtendMemoryBlockLookaside"

    /*
        688B8A15DB           | push 0xdb158a8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 8a 15 db ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExtendMemoryZone
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExtendMemoryZone"

    /*
        684F87229F           | push 0x9f22874f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 87 22 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlExtractBitMap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlExtractBitMap"

    /*
        68EF3DE8E3           | push 0xe3e83def
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 3d e8 e3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFillMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFillMemory"

    /*
        68D46078B7           | push 0xb77860d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 60 78 b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFillMemoryNonTemporal
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFillMemoryNonTemporal"

    /*
        68408E5FCF           | push 0xcf5f8e40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 8e 5f cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFillNonVolatileMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFillNonVolatileMemory"

    /*
        68B4E5F6BF           | push 0xbff6e5b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 e5 f6 bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFinalReleaseOutOfProcessMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFinalReleaseOutOfProcessMemoryStream"

    /*
        685AD9A3BE           | push 0xbea3d95a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a d9 a3 be ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindAceByType
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindAceByType"

    /*
        68E43E01BC           | push 0xbc013ee4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 3e 01 bc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindActivationContextSectionGuid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindActivationContextSectionGuid"

    /*
        68B0A94357           | push 0x5743a9b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 a9 43 57 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindActivationContextSectionString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindActivationContextSectionString"

    /*
        68145B67F6           | push 0xf6675b14
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 5b 67 f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindCharInUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindCharInUnicodeString"

    /*
        68620DFB87           | push 0x87fb0d62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 0d fb 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindClearBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindClearBits"

    /*
        68E02FEC25           | push 0x25ec2fe0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 2f ec 25 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindClearBitsAndSet
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindClearBitsAndSet"

    /*
        680F0E8C4B           | push 0x4b8c0e0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 0e 8c 4b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindClearRuns
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindClearRuns"

    /*
        68602EED3D           | push 0x3ded2e60
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 2e ed 3d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindClosestEncodableLength
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindClosestEncodableLength"

    /*
        68BAF21A75           | push 0x751af2ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba f2 1a 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindExportedRoutineByName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindExportedRoutineByName"

    /*
        6898CD109C           | push 0x9c10cd98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 cd 10 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindLastBackwardRunClear
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindLastBackwardRunClear"

    /*
        68EEBFA100           | push 0x00a1bfee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee bf a1 00 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindLeastSignificantBit
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindLeastSignificantBit"

    /*
        687589E528           | push 0x28e58975
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 89 e5 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindLongestRunClear
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindLongestRunClear"

    /*
        68A6F19632           | push 0x3296f1a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 f1 96 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindMessage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindMessage"

    /*
        68C429EE63           | push 0x63ee29c4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 29 ee 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindMostSignificantBit
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindMostSignificantBit"

    /*
        6859C18EB7           | push 0xb78ec159
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 c1 8e b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindNextForwardRunClear
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindNextForwardRunClear"

    /*
        68556F705C           | push 0x5c706f55
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 6f 70 5c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindSetBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindSetBits"

    /*
        68C41D5BF4           | push 0xf45b1dc4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 1d 5b f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindSetBitsAndClear
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindSetBitsAndClear"

    /*
        6878BE7644           | push 0x4476be78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 be 76 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFindUnicodeSubstring
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFindUnicodeSubstring"

    /*
        6856793D43           | push 0x433d7956
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 79 3d 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFirstEntrySList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFirstEntrySList"

    /*
        686421FC58           | push 0x58fc2164
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 21 fc 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFirstFreeAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFirstFreeAce"

    /*
        6889F567B0           | push 0xb067f589
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 f5 67 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlsAlloc
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlsAlloc"

    /*
        68CD602CE2           | push 0xe22c60cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 60 2c e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlsFree
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlsFree"

    /*
        689E397A93           | push 0x937a399e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 39 7a 93 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlsGetValue
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlsGetValue"

    /*
        683638299D           | push 0x9d293836
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 38 29 9d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlsSetValue
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlsSetValue"

    /*
        68363829A9           | push 0xa9293836
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 38 29 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlushHeaps
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlushHeaps"

    /*
        6825F9B324           | push 0x24b3f925
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 f9 b3 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlushNonVolatileMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlushNonVolatileMemory"

    /*
        681F150A0E           | push 0x0e0a151f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 15 0a 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlushNonVolatileMemoryRanges
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlushNonVolatileMemoryRanges"

    /*
        68804EC488           | push 0x88c44e80
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 4e c4 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFlushSecureMemoryCache
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFlushSecureMemoryCache"

    /*
        68E1EF67DA           | push 0xda67efe1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 ef 67 da ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFormatCurrentUserKeyPath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFormatCurrentUserKeyPath"

    /*
        6875B588BE           | push 0xbe88b575
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 b5 88 be ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFormatMessage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFormatMessage"

    /*
        68032A98DD           | push 0xdd982a03
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 2a 98 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFormatMessageEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFormatMessageEx"

    /*
        68B6D5DE01           | push 0x01ded5b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 d5 de 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeActivationContextStack
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeActivationContextStack"

    /*
        688144C5C4           | push 0xc4c54481
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 44 c5 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeAnsiString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeAnsiString"

    /*
        6828F16782           | push 0x8267f128
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 f1 67 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeHandle
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeHandle"

    /*
        6872B6C499           | push 0x99c4b672
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 b6 c4 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeHeap"

    /*
        681F1E5AD4           | push 0xd45a1e1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 1e 5a d4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeMemoryBlockLookaside"

    /*
        6833738175           | push 0x75817333
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 73 81 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeNonVolatileToken
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeNonVolatileToken"

    /*
        684D768752           | push 0x5287764d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 76 87 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeOemString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeOemString"

    /*
        68F28F455E           | push 0x5e458ff2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 8f 45 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeSid"

    /*
        68972A8C55           | push 0x558c2a97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 2a 8c 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeThreadActivationContextStack
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeThreadActivationContextStack"

    /*
        6841A71E96           | push 0x961ea741
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 a7 1e 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeUnicodeString"

    /*
        68E55CEF3F           | push 0x3fef5ce5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 5c ef 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeUserFiberShadowStack
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeUserFiberShadowStack"

    /*
        6831C71615           | push 0x1516c731
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 c7 16 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlFreeUserStack
{
    meta:
        desc = "Metasploit::API::ntdll::RtlFreeUserStack"

    /*
        6821DCE1DC           | push 0xdce1dc21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 dc e1 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGUIDFromString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGUIDFromString"

    /*
        68E913A6AF           | push 0xafa613e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 13 a6 af ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGenerate8dot3Name
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGenerate8dot3Name"

    /*
        68FE64E85E           | push 0x5ee864fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 64 e8 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetAce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetAce"

    /*
        68C20DE8B8           | push 0xb8e80dc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 0d e8 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetActiveActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetActiveActivationContext"

    /*
        6896ED3A59           | push 0x593aed96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 ed 3a 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetActiveConsoleId
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetActiveConsoleId"

    /*
        68687DDAE9           | push 0xe9da7d68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 7d da e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetAppContainerNamedObjectPath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetAppContainerNamedObjectPath"

    /*
        68F8A8BE06           | push 0x06bea8f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 a8 be 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetAppContainerParent
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetAppContainerParent"

    /*
        68D9539D39           | push 0x399d53d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 53 9d 39 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetAppContainerSidType
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetAppContainerSidType"

    /*
        68C1DE383C           | push 0x3c38dec1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 de 38 3c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCallersAddress
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCallersAddress"

    /*
        6887E98BAD           | push 0xad8be987
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 e9 8b ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCompressionWorkSpaceSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCompressionWorkSpaceSize"

    /*
        682156D70B           | push 0x0bd75621
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 56 d7 0b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetConsoleSessionForegroundProcessId
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetConsoleSessionForegroundProcessId"

    /*
        68888B3A07           | push 0x073a8b88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 8b 3a 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetControlSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetControlSecurityDescriptor"

    /*
        68D1F924F4           | push 0xf424f9d1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 f9 24 f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCriticalSectionRecursionCount
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCriticalSectionRecursionCount"

    /*
        68C9A4CBCA           | push 0xcacba4c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 a4 cb ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCurrentDirectory_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCurrentDirectory_U"

    /*
        686F467D41           | push 0x417d466f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 46 7d 41 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCurrentPeb
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCurrentPeb"

    /*
        6876DD04BA           | push 0xba04dd76
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 dd 04 ba ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCurrentProcessorNumber
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCurrentProcessorNumber"

    /*
        68CF436374           | push 0x746343cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 43 63 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCurrentProcessorNumberEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCurrentProcessorNumberEx"

    /*
        689C48A5B4           | push 0xb4a5489c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 48 a5 b4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCurrentServiceSessionId
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCurrentServiceSessionId"

    /*
        6831BC1694           | push 0x9416bc31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 bc 16 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCurrentTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCurrentTransaction"

    /*
        686BE4186B           | push 0x6b18e46b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b e4 18 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetCurrentUmsThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetCurrentUmsThread"

    /*
        688E67AF2D           | push 0x2daf678e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 67 af 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetDaclSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetDaclSecurityDescriptor"

    /*
        682DF97F85           | push 0x857ff92d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d f9 7f 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetDeviceFamilyInfoEnum
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetDeviceFamilyInfoEnum"

    /*
        68633408C1           | push 0xc1083463
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 34 08 c1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetElementGenericTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetElementGenericTable"

    /*
        6880B643CD           | push 0xcd43b680
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 b6 43 cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetElementGenericTableAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetElementGenericTableAvl"

    /*
        680D881727           | push 0x2717880d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 88 17 27 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetEnabledExtendedFeatures
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetEnabledExtendedFeatures"

    /*
        682C3FB352           | push 0x52b33f2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 3f b3 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetExePath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetExePath"

    /*
        68746C9AE3           | push 0xe39a6c74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 6c 9a e3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetExtendedContextLength
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetExtendedContextLength"

    /*
        680B97F6D1           | push 0xd1f6970b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 97 f6 d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetExtendedContextLength2
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetExtendedContextLength2"

    /*
        6832B20E3E           | push 0x3e0eb232
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 b2 0e 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetExtendedFeaturesMask
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetExtendedFeaturesMask"

    /*
        68D22BF803           | push 0x03f82bd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 2b f8 03 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetFileMUIPath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetFileMUIPath"

    /*
        680CC4B7DD           | push 0xddb7c40c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c c4 b7 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetFrame
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetFrame"

    /*
        6870BF404D           | push 0x4d40bf70
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 bf 40 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetFullPathName_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetFullPathName_U"

    /*
        68601D43F7           | push 0xf7431d60
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 1d 43 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetFullPathName_UEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetFullPathName_UEx"

    /*
        68FDAC9B6C           | push 0x6c9bacfd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd ac 9b 6c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetFullPathName_UstrEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetFullPathName_UstrEx"

    /*
        68D2EBB582           | push 0x82b5ebd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 eb b5 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetFunctionTableListHead
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetFunctionTableListHead"

    /*
        6841CC5D3A           | push 0x3a5dcc41
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 cc 5d 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetGroupSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetGroupSecurityDescriptor"

    /*
        68D7F9FD91           | push 0x91fdf9d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 f9 fd 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetIntegerAtom
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetIntegerAtom"

    /*
        68221625C4           | push 0xc4251622
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 16 25 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetInterruptTimePrecise
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetInterruptTimePrecise"

    /*
        686F7EDF09           | push 0x09df7e6f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 7e df 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetLastNtStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetLastNtStatus"

    /*
        68D08F3769           | push 0x69378fd0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 8f 37 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetLastWin32Error
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetLastWin32Error"

    /*
        6824C3CBC1           | push 0xc1cbc324
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 c3 cb c1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetLengthWithoutLastFullDosOrNtPathElement
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetLengthWithoutLastFullDosOrNtPathElement"

    /*
        687BC66417           | push 0x1764c67b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b c6 64 17 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetLengthWithoutTrailingPathSeperators
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetLengthWithoutTrailingPathSeperators"

    /*
        6868DFCCCC           | push 0xccccdf68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 df cc cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetLocaleFileMappingAddress
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetLocaleFileMappingAddress"

    /*
        68F71C0555           | push 0x55051cf7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 1c 05 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetLongestNtPathLength
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetLongestNtPathLength"

    /*
        68198BD8D9           | push 0xd9d88b19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 8b d8 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetMultiTimePrecise
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetMultiTimePrecise"

    /*
        68EA1F05EF           | push 0xef051fea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 1f 05 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNativeSystemInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNativeSystemInformation"

    /*
        6878D6E2FA           | push 0xfae2d678
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 d6 e2 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNextEntryHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNextEntryHashTable"

    /*
        68256BECD2           | push 0xd2ec6b25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 6b ec d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNextUmsListItem
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNextUmsListItem"

    /*
        687EDCDF06           | push 0x06dfdc7e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e dc df 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNonVolatileToken
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNonVolatileToken"

    /*
        683F204BA8           | push 0xa84b203f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 20 4b a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNtGlobalFlags
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNtGlobalFlags"

    /*
        681BF4C34C           | push 0x4cc3f41b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b f4 c3 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNtProductType
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNtProductType"

    /*
        68F37840FE           | push 0xfe4078f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 78 40 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNtSystemRoot
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNtSystemRoot"

    /*
        6864C6AC04           | push 0x04acc664
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 c6 ac 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetNtVersionNumbers
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetNtVersionNumbers"

    /*
        68FEC73FC9           | push 0xc93fc7fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe c7 3f c9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetOwnerSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetOwnerSecurityDescriptor"

    /*
        68EA7DFD92           | push 0x92fd7dea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 7d fd 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetParentLocaleName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetParentLocaleName"

    /*
        68D0F8AE15           | push 0x15aef8d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 f8 ae 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetPersistedStateLocation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetPersistedStateLocation"

    /*
        6853118732           | push 0x32871153
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 11 87 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetProcessHeaps
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetProcessHeaps"

    /*
        689946D95A           | push 0x5ad94699
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 46 d9 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetProcessPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetProcessPreferredUILanguages"

    /*
        68857C7C6A           | push 0x6a7c7c85
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 7c 7c 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetProductInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetProductInfo"

    /*
        68A46D3BB7           | push 0xb73b6da4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 6d 3b b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSaclSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSaclSecurityDescriptor"

    /*
        6869F97F85           | push 0x857ff969
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 f9 7f 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSearchPath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSearchPath"

    /*
        6837212ACB           | push 0xcb2a2137
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 21 2a cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSecurityDescriptorRMControl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSecurityDescriptorRMControl"

    /*
        68F4ACB463           | push 0x63b4acf4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 ac b4 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSessionProperties
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSessionProperties"

    /*
        6848B00AB2           | push 0xb20ab048
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 b0 0a b2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSetBootStatusData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSetBootStatusData"

    /*
        688900C3F6           | push 0xf6c30089
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 00 c3 f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSuiteMask
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSuiteMask"

    /*
        68FA7D9571           | push 0x71957dfa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 7d 95 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSystemBootStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSystemBootStatus"

    /*
        68A930314F           | push 0x4f3130a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 30 31 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSystemBootStatusEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSystemBootStatusEx"

    /*
        68137F2068           | push 0x68207f13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 7f 20 68 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSystemPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSystemPreferredUILanguages"

    /*
        6874BDD24C           | push 0x4cd2bd74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 bd d2 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetSystemTimePrecise
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetSystemTimePrecise"

    /*
        68A87BAD65           | push 0x65ad7ba8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 7b ad 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetThreadErrorMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetThreadErrorMode"

    /*
        686CB8A69F           | push 0x9fa6b86c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c b8 a6 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetThreadLangIdByIndex
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetThreadLangIdByIndex"

    /*
        68E0973DEF           | push 0xef3d97e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 97 3d ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetThreadPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetThreadPreferredUILanguages"

    /*
        68637CEEC2           | push 0xc2ee7c63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 7c ee c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetThreadWorkOnBehalfTicket
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetThreadWorkOnBehalfTicket"

    /*
        68A5D19DBF           | push 0xbf9dd1a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 d1 9d bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetTokenNamedObjectPath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetTokenNamedObjectPath"

    /*
        685CAA152B           | push 0x2b15aa5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c aa 15 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetUILanguageInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetUILanguageInfo"

    /*
        684A485F75           | push 0x755f484a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 48 5f 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetUmsCompletionListEvent
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetUmsCompletionListEvent"

    /*
        68B90C16CA           | push 0xca160cb9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 0c 16 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetUnloadEventTrace
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetUnloadEventTrace"

    /*
        681857B67C           | push 0x7cb65718
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 57 b6 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetUnloadEventTraceEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetUnloadEventTraceEx"

    /*
        68DE1A6AC9           | push 0xc96a1ade
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 1a 6a c9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetUserInfoHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetUserInfoHeap"

    /*
        689AEA8D46           | push 0x468dea9a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a ea 8d 46 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetUserPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetUserPreferredUILanguages"

    /*
        6847351BBD           | push 0xbd1b3547
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 35 1b bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGetVersion
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGetVersion"

    /*
        685B9D8073           | push 0x73809d5b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 9d 80 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGrowFunctionTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGrowFunctionTable"

    /*
        680EBED46F           | push 0x6fd4be0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e be d4 6f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlGuardCheckLongJumpTarget
{
    meta:
        desc = "Metasploit::API::ntdll::RtlGuardCheckLongJumpTarget"

    /*
        681A103EE0           | push 0xe03e101a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 10 3e e0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlHashUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlHashUnicodeString"

    /*
        68F668DEFF           | push 0xffde68f6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 68 de ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlHeapTrkInitialize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlHeapTrkInitialize"

    /*
        680426AEC4           | push 0xc4ae2604
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 26 ae c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIdentifierAuthoritySid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIdentifierAuthoritySid"

    /*
        68B9FC6DBD           | push 0xbd6dfcb9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 fc 6d bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIdnToAscii
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIdnToAscii"

    /*
        6883938061           | push 0x61809383
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 93 80 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIdnToNameprepUnicode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIdnToNameprepUnicode"

    /*
        6810EA4A3F           | push 0x3f4aea10
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 ea 4a 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIdnToUnicode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIdnToUnicode"

    /*
        68DADF4C07           | push 0x074cdfda
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da df 4c 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlImageDirectoryEntryToData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlImageDirectoryEntryToData"

    /*
        6814ACF7E6           | push 0xe6f7ac14
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 ac f7 e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlImageNtHeader
{
    meta:
        desc = "Metasploit::API::ntdll::RtlImageNtHeader"

    /*
        683B2EE93E           | push 0x3ee92e3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 2e e9 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlImageNtHeaderEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlImageNtHeaderEx"

    /*
        688FE31F56           | push 0x561fe38f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f e3 1f 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlImageRvaToSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlImageRvaToSection"

    /*
        6833A983D3           | push 0xd383a933
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 a9 83 d3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlImageRvaToVa
{
    meta:
        desc = "Metasploit::API::ntdll::RtlImageRvaToVa"

    /*
        68F3835EBD           | push 0xbd5e83f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 83 5e bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlImpersonateSelf
{
    meta:
        desc = "Metasploit::API::ntdll::RtlImpersonateSelf"

    /*
        68B8A47429           | push 0x2974a4b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 a4 74 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlImpersonateSelfEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlImpersonateSelfEx"

    /*
        680983FDF8           | push 0xf8fd8309
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 83 fd f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIncrementCorrelationVector
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIncrementCorrelationVector"

    /*
        687CB40881           | push 0x8108b47c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c b4 08 81 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitAnsiString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitAnsiString"

    /*
        6868FD8580           | push 0x8085fd68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 fd 85 80 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitAnsiStringEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitAnsiStringEx"

    /*
        68DFAE53BD           | push 0xbd53aedf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df ae 53 bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitBarrier
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitBarrier"

    /*
        68E5EF4B44           | push 0x444befe5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 ef 4b 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitCodePageTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitCodePageTable"

    /*
        68BD901726           | push 0x261790bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 90 17 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitEnumerationHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitEnumerationHashTable"

    /*
        684C46073F           | push 0x3f07464c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 46 07 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitMemoryStream"

    /*
        6843276ED7           | push 0xd76e2743
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 27 6e d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitNlsTables
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitNlsTables"

    /*
        682C8630AD           | push 0xad30862c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 86 30 ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitOutOfProcessMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitOutOfProcessMemoryStream"

    /*
        6812D3049A           | push 0x9a04d312
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 d3 04 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitString"

    /*
        68DCD800E8           | push 0xe800d8dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc d8 00 e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitStringEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitStringEx"

    /*
        68F98B0A9C           | push 0x9c0a8bf9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 8b 0a 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitStrongEnumerationHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitStrongEnumerationHashTable"

    /*
        68196746AC           | push 0xac466719
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 67 46 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitUnicodeString"

    /*
        68FD98EBBF           | push 0xbfeb98fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 98 eb bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitUnicodeStringEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitUnicodeStringEx"

    /*
        682F94BA96           | push 0x96ba942f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 94 ba 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitWeakEnumerationHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitWeakEnumerationHashTable"

    /*
        68668A7A52           | push 0x527a8a66
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 8a 7a 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeAtomPackage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeAtomPackage"

    /*
        68BBB6DABB           | push 0xbbdab6bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb b6 da bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeBitMap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeBitMap"

    /*
        687D163AEF           | push 0xef3a167d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 16 3a ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeBitMapEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeBitMapEx"

    /*
        683BF4596A           | push 0x6a59f43b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b f4 59 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeConditionVariable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeConditionVariable"

    /*
        68477CC9E0           | push 0xe0c97c47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 7c c9 e0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeContext"

    /*
        686C0ECA43           | push 0x43ca0e6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 0e ca 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeCorrelationVector
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeCorrelationVector"

    /*
        6827AEB1DB           | push 0xdbb1ae27
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 ae b1 db ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeCriticalSection"

    /*
        68932132DC           | push 0xdc322193
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 21 32 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeCriticalSectionAndSpinCount
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeCriticalSectionAndSpinCount"

    /*
        68847058F8           | push 0xf8587084
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 70 58 f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeCriticalSectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeCriticalSectionEx"

    /*
        68B6B95CA8           | push 0xa85cb9b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 b9 5c a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeExtendedContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeExtendedContext"

    /*
        68E95814D2           | push 0xd21458e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 58 14 d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeExtendedContext2
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeExtendedContext2"

    /*
        6821B3FE4C           | push 0x4cfeb321
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 b3 fe 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeGenericTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeGenericTable"

    /*
        6868C40795           | push 0x9507c468
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 c4 07 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeGenericTableAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeGenericTableAvl"

    /*
        682910A7F6           | push 0xf6a71029
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 10 a7 f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeHandleTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeHandleTable"

    /*
        686F13F874           | push 0x74f8136f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 13 f8 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeNtUserPfn
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeNtUserPfn"

    /*
        68F0EC034B           | push 0x4b03ecf0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 ec 03 4b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeRXact
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeRXact"

    /*
        687AE21619           | push 0x1916e27a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a e2 16 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeResource"

    /*
        684C3BBF7D           | push 0x7dbf3b4c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 3b bf 7d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeSListHead
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeSListHead"

    /*
        683776B1CC           | push 0xccb17637
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 76 b1 cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeSRWLock
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeSRWLock"

    /*
        68208B0BD7           | push 0xd70b8b20
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 8b 0b d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeSid"

    /*
        68588E0DF0           | push 0xf00d8e58
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 8e 0d f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInitializeSidEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInitializeSidEx"

    /*
        68FBEA379F           | push 0x9f37eafb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb ea 37 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInsertElementGenericTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInsertElementGenericTable"

    /*
        68E031658B           | push 0x8b6531e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 31 65 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInsertElementGenericTableAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInsertElementGenericTableAvl"

    /*
        6804CB93E6           | push 0xe693cb04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 cb 93 e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInsertElementGenericTableFull
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInsertElementGenericTableFull"

    /*
        681CA7A7DD           | push 0xdda7a71c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c a7 a7 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInsertElementGenericTableFullAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInsertElementGenericTableFullAvl"

    /*
        68EF4F385F           | push 0x5f384fef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 4f 38 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInsertEntryHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInsertEntryHashTable"

    /*
        68438DF817           | push 0x17f88d43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 8d f8 17 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInstallFunctionTableCallback
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInstallFunctionTableCallback"

    /*
        68D8BBF53E           | push 0x3ef5bbd8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 bb f5 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInt64ToUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInt64ToUnicodeString"

    /*
        68327A279C           | push 0x9c277a32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 7a 27 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIntegerToChar
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIntegerToChar"

    /*
        680F5D3DDE           | push 0xde3d5d0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 5d 3d de ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIntegerToUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIntegerToUnicodeString"

    /*
        6803DD66DC           | push 0xdc66dd03
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 dd 66 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInterlockedClearBitRun
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInterlockedClearBitRun"

    /*
        68FA9FCB55           | push 0x55cb9ffa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 9f cb 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInterlockedFlushSList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInterlockedFlushSList"

    /*
        6850B47DA9           | push 0xa97db450
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 b4 7d a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInterlockedPopEntrySList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInterlockedPopEntrySList"

    /*
        681EB043BD           | push 0xbd43b01e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e b0 43 bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInterlockedPushEntrySList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInterlockedPushEntrySList"

    /*
        68A40B923A           | push 0x3a920ba4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 0b 92 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInterlockedPushListSList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInterlockedPushListSList"

    /*
        68A7A03472           | push 0x7234a0a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 a0 34 72 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInterlockedPushListSListEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInterlockedPushListSListEx"

    /*
        689B7EFC28           | push 0x28fc7e9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 7e fc 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlInterlockedSetBitRun
{
    meta:
        desc = "Metasploit::API::ntdll::RtlInterlockedSetBitRun"

    /*
        6817BF5036           | push 0x3650bf17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 bf 50 36 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIoDecodeMemIoResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIoDecodeMemIoResource"

    /*
        6825FE48F9           | push 0xf948fe25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 fe 48 f9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIoEncodeMemIoResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIoEncodeMemIoResource"

    /*
        68250089FB           | push 0xfb890025
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 00 89 fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4AddressToStringA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4AddressToStringA"

    /*
        6897E59ABF           | push 0xbf9ae597
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 e5 9a bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4AddressToStringExA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4AddressToStringExA"

    /*
        686FC7D588           | push 0x88d5c76f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f c7 d5 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4AddressToStringExW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4AddressToStringExW"

    /*
        686FC78589           | push 0x8985c76f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f c7 85 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4AddressToStringW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4AddressToStringW"

    /*
        6897E54AC0           | push 0xc04ae597
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 e5 4a c0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4StringToAddressA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4StringToAddressA"

    /*
        6841BBD5D6           | push 0xd6d5bb41
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 bb d5 d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4StringToAddressExA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4StringToAddressExA"

    /*
        68F5318B57           | push 0x578b31f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 31 8b 57 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4StringToAddressExW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4StringToAddressExW"

    /*
        68F5313B58           | push 0x583b31f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 31 3b 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv4StringToAddressW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv4StringToAddressW"

    /*
        6841BB85D7           | push 0xd785bb41
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 bb 85 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6AddressToStringA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6AddressToStringA"

    /*
        68A7E59ABF           | push 0xbf9ae5a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 e5 9a bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6AddressToStringExA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6AddressToStringExA"

    /*
        686FCBD588           | push 0x88d5cb6f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f cb d5 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6AddressToStringExW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6AddressToStringExW"

    /*
        686FCB8589           | push 0x8985cb6f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f cb 85 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6AddressToStringW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6AddressToStringW"

    /*
        68A7E54AC0           | push 0xc04ae5a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 e5 4a c0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6StringToAddressA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6StringToAddressA"

    /*
        6851BBD5D6           | push 0xd6d5bb51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 bb d5 d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6StringToAddressExA
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6StringToAddressExA"

    /*
        68F5358B57           | push 0x578b35f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 35 8b 57 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6StringToAddressExW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6StringToAddressExW"

    /*
        68F5353B58           | push 0x583b35f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 35 3b 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIpv6StringToAddressW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIpv6StringToAddressW"

    /*
        6851BB85D7           | push 0xd785bb51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 bb 85 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsActivationContextActive
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsActivationContextActive"

    /*
        68B9CF6D0D           | push 0x0d6dcfb9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 cf 6d 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsCapabilitySid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsCapabilitySid"

    /*
        681BB5B6E9           | push 0xe9b6b51b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b b5 b6 e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsCloudFilesPlaceholder
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsCloudFilesPlaceholder"

    /*
        68B60BD3C8           | push 0xc8d30bb6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 0b d3 c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsCriticalSectionLocked
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsCriticalSectionLocked"

    /*
        681FB0F538           | push 0x38f5b01f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f b0 f5 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsCriticalSectionLockedByThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsCriticalSectionLockedByThread"

    /*
        687CBA0B20           | push 0x200bba7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c ba 0b 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsCurrentProcess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsCurrentProcess"

    /*
        68EF98B2FA           | push 0xfab298ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 98 b2 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsCurrentThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsCurrentThread"

    /*
        685A5D6652           | push 0x52665d5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 5d 66 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsCurrentThreadAttachExempt
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsCurrentThreadAttachExempt"

    /*
        686AFD03BE           | push 0xbe03fd6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a fd 03 be ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsDosDeviceName_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsDosDeviceName_U"

    /*
        6894FE4365           | push 0x6543fe94
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 fe 43 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsElevatedRid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsElevatedRid"

    /*
        683C5DF182           | push 0x82f15d3c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 5d f1 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsGenericTableEmpty
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsGenericTableEmpty"

    /*
        682C4A27DD           | push 0xdd274a2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 4a 27 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsGenericTableEmptyAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsGenericTableEmptyAvl"

    /*
        68354F377F           | push 0x7f374f35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 4f 37 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsMultiSessionSku
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsMultiSessionSku"

    /*
        68530E38AF           | push 0xaf380e53
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 0e 38 af ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsMultiUsersInSessionSku
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsMultiUsersInSessionSku"

    /*
        68E3CAB9C0           | push 0xc0b9cae3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 ca b9 c0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsNameInExpression
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsNameInExpression"

    /*
        68D6C5BEEB           | push 0xebbec5d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 c5 be eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsNameInUnUpcasedExpression
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsNameInUnUpcasedExpression"

    /*
        68D04585A8           | push 0xa88545d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 45 85 a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsNameLegalDOS8Dot3
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsNameLegalDOS8Dot3"

    /*
        68810EB147           | push 0x47b10e81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 0e b1 47 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsNonEmptyDirectoryReparsePointAllowed
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsNonEmptyDirectoryReparsePointAllowed"

    /*
        6851CDEDE2           | push 0xe2edcd51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 cd ed e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsNormalizedString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsNormalizedString"

    /*
        6861D93A24           | push 0x243ad961
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 d9 3a 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsPackageSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsPackageSid"

    /*
        68D26B2F43           | push 0x432f6bd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 6b 2f 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsParentOfChildAppContainer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsParentOfChildAppContainer"

    /*
        6803982199           | push 0x99219803
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 98 21 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsPartialPlaceholder
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsPartialPlaceholder"

    /*
        682E9BDE4E           | push 0x4ede9b2e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 9b de 4e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsPartialPlaceholderFileHandle
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsPartialPlaceholderFileHandle"

    /*
        682988FD3A           | push 0x3afd8829
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 88 fd 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsPartialPlaceholderFileInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsPartialPlaceholderFileInfo"

    /*
        68A612D7C4           | push 0xc4d712a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 12 d7 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsProcessorFeaturePresent
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsProcessorFeaturePresent"

    /*
        688FDE184B           | push 0x4b18de8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f de 18 4b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsStateSeparationEnabled
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsStateSeparationEnabled"

    /*
        682A91C21B           | push 0x1bc2912a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 91 c2 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsTextUnicode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsTextUnicode"

    /*
        687CE2FFFA           | push 0xfaffe27c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c e2 ff fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsThreadWithinLoaderCallout
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsThreadWithinLoaderCallout"

    /*
        680C7A8232           | push 0x32827a0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 7a 82 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsUntrustedObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsUntrustedObject"

    /*
        685626E048           | push 0x48e02656
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 26 e0 48 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsValidHandle
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsValidHandle"

    /*
        6857366CD9           | push 0xd96c3657
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 36 6c d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsValidIndexHandle
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsValidIndexHandle"

    /*
        6887D3BF17           | push 0x17bfd387
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 d3 bf 17 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsValidLocaleName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsValidLocaleName"

    /*
        68DD0BB81A           | push 0x1ab80bdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 0b b8 1a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlIsValidProcessTrustLabelSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlIsValidProcessTrustLabelSid"

    /*
        6884B5ED28           | push 0x28edb584
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 b5 ed 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlKnownExceptionFilter
{
    meta:
        desc = "Metasploit::API::ntdll::RtlKnownExceptionFilter"

    /*
        68870E53C3           | push 0xc3530e87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 0e 53 c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLCIDToCultureName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLCIDToCultureName"

    /*
        68DE825DBF           | push 0xbf5d82de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 82 5d bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLargeIntegerToChar
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLargeIntegerToChar"

    /*
        681D1C8791           | push 0x91871c1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 1c 87 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLcidToLocaleName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLcidToLocaleName"

    /*
        68A2E7A698           | push 0x98a6e7a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 e7 a6 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLeaveCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLeaveCriticalSection"

    /*
        688724183A           | push 0x3a182487
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 24 18 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLengthRequiredSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLengthRequiredSid"

    /*
        68EF939754           | push 0x549793ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 93 97 54 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLengthSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLengthSecurityDescriptor"

    /*
        6893D884B6           | push 0xb684d893
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 d8 84 b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLengthSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLengthSid"

    /*
        68C524474F           | push 0x4f4724c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 24 47 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLengthSidAsUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLengthSidAsUnicodeString"

    /*
        685A4C9246           | push 0x46924c5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 4c 92 46 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLoadString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLoadString"

    /*
        68DDDE00A0           | push 0xa000dedd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd de 00 a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLocalTimeToSystemTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLocalTimeToSystemTime"

    /*
        68BF1FFA32           | push 0x32fa1fbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 1f fa 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLocaleNameToLcid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLocaleNameToLcid"

    /*
        68A940AAA4           | push 0xa4aa40a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 40 aa a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLocateExtendedFeature
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLocateExtendedFeature"

    /*
        6889A88A03           | push 0x038aa889
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 a8 8a 03 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLocateExtendedFeature2
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLocateExtendedFeature2"

    /*
        68D33E00CA           | push 0xca003ed3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 3e 00 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLocateLegacyContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLocateLegacyContext"

    /*
        68C5CC2B4A           | push 0x4a2bccc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 cc 2b 4a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLockBootStatusData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLockBootStatusData"

    /*
        689B0D7492           | push 0x92740d9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 0d 74 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLockCurrentThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLockCurrentThread"

    /*
        682224EAB8           | push 0xb8ea2422
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 24 ea b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLockHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLockHeap"

    /*
        68C21D52DA           | push 0xda521dc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 1d 52 da ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLockMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLockMemoryBlockLookaside"

    /*
        682B792475           | push 0x7524792b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 79 24 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLockMemoryStreamRegion
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLockMemoryStreamRegion"

    /*
        689E742B75           | push 0x752b749e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 74 2b 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLockMemoryZone
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLockMemoryZone"

    /*
        68CD415E07           | push 0x075e41cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 41 5e 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLockModuleSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLockModuleSection"

    /*
        68207B62FD           | push 0xfd627b20
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 7b 62 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLogStackBackTrace
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLogStackBackTrace"

    /*
        6837A9AE7C           | push 0x7caea937
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 a9 ae 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupAtomInAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupAtomInAtomTable"

    /*
        68AD64696D           | push 0x6d6964ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 64 69 6d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupElementGenericTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupElementGenericTable"

    /*
        68F8B2E662           | push 0x62e6b2f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 b2 e6 62 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupElementGenericTableAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupElementGenericTableAvl"

    /*
        6806CE4216           | push 0x1642ce06
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 ce 42 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupElementGenericTableFull
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupElementGenericTableFull"

    /*
        689424B9F5           | push 0xf5b92494
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 24 b9 f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupElementGenericTableFullAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupElementGenericTableFullAvl"

    /*
        68EA72684F           | push 0x4f6872ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 72 68 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupEntryHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupEntryHashTable"

    /*
        68738FFBC6           | push 0xc6fb8f73
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 8f fb c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupFirstMatchingElementGenericTableAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupFirstMatchingElementGenericTableAvl"

    /*
        6877CFD2EC           | push 0xecd2cf77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 cf d2 ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupFunctionEntry
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupFunctionEntry"

    /*
        6811266875           | push 0x75682611
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 26 68 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlLookupFunctionTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlLookupFunctionTable"

    /*
        689854C7D0           | push 0xd0c75498
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 54 c7 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMakeSelfRelativeSD
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMakeSelfRelativeSD"

    /*
        6855EEB69F           | push 0x9fb6ee55
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 ee b6 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMapGenericMask
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMapGenericMask"

    /*
        6838C021DC           | push 0xdc21c038
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 c0 21 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMapSecurityErrorToNtStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMapSecurityErrorToNtStatus"

    /*
        686EDD0CD8           | push 0xd80cdd6e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e dd 0c d8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMoveMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMoveMemory"

    /*
        68F68F7881           | push 0x81788ff6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 8f 78 81 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMultiAppendUnicodeStringBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMultiAppendUnicodeStringBuffer"

    /*
        68C7953840           | push 0x403895c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 95 38 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMultiByteToUnicodeN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMultiByteToUnicodeN"

    /*
        689254F21A           | push 0x1af25492
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 54 f2 1a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMultiByteToUnicodeSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMultiByteToUnicodeSize"

    /*
        684A367B9B           | push 0x9b7b364a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 36 7b 9b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMultipleAllocateHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMultipleAllocateHeap"

    /*
        6890D72B1A           | push 0x1a2bd790
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 d7 2b 1a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlMultipleFreeHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlMultipleFreeHeap"

    /*
        681C44E5CB           | push 0xcbe5441c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 44 e5 cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNewInstanceSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNewInstanceSecurityObject"

    /*
        6840CCE1A1           | push 0xa1e1cc40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 cc e1 a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNewSecurityGrantedAccess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNewSecurityGrantedAccess"

    /*
        68259614F1           | push 0xf1149625
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 96 14 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNewSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNewSecurityObject"

    /*
        6832645150           | push 0x50516432
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 64 51 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNewSecurityObjectEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNewSecurityObjectEx"

    /*
        6853612DB0           | push 0xb02d6153
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 61 2d b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNewSecurityObjectWithMultipleInheritance
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNewSecurityObjectWithMultipleInheritance"

    /*
        68F72A34A0           | push 0xa0342af7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 2a 34 a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNormalizeProcessParams
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNormalizeProcessParams"

    /*
        680AF7BDF7           | push 0xf7bdf70a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a f7 bd f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNormalizeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNormalizeString"

    /*
        683F6ED89D           | push 0x9dd86e3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 6e d8 9d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNtPathNameToDosPathName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNtPathNameToDosPathName"

    /*
        68472A83B4           | push 0xb4832a47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 2a 83 b4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNtStatusToDosError
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNtStatusToDosError"

    /*
        682D40E5FA           | push 0xfae5402d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 40 e5 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNtStatusToDosErrorNoTeb
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNtStatusToDosErrorNoTeb"

    /*
        6826B5D647           | push 0x47d6b526
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 b5 d6 47 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNtdllName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNtdllName"

    /*
        688194617A           | push 0x7a619481
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 94 61 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNumberGenericTableElements
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNumberGenericTableElements"

    /*
        68DB315577           | push 0x775531db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db 31 55 77 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNumberGenericTableElementsAvl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNumberGenericTableElementsAvl"

    /*
        6804AB6BDC           | push 0xdc6bab04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 ab 6b dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNumberOfClearBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNumberOfClearBits"

    /*
        68E5F25110           | push 0x1051f2e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 f2 51 10 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNumberOfClearBitsInRange
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNumberOfClearBitsInRange"

    /*
        6833BD7B56           | push 0x567bbd33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 bd 7b 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNumberOfSetBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNumberOfSetBits"

    /*
        68D0B40408           | push 0x0804b4d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 b4 04 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNumberOfSetBitsInRange
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNumberOfSetBitsInRange"

    /*
        6892FAD34C           | push 0x4cd3fa92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 fa d3 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlNumberOfSetBitsUlongPtr
{
    meta:
        desc = "Metasploit::API::ntdll::RtlNumberOfSetBitsUlongPtr"

    /*
        68A41CB6BA           | push 0xbab61ca4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 1c b6 ba ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlOemStringToUnicodeSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlOemStringToUnicodeSize"

    /*
        68D1FD22EE           | push 0xee22fdd1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 fd 22 ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlOemStringToUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlOemStringToUnicodeString"

    /*
        6880530BAC           | push 0xac0b5380
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 53 0b ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlOemToUnicodeN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlOemToUnicodeN"

    /*
        68F55C6688           | push 0x88665cf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 5c 66 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlOpenCurrentUser
{
    meta:
        desc = "Metasploit::API::ntdll::RtlOpenCurrentUser"

    /*
        6811E8DE03           | push 0x03dee811
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 e8 de 03 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlOsDeploymentState
{
    meta:
        desc = "Metasploit::API::ntdll::RtlOsDeploymentState"

    /*
        689D6FF01E           | push 0x1ef06f9d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 6f f0 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlOwnerAcesPresent
{
    meta:
        desc = "Metasploit::API::ntdll::RtlOwnerAcesPresent"

    /*
        68AAFB5FF1           | push 0xf15ffbaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa fb 5f f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPcToFileHeader
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPcToFileHeader"

    /*
        6851DD262A           | push 0x2a26dd51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 dd 26 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPinAtomInAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPinAtomInAtomTable"

    /*
        689D0A2AA8           | push 0xa82a0a9d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 0a 2a a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPopFrame
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPopFrame"

    /*
        68B0C03056           | push 0x5630c0b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 c0 30 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPrefixString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPrefixString"

    /*
        682D670E35           | push 0x350e672d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 67 0e 35 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPrefixUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPrefixUnicodeString"

    /*
        6827639D61           | push 0x619d6327
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 63 9d 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPrepareForProcessCloning
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPrepareForProcessCloning"

    /*
        68F132995A           | push 0x5a9932f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 32 99 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlProcessFlsData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlProcessFlsData"

    /*
        68F05E95F2           | push 0xf2955ef0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 5e 95 f2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlProtectHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlProtectHeap"

    /*
        6846834F3C           | push 0x3c4f8346
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 83 4f 3c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPublishWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPublishWnfStateData"

    /*
        68988E3DAC           | push 0xac3d8e98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 8e 3d ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlPushFrame
{
    meta:
        desc = "Metasploit::API::ntdll::RtlPushFrame"

    /*
        684EE6537B           | push 0x7b53e64e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e e6 53 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryActivationContextApplicationSettings
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryActivationContextApplicationSettings"

    /*
        685EA394FF           | push 0xff94a35e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e a3 94 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryAtomInAtomTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryAtomInAtomTable"

    /*
        68B31EC287           | push 0x87c21eb3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 1e c2 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryCriticalSectionOwner
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryCriticalSectionOwner"

    /*
        6844B77A44           | push 0x447ab744
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 b7 7a 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryDepthSList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryDepthSList"

    /*
        689509426E           | push 0x6e420995
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 09 42 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryDynamicTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryDynamicTimeZoneInformation"

    /*
        687D7732FA           | push 0xfa32777d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 77 32 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryElevationFlags
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryElevationFlags"

    /*
        680160CEE3           | push 0xe3ce6001
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 60 ce e3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryEnvironmentVariable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryEnvironmentVariable"

    /*
        6891923FF0           | push 0xf03f9291
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 92 3f f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryEnvironmentVariable_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryEnvironmentVariable_U"

    /*
        68BBFFA0AA           | push 0xaaa0ffbb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb ff a0 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryHeapInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryHeapInformation"

    /*
        680A3C0CEA           | push 0xea0c3c0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 3c 0c ea ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryImageMitigationPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryImageMitigationPolicy"

    /*
        689032B701           | push 0x01b73290
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 32 b7 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryInformationAcl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryInformationAcl"

    /*
        68CA57745C           | push 0x5c7457ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 57 74 5c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryInformationActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryInformationActivationContext"

    /*
        688A8CEC60           | push 0x60ec8c8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 8c ec 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryInformationActiveActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryInformationActiveActivationContext"

    /*
        68363270D3           | push 0xd3703236
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 32 70 d3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryInterfaceMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryInterfaceMemoryStream"

    /*
        6838A404CA           | push 0xca04a438
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 a4 04 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryModuleInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryModuleInformation"

    /*
        68AE67C747           | push 0x47c767ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 67 c7 47 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryPackageClaims
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryPackageClaims"

    /*
        684E1DDEF9           | push 0xf9de1d4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 1d de f9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryPackageIdentity
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryPackageIdentity"

    /*
        6840237485           | push 0x85742340
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 23 74 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryPackageIdentityEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryPackageIdentityEx"

    /*
        68E024DDF8           | push 0xf8dd24e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 24 dd f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryPerformanceCounter
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryPerformanceCounter"

    /*
        682A578E69           | push 0x698e572a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 57 8e 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryPerformanceFrequency
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryPerformanceFrequency"

    /*
        68DA3C7E7A           | push 0x7a7e3cda
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 3c 7e 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryProcessBackTraceInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryProcessBackTraceInformation"

    /*
        68195DE6F7           | push 0xf7e65d19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 5d e6 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryProcessDebugInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryProcessDebugInformation"

    /*
        686EBF4C1C           | push 0x1c4cbf6e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e bf 4c 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryProcessHeapInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryProcessHeapInformation"

    /*
        682B04C745           | push 0x45c7042b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 04 c7 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryProcessLockInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryProcessLockInformation"

    /*
        68DB2BC7C6           | push 0xc6c72bdb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db 2b c7 c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryProcessPlaceholderCompatibilityMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryProcessPlaceholderCompatibilityMode"

    /*
        682486F4A8           | push 0xa8f48624
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 86 f4 a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryProtectedPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryProtectedPolicy"

    /*
        688F5B2827           | push 0x27285b8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 5b 28 27 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryRegistryValueWithFallback
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryRegistryValueWithFallback"

    /*
        68383FC747           | push 0x47c73f38
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 3f c7 47 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryRegistryValues
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryRegistryValues"

    /*
        68F394D410           | push 0x10d494f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 94 d4 10 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryRegistryValuesEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryRegistryValuesEx"

    /*
        68C391F9D0           | push 0xd0f991c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 91 f9 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryResourcePolicy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryResourcePolicy"

    /*
        68BB82F869           | push 0x69f882bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 82 f8 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQuerySecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQuerySecurityObject"

    /*
        683320D832           | push 0x32d82033
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 20 d8 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryTagHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryTagHeap"

    /*
        68771F92BD           | push 0xbd921f77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 1f 92 bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryThreadPlaceholderCompatibilityMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryThreadPlaceholderCompatibilityMode"

    /*
        68A44258CD           | push 0xcd5842a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 42 58 cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryThreadProfiling
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryThreadProfiling"

    /*
        68BD1667F5           | push 0xf56716bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 16 67 f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryTimeZoneInformation"

    /*
        68A272F815           | push 0x15f872a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 72 f8 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryTokenHostIdAsUlong64
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryTokenHostIdAsUlong64"

    /*
        68E9B34D32           | push 0x324db3e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 b3 4d 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryUmsThreadInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryUmsThreadInformation"

    /*
        6842201DFD           | push 0xfd1d2042
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 20 1d fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryUnbiasedInterruptTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryUnbiasedInterruptTime"

    /*
        683FC06745           | push 0x4567c03f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f c0 67 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryValidationRunlevel
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryValidationRunlevel"

    /*
        68B6F96373           | push 0x7363f9b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 f9 63 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryWnfMetaNotification
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryWnfMetaNotification"

    /*
        68DDA1C4E7           | push 0xe7c4a1dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd a1 c4 e7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryWnfStateData"

    /*
        68C6D04C92           | push 0x924cd0c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 d0 4c 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueryWnfStateDataWithExplicitScope
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueryWnfStateDataWithExplicitScope"

    /*
        68B62EFC45           | push 0x45fc2eb6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 2e fc 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueueApcWow64Thread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueueApcWow64Thread"

    /*
        6813BFB3B9           | push 0xb9b3bf13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 bf b3 b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlQueueWorkItem
{
    meta:
        desc = "Metasploit::API::ntdll::RtlQueueWorkItem"

    /*
        6821AE6FEC           | push 0xec6fae21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 ae 6f ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRaiseCustomSystemEventTrigger
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRaiseCustomSystemEventTrigger"

    /*
        688040B3EF           | push 0xefb34080
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 40 b3 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRaiseException
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRaiseException"

    /*
        68EFF8827F           | push 0x7f82f8ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef f8 82 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRaiseStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRaiseStatus"

    /*
        6842E82C19           | push 0x192ce842
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 e8 2c 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRandom
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRandom"

    /*
        68C0B053FF           | push 0xff53b0c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 b0 53 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRandomEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRandomEx"

    /*
        68FF84C070           | push 0x70c084ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 84 c0 70 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRbInsertNodeEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRbInsertNodeEx"

    /*
        6892EEEC71           | push 0x71ecee92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 ee ec 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRbRemoveNode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRbRemoveNode"

    /*
        68A11B6805           | push 0x05681ba1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 1b 68 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReAllocateHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReAllocateHeap"

    /*
        68AB82BFA4           | push 0xa4bf82ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 82 bf a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReadMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReadMemoryStream"

    /*
        68420777AF           | push 0xaf770742
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 07 77 af ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReadOutOfProcessMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReadOutOfProcessMemoryStream"

    /*
        68FFD2921A           | push 0x1a92d2ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff d2 92 1a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReadThreadProfilingData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReadThreadProfilingData"

    /*
        68177A2CBF           | push 0xbf2c7a17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 7a 2c bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRealPredecessor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRealPredecessor"

    /*
        686936CE13           | push 0x13ce3669
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 36 ce 13 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRealSuccessor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRealSuccessor"

    /*
        681CBED5C8           | push 0xc8d5be1c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c be d5 c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRegisterForWnfMetaNotification
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRegisterForWnfMetaNotification"

    /*
        6884A87008           | push 0x0870a884
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 a8 70 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRegisterSecureMemoryCacheCallback
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRegisterSecureMemoryCacheCallback"

    /*
        6895483B4F           | push 0x4f3b4895
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 48 3b 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRegisterThreadWithCsrss
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRegisterThreadWithCsrss"

    /*
        68EB279B22           | push 0x229b27eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 27 9b 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRegisterWait
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRegisterWait"

    /*
        688DCDA2AF           | push 0xafa2cd8d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d cd a2 af ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleaseActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleaseActivationContext"

    /*
        68855C7E0E           | push 0x0e7e5c85
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 5c 7e 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleaseMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleaseMemoryStream"

    /*
        68905084EC           | push 0xec845090
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 50 84 ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleasePath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleasePath"

    /*
        687CEF5365           | push 0x6553ef7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c ef 53 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleasePebLock
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleasePebLock"

    /*
        68B7E34D7A           | push 0x7a4de3b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 e3 4d 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleasePrivilege
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleasePrivilege"

    /*
        68FADB5D30           | push 0x305ddbfa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa db 5d 30 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleaseRelativeName
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleaseRelativeName"

    /*
        68D8A1CD26           | push 0x26cda1d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 a1 cd 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleaseResource
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleaseResource"

    /*
        68FF524845           | push 0x454852ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 52 48 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleaseSRWLockExclusive
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleaseSRWLockExclusive"

    /*
        6846AFE14B           | push 0x4be1af46
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 af e1 4b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReleaseSRWLockShared
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReleaseSRWLockShared"

    /*
        68632E175A           | push 0x5a172e63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 2e 17 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRemoteCall
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRemoteCall"

    /*
        68B79FA99C           | push 0x9ca99fb7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 9f a9 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRemoveEntryHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRemoveEntryHashTable"

    /*
        68927B7CC6           | push 0xc67c7b92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 7b 7c c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRemovePrivileges
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRemovePrivileges"

    /*
        6867827E70           | push 0x707e8267
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 82 7e 70 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRemoveVectoredContinueHandler
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRemoveVectoredContinueHandler"

    /*
        682017DD66           | push 0x66dd1720
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 17 dd 66 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRemoveVectoredExceptionHandler
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRemoveVectoredExceptionHandler"

    /*
        687AF70C8D           | push 0x8d0cf77a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a f7 0c 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReplaceSidInSd
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReplaceSidInSd"

    /*
        6858303378           | push 0x78333058
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 30 33 78 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReplaceSystemDirectoryInPath
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReplaceSystemDirectoryInPath"

    /*
        68AFA80C20           | push 0x200ca8af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af a8 0c 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReportException
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReportException"

    /*
        685F46791B           | push 0x1b79465f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 46 79 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReportExceptionEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReportExceptionEx"

    /*
        68C6EC257A           | push 0x7a25ecc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 ec 25 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReportSilentProcessExit
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReportSilentProcessExit"

    /*
        680A76A606           | push 0x06a6760a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 76 a6 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlReportSqmEscalation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlReportSqmEscalation"

    /*
        685F970A7D           | push 0x7d0a975f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 97 0a 7d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlResetMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlResetMemoryBlockLookaside"

    /*
        687612C7AA           | push 0xaac71276
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 12 c7 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlResetMemoryZone
{
    meta:
        desc = "Metasploit::API::ntdll::RtlResetMemoryZone"

    /*
        68FAA6E8DD           | push 0xdde8a6fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa a6 e8 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlResetNtUserPfn
{
    meta:
        desc = "Metasploit::API::ntdll::RtlResetNtUserPfn"

    /*
        688D1D9F8B           | push 0x8b9f1d8d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 1d 9f 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlResetRtlTranslations
{
    meta:
        desc = "Metasploit::API::ntdll::RtlResetRtlTranslations"

    /*
        68EAE45093           | push 0x9350e4ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea e4 50 93 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRestoreBootStatusDefaults
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRestoreBootStatusDefaults"

    /*
        68963081AF           | push 0xaf813096
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 30 81 af ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRestoreContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRestoreContext"

    /*
        68D05FDEE6           | push 0xe6de5fd0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 5f de e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRestoreLastWin32Error
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRestoreLastWin32Error"

    /*
        6813168222           | push 0x22821613
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 16 82 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRestoreSystemBootStatusDefaults
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRestoreSystemBootStatusDefaults"

    /*
        68F5BC0F12           | push 0x120fbcf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 bc 0f 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRetrieveNtUserPfn
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRetrieveNtUserPfn"

    /*
        68AF84B308           | push 0x08b384af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 84 b3 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRevertMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRevertMemoryStream"

    /*
        68117F44EF           | push 0xef447f11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 7f 44 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRunDecodeUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRunDecodeUnicodeString"

    /*
        6819F3E67B           | push 0x7be6f319
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 f3 e6 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRunEncodeUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRunEncodeUnicodeString"

    /*
        6819F5267E           | push 0x7e26f519
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 f5 26 7e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRunOnceBeginInitialize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRunOnceBeginInitialize"

    /*
        6895A56E4C           | push 0x4c6ea595
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 a5 6e 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRunOnceComplete
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRunOnceComplete"

    /*
        681B074A9D           | push 0x9d4a071b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 07 4a 9d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRunOnceExecuteOnce
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRunOnceExecuteOnce"

    /*
        680AF1BD69           | push 0x69bdf10a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a f1 bd 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlRunOnceInitialize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlRunOnceInitialize"

    /*
        6866A1B171           | push 0x71b1a166
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 a1 b1 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSecondsSince1970ToTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSecondsSince1970ToTime"

    /*
        6883C18B8D           | push 0x8d8bc183
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 c1 8b 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSecondsSince1980ToTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSecondsSince1980ToTime"

    /*
        6883C18B8E           | push 0x8e8bc183
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 c1 8b 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSeekMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSeekMemoryStream"

    /*
        684217F8B2           | push 0xb2f81742
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 17 f8 b2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSelfRelativeToAbsoluteSD
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSelfRelativeToAbsoluteSD"

    /*
        68EC89393B           | push 0x3b3989ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 89 39 3b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSelfRelativeToAbsoluteSD2
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSelfRelativeToAbsoluteSD2"

    /*
        684AFC19D5           | push 0xd519fc4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a fc 19 d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSendMsgToSm
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSendMsgToSm"

    /*
        68BD347E80           | push 0x807e34bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 34 7e 80 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetAllBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetAllBits"

    /*
        68FB8BC173           | push 0x73c18bfb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 8b c1 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetAttributesSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetAttributesSecurityDescriptor"

    /*
        68E03AE691           | push 0x91e63ae0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 3a e6 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetBit
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetBit"

    /*
        68420F90BB           | push 0xbb900f42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 0f 90 bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetBits
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetBits"

    /*
        68FEFECD01           | push 0x01cdfefe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe fe cd 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetControlSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetControlSecurityDescriptor"

    /*
        68D1F9E4F4           | push 0xf4e4f9d1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 f9 e4 f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetCriticalSectionSpinCount
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetCriticalSectionSpinCount"

    /*
        687FE3C21E           | push 0x1ec2e37f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f e3 c2 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetCurrentDirectory_U
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetCurrentDirectory_U"

    /*
        686F468341           | push 0x4183466f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 46 83 41 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetCurrentEnvironment
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetCurrentEnvironment"

    /*
        680F1C69DE           | push 0xde691c0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 1c 69 de ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetCurrentTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetCurrentTransaction"

    /*
        686BE41E6B           | push 0x6b1ee46b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b e4 1e 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetDaclSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetDaclSecurityDescriptor"

    /*
        682DF97FE5           | push 0xe57ff92d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d f9 7f e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetDynamicTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetDynamicTimeZoneInformation"

    /*
        68D9B9C6D1           | push 0xd1c6b9d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 b9 c6 d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetEnvironmentStrings
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetEnvironmentStrings"

    /*
        68D6C9C89C           | push 0x9cc8c9d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 c9 c8 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetEnvironmentVar
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetEnvironmentVar"

    /*
        688FFB01D1           | push 0xd101fb8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f fb 01 d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetEnvironmentVariable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetEnvironmentVariable"

    /*
        68A434FCCE           | push 0xcefc34a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 34 fc ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetExtendedFeaturesMask
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetExtendedFeaturesMask"

    /*
        68D22B7805           | push 0x05782bd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 2b 78 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetGroupSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetGroupSecurityDescriptor"

    /*
        68D7F90092           | push 0x9200f9d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 f9 00 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetHeapInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetHeapInformation"

    /*
        68D4273A0B           | push 0x0b3a27d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 27 3a 0b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetImageMitigationPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetImageMitigationPolicy"

    /*
        6848B7DFB0           | push 0xb0dfb748
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 b7 df b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetInformationAcl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetInformationAcl"

    /*
        68EF9BED19           | push 0x19ed9bef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 9b ed 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetIoCompletionCallback
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetIoCompletionCallback"

    /*
        68E452DC87           | push 0x87dc52e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 52 dc 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetLastWin32Error
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetLastWin32Error"

    /*
        6884C3CBC1           | push 0xc1cbc384
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 c3 cb c1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetLastWin32ErrorAndNtStatusFromNtStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetLastWin32ErrorAndNtStatusFromNtStatus"

    /*
        6867E71178           | push 0x7811e767
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 e7 11 78 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetMemoryStreamSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetMemoryStreamSize"

    /*
        68D7788A79           | push 0x798a78d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 78 8a 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetOwnerSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetOwnerSecurityDescriptor"

    /*
        68EA7D0093           | push 0x93007dea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 7d 00 93 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetPortableOperatingSystem
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetPortableOperatingSystem"

    /*
        68F2A110BF           | push 0xbf10a1f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 a1 10 bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetProcessDebugInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetProcessDebugInformation"

    /*
        685AED6DE6           | push 0xe66ded5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a ed 6d e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetProcessIsCritical
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetProcessIsCritical"

    /*
        68AFC7F8F7           | push 0xf7f8c7af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af c7 f8 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetProcessPlaceholderCompatibilityMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetProcessPlaceholderCompatibilityMode"

    /*
        68E164074B           | push 0x4b0764e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 64 07 4b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetProcessPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetProcessPreferredUILanguages"

    /*
        68857C7C9A           | push 0x9a7c7c85
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 7c 7c 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetProtectedPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetProtectedPolicy"

    /*
        685A475648           | push 0x4856475a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 47 56 48 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetProxiedProcessId
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetProxiedProcessId"

    /*
        684955E671           | push 0x71e65549
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 55 e6 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetSaclSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetSaclSecurityDescriptor"

    /*
        6869F97FE5           | push 0xe57ff969
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 f9 7f e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetSearchPathMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetSearchPathMode"

    /*
        6878896520           | push 0x20658978
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 89 65 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetSecurityDescriptorRMControl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetSecurityDescriptorRMControl"

    /*
        68F4ACB493           | push 0x93b4acf4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 ac b4 93 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetSecurityObject"

    /*
        68596451F0           | push 0xf0516459
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 64 51 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetSecurityObjectEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetSecurityObjectEx"

    /*
        683B6B2DB0           | push 0xb02d6b3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 6b 2d b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetSystemBootStatus
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetSystemBootStatus"

    /*
        68A948314F           | push 0x4f3148a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 48 31 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetSystemBootStatusEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetSystemBootStatusEx"

    /*
        68137F2668           | push 0x68267f13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 7f 26 68 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetThreadErrorMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetThreadErrorMode"

    /*
        686CB8A6A2           | push 0xa2a6b86c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c b8 a6 a2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetThreadIsCritical
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetThreadIsCritical"

    /*
        6828DFC099           | push 0x99c0df28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 df c0 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetThreadPlaceholderCompatibilityMode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetThreadPlaceholderCompatibilityMode"

    /*
        68E6D62F29           | push 0x292fd6e6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 d6 2f 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetThreadPoolStartFunc
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetThreadPoolStartFunc"

    /*
        68276F79E2           | push 0xe2796f27
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 6f 79 e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetThreadPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetThreadPreferredUILanguages"

    /*
        686382EEC2           | push 0xc2ee8263
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 82 ee c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetThreadSubProcessTag
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetThreadSubProcessTag"

    /*
        687F34CF1C           | push 0x1ccf347f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 34 cf 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetThreadWorkOnBehalfTicket
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetThreadWorkOnBehalfTicket"

    /*
        68BDD19DBF           | push 0xbf9dd1bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd d1 9d bf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetTimeZoneInformation"

    /*
        68B514B5F4           | push 0xf4b514b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 14 b5 f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetTimer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetTimer"

    /*
        68772DA871           | push 0x71a82d77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 2d a8 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetUmsThreadInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetUmsThreadInformation"

    /*
        682716B40D           | push 0x0db41627
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 16 b4 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetUnhandledExceptionFilter
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetUnhandledExceptionFilter"

    /*
        687449DDE4           | push 0xe4dd4974
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 49 dd e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetUserFlagsHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetUserFlagsHeap"

    /*
        68A36A5C62           | push 0x625c6aa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 6a 5c 62 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSetUserValueHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSetUserValueHeap"

    /*
        68FCEB9457           | push 0x5794ebfc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc eb 94 57 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSidDominates
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSidDominates"

    /*
        68BA43B211           | push 0x11b243ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 43 b2 11 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSidDominatesForTrust
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSidDominatesForTrust"

    /*
        68467ADCDF           | push 0xdfdc7a46
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 7a dc df ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSidEqualLevel
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSidEqualLevel"

    /*
        6886CB4F8F           | push 0x8f4fcb86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 cb 4f 8f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSidHashInitialize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSidHashInitialize"

    /*
        686C862B2B           | push 0x2b2b866c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 86 2b 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSidHashLookup
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSidHashLookup"

    /*
        6878F0EFB6           | push 0xb6eff078
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 f0 ef b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSidIsHigherLevel
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSidIsHigherLevel"

    /*
        680D04313A           | push 0x3a31040d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 04 31 3a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSizeHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSizeHeap"

    /*
        68FF1CAEE1           | push 0xe1ae1cff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 1c ae e1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSleepConditionVariableCS
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSleepConditionVariableCS"

    /*
        68263312DE           | push 0xde123326
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 33 12 de ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSleepConditionVariableSRW
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSleepConditionVariableSRW"

    /*
        68D0120F40           | push 0x400f12d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 12 0f 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSplay
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSplay"

    /*
        68393E19EE           | push 0xee193e39
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 3e 19 ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlStartRXact
{
    meta:
        desc = "Metasploit::API::ntdll::RtlStartRXact"

    /*
        68CE65EB50           | push 0x50eb65ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce 65 eb 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlStatMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlStatMemoryStream"

    /*
        6844077897           | push 0x97780744
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 07 78 97 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlStringFromGUID
{
    meta:
        desc = "Metasploit::API::ntdll::RtlStringFromGUID"

    /*
        68DF35C5ED           | push 0xedc535df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 35 c5 ed ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlStringFromGUIDEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlStringFromGUIDEx"

    /*
        68BACC210D           | push 0x0d21ccba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba cc 21 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlStronglyEnumerateEntryHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlStronglyEnumerateEntryHashTable"

    /*
        68D9E2D3B0           | push 0xb0d3e2d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 e2 d3 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSubAuthorityCountSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSubAuthorityCountSid"

    /*
        68CFDC5838           | push 0x3858dccf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf dc 58 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSubAuthoritySid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSubAuthoritySid"

    /*
        68E1EB40FF           | push 0xff40ebe1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 eb 40 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSubscribeWnfStateChangeNotification
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSubscribeWnfStateChangeNotification"

    /*
        68BF515433           | push 0x335451bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 51 54 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSubtreePredecessor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSubtreePredecessor"

    /*
        680D422E96           | push 0x962e420d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 42 2e 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSubtreeSuccessor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSubtreeSuccessor"

    /*
        684B3EDF56           | push 0x56df3e4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 3e df 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSwitchedVVI
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSwitchedVVI"

    /*
        68401033DD           | push 0xdd331040
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 10 33 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlSystemTimeToLocalTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlSystemTimeToLocalTime"

    /*
        687C468FB7           | push 0xb78f467c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 46 8f b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTestAndPublishWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTestAndPublishWnfStateData"

    /*
        682F2B106A           | push 0x6a102b2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 2b 10 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTestBit
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTestBit"

    /*
        685D1CD933           | push 0x33d91c5d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 1c d9 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTestBitEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTestBitEx"

    /*
        684C6C1B92           | push 0x921b6c4c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 6c 1b 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTestProtectedAccess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTestProtectedAccess"

    /*
        680B8D7AC4           | push 0xc47a8d0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 8d 7a c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTimeFieldsToTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTimeFieldsToTime"

    /*
        680E41C3A9           | push 0xa9c3410e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 41 c3 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTimeToElapsedTimeFields
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTimeToElapsedTimeFields"

    /*
        686CB39579           | push 0x7995b36c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c b3 95 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTimeToSecondsSince1970
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTimeToSecondsSince1970"

    /*
        68DD30FEB7           | push 0xb7fe30dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 30 fe b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTimeToSecondsSince1980
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTimeToSecondsSince1980"

    /*
        681D31FEB7           | push 0xb7fe311d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 31 fe b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTimeToTimeFields
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTimeToTimeFields"

    /*
        68E7350879           | push 0x790835e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 35 08 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseAdd
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseAdd"

    /*
        68A05EA675           | push 0x75a65ea0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 5e a6 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseCreate
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseCreate"

    /*
        68E55C38A6           | push 0xa6385ce5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 5c 38 a6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseDestroy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseDestroy"

    /*
        68E886E26A           | push 0x6ae286e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 86 e2 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseEnumerate
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseEnumerate"

    /*
        68D352C2AC           | push 0xacc252d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 52 c2 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseFind
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseFind"

    /*
        6831224486           | push 0x86442231
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 22 44 86 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseLock
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseLock"

    /*
        68717F7C92           | push 0x927c7f71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 7f 7c 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseUnlock
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseUnlock"

    /*
        68A3C8B0C2           | push 0xc2b0c8a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 c8 b0 c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTraceDatabaseValidate
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTraceDatabaseValidate"

    /*
        68CC976E34           | push 0x346e97cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 97 6e 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTryAcquirePebLock
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTryAcquirePebLock"

    /*
        6820806C54           | push 0x546c8020
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 80 6c 54 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTryAcquireSRWLockExclusive
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTryAcquireSRWLockExclusive"

    /*
        6817F6C440           | push 0x40c4f617
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 f6 c4 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTryAcquireSRWLockShared
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTryAcquireSRWLockShared"

    /*
        68DD96BACB           | push 0xcbba96dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 96 ba cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTryConvertSRWLockSharedToExclusiveOrRelease
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTryConvertSRWLockSharedToExclusiveOrRelease"

    /*
        683B90362E           | push 0x2e36903b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 90 36 2e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlTryEnterCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlTryEnterCriticalSection"

    /*
        68FBA1406F           | push 0x6f40a1fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb a1 40 6f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUTF8ToUnicodeN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUTF8ToUnicodeN"

    /*
        6894019E8A           | push 0x8a9e0194
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 01 9e 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUdiv128
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUdiv128"

    /*
        68B82EF50F           | push 0x0ff52eb8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 2e f5 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUmsThreadYield
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUmsThreadYield"

    /*
        6884BCF1A9           | push 0xa9f1bc84
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 bc f1 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnhandledExceptionFilter
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnhandledExceptionFilter"

    /*
        6871CF2056           | push 0x5620cf71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 cf 20 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnhandledExceptionFilter2
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnhandledExceptionFilter2"

    /*
        6884D33A01           | push 0x013ad384
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 d3 3a 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeStringToAnsiSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeStringToAnsiSize"

    /*
        68B2092480           | push 0x802409b2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 09 24 80 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeStringToAnsiString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeStringToAnsiString"

    /*
        68A44B4E2C           | push 0x2c4e4ba4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 4b 4e 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeStringToCountedOemString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeStringToCountedOemString"

    /*
        68A744E07F           | push 0x7fe044a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 44 e0 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeStringToInteger
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeStringToInteger"

    /*
        681B3FA624           | push 0x24a63f1b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 3f a6 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeStringToOemSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeStringToOemSize"

    /*
        68182519A8           | push 0xa8192518
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 25 19 a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeStringToOemString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeStringToOemString"

    /*
        682E259529           | push 0x2995252e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 25 95 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeToCustomCPN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeToCustomCPN"

    /*
        68D7BF5F66           | push 0x665fbfd7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 bf 5f 66 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeToMultiByteN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeToMultiByteN"

    /*
        6829BB36C6           | push 0xc636bb29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 bb 36 c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeToMultiByteSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeToMultiByteSize"

    /*
        6817BFD1C8           | push 0xc8d1bf17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 bf d1 c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeToOemN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeToOemN"

    /*
        686F5E085C           | push 0x5c085e6f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 5e 08 5c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnicodeToUTF8N
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnicodeToUTF8N"

    /*
        6843ED092C           | push 0x2c09ed43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 ed 09 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUniform
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUniform"

    /*
        68B93EC48D           | push 0x8dc43eb9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 3e c4 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnlockBootStatusData
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnlockBootStatusData"

    /*
        686913C1B4           | push 0xb4c11369
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 13 c1 b4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnlockCurrentThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnlockCurrentThread"

    /*
        686CE8A359           | push 0x59a3e86c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c e8 a3 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnlockHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnlockHeap"

    /*
        68FB348663           | push 0x638634fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 34 86 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnlockMemoryBlockLookaside
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnlockMemoryBlockLookaside"

    /*
        685F025D8C           | push 0x8c5d025f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 02 5d 8c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnlockMemoryStreamRegion
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnlockMemoryStreamRegion"

    /*
        68C3568845           | push 0x458856c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 56 88 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnlockMemoryZone
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnlockMemoryZone"

    /*
        689E664064           | push 0x6440669e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 66 40 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnlockModuleSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnlockModuleSection"

    /*
        686A3F1C9E           | push 0x9e1c3f6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 3f 1c 9e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnsubscribeWnfNotificationWaitForCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnsubscribeWnfNotificationWaitForCompletion"

    /*
        68A56FE914           | push 0x14e96fa5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 6f e9 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnsubscribeWnfNotificationWithCompletionCallback
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnsubscribeWnfNotificationWithCompletionCallback"

    /*
        68F9A65014           | push 0x1450a6f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 a6 50 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnsubscribeWnfStateChangeNotification
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnsubscribeWnfStateChangeNotification"

    /*
        683180BC45           | push 0x45bc8031
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 80 bc 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnwind
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnwind"

    /*
        6887401889           | push 0x89184087
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 40 18 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUnwindEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUnwindEx"

    /*
        68A176E4E1           | push 0xe1e476a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 76 e4 e1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeChar
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeChar"

    /*
        68C82A5E4C           | push 0x4c5e2ac8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 2a 5e 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeString"

    /*
        68182118A1           | push 0xa1182118
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 21 18 a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeStringToAnsiString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeStringToAnsiString"

    /*
        681072E7F0           | push 0xf0e77210
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 72 e7 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeStringToCountedOemString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeStringToCountedOemString"

    /*
        680B578F19           | push 0x198f570b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 57 8f 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeStringToOemString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeStringToOemString"

    /*
        68C29D624E           | push 0x4e629dc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 9d 62 4e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeToCustomCPN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeToCustomCPN"

    /*
        680A8984C4           | push 0xc484890a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 89 84 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeToMultiByteN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeToMultiByteN"

    /*
        684FACD10F           | push 0x0fd1ac4f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f ac d1 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpcaseUnicodeToOemN
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpcaseUnicodeToOemN"

    /*
        68D5F05118           | push 0x1851f0d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 f0 51 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpdateClonedCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpdateClonedCriticalSection"

    /*
        6874535FB0           | push 0xb05f5374
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 53 5f b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpdateClonedSRWLock
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpdateClonedSRWLock"

    /*
        68F46B3D04           | push 0x043d6bf4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 6b 3d 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpdateTimer
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpdateTimer"

    /*
        68163E73B9           | push 0xb9733e16
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 3e 73 b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpperChar
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpperChar"

    /*
        68041BAD84           | push 0x84ad1b04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 1b ad 84 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUpperString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUpperString"

    /*
        682630D4B4           | push 0xb4d43026
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 30 d4 b4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUserFiberStart
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUserFiberStart"

    /*
        689825E622           | push 0x22e62598
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 25 e6 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlUserThreadStart
{
    meta:
        desc = "Metasploit::API::ntdll::RtlUserThreadStart"

    /*
        68FEE6EAD2           | push 0xd2eae6fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe e6 ea d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidAcl
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidAcl"

    /*
        6881DC579C           | push 0x9c57dc81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 dc 57 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidProcessProtection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidProcessProtection"

    /*
        68F56E348F           | push 0x8f346ef5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 6e 34 8f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidRelativeSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidRelativeSecurityDescriptor"

    /*
        68BC7D382C           | push 0x2c387dbc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 7d 38 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidSecurityDescriptor"

    /*
        68BBEF9E44           | push 0x449eefbb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb ef 9e 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidSid
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidSid"

    /*
        6801DE17C0           | push 0xc017de01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 de 17 c0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidateCorrelationVector
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidateCorrelationVector"

    /*
        689BD56C7A           | push 0x7a6cd59b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b d5 6c 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidateHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidateHeap"

    /*
        6868D9B568           | push 0x68b5d968
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 d9 b5 68 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidateProcessHeaps
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidateProcessHeaps"

    /*
        6819464804           | push 0x04484619
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 46 48 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlValidateUnicodeString
{
    meta:
        desc = "Metasploit::API::ntdll::RtlValidateUnicodeString"

    /*
        6887A1C91D           | push 0x1dc9a187
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 a1 c9 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlVerifyVersionInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlVerifyVersionInfo"

    /*
        6894F4E981           | push 0x81e9f494
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 f4 e9 81 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlVirtualUnwind
{
    meta:
        desc = "Metasploit::API::ntdll::RtlVirtualUnwind"

    /*
        68420F5122           | push 0x22510f42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 0f 51 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWaitForWnfMetaNotification
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWaitForWnfMetaNotification"

    /*
        689422DC26           | push 0x26dc2294
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 22 dc 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWaitOnAddress
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWaitOnAddress"

    /*
        689D8A7128           | push 0x28718a9d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 8a 71 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWakeAddressAll
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWakeAddressAll"

    /*
        6827F6579B           | push 0x9b57f627
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 f6 57 9b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWakeAddressAllNoFence
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWakeAddressAllNoFence"

    /*
        68FE6440B7           | push 0xb74064fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 64 40 b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWakeAddressSingle
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWakeAddressSingle"

    /*
        680CCEC340           | push 0x40c3ce0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c ce c3 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWakeAddressSingleNoFence
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWakeAddressSingleNoFence"

    /*
        689361BB64           | push 0x64bb6193
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 61 bb 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWakeAllConditionVariable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWakeAllConditionVariable"

    /*
        687D09C72A           | push 0x2ac7097d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 09 c7 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWakeConditionVariable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWakeConditionVariable"

    /*
        68DC0143CB           | push 0xcb4301dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 01 43 cb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWalkFrameChain
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWalkFrameChain"

    /*
        68C0B47318           | push 0x1873b4c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 b4 73 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWalkHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWalkHeap"

    /*
        68021C76E5           | push 0xe5761c02
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 1c 76 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWeaklyEnumerateEntryHashTable
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWeaklyEnumerateEntryHashTable"

    /*
        68A5E0988C           | push 0x8c98e0a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 e0 98 8c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWerpReportException
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWerpReportException"

    /*
        689EF577E0           | push 0xe077f59e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e f5 77 e0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWnfCompareChangeStamp
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWnfCompareChangeStamp"

    /*
        6840B5192D           | push 0x2d19b540
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 b5 19 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWnfDllUnloadCallback
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWnfDllUnloadCallback"

    /*
        6841B7EDD4           | push 0xd4edb741
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 b7 ed d4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64CallFunction64
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64CallFunction64"

    /*
        68438F9E19           | push 0x199e8f43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 8f 9e 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64EnableFsRedirection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64EnableFsRedirection"

    /*
        68672349AC           | push 0xac492367
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 23 49 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64EnableFsRedirectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64EnableFsRedirectionEx"

    /*
        68AA2E1DAE           | push 0xae1d2eaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 2e 1d ae ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetCpuAreaInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetCpuAreaInfo"

    /*
        68AA4DE66F           | push 0x6fe64daa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 4d e6 6f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetCurrentCpuArea
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetCurrentCpuArea"

    /*
        681030EC31           | push 0x31ec3010
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 30 ec 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetCurrentMachine
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetCurrentMachine"

    /*
        6887A3D21F           | push 0x1fd2a387
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 a3 d2 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetEquivalentMachineCHPE
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetEquivalentMachineCHPE"

    /*
        6853FF8D40           | push 0x408dff53
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 ff 8d 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetProcessMachines
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetProcessMachines"

    /*
        68260C7982           | push 0x82790c26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 0c 79 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetSharedInfoProcess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetSharedInfoProcess"

    /*
        680EAAB529           | push 0x29b5aa0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e aa b5 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetThreadContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetThreadContext"

    /*
        68E41F5A89           | push 0x895a1fe4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 1f 5a 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64GetThreadSelectorEntry
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64GetThreadSelectorEntry"

    /*
        68AE2D8212           | push 0x12822dae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 2d 82 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64IsWowGuestMachineSupported
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64IsWowGuestMachineSupported"

    /*
        68DAA0908B           | push 0x8b90a0da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da a0 90 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64LogMessageInEventLogger
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64LogMessageInEventLogger"

    /*
        688C2CDD00           | push 0x00dd2c8c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c 2c dd 00 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64PopAllCrossProcessWorkFromWorkList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64PopAllCrossProcessWorkFromWorkList"

    /*
        68A02F4F40           | push 0x404f2fa0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 2f 4f 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64PopCrossProcessWorkFromFreeList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64PopCrossProcessWorkFromFreeList"

    /*
        68C78A6743           | push 0x43678ac7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 8a 67 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64PushCrossProcessWorkOntoFreeList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64PushCrossProcessWorkOntoFreeList"

    /*
        686AAB3575           | push 0x7535ab6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a ab 35 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64PushCrossProcessWorkOntoWorkList
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64PushCrossProcessWorkOntoWorkList"

    /*
        680DAB6986           | push 0x8669ab0d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d ab 69 86 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64RequestCrossProcessHeavyFlush
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64RequestCrossProcessHeavyFlush"

    /*
        681D9B0F98           | push 0x980f9b1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 9b 0f 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64SetThreadContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64SetThreadContext"

    /*
        68E41F6689           | push 0x89661fe4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 1f 66 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64SuspendProcess
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64SuspendProcess"

    /*
        689EE495C9           | push 0xc995e49e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e e4 95 c9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWow64SuspendThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWow64SuspendThread"

    /*
        683637DCBB           | push 0xbbdc3736
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 37 dc bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWriteMemoryStream
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWriteMemoryStream"

    /*
        68A096174E           | push 0x4e1796a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 96 17 4e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWriteNonVolatileMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWriteNonVolatileMemory"

    /*
        6863174D4D           | push 0x4d4d1763
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 17 4d 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlWriteRegistryValue
{
    meta:
        desc = "Metasploit::API::ntdll::RtlWriteRegistryValue"

    /*
        680B61D2CF           | push 0xcfd2610b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 61 d2 cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlZeroHeap
{
    meta:
        desc = "Metasploit::API::ntdll::RtlZeroHeap"

    /*
        68841C8EE8           | push 0xe88e1c84
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 1c 8e e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlZeroMemory
{
    meta:
        desc = "Metasploit::API::ntdll::RtlZeroMemory"

    /*
        68394178BD           | push 0xbd784139
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 41 78 bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlZombifyActivationContext
{
    meta:
        desc = "Metasploit::API::ntdll::RtlZombifyActivationContext"

    /*
        688ACABC94           | push 0x94bcca8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a ca bc 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpApplyLengthFunction
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpApplyLengthFunction"

    /*
        684580FE55           | push 0x55fe8045
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 80 fe 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpCheckDynamicTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpCheckDynamicTimeZoneInformation"

    /*
        68E6BF0069           | push 0x6900bfe6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 bf 00 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpCleanupRegistryKeys
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpCleanupRegistryKeys"

    /*
        6893A0A5DF           | push 0xdfa5a093
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 a0 a5 df ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpConvertAbsoluteToRelativeSecurityAttribute
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpConvertAbsoluteToRelativeSecurityAttribute"

    /*
        6848446E0D           | push 0x0d6e4448
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 44 6e 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpConvertCultureNamesToLCIDs
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpConvertCultureNamesToLCIDs"

    /*
        68E04BB88F           | push 0x8fb84be0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 4b b8 8f ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpConvertLCIDsToCultureNames
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpConvertLCIDsToCultureNames"

    /*
        6819480A52           | push 0x520a4819
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 48 0a 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpConvertRelativeToAbsoluteSecurityAttribute
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpConvertRelativeToAbsoluteSecurityAttribute"

    /*
        68323F1338           | push 0x38133f32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 3f 13 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpCreateProcessRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpCreateProcessRegistryInfo"

    /*
        68B0294846           | push 0x464829b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 29 48 46 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpEnsureBufferSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpEnsureBufferSize"

    /*
        688CD9F031           | push 0x31f0d98c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c d9 f0 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpExecuteUmsThread
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpExecuteUmsThread"

    /*
        68218DC327           | push 0x27c38d21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 8d c3 27 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpFreezeTimeBias
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpFreezeTimeBias"

    /*
        68FFA6A4B8           | push 0xb8a4a6ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff a6 a4 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpGetDeviceFamilyInfoEnum
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpGetDeviceFamilyInfoEnum"

    /*
        6807B91081           | push 0x8110b907
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 b9 10 81 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpGetLCIDFromLangInfoNode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpGetLCIDFromLangInfoNode"

    /*
        689111641D           | push 0x1d641191
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 11 64 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpGetNameFromLangInfoNode
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpGetNameFromLangInfoNode"

    /*
        689A4E6446           | push 0x46644e9a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 4e 64 46 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpGetSystemDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpGetSystemDefaultUILanguage"

    /*
        68351DFFE9           | push 0xe9ff1d35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 1d ff e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpGetUserOrMachineUILanguage4NLS
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpGetUserOrMachineUILanguage4NLS"

    /*
        68BBCC989C           | push 0x9c98ccbb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb cc 98 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpInitializeLangRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpInitializeLangRegistryInfo"

    /*
        688A0F7ED3           | push 0xd37e0f8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 0f 7e d3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpIsQualifiedLanguage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpIsQualifiedLanguage"

    /*
        6848FA838E           | push 0x8e83fa48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 fa 83 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpLoadMachineUIByPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpLoadMachineUIByPolicy"

    /*
        689B28FF53           | push 0x53ff289b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 28 ff 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpLoadUserUIByPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpLoadUserUIByPolicy"

    /*
        68A086ACA5           | push 0xa5ac86a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 86 ac a5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpMergeSecurityAttributeInformation
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpMergeSecurityAttributeInformation"

    /*
        683BFBE95D           | push 0x5de9fb3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b fb e9 5d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpMuiFreeLangRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpMuiFreeLangRegistryInfo"

    /*
        687AAEAC0A           | push 0x0aacae7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a ae ac 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpMuiRegCreateRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpMuiRegCreateRegistryInfo"

    /*
        68F80D581B           | push 0x1b580df8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 0d 58 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpMuiRegFreeRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpMuiRegFreeRegistryInfo"

    /*
        684BC5039E           | push 0x9e03c54b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b c5 03 9e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpMuiRegLoadRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpMuiRegLoadRegistryInfo"

    /*
        684AB5893D           | push 0x3d89b54a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a b5 89 3d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpNotOwnerCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpNotOwnerCriticalSection"

    /*
        6893B806CD           | push 0xcd06b893
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 b8 06 cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpNtCreateKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpNtCreateKey"

    /*
        68917C8CC2           | push 0xc28c7c91
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 7c 8c c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpNtEnumerateSubKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpNtEnumerateSubKey"

    /*
        68D7FEA085           | push 0x85a0fed7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 fe a0 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpNtMakeTemporaryKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpNtMakeTemporaryKey"

    /*
        685FE544B0           | push 0xb044e55f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f e5 44 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpNtOpenKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpNtOpenKey"

    /*
        68FE9103F8           | push 0xf80391fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 91 03 f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpNtQueryValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpNtQueryValueKey"

    /*
        68C0D3D836           | push 0x36d8d3c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 d3 d8 36 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpNtSetValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpNtSetValueKey"

    /*
        68E1F63798           | push 0x9837f6e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 f6 37 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpQueryDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpQueryDefaultUILanguage"

    /*
        68B3B3E229           | push 0x29e2b3b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 b3 e2 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpQueryProcessDebugInformationFromWow64
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpQueryProcessDebugInformationFromWow64"

    /*
        68C9E04AD9           | push 0xd94ae0c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 e0 4a d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpQueryProcessDebugInformationRemote
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpQueryProcessDebugInformationRemote"

    /*
        685EFBD74A           | push 0x4ad7fb5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e fb d7 4a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpRefreshCachedUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpRefreshCachedUILanguage"

    /*
        6857A7E10D           | push 0x0de1a757
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 a7 e1 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpSetInstallLanguage
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpSetInstallLanguage"

    /*
        683E913701           | push 0x0137913e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 91 37 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpSetPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpSetPreferredUILanguages"

    /*
        685BD65F2A           | push 0x2a5fd65b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b d6 5f 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpSetUserPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpSetUserPreferredUILanguages"

    /*
        6860716545           | push 0x45657160
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 71 65 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpTimeFieldsToTime
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpTimeFieldsToTime"

    /*
        683385C3C7           | push 0xc7c38533
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 85 c3 c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpTimeToTimeFields
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpTimeToTimeFields"

    /*
        680C7A0897           | push 0x97087a0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 7a 08 97 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpUmsExecuteYieldThreadEnd
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpUmsExecuteYieldThreadEnd"

    /*
        681D31E3B6           | push 0xb6e3311d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 31 e3 b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpUmsThreadYield
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpUmsThreadYield"

    /*
        6894BD693E           | push 0x3e69bd94
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 bd 69 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpUnWaitCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpUnWaitCriticalSection"

    /*
        6814FC5BED           | push 0xed5bfc14
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 fc 5b ed ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpVerifyAndCommitUILanguageSettings
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpVerifyAndCommitUILanguageSettings"

    /*
        6878B464E1           | push 0xe164b478
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 b4 64 e1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpWaitForCriticalSection
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpWaitForCriticalSection"

    /*
        68E1AD34A7           | push 0xa734ade1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 ad 34 a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpWow64CtxFromAmd64
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpWow64CtxFromAmd64"

    /*
        68EDE97853           | push 0x5378e9ed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed e9 78 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpWow64GetContextOnAmd64
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpWow64GetContextOnAmd64"

    /*
        6877AD1722           | push 0x2217ad77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 ad 17 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlpWow64SetContextOnAmd64
{
    meta:
        desc = "Metasploit::API::ntdll::RtlpWow64SetContextOnAmd64"

    /*
        68D7AD1722           | push 0x2217add7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 ad 17 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlxAnsiStringToUnicodeSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlxAnsiStringToUnicodeSize"

    /*
        68F202E778           | push 0x78e702f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 02 e7 78 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlxOemStringToUnicodeSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlxOemStringToUnicodeSize"

    /*
        68D275B7FF           | push 0xffb775d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 75 b7 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlxUnicodeStringToAnsiSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlxUnicodeStringToAnsiSize"

    /*
        6856962C40           | push 0x402c9656
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 96 2c 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_RtlxUnicodeStringToOemSize
{
    meta:
        desc = "Metasploit::API::ntdll::RtlxUnicodeStringToOemSize"

    /*
        68199DADB9           | push 0xb9ad9d19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 9d ad b9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_SbExecuteProcedure
{
    meta:
        desc = "Metasploit::API::ntdll::SbExecuteProcedure"

    /*
        686BA0C5A6           | push 0xa6c5a06b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b a0 c5 a6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_SbSelectProcedure
{
    meta:
        desc = "Metasploit::API::ntdll::SbSelectProcedure"

    /*
        68F29E80B6           | push 0xb6809ef2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 9e 80 b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ShipAssert
{
    meta:
        desc = "Metasploit::API::ntdll::ShipAssert"

    /*
        681EB248B6           | push 0xb648b21e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e b2 48 b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ShipAssertGetBufferInfo
{
    meta:
        desc = "Metasploit::API::ntdll::ShipAssertGetBufferInfo"

    /*
        687753D291           | push 0x91d25377
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 53 d2 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ShipAssertMsgA
{
    meta:
        desc = "Metasploit::API::ntdll::ShipAssertMsgA"

    /*
        688AF85310           | push 0x1053f88a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a f8 53 10 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ShipAssertMsgW
{
    meta:
        desc = "Metasploit::API::ntdll::ShipAssertMsgW"

    /*
        688AF80311           | push 0x1103f88a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a f8 03 11 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocAlpcCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocAlpcCompletion"

    /*
        68C7892575           | push 0x752589c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 89 25 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocAlpcCompletionEx
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocAlpcCompletionEx"

    /*
        689CC636E5           | push 0xe536c69c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c c6 36 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocCleanupGroup
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocCleanupGroup"

    /*
        68B2D5AA1E           | push 0x1eaad5b2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 d5 aa 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocIoCompletion"

    /*
        68F9639191           | push 0x919163f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 63 91 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocJobNotification
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocJobNotification"

    /*
        6833661C99           | push 0x991c6633
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 66 1c 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocPool
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocPool"

    /*
        68DD48650E           | push 0x0e6548dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 48 65 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocTimer
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocTimer"

    /*
        68EA33A0CA           | push 0xcaa033ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 33 a0 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocWait
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocWait"

    /*
        685DB7A5F2           | push 0xf2a5b75d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d b7 a5 f2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAllocWork
{
    meta:
        desc = "Metasploit::API::ntdll::TpAllocWork"

    /*
        689DB95D0E           | push 0x0e5db99d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d b9 5d 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAlpcRegisterCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::TpAlpcRegisterCompletionList"

    /*
        6832446801           | push 0x01684432
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 44 68 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpAlpcUnregisterCompletionList
{
    meta:
        desc = "Metasploit::API::ntdll::TpAlpcUnregisterCompletionList"

    /*
        68AB21A409           | push 0x09a421ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 21 a4 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackDetectedUnrecoverableError
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackDetectedUnrecoverableError"

    /*
        68C63FFD6D           | push 0x6dfd3fc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 3f fd 6d ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackIndependent
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackIndependent"

    /*
        6846B5C17D           | push 0x7dc1b546
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 b5 c1 7d ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackLeaveCriticalSectionOnCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackLeaveCriticalSectionOnCompletion"

    /*
        68FE7933DE           | push 0xde3379fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 79 33 de ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackMayRunLong
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackMayRunLong"

    /*
        68A57632DD           | push 0xdd3276a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 76 32 dd ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackReleaseMutexOnCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackReleaseMutexOnCompletion"

    /*
        687A7AF0C7           | push 0xc7f07a7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 7a f0 c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackReleaseSemaphoreOnCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackReleaseSemaphoreOnCompletion"

    /*
        68552851CD           | push 0xcd512855
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 28 51 cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackSendAlpcMessageOnCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackSendAlpcMessageOnCompletion"

    /*
        689F686BEC           | push 0xec6b689f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 68 6b ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackSendPendingAlpcMessage
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackSendPendingAlpcMessage"

    /*
        68ACF6CCBC           | push 0xbcccf6ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac f6 cc bc ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackSetEventOnCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackSetEventOnCompletion"

    /*
        68D09EBAAB           | push 0xabba9ed0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 9e ba ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCallbackUnloadDllOnCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpCallbackUnloadDllOnCompletion"

    /*
        68640E8858           | push 0x58880e64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 0e 88 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCancelAsyncIoOperation
{
    meta:
        desc = "Metasploit::API::ntdll::TpCancelAsyncIoOperation"

    /*
        68AE802265           | push 0x652280ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 80 22 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCaptureCaller
{
    meta:
        desc = "Metasploit::API::ntdll::TpCaptureCaller"

    /*
        68986BA2AF           | push 0xafa26b98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 6b a2 af ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpCheckTerminateWorker
{
    meta:
        desc = "Metasploit::API::ntdll::TpCheckTerminateWorker"

    /*
        68CAD44791           | push 0x9147d4ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca d4 47 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpDbgDumpHeapUsage
{
    meta:
        desc = "Metasploit::API::ntdll::TpDbgDumpHeapUsage"

    /*
        685354AB62           | push 0x62ab5453
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 54 ab 62 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpDbgSetLogRoutine
{
    meta:
        desc = "Metasploit::API::ntdll::TpDbgSetLogRoutine"

    /*
        683A9B367C           | push 0x7c369b3a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 9b 36 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpDisablePoolCallbackChecks
{
    meta:
        desc = "Metasploit::API::ntdll::TpDisablePoolCallbackChecks"

    /*
        6837E3BDA0           | push 0xa0bde337
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 e3 bd a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpDisassociateCallback
{
    meta:
        desc = "Metasploit::API::ntdll::TpDisassociateCallback"

    /*
        687D1D5B38           | push 0x385b1d7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 1d 5b 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpIsTimerSet
{
    meta:
        desc = "Metasploit::API::ntdll::TpIsTimerSet"

    /*
        6834FBD8FE           | push 0xfed8fb34
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 fb d8 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpPostWork
{
    meta:
        desc = "Metasploit::API::ntdll::TpPostWork"

    /*
        68FF31C771           | push 0x71c731ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 31 c7 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpQueryPoolStackInformation
{
    meta:
        desc = "Metasploit::API::ntdll::TpQueryPoolStackInformation"

    /*
        683215E9E7           | push 0xe7e91532
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 15 e9 e7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseAlpcCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseAlpcCompletion"

    /*
        682EE1E80D           | push 0x0de8e12e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e e1 e8 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseCleanupGroup
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseCleanupGroup"

    /*
        6810E30DBD           | push 0xbd0de310
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 e3 0d bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseCleanupGroupMembers
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseCleanupGroupMembers"

    /*
        68D6D5455C           | push 0x5c45d5d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 d5 45 5c ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseIoCompletion"

    /*
        685671F42F           | push 0x2ff47156
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 71 f4 2f ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseJobNotification
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseJobNotification"

    /*
        684E2C5954           | push 0x54592c4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 2c 59 54 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleasePool
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleasePool"

    /*
        687CA67271           | push 0x7172a67c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c a6 72 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseTimer
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseTimer"

    /*
        68554C93B7           | push 0xb7934c55
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 4c 93 b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseWait
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseWait"

    /*
        68FC14B355           | push 0x55b314fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 14 b3 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpReleaseWork
{
    meta:
        desc = "Metasploit::API::ntdll::TpReleaseWork"

    /*
        683C176B71           | push 0x716b173c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 17 6b 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetDefaultPoolMaxThreads
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetDefaultPoolMaxThreads"

    /*
        689DFEB86B           | push 0x6bb8fe9d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d fe b8 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetDefaultPoolStackInformation
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetDefaultPoolStackInformation"

    /*
        68D0F331E5           | push 0xe531f3d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 f3 31 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetPoolMaxThreads
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetPoolMaxThreads"

    /*
        68B3849A92           | push 0x929a84b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 84 9a 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetPoolMaxThreadsSoftLimit
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetPoolMaxThreadsSoftLimit"

    /*
        6816897E90           | push 0x907e8916
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 89 7e 90 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetPoolMinThreads
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetPoolMinThreads"

    /*
        68B3C49A88           | push 0x889ac4b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 c4 9a 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetPoolStackInformation
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetPoolStackInformation"

    /*
        68568F8AFD           | push 0xfd8a8f56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 8f 8a fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetPoolThreadBasePriority
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetPoolThreadBasePriority"

    /*
        6842D51A25           | push 0x251ad542
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 d5 1a 25 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetPoolThreadCpuSets
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetPoolThreadCpuSets"

    /*
        6867F9878A           | push 0x8a87f967
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 f9 87 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetPoolWorkerThreadIdleTimeout
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetPoolWorkerThreadIdleTimeout"

    /*
        6889B7671B           | push 0x1b67b789
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 b7 67 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetTimer
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetTimer"

    /*
        686F4D0471           | push 0x71044d6f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 4d 04 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetTimerEx
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetTimerEx"

    /*
        689BB0E7DC           | push 0xdce7b09b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b b0 e7 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetWait
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetWait"

    /*
        682A4CD675           | push 0x75d64c2a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 4c d6 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSetWaitEx
{
    meta:
        desc = "Metasploit::API::ntdll::TpSetWaitEx"

    /*
        685C5F6711           | push 0x11675f5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 5f 67 11 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpSimpleTryPost
{
    meta:
        desc = "Metasploit::API::ntdll::TpSimpleTryPost"

    /*
        68836566B1           | push 0xb1666583
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 65 66 b1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpStartAsyncIoOperation
{
    meta:
        desc = "Metasploit::API::ntdll::TpStartAsyncIoOperation"

    /*
        68A229DBC4           | push 0xc4db29a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 29 db c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpTimerOutstandingCallbackCount
{
    meta:
        desc = "Metasploit::API::ntdll::TpTimerOutstandingCallbackCount"

    /*
        686162C1B2           | push 0xb2c16261
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 62 c1 b2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpTrimPools
{
    meta:
        desc = "Metasploit::API::ntdll::TpTrimPools"

    /*
        68B4CF9794           | push 0x9497cfb4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 cf 97 94 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpWaitForAlpcCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpWaitForAlpcCompletion"

    /*
        68585AA771           | push 0x71a75a58
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 5a a7 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpWaitForIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::TpWaitForIoCompletion"

    /*
        683B6B83D5           | push 0xd5836b3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 6b 83 d5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpWaitForJobNotification
{
    meta:
        desc = "Metasploit::API::ntdll::TpWaitForJobNotification"

    /*
        68414AA41D           | push 0x1da44a41
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 4a a4 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpWaitForTimer
{
    meta:
        desc = "Metasploit::API::ntdll::TpWaitForTimer"

    /*
        6824C4BFDC           | push 0xdcbfc424
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 c4 bf dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpWaitForWait
{
    meta:
        desc = "Metasploit::API::ntdll::TpWaitForWait"

    /*
        68A1F9ACE4           | push 0xe4acf9a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 f9 ac e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_TpWaitForWork
{
    meta:
        desc = "Metasploit::API::ntdll::TpWaitForWork"

    /*
        68E1FB6400           | push 0x0064fbe1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 fb 64 00 ff d5 }

    condition:
        any of them
}

    
rule ntdll_VerSetConditionMask
{
    meta:
        desc = "Metasploit::API::ntdll::VerSetConditionMask"

    /*
        680DE0A755           | push 0x55a7e00d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d e0 a7 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WerReportExceptionWorker
{
    meta:
        desc = "Metasploit::API::ntdll::WerReportExceptionWorker"

    /*
        685CC9F053           | push 0x53f0c95c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c c9 f0 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WerReportSQMEvent
{
    meta:
        desc = "Metasploit::API::ntdll::WerReportSQMEvent"

    /*
        68F58E3DD4           | push 0xd43d8ef5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 8e 3d d4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmAddToAverageDWORD
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmAddToAverageDWORD"

    /*
        68B9728090           | push 0x908072b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 72 80 90 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmAddToStream
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmAddToStream"

    /*
        6859D3C45A           | push 0x5ac4d359
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 d3 c4 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmAddToStreamEx
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmAddToStreamEx"

    /*
        68162B094D           | push 0x4d092b16
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 2b 09 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCheckEscalationAddToStreamEx
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCheckEscalationAddToStreamEx"

    /*
        689A338D07           | push 0x078d339a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 33 8d 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCheckEscalationSetDWORD
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCheckEscalationSetDWORD"

    /*
        689784C21D           | push 0x1dc28497
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 84 c2 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCheckEscalationSetDWORD64
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCheckEscalationSetDWORD64"

    /*
        680677550A           | push 0x0a557706
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 77 55 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCheckEscalationSetString
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCheckEscalationSetString"

    /*
        68214B575A           | push 0x5a574b21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 4b 57 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCommonDatapointDelete
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCommonDatapointDelete"

    /*
        681BC8C8FF           | push 0xffc8c81b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b c8 c8 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCommonDatapointSetDWORD
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCommonDatapointSetDWORD"

    /*
        68EE8E84EF           | push 0xef848eee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 8e 84 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCommonDatapointSetDWORD64
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCommonDatapointSetDWORD64"

    /*
        68BB0CD87A           | push 0x7ad80cbb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 0c d8 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCommonDatapointSetStreamEx
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCommonDatapointSetStreamEx"

    /*
        6828D149EB           | push 0xeb49d128
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 d1 49 eb ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmCommonDatapointSetString
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmCommonDatapointSetString"

    /*
        6831D90DAD           | push 0xad0dd931
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 d9 0d ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmEndSession
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmEndSession"

    /*
        68D89C5B84           | push 0x845b9cd8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 9c 5b 84 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmEventEnabled
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmEventEnabled"

    /*
        681C9517FD           | push 0xfd17951c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 95 17 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmEventWrite
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmEventWrite"

    /*
        686AD14F85           | push 0x854fd16a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a d1 4f 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmGetEscalationRuleStatus
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmGetEscalationRuleStatus"

    /*
        687B14D26D           | push 0x6dd2147b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b 14 d2 6d ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmGetInstrumentationProperty
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmGetInstrumentationProperty"

    /*
        680FC2AA77           | push 0x77aac20f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f c2 aa 77 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmIncrementDWORD
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmIncrementDWORD"

    /*
        68A6106AE9           | push 0xe96a10a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 10 6a e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmIsOptedIn
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmIsOptedIn"

    /*
        680075B6D6           | push 0xd6b67500
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 75 b6 d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmIsOptedInEx
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmIsOptedInEx"

    /*
        68F5947149           | push 0x497194f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 94 71 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmIsSessionDisabled
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmIsSessionDisabled"

    /*
        68284FAE90           | push 0x90ae4f28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 4f ae 90 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmSetDWORD
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmSetDWORD"

    /*
        688E73BAA8           | push 0xa8ba738e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 73 ba a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmSetDWORD64
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmSetDWORD64"

    /*
        68A93451C8           | push 0xc85134a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 34 51 c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmSetEscalationInfo
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmSetEscalationInfo"

    /*
        68C2D6D5A4           | push 0xa4d5d6c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 d6 d5 a4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmSetIfMaxDWORD
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmSetIfMaxDWORD"

    /*
        68F243A0D2           | push 0xd2a043f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 43 a0 d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmSetIfMinDWORD
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmSetIfMinDWORD"

    /*
        68F24478D2           | push 0xd27844f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 44 78 d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmSetString
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmSetString"

    /*
        68E0A20BD2           | push 0xd20ba2e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 a2 0b d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmStartSession
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmStartSession"

    /*
        6844CA40F7           | push 0xf740ca44
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 ca 40 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmStartSessionForPartner
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmStartSessionForPartner"

    /*
        68989FE27F           | push 0x7fe29f98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 9f e2 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_WinSqmStartSqmOptinListener
{
    meta:
        desc = "Metasploit::API::ntdll::WinSqmStartSqmOptinListener"

    /*
        681F94A1CF           | push 0xcfa1941f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 94 a1 cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAcceptConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAcceptConnectPort"

    /*
        681A027A06           | push 0x067a021a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 02 7a 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAccessCheck
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAccessCheck"

    /*
        681ADE49E0           | push 0xe049de1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a de 49 e0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAccessCheckAndAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAccessCheckAndAuditAlarm"

    /*
        68E487F5B0           | push 0xb0f587e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 87 f5 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAccessCheckByType
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAccessCheckByType"

    /*
        684BFAFDCF           | push 0xcffdfa4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b fa fd cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAccessCheckByTypeAndAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAccessCheckByTypeAndAuditAlarm"

    /*
        68F2616DC9           | push 0xc96d61f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 61 6d c9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAccessCheckByTypeResultList
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAccessCheckByTypeResultList"

    /*
        68BD234B2D           | push 0x2d4b23bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 23 4b 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAccessCheckByTypeResultListAndAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAccessCheckByTypeResultListAndAuditAlarm"

    /*
        6887089C82           | push 0x829c0887
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 08 9c 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAccessCheckByTypeResultListAndAuditAlarmByHandle
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAccessCheckByTypeResultListAndAuditAlarmByHandle"

    /*
        6891232D05           | push 0x052d2391
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 23 2d 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAcquireProcessActivityReference
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAcquireProcessActivityReference"

    /*
        685E5B23BA           | push 0xba235b5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 5b 23 ba ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAddAtom
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAddAtom"

    /*
        68621B99A2           | push 0xa2991b62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 1b 99 a2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAddAtomEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAddAtomEx"

    /*
        68682D1B42           | push 0x421b2d68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 2d 1b 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAddBootEntry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAddBootEntry"

    /*
        68FC9D8457           | push 0x57849dfc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 9d 84 57 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAddDriverEntry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAddDriverEntry"

    /*
        68FE7217B5           | push 0xb51772fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 72 17 b5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAdjustGroupsToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAdjustGroupsToken"

    /*
        682C3815A7           | push 0xa715382c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 38 15 a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAdjustPrivilegesToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAdjustPrivilegesToken"

    /*
        68597E491F           | push 0x1f497e59
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 7e 49 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAdjustTokenClaimsAndDeviceGroups
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAdjustTokenClaimsAndDeviceGroups"

    /*
        68E4B8A375           | push 0x75a3b8e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 b8 a3 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlertResumeThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlertResumeThread"

    /*
        68B5870D33           | push 0x330d87b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 87 0d 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlertThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlertThread"

    /*
        68CF8D96AC           | push 0xac968dcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 8d 96 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlertThreadByThreadId
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlertThreadByThreadId"

    /*
        68732C0B7B           | push 0x7b0b2c73
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 2c 0b 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAllocateLocallyUniqueId
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAllocateLocallyUniqueId"

    /*
        681754BF75           | push 0x75bf5417
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 54 bf 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAllocateReserveObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAllocateReserveObject"

    /*
        685464EA54           | push 0x54ea6454
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 64 ea 54 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAllocateUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAllocateUserPhysicalPages"

    /*
        68A1FC623D           | push 0x3d62fca1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 fc 62 3d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAllocateUuids
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAllocateUuids"

    /*
        68E1892A18           | push 0x182a89e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 89 2a 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAllocateVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAllocateVirtualMemory"

    /*
        6839B10896           | push 0x9608b139
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 b1 08 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAllocateVirtualMemoryEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAllocateVirtualMemoryEx"

    /*
        6824A3001E           | push 0x1e00a324
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 a3 00 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcAcceptConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcAcceptConnectPort"

    /*
        68FDAFDACC           | push 0xccdaaffd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd af da cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcCancelMessage
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcCancelMessage"

    /*
        6828DBEAF1           | push 0xf1eadb28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 db ea f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcConnectPort"

    /*
        68CE69CDA8           | push 0xa8cd69ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce 69 cd a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcConnectPortEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcConnectPortEx"

    /*
        6869C82ECF           | push 0xcf2ec869
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 c8 2e cf ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcCreatePort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcCreatePort"

    /*
        6842DB33DE           | push 0xde33db42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 db 33 de ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcCreatePortSection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcCreatePortSection"

    /*
        6815FCDD88           | push 0x88ddfc15
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 fc dd 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcCreateResourceReserve
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcCreateResourceReserve"

    /*
        684ABEB055           | push 0x55b0be4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a be b0 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcCreateSectionView
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcCreateSectionView"

    /*
        6858A45189           | push 0x8951a458
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 a4 51 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcCreateSecurityContext
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcCreateSecurityContext"

    /*
        6845354CA8           | push 0xa84c3545
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 35 4c a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcDeletePortSection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcDeletePortSection"

    /*
        681E0CD168           | push 0x68d10c1e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 0c d1 68 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcDeleteResourceReserve
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcDeleteResourceReserve"

    /*
        68494CB186           | push 0x86b14c49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 4c b1 86 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcDeleteSectionView
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcDeleteSectionView"

    /*
        6861B44469           | push 0x6944b461
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 b4 44 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcDeleteSecurityContext
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcDeleteSecurityContext"

    /*
        6844C34CD9           | push 0xd94cc344
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 c3 4c d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcDisconnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcDisconnectPort"

    /*
        6868B9C695           | push 0x95c6b968
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 b9 c6 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcImpersonateClientContainerOfPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcImpersonateClientContainerOfPort"

    /*
        68A1ED66DA           | push 0xda66eda1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 ed 66 da ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcImpersonateClientOfPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcImpersonateClientOfPort"

    /*
        6891B8EA20           | push 0x20eab891
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 b8 ea 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcOpenSenderProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcOpenSenderProcess"

    /*
        6818B9F2AE           | push 0xaef2b918
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 b9 f2 ae ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcOpenSenderThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcOpenSenderThread"

    /*
        68E2736B56           | push 0x566b73e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 73 6b 56 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcQueryInformation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcQueryInformation"

    /*
        68BFA9E98A           | push 0x8ae9a9bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf a9 e9 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcQueryInformationMessage
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcQueryInformationMessage"

    /*
        68F2B84F0F           | push 0x0f4fb8f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 b8 4f 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcRevokeSecurityContext
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcRevokeSecurityContext"

    /*
        68FCD6D3DB           | push 0xdbd3d6fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc d6 d3 db ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcSendWaitReceivePort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcSendWaitReceivePort"

    /*
        68B0063D7E           | push 0x7e3d06b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 06 3d 7e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAlpcSetInformation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAlpcSetInformation"

    /*
        684EF68CC8           | push 0xc88cf64e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e f6 8c c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwApphelpCacheControl
{
    meta:
        desc = "Metasploit::API::ntdll::ZwApphelpCacheControl"

    /*
        6884F519B2           | push 0xb219f584
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 f5 19 b2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAreMappedFilesTheSame
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAreMappedFilesTheSame"

    /*
        68B77C4F6A           | push 0x6a4f7cb7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 7c 4f 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAssignProcessToJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAssignProcessToJobObject"

    /*
        683FEAC321           | push 0x21c3ea3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f ea c3 21 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwAssociateWaitCompletionPacket
{
    meta:
        desc = "Metasploit::API::ntdll::ZwAssociateWaitCompletionPacket"

    /*
        684C437DB3           | push 0xb37d434c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 43 7d b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCallEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCallEnclave"

    /*
        682A650A5F           | push 0x5f0a652a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 65 0a 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCallbackReturn
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCallbackReturn"

    /*
        684A9C0FA2           | push 0xa20f9c4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 9c 0f a2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCancelIoFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCancelIoFile"

    /*
        68532431B6           | push 0xb6312453
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 24 31 b6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCancelIoFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCancelIoFileEx"

    /*
        68AC691D28           | push 0x281d69ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac 69 1d 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCancelSynchronousIoFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCancelSynchronousIoFile"

    /*
        6856F1DEA2           | push 0xa2def156
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 f1 de a2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCancelTimer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCancelTimer"

    /*
        68E2446AEE           | push 0xee6a44e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 44 6a ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCancelTimer2
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCancelTimer2"

    /*
        68D095C7AC           | push 0xacc795d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 95 c7 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCancelWaitCompletionPacket
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCancelWaitCompletionPacket"

    /*
        6896671AC6           | push 0xc61a6796
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 67 1a c6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwClearEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwClearEvent"

    /*
        68C304FBB3           | push 0xb3fb04c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 04 fb b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwClose
{
    meta:
        desc = "Metasploit::API::ntdll::ZwClose"

    /*
        6871FFA4A1           | push 0xa1a4ff71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 ff a4 a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCloseObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCloseObjectAuditAlarm"

    /*
        6868BAB785           | push 0x85b7ba68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 ba b7 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCommitComplete
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCommitComplete"

    /*
        6861B535A9           | push 0xa935b561
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 b5 35 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCommitEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCommitEnlistment"

    /*
        68913E3DE8           | push 0xe83d3e91
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 3e 3d e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCommitRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCommitRegistryTransaction"

    /*
        6806BADE9C           | push 0x9cdeba06
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 ba de 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCommitTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCommitTransaction"

    /*
        6824FBF176           | push 0x76f1fb24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 fb f1 76 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCompactKeys
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCompactKeys"

    /*
        6876614C6B           | push 0x6b4c6176
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 61 4c 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCompareObjects
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCompareObjects"

    /*
        685C317FC7           | push 0xc77f315c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 31 7f c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCompareSigningLevels
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCompareSigningLevels"

    /*
        6808E59931           | push 0x3199e508
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 e5 99 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCompareTokens
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCompareTokens"

    /*
        68BFDAE761           | push 0x61e7dabf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf da e7 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCompleteConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCompleteConnectPort"

    /*
        6893D4B396           | push 0x96b3d493
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 d4 b3 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCompressKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCompressKey"

    /*
        6895DE86B7           | push 0xb786de95
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 de 86 b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwConnectPort"

    /*
        6836B8547D           | push 0x7d54b836
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 b8 54 7d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwContinue
{
    meta:
        desc = "Metasploit::API::ntdll::ZwContinue"

    /*
        68C08A84E2           | push 0xe2848ac0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 8a 84 e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter
{
    meta:
        desc = "Metasploit::API::ntdll::ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter"

    /*
        68A9D79309           | push 0x0993d7a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 d7 93 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateCrossVmEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateCrossVmEvent"

    /*
        68A0FB84C5           | push 0xc584fba0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 fb 84 c5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateDebugObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateDebugObject"

    /*
        68AF2D3CBB           | push 0xbb3c2daf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 2d 3c bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateDirectoryObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateDirectoryObject"

    /*
        685A514F7D           | push 0x7d4f515a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 51 4f 7d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateDirectoryObjectEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateDirectoryObjectEx"

    /*
        685EABA8EF           | push 0xefa8ab5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e ab a8 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateEnclave"

    /*
        68E580D08C           | push 0x8cd080e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 80 d0 8c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateEnlistment"

    /*
        68421F1F42           | push 0x421f1f42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 1f 1f 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateEvent"

    /*
        68FFD05E9C           | push 0x9c5ed0ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff d0 5e 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateEventPair"

    /*
        686C37CA4F           | push 0x4fca376c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 37 ca 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateFile"

    /*
        68533488BB           | push 0xbb883453
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 34 88 bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateIRTimer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateIRTimer"

    /*
        681D4DC824           | push 0x24c84d1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 4d c8 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateIoCompletion"

    /*
        6885BF4AC7           | push 0xc74abf85
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 bf 4a c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateJobObject"

    /*
        6883FD5F50           | push 0x505ffd83
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 fd 5f 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateJobSet
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateJobSet"

    /*
        68B1D1D059           | push 0x59d0d1b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 d1 d0 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateKey"

    /*
        6887A5A20C           | push 0x0ca2a587
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 a5 a2 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateKeyTransacted
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateKeyTransacted"

    /*
        6824221240           | push 0x40122224
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 22 12 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateKeyedEvent"

    /*
        68AC66E34E           | push 0x4ee366ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac 66 e3 4e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateLowBoxToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateLowBoxToken"

    /*
        682A27C114           | push 0x14c1272a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 27 c1 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateMailslotFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateMailslotFile"

    /*
        6896C6EFCC           | push 0xccefc696
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 c6 ef cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateMutant
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateMutant"

    /*
        68F4F3DD75           | push 0x75ddf3f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 f3 dd 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateNamedPipeFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateNamedPipeFile"

    /*
        680AE3735A           | push 0x5a73e30a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a e3 73 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreatePagingFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreatePagingFile"

    /*
        68BE469084           | push 0x849046be
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 46 90 84 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreatePartition
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreatePartition"

    /*
        6886D2C4CA           | push 0xcac4d286
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 d2 c4 ca ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreatePort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreatePort"

    /*
        68D3D500C8           | push 0xc800d5d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 d5 00 c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreatePrivateNamespace
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreatePrivateNamespace"

    /*
        685B78B31E           | push 0x1eb3785b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 78 b3 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateProcess"

    /*
        688BF14F95           | push 0x954ff18b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b f1 4f 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateProcessEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateProcessEx"

    /*
        68A4B7D0EF           | push 0xefd0b7a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 b7 d0 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateProfile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateProfile"

    /*
        68CB1FE09C           | push 0x9ce01fcb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 1f e0 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateProfileEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateProfileEx"

    /*
        68A647DCD3           | push 0xd3dc47a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 47 dc d3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateRegistryTransaction"

    /*
        68D53CE4AB           | push 0xabe43cd5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 3c e4 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateResourceManager"

    /*
        68014D2AB5           | push 0xb52a4d01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 4d 2a b5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateSection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateSection"

    /*
        68E500F59C           | push 0x9cf500e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 00 f5 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateSectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateSectionEx"

    /*
        68268E14D9           | push 0xd9148e26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 8e 14 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateSemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateSemaphore"

    /*
        68AA2A305A           | push 0x5a302aaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 2a 30 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateSymbolicLinkObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateSymbolicLinkObject"

    /*
        68B7FAFC0D           | push 0x0dfcfab7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 fa fc 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateThread"

    /*
        68ADD079FD           | push 0xfd79d0ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad d0 79 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateThreadEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateThreadEx"

    /*
        683E8048FA           | push 0xfa48803e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 80 48 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateTimer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateTimer"

    /*
        68C6FE4D2C           | push 0x2c4dfec6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 fe 4d 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateTimer2
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateTimer2"

    /*
        68EE84E97B           | push 0x7be984ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 84 e9 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateToken"

    /*
        68C65E2E28           | push 0x282e5ec6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 5e 2e 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateTokenEx"

    /*
        6889066CA7           | push 0xa76c0689
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 06 6c a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateTransaction"

    /*
        6833CA747C           | push 0x7c74ca33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 ca 74 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateTransactionManager"

    /*
        68EEA60ACD           | push 0xcd0aa6ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee a6 0a cd ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateUserProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateUserProcess"

    /*
        68D9D6E1B8           | push 0xb8e1d6d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 d6 e1 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateWaitCompletionPacket
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateWaitCompletionPacket"

    /*
        68D3DED64D           | push 0x4dd6ded3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 de d6 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateWaitablePort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateWaitablePort"

    /*
        686FA75C47           | push 0x475ca76f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f a7 5c 47 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateWnfStateName
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateWnfStateName"

    /*
        680E7E1D7E           | push 0x7e1d7e0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 7e 1d 7e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwCreateWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwCreateWorkerFactory"

    /*
        680AC9640D           | push 0x0d64c90a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a c9 64 0d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDebugActiveProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDebugActiveProcess"

    /*
        68CEB1D0A5           | push 0xa5d0b1ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce b1 d0 a5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDebugContinue
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDebugContinue"

    /*
        6822ED4905           | push 0x0549ed22
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 ed 49 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDelayExecution
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDelayExecution"

    /*
        68D8BE3C61           | push 0x613cbed8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 be 3c 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteAtom
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteAtom"

    /*
        68937DC718           | push 0x18c77d93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 7d c7 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteBootEntry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteBootEntry"

    /*
        6814CF9B12           | push 0x129bcf14
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 cf 9b 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteDriverEntry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteDriverEntry"

    /*
        682DB9E37A           | push 0x7ae3b92d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d b9 e3 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteFile"

    /*
        68D3CC8702           | push 0x0287ccd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 cc 87 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteKey"

    /*
        6867AEB2FF           | push 0xffb2ae67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 ae b2 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteObjectAuditAlarm"

    /*
        689CFFA889           | push 0x89a8ff9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c ff a8 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeletePrivateNamespace
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeletePrivateNamespace"

    /*
        686000AD8E           | push 0x8ead0060
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 00 ad 8e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteValueKey"

    /*
        68D6CBC0C3           | push 0xc3c0cbd6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 cb c0 c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteWnfStateData"

    /*
        6866DF43FE           | push 0xfe43df66
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 df 43 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeleteWnfStateName
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeleteWnfStateName"

    /*
        68A67D64FE           | push 0xfe647da6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 7d 64 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDeviceIoControlFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDeviceIoControlFile"

    /*
        6896376458           | push 0x58643796
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 37 64 58 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDisableLastKnownGood
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDisableLastKnownGood"

    /*
        68D6F9E293           | push 0x93e2f9d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 f9 e2 93 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDisplayString
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDisplayString"

    /*
        68E1A410D9           | push 0xd910a4e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 a4 10 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDrawText
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDrawText"

    /*
        68E23BC751           | push 0x51c73be2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 3b c7 51 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDuplicateObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDuplicateObject"

    /*
        6892C2CAFA           | push 0xfacac292
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 c2 ca fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwDuplicateToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwDuplicateToken"

    /*
        68635E5BD6           | push 0xd65b5e63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 5e 5b d6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwEnableLastKnownGood
{
    meta:
        desc = "Metasploit::API::ntdll::ZwEnableLastKnownGood"

    /*
        68713094C2           | push 0xc2943071
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 30 94 c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwEnumerateBootEntries
{
    meta:
        desc = "Metasploit::API::ntdll::ZwEnumerateBootEntries"

    /*
        68B8BC5B32           | push 0x325bbcb8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 bc 5b 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwEnumerateDriverEntries
{
    meta:
        desc = "Metasploit::API::ntdll::ZwEnumerateDriverEntries"

    /*
        6861558123           | push 0x23815561
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 55 81 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwEnumerateKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwEnumerateKey"

    /*
        6877634DBB           | push 0xbb4d6377
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 63 4d bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwEnumerateSystemEnvironmentValuesEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwEnumerateSystemEnvironmentValuesEx"

    /*
        680D3C0916           | push 0x16093c0d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 3c 09 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwEnumerateTransactionObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwEnumerateTransactionObject"

    /*
        6866860584           | push 0x84058666
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 86 05 84 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwEnumerateValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwEnumerateValueKey"

    /*
        685E268EA1           | push 0xa18e265e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 26 8e a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwExtendSection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwExtendSection"

    /*
        6846D1129D           | push 0x9d12d146
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 d1 12 9d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFilterBootOption
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFilterBootOption"

    /*
        68EEB3FC75           | push 0x75fcb3ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee b3 fc 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFilterToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFilterToken"

    /*
        68E49468FB           | push 0xfb6894e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 94 68 fb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFilterTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFilterTokenEx"

    /*
        68FE8DF975           | push 0x75f98dfe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 8d f9 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFindAtom
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFindAtom"

    /*
        687808C2F1           | push 0xf1c20878
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 08 c2 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushBuffersFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushBuffersFile"

    /*
        688CAD5D0C           | push 0x0c5dad8c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c ad 5d 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushBuffersFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushBuffersFileEx"

    /*
        6802B83FB3           | push 0xb33fb802
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 b8 3f b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushInstallUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushInstallUILanguage"

    /*
        68AEEF621C           | push 0x1c62efae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae ef 62 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushInstructionCache
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushInstructionCache"

    /*
        68BBB1DC95           | push 0x95dcb1bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb b1 dc 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushKey"

    /*
        685F764020           | push 0x2040765f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 76 40 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushProcessWriteBuffers
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushProcessWriteBuffers"

    /*
        6830F929F0           | push 0xf029f930
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 f9 29 f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushVirtualMemory"

    /*
        68A4517C40           | push 0x407c51a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 51 7c 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFlushWriteBuffer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFlushWriteBuffer"

    /*
        68CDC33154           | push 0x5431c3cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd c3 31 54 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFreeUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFreeUserPhysicalPages"

    /*
        680D32F642           | push 0x42f6320d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 32 f6 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFreeVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFreeVirtualMemory"

    /*
        686C0AB9EC           | push 0xecb90a6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 0a b9 ec ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFreezeRegistry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFreezeRegistry"

    /*
        6822B72D98           | push 0x982db722
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 b7 2d 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFreezeTransactions
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFreezeTransactions"

    /*
        68251E145A           | push 0x5a141e25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 1e 14 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwFsControlFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwFsControlFile"

    /*
        681DF40DAD           | push 0xad0df41d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d f4 0d ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetCachedSigningLevel
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetCachedSigningLevel"

    /*
        68B704FBF7           | push 0xf7fb04b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 04 fb f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetCompleteWnfStateSubscription
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetCompleteWnfStateSubscription"

    /*
        68A41611FE           | push 0xfe1116a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 16 11 fe ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetContextThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetContextThread"

    /*
        681661395E           | push 0x5e396116
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 61 39 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetCurrentProcessorNumber
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetCurrentProcessorNumber"

    /*
        689B03466F           | push 0x6f46039b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 03 46 6f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetCurrentProcessorNumberEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetCurrentProcessorNumberEx"

    /*
        689B3B556D           | push 0x6d553b9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 3b 55 6d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetDevicePowerState
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetDevicePowerState"

    /*
        681269925B           | push 0x5b926912
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 69 92 5b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetMUIRegistryInfo
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetMUIRegistryInfo"

    /*
        68FE61624A           | push 0x4a6261fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 61 62 4a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetNextProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetNextProcess"

    /*
        68B0517B55           | push 0x557b51b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 51 7b 55 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetNextThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetNextThread"

    /*
        68B3687E69           | push 0x697e68b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 68 7e 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetNlsSectionPtr
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetNlsSectionPtr"

    /*
        68A1258765           | push 0x658725a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 25 87 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetNotificationResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetNotificationResourceManager"

    /*
        681BA72E6C           | push 0x6c2ea71b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b a7 2e 6c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwGetWriteWatch
{
    meta:
        desc = "Metasploit::API::ntdll::ZwGetWriteWatch"

    /*
        682CC1E138           | push 0x38e1c12c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c c1 e1 38 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwImpersonateAnonymousToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwImpersonateAnonymousToken"

    /*
        68CFB20943           | push 0x4309b2cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf b2 09 43 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwImpersonateClientOfPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwImpersonateClientOfPort"

    /*
        680F9F5F69           | push 0x695f9f0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 9f 5f 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwImpersonateThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwImpersonateThread"

    /*
        6806B62159           | push 0x5921b606
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 b6 21 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwInitializeEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::ZwInitializeEnclave"

    /*
        68215A0D9E           | push 0x9e0d5a21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 5a 0d 9e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwInitializeNlsFiles
{
    meta:
        desc = "Metasploit::API::ntdll::ZwInitializeNlsFiles"

    /*
        689692054E           | push 0x4e059296
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 92 05 4e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwInitializeRegistry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwInitializeRegistry"

    /*
        68073506E2           | push 0xe2063507
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 35 06 e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwInitiatePowerAction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwInitiatePowerAction"

    /*
        684A59DCA0           | push 0xa0dc594a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 59 dc a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwIsProcessInJob
{
    meta:
        desc = "Metasploit::API::ntdll::ZwIsProcessInJob"

    /*
        68BF623F97           | push 0x973f62bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 62 3f 97 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwIsSystemResumeAutomatic
{
    meta:
        desc = "Metasploit::API::ntdll::ZwIsSystemResumeAutomatic"

    /*
        68B9D58961           | push 0x6189d5b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 d5 89 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwIsUILanguageComitted
{
    meta:
        desc = "Metasploit::API::ntdll::ZwIsUILanguageComitted"

    /*
        68CFCF84A8           | push 0xa884cfcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf cf 84 a8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwListenPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwListenPort"

    /*
        683A90C495           | push 0x95c4903a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 90 c4 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLoadDriver
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLoadDriver"

    /*
        68FC4A3291           | push 0x91324afc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 4a 32 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLoadEnclaveData
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLoadEnclaveData"

    /*
        68D75D0423           | push 0x23045dd7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 5d 04 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLoadKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLoadKey"

    /*
        68404A27D1           | push 0xd1274a40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 4a 27 d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLoadKey2
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLoadKey2"

    /*
        68B8ABB6D7           | push 0xd7b6abb8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 ab b6 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLoadKey3
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLoadKey3"

    /*
        68B8ABBED7           | push 0xd7beabb8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 ab be d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLoadKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLoadKeyEx"

    /*
        68F3E4A6E5           | push 0xe5a6e4f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 e4 a6 e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLockFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLockFile"

    /*
        687C585661           | push 0x6156587c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 58 56 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLockProductActivationKeys
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLockProductActivationKeys"

    /*
        686519535A           | push 0x5a531965
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 19 53 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLockRegistryKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLockRegistryKey"

    /*
        68CBCCD935           | push 0x35d9cccb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb cc d9 35 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwLockVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwLockVirtualMemory"

    /*
        689C22B6AC           | push 0xacb6229c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 22 b6 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwMakePermanentObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwMakePermanentObject"

    /*
        68163F16BE           | push 0xbe163f16
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 3f 16 be ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwMakeTemporaryObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwMakeTemporaryObject"

    /*
        68E81FB23F           | push 0x3fb21fe8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 1f b2 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwManageHotPatch
{
    meta:
        desc = "Metasploit::API::ntdll::ZwManageHotPatch"

    /*
        6821B15045           | push 0x4550b121
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 b1 50 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwManagePartition
{
    meta:
        desc = "Metasploit::API::ntdll::ZwManagePartition"

    /*
        68878E2A0F           | push 0x0f2a8e87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 8e 2a 0f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwMapCMFModule
{
    meta:
        desc = "Metasploit::API::ntdll::ZwMapCMFModule"

    /*
        6833004236           | push 0x36420033
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 00 42 36 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwMapUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::ntdll::ZwMapUserPhysicalPages"

    /*
        6896A98EEA           | push 0xea8ea996
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 a9 8e ea ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwMapUserPhysicalPagesScatter
{
    meta:
        desc = "Metasploit::API::ntdll::ZwMapUserPhysicalPagesScatter"

    /*
        6815C44F2A           | push 0x2a4fc415
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 c4 4f 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwMapViewOfSection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwMapViewOfSection"

    /*
        6813C0401E           | push 0x1e40c013
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 c0 40 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwMapViewOfSectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwMapViewOfSectionEx"

    /*
        68C659042C           | push 0x2c0459c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 59 04 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwModifyBootEntry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwModifyBootEntry"

    /*
        685AF77F2E           | push 0x2e7ff75a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a f7 7f 2e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwModifyDriverEntry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwModifyDriverEntry"

    /*
        68B4CAED73           | push 0x73edcab4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 ca ed 73 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwNotifyChangeDirectoryFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwNotifyChangeDirectoryFile"

    /*
        688D0DB775           | push 0x75b70d8d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 0d b7 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwNotifyChangeDirectoryFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwNotifyChangeDirectoryFileEx"

    /*
        681CB89709           | push 0x0997b81c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c b8 97 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwNotifyChangeKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwNotifyChangeKey"

    /*
        686B6A67FD           | push 0xfd676a6b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 6a 67 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwNotifyChangeMultipleKeys
{
    meta:
        desc = "Metasploit::API::ntdll::ZwNotifyChangeMultipleKeys"

    /*
        68D579A321           | push 0x21a379d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 79 a3 21 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwNotifyChangeSession
{
    meta:
        desc = "Metasploit::API::ntdll::ZwNotifyChangeSession"

    /*
        68F92F43E9           | push 0xe9432ff9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 2f 43 e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenDirectoryObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenDirectoryObject"

    /*
        6806A3E3C5           | push 0xc5e3a306
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 a3 e3 c5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenEnlistment"

    /*
        689AC247D3           | push 0xd347c29a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a c2 47 d3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenEvent"

    /*
        68B017B0BE           | push 0xbeb017b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 17 b0 be ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenEventPair"

    /*
        6891493564           | push 0x64354991
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 49 35 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenFile"

    /*
        689D585EE4           | push 0xe45e589d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 58 5e e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenIoCompletion"

    /*
        68A9957311           | push 0x117395a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 95 73 11 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenJobObject"

    /*
        68A80FCB64           | push 0x64cb0fa8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 0f cb 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenKey"

    /*
        68A2EA2BD1           | push 0xd12beaa2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 ea 2b d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenKeyEx"

    /*
        6873FDCEE6           | push 0xe6cefd73
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 fd ce e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenKeyTransacted
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenKeyTransacted"

    /*
        686A7334F1           | push 0xf134736a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 73 34 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenKeyTransactedEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenKeyTransactedEx"

    /*
        687B2FF1E8           | push 0xe8f12f7b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b 2f f1 e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenKeyedEvent"

    /*
        68040A0CE0           | push 0xe00c0a04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 0a 0c e0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenMutant
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenMutant"

    /*
        687E0667AB           | push 0xab67067e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 06 67 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenObjectAuditAlarm"

    /*
        683ABC11A7           | push 0xa711bc3a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a bc 11 a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenPartition
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenPartition"

    /*
        68ABE42FDF           | push 0xdf2fe4ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab e4 2f df ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenPrivateNamespace
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenPrivateNamespace"

    /*
        68FEBC15AC           | push 0xac15bcfe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe bc 15 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenProcess"

    /*
        68D39DA129           | push 0x29a19dd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 9d a1 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenProcessToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenProcessToken"

    /*
        68FCE3948D           | push 0x8d94e3fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc e3 94 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenProcessTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenProcessTokenEx"

    /*
        68E2530D01           | push 0x010d53e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 53 0d 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenRegistryTransaction"

    /*
        685E01FFF0           | push 0xf0ff015e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 01 ff f0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenResourceManager"

    /*
        68AD9EBEFD           | push 0xfdbe9ead
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 9e be fd ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenSection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenSection"

    /*
        682DAD4631           | push 0x3146ad2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d ad 46 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenSemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenSemaphore"

    /*
        68CF3C9B6E           | push 0x6e9b3ccf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 3c 9b 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenSession
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenSession"

    /*
        68359D4631           | push 0x31469d35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 9d 46 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenSymbolicLinkObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenSymbolicLinkObject"

    /*
        685B238E66           | push 0x668e235b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 23 8e 66 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenThread"

    /*
        6837E30233           | push 0x3302e337
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 e3 02 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenThreadToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenThreadToken"

    /*
        68AE864592           | push 0x924586ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 86 45 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenThreadTokenEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenThreadTokenEx"

    /*
        686300362D           | push 0x2d360063
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 00 36 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenTimer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenTimer"

    /*
        6878459F4E           | push 0x4e9f4578
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 45 9f 4e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenTransaction"

    /*
        6878533997           | push 0x97395378
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 53 39 97 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwOpenTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwOpenTransactionManager"

    /*
        6891CF9B25           | push 0x259bcf91
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 cf 9b 25 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPlugPlayControl
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPlugPlayControl"

    /*
        680C3D59DC           | push 0xdc593d0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 3d 59 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPowerInformation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPowerInformation"

    /*
        688298ACAE           | push 0xaeac9882
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 98 ac ae ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPrePrepareComplete
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPrePrepareComplete"

    /*
        6824EB29B8           | push 0xb829eb24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 eb 29 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPrePrepareEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPrePrepareEnlistment"

    /*
        6855AF4AA5           | push 0xa54aaf55
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 af 4a a5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPrepareComplete
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPrepareComplete"

    /*
        685EFC3A04           | push 0x043afc5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e fc 3a 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPrepareEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPrepareEnlistment"

    /*
        68E8FD8EA9           | push 0xa98efde8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 fd 8e a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPrivilegeCheck
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPrivilegeCheck"

    /*
        68CB63D74C           | push 0x4cd763cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 63 d7 4c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPrivilegeObjectAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPrivilegeObjectAuditAlarm"

    /*
        681AD9C804           | push 0x04c8d91a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a d9 c8 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPrivilegedServiceAuditAlarm
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPrivilegedServiceAuditAlarm"

    /*
        6851F96D85           | push 0x856df951
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 f9 6d 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPropagationComplete
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPropagationComplete"

    /*
        684FB9F1EE           | push 0xeef1b94f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f b9 f1 ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPropagationFailed
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPropagationFailed"

    /*
        689B935239           | push 0x3952939b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 93 52 39 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwProtectVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwProtectVirtualMemory"

    /*
        6849F9E7AA           | push 0xaae7f949
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 f9 e7 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwPulseEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwPulseEvent"

    /*
        68064FC7FA           | push 0xfac74f06
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 4f c7 fa ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryAttributesFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryAttributesFile"

    /*
        68A2612233           | push 0x332261a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 61 22 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryAuxiliaryCounterFrequency
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryAuxiliaryCounterFrequency"

    /*
        68893072B8           | push 0xb8723089
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 30 72 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryBootEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryBootEntryOrder"

    /*
        6837836126           | push 0x26618337
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 83 61 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryBootOptions
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryBootOptions"

    /*
        685DE45246           | push 0x4652e45d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d e4 52 46 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryDebugFilterState
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryDebugFilterState"

    /*
        685CBFCF8C           | push 0x8ccfbf5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c bf cf 8c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryDefaultLocale
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryDefaultLocale"

    /*
        682CF56F48           | push 0x486ff52c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c f5 6f 48 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryDefaultUILanguage"

    /*
        68B021AE8A           | push 0x8aae21b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 21 ae 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryDirectoryFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryDirectoryFile"

    /*
        68D2941D61           | push 0x611d94d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 94 1d 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryDirectoryFileEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryDirectoryFileEx"

    /*
        68578939E3           | push 0xe3398957
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 89 39 e3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryDirectoryObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryDirectoryObject"

    /*
        68D4703D63           | push 0x633d70d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 70 3d 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryDriverEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryDriverEntryOrder"

    /*
        6812C92B34           | push 0x342bc912
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 c9 2b 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryEaFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryEaFile"

    /*
        682ED17F74           | push 0x747fd12e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e d1 7f 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryEvent"

    /*
        68E64E1734           | push 0x34174ee6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 4e 17 34 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryFullAttributesFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryFullAttributesFile"

    /*
        68F7AA8211           | push 0x1182aaf7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 aa 82 11 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationAtom
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationAtom"

    /*
        687986A05D           | push 0x5da08679
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 86 a0 5d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationByName
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationByName"

    /*
        6819ED5F6B           | push 0x6b5fed19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 ed 5f 6b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationEnlistment"

    /*
        68A44EB5C7           | push 0xc7b54ea4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 4e b5 c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationFile"

    /*
        68B9D56047           | push 0x4760d5b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 d5 60 47 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationJobObject"

    /*
        68354E4C16           | push 0x164c4e35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 4e 4c 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationPort"

    /*
        683977D953           | push 0x53d97739
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 77 d9 53 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationProcess"

    /*
        68CEA26760           | push 0x6067a2ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce a2 67 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationResourceManager"

    /*
        68B264F5F7           | push 0xf7f564b2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 64 f5 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationThread"

    /*
        68102AA2F3           | push 0xf3a22a10
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 2a a2 f3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationToken"

    /*
        688BBD5A33           | push 0x335abd8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b bd 5a 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationTransaction"

    /*
        68E4F688F7           | push 0xf788f6e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 f6 88 f7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationTransactionManager"

    /*
        681D3D902F           | push 0x2f903d1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 3d 90 2f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInformationWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInformationWorkerFactory"

    /*
        6869F56FD2           | push 0xd26ff569
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 f5 6f d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryInstallUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryInstallUILanguage"

    /*
        68D96DA720           | push 0x20a76dd9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 6d a7 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryIntervalProfile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryIntervalProfile"

    /*
        68FBD16E06           | push 0x066ed1fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb d1 6e 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryIoCompletion"

    /*
        68787C5ABE           | push 0xbe5a7c78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 7c 5a be ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryKey"

    /*
        687F8701AB           | push 0xab01877f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 87 01 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryLicenseValue
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryLicenseValue"

    /*
        6889FEE844           | push 0x44e8fe89
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 fe e8 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryMultipleValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryMultipleValueKey"

    /*
        684FBB3303           | push 0x0333bb4f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f bb 33 03 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryMutant
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryMutant"

    /*
        68B8B11A65           | push 0x651ab1b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 b1 1a 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryObject"

    /*
        68EE0E22ED           | push 0xed220eee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 0e 22 ed ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryOpenSubKeys
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryOpenSubKeys"

    /*
        6894B77E6C           | push 0x6c7eb794
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 b7 7e 6c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryOpenSubKeysEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryOpenSubKeysEx"

    /*
        68DA3982BB           | push 0xbb8239da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 39 82 bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryPerformanceCounter
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryPerformanceCounter"

    /*
        6829E27999           | push 0x9979e229
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 e2 79 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryPortInformationProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryPortInformationProcess"

    /*
        68DC00FAC4           | push 0xc4fa00dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 00 fa c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryQuotaInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryQuotaInformationFile"

    /*
        68DF0B88DE           | push 0xde880bdf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 0b 88 de ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySection"

    /*
        68CB7A148B           | push 0x8b147acb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 7a 14 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySecurityAttributesToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySecurityAttributesToken"

    /*
        68450B2ADB           | push 0xdb2a0b45
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 0b 2a db ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySecurityObject"

    /*
        68EC1ECBE2           | push 0xe2cb1eec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 1e cb e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySecurityPolicy
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySecurityPolicy"

    /*
        68F33EF76A           | push 0x6af73ef3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 3e f7 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySemaphore"

    /*
        6825A40EE2           | push 0xe20ea425
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 a4 0e e2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySymbolicLinkObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySymbolicLinkObject"

    /*
        68F6D6C801           | push 0x01c8d6f6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 d6 c8 01 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySystemEnvironmentValue
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySystemEnvironmentValue"

    /*
        6825E66B7E           | push 0x7e6be625
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 e6 6b 7e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySystemEnvironmentValueEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySystemEnvironmentValueEx"

    /*
        681EDECD36           | push 0x36cdde1e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e de cd 36 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySystemInformation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySystemInformation"

    /*
        685D4AB195           | push 0x95b14a5d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 4a b1 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySystemInformationEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySystemInformationEx"

    /*
        6824EC2608           | push 0x0826ec24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 ec 26 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQuerySystemTime
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQuerySystemTime"

    /*
        6855274A1C           | push 0x1c4a2755
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 27 4a 1c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryTimer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryTimer"

    /*
        68AE7C06C4           | push 0xc4067cae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 7c 06 c4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryTimerResolution
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryTimerResolution"

    /*
        6897C21F6A           | push 0x6a1fc297
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 c2 1f 6a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryValueKey"

    /*
        6862386899           | push 0x99683862
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 38 68 99 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryVirtualMemory"

    /*
        68EB952C23           | push 0x232c95eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 95 2c 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryVolumeInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryVolumeInformationFile"

    /*
        6800EA30E7           | push 0xe730ea00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 ea 30 e7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryWnfStateData"

    /*
        68C19C0C75           | push 0x750c9cc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 9c 0c 75 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueryWnfStateNameInformation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueryWnfStateNameInformation"

    /*
        68C21EBFCC           | push 0xccbf1ec2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 1e bf cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueueApcThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueueApcThread"

    /*
        689CAED8D8           | push 0xd8d8ae9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c ae d8 d8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwQueueApcThreadEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwQueueApcThreadEx"

    /*
        68F5FBFFD1           | push 0xd1fffbf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 fb ff d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRaiseException
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRaiseException"

    /*
        6860F668DF           | push 0xdf68f660
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 f6 68 df ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRaiseHardError
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRaiseHardError"

    /*
        682BF0845A           | push 0x5a84f02b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b f0 84 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReadFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReadFile"

    /*
        6838574EE7           | push 0xe74e5738
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 57 4e e7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReadFileScatter
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReadFileScatter"

    /*
        68557845C2           | push 0xc2457855
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 78 45 c2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReadOnlyEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReadOnlyEnlistment"

    /*
        6835B4E526           | push 0x26e5b435
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 b4 e5 26 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReadRequestData
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReadRequestData"

    /*
        685DA6122C           | push 0x2c12a65d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d a6 12 2c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReadVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReadVirtualMemory"

    /*
        68CC06AC6C           | push 0x6cac06cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 06 ac 6c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRecoverEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRecoverEnlistment"

    /*
        6828F91B74           | push 0x741bf928
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 f9 1b 74 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRecoverResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRecoverResourceManager"

    /*
        68F4B928CE           | push 0xce28b9f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 b9 28 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRecoverTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRecoverTransactionManager"

    /*
        68C8A33CB3           | push 0xb33ca3c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 a3 3c b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRegisterProtocolAddressInformation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRegisterProtocolAddressInformation"

    /*
        688F28D261           | push 0x61d2288f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 28 d2 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRegisterThreadTerminatePort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRegisterThreadTerminatePort"

    /*
        68A8227A23           | push 0x237a22a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 22 7a 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReleaseKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReleaseKeyedEvent"

    /*
        6873194696           | push 0x96461973
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 19 46 96 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReleaseMutant
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReleaseMutant"

    /*
        681F6A52A2           | push 0xa2526a1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 6a 52 a2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReleaseSemaphore
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReleaseSemaphore"

    /*
        68961389B0           | push 0xb0891396
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 13 89 b0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReleaseWorkerFactoryWorker
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReleaseWorkerFactoryWorker"

    /*
        682DC61276           | push 0x7612c62d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d c6 12 76 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRemoveIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRemoveIoCompletion"

    /*
        681FC7128B           | push 0x8b12c71f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f c7 12 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRemoveIoCompletionEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRemoveIoCompletionEx"

    /*
        68A21C8660           | push 0x60861ca2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 1c 86 60 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRemoveProcessDebug
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRemoveProcessDebug"

    /*
        686979FBF4           | push 0xf4fb7969
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 79 fb f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRenameKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRenameKey"

    /*
        68A41EA37F           | push 0x7fa31ea4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 1e a3 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRenameTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRenameTransactionManager"

    /*
        6812B66A5B           | push 0x5b6ab612
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 b6 6a 5b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReplaceKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReplaceKey"

    /*
        68F6BBDD4A           | push 0x4addbbf6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 bb dd 4a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReplacePartitionUnit
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReplacePartitionUnit"

    /*
        68EEBF8159           | push 0x5981bfee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee bf 81 59 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReplyPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReplyPort"

    /*
        682AD2A5C7           | push 0xc7a5d22a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a d2 a5 c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReplyWaitReceivePort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReplyWaitReceivePort"

    /*
        685433F598           | push 0x98f53354
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 33 f5 98 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReplyWaitReceivePortEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReplyWaitReceivePortEx"

    /*
        68E52921D9           | push 0xd92129e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 29 21 d9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwReplyWaitReplyPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwReplyWaitReplyPort"

    /*
        6875AD3668           | push 0x6836ad75
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 ad 36 68 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRequestPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRequestPort"

    /*
        6833D0B204           | push 0x04b2d033
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 d0 b2 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRequestWaitReplyPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRequestWaitReplyPort"

    /*
        685DF726D0           | push 0xd026f75d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d f7 26 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwResetEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwResetEvent"

    /*
        6847CD0282           | push 0x8202cd47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 cd 02 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwResetWriteWatch
{
    meta:
        desc = "Metasploit::API::ntdll::ZwResetWriteWatch"

    /*
        68FC7B584F           | push 0x4f587bfc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 7b 58 4f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRestoreKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRestoreKey"

    /*
        68FDBC15CE           | push 0xce15bcfd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd bc 15 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwResumeProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwResumeProcess"

    /*
        68C0B8EB9C           | push 0x9cebb8c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 b8 eb 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwResumeThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwResumeThread"

    /*
        68A1716076           | push 0x766071a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 71 60 76 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRevertContainerImpersonation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRevertContainerImpersonation"

    /*
        68C07AD3AA           | push 0xaad37ac0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 7a d3 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRollbackComplete
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRollbackComplete"

    /*
        686614163E           | push 0x3e161466
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 14 16 3e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRollbackEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRollbackEnlistment"

    /*
        68F6FF5420           | push 0x2054fff6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 ff 54 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRollbackRegistryTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRollbackRegistryTransaction"

    /*
        68C7E3E95A           | push 0x5ae9e3c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 e3 e9 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRollbackTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRollbackTransaction"

    /*
        68E2BB1B82           | push 0x821bbbe2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 bb 1b 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwRollforwardTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwRollforwardTransactionManager"

    /*
        680FBB0A08           | push 0x080abb0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f bb 0a 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSaveKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSaveKey"

    /*
        682B5BEF50           | push 0x50ef5b2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 5b ef 50 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSaveKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSaveKeyEx"

    /*
        68931FABD7           | push 0xd7ab1f93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 1f ab d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSaveMergedKeys
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSaveMergedKeys"

    /*
        68246E73D1           | push 0xd1736e24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 6e 73 d1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSecureConnectPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSecureConnectPort"

    /*
        68BA417C07           | push 0x077c41ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 41 7c 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSerializeBoot
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSerializeBoot"

    /*
        68D84A8FB8           | push 0xb88f4ad8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 4a 8f b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetBootEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetBootEntryOrder"

    /*
        689F94A716           | push 0x16a7949f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 94 a7 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetBootOptions
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetBootOptions"

    /*
        6855985B69           | push 0x695b9855
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 98 5b 69 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetCachedSigningLevel
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetCachedSigningLevel"

    /*
        68B70401F8           | push 0xf80104b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 04 01 f8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetCachedSigningLevel2
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetCachedSigningLevel2"

    /*
        6886E26FAB           | push 0xab6fe286
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 e2 6f ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetContextThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetContextThread"

    /*
        681661455E           | push 0x5e456116
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 61 45 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetDebugFilterState
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetDebugFilterState"

    /*
        685819549E           | push 0x9e541958
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 19 54 9e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetDefaultHardErrorPort
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetDefaultHardErrorPort"

    /*
        682386736D           | push 0x6d738623
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 86 73 6d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetDefaultLocale
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetDefaultLocale"

    /*
        6834F39C0A           | push 0x0a9cf334
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 f3 9c 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetDefaultUILanguage"

    /*
        68D3AD8E5A           | push 0x5a8eadd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 ad 8e 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetDriverEntryOrder
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetDriverEntryOrder"

    /*
        680F23B045           | push 0x45b0230f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 23 b0 45 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetEaFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetEaFile"

    /*
        681E3991BA           | push 0xba91391e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 39 91 ba ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetEvent"

    /*
        68A9571561           | push 0x611557a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 57 15 61 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetEventBoostPriority
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetEventBoostPriority"

    /*
        68744700F5           | push 0xf5004774
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 47 00 f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetHighEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetHighEventPair"

    /*
        68D9408C57           | push 0x578c40d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 40 8c 57 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetHighWaitLowEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetHighWaitLowEventPair"

    /*
        682F5D7B0B           | push 0x0b7b5d2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 5d 7b 0b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetIRTimer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetIRTimer"

    /*
        688FF76952           | push 0x5269f78f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f f7 69 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationDebugObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationDebugObject"

    /*
        6872A0409E           | push 0x9e40a072
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 a0 40 9e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationEnlistment
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationEnlistment"

    /*
        68A27B77D0           | push 0xd0777ba2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 7b 77 d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationFile"

    /*
        68E957A0D2           | push 0xd2a057e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 57 a0 d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationJobObject"

    /*
        684E0FEC5B           | push 0x5bec0f4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 0f ec 5b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationKey"

    /*
        686A681511           | push 0x1115686a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 68 15 11 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationObject"

    /*
        68B036EEC3           | push 0xc3ee36b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 36 ee c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationProcess"

    /*
        68D2217EC1           | push 0xc17e21d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 21 7e c1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationResourceManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationResourceManager"

    /*
        68317B56FC           | push 0xfc567b31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 7b 56 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationSymbolicLink
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationSymbolicLink"

    /*
        6892EF4EDF           | push 0xdf4eef92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 ef 4e df ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationThread"

    /*
        6833B682C3           | push 0xc382b633
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 b6 82 c3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationToken
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationToken"

    /*
        688817DF44           | push 0x44df1788
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 17 df 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationTransaction
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationTransaction"

    /*
        68F63C795F           | push 0x5f793cf6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 3c 79 5f ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationTransactionManager
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationTransactionManager"

    /*
        684AFF982D           | push 0x2d98ff4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a ff 98 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationVirtualMemory"

    /*
        68268EB1FC           | push 0xfcb18e26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 8e b1 fc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetInformationWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetInformationWorkerFactory"

    /*
        68C37981CE           | push 0xce8179c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 79 81 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetIntervalProfile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetIntervalProfile"

    /*
        682C54AE91           | push 0x91ae542c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 54 ae 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetIoCompletion
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetIoCompletion"

    /*
        68BE941B5E           | push 0x5e1b94be
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 94 1b 5e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetIoCompletionEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetIoCompletionEx"

    /*
        685684B922           | push 0x22b98456
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 84 b9 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetLdtEntries
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetLdtEntries"

    /*
        68D85B5EF4           | push 0xf45e5bd8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 5b 5e f4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetLowEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetLowEventPair"

    /*
        68220240D7           | push 0xd7400222
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 02 40 d7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetLowWaitHighEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetLowWaitHighEventPair"

    /*
        6875967579           | push 0x79759675
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 96 75 79 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetQuotaInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetQuotaInformationFile"

    /*
        68F7CC2724           | push 0x2427ccf7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 cc 27 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetSecurityObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetSecurityObject"

    /*
        68543011D3           | push 0xd3113054
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 30 11 d3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetSystemEnvironmentValue
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetSystemEnvironmentValue"

    /*
        68362C5CE6           | push 0xe65c2c36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 2c 5c e6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetSystemEnvironmentValueEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetSystemEnvironmentValueEx"

    /*
        687862DF32           | push 0x32df6278
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 62 df 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetSystemInformation
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetSystemInformation"

    /*
        6880D69165           | push 0x6591d680
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 d6 91 65 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetSystemPowerState
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetSystemPowerState"

    /*
        68347531E1           | push 0xe1317534
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 75 31 e1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetSystemTime
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetSystemTime"

    /*
        68B62BC932           | push 0x32c92bb6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 2b c9 32 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetThreadExecutionState
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetThreadExecutionState"

    /*
        689788C822           | push 0x22c88897
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 88 c8 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetTimer
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetTimer"

    /*
        68708504F1           | push 0xf1048570
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 85 04 f1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetTimer2
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetTimer2"

    /*
        68A2AA37B1           | push 0xb137aaa2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 aa 37 b1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetTimerEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetTimerEx"

    /*
        68FBB0F5DC           | push 0xdcf5b0fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb b0 f5 dc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetTimerResolution
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetTimerResolution"

    /*
        68C7445FF5           | push 0xf55f44c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 44 5f f5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetUuidSeed
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetUuidSeed"

    /*
        68EB160DD0           | push 0xd00d16eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 16 0d d0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetValueKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetValueKey"

    /*
        687334C21D           | push 0x1dc23473
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 34 c2 1d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetVolumeInformationFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetVolumeInformationFile"

    /*
        68FE16F3EF           | push 0xeff316fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 16 f3 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSetWnfProcessNotificationEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSetWnfProcessNotificationEvent"

    /*
        684839D1E9           | push 0xe9d13948
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 39 d1 e9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwShutdownSystem
{
    meta:
        desc = "Metasploit::API::ntdll::ZwShutdownSystem"

    /*
        68043A9C37           | push 0x379c3a04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 3a 9c 37 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwShutdownWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwShutdownWorkerFactory"

    /*
        68DED22F89           | push 0x892fd2de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de d2 2f 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSignalAndWaitForSingleObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSignalAndWaitForSingleObject"

    /*
        68DEE50937           | push 0x3709e5de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de e5 09 37 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSinglePhaseReject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSinglePhaseReject"

    /*
        68F23D5715           | push 0x15573df2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 3d 57 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwStartProfile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwStartProfile"

    /*
        68D099FD85           | push 0x85fd99d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 99 fd 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwStopProfile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwStopProfile"

    /*
        68141C3A33           | push 0x333a1c14
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 1c 3a 33 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSubscribeWnfStateChange
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSubscribeWnfStateChange"

    /*
        6894FAF291           | push 0x91f2fa94
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 fa f2 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSuspendProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSuspendProcess"

    /*
        68A031BF4D           | push 0x4dbf31a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 31 bf 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSuspendThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSuspendThread"

    /*
        68BB677CE5           | push 0xe57c67bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 67 7c e5 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwSystemDebugControl
{
    meta:
        desc = "Metasploit::API::ntdll::ZwSystemDebugControl"

    /*
        68DCAD407B           | push 0x7b40addc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc ad 40 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTerminateEnclave
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTerminateEnclave"

    /*
        680E70B618           | push 0x18b6700e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 70 b6 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTerminateJobObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTerminateJobObject"

    /*
        68E6C7DB49           | push 0x49dbc7e6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 c7 db 49 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTerminateProcess
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTerminateProcess"

    /*
        68B4E03521           | push 0x2135e0b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 e0 35 21 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTerminateThread
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTerminateThread"

    /*
        682A025FBB           | push 0xbb5f022a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 02 5f bb ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTestAlert
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTestAlert"

    /*
        686EA2C7B3           | push 0xb3c7a26e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e a2 c7 b3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwThawRegistry
{
    meta:
        desc = "Metasploit::API::ntdll::ZwThawRegistry"

    /*
        68FD955A7A           | push 0x7a5a95fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 95 5a 7a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwThawTransactions
{
    meta:
        desc = "Metasploit::API::ntdll::ZwThawTransactions"

    /*
        6847CC0128           | push 0x2801cc47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 cc 01 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTraceControl
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTraceControl"

    /*
        68FF002609           | push 0x092600ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 00 26 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTraceEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTraceEvent"

    /*
        680735C7EF           | push 0xefc73507
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 35 c7 ef ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwTranslateFilePath
{
    meta:
        desc = "Metasploit::API::ntdll::ZwTranslateFilePath"

    /*
        682CDF0844           | push 0x4408df2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c df 08 44 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUmsThreadYield
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUmsThreadYield"

    /*
        68F5B9D709           | push 0x09d7b9f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 b9 d7 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnloadDriver
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnloadDriver"

    /*
        68B4B2A1CC           | push 0xcca1b2b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 b2 a1 cc ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnloadKey
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnloadKey"

    /*
        685E26DB88           | push 0x88db265e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 26 db 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnloadKey2
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnloadKey2"

    /*
        685769A4B8           | push 0xb8a46957
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 69 a4 b8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnloadKeyEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnloadKeyEx"

    /*
        6861EC9DD2           | push 0xd29dec61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 ec 9d d2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnlockFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnlockFile"

    /*
        681B164442           | push 0x4244161b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 16 44 42 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnlockVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnlockVirtualMemory"

    /*
        68A319A31A           | push 0x1aa319a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 19 a3 1a ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnmapViewOfSection
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnmapViewOfSection"

    /*
        68D1AD21BD           | push 0xbd21add1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 ad 21 bd ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnmapViewOfSectionEx
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnmapViewOfSectionEx"

    /*
        682EC93FE4           | push 0xe43fc92e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e c9 3f e4 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUnsubscribeWnfStateChange
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUnsubscribeWnfStateChange"

    /*
        6848B2106E           | push 0x6e10b248
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 b2 10 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwUpdateWnfStateData
{
    meta:
        desc = "Metasploit::API::ntdll::ZwUpdateWnfStateData"

    /*
        68BEDF7B82           | push 0x827bdfbe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be df 7b 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwVdmControl
{
    meta:
        desc = "Metasploit::API::ntdll::ZwVdmControl"

    /*
        685CA1AE15           | push 0x15aea15c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c a1 ae 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitForAlertByThreadId
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitForAlertByThreadId"

    /*
        68D68CF963           | push 0x63f98cd6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 8c f9 63 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitForDebugEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitForDebugEvent"

    /*
        685957E851           | push 0x51e85759
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 57 e8 51 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitForKeyedEvent
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitForKeyedEvent"

    /*
        685A55DC28           | push 0x28dc555a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 55 dc 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitForMultipleObjects
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitForMultipleObjects"

    /*
        68A5909BF6           | push 0xf69b90a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 90 9b f6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitForMultipleObjects32
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitForMultipleObjects32"

    /*
        68BD798840           | push 0x408879bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 79 88 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitForSingleObject
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitForSingleObject"

    /*
        688587357C           | push 0x7c358785
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 87 35 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitForWorkViaWorkerFactory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitForWorkViaWorkerFactory"

    /*
        68A4F4AE05           | push 0x05aef4a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 f4 ae 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitHighEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitHighEventPair"

    /*
        68D9F3DADE           | push 0xdedaf3d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 f3 da de ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWaitLowEventPair
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWaitLowEventPair"

    /*
        680C13A0AD           | push 0xada0130c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 13 a0 ad ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWorkerFactoryWorkerReady
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWorkerFactoryWorkerReady"

    /*
        68AD20F412           | push 0x12f420ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 20 f4 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWriteFile
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWriteFile"

    /*
        68C0574DC8           | push 0xc84d57c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 57 4d c8 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWriteFileGather
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWriteFileGather"

    /*
        688D971395           | push 0x9513978d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 97 13 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWriteRequestData
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWriteRequestData"

    /*
        685AB7F24B           | push 0x4bf2b75a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a b7 f2 4b ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwWriteVirtualMemory
{
    meta:
        desc = "Metasploit::API::ntdll::ZwWriteVirtualMemory"

    /*
        68D445B064           | push 0x64b045d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 45 b0 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ZwYieldExecution
{
    meta:
        desc = "Metasploit::API::ntdll::ZwYieldExecution"

    /*
        6862125323           | push 0x23531262
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 12 53 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll___C_specific_handler
{
    meta:
        desc = "Metasploit::API::ntdll::__C_specific_handler"

    /*
        687DF138EE           | push 0xee38f17d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d f1 38 ee ff d5 }

    condition:
        any of them
}

    
rule ntdll___chkstk
{
    meta:
        desc = "Metasploit::API::ntdll::__chkstk"

    /*
        6864F08488           | push 0x8884f064
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 f0 84 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll___isascii
{
    meta:
        desc = "Metasploit::API::ntdll::__isascii"

    /*
        68E066B8E8           | push 0xe8b866e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 66 b8 e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll___iscsym
{
    meta:
        desc = "Metasploit::API::ntdll::__iscsym"

    /*
        68A971AC08           | push 0x08ac71a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 71 ac 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll___iscsymf
{
    meta:
        desc = "Metasploit::API::ntdll::__iscsymf"

    /*
        68E167A014           | push 0x14a067e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 67 a0 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll___misaligned_access
{
    meta:
        desc = "Metasploit::API::ntdll::__misaligned_access"

    /*
        6843E4B820           | push 0x20b8e443
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 e4 b8 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll___toascii
{
    meta:
        desc = "Metasploit::API::ntdll::__toascii"

    /*
        684068A8E8           | push 0xe8a86840
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 68 a8 e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll__atoi64
{
    meta:
        desc = "Metasploit::API::ntdll::_atoi64"

    /*
        68E920C513           | push 0x13c520e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 20 c5 13 ff d5 }

    condition:
        any of them
}

    
rule ntdll__errno
{
    meta:
        desc = "Metasploit::API::ntdll::_errno"

    /*
        68025395A7           | push 0xa7955302
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 53 95 a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll__fltused
{
    meta:
        desc = "Metasploit::API::ntdll::_fltused"

    /*
        688A8D7188           | push 0x88718d8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 8d 71 88 ff d5 }

    condition:
        any of them
}

    
rule ntdll__i64toa
{
    meta:
        desc = "Metasploit::API::ntdll::_i64toa"

    /*
        680A7F492B           | push 0x2b497f0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 7f 49 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll__i64toa_s
{
    meta:
        desc = "Metasploit::API::ntdll::_i64toa_s"

    /*
        680A1E0C6E           | push 0x6e0c1e0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 1e 0c 6e ff d5 }

    condition:
        any of them
}

    
rule ntdll__i64tow
{
    meta:
        desc = "Metasploit::API::ntdll::_i64tow"

    /*
        680A7FF92B           | push 0x2bf97f0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 7f f9 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll__i64tow_s
{
    meta:
        desc = "Metasploit::API::ntdll::_i64tow_s"

    /*
        680A1E0C9A           | push 0x9a0c1e0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 1e 0c 9a ff d5 }

    condition:
        any of them
}

    
rule ntdll__itoa
{
    meta:
        desc = "Metasploit::API::ntdll::_itoa"

    /*
        683FC3A8A9           | push 0xa9a8c33f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f c3 a8 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll__itoa_s
{
    meta:
        desc = "Metasploit::API::ntdll::_itoa_s"

    /*
        68292BDD05           | push 0x05dd2b29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 2b dd 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll__itow
{
    meta:
        desc = "Metasploit::API::ntdll::_itow"

    /*
        683FC358AA           | push 0xaa58c33f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f c3 58 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll__itow_s
{
    meta:
        desc = "Metasploit::API::ntdll::_itow_s"

    /*
        68292BDD31           | push 0x31dd2b29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 2b dd 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll__lfind
{
    meta:
        desc = "Metasploit::API::ntdll::_lfind"

    /*
        6805933C15           | push 0x153c9305
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 93 3c 15 ff d5 }

    condition:
        any of them
}

    
rule ntdll__local_unwind
{
    meta:
        desc = "Metasploit::API::ntdll::_local_unwind"

    /*
        68C0BDF671           | push 0x71f6bdc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 bd f6 71 ff d5 }

    condition:
        any of them
}

    
rule ntdll__ltoa
{
    meta:
        desc = "Metasploit::API::ntdll::_ltoa"

    /*
        683FF3A8A9           | push 0xa9a8f33f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f f3 a8 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll__ltoa_s
{
    meta:
        desc = "Metasploit::API::ntdll::_ltoa_s"

    /*
        68292BE905           | push 0x05e92b29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 2b e9 05 ff d5 }

    condition:
        any of them
}

    
rule ntdll__ltow
{
    meta:
        desc = "Metasploit::API::ntdll::_ltow"

    /*
        683FF358AA           | push 0xaa58f33f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f f3 58 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll__ltow_s
{
    meta:
        desc = "Metasploit::API::ntdll::_ltow_s"

    /*
        68292BE931           | push 0x31e92b29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 2b e9 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll__makepath_s
{
    meta:
        desc = "Metasploit::API::ntdll::_makepath_s"

    /*
        68FC83BA3F           | push 0x3fba83fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 83 ba 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll__memccpy
{
    meta:
        desc = "Metasploit::API::ntdll::_memccpy"

    /*
        682671FCE8           | push 0xe8fc7126
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 71 fc e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll__memicmp
{
    meta:
        desc = "Metasploit::API::ntdll::_memicmp"

    /*
        6866D0B4E8           | push 0xe8b4d066
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 d0 b4 e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll__setjmp
{
    meta:
        desc = "Metasploit::API::ntdll::_setjmp"

    /*
        68A27EED97           | push 0x97ed7ea2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 7e ed 97 ff d5 }

    condition:
        any of them
}

    
rule ntdll__setjmpex
{
    meta:
        desc = "Metasploit::API::ntdll::_setjmpex"

    /*
        6865053497           | push 0x97340565
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 05 34 97 ff d5 }

    condition:
        any of them
}

    
rule ntdll__snprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_snprintf"

    /*
        6849CA9392           | push 0x9293ca49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 ca 93 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll__snprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::_snprintf_s"

    /*
        68A4ED9E40           | push 0x409eeda4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 ed 9e 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll__snscanf_s
{
    meta:
        desc = "Metasploit::API::ntdll::_snscanf_s"

    /*
        68B8B5C8BD           | push 0xbdc8b5b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 b5 c8 bd ff d5 }

    condition:
        any of them
}

    
rule ntdll__snwprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_snwprintf"

    /*
        68816B944D           | push 0x4d946b81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 6b 94 4d ff d5 }

    condition:
        any of them
}

    
rule ntdll__snwprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::_snwprintf_s"

    /*
        68923BC700           | push 0x00c73b92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 3b c7 00 ff d5 }

    condition:
        any of them
}

    
rule ntdll__snwscanf_s
{
    meta:
        desc = "Metasploit::API::ntdll::_snwscanf_s"

    /*
        68BD8D86C7           | push 0xc7868dbd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 8d 86 c7 ff d5 }

    condition:
        any of them
}

    
rule ntdll__splitpath
{
    meta:
        desc = "Metasploit::API::ntdll::_splitpath"

    /*
        6821DA8835           | push 0x3588da21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 da 88 35 ff d5 }

    condition:
        any of them
}

    
rule ntdll__splitpath_s
{
    meta:
        desc = "Metasploit::API::ntdll::_splitpath_s"

    /*
        68CCE3E2FD           | push 0xfde2e3cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc e3 e2 fd ff d5 }

    condition:
        any of them
}

    
rule ntdll__strcmpi
{
    meta:
        desc = "Metasploit::API::ntdll::_strcmpi"

    /*
        68E971B87C           | push 0x7cb871e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 71 b8 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll__stricmp
{
    meta:
        desc = "Metasploit::API::ntdll::_stricmp"

    /*
        6829D1F068           | push 0x68f0d129
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 d1 f0 68 ff d5 }

    condition:
        any of them
}

    
rule ntdll__strlwr
{
    meta:
        desc = "Metasploit::API::ntdll::_strlwr"

    /*
        682961FD1B           | push 0x1bfd6129
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 61 fd 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll__strlwr_s
{
    meta:
        desc = "Metasploit::API::ntdll::_strlwr_s"

    /*
        68C6A5049B           | push 0x9b04a5c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 a5 04 9b ff d5 }

    condition:
        any of them
}

    
rule ntdll__strnicmp
{
    meta:
        desc = "Metasploit::API::ntdll::_strnicmp"

    /*
        6847C9EB7C           | push 0x7cebc947
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 c9 eb 7c ff d5 }

    condition:
        any of them
}

    
rule ntdll__strnset_s
{
    meta:
        desc = "Metasploit::API::ntdll::_strnset_s"

    /*
        68A125F4DF           | push 0xdff425a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 25 f4 df ff d5 }

    condition:
        any of them
}

    
rule ntdll__strset_s
{
    meta:
        desc = "Metasploit::API::ntdll::_strset_s"

    /*
        68C985031F           | push 0x1f0385c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 85 03 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll__strupr
{
    meta:
        desc = "Metasploit::API::ntdll::_strupr"

    /*
        68695FFD2D           | push 0x2dfd5f69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 5f fd 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll__strupr_s
{
    meta:
        desc = "Metasploit::API::ntdll::_strupr_s"

    /*
        68CA35041B           | push 0x1b0435ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 35 04 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll__swprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_swprintf"

    /*
        6869CB9392           | push 0x9293cb69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 cb 93 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll__ui64toa
{
    meta:
        desc = "Metasploit::API::ntdll::_ui64toa"

    /*
        68CB81498A           | push 0x8a4981cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 81 49 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll__ui64toa_s
{
    meta:
        desc = "Metasploit::API::ntdll::_ui64toa_s"

    /*
        6821CE0C2E           | push 0x2e0cce21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 ce 0c 2e ff d5 }

    condition:
        any of them
}

    
rule ntdll__ui64tow
{
    meta:
        desc = "Metasploit::API::ntdll::_ui64tow"

    /*
        68CB81F98A           | push 0x8af981cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 81 f9 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll__ui64tow_s
{
    meta:
        desc = "Metasploit::API::ntdll::_ui64tow_s"

    /*
        6822CE0C5A           | push 0x5a0cce22
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 ce 0c 5a ff d5 }

    condition:
        any of them
}

    
rule ntdll__ultoa
{
    meta:
        desc = "Metasploit::API::ntdll::_ultoa"

    /*
        684AF324AB           | push 0xab24f34a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a f3 24 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll__ultoa_s
{
    meta:
        desc = "Metasploit::API::ntdll::_ultoa_s"

    /*
        68EA2DE964           | push 0x64e92dea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 2d e9 64 ff d5 }

    condition:
        any of them
}

    
rule ntdll__ultow
{
    meta:
        desc = "Metasploit::API::ntdll::_ultow"

    /*
        684AF3D4AB           | push 0xabd4f34a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a f3 d4 ab ff d5 }

    condition:
        any of them
}

    
rule ntdll__ultow_s
{
    meta:
        desc = "Metasploit::API::ntdll::_ultow_s"

    /*
        68EA2DE990           | push 0x90e92dea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 2d e9 90 ff d5 }

    condition:
        any of them
}

    
rule ntdll__vscprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_vscprintf"

    /*
        6801819452           | push 0x52948101
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 81 94 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll__vscwprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_vscwprintf"

    /*
        68866B5203           | push 0x03526b86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 6b 52 03 ff d5 }

    condition:
        any of them
}

    
rule ntdll__vsnprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_vsnprintf"

    /*
        6861829452           | push 0x52948261
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 82 94 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll__vsnprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::_vsnprintf_s"

    /*
        6894F3CC40           | push 0x40ccf394
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 f3 cc 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll__vsnwprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_vsnwprintf"

    /*
        68866B520E           | push 0x0e526b86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 6b 52 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll__vsnwprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::_vsnwprintf_s"

    /*
        68023D4730           | push 0x30473d02
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 3d 47 30 ff d5 }

    condition:
        any of them
}

    
rule ntdll__vswprintf
{
    meta:
        desc = "Metasploit::API::ntdll::_vswprintf"

    /*
        6881839452           | push 0x52948381
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 83 94 52 ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcsicmp
{
    meta:
        desc = "Metasploit::API::ntdll::_wcsicmp"

    /*
        68A9D1ACE8           | push 0xe8acd1a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 d1 ac e8 ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcslwr
{
    meta:
        desc = "Metasploit::API::ntdll::_wcslwr"

    /*
        6821710D9C           | push 0x9c0d7121
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 71 0d 9c ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcslwr_s
{
    meta:
        desc = "Metasploit::API::ntdll::_wcslwr_s"

    /*
        68A6A3089F           | push 0x9f08a3a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 a3 08 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcsnicmp
{
    meta:
        desc = "Metasploit::API::ntdll::_wcsnicmp"

    /*
        6827C7EF80           | push 0x80efc727
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 c7 ef 80 ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcsnset_s
{
    meta:
        desc = "Metasploit::API::ntdll::_wcsnset_s"

    /*
        68C145F4CE           | push 0xcef445c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 45 f4 ce ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcsset_s
{
    meta:
        desc = "Metasploit::API::ntdll::_wcsset_s"

    /*
        68A9830723           | push 0x230783a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 83 07 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcstoi64
{
    meta:
        desc = "Metasploit::API::ntdll::_wcstoi64"

    /*
        686A19108B           | push 0x8b10196a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 19 10 8b ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcstoui64
{
    meta:
        desc = "Metasploit::API::ntdll::_wcstoui64"

    /*
        687F3B15B7           | push 0xb7153b7f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 3b 15 b7 ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcsupr
{
    meta:
        desc = "Metasploit::API::ntdll::_wcsupr"

    /*
        68616F0DAE           | push 0xae0d6f61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 6f 0d ae ff d5 }

    condition:
        any of them
}

    
rule ntdll__wcsupr_s
{
    meta:
        desc = "Metasploit::API::ntdll::_wcsupr_s"

    /*
        68AA33081F           | push 0x1f0833aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 33 08 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll__wmakepath_s
{
    meta:
        desc = "Metasploit::API::ntdll::_wmakepath_s"

    /*
        68EC89EA3F           | push 0x3fea89ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 89 ea 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll__wsplitpath_s
{
    meta:
        desc = "Metasploit::API::ntdll::_wsplitpath_s"

    /*
        684CE5622D           | push 0x2d62e54c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c e5 62 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll__wtoi
{
    meta:
        desc = "Metasploit::API::ntdll::_wtoi"

    /*
        683FA3E9A9           | push 0xa9e9a33f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f a3 e9 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll__wtoi64
{
    meta:
        desc = "Metasploit::API::ntdll::_wtoi64"

    /*
        68E9201D14           | push 0x141d20e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 20 1d 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll__wtol
{
    meta:
        desc = "Metasploit::API::ntdll::_wtol"

    /*
        683FA301AA           | push 0xaa01a33f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f a3 01 aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_abs
{
    meta:
        desc = "Metasploit::API::ntdll::abs"

    /*
        68CF2F3204           | push 0x04322fcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 2f 32 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_atan
{
    meta:
        desc = "Metasploit::API::ntdll::atan"

    /*
        688F3F102A           | push 0x2a103f8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 3f 10 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_atan2
{
    meta:
        desc = "Metasploit::API::ntdll::atan2"

    /*
        6800733182           | push 0x82317300
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 73 31 82 ff d5 }

    condition:
        any of them
}

    
rule ntdll_atoi
{
    meta:
        desc = "Metasploit::API::ntdll::atoi"

    /*
        680F43E829           | push 0x29e8430f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 43 e8 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_atol
{
    meta:
        desc = "Metasploit::API::ntdll::atol"

    /*
        680F43002A           | push 0x2a00430f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 43 00 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_bsearch
{
    meta:
        desc = "Metasploit::API::ntdll::bsearch"

    /*
        68824CACA7           | push 0xa7ac4c82
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 4c ac a7 ff d5 }

    condition:
        any of them
}

    
rule ntdll_bsearch_s
{
    meta:
        desc = "Metasploit::API::ntdll::bsearch_s"

    /*
        68E97BBF86           | push 0x86bf7be9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 7b bf 86 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ceil
{
    meta:
        desc = "Metasploit::API::ntdll::ceil"

    /*
        688F61000C           | push 0x0c00618f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 61 00 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_cos
{
    meta:
        desc = "Metasploit::API::ntdll::cos"

    /*
        680F333208           | push 0x0832330f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 33 32 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_fabs
{
    meta:
        desc = "Metasploit::API::ntdll::fabs"

    /*
        68CF8F3804           | push 0x04388fcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 8f 38 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_floor
{
    meta:
        desc = "Metasploit::API::ntdll::floor"

    /*
        6842F33020           | push 0x2030f342
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 f3 30 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_isalnum
{
    meta:
        desc = "Metasploit::API::ntdll::isalnum"

    /*
        68E001D59F           | push 0x9fd501e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 01 d5 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_isalpha
{
    meta:
        desc = "Metasploit::API::ntdll::isalpha"

    /*
        68A0FE74A3           | push 0xa374fea0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 fe 74 a3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_iscntrl
{
    meta:
        desc = "Metasploit::API::ntdll::iscntrl"

    /*
        682121CDAB           | push 0xabcd2121
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 21 cd ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_isdigit
{
    meta:
        desc = "Metasploit::API::ntdll::isdigit"

    /*
        68E1CE0C12           | push 0x120ccee1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 ce 0c 12 ff d5 }

    condition:
        any of them
}

    
rule ntdll_isgraph
{
    meta:
        desc = "Metasploit::API::ntdll::isgraph"

    /*
        68A360AD85           | push 0x85ad60a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 60 ad 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_islower
{
    meta:
        desc = "Metasploit::API::ntdll::islower"

    /*
        68E52DFD31           | push 0x31fd2de5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 2d fd 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_isprint
{
    meta:
        desc = "Metasploit::API::ntdll::isprint"

    /*
        6827600D16           | push 0x160d6027
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 60 0d 16 ff d5 }

    condition:
        any of them
}

    
rule ntdll_ispunct
{
    meta:
        desc = "Metasploit::API::ntdll::ispunct"

    /*
        68678D0D20           | push 0x200d8d67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 8d 0d 20 ff d5 }

    condition:
        any of them
}

    
rule ntdll_isspace
{
    meta:
        desc = "Metasploit::API::ntdll::isspace"

    /*
        68693D9585           | push 0x85953d69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 3d 95 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_isupper
{
    meta:
        desc = "Metasploit::API::ntdll::isupper"

    /*
        68EA3DFDA3           | push 0xa3fd3dea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 3d fd a3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswalnum
{
    meta:
        desc = "Metasploit::API::ntdll::iswalnum"

    /*
        682003E508           | push 0x08e50320
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 03 e5 08 ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswalpha
{
    meta:
        desc = "Metasploit::API::ntdll::iswalpha"

    /*
        68E0FF840C           | push 0x0c84ffe0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 ff 84 0c ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswascii
{
    meta:
        desc = "Metasploit::API::ntdll::iswascii"

    /*
        682070C5F2           | push 0xf2c57020
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 70 c5 f2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswctype
{
    meta:
        desc = "Metasploit::API::ntdll::iswctype"

    /*
        68E181A51E           | push 0x1ea581e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 81 a5 1e ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswdigit
{
    meta:
        desc = "Metasploit::API::ntdll::iswdigit"

    /*
        6822D01C7B           | push 0x7b1cd022
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 d0 1c 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswgraph
{
    meta:
        desc = "Metasploit::API::ntdll::iswgraph"

    /*
        68E361BDEE           | push 0xeebd61e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 61 bd ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswlower
{
    meta:
        desc = "Metasploit::API::ntdll::iswlower"

    /*
        68262F0D9B           | push 0x9b0d2f26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 2f 0d 9b ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswprint
{
    meta:
        desc = "Metasploit::API::ntdll::iswprint"

    /*
        6868611D7F           | push 0x7f1d6168
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 61 1d 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswspace
{
    meta:
        desc = "Metasploit::API::ntdll::iswspace"

    /*
        68A93EA5EE           | push 0xeea53ea9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 3e a5 ee ff d5 }

    condition:
        any of them
}

    
rule ntdll_iswxdigit
{
    meta:
        desc = "Metasploit::API::ntdll::iswxdigit"

    /*
        68A2182485           | push 0x852418a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 18 24 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_isxdigit
{
    meta:
        desc = "Metasploit::API::ntdll::isxdigit"

    /*
        6822D0207B           | push 0x7b20d022
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 d0 20 7b ff d5 }

    condition:
        any of them
}

    
rule ntdll_labs
{
    meta:
        desc = "Metasploit::API::ntdll::labs"

    /*
        68CFEF3804           | push 0x0438efcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf ef 38 04 ff d5 }

    condition:
        any of them
}

    
rule ntdll_log
{
    meta:
        desc = "Metasploit::API::ntdll::log"

    /*
        680F33D219           | push 0x19d2330f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 33 d2 19 ff d5 }

    condition:
        any of them
}

    
rule ntdll_longjmp
{
    meta:
        desc = "Metasploit::API::ntdll::longjmp"

    /*
        6846B0DC17           | push 0x17dcb046
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 b0 dc 17 ff d5 }

    condition:
        any of them
}

    
rule ntdll_mbstowcs
{
    meta:
        desc = "Metasploit::API::ntdll::mbstowcs"

    /*
        688A2C059F           | push 0x9f052c8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 2c 05 9f ff d5 }

    condition:
        any of them
}

    
rule ntdll_memchr
{
    meta:
        desc = "Metasploit::API::ntdll::memchr"

    /*
        688201E589           | push 0x89e50182
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 01 e5 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_memcmp
{
    meta:
        desc = "Metasploit::API::ntdll::memcmp"

    /*
        68C202D589           | push 0x89d502c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 02 d5 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_memcpy
{
    meta:
        desc = "Metasploit::API::ntdll::memcpy"

    /*
        6882031D8A           | push 0x8a1d0382
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 03 1d 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_memcpy_s
{
    meta:
        desc = "Metasploit::API::ntdll::memcpy_s"

    /*
        68E13BED22           | push 0x22ed3be1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 3b ed 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_memmove
{
    meta:
        desc = "Metasploit::API::ntdll::memmove"

    /*
        68A6125DA1           | push 0xa15d12a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 12 5d a1 ff d5 }

    condition:
        any of them
}

    
rule ntdll_memmove_s
{
    meta:
        desc = "Metasploit::API::ntdll::memmove_s"

    /*
        68E704F1F2           | push 0xf2f104e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 04 f1 f2 ff d5 }

    condition:
        any of them
}

    
rule ntdll_memset
{
    meta:
        desc = "Metasploit::API::ntdll::memset"

    /*
        68C200F5A9           | push 0xa9f500c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 00 f5 a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_pow
{
    meta:
        desc = "Metasploit::API::ntdll::pow"

    /*
        680F335222           | push 0x2252330f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 33 52 22 ff d5 }

    condition:
        any of them
}

    
rule ntdll_qsort
{
    meta:
        desc = "Metasploit::API::ntdll::qsort"

    /*
        68086441A0           | push 0xa0416408
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 64 41 a0 ff d5 }

    condition:
        any of them
}

    
rule ntdll_qsort_s
{
    meta:
        desc = "Metasploit::API::ntdll::qsort_s"

    /*
        68675D05AC           | push 0xac055d67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 5d 05 ac ff d5 }

    condition:
        any of them
}

    
rule ntdll_sin
{
    meta:
        desc = "Metasploit::API::ntdll::sin"

    /*
        688F310A28           | push 0x280a318f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 31 0a 28 ff d5 }

    condition:
        any of them
}

    
rule ntdll_sprintf
{
    meta:
        desc = "Metasploit::API::ntdll::sprintf"

    /*
        68E8D2901F           | push 0x1f90d2e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 d2 90 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_sprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::sprintf_s"

    /*
        688715E17F           | push 0x7fe11587
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 15 e1 7f ff d5 }

    condition:
        any of them
}

    
rule ntdll_sqrt
{
    meta:
        desc = "Metasploit::API::ntdll::sqrt"

    /*
        68CF634124           | push 0x244163cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 63 41 24 ff d5 }

    condition:
        any of them
}

    
rule ntdll_sscanf
{
    meta:
        desc = "Metasploit::API::ntdll::sscanf"

    /*
        6809639C85           | push 0x859c6309
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 63 9c 85 ff d5 }

    condition:
        any of them
}

    
rule ntdll_sscanf_s
{
    meta:
        desc = "Metasploit::API::ntdll::sscanf_s"

    /*
        68A01DC502           | push 0x02c51da0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 1d c5 02 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strcat
{
    meta:
        desc = "Metasploit::API::ntdll::strcat"

    /*
        68C94F0D0A           | push 0x0a0d4fc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 4f 0d 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_strcat_s
{
    meta:
        desc = "Metasploit::API::ntdll::strcat_s"

    /*
        68C14D001F           | push 0x1f004dc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 4d 00 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_strchr
{
    meta:
        desc = "Metasploit::API::ntdll::strchr"

    /*
        688951FD09           | push 0x09fd5189
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 51 fd 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strcmp
{
    meta:
        desc = "Metasploit::API::ntdll::strcmp"

    /*
        68C952ED09           | push 0x09ed52c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 52 ed 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strcpy
{
    meta:
        desc = "Metasploit::API::ntdll::strcpy"

    /*
        688953350A           | push 0x0a355389
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 53 35 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_strcpy_s
{
    meta:
        desc = "Metasploit::API::ntdll::strcpy_s"

    /*
        68C13D0129           | push 0x29013dc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 3d 01 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strcspn
{
    meta:
        desc = "Metasploit::API::ntdll::strcspn"

    /*
        68E871E029           | push 0x29e071e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 71 e0 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strlen
{
    meta:
        desc = "Metasploit::API::ntdll::strlen"

    /*
        68C950DD1B           | push 0x1bdd50c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 50 dd 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_strncat
{
    meta:
        desc = "Metasploit::API::ntdll::strncat"

    /*
        68281E110A           | push 0x0a111e28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 1e 11 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_strncat_s
{
    meta:
        desc = "Metasploit::API::ntdll::strncat_s"

    /*
        6881E5F31F           | push 0x1ff3e581
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 e5 f3 1f ff d5 }

    condition:
        any of them
}

    
rule ntdll_strncmp
{
    meta:
        desc = "Metasploit::API::ntdll::strncmp"

    /*
        682821F109           | push 0x09f12128
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 21 f1 09 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strncpy
{
    meta:
        desc = "Metasploit::API::ntdll::strncpy"

    /*
        68E821390A           | push 0x0a3921e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 21 39 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_strncpy_s
{
    meta:
        desc = "Metasploit::API::ntdll::strncpy_s"

    /*
        6881D5F429           | push 0x29f4d581
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 d5 f4 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strnlen
{
    meta:
        desc = "Metasploit::API::ntdll::strnlen"

    /*
        68281FE11B           | push 0x1be11f28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 1f e1 1b ff d5 }

    condition:
        any of them
}

    
rule ntdll_strpbrk
{
    meta:
        desc = "Metasploit::API::ntdll::strpbrk"

    /*
        686842C907           | push 0x07c94268
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 42 c9 07 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strrchr
{
    meta:
        desc = "Metasploit::API::ntdll::strrchr"

    /*
        68E85F010A           | push 0x0a015fe8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 5f 01 0a ff d5 }

    condition:
        any of them
}

    
rule ntdll_strspn
{
    meta:
        desc = "Metasploit::API::ntdll::strspn"

    /*
        688953DD29           | push 0x29dd5389
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 53 dd 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strstr
{
    meta:
        desc = "Metasploit::API::ntdll::strstr"

    /*
        688954FD29           | push 0x29fd5489
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 54 fd 29 ff d5 }

    condition:
        any of them
}

    
rule ntdll_strtok_s
{
    meta:
        desc = "Metasploit::API::ntdll::strtok_s"

    /*
        68CA2D018D           | push 0x8d012dca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 2d 01 8d ff d5 }

    condition:
        any of them
}

    
rule ntdll_strtol
{
    meta:
        desc = "Metasploit::API::ntdll::strtol"

    /*
        684953CD2B           | push 0x2bcd5349
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 53 cd 2b ff d5 }

    condition:
        any of them
}

    
rule ntdll_strtoul
{
    meta:
        desc = "Metasploit::API::ntdll::strtoul"

    /*
        682883D121           | push 0x21d18328
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 83 d1 21 ff d5 }

    condition:
        any of them
}

    
rule ntdll_swprintf
{
    meta:
        desc = "Metasploit::API::ntdll::swprintf"

    /*
        6869D39092           | push 0x9290d369
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 d3 90 92 ff d5 }

    condition:
        any of them
}

    
rule ntdll_swprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::swprintf_s"

    /*
        68A435E13F           | push 0x3fe135a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 35 e1 3f ff d5 }

    condition:
        any of them
}

    
rule ntdll_swscanf_s
{
    meta:
        desc = "Metasploit::API::ntdll::swscanf_s"

    /*
        68A0B5C806           | push 0x06c8b5a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 b5 c8 06 ff d5 }

    condition:
        any of them
}

    
rule ntdll_tan
{
    meta:
        desc = "Metasploit::API::ntdll::tan"

    /*
        688F2F0A2A           | push 0x2a0a2f8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 2f 0a 2a ff d5 }

    condition:
        any of them
}

    
rule ntdll_tolower
{
    meta:
        desc = "Metasploit::API::ntdll::tolower"

    /*
        68452FED31           | push 0x31ed2f45
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 2f ed 31 ff d5 }

    condition:
        any of them
}

    
rule ntdll_toupper
{
    meta:
        desc = "Metasploit::API::ntdll::toupper"

    /*
        684A3FEDA3           | push 0xa3ed3f4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 3f ed a3 ff d5 }

    condition:
        any of them
}

    
rule ntdll_towlower
{
    meta:
        desc = "Metasploit::API::ntdll::towlower"

    /*
        68A62E0DA6           | push 0xa60d2ea6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 2e 0d a6 ff d5 }

    condition:
        any of them
}

    
rule ntdll_towupper
{
    meta:
        desc = "Metasploit::API::ntdll::towupper"

    /*
        68AA3E0D18           | push 0x180d3eaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 3e 0d 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_vDbgPrintEx
{
    meta:
        desc = "Metasploit::API::ntdll::vDbgPrintEx"

    /*
        68D5221814           | push 0x141822d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 22 18 14 ff d5 }

    condition:
        any of them
}

    
rule ntdll_vDbgPrintExWithPrefix
{
    meta:
        desc = "Metasploit::API::ntdll::vDbgPrintExWithPrefix"

    /*
        68C05903F9           | push 0xf90359c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 59 03 f9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_vsprintf
{
    meta:
        desc = "Metasploit::API::ntdll::vsprintf"

    /*
        68E9D29095           | push 0x9590d2e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 d2 90 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_vsprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::vsprintf_s"

    /*
        68A415E1FF           | push 0xffe115a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 15 e1 ff ff d5 }

    condition:
        any of them
}

    
rule ntdll_vswprintf_s
{
    meta:
        desc = "Metasploit::API::ntdll::vswprintf_s"

    /*
        68A435CD40           | push 0x40cd35a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 35 cd 40 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcscat
{
    meta:
        desc = "Metasploit::API::ntdll::wcscat"

    /*
        68C15F1D8A           | push 0x8a1d5fc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 5f 1d 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcscat_s
{
    meta:
        desc = "Metasploit::API::ntdll::wcscat_s"

    /*
        68A14B0423           | push 0x23044ba1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 4b 04 23 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcschr
{
    meta:
        desc = "Metasploit::API::ntdll::wcschr"

    /*
        6881610D8A           | push 0x8a0d6181
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 61 0d 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcscmp
{
    meta:
        desc = "Metasploit::API::ntdll::wcscmp"

    /*
        68C162FD89           | push 0x89fd62c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 62 fd 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcscpy
{
    meta:
        desc = "Metasploit::API::ntdll::wcscpy"

    /*
        688163458A           | push 0x8a456381
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 63 45 8a ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcscpy_s
{
    meta:
        desc = "Metasploit::API::ntdll::wcscpy_s"

    /*
        68A13B052D           | push 0x2d053ba1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 3b 05 2d ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcscspn
{
    meta:
        desc = "Metasploit::API::ntdll::wcscspn"

    /*
        6869729CA9           | push 0xa99c7269
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 72 9c a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcslen
{
    meta:
        desc = "Metasploit::API::ntdll::wcslen"

    /*
        68C160ED9B           | push 0x9bed60c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 60 ed 9b ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsncat
{
    meta:
        desc = "Metasploit::API::ntdll::wcsncat"

    /*
        68A91ECD89           | push 0x89cd1ea9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 1e cd 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsncat_s
{
    meta:
        desc = "Metasploit::API::ntdll::wcsncat_s"

    /*
        68A105F40E           | push 0x0ef405a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 05 f4 0e ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsncmp
{
    meta:
        desc = "Metasploit::API::ntdll::wcsncmp"

    /*
        68A921AD89           | push 0x89ad21a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 21 ad 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsncpy
{
    meta:
        desc = "Metasploit::API::ntdll::wcsncpy"

    /*
        686922F589           | push 0x89f52269
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 22 f5 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsncpy_s
{
    meta:
        desc = "Metasploit::API::ntdll::wcsncpy_s"

    /*
        68A1F5F418           | push 0x18f4f5a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 f5 f4 18 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsnlen
{
    meta:
        desc = "Metasploit::API::ntdll::wcsnlen"

    /*
        68A91F9D9B           | push 0x9b9d1fa9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 1f 9d 9b ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcspbrk
{
    meta:
        desc = "Metasploit::API::ntdll::wcspbrk"

    /*
        68E9428587           | push 0x878542e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 42 85 87 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsrchr
{
    meta:
        desc = "Metasploit::API::ntdll::wcsrchr"

    /*
        686960BD89           | push 0x89bd6069
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 60 bd 89 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsspn
{
    meta:
        desc = "Metasploit::API::ntdll::wcsspn"

    /*
        688163EDA9           | push 0xa9ed6381
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 63 ed a9 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcsstr
{
    meta:
        desc = "Metasploit::API::ntdll::wcsstr"

    /*
        6881640DAA           | push 0xaa0d6481
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 64 0d aa ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcstok_s
{
    meta:
        desc = "Metasploit::API::ntdll::wcstok_s"

    /*
        68AA2B0591           | push 0x91052baa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 2b 05 91 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcstol
{
    meta:
        desc = "Metasploit::API::ntdll::wcstol"

    /*
        684163DDAB           | push 0xabdd6341
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 63 dd ab ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcstombs
{
    meta:
        desc = "Metasploit::API::ntdll::wcstombs"

    /*
        686A2C0595           | push 0x95052c6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 2c 05 95 ff d5 }

    condition:
        any of them
}

    
rule ntdll_wcstoul
{
    meta:
        desc = "Metasploit::API::ntdll::wcstoul"

    /*
        68A9838DA1           | push 0xa18d83a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 83 8d a1 ff d5 }

    condition:
        any of them
}

    