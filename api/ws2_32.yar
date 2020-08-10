
rule ws2_32_FreeAddrInfoEx
{
    meta:
        desc = "Metasploit::API::ws2_32::FreeAddrInfoEx"

    /*
        685A5ECA52           | push 0x52ca5e5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 5e ca 52 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_FreeAddrInfoExW
{
    meta:
        desc = "Metasploit::API::ws2_32::FreeAddrInfoExW"

    /*
        6807A68F85           | push 0x858fa607
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 a6 8f 85 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_FreeAddrInfoW
{
    meta:
        desc = "Metasploit::API::ws2_32::FreeAddrInfoW"

    /*
        68E1B764AA           | push 0xaa64b7e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 b7 64 aa ff d5 }

    condition:
        any of them
}

    
rule ws2_32_GetAddrInfoExA
{
    meta:
        desc = "Metasploit::API::ws2_32::GetAddrInfoExA"

    /*
        68EFFADEC4           | push 0xc4defaef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef fa de c4 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_GetAddrInfoExCancel
{
    meta:
        desc = "Metasploit::API::ws2_32::GetAddrInfoExCancel"

    /*
        680947E774           | push 0x74e74709
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 47 e7 74 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_GetAddrInfoExOverlappedResult
{
    meta:
        desc = "Metasploit::API::ws2_32::GetAddrInfoExOverlappedResult"

    /*
        6836BE2F06           | push 0x062fbe36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 be 2f 06 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_GetAddrInfoExW
{
    meta:
        desc = "Metasploit::API::ws2_32::GetAddrInfoExW"

    /*
        68EFFA8EC5           | push 0xc58efaef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef fa 8e c5 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_GetAddrInfoW
{
    meta:
        desc = "Metasploit::API::ws2_32::GetAddrInfoW"

    /*
        6834B56447           | push 0x4764b534
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 b5 64 47 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_GetHostNameW
{
    meta:
        desc = "Metasploit::API::ws2_32::GetHostNameW"

    /*
        68971C6CE0           | push 0xe06c1c97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 1c 6c e0 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_GetNameInfoW
{
    meta:
        desc = "Metasploit::API::ws2_32::GetNameInfoW"

    /*
        68541E3144           | push 0x44311e54
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 1e 31 44 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_InetNtopW
{
    meta:
        desc = "Metasploit::API::ws2_32::InetNtopW"

    /*
        680A51A3E2           | push 0xe2a3510a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 51 a3 e2 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_InetPtonW
{
    meta:
        desc = "Metasploit::API::ws2_32::InetPtonW"

    /*
        688B50A3E2           | push 0xe2a3508b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 50 a3 e2 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_SetAddrInfoExA
{
    meta:
        desc = "Metasploit::API::ws2_32::SetAddrInfoExA"

    /*
        68EF2ADFC4           | push 0xc4df2aef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 2a df c4 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_SetAddrInfoExW
{
    meta:
        desc = "Metasploit::API::ws2_32::SetAddrInfoExW"

    /*
        68EF2A8FC5           | push 0xc58f2aef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 2a 8f c5 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WEP
{
    meta:
        desc = "Metasploit::API::ws2_32::WEP"

    /*
        6882B19142           | push 0x4291b182
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 b1 91 42 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WPUCompleteOverlappedRequest
{
    meta:
        desc = "Metasploit::API::ws2_32::WPUCompleteOverlappedRequest"

    /*
        6895A944B1           | push 0xb144a995
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 a9 44 b1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WPUGetProviderPathEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WPUGetProviderPathEx"

    /*
        684A09AFCB           | push 0xcbaf094a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 09 af cb ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAccept
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAccept"

    /*
        6894ACBE33           | push 0x33beac94
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 ac be 33 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAddressToStringA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAddressToStringA"

    /*
        681D3BDC6F           | push 0x6fdc3b1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 3b dc 6f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAddressToStringW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAddressToStringW"

    /*
        681D3B8C70           | push 0x708c3b1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 3b 8c 70 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAdvertiseProvider
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAdvertiseProvider"

    /*
        6877C3DFE9           | push 0xe9dfc377
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 c3 df e9 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAsyncGetHostByAddr
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAsyncGetHostByAddr"

    /*
        680CE8FF76           | push 0x76ffe80c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c e8 ff 76 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAsyncGetHostByName
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAsyncGetHostByName"

    /*
        684CBA9870           | push 0x7098ba4c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c ba 98 70 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAsyncGetProtoByName
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAsyncGetProtoByName"

    /*
        68304CC38C           | push 0x8cc34c30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 4c c3 8c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAsyncGetProtoByNumber
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAsyncGetProtoByNumber"

    /*
        684AB50C3C           | push 0x3c0cb54a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a b5 0c 3c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAsyncGetServByName
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAsyncGetServByName"

    /*
        688F6A982F           | push 0x2f986a8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 6a 98 2f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAsyncGetServByPort
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAsyncGetServByPort"

    /*
        68CF8B104C           | push 0x4c108bcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 8b 10 4c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAAsyncSelect
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAAsyncSelect"

    /*
        68C2AD0B39           | push 0x390badc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 ad 0b 39 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSACancelAsyncRequest
{
    meta:
        desc = "Metasploit::API::ws2_32::WSACancelAsyncRequest"

    /*
        68C324925C           | push 0x5c9224c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 24 92 5c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSACancelBlockingCall
{
    meta:
        desc = "Metasploit::API::ws2_32::WSACancelBlockingCall"

    /*
        68ECAD64DC           | push 0xdc64adec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec ad 64 dc ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSACleanup
{
    meta:
        desc = "Metasploit::API::ws2_32::WSACleanup"

    /*
        682B6E4AF4           | push 0xf44a6e2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 6e 4a f4 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSACloseEvent
{
    meta:
        desc = "Metasploit::API::ws2_32::WSACloseEvent"

    /*
        68868F523C           | push 0x3c528f86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 8f 52 3c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAConnect
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAConnect"

    /*
        68AF397762           | push 0x627739af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 39 77 62 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAConnectByList
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAConnectByList"

    /*
        68D5BE754E           | push 0x4e75bed5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 be 75 4e ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAConnectByNameA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAConnectByNameA"

    /*
        68A3FFB67C           | push 0x7cb6ffa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 ff b6 7c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAConnectByNameW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAConnectByNameW"

    /*
        68A3FF667D           | push 0x7d66ffa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 ff 66 7d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSACreateEvent
{
    meta:
        desc = "Metasploit::API::ws2_32::WSACreateEvent"

    /*
        6892B257EC           | push 0xec57b292
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 b2 57 ec ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSADuplicateSocketA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSADuplicateSocketA"

    /*
        68938EAC70           | push 0x70ac8e93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 8e ac 70 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSADuplicateSocketW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSADuplicateSocketW"

    /*
        68938E5C71           | push 0x715c8e93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 8e 5c 71 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEnumNameSpaceProvidersA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEnumNameSpaceProvidersA"

    /*
        686D94A903           | push 0x03a9946d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 94 a9 03 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEnumNameSpaceProvidersExA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEnumNameSpaceProvidersExA"

    /*
        681EC91602           | push 0x0216c91e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e c9 16 02 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEnumNameSpaceProvidersExW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEnumNameSpaceProvidersExW"

    /*
        681EC9C602           | push 0x02c6c91e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e c9 c6 02 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEnumNameSpaceProvidersW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEnumNameSpaceProvidersW"

    /*
        686D945904           | push 0x0459946d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 94 59 04 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEnumNetworkEvents
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEnumNetworkEvents"

    /*
        6888F55FED           | push 0xed5ff588
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 f5 5f ed ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEnumProtocolsA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEnumProtocolsA"

    /*
        68D9690EB5           | push 0xb50e69d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 69 0e b5 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEnumProtocolsW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEnumProtocolsW"

    /*
        68D969BEB5           | push 0xb5be69d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 69 be b5 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAEventSelect
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAEventSelect"

    /*
        68E30F13F9           | push 0xf9130fe3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 0f 13 f9 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAGetLastError
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAGetLastError"

    /*
        681D9BC65D           | push 0x5dc69b1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 9b c6 5d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAGetOverlappedResult
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAGetOverlappedResult"

    /*
        68E0258189           | push 0x898125e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 25 81 89 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAGetQOSByName
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAGetQOSByName"

    /*
        68B77E9428           | push 0x28947eb7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 7e 94 28 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAGetServiceClassInfoA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAGetServiceClassInfoA"

    /*
        68BF36A210           | push 0x10a236bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 36 a2 10 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAGetServiceClassInfoW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAGetServiceClassInfoW"

    /*
        68BF365211           | push 0x115236bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 36 52 11 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAGetServiceClassNameByClassIdA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAGetServiceClassNameByClassIdA"

    /*
        6861BFC8A8           | push 0xa8c8bf61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 bf c8 a8 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAGetServiceClassNameByClassIdW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAGetServiceClassNameByClassIdW"

    /*
        6861BF78A9           | push 0xa978bf61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 bf 78 a9 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAHtonl
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAHtonl"

    /*
        6847067DCB           | push 0xcb7d0647
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 06 7d cb ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAHtons
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAHtons"

    /*
        684706B5CB           | push 0xcbb50647
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 06 b5 cb ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAInstallServiceClassA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAInstallServiceClassA"

    /*
        684539B7C0           | push 0xc0b73945
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 39 b7 c0 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAInstallServiceClassW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAInstallServiceClassW"

    /*
        68453967C1           | push 0xc1673945
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 39 67 c1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAIoctl
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAIoctl"

    /*
        68C7B77C33           | push 0x337cb7c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 b7 7c 33 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAIsBlocking
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAIsBlocking"

    /*
        68B7161297           | push 0x971216b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 16 12 97 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAJoinLeaf
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAJoinLeaf"

    /*
        68AE8E9A6B           | push 0x6b9a8eae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 8e 9a 6b ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSALookupServiceBeginA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSALookupServiceBeginA"

    /*
        68EA63E6C0           | push 0xc0e663ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 63 e6 c0 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSALookupServiceBeginW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSALookupServiceBeginW"

    /*
        68EA6396C1           | push 0xc19663ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 63 96 c1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSALookupServiceEnd
{
    meta:
        desc = "Metasploit::API::ws2_32::WSALookupServiceEnd"

    /*
        682FB64DFE           | push 0xfe4db62f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f b6 4d fe ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSALookupServiceNextA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSALookupServiceNextA"

    /*
        68A1A81E4B           | push 0x4b1ea8a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 a8 1e 4b ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSALookupServiceNextW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSALookupServiceNextW"

    /*
        68A1A8CE4B           | push 0x4bcea8a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 a8 ce 4b ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSANSPIoctl
{
    meta:
        desc = "Metasploit::API::ws2_32::WSANSPIoctl"

    /*
        68DCBF68EB           | push 0xeb68bfdc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc bf 68 eb ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSANtohl
{
    meta:
        desc = "Metasploit::API::ws2_32::WSANtohl"

    /*
        68CA047DCB           | push 0xcb7d04ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 04 7d cb ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSANtohs
{
    meta:
        desc = "Metasploit::API::ws2_32::WSANtohs"

    /*
        68CA04B5CB           | push 0xcbb504ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 04 b5 cb ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAPoll
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAPoll"

    /*
        6843C6C2F4           | push 0xf4c2c643
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 c6 c2 f4 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAProviderCompleteAsyncCall
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAProviderCompleteAsyncCall"

    /*
        68AAC99E53           | push 0x539ec9aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa c9 9e 53 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAProviderConfigChange
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAProviderConfigChange"

    /*
        687008593C           | push 0x3c590870
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 08 59 3c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSARecv
{
    meta:
        desc = "Metasploit::API::ws2_32::WSARecv"

    /*
        6803E412E1           | push 0xe112e403
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 e4 12 e1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSARecvDisconnect
{
    meta:
        desc = "Metasploit::API::ws2_32::WSARecvDisconnect"

    /*
        689B3E3828           | push 0x28383e9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 3e 38 28 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSARecvFrom
{
    meta:
        desc = "Metasploit::API::ws2_32::WSARecvFrom"

    /*
        68F230BA8D           | push 0x8dba30f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 30 ba 8d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSARemoveServiceClass
{
    meta:
        desc = "Metasploit::API::ws2_32::WSARemoveServiceClass"

    /*
        680C1CAD1A           | push 0x1aad1c0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 1c ad 1a ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAResetEvent
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAResetEvent"

    /*
        68CA558E00           | push 0x008e55ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 55 8e 00 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASend
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASend"

    /*
        68C3F682E0           | push 0xe082f6c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 f6 82 e0 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASendDisconnect
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASendDisconnect"

    /*
        684B431428           | push 0x2814434b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 43 14 28 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASendMsg
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASendMsg"

    /*
        68AF9FE631           | push 0x31e69faf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 9f e6 31 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASendTo
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASendTo"

    /*
        689555DF31           | push 0x31df5595
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 55 df 31 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASetBlockingHook
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASetBlockingHook"

    /*
        6835FC03D1           | push 0xd103fc35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 fc 03 d1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASetEvent
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASetEvent"

    /*
        689A3039F5           | push 0xf539309a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 30 39 f5 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASetLastError
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASetLastError"

    /*
        68DD9BC65D           | push 0x5dc69bdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 9b c6 5d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASetServiceA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASetServiceA"

    /*
        6887561319           | push 0x19135687
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 56 13 19 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASetServiceW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASetServiceW"

    /*
        688756C319           | push 0x19c35687
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 56 c3 19 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASocketA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASocketA"

    /*
        68EA0FDFE0           | push 0xe0df0fea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 0f df e0 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSASocketW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSASocketW"

    /*
        68EA0F8FE1           | push 0xe18f0fea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 0f 8f e1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAStartup
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAStartup"

    /*
        6829806B00           | push 0x006b8029
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 80 6b 00 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAStringToAddressA
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAStringToAddressA"

    /*
        68C7101787           | push 0x871710c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 10 17 87 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAStringToAddressW
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAStringToAddressW"

    /*
        68C710C787           | push 0x87c710c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 10 c7 87 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAUnadvertiseProvider
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAUnadvertiseProvider"

    /*
        68D2494995           | push 0x954949d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 49 49 95 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAUnhookBlockingHook
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAUnhookBlockingHook"

    /*
        681527577C           | push 0x7c572715
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 27 57 7c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSAWaitForMultipleEvents
{
    meta:
        desc = "Metasploit::API::ws2_32::WSAWaitForMultipleEvents"

    /*
        6841812CD2           | push 0xd22c8141
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 81 2c d2 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSApSetPostRoutine
{
    meta:
        desc = "Metasploit::API::ws2_32::WSApSetPostRoutine"

    /*
        683FF42266           | push 0x6622f43f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f f4 22 66 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCDeinstallProvider
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCDeinstallProvider"

    /*
        688B1FD18A           | push 0x8ad11f8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 1f d1 8a ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCDeinstallProvider32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCDeinstallProvider32"

    /*
        68807F81C3           | push 0xc3817f80
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 7f 81 c3 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCDeinstallProviderEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCDeinstallProviderEx"

    /*
        680084B1C5           | push 0xc5b18400
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 84 b1 c5 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCEnableNSProvider
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCEnableNSProvider"

    /*
        68F72A3836           | push 0x36382af7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 2a 38 36 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCEnableNSProvider32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCEnableNSProvider32"

    /*
        686B5A449D           | push 0x9d445a6b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 5a 44 9d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCEnumNameSpaceProviders32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCEnumNameSpaceProviders32"

    /*
        688129FD44           | push 0x44fd2981
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 29 fd 44 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCEnumNameSpaceProvidersEx32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCEnumNameSpaceProvidersEx32"

    /*
        68EF1C85DA           | push 0xda851cef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 1c 85 da ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCEnumProtocols
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCEnumProtocols"

    /*
        68608C442B           | push 0x2b448c60
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 8c 44 2b ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCEnumProtocols32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCEnumProtocols32"

    /*
        68A8B45CE0           | push 0xe05cb4a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 b4 5c e0 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCEnumProtocolsEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCEnumProtocolsEx"

    /*
        6828B98CE2           | push 0xe28cb928
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 b9 8c e2 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCGetApplicationCategory
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCGetApplicationCategory"

    /*
        6824960667           | push 0x67069624
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 96 06 67 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCGetApplicationCategoryEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCGetApplicationCategoryEx"

    /*
        68372A0FD3           | push 0xd30f2a37
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 2a 0f d3 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCGetProviderInfo
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCGetProviderInfo"

    /*
        6839A20ECD           | push 0xcd0ea239
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 a2 0e cd ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCGetProviderInfo32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCGetProviderInfo32"

    /*
        68D02AE252           | push 0x52e22ad0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 2a e2 52 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCGetProviderPath
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCGetProviderPath"

    /*
        68B915D7B2           | push 0xb2d715b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 15 d7 b2 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCGetProviderPath32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCGetProviderPath32"

    /*
        68CA0AFFC4           | push 0xc4ff0aca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 0a ff c4 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallNameSpace
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallNameSpace"

    /*
        681DB9BA49           | push 0x49bab91d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d b9 ba 49 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallNameSpace32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallNameSpace32"

    /*
        68EFE3E77D           | push 0x7de7e3ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef e3 e7 7d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallNameSpaceEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallNameSpaceEx"

    /*
        686FE81780           | push 0x8017e86f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f e8 17 80 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallNameSpaceEx2
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallNameSpaceEx2"

    /*
        68741011D5           | push 0xd5111074
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 10 11 d5 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallNameSpaceEx32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallNameSpaceEx32"

    /*
        687DB83315           | push 0x1533b87d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d b8 33 15 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallProvider
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallProvider"

    /*
        68FA79AE1F           | push 0x1fae79fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 79 ae 1f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallProvider64_32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallProvider64_32"

    /*
        68FA597398           | push 0x987359fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 59 73 98 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallProviderAndChains64_32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallProviderAndChains64_32"

    /*
        686EEF6167           | push 0x6761ef6e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e ef 61 67 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCInstallProviderEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCInstallProviderEx"

    /*
        68A51F08FD           | push 0xfd081fa5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 1f 08 fd ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCSetApplicationCategory
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCSetApplicationCategory"

    /*
        6854960667           | push 0x67069654
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 96 06 67 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCSetApplicationCategoryEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCSetApplicationCategoryEx"

    /*
        6837360FD3           | push 0xd30f3637
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 36 0f d3 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCSetProviderInfo
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCSetProviderInfo"

    /*
        683AA20E4D           | push 0x4d0ea23a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a a2 0e 4d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCSetProviderInfo32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCSetProviderInfo32"

    /*
        68302BE252           | push 0x52e22b30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 2b e2 52 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCUnInstallNameSpace
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCUnInstallNameSpace"

    /*
        687A12667A           | push 0x7a66127a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 12 66 7a ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCUnInstallNameSpace32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCUnInstallNameSpace32"

    /*
        683C3BBEA8           | push 0xa8be3b3c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 3b be a8 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCUnInstallNameSpaceEx2
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCUnInstallNameSpaceEx2"

    /*
        682667728F           | push 0x8f726726
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 67 72 8f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCUpdateProvider
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCUpdateProvider"

    /*
        681BDD7D48           | push 0x487ddd1b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b dd 7d 48 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCUpdateProvider32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCUpdateProvider32"

    /*
        686FE3B02E           | push 0x2eb0e36f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f e3 b0 2e ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCUpdateProviderEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCUpdateProviderEx"

    /*
        68EFE7E030           | push 0x30e0e7ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef e7 e0 30 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCWriteNameSpaceOrder
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCWriteNameSpaceOrder"

    /*
        68A4D7A91E           | push 0x1ea9d7a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 d7 a9 1e ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCWriteNameSpaceOrder32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCWriteNameSpaceOrder32"

    /*
        68A585AFB9           | push 0xb9af85a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 85 af b9 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCWriteProviderOrder
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCWriteProviderOrder"

    /*
        682CD3A8B2           | push 0xb2a8d32c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c d3 a8 b2 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCWriteProviderOrder32
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCWriteProviderOrder32"

    /*
        688A676EB9           | push 0xb96e678a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 67 6e b9 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WSCWriteProviderOrderEx
{
    meta:
        desc = "Metasploit::API::ws2_32::WSCWriteProviderOrderEx"

    /*
        680A6C9EBB           | push 0xbb9e6c0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 6c 9e bb ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCloseApcHelper
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCloseApcHelper"

    /*
        68E4A312DE           | push 0xde12a3e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 a3 12 de ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCloseHandleHelper
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCloseHandleHelper"

    /*
        681C3B7C80           | push 0x807c3b1c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 3b 7c 80 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCloseNotificationHandleHelper
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCloseNotificationHandleHelper"

    /*
        68960EC290           | push 0x90c20e96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 0e c2 90 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCloseSocketHandle
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCloseSocketHandle"

    /*
        68689730A1           | push 0xa1309768
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 97 30 a1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCloseThread
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCloseThread"

    /*
        68F2BF9304           | push 0x0493bff2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 bf 93 04 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCompleteRequest
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCompleteRequest"

    /*
        68A57DD233           | push 0x33d27da5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 7d d2 33 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCreateHandleContextTable
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCreateHandleContextTable"

    /*
        681A016B94           | push 0x946b011a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 01 6b 94 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCreateNotificationHandle
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCreateNotificationHandle"

    /*
        6852622545           | push 0x45256252
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 62 25 45 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahCreateSocketHandle
{
    meta:
        desc = "Metasploit::API::ws2_32::WahCreateSocketHandle"

    /*
        68DE2A1578           | push 0x78152ade
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 2a 15 78 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahDestroyHandleContextTable
{
    meta:
        desc = "Metasploit::API::ws2_32::WahDestroyHandleContextTable"

    /*
        68688B052A           | push 0x2a058b68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 8b 05 2a ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahDisableNonIFSHandleSupport
{
    meta:
        desc = "Metasploit::API::ws2_32::WahDisableNonIFSHandleSupport"

    /*
        68DEB9EE85           | push 0x85eeb9de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de b9 ee 85 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahEnableNonIFSHandleSupport
{
    meta:
        desc = "Metasploit::API::ws2_32::WahEnableNonIFSHandleSupport"

    /*
        684F895765           | push 0x6557894f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 89 57 65 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahEnumerateHandleContexts
{
    meta:
        desc = "Metasploit::API::ws2_32::WahEnumerateHandleContexts"

    /*
        682FE19999           | push 0x9999e12f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f e1 99 99 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahInsertHandleContext
{
    meta:
        desc = "Metasploit::API::ws2_32::WahInsertHandleContext"

    /*
        680C546CC7           | push 0xc76c540c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 54 6c c7 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahNotifyAllProcesses
{
    meta:
        desc = "Metasploit::API::ws2_32::WahNotifyAllProcesses"

    /*
        684C67B9F0           | push 0xf0b9674c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 67 b9 f0 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahOpenApcHelper
{
    meta:
        desc = "Metasploit::API::ws2_32::WahOpenApcHelper"

    /*
        683D356D2F           | push 0x2f6d353d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 35 6d 2f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahOpenCurrentThread
{
    meta:
        desc = "Metasploit::API::ws2_32::WahOpenCurrentThread"

    /*
        682E93629B           | push 0x9b62932e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 93 62 9b ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahOpenHandleHelper
{
    meta:
        desc = "Metasploit::API::ws2_32::WahOpenHandleHelper"

    /*
        683FF01E33           | push 0x331ef03f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f f0 1e 33 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahOpenNotificationHandleHelper
{
    meta:
        desc = "Metasploit::API::ws2_32::WahOpenNotificationHandleHelper"

    /*
        68C260EDBA           | push 0xbaed60c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 60 ed ba ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahQueueUserApc
{
    meta:
        desc = "Metasploit::API::ws2_32::WahQueueUserApc"

    /*
        684918EC52           | push 0x52ec1849
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 18 ec 52 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahReferenceContextByHandle
{
    meta:
        desc = "Metasploit::API::ws2_32::WahReferenceContextByHandle"

    /*
        6862EF0041           | push 0x4100ef62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 ef 00 41 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahRemoveHandleContext
{
    meta:
        desc = "Metasploit::API::ws2_32::WahRemoveHandleContext"

    /*
        68DC293645           | push 0x453629dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 29 36 45 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahWaitForNotification
{
    meta:
        desc = "Metasploit::API::ws2_32::WahWaitForNotification"

    /*
        680445DDE1           | push 0xe1dd4504
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 45 dd e1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_WahWriteLSPEvent
{
    meta:
        desc = "Metasploit::API::ws2_32::WahWriteLSPEvent"

    /*
        688EF5A679           | push 0x79a6f58e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e f5 a6 79 ff d5 }

    condition:
        any of them
}

    
rule ws2_32___WSAFDIsSet
{
    meta:
        desc = "Metasploit::API::ws2_32::__WSAFDIsSet"

    /*
        686D9089BE           | push 0xbe89906d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 90 89 be ff d5 }

    condition:
        any of them
}

    
rule ws2_32_accept
{
    meta:
        desc = "Metasploit::API::ws2_32::accept"

    /*
        6874EC3BE1           | push 0xe13bec74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 ec 3b e1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_bind
{
    meta:
        desc = "Metasploit::API::ws2_32::bind"

    /*
        68C2DB3767           | push 0x6737dbc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 db 37 67 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_closesocket
{
    meta:
        desc = "Metasploit::API::ws2_32::closesocket"

    /*
        68756E4D61           | push 0x614d6e75
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 6e 4d 61 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_connect
{
    meta:
        desc = "Metasploit::API::ws2_32::connect"

    /*
        6899A57461           | push 0x6174a599
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 a5 74 61 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_freeaddrinfo
{
    meta:
        desc = "Metasploit::API::ws2_32::freeaddrinfo"

    /*
        68F5840715           | push 0x150784f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 84 07 15 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getaddrinfo
{
    meta:
        desc = "Metasploit::API::ws2_32::getaddrinfo"

    /*
        6895F6F114           | push 0x14f1f695
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 f6 f1 14 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_gethostbyaddr
{
    meta:
        desc = "Metasploit::API::ws2_32::gethostbyaddr"

    /*
        6869569B86           | push 0x869b5669
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 56 9b 86 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_gethostbyname
{
    meta:
        desc = "Metasploit::API::ws2_32::gethostbyname"

    /*
        68A9283480           | push 0x803428a9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 28 34 80 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_gethostname
{
    meta:
        desc = "Metasploit::API::ws2_32::gethostname"

    /*
        68B649DE01           | push 0x01de49b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 49 de 01 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getnameinfo
{
    meta:
        desc = "Metasploit::API::ws2_32::getnameinfo"

    /*
        682FF615A2           | push 0xa215f62f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f f6 15 a2 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getpeername
{
    meta:
        desc = "Metasploit::API::ws2_32::getpeername"

    /*
        687548A609           | push 0x09a64875
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 48 a6 09 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getprotobyname
{
    meta:
        desc = "Metasploit::API::ws2_32::getprotobyname"

    /*
        68FCC42D00           | push 0x002dc4fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc c4 2d 00 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getprotobynumber
{
    meta:
        desc = "Metasploit::API::ws2_32::getprotobynumber"

    /*
        6827E8AA16           | push 0x16aae827
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 e8 aa 16 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getservbyname
{
    meta:
        desc = "Metasploit::API::ws2_32::getservbyname"

    /*
        68ECD8333F           | push 0x3f33d8ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec d8 33 3f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getservbyport
{
    meta:
        desc = "Metasploit::API::ws2_32::getservbyport"

    /*
        682CFAAB5B           | push 0x5babfa2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c fa ab 5b ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getsockname
{
    meta:
        desc = "Metasploit::API::ws2_32::getsockname"

    /*
        68B1499E8C           | push 0x8c9e49b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 49 9e 8c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_getsockopt
{
    meta:
        desc = "Metasploit::API::ws2_32::getsockopt"

    /*
        68EEA27729           | push 0x2977a2ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee a2 77 29 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_htonl
{
    meta:
        desc = "Metasploit::API::ws2_32::htonl"

    /*
        68F6FB7873           | push 0x7378fbf6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 fb 78 73 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_htons
{
    meta:
        desc = "Metasploit::API::ws2_32::htons"

    /*
        68F6FBB073           | push 0x73b0fbf6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 fb b0 73 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_inet_addr
{
    meta:
        desc = "Metasploit::API::ws2_32::inet_addr"

    /*
        68121E7B4D           | push 0x4d7b1e12
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 1e 7b 4d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_inet_ntoa
{
    meta:
        desc = "Metasploit::API::ws2_32::inet_ntoa"

    /*
        68D2F0F36C           | push 0x6cf3f0d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 f0 f3 6c ff d5 }

    condition:
        any of them
}

    
rule ws2_32_inet_ntop
{
    meta:
        desc = "Metasploit::API::ws2_32::inet_ntop"

    /*
        68D2F06B6D           | push 0x6d6bf0d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 f0 6b 6d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_inet_pton
{
    meta:
        desc = "Metasploit::API::ws2_32::inet_pton"

    /*
        68D2105C6D           | push 0x6d5c10d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 10 5c 6d ff d5 }

    condition:
        any of them
}

    
rule ws2_32_ioctlsocket
{
    meta:
        desc = "Metasploit::API::ws2_32::ioctlsocket"

    /*
        68560F5922           | push 0x22590f56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 0f 59 22 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_listen
{
    meta:
        desc = "Metasploit::API::ws2_32::listen"

    /*
        68B7E938FF           | push 0xff38e9b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 e9 38 ff ff d5 }

    condition:
        any of them
}

    
rule ws2_32_ntohl
{
    meta:
        desc = "Metasploit::API::ws2_32::ntohl"

    /*
        6879FA7873           | push 0x7378fa79
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 fa 78 73 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_ntohs
{
    meta:
        desc = "Metasploit::API::ws2_32::ntohs"

    /*
        6879FAB073           | push 0x73b0fa79
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 fa b0 73 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_recv
{
    meta:
        desc = "Metasploit::API::ws2_32::recv"

    /*
        6802D9C85F           | push 0x5fc8d902
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 d9 c8 5f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_recvfrom
{
    meta:
        desc = "Metasploit::API::ws2_32::recvfrom"

    /*
        68DE280CED           | push 0xed0c28de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 28 0c ed ff d5 }

    condition:
        any of them
}

    
rule ws2_32_select
{
    meta:
        desc = "Metasploit::API::ws2_32::select"

    /*
        68357984E1           | push 0xe1847935
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 79 84 e1 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_send
{
    meta:
        desc = "Metasploit::API::ws2_32::send"

    /*
        68C2EB385F           | push 0x5f38ebc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 eb 38 5f ff d5 }

    condition:
        any of them
}

    
rule ws2_32_sendto
{
    meta:
        desc = "Metasploit::API::ws2_32::sendto"

    /*
        68759D5CDF           | push 0xdf5c9d75
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 9d 5c df ff d5 }

    condition:
        any of them
}

    
rule ws2_32_setsockopt
{
    meta:
        desc = "Metasploit::API::ws2_32::setsockopt"

    /*
        68F1A27729           | push 0x2977a2f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 a2 77 29 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_shutdown
{
    meta:
        desc = "Metasploit::API::ws2_32::shutdown"

    /*
        683D0B5CE8           | push 0xe85c0b3d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 0b 5c e8 ff d5 }

    condition:
        any of them
}

    
rule ws2_32_socket
{
    meta:
        desc = "Metasploit::API::ws2_32::socket"

    /*
        68BAE983ED           | push 0xed83e9ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba e9 83 ed ff d5 }

    condition:
        any of them
}

    