
rule winhttp_DllCanUnloadNow
{
    meta:
        desc = "Metasploit::API::winhttp::DllCanUnloadNow"

    /*
        68B65CE713           | push 0x13e75cb6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 5c e7 13 ff d5 }

    condition:
        any of them
}

    
rule winhttp_DllGetClassObject
{
    meta:
        desc = "Metasploit::API::winhttp::DllGetClassObject"

    /*
        68CB8BFF42           | push 0x42ff8bcb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 8b ff 42 ff d5 }

    condition:
        any of them
}

    
rule winhttp_Private1
{
    meta:
        desc = "Metasploit::API::winhttp::Private1"

    /*
        68ADCED888           | push 0x88d8cead
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad ce d8 88 ff d5 }

    condition:
        any of them
}

    
rule winhttp_SvchostPushServiceGlobals
{
    meta:
        desc = "Metasploit::API::winhttp::SvchostPushServiceGlobals"

    /*
        68A3297156           | push 0x567129a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 29 71 56 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpAddRequestHeaders
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpAddRequestHeaders"

    /*
        68A026F16D           | push 0x6df126a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 26 f1 6d ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpAutoProxySvcMain
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpAutoProxySvcMain"

    /*
        68170EB64E           | push 0x4eb60e17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 0e b6 4e ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpCheckPlatform
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpCheckPlatform"

    /*
        681914DD6E           | push 0x6edd1419
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 14 dd 6e ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpCloseHandle
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpCloseHandle"

    /*
        682FF1AE5D           | push 0x5daef12f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f f1 ae 5d ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnect
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnect"

    /*
        68469B1EC2           | push 0xc21e9b46
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 9b 1e c2 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionDeletePolicyEntries
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionDeletePolicyEntries"

    /*
        6886AA9752           | push 0x5297aa86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 aa 97 52 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionDeleteProxyInfo
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionDeleteProxyInfo"

    /*
        68798AFA47           | push 0x47fa8a79
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 8a fa 47 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionFreeNameList
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionFreeNameList"

    /*
        6815697739           | push 0x39776915
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 69 77 39 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionFreeProxyInfo
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionFreeProxyInfo"

    /*
        684E029069           | push 0x6990024e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 02 90 69 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionFreeProxyList
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionFreeProxyList"

    /*
        688E35B85F           | push 0x5fb8358e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 35 b8 5f ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionGetNameList
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionGetNameList"

    /*
        68CF20244B           | push 0x4b2420cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 20 24 4b ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionGetProxyInfo
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionGetProxyInfo"

    /*
        68B38F6027           | push 0x27608fb3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 8f 60 27 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionGetProxyList
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionGetProxyList"

    /*
        68F3C2881D           | push 0x1d88c2f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 c2 88 1d ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionSetPolicyEntries
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionSetPolicyEntries"

    /*
        687C48F7B2           | push 0xb2f7487c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 48 f7 b2 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionSetProxyInfo
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionSetProxyInfo"

    /*
        6873906027           | push 0x27609073
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 90 60 27 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpConnectionUpdateIfIndexTable
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpConnectionUpdateIfIndexTable"

    /*
        682D2D0A16           | push 0x160a2d2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 2d 0a 16 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpCrackUrl
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpCrackUrl"

    /*
        688B9A7ED7           | push 0xd77e9a8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 9a 7e d7 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpCreateProxyResolver
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpCreateProxyResolver"

    /*
        6858991E28           | push 0x281e9958
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 99 1e 28 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpCreateUrl
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpCreateUrl"

    /*
        68B5E7D3B3           | push 0xb3d3e7b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 e7 d3 b3 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpDetectAutoProxyConfigUrl
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpDetectAutoProxyConfigUrl"

    /*
        68EE59C8BB           | push 0xbbc859ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 59 c8 bb ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpFreeProxyResult
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpFreeProxyResult"

    /*
        68BD4C60A5           | push 0xa5604cbd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 4c 60 a5 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpFreeProxyResultEx
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpFreeProxyResultEx"

    /*
        68461BD43F           | push 0x3fd41b46
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 1b d4 3f ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpFreeProxySettings
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpFreeProxySettings"

    /*
        68C6F3AFB4           | push 0xb4aff3c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 f3 af b4 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetDefaultProxyConfiguration
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetDefaultProxyConfiguration"

    /*
        680CDABD35           | push 0x35bdda0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c da bd 35 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetIEProxyConfigForCurrentUser
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetIEProxyConfigForCurrentUser"

    /*
        6821A70B60           | push 0x600ba721
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 a7 0b 60 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetProxyForUrl
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetProxyForUrl"

    /*
        68DADDEA49           | push 0x49eaddda
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da dd ea 49 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetProxyForUrlEx
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetProxyForUrlEx"

    /*
        68B0627862           | push 0x627862b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 62 78 62 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetProxyForUrlEx2
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetProxyForUrlEx2"

    /*
        687F3D2FAD           | push 0xad2f3d7f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 3d 2f ad ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetProxyForUrlHvsi
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetProxyForUrlHvsi"

    /*
        6876D36181           | push 0x8161d376
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 d3 61 81 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetProxyResult
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetProxyResult"

    /*
        6856EC5A8A           | push 0x8a5aec56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 ec 5a 8a ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetProxyResultEx
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetProxyResultEx"

    /*
        6880017C7E           | push 0x7e7c0180
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 01 7c 7e ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetProxySettingsVersion
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetProxySettingsVersion"

    /*
        687F4FDADA           | push 0xdada4f7f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 4f da da ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpGetTunnelSocket
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpGetTunnelSocket"

    /*
        68510C2DA6           | push 0xa62d0c51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 0c 2d a6 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpOpen
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpOpen"

    /*
        68041F9DBB           | push 0xbb9d1f04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 1f 9d bb ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpOpenRequest
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpOpenRequest"

    /*
        689810B35B           | push 0x5bb31098
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 10 b3 5b ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpPacJsWorkerMain
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpPacJsWorkerMain"

    /*
        688EA4BF76           | push 0x76bfa48e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e a4 bf 76 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpProbeConnectivity
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpProbeConnectivity"

    /*
        681F606007           | push 0x0760601f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 60 60 07 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpQueryAuthSchemes
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpQueryAuthSchemes"

    /*
        68AB33C156           | push 0x56c133ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 33 c1 56 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpQueryDataAvailable
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpQueryDataAvailable"

    /*
        68500E054A           | push 0x4a050e50
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 0e 05 4a ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpQueryHeaders
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpQueryHeaders"

    /*
        684A135129           | push 0x2951134a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 13 51 29 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpQueryOption
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpQueryOption"

    /*
        6878042F27           | push 0x272f0478
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 04 2f 27 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpReadData
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpReadData"

    /*
        686C29247E           | push 0x7e24296c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 29 24 7e ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpReadProxySettings
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpReadProxySettings"

    /*
        6825F0A234           | push 0x34a2f025
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 f0 a2 34 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpReadProxySettingsHvsi
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpReadProxySettingsHvsi"

    /*
        6821828602           | push 0x02868221
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 82 86 02 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpReceiveResponse
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpReceiveResponse"

    /*
        6805889D70           | push 0x709d8805
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 88 9d 70 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpResetAutoProxy
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpResetAutoProxy"

    /*
        689C9A1F7C           | push 0x7c1f9a9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 9a 1f 7c ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpSaveProxyCredentials
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpSaveProxyCredentials"

    /*
        68358A2B42           | push 0x422b8a35
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 8a 2b 42 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpSendRequest
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpSendRequest"

    /*
        689558BB91           | push 0x91bb5895
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 58 bb 91 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpSetCredentials
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpSetCredentials"

    /*
        68DD29A8CE           | push 0xcea829dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 29 a8 ce ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpSetDefaultProxyConfiguration
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpSetDefaultProxyConfiguration"

    /*
        680CDA7D36           | push 0x367dda0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c da 7d 36 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpSetOption
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpSetOption"

    /*
        68D3589DCE           | push 0xce9d58d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 58 9d ce ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpSetStatusCallback
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpSetStatusCallback"

    /*
        689B094CBC           | push 0xbc4c099b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 09 4c bc ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpSetTimeouts
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpSetTimeouts"

    /*
        68AF2BD3A1           | push 0xa1d32baf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 2b d3 a1 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpTimeFromSystemTime
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpTimeFromSystemTime"

    /*
        686C35AFCC           | push 0xccaf356c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 35 af cc ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpTimeToSystemTime
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpTimeToSystemTime"

    /*
        68736F37D3           | push 0xd3376f73
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 6f 37 d3 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWebSocketClose
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWebSocketClose"

    /*
        68645A70B1           | push 0xb1705a64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 5a 70 b1 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWebSocketCompleteUpgrade
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWebSocketCompleteUpgrade"

    /*
        688BF79911           | push 0x1199f78b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b f7 99 11 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWebSocketQueryCloseStatus
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWebSocketQueryCloseStatus"

    /*
        68FCE98E54           | push 0x548ee9fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc e9 8e 54 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWebSocketReceive
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWebSocketReceive"

    /*
        6823B3224B           | push 0x4b22b323
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 b3 22 4b ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWebSocketSend
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWebSocketSend"

    /*
        68C5029E77           | push 0x779e02c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 02 9e 77 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWebSocketShutdown
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWebSocketShutdown"

    /*
        68B937F6A5           | push 0xa5f637b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 37 f6 a5 ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWriteData
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWriteData"

    /*
        68AD78C64B           | push 0x4bc678ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 78 c6 4b ff d5 }

    condition:
        any of them
}

    
rule winhttp_WinHttpWriteProxySettings
{
    meta:
        desc = "Metasploit::API::winhttp::WinHttpWriteProxySettings"

    /*
        6892FE1C47           | push 0x471cfe92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 fe 1c 47 ff d5 }

    condition:
        any of them
}

    