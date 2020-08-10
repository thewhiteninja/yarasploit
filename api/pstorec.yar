
rule pstorec_DllCanUnloadNow
{
    meta:
        desc = "Metasploit::API::pstorec::DllCanUnloadNow"

    /*
        68EE6872CB           | push 0xcb7268ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 68 72 cb ff d5 }

    condition:
        any of them
}

    
rule pstorec_DllGetClassObject
{
    meta:
        desc = "Metasploit::API::pstorec::DllGetClassObject"

    /*
        6803988AFA           | push 0xfa8a9803
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 98 8a fa ff d5 }

    condition:
        any of them
}

    
rule pstorec_DllRegisterServer
{
    meta:
        desc = "Metasploit::API::pstorec::DllRegisterServer"

    /*
        6897DBD74E           | push 0x4ed7db97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 db d7 4e ff d5 }

    condition:
        any of them
}

    
rule pstorec_DllUnregisterServer
{
    meta:
        desc = "Metasploit::API::pstorec::DllUnregisterServer"

    /*
        68D7E4C1A9           | push 0xa9c1e4d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 e4 c1 a9 ff d5 }

    condition:
        any of them
}

    
rule pstorec_PStoreCreateInstance
{
    meta:
        desc = "Metasploit::API::pstorec::PStoreCreateInstance"

    /*
        68DBBD6426           | push 0x2664bddb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db bd 64 26 ff d5 }

    condition:
        any of them
}

    
rule pstorec_PStoreEnumProviders
{
    meta:
        desc = "Metasploit::API::pstorec::PStoreEnumProviders"

    /*
        6868CC457F           | push 0x7f45cc68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 cc 45 7f ff d5 }

    condition:
        any of them
}

    