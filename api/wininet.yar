
rule wininet_AppCacheCheckManifest
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheCheckManifest"

    /*
        68C2752016           | push 0x162075c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 75 20 16 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheCloseHandle
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheCloseHandle"

    /*
        68C12E4CB6           | push 0xb64c2ec1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 2e 4c b6 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheCreateAndCommitFile
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheCreateAndCommitFile"

    /*
        6812019E24           | push 0x249e0112
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 01 9e 24 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheDeleteGroup
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheDeleteGroup"

    /*
        68D25A1AFF           | push 0xff1a5ad2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 5a 1a ff ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheDeleteIEGroup
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheDeleteIEGroup"

    /*
        68027BEBC1           | push 0xc1eb7b02
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 7b eb c1 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheDuplicateHandle
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheDuplicateHandle"

    /*
        68AF48D210           | push 0x10d248af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 48 d2 10 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheFinalize
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheFinalize"

    /*
        680171A145           | push 0x45a17101
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 71 a1 45 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheFreeDownloadList
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheFreeDownloadList"

    /*
        6825162335           | push 0x35231625
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 16 23 35 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheFreeGroupList
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheFreeGroupList"

    /*
        6826B8B944           | push 0x44b9b826
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 b8 b9 44 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheFreeIESpace
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheFreeIESpace"

    /*
        68FBF84522           | push 0x2245f8fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb f8 45 22 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheFreeSpace
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheFreeSpace"

    /*
        68E200B5B0           | push 0xb0b500e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 00 b5 b0 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheGetDownloadList
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheGetDownloadList"

    /*
        683651B8F5           | push 0xf5b85136
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 51 b8 f5 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheGetFallbackUrl
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheGetFallbackUrl"

    /*
        68727D0A4D           | push 0x4d0a7d72
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 7d 0a 4d ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheGetGroupList
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheGetGroupList"

    /*
        688740578F           | push 0x8f574087
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 40 57 8f ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheGetIEGroupList
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheGetIEGroupList"

    /*
        6852679DFB           | push 0xfb9d6752
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 67 9d fb ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheGetInfo
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheGetInfo"

    /*
        68E44D06E5           | push 0xe5064de4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 4d 06 e5 ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheGetManifestUrl
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheGetManifestUrl"

    /*
        68FA1D294A           | push 0x4a291dfa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 1d 29 4a ff d5 }

    condition:
        any of them
}

    
rule wininet_AppCacheLookup
{
    meta:
        desc = "Metasploit::API::wininet::AppCacheLookup"

    /*
        6829D46FC1           | push 0xc16fd429
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 d4 6f c1 ff d5 }

    condition:
        any of them
}

    
rule wininet_CommitUrlCacheEntryA
{
    meta:
        desc = "Metasploit::API::wininet::CommitUrlCacheEntryA"

    /*
        686356861A           | push 0x1a865663
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 56 86 1a ff d5 }

    condition:
        any of them
}

    
rule wininet_CommitUrlCacheEntryBinaryBlob
{
    meta:
        desc = "Metasploit::API::wininet::CommitUrlCacheEntryBinaryBlob"

    /*
        68B883094F           | push 0x4f0983b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 83 09 4f ff d5 }

    condition:
        any of them
}

    
rule wininet_CommitUrlCacheEntryW
{
    meta:
        desc = "Metasploit::API::wininet::CommitUrlCacheEntryW"

    /*
        686356361B           | push 0x1b365663
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 56 36 1b ff d5 }

    condition:
        any of them
}

    
rule wininet_CreateMD5SSOHash
{
    meta:
        desc = "Metasploit::API::wininet::CreateMD5SSOHash"

    /*
        68A2F94FB3           | push 0xb34ff9a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 f9 4f b3 ff d5 }

    condition:
        any of them
}

    
rule wininet_CreateUrlCacheContainerA
{
    meta:
        desc = "Metasploit::API::wininet::CreateUrlCacheContainerA"

    /*
        68F2362EF8           | push 0xf82e36f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 36 2e f8 ff d5 }

    condition:
        any of them
}

    
rule wininet_CreateUrlCacheContainerW
{
    meta:
        desc = "Metasploit::API::wininet::CreateUrlCacheContainerW"

    /*
        68F236DEF8           | push 0xf8de36f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 36 de f8 ff d5 }

    condition:
        any of them
}

    
rule wininet_CreateUrlCacheEntryA
{
    meta:
        desc = "Metasploit::API::wininet::CreateUrlCacheEntryA"

    /*
        68015C9138           | push 0x38915c01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 5c 91 38 ff d5 }

    condition:
        any of them
}

    
rule wininet_CreateUrlCacheEntryExW
{
    meta:
        desc = "Metasploit::API::wininet::CreateUrlCacheEntryExW"

    /*
        6864F79729           | push 0x2997f764
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 f7 97 29 ff d5 }

    condition:
        any of them
}

    
rule wininet_CreateUrlCacheEntryW
{
    meta:
        desc = "Metasploit::API::wininet::CreateUrlCacheEntryW"

    /*
        68015C4139           | push 0x39415c01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 5c 41 39 ff d5 }

    condition:
        any of them
}

    
rule wininet_CreateUrlCacheGroup
{
    meta:
        desc = "Metasploit::API::wininet::CreateUrlCacheGroup"

    /*
        68C40D88D4           | push 0xd4880dc4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 0d 88 d4 ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteIE3Cache
{
    meta:
        desc = "Metasploit::API::wininet::DeleteIE3Cache"

    /*
        689708774C           | push 0x4c770897
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 08 77 4c ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteUrlCacheContainerA
{
    meta:
        desc = "Metasploit::API::wininet::DeleteUrlCacheContainerA"

    /*
        680E3890F6           | push 0xf690380e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 38 90 f6 ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteUrlCacheContainerW
{
    meta:
        desc = "Metasploit::API::wininet::DeleteUrlCacheContainerW"

    /*
        680E3840F7           | push 0xf740380e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 38 40 f7 ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteUrlCacheEntry
{
    meta:
        desc = "Metasploit::API::wininet::DeleteUrlCacheEntry"

    /*
        683BCF93DB           | push 0xdb93cf3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b cf 93 db ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteUrlCacheEntryA
{
    meta:
        desc = "Metasploit::API::wininet::DeleteUrlCacheEntryA"

    /*
        682142514A           | push 0x4a514221
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 42 51 4a ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteUrlCacheEntryW
{
    meta:
        desc = "Metasploit::API::wininet::DeleteUrlCacheEntryW"

    /*
        682142014B           | push 0x4b014221
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 42 01 4b ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteUrlCacheGroup
{
    meta:
        desc = "Metasploit::API::wininet::DeleteUrlCacheGroup"

    /*
        68FC0F4CD1           | push 0xd14c0ffc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 0f 4c d1 ff d5 }

    condition:
        any of them
}

    
rule wininet_DeleteWpadCacheForNetworks
{
    meta:
        desc = "Metasploit::API::wininet::DeleteWpadCacheForNetworks"

    /*
        6805A2960F           | push 0x0f96a205
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 a2 96 0f ff d5 }

    condition:
        any of them
}

    
rule wininet_DetectAutoProxyUrl
{
    meta:
        desc = "Metasploit::API::wininet::DetectAutoProxyUrl"

    /*
        68565DB571           | push 0x71b55d56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 5d b5 71 ff d5 }

    condition:
        any of them
}

    
rule wininet_DispatchAPICall
{
    meta:
        desc = "Metasploit::API::wininet::DispatchAPICall"

    /*
        6863AD19EF           | push 0xef19ad63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 ad 19 ef ff d5 }

    condition:
        any of them
}

    
rule wininet_DllCanUnloadNow
{
    meta:
        desc = "Metasploit::API::wininet::DllCanUnloadNow"

    /*
        68BD5C6F4C           | push 0x4c6f5cbd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 5c 6f 4c ff d5 }

    condition:
        any of them
}

    
rule wininet_DllGetClassObject
{
    meta:
        desc = "Metasploit::API::wininet::DllGetClassObject"

    /*
        68D28B877B           | push 0x7b878bd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 8b 87 7b ff d5 }

    condition:
        any of them
}

    
rule wininet_DllInstall
{
    meta:
        desc = "Metasploit::API::wininet::DllInstall"

    /*
        68635B5139           | push 0x39515b63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 5b 51 39 ff d5 }

    condition:
        any of them
}

    
rule wininet_DllRegisterServer
{
    meta:
        desc = "Metasploit::API::wininet::DllRegisterServer"

    /*
        6866CFD4CF           | push 0xcfd4cf66
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 cf d4 cf ff d5 }

    condition:
        any of them
}

    
rule wininet_DllUnregisterServer
{
    meta:
        desc = "Metasploit::API::wininet::DllUnregisterServer"

    /*
        68A6D8BE2A           | push 0x2abed8a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 d8 be 2a ff d5 }

    condition:
        any of them
}

    
rule wininet_FindCloseUrlCache
{
    meta:
        desc = "Metasploit::API::wininet::FindCloseUrlCache"

    /*
        687590D8C8           | push 0xc8d89075
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 90 d8 c8 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindFirstUrlCacheContainerA
{
    meta:
        desc = "Metasploit::API::wininet::FindFirstUrlCacheContainerA"

    /*
        689136D152           | push 0x52d13691
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 36 d1 52 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindFirstUrlCacheContainerW
{
    meta:
        desc = "Metasploit::API::wininet::FindFirstUrlCacheContainerW"

    /*
        6891368153           | push 0x53813691
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 36 81 53 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindFirstUrlCacheEntryA
{
    meta:
        desc = "Metasploit::API::wininet::FindFirstUrlCacheEntryA"

    /*
        6831068732           | push 0x32870631
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 06 87 32 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindFirstUrlCacheEntryExA
{
    meta:
        desc = "Metasploit::API::wininet::FindFirstUrlCacheEntryExA"

    /*
        68638352A6           | push 0xa6528363
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 83 52 a6 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindFirstUrlCacheEntryExW
{
    meta:
        desc = "Metasploit::API::wininet::FindFirstUrlCacheEntryExW"

    /*
        68638302A7           | push 0xa7028363
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 83 02 a7 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindFirstUrlCacheEntryW
{
    meta:
        desc = "Metasploit::API::wininet::FindFirstUrlCacheEntryW"

    /*
        6831063733           | push 0x33370631
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 06 37 33 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindFirstUrlCacheGroup
{
    meta:
        desc = "Metasploit::API::wininet::FindFirstUrlCacheGroup"

    /*
        68030DCE89           | push 0x89ce0d03
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 0d ce 89 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindNextUrlCacheContainerA
{
    meta:
        desc = "Metasploit::API::wininet::FindNextUrlCacheContainerA"

    /*
        6899FF817E           | push 0x7e81ff99
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 ff 81 7e ff d5 }

    condition:
        any of them
}

    
rule wininet_FindNextUrlCacheContainerW
{
    meta:
        desc = "Metasploit::API::wininet::FindNextUrlCacheContainerW"

    /*
        6899FF317F           | push 0x7f31ff99
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 ff 31 7f ff d5 }

    condition:
        any of them
}

    
rule wininet_FindNextUrlCacheEntryA
{
    meta:
        desc = "Metasploit::API::wininet::FindNextUrlCacheEntryA"

    /*
        683EC109C3           | push 0xc309c13e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e c1 09 c3 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindNextUrlCacheEntryExA
{
    meta:
        desc = "Metasploit::API::wininet::FindNextUrlCacheEntryExA"

    /*
        68874601C7           | push 0xc7014687
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 46 01 c7 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindNextUrlCacheEntryExW
{
    meta:
        desc = "Metasploit::API::wininet::FindNextUrlCacheEntryExW"

    /*
        688746B1C7           | push 0xc7b14687
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 46 b1 c7 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindNextUrlCacheEntryW
{
    meta:
        desc = "Metasploit::API::wininet::FindNextUrlCacheEntryW"

    /*
        683EC1B9C3           | push 0xc3b9c13e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e c1 b9 c3 ff d5 }

    condition:
        any of them
}

    
rule wininet_FindNextUrlCacheGroup
{
    meta:
        desc = "Metasploit::API::wininet::FindNextUrlCacheGroup"

    /*
        68139F2FE1           | push 0xe12f9f13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 9f 2f e1 ff d5 }

    condition:
        any of them
}

    
rule wininet_ForceNexusLookup
{
    meta:
        desc = "Metasploit::API::wininet::ForceNexusLookup"

    /*
        6848414DA8           | push 0xa84d4148
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 41 4d a8 ff d5 }

    condition:
        any of them
}

    
rule wininet_ForceNexusLookupExW
{
    meta:
        desc = "Metasploit::API::wininet::ForceNexusLookupExW"

    /*
        684DF22AB3           | push 0xb32af24d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d f2 2a b3 ff d5 }

    condition:
        any of them
}

    
rule wininet_FreeUrlCacheSpaceA
{
    meta:
        desc = "Metasploit::API::wininet::FreeUrlCacheSpaceA"

    /*
        688643F8E2           | push 0xe2f84386
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 43 f8 e2 ff d5 }

    condition:
        any of them
}

    
rule wininet_FreeUrlCacheSpaceW
{
    meta:
        desc = "Metasploit::API::wininet::FreeUrlCacheSpaceW"

    /*
        688643A8E3           | push 0xe3a84386
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 43 a8 e3 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpCommandA
{
    meta:
        desc = "Metasploit::API::wininet::FtpCommandA"

    /*
        682C4E8029           | push 0x29804e2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 4e 80 29 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpCommandW
{
    meta:
        desc = "Metasploit::API::wininet::FtpCommandW"

    /*
        682C4E302A           | push 0x2a304e2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 4e 30 2a ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpCreateDirectoryA
{
    meta:
        desc = "Metasploit::API::wininet::FtpCreateDirectoryA"

    /*
        68F2245C6E           | push 0x6e5c24f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 24 5c 6e ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpCreateDirectoryW
{
    meta:
        desc = "Metasploit::API::wininet::FtpCreateDirectoryW"

    /*
        68F2240C6F           | push 0x6f0c24f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 24 0c 6f ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpDeleteFileA
{
    meta:
        desc = "Metasploit::API::wininet::FtpDeleteFileA"

    /*
        68F5CD5D41           | push 0x415dcdf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 cd 5d 41 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpDeleteFileW
{
    meta:
        desc = "Metasploit::API::wininet::FtpDeleteFileW"

    /*
        68F5CD0D42           | push 0x420dcdf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 cd 0d 42 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpFindFirstFileA
{
    meta:
        desc = "Metasploit::API::wininet::FtpFindFirstFileA"

    /*
        68ECB7CD89           | push 0x89cdb7ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec b7 cd 89 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpFindFirstFileW
{
    meta:
        desc = "Metasploit::API::wininet::FtpFindFirstFileW"

    /*
        68ECB77D8A           | push 0x8a7db7ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec b7 7d 8a ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpGetCurrentDirectoryA
{
    meta:
        desc = "Metasploit::API::wininet::FtpGetCurrentDirectoryA"

    /*
        68FF96A4E9           | push 0xe9a496ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 96 a4 e9 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpGetCurrentDirectoryW
{
    meta:
        desc = "Metasploit::API::wininet::FtpGetCurrentDirectoryW"

    /*
        68FF9654EA           | push 0xea5496ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 96 54 ea ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpGetFileA
{
    meta:
        desc = "Metasploit::API::wininet::FtpGetFileA"

    /*
        6819CD9CA9           | push 0xa99ccd19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 cd 9c a9 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpGetFileEx
{
    meta:
        desc = "Metasploit::API::wininet::FtpGetFileEx"

    /*
        6869B3F73A           | push 0x3af7b369
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 b3 f7 3a ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpGetFileSize
{
    meta:
        desc = "Metasploit::API::wininet::FtpGetFileSize"

    /*
        68E5B19E9D           | push 0x9d9eb1e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 b1 9e 9d ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpGetFileW
{
    meta:
        desc = "Metasploit::API::wininet::FtpGetFileW"

    /*
        6819CD4CAA           | push 0xaa4ccd19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 cd 4c aa ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpOpenFileA
{
    meta:
        desc = "Metasploit::API::wininet::FtpOpenFileA"

    /*
        6878C9DFD2           | push 0xd2dfc978
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 c9 df d2 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpOpenFileW
{
    meta:
        desc = "Metasploit::API::wininet::FtpOpenFileW"

    /*
        6878C98FD3           | push 0xd38fc978
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 c9 8f d3 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpPutFileA
{
    meta:
        desc = "Metasploit::API::wininet::FtpPutFileA"

    /*
        6819CF9CB2           | push 0xb29ccf19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 cf 9c b2 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpPutFileEx
{
    meta:
        desc = "Metasploit::API::wininet::FtpPutFileEx"

    /*
        6869FBF74A           | push 0x4af7fb69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 fb f7 4a ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpPutFileW
{
    meta:
        desc = "Metasploit::API::wininet::FtpPutFileW"

    /*
        6819CF4CB3           | push 0xb34ccf19
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 cf 4c b3 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpRemoveDirectoryA
{
    meta:
        desc = "Metasploit::API::wininet::FtpRemoveDirectoryA"

    /*
        6811456BD5           | push 0xd56b4511
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 45 6b d5 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpRemoveDirectoryW
{
    meta:
        desc = "Metasploit::API::wininet::FtpRemoveDirectoryW"

    /*
        6811451BD6           | push 0xd61b4511
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 45 1b d6 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpRenameFileA
{
    meta:
        desc = "Metasploit::API::wininet::FtpRenameFileA"

    /*
        6815DD793D           | push 0x3d79dd15
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 dd 79 3d ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpRenameFileW
{
    meta:
        desc = "Metasploit::API::wininet::FtpRenameFileW"

    /*
        6815DD293E           | push 0x3e29dd15
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 dd 29 3e ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpSetCurrentDirectoryA
{
    meta:
        desc = "Metasploit::API::wininet::FtpSetCurrentDirectoryA"

    /*
        680097A4A9           | push 0xa9a49700
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 97 a4 a9 ff d5 }

    condition:
        any of them
}

    
rule wininet_FtpSetCurrentDirectoryW
{
    meta:
        desc = "Metasploit::API::wininet::FtpSetCurrentDirectoryW"

    /*
        68009754AA           | push 0xaa549700
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 97 54 aa ff d5 }

    condition:
        any of them
}

    
rule wininet_GetProxyDllInfo
{
    meta:
        desc = "Metasploit::API::wininet::GetProxyDllInfo"

    /*
        6854A244BB           | push 0xbb44a254
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 a2 44 bb ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheConfigInfoA
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheConfigInfoA"

    /*
        68F9D05AAD           | push 0xad5ad0f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 d0 5a ad ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheConfigInfoW
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheConfigInfoW"

    /*
        68F9D00AAE           | push 0xae0ad0f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 d0 0a ae ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheEntryBinaryBlob
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheEntryBinaryBlob"

    /*
        685EE10F28           | push 0x280fe15e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e e1 0f 28 ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheEntryInfoA
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheEntryInfoA"

    /*
        684D074182           | push 0x8241074d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 07 41 82 ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheEntryInfoExA
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheEntryInfoExA"

    /*
        6877CAD294           | push 0x94d2ca77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 ca d2 94 ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheEntryInfoExW
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheEntryInfoExW"

    /*
        6877CA8295           | push 0x9582ca77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 ca 82 95 ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheEntryInfoW
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheEntryInfoW"

    /*
        684D07F182           | push 0x82f1074d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 07 f1 82 ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheGroupAttributeA
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheGroupAttributeA"

    /*
        68237955BA           | push 0xba557923
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 79 55 ba ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheGroupAttributeW
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheGroupAttributeW"

    /*
        68237905BB           | push 0xbb057923
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 79 05 bb ff d5 }

    condition:
        any of them
}

    
rule wininet_GetUrlCacheHeaderData
{
    meta:
        desc = "Metasploit::API::wininet::GetUrlCacheHeaderData"

    /*
        68E31EEEA5           | push 0xa5ee1ee3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 1e ee a5 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherCreateLocatorA
{
    meta:
        desc = "Metasploit::API::wininet::GopherCreateLocatorA"

    /*
        68491DF639           | push 0x39f61d49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 1d f6 39 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherCreateLocatorW
{
    meta:
        desc = "Metasploit::API::wininet::GopherCreateLocatorW"

    /*
        68491DA63A           | push 0x3aa61d49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 1d a6 3a ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherFindFirstFileA
{
    meta:
        desc = "Metasploit::API::wininet::GopherFindFirstFileA"

    /*
        680097BF55           | push 0x55bf9700
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 97 bf 55 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherFindFirstFileW
{
    meta:
        desc = "Metasploit::API::wininet::GopherFindFirstFileW"

    /*
        6800976F56           | push 0x566f9700
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 97 6f 56 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherGetAttributeA
{
    meta:
        desc = "Metasploit::API::wininet::GopherGetAttributeA"

    /*
        68970E7806           | push 0x06780e97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 0e 78 06 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherGetAttributeW
{
    meta:
        desc = "Metasploit::API::wininet::GopherGetAttributeW"

    /*
        68970E2807           | push 0x07280e97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 0e 28 07 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherGetLocatorTypeA
{
    meta:
        desc = "Metasploit::API::wininet::GopherGetLocatorTypeA"

    /*
        6854527FC3           | push 0xc37f5254
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 52 7f c3 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherGetLocatorTypeW
{
    meta:
        desc = "Metasploit::API::wininet::GopherGetLocatorTypeW"

    /*
        6854522FC4           | push 0xc42f5254
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 52 2f c4 ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherOpenFileA
{
    meta:
        desc = "Metasploit::API::wininet::GopherOpenFileA"

    /*
        68A187C36A           | push 0x6ac387a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 87 c3 6a ff d5 }

    condition:
        any of them
}

    
rule wininet_GopherOpenFileW
{
    meta:
        desc = "Metasploit::API::wininet::GopherOpenFileW"

    /*
        68A187736B           | push 0x6b7387a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 87 73 6b ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpAddRequestHeadersA
{
    meta:
        desc = "Metasploit::API::wininet::HttpAddRequestHeadersA"

    /*
        684930EF3F           | push 0x3fef3049
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 30 ef 3f ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpAddRequestHeadersW
{
    meta:
        desc = "Metasploit::API::wininet::HttpAddRequestHeadersW"

    /*
        6849309F40           | push 0x409f3049
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 30 9f 40 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpCheckDavCompliance
{
    meta:
        desc = "Metasploit::API::wininet::HttpCheckDavCompliance"

    /*
        6882DC5DE8           | push 0xe85ddc82
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 dc 5d e8 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpCloseDependencyHandle
{
    meta:
        desc = "Metasploit::API::wininet::HttpCloseDependencyHandle"

    /*
        6840AF7174           | push 0x7471af40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 af 71 74 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpDuplicateDependencyHandle
{
    meta:
        desc = "Metasploit::API::wininet::HttpDuplicateDependencyHandle"

    /*
        6818B9A0CB           | push 0xcba0b918
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 b9 a0 cb ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpEndRequestA
{
    meta:
        desc = "Metasploit::API::wininet::HttpEndRequestA"

    /*
        68F80790FC           | push 0xfc9007f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 07 90 fc ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpEndRequestW
{
    meta:
        desc = "Metasploit::API::wininet::HttpEndRequestW"

    /*
        68F80740FD           | push 0xfd4007f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 07 40 fd ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpGetServerCredentials
{
    meta:
        desc = "Metasploit::API::wininet::HttpGetServerCredentials"

    /*
        688A6CAE40           | push 0x40ae6c8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 6c ae 40 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpGetTunnelSocket
{
    meta:
        desc = "Metasploit::API::wininet::HttpGetTunnelSocket"

    /*
        68F58A80FE           | push 0xfe808af5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 8a 80 fe ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpIndicatePageLoadComplete
{
    meta:
        desc = "Metasploit::API::wininet::HttpIndicatePageLoadComplete"

    /*
        689FD3560B           | push 0x0b56d39f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f d3 56 0b ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpIsHostHstsEnabled
{
    meta:
        desc = "Metasploit::API::wininet::HttpIsHostHstsEnabled"

    /*
        68BF26BAAC           | push 0xacba26bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 26 ba ac ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpOpenDependencyHandle
{
    meta:
        desc = "Metasploit::API::wininet::HttpOpenDependencyHandle"

    /*
        6894050861           | push 0x61080594
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 05 08 61 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpOpenRequestA
{
    meta:
        desc = "Metasploit::API::wininet::HttpOpenRequestA"

    /*
        68EB552E3B           | push 0x3b2e55eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 55 2e 3b ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpOpenRequestW
{
    meta:
        desc = "Metasploit::API::wininet::HttpOpenRequestW"

    /*
        68EB55DE3B           | push 0x3bde55eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 55 de 3b ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpPushClose
{
    meta:
        desc = "Metasploit::API::wininet::HttpPushClose"

    /*
        689609E882           | push 0x82e80996
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 09 e8 82 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpPushEnable
{
    meta:
        desc = "Metasploit::API::wininet::HttpPushEnable"

    /*
        68849E55FC           | push 0xfc559e84
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 9e 55 fc ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpPushWait
{
    meta:
        desc = "Metasploit::API::wininet::HttpPushWait"

    /*
        68AAB48B9E           | push 0x9e8bb4aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa b4 8b 9e ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpQueryInfoA
{
    meta:
        desc = "Metasploit::API::wininet::HttpQueryInfoA"

    /*
        68727006B6           | push 0xb6067072
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 70 06 b6 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpQueryInfoW
{
    meta:
        desc = "Metasploit::API::wininet::HttpQueryInfoW"

    /*
        687270B6B6           | push 0xb6b67072
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 70 b6 b6 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpSendRequestA
{
    meta:
        desc = "Metasploit::API::wininet::HttpSendRequestA"

    /*
        682D06187B           | push 0x7b18062d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 06 18 7b ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpSendRequestExA
{
    meta:
        desc = "Metasploit::API::wininet::HttpSendRequestExA"

    /*
        68758292CA           | push 0xca928275
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 82 92 ca ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpSendRequestExW
{
    meta:
        desc = "Metasploit::API::wininet::HttpSendRequestExW"

    /*
        68758242CB           | push 0xcb428275
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 82 42 cb ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpSendRequestW
{
    meta:
        desc = "Metasploit::API::wininet::HttpSendRequestW"

    /*
        682D06C87B           | push 0x7bc8062d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 06 c8 7b ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpWebSocketClose
{
    meta:
        desc = "Metasploit::API::wininet::HttpWebSocketClose"

    /*
        6864FECB59           | push 0x59cbfe64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 fe cb 59 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpWebSocketCompleteUpgrade
{
    meta:
        desc = "Metasploit::API::wininet::HttpWebSocketCompleteUpgrade"

    /*
        6891E016A6           | push 0xa616e091
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 e0 16 a6 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpWebSocketQueryCloseStatus
{
    meta:
        desc = "Metasploit::API::wininet::HttpWebSocketQueryCloseStatus"

    /*
        68AAC909D5           | push 0xd509c9aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa c9 09 d5 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpWebSocketReceive
{
    meta:
        desc = "Metasploit::API::wininet::HttpWebSocketReceive"

    /*
        6886B19378           | push 0x7893b186
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 b1 93 78 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpWebSocketSend
{
    meta:
        desc = "Metasploit::API::wininet::HttpWebSocketSend"

    /*
        68C630A524           | push 0x24a530c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 30 a5 24 ff d5 }

    condition:
        any of them
}

    
rule wininet_HttpWebSocketShutdown
{
    meta:
        desc = "Metasploit::API::wininet::HttpWebSocketShutdown"

    /*
        6808DF5DD1           | push 0xd15ddf08
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 df 5d d1 ff d5 }

    condition:
        any of them
}

    
rule wininet_IncrementUrlCacheHeaderData
{
    meta:
        desc = "Metasploit::API::wininet::IncrementUrlCacheHeaderData"

    /*
        682C13B95A           | push 0x5ab9132c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 13 b9 5a ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetAlgIdToStringA
{
    meta:
        desc = "Metasploit::API::wininet::InternetAlgIdToStringA"

    /*
        6885C4BFE8           | push 0xe8bfc485
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 c4 bf e8 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetAlgIdToStringW
{
    meta:
        desc = "Metasploit::API::wininet::InternetAlgIdToStringW"

    /*
        6885C46FE9           | push 0xe96fc485
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 c4 6f e9 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetAttemptConnect
{
    meta:
        desc = "Metasploit::API::wininet::InternetAttemptConnect"

    /*
        6855F27C21           | push 0x217cf255
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 f2 7c 21 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetAutodial
{
    meta:
        desc = "Metasploit::API::wininet::InternetAutodial"

    /*
        6857750F52           | push 0x520f7557
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 75 0f 52 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetAutodialCallback
{
    meta:
        desc = "Metasploit::API::wininet::InternetAutodialCallback"

    /*
        68EDBC08F0           | push 0xf008bced
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed bc 08 f0 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetAutodialHangup
{
    meta:
        desc = "Metasploit::API::wininet::InternetAutodialHangup"

    /*
        68ECC35452           | push 0x5254c3ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec c3 54 52 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCanonicalizeUrlA
{
    meta:
        desc = "Metasploit::API::wininet::InternetCanonicalizeUrlA"

    /*
        68C880F1B9           | push 0xb9f180c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 80 f1 b9 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCanonicalizeUrlW
{
    meta:
        desc = "Metasploit::API::wininet::InternetCanonicalizeUrlW"

    /*
        68C880A1BA           | push 0xbaa180c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 80 a1 ba ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCheckConnectionA
{
    meta:
        desc = "Metasploit::API::wininet::InternetCheckConnectionA"

    /*
        68A3044B0F           | push 0x0f4b04a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 04 4b 0f ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCheckConnectionW
{
    meta:
        desc = "Metasploit::API::wininet::InternetCheckConnectionW"

    /*
        68A304FB0F           | push 0x0ffb04a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 04 fb 0f ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetClearAllPerSiteCookieDecisions
{
    meta:
        desc = "Metasploit::API::wininet::InternetClearAllPerSiteCookieDecisions"

    /*
        68AD5C3658           | push 0x58365cad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 5c 36 58 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCloseHandle
{
    meta:
        desc = "Metasploit::API::wininet::InternetCloseHandle"

    /*
        68D36B6ED4           | push 0xd46e6bd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 6b 6e d4 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCombineUrlA
{
    meta:
        desc = "Metasploit::API::wininet::InternetCombineUrlA"

    /*
        6856CCE49E           | push 0x9ee4cc56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 cc e4 9e ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCombineUrlW
{
    meta:
        desc = "Metasploit::API::wininet::InternetCombineUrlW"

    /*
        6856CC949F           | push 0x9f94cc56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 cc 94 9f ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetConfirmZoneCrossing
{
    meta:
        desc = "Metasploit::API::wininet::InternetConfirmZoneCrossing"

    /*
        6880D74102           | push 0x0241d780
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 d7 41 02 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetConfirmZoneCrossingA
{
    meta:
        desc = "Metasploit::API::wininet::InternetConfirmZoneCrossingA"

    /*
        6892777A8C           | push 0x8c7a7792
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 77 7a 8c ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetConfirmZoneCrossingW
{
    meta:
        desc = "Metasploit::API::wininet::InternetConfirmZoneCrossingW"

    /*
        6892772A8D           | push 0x8d2a7792
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 77 2a 8d ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetConnectA
{
    meta:
        desc = "Metasploit::API::wininet::InternetConnectA"

    /*
        6857899FC6           | push 0xc69f8957
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 89 9f c6 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetConnectW
{
    meta:
        desc = "Metasploit::API::wininet::InternetConnectW"

    /*
        6857894FC7           | push 0xc74f8957
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 89 4f c7 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetConvertUrlFromWireToWideChar
{
    meta:
        desc = "Metasploit::API::wininet::InternetConvertUrlFromWireToWideChar"

    /*
        688BB2826F           | push 0x6f82b28b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b b2 82 6f ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCrackUrlA
{
    meta:
        desc = "Metasploit::API::wininet::InternetCrackUrlA"

    /*
        68A2C3031A           | push 0x1a03c3a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 c3 03 1a ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCrackUrlW
{
    meta:
        desc = "Metasploit::API::wininet::InternetCrackUrlW"

    /*
        68A2C3B31A           | push 0x1ab3c3a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 c3 b3 1a ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCreateUrlA
{
    meta:
        desc = "Metasploit::API::wininet::InternetCreateUrlA"

    /*
        682970ADFD           | push 0xfdad7029
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 70 ad fd ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetCreateUrlW
{
    meta:
        desc = "Metasploit::API::wininet::InternetCreateUrlW"

    /*
        6829705DFE           | push 0xfe5d7029
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 70 5d fe ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetDial
{
    meta:
        desc = "Metasploit::API::wininet::InternetDial"

    /*
        68E02906D0           | push 0xd00629e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 29 06 d0 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetDialA
{
    meta:
        desc = "Metasploit::API::wininet::InternetDialA"

    /*
        68B4E5781F           | push 0x1f78e5b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 e5 78 1f ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetDialW
{
    meta:
        desc = "Metasploit::API::wininet::InternetDialW"

    /*
        68B4E52820           | push 0x2028e5b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 e5 28 20 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetEnumPerSiteCookieDecisionA
{
    meta:
        desc = "Metasploit::API::wininet::InternetEnumPerSiteCookieDecisionA"

    /*
        686DFC8DAF           | push 0xaf8dfc6d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d fc 8d af ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetEnumPerSiteCookieDecisionW
{
    meta:
        desc = "Metasploit::API::wininet::InternetEnumPerSiteCookieDecisionW"

    /*
        686DFC3DB0           | push 0xb03dfc6d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d fc 3d b0 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetErrorDlg
{
    meta:
        desc = "Metasploit::API::wininet::InternetErrorDlg"

    /*
        68B757E00B           | push 0x0be057b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 57 e0 0b ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetFindNextFileA
{
    meta:
        desc = "Metasploit::API::wininet::InternetFindNextFileA"

    /*
        68A801C184           | push 0x84c101a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 01 c1 84 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetFindNextFileW
{
    meta:
        desc = "Metasploit::API::wininet::InternetFindNextFileW"

    /*
        68A8017185           | push 0x857101a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 01 71 85 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetFortezzaCommand
{
    meta:
        desc = "Metasploit::API::wininet::InternetFortezzaCommand"

    /*
        685D07301D           | push 0x1d30075d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 07 30 1d ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetFreeCookies
{
    meta:
        desc = "Metasploit::API::wininet::InternetFreeCookies"

    /*
        68DBE57F51           | push 0x517fe5db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db e5 7f 51 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetFreeProxyInfoList
{
    meta:
        desc = "Metasploit::API::wininet::InternetFreeProxyInfoList"

    /*
        68C8207B43           | push 0x437b20c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 20 7b 43 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetCertByURL
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetCertByURL"

    /*
        68A1D9A641           | push 0x41a6d9a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 d9 a6 41 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetCertByURLA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetCertByURLA"

    /*
        68BA72849D           | push 0x9d8472ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 72 84 9d ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetConnectedState
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetConnectedState"

    /*
        68A0676D8D           | push 0x8d6d67a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 67 6d 8d ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetConnectedStateEx
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetConnectedStateEx"

    /*
        6839D2A259           | push 0x59a2d239
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 d2 a2 59 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetConnectedStateExA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetConnectedStateExA"

    /*
        6899324562           | push 0x62453299
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 32 45 62 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetConnectedStateExW
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetConnectedStateExW"

    /*
        689932F562           | push 0x62f53299
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 32 f5 62 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetCookieA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetCookieA"

    /*
        68AF629AFA           | push 0xfa9a62af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 62 9a fa ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetCookieEx2
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetCookieEx2"

    /*
        68D5A2B1AA           | push 0xaab1a2d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 a2 b1 aa ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetCookieExA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetCookieExA"

    /*
        68D5A229AB           | push 0xab29a2d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 a2 29 ab ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetCookieExW
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetCookieExW"

    /*
        68D5A2D9AB           | push 0xabd9a2d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 a2 d9 ab ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetCookieW
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetCookieW"

    /*
        68AF624AFB           | push 0xfb4a62af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 62 4a fb ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetLastResponseInfoA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetLastResponseInfoA"

    /*
        689030C695           | push 0x95c63090
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 30 c6 95 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetLastResponseInfoW
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetLastResponseInfoW"

    /*
        6890307696           | push 0x96763090
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 30 76 96 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetPerSiteCookieDecisionA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetPerSiteCookieDecisionA"

    /*
        68077CE343           | push 0x43e37c07
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 7c e3 43 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetPerSiteCookieDecisionW
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetPerSiteCookieDecisionW"

    /*
        68077C9344           | push 0x44937c07
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 7c 93 44 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetProxyForUrl
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetProxyForUrl"

    /*
        68D74CEFBC           | push 0xbcef4cd7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 4c ef bc ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetSecurityInfoByURL
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetSecurityInfoByURL"

    /*
        6824AC4B44           | push 0x444bac24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 ac 4b 44 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetSecurityInfoByURLA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetSecurityInfoByURLA"

    /*
        68E0879C31           | push 0x319c87e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 87 9c 31 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGetSecurityInfoByURLW
{
    meta:
        desc = "Metasploit::API::wininet::InternetGetSecurityInfoByURLW"

    /*
        68E0874C32           | push 0x324c87e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 87 4c 32 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGoOnline
{
    meta:
        desc = "Metasploit::API::wininet::InternetGoOnline"

    /*
        68D7F743D7           | push 0xd743f7d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 f7 43 d7 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGoOnlineA
{
    meta:
        desc = "Metasploit::API::wininet::InternetGoOnlineA"

    /*
        68A31F318F           | push 0x8f311fa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 1f 31 8f ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetGoOnlineW
{
    meta:
        desc = "Metasploit::API::wininet::InternetGoOnlineW"

    /*
        68A31FE18F           | push 0x8fe11fa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 1f e1 8f ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetHangUp
{
    meta:
        desc = "Metasploit::API::wininet::InternetHangUp"

    /*
        684636A4F5           | push 0xf5a43646
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 36 a4 f5 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetInitializeAutoProxyDll
{
    meta:
        desc = "Metasploit::API::wininet::InternetInitializeAutoProxyDll"

    /*
        68B0BD820B           | push 0x0b82bdb0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 bd 82 0b ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetLockRequestFile
{
    meta:
        desc = "Metasploit::API::wininet::InternetLockRequestFile"

    /*
        688C529F39           | push 0x399f528c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c 52 9f 39 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetOpenA
{
    meta:
        desc = "Metasploit::API::wininet::InternetOpenA"

    /*
        683A5679A7           | push 0xa779563a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 56 79 a7 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetOpenUrlA
{
    meta:
        desc = "Metasploit::API::wininet::InternetOpenUrlA"

    /*
        6877877AF0           | push 0xf07a8777
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 87 7a f0 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetOpenUrlW
{
    meta:
        desc = "Metasploit::API::wininet::InternetOpenUrlW"

    /*
        6877872AF1           | push 0xf12a8777
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 87 2a f1 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetOpenW
{
    meta:
        desc = "Metasploit::API::wininet::InternetOpenW"

    /*
        683A5629A8           | push 0xa829563a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 56 29 a8 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetQueryDataAvailable
{
    meta:
        desc = "Metasploit::API::wininet::InternetQueryDataAvailable"

    /*
        68FF617C49           | push 0x497c61ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 61 7c 49 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetQueryFortezzaStatus
{
    meta:
        desc = "Metasploit::API::wininet::InternetQueryFortezzaStatus"

    /*
        6859CCC691           | push 0x91c6cc59
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 cc c6 91 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetQueryOptionA
{
    meta:
        desc = "Metasploit::API::wininet::InternetQueryOptionA"

    /*
        68F7545FC9           | push 0xc95f54f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 54 5f c9 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetQueryOptionW
{
    meta:
        desc = "Metasploit::API::wininet::InternetQueryOptionW"

    /*
        68F7540FCA           | push 0xca0f54f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 54 0f ca ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetReadFile
{
    meta:
        desc = "Metasploit::API::wininet::InternetReadFile"

    /*
        68129689E2           | push 0xe2899612
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 96 89 e2 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetReadFileExA
{
    meta:
        desc = "Metasploit::API::wininet::InternetReadFileExA"

    /*
        68F66AEF46           | push 0x46ef6af6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 6a ef 46 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetReadFileExW
{
    meta:
        desc = "Metasploit::API::wininet::InternetReadFileExW"

    /*
        68F66A9F47           | push 0x479f6af6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 6a 9f 47 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSecurityProtocolToStringA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSecurityProtocolToStringA"

    /*
        6842CD0FDE           | push 0xde0fcd42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 cd 0f de ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSecurityProtocolToStringW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSecurityProtocolToStringW"

    /*
        6842CDBFDE           | push 0xdebfcd42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 cd bf de ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetCookieA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetCookieA"

    /*
        68B2629AFA           | push 0xfa9a62b2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 62 9a fa ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetCookieEx2
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetCookieEx2"

    /*
        6895A3B1AA           | push 0xaab1a395
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 a3 b1 aa ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetCookieExA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetCookieExA"

    /*
        6895A329AB           | push 0xab29a395
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 a3 29 ab ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetCookieExW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetCookieExW"

    /*
        6895A3D9AB           | push 0xabd9a395
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 a3 d9 ab ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetCookieW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetCookieW"

    /*
        68B2624AFB           | push 0xfb4a62b2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 62 4a fb ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetDialState
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetDialState"

    /*
        68CA984EDE           | push 0xde4e98ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 98 4e de ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetDialStateA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetDialStateA"

    /*
        68F857C996           | push 0x96c957f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 57 c9 96 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetDialStateW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetDialStateW"

    /*
        68F8577997           | push 0x977957f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 57 79 97 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetFilePointer
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetFilePointer"

    /*
        68721CAFA8           | push 0xa8af1c72
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 1c af a8 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetOptionA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetOptionA"

    /*
        6875469E86           | push 0x869e4675
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 46 9e 86 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetOptionExA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetOptionExA"

    /*
        68389422AC           | push 0xac229438
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 94 22 ac ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetOptionExW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetOptionExW"

    /*
        683894D2AC           | push 0xacd29438
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 94 d2 ac ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetOptionW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetOptionW"

    /*
        6875464E87           | push 0x874e4675
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 46 4e 87 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetPerSiteCookieDecisionA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetPerSiteCookieDecisionA"

    /*
        68087CE3A3           | push 0xa3e37c08
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 7c e3 a3 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetPerSiteCookieDecisionW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetPerSiteCookieDecisionW"

    /*
        68087C93A4           | push 0xa4937c08
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 7c 93 a4 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetStatusCallback
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetStatusCallback"

    /*
        68800249DF           | push 0xdf490280
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 02 49 df ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetStatusCallbackA
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetStatusCallbackA"

    /*
        68CB5F79E4           | push 0xe4795fcb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 5f 79 e4 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetSetStatusCallbackW
{
    meta:
        desc = "Metasploit::API::wininet::InternetSetStatusCallbackW"

    /*
        68CB5F29E5           | push 0xe5295fcb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 5f 29 e5 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetShowSecurityInfoByURL
{
    meta:
        desc = "Metasploit::API::wininet::InternetShowSecurityInfoByURL"

    /*
        68EFA027BE           | push 0xbe27a0ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef a0 27 be ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetShowSecurityInfoByURLA
{
    meta:
        desc = "Metasploit::API::wininet::InternetShowSecurityInfoByURLA"

    /*
        68C056F0D7           | push 0xd7f056c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 56 f0 d7 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetShowSecurityInfoByURLW
{
    meta:
        desc = "Metasploit::API::wininet::InternetShowSecurityInfoByURLW"

    /*
        68C056A0D8           | push 0xd8a056c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 56 a0 d8 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetTimeFromSystemTime
{
    meta:
        desc = "Metasploit::API::wininet::InternetTimeFromSystemTime"

    /*
        681B8926CC           | push 0xcc26891b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 89 26 cc ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetTimeFromSystemTimeA
{
    meta:
        desc = "Metasploit::API::wininet::InternetTimeFromSystemTimeA"

    /*
        68B7C65019           | push 0x1950c6b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 c6 50 19 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetTimeFromSystemTimeW
{
    meta:
        desc = "Metasploit::API::wininet::InternetTimeFromSystemTimeW"

    /*
        68B7C6001A           | push 0x1a00c6b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 c6 00 1a ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetTimeToSystemTime
{
    meta:
        desc = "Metasploit::API::wininet::InternetTimeToSystemTime"

    /*
        68C92CDBAA           | push 0xaadb2cc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 2c db aa ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetTimeToSystemTimeA
{
    meta:
        desc = "Metasploit::API::wininet::InternetTimeToSystemTimeA"

    /*
        685CBCBF36           | push 0x36bfbc5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c bc bf 36 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetTimeToSystemTimeW
{
    meta:
        desc = "Metasploit::API::wininet::InternetTimeToSystemTimeW"

    /*
        685CBC6F37           | push 0x376fbc5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c bc 6f 37 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetUnlockRequestFile
{
    meta:
        desc = "Metasploit::API::wininet::InternetUnlockRequestFile"

    /*
        68EFA57818           | push 0x1878a5ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef a5 78 18 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetWriteFile
{
    meta:
        desc = "Metasploit::API::wininet::InternetWriteFile"

    /*
        689F746709           | push 0x0967749f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 74 67 09 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetWriteFileExA
{
    meta:
        desc = "Metasploit::API::wininet::InternetWriteFileExA"

    /*
        68B3263D61           | push 0x613d26b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 26 3d 61 ff d5 }

    condition:
        any of them
}

    
rule wininet_InternetWriteFileExW
{
    meta:
        desc = "Metasploit::API::wininet::InternetWriteFileExW"

    /*
        68B326ED61           | push 0x61ed26b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 26 ed 61 ff d5 }

    condition:
        any of them
}

    
rule wininet_IsHostInProxyBypassList
{
    meta:
        desc = "Metasploit::API::wininet::IsHostInProxyBypassList"

    /*
        68C801CA1C           | push 0x1cca01c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 01 ca 1c ff d5 }

    condition:
        any of them
}

    
rule wininet_IsUrlCacheEntryExpiredA
{
    meta:
        desc = "Metasploit::API::wininet::IsUrlCacheEntryExpiredA"

    /*
        68129FD9F6           | push 0xf6d99f12
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 9f d9 f6 ff d5 }

    condition:
        any of them
}

    
rule wininet_IsUrlCacheEntryExpiredW
{
    meta:
        desc = "Metasploit::API::wininet::IsUrlCacheEntryExpiredW"

    /*
        68129F89F7           | push 0xf7899f12
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 9f 89 f7 ff d5 }

    condition:
        any of them
}

    
rule wininet_LoadUrlCacheContent
{
    meta:
        desc = "Metasploit::API::wininet::LoadUrlCacheContent"

    /*
        686BA27D6D           | push 0x6d7da26b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b a2 7d 6d ff d5 }

    condition:
        any of them
}

    
rule wininet_ParseX509EncodedCertificateForListBoxEntry
{
    meta:
        desc = "Metasploit::API::wininet::ParseX509EncodedCertificateForListBoxEntry"

    /*
        68C7073E67           | push 0x673e07c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 07 3e 67 ff d5 }

    condition:
        any of them
}

    
rule wininet_PrivacyGetZonePreferenceW
{
    meta:
        desc = "Metasploit::API::wininet::PrivacyGetZonePreferenceW"

    /*
        688C70E0FD           | push 0xfde0708c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c 70 e0 fd ff d5 }

    condition:
        any of them
}

    
rule wininet_PrivacySetZonePreferenceW
{
    meta:
        desc = "Metasploit::API::wininet::PrivacySetZonePreferenceW"

    /*
        688C70E000           | push 0x00e0708c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c 70 e0 00 ff d5 }

    condition:
        any of them
}

    
rule wininet_ReadUrlCacheEntryStream
{
    meta:
        desc = "Metasploit::API::wininet::ReadUrlCacheEntryStream"

    /*
        680540AD02           | push 0x02ad4005
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 40 ad 02 ff d5 }

    condition:
        any of them
}

    
rule wininet_ReadUrlCacheEntryStreamEx
{
    meta:
        desc = "Metasploit::API::wininet::ReadUrlCacheEntryStreamEx"

    /*
        6897EB98A9           | push 0xa998eb97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 eb 98 a9 ff d5 }

    condition:
        any of them
}

    
rule wininet_RegisterUrlCacheNotification
{
    meta:
        desc = "Metasploit::API::wininet::RegisterUrlCacheNotification"

    /*
        689208EA9D           | push 0x9dea0892
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 08 ea 9d ff d5 }

    condition:
        any of them
}

    
rule wininet_ResumeSuspendedDownload
{
    meta:
        desc = "Metasploit::API::wininet::ResumeSuspendedDownload"

    /*
        688BC2ADF4           | push 0xf4adc28b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b c2 ad f4 ff d5 }

    condition:
        any of them
}

    
rule wininet_RetrieveUrlCacheEntryFileA
{
    meta:
        desc = "Metasploit::API::wininet::RetrieveUrlCacheEntryFileA"

    /*
        68748CA454           | push 0x54a48c74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 8c a4 54 ff d5 }

    condition:
        any of them
}

    
rule wininet_RetrieveUrlCacheEntryFileW
{
    meta:
        desc = "Metasploit::API::wininet::RetrieveUrlCacheEntryFileW"

    /*
        68748C5455           | push 0x55548c74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 8c 54 55 ff d5 }

    condition:
        any of them
}

    
rule wininet_RetrieveUrlCacheEntryStreamA
{
    meta:
        desc = "Metasploit::API::wininet::RetrieveUrlCacheEntryStreamA"

    /*
        680E13E065           | push 0x65e0130e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 13 e0 65 ff d5 }

    condition:
        any of them
}

    
rule wininet_RetrieveUrlCacheEntryStreamW
{
    meta:
        desc = "Metasploit::API::wininet::RetrieveUrlCacheEntryStreamW"

    /*
        680E139066           | push 0x6690130e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 13 90 66 ff d5 }

    condition:
        any of them
}

    
rule wininet_RunOnceUrlCache
{
    meta:
        desc = "Metasploit::API::wininet::RunOnceUrlCache"

    /*
        686DD0ED5D           | push 0x5dedd06d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d d0 ed 5d ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheConfigInfoA
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheConfigInfoA"

    /*
        6829D15AAD           | push 0xad5ad129
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 d1 5a ad ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheConfigInfoW
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheConfigInfoW"

    /*
        6829D10AAE           | push 0xae0ad129
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 d1 0a ae ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheEntryGroup
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheEntryGroup"

    /*
        68CD48BF95           | push 0x95bf48cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 48 bf 95 ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheEntryGroupA
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheEntryGroupA"

    /*
        687D13DF16           | push 0x16df137d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 13 df 16 ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheEntryGroupW
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheEntryGroupW"

    /*
        687D138F17           | push 0x178f137d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 13 8f 17 ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheEntryInfoA
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheEntryInfoA"

    /*
        684D074782           | push 0x8247074d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 07 47 82 ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheEntryInfoW
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheEntryInfoW"

    /*
        684D07F782           | push 0x82f7074d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 07 f7 82 ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheGroupAttributeA
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheGroupAttributeA"

    /*
        68237958BA           | push 0xba587923
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 79 58 ba ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheGroupAttributeW
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheGroupAttributeW"

    /*
        68237908BB           | push 0xbb087923
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 79 08 bb ff d5 }

    condition:
        any of them
}

    
rule wininet_SetUrlCacheHeaderData
{
    meta:
        desc = "Metasploit::API::wininet::SetUrlCacheHeaderData"

    /*
        68E31EF4A5           | push 0xa5f41ee3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 1e f4 a5 ff d5 }

    condition:
        any of them
}

    
rule wininet_ShowCertificate
{
    meta:
        desc = "Metasploit::API::wininet::ShowCertificate"

    /*
        68E1280019           | push 0x190028e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 28 00 19 ff d5 }

    condition:
        any of them
}

    
rule wininet_ShowClientAuthCerts
{
    meta:
        desc = "Metasploit::API::wininet::ShowClientAuthCerts"

    /*
        68887A4414           | push 0x14447a88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 7a 44 14 ff d5 }

    condition:
        any of them
}

    
rule wininet_ShowSecurityInfo
{
    meta:
        desc = "Metasploit::API::wininet::ShowSecurityInfo"

    /*
        682BB71D56           | push 0x561db72b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b b7 1d 56 ff d5 }

    condition:
        any of them
}

    
rule wininet_ShowX509EncodedCertificate
{
    meta:
        desc = "Metasploit::API::wininet::ShowX509EncodedCertificate"

    /*
        688B3DB3F4           | push 0xf4b33d8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 3d b3 f4 ff d5 }

    condition:
        any of them
}

    
rule wininet_UnlockUrlCacheEntryFile
{
    meta:
        desc = "Metasploit::API::wininet::UnlockUrlCacheEntryFile"

    /*
        6873257F52           | push 0x527f2573
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 25 7f 52 ff d5 }

    condition:
        any of them
}

    
rule wininet_UnlockUrlCacheEntryFileA
{
    meta:
        desc = "Metasploit::API::wininet::UnlockUrlCacheEntryFileA"

    /*
        687CF914FC           | push 0xfc14f97c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c f9 14 fc ff d5 }

    condition:
        any of them
}

    
rule wininet_UnlockUrlCacheEntryFileW
{
    meta:
        desc = "Metasploit::API::wininet::UnlockUrlCacheEntryFileW"

    /*
        687CF9C4FC           | push 0xfcc4f97c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c f9 c4 fc ff d5 }

    condition:
        any of them
}

    
rule wininet_UnlockUrlCacheEntryStream
{
    meta:
        desc = "Metasploit::API::wininet::UnlockUrlCacheEntryStream"

    /*
        6830AEEE1D           | push 0x1deeae30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 ae ee 1d ff d5 }

    condition:
        any of them
}

    
rule wininet_UpdateUrlCacheContentPath
{
    meta:
        desc = "Metasploit::API::wininet::UpdateUrlCacheContentPath"

    /*
        6838E234F7           | push 0xf734e238
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 e2 34 f7 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheCheckEntriesExist
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheCheckEntriesExist"

    /*
        6822265D1C           | push 0x1c5d2622
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 26 5d 1c ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheCloseEntryHandle
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheCloseEntryHandle"

    /*
        68A1A332B7           | push 0xb732a3a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 a3 32 b7 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheContainerSetEntryMaximumAge
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheContainerSetEntryMaximumAge"

    /*
        6870E36C41           | push 0x416ce370
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 e3 6c 41 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheCreateContainer
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheCreateContainer"

    /*
        6867FBFC7D           | push 0x7dfcfb67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 fb fc 7d ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheFindFirstEntry
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheFindFirstEntry"

    /*
        686D93FB93           | push 0x93fb936d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 93 fb 93 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheFindNextEntry
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheFindNextEntry"

    /*
        686108FCAD           | push 0xadfc0861
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 08 fc ad ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheFreeEntryInfo
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheFreeEntryInfo"

    /*
        688B6D8FEA           | push 0xea8f6d8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 6d 8f ea ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheFreeGlobalSpace
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheFreeGlobalSpace"

    /*
        6882C91C76           | push 0x761cc982
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 c9 1c 76 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheGetContentPaths
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheGetContentPaths"

    /*
        6842CE7BC7           | push 0xc77bce42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 ce 7b c7 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheGetEntryInfo
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheGetEntryInfo"

    /*
        68EC012354           | push 0x542301ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 01 23 54 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheGetGlobalCacheSize
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheGetGlobalCacheSize"

    /*
        6805BB1D81           | push 0x811dbb05
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 bb 1d 81 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheGetGlobalLimit
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheGetGlobalLimit"

    /*
        6859737973           | push 0x73797359
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 73 79 73 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheReadEntryStream
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheReadEntryStream"

    /*
        6805E0F40B           | push 0x0bf4e005
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 e0 f4 0b ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheReloadSettings
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheReloadSettings"

    /*
        68EB46E1A6           | push 0xa6e146eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 46 e1 a6 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheRetrieveEntryFile
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheRetrieveEntryFile"

    /*
        68D2DCE93F           | push 0x3fe9dcd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 dc e9 3f ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheRetrieveEntryStream
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheRetrieveEntryStream"

    /*
        68EB859C78           | push 0x789c85eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 85 9c 78 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheServer
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheServer"

    /*
        68E44F9CD8           | push 0xd89c4fe4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 4f 9c d8 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheSetGlobalLimit
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheSetGlobalLimit"

    /*
        6859A37973           | push 0x7379a359
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 a3 79 73 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlCacheUpdateEntryExtraData
{
    meta:
        desc = "Metasploit::API::wininet::UrlCacheUpdateEntryExtraData"

    /*
        68A80C5DF0           | push 0xf05d0ca8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 0c 5d f0 ff d5 }

    condition:
        any of them
}

    
rule wininet_UrlZonesDetach
{
    meta:
        desc = "Metasploit::API::wininet::UrlZonesDetach"

    /*
        6827C93E2B           | push 0x2b3ec927
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 c9 3e 2b ff d5 }

    condition:
        any of them
}

    
rule wininet__GetFileExtensionFromUrl
{
    meta:
        desc = "Metasploit::API::wininet::_GetFileExtensionFromUrl"

    /*
        683A11291B           | push 0x1b29113a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 11 29 1b ff d5 }

    condition:
        any of them
}

    