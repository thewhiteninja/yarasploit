
rule kernel32_AcquireSRWLockExclusive
{
    meta:
        desc = "Metasploit::API::kernel32::AcquireSRWLockExclusive"

    /*
        68C65284FD           | push 0xfd8452c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 52 84 fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_AcquireSRWLockShared
{
    meta:
        desc = "Metasploit::API::kernel32::AcquireSRWLockShared"

    /*
        689C28FE74           | push 0x74fe289c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 28 fe 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ActivateActCtx
{
    meta:
        desc = "Metasploit::API::kernel32::ActivateActCtx"

    /*
        680A94D0C3           | push 0xc3d0940a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 94 d0 c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ActivateActCtxWorker
{
    meta:
        desc = "Metasploit::API::kernel32::ActivateActCtxWorker"

    /*
        68D81463E2           | push 0xe26314d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 14 63 e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddAtomA
{
    meta:
        desc = "Metasploit::API::kernel32::AddAtomA"

    /*
        68BB7E4E35           | push 0x354e7ebb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 7e 4e 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddAtomW
{
    meta:
        desc = "Metasploit::API::kernel32::AddAtomW"

    /*
        68BB7EFE35           | push 0x35fe7ebb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 7e fe 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddConsoleAliasA
{
    meta:
        desc = "Metasploit::API::kernel32::AddConsoleAliasA"

    /*
        688ADF6326           | push 0x2663df8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a df 63 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddConsoleAliasW
{
    meta:
        desc = "Metasploit::API::kernel32::AddConsoleAliasW"

    /*
        688ADF1327           | push 0x2713df8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a df 13 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddDllDirectory
{
    meta:
        desc = "Metasploit::API::kernel32::AddDllDirectory"

    /*
        683036EEB1           | push 0xb1ee3630
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 36 ee b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddIntegrityLabelToBoundaryDescriptor
{
    meta:
        desc = "Metasploit::API::kernel32::AddIntegrityLabelToBoundaryDescriptor"

    /*
        6841AF2210           | push 0x1022af41
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 af 22 10 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddLocalAlternateComputerNameA
{
    meta:
        desc = "Metasploit::API::kernel32::AddLocalAlternateComputerNameA"

    /*
        6814B2D813           | push 0x13d8b214
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 b2 d8 13 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddLocalAlternateComputerNameW
{
    meta:
        desc = "Metasploit::API::kernel32::AddLocalAlternateComputerNameW"

    /*
        6814B28814           | push 0x1488b214
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 b2 88 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddRefActCtx
{
    meta:
        desc = "Metasploit::API::kernel32::AddRefActCtx"

    /*
        68F5144503           | push 0x034514f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 14 45 03 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddRefActCtxWorker
{
    meta:
        desc = "Metasploit::API::kernel32::AddRefActCtxWorker"

    /*
        68AA1210E6           | push 0xe61012aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 12 10 e6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddResourceAttributeAce
{
    meta:
        desc = "Metasploit::API::kernel32::AddResourceAttributeAce"

    /*
        685D7BA63B           | push 0x3ba67b5d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 7b a6 3b ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddSIDToBoundaryDescriptor
{
    meta:
        desc = "Metasploit::API::kernel32::AddSIDToBoundaryDescriptor"

    /*
        6813850DE0           | push 0xe00d8513
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 85 0d e0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddScopedPolicyIDAce
{
    meta:
        desc = "Metasploit::API::kernel32::AddScopedPolicyIDAce"

    /*
        68256D48FF           | push 0xff486d25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 6d 48 ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddSecureMemoryCacheCallback
{
    meta:
        desc = "Metasploit::API::kernel32::AddSecureMemoryCacheCallback"

    /*
        6836737A11           | push 0x117a7336
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 73 7a 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddVectoredContinueHandler
{
    meta:
        desc = "Metasploit::API::kernel32::AddVectoredContinueHandler"

    /*
        687CEB8774           | push 0x7487eb7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c eb 87 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AddVectoredExceptionHandler
{
    meta:
        desc = "Metasploit::API::kernel32::AddVectoredExceptionHandler"

    /*
        68B3C3AF87           | push 0x87afc3b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 c3 af 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AdjustCalendarDate
{
    meta:
        desc = "Metasploit::API::kernel32::AdjustCalendarDate"

    /*
        680E7CD0B2           | push 0xb2d07c0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 7c d0 b2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AllocConsole
{
    meta:
        desc = "Metasploit::API::kernel32::AllocConsole"

    /*
        689DE675D9           | push 0xd975e69d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d e6 75 d9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AllocateUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::kernel32::AllocateUserPhysicalPages"

    /*
        68783B5A91           | push 0x915a3b78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 3b 5a 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AllocateUserPhysicalPagesNuma
{
    meta:
        desc = "Metasploit::API::kernel32::AllocateUserPhysicalPagesNuma"

    /*
        6805020632           | push 0x32060205
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 02 06 32 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetClrCompat
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetClrCompat"

    /*
        68AC193DD5           | push 0xd53d19ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac 19 3d d5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetCreateFileAccess
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetCreateFileAccess"

    /*
        68FAD6017A           | push 0x7a01d6fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa d6 01 7a ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetLifecycleManagement
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetLifecycleManagement"

    /*
        68C4D95C99           | push 0x995cd9c4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 d9 5c 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetMediaFoundationCodecLoading
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetMediaFoundationCodecLoading"

    /*
        6863E4CE40           | push 0x40cee463
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 e4 ce 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetProcessTerminationMethod
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetProcessTerminationMethod"

    /*
        687E5C2475           | push 0x75245c7e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 5c 24 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetShowDeveloperDiagnostic
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetShowDeveloperDiagnostic"

    /*
        68C0EB7C11           | push 0x117cebc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 eb 7c 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetThreadInitializationType
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetThreadInitializationType"

    /*
        68E0F2068D           | push 0x8d06f2e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 f2 06 8d ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppPolicyGetWindowingModel
{
    meta:
        desc = "Metasploit::API::kernel32::AppPolicyGetWindowingModel"

    /*
        680AC3EBF6           | push 0xf6ebc30a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a c3 eb f6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AppXGetOSMaxVersionTested
{
    meta:
        desc = "Metasploit::API::kernel32::AppXGetOSMaxVersionTested"

    /*
        68877841F4           | push 0xf4417887
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 78 41 f4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ApplicationRecoveryFinished
{
    meta:
        desc = "Metasploit::API::kernel32::ApplicationRecoveryFinished"

    /*
        68818C5D6F           | push 0x6f5d8c81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 8c 5d 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_ApplicationRecoveryInProgress
{
    meta:
        desc = "Metasploit::API::kernel32::ApplicationRecoveryInProgress"

    /*
        68B196D5E5           | push 0xe5d596b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 96 d5 e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AreFileApisANSI
{
    meta:
        desc = "Metasploit::API::kernel32::AreFileApisANSI"

    /*
        68573EF646           | push 0x46f63e57
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 3e f6 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_AssignProcessToJobObject
{
    meta:
        desc = "Metasploit::API::kernel32::AssignProcessToJobObject"

    /*
        68C769C2BD           | push 0xbdc269c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 69 c2 bd ff d5 }

    condition:
        any of them
}

    
rule kernel32_AttachConsole
{
    meta:
        desc = "Metasploit::API::kernel32::AttachConsole"

    /*
        68CA89053F           | push 0x3f0589ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 89 05 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_BackupRead
{
    meta:
        desc = "Metasploit::API::kernel32::BackupRead"

    /*
        68C364AB44           | push 0x44ab64c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 64 ab 44 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BackupSeek
{
    meta:
        desc = "Metasploit::API::kernel32::BackupSeek"

    /*
        68C375E344           | push 0x44e375c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 75 e3 44 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BackupWrite
{
    meta:
        desc = "Metasploit::API::kernel32::BackupWrite"

    /*
        68BF7A2595           | push 0x95257abf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 7a 25 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseCheckAppcompatCache
{
    meta:
        desc = "Metasploit::API::kernel32::BaseCheckAppcompatCache"

    /*
        68F8CA5419           | push 0x1954caf8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 ca 54 19 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseCheckAppcompatCacheEx
{
    meta:
        desc = "Metasploit::API::kernel32::BaseCheckAppcompatCacheEx"

    /*
        68BB2FDC3F           | push 0x3fdc2fbb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 2f dc 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseCheckAppcompatCacheExWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseCheckAppcompatCacheExWorker"

    /*
        6806052951           | push 0x51290506
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 05 29 51 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseCheckAppcompatCacheWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseCheckAppcompatCacheWorker"

    /*
        68E96A1CBE           | push 0xbe1c6ae9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 6a 1c be ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseCheckElevation
{
    meta:
        desc = "Metasploit::API::kernel32::BaseCheckElevation"

    /*
        68EBBCBAFB           | push 0xfbbabceb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb bc ba fb ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseCleanupAppcompatCacheSupport
{
    meta:
        desc = "Metasploit::API::kernel32::BaseCleanupAppcompatCacheSupport"

    /*
        68286D35D6           | push 0xd6356d28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 6d 35 d6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseCleanupAppcompatCacheSupportWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseCleanupAppcompatCacheSupportWorker"

    /*
        686B5EDB46           | push 0x46db5e6b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 5e db 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseDestroyVDMEnvironment
{
    meta:
        desc = "Metasploit::API::kernel32::BaseDestroyVDMEnvironment"

    /*
        68F9699319           | push 0x199369f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 69 93 19 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseDllReadWriteIniFile
{
    meta:
        desc = "Metasploit::API::kernel32::BaseDllReadWriteIniFile"

    /*
        68B1D148D5           | push 0xd548d1b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 d1 48 d5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseDumpAppcompatCache
{
    meta:
        desc = "Metasploit::API::kernel32::BaseDumpAppcompatCache"

    /*
        68FD0E1688           | push 0x88160efd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 0e 16 88 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseDumpAppcompatCacheWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseDumpAppcompatCacheWorker"

    /*
        68EE2532CE           | push 0xce3225ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 25 32 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseElevationPostProcessing
{
    meta:
        desc = "Metasploit::API::kernel32::BaseElevationPostProcessing"

    /*
        68CD324A6F           | push 0x6f4a32cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 32 4a 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseFlushAppcompatCache
{
    meta:
        desc = "Metasploit::API::kernel32::BaseFlushAppcompatCache"

    /*
        6878D164BA           | push 0xba64d178
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 d1 64 ba ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseFlushAppcompatCacheWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseFlushAppcompatCacheWorker"

    /*
        6829EF1AD8           | push 0xd81aef29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 ef 1a d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseFormatObjectAttributes
{
    meta:
        desc = "Metasploit::API::kernel32::BaseFormatObjectAttributes"

    /*
        689B2ED8F4           | push 0xf4d82e9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 2e d8 f4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseFormatTimeOut
{
    meta:
        desc = "Metasploit::API::kernel32::BaseFormatTimeOut"

    /*
        68FB3343EE           | push 0xee4333fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 33 43 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseFreeAppCompatDataForProcessWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseFreeAppCompatDataForProcessWorker"

    /*
        68C2345A90           | push 0x905a34c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 34 5a 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseGenerateAppCompatData
{
    meta:
        desc = "Metasploit::API::kernel32::BaseGenerateAppCompatData"

    /*
        686157CAAF           | push 0xafca5761
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 57 ca af ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseGetNamedObjectDirectory
{
    meta:
        desc = "Metasploit::API::kernel32::BaseGetNamedObjectDirectory"

    /*
        688C9CB311           | push 0x11b39c8c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c 9c b3 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseInitAppcompatCacheSupport
{
    meta:
        desc = "Metasploit::API::kernel32::BaseInitAppcompatCacheSupport"

    /*
        68813B894A           | push 0x4a893b81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 3b 89 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseInitAppcompatCacheSupportWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseInitAppcompatCacheSupportWorker"

    /*
        68BA2F4180           | push 0x80412fba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 2f 41 80 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseIsAppcompatInfrastructureDisabled
{
    meta:
        desc = "Metasploit::API::kernel32::BaseIsAppcompatInfrastructureDisabled"

    /*
        68516D1EDC           | push 0xdc1e6d51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 6d 1e dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseIsAppcompatInfrastructureDisabledWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseIsAppcompatInfrastructureDisabledWorker"

    /*
        680F767F47           | push 0x477f760f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 76 7f 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseIsDosApplication
{
    meta:
        desc = "Metasploit::API::kernel32::BaseIsDosApplication"

    /*
        6872DCC22A           | push 0x2ac2dc72
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 dc c2 2a ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseQueryModuleData
{
    meta:
        desc = "Metasploit::API::kernel32::BaseQueryModuleData"

    /*
        68835D88E9           | push 0xe9885d83
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 5d 88 e9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseReadAppCompatDataForProcessWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseReadAppCompatDataForProcessWorker"

    /*
        68B5B4B98C           | push 0x8cb9b4b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 b4 b9 8c ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseSetLastNTError
{
    meta:
        desc = "Metasploit::API::kernel32::BaseSetLastNTError"

    /*
        68EB4AA693           | push 0x93a64aeb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 4a a6 93 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseThreadInitThunk
{
    meta:
        desc = "Metasploit::API::kernel32::BaseThreadInitThunk"

    /*
        68B13549C2           | push 0xc24935b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 35 49 c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseUpdateAppcompatCache
{
    meta:
        desc = "Metasploit::API::kernel32::BaseUpdateAppcompatCache"

    /*
        681E673F5C           | push 0x5c3f671e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 67 3f 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseUpdateAppcompatCacheWorker
{
    meta:
        desc = "Metasploit::API::kernel32::BaseUpdateAppcompatCacheWorker"

    /*
        689376B52E           | push 0x2eb57693
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 76 b5 2e ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseUpdateVDMEntry
{
    meta:
        desc = "Metasploit::API::kernel32::BaseUpdateVDMEntry"

    /*
        686FA16B3F           | push 0x3f6ba16f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f a1 6b 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseVerifyUnicodeString
{
    meta:
        desc = "Metasploit::API::kernel32::BaseVerifyUnicodeString"

    /*
        6855F3B4EA           | push 0xeab4f355
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 f3 b4 ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_BaseWriteErrorElevationRequiredEvent
{
    meta:
        desc = "Metasploit::API::kernel32::BaseWriteErrorElevationRequiredEvent"

    /*
        68FA3C9514           | push 0x14953cfa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 3c 95 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Basep8BitStringToDynamicUnicodeString
{
    meta:
        desc = "Metasploit::API::kernel32::Basep8BitStringToDynamicUnicodeString"

    /*
        681E73721C           | push 0x1c72731e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 73 72 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepAllocateActivationContextActivationBlock
{
    meta:
        desc = "Metasploit::API::kernel32::BasepAllocateActivationContextActivationBlock"

    /*
        688982B58A           | push 0x8ab58289
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 82 b5 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepAnsiStringToDynamicUnicodeString
{
    meta:
        desc = "Metasploit::API::kernel32::BasepAnsiStringToDynamicUnicodeString"

    /*
        68A7ED7744           | push 0x4477eda7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 ed 77 44 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepAppContainerEnvironmentExtension
{
    meta:
        desc = "Metasploit::API::kernel32::BasepAppContainerEnvironmentExtension"

    /*
        68B1EDA72D           | push 0x2da7edb1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 ed a7 2d ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepAppXExtension
{
    meta:
        desc = "Metasploit::API::kernel32::BasepAppXExtension"

    /*
        687D6311B4           | push 0xb411637d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 63 11 b4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepCheckAppCompat
{
    meta:
        desc = "Metasploit::API::kernel32::BasepCheckAppCompat"

    /*
        6863AFD074           | push 0x74d0af63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 af d0 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepCheckWebBladeHashes
{
    meta:
        desc = "Metasploit::API::kernel32::BasepCheckWebBladeHashes"

    /*
        682F242D05           | push 0x052d242f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 24 2d 05 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepCheckWinSaferRestrictions
{
    meta:
        desc = "Metasploit::API::kernel32::BasepCheckWinSaferRestrictions"

    /*
        6875F8AC61           | push 0x61acf875
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 f8 ac 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepConstructSxsCreateProcessMessage
{
    meta:
        desc = "Metasploit::API::kernel32::BasepConstructSxsCreateProcessMessage"

    /*
        6884AA7D7B           | push 0x7b7daa84
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 aa 7d 7b ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepCopyEncryption
{
    meta:
        desc = "Metasploit::API::kernel32::BasepCopyEncryption"

    /*
        68CA8B265E           | push 0x5e268bca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 8b 26 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepFreeActivationContextActivationBlock
{
    meta:
        desc = "Metasploit::API::kernel32::BasepFreeActivationContextActivationBlock"

    /*
        688139B0EA           | push 0xeab03981
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 39 b0 ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepFreeAppCompatData
{
    meta:
        desc = "Metasploit::API::kernel32::BasepFreeAppCompatData"

    /*
        6872E24794           | push 0x9447e272
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 e2 47 94 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepGetAppCompatData
{
    meta:
        desc = "Metasploit::API::kernel32::BasepGetAppCompatData"

    /*
        68B8BA4D71           | push 0x714dbab8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 ba 4d 71 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepGetComputerNameFromNtPath
{
    meta:
        desc = "Metasploit::API::kernel32::BasepGetComputerNameFromNtPath"

    /*
        68A50B25FD           | push 0xfd250ba5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 0b 25 fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepGetExeArchType
{
    meta:
        desc = "Metasploit::API::kernel32::BasepGetExeArchType"

    /*
        6853541C16           | push 0x161c5453
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 54 1c 16 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepInitAppCompatData
{
    meta:
        desc = "Metasploit::API::kernel32::BasepInitAppCompatData"

    /*
        688A1E4414           | push 0x14441e8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 1e 44 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepIsProcessAllowed
{
    meta:
        desc = "Metasploit::API::kernel32::BasepIsProcessAllowed"

    /*
        680FF1FBFB           | push 0xfbfbf10f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f f1 fb fb ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepMapModuleHandle
{
    meta:
        desc = "Metasploit::API::kernel32::BasepMapModuleHandle"

    /*
        68CA141261           | push 0x611214ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 14 12 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepNotifyLoadStringResource
{
    meta:
        desc = "Metasploit::API::kernel32::BasepNotifyLoadStringResource"

    /*
        68F23E2190           | push 0x90213ef2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 3e 21 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepPostSuccessAppXExtension
{
    meta:
        desc = "Metasploit::API::kernel32::BasepPostSuccessAppXExtension"

    /*
        68490D8840           | push 0x40880d49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 0d 88 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepProcessInvalidImage
{
    meta:
        desc = "Metasploit::API::kernel32::BasepProcessInvalidImage"

    /*
        68E54D05C9           | push 0xc9054de5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 4d 05 c9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepQueryAppCompat
{
    meta:
        desc = "Metasploit::API::kernel32::BasepQueryAppCompat"

    /*
        6867E76EFB           | push 0xfb6ee767
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 e7 6e fb ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepQueryModuleChpeSettings
{
    meta:
        desc = "Metasploit::API::kernel32::BasepQueryModuleChpeSettings"

    /*
        68E851A704           | push 0x04a751e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 51 a7 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepReleaseAppXContext
{
    meta:
        desc = "Metasploit::API::kernel32::BasepReleaseAppXContext"

    /*
        689DEC7F01           | push 0x017fec9d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d ec 7f 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepReleaseSxsCreateProcessUtilityStruct
{
    meta:
        desc = "Metasploit::API::kernel32::BasepReleaseSxsCreateProcessUtilityStruct"

    /*
        68B1ECD404           | push 0x04d4ecb1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 ec d4 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepReportFault
{
    meta:
        desc = "Metasploit::API::kernel32::BasepReportFault"

    /*
        6863A39084           | push 0x8490a363
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 a3 90 84 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BasepSetFileEncryptionCompression
{
    meta:
        desc = "Metasploit::API::kernel32::BasepSetFileEncryptionCompression"

    /*
        68B1D1C4A7           | push 0xa7c4d1b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 d1 c4 a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Beep
{
    meta:
        desc = "Metasploit::API::kernel32::Beep"

    /*
        681A503360           | push 0x6033501a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 50 33 60 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BeginUpdateResourceA
{
    meta:
        desc = "Metasploit::API::kernel32::BeginUpdateResourceA"

    /*
        683582958E           | push 0x8e958235
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 82 95 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_BeginUpdateResourceW
{
    meta:
        desc = "Metasploit::API::kernel32::BeginUpdateResourceW"

    /*
        683582458F           | push 0x8f458235
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 82 45 8f ff d5 }

    condition:
        any of them
}

    
rule kernel32_BindIoCompletionCallback
{
    meta:
        desc = "Metasploit::API::kernel32::BindIoCompletionCallback"

    /*
        688FA8943E           | push 0x3e94a88f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f a8 94 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_BuildCommDCBA
{
    meta:
        desc = "Metasploit::API::kernel32::BuildCommDCBA"

    /*
        68DC9C4401           | push 0x01449cdc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 9c 44 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BuildCommDCBAndTimeoutsA
{
    meta:
        desc = "Metasploit::API::kernel32::BuildCommDCBAndTimeoutsA"

    /*
        68B60E3674           | push 0x74360eb6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 0e 36 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BuildCommDCBAndTimeoutsW
{
    meta:
        desc = "Metasploit::API::kernel32::BuildCommDCBAndTimeoutsW"

    /*
        68B60EE674           | push 0x74e60eb6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 0e e6 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32_BuildCommDCBW
{
    meta:
        desc = "Metasploit::API::kernel32::BuildCommDCBW"

    /*
        68DC9CF401           | push 0x01f49cdc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 9c f4 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CallNamedPipeA
{
    meta:
        desc = "Metasploit::API::kernel32::CallNamedPipeA"

    /*
        68B7E7A994           | push 0x94a9e7b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 e7 a9 94 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CallNamedPipeW
{
    meta:
        desc = "Metasploit::API::kernel32::CallNamedPipeW"

    /*
        68B7E75995           | push 0x9559e7b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 e7 59 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CallbackMayRunLong
{
    meta:
        desc = "Metasploit::API::kernel32::CallbackMayRunLong"

    /*
        682B9646F1           | push 0xf146962b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 96 46 f1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CancelDeviceWakeupRequest
{
    meta:
        desc = "Metasploit::API::kernel32::CancelDeviceWakeupRequest"

    /*
        688E3EE21D           | push 0x1de23e8e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 3e e2 1d ff d5 }

    condition:
        any of them
}

    
rule kernel32_CancelIo
{
    meta:
        desc = "Metasploit::API::kernel32::CancelIo"

    /*
        686C85E532           | push 0x32e5856c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 85 e5 32 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CancelIoEx
{
    meta:
        desc = "Metasploit::API::kernel32::CancelIoEx"

    /*
        68C2CC0AA4           | push 0xa40accc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 cc 0a a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CancelSynchronousIo
{
    meta:
        desc = "Metasploit::API::kernel32::CancelSynchronousIo"

    /*
        685808EB12           | push 0x12eb0858
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 08 eb 12 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CancelThreadpoolIo
{
    meta:
        desc = "Metasploit::API::kernel32::CancelThreadpoolIo"

    /*
        6843EAF078           | push 0x78f0ea43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 ea f0 78 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CancelTimerQueueTimer
{
    meta:
        desc = "Metasploit::API::kernel32::CancelTimerQueueTimer"

    /*
        68828091F7           | push 0xf7918082
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 80 91 f7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CancelWaitableTimer
{
    meta:
        desc = "Metasploit::API::kernel32::CancelWaitableTimer"

    /*
        686F15D4B8           | push 0xb8d4156f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 15 d4 b8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CeipIsOptedIn
{
    meta:
        desc = "Metasploit::API::kernel32::CeipIsOptedIn"

    /*
        68A1D139F5           | push 0xf539d1a1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 d1 39 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ChangeTimerQueueTimer
{
    meta:
        desc = "Metasploit::API::kernel32::ChangeTimerQueueTimer"

    /*
        6892664A6A           | push 0x6a4a6692
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 66 4a 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckAllowDecryptedRemoteDestinationPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::CheckAllowDecryptedRemoteDestinationPolicy"

    /*
        68D4EE4940           | push 0x4049eed4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 ee 49 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckElevation
{
    meta:
        desc = "Metasploit::API::kernel32::CheckElevation"

    /*
        68D6B9C74A           | push 0x4ac7b9d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 b9 c7 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckElevationEnabled
{
    meta:
        desc = "Metasploit::API::kernel32::CheckElevationEnabled"

    /*
        6882B8A1F2           | push 0xf2a1b882
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 b8 a1 f2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckForReadOnlyResource
{
    meta:
        desc = "Metasploit::API::kernel32::CheckForReadOnlyResource"

    /*
        68B531D0F9           | push 0xf9d031b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 31 d0 f9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckForReadOnlyResourceFilter
{
    meta:
        desc = "Metasploit::API::kernel32::CheckForReadOnlyResourceFilter"

    /*
        68D38CCB6A           | push 0x6acb8cd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 8c cb 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckNameLegalDOS8Dot3A
{
    meta:
        desc = "Metasploit::API::kernel32::CheckNameLegalDOS8Dot3A"

    /*
        6863CF63EC           | push 0xec63cf63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 cf 63 ec ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckNameLegalDOS8Dot3W
{
    meta:
        desc = "Metasploit::API::kernel32::CheckNameLegalDOS8Dot3W"

    /*
        6863CF13ED           | push 0xed13cf63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 cf 13 ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckRemoteDebuggerPresent
{
    meta:
        desc = "Metasploit::API::kernel32::CheckRemoteDebuggerPresent"

    /*
        685534B17E           | push 0x7eb13455
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 34 b1 7e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckTokenCapability
{
    meta:
        desc = "Metasploit::API::kernel32::CheckTokenCapability"

    /*
        68B79D121A           | push 0x1a129db7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 9d 12 1a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CheckTokenMembershipEx
{
    meta:
        desc = "Metasploit::API::kernel32::CheckTokenMembershipEx"

    /*
        683A397420           | push 0x2074393a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 39 74 20 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ClearCommBreak
{
    meta:
        desc = "Metasploit::API::kernel32::ClearCommBreak"

    /*
        6848878787           | push 0x87878748
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 87 87 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ClearCommError
{
    meta:
        desc = "Metasploit::API::kernel32::ClearCommError"

    /*
        68CA8ABF21           | push 0x21bf8aca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 8a bf 21 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseConsoleHandle
{
    meta:
        desc = "Metasploit::API::kernel32::CloseConsoleHandle"

    /*
        6827358E9E           | push 0x9e8e3527
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 35 8e 9e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseHandle
{
    meta:
        desc = "Metasploit::API::kernel32::CloseHandle"

    /*
        68C6968752           | push 0x528796c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 96 87 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ClosePackageInfo
{
    meta:
        desc = "Metasploit::API::kernel32::ClosePackageInfo"

    /*
        6823A72F59           | push 0x592fa723
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 a7 2f 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ClosePrivateNamespace
{
    meta:
        desc = "Metasploit::API::kernel32::ClosePrivateNamespace"

    /*
        68DBB890D3           | push 0xd390b8db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db b8 90 d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseProfileUserMapping
{
    meta:
        desc = "Metasploit::API::kernel32::CloseProfileUserMapping"

    /*
        68F45D28DF           | push 0xdf285df4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 5d 28 df ff d5 }

    condition:
        any of them
}

    
rule kernel32_ClosePseudoConsole
{
    meta:
        desc = "Metasploit::API::kernel32::ClosePseudoConsole"

    /*
        682E2998BE           | push 0xbe98292e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 29 98 be ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseState
{
    meta:
        desc = "Metasploit::API::kernel32::CloseState"

    /*
        6875E27508           | push 0x0875e275
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 e2 75 08 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseThreadpool
{
    meta:
        desc = "Metasploit::API::kernel32::CloseThreadpool"

    /*
        68BA36E97F           | push 0x7fe936ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 36 e9 7f ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseThreadpoolCleanupGroup
{
    meta:
        desc = "Metasploit::API::kernel32::CloseThreadpoolCleanupGroup"

    /*
        68366D7378           | push 0x78736d36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 6d 73 78 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseThreadpoolCleanupGroupMembers
{
    meta:
        desc = "Metasploit::API::kernel32::CloseThreadpoolCleanupGroupMembers"

    /*
        68CE286C9A           | push 0x9a6c28ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce 28 6c 9a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseThreadpoolIo
{
    meta:
        desc = "Metasploit::API::kernel32::CloseThreadpoolIo"

    /*
        685521AFE4           | push 0xe4af2155
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 21 af e4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseThreadpoolTimer
{
    meta:
        desc = "Metasploit::API::kernel32::CloseThreadpoolTimer"

    /*
        6835D0E2E6           | push 0xe6e2d035
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 d0 e2 e6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseThreadpoolWait
{
    meta:
        desc = "Metasploit::API::kernel32::CloseThreadpoolWait"

    /*
        68EEAF52FA           | push 0xfa52afee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee af 52 fa ff d5 }

    condition:
        any of them
}

    
rule kernel32_CloseThreadpoolWork
{
    meta:
        desc = "Metasploit::API::kernel32::CloseThreadpoolWork"

    /*
        682EB20A16           | push 0x160ab22e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e b2 0a 16 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CmdBatNotification
{
    meta:
        desc = "Metasploit::API::kernel32::CmdBatNotification"

    /*
        685954B9DB           | push 0xdbb95459
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 54 b9 db ff d5 }

    condition:
        any of them
}

    
rule kernel32_CommConfigDialogA
{
    meta:
        desc = "Metasploit::API::kernel32::CommConfigDialogA"

    /*
        687BFE319E           | push 0x9e31fe7b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b fe 31 9e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CommConfigDialogW
{
    meta:
        desc = "Metasploit::API::kernel32::CommConfigDialogW"

    /*
        687BFEE19E           | push 0x9ee1fe7b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b fe e1 9e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CompareCalendarDates
{
    meta:
        desc = "Metasploit::API::kernel32::CompareCalendarDates"

    /*
        68193814D2           | push 0xd2143819
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 38 14 d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CompareFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::CompareFileTime"

    /*
        68926AD346           | push 0x46d36a92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 6a d3 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CompareStringA
{
    meta:
        desc = "Metasploit::API::kernel32::CompareStringA"

    /*
        681C6EF24F           | push 0x4ff26e1c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 6e f2 4f ff d5 }

    condition:
        any of them
}

    
rule kernel32_CompareStringEx
{
    meta:
        desc = "Metasploit::API::kernel32::CompareStringEx"

    /*
        68F4018550           | push 0x508501f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 01 85 50 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CompareStringOrdinal
{
    meta:
        desc = "Metasploit::API::kernel32::CompareStringOrdinal"

    /*
        681AB6E8D0           | push 0xd0e8b61a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a b6 e8 d0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CompareStringW
{
    meta:
        desc = "Metasploit::API::kernel32::CompareStringW"

    /*
        681C6EA250           | push 0x50a26e1c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 6e a2 50 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConnectNamedPipe
{
    meta:
        desc = "Metasploit::API::kernel32::ConnectNamedPipe"

    /*
        68286F7DE2           | push 0xe27d6f28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 6f 7d e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConsoleMenuControl
{
    meta:
        desc = "Metasploit::API::kernel32::ConsoleMenuControl"

    /*
        6822B19FD8           | push 0xd89fb122
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 b1 9f d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ContinueDebugEvent
{
    meta:
        desc = "Metasploit::API::kernel32::ContinueDebugEvent"

    /*
        680578EF0C           | push 0x0cef7805
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 78 ef 0c ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConvertCalDateTimeToSystemTime
{
    meta:
        desc = "Metasploit::API::kernel32::ConvertCalDateTimeToSystemTime"

    /*
        6854B5B878           | push 0x78b8b554
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 b5 b8 78 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConvertDefaultLocale
{
    meta:
        desc = "Metasploit::API::kernel32::ConvertDefaultLocale"

    /*
        68BDD0C433           | push 0x33c4d0bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd d0 c4 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConvertFiberToThread
{
    meta:
        desc = "Metasploit::API::kernel32::ConvertFiberToThread"

    /*
        689BA5D5A4           | push 0xa4d5a59b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b a5 d5 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConvertNLSDayOfWeekToWin32DayOfWeek
{
    meta:
        desc = "Metasploit::API::kernel32::ConvertNLSDayOfWeekToWin32DayOfWeek"

    /*
        68D4188C66           | push 0x668c18d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 18 8c 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConvertSystemTimeToCalDateTime
{
    meta:
        desc = "Metasploit::API::kernel32::ConvertSystemTimeToCalDateTime"

    /*
        687FB47441           | push 0x4174b47f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f b4 74 41 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConvertThreadToFiber
{
    meta:
        desc = "Metasploit::API::kernel32::ConvertThreadToFiber"

    /*
        681A8BD0B6           | push 0xb6d08b1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 8b d0 b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ConvertThreadToFiberEx
{
    meta:
        desc = "Metasploit::API::kernel32::ConvertThreadToFiberEx"

    /*
        682338CC9E           | push 0x9ecc3823
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 38 cc 9e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyContext
{
    meta:
        desc = "Metasploit::API::kernel32::CopyContext"

    /*
        688EFD9B9B           | push 0x9b9bfd8e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e fd 9b 9b ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyFile2
{
    meta:
        desc = "Metasploit::API::kernel32::CopyFile2"

    /*
        683EE62BDD           | push 0xdd2be63e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e e6 2b dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyFileA
{
    meta:
        desc = "Metasploit::API::kernel32::CopyFileA"

    /*
        683EE6A3DD           | push 0xdda3e63e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e e6 a3 dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyFileExA
{
    meta:
        desc = "Metasploit::API::kernel32::CopyFileExA"

    /*
        68EC0DEB59           | push 0x59eb0dec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 0d eb 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyFileExW
{
    meta:
        desc = "Metasploit::API::kernel32::CopyFileExW"

    /*
        68EC0D9B5A           | push 0x5a9b0dec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 0d 9b 5a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyFileTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::CopyFileTransactedA"

    /*
        6862BA28E1           | push 0xe128ba62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 ba 28 e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyFileTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::CopyFileTransactedW"

    /*
        6862BAD8E1           | push 0xe1d8ba62
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 ba d8 e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyFileW
{
    meta:
        desc = "Metasploit::API::kernel32::CopyFileW"

    /*
        683EE653DE           | push 0xde53e63e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e e6 53 de ff d5 }

    condition:
        any of them
}

    
rule kernel32_CopyLZFile
{
    meta:
        desc = "Metasploit::API::kernel32::CopyLZFile"

    /*
        6839190F99           | push 0x990f1939
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 19 0f 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateActCtxA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateActCtxA"

    /*
        686D149545           | push 0x4595146d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 14 95 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateActCtxW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateActCtxW"

    /*
        686D144546           | push 0x4645146d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 14 45 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateActCtxWWorker
{
    meta:
        desc = "Metasploit::API::kernel32::CreateActCtxWWorker"

    /*
        68AA1EF1E3           | push 0xe3f11eaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa 1e f1 e3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateBoundaryDescriptorA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateBoundaryDescriptorA"

    /*
        68BDA0F861           | push 0x61f8a0bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd a0 f8 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateBoundaryDescriptorW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateBoundaryDescriptorW"

    /*
        68BDA0A862           | push 0x62a8a0bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd a0 a8 62 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateConsoleScreenBuffer
{
    meta:
        desc = "Metasploit::API::kernel32::CreateConsoleScreenBuffer"

    /*
        686C78A66C           | push 0x6ca6786c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 78 a6 6c ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateDirectoryA"

    /*
        685415DC5D           | push 0x5ddc1554
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 15 dc 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateDirectoryExA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateDirectoryExA"

    /*
        688CD3F667           | push 0x67f6d38c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c d3 f6 67 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateDirectoryExW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateDirectoryExW"

    /*
        688CD3A668           | push 0x68a6d38c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c d3 a6 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateDirectoryTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateDirectoryTransactedA"

    /*
        6827C63681           | push 0x8136c627
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 c6 36 81 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateDirectoryTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateDirectoryTransactedW"

    /*
        6827C6E681           | push 0x81e6c627
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 c6 e6 81 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateDirectoryW"

    /*
        6854158C5E           | push 0x5e8c1554
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 15 8c 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateEnclave
{
    meta:
        desc = "Metasploit::API::kernel32::CreateEnclave"

    /*
        6865A4E3A0           | push 0xa0e3a465
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 a4 e3 a0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateEventA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateEventA"

    /*
        68FF9CB826           | push 0x26b89cff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 9c b8 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateEventExA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateEventExA"

    /*
        683FBE189F           | push 0x9f18be3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f be 18 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateEventExW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateEventExW"

    /*
        683FBEC89F           | push 0x9fc8be3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f be c8 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateEventW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateEventW"

    /*
        68FF9C6827           | push 0x27689cff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 9c 68 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFiber
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFiber"

    /*
        68DAF6623D           | push 0x3d62f6da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da f6 62 3d ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFiberEx
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFiberEx"

    /*
        6844286743           | push 0x43672844
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 28 67 43 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFile2
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFile2"

    /*
        68DAF6624F           | push 0x4f62f6da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da f6 62 4f ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileA"

    /*
        68DAF6DA4F           | push 0x4fdaf6da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da f6 da 4f ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileMappingA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileMappingA"

    /*
        680ACDF923           | push 0x23f9cd0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a cd f9 23 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileMappingFromApp
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileMappingFromApp"

    /*
        68DC48C072           | push 0x72c048dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 48 c0 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileMappingNumaA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileMappingNumaA"

    /*
        683688219A           | push 0x9a218836
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 88 21 9a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileMappingNumaW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileMappingNumaW"

    /*
        683688D19A           | push 0x9ad18836
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 88 d1 9a ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileMappingW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileMappingW"

    /*
        680ACDA924           | push 0x24a9cd0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a cd a9 24 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileTransactedA"

    /*
        68897EB6FD           | push 0xfdb67e89
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 7e b6 fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileTransactedW"

    /*
        68897E66FE           | push 0xfe667e89
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 7e 66 fe ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateFileW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateFileW"

    /*
        68DAF68A50           | push 0x508af6da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da f6 8a 50 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateHardLinkA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateHardLinkA"

    /*
        6833DEB9A6           | push 0xa6b9de33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 de b9 a6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateHardLinkTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateHardLinkTransactedA"

    /*
        685F386E13           | push 0x136e385f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 38 6e 13 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateHardLinkTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateHardLinkTransactedW"

    /*
        685F381E14           | push 0x141e385f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 38 1e 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateHardLinkW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateHardLinkW"

    /*
        6833DE69A7           | push 0xa769de33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 de 69 a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateIoCompletionPort
{
    meta:
        desc = "Metasploit::API::kernel32::CreateIoCompletionPort"

    /*
        68E541F76F           | push 0x6ff741e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 41 f7 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateJobObjectA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateJobObjectA"

    /*
        6851A1D7AF           | push 0xafd7a151
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 a1 d7 af ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateJobObjectW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateJobObjectW"

    /*
        6851A187B0           | push 0xb087a151
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 a1 87 b0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateJobSet
{
    meta:
        desc = "Metasploit::API::kernel32::CreateJobSet"

    /*
        683B696472           | push 0x7264693b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 69 64 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateMailslotA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateMailslotA"

    /*
        686637DA28           | push 0x28da3766
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 37 da 28 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateMailslotW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateMailslotW"

    /*
        6866378A29           | push 0x298a3766
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 37 8a 29 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateMemoryResourceNotification
{
    meta:
        desc = "Metasploit::API::kernel32::CreateMemoryResourceNotification"

    /*
        68CEC6C9D1           | push 0xd1c9c6ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce c6 c9 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateMutexA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateMutexA"

    /*
        68FF8DD994           | push 0x94d98dff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 8d d9 94 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateMutexExA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateMutexExA"

    /*
        681AFE5427           | push 0x2754fe1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a fe 54 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateMutexExW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateMutexExW"

    /*
        681AFE0428           | push 0x2804fe1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a fe 04 28 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateMutexW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateMutexW"

    /*
        68FF8D8995           | push 0x95898dff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 8d 89 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateNamedPipeA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateNamedPipeA"

    /*
        684570DFD4           | push 0xd4df7045
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 70 df d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateNamedPipeW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateNamedPipeW"

    /*
        6845708FD5           | push 0xd58f7045
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 70 8f d5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreatePipe
{
    meta:
        desc = "Metasploit::API::kernel32::CreatePipe"

    /*
        683ECFAF0E           | push 0x0eafcf3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e cf af 0e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreatePrivateNamespaceA
{
    meta:
        desc = "Metasploit::API::kernel32::CreatePrivateNamespaceA"

    /*
        68A2A01DCD           | push 0xcd1da0a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 a0 1d cd ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreatePrivateNamespaceW
{
    meta:
        desc = "Metasploit::API::kernel32::CreatePrivateNamespaceW"

    /*
        68A2A0CDCD           | push 0xcdcda0a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 a0 cd cd ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateProcessA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateProcessA"

    /*
        6879CC3F86           | push 0x863fcc79
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 cc 3f 86 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateProcessAsUserA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateProcessAsUserA"

    /*
        68C8310AB7           | push 0xb70a31c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 31 0a b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateProcessAsUserW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateProcessAsUserW"

    /*
        68C831BAB7           | push 0xb7ba31c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 31 ba b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateProcessInternalA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateProcessInternalA"

    /*
        6849F14566           | push 0x6645f149
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 f1 45 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateProcessInternalW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateProcessInternalW"

    /*
        6849F1F566           | push 0x66f5f149
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 f1 f5 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateProcessW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateProcessW"

    /*
        6879CCEF86           | push 0x86efcc79
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 cc ef 86 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreatePseudoConsole
{
    meta:
        desc = "Metasploit::API::kernel32::CreatePseudoConsole"

    /*
        68F6AE4AEA           | push 0xea4aaef6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 ae 4a ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateRemoteThread
{
    meta:
        desc = "Metasploit::API::kernel32::CreateRemoteThread"

    /*
        68C6AC9A79           | push 0x799aacc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 ac 9a 79 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateRemoteThreadEx
{
    meta:
        desc = "Metasploit::API::kernel32::CreateRemoteThreadEx"

    /*
        6853A35451           | push 0x5154a353
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 a3 54 51 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSemaphoreA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSemaphoreA"

    /*
        68D2EF0F19           | push 0x190fefd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 ef 0f 19 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSemaphoreExA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSemaphoreExA"

    /*
        68FB72ED34           | push 0x34ed72fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 72 ed 34 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSemaphoreExW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSemaphoreExW"

    /*
        68FB729D35           | push 0x359d72fb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 72 9d 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSemaphoreW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSemaphoreW"

    /*
        68D2EFBF19           | push 0x19bfefd2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 ef bf 19 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSymbolicLinkA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSymbolicLinkA"

    /*
        68C06B8A25           | push 0x258a6bc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 6b 8a 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSymbolicLinkTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSymbolicLinkTransactedA"

    /*
        68C25B2273           | push 0x73225bc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 5b 22 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSymbolicLinkTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSymbolicLinkTransactedW"

    /*
        68C25BD273           | push 0x73d25bc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 5b d2 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateSymbolicLinkW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateSymbolicLinkW"

    /*
        68C06B3A26           | push 0x263a6bc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 6b 3a 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateTapePartition
{
    meta:
        desc = "Metasploit::API::kernel32::CreateTapePartition"

    /*
        686F24BC52           | push 0x52bc246f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 24 bc 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateThread
{
    meta:
        desc = "Metasploit::API::kernel32::CreateThread"

    /*
        6838680D16           | push 0x160d6838
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 68 0d 16 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateThreadpool
{
    meta:
        desc = "Metasploit::API::kernel32::CreateThreadpool"

    /*
        68D01A2C59           | push 0x592c1ad0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 1a 2c 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateThreadpoolCleanupGroup
{
    meta:
        desc = "Metasploit::API::kernel32::CreateThreadpoolCleanupGroup"

    /*
        6894AEA10C           | push 0x0ca1ae94
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 ae a1 0c ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateThreadpoolIo
{
    meta:
        desc = "Metasploit::API::kernel32::CreateThreadpoolIo"

    /*
        68CB266835           | push 0x356826cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 26 68 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateThreadpoolTimer
{
    meta:
        desc = "Metasploit::API::kernel32::CreateThreadpoolTimer"

    /*
        68404284D3           | push 0xd3844240
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 42 84 d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateThreadpoolWait
{
    meta:
        desc = "Metasploit::API::kernel32::CreateThreadpoolWait"

    /*
        68820D9428           | push 0x28940d82
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 0d 94 28 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateThreadpoolWork
{
    meta:
        desc = "Metasploit::API::kernel32::CreateThreadpoolWork"

    /*
        68C20F4C44           | push 0x444c0fc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 0f 4c 44 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateTimerQueue
{
    meta:
        desc = "Metasploit::API::kernel32::CreateTimerQueue"

    /*
        68477438C0           | push 0xc0387447
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 74 38 c0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateTimerQueueTimer
{
    meta:
        desc = "Metasploit::API::kernel32::CreateTimerQueueTimer"

    /*
        68FB6E0A07           | push 0x070a6efb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 6e 0a 07 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateToolhelp32Snapshot
{
    meta:
        desc = "Metasploit::API::kernel32::CreateToolhelp32Snapshot"

    /*
        6880391E92           | push 0x921e3980
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 39 1e 92 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateUmsCompletionList
{
    meta:
        desc = "Metasploit::API::kernel32::CreateUmsCompletionList"

    /*
        6862A8B4A8           | push 0xa8b4a862
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 a8 b4 a8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateUmsThreadContext
{
    meta:
        desc = "Metasploit::API::kernel32::CreateUmsThreadContext"

    /*
        68531E8A3E           | push 0x3e8a1e53
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 1e 8a 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateWaitableTimerA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateWaitableTimerA"

    /*
        68F1692FA7           | push 0xa72f69f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 69 2f a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateWaitableTimerExA
{
    meta:
        desc = "Metasploit::API::kernel32::CreateWaitableTimerExA"

    /*
        689FFACBBC           | push 0xbccbfa9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f fa cb bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateWaitableTimerExW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateWaitableTimerExW"

    /*
        689FFA7BBD           | push 0xbd7bfa9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f fa 7b bd ff d5 }

    condition:
        any of them
}

    
rule kernel32_CreateWaitableTimerW
{
    meta:
        desc = "Metasploit::API::kernel32::CreateWaitableTimerW"

    /*
        68F169DFA7           | push 0xa7df69f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 69 df a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_CtrlRoutine
{
    meta:
        desc = "Metasploit::API::kernel32::CtrlRoutine"

    /*
        68F20C2456           | push 0x56240cf2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 0c 24 56 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeactivateActCtx
{
    meta:
        desc = "Metasploit::API::kernel32::DeactivateActCtx"

    /*
        6816141564           | push 0x64151416
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 14 15 64 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeactivateActCtxWorker
{
    meta:
        desc = "Metasploit::API::kernel32::DeactivateActCtxWorker"

    /*
        68EA9595E2           | push 0xe29595ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 95 95 e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DebugActiveProcess
{
    meta:
        desc = "Metasploit::API::kernel32::DebugActiveProcess"

    /*
        6853C3E459           | push 0x59e4c353
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 c3 e4 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DebugActiveProcessStop
{
    meta:
        desc = "Metasploit::API::kernel32::DebugActiveProcessStop"

    /*
        680EFFFBD8           | push 0xd8fbff0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e ff fb d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DebugBreak
{
    meta:
        desc = "Metasploit::API::kernel32::DebugBreak"

    /*
        68ED85ADC3           | push 0xc3ad85ed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 85 ad c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DebugBreakProcess
{
    meta:
        desc = "Metasploit::API::kernel32::DebugBreakProcess"

    /*
        683850E301           | push 0x01e35038
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 50 e3 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DebugSetProcessKillOnExit
{
    meta:
        desc = "Metasploit::API::kernel32::DebugSetProcessKillOnExit"

    /*
        687E1DE140           | push 0x40e11d7e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 1d e1 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DecodePointer
{
    meta:
        desc = "Metasploit::API::kernel32::DecodePointer"

    /*
        68BB40CB47           | push 0x47cb40bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 40 cb 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DecodeSystemPointer
{
    meta:
        desc = "Metasploit::API::kernel32::DecodeSystemPointer"

    /*
        6821691C31           | push 0x311c6921
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 69 1c 31 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DefineDosDeviceA
{
    meta:
        desc = "Metasploit::API::kernel32::DefineDosDeviceA"

    /*
        68D4DFE4A4           | push 0xa4e4dfd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 df e4 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DefineDosDeviceW
{
    meta:
        desc = "Metasploit::API::kernel32::DefineDosDeviceW"

    /*
        68D4DF94A5           | push 0xa594dfd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 df 94 a5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DelayLoadFailureHook
{
    meta:
        desc = "Metasploit::API::kernel32::DelayLoadFailureHook"

    /*
        68DC985EAE           | push 0xae5e98dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 98 5e ae ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteAtom
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteAtom"

    /*
        687E77EE6B           | push 0x6bee777e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 77 ee 6b ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteBoundaryDescriptor
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteBoundaryDescriptor"

    /*
        689E914DC2           | push 0xc24d919e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 91 4d c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteCriticalSection
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteCriticalSection"

    /*
        683430D914           | push 0x14d93034
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 30 d9 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteFiber
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteFiber"

    /*
        68D72E6501           | push 0x01652ed7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 2e 65 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteFileA
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteFileA"

    /*
        68D72EDD13           | push 0x13dd2ed7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 2e dd 13 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteFileTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteFileTransactedA"

    /*
        68880CB72E           | push 0x2eb70c88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 0c b7 2e ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteFileTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteFileTransactedW"

    /*
        68880C672F           | push 0x2f670c88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 0c 67 2f ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteFileW
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteFileW"

    /*
        68D72E8D14           | push 0x148d2ed7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 2e 8d 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteProcThreadAttributeList
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteProcThreadAttributeList"

    /*
        6810D79708           | push 0x0897d710
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 d7 97 08 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteSynchronizationBarrier
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteSynchronizationBarrier"

    /*
        687C3A5F49           | push 0x495f3a7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 3a 5f 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteTimerQueue
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteTimerQueue"

    /*
        6845903922           | push 0x22399045
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 90 39 22 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteTimerQueueEx
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteTimerQueueEx"

    /*
        68FD820D79           | push 0x790d82fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 82 0d 79 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteTimerQueueTimer
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteTimerQueueTimer"

    /*
        68FAFC0A38           | push 0x380afcfa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa fc 0a 38 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteUmsCompletionList
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteUmsCompletionList"

    /*
        682E28D8E8           | push 0xe8d8282e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 28 d8 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteUmsThreadContext
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteUmsThreadContext"

    /*
        6858A683AE           | push 0xae83a658
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 a6 83 ae ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteVolumeMountPointA
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteVolumeMountPointA"

    /*
        6856418349           | push 0x49834156
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 41 83 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeleteVolumeMountPointW
{
    meta:
        desc = "Metasploit::API::kernel32::DeleteVolumeMountPointW"

    /*
        685641334A           | push 0x4a334156
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 41 33 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_DequeueUmsCompletionListItems
{
    meta:
        desc = "Metasploit::API::kernel32::DequeueUmsCompletionListItems"

    /*
        68015E750D           | push 0x0d755e01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 5e 75 0d ff d5 }

    condition:
        any of them
}

    
rule kernel32_DeviceIoControl
{
    meta:
        desc = "Metasploit::API::kernel32::DeviceIoControl"

    /*
        68E45D9CE6           | push 0xe69c5de4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 5d 9c e6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DisableThreadLibraryCalls
{
    meta:
        desc = "Metasploit::API::kernel32::DisableThreadLibraryCalls"

    /*
        68EFA00CA8           | push 0xa80ca0ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef a0 0c a8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DisableThreadProfiling
{
    meta:
        desc = "Metasploit::API::kernel32::DisableThreadProfiling"

    /*
        685A6D665E           | push 0x5e666d5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 6d 66 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_DisassociateCurrentThreadFromCallback
{
    meta:
        desc = "Metasploit::API::kernel32::DisassociateCurrentThreadFromCallback"

    /*
        68CA2C62C7           | push 0xc7622cca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 2c 62 c7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DiscardVirtualMemory
{
    meta:
        desc = "Metasploit::API::kernel32::DiscardVirtualMemory"

    /*
        68E524BD1F           | push 0x1fbd24e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 24 bd 1f ff d5 }

    condition:
        any of them
}

    
rule kernel32_DisconnectNamedPipe
{
    meta:
        desc = "Metasploit::API::kernel32::DisconnectNamedPipe"

    /*
        68C0FADDFC           | push 0xfcddfac0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 fa dd fc ff d5 }

    condition:
        any of them
}

    
rule kernel32_DnsHostnameToComputerNameA
{
    meta:
        desc = "Metasploit::API::kernel32::DnsHostnameToComputerNameA"

    /*
        68278CD558           | push 0x58d58c27
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 8c d5 58 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DnsHostnameToComputerNameExW
{
    meta:
        desc = "Metasploit::API::kernel32::DnsHostnameToComputerNameExW"

    /*
        684B880427           | push 0x2704884b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 88 04 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DnsHostnameToComputerNameW
{
    meta:
        desc = "Metasploit::API::kernel32::DnsHostnameToComputerNameW"

    /*
        68278C8559           | push 0x59858c27
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 8c 85 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DosDateTimeToFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::DosDateTimeToFileTime"

    /*
        686E377206           | push 0x0672376e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e 37 72 06 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DosPathToSessionPathA
{
    meta:
        desc = "Metasploit::API::kernel32::DosPathToSessionPathA"

    /*
        684C255BE4           | push 0xe45b254c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 25 5b e4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DosPathToSessionPathW
{
    meta:
        desc = "Metasploit::API::kernel32::DosPathToSessionPathW"

    /*
        684C250BE5           | push 0xe50b254c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 25 0b e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DuplicateConsoleHandle
{
    meta:
        desc = "Metasploit::API::kernel32::DuplicateConsoleHandle"

    /*
        68F68D3BC8           | push 0xc83b8df6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 8d 3b c8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DuplicateEncryptionInfoFileExt
{
    meta:
        desc = "Metasploit::API::kernel32::DuplicateEncryptionInfoFileExt"

    /*
        689A90BE03           | push 0x03be909a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 90 be 03 ff d5 }

    condition:
        any of them
}

    
rule kernel32_DuplicateHandle
{
    meta:
        desc = "Metasploit::API::kernel32::DuplicateHandle"

    /*
        688D01D5CB           | push 0xcbd5018d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 01 d5 cb ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnableThreadProfiling
{
    meta:
        desc = "Metasploit::API::kernel32::EnableThreadProfiling"

    /*
        684A6C540E           | push 0x0e546c4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 6c 54 0e ff d5 }

    condition:
        any of them
}

    
rule kernel32_EncodePointer
{
    meta:
        desc = "Metasploit::API::kernel32::EncodePointer"

    /*
        684B414B48           | push 0x484b414b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 41 4b 48 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EncodeSystemPointer
{
    meta:
        desc = "Metasploit::API::kernel32::EncodeSystemPointer"

    /*
        68216B5C33           | push 0x335c6b21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 6b 5c 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EndUpdateResourceA
{
    meta:
        desc = "Metasploit::API::kernel32::EndUpdateResourceA"

    /*
        6859B80A66           | push 0x660ab859
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 b8 0a 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EndUpdateResourceW
{
    meta:
        desc = "Metasploit::API::kernel32::EndUpdateResourceW"

    /*
        6859B8BA66           | push 0x66bab859
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 b8 ba 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnterCriticalSection
{
    meta:
        desc = "Metasploit::API::kernel32::EnterCriticalSection"

    /*
        68BA338418           | push 0x188433ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 33 84 18 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnterSynchronizationBarrier
{
    meta:
        desc = "Metasploit::API::kernel32::EnterSynchronizationBarrier"

    /*
        683DABBFBE           | push 0xbebfab3d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d ab bf be ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnterUmsSchedulingMode
{
    meta:
        desc = "Metasploit::API::kernel32::EnterUmsSchedulingMode"

    /*
        6899D50751           | push 0x5107d599
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 d5 07 51 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumCalendarInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumCalendarInfoA"

    /*
        683F4B5149           | push 0x49514b3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 4b 51 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumCalendarInfoExA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumCalendarInfoExA"

    /*
        68474E4445           | push 0x45444e47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 4e 44 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumCalendarInfoExEx
{
    meta:
        desc = "Metasploit::API::kernel32::EnumCalendarInfoExEx"

    /*
        6883ACDC51           | push 0x51dcac83
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 ac dc 51 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumCalendarInfoExW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumCalendarInfoExW"

    /*
        68474EF445           | push 0x45f44e47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 4e f4 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumCalendarInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumCalendarInfoW"

    /*
        683F4B014A           | push 0x4a014b3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 4b 01 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumDateFormatsA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumDateFormatsA"

    /*
        681C52113C           | push 0x3c11521c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 52 11 3c ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumDateFormatsExA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumDateFormatsExA"

    /*
        68840546F5           | push 0xf5460584
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 05 46 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumDateFormatsExEx
{
    meta:
        desc = "Metasploit::API::kernel32::EnumDateFormatsExEx"

    /*
        68912CC20B           | push 0x0bc22c91
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 2c c2 0b ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumDateFormatsExW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumDateFormatsExW"

    /*
        688405F6F5           | push 0xf5f60584
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 05 f6 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumDateFormatsW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumDateFormatsW"

    /*
        681C52C13C           | push 0x3cc1521c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 52 c1 3c ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumLanguageGroupLocalesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumLanguageGroupLocalesA"

    /*
        685A6C95D1           | push 0xd1956c5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 6c 95 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumLanguageGroupLocalesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumLanguageGroupLocalesW"

    /*
        685A6C45D2           | push 0xd2456c5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 6c 45 d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceLanguagesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceLanguagesA"

    /*
        6840718BCD           | push 0xcd8b7140
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 71 8b cd ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceLanguagesExA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceLanguagesExA"

    /*
        6868CECD53           | push 0x53cdce68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 ce cd 53 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceLanguagesExW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceLanguagesExW"

    /*
        6868CE7D54           | push 0x547dce68
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 ce 7d 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceLanguagesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceLanguagesW"

    /*
        6840713BCE           | push 0xce3b7140
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 71 3b ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceNamesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceNamesA"

    /*
        6836F30D68           | push 0x680df336
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 f3 0d 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceNamesExA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceNamesExA"

    /*
        680F4C6EF4           | push 0xf46e4c0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 4c 6e f4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceNamesExW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceNamesExW"

    /*
        680F4C1EF5           | push 0xf51e4c0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 4c 1e f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceNamesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceNamesW"

    /*
        6836F3BD68           | push 0x68bdf336
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 f3 bd 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceTypesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceTypesA"

    /*
        6842232668           | push 0x68262342
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 23 26 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceTypesExA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceTypesExA"

    /*
        680F4F7AFA           | push 0xfa7a4f0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 4f 7a fa ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceTypesExW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceTypesExW"

    /*
        680F4F2AFB           | push 0xfb2a4f0f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 4f 2a fb ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumResourceTypesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumResourceTypesW"

    /*
        684223D668           | push 0x68d62342
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 23 d6 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemCodePagesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemCodePagesA"

    /*
        6848DA70CC           | push 0xcc70da48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 da 70 cc ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemCodePagesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemCodePagesW"

    /*
        6848DA20CD           | push 0xcd20da48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 da 20 cd ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemFirmwareTables
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemFirmwareTables"

    /*
        68B0401852           | push 0x521840b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 40 18 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemGeoID
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemGeoID"

    /*
        68D5DCB483           | push 0x83b4dcd5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 dc b4 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemGeoNames
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemGeoNames"

    /*
        68A90B2BE8           | push 0xe82b0ba9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 0b 2b e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemLanguageGroupsA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemLanguageGroupsA"

    /*
        682A28AD37           | push 0x37ad282a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 28 ad 37 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemLanguageGroupsW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemLanguageGroupsW"

    /*
        682A285D38           | push 0x385d282a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 28 5d 38 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemLocalesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemLocalesA"

    /*
        6872C06B5B           | push 0x5b6bc072
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 c0 6b 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemLocalesEx
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemLocalesEx"

    /*
        68BF5D35E3           | push 0xe3355dbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 5d 35 e3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumSystemLocalesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumSystemLocalesW"

    /*
        6872C01B5C           | push 0x5c1bc072
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 c0 1b 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumTimeFormatsA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumTimeFormatsA"

    /*
        681A53217C           | push 0x7c21531a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 53 21 7c ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumTimeFormatsEx
{
    meta:
        desc = "Metasploit::API::kernel32::EnumTimeFormatsEx"

    /*
        686B637678           | push 0x7876636b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 63 76 78 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumTimeFormatsW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumTimeFormatsW"

    /*
        681A53D17C           | push 0x7cd1531a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 53 d1 7c ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumUILanguagesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumUILanguagesA"

    /*
        681C92ED45           | push 0x45ed921c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 92 ed 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumUILanguagesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumUILanguagesW"

    /*
        681C929D46           | push 0x469d921c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 92 9d 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumerateLocalComputerNamesA
{
    meta:
        desc = "Metasploit::API::kernel32::EnumerateLocalComputerNamesA"

    /*
        6888076424           | push 0x24640788
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 07 64 24 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EnumerateLocalComputerNamesW
{
    meta:
        desc = "Metasploit::API::kernel32::EnumerateLocalComputerNamesW"

    /*
        6888071425           | push 0x25140788
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 07 14 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_EraseTape
{
    meta:
        desc = "Metasploit::API::kernel32::EraseTape"

    /*
        682DA7AA4B           | push 0x4baaa72d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d a7 aa 4b ff d5 }

    condition:
        any of them
}

    
rule kernel32_EscapeCommFunction
{
    meta:
        desc = "Metasploit::API::kernel32::EscapeCommFunction"

    /*
        685CB1E4D4           | push 0xd4e4b15c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c b1 e4 d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExecuteUmsThread
{
    meta:
        desc = "Metasploit::API::kernel32::ExecuteUmsThread"

    /*
        6827A1D740           | push 0x40d7a127
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 a1 d7 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExitProcess
{
    meta:
        desc = "Metasploit::API::kernel32::ExitProcess"

    /*
        68F0B5A256           | push 0x56a2b5f0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 b5 a2 56 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExitThread
{
    meta:
        desc = "Metasploit::API::kernel32::ExitThread"

    /*
        68E01D2A0A           | push 0x0a2a1de0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 1d 2a 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExitVDM
{
    meta:
        desc = "Metasploit::API::kernel32::ExitVDM"

    /*
        68AF70FEC2           | push 0xc2fe70af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 70 fe c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExpandEnvironmentStringsA
{
    meta:
        desc = "Metasploit::API::kernel32::ExpandEnvironmentStringsA"

    /*
        68868C76C1           | push 0xc1768c86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 8c 76 c1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExpandEnvironmentStringsW
{
    meta:
        desc = "Metasploit::API::kernel32::ExpandEnvironmentStringsW"

    /*
        68868C26C2           | push 0xc2268c86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 8c 26 c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExpungeConsoleCommandHistoryA
{
    meta:
        desc = "Metasploit::API::kernel32::ExpungeConsoleCommandHistoryA"

    /*
        683F4A6C5A           | push 0x5a6c4a3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 4a 6c 5a ff d5 }

    condition:
        any of them
}

    
rule kernel32_ExpungeConsoleCommandHistoryW
{
    meta:
        desc = "Metasploit::API::kernel32::ExpungeConsoleCommandHistoryW"

    /*
        683F4A1C5B           | push 0x5b1c4a3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 4a 1c 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_FatalAppExitA
{
    meta:
        desc = "Metasploit::API::kernel32::FatalAppExitA"

    /*
        6825286A8D           | push 0x8d6a2825
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 28 6a 8d ff d5 }

    condition:
        any of them
}

    
rule kernel32_FatalAppExitW
{
    meta:
        desc = "Metasploit::API::kernel32::FatalAppExitW"

    /*
        6825281A8E           | push 0x8e1a2825
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 28 1a 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_FatalExit
{
    meta:
        desc = "Metasploit::API::kernel32::FatalExit"

    /*
        68D1BFD9E8           | push 0xe8d9bfd1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 bf d9 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FileTimeToDosDateTime
{
    meta:
        desc = "Metasploit::API::kernel32::FileTimeToDosDateTime"

    /*
        682D8C0662           | push 0x62068c2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 8c 06 62 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FileTimeToLocalFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::FileTimeToLocalFileTime"

    /*
        68924FF389           | push 0x89f34f92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 4f f3 89 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FileTimeToSystemTime
{
    meta:
        desc = "Metasploit::API::kernel32::FileTimeToSystemTime"

    /*
        6860D728EB           | push 0xeb28d760
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 d7 28 eb ff d5 }

    condition:
        any of them
}

    
rule kernel32_FillConsoleOutputAttribute
{
    meta:
        desc = "Metasploit::API::kernel32::FillConsoleOutputAttribute"

    /*
        682D9C82E2           | push 0xe2829c2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 9c 82 e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FillConsoleOutputCharacterA
{
    meta:
        desc = "Metasploit::API::kernel32::FillConsoleOutputCharacterA"

    /*
        68B628318E           | push 0x8e3128b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 28 31 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_FillConsoleOutputCharacterW
{
    meta:
        desc = "Metasploit::API::kernel32::FillConsoleOutputCharacterW"

    /*
        68B628E18E           | push 0x8ee128b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 28 e1 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindActCtxSectionGuid
{
    meta:
        desc = "Metasploit::API::kernel32::FindActCtxSectionGuid"

    /*
        6829B8C099           | push 0x99c0b829
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 b8 c0 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindActCtxSectionGuidWorker
{
    meta:
        desc = "Metasploit::API::kernel32::FindActCtxSectionGuidWorker"

    /*
        68986CDE72           | push 0x72de6c98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 6c de 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindActCtxSectionStringA
{
    meta:
        desc = "Metasploit::API::kernel32::FindActCtxSectionStringA"

    /*
        6861A5C18E           | push 0x8ec1a561
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 a5 c1 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindActCtxSectionStringW
{
    meta:
        desc = "Metasploit::API::kernel32::FindActCtxSectionStringW"

    /*
        6861A5718F           | push 0x8f71a561
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 a5 71 8f ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindActCtxSectionStringWWorker
{
    meta:
        desc = "Metasploit::API::kernel32::FindActCtxSectionStringWWorker"

    /*
        685C43C227           | push 0x27c2435c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 43 c2 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindAtomA
{
    meta:
        desc = "Metasploit::API::kernel32::FindAtomA"

    /*
        68FBAF505D           | push 0x5d50affb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb af 50 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindAtomW
{
    meta:
        desc = "Metasploit::API::kernel32::FindAtomW"

    /*
        68FBAF005E           | push 0x5e00affb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb af 00 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindClose
{
    meta:
        desc = "Metasploit::API::kernel32::FindClose"

    /*
        687C31705E           | push 0x5e70317c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 31 70 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindCloseChangeNotification
{
    meta:
        desc = "Metasploit::API::kernel32::FindCloseChangeNotification"

    /*
        687D5CE9FC           | push 0xfce95c7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 5c e9 fc ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstChangeNotificationA
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstChangeNotificationA"

    /*
        68B96B72B1           | push 0xb1726bb9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 6b 72 b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstChangeNotificationW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstChangeNotificationW"

    /*
        68B96B22B2           | push 0xb2226bb9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 6b 22 b2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileA
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileA"

    /*
        689035DA95           | push 0x95da3590
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 35 da 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileExA
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileExA"

    /*
        685AE27E67           | push 0x677ee25a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a e2 7e 67 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileExW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileExW"

    /*
        685AE22E68           | push 0x682ee25a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a e2 2e 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileNameTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileNameTransactedW"

    /*
        68E7E89952           | push 0x5299e8e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 e8 99 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileNameW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileNameW"

    /*
        6854A058A1           | push 0xa158a054
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 a0 58 a1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileTransactedA"

    /*
        68364E364F           | push 0x4f364e36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 4e 36 4f ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileTransactedW"

    /*
        68364EE64F           | push 0x4fe64e36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 4e e6 4f ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstFileW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstFileW"

    /*
        6890358A96           | push 0x968a3590
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 35 8a 96 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstStreamTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstStreamTransactedW"

    /*
        6822795AD2           | push 0xd25a7922
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 79 5a d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstStreamW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstStreamW"

    /*
        683EE15AA0           | push 0xa05ae13e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e e1 5a a0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstVolumeA
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstVolumeA"

    /*
        689BDF97B7           | push 0xb797df9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b df 97 b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstVolumeMountPointA
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstVolumeMountPointA"

    /*
        68DEAC5369           | push 0x6953acde
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de ac 53 69 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstVolumeMountPointW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstVolumeMountPointW"

    /*
        68DEAC036A           | push 0x6a03acde
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de ac 03 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindFirstVolumeW
{
    meta:
        desc = "Metasploit::API::kernel32::FindFirstVolumeW"

    /*
        689BDF47B8           | push 0xb847df9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b df 47 b8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNLSString
{
    meta:
        desc = "Metasploit::API::kernel32::FindNLSString"

    /*
        689ED318D9           | push 0xd918d39e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e d3 18 d9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNLSStringEx
{
    meta:
        desc = "Metasploit::API::kernel32::FindNLSStringEx"

    /*
        682B59DE30           | push 0x30de592b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 59 de 30 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextChangeNotification
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextChangeNotification"

    /*
        6879C3FB28           | push 0x28fbc379
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 c3 fb 28 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextFileA
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextFileA"

    /*
        68E7456CF7           | push 0xf76c45e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 45 6c f7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextFileNameW
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextFileNameW"

    /*
        686D165EC2           | push 0xc25e166d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 16 5e c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextFileW
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextFileW"

    /*
        68E7451CF8           | push 0xf81c45e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 45 1c f8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextStreamW
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextStreamW"

    /*
        6816F7DE04           | push 0x04def716
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 f7 de 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextVolumeA
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextVolumeA"

    /*
        6873F51B1C           | push 0x1c1bf573
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 f5 1b 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextVolumeMountPointA
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextVolumeMountPointA"

    /*
        6854B27482           | push 0x8274b254
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 b2 74 82 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextVolumeMountPointW
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextVolumeMountPointW"

    /*
        6854B22483           | push 0x8324b254
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 b2 24 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindNextVolumeW
{
    meta:
        desc = "Metasploit::API::kernel32::FindNextVolumeW"

    /*
        6873F5CB1C           | push 0x1ccbf573
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 f5 cb 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindPackagesByPackageFamily
{
    meta:
        desc = "Metasploit::API::kernel32::FindPackagesByPackageFamily"

    /*
        6821ECE0BD           | push 0xbde0ec21
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 ec e0 bd ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindResourceA
{
    meta:
        desc = "Metasploit::API::kernel32::FindResourceA"

    /*
        685EF55865           | push 0x6558f55e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e f5 58 65 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindResourceExA
{
    meta:
        desc = "Metasploit::API::kernel32::FindResourceExA"

    /*
        680ED62E47           | push 0x472ed60e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e d6 2e 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindResourceExW
{
    meta:
        desc = "Metasploit::API::kernel32::FindResourceExW"

    /*
        680ED6DE47           | push 0x47ded60e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e d6 de 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindResourceW
{
    meta:
        desc = "Metasploit::API::kernel32::FindResourceW"

    /*
        685EF50866           | push 0x6608f55e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e f5 08 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindStringOrdinal
{
    meta:
        desc = "Metasploit::API::kernel32::FindStringOrdinal"

    /*
        68C5D2AF05           | push 0x05afd2c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 d2 af 05 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindVolumeClose
{
    meta:
        desc = "Metasploit::API::kernel32::FindVolumeClose"

    /*
        68C10B2322           | push 0x22230bc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 0b 23 22 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FindVolumeMountPointClose
{
    meta:
        desc = "Metasploit::API::kernel32::FindVolumeMountPointClose"

    /*
        687B82AC85           | push 0x85ac827b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b 82 ac 85 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlsAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::FlsAlloc"

    /*
        683B009A35           | push 0x359a003b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 00 9a 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlsFree
{
    meta:
        desc = "Metasploit::API::kernel32::FlsFree"

    /*
        6814998BFB           | push 0xfb8b9914
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 99 8b fb ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlsGetValue
{
    meta:
        desc = "Metasploit::API::kernel32::FlsGetValue"

    /*
        6801E93CB7           | push 0xb73ce901
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 e9 3c b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlsSetValue
{
    meta:
        desc = "Metasploit::API::kernel32::FlsSetValue"

    /*
        6801E93CC3           | push 0xc33ce901
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 e9 3c c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlushConsoleInputBuffer
{
    meta:
        desc = "Metasploit::API::kernel32::FlushConsoleInputBuffer"

    /*
        687F360EB9           | push 0xb90e367f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 36 0e b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlushFileBuffers
{
    meta:
        desc = "Metasploit::API::kernel32::FlushFileBuffers"

    /*
        6876D678C1           | push 0xc178d676
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 d6 78 c1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlushInstructionCache
{
    meta:
        desc = "Metasploit::API::kernel32::FlushInstructionCache"

    /*
        686AAFB1DE           | push 0xdeb1af6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a af b1 de ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlushProcessWriteBuffers
{
    meta:
        desc = "Metasploit::API::kernel32::FlushProcessWriteBuffers"

    /*
        68B778288C           | push 0x8c2878b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 78 28 8c ff d5 }

    condition:
        any of them
}

    
rule kernel32_FlushViewOfFile
{
    meta:
        desc = "Metasploit::API::kernel32::FlushViewOfFile"

    /*
        683CA06C49           | push 0x496ca03c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c a0 6c 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FoldStringA
{
    meta:
        desc = "Metasploit::API::kernel32::FoldStringA"

    /*
        68502B1D97           | push 0x971d2b50
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 2b 1d 97 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FoldStringW
{
    meta:
        desc = "Metasploit::API::kernel32::FoldStringW"

    /*
        68502BCD97           | push 0x97cd2b50
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 2b cd 97 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FormatApplicationUserModelId
{
    meta:
        desc = "Metasploit::API::kernel32::FormatApplicationUserModelId"

    /*
        68FD1397EF           | push 0xef9713fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 13 97 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_FormatMessageA
{
    meta:
        desc = "Metasploit::API::kernel32::FormatMessageA"

    /*
        682D0CE8A9           | push 0xa9e80c2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 0c e8 a9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FormatMessageW
{
    meta:
        desc = "Metasploit::API::kernel32::FormatMessageW"

    /*
        682D0C98AA           | push 0xaa980c2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 0c 98 aa ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeConsole
{
    meta:
        desc = "Metasploit::API::kernel32::FreeConsole"

    /*
        688E92295B           | push 0x5b29928e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 92 29 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeEnvironmentStringsA
{
    meta:
        desc = "Metasploit::API::kernel32::FreeEnvironmentStringsA"

    /*
        68C89431A4           | push 0xa43194c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 94 31 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeEnvironmentStringsW
{
    meta:
        desc = "Metasploit::API::kernel32::FreeEnvironmentStringsW"

    /*
        68C894E1A4           | push 0xa4e194c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 94 e1 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeLibrary
{
    meta:
        desc = "Metasploit::API::kernel32::FreeLibrary"

    /*
        682885B13F           | push 0x3fb18528
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 85 b1 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeLibraryAndExitThread
{
    meta:
        desc = "Metasploit::API::kernel32::FreeLibraryAndExitThread"

    /*
        68F7A5C852           | push 0x52c8a5f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 a5 c8 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeLibraryWhenCallbackReturns
{
    meta:
        desc = "Metasploit::API::kernel32::FreeLibraryWhenCallbackReturns"

    /*
        68387EF6DC           | push 0xdcf67e38
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 7e f6 dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeMemoryJobObject
{
    meta:
        desc = "Metasploit::API::kernel32::FreeMemoryJobObject"

    /*
        684C56DF04           | push 0x04df564c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 56 df 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeResource
{
    meta:
        desc = "Metasploit::API::kernel32::FreeResource"

    /*
        68EBB8918E           | push 0x8e91b8eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb b8 91 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_FreeUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::kernel32::FreeUserPhysicalPages"

    /*
        68BB2FCB8B           | push 0x8bcb2fbb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb 2f cb 8b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GenerateConsoleCtrlEvent
{
    meta:
        desc = "Metasploit::API::kernel32::GenerateConsoleCtrlEvent"

    /*
        68BC0579FA           | push 0xfa7905bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 05 79 fa ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetACP
{
    meta:
        desc = "Metasploit::API::kernel32::GetACP"

    /*
        68CD675298           | push 0x985267cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 67 52 98 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetActiveProcessorCount
{
    meta:
        desc = "Metasploit::API::kernel32::GetActiveProcessorCount"

    /*
        6853DA79C5           | push 0xc579da53
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 da 79 c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetActiveProcessorGroupCount
{
    meta:
        desc = "Metasploit::API::kernel32::GetActiveProcessorGroupCount"

    /*
        681A9DAB93           | push 0x93ab9d1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 9d ab 93 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetAppContainerAce
{
    meta:
        desc = "Metasploit::API::kernel32::GetAppContainerAce"

    /*
        6869C4ADE5           | push 0xe5adc469
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 c4 ad e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetAppContainerNamedObjectPath
{
    meta:
        desc = "Metasploit::API::kernel32::GetAppContainerNamedObjectPath"

    /*
        680F283658           | push 0x5836280f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 28 36 58 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetApplicationRecoveryCallback
{
    meta:
        desc = "Metasploit::API::kernel32::GetApplicationRecoveryCallback"

    /*
        6884ADCC01           | push 0x01ccad84
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 ad cc 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetApplicationRecoveryCallbackWorker
{
    meta:
        desc = "Metasploit::API::kernel32::GetApplicationRecoveryCallbackWorker"

    /*
        68C80C4C48           | push 0x484c0cc8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 0c 4c 48 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetApplicationRestartSettings
{
    meta:
        desc = "Metasploit::API::kernel32::GetApplicationRestartSettings"

    /*
        68694A2680           | push 0x80264a69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 4a 26 80 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetApplicationRestartSettingsWorker
{
    meta:
        desc = "Metasploit::API::kernel32::GetApplicationRestartSettingsWorker"

    /*
        682F06E2BB           | push 0xbbe2062f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 06 e2 bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetApplicationUserModelId
{
    meta:
        desc = "Metasploit::API::kernel32::GetApplicationUserModelId"

    /*
        681E971ABB           | push 0xbb1a971e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 97 1a bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetAtomNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetAtomNameA"

    /*
        68AF5A3DE5           | push 0xe53d5aaf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 5a 3d e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetAtomNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetAtomNameW"

    /*
        68AF5AEDE5           | push 0xe5ed5aaf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 5a ed e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetBinaryType
{
    meta:
        desc = "Metasploit::API::kernel32::GetBinaryType"

    /*
        6898CD0F1C           | push 0x1c0fcd98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 cd 0f 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetBinaryTypeA
{
    meta:
        desc = "Metasploit::API::kernel32::GetBinaryTypeA"

    /*
        68DF61AB4A           | push 0x4aab61df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 61 ab 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetBinaryTypeW
{
    meta:
        desc = "Metasploit::API::kernel32::GetBinaryTypeW"

    /*
        68DF615B4B           | push 0x4b5b61df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 61 5b 4b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCPInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetCPInfo"

    /*
        6803073AD8           | push 0xd83a0703
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 03 07 3a d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCPInfoExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetCPInfoExA"

    /*
        68BA4A4271           | push 0x71424aba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 4a 42 71 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCPInfoExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetCPInfoExW"

    /*
        68BA4AF271           | push 0x71f24aba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 4a f2 71 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCachedSigningLevel
{
    meta:
        desc = "Metasploit::API::kernel32::GetCachedSigningLevel"

    /*
        686602D040           | push 0x40d00266
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 02 d0 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarDateFormat
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarDateFormat"

    /*
        682F8DA799           | push 0x99a78d2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 8d a7 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarDateFormatEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarDateFormatEx"

    /*
        685BBD8C54           | push 0x548cbd5b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b bd 8c 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarDaysInMonth
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarDaysInMonth"

    /*
        68EB9693F0           | push 0xf09396eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 96 93 f0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarDifferenceInDays
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarDifferenceInDays"

    /*
        68416149F5           | push 0xf5496141
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 61 49 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarInfoA"

    /*
        6815652A49           | push 0x492a6515
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 65 2a 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarInfoEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarInfoEx"

    /*
        68B4CB4C08           | push 0x084ccbb4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 cb 4c 08 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarInfoW"

    /*
        681565DA49           | push 0x49da6515
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 65 da 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarMonthsInYear
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarMonthsInYear"

    /*
        686ABDD457           | push 0x57d4bd6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a bd d4 57 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarSupportedDateRange
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarSupportedDateRange"

    /*
        687C6CA34E           | push 0x4ea36c7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 6c a3 4e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCalendarWeekNumber
{
    meta:
        desc = "Metasploit::API::kernel32::GetCalendarWeekNumber"

    /*
        68F65EB734           | push 0x34b75ef6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 5e b7 34 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetComPlusPackageInstallStatus
{
    meta:
        desc = "Metasploit::API::kernel32::GetComPlusPackageInstallStatus"

    /*
        681B7F3BA3           | push 0xa33b7f1b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 7f 3b a3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommConfig
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommConfig"

    /*
        68539D6534           | push 0x34659d53
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 9d 65 34 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommMask
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommMask"

    /*
        68CAB1515D           | push 0x5d51b1ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca b1 51 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommModemStatus
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommModemStatus"

    /*
        681138EC4D           | push 0x4dec3811
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 38 ec 4d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommProperties
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommProperties"

    /*
        687E23A691           | push 0x91a6237e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 23 a6 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommState
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommState"

    /*
        68319E5E49           | push 0x495e9e31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 9e 5e 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommTimeouts
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommTimeouts"

    /*
        688231E5B0           | push 0xb0e53182
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 31 e5 b0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommandLineA
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommandLineA"

    /*
        6855CE302E           | push 0x2e30ce55
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 ce 30 2e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCommandLineW
{
    meta:
        desc = "Metasploit::API::kernel32::GetCommandLineW"

    /*
        6855CEE02E           | push 0x2ee0ce55
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 ce e0 2e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCompressedFileSizeA
{
    meta:
        desc = "Metasploit::API::kernel32::GetCompressedFileSizeA"

    /*
        68A7A3024A           | push 0x4a02a3a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 a3 02 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCompressedFileSizeTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::GetCompressedFileSizeTransactedA"

    /*
        68BC69403C           | push 0x3c4069bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 69 40 3c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCompressedFileSizeTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::GetCompressedFileSizeTransactedW"

    /*
        68BC69F03C           | push 0x3cf069bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 69 f0 3c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCompressedFileSizeW
{
    meta:
        desc = "Metasploit::API::kernel32::GetCompressedFileSizeW"

    /*
        68A7A3B24A           | push 0x4ab2a3a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 a3 b2 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetComputerNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetComputerNameA"

    /*
        68FBCB2BA7           | push 0xa72bcbfb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb cb 2b a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetComputerNameExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetComputerNameExA"

    /*
        681F7DE4BB           | push 0xbbe47d1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 7d e4 bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetComputerNameExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetComputerNameExW"

    /*
        681F7D94BC           | push 0xbc947d1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 7d 94 bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetComputerNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetComputerNameW"

    /*
        68FBCBDBA7           | push 0xa7dbcbfb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb cb db a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasA"

    /*
        688A1F6A46           | push 0x466a1f8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 1f 6a 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasExesA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasExesA"

    /*
        68D8BE490F           | push 0x0f49bed8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 be 49 0f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasExesLengthA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasExesLengthA"

    /*
        68DC944B1E           | push 0x1e4b94dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 94 4b 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasExesLengthW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasExesLengthW"

    /*
        68DC94FB1E           | push 0x1efb94dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 94 fb 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasExesW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasExesW"

    /*
        68D8BEF90F           | push 0x0ff9bed8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 be f9 0f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasW"

    /*
        688A1F1A47           | push 0x471a1f8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 1f 1a 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasesA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasesA"

    /*
        68C75F79CB           | push 0xcb795fc7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 5f 79 cb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasesLengthA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasesLengthA"

    /*
        689B8506A2           | push 0xa206859b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 85 06 a2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasesLengthW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasesLengthW"

    /*
        689B85B6A2           | push 0xa2b6859b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 85 b6 a2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleAliasesW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleAliasesW"

    /*
        68C75F29CC           | push 0xcc295fc7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 5f 29 cc ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCP
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCP"

    /*
        681F12CE50           | push 0x50ce121f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 12 ce 50 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCharType
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCharType"

    /*
        688F6E7776           | push 0x76776e8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 6e 77 76 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCommandHistoryA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCommandHistoryA"

    /*
        68DEE4AE1C           | push 0x1caee4de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de e4 ae 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCommandHistoryLengthA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCommandHistoryLengthA"

    /*
        6871CA63B6           | push 0xb663ca71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 ca 63 b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCommandHistoryLengthW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCommandHistoryLengthW"

    /*
        6871CA13B7           | push 0xb713ca71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 ca 13 b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCommandHistoryW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCommandHistoryW"

    /*
        68DEE45E1D           | push 0x1d5ee4de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de e4 5e 1d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCursorInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCursorInfo"

    /*
        68EF15A72B           | push 0x2ba715ef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef 15 a7 2b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleCursorMode
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleCursorMode"

    /*
        686F55572D           | push 0x2d57556f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 55 57 2d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleDisplayMode
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleDisplayMode"

    /*
        688FD33F9D           | push 0x9d3fd38f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f d3 3f 9d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleFontInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleFontInfo"

    /*
        68F0BCFA63           | push 0x63fabcf0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 bc fa 63 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleFontSize
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleFontSize"

    /*
        68F061AB59           | push 0x59ab61f0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 61 ab 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleHardwareState
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleHardwareState"

    /*
        68ABB76534           | push 0x3465b7ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab b7 65 34 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleHistoryInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleHistoryInfo"

    /*
        686F94DB9F           | push 0x9fdb946f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 94 db 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleInputExeNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleInputExeNameA"

    /*
        687D6DC0EF           | push 0xefc06d7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 6d c0 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleInputExeNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleInputExeNameW"

    /*
        687D6D70F0           | push 0xf0706d7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 6d 70 f0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleInputWaitHandle
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleInputWaitHandle"

    /*
        6870B7C8A3           | push 0xa3c8b770
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 b7 c8 a3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleKeyboardLayoutNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleKeyboardLayoutNameA"

    /*
        683E8FC42F           | push 0x2fc48f3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 8f c4 2f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleKeyboardLayoutNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleKeyboardLayoutNameW"

    /*
        683E8F7430           | push 0x30748f3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 8f 74 30 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleMode
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleMode"

    /*
        6849A1965B           | push 0x5b96a149
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 a1 96 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleNlsMode
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleNlsMode"

    /*
        68177F5BD3           | push 0xd35b7f17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 7f 5b d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleOriginalTitleA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleOriginalTitleA"

    /*
        68D5D8CF82           | push 0x82cfd8d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 d8 cf 82 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleOriginalTitleW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleOriginalTitleW"

    /*
        68D5D87F83           | push 0x837fd8d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 d8 7f 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleOutputCP
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleOutputCP"

    /*
        68EE741D78           | push 0x781d74ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 74 1d 78 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleProcessList
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleProcessList"

    /*
        686EA617C5           | push 0xc517a66e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e a6 17 c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleScreenBufferInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleScreenBufferInfo"

    /*
        68AF5A1E69           | push 0x691e5aaf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 5a 1e 69 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleScreenBufferInfoEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleScreenBufferInfoEx"

    /*
        688F1D4032           | push 0x32401d8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 1d 40 32 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleSelectionInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleSelectionInfo"

    /*
        6859634E27           | push 0x274e6359
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 63 4e 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleTitleA
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleTitleA"

    /*
        6809CCB6DC           | push 0xdcb6cc09
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 cc b6 dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleTitleW
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleTitleW"

    /*
        6809CC66DD           | push 0xdd66cc09
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 cc 66 dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetConsoleWindow
{
    meta:
        desc = "Metasploit::API::kernel32::GetConsoleWindow"

    /*
        68896E72CE           | push 0xce726e89
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 6e 72 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrencyFormatA
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrencyFormatA"

    /*
        6840037DFD           | push 0xfd7d0340
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 03 7d fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrencyFormatEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrencyFormatEx"

    /*
        68496EA2F9           | push 0xf9a26e49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 6e a2 f9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrencyFormatW
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrencyFormatW"

    /*
        6840032DFE           | push 0xfe2d0340
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 03 2d fe ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentActCtx
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentActCtx"

    /*
        6805822A4E           | push 0x4e2a8205
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 82 2a 4e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentActCtxWorker
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentActCtxWorker"

    /*
        68403E519A           | push 0x9a513e40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 3e 51 9a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentApplicationUserModelId
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentApplicationUserModelId"

    /*
        68CBE29382           | push 0x8293e2cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb e2 93 82 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentConsoleFont
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentConsoleFont"

    /*
        688617E501           | push 0x01e51786
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 17 e5 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentConsoleFontEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentConsoleFontEx"

    /*
        683553EF63           | push 0x63ef5335
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 53 ef 63 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentDirectoryA"

    /*
        6811152DED           | push 0xed2d1511
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 15 2d ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentDirectoryW"

    /*
        681115DDED           | push 0xeddd1511
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 15 dd ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentPackageFamilyName
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentPackageFamilyName"

    /*
        68E53D2F74           | push 0x742f3de5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 3d 2f 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentPackageFullName
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentPackageFullName"

    /*
        684AA14212           | push 0x1242a14a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a a1 42 12 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentPackageId
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentPackageId"

    /*
        68C785E535           | push 0x35e585c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 85 e5 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentPackageInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentPackageInfo"

    /*
        68C2EBC277           | push 0x77c2ebc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 eb c2 77 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentPackagePath
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentPackagePath"

    /*
        68425F8B5D           | push 0x5d8b5f42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 5f 8b 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentProcess
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentProcess"

    /*
        6852F3E251           | push 0x51e2f352
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 f3 e2 51 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentProcessId
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentProcessId"

    /*
        684947C662           | push 0x62c64749
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 47 c6 62 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentProcessorNumber
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentProcessorNumber"

    /*
        6872423DC3           | push 0xc33d4272
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 42 3d c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentProcessorNumberEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentProcessorNumberEx"

    /*
        68260EFAB9           | push 0xb9fa0e26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 0e fa b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentThread
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentThread"

    /*
        68485DD611           | push 0x11d65d48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 5d d6 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentThreadId
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentThreadId"

    /*
        68B9C4A05F           | push 0x5fa0c4b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 c4 a0 5f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentThreadStackLimits
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentThreadStackLimits"

    /*
        68DB1704DA           | push 0xda0417db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db 17 04 da ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetCurrentUmsThread
{
    meta:
        desc = "Metasploit::API::kernel32::GetCurrentUmsThread"

    /*
        68CB658AC1           | push 0xc18a65cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 65 8a c1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDateFormatA
{
    meta:
        desc = "Metasploit::API::kernel32::GetDateFormatA"

    /*
        682CD08630           | push 0x3086d02c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c d0 86 30 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDateFormatAWorker
{
    meta:
        desc = "Metasploit::API::kernel32::GetDateFormatAWorker"

    /*
        68B1C7ECD2           | push 0xd2ecc7b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 c7 ec d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDateFormatEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetDateFormatEx"

    /*
        6897060461           | push 0x61040697
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 06 04 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDateFormatW
{
    meta:
        desc = "Metasploit::API::kernel32::GetDateFormatW"

    /*
        682CD03631           | push 0x3136d02c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c d0 36 31 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDateFormatWWorker
{
    meta:
        desc = "Metasploit::API::kernel32::GetDateFormatWWorker"

    /*
        6871CAECD2           | push 0xd2ecca71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 ca ec d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDefaultCommConfigA
{
    meta:
        desc = "Metasploit::API::kernel32::GetDefaultCommConfigA"

    /*
        68C8478F4D           | push 0x4d8f47c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 47 8f 4d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDefaultCommConfigW
{
    meta:
        desc = "Metasploit::API::kernel32::GetDefaultCommConfigW"

    /*
        68C8473F4E           | push 0x4e3f47c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 47 3f 4e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDevicePowerState
{
    meta:
        desc = "Metasploit::API::kernel32::GetDevicePowerState"

    /*
        6895687A3F           | push 0x3f7a6895
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 68 7a 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDiskFreeSpaceA
{
    meta:
        desc = "Metasploit::API::kernel32::GetDiskFreeSpaceA"

    /*
        687BF6C8F6           | push 0xf6c8f67b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b f6 c8 f6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDiskFreeSpaceExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetDiskFreeSpaceExA"

    /*
        68331D2FA3           | push 0xa32f1d33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 1d 2f a3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDiskFreeSpaceExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetDiskFreeSpaceExW"

    /*
        68331DDFA3           | push 0xa3df1d33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 1d df a3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDiskFreeSpaceW
{
    meta:
        desc = "Metasploit::API::kernel32::GetDiskFreeSpaceW"

    /*
        687BF678F7           | push 0xf778f67b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b f6 78 f7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDiskSpaceInformationA
{
    meta:
        desc = "Metasploit::API::kernel32::GetDiskSpaceInformationA"

    /*
        68590A9671           | push 0x71960a59
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 0a 96 71 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDiskSpaceInformationW
{
    meta:
        desc = "Metasploit::API::kernel32::GetDiskSpaceInformationW"

    /*
        68590A4672           | push 0x72460a59
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 0a 46 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDllDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::GetDllDirectoryA"

    /*
        68D3506EAF           | push 0xaf6e50d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 50 6e af ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDllDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::GetDllDirectoryW"

    /*
        68D3501EB0           | push 0xb01e50d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 50 1e b0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDriveTypeA
{
    meta:
        desc = "Metasploit::API::kernel32::GetDriveTypeA"

    /*
        686665BE03           | push 0x03be6566
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 65 be 03 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDriveTypeW
{
    meta:
        desc = "Metasploit::API::kernel32::GetDriveTypeW"

    /*
        6866656E04           | push 0x046e6566
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 65 6e 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDurationFormat
{
    meta:
        desc = "Metasploit::API::kernel32::GetDurationFormat"

    /*
        6896BE191C           | push 0x1c19be96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 be 19 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDurationFormatEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetDurationFormatEx"

    /*
        683C1719F1           | push 0xf119173c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 17 19 f1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetDynamicTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetDynamicTimeZoneInformation"

    /*
        681033CD75           | push 0x75cd3310
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 33 cd 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEnabledXStateFeatures
{
    meta:
        desc = "Metasploit::API::kernel32::GetEnabledXStateFeatures"

    /*
        6895AAC171           | push 0x71c1aa95
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 aa c1 71 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEncryptedFileVersionExt
{
    meta:
        desc = "Metasploit::API::kernel32::GetEncryptedFileVersionExt"

    /*
        68B71592B6           | push 0xb69215b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 15 92 b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEnvironmentStrings
{
    meta:
        desc = "Metasploit::API::kernel32::GetEnvironmentStrings"

    /*
        68B17557E2           | push 0xe25775b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 75 57 e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEnvironmentStringsA
{
    meta:
        desc = "Metasploit::API::kernel32::GetEnvironmentStringsA"

    /*
        681C94718B           | push 0x8b71941c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 94 71 8b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEnvironmentStringsW
{
    meta:
        desc = "Metasploit::API::kernel32::GetEnvironmentStringsW"

    /*
        681C94218C           | push 0x8c21941c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 94 21 8c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEnvironmentVariableA
{
    meta:
        desc = "Metasploit::API::kernel32::GetEnvironmentVariableA"

    /*
        68E7ADCEDD           | push 0xddceade7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 ad ce dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEnvironmentVariableW
{
    meta:
        desc = "Metasploit::API::kernel32::GetEnvironmentVariableW"

    /*
        68E7AD7EDE           | push 0xde7eade7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 ad 7e de ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetEraNameCountedString
{
    meta:
        desc = "Metasploit::API::kernel32::GetEraNameCountedString"

    /*
        6836826582           | push 0x82658236
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 82 65 82 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetErrorMode
{
    meta:
        desc = "Metasploit::API::kernel32::GetErrorMode"

    /*
        68E13A64E8           | push 0xe8643ae1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 3a 64 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetExitCodeProcess
{
    meta:
        desc = "Metasploit::API::kernel32::GetExitCodeProcess"

    /*
        685F7854EE           | push 0xee54785f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 78 54 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetExitCodeThread
{
    meta:
        desc = "Metasploit::API::kernel32::GetExitCodeThread"

    /*
        68D6F07742           | push 0x4277f0d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 f0 77 42 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetExpandedNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetExpandedNameA"

    /*
        688794F9D7           | push 0xd7f99487
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 94 f9 d7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetExpandedNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetExpandedNameW"

    /*
        688794A9D8           | push 0xd8a99487
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 94 a9 d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileAttributesA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileAttributesA"

    /*
        6893CE015B           | push 0x5b01ce93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 ce 01 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileAttributesExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileAttributesExA"

    /*
        684C2365B1           | push 0xb165234c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 23 65 b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileAttributesExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileAttributesExW"

    /*
        684C2315B2           | push 0xb215234c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 23 15 b2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileAttributesTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileAttributesTransactedA"

    /*
        6877348040           | push 0x40803477
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 34 80 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileAttributesTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileAttributesTransactedW"

    /*
        6877343041           | push 0x41303477
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 34 30 41 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileAttributesW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileAttributesW"

    /*
        6893CEB15B           | push 0x5bb1ce93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 ce b1 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileBandwidthReservation
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileBandwidthReservation"

    /*
        68187D0BD3           | push 0xd30b7d18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 7d 0b d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileInformationByHandle
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileInformationByHandle"

    /*
        6873174DEF           | push 0xef4d1773
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 17 4d ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileInformationByHandleEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileInformationByHandleEx"

    /*
        68714EEFBD           | push 0xbdef4e71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 4e ef bd ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileMUIInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileMUIInfo"

    /*
        687A4D90CB           | push 0xcb904d7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 4d 90 cb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileMUIPath
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileMUIPath"

    /*
        68FAC058B1           | push 0xb158c0fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa c0 58 b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileSize
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileSize"

    /*
        68C6121E70           | push 0x701e12c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 12 1e 70 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileSizeEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileSizeEx"

    /*
        6851232EF2           | push 0xf22e2351
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 23 2e f2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileTime"

    /*
        68861F1E70           | push 0x701e1f86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 1f 1e 70 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFileType
{
    meta:
        desc = "Metasploit::API::kernel32::GetFileType"

    /*
        6846201E90           | push 0x901e2046
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 20 1e 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFinalPathNameByHandleA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFinalPathNameByHandleA"

    /*
        682BDA3511           | push 0x1135da2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b da 35 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFinalPathNameByHandleW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFinalPathNameByHandleW"

    /*
        682BDAE511           | push 0x11e5da2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b da e5 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFirmwareEnvironmentVariableA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFirmwareEnvironmentVariableA"

    /*
        68F23F8DE1           | push 0xe18d3ff2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 3f 8d e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFirmwareEnvironmentVariableExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFirmwareEnvironmentVariableExA"

    /*
        68ED7A4154           | push 0x54417aed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 7a 41 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFirmwareEnvironmentVariableExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFirmwareEnvironmentVariableExW"

    /*
        68ED7AF154           | push 0x54f17aed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 7a f1 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFirmwareEnvironmentVariableW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFirmwareEnvironmentVariableW"

    /*
        68F23F3DE2           | push 0xe23d3ff2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 3f 3d e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFirmwareType
{
    meta:
        desc = "Metasploit::API::kernel32::GetFirmwareType"

    /*
        68B37F7B1B           | push 0x1b7b7fb3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 7f 7b 1b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFullPathNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFullPathNameA"

    /*
        683AA68095           | push 0x9580a63a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a a6 80 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFullPathNameTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::GetFullPathNameTransactedA"

    /*
        6861EA1FCF           | push 0xcf1fea61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 ea 1f cf ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFullPathNameTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFullPathNameTransactedW"

    /*
        6861EACFCF           | push 0xcfcfea61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 ea cf cf ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetFullPathNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetFullPathNameW"

    /*
        683AA63096           | push 0x9630a63a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a a6 30 96 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetGeoInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::GetGeoInfoA"

    /*
        6878BF0B6A           | push 0x6a0bbf78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 bf 0b 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetGeoInfoEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetGeoInfoEx"

    /*
        68BFD265DB           | push 0xdb65d2bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf d2 65 db ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetGeoInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::GetGeoInfoW"

    /*
        6878BFBB6A           | push 0x6abbbf78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 bf bb 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetHandleInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetHandleInformation"

    /*
        68C913D35C           | push 0x5cd313c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 13 d3 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLargePageMinimum
{
    meta:
        desc = "Metasploit::API::kernel32::GetLargePageMinimum"

    /*
        6806667384           | push 0x84736606
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 66 73 84 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLargestConsoleWindowSize
{
    meta:
        desc = "Metasploit::API::kernel32::GetLargestConsoleWindowSize"

    /*
        687283C429           | push 0x29c48372
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 83 c4 29 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLastError
{
    meta:
        desc = "Metasploit::API::kernel32::GetLastError"

    /*
        68AAC5E25D           | push 0x5de2c5aa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa c5 e2 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLocalTime
{
    meta:
        desc = "Metasploit::API::kernel32::GetLocalTime"

    /*
        683EE32CD9           | push 0xd92ce33e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e e3 2c d9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLocaleInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::GetLocaleInfoA"

    /*
        689B5B6E36           | push 0x366e5b9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 5b 6e 36 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLocaleInfoEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetLocaleInfoEx"

    /*
        68D4357CBC           | push 0xbc7c35d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 35 7c bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLocaleInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::GetLocaleInfoW"

    /*
        689B5B1E37           | push 0x371e5b9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 5b 1e 37 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLogicalDriveStringsA
{
    meta:
        desc = "Metasploit::API::kernel32::GetLogicalDriveStringsA"

    /*
        687AE49ADD           | push 0xdd9ae47a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a e4 9a dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLogicalDriveStringsW
{
    meta:
        desc = "Metasploit::API::kernel32::GetLogicalDriveStringsW"

    /*
        687AE44ADE           | push 0xde4ae47a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a e4 4a de ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLogicalDrives
{
    meta:
        desc = "Metasploit::API::kernel32::GetLogicalDrives"

    /*
        68EBBC77EB           | push 0xeb77bceb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb bc 77 eb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLogicalProcessorInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetLogicalProcessorInformation"

    /*
        6813C909F5           | push 0xf509c913
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 c9 09 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLogicalProcessorInformationEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetLogicalProcessorInformationEx"

    /*
        6872B61B2D           | push 0x2d1bb672
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 b6 1b 2d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLongPathNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetLongPathNameA"

    /*
        68D8A58458           | push 0x5884a5d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 a5 84 58 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLongPathNameTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::GetLongPathNameTransactedA"

    /*
        6848EAE07F           | push 0x7fe0ea48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 ea e0 7f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLongPathNameTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::GetLongPathNameTransactedW"

    /*
        6848EA9080           | push 0x8090ea48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 ea 90 80 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetLongPathNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetLongPathNameW"

    /*
        68D8A53459           | push 0x5934a5d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 a5 34 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetMailslotInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetMailslotInfo"

    /*
        6808C7AE41           | push 0x41aec708
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 c7 ae 41 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetMaximumProcessorCount
{
    meta:
        desc = "Metasploit::API::kernel32::GetMaximumProcessorCount"

    /*
        68B2CB65C6           | push 0xc665cbb2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 cb 65 c6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetMaximumProcessorGroupCount
{
    meta:
        desc = "Metasploit::API::kernel32::GetMaximumProcessorGroupCount"

    /*
        68C9952114           | push 0x142195c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 95 21 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetMemoryErrorHandlingCapabilities
{
    meta:
        desc = "Metasploit::API::kernel32::GetMemoryErrorHandlingCapabilities"

    /*
        6845A4EB10           | push 0x10eba445
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 a4 eb 10 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetModuleFileNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetModuleFileNameA"

    /*
        685D4461FE           | push 0xfe61445d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 44 61 fe ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetModuleFileNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetModuleFileNameW"

    /*
        685D4411FF           | push 0xff11445d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 44 11 ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetModuleHandleA
{
    meta:
        desc = "Metasploit::API::kernel32::GetModuleHandleA"

    /*
        686CB0D5DA           | push 0xdad5b06c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c b0 d5 da ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetModuleHandleExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetModuleHandleExA"

    /*
        686C995DA6           | push 0xa65d996c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 99 5d a6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetModuleHandleExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetModuleHandleExW"

    /*
        686C990DA7           | push 0xa70d996c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 99 0d a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetModuleHandleW
{
    meta:
        desc = "Metasploit::API::kernel32::GetModuleHandleW"

    /*
        686CB085DB           | push 0xdb85b06c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c b0 85 db ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNLSVersion
{
    meta:
        desc = "Metasploit::API::kernel32::GetNLSVersion"

    /*
        68F7D32461           | push 0x6124d3f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 d3 24 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNLSVersionEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetNLSVersionEx"

    /*
        688D6FDE33           | push 0x33de6f8d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 6f de 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeAttribute
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeAttribute"

    /*
        68546C9AE2           | push 0xe29a6c54
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 6c 9a e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeClientComputerNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeClientComputerNameA"

    /*
        68B51587FD           | push 0xfd8715b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 15 87 fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeClientComputerNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeClientComputerNameW"

    /*
        68B51537FE           | push 0xfe3715b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 15 37 fe ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeClientProcessId
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeClientProcessId"

    /*
        686F51D40B           | push 0x0bd4516f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 51 d4 0b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeClientSessionId
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeClientSessionId"

    /*
        68F12914F5           | push 0xf51429f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 29 14 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeHandleStateA
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeHandleStateA"

    /*
        689457A8F3           | push 0xf3a85794
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 57 a8 f3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeHandleStateW
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeHandleStateW"

    /*
        68945758F4           | push 0xf4585794
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 57 58 f4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeInfo"

    /*
        68E3C3114C           | push 0x4c11c3e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 c3 11 4c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeServerProcessId
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeServerProcessId"

    /*
        6880364290           | push 0x90423680
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 36 42 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNamedPipeServerSessionId
{
    meta:
        desc = "Metasploit::API::kernel32::GetNamedPipeServerSessionId"

    /*
        68020F8279           | push 0x79820f02
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 0f 82 79 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNativeSystemInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetNativeSystemInfo"

    /*
        6833009E95           | push 0x959e0033
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 00 9e 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNextUmsListItem
{
    meta:
        desc = "Metasploit::API::kernel32::GetNextUmsListItem"

    /*
        680204CB1A           | push 0x1acb0402
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 04 cb 1a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNextVDMCommand
{
    meta:
        desc = "Metasploit::API::kernel32::GetNextVDMCommand"

    /*
        68CD6C625A           | push 0x5a626ccd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 6c 62 5a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaAvailableMemoryNode
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaAvailableMemoryNode"

    /*
        68BE0B65B4           | push 0xb4650bbe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 0b 65 b4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaAvailableMemoryNodeEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaAvailableMemoryNodeEx"

    /*
        682261EC03           | push 0x03ec6122
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 61 ec 03 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaHighestNodeNumber
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaHighestNodeNumber"

    /*
        685D515C48           | push 0x485c515d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 51 5c 48 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaNodeNumberFromHandle
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaNodeNumberFromHandle"

    /*
        688E5B2048           | push 0x48205b8e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 5b 20 48 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaNodeProcessorMask
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaNodeProcessorMask"

    /*
        68C1FA21AB           | push 0xab21fac1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 fa 21 ab ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaNodeProcessorMaskEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaNodeProcessorMaskEx"

    /*
        68E02128B3           | push 0xb32821e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 21 28 b3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaProcessorNode
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaProcessorNode"

    /*
        682F9EF0FE           | push 0xfef09e2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 9e f0 fe ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaProcessorNodeEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaProcessorNodeEx"

    /*
        6875FDD0A6           | push 0xa6d0fd75
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 fd d0 a6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaProximityNode
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaProximityNode"

    /*
        68F8BC04B9           | push 0xb904bcf8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 bc 04 b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumaProximityNodeEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumaProximityNodeEx"

    /*
        68A3AFD82B           | push 0x2bd8afa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 af d8 2b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumberFormatA
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumberFormatA"

    /*
        68490CA012           | push 0x12a00c49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 0c a0 12 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumberFormatEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumberFormatEx"

    /*
        686117EB41           | push 0x41eb1761
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 17 eb 41 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumberFormatW
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumberFormatW"

    /*
        68490C5013           | push 0x13500c49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 0c 50 13 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumberOfConsoleFonts
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumberOfConsoleFonts"

    /*
        6881F884DB           | push 0xdb84f881
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 f8 84 db ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumberOfConsoleInputEvents
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumberOfConsoleInputEvents"

    /*
        688DB704BB           | push 0xbb04b78d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d b7 04 bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetNumberOfConsoleMouseButtons
{
    meta:
        desc = "Metasploit::API::kernel32::GetNumberOfConsoleMouseButtons"

    /*
        682FA8DE42           | push 0x42dea82f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f a8 de 42 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetOEMCP
{
    meta:
        desc = "Metasploit::API::kernel32::GetOEMCP"

    /*
        68628403F8           | push 0xf8038462
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 84 03 f8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetOverlappedResult
{
    meta:
        desc = "Metasploit::API::kernel32::GetOverlappedResult"

    /*
        68181BF579           | push 0x79f51b18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 1b f5 79 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetOverlappedResultEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetOverlappedResultEx"

    /*
        68D337F067           | push 0x67f037d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 37 f0 67 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackageApplicationIds
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackageApplicationIds"

    /*
        689753BE5B           | push 0x5bbe5397
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 53 be 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackageFamilyName
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackageFamilyName"

    /*
        688AA63CE5           | push 0xe53ca68a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a a6 3c e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackageFullName
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackageFullName"

    /*
        68EDD606A4           | push 0xa406d6ed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed d6 06 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackageId
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackageId"

    /*
        68382A4E43           | push 0x434e2a38
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 2a 4e 43 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackageInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackageInfo"

    /*
        680608ECD1           | push 0xd1ec0806
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 08 ec d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackagePath
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackagePath"

    /*
        68867BB4B7           | push 0xb7b47b86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 7b b4 b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackagePathByFullName
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackagePathByFullName"

    /*
        682C42D128           | push 0x28d1422c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 42 d1 28 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPackagesByPackageFamily
{
    meta:
        desc = "Metasploit::API::kernel32::GetPackagesByPackageFamily"

    /*
        68947BD875           | push 0x75d87b94
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 7b d8 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPhysicallyInstalledSystemMemory
{
    meta:
        desc = "Metasploit::API::kernel32::GetPhysicallyInstalledSystemMemory"

    /*
        680531368B           | push 0x8b363105
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 31 36 8b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPriorityClass
{
    meta:
        desc = "Metasploit::API::kernel32::GetPriorityClass"

    /*
        68856950CC           | push 0xcc506985
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 69 50 cc ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileIntA
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileIntA"

    /*
        683F3F9E37           | push 0x379e3f3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 3f 9e 37 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileIntW
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileIntW"

    /*
        683F3F4E38           | push 0x384e3f3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 3f 4e 38 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileSectionA
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileSectionA"

    /*
        68A31B00EF           | push 0xef001ba3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 1b 00 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileSectionNamesA
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileSectionNamesA"

    /*
        682F861A8D           | push 0x8d1a862f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 86 1a 8d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileSectionNamesW
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileSectionNamesW"

    /*
        682F86CA8D           | push 0x8dca862f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 86 ca 8d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileSectionW
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileSectionW"

    /*
        68A31BB0EF           | push 0xefb01ba3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 1b b0 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileStringA
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileStringA"

    /*
        682A901B3C           | push 0x3c1b902a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 90 1b 3c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileStringW
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileStringW"

    /*
        682A90CB3C           | push 0x3ccb902a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 90 cb 3c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileStructA
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileStructA"

    /*
        686A531C26           | push 0x261c536a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 53 1c 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetPrivateProfileStructW
{
    meta:
        desc = "Metasploit::API::kernel32::GetPrivateProfileStructW"

    /*
        686A53CC26           | push 0x26cc536a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 53 cc 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcAddress
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcAddress"

    /*
        6849F70278           | push 0x7802f749
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 f7 02 78 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessAffinityMask
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessAffinityMask"

    /*
        68C94D43FF           | push 0xff434dc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 4d 43 ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessDEPPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessDEPPolicy"

    /*
        68ED6DB87A           | push 0x7ab86ded
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 6d b8 7a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessDefaultCpuSets
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessDefaultCpuSets"

    /*
        68000D4F6F           | push 0x6f4f0d00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 0d 4f 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessGroupAffinity
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessGroupAffinity"

    /*
        68CC5CB914           | push 0x14b95ccc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 5c b9 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessHandleCount
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessHandleCount"

    /*
        68E8A692A4           | push 0xa492a6e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 a6 92 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessHeap
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessHeap"

    /*
        68515724F8           | push 0xf8245751
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 57 24 f8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessHeaps
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessHeaps"

    /*
        688442029A           | push 0x9a024284
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 42 02 9a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessId
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessId"

    /*
        68BAEB2E70           | push 0x702eebba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba eb 2e 70 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessIdOfThread
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessIdOfThread"

    /*
        68E3DB0391           | push 0x9103dbe3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 db 03 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessInformation"

    /*
        68FAB784D7           | push 0xd784b7fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa b7 84 d7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessIoCounters
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessIoCounters"

    /*
        6846590086           | push 0x86005946
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 59 00 86 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessMitigationPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessMitigationPolicy"

    /*
        68969F5C2D           | push 0x2d5c9f96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 9f 5c 2d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessPreferredUILanguages"

    /*
        689CFBF3BB           | push 0xbbf3fb9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c fb f3 bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessPriorityBoost
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessPriorityBoost"

    /*
        68377E514D           | push 0x4d517e37
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 7e 51 4d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessShutdownParameters
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessShutdownParameters"

    /*
        68E0FC38E4           | push 0xe438fce0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 fc 38 e4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessTimes
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessTimes"

    /*
        68CA7F02B2           | push 0xb2027fca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 7f 02 b2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessVersion
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessVersion"

    /*
        68E44EEAD6           | push 0xd6ea4ee4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 4e ea d6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessWorkingSetSize
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessWorkingSetSize"

    /*
        683D6DC7EE           | push 0xeec76d3d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 6d c7 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessWorkingSetSizeEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessWorkingSetSizeEx"

    /*
        68F1C0849C           | push 0x9c84c0f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 c0 84 9c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProcessorSystemCycleTime
{
    meta:
        desc = "Metasploit::API::kernel32::GetProcessorSystemCycleTime"

    /*
        68DF7D9858           | push 0x58987ddf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 7d 98 58 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProductInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetProductInfo"

    /*
        68916ADC8A           | push 0x8adc6a91
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 6a dc 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProfileIntA
{
    meta:
        desc = "Metasploit::API::kernel32::GetProfileIntA"

    /*
        688A6C900B           | push 0x0b906c8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 6c 90 0b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProfileIntW
{
    meta:
        desc = "Metasploit::API::kernel32::GetProfileIntW"

    /*
        688A6C400C           | push 0x0c406c8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 6c 40 0c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProfileSectionA
{
    meta:
        desc = "Metasploit::API::kernel32::GetProfileSectionA"

    /*
        68E2C8D411           | push 0x11d4c8e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 c8 d4 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProfileSectionW
{
    meta:
        desc = "Metasploit::API::kernel32::GetProfileSectionW"

    /*
        68E2C88412           | push 0x1284c8e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 c8 84 12 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProfileStringA
{
    meta:
        desc = "Metasploit::API::kernel32::GetProfileStringA"

    /*
        688574C3D1           | push 0xd1c37485
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 74 c3 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetProfileStringW
{
    meta:
        desc = "Metasploit::API::kernel32::GetProfileStringW"

    /*
        68857473D2           | push 0xd2737485
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 74 73 d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetQueuedCompletionStatus
{
    meta:
        desc = "Metasploit::API::kernel32::GetQueuedCompletionStatus"

    /*
        686D28A7B7           | push 0xb7a7286d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 28 a7 b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetQueuedCompletionStatusEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetQueuedCompletionStatusEx"

    /*
        68E38C73D4           | push 0xd4738ce3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 8c 73 d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetShortPathNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetShortPathNameA"

    /*
        681524AA86           | push 0x86aa2415
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 24 aa 86 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetShortPathNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetShortPathNameW"

    /*
        6815245A87           | push 0x875a2415
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 24 5a 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStagedPackagePathByFullName
{
    meta:
        desc = "Metasploit::API::kernel32::GetStagedPackagePathByFullName"

    /*
        6816952E54           | push 0x542e9516
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 95 2e 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStartupInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::GetStartupInfoA"

    /*
        68B14A6BB1           | push 0xb16b4ab1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 4a 6b b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStartupInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::GetStartupInfoW"

    /*
        68B14A1BB2           | push 0xb21b4ab1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 4a 1b b2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStateFolder
{
    meta:
        desc = "Metasploit::API::kernel32::GetStateFolder"

    /*
        684F288886           | push 0x8688284f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 28 88 86 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStdHandle
{
    meta:
        desc = "Metasploit::API::kernel32::GetStdHandle"

    /*
        6818BBCA53           | push 0x53cabb18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 bb ca 53 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStringScripts
{
    meta:
        desc = "Metasploit::API::kernel32::GetStringScripts"

    /*
        68DB158AE9           | push 0xe98a15db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db 15 8a e9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStringTypeA
{
    meta:
        desc = "Metasploit::API::kernel32::GetStringTypeA"

    /*
        6862818512           | push 0x12858162
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 81 85 12 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStringTypeExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetStringTypeExA"

    /*
        68F9D65192           | push 0x9251d6f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 d6 51 92 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStringTypeExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetStringTypeExW"

    /*
        68FAD60193           | push 0x9301d6fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa d6 01 93 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetStringTypeW
{
    meta:
        desc = "Metasploit::API::kernel32::GetStringTypeW"

    /*
        6862813513           | push 0x13358162
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 81 35 13 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemAppDataKey
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemAppDataKey"

    /*
        68E42C7452           | push 0x52742ce4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 2c 74 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemCpuSetInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemCpuSetInformation"

    /*
        687C864D3A           | push 0x3a4d867c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 86 4d 3a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemDEPPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemDEPPolicy"

    /*
        686008401B           | push 0x1b400860
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 08 40 1b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemDefaultLCID
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemDefaultLCID"

    /*
        6889CB0ADE           | push 0xde0acb89
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 89 cb 0a de ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemDefaultLangID
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemDefaultLangID"

    /*
        68FCA4BEB1           | push 0xb1bea4fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc a4 be b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemDefaultLocaleName
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemDefaultLocaleName"

    /*
        685CA34AC6           | push 0xc64aa35c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c a3 4a c6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemDefaultUILanguage"

    /*
        68DFE153EF           | push 0xef53e1df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df e1 53 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemDirectoryA"

    /*
        6805DEBC60           | push 0x60bcde05
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 de bc 60 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemDirectoryW"

    /*
        6805DE6C61           | push 0x616cde05
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 de 6c 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemFileCacheSize
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemFileCacheSize"

    /*
        685F6F3FAD           | push 0xad3f6f5f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 6f 3f ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemFirmwareTable
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemFirmwareTable"

    /*
        68B8ED411F           | push 0x1f41edb8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 ed 41 1f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemInfo"

    /*
        68769D2B4B           | push 0x4b2b9d76
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 9d 2b 4b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemPowerStatus
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemPowerStatus"

    /*
        682CAE38C5           | push 0xc538ae2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c ae 38 c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemPreferredUILanguages"

    /*
        68AB3CD9F0           | push 0xf0d93cab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 3c d9 f0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemRegistryQuota
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemRegistryQuota"

    /*
        68760F5DD2           | push 0xd25d0f76
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 0f 5d d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemTime
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemTime"

    /*
        68364FDC40           | push 0x40dc4f36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 4f dc 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemTimeAdjustment
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemTimeAdjustment"

    /*
        685C7FB037           | push 0x37b07f5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 7f b0 37 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemTimeAsFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemTimeAsFileTime"

    /*
        6895651B9B           | push 0x9b1b6595
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 65 1b 9b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemTimePreciseAsFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemTimePreciseAsFileTime"

    /*
        682070B7B6           | push 0xb6b77020
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 70 b7 b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemTimes
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemTimes"

    /*
        6843882C59           | push 0x592c8843
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 88 2c 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemWindowsDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemWindowsDirectoryA"

    /*
        682A940A73           | push 0x730a942a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 94 0a 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemWindowsDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemWindowsDirectoryW"

    /*
        682A94BA73           | push 0x73ba942a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 94 ba 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemWow64DirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemWow64DirectoryA"

    /*
        6871EB6EC2           | push 0xc26eeb71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 eb 6e c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetSystemWow64DirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::GetSystemWow64DirectoryW"

    /*
        6871EB1EC3           | push 0xc31eeb71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 eb 1e c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTapeParameters
{
    meta:
        desc = "Metasploit::API::kernel32::GetTapeParameters"

    /*
        6808E1B505           | push 0x05b5e108
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 e1 b5 05 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTapePosition
{
    meta:
        desc = "Metasploit::API::kernel32::GetTapePosition"

    /*
        681442B954           | push 0x54b94214
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 42 b9 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTapeStatus
{
    meta:
        desc = "Metasploit::API::kernel32::GetTapeStatus"

    /*
        685A5F0414           | push 0x14045f5a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5a 5f 04 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTempFileNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetTempFileNameA"

    /*
        683B5476A4           | push 0xa476543b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 54 76 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTempFileNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetTempFileNameW"

    /*
        683B5426A5           | push 0xa526543b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 54 26 a5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTempPathA
{
    meta:
        desc = "Metasploit::API::kernel32::GetTempPathA"

    /*
        6830F349E4           | push 0xe449f330
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 f3 49 e4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTempPathW
{
    meta:
        desc = "Metasploit::API::kernel32::GetTempPathW"

    /*
        6830F3F9E4           | push 0xe4f9f330
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 f3 f9 e4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadContext
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadContext"

    /*
        68185C42D1           | push 0xd1425c18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 5c 42 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadDescription
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadDescription"

    /*
        681F80400B           | push 0x0b40801f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 80 40 0b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadErrorMode
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadErrorMode"

    /*
        68F0DF91B3           | push 0xb391dff0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 df 91 b3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadGroupAffinity
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadGroupAffinity"

    /*
        68CC64110A           | push 0x0a1164cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 64 11 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadIOPendingFlag
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadIOPendingFlag"

    /*
        6837CE6033           | push 0x3360ce37
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 ce 60 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadId
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadId"

    /*
        6866E62E74           | push 0x742ee666
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 e6 2e 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadIdealProcessorEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadIdealProcessorEx"

    /*
        68576BA50F           | push 0x0fa56b57
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 6b a5 0f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadInformation"

    /*
        681A185AD7           | push 0xd75a181a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 18 5a d7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadLocale
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadLocale"

    /*
        68F82FE2D4           | push 0xd4e22ff8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 2f e2 d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadPreferredUILanguages"

    /*
        689AFBF466           | push 0x66f4fb9a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a fb f4 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadPriority
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadPriority"

    /*
        68D1DB552F           | push 0x2f55dbd1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 db 55 2f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadPriorityBoost
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadPriorityBoost"

    /*
        683786A942           | push 0x42a98637
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 86 a9 42 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadSelectedCpuSets
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadSelectedCpuSets"

    /*
        68CB5E4683           | push 0x83465ecb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 5e 46 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadSelectorEntry
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadSelectorEntry"

    /*
        6886FC3A59           | push 0x593afc86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 fc 3a 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadTimes
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadTimes"

    /*
        68BF7F0A0A           | push 0x0a0a7fbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 7f 0a 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetThreadUILanguage
{
    meta:
        desc = "Metasploit::API::kernel32::GetThreadUILanguage"

    /*
        68C13477B2           | push 0xb27734c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 34 77 b2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTickCount
{
    meta:
        desc = "Metasploit::API::kernel32::GetTickCount"

    /*
        6869D3CE6B           | push 0x6bced369
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 d3 ce 6b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTickCount64
{
    meta:
        desc = "Metasploit::API::kernel32::GetTickCount64"

    /*
        6850483EDC           | push 0xdc3e4850
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 48 3e dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTimeFormatA
{
    meta:
        desc = "Metasploit::API::kernel32::GetTimeFormatA"

    /*
        682E98A630           | push 0x30a6982e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 98 a6 30 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTimeFormatAWorker
{
    meta:
        desc = "Metasploit::API::kernel32::GetTimeFormatAWorker"

    /*
        6830C8F4F2           | push 0xf2f4c830
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 c8 f4 f2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTimeFormatEx
{
    meta:
        desc = "Metasploit::API::kernel32::GetTimeFormatEx"

    /*
        68960714A1           | push 0xa1140796
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 07 14 a1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTimeFormatW
{
    meta:
        desc = "Metasploit::API::kernel32::GetTimeFormatW"

    /*
        682E985631           | push 0x3156982e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 98 56 31 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTimeFormatWWorker
{
    meta:
        desc = "Metasploit::API::kernel32::GetTimeFormatWWorker"

    /*
        68F0CAF4F2           | push 0xf2f4caf0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 ca f4 f2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetTimeZoneInformation"

    /*
        680EA049AB           | push 0xab49a00e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e a0 49 ab ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetTimeZoneInformationForYear
{
    meta:
        desc = "Metasploit::API::kernel32::GetTimeZoneInformationForYear"

    /*
        6896EE5175           | push 0x7551ee96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 ee 51 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUILanguageInfo
{
    meta:
        desc = "Metasploit::API::kernel32::GetUILanguageInfo"

    /*
        68CF5F738E           | push 0x8e735fcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 5f 73 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUmsCompletionListEvent
{
    meta:
        desc = "Metasploit::API::kernel32::GetUmsCompletionListEvent"

    /*
        685C0BF018           | push 0x18f00b5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 0b f0 18 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUmsSystemThreadInformation
{
    meta:
        desc = "Metasploit::API::kernel32::GetUmsSystemThreadInformation"

    /*
        686C71991E           | push 0x1e99716c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 71 99 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUserDefaultGeoName
{
    meta:
        desc = "Metasploit::API::kernel32::GetUserDefaultGeoName"

    /*
        685CFD7F66           | push 0x667ffd5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c fd 7f 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUserDefaultLCID
{
    meta:
        desc = "Metasploit::API::kernel32::GetUserDefaultLCID"

    /*
        6861FEC4A2           | push 0xa2c4fe61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 fe c4 a2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUserDefaultLangID
{
    meta:
        desc = "Metasploit::API::kernel32::GetUserDefaultLangID"

    /*
        68ED5A4BE0           | push 0xe04b5aed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 5a 4b e0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUserDefaultLocaleName
{
    meta:
        desc = "Metasploit::API::kernel32::GetUserDefaultLocaleName"

    /*
        6844B6A991           | push 0x91a9b644
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 b6 a9 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUserDefaultUILanguage
{
    meta:
        desc = "Metasploit::API::kernel32::GetUserDefaultUILanguage"

    /*
        68C8F4B2BA           | push 0xbab2f4c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 f4 b2 ba ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUserGeoID
{
    meta:
        desc = "Metasploit::API::kernel32::GetUserGeoID"

    /*
        686B326A68           | push 0x686a326b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 32 6a 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetUserPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::kernel32::GetUserPreferredUILanguages"

    /*
        68D1FA6FC2           | push 0xc26ffad1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 fa 6f c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVDMCurrentDirectories
{
    meta:
        desc = "Metasploit::API::kernel32::GetVDMCurrentDirectories"

    /*
        68976EA964           | push 0x64a96e97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 6e a9 64 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVersion
{
    meta:
        desc = "Metasploit::API::kernel32::GetVersion"

    /*
        68A695BD9D           | push 0x9dbd95a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 95 bd 9d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVersionExA
{
    meta:
        desc = "Metasploit::API::kernel32::GetVersionExA"

    /*
        68D851CDB6           | push 0xb6cd51d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 51 cd b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVersionExW
{
    meta:
        desc = "Metasploit::API::kernel32::GetVersionExW"

    /*
        68D8517DB7           | push 0xb77d51d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 51 7d b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumeInformationA
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumeInformationA"

    /*
        686C6CB39F           | push 0x9fb36c6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 6c b3 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumeInformationByHandleW
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumeInformationByHandleW"

    /*
        68A785FE79           | push 0x79fe85a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 85 fe 79 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumeInformationW
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumeInformationW"

    /*
        686C6C63A0           | push 0xa0636c6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 6c 63 a0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumeNameForVolumeMountPointA
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumeNameForVolumeMountPointA"

    /*
        6848FE81E9           | push 0xe981fe48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 fe 81 e9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumeNameForVolumeMountPointW
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumeNameForVolumeMountPointW"

    /*
        6848FE31EA           | push 0xea31fe48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 fe 31 ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumePathNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumePathNameA"

    /*
        685E956F1A           | push 0x1a6f955e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 95 6f 1a ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumePathNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumePathNameW"

    /*
        685E951F1B           | push 0x1b1f955e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 95 1f 1b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumePathNamesForVolumeNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumePathNamesForVolumeNameA"

    /*
        6843DF7B1F           | push 0x1f7bdf43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 df 7b 1f ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetVolumePathNamesForVolumeNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GetVolumePathNamesForVolumeNameW"

    /*
        6843DF2B20           | push 0x202bdf43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 df 2b 20 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetWindowsDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::GetWindowsDirectoryA"

    /*
        6840DE1E72           | push 0x721ede40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 de 1e 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetWindowsDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::GetWindowsDirectoryW"

    /*
        6840DECE72           | push 0x72cede40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 de ce 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetWriteWatch
{
    meta:
        desc = "Metasploit::API::kernel32::GetWriteWatch"

    /*
        68ACE4F44C           | push 0x4cf4e4ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac e4 f4 4c ff d5 }

    condition:
        any of them
}

    
rule kernel32_GetXStateFeaturesMask
{
    meta:
        desc = "Metasploit::API::kernel32::GetXStateFeaturesMask"

    /*
        6837F18748           | push 0x4887f137
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 f1 87 48 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalAddAtomA
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalAddAtomA"

    /*
        68C40117AC           | push 0xac1701c4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 01 17 ac ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalAddAtomExA
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalAddAtomExA"

    /*
        6860EFB1F6           | push 0xf6b1ef60
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 ef b1 f6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalAddAtomExW
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalAddAtomExW"

    /*
        6860EF61F7           | push 0xf761ef60
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 ef 61 f7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalAddAtomW
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalAddAtomW"

    /*
        68C401C7AC           | push 0xacc701c4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 01 c7 ac ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalAlloc"

    /*
        68F6760F52           | push 0x520f76f6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 76 0f 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalCompact
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalCompact"

    /*
        680A4773EA           | push 0xea73470a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 47 73 ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalDeleteAtom
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalDeleteAtom"

    /*
        689C390F1E           | push 0x1e0f399c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 39 0f 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalFindAtomA
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalFindAtomA"

    /*
        683F669475           | push 0x7594663f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 66 94 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalFindAtomW
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalFindAtomW"

    /*
        683F664476           | push 0x7644663f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 66 44 76 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalFix
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalFix"

    /*
        682B370010           | push 0x1000372b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 37 00 10 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalFlags
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalFlags"

    /*
        68F9748FBC           | push 0xbc8f74f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 74 8f bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalFree
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalFree"

    /*
        68A3FC62AA           | push 0xaa62fca3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 fc 62 aa ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalGetAtomNameA
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalGetAtomNameA"

    /*
        681BE26D6D           | push 0x6d6de21b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b e2 6d 6d ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalGetAtomNameW
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalGetAtomNameW"

    /*
        681BE21D6E           | push 0x6e1de21b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b e2 1d 6e ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalHandle
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalHandle"

    /*
        681734D900           | push 0x00d93417
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 34 d9 00 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalLock
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalLock"

    /*
        68235C93A4           | push 0xa4935c23
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 5c 93 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalMemoryStatus
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalMemoryStatus"

    /*
        68CD5797BA           | push 0xba9757cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 57 97 ba ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalMemoryStatusEx
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalMemoryStatusEx"

    /*
        68E3647F90           | push 0x907f64e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 64 7f 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalReAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalReAlloc"

    /*
        68D40BC3FF           | push 0xffc30bd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 0b c3 ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalSize
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalSize"

    /*
        68E3D16398           | push 0x9863d1e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 d1 63 98 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalUnWire
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalUnWire"

    /*
        689DC50B8B           | push 0x8b0bc59d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d c5 0b 8b ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalUnfix
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalUnfix"

    /*
        688095B746           | push 0x46b79580
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 95 b7 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalUnlock
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalUnlock"

    /*
        68DE113D97           | push 0x973d11de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 11 3d 97 ff d5 }

    condition:
        any of them
}

    
rule kernel32_GlobalWire
{
    meta:
        desc = "Metasploit::API::kernel32::GlobalWire"

    /*
        68E30F6498           | push 0x98640fe3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 0f 64 98 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Heap32First
{
    meta:
        desc = "Metasploit::API::kernel32::Heap32First"

    /*
        6837D2B02B           | push 0x2bb0d237
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 d2 b0 2b ff d5 }

    condition:
        any of them
}

    
rule kernel32_Heap32ListFirst
{
    meta:
        desc = "Metasploit::API::kernel32::Heap32ListFirst"

    /*
        6834CD0F96           | push 0x960fcd34
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 cd 0f 96 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Heap32ListNext
{
    meta:
        desc = "Metasploit::API::kernel32::Heap32ListNext"

    /*
        6852D882A1           | push 0xa182d852
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 d8 82 a1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Heap32Next
{
    meta:
        desc = "Metasploit::API::kernel32::Heap32Next"

    /*
        68064B23C2           | push 0xc2234b06
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 4b 23 c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::HeapAlloc"

    /*
        68DB3E9054           | push 0x54903edb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db 3e 90 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapCompact
{
    meta:
        desc = "Metasploit::API::kernel32::HeapCompact"

    /*
        684A40A58A           | push 0x8aa5404a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 40 a5 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapCreate
{
    meta:
        desc = "Metasploit::API::kernel32::HeapCreate"

    /*
        6826BAECB9           | push 0xb9ecba26
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 ba ec b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapDestroy
{
    meta:
        desc = "Metasploit::API::kernel32::HeapDestroy"

    /*
        686E83A5AC           | push 0xaca5836e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e 83 a5 ac ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapFree
{
    meta:
        desc = "Metasploit::API::kernel32::HeapFree"

    /*
        68F39C5FC3           | push 0xc35f9cf3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 9c 5f c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapLock
{
    meta:
        desc = "Metasploit::API::kernel32::HeapLock"

    /*
        6873FC8FBD           | push 0xbd8ffc73
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 fc 8f bd ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapQueryInformation
{
    meta:
        desc = "Metasploit::API::kernel32::HeapQueryInformation"

    /*
        684A1A034B           | push 0x4b031a4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 1a 03 4b ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapReAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::HeapReAlloc"

    /*
        681505F59F           | push 0x9ff50515
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 05 f5 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapSetInformation
{
    meta:
        desc = "Metasploit::API::kernel32::HeapSetInformation"

    /*
        689D07521E           | push 0x1e52079d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 07 52 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapSize
{
    meta:
        desc = "Metasploit::API::kernel32::HeapSize"

    /*
        68337260B1           | push 0xb1607233
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 72 60 b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapSummary
{
    meta:
        desc = "Metasploit::API::kernel32::HeapSummary"

    /*
        680A16E58A           | push 0x8ae5160a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 16 e5 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapUnlock
{
    meta:
        desc = "Metasploit::API::kernel32::HeapUnlock"

    /*
        68E42565D6           | push 0xd66525e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 25 65 d6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapValidate
{
    meta:
        desc = "Metasploit::API::kernel32::HeapValidate"

    /*
        68C7045B70           | push 0x705b04c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 04 5b 70 ff d5 }

    condition:
        any of them
}

    
rule kernel32_HeapWalk
{
    meta:
        desc = "Metasploit::API::kernel32::HeapWalk"

    /*
        68B3AE90A1           | push 0xa190aeb3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 ae 90 a1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IdnToAscii
{
    meta:
        desc = "Metasploit::API::kernel32::IdnToAscii"

    /*
        68CD8BBD8B           | push 0x8bbd8bcd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 8b bd 8b ff d5 }

    condition:
        any of them
}

    
rule kernel32_IdnToNameprepUnicode
{
    meta:
        desc = "Metasploit::API::kernel32::IdnToNameprepUnicode"

    /*
        68CAE7E988           | push 0x88e9e7ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca e7 e9 88 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IdnToUnicode
{
    meta:
        desc = "Metasploit::API::kernel32::IdnToUnicode"

    /*
        685B0F60E5           | push 0xe5600f5b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 0f 60 e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitAtomTable
{
    meta:
        desc = "Metasploit::API::kernel32::InitAtomTable"

    /*
        68E25EE5F4           | push 0xf4e55ee2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 5e e5 f4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitOnceBeginInitialize
{
    meta:
        desc = "Metasploit::API::kernel32::InitOnceBeginInitialize"

    /*
        688D311D6C           | push 0x6c1d318d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 31 1d 6c ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitOnceComplete
{
    meta:
        desc = "Metasploit::API::kernel32::InitOnceComplete"

    /*
        6809D3BB5F           | push 0x5fbbd309
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 d3 bb 5f ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitOnceExecuteOnce
{
    meta:
        desc = "Metasploit::API::kernel32::InitOnceExecuteOnce"

    /*
        682DAAAF84           | push 0x84afaa2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d aa af 84 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitOnceInitialize
{
    meta:
        desc = "Metasploit::API::kernel32::InitOnceInitialize"

    /*
        68CCB9F95C           | push 0x5cf9b9cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc b9 f9 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeConditionVariable
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeConditionVariable"

    /*
        68D1411EE6           | push 0xe61e41d1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 41 1e e6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeContext
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeContext"

    /*
        68F125DE5C           | push 0x5cde25f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 25 de 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeContext2
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeContext2"

    /*
        685268FD0C           | push 0x0cfd6852
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 68 fd 0c ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeCriticalSection
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeCriticalSection"

    /*
        6836200C2B           | push 0x2b0c2036
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 20 0c 2b ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeCriticalSectionAndSpinCount
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeCriticalSectionAndSpinCount"

    /*
        688F61BDF8           | push 0xf8bd618f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 61 bd f8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeCriticalSectionEx
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeCriticalSectionEx"

    /*
        68407FB1AD           | push 0xadb17f40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 7f b1 ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeEnclave
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeEnclave"

    /*
        68ACA561D4           | push 0xd461a5ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac a5 61 d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeProcThreadAttributeList
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeProcThreadAttributeList"

    /*
        68000AAE0A           | push 0x0aae0a00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 0a ae 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeSListHead
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeSListHead"

    /*
        6873748C60           | push 0x608c7473
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 74 8c 60 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeSRWLock
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeSRWLock"

    /*
        68A6A21FF0           | push 0xf01fa2a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 a2 1f f0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InitializeSynchronizationBarrier
{
    meta:
        desc = "Metasploit::API::kernel32::InitializeSynchronizationBarrier"

    /*
        68BF3ABD0F           | push 0x0fbd3abf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 3a bd 0f ff d5 }

    condition:
        any of them
}

    
rule kernel32_InstallELAMCertificateInfo
{
    meta:
        desc = "Metasploit::API::kernel32::InstallELAMCertificateInfo"

    /*
        68A6F0E8C2           | push 0xc2e8f0a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 f0 e8 c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InterlockedFlushSList
{
    meta:
        desc = "Metasploit::API::kernel32::InterlockedFlushSList"

    /*
        682B6012EF           | push 0xef12602b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 60 12 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_InterlockedPopEntrySList
{
    meta:
        desc = "Metasploit::API::kernel32::InterlockedPopEntrySList"

    /*
        6802AF3BB1           | push 0xb13baf02
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 af 3b b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InterlockedPushEntrySList
{
    meta:
        desc = "Metasploit::API::kernel32::InterlockedPushEntrySList"

    /*
        68470A6C89           | push 0x896c0a47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 0a 6c 89 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InterlockedPushListSList
{
    meta:
        desc = "Metasploit::API::kernel32::InterlockedPushListSList"

    /*
        688A9F2C66           | push 0x662c9f8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 9f 2c 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InterlockedPushListSListEx
{
    meta:
        desc = "Metasploit::API::kernel32::InterlockedPushListSListEx"

    /*
        684E54D175           | push 0x75d1544e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 54 d1 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_InvalidateConsoleDIBits
{
    meta:
        desc = "Metasploit::API::kernel32::InvalidateConsoleDIBits"

    /*
        689950B9EB           | push 0xebb95099
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 50 b9 eb ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsBadCodePtr
{
    meta:
        desc = "Metasploit::API::kernel32::IsBadCodePtr"

    /*
        680D99EA1C           | push 0x1cea990d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 99 ea 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsBadHugeReadPtr
{
    meta:
        desc = "Metasploit::API::kernel32::IsBadHugeReadPtr"

    /*
        68B7C436EE           | push 0xee36c4b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 c4 36 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsBadHugeWritePtr
{
    meta:
        desc = "Metasploit::API::kernel32::IsBadHugeWritePtr"

    /*
        683F454BC2           | push 0xc24b453f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 45 4b c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsBadReadPtr
{
    meta:
        desc = "Metasploit::API::kernel32::IsBadReadPtr"

    /*
        68EC8AC29C           | push 0x9cc28aec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 8a c2 9c ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsBadStringPtrA
{
    meta:
        desc = "Metasploit::API::kernel32::IsBadStringPtrA"

    /*
        68DCB24172           | push 0x7241b2dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc b2 41 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsBadStringPtrW
{
    meta:
        desc = "Metasploit::API::kernel32::IsBadStringPtrW"

    /*
        68DCB2F172           | push 0x72f1b2dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc b2 f1 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsBadWritePtr
{
    meta:
        desc = "Metasploit::API::kernel32::IsBadWritePtr"

    /*
        689DB9F0F3           | push 0xf3f0b99d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d b9 f0 f3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsCalendarLeapDay
{
    meta:
        desc = "Metasploit::API::kernel32::IsCalendarLeapDay"

    /*
        6885CD65A9           | push 0xa965cd85
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 cd 65 a9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsCalendarLeapMonth
{
    meta:
        desc = "Metasploit::API::kernel32::IsCalendarLeapMonth"

    /*
        68A4BE9DAD           | push 0xad9dbea4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 be 9d ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsCalendarLeapYear
{
    meta:
        desc = "Metasploit::API::kernel32::IsCalendarLeapYear"

    /*
        688F169953           | push 0x5399168f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 16 99 53 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsDBCSLeadByte
{
    meta:
        desc = "Metasploit::API::kernel32::IsDBCSLeadByte"

    /*
        68FE2067CF           | push 0xcf6720fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 20 67 cf ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsDBCSLeadByteEx
{
    meta:
        desc = "Metasploit::API::kernel32::IsDBCSLeadByteEx"

    /*
        6829B171C4           | push 0xc471b129
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 b1 71 c4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsDebuggerPresent
{
    meta:
        desc = "Metasploit::API::kernel32::IsDebuggerPresent"

    /*
        68483264C6           | push 0xc6643248
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 32 64 c6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsEnclaveTypeSupported
{
    meta:
        desc = "Metasploit::API::kernel32::IsEnclaveTypeSupported"

    /*
        6893F2D508           | push 0x08d5f293
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 f2 d5 08 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsNLSDefinedString
{
    meta:
        desc = "Metasploit::API::kernel32::IsNLSDefinedString"

    /*
        68212599C3           | push 0xc3992521
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 25 99 c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsNativeVhdBoot
{
    meta:
        desc = "Metasploit::API::kernel32::IsNativeVhdBoot"

    /*
        68C0DFE062           | push 0x62e0dfc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 df e0 62 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsNormalizedString
{
    meta:
        desc = "Metasploit::API::kernel32::IsNormalizedString"

    /*
        68E5002638           | push 0x382600e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 00 26 38 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsProcessCritical
{
    meta:
        desc = "Metasploit::API::kernel32::IsProcessCritical"

    /*
        6834367C99           | push 0x997c3634
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 36 7c 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsProcessInJob
{
    meta:
        desc = "Metasploit::API::kernel32::IsProcessInJob"

    /*
        683B62FA0A           | push 0x0afa623b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 62 fa 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsProcessorFeaturePresent
{
    meta:
        desc = "Metasploit::API::kernel32::IsProcessorFeaturePresent"

    /*
        6832DDF299           | push 0x99f2dd32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 dd f2 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsSystemResumeAutomatic
{
    meta:
        desc = "Metasploit::API::kernel32::IsSystemResumeAutomatic"

    /*
        68415E9EE5           | push 0xe59e5e41
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 5e 9e e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsThreadAFiber
{
    meta:
        desc = "Metasploit::API::kernel32::IsThreadAFiber"

    /*
        681A1E9E76           | push 0x769e1e1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 1e 9e 76 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsThreadpoolTimerSet
{
    meta:
        desc = "Metasploit::API::kernel32::IsThreadpoolTimerSet"

    /*
        68DA31604A           | push 0x4a6031da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 31 60 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsValidCalDateTime
{
    meta:
        desc = "Metasploit::API::kernel32::IsValidCalDateTime"

    /*
        686A984DD5           | push 0xd54d986a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 98 4d d5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsValidCodePage
{
    meta:
        desc = "Metasploit::API::kernel32::IsValidCodePage"

    /*
        68E13049A8           | push 0xa84930e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 30 49 a8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsValidLanguageGroup
{
    meta:
        desc = "Metasploit::API::kernel32::IsValidLanguageGroup"

    /*
        6862889803           | push 0x03988862
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 88 98 03 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsValidLocale
{
    meta:
        desc = "Metasploit::API::kernel32::IsValidLocale"

    /*
        68DBD53CA7           | push 0xa73cd5db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db d5 3c a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsValidLocaleName
{
    meta:
        desc = "Metasploit::API::kernel32::IsValidLocaleName"

    /*
        686323CC33           | push 0x33cc2363
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 23 cc 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsValidNLSVersion
{
    meta:
        desc = "Metasploit::API::kernel32::IsValidNLSVersion"

    /*
        688A5AF933           | push 0x33f95a8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 5a f9 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsWow64GuestMachineSupported
{
    meta:
        desc = "Metasploit::API::kernel32::IsWow64GuestMachineSupported"

    /*
        68690F0EFA           | push 0xfa0e0f69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 0f 0e fa ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsWow64Process
{
    meta:
        desc = "Metasploit::API::kernel32::IsWow64Process"

    /*
        6860477610           | push 0x10764760
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 47 76 10 ff d5 }

    condition:
        any of them
}

    
rule kernel32_IsWow64Process2
{
    meta:
        desc = "Metasploit::API::kernel32::IsWow64Process2"

    /*
        6813057318           | push 0x18730513
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 05 73 18 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32EmptyWorkingSet
{
    meta:
        desc = "Metasploit::API::kernel32::K32EmptyWorkingSet"

    /*
        68A8E2E25B           | push 0x5be2e2a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 e2 e2 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32EnumDeviceDrivers
{
    meta:
        desc = "Metasploit::API::kernel32::K32EnumDeviceDrivers"

    /*
        68B5D6F506           | push 0x06f5d6b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 d6 f5 06 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32EnumPageFilesA
{
    meta:
        desc = "Metasploit::API::kernel32::K32EnumPageFilesA"

    /*
        683226E7BE           | push 0xbee72632
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 26 e7 be ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32EnumPageFilesW
{
    meta:
        desc = "Metasploit::API::kernel32::K32EnumPageFilesW"

    /*
        68322697BF           | push 0xbf972632
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 26 97 bf ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32EnumProcessModules
{
    meta:
        desc = "Metasploit::API::kernel32::K32EnumProcessModules"

    /*
        687750B03E           | push 0x3eb05077
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 50 b0 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32EnumProcessModulesEx
{
    meta:
        desc = "Metasploit::API::kernel32::K32EnumProcessModulesEx"

    /*
        68858FBD96           | push 0x96bd8f85
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 8f bd 96 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32EnumProcesses
{
    meta:
        desc = "Metasploit::API::kernel32::K32EnumProcesses"

    /*
        682FBD9233           | push 0x3392bd2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f bd 92 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetDeviceDriverBaseNameA
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetDeviceDriverBaseNameA"

    /*
        68AD26140E           | push 0x0e1426ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 26 14 0e ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetDeviceDriverBaseNameW
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetDeviceDriverBaseNameW"

    /*
        68AD26C40E           | push 0x0ec426ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 26 c4 0e ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetDeviceDriverFileNameA
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetDeviceDriverFileNameA"

    /*
        68CD451416           | push 0x161445cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 45 14 16 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetDeviceDriverFileNameW
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetDeviceDriverFileNameW"

    /*
        68CD45C416           | push 0x16c445cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 45 c4 16 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetMappedFileNameA
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetMappedFileNameA"

    /*
        6810F078F4           | push 0xf478f010
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 f0 78 f4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetMappedFileNameW
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetMappedFileNameW"

    /*
        6810F028F5           | push 0xf528f010
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 f0 28 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetModuleBaseNameA
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetModuleBaseNameA"

    /*
        6840098726           | push 0x26870940
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 09 87 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetModuleBaseNameW
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetModuleBaseNameW"

    /*
        6840093727           | push 0x27370940
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 09 37 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetModuleFileNameExA
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetModuleFileNameExA"

    /*
        688196BB92           | push 0x92bb9681
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 96 bb 92 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetModuleFileNameExW
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetModuleFileNameExW"

    /*
        6881966B93           | push 0x936b9681
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 96 6b 93 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetModuleInformation
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetModuleInformation"

    /*
        68BC585A26           | push 0x265a58bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 58 5a 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetPerformanceInfo
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetPerformanceInfo"

    /*
        68FFB7F450           | push 0x50f4b7ff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff b7 f4 50 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetProcessImageFileNameA
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetProcessImageFileNameA"

    /*
        689092AB86           | push 0x86ab9290
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 92 ab 86 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetProcessImageFileNameW
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetProcessImageFileNameW"

    /*
        6890925B87           | push 0x875b9290
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 92 5b 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetProcessMemoryInfo
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetProcessMemoryInfo"

    /*
        6819574A4B           | push 0x4b4a5719
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 57 4a 4b ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetWsChanges
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetWsChanges"

    /*
        6842A1BBD2           | push 0xd2bba142
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 a1 bb d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32GetWsChangesEx
{
    meta:
        desc = "Metasploit::API::kernel32::K32GetWsChangesEx"

    /*
        682AC29199           | push 0x9991c22a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a c2 91 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32InitializeProcessForWsWatch
{
    meta:
        desc = "Metasploit::API::kernel32::K32InitializeProcessForWsWatch"

    /*
        68175C7133           | push 0x33715c17
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 5c 71 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32QueryWorkingSet
{
    meta:
        desc = "Metasploit::API::kernel32::K32QueryWorkingSet"

    /*
        688A0263D6           | push 0xd663028a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 02 63 d6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_K32QueryWorkingSetEx
{
    meta:
        desc = "Metasploit::API::kernel32::K32QueryWorkingSetEx"

    /*
        682A146A83           | push 0x836a142a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 14 6a 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LCIDToLocaleName
{
    meta:
        desc = "Metasploit::API::kernel32::LCIDToLocaleName"

    /*
        68C9BFBABF           | push 0xbfbabfc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 bf ba bf ff d5 }

    condition:
        any of them
}

    
rule kernel32_LCMapStringA
{
    meta:
        desc = "Metasploit::API::kernel32::LCMapStringA"

    /*
        6807D81623           | push 0x2316d807
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 d8 16 23 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LCMapStringEx
{
    meta:
        desc = "Metasploit::API::kernel32::LCMapStringEx"

    /*
        68189BDB9F           | push 0x9fdb9b18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 9b db 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_LCMapStringW
{
    meta:
        desc = "Metasploit::API::kernel32::LCMapStringW"

    /*
        6807D8C623           | push 0x23c6d807
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 d8 c6 23 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZClose
{
    meta:
        desc = "Metasploit::API::kernel32::LZClose"

    /*
        683CFD45F5           | push 0xf545fd3c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c fd 45 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZCloseFile
{
    meta:
        desc = "Metasploit::API::kernel32::LZCloseFile"

    /*
        6804B841D6           | push 0xd641b804
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 b8 41 d6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZCopy
{
    meta:
        desc = "Metasploit::API::kernel32::LZCopy"

    /*
        680763AB75           | push 0x75ab6307
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 63 ab 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZCreateFileW
{
    meta:
        desc = "Metasploit::API::kernel32::LZCreateFileW"

    /*
        687AFC8A76           | push 0x768afc7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a fc 8a 76 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZDone
{
    meta:
        desc = "Metasploit::API::kernel32::LZDone"

    /*
        6887720B75           | push 0x750b7287
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 72 0b 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZInit
{
    meta:
        desc = "Metasploit::API::kernel32::LZInit"

    /*
        6847C18373           | push 0x7383c147
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 c1 83 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZOpenFileA
{
    meta:
        desc = "Metasploit::API::kernel32::LZOpenFileA"

    /*
        68F444105F           | push 0x5f1044f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 44 10 5f ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZOpenFileW
{
    meta:
        desc = "Metasploit::API::kernel32::LZOpenFileW"

    /*
        68F444C05F           | push 0x5fc044f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 44 c0 5f ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZRead
{
    meta:
        desc = "Metasploit::API::kernel32::LZRead"

    /*
        68474F0461           | push 0x61044f47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 4f 04 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZSeek
{
    meta:
        desc = "Metasploit::API::kernel32::LZSeek"

    /*
        6847603C61           | push 0x613c6047
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 60 3c 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LZStart
{
    meta:
        desc = "Metasploit::API::kernel32::LZStart"

    /*
        68047DBED9           | push 0xd9be7d04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 7d be d9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LeaveCriticalSection
{
    meta:
        desc = "Metasploit::API::kernel32::LeaveCriticalSection"

    /*
        684222B783           | push 0x83b72242
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 22 b7 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LeaveCriticalSectionWhenCallbackReturns
{
    meta:
        desc = "Metasploit::API::kernel32::LeaveCriticalSectionWhenCallbackReturns"

    /*
        68C0B230E8           | push 0xe830b2c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 b2 30 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadAppInitDlls
{
    meta:
        desc = "Metasploit::API::kernel32::LoadAppInitDlls"

    /*
        683AC2F669           | push 0x69f6c23a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a c2 f6 69 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadEnclaveData
{
    meta:
        desc = "Metasploit::API::kernel32::LoadEnclaveData"

    /*
        68925AA276           | push 0x76a25a92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 5a a2 76 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadLibraryA
{
    meta:
        desc = "Metasploit::API::kernel32::LoadLibraryA"

    /*
        684C772607           | push 0x0726774c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 77 26 07 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadLibraryExA
{
    meta:
        desc = "Metasploit::API::kernel32::LoadLibraryExA"

    /*
        6877518FBA           | push 0xba8f5177
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 51 8f ba ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadLibraryExW
{
    meta:
        desc = "Metasploit::API::kernel32::LoadLibraryExW"

    /*
        6877513FBB           | push 0xbb3f5177
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 51 3f bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadLibraryW
{
    meta:
        desc = "Metasploit::API::kernel32::LoadLibraryW"

    /*
        684C77D607           | push 0x07d6774c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 77 d6 07 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadModule
{
    meta:
        desc = "Metasploit::API::kernel32::LoadModule"

    /*
        68A5F61462           | push 0x6214f6a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 f6 14 62 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadPackagedLibrary
{
    meta:
        desc = "Metasploit::API::kernel32::LoadPackagedLibrary"

    /*
        68E8AA8DCC           | push 0xcc8daae8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 aa 8d cc ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadResource
{
    meta:
        desc = "Metasploit::API::kernel32::LoadResource"

    /*
        684AB18B8E           | push 0x8e8bb14a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a b1 8b 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadStringBaseExW
{
    meta:
        desc = "Metasploit::API::kernel32::LoadStringBaseExW"

    /*
        681B97C992           | push 0x92c9971b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 97 c9 92 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LoadStringBaseW
{
    meta:
        desc = "Metasploit::API::kernel32::LoadStringBaseW"

    /*
        6863A03497           | push 0x9734a063
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 a0 34 97 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::LocalAlloc"

    /*
        68EE768152           | push 0x528176ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 76 81 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalCompact
{
    meta:
        desc = "Metasploit::API::kernel32::LocalCompact"

    /*
        680A45F306           | push 0x06f3450a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 45 f3 06 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalFileTimeToFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::LocalFileTimeToFileTime"

    /*
        6869AB7930           | push 0x3079ab69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 ab 79 30 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalFileTimeToLocalSystemTime
{
    meta:
        desc = "Metasploit::API::kernel32::LocalFileTimeToLocalSystemTime"

    /*
        68808A73EC           | push 0xec738a80
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 8a 73 ec ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalFlags
{
    meta:
        desc = "Metasploit::API::kernel32::LocalFlags"

    /*
        68F17401BD           | push 0xbd0174f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 74 01 bd ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalFree
{
    meta:
        desc = "Metasploit::API::kernel32::LocalFree"

    /*
        68B1FC61EA           | push 0xea61fcb1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 fc 61 ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalHandle
{
    meta:
        desc = "Metasploit::API::kernel32::LocalHandle"

    /*
        68A7379900           | push 0x009937a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 37 99 00 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalLock
{
    meta:
        desc = "Metasploit::API::kernel32::LocalLock"

    /*
        68315C92E4           | push 0xe4925c31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 5c 92 e4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalReAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::LocalReAlloc"

    /*
        68D409431C           | push 0x1c4309d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 09 43 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalShrink
{
    meta:
        desc = "Metasploit::API::kernel32::LocalShrink"

    /*
        682A78F58A           | push 0x8af5782a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 78 f5 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalSize
{
    meta:
        desc = "Metasploit::API::kernel32::LocalSize"

    /*
        68F1D162D8           | push 0xd862d1f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 d1 62 d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalSystemTimeToLocalFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::LocalSystemTimeToLocalFileTime"

    /*
        680581DBDD           | push 0xdddb8105
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 81 db dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocalUnlock
{
    meta:
        desc = "Metasploit::API::kernel32::LocalUnlock"

    /*
        686E15FD96           | push 0x96fd156e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e 15 fd 96 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocaleNameToLCID
{
    meta:
        desc = "Metasploit::API::kernel32::LocaleNameToLCID"

    /*
        68D490BE9A           | push 0x9abe90d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 90 be 9a ff d5 }

    condition:
        any of them
}

    
rule kernel32_LocateXStateFeature
{
    meta:
        desc = "Metasploit::API::kernel32::LocateXStateFeature"

    /*
        68BA50816F           | push 0x6f8150ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 50 81 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_LockFile
{
    meta:
        desc = "Metasploit::API::kernel32::LockFile"

    /*
        68F09F6735           | push 0x35679ff0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 9f 67 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LockFileEx
{
    meta:
        desc = "Metasploit::API::kernel32::LockFileEx"

    /*
        68C26D9144           | push 0x44916dc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 6d 91 44 ff d5 }

    condition:
        any of them
}

    
rule kernel32_LockResource
{
    meta:
        desc = "Metasploit::API::kernel32::LockResource"

    /*
        684BE98B0E           | push 0x0e8be94b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b e9 8b 0e ff d5 }

    condition:
        any of them
}

    
rule kernel32_MapUserPhysicalPages
{
    meta:
        desc = "Metasploit::API::kernel32::MapUserPhysicalPages"

    /*
        68B927683E           | push 0x3e6827b9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b9 27 68 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_MapUserPhysicalPagesScatter
{
    meta:
        desc = "Metasploit::API::kernel32::MapUserPhysicalPagesScatter"

    /*
        68A096F476           | push 0x76f496a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 96 f4 76 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MapViewOfFile
{
    meta:
        desc = "Metasploit::API::kernel32::MapViewOfFile"

    /*
        6813EF7A75           | push 0x757aef13
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 ef 7a 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MapViewOfFileEx
{
    meta:
        desc = "Metasploit::API::kernel32::MapViewOfFileEx"

    /*
        6892366549           | push 0x49653692
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 36 65 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MapViewOfFileExNuma
{
    meta:
        desc = "Metasploit::API::kernel32::MapViewOfFileExNuma"

    /*
        68869DB7E1           | push 0xe1b79d86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 9d b7 e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MapViewOfFileFromApp
{
    meta:
        desc = "Metasploit::API::kernel32::MapViewOfFileFromApp"

    /*
        680E1379F3           | push 0xf379130e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 13 79 f3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Module32First
{
    meta:
        desc = "Metasploit::API::kernel32::Module32First"

    /*
        682B316947           | push 0x4769312b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 31 69 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Module32FirstW
{
    meta:
        desc = "Metasploit::API::kernel32::Module32FirstW"

    /*
        68AABCF467           | push 0x67f4bcaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa bc f4 67 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Module32Next
{
    meta:
        desc = "Metasploit::API::kernel32::Module32Next"

    /*
        687DCE01CE           | push 0xce01ce7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d ce 01 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_Module32NextW
{
    meta:
        desc = "Metasploit::API::kernel32::Module32NextW"

    /*
        686FF18052           | push 0x5280f16f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f f1 80 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileA
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileA"

    /*
        68FE3654DD           | push 0xdd5436fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 36 54 dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileExA
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileExA"

    /*
        68EC3DFF45           | push 0x45ff3dec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 3d ff 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileExW
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileExW"

    /*
        68EC3DAF46           | push 0x46af3dec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 3d af 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileTransactedA"

    /*
        6892CE14E1           | push 0xe114ce92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 ce 14 e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileTransactedW"

    /*
        6892CEC4E1           | push 0xe1c4ce92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 ce c4 e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileW
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileW"

    /*
        68FE3604DE           | push 0xde0436fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 36 04 de ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileWithProgressA
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileWithProgressA"

    /*
        68A31A96A4           | push 0xa4961aa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 1a 96 a4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MoveFileWithProgressW
{
    meta:
        desc = "Metasploit::API::kernel32::MoveFileWithProgressW"

    /*
        68A31A46A5           | push 0xa5461aa3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 1a 46 a5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_MulDiv
{
    meta:
        desc = "Metasploit::API::kernel32::MulDiv"

    /*
        6855F1999F           | push 0x9f99f155
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 f1 99 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_MultiByteToWideChar
{
    meta:
        desc = "Metasploit::API::kernel32::MultiByteToWideChar"

    /*
        683091D6B9           | push 0xb9d69130
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 91 d6 b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NeedCurrentDirectoryForExePathA
{
    meta:
        desc = "Metasploit::API::kernel32::NeedCurrentDirectoryForExePathA"

    /*
        68AD1F08D1           | push 0xd1081fad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 1f 08 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NeedCurrentDirectoryForExePathW
{
    meta:
        desc = "Metasploit::API::kernel32::NeedCurrentDirectoryForExePathW"

    /*
        68AD1FB8D1           | push 0xd1b81fad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 1f b8 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NlsCheckPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::NlsCheckPolicy"

    /*
        687C644883           | push 0x8348647c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 64 48 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NlsEventDataDescCreate
{
    meta:
        desc = "Metasploit::API::kernel32::NlsEventDataDescCreate"

    /*
        683B5E54CB           | push 0xcb545e3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 5e 54 cb ff d5 }

    condition:
        any of them
}

    
rule kernel32_NlsGetCacheUpdateCount
{
    meta:
        desc = "Metasploit::API::kernel32::NlsGetCacheUpdateCount"

    /*
        6854765201           | push 0x01527654
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 76 52 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NlsUpdateLocale
{
    meta:
        desc = "Metasploit::API::kernel32::NlsUpdateLocale"

    /*
        68252C7247           | push 0x47722c25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 2c 72 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NlsUpdateSystemLocale
{
    meta:
        desc = "Metasploit::API::kernel32::NlsUpdateSystemLocale"

    /*
        6892CE5027           | push 0x2750ce92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 ce 50 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NlsWriteEtwEvent
{
    meta:
        desc = "Metasploit::API::kernel32::NlsWriteEtwEvent"

    /*
        68489CD7D3           | push 0xd3d79c48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 9c d7 d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NormalizeString
{
    meta:
        desc = "Metasploit::API::kernel32::NormalizeString"

    /*
        682A6A01DD           | push 0xdd016a2a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 6a 01 dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_NotifyMountMgr
{
    meta:
        desc = "Metasploit::API::kernel32::NotifyMountMgr"

    /*
        680B867137           | push 0x3771860b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 86 71 37 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NotifyUILanguageChange
{
    meta:
        desc = "Metasploit::API::kernel32::NotifyUILanguageChange"

    /*
        687DE348C5           | push 0xc548e37d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d e3 48 c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_NtVdm64CreateProcessInternalW
{
    meta:
        desc = "Metasploit::API::kernel32::NtVdm64CreateProcessInternalW"

    /*
        68F94ECFDC           | push 0xdccf4ef9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 4e cf dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_OOBEComplete
{
    meta:
        desc = "Metasploit::API::kernel32::OOBEComplete"

    /*
        68F32E3225           | push 0x25322ef3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 2e 32 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OfferVirtualMemory
{
    meta:
        desc = "Metasploit::API::kernel32::OfferVirtualMemory"

    /*
        68F78AC136           | push 0x36c18af7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 8a c1 36 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenConsoleW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenConsoleW"

    /*
        683DA30973           | push 0x7309a33d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d a3 09 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenConsoleWStub
{
    meta:
        desc = "Metasploit::API::kernel32::OpenConsoleWStub"

    /*
        6820A28A26           | push 0x268aa220
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 a2 8a 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenEventA
{
    meta:
        desc = "Metasploit::API::kernel32::OpenEventA"

    /*
        68EA11D596           | push 0x96d511ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 11 d5 96 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenEventW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenEventW"

    /*
        68EA118597           | push 0x978511ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 11 85 97 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenFile
{
    meta:
        desc = "Metasploit::API::kernel32::OpenFile"

    /*
        6812A06FB8           | push 0xb86fa012
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 a0 6f b8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenFileById
{
    meta:
        desc = "Metasploit::API::kernel32::OpenFileById"

    /*
        6876CB6690           | push 0x9066cb76
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 cb 66 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenFileMappingA
{
    meta:
        desc = "Metasploit::API::kernel32::OpenFileMappingA"

    /*
        687C8DA3F7           | push 0xf7a38d7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 8d a3 f7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenFileMappingW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenFileMappingW"

    /*
        687C8D53F8           | push 0xf8538d7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 8d 53 f8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenJobObjectA
{
    meta:
        desc = "Metasploit::API::kernel32::OpenJobObjectA"

    /*
        6852482677           | push 0x77264852
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 48 26 77 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenJobObjectW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenJobObjectW"

    /*
        685248D677           | push 0x77d64852
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 48 d6 77 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenMutexA
{
    meta:
        desc = "Metasploit::API::kernel32::OpenMutexA"

    /*
        68E902F604           | push 0x04f602e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 02 f6 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenMutexW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenMutexW"

    /*
        68E902A605           | push 0x05a602e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 02 a6 05 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenPackageInfoByFullName
{
    meta:
        desc = "Metasploit::API::kernel32::OpenPackageInfoByFullName"

    /*
        68374E5FA7           | push 0xa75f4e37
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 4e 5f a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenPrivateNamespaceA
{
    meta:
        desc = "Metasploit::API::kernel32::OpenPrivateNamespaceA"

    /*
        68DB80F2B6           | push 0xb6f280db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db 80 f2 b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenPrivateNamespaceW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenPrivateNamespaceW"

    /*
        68DB80A2B7           | push 0xb7a280db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db 80 a2 b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenProcess
{
    meta:
        desc = "Metasploit::API::kernel32::OpenProcess"

    /*
        68EE95B650           | push 0x50b695ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 95 b6 50 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenProcessToken
{
    meta:
        desc = "Metasploit::API::kernel32::OpenProcessToken"

    /*
        68CFDF29CB           | push 0xcb29dfcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf df 29 cb ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenProfileUserMapping
{
    meta:
        desc = "Metasploit::API::kernel32::OpenProfileUserMapping"

    /*
        687FEFC8F6           | push 0xf6c8ef7f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f ef c8 f6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenSemaphoreA
{
    meta:
        desc = "Metasploit::API::kernel32::OpenSemaphoreA"

    /*
        68D4965EE0           | push 0xe05e96d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 96 5e e0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenSemaphoreW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenSemaphoreW"

    /*
        68D4960EE1           | push 0xe10e96d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 96 0e e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenState
{
    meta:
        desc = "Metasploit::API::kernel32::OpenState"

    /*
        68A4F89849           | push 0x4998f8a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 f8 98 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenStateExplicit
{
    meta:
        desc = "Metasploit::API::kernel32::OpenStateExplicit"

    /*
        6832BACC6D           | push 0x6dccba32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 ba cc 6d ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenThread
{
    meta:
        desc = "Metasploit::API::kernel32::OpenThread"

    /*
        6822DD2986           | push 0x8629dd22
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 dd 29 86 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenThreadToken
{
    meta:
        desc = "Metasploit::API::kernel32::OpenThreadToken"

    /*
        686983E3E5           | push 0xe5e38369
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 83 e3 e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenWaitableTimerA
{
    meta:
        desc = "Metasploit::API::kernel32::OpenWaitableTimerA"

    /*
        6865869F91           | push 0x919f8665
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 86 9f 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OpenWaitableTimerW
{
    meta:
        desc = "Metasploit::API::kernel32::OpenWaitableTimerW"

    /*
        6865864F92           | push 0x924f8665
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 86 4f 92 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OutputDebugStringA
{
    meta:
        desc = "Metasploit::API::kernel32::OutputDebugStringA"

    /*
        68434F91A8           | push 0xa8914f43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 4f 91 a8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_OutputDebugStringW
{
    meta:
        desc = "Metasploit::API::kernel32::OutputDebugStringW"

    /*
        68434F41A9           | push 0xa9414f43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 4f 41 a9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PackageFamilyNameFromFullName
{
    meta:
        desc = "Metasploit::API::kernel32::PackageFamilyNameFromFullName"

    /*
        6829E83FB9           | push 0xb93fe829
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 e8 3f b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PackageFamilyNameFromId
{
    meta:
        desc = "Metasploit::API::kernel32::PackageFamilyNameFromId"

    /*
        68862F9D87           | push 0x879d2f86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 2f 9d 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PackageFullNameFromId
{
    meta:
        desc = "Metasploit::API::kernel32::PackageFullNameFromId"

    /*
        68E2159A64           | push 0x649a15e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 15 9a 64 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PackageIdFromFullName
{
    meta:
        desc = "Metasploit::API::kernel32::PackageIdFromFullName"

    /*
        68877AC45D           | push 0x5dc47a87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 7a c4 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_PackageNameAndPublisherIdFromFamilyName
{
    meta:
        desc = "Metasploit::API::kernel32::PackageNameAndPublisherIdFromFamilyName"

    /*
        686D385155           | push 0x5551386d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 38 51 55 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ParseApplicationUserModelId
{
    meta:
        desc = "Metasploit::API::kernel32::ParseApplicationUserModelId"

    /*
        68BFE55211           | push 0x1152e5bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf e5 52 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PeekConsoleInputA
{
    meta:
        desc = "Metasploit::API::kernel32::PeekConsoleInputA"

    /*
        684B6EA86E           | push 0x6ea86e4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 6e a8 6e ff d5 }

    condition:
        any of them
}

    
rule kernel32_PeekConsoleInputW
{
    meta:
        desc = "Metasploit::API::kernel32::PeekConsoleInputW"

    /*
        684B6E586F           | push 0x6f586e4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 6e 58 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_PeekNamedPipe
{
    meta:
        desc = "Metasploit::API::kernel32::PeekNamedPipe"

    /*
        6818B73CB3           | push 0xb33cb718
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 b7 3c b3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PostQueuedCompletionStatus
{
    meta:
        desc = "Metasploit::API::kernel32::PostQueuedCompletionStatus"

    /*
        686E36BBF7           | push 0xf7bb366e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e 36 bb f7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PowerClearRequest
{
    meta:
        desc = "Metasploit::API::kernel32::PowerClearRequest"

    /*
        68EC3036AE           | push 0xae3630ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 30 36 ae ff d5 }

    condition:
        any of them
}

    
rule kernel32_PowerCreateRequest
{
    meta:
        desc = "Metasploit::API::kernel32::PowerCreateRequest"

    /*
        68D000B15D           | push 0x5db100d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 00 b1 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_PowerSetRequest
{
    meta:
        desc = "Metasploit::API::kernel32::PowerSetRequest"

    /*
        6882785352           | push 0x52537882
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 78 53 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PrefetchVirtualMemory
{
    meta:
        desc = "Metasploit::API::kernel32::PrefetchVirtualMemory"

    /*
        68F62CB81C           | push 0x1cb82cf6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 2c b8 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_PrepareTape
{
    meta:
        desc = "Metasploit::API::kernel32::PrepareTape"

    /*
        684AA747CA           | push 0xca47a74a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a a7 47 ca ff d5 }

    condition:
        any of them
}

    
rule kernel32_PrivCopyFileExW
{
    meta:
        desc = "Metasploit::API::kernel32::PrivCopyFileExW"

    /*
        6856DD1C8F           | push 0x8f1cdd56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 dd 1c 8f ff d5 }

    condition:
        any of them
}

    
rule kernel32_PrivMoveFileIdentityW
{
    meta:
        desc = "Metasploit::API::kernel32::PrivMoveFileIdentityW"

    /*
        681C891945           | push 0x4519891c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 89 19 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Process32First
{
    meta:
        desc = "Metasploit::API::kernel32::Process32First"

    /*
        6827A9E867           | push 0x67e8a927
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 a9 e8 67 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Process32FirstW
{
    meta:
        desc = "Metasploit::API::kernel32::Process32FirstW"

    /*
        68A6C0D527           | push 0x27d5c0a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 c0 d5 27 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Process32Next
{
    meta:
        desc = "Metasploit::API::kernel32::Process32Next"

    /*
        688D5201BD           | push 0xbd01528d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 52 01 bd ff d5 }

    condition:
        any of them
}

    
rule kernel32_Process32NextW
{
    meta:
        desc = "Metasploit::API::kernel32::Process32NextW"

    /*
        686B690073           | push 0x7300696b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 69 00 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ProcessIdToSessionId
{
    meta:
        desc = "Metasploit::API::kernel32::ProcessIdToSessionId"

    /*
        683779F4B9           | push 0xb9f47937
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 79 f4 b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssCaptureSnapshot
{
    meta:
        desc = "Metasploit::API::kernel32::PssCaptureSnapshot"

    /*
        6890273CE8           | push 0xe83c2790
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 27 3c e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssDuplicateSnapshot
{
    meta:
        desc = "Metasploit::API::kernel32::PssDuplicateSnapshot"

    /*
        681337570D           | push 0x0d573713
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 37 57 0d ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssFreeSnapshot
{
    meta:
        desc = "Metasploit::API::kernel32::PssFreeSnapshot"

    /*
        6816694335           | push 0x35436916
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 69 43 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssQuerySnapshot
{
    meta:
        desc = "Metasploit::API::kernel32::PssQuerySnapshot"

    /*
        680E0C7AC4           | push 0xc47a0c0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 0c 7a c4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerCreate
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerCreate"

    /*
        68E54248B1           | push 0xb14842e5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 42 48 b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerFree
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerFree"

    /*
        68160B3DBF           | push 0xbf3d0b16
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 0b 3d bf ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerGetPosition
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerGetPosition"

    /*
        683180B326           | push 0x26b38031
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 80 b3 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerRewind
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerRewind"

    /*
        685E617D41           | push 0x417d615e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 61 7d 41 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerSeek
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerSeek"

    /*
        6816DB6DA5           | push 0xa56ddb16
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 db 6d a5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerSeekToBeginning
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerSeekToBeginning"

    /*
        680B55B417           | push 0x17b4550b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 55 b4 17 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerSetPosition
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerSetPosition"

    /*
        683180CB26           | push 0x26cb8031
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 80 cb 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkMarkerTell
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkMarkerTell"

    /*
        68D6EC75A5           | push 0xa575ecd6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 ec 75 a5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PssWalkSnapshot
{
    meta:
        desc = "Metasploit::API::kernel32::PssWalkSnapshot"

    /*
        68289A21F5           | push 0xf5219a28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 9a 21 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_PulseEvent
{
    meta:
        desc = "Metasploit::API::kernel32::PulseEvent"

    /*
        68F148EE4D           | push 0x4dee48f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 48 ee 4d ff d5 }

    condition:
        any of them
}

    
rule kernel32_PurgeComm
{
    meta:
        desc = "Metasploit::API::kernel32::PurgeComm"

    /*
        688DF0B96A           | push 0x6ab9f08d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d f0 b9 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryActCtxSettingsW
{
    meta:
        desc = "Metasploit::API::kernel32::QueryActCtxSettingsW"

    /*
        683B38E4CE           | push 0xcee4383b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 38 e4 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryActCtxSettingsWWorker
{
    meta:
        desc = "Metasploit::API::kernel32::QueryActCtxSettingsWWorker"

    /*
        6826412773           | push 0x73274126
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 41 27 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryActCtxW
{
    meta:
        desc = "Metasploit::API::kernel32::QueryActCtxW"

    /*
        685E02E538           | push 0x38e5025e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 02 e5 38 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryActCtxWWorker
{
    meta:
        desc = "Metasploit::API::kernel32::QueryActCtxWWorker"

    /*
        682AE9B49B           | push 0x9bb4e92a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a e9 b4 9b ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryDepthSList
{
    meta:
        desc = "Metasploit::API::kernel32::QueryDepthSList"

    /*
        6880056BAD           | push 0xad6b0580
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 05 6b ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryDosDeviceA
{
    meta:
        desc = "Metasploit::API::kernel32::QueryDosDeviceA"

    /*
        68111CC922           | push 0x22c91c11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 1c c9 22 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryDosDeviceW
{
    meta:
        desc = "Metasploit::API::kernel32::QueryDosDeviceW"

    /*
        68111C7923           | push 0x23791c11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 1c 79 23 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryFullProcessImageNameA
{
    meta:
        desc = "Metasploit::API::kernel32::QueryFullProcessImageNameA"

    /*
        68E1C9A646           | push 0x46a6c9e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 c9 a6 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryFullProcessImageNameW
{
    meta:
        desc = "Metasploit::API::kernel32::QueryFullProcessImageNameW"

    /*
        68E1C95647           | push 0x4756c9e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 c9 56 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryIdleProcessorCycleTime
{
    meta:
        desc = "Metasploit::API::kernel32::QueryIdleProcessorCycleTime"

    /*
        6866B3CD88           | push 0x88cdb366
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 b3 cd 88 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryIdleProcessorCycleTimeEx
{
    meta:
        desc = "Metasploit::API::kernel32::QueryIdleProcessorCycleTimeEx"

    /*
        68574B161E           | push 0x1e164b57
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 4b 16 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryInformationJobObject
{
    meta:
        desc = "Metasploit::API::kernel32::QueryInformationJobObject"

    /*
        680C8D436A           | push 0x6a438d0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 8d 43 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryIoRateControlInformationJobObject
{
    meta:
        desc = "Metasploit::API::kernel32::QueryIoRateControlInformationJobObject"

    /*
        6873B5E545           | push 0x45e5b573
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 b5 e5 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryMemoryResourceNotification
{
    meta:
        desc = "Metasploit::API::kernel32::QueryMemoryResourceNotification"

    /*
        68B3A8A511           | push 0x11a5a8b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 a8 a5 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryPerformanceCounter
{
    meta:
        desc = "Metasploit::API::kernel32::QueryPerformanceCounter"

    /*
        68B16A8E1D           | push 0x1d8e6ab1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 6a 8e 1d ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryPerformanceFrequency
{
    meta:
        desc = "Metasploit::API::kernel32::QueryPerformanceFrequency"

    /*
        687D3B58C9           | push 0xc9583b7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 3b 58 c9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryProcessAffinityUpdateMode
{
    meta:
        desc = "Metasploit::API::kernel32::QueryProcessAffinityUpdateMode"

    /*
        68BBA34B08           | push 0x084ba3bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb a3 4b 08 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryProcessCycleTime
{
    meta:
        desc = "Metasploit::API::kernel32::QueryProcessCycleTime"

    /*
        68F8A6EF01           | push 0x01efa6f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 a6 ef 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryProtectedPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::QueryProtectedPolicy"

    /*
        684A59C770           | push 0x70c7594a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 59 c7 70 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryThreadCycleTime
{
    meta:
        desc = "Metasploit::API::kernel32::QueryThreadCycleTime"

    /*
        68B62A0C46           | push 0x460c2ab6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 2a 0c 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryThreadProfiling
{
    meta:
        desc = "Metasploit::API::kernel32::QueryThreadProfiling"

    /*
        687814063F           | push 0x3f061478
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 14 06 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryThreadpoolStackInformation
{
    meta:
        desc = "Metasploit::API::kernel32::QueryThreadpoolStackInformation"

    /*
        6848E416CF           | push 0xcf16e448
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 e4 16 cf ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryUmsThreadInformation
{
    meta:
        desc = "Metasploit::API::kernel32::QueryUmsThreadInformation"

    /*
        68E51EF74B           | push 0x4bf71ee5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 1e f7 4b ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueryUnbiasedInterruptTime
{
    meta:
        desc = "Metasploit::API::kernel32::QueryUnbiasedInterruptTime"

    /*
        68F1953C92           | push 0x923c95f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 95 3c 92 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueueUserAPC
{
    meta:
        desc = "Metasploit::API::kernel32::QueueUserAPC"

    /*
        68D602883E           | push 0x3e8802d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 02 88 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_QueueUserWorkItem
{
    meta:
        desc = "Metasploit::API::kernel32::QueueUserWorkItem"

    /*
        682E3AC46A           | push 0x6ac43a2e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 3a c4 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkGetData2Worker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkGetData2Worker"

    /*
        6840BF613F           | push 0x3f61bf40
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 bf 61 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkGetDataWorker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkGetDataWorker"

    /*
        688A1AB8DA           | push 0xdab81a8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 1a b8 da ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabled2Worker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabled2Worker"

    /*
        682BEE5C56           | push 0x565cee2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b ee 5c 56 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabled3Worker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabled3Worker"

    /*
        684BEE5C56           | push 0x565cee4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b ee 5c 56 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabledForPackage2Worker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabledForPackage2Worker"

    /*
        68FF7C9A5E           | push 0x5e9a7cff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff 7c 9a 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabledForPackage3Worker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabledForPackage3Worker"

    /*
        681F7D9A5E           | push 0x5e9a7d1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 7d 9a 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabledForPackage4Worker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabledForPackage4Worker"

    /*
        683F7D9A5E           | push 0x5e9a7d3f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 7d 9a 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabledForPackageWorker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabledForPackageWorker"

    /*
        6871FE6FF2           | push 0xf26ffe71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 fe 6f f2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabledForProcessWorker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabledForProcessWorker"

    /*
        683F2188FE           | push 0xfe88213f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 21 88 fe ff d5 }

    condition:
        any of them
}

    
rule kernel32_QuirkIsEnabledWorker
{
    meta:
        desc = "Metasploit::API::kernel32::QuirkIsEnabledWorker"

    /*
        68697D9540           | push 0x40957d69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 7d 95 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RaiseException
{
    meta:
        desc = "Metasploit::API::kernel32::RaiseException"

    /*
        68DCF52353           | push 0x5323f5dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc f5 23 53 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RaiseFailFastException
{
    meta:
        desc = "Metasploit::API::kernel32::RaiseFailFastException"

    /*
        68ECC676CF           | push 0xcf76c6ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec c6 76 cf ff d5 }

    condition:
        any of them
}

    
rule kernel32_RaiseInvalid16BitExeError
{
    meta:
        desc = "Metasploit::API::kernel32::RaiseInvalid16BitExeError"

    /*
        6820572305           | push 0x05235720
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 57 23 05 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReOpenFile
{
    meta:
        desc = "Metasploit::API::kernel32::ReOpenFile"

    /*
        6826C87238           | push 0x3872c826
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 c8 72 38 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleA
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleA"

    /*
        686C534372           | push 0x7243536c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 53 43 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleInputA
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleInputA"

    /*
        685B52A8EE           | push 0xeea8525b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 52 a8 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleInputExA
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleInputExA"

    /*
        683115069B           | push 0x9b061531
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 15 06 9b ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleInputExW
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleInputExW"

    /*
        683115B69B           | push 0x9bb61531
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 15 b6 9b ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleInputW
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleInputW"

    /*
        685B5258EF           | push 0xef58525b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 52 58 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleOutputA
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleOutputA"

    /*
        6825B4DD72           | push 0x72ddb425
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 b4 dd 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleOutputAttribute
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleOutputAttribute"

    /*
        682D9185C1           | push 0xc185912d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 91 85 c1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleOutputCharacterA
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleOutputCharacterA"

    /*
        68CE203036           | push 0x363020ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce 20 30 36 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleOutputCharacterW
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleOutputCharacterW"

    /*
        68CE20E036           | push 0x36e020ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce 20 e0 36 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleOutputW
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleOutputW"

    /*
        6825B48D73           | push 0x738db425
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 b4 8d 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadConsoleW
{
    meta:
        desc = "Metasploit::API::kernel32::ReadConsoleW"

    /*
        686C53F372           | push 0x72f3536c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 53 f3 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadDirectoryChangesExW
{
    meta:
        desc = "Metasploit::API::kernel32::ReadDirectoryChangesExW"

    /*
        68359797BF           | push 0xbf979735
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 97 97 bf ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadDirectoryChangesW
{
    meta:
        desc = "Metasploit::API::kernel32::ReadDirectoryChangesW"

    /*
        6863D8E7FF           | push 0xffe7d863
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 d8 e7 ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadFile
{
    meta:
        desc = "Metasploit::API::kernel32::ReadFile"

    /*
        68AD9E5FBB           | push 0xbb5f9ead
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 9e 5f bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadFileEx
{
    meta:
        desc = "Metasploit::API::kernel32::ReadFileEx"

    /*
        68E41C91C2           | push 0xc2911ce4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 1c 91 c2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadFileScatter
{
    meta:
        desc = "Metasploit::API::kernel32::ReadFileScatter"

    /*
        681075E315           | push 0x15e37510
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 75 e3 15 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadProcessMemory
{
    meta:
        desc = "Metasploit::API::kernel32::ReadProcessMemory"

    /*
        68C2D3F971           | push 0x71f9d3c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 d3 f9 71 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReadThreadProfilingData
{
    meta:
        desc = "Metasploit::API::kernel32::ReadThreadProfilingData"

    /*
        689E8D2C73           | push 0x732c8d9e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 8d 2c 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReclaimVirtualMemory
{
    meta:
        desc = "Metasploit::API::kernel32::ReclaimVirtualMemory"

    /*
        682D41BDDB           | push 0xdbbd412d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 41 bd db ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegCloseKey
{
    meta:
        desc = "Metasploit::API::kernel32::RegCloseKey"

    /*
        68EDC5E031           | push 0x31e0c5ed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed c5 e0 31 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegCopyTreeW
{
    meta:
        desc = "Metasploit::API::kernel32::RegCopyTreeW"

    /*
        687E7B1E91           | push 0x911e7b7e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 7b 1e 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegCreateKeyExA
{
    meta:
        desc = "Metasploit::API::kernel32::RegCreateKeyExA"

    /*
        68017253C8           | push 0xc8537201
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 72 53 c8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegCreateKeyExW
{
    meta:
        desc = "Metasploit::API::kernel32::RegCreateKeyExW"

    /*
        68017203C9           | push 0xc9037201
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 72 03 c9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegDeleteKeyExA
{
    meta:
        desc = "Metasploit::API::kernel32::RegDeleteKeyExA"

    /*
        6812923988           | push 0x88399212
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 92 39 88 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegDeleteKeyExW
{
    meta:
        desc = "Metasploit::API::kernel32::RegDeleteKeyExW"

    /*
        681292E988           | push 0x88e99212
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 92 e9 88 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegDeleteTreeA
{
    meta:
        desc = "Metasploit::API::kernel32::RegDeleteTreeA"

    /*
        684E0D5F38           | push 0x385f0d4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 0d 5f 38 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegDeleteTreeW
{
    meta:
        desc = "Metasploit::API::kernel32::RegDeleteTreeW"

    /*
        684E0D0F39           | push 0x390f0d4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 0d 0f 39 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegDeleteValueA
{
    meta:
        desc = "Metasploit::API::kernel32::RegDeleteValueA"

    /*
        6851BD64E8           | push 0xe864bd51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 bd 64 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegDeleteValueW
{
    meta:
        desc = "Metasploit::API::kernel32::RegDeleteValueW"

    /*
        6851BD14E9           | push 0xe914bd51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 bd 14 e9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegDisablePredefinedCacheEx
{
    meta:
        desc = "Metasploit::API::kernel32::RegDisablePredefinedCacheEx"

    /*
        682E506D18           | push 0x186d502e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 50 6d 18 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegEnumKeyExA
{
    meta:
        desc = "Metasploit::API::kernel32::RegEnumKeyExA"

    /*
        680E49BC7E           | push 0x7ebc490e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 49 bc 7e ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegEnumKeyExW
{
    meta:
        desc = "Metasploit::API::kernel32::RegEnumKeyExW"

    /*
        680E496C7F           | push 0x7f6c490e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 49 6c 7f ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegEnumValueA
{
    meta:
        desc = "Metasploit::API::kernel32::RegEnumValueA"

    /*
        684D74E7DE           | push 0xdee7744d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 74 e7 de ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegEnumValueW
{
    meta:
        desc = "Metasploit::API::kernel32::RegEnumValueW"

    /*
        684D7497DF           | push 0xdf97744d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 74 97 df ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegFlushKey
{
    meta:
        desc = "Metasploit::API::kernel32::RegFlushKey"

    /*
        68EDF5F834           | push 0x34f8f5ed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed f5 f8 34 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegGetKeySecurity
{
    meta:
        desc = "Metasploit::API::kernel32::RegGetKeySecurity"

    /*
        68AB4E8A90           | push 0x908a4eab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 4e 8a 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegGetValueA
{
    meta:
        desc = "Metasploit::API::kernel32::RegGetValueA"

    /*
        68053CE225           | push 0x25e23c05
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 3c e2 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegGetValueW
{
    meta:
        desc = "Metasploit::API::kernel32::RegGetValueW"

    /*
        68053C9226           | push 0x26923c05
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 3c 92 26 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegLoadKeyA
{
    meta:
        desc = "Metasploit::API::kernel32::RegLoadKeyA"

    /*
        68462BE7EC           | push 0xece72b46
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 2b e7 ec ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegLoadKeyW
{
    meta:
        desc = "Metasploit::API::kernel32::RegLoadKeyW"

    /*
        68462B97ED           | push 0xed972b46
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 2b 97 ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegLoadMUIStringA
{
    meta:
        desc = "Metasploit::API::kernel32::RegLoadMUIStringA"

    /*
        68F4AB3E14           | push 0x143eabf4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 ab 3e 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegLoadMUIStringW
{
    meta:
        desc = "Metasploit::API::kernel32::RegLoadMUIStringW"

    /*
        68F4ABEE14           | push 0x14eeabf4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 ab ee 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegNotifyChangeKeyValue
{
    meta:
        desc = "Metasploit::API::kernel32::RegNotifyChangeKeyValue"

    /*
        6800EE7BD7           | push 0xd77bee00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 ee 7b d7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegOpenCurrentUser
{
    meta:
        desc = "Metasploit::API::kernel32::RegOpenCurrentUser"

    /*
        6824E7EE57           | push 0x57eee724
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 e7 ee 57 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegOpenKeyExA
{
    meta:
        desc = "Metasploit::API::kernel32::RegOpenKeyExA"

    /*
        683159BCEE           | push 0xeebc5931
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 59 bc ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegOpenKeyExW
{
    meta:
        desc = "Metasploit::API::kernel32::RegOpenKeyExW"

    /*
        6831596CEF           | push 0xef6c5931
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 59 6c ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegOpenUserClassesRoot
{
    meta:
        desc = "Metasploit::API::kernel32::RegOpenUserClassesRoot"

    /*
        68F15E94C8           | push 0xc8945ef1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 5e 94 c8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegQueryInfoKeyA
{
    meta:
        desc = "Metasploit::API::kernel32::RegQueryInfoKeyA"

    /*
        688B5EF572           | push 0x72f55e8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 5e f5 72 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegQueryInfoKeyW
{
    meta:
        desc = "Metasploit::API::kernel32::RegQueryInfoKeyW"

    /*
        688B5EA573           | push 0x73a55e8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 5e a5 73 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegQueryValueExA
{
    meta:
        desc = "Metasploit::API::kernel32::RegQueryValueExA"

    /*
        68AEFC0E40           | push 0x400efcae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae fc 0e 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegQueryValueExW
{
    meta:
        desc = "Metasploit::API::kernel32::RegQueryValueExW"

    /*
        68AEFCBE40           | push 0x40befcae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae fc be 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegRestoreKeyA
{
    meta:
        desc = "Metasploit::API::kernel32::RegRestoreKeyA"

    /*
        68B7D9ACC7           | push 0xc7acd9b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 d9 ac c7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegRestoreKeyW
{
    meta:
        desc = "Metasploit::API::kernel32::RegRestoreKeyW"

    /*
        68B7D95CC8           | push 0xc85cd9b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 d9 5c c8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegSaveKeyExA
{
    meta:
        desc = "Metasploit::API::kernel32::RegSaveKeyExA"

    /*
        6812E0BBFF           | push 0xffbbe012
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 e0 bb ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegSaveKeyExW
{
    meta:
        desc = "Metasploit::API::kernel32::RegSaveKeyExW"

    /*
        6812E06B00           | push 0x006be012
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 e0 6b 00 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegSetKeySecurity
{
    meta:
        desc = "Metasploit::API::kernel32::RegSetKeySecurity"

    /*
        68AB7E8A90           | push 0x908a7eab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 7e 8a 90 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegSetValueExA
{
    meta:
        desc = "Metasploit::API::kernel32::RegSetValueExA"

    /*
        68BE7F9869           | push 0x69987fbe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 7f 98 69 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegSetValueExW
{
    meta:
        desc = "Metasploit::API::kernel32::RegSetValueExW"

    /*
        68BE7F486A           | push 0x6a487fbe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 7f 48 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegUnLoadKeyA
{
    meta:
        desc = "Metasploit::API::kernel32::RegUnLoadKeyA"

    /*
        6892691116           | push 0x16116992
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 69 11 16 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegUnLoadKeyW
{
    meta:
        desc = "Metasploit::API::kernel32::RegUnLoadKeyW"

    /*
        689269C116           | push 0x16c16992
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 69 c1 16 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterApplicationRecoveryCallback
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterApplicationRecoveryCallback"

    /*
        682E27F35C           | push 0x5cf3272e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 27 f3 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterApplicationRestart
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterApplicationRestart"

    /*
        68627077D0           | push 0xd0777062
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 70 77 d0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterBadMemoryNotification
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterBadMemoryNotification"

    /*
        68BE3FEF3B           | push 0x3bef3fbe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 be 3f ef 3b ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterConsoleIME
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterConsoleIME"

    /*
        6847D669C6           | push 0xc669d647
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 d6 69 c6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterConsoleOS2
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterConsoleOS2"

    /*
        68C7D7D1D1           | push 0xd1d1d7c7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c7 d7 d1 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterConsoleVDM
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterConsoleVDM"

    /*
        6807D4A9E0           | push 0xe0a9d407
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 d4 a9 e0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterWaitForInputIdle
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterWaitForInputIdle"

    /*
        68D17FFEFE           | push 0xfefe7fd1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 7f fe fe ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterWaitForSingleObject
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterWaitForSingleObject"

    /*
        6887B2C9C6           | push 0xc6c9b287
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 b2 c9 c6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterWaitForSingleObjectEx
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterWaitForSingleObjectEx"

    /*
        686713169D           | push 0x9d161367
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 13 16 9d ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterWaitUntilOOBECompleted
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterWaitUntilOOBECompleted"

    /*
        6829205019           | push 0x19502029
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 20 50 19 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterWowBaseHandlers
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterWowBaseHandlers"

    /*
        68B752333E           | push 0x3e3352b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 52 33 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_RegisterWowExec
{
    meta:
        desc = "Metasploit::API::kernel32::RegisterWowExec"

    /*
        68EE4DF2ED           | push 0xedf24dee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 4d f2 ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseActCtx
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseActCtx"

    /*
        68158F557A           | push 0x7a558f15
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 8f 55 7a ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseActCtxWorker
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseActCtxWorker"

    /*
        68ECEE91CE           | push 0xce91eeec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec ee 91 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseMutex
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseMutex"

    /*
        68DCBBD761           | push 0x61d7bbdc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc bb d7 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseMutexWhenCallbackReturns
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseMutexWhenCallbackReturns"

    /*
        687CE66329           | push 0x2963e67c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c e6 63 29 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseSRWLockExclusive
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseSRWLockExclusive"

    /*
        68CDC2E1FF           | push 0xffe1c2cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd c2 e1 ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseSRWLockShared
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseSRWLockShared"

    /*
        681E2CB6A3           | push 0xa3b62c1e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e 2c b6 a3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseSemaphore
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseSemaphore"

    /*
        68690F1EEE           | push 0xee1e0f69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 0f 1e ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReleaseSemaphoreWhenCallbackReturns
{
    meta:
        desc = "Metasploit::API::kernel32::ReleaseSemaphoreWhenCallbackReturns"

    /*
        6895FF0AB6           | push 0xb60aff95
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 ff 0a b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveDirectoryA"

    /*
        687335EBC4           | push 0xc4eb3573
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 35 eb c4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveDirectoryTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveDirectoryTransactedA"

    /*
        682F8EFA1A           | push 0x1afa8e2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 8e fa 1a ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveDirectoryTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveDirectoryTransactedW"

    /*
        682F8EAA1B           | push 0x1baa8e2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 8e aa 1b ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveDirectoryW"

    /*
        6873359BC5           | push 0xc59b3573
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 35 9b c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveDllDirectory
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveDllDirectory"

    /*
        685D815B87           | push 0x875b815d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 81 5b 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveLocalAlternateComputerNameA
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveLocalAlternateComputerNameA"

    /*
        687A5B86CE           | push 0xce865b7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 5b 86 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveLocalAlternateComputerNameW
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveLocalAlternateComputerNameW"

    /*
        687A5B36CF           | push 0xcf365b7a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 5b 36 cf ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveSecureMemoryCacheCallback
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveSecureMemoryCacheCallback"

    /*
        68DC2965A8           | push 0xa86529dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 29 65 a8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveVectoredContinueHandler
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveVectoredContinueHandler"

    /*
        685796E30A           | push 0x0ae39657
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 96 e3 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_RemoveVectoredExceptionHandler
{
    meta:
        desc = "Metasploit::API::kernel32::RemoveVectoredExceptionHandler"

    /*
        68917684DE           | push 0xde847691
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 91 76 84 de ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReplaceFile
{
    meta:
        desc = "Metasploit::API::kernel32::ReplaceFile"

    /*
        68471E0F96           | push 0x960f1e47
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 1e 0f 96 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReplaceFileA
{
    meta:
        desc = "Metasploit::API::kernel32::ReplaceFileA"

    /*
        68DA311FD0           | push 0xd01f31da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 31 1f d0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReplaceFileW
{
    meta:
        desc = "Metasploit::API::kernel32::ReplaceFileW"

    /*
        68DA31CFD0           | push 0xd0cf31da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 31 cf d0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ReplacePartitionUnit
{
    meta:
        desc = "Metasploit::API::kernel32::ReplacePartitionUnit"

    /*
        68113E5BAD           | push 0xad5b3e11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 3e 5b ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_RequestDeviceWakeup
{
    meta:
        desc = "Metasploit::API::kernel32::RequestDeviceWakeup"

    /*
        68DEB016B9           | push 0xb916b0de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de b0 16 b9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RequestWakeupLatency
{
    meta:
        desc = "Metasploit::API::kernel32::RequestWakeupLatency"

    /*
        683AD502ED           | push 0xed02d53a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a d5 02 ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_ResetEvent
{
    meta:
        desc = "Metasploit::API::kernel32::ResetEvent"

    /*
        6832C729D5           | push 0xd529c732
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 c7 29 d5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ResetWriteWatch
{
    meta:
        desc = "Metasploit::API::kernel32::ResetWriteWatch"

    /*
        68B778F6A2           | push 0xa2f678b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 78 f6 a2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ResizePseudoConsole
{
    meta:
        desc = "Metasploit::API::kernel32::ResizePseudoConsole"

    /*
        6867CD12A7           | push 0xa712cd67
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 cd 12 a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ResolveDelayLoadedAPI
{
    meta:
        desc = "Metasploit::API::kernel32::ResolveDelayLoadedAPI"

    /*
        687ED73287           | push 0x8732d77e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e d7 32 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ResolveDelayLoadsFromDll
{
    meta:
        desc = "Metasploit::API::kernel32::ResolveDelayLoadsFromDll"

    /*
        68AB75BEF6           | push 0xf6be75ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 75 be f6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ResolveLocaleName
{
    meta:
        desc = "Metasploit::API::kernel32::ResolveLocaleName"

    /*
        687F5CC0D3           | push 0xd3c05c7f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f 5c c0 d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RestoreLastError
{
    meta:
        desc = "Metasploit::API::kernel32::RestoreLastError"

    /*
        6833945078           | push 0x78509433
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 94 50 78 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ResumeThread
{
    meta:
        desc = "Metasploit::API::kernel32::ResumeThread"

    /*
        682B09F48E           | push 0x8ef4092b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 09 f4 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlAddFunctionTable
{
    meta:
        desc = "Metasploit::API::kernel32::RtlAddFunctionTable"

    /*
        68BA2EB845           | push 0x45b82eba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 2e b8 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlCaptureContext
{
    meta:
        desc = "Metasploit::API::kernel32::RtlCaptureContext"

    /*
        682D23F3B8           | push 0xb8f3232d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 23 f3 b8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlCaptureStackBackTrace
{
    meta:
        desc = "Metasploit::API::kernel32::RtlCaptureStackBackTrace"

    /*
        68BA756891           | push 0x916875ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 75 68 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlCompareMemory
{
    meta:
        desc = "Metasploit::API::kernel32::RtlCompareMemory"

    /*
        6848CF620A           | push 0x0a62cf48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 cf 62 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlCopyMemory
{
    meta:
        desc = "Metasploit::API::kernel32::RtlCopyMemory"

    /*
        68FE918D4F           | push 0x4f8d91fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 91 8d 4f ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlDeleteFunctionTable
{
    meta:
        desc = "Metasploit::API::kernel32::RtlDeleteFunctionTable"

    /*
        680B185602           | push 0x0256180b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 18 56 02 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlFillMemory
{
    meta:
        desc = "Metasploit::API::kernel32::RtlFillMemory"

    /*
        685F608D0B           | push 0x0b8d605f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 60 8d 0b ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlInstallFunctionTableCallback
{
    meta:
        desc = "Metasploit::API::kernel32::RtlInstallFunctionTableCallback"

    /*
        6863BB0A93           | push 0x930abb63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 bb 0a 93 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlLookupFunctionEntry
{
    meta:
        desc = "Metasploit::API::kernel32::RtlLookupFunctionEntry"

    /*
        689C257DC9           | push 0xc97d259c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 25 7d c9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlMoveMemory
{
    meta:
        desc = "Metasploit::API::kernel32::RtlMoveMemory"

    /*
        68818F8DD5           | push 0xd58d8f81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 8f 8d d5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlPcToFileHeader
{
    meta:
        desc = "Metasploit::API::kernel32::RtlPcToFileHeader"

    /*
        68DCDC3B7E           | push 0x7e3bdcdc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc dc 3b 7e ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlRaiseException
{
    meta:
        desc = "Metasploit::API::kernel32::RtlRaiseException"

    /*
        687AF897D3           | push 0xd397f87a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a f8 97 d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlRestoreContext
{
    meta:
        desc = "Metasploit::API::kernel32::RtlRestoreContext"

    /*
        685B5FF33A           | push 0x3af35f5b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 5f f3 3a ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlUnwind
{
    meta:
        desc = "Metasploit::API::kernel32::RtlUnwind"

    /*
        6812402DDD           | push 0xdd2d4012
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 40 2d dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlUnwindEx
{
    meta:
        desc = "Metasploit::API::kernel32::RtlUnwindEx"

    /*
        682C76F935           | push 0x35f9762c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 76 f9 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlVirtualUnwind
{
    meta:
        desc = "Metasploit::API::kernel32::RtlVirtualUnwind"

    /*
        68CD0E6676           | push 0x76660ecd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 0e 66 76 ff d5 }

    condition:
        any of them
}

    
rule kernel32_RtlZeroMemory
{
    meta:
        desc = "Metasploit::API::kernel32::RtlZeroMemory"

    /*
        68C4408D11           | push 0x118d40c4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 40 8d 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ScrollConsoleScreenBufferA
{
    meta:
        desc = "Metasploit::API::kernel32::ScrollConsoleScreenBufferA"

    /*
        687473152B           | push 0x2b157374
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 73 15 2b ff d5 }

    condition:
        any of them
}

    
rule kernel32_ScrollConsoleScreenBufferW
{
    meta:
        desc = "Metasploit::API::kernel32::ScrollConsoleScreenBufferW"

    /*
        687473C52B           | push 0x2bc57374
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 73 c5 2b ff d5 }

    condition:
        any of them
}

    
rule kernel32_SearchPathA
{
    meta:
        desc = "Metasploit::API::kernel32::SearchPathA"

    /*
        687C550631           | push 0x3106557c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 55 06 31 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SearchPathW
{
    meta:
        desc = "Metasploit::API::kernel32::SearchPathW"

    /*
        687C55B631           | push 0x31b6557c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 55 b6 31 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCachedSigningLevel
{
    meta:
        desc = "Metasploit::API::kernel32::SetCachedSigningLevel"

    /*
        686602D640           | push 0x40d60266
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 02 d6 40 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCalendarInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::SetCalendarInfoA"

    /*
        6815653649           | push 0x49366515
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 65 36 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCalendarInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::SetCalendarInfoW"

    /*
        681565E649           | push 0x49e66515
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 65 e6 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetComPlusPackageInstallStatus
{
    meta:
        desc = "Metasploit::API::kernel32::SetComPlusPackageInstallStatus"

    /*
        681B7F3BD3           | push 0xd33b7f1b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 7f 3b d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCommBreak
{
    meta:
        desc = "Metasploit::API::kernel32::SetCommBreak"

    /*
        68297A8ED1           | push 0xd18e7a29
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 7a 8e d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCommConfig
{
    meta:
        desc = "Metasploit::API::kernel32::SetCommConfig"

    /*
        68539D653A           | push 0x3a659d53
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 53 9d 65 3a ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCommMask
{
    meta:
        desc = "Metasploit::API::kernel32::SetCommMask"

    /*
        68CAB1695D           | push 0x5d69b1ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca b1 69 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCommState
{
    meta:
        desc = "Metasploit::API::kernel32::SetCommState"

    /*
        68F19E5E49           | push 0x495e9ef1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 9e 5e 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCommTimeouts
{
    meta:
        desc = "Metasploit::API::kernel32::SetCommTimeouts"

    /*
        688331E530           | push 0x30e53183
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 31 e5 30 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetComputerNameA
{
    meta:
        desc = "Metasploit::API::kernel32::SetComputerNameA"

    /*
        68FBCB37A7           | push 0xa737cbfb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb cb 37 a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetComputerNameEx2W
{
    meta:
        desc = "Metasploit::API::kernel32::SetComputerNameEx2W"

    /*
        68C57490C7           | push 0xc79074c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 74 90 c7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetComputerNameExA
{
    meta:
        desc = "Metasploit::API::kernel32::SetComputerNameExA"

    /*
        681F7DE4BE           | push 0xbee47d1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 7d e4 be ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetComputerNameExW
{
    meta:
        desc = "Metasploit::API::kernel32::SetComputerNameExW"

    /*
        681F7D94BF           | push 0xbf947d1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 7d 94 bf ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetComputerNameW
{
    meta:
        desc = "Metasploit::API::kernel32::SetComputerNameW"

    /*
        68FBCBE7A7           | push 0xa7e7cbfb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb cb e7 a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleActiveScreenBuffer
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleActiveScreenBuffer"

    /*
        6826629217           | push 0x17926226
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 62 92 17 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleCP
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleCP"

    /*
        68DF12CE50           | push 0x50ce12df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 12 ce 50 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleCtrlHandler
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleCtrlHandler"

    /*
        684C37ADD3           | push 0xd3ad374c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 37 ad d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleCursor
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleCursor"

    /*
        688FAE06EC           | push 0xec06ae8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f ae 06 ec ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleCursorInfo
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleCursorInfo"

    /*
        68F015A7EB           | push 0xeba715f0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 15 a7 eb ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleCursorMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleCursorMode"

    /*
        68705557ED           | push 0xed575570
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 55 57 ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleCursorPosition
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleCursorPosition"

    /*
        6847D84BEF           | push 0xef4bd847
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 d8 4b ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleDisplayMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleDisplayMode"

    /*
        688FD3459D           | push 0x9d45d38f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f d3 45 9d ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleFont
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleFont"

    /*
        68C9630E5C           | push 0x5c0e63c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 63 0e 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleHardwareState
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleHardwareState"

    /*
        68ABB7E535           | push 0x35e5b7ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab b7 e5 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleHistoryInfo
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleHistoryInfo"

    /*
        686F94E19F           | push 0x9fe1946f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 94 e1 9f ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleIcon
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleIcon"

    /*
        680994DE43           | push 0x43de9409
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 94 de 43 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleInputExeNameA
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleInputExeNameA"

    /*
        687D6D40F1           | push 0xf1406d7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 6d 40 f1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleInputExeNameW
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleInputExeNameW"

    /*
        687D6DF0F1           | push 0xf1f06d7d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 6d f0 f1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleKeyShortcuts
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleKeyShortcuts"

    /*
        6895C9C999           | push 0x99c9c995
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 c9 c9 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleLocalEUDC
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleLocalEUDC"

    /*
        68284D2F23           | push 0x232f4d28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 4d 2f 23 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleMaximumWindowSize
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleMaximumWindowSize"

    /*
        685C45CC06           | push 0x06cc455c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 45 cc 06 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleMenuClose
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleMenuClose"

    /*
        6834D291CE           | push 0xce91d234
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 d2 91 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleMode"

    /*
        6849D1965B           | push 0x5b96d149
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 d1 96 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleNlsMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleNlsMode"

    /*
        68777F5BD3           | push 0xd35b7f77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 7f 5b d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleNumberOfCommandsA
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleNumberOfCommandsA"

    /*
        688BA87C58           | push 0x587ca88b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b a8 7c 58 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleNumberOfCommandsW
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleNumberOfCommandsW"

    /*
        688BA82C59           | push 0x592ca88b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b a8 2c 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleOS2OemFormat
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleOS2OemFormat"

    /*
        68C094FE45           | push 0x45fe94c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 94 fe 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleOutputCP
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleOutputCP"

    /*
        68EE741D7B           | push 0x7b1d74ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 74 1d 7b ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsolePalette
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsolePalette"

    /*
        68B303315D           | push 0x5d3103b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 03 31 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleScreenBufferInfoEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleScreenBufferInfoEx"

    /*
        688F1D0033           | push 0x33001d8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 1d 00 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleScreenBufferSize
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleScreenBufferSize"

    /*
        68AFFFD15E           | push 0x5ed1ffaf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af ff d1 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleTextAttribute
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleTextAttribute"

    /*
        683AE82277           | push 0x7722e83a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a e8 22 77 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleTitleA
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleTitleA"

    /*
        6809CCC2DC           | push 0xdcc2cc09
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 cc c2 dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleTitleW
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleTitleW"

    /*
        6809CC72DD           | push 0xdd72cc09
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 cc 72 dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetConsoleWindowInfo
{
    meta:
        desc = "Metasploit::API::kernel32::SetConsoleWindowInfo"

    /*
        6817B4A667           | push 0x67a6b417
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 b4 a6 67 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCriticalSectionSpinCount
{
    meta:
        desc = "Metasploit::API::kernel32::SetCriticalSectionSpinCount"

    /*
        6809A91724           | push 0x2417a909
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 a9 17 24 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCurrentConsoleFontEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetCurrentConsoleFontEx"

    /*
        6835536F65           | push 0x656f5335
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 53 6f 65 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCurrentDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::SetCurrentDirectoryA"

    /*
        6812152DAD           | push 0xad2d1512
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 15 2d ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetCurrentDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::SetCurrentDirectoryW"

    /*
        681215DDAD           | push 0xaddd1512
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 12 15 dd ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetDefaultCommConfigA
{
    meta:
        desc = "Metasploit::API::kernel32::SetDefaultCommConfigA"

    /*
        68C847954D           | push 0x4d9547c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 47 95 4d ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetDefaultCommConfigW
{
    meta:
        desc = "Metasploit::API::kernel32::SetDefaultCommConfigW"

    /*
        68C847454E           | push 0x4e4547c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 47 45 4e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetDefaultDllDirectories
{
    meta:
        desc = "Metasploit::API::kernel32::SetDefaultDllDirectories"

    /*
        681A281ABB           | push 0xbb1a281a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 28 1a bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetDllDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::SetDllDirectoryA"

    /*
        68D3507AAF           | push 0xaf7a50d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 50 7a af ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetDllDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::SetDllDirectoryW"

    /*
        68D3502AB0           | push 0xb02a50d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 50 2a b0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetDynamicTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::kernel32::SetDynamicTimeZoneInformation"

    /*
        681039CD75           | push 0x75cd3910
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 39 cd 75 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetEndOfFile
{
    meta:
        desc = "Metasploit::API::kernel32::SetEndOfFile"

    /*
        68DBCBE3D7           | push 0xd7e3cbdb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db cb e3 d7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetEnvironmentStringsA
{
    meta:
        desc = "Metasploit::API::kernel32::SetEnvironmentStringsA"

    /*
        684C94718B           | push 0x8b71944c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 94 71 8b ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetEnvironmentStringsW
{
    meta:
        desc = "Metasploit::API::kernel32::SetEnvironmentStringsW"

    /*
        684C94218C           | push 0x8c21944c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 94 21 8c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetEnvironmentVariableA
{
    meta:
        desc = "Metasploit::API::kernel32::SetEnvironmentVariableA"

    /*
        68E7AD4EDF           | push 0xdf4eade7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 ad 4e df ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetEnvironmentVariableW
{
    meta:
        desc = "Metasploit::API::kernel32::SetEnvironmentVariableW"

    /*
        68E7ADFEDF           | push 0xdffeade7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 ad fe df ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetErrorMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetErrorMode"

    /*
        68A13B64E8           | push 0xe8643ba1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 3b 64 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetEvent
{
    meta:
        desc = "Metasploit::API::kernel32::SetEvent"

    /*
        681D9F2635           | push 0x35269f1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 9f 26 35 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetEventWhenCallbackReturns
{
    meta:
        desc = "Metasploit::API::kernel32::SetEventWhenCallbackReturns"

    /*
        6823682AC7           | push 0xc72a6823
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 68 2a c7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileApisToANSI
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileApisToANSI"

    /*
        68A9EBFE10           | push 0x10feeba9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 eb fe 10 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileApisToOEM
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileApisToOEM"

    /*
        681B0419A9           | push 0xa919041b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 04 19 a9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileAttributesA
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileAttributesA"

    /*
        6893CE015E           | push 0x5e01ce93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 ce 01 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileAttributesTransactedA
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileAttributesTransactedA"

    /*
        6877344041           | push 0x41403477
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 34 40 41 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileAttributesTransactedW
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileAttributesTransactedW"

    /*
        687734F041           | push 0x41f03477
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 34 f0 41 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileAttributesW
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileAttributesW"

    /*
        6893CEB15E           | push 0x5eb1ce93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 ce b1 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileBandwidthReservation
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileBandwidthReservation"

    /*
        68307D0BD3           | push 0xd30b7d30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 7d 0b d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileCompletionNotificationModes
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileCompletionNotificationModes"

    /*
        68A296180C           | push 0x0c1896a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 96 18 0c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileInformationByHandle
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileInformationByHandle"

    /*
        68731750EF           | push 0xef501773
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 17 50 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileIoOverlappedRange
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileIoOverlappedRange"

    /*
        68C5DB3DED           | push 0xed3ddbc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 db 3d ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFilePointer
{
    meta:
        desc = "Metasploit::API::kernel32::SetFilePointer"

    /*
        68AACD12D8           | push 0xd812cdaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa cd 12 d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFilePointerEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetFilePointerEx"

    /*
        682BDC5CEF           | push 0xef5cdc2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b dc 5c ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileShortNameA
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileShortNameA"

    /*
        68FDAF4055           | push 0x5540affd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd af 40 55 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileShortNameW
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileShortNameW"

    /*
        68FDAFF055           | push 0x55f0affd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd af f0 55 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileTime"

    /*
        68861F3670           | push 0x70361f86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 1f 36 70 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFileValidData
{
    meta:
        desc = "Metasploit::API::kernel32::SetFileValidData"

    /*
        6843088FBE           | push 0xbe8f0843
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 08 8f be ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFirmwareEnvironmentVariableA
{
    meta:
        desc = "Metasploit::API::kernel32::SetFirmwareEnvironmentVariableA"

    /*
        68F2BF8EE1           | push 0xe18ebff2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 bf 8e e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFirmwareEnvironmentVariableExA
{
    meta:
        desc = "Metasploit::API::kernel32::SetFirmwareEnvironmentVariableExA"

    /*
        68ED7AA154           | push 0x54a17aed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 7a a1 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFirmwareEnvironmentVariableExW
{
    meta:
        desc = "Metasploit::API::kernel32::SetFirmwareEnvironmentVariableExW"

    /*
        68ED7A5155           | push 0x55517aed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 7a 51 55 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetFirmwareEnvironmentVariableW
{
    meta:
        desc = "Metasploit::API::kernel32::SetFirmwareEnvironmentVariableW"

    /*
        68F2BF3EE2           | push 0xe23ebff2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 bf 3e e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetHandleCount
{
    meta:
        desc = "Metasploit::API::kernel32::SetHandleCount"

    /*
        6855F3FED8           | push 0xd8fef355
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 f3 fe d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetHandleInformation
{
    meta:
        desc = "Metasploit::API::kernel32::SetHandleInformation"

    /*
        68CA13D31C           | push 0x1cd313ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 13 d3 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetInformationJobObject
{
    meta:
        desc = "Metasploit::API::kernel32::SetInformationJobObject"

    /*
        68D69700E0           | push 0xe00097d6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 97 00 e0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetIoRateControlInformationJobObject
{
    meta:
        desc = "Metasploit::API::kernel32::SetIoRateControlInformationJobObject"

    /*
        68F993A0AA           | push 0xaaa093f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 93 a0 aa ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetLastConsoleEventActive
{
    meta:
        desc = "Metasploit::API::kernel32::SetLastConsoleEventActive"

    /*
        683A3F5155           | push 0x55513f3a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 3f 51 55 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetLastError
{
    meta:
        desc = "Metasploit::API::kernel32::SetLastError"

    /*
        686AC6E25D           | push 0x5de2c66a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a c6 e2 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetLocalPrimaryComputerNameA
{
    meta:
        desc = "Metasploit::API::kernel32::SetLocalPrimaryComputerNameA"

    /*
        68BA386AD3           | push 0xd36a38ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 38 6a d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetLocalPrimaryComputerNameW
{
    meta:
        desc = "Metasploit::API::kernel32::SetLocalPrimaryComputerNameW"

    /*
        68BA381AD4           | push 0xd41a38ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 38 1a d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetLocalTime
{
    meta:
        desc = "Metasploit::API::kernel32::SetLocalTime"

    /*
        68FEE32CD9           | push 0xd92ce3fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe e3 2c d9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetLocaleInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::SetLocaleInfoA"

    /*
        689B8B6E36           | push 0x366e8b9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 8b 6e 36 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetLocaleInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::SetLocaleInfoW"

    /*
        689B8B1E37           | push 0x371e8b9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 8b 1e 37 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetMailslotInfo
{
    meta:
        desc = "Metasploit::API::kernel32::SetMailslotInfo"

    /*
        680AC7AEC1           | push 0xc1aec70a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a c7 ae c1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetMessageWaitingIndicator
{
    meta:
        desc = "Metasploit::API::kernel32::SetMessageWaitingIndicator"

    /*
        68C9BCCF04           | push 0x04cfbcc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 bc cf 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetNamedPipeAttribute
{
    meta:
        desc = "Metasploit::API::kernel32::SetNamedPipeAttribute"

    /*
        68546CA0E2           | push 0xe2a06c54
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 6c a0 e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetNamedPipeHandleState
{
    meta:
        desc = "Metasploit::API::kernel32::SetNamedPipeHandleState"

    /*
        68B86246BC           | push 0xbc4662b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 62 46 bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetPriorityClass
{
    meta:
        desc = "Metasploit::API::kernel32::SetPriorityClass"

    /*
        6885695CCC           | push 0xcc5c6985
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 69 5c cc ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessAffinityMask
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessAffinityMask"

    /*
        68F94D43FF           | push 0xff434df9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 4d 43 ff ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessAffinityUpdateMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessAffinityUpdateMode"

    /*
        6820292AC3           | push 0xc32a2920
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 29 2a c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessDEPPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessDEPPolicy"

    /*
        68ED85B87A           | push 0x7ab885ed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 85 b8 7a ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessDefaultCpuSets
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessDefaultCpuSets"

    /*
        6800194F6F           | push 0x6f4f1900
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 19 4f 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessInformation
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessInformation"

    /*
        68FAB78AD7           | push 0xd78ab7fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa b7 8a d7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessMitigationPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessMitigationPolicy"

    /*
        68969F5F2D           | push 0x2d5f9f96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 9f 5f 2d ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessPreferredUILanguages"

    /*
        689CFBF3EB           | push 0xebf3fb9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c fb f3 eb ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessPriorityBoost
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessPriorityBoost"

    /*
        68377ED14E           | push 0x4ed17e37
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 7e d1 4e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessShutdownParameters
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessShutdownParameters"

    /*
        68E0FCF8E4           | push 0xe4f8fce0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 fc f8 e4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessWorkingSetSize
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessWorkingSetSize"

    /*
        683D79C7EE           | push 0xeec7793d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 79 c7 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProcessWorkingSetSizeEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetProcessWorkingSetSizeEx"

    /*
        68F1C0879C           | push 0x9c87c0f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 c0 87 9c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetProtectedPolicy
{
    meta:
        desc = "Metasploit::API::kernel32::SetProtectedPolicy"

    /*
        68DD6E415C           | push 0x5c416edd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 6e 41 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetSearchPathMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetSearchPathMode"

    /*
        68FEA07939           | push 0x3979a0fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe a0 79 39 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetStdHandle
{
    meta:
        desc = "Metasploit::API::kernel32::SetStdHandle"

    /*
        68D8BBCA53           | push 0x53cabbd8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 bb ca 53 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetStdHandleEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetStdHandleEx"

    /*
        68CA6758DD           | push 0xdd5867ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 67 58 dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetSystemFileCacheSize
{
    meta:
        desc = "Metasploit::API::kernel32::SetSystemFileCacheSize"

    /*
        688F6F3FAD           | push 0xad3f6f8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 6f 3f ad ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetSystemPowerState
{
    meta:
        desc = "Metasploit::API::kernel32::SetSystemPowerState"

    /*
        68B87419C5           | push 0xc51974b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 74 19 c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetSystemTime
{
    meta:
        desc = "Metasploit::API::kernel32::SetSystemTime"

    /*
        68364FDC46           | push 0x46dc4f36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 4f dc 46 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetSystemTimeAdjustment
{
    meta:
        desc = "Metasploit::API::kernel32::SetSystemTimeAdjustment"

    /*
        685C7F3039           | push 0x39307f5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 7f 30 39 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetTapeParameters
{
    meta:
        desc = "Metasploit::API::kernel32::SetTapeParameters"

    /*
        6868E1B505           | push 0x05b5e168
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 e1 b5 05 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetTapePosition
{
    meta:
        desc = "Metasploit::API::kernel32::SetTapePosition"

    /*
        681642B9D4           | push 0xd4b94216
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 42 b9 d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetTermsrvAppInstallMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetTermsrvAppInstallMode"

    /*
        68CAEB9FDA           | push 0xda9febca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca eb 9f da ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadAffinityMask
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadAffinityMask"

    /*
        68744C4900           | push 0x00494c74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 4c 49 00 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadContext
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadContext"

    /*
        68185C4ED1           | push 0xd14e5c18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 5c 4e d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadDescription
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadDescription"

    /*
        68208040CB           | push 0xcb408020
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 80 40 cb ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadErrorMode
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadErrorMode"

    /*
        68F0DF91B6           | push 0xb691dff0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 df 91 b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadExecutionState
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadExecutionState"

    /*
        682011DDA6           | push 0xa6dd1120
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 11 dd a6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadGroupAffinity
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadGroupAffinity"

    /*
        68FC64110A           | push 0x0a1164fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 64 11 0a ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadIdealProcessor
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadIdealProcessor"

    /*
        68E6EF138A           | push 0x8a13efe6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 ef 13 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadIdealProcessorEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadIdealProcessorEx"

    /*
        68576BA56F           | push 0x6fa56b57
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 6b a5 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadInformation
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadInformation"

    /*
        681B185A97           | push 0x975a181b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b 18 5a 97 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadLocale
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadLocale"

    /*
        68F92FE254           | push 0x54e22ff9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 2f e2 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadPreferredUILanguages
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadPreferredUILanguages"

    /*
        689A01F566           | push 0x66f5019a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 01 f5 66 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadPriority
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadPriority"

    /*
        6831DC552F           | push 0x2f55dc31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 dc 55 2f ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadPriorityBoost
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadPriorityBoost"

    /*
        686786A942           | push 0x42a98667
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 86 a9 42 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadSelectedCpuSets
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadSelectedCpuSets"

    /*
        68CB6A4683           | push 0x83466acb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 6a 46 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadStackGuarantee
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadStackGuarantee"

    /*
        68647BEB56           | push 0x56eb7b64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 7b eb 56 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadToken
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadToken"

    /*
        68BF0FE305           | push 0x05e30fbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 0f e3 05 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadUILanguage
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadUILanguage"

    /*
        68C14C77B2           | push 0xb2774cc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 4c 77 b2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadpoolStackInformation
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadpoolStackInformation"

    /*
        683CBB3CFA           | push 0xfa3cbb3c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c bb 3c fa ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadpoolThreadMaximum
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadpoolThreadMaximum"

    /*
        68C887C8BC           | push 0xbcc887c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 87 c8 bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadpoolThreadMinimum
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadpoolThreadMinimum"

    /*
        68C387E8BC           | push 0xbce887c3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c3 87 e8 bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadpoolTimer
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadpoolTimer"

    /*
        68C1F7F0AF           | push 0xaff0f7c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 f7 f0 af ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadpoolTimerEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadpoolTimerEx"

    /*
        68E161E7E6           | push 0xe6e761e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 61 e7 e6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadpoolWait
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadpoolWait"

    /*
        68102944BF           | push 0xbf442910
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 29 44 bf ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetThreadpoolWaitEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetThreadpoolWaitEx"

    /*
        68A5B5B3BB           | push 0xbbb3b5a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 b5 b3 bb ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::kernel32::SetTimeZoneInformation"

    /*
        683EA049AB           | push 0xab49a03e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e a0 49 ab ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetTimerQueueTimer
{
    meta:
        desc = "Metasploit::API::kernel32::SetTimerQueueTimer"

    /*
        687C2477E3           | push 0xe377247c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 24 77 e3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetUmsThreadInformation
{
    meta:
        desc = "Metasploit::API::kernel32::SetUmsThreadInformation"

    /*
        68AF29B4C1           | push 0xc1b429af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 29 b4 c1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetUnhandledExceptionFilter
{
    meta:
        desc = "Metasploit::API::kernel32::SetUnhandledExceptionFilter"

    /*
        68FE0E32EA           | push 0xea320efe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 0e 32 ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetUserGeoID
{
    meta:
        desc = "Metasploit::API::kernel32::SetUserGeoID"

    /*
        682B336A68           | push 0x686a332b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 33 6a 68 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetUserGeoName
{
    meta:
        desc = "Metasploit::API::kernel32::SetUserGeoName"

    /*
        688F969E3E           | push 0x3e9e968f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 96 9e 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetVDMCurrentDirectories
{
    meta:
        desc = "Metasploit::API::kernel32::SetVDMCurrentDirectories"

    /*
        68977AA964           | push 0x64a97a97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 7a a9 64 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetVolumeLabelA
{
    meta:
        desc = "Metasploit::API::kernel32::SetVolumeLabelA"

    /*
        6831A0D0E7           | push 0xe7d0a031
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 a0 d0 e7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetVolumeLabelW
{
    meta:
        desc = "Metasploit::API::kernel32::SetVolumeLabelW"

    /*
        6831A080E8           | push 0xe880a031
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 a0 80 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetVolumeMountPointA
{
    meta:
        desc = "Metasploit::API::kernel32::SetVolumeMountPointA"

    /*
        68C1218D24           | push 0x248d21c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 21 8d 24 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetVolumeMountPointW
{
    meta:
        desc = "Metasploit::API::kernel32::SetVolumeMountPointW"

    /*
        68C1213D25           | push 0x253d21c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 21 3d 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetVolumeMountPointWStub
{
    meta:
        desc = "Metasploit::API::kernel32::SetVolumeMountPointWStub"

    /*
        6843DD725E           | push 0x5e72dd43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 dd 72 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetWaitableTimer
{
    meta:
        desc = "Metasploit::API::kernel32::SetWaitableTimer"

    /*
        68FFAB83A0           | push 0xa083abff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff ab 83 a0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetWaitableTimerEx
{
    meta:
        desc = "Metasploit::API::kernel32::SetWaitableTimerEx"

    /*
        685D71940B           | push 0x0b94715d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 71 94 0b ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetXStateFeaturesMask
{
    meta:
        desc = "Metasploit::API::kernel32::SetXStateFeaturesMask"

    /*
        6837F18D48           | push 0x488df137
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 f1 8d 48 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SetupComm
{
    meta:
        desc = "Metasploit::API::kernel32::SetupComm"

    /*
        68D308F2DA           | push 0xdaf208d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 08 f2 da ff d5 }

    condition:
        any of them
}

    
rule kernel32_ShowConsoleCursor
{
    meta:
        desc = "Metasploit::API::kernel32::ShowConsoleCursor"

    /*
        6828BD1B2C           | push 0x2c1bbd28
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 28 bd 1b 2c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SignalObjectAndWait
{
    meta:
        desc = "Metasploit::API::kernel32::SignalObjectAndWait"

    /*
        68EA201471           | push 0x711420ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 20 14 71 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SizeofResource
{
    meta:
        desc = "Metasploit::API::kernel32::SizeofResource"

    /*
        682E10F942           | push 0x42f9102e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 10 f9 42 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Sleep
{
    meta:
        desc = "Metasploit::API::kernel32::Sleep"

    /*
        6844F035E0           | push 0xe035f044
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 f0 35 e0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SleepConditionVariableCS
{
    meta:
        desc = "Metasploit::API::kernel32::SleepConditionVariableCS"

    /*
        680A320AD2           | push 0xd20a320a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 32 0a d2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SleepConditionVariableSRW
{
    meta:
        desc = "Metasploit::API::kernel32::SleepConditionVariableSRW"

    /*
        687211E98E           | push 0x8ee91172
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 11 e9 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_SleepEx
{
    meta:
        desc = "Metasploit::API::kernel32::SleepEx"

    /*
        68AD8225F8           | push 0xf82582ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 82 25 f8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SortCloseHandle
{
    meta:
        desc = "Metasploit::API::kernel32::SortCloseHandle"

    /*
        68115A89EB           | push 0xeb895a11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 5a 89 eb ff d5 }

    condition:
        any of them
}

    
rule kernel32_SortGetHandle
{
    meta:
        desc = "Metasploit::API::kernel32::SortGetHandle"

    /*
        68985F646E           | push 0x6e645f98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 5f 64 6e ff d5 }

    condition:
        any of them
}

    
rule kernel32_StartThreadpoolIo
{
    meta:
        desc = "Metasploit::API::kernel32::StartThreadpoolIo"

    /*
        68D31D372C           | push 0x2c371dd3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 1d 37 2c ff d5 }

    condition:
        any of them
}

    
rule kernel32_SubmitThreadpoolWork
{
    meta:
        desc = "Metasploit::API::kernel32::SubmitThreadpoolWork"

    /*
        6825168123           | push 0x23811625
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 16 81 23 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SuspendThread
{
    meta:
        desc = "Metasploit::API::kernel32::SuspendThread"

    /*
        683B8B8FF9           | push 0xf98f8b3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 8b 8f f9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SwitchToFiber
{
    meta:
        desc = "Metasploit::API::kernel32::SwitchToFiber"

    /*
        684BEA56EE           | push 0xee56ea4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b ea 56 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_SwitchToThread
{
    meta:
        desc = "Metasploit::API::kernel32::SwitchToThread"

    /*
        68D8EF92B1           | push 0xb192efd8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 ef 92 b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SystemTimeToFileTime
{
    meta:
        desc = "Metasploit::API::kernel32::SystemTimeToFileTime"

    /*
        6805440152           | push 0x52014405
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 44 01 52 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SystemTimeToTzSpecificLocalTime
{
    meta:
        desc = "Metasploit::API::kernel32::SystemTimeToTzSpecificLocalTime"

    /*
        68B860D715           | push 0x15d760b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 60 d7 15 ff d5 }

    condition:
        any of them
}

    
rule kernel32_SystemTimeToTzSpecificLocalTimeEx
{
    meta:
        desc = "Metasploit::API::kernel32::SystemTimeToTzSpecificLocalTimeEx"

    /*
        68BA9F8160           | push 0x60819fba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 9f 81 60 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TerminateJobObject
{
    meta:
        desc = "Metasploit::API::kernel32::TerminateJobObject"

    /*
        686BD9EFFD           | push 0xfdefd96b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b d9 ef fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_TerminateProcess
{
    meta:
        desc = "Metasploit::API::kernel32::TerminateProcess"

    /*
        6887DCCA5E           | push 0x5ecadc87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 dc ca 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_TerminateThread
{
    meta:
        desc = "Metasploit::API::kernel32::TerminateThread"

    /*
        68E5FEFC0E           | push 0x0efcfee5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e5 fe fc 0e ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvAppInstallMode
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvAppInstallMode"

    /*
        68FA96FFCD           | push 0xcdff96fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 96 ff cd ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvConvertSysRootToUserDir
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvConvertSysRootToUserDir"

    /*
        68CC079DC5           | push 0xc59d07cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 07 9d c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvCreateRegEntry
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvCreateRegEntry"

    /*
        683842BDB7           | push 0xb7bd4238
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 42 bd b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvDeleteKey
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvDeleteKey"

    /*
        682F7DCDEA           | push 0xeacd7d2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 7d cd ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvDeleteValue
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvDeleteValue"

    /*
        6875897003           | push 0x03708975
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 89 70 03 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvGetPreSetValue
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvGetPreSetValue"

    /*
        68F083AEA1           | push 0xa1ae83f0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 83 ae a1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvGetWindowsDirectoryA
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvGetWindowsDirectoryA"

    /*
        68B48DD310           | push 0x10d38db4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 8d d3 10 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvGetWindowsDirectoryW
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvGetWindowsDirectoryW"

    /*
        68B48D8311           | push 0x11838db4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 8d 83 11 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvOpenRegEntry
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvOpenRegEntry"

    /*
        68C508AD47           | push 0x47ad08c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 08 ad 47 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvOpenUserClasses
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvOpenUserClasses"

    /*
        6899B69680           | push 0x8096b699
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 b6 96 80 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvRestoreKey
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvRestoreKey"

    /*
        68B7740F9C           | push 0x9c0f74b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 74 0f 9c ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvSetKeySecurity
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvSetKeySecurity"

    /*
        68BC6302DC           | push 0xdc0263bc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bc 63 02 dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvSetValueKey
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvSetValueKey"

    /*
        6824034B33           | push 0x334b0324
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 03 4b 33 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TermsrvSyncUserIniFileExt
{
    meta:
        desc = "Metasploit::API::kernel32::TermsrvSyncUserIniFileExt"

    /*
        68C52E0B49           | push 0x490b2ec5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 2e 0b 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Thread32First
{
    meta:
        desc = "Metasploit::API::kernel32::Thread32First"

    /*
        68B7D8044A           | push 0x4a04d8b7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 d8 04 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_Thread32Next
{
    meta:
        desc = "Metasploit::API::kernel32::Thread32Next"

    /*
        68D04EF342           | push 0x42f34ed0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 4e f3 42 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TlsAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::TlsAlloc"

    /*
        683B009A43           | push 0x439a003b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 00 9a 43 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TlsFree
{
    meta:
        desc = "Metasploit::API::kernel32::TlsFree"

    /*
        68D49A8BFB           | push 0xfb8b9ad4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 9a 8b fb ff d5 }

    condition:
        any of them
}

    
rule kernel32_TlsGetValue
{
    meta:
        desc = "Metasploit::API::kernel32::TlsGetValue"

    /*
        6801E958B7           | push 0xb758e901
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 e9 58 b7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TlsSetValue
{
    meta:
        desc = "Metasploit::API::kernel32::TlsSetValue"

    /*
        6801E958C3           | push 0xc358e901
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 e9 58 c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Toolhelp32ReadProcessMemory
{
    meta:
        desc = "Metasploit::API::kernel32::Toolhelp32ReadProcessMemory"

    /*
        680968CC03           | push 0x03cc6809
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 68 cc 03 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TransactNamedPipe
{
    meta:
        desc = "Metasploit::API::kernel32::TransactNamedPipe"

    /*
        6886712C25           | push 0x252c7186
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 71 2c 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TransmitCommChar
{
    meta:
        desc = "Metasploit::API::kernel32::TransmitCommChar"

    /*
        688A982AE3           | push 0xe32a988a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a 98 2a e3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TryAcquireSRWLockExclusive
{
    meta:
        desc = "Metasploit::API::kernel32::TryAcquireSRWLockExclusive"

    /*
        68C9CB998D           | push 0x8d99cbc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 cb 99 8d ff d5 }

    condition:
        any of them
}

    
rule kernel32_TryAcquireSRWLockShared
{
    meta:
        desc = "Metasploit::API::kernel32::TryAcquireSRWLockShared"

    /*
        6864AABA7F           | push 0x7fbaaa64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 aa ba 7f ff d5 }

    condition:
        any of them
}

    
rule kernel32_TryEnterCriticalSection
{
    meta:
        desc = "Metasploit::API::kernel32::TryEnterCriticalSection"

    /*
        6882B54023           | push 0x2340b582
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 82 b5 40 23 ff d5 }

    condition:
        any of them
}

    
rule kernel32_TrySubmitThreadpoolCallback
{
    meta:
        desc = "Metasploit::API::kernel32::TrySubmitThreadpoolCallback"

    /*
        68948706AC           | push 0xac068794
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 87 06 ac ff d5 }

    condition:
        any of them
}

    
rule kernel32_TzSpecificLocalTimeToSystemTime
{
    meta:
        desc = "Metasploit::API::kernel32::TzSpecificLocalTimeToSystemTime"

    /*
        68769DD2BC           | push 0xbcd29d76
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 9d d2 bc ff d5 }

    condition:
        any of them
}

    
rule kernel32_TzSpecificLocalTimeToSystemTimeEx
{
    meta:
        desc = "Metasploit::API::kernel32::TzSpecificLocalTimeToSystemTimeEx"

    /*
        6824CF501F           | push 0x1f50cf24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 cf 50 1f ff d5 }

    condition:
        any of them
}

    
rule kernel32_UTRegister
{
    meta:
        desc = "Metasploit::API::kernel32::UTRegister"

    /*
        68040DE591           | push 0x91e50d04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 0d e5 91 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UTUnRegister
{
    meta:
        desc = "Metasploit::API::kernel32::UTUnRegister"

    /*
        6854E28D92           | push 0x928de254
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 e2 8d 92 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UmsThreadYield
{
    meta:
        desc = "Metasploit::API::kernel32::UmsThreadYield"

    /*
        6871B9927D           | push 0x7d92b971
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 b9 92 7d ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnhandledExceptionFilter
{
    meta:
        desc = "Metasploit::API::kernel32::UnhandledExceptionFilter"

    /*
        6854CE184A           | push 0x4a18ce54
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 ce 18 4a ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnlockFile
{
    meta:
        desc = "Metasploit::API::kernel32::UnlockFile"

    /*
        6806106B95           | push 0x956b1006
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 10 6b 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnlockFileEx
{
    meta:
        desc = "Metasploit::API::kernel32::UnlockFileEx"

    /*
        681A736D45           | push 0x456d731a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 73 6d 45 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnmapViewOfFile
{
    meta:
        desc = "Metasploit::API::kernel32::UnmapViewOfFile"

    /*
        681EA77C25           | push 0x257ca71e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1e a7 7c 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnmapViewOfFileEx
{
    meta:
        desc = "Metasploit::API::kernel32::UnmapViewOfFileEx"

    /*
        683E39D349           | push 0x49d3393e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 39 d3 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnregisterApplicationRecoveryCallback
{
    meta:
        desc = "Metasploit::API::kernel32::UnregisterApplicationRecoveryCallback"

    /*
        685907FA1C           | push 0x1cfa0759
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 07 fa 1c ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnregisterApplicationRestart
{
    meta:
        desc = "Metasploit::API::kernel32::UnregisterApplicationRestart"

    /*
        683E71CFD5           | push 0xd5cf713e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 71 cf d5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnregisterBadMemoryNotification
{
    meta:
        desc = "Metasploit::API::kernel32::UnregisterBadMemoryNotification"

    /*
        68C0EFF9F3           | push 0xf3f9efc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 ef f9 f3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnregisterConsoleIME
{
    meta:
        desc = "Metasploit::API::kernel32::UnregisterConsoleIME"

    /*
        684CB26A1E           | push 0x1e6ab24c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c b2 6a 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnregisterWait
{
    meta:
        desc = "Metasploit::API::kernel32::UnregisterWait"

    /*
        680E53B7C4           | push 0xc4b7530e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 53 b7 c4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnregisterWaitEx
{
    meta:
        desc = "Metasploit::API::kernel32::UnregisterWaitEx"

    /*
        6826357E18           | push 0x187e3526
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 35 7e 18 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UnregisterWaitUntilOOBECompleted
{
    meta:
        desc = "Metasploit::API::kernel32::UnregisterWaitUntilOOBECompleted"

    /*
        687FE05D99           | push 0x995de07f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7f e0 5d 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UpdateCalendarDayOfWeek
{
    meta:
        desc = "Metasploit::API::kernel32::UpdateCalendarDayOfWeek"

    /*
        68B655822E           | push 0x2e8255b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 55 82 2e ff d5 }

    condition:
        any of them
}

    
rule kernel32_UpdateProcThreadAttribute
{
    meta:
        desc = "Metasploit::API::kernel32::UpdateProcThreadAttribute"

    /*
        6808260951           | push 0x51092608
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 26 09 51 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UpdateResourceA
{
    meta:
        desc = "Metasploit::API::kernel32::UpdateResourceA"

    /*
        68E9B46654           | push 0x5466b4e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 b4 66 54 ff d5 }

    condition:
        any of them
}

    
rule kernel32_UpdateResourceW
{
    meta:
        desc = "Metasploit::API::kernel32::UpdateResourceW"

    /*
        68E9B41655           | push 0x5516b4e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 b4 16 55 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VDMConsoleOperation
{
    meta:
        desc = "Metasploit::API::kernel32::VDMConsoleOperation"

    /*
        68EB648EC5           | push 0xc58e64eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 64 8e c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VDMOperationStarted
{
    meta:
        desc = "Metasploit::API::kernel32::VDMOperationStarted"

    /*
        684C1BE3F8           | push 0xf8e31b4c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 1b e3 f8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VerLanguageNameA
{
    meta:
        desc = "Metasploit::API::kernel32::VerLanguageNameA"

    /*
        6858C38858           | push 0x5888c358
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 c3 88 58 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VerLanguageNameW
{
    meta:
        desc = "Metasploit::API::kernel32::VerLanguageNameW"

    /*
        6858C33859           | push 0x5938c358
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 c3 38 59 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VerSetConditionMask
{
    meta:
        desc = "Metasploit::API::kernel32::VerSetConditionMask"

    /*
        6898DFBCA9           | push 0xa9bcdf98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 df bc a9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VerifyConsoleIoHandle
{
    meta:
        desc = "Metasploit::API::kernel32::VerifyConsoleIoHandle"

    /*
        6875F2C52A           | push 0x2ac5f275
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 f2 c5 2a ff d5 }

    condition:
        any of them
}

    
rule kernel32_VerifyScripts
{
    meta:
        desc = "Metasploit::API::kernel32::VerifyScripts"

    /*
        68DE04C15C           | push 0x5cc104de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 04 c1 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_VerifyVersionInfoA
{
    meta:
        desc = "Metasploit::API::kernel32::VerifyVersionInfoA"

    /*
        685159B73E           | push 0x3eb75951
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 59 b7 3e ff d5 }

    condition:
        any of them
}

    
rule kernel32_VerifyVersionInfoW
{
    meta:
        desc = "Metasploit::API::kernel32::VerifyVersionInfoW"

    /*
        685159673F           | push 0x3f675951
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 59 67 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualAlloc
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualAlloc"

    /*
        6858A453E5           | push 0xe553a458
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 a4 53 e5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualAllocEx
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualAllocEx"

    /*
        68AE87923F           | push 0x3f9287ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 87 92 3f ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualAllocExNuma
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualAllocExNuma"

    /*
        68E95CC9B6           | push 0xb6c95ce9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 5c c9 b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualFree
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualFree"

    /*
        680B2F0F30           | push 0x300f2f0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 2f 0f 30 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualFreeEx
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualFreeEx"

    /*
        68813475EE           | push 0xee753481
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 34 75 ee ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualLock
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualLock"

    /*
        688B8E3F2A           | push 0x2a3f8e8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 8e 3f 2a ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualProtect
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualProtect"

    /*
        6810E18AC3           | push 0xc38ae110
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 e1 8a c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualProtectEx
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualProtectEx"

    /*
        68A6B561CD           | push 0xcd61b5a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 b5 61 cd ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualQuery
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualQuery"

    /*
        68203504D8           | push 0xd8043520
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 35 04 d8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualQueryEx
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualQueryEx"

    /*
        68ABB9B6EB           | push 0xebb6b9ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab b9 b6 eb ff d5 }

    condition:
        any of them
}

    
rule kernel32_VirtualUnlock
{
    meta:
        desc = "Metasploit::API::kernel32::VirtualUnlock"

    /*
        68FFAB4902           | push 0x0249abff
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ff ab 49 02 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WTSGetActiveConsoleSessionId
{
    meta:
        desc = "Metasploit::API::kernel32::WTSGetActiveConsoleSessionId"

    /*
        68A4FAF85C           | push 0x5cf8faa4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 fa f8 5c ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitCommEvent
{
    meta:
        desc = "Metasploit::API::kernel32::WaitCommEvent"

    /*
        684ABE5E7D           | push 0x7d5ebe4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a be 5e 7d ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForDebugEvent
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForDebugEvent"

    /*
        68E3A23C88           | push 0x883ca2e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 a2 3c 88 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForDebugEventEx
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForDebugEventEx"

    /*
        68972AD2F9           | push 0xf9d22a97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 2a d2 f9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForMultipleObjects
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForMultipleObjects"

    /*
        683036D03B           | push 0x3bd03630
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 36 d0 3b ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForMultipleObjectsEx
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForMultipleObjectsEx"

    /*
        68C4FDB6DE           | push 0xdeb6fdc4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 fd b6 de ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForSingleObject
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForSingleObject"

    /*
        6808871D60           | push 0x601d8708
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 87 1d 60 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForSingleObjectEx
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForSingleObjectEx"

    /*
        68CD330BF2           | push 0xf20b33cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 33 0b f2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForThreadpoolIoCallbacks
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForThreadpoolIoCallbacks"

    /*
        68D2994C04           | push 0x044c99d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 99 4c 04 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForThreadpoolTimerCallbacks
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForThreadpoolTimerCallbacks"

    /*
        689D345449           | push 0x4954349d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 34 54 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForThreadpoolWaitCallbacks
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForThreadpoolWaitCallbacks"

    /*
        681A081E1A           | push 0x1a1e081a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 08 1e 1a ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitForThreadpoolWorkCallbacks
{
    meta:
        desc = "Metasploit::API::kernel32::WaitForThreadpoolWorkCallbacks"

    /*
        68F80830DA           | push 0xda3008f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 08 30 da ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitNamedPipeA
{
    meta:
        desc = "Metasploit::API::kernel32::WaitNamedPipeA"

    /*
        688737BA94           | push 0x94ba3787
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 37 ba 94 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WaitNamedPipeW
{
    meta:
        desc = "Metasploit::API::kernel32::WaitNamedPipeW"

    /*
        6887376A95           | push 0x956a3787
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 37 6a 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WakeAllConditionVariable
{
    meta:
        desc = "Metasploit::API::kernel32::WakeAllConditionVariable"

    /*
        686108BF1E           | push 0x1ebf0861
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 08 bf 1e ff d5 }

    condition:
        any of them
}

    
rule kernel32_WakeConditionVariable
{
    meta:
        desc = "Metasploit::API::kernel32::WakeConditionVariable"

    /*
        68B7ADD710           | push 0x10d7adb7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 ad d7 10 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerGetFlags
{
    meta:
        desc = "Metasploit::API::kernel32::WerGetFlags"

    /*
        68778DCFE1           | push 0xe1cf8d77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 8d cf e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerGetFlagsWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerGetFlagsWorker"

    /*
        68D48C17C8           | push 0xc8178cd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 8c 17 c8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterAdditionalProcess
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterAdditionalProcess"

    /*
        680A548388           | push 0x8883540a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 54 83 88 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterAppLocalDump
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterAppLocalDump"

    /*
        68CD45E8EF           | push 0xefe845cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 45 e8 ef ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterCustomMetadata
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterCustomMetadata"

    /*
        68F7B792B5           | push 0xb592b7f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 b7 92 b5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterExcludedMemoryBlock
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterExcludedMemoryBlock"

    /*
        687CE749E0           | push 0xe049e77c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c e7 49 e0 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterFile
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterFile"

    /*
        68D9813EB6           | push 0xb63e81d9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d9 81 3e b6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterFileWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterFileWorker"

    /*
        6890DE9E99           | push 0x999ede90
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 de 9e 99 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterMemoryBlock
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterMemoryBlock"

    /*
        68DF65EDF1           | push 0xf1ed65df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 65 ed f1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterMemoryBlockWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterMemoryBlockWorker"

    /*
        684BCDB729           | push 0x29b7cd4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b cd b7 29 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterRuntimeExceptionModule
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterRuntimeExceptionModule"

    /*
        68BBB3EA3C           | push 0x3ceab3bb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb b3 ea 3c ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerRegisterRuntimeExceptionModuleWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerRegisterRuntimeExceptionModuleWorker"

    /*
        6840F92861           | push 0x6128f940
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 40 f9 28 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerSetFlags
{
    meta:
        desc = "Metasploit::API::kernel32::WerSetFlags"

    /*
        68778DCFED           | push 0xedcf8d77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 8d cf ed ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerSetFlagsWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerSetFlagsWorker"

    /*
        68D4BC17C8           | push 0xc817bcd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 bc 17 c8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterAdditionalProcess
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterAdditionalProcess"

    /*
        686D8632E6           | push 0xe632866d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 86 32 e6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterAppLocalDump
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterAppLocalDump"

    /*
        6892AA46AB           | push 0xab46aa92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 aa 46 ab ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterCustomMetadata
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterCustomMetadata"

    /*
        6825E92B8D           | push 0x8d2be925
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 e9 2b 8d ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterExcludedMemoryBlock
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterExcludedMemoryBlock"

    /*
        681380164C           | push 0x4c168013
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 13 80 16 4c ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterFile
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterFile"

    /*
        689446A314           | push 0x14a34694
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 46 a3 14 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterFileWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterFileWorker"

    /*
        6823588CAC           | push 0xac8c5823
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 58 8c ac ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterMemoryBlock
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterMemoryBlock"

    /*
        684BFD85BE           | push 0xbe85fd4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b fd 85 be ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterMemoryBlockWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterMemoryBlockWorker"

    /*
        68ADFF6687           | push 0x8766ffad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad ff 66 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterRuntimeExceptionModule
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterRuntimeExceptionModule"

    /*
        68EC4CC26B           | push 0x6bc24cec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec 4c c2 6b ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerUnregisterRuntimeExceptionModuleWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerUnregisterRuntimeExceptionModuleWorker"

    /*
        689FB4EDC5           | push 0xc5edb49f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f b4 ed c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerpGetDebugger
{
    meta:
        desc = "Metasploit::API::kernel32::WerpGetDebugger"

    /*
        6819E86083           | push 0x8360e819
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 e8 60 83 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerpInitiateRemoteRecovery
{
    meta:
        desc = "Metasploit::API::kernel32::WerpInitiateRemoteRecovery"

    /*
        6862356FE8           | push 0xe86f3562
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 35 6f e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerpLaunchAeDebug
{
    meta:
        desc = "Metasploit::API::kernel32::WerpLaunchAeDebug"

    /*
        684F6DD5AA           | push 0xaad56d4f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 6d d5 aa ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerpNotifyLoadStringResourceWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerpNotifyLoadStringResourceWorker"

    /*
        68A7439609           | push 0x099643a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 43 96 09 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WerpNotifyUseStringResourceWorker
{
    meta:
        desc = "Metasploit::API::kernel32::WerpNotifyUseStringResourceWorker"

    /*
        68B8CA97F5           | push 0xf597cab8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 ca 97 f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WideCharToMultiByte
{
    meta:
        desc = "Metasploit::API::kernel32::WideCharToMultiByte"

    /*
        68F4217DEA           | push 0xea7d21f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 21 7d ea ff d5 }

    condition:
        any of them
}

    
rule kernel32_WinExec
{
    meta:
        desc = "Metasploit::API::kernel32::WinExec"

    /*
        68318B6F87           | push 0x876f8b31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 8b 6f 87 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Wow64DisableWow64FsRedirection
{
    meta:
        desc = "Metasploit::API::kernel32::Wow64DisableWow64FsRedirection"

    /*
        684FE8A8DE           | push 0xdea8e84f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f e8 a8 de ff d5 }

    condition:
        any of them
}

    
rule kernel32_Wow64EnableWow64FsRedirection
{
    meta:
        desc = "Metasploit::API::kernel32::Wow64EnableWow64FsRedirection"

    /*
        68CF388901           | push 0x018938cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 38 89 01 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Wow64GetThreadContext
{
    meta:
        desc = "Metasploit::API::kernel32::Wow64GetThreadContext"

    /*
        68BFCBEECE           | push 0xceeecbbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf cb ee ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_Wow64GetThreadSelectorEntry
{
    meta:
        desc = "Metasploit::API::kernel32::Wow64GetThreadSelectorEntry"

    /*
        6838F3D617           | push 0x17d6f338
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 f3 d6 17 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Wow64RevertWow64FsRedirection
{
    meta:
        desc = "Metasploit::API::kernel32::Wow64RevertWow64FsRedirection"

    /*
        6823E46A60           | push 0x606ae423
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 e4 6a 60 ff d5 }

    condition:
        any of them
}

    
rule kernel32_Wow64SetThreadContext
{
    meta:
        desc = "Metasploit::API::kernel32::Wow64SetThreadContext"

    /*
        68BFCBFACE           | push 0xcefacbbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf cb fa ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_Wow64SuspendThread
{
    meta:
        desc = "Metasploit::API::kernel32::Wow64SuspendThread"

    /*
        68BA5EC7CF           | push 0xcfc75eba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 5e c7 cf ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleA
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleA"

    /*
        68715DCB5D           | push 0x5dcb5d71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 5d cb 5d ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleInputA
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleInputA"

    /*
        685D576C64           | push 0x646c575d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 57 6c 64 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleInputVDMA
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleInputVDMA"

    /*
        689BF45B24           | push 0x245bf49b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b f4 5b 24 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleInputVDMW
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleInputVDMW"

    /*
        689BF40B25           | push 0x250bf49b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b f4 0b 25 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleInputW
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleInputW"

    /*
        685D571C65           | push 0x651c575d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d 57 1c 65 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleOutputA
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleOutputA"

    /*
        684662F19A           | push 0x9af16246
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 62 f1 9a ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleOutputAttribute
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleOutputAttribute"

    /*
        68DBA4ADE1           | push 0xe1ada4db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db a4 ad e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleOutputCharacterA
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleOutputCharacterA"

    /*
        680F22A1D3           | push 0xd3a1220f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 22 a1 d3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleOutputCharacterW
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleOutputCharacterW"

    /*
        680F2251D4           | push 0xd451220f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f 22 51 d4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleOutputW
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleOutputW"

    /*
        684662A19B           | push 0x9ba16246
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 62 a1 9b ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteConsoleW
{
    meta:
        desc = "Metasploit::API::kernel32::WriteConsoleW"

    /*
        68715D7B5E           | push 0x5e7b5d71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 5d 7b 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteFile
{
    meta:
        desc = "Metasploit::API::kernel32::WriteFile"

    /*
        682D57AE5B           | push 0x5bae572d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 57 ae 5b ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteFileEx
{
    meta:
        desc = "Metasploit::API::kernel32::WriteFileEx"

    /*
        680C3D3FD6           | push 0xd63f3d0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 3d 3f d6 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteFileGather
{
    meta:
        desc = "Metasploit::API::kernel32::WriteFileGather"

    /*
        684894B1E8           | push 0xe8b19448
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 94 b1 e8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WritePrivateProfileSectionA
{
    meta:
        desc = "Metasploit::API::kernel32::WritePrivateProfileSectionA"

    /*
        6852AB3CFD           | push 0xfd3cab52
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 ab 3c fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_WritePrivateProfileSectionW
{
    meta:
        desc = "Metasploit::API::kernel32::WritePrivateProfileSectionW"

    /*
        6852ABECFD           | push 0xfdecab52
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 ab ec fd ff d5 }

    condition:
        any of them
}

    
rule kernel32_WritePrivateProfileStringA
{
    meta:
        desc = "Metasploit::API::kernel32::WritePrivateProfileStringA"

    /*
        68F27111CE           | push 0xce1171f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 71 11 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_WritePrivateProfileStringW
{
    meta:
        desc = "Metasploit::API::kernel32::WritePrivateProfileStringW"

    /*
        68F271C1CE           | push 0xcec171f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 71 c1 ce ff d5 }

    condition:
        any of them
}

    
rule kernel32_WritePrivateProfileStructA
{
    meta:
        desc = "Metasploit::API::kernel32::WritePrivateProfileStructA"

    /*
        68323512B8           | push 0xb8123532
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 35 12 b8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WritePrivateProfileStructW
{
    meta:
        desc = "Metasploit::API::kernel32::WritePrivateProfileStructW"

    /*
        683235C2B8           | push 0xb8c23532
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 35 c2 b8 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteProcessMemory
{
    meta:
        desc = "Metasploit::API::kernel32::WriteProcessMemory"

    /*
        68C5D8BDE7           | push 0xe7bdd8c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 d8 bd e7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteProfileSectionA
{
    meta:
        desc = "Metasploit::API::kernel32::WriteProfileSectionA"

    /*
        685FAD468A           | push 0x8a46ad5f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f ad 46 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteProfileSectionW
{
    meta:
        desc = "Metasploit::API::kernel32::WriteProfileSectionW"

    /*
        685FADF68A           | push 0x8af6ad5f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f ad f6 8a ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteProfileStringA
{
    meta:
        desc = "Metasploit::API::kernel32::WriteProfileStringA"

    /*
        689323530E           | push 0x0e532393
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 23 53 0e ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteProfileStringW
{
    meta:
        desc = "Metasploit::API::kernel32::WriteProfileStringW"

    /*
        689323030F           | push 0x0f032393
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 23 03 0f ff d5 }

    condition:
        any of them
}

    
rule kernel32_WriteTapemark
{
    meta:
        desc = "Metasploit::API::kernel32::WriteTapemark"

    /*
        68EA3E235A           | push 0x5a233eea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea 3e 23 5a ff d5 }

    condition:
        any of them
}

    
rule kernel32_ZombifyActCtx
{
    meta:
        desc = "Metasploit::API::kernel32::ZombifyActCtx"

    /*
        6835D257B1           | push 0xb157d235
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 d2 57 b1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_ZombifyActCtxWorker
{
    meta:
        desc = "Metasploit::API::kernel32::ZombifyActCtxWorker"

    /*
        68F5CA0EDB           | push 0xdb0ecaf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 ca 0e db ff d5 }

    condition:
        any of them
}

    
rule kernel32___C_specific_handler
{
    meta:
        desc = "Metasploit::API::kernel32::__C_specific_handler"

    /*
        6808F14D42           | push 0x424df108
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 f1 4d 42 ff d5 }

    condition:
        any of them
}

    
rule kernel32___chkstk
{
    meta:
        desc = "Metasploit::API::kernel32::__chkstk"

    /*
        68EFEF99DC           | push 0xdc99efef
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ef ef 99 dc ff d5 }

    condition:
        any of them
}

    
rule kernel32___misaligned_access
{
    meta:
        desc = "Metasploit::API::kernel32::__misaligned_access"

    /*
        68CEE3CD74           | push 0x74cde3ce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce e3 cd 74 ff d5 }

    condition:
        any of them
}

    
rule kernel32__hread
{
    meta:
        desc = "Metasploit::API::kernel32::_hread"

    /*
        684E4F5261           | push 0x61524f4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 4f 52 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32__hwrite
{
    meta:
        desc = "Metasploit::API::kernel32::_hwrite"

    /*
        68F65F7EE9           | push 0xe97e5ff6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 5f 7e e9 ff d5 }

    condition:
        any of them
}

    
rule kernel32__lclose
{
    meta:
        desc = "Metasploit::API::kernel32::_lclose"

    /*
        68ACFF8DF5           | push 0xf58dffac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac ff 8d f5 ff d5 }

    condition:
        any of them
}

    
rule kernel32__lcreat
{
    meta:
        desc = "Metasploit::API::kernel32::_lcreat"

    /*
        682C5B06E2           | push 0xe2065b2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 5b 06 e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32__llseek
{
    meta:
        desc = "Metasploit::API::kernel32::_llseek"

    /*
        68306CBE61           | push 0x61be6c30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 6c be 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32__local_unwind
{
    meta:
        desc = "Metasploit::API::kernel32::_local_unwind"

    /*
        684BBD0BC6           | push 0xc60bbd4b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b bd 0b c6 ff d5 }

    condition:
        any of them
}

    
rule kernel32__lopen
{
    meta:
        desc = "Metasploit::API::kernel32::_lopen"

    /*
        685020A277           | push 0x77a22050
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 20 a2 77 ff d5 }

    condition:
        any of them
}

    
rule kernel32__lread
{
    meta:
        desc = "Metasploit::API::kernel32::_lread"

    /*
        68504F5261           | push 0x61524f50
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 4f 52 61 ff d5 }

    condition:
        any of them
}

    
rule kernel32__lwrite
{
    meta:
        desc = "Metasploit::API::kernel32::_lwrite"

    /*
        68F65F8EE9           | push 0xe98e5ff6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 5f 8e e9 ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcat
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcat"

    /*
        68D45C225E           | push 0x5e225cd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 5c 22 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcatA
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcatA"

    /*
        6874728DC4           | push 0xc48d7274
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 72 8d c4 ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcatW
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcatW"

    /*
        6874723DC5           | push 0xc53d7274
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 72 3d c5 ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcmp
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcmp"

    /*
        68D45F025E           | push 0x5e025fd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 5f 02 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcmpA
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcmpA"

    /*
        6874718DDC           | push 0xdc8d7174
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 71 8d dc ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcmpW
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcmpW"

    /*
        6874713DDD           | push 0xdd3d7174
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 71 3d dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcmpi
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcmpi"

    /*
        687471CDDD           | push 0xddcd7174
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 71 cd dd ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcmpiA
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcmpiA"

    /*
        68CC6F8969           | push 0x69896fcc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 6f 89 69 ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcmpiW
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcmpiW"

    /*
        68CC6F396A           | push 0x6a396fcc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 6f 39 6a ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcpy
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcpy"

    /*
        6894604A5E           | push 0x5e4a6094
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 60 4a 5e ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcpyA
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcpyA"

    /*
        68B4738DE2           | push 0xe28d73b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 73 8d e2 ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcpyW
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcpyW"

    /*
        68B4733DE3           | push 0xe33d73b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 73 3d e3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcpyn
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcpyn"

    /*
        68B473F5E3           | push 0xe3f573b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 73 f5 e3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcpynA
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcpynA"

    /*
        680CA1897B           | push 0x7b89a10c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c a1 89 7b ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrcpynW
{
    meta:
        desc = "Metasploit::API::kernel32::lstrcpynW"

    /*
        680CA1397C           | push 0x7c39a10c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c a1 39 7c ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrlen
{
    meta:
        desc = "Metasploit::API::kernel32::lstrlen"

    /*
        68D45DF26F           | push 0x6ff25dd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 5d f2 6f ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrlenA
{
    meta:
        desc = "Metasploit::API::kernel32::lstrlenA"

    /*
        68F4008ECC           | push 0xcc8e00f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 00 8e cc ff d5 }

    condition:
        any of them
}

    
rule kernel32_lstrlenW
{
    meta:
        desc = "Metasploit::API::kernel32::lstrlenW"

    /*
        68F4003ECD           | push 0xcd3e00f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 00 3e cd ff d5 }

    condition:
        any of them
}

    
rule kernel32_timeBeginPeriod
{
    meta:
        desc = "Metasploit::API::kernel32::timeBeginPeriod"

    /*
        6805431F49           | push 0x491f4305
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 43 1f 49 ff d5 }

    condition:
        any of them
}

    
rule kernel32_timeEndPeriod
{
    meta:
        desc = "Metasploit::API::kernel32::timeEndPeriod"

    /*
        68F78DF2D1           | push 0xd1f28df7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 8d f2 d1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_timeGetDevCaps
{
    meta:
        desc = "Metasploit::API::kernel32::timeGetDevCaps"

    /*
        68786A2EC3           | push 0xc32e6a78
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 6a 2e c3 ff d5 }

    condition:
        any of them
}

    
rule kernel32_timeGetSystemTime
{
    meta:
        desc = "Metasploit::API::kernel32::timeGetSystemTime"

    /*
        68E4E646E1           | push 0xe146e6e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 e6 46 e1 ff d5 }

    condition:
        any of them
}

    
rule kernel32_timeGetTime
{
    meta:
        desc = "Metasploit::API::kernel32::timeGetTime"

    /*
        684FE35B0F           | push 0x0f5be34f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f e3 5b 0f ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_lstrcmpW
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_lstrcmpW"

    /*
        68E270029E           | push 0x9e0270e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 70 02 9e ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_lstrcmpiW
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_lstrcmpiW"

    /*
        68F475A765           | push 0x65a775f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 75 a7 65 ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_lstrlenW
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_lstrlenW"

    /*
        686100038E           | push 0x8e030061
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 00 03 8e ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_wcschr
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_wcschr"

    /*
        680A752595           | push 0x9525750a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 75 25 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_wcscpy
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_wcscpy"

    /*
        680A775D95           | push 0x955d770a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 77 5d 95 ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_wcsicmp
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_wcsicmp"

    /*
        684C89AF7D           | push 0x7daf894c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 89 af 7d ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_wcslen
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_wcslen"

    /*
        684A7405A7           | push 0xa705744a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 74 05 a7 ff d5 }

    condition:
        any of them
}

    
rule kernel32_uaw_wcsrchr
{
    meta:
        desc = "Metasploit::API::kernel32::uaw_wcsrchr"

    /*
        680C18C07D           | push 0x7dc0180c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 18 c0 7d ff d5 }

    condition:
        any of them
}

    