
rule advapi32_A_SHAFinal
{
    meta:
        desc = "Metasploit::API::advapi32::A_SHAFinal"

    /*
        68A5A6FE55           | push 0x55fea6a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 a6 fe 55 ff d5 }

    condition:
        any of them
}

    
rule advapi32_A_SHAInit
{
    meta:
        desc = "Metasploit::API::advapi32::A_SHAInit"

    /*
        68F2B957A2           | push 0xa257b9f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 b9 57 a2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_A_SHAUpdate
{
    meta:
        desc = "Metasploit::API::advapi32::A_SHAUpdate"

    /*
        68A1FA97B1           | push 0xb197faa1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 fa 97 b1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AbortSystemShutdownA
{
    meta:
        desc = "Metasploit::API::advapi32::AbortSystemShutdownA"

    /*
        687E62F342           | push 0x42f3627e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 62 f3 42 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AbortSystemShutdownW
{
    meta:
        desc = "Metasploit::API::advapi32::AbortSystemShutdownW"

    /*
        687E62A343           | push 0x43a3627e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 62 a3 43 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheck
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheck"

    /*
        688CBC4057           | push 0x5740bc8c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c bc 40 57 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckAndAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckAndAuditAlarmA"

    /*
        6858CF2669           | push 0x6926cf58
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 cf 26 69 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckAndAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckAndAuditAlarmW"

    /*
        6858CFD669           | push 0x69d6cf58
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 cf d6 69 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByType
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByType"

    /*
        682D2C3456           | push 0x56342c2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 2c 34 56 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByTypeAndAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByTypeAndAuditAlarmA"

    /*
        685453E536           | push 0x36e55354
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 53 e5 36 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByTypeAndAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByTypeAndAuditAlarmW"

    /*
        6854539537           | push 0x37955354
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 53 95 37 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByTypeResultList
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByTypeResultList"

    /*
        689FDCD1C9           | push 0xc9d1dc9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f dc d1 c9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByTypeResultListAndAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByTypeResultListAndAuditAlarmA"

    /*
        68221DA7AD           | push 0xada71d22
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 1d a7 ad ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByTypeResultListAndAuditAlarmByHandleA
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByTypeResultListAndAuditAlarmByHandleA"

    /*
        68C97DEE28           | push 0x28ee7dc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 7d ee 28 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByTypeResultListAndAuditAlarmByHandleW
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByTypeResultListAndAuditAlarmByHandleW"

    /*
        68C97D9E29           | push 0x299e7dc9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 7d 9e 29 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AccessCheckByTypeResultListAndAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::AccessCheckByTypeResultListAndAuditAlarmW"

    /*
        68221D57AE           | push 0xae571d22
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 1d 57 ae ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAccessAllowedAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddAccessAllowedAce"

    /*
        6871DC4742           | push 0x4247dc71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 dc 47 42 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAccessAllowedAceEx
{
    meta:
        desc = "Metasploit::API::advapi32::AddAccessAllowedAceEx"

    /*
        6888DE08D4           | push 0xd408de88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 de 08 d4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAccessAllowedObjectAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddAccessAllowedObjectAce"

    /*
        689E455665           | push 0x6556459e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 45 56 65 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAccessDeniedAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddAccessDeniedAce"

    /*
        6879197171           | push 0x71711979
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 19 71 71 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAccessDeniedAceEx
{
    meta:
        desc = "Metasploit::API::advapi32::AddAccessDeniedAceEx"

    /*
        689420589E           | push 0x9e582094
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 20 58 9e ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAccessDeniedObjectAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddAccessDeniedObjectAce"

    /*
        6843027759           | push 0x59770243
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 02 77 59 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddAce"

    /*
        682356C368           | push 0x68c35623
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 56 c3 68 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAuditAccessAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddAuditAccessAce"

    /*
        68FD660D08           | push 0x080d66fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 66 0d 08 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAuditAccessAceEx
{
    meta:
        desc = "Metasploit::API::advapi32::AddAuditAccessAceEx"

    /*
        687A816B45           | push 0x456b817a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7a 81 6b 45 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddAuditAccessObjectAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddAuditAccessObjectAce"

    /*
        68B45C858F           | push 0x8f855cb4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 5c 85 8f ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddConditionalAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddConditionalAce"

    /*
        681199284B           | push 0x4b289911
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 99 28 4b ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddMandatoryAce
{
    meta:
        desc = "Metasploit::API::advapi32::AddMandatoryAce"

    /*
        689E69439D           | push 0x9d43699e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 69 43 9d ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddUsersToEncryptedFile
{
    meta:
        desc = "Metasploit::API::advapi32::AddUsersToEncryptedFile"

    /*
        6810FDA2BE           | push 0xbea2fd10
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 fd a2 be ff d5 }

    condition:
        any of them
}

    
rule advapi32_AddUsersToEncryptedFileEx
{
    meta:
        desc = "Metasploit::API::advapi32::AddUsersToEncryptedFileEx"

    /*
        686806D1EA           | push 0xead10668
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 06 d1 ea ff d5 }

    condition:
        any of them
}

    
rule advapi32_AdjustTokenGroups
{
    meta:
        desc = "Metasploit::API::advapi32::AdjustTokenGroups"

    /*
        689C4CDD70           | push 0x70dd4c9c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9c 4c dd 70 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AdjustTokenPrivileges
{
    meta:
        desc = "Metasploit::API::advapi32::AdjustTokenPrivileges"

    /*
        68751F0A33           | push 0x330a1f75
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 1f 0a 33 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AllocateAndInitializeSid
{
    meta:
        desc = "Metasploit::API::advapi32::AllocateAndInitializeSid"

    /*
        6818DCAB2E           | push 0x2eabdc18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 dc ab 2e ff d5 }

    condition:
        any of them
}

    
rule advapi32_AllocateLocallyUniqueId
{
    meta:
        desc = "Metasploit::API::advapi32::AllocateLocallyUniqueId"

    /*
        68F6C2B549           | push 0x49b5c2f6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f6 c2 b5 49 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AreAllAccessesGranted
{
    meta:
        desc = "Metasploit::API::advapi32::AreAllAccessesGranted"

    /*
        685F07B805           | push 0x05b8075f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5f 07 b8 05 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AreAnyAccessesGranted
{
    meta:
        desc = "Metasploit::API::advapi32::AreAnyAccessesGranted"

    /*
        686F07C505           | push 0x05c5076f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6f 07 c5 05 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditComputeEffectivePolicyBySid
{
    meta:
        desc = "Metasploit::API::advapi32::AuditComputeEffectivePolicyBySid"

    /*
        68B61463EA           | push 0xea6314b6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 14 63 ea ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditComputeEffectivePolicyByToken
{
    meta:
        desc = "Metasploit::API::advapi32::AuditComputeEffectivePolicyByToken"

    /*
        68B3578768           | push 0x688757b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 57 87 68 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditEnumerateCategories
{
    meta:
        desc = "Metasploit::API::advapi32::AuditEnumerateCategories"

    /*
        68E66ADDA9           | push 0xa9dd6ae6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 6a dd a9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditEnumeratePerUserPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::AuditEnumeratePerUserPolicy"

    /*
        680E9FFF1F           | push 0x1fff9f0e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e 9f ff 1f ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditEnumerateSubCategories
{
    meta:
        desc = "Metasploit::API::advapi32::AuditEnumerateSubCategories"

    /*
        68E96E8BB0           | push 0xb08b6ee9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 6e 8b b0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditFree
{
    meta:
        desc = "Metasploit::API::advapi32::AuditFree"

    /*
        682C8B6340           | push 0x40638b2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 8b 63 40 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditLookupCategoryGuidFromCategoryId
{
    meta:
        desc = "Metasploit::API::advapi32::AuditLookupCategoryGuidFromCategoryId"

    /*
        68B48F4A9D           | push 0x9d4a8fb4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 8f 4a 9d ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditLookupCategoryIdFromCategoryGuid
{
    meta:
        desc = "Metasploit::API::advapi32::AuditLookupCategoryIdFromCategoryGuid"

    /*
        68BFA93986           | push 0x8639a9bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf a9 39 86 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditLookupCategoryNameA
{
    meta:
        desc = "Metasploit::API::advapi32::AuditLookupCategoryNameA"

    /*
        682091F09C           | push 0x9cf09120
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 91 f0 9c ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditLookupCategoryNameW
{
    meta:
        desc = "Metasploit::API::advapi32::AuditLookupCategoryNameW"

    /*
        682091A09D           | push 0x9da09120
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 20 91 a0 9d ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditLookupSubCategoryNameA
{
    meta:
        desc = "Metasploit::API::advapi32::AuditLookupSubCategoryNameA"

    /*
        684DFF586E           | push 0x6e58ff4d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d ff 58 6e ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditLookupSubCategoryNameW
{
    meta:
        desc = "Metasploit::API::advapi32::AuditLookupSubCategoryNameW"

    /*
        684DFF086F           | push 0x6f08ff4d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d ff 08 6f ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditQueryGlobalSaclA
{
    meta:
        desc = "Metasploit::API::advapi32::AuditQueryGlobalSaclA"

    /*
        68DC9394D2           | push 0xd29493dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 93 94 d2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditQueryGlobalSaclW
{
    meta:
        desc = "Metasploit::API::advapi32::AuditQueryGlobalSaclW"

    /*
        68DC9344D3           | push 0xd34493dc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dc 93 44 d3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditQueryPerUserPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::AuditQueryPerUserPolicy"

    /*
        68605481F4           | push 0xf4815460
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 54 81 f4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditQuerySecurity
{
    meta:
        desc = "Metasploit::API::advapi32::AuditQuerySecurity"

    /*
        682EEADF66           | push 0x66dfea2e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e ea df 66 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditQuerySystemPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::AuditQuerySystemPolicy"

    /*
        68B5A6C799           | push 0x99c7a6b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 a6 c7 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditSetGlobalSaclA
{
    meta:
        desc = "Metasploit::API::advapi32::AuditSetGlobalSaclA"

    /*
        6805850B5F           | push 0x5f0b8505
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 85 0b 5f ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditSetGlobalSaclW
{
    meta:
        desc = "Metasploit::API::advapi32::AuditSetGlobalSaclW"

    /*
        680585BB5F           | push 0x5fbb8505
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 85 bb 5f ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditSetPerUserPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::AuditSetPerUserPolicy"

    /*
        68839E3D12           | push 0x123d9e83
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 9e 3d 12 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditSetSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::AuditSetSecurity"

    /*
        68747E58A2           | push 0xa2587e74
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 7e 58 a2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_AuditSetSystemPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::AuditSetSystemPolicy"

    /*
        686D0A0C23           | push 0x230c0a6d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d 0a 0c 23 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BackupEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::BackupEventLogA"

    /*
        68A096C3AC           | push 0xacc396a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 96 c3 ac ff d5 }

    condition:
        any of them
}

    
rule advapi32_BackupEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::BackupEventLogW"

    /*
        68A09673AD           | push 0xad7396a0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a0 96 73 ad ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegCloseKey
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegCloseKey"

    /*
        689D3644FB           | push 0xfb44369d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 36 44 fb ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegCreateKey
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegCreateKey"

    /*
        68925C7303           | push 0x03735c92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 5c 73 03 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegDeleteKeyEx
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegDeleteKeyEx"

    /*
        68B61EEBE2           | push 0xe2eb1eb6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b6 1e eb e2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegDeleteValue
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegDeleteValue"

    /*
        68BBEA5248           | push 0x4852eabb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bb ea 52 48 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegFlushKey
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegFlushKey"

    /*
        689D665CFE           | push 0xfe5c669d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 66 5c fe ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegGetVersion
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegGetVersion"

    /*
        686B18D077           | push 0x77d0186b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b 18 d0 77 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegLoadKey
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegLoadKey"

    /*
        6867976916           | push 0x16699767
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 97 69 16 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegOpenKey
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegOpenKey"

    /*
        68C9376E16           | push 0x166e37c9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c9 37 6e 16 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegRestoreKey
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegRestoreKey"

    /*
        68AE394FFB           | push 0xfb4f39ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 39 4f fb ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegSaveKeyEx
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegSaveKeyEx"

    /*
        689DD67BCE           | push 0xce7bd69d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d d6 7b ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegSetKeySecurity
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegSetKeySecurity"

    /*
        68094BCE09           | push 0x09ce4b09
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 4b ce 09 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegSetValue
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegSetValue"

    /*
        68AEF9B7CC           | push 0xccb7f9ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae f9 b7 cc ff d5 }

    condition:
        any of them
}

    
rule advapi32_BaseRegUnLoadKey
{
    meta:
        desc = "Metasploit::API::advapi32::BaseRegUnLoadKey"

    /*
        6868D9AB7F           | push 0x7fabd968
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 d9 ab 7f ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildExplicitAccessWithNameA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildExplicitAccessWithNameA"

    /*
        68AAFBF081           | push 0x81f0fbaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa fb f0 81 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildExplicitAccessWithNameW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildExplicitAccessWithNameW"

    /*
        68AAFBA082           | push 0x82a0fbaa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 aa fb a0 82 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildImpersonateExplicitAccessWithNameA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildImpersonateExplicitAccessWithNameA"

    /*
        6843B10EDA           | push 0xda0eb143
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 b1 0e da ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildImpersonateExplicitAccessWithNameW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildImpersonateExplicitAccessWithNameW"

    /*
        6843B1BEDA           | push 0xdabeb143
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 b1 be da ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildImpersonateTrusteeA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildImpersonateTrusteeA"

    /*
        6821393767           | push 0x67373921
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 39 37 67 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildImpersonateTrusteeW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildImpersonateTrusteeW"

    /*
        682139E767           | push 0x67e73921
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 39 e7 67 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildSecurityDescriptorA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildSecurityDescriptorA"

    /*
        68A4985D4A           | push 0x4a5d98a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 98 5d 4a ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildSecurityDescriptorW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildSecurityDescriptorW"

    /*
        68A4980D4B           | push 0x4b0d98a4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 98 0d 4b ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithNameA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithNameA"

    /*
        68A89D034F           | push 0x4f039da8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 9d 03 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithNameW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithNameW"

    /*
        68A89DB34F           | push 0x4fb39da8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 9d b3 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithObjectsAndNameA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithObjectsAndNameA"

    /*
        68947813FB           | push 0xfb137894
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 78 13 fb ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithObjectsAndNameW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithObjectsAndNameW"

    /*
        689478C3FB           | push 0xfbc37894
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 78 c3 fb ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithObjectsAndSidA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithObjectsAndSidA"

    /*
        68C0ADDD40           | push 0x40ddadc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 ad dd 40 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithObjectsAndSidW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithObjectsAndSidW"

    /*
        68C0AD8D41           | push 0x418dadc0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 ad 8d 41 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithSidA
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithSidA"

    /*
        683E388045           | push 0x4580383e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 38 80 45 ff d5 }

    condition:
        any of them
}

    
rule advapi32_BuildTrusteeWithSidW
{
    meta:
        desc = "Metasploit::API::advapi32::BuildTrusteeWithSidW"

    /*
        683E383046           | push 0x4630383e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 38 30 46 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CancelOverlappedAccess
{
    meta:
        desc = "Metasploit::API::advapi32::CancelOverlappedAccess"

    /*
        6801BCBA89           | push 0x89babc01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 bc ba 89 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ChangeServiceConfig2A
{
    meta:
        desc = "Metasploit::API::advapi32::ChangeServiceConfig2A"

    /*
        6887B035ED           | push 0xed35b087
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 b0 35 ed ff d5 }

    condition:
        any of them
}

    
rule advapi32_ChangeServiceConfig2W
{
    meta:
        desc = "Metasploit::API::advapi32::ChangeServiceConfig2W"

    /*
        6887B0E5ED           | push 0xede5b087
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 b0 e5 ed ff d5 }

    condition:
        any of them
}

    
rule advapi32_ChangeServiceConfigA
{
    meta:
        desc = "Metasploit::API::advapi32::ChangeServiceConfigA"

    /*
        6844BE7379           | push 0x7973be44
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 be 73 79 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ChangeServiceConfigW
{
    meta:
        desc = "Metasploit::API::advapi32::ChangeServiceConfigW"

    /*
        6844BE237A           | push 0x7a23be44
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 be 23 7a ff d5 }

    condition:
        any of them
}

    
rule advapi32_CheckForHiberboot
{
    meta:
        desc = "Metasploit::API::advapi32::CheckForHiberboot"

    /*
        680C189585           | push 0x8595180c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 18 95 85 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CheckTokenMembership
{
    meta:
        desc = "Metasploit::API::advapi32::CheckTokenMembership"

    /*
        687511B964           | push 0x64b91175
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 75 11 b9 64 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ClearEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::ClearEventLogA"

    /*
        68391E1BF1           | push 0xf11b1e39
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 1e 1b f1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ClearEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::ClearEventLogW"

    /*
        68391ECBF1           | push 0xf1cb1e39
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 1e cb f1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CloseCodeAuthzLevel
{
    meta:
        desc = "Metasploit::API::advapi32::CloseCodeAuthzLevel"

    /*
        686DB7A17B           | push 0x7ba1b76d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6d b7 a1 7b ff d5 }

    condition:
        any of them
}

    
rule advapi32_CloseEncryptedFileRaw
{
    meta:
        desc = "Metasploit::API::advapi32::CloseEncryptedFileRaw"

    /*
        68518BFFC6           | push 0xc6ff8b51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 8b ff c6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CloseEventLog
{
    meta:
        desc = "Metasploit::API::advapi32::CloseEventLog"

    /*
        68C596C5A6           | push 0xa6c596c5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 96 c5 a6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CloseServiceHandle
{
    meta:
        desc = "Metasploit::API::advapi32::CloseServiceHandle"

    /*
        68DEEA77AD           | push 0xad77eade
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de ea 77 ad ff d5 }

    condition:
        any of them
}

    
rule advapi32_CloseThreadWaitChainSession
{
    meta:
        desc = "Metasploit::API::advapi32::CloseThreadWaitChainSession"

    /*
        68E185F8FF           | push 0xfff885e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 85 f8 ff ff d5 }

    condition:
        any of them
}

    
rule advapi32_CloseTrace
{
    meta:
        desc = "Metasploit::API::advapi32::CloseTrace"

    /*
        688CA457D8           | push 0xd857a48c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8c a4 57 d8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CommandLineFromMsiDescriptor
{
    meta:
        desc = "Metasploit::API::advapi32::CommandLineFromMsiDescriptor"

    /*
        687E8A2BEE           | push 0xee2b8a7e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 8a 2b ee ff d5 }

    condition:
        any of them
}

    
rule advapi32_ComputeAccessTokenFromCodeAuthzLevel
{
    meta:
        desc = "Metasploit::API::advapi32::ComputeAccessTokenFromCodeAuthzLevel"

    /*
        68492FB0E0           | push 0xe0b02f49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 2f b0 e0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ControlService
{
    meta:
        desc = "Metasploit::API::advapi32::ControlService"

    /*
        68870BC1DD           | push 0xddc10b87
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 0b c1 dd ff d5 }

    condition:
        any of them
}

    
rule advapi32_ControlServiceExA
{
    meta:
        desc = "Metasploit::API::advapi32::ControlServiceExA"

    /*
        684E7B8F1C           | push 0x1c8f7b4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 7b 8f 1c ff d5 }

    condition:
        any of them
}

    
rule advapi32_ControlServiceExW
{
    meta:
        desc = "Metasploit::API::advapi32::ControlServiceExW"

    /*
        684E7B3F1D           | push 0x1d3f7b4e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e 7b 3f 1d ff d5 }

    condition:
        any of them
}

    
rule advapi32_ControlTraceA
{
    meta:
        desc = "Metasploit::API::advapi32::ControlTraceA"

    /*
        6838CB4E3D           | push 0x3d4ecb38
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 cb 4e 3d ff d5 }

    condition:
        any of them
}

    
rule advapi32_ControlTraceW
{
    meta:
        desc = "Metasploit::API::advapi32::ControlTraceW"

    /*
        6838CBFE3D           | push 0x3dfecb38
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 38 cb fe 3d ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertAccessToSecurityDescriptorA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertAccessToSecurityDescriptorA"

    /*
        688186F1B0           | push 0xb0f18681
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 86 f1 b0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertAccessToSecurityDescriptorW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertAccessToSecurityDescriptorW"

    /*
        688186A1B1           | push 0xb1a18681
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 86 a1 b1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSDToStringSDDomainW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSDToStringSDDomainW"

    /*
        685B7865AF           | push 0xaf65785b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 78 65 af ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSDToStringSDRootDomainA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSDToStringSDRootDomainA"

    /*
        68EAE07111           | push 0x1171e0ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea e0 71 11 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSDToStringSDRootDomainW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSDToStringSDRootDomainW"

    /*
        68EAE02112           | push 0x1221e0ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea e0 21 12 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSecurityDescriptorToAccessA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSecurityDescriptorToAccessA"

    /*
        68CB0A0C23           | push 0x230c0acb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 0a 0c 23 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSecurityDescriptorToAccessNamedA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSecurityDescriptorToAccessNamedA"

    /*
        682F6D114F           | push 0x4f116d2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 6d 11 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSecurityDescriptorToAccessNamedW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSecurityDescriptorToAccessNamedW"

    /*
        682F6DC14F           | push 0x4fc16d2f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 6d c1 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSecurityDescriptorToAccessW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSecurityDescriptorToAccessW"

    /*
        68CB0ABC23           | push 0x23bc0acb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 0a bc 23 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSecurityDescriptorToStringSecurityDescriptorA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorA"

    /*
        68CD82F433           | push 0x33f482cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 82 f4 33 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSecurityDescriptorToStringSecurityDescriptorW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorW"

    /*
        68CD82A434           | push 0x34a482cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 82 a4 34 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSidToStringSidA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSidToStringSidA"

    /*
        68880D26F7           | push 0xf7260d88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 0d 26 f7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertSidToStringSidW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertSidToStringSidW"

    /*
        68880DD6F7           | push 0xf7d60d88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 0d d6 f7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSDToSDDomainA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSDToSDDomainA"

    /*
        680143FB0A           | push 0x0afb4301
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 43 fb 0a ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSDToSDDomainW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSDToSDDomainW"

    /*
        680143AB0B           | push 0x0bab4301
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 43 ab 0b ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSDToSDRootDomainA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSDToSDRootDomainA"

    /*
        68AE361C6E           | push 0x6e1c36ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 36 1c 6e ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSDToSDRootDomainW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSDToSDRootDomainW"

    /*
        68AE36CC6E           | push 0x6ecc36ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 36 cc 6e ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSecurityDescriptorToSecurityDescriptorA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorA"

    /*
        689A636FDA           | push 0xda6f639a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 63 6f da ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSecurityDescriptorToSecurityDescriptorW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW"

    /*
        689A631FDB           | push 0xdb1f639a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a 63 1f db ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSidToSidA
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSidToSidA"

    /*
        684132BBF4           | push 0xf4bb3241
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 32 bb f4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertStringSidToSidW
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertStringSidToSidW"

    /*
        6841326BF5           | push 0xf56b3241
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 32 6b f5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ConvertToAutoInheritPrivateObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::ConvertToAutoInheritPrivateObjectSecurity"

    /*
        6847A60A43           | push 0x430aa647
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 a6 0a 43 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CopySid
{
    meta:
        desc = "Metasploit::API::advapi32::CopySid"

    /*
        6809B0748D           | push 0x8d74b009
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 09 b0 74 8d ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateCodeAuthzLevel
{
    meta:
        desc = "Metasploit::API::advapi32::CreateCodeAuthzLevel"

    /*
        680115E3A9           | push 0xa9e31501
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 15 e3 a9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreatePrivateObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::CreatePrivateObjectSecurity"

    /*
        68FEE17493           | push 0x9374e1fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe e1 74 93 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreatePrivateObjectSecurityEx
{
    meta:
        desc = "Metasploit::API::advapi32::CreatePrivateObjectSecurityEx"

    /*
        68DD414A1F           | push 0x1f4a41dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 41 4a 1f ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreatePrivateObjectSecurityWithMultipleInheritance
{
    meta:
        desc = "Metasploit::API::advapi32::CreatePrivateObjectSecurityWithMultipleInheritance"

    /*
        686CF67E41           | push 0x417ef66c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c f6 7e 41 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateProcessAsUserA
{
    meta:
        desc = "Metasploit::API::advapi32::CreateProcessAsUserA"

    /*
        681F18EC06           | push 0x06ec181f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 18 ec 06 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateProcessAsUserW
{
    meta:
        desc = "Metasploit::API::advapi32::CreateProcessAsUserW"

    /*
        681F189C07           | push 0x079c181f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 18 9c 07 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateProcessWithLogonW
{
    meta:
        desc = "Metasploit::API::advapi32::CreateProcessWithLogonW"

    /*
        688BDD2FBE           | push 0xbe2fdd8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b dd 2f be ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateProcessWithTokenW
{
    meta:
        desc = "Metasploit::API::advapi32::CreateProcessWithTokenW"

    /*
        688B1D50AA           | push 0xaa501d8b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8b 1d 50 aa ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateRestrictedToken
{
    meta:
        desc = "Metasploit::API::advapi32::CreateRestrictedToken"

    /*
        684814C824           | push 0x24c81448
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 14 c8 24 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateServiceA
{
    meta:
        desc = "Metasploit::API::advapi32::CreateServiceA"

    /*
        68BAED2D39           | push 0x392dedba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba ed 2d 39 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateServiceEx
{
    meta:
        desc = "Metasploit::API::advapi32::CreateServiceEx"

    /*
        6818B39B6A           | push 0x6a9bb318
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 b3 9b 6a ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateServiceW
{
    meta:
        desc = "Metasploit::API::advapi32::CreateServiceW"

    /*
        68BAEDDD39           | push 0x39ddedba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba ed dd 39 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateTraceInstanceId
{
    meta:
        desc = "Metasploit::API::advapi32::CreateTraceInstanceId"

    /*
        681DDA514E           | push 0x4e51da1d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d da 51 4e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CreateWellKnownSid
{
    meta:
        desc = "Metasploit::API::advapi32::CreateWellKnownSid"

    /*
        68943EE8BC           | push 0xbce83e94
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 94 3e e8 bc ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredBackupCredentials
{
    meta:
        desc = "Metasploit::API::advapi32::CredBackupCredentials"

    /*
        684CDC7562           | push 0x6275dc4c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c dc 75 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredDeleteA
{
    meta:
        desc = "Metasploit::API::advapi32::CredDeleteA"

    /*
        684497BCB2           | push 0xb2bc9744
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 97 bc b2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredDeleteW
{
    meta:
        desc = "Metasploit::API::advapi32::CredDeleteW"

    /*
        6844976CB3           | push 0xb36c9744
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 97 6c b3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredEncryptAndMarshalBinaryBlob
{
    meta:
        desc = "Metasploit::API::advapi32::CredEncryptAndMarshalBinaryBlob"

    /*
        68B8C46AC1           | push 0xc16ac4b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 c4 6a c1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredEnumerateA
{
    meta:
        desc = "Metasploit::API::advapi32::CredEnumerateA"

    /*
        68ACB6FFBC           | push 0xbcffb6ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac b6 ff bc ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredEnumerateW
{
    meta:
        desc = "Metasploit::API::advapi32::CredEnumerateW"

    /*
        68ACB6AFBD           | push 0xbdafb6ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac b6 af bd ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredFindBestCredentialA
{
    meta:
        desc = "Metasploit::API::advapi32::CredFindBestCredentialA"

    /*
        68AF899969           | push 0x699989af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 89 99 69 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredFindBestCredentialW
{
    meta:
        desc = "Metasploit::API::advapi32::CredFindBestCredentialW"

    /*
        68AF89496A           | push 0x6a4989af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 89 49 6a ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredFree
{
    meta:
        desc = "Metasploit::API::advapi32::CredFree"

    /*
        68E484510E           | push 0x0e5184e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 84 51 0e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredGetSessionTypes
{
    meta:
        desc = "Metasploit::API::advapi32::CredGetSessionTypes"

    /*
        68FA6E9C28           | push 0x289c6efa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 6e 9c 28 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredGetTargetInfoA
{
    meta:
        desc = "Metasploit::API::advapi32::CredGetTargetInfoA"

    /*
        68ABBCC19D           | push 0x9dc1bcab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab bc c1 9d ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredGetTargetInfoW
{
    meta:
        desc = "Metasploit::API::advapi32::CredGetTargetInfoW"

    /*
        68ABBC719E           | push 0x9e71bcab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab bc 71 9e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredIsMarshaledCredentialA
{
    meta:
        desc = "Metasploit::API::advapi32::CredIsMarshaledCredentialA"

    /*
        6839FF1569           | push 0x6915ff39
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 ff 15 69 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredIsMarshaledCredentialW
{
    meta:
        desc = "Metasploit::API::advapi32::CredIsMarshaledCredentialW"

    /*
        6839FFC569           | push 0x69c5ff39
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 ff c5 69 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredIsProtectedA
{
    meta:
        desc = "Metasploit::API::advapi32::CredIsProtectedA"

    /*
        68968D6212           | push 0x12628d96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 8d 62 12 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredIsProtectedW
{
    meta:
        desc = "Metasploit::API::advapi32::CredIsProtectedW"

    /*
        68968D1213           | push 0x13128d96
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 8d 12 13 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredMarshalCredentialA
{
    meta:
        desc = "Metasploit::API::advapi32::CredMarshalCredentialA"

    /*
        6811504E81           | push 0x814e5011
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 50 4e 81 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredMarshalCredentialW
{
    meta:
        desc = "Metasploit::API::advapi32::CredMarshalCredentialW"

    /*
        681150FE81           | push 0x81fe5011
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 50 fe 81 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredProfileLoaded
{
    meta:
        desc = "Metasploit::API::advapi32::CredProfileLoaded"

    /*
        68A8143CE4           | push 0xe43c14a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 14 3c e4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredProfileLoadedEx
{
    meta:
        desc = "Metasploit::API::advapi32::CredProfileLoadedEx"

    /*
        6831EC1651           | push 0x5116ec31
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 ec 16 51 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredProfileUnloaded
{
    meta:
        desc = "Metasploit::API::advapi32::CredProfileUnloaded"

    /*
        6816B4A2D9           | push 0xd9a2b416
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 b4 a2 d9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredProtectA
{
    meta:
        desc = "Metasploit::API::advapi32::CredProtectA"

    /*
        68F59C423D           | push 0x3d429cf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 9c 42 3d ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredProtectW
{
    meta:
        desc = "Metasploit::API::advapi32::CredProtectW"

    /*
        68F59CF23D           | push 0x3df29cf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 9c f2 3d ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredReadA
{
    meta:
        desc = "Metasploit::API::advapi32::CredReadA"

    /*
        68FB8A311A           | push 0x1a318afb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 8a 31 1a ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredReadByTokenHandle
{
    meta:
        desc = "Metasploit::API::advapi32::CredReadByTokenHandle"

    /*
        68714214CF           | push 0xcf144271
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 42 14 cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredReadDomainCredentialsA
{
    meta:
        desc = "Metasploit::API::advapi32::CredReadDomainCredentialsA"

    /*
        68067289F9           | push 0xf9897206
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 72 89 f9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredReadDomainCredentialsW
{
    meta:
        desc = "Metasploit::API::advapi32::CredReadDomainCredentialsW"

    /*
        68067239FA           | push 0xfa397206
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 72 39 fa ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredReadW
{
    meta:
        desc = "Metasploit::API::advapi32::CredReadW"

    /*
        68FB8AE11A           | push 0x1ae18afb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fb 8a e1 1a ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredRenameA
{
    meta:
        desc = "Metasploit::API::advapi32::CredRenameA"

    /*
        680559BCA4           | push 0xa4bc5905
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 59 bc a4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredRenameW
{
    meta:
        desc = "Metasploit::API::advapi32::CredRenameW"

    /*
        6805596CA5           | push 0xa56c5905
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 59 6c a5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredRestoreCredentials
{
    meta:
        desc = "Metasploit::API::advapi32::CredRestoreCredentials"

    /*
        68C16B9FAC           | push 0xac9f6bc1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 6b 9f ac ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredUnmarshalCredentialA
{
    meta:
        desc = "Metasploit::API::advapi32::CredUnmarshalCredentialA"

    /*
        6898A78797           | push 0x9787a798
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 a7 87 97 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredUnmarshalCredentialW
{
    meta:
        desc = "Metasploit::API::advapi32::CredUnmarshalCredentialW"

    /*
        6898A73798           | push 0x9837a798
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 a7 37 98 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredUnprotectA
{
    meta:
        desc = "Metasploit::API::advapi32::CredUnprotectA"

    /*
        6811FB2796           | push 0x9627fb11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 fb 27 96 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredUnprotectW
{
    meta:
        desc = "Metasploit::API::advapi32::CredUnprotectW"

    /*
        6811FBD796           | push 0x96d7fb11
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 11 fb d7 96 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredWriteA
{
    meta:
        desc = "Metasploit::API::advapi32::CredWriteA"

    /*
        683C43FFF2           | push 0xf2ff433c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 43 ff f2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredWriteDomainCredentialsA
{
    meta:
        desc = "Metasploit::API::advapi32::CredWriteDomainCredentialsA"

    /*
        680C34F7BF           | push 0xbff7340c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 34 f7 bf ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredWriteDomainCredentialsW
{
    meta:
        desc = "Metasploit::API::advapi32::CredWriteDomainCredentialsW"

    /*
        680C34A7C0           | push 0xc0a7340c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c 34 a7 c0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredWriteW
{
    meta:
        desc = "Metasploit::API::advapi32::CredWriteW"

    /*
        683C43AFF3           | push 0xf3af433c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3c 43 af f3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredpConvertCredential
{
    meta:
        desc = "Metasploit::API::advapi32::CredpConvertCredential"

    /*
        68929CA23E           | push 0x3ea29c92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 9c a2 3e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredpConvertOneCredentialSize
{
    meta:
        desc = "Metasploit::API::advapi32::CredpConvertOneCredentialSize"

    /*
        680229D249           | push 0x49d22902
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 29 d2 49 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredpConvertTargetInfo
{
    meta:
        desc = "Metasploit::API::advapi32::CredpConvertTargetInfo"

    /*
        683966B795           | push 0x95b76639
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 39 66 b7 95 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredpDecodeCredential
{
    meta:
        desc = "Metasploit::API::advapi32::CredpDecodeCredential"

    /*
        680ED241F0           | push 0xf041d20e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e d2 41 f0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredpEncodeCredential
{
    meta:
        desc = "Metasploit::API::advapi32::CredpEncodeCredential"

    /*
        680FD24210           | push 0x1042d20f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0f d2 42 10 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CredpEncodeSecret
{
    meta:
        desc = "Metasploit::API::advapi32::CredpEncodeSecret"

    /*
        68D261D648           | push 0x48d661d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 61 d6 48 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptAcquireContextA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptAcquireContextA"

    /*
        68451B6341           | push 0x41631b45
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 1b 63 41 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptAcquireContextW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptAcquireContextW"

    /*
        68451B1342           | push 0x42131b45
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 1b 13 42 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptContextAddRef
{
    meta:
        desc = "Metasploit::API::advapi32::CryptContextAddRef"

    /*
        68CF676536           | push 0x366567cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 67 65 36 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptCreateHash
{
    meta:
        desc = "Metasploit::API::advapi32::CryptCreateHash"

    /*
        685E0513EC           | push 0xec13055e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 05 13 ec ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptDecrypt
{
    meta:
        desc = "Metasploit::API::advapi32::CryptDecrypt"

    /*
        6832C6B30E           | push 0x0eb3c632
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 c6 b3 0e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptDeriveKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptDeriveKey"

    /*
        689AA8E61C           | push 0x1ce6a89a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9a a8 e6 1c ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptDestroyHash
{
    meta:
        desc = "Metasploit::API::advapi32::CryptDestroyHash"

    /*
        68D62B6256           | push 0x56622bd6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 2b 62 56 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptDestroyKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptDestroyKey"

    /*
        6843AC950E           | push 0x0e95ac43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 ac 95 0e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptDuplicateHash
{
    meta:
        desc = "Metasploit::API::advapi32::CryptDuplicateHash"

    /*
        684DC9C3C0           | push 0xc0c3c94d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d c9 c3 c0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptDuplicateKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptDuplicateKey"

    /*
        688F994442           | push 0x4244998f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 99 44 42 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptEncrypt
{
    meta:
        desc = "Metasploit::API::advapi32::CryptEncrypt"

    /*
        6852C6D70E           | push 0x0ed7c652
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 c6 d7 0e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptEnumProviderTypesA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptEnumProviderTypesA"

    /*
        68C5FC32C9           | push 0xc932fcc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 fc 32 c9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptEnumProviderTypesW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptEnumProviderTypesW"

    /*
        68C5FCE2C9           | push 0xc9e2fcc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 fc e2 c9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptEnumProvidersA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptEnumProvidersA"

    /*
        681FAE120E           | push 0x0e12ae1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f ae 12 0e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptEnumProvidersW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptEnumProvidersW"

    /*
        681FAEC20E           | push 0x0ec2ae1f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f ae c2 0e ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptExportKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptExportKey"

    /*
        6858A0FF2F           | push 0x2fffa058
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 a0 ff 2f ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGenKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGenKey"

    /*
        6841CD05EE           | push 0xee05cd41
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 cd 05 ee ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGenRandom
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGenRandom"

    /*
        688F522BCE           | push 0xce2b528f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 52 2b ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGetDefaultProviderA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGetDefaultProviderA"

    /*
        68CB5DD0DB           | push 0xdbd05dcb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 5d d0 db ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGetDefaultProviderW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGetDefaultProviderW"

    /*
        68CB5D80DC           | push 0xdc805dcb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 5d 80 dc ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGetHashParam
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGetHashParam"

    /*
        68AE3ADF87           | push 0x87df3aae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 3a df 87 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGetKeyParam
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGetKeyParam"

    /*
        68A1BDB9CF           | push 0xcfb9bda1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 bd b9 cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGetProvParam
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGetProvParam"

    /*
        682E7A1799           | push 0x99177a2e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 7a 17 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptGetUserKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptGetUserKey"

    /*
        685E3899CF           | push 0xcf99385e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 38 99 cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptHashData
{
    meta:
        desc = "Metasploit::API::advapi32::CryptHashData"

    /*
        68C20DDF13           | push 0x13df0dc2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 0d df 13 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptHashSessionKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptHashSessionKey"

    /*
        6825DE48FF           | push 0xff48de25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 de 48 ff ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptImportKey
{
    meta:
        desc = "Metasploit::API::advapi32::CryptImportKey"

    /*
        6858C0FF24           | push 0x24ffc058
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 c0 ff 24 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptReleaseContext
{
    meta:
        desc = "Metasploit::API::advapi32::CryptReleaseContext"

    /*
        6878D43327           | push 0x2733d478
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 d4 33 27 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSetHashParam
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSetHashParam"

    /*
        686E3BDF87           | push 0x87df3b6e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e 3b df 87 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSetKeyParam
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSetKeyParam"

    /*
        68A1BDD1CF           | push 0xcfd1bda1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a1 bd d1 cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSetProvParam
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSetProvParam"

    /*
        68EE7A1799           | push 0x99177aee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 7a 17 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSetProviderA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSetProviderA"

    /*
        683BAFB7FD           | push 0xfdb7af3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b af b7 fd ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSetProviderExA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSetProviderExA"

    /*
        68B79D45B6           | push 0xb6459db7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 9d 45 b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSetProviderExW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSetProviderExW"

    /*
        68B79DF5B6           | push 0xb6f59db7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 9d f5 b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSetProviderW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSetProviderW"

    /*
        683BAF67FE           | push 0xfe67af3b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b af 67 fe ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSignHashA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSignHashA"

    /*
        68E3DF3A6F           | push 0x6f3adfe3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 df 3a 6f ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptSignHashW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptSignHashW"

    /*
        68E3DFEA6F           | push 0x6feadfe3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 df ea 6f ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptVerifySignatureA
{
    meta:
        desc = "Metasploit::API::advapi32::CryptVerifySignatureA"

    /*
        6895001403           | push 0x03140095
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 00 14 03 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CryptVerifySignatureW
{
    meta:
        desc = "Metasploit::API::advapi32::CryptVerifySignatureW"

    /*
        689500C403           | push 0x03c40095
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 95 00 c4 03 ff d5 }

    condition:
        any of them
}

    
rule advapi32_CveEventWrite
{
    meta:
        desc = "Metasploit::API::advapi32::CveEventWrite"

    /*
        688FFFDD00           | push 0x00ddff8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f ff dd 00 ff d5 }

    condition:
        any of them
}

    
rule advapi32_DecryptFileA
{
    meta:
        desc = "Metasploit::API::advapi32::DecryptFileA"

    /*
        68EE483DF8           | push 0xf83d48ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 48 3d f8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_DecryptFileW
{
    meta:
        desc = "Metasploit::API::advapi32::DecryptFileW"

    /*
        68EE48EDF8           | push 0xf8ed48ee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 48 ed f8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_DeleteAce
{
    meta:
        desc = "Metasploit::API::advapi32::DeleteAce"

    /*
        68AB9355CE           | push 0xce5593ab
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ab 93 55 ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_DeleteService
{
    meta:
        desc = "Metasploit::API::advapi32::DeleteService"

    /*
        68F4263081           | push 0x813026f4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f4 26 30 81 ff d5 }

    condition:
        any of them
}

    
rule advapi32_DeregisterEventSource
{
    meta:
        desc = "Metasploit::API::advapi32::DeregisterEventSource"

    /*
        68345BE735           | push 0x35e75b34
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 5b e7 35 ff d5 }

    condition:
        any of them
}

    
rule advapi32_DestroyPrivateObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::DestroyPrivateObjectSecurity"

    /*
        689333150F           | push 0x0f153393
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 33 15 0f ff d5 }

    condition:
        any of them
}

    
rule advapi32_DuplicateEncryptionInfoFile
{
    meta:
        desc = "Metasploit::API::advapi32::DuplicateEncryptionInfoFile"

    /*
        6822DD3E9A           | push 0x9a3edd22
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 22 dd 3e 9a ff d5 }

    condition:
        any of them
}

    
rule advapi32_DuplicateToken
{
    meta:
        desc = "Metasploit::API::advapi32::DuplicateToken"

    /*
        683644F899           | push 0x99f84436
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 44 f8 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_DuplicateTokenEx
{
    meta:
        desc = "Metasploit::API::advapi32::DuplicateTokenEx"

    /*
        68DECF22C0           | push 0xc022cfde
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de cf 22 c0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfBackupEventLogFileA
{
    meta:
        desc = "Metasploit::API::advapi32::ElfBackupEventLogFileA"

    /*
        6831A46CC6           | push 0xc66ca431
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 a4 6c c6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfBackupEventLogFileW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfBackupEventLogFileW"

    /*
        6831A41CC7           | push 0xc71ca431
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 31 a4 1c c7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfChangeNotify
{
    meta:
        desc = "Metasploit::API::advapi32::ElfChangeNotify"

    /*
        68DA876DB4           | push 0xb46d87da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 87 6d b4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfClearEventLogFileA
{
    meta:
        desc = "Metasploit::API::advapi32::ElfClearEventLogFileA"

    /*
        686373D39E           | push 0x9ed37363
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 73 d3 9e ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfClearEventLogFileW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfClearEventLogFileW"

    /*
        686373839F           | push 0x9f837363
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 73 83 9f ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfCloseEventLog
{
    meta:
        desc = "Metasploit::API::advapi32::ElfCloseEventLog"

    /*
        68D32E0C27           | push 0x270c2ed3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 2e 0c 27 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfDeregisterEventSource
{
    meta:
        desc = "Metasploit::API::advapi32::ElfDeregisterEventSource"

    /*
        68CCA16743           | push 0x4367a1cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc a1 67 43 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfFlushEventLog
{
    meta:
        desc = "Metasploit::API::advapi32::ElfFlushEventLog"

    /*
        68D3469828           | push 0x289846d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 46 98 28 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfNumberOfRecords
{
    meta:
        desc = "Metasploit::API::advapi32::ElfNumberOfRecords"

    /*
        684A66B83A           | push 0x3ab8664a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 66 b8 3a ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfOldestRecord
{
    meta:
        desc = "Metasploit::API::advapi32::ElfOldestRecord"

    /*
        687635DC8B           | push 0x8bdc3576
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 35 dc 8b ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfOpenBackupEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::ElfOpenBackupEventLogA"

    /*
        68E3386829           | push 0x296838e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 38 68 29 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfOpenBackupEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfOpenBackupEventLogW"

    /*
        68E338182A           | push 0x2a1838e3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 38 18 2a ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfOpenEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::ElfOpenEventLogA"

    /*
        68F5AAE862           | push 0x62e8aaf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 aa e8 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfOpenEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfOpenEventLogW"

    /*
        68F5AA9863           | push 0x6398aaf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 aa 98 63 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfReadEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::ElfReadEventLogA"

    /*
        6843AA60E4           | push 0xe460aa43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 aa 60 e4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfReadEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfReadEventLogW"

    /*
        6843AA10E5           | push 0xe510aa43
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 aa 10 e5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfRegisterEventSourceA
{
    meta:
        desc = "Metasploit::API::advapi32::ElfRegisterEventSourceA"

    /*
        68811854DD           | push 0xdd541881
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 18 54 dd ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfRegisterEventSourceW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfRegisterEventSourceW"

    /*
        68811804DE           | push 0xde041881
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 18 04 de ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfReportEventA
{
    meta:
        desc = "Metasploit::API::advapi32::ElfReportEventA"

    /*
        6832A68207           | push 0x0782a632
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 a6 82 07 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfReportEventAndSourceW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfReportEventAndSourceW"

    /*
        6834BA571E           | push 0x1e57ba34
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 ba 57 1e ff d5 }

    condition:
        any of them
}

    
rule advapi32_ElfReportEventW
{
    meta:
        desc = "Metasploit::API::advapi32::ElfReportEventW"

    /*
        6832A63208           | push 0x0832a632
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 a6 32 08 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnableTrace
{
    meta:
        desc = "Metasploit::API::advapi32::EnableTrace"

    /*
        68B74BE18B           | push 0x8be14bb7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b7 4b e1 8b ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnableTraceEx
{
    meta:
        desc = "Metasploit::API::advapi32::EnableTraceEx"

    /*
        681BB0643A           | push 0x3a64b01b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1b b0 64 3a ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnableTraceEx2
{
    meta:
        desc = "Metasploit::API::advapi32::EnableTraceEx2"

    /*
        68CEBB737B           | push 0x7b73bbce
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ce bb 73 7b ff d5 }

    condition:
        any of them
}

    
rule advapi32_EncryptFileA
{
    meta:
        desc = "Metasploit::API::advapi32::EncryptFileA"

    /*
        68FE484FF8           | push 0xf84f48fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 48 4f f8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EncryptFileW
{
    meta:
        desc = "Metasploit::API::advapi32::EncryptFileW"

    /*
        68FE48FFF8           | push 0xf8ff48fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 48 ff f8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EncryptedFileKeyInfo
{
    meta:
        desc = "Metasploit::API::advapi32::EncryptedFileKeyInfo"

    /*
        684BC6EC84           | push 0x84ecc64b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b c6 ec 84 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EncryptionDisable
{
    meta:
        desc = "Metasploit::API::advapi32::EncryptionDisable"

    /*
        683A7A3E77           | push 0x773e7a3a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 7a 3e 77 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumDependentServicesA
{
    meta:
        desc = "Metasploit::API::advapi32::EnumDependentServicesA"

    /*
        68238DFFC9           | push 0xc9ff8d23
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 8d ff c9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumDependentServicesW
{
    meta:
        desc = "Metasploit::API::advapi32::EnumDependentServicesW"

    /*
        68238DAFCA           | push 0xcaaf8d23
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 8d af ca ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumDynamicTimeZoneInformation
{
    meta:
        desc = "Metasploit::API::advapi32::EnumDynamicTimeZoneInformation"

    /*
        68DA2CAFDA           | push 0xdaaf2cda
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 2c af da ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumServiceGroupW
{
    meta:
        desc = "Metasploit::API::advapi32::EnumServiceGroupW"

    /*
        68AF1A437E           | push 0x7e431aaf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 1a 43 7e ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumServicesStatusA
{
    meta:
        desc = "Metasploit::API::advapi32::EnumServicesStatusA"

    /*
        68AEB53439           | push 0x3934b5ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae b5 34 39 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumServicesStatusExA
{
    meta:
        desc = "Metasploit::API::advapi32::EnumServicesStatusExA"

    /*
        68863A8795           | push 0x95873a86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 3a 87 95 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumServicesStatusExW
{
    meta:
        desc = "Metasploit::API::advapi32::EnumServicesStatusExW"

    /*
        68863A3796           | push 0x96373a86
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 3a 37 96 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumServicesStatusW
{
    meta:
        desc = "Metasploit::API::advapi32::EnumServicesStatusW"

    /*
        68AEB5E439           | push 0x39e4b5ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae b5 e4 39 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumerateTraceGuids
{
    meta:
        desc = "Metasploit::API::advapi32::EnumerateTraceGuids"

    /*
        68BF5F0188           | push 0x88015fbf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf 5f 01 88 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EnumerateTraceGuidsEx
{
    meta:
        desc = "Metasploit::API::advapi32::EnumerateTraceGuidsEx"

    /*
        681AB26942           | push 0x4269b21a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a b2 69 42 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EqualDomainSid
{
    meta:
        desc = "Metasploit::API::advapi32::EqualDomainSid"

    /*
        68B14081B5           | push 0xb58140b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 40 81 b5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EqualPrefixSid
{
    meta:
        desc = "Metasploit::API::advapi32::EqualPrefixSid"

    /*
        68B13F96B8           | push 0xb8963fb1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 3f 96 b8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EqualSid
{
    meta:
        desc = "Metasploit::API::advapi32::EqualSid"

    /*
        68C2E58B52           | push 0x528be5c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 e5 8b 52 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventAccessControl
{
    meta:
        desc = "Metasploit::API::advapi32::EventAccessControl"

    /*
        6890D3A471           | push 0x71a4d390
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 d3 a4 71 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventAccessQuery
{
    meta:
        desc = "Metasploit::API::advapi32::EventAccessQuery"

    /*
        68A22BF84E           | push 0x4ef82ba2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 2b f8 4e ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventAccessRemove
{
    meta:
        desc = "Metasploit::API::advapi32::EventAccessRemove"

    /*
        68A2DF4853           | push 0x5348dfa2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 df 48 53 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventActivityIdControl
{
    meta:
        desc = "Metasploit::API::advapi32::EventActivityIdControl"

    /*
        6868333F99           | push 0x993f3368
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 33 3f 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventEnabled
{
    meta:
        desc = "Metasploit::API::advapi32::EventEnabled"

    /*
        68ACB35EF4           | push 0xf45eb3ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac b3 5e f4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventProviderEnabled
{
    meta:
        desc = "Metasploit::API::advapi32::EventProviderEnabled"

    /*
        683A267B53           | push 0x537b263a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3a 26 7b 53 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventRegister
{
    meta:
        desc = "Metasploit::API::advapi32::EventRegister"

    /*
        68C2FA1145           | push 0x4511fac2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 fa 11 45 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventSetInformation
{
    meta:
        desc = "Metasploit::API::advapi32::EventSetInformation"

    /*
        68F577C1F9           | push 0xf9c177f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 77 c1 f9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventUnregister
{
    meta:
        desc = "Metasploit::API::advapi32::EventUnregister"

    /*
        6844A231D5           | push 0xd531a244
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 a2 31 d5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventWrite
{
    meta:
        desc = "Metasploit::API::advapi32::EventWrite"

    /*
        682EF893DE           | push 0xde93f82e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e f8 93 de ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventWriteEndScenario
{
    meta:
        desc = "Metasploit::API::advapi32::EventWriteEndScenario"

    /*
        682A4C2C95           | push 0x952c4c2a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2a 4c 2c 95 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventWriteEx
{
    meta:
        desc = "Metasploit::API::advapi32::EventWriteEx"

    /*
        68F0CD0FE7           | push 0xe70fcdf0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 cd 0f e7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventWriteStartScenario
{
    meta:
        desc = "Metasploit::API::advapi32::EventWriteStartScenario"

    /*
        68E3DCE647           | push 0x47e6dce3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e3 dc e6 47 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventWriteString
{
    meta:
        desc = "Metasploit::API::advapi32::EventWriteString"

    /*
        68F72814A5           | push 0xa51428f7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 28 14 a5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_EventWriteTransfer
{
    meta:
        desc = "Metasploit::API::advapi32::EventWriteTransfer"

    /*
        68E457A805           | push 0x05a857e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 57 a8 05 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FileEncryptionStatusA
{
    meta:
        desc = "Metasploit::API::advapi32::FileEncryptionStatusA"

    /*
        68D885AF45           | push 0x45af85d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 85 af 45 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FileEncryptionStatusW
{
    meta:
        desc = "Metasploit::API::advapi32::FileEncryptionStatusW"

    /*
        68D8855F46           | push 0x465f85d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 85 5f 46 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FindFirstFreeAce
{
    meta:
        desc = "Metasploit::API::advapi32::FindFirstFreeAce"

    /*
        686EC3A430           | push 0x30a4c36e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e c3 a4 30 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FlushEfsCache
{
    meta:
        desc = "Metasploit::API::advapi32::FlushEfsCache"

    /*
        68F07A7856           | push 0x56787af0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 7a 78 56 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FlushTraceA
{
    meta:
        desc = "Metasploit::API::advapi32::FlushTraceA"

    /*
        68C6DB7E1F           | push 0x1f7edbc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 db 7e 1f ff d5 }

    condition:
        any of them
}

    
rule advapi32_FlushTraceW
{
    meta:
        desc = "Metasploit::API::advapi32::FlushTraceW"

    /*
        68C6DB2E20           | push 0x202edbc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 db 2e 20 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FreeEncryptedFileKeyInfo
{
    meta:
        desc = "Metasploit::API::advapi32::FreeEncryptedFileKeyInfo"

    /*
        68DF8D5F93           | push 0x935f8ddf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 8d 5f 93 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FreeEncryptedFileMetadata
{
    meta:
        desc = "Metasploit::API::advapi32::FreeEncryptedFileMetadata"

    /*
        68F1E4F962           | push 0x62f9e4f1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f1 e4 f9 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FreeEncryptionCertificateHashList
{
    meta:
        desc = "Metasploit::API::advapi32::FreeEncryptionCertificateHashList"

    /*
        68986BEEC4           | push 0xc4ee6b98
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 98 6b ee c4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FreeInheritedFromArray
{
    meta:
        desc = "Metasploit::API::advapi32::FreeInheritedFromArray"

    /*
        68671144F6           | push 0xf6441167
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 11 44 f6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_FreeSid
{
    meta:
        desc = "Metasploit::API::advapi32::FreeSid"

    /*
        6864707F0D           | push 0x0d7f7064
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 70 7f 0d ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetAccessPermissionsForObjectA
{
    meta:
        desc = "Metasploit::API::advapi32::GetAccessPermissionsForObjectA"

    /*
        6868D827EC           | push 0xec27d868
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 d8 27 ec ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetAccessPermissionsForObjectW
{
    meta:
        desc = "Metasploit::API::advapi32::GetAccessPermissionsForObjectW"

    /*
        6868D8D7EC           | push 0xecd7d868
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 d8 d7 ec ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetAce
{
    meta:
        desc = "Metasploit::API::advapi32::GetAce"

    /*
        682456DCE8           | push 0xe8dc5624
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 56 dc e8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetAclInformation
{
    meta:
        desc = "Metasploit::API::advapi32::GetAclInformation"

    /*
        6884A437DB           | push 0xdb37a484
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 a4 37 db ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetAuditedPermissionsFromAclA
{
    meta:
        desc = "Metasploit::API::advapi32::GetAuditedPermissionsFromAclA"

    /*
        68338F1D62           | push 0x621d8f33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 8f 1d 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetAuditedPermissionsFromAclW
{
    meta:
        desc = "Metasploit::API::advapi32::GetAuditedPermissionsFromAclW"

    /*
        68338FCD62           | push 0x62cd8f33
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 8f cd 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetCurrentHwProfileA
{
    meta:
        desc = "Metasploit::API::advapi32::GetCurrentHwProfileA"

    /*
        6802083F0F           | push 0x0f3f0802
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 08 3f 0f ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetCurrentHwProfileW
{
    meta:
        desc = "Metasploit::API::advapi32::GetCurrentHwProfileW"

    /*
        680208EF0F           | push 0x0fef0802
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 08 ef 0f ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetDynamicTimeZoneInformationEffectiveYears
{
    meta:
        desc = "Metasploit::API::advapi32::GetDynamicTimeZoneInformationEffectiveYears"

    /*
        68A40E03FF           | push 0xff030ea4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 0e 03 ff ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetEffectiveRightsFromAclA
{
    meta:
        desc = "Metasploit::API::advapi32::GetEffectiveRightsFromAclA"

    /*
        682C1C0AE6           | push 0xe60a1c2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 1c 0a e6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetEffectiveRightsFromAclW
{
    meta:
        desc = "Metasploit::API::advapi32::GetEffectiveRightsFromAclW"

    /*
        682C1CBAE6           | push 0xe6ba1c2c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c 1c ba e6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetEncryptedFileMetadata
{
    meta:
        desc = "Metasploit::API::advapi32::GetEncryptedFileMetadata"

    /*
        682BBAF932           | push 0x32f9ba2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b ba f9 32 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetEventLogInformation
{
    meta:
        desc = "Metasploit::API::advapi32::GetEventLogInformation"

    /*
        6848DCF33E           | push 0x3ef3dc48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 dc f3 3e ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetExplicitEntriesFromAclA
{
    meta:
        desc = "Metasploit::API::advapi32::GetExplicitEntriesFromAclA"

    /*
        681C994F97           | push 0x974f991c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 99 4f 97 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetExplicitEntriesFromAclW
{
    meta:
        desc = "Metasploit::API::advapi32::GetExplicitEntriesFromAclW"

    /*
        681C99FF97           | push 0x97ff991c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1c 99 ff 97 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetFileSecurityA
{
    meta:
        desc = "Metasploit::API::advapi32::GetFileSecurityA"

    /*
        68C1269737           | push 0x379726c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 26 97 37 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetFileSecurityW
{
    meta:
        desc = "Metasploit::API::advapi32::GetFileSecurityW"

    /*
        68C1264738           | push 0x384726c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 26 47 38 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetInformationCodeAuthzLevelW
{
    meta:
        desc = "Metasploit::API::advapi32::GetInformationCodeAuthzLevelW"

    /*
        68CC21301A           | push 0x1a3021cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 21 30 1a ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetInformationCodeAuthzPolicyW
{
    meta:
        desc = "Metasploit::API::advapi32::GetInformationCodeAuthzPolicyW"

    /*
        6825034BF8           | push 0xf84b0325
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 03 4b f8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetInheritanceSourceA
{
    meta:
        desc = "Metasploit::API::advapi32::GetInheritanceSourceA"

    /*
        68EB936F49           | push 0x496f93eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 93 6f 49 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetInheritanceSourceW
{
    meta:
        desc = "Metasploit::API::advapi32::GetInheritanceSourceW"

    /*
        68EB931F4A           | push 0x4a1f93eb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 eb 93 1f 4a ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetKernelObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::GetKernelObjectSecurity"

    /*
        68DBF8BAD4           | push 0xd4baf8db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db f8 ba d4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetLengthSid
{
    meta:
        desc = "Metasploit::API::advapi32::GetLengthSid"

    /*
        68F90920F3           | push 0xf32009f9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f9 09 20 f3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetLocalManagedApplicationData
{
    meta:
        desc = "Metasploit::API::advapi32::GetLocalManagedApplicationData"

    /*
        68E9D06179           | push 0x7961d0e9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 d0 61 79 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetLocalManagedApplications
{
    meta:
        desc = "Metasploit::API::advapi32::GetLocalManagedApplications"

    /*
        68195964C8           | push 0xc8645919
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 59 64 c8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetManagedApplicationCategories
{
    meta:
        desc = "Metasploit::API::advapi32::GetManagedApplicationCategories"

    /*
        68FC88468C           | push 0x8c4688fc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fc 88 46 8c ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetManagedApplications
{
    meta:
        desc = "Metasploit::API::advapi32::GetManagedApplications"

    /*
        6818CC6C9A           | push 0x9a6ccc18
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 18 cc 6c 9a ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetMultipleTrusteeA
{
    meta:
        desc = "Metasploit::API::advapi32::GetMultipleTrusteeA"

    /*
        6845D5E678           | push 0x78e6d545
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 d5 e6 78 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetMultipleTrusteeOperationA
{
    meta:
        desc = "Metasploit::API::advapi32::GetMultipleTrusteeOperationA"

    /*
        68E2DBE757           | push 0x57e7dbe2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 db e7 57 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetMultipleTrusteeOperationW
{
    meta:
        desc = "Metasploit::API::advapi32::GetMultipleTrusteeOperationW"

    /*
        68E2DB9758           | push 0x5897dbe2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 db 97 58 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetMultipleTrusteeW
{
    meta:
        desc = "Metasploit::API::advapi32::GetMultipleTrusteeW"

    /*
        6845D59679           | push 0x7996d545
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 d5 96 79 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetNamedSecurityInfoA
{
    meta:
        desc = "Metasploit::API::advapi32::GetNamedSecurityInfoA"

    /*
        681F99E009           | push 0x09e0991f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 99 e0 09 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetNamedSecurityInfoExA
{
    meta:
        desc = "Metasploit::API::advapi32::GetNamedSecurityInfoExA"

    /*
        68BA1680C0           | push 0xc08016ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 16 80 c0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetNamedSecurityInfoExW
{
    meta:
        desc = "Metasploit::API::advapi32::GetNamedSecurityInfoExW"

    /*
        68BA1630C1           | push 0xc13016ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 16 30 c1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetNamedSecurityInfoW
{
    meta:
        desc = "Metasploit::API::advapi32::GetNamedSecurityInfoW"

    /*
        681F99900A           | push 0x0a90991f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 99 90 0a ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetNumberOfEventLogRecords
{
    meta:
        desc = "Metasploit::API::advapi32::GetNumberOfEventLogRecords"

    /*
        68F5E920F5           | push 0xf520e9f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 e9 20 f5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetOldestEventLogRecord
{
    meta:
        desc = "Metasploit::API::advapi32::GetOldestEventLogRecord"

    /*
        6801AE6C82           | push 0x826cae01
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 ae 6c 82 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetOverlappedAccessResults
{
    meta:
        desc = "Metasploit::API::advapi32::GetOverlappedAccessResults"

    /*
        686434E51E           | push 0x1ee53464
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 34 e5 1e ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetPrivateObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::GetPrivateObjectSecurity"

    /*
        68B1477869           | push 0x697847b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 47 78 69 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityDescriptorControl
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityDescriptorControl"

    /*
        680CBE652F           | push 0x2f65be0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c be 65 2f ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityDescriptorDacl
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityDescriptorDacl"

    /*
        68A397A380           | push 0x80a397a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 97 a3 80 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityDescriptorGroup
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityDescriptorGroup"

    /*
        680700A751           | push 0x51a70007
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 00 a7 51 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityDescriptorLength
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityDescriptorLength"

    /*
        68DA669860           | push 0x609866da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 66 98 60 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityDescriptorOwner
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityDescriptorOwner"

    /*
        680B4CB74F           | push 0x4fb74c0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 4c b7 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityDescriptorRMControl
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityDescriptorRMControl"

    /*
        6862120E05           | push 0x050e1262
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 12 0e 05 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityDescriptorSacl
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityDescriptorSacl"

    /*
        68A387A480           | push 0x80a487a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 87 a4 80 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityInfo
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityInfo"

    /*
        6860F5AC90           | push 0x90acf560
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 60 f5 ac 90 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityInfoExA
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityInfoExA"

    /*
        682153F5CD           | push 0xcdf55321
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 53 f5 cd ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSecurityInfoExW
{
    meta:
        desc = "Metasploit::API::advapi32::GetSecurityInfoExW"

    /*
        682153A5CE           | push 0xcea55321
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 53 a5 ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetServiceDisplayNameA
{
    meta:
        desc = "Metasploit::API::advapi32::GetServiceDisplayNameA"

    /*
        68D66DC399           | push 0x99c36dd6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 6d c3 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetServiceDisplayNameW
{
    meta:
        desc = "Metasploit::API::advapi32::GetServiceDisplayNameW"

    /*
        68D66D739A           | push 0x9a736dd6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d6 6d 73 9a ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetServiceKeyNameA
{
    meta:
        desc = "Metasploit::API::advapi32::GetServiceKeyNameA"

    /*
        68E4F98D77           | push 0x778df9e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 f9 8d 77 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetServiceKeyNameW
{
    meta:
        desc = "Metasploit::API::advapi32::GetServiceKeyNameW"

    /*
        68E4F93D78           | push 0x783df9e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 f9 3d 78 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSidIdentifierAuthority
{
    meta:
        desc = "Metasploit::API::advapi32::GetSidIdentifierAuthority"

    /*
        682177F182           | push 0x82f17721
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 77 f1 82 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSidLengthRequired
{
    meta:
        desc = "Metasploit::API::advapi32::GetSidLengthRequired"

    /*
        68F2F637DE           | push 0xde37f6f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 f6 37 de ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSidSubAuthority
{
    meta:
        desc = "Metasploit::API::advapi32::GetSidSubAuthority"

    /*
        6864FD21D4           | push 0xd421fd64
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 64 fd 21 d4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetSidSubAuthorityCount
{
    meta:
        desc = "Metasploit::API::advapi32::GetSidSubAuthorityCount"

    /*
        68ED880049           | push 0x490088ed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 88 00 49 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetStringConditionFromBinary
{
    meta:
        desc = "Metasploit::API::advapi32::GetStringConditionFromBinary"

    /*
        687C6EF2A4           | push 0xa4f26e7c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7c 6e f2 a4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetThreadWaitChain
{
    meta:
        desc = "Metasploit::API::advapi32::GetThreadWaitChain"

    /*
        684F06D256           | push 0x56d2064f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 06 d2 56 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTokenInformation
{
    meta:
        desc = "Metasploit::API::advapi32::GetTokenInformation"

    /*
        680CDC6755           | push 0x5567dc0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c dc 67 55 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTraceEnableFlags
{
    meta:
        desc = "Metasploit::API::advapi32::GetTraceEnableFlags"

    /*
        68AF086717           | push 0x176708af
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 af 08 67 17 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTraceEnableLevel
{
    meta:
        desc = "Metasploit::API::advapi32::GetTraceEnableLevel"

    /*
        6832982E41           | push 0x412e9832
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 98 2e 41 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTraceLoggerHandle
{
    meta:
        desc = "Metasploit::API::advapi32::GetTraceLoggerHandle"

    /*
        682D9CB534           | push 0x34b59c2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 9c b5 34 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTrusteeFormA
{
    meta:
        desc = "Metasploit::API::advapi32::GetTrusteeFormA"

    /*
        689B461D99           | push 0x991d469b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 46 1d 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTrusteeFormW
{
    meta:
        desc = "Metasploit::API::advapi32::GetTrusteeFormW"

    /*
        689B46CD99           | push 0x99cd469b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 46 cd 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTrusteeNameA
{
    meta:
        desc = "Metasploit::API::advapi32::GetTrusteeNameA"

    /*
        689F641C8F           | push 0x8f1c649f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 64 1c 8f ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTrusteeNameW
{
    meta:
        desc = "Metasploit::API::advapi32::GetTrusteeNameW"

    /*
        689F64CC8F           | push 0x8fcc649f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 64 cc 8f ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTrusteeTypeA
{
    meta:
        desc = "Metasploit::API::advapi32::GetTrusteeTypeA"

    /*
        68A2E41D95           | push 0x951de4a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 e4 1d 95 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetTrusteeTypeW
{
    meta:
        desc = "Metasploit::API::advapi32::GetTrusteeTypeW"

    /*
        68A2E4CD95           | push 0x95cde4a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 e4 cd 95 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetUserNameA
{
    meta:
        desc = "Metasploit::API::advapi32::GetUserNameA"

    /*
        68C6DF3334           | push 0x3433dfc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 df 33 34 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetUserNameW
{
    meta:
        desc = "Metasploit::API::advapi32::GetUserNameW"

    /*
        68C6DFE334           | push 0x34e3dfc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 df e3 34 ff d5 }

    condition:
        any of them
}

    
rule advapi32_GetWindowsAccountDomainSid
{
    meta:
        desc = "Metasploit::API::advapi32::GetWindowsAccountDomainSid"

    /*
        6805D0C6A5           | push 0xa5c6d005
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 d0 c6 a5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_QueryTagInformation
{
    meta:
        desc = "Metasploit::API::advapi32::I_QueryTagInformation"

    /*
        682B13AA87           | push 0x87aa132b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 13 aa 87 ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScGetCurrentGroupStateW
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScGetCurrentGroupStateW"

    /*
        685414E5EE           | push 0xeee51454
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 14 e5 ee ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScIsSecurityProcess
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScIsSecurityProcess"

    /*
        68ECB7B886           | push 0x86b8b7ec
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ec b7 b8 86 ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScPnPGetServiceName
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScPnPGetServiceName"

    /*
        68AEE1C71B           | push 0x1bc7e1ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae e1 c7 1b ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScQueryServiceConfig
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScQueryServiceConfig"

    /*
        6896811AC5           | push 0xc51a8196
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 96 81 1a c5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScRegisterPreshutdownRestart
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScRegisterPreshutdownRestart"

    /*
        6842C41EB6           | push 0xb61ec442
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 c4 1e b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScReparseServiceDatabase
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScReparseServiceDatabase"

    /*
        68B0E3F0E8           | push 0xe8f0e3b0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 e3 f0 e8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScSendPnPMessage
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScSendPnPMessage"

    /*
        68C416341F           | push 0x1f3416c4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c4 16 34 1f ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScSendTSMessage
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScSendTSMessage"

    /*
        6887851307           | push 0x07138587
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 87 85 13 07 ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScSetServiceBitsA
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScSetServiceBitsA"

    /*
        686294266A           | push 0x6a269462
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 94 26 6a ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScSetServiceBitsW
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScSetServiceBitsW"

    /*
        686294D66A           | push 0x6ad69462
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 94 d6 6a ff d5 }

    condition:
        any of them
}

    
rule advapi32_I_ScValidatePnPService
{
    meta:
        desc = "Metasploit::API::advapi32::I_ScValidatePnPService"

    /*
        681DD2BFA0           | push 0xa0bfd21d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d d2 bf a0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_IdentifyCodeAuthzLevelW
{
    meta:
        desc = "Metasploit::API::advapi32::IdentifyCodeAuthzLevelW"

    /*
        68E156146F           | push 0x6f1456e1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e1 56 14 6f ff d5 }

    condition:
        any of them
}

    
rule advapi32_ImpersonateAnonymousToken
{
    meta:
        desc = "Metasploit::API::advapi32::ImpersonateAnonymousToken"

    /*
        68FDD7E2E6           | push 0xe6e2d7fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd d7 e2 e6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ImpersonateLoggedOnUser
{
    meta:
        desc = "Metasploit::API::advapi32::ImpersonateLoggedOnUser"

    /*
        6841694CBC           | push 0xbc4c6941
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 41 69 4c bc ff d5 }

    condition:
        any of them
}

    
rule advapi32_ImpersonateNamedPipeClient
{
    meta:
        desc = "Metasploit::API::advapi32::ImpersonateNamedPipeClient"

    /*
        6868992296           | push 0x96229968
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 68 99 22 96 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ImpersonateSelf
{
    meta:
        desc = "Metasploit::API::advapi32::ImpersonateSelf"

    /*
        68FA867FB8           | push 0xb87f86fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 86 7f b8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitializeAcl
{
    meta:
        desc = "Metasploit::API::advapi32::InitializeAcl"

    /*
        68ACC2F0EF           | push 0xeff0c2ac
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ac c2 f0 ef ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitializeSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::advapi32::InitializeSecurityDescriptor"

    /*
        68A6158AFE           | push 0xfe8a15a6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a6 15 8a fe ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitializeSid
{
    meta:
        desc = "Metasploit::API::advapi32::InitializeSid"

    /*
        682CC4B013           | push 0x13b0c42c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c c4 b0 13 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitiateShutdownA
{
    meta:
        desc = "Metasploit::API::advapi32::InitiateShutdownA"

    /*
        6802884AD2           | push 0xd24a8802
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 88 4a d2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitiateShutdownW
{
    meta:
        desc = "Metasploit::API::advapi32::InitiateShutdownW"

    /*
        680288FAD2           | push 0xd2fa8802
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 88 fa d2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitiateSystemShutdownA
{
    meta:
        desc = "Metasploit::API::advapi32::InitiateSystemShutdownA"

    /*
        6849F2B878           | push 0x78b8f249
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 f2 b8 78 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitiateSystemShutdownExA
{
    meta:
        desc = "Metasploit::API::advapi32::InitiateSystemShutdownExA"

    /*
        6856619676           | push 0x76966156
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 61 96 76 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitiateSystemShutdownExW
{
    meta:
        desc = "Metasploit::API::advapi32::InitiateSystemShutdownExW"

    /*
        6856614677           | push 0x77466156
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 61 46 77 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InitiateSystemShutdownW
{
    meta:
        desc = "Metasploit::API::advapi32::InitiateSystemShutdownW"

    /*
        6849F26879           | push 0x7968f249
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 f2 68 79 ff d5 }

    condition:
        any of them
}

    
rule advapi32_InstallApplication
{
    meta:
        desc = "Metasploit::API::advapi32::InstallApplication"

    /*
        689D74CE6E           | push 0x6ece749d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 74 ce 6e ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsTextUnicode
{
    meta:
        desc = "Metasploit::API::advapi32::IsTextUnicode"

    /*
        685018A31E           | push 0x1ea31850
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 18 a3 1e ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsTokenRestricted
{
    meta:
        desc = "Metasploit::API::advapi32::IsTokenRestricted"

    /*
        68DE4153F9           | push 0xf95341de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 41 53 f9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsTokenUntrusted
{
    meta:
        desc = "Metasploit::API::advapi32::IsTokenUntrusted"

    /*
        68065417D6           | push 0xd6175406
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 54 17 d6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsValidAcl
{
    meta:
        desc = "Metasploit::API::advapi32::IsValidAcl"

    /*
        6858FAAA7F           | push 0x7faafa58
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 fa aa 7f ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsValidRelativeSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::advapi32::IsValidRelativeSecurityDescriptor"

    /*
        68254FD7CE           | push 0xced74f25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 4f d7 ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsValidSecurityDescriptor
{
    meta:
        desc = "Metasploit::API::advapi32::IsValidSecurityDescriptor"

    /*
        689B5C8190           | push 0x90815c9b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9b 5c 81 90 ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsValidSid
{
    meta:
        desc = "Metasploit::API::advapi32::IsValidSid"

    /*
        68D8FB6AA3           | push 0xa36afbd8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 fb 6a a3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_IsWellKnownSid
{
    meta:
        desc = "Metasploit::API::advapi32::IsWellKnownSid"

    /*
        68F88EC292           | push 0x92c28ef8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 8e c2 92 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LockServiceDatabase
{
    meta:
        desc = "Metasploit::API::advapi32::LockServiceDatabase"

    /*
        68DEA491E3           | push 0xe391a4de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de a4 91 e3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LogonUserA
{
    meta:
        desc = "Metasploit::API::advapi32::LogonUserA"

    /*
        68CFCF5B97           | push 0x975bcfcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf cf 5b 97 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LogonUserExA
{
    meta:
        desc = "Metasploit::API::advapi32::LogonUserExA"

    /*
        68DEC24D1F           | push 0x1f4dc2de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de c2 4d 1f ff d5 }

    condition:
        any of them
}

    
rule advapi32_LogonUserExExW
{
    meta:
        desc = "Metasploit::API::advapi32::LogonUserExExW"

    /*
        6880867A1C           | push 0x1c7a8680
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 86 7a 1c ff d5 }

    condition:
        any of them
}

    
rule advapi32_LogonUserExW
{
    meta:
        desc = "Metasploit::API::advapi32::LogonUserExW"

    /*
        68DEC2FD1F           | push 0x1ffdc2de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de c2 fd 1f ff d5 }

    condition:
        any of them
}

    
rule advapi32_LogonUserW
{
    meta:
        desc = "Metasploit::API::advapi32::LogonUserW"

    /*
        68CFCF0B98           | push 0x980bcfcf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf cf 0b 98 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupAccountNameA
{
    meta:
        desc = "Metasploit::API::advapi32::LookupAccountNameA"

    /*
        680788A9A1           | push 0xa1a98807
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 88 a9 a1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupAccountNameW
{
    meta:
        desc = "Metasploit::API::advapi32::LookupAccountNameW"

    /*
        68078859A2           | push 0xa2598807
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 88 59 a2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupAccountSidA
{
    meta:
        desc = "Metasploit::API::advapi32::LookupAccountSidA"

    /*
        689322CC02           | push 0x02cc2293
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 22 cc 02 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupAccountSidW
{
    meta:
        desc = "Metasploit::API::advapi32::LookupAccountSidW"

    /*
        6893227C03           | push 0x037c2293
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 22 7c 03 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupPrivilegeDisplayNameA
{
    meta:
        desc = "Metasploit::API::advapi32::LookupPrivilegeDisplayNameA"

    /*
        68CD55AB84           | push 0x84ab55cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 55 ab 84 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupPrivilegeDisplayNameW
{
    meta:
        desc = "Metasploit::API::advapi32::LookupPrivilegeDisplayNameW"

    /*
        68CD555B85           | push 0x855b55cd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd 55 5b 85 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupPrivilegeNameA
{
    meta:
        desc = "Metasploit::API::advapi32::LookupPrivilegeNameA"

    /*
        688EBB597B           | push 0x7b59bb8e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e bb 59 7b ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupPrivilegeNameW
{
    meta:
        desc = "Metasploit::API::advapi32::LookupPrivilegeNameW"

    /*
        688EBB097C           | push 0x7c09bb8e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e bb 09 7c ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupPrivilegeValueA
{
    meta:
        desc = "Metasploit::API::advapi32::LookupPrivilegeValueA"

    /*
        6877BCA5F7           | push 0xf7a5bc77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 bc a5 f7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupPrivilegeValueW
{
    meta:
        desc = "Metasploit::API::advapi32::LookupPrivilegeValueW"

    /*
        6877BC55F8           | push 0xf855bc77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 bc 55 f8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupSecurityDescriptorPartsA
{
    meta:
        desc = "Metasploit::API::advapi32::LookupSecurityDescriptorPartsA"

    /*
        6861DE6490           | push 0x9064de61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 de 64 90 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LookupSecurityDescriptorPartsW
{
    meta:
        desc = "Metasploit::API::advapi32::LookupSecurityDescriptorPartsW"

    /*
        6861DE1491           | push 0x9114de61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 de 14 91 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaAddAccountRights
{
    meta:
        desc = "Metasploit::API::advapi32::LsaAddAccountRights"

    /*
        684772C423           | push 0x23c47247
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 72 c4 23 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaAddPrivilegesToAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaAddPrivilegesToAccount"

    /*
        68F27E5B9D           | push 0x9d5b7ef2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 7e 5b 9d ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaClearAuditLog
{
    meta:
        desc = "Metasploit::API::advapi32::LsaClearAuditLog"

    /*
        68AD82FB02           | push 0x02fb82ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 82 fb 02 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaClose
{
    meta:
        desc = "Metasploit::API::advapi32::LsaClose"

    /*
        6873E84391           | push 0x9143e873
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 73 e8 43 91 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaCreateAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaCreateAccount"

    /*
        684A3C5F79           | push 0x795f3c4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a 3c 5f 79 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaCreateSecret
{
    meta:
        desc = "Metasploit::API::advapi32::LsaCreateSecret"

    /*
        68972BECB0           | push 0xb0ec2b97
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 2b ec b0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaCreateTrustedDomain
{
    meta:
        desc = "Metasploit::API::advapi32::LsaCreateTrustedDomain"

    /*
        68D3392226           | push 0x262239d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 39 22 26 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaCreateTrustedDomainEx
{
    meta:
        desc = "Metasploit::API::advapi32::LsaCreateTrustedDomainEx"

    /*
        680137A0CA           | push 0xcaa03701
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 01 37 a0 ca ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaDelete
{
    meta:
        desc = "Metasploit::API::advapi32::LsaDelete"

    /*
        688446D2A3           | push 0xa3d24684
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 84 46 d2 a3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaDeleteTrustedDomain
{
    meta:
        desc = "Metasploit::API::advapi32::LsaDeleteTrustedDomain"

    /*
        680B3CE622           | push 0x22e63c0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 3c e6 22 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaEnumerateAccountRights
{
    meta:
        desc = "Metasploit::API::advapi32::LsaEnumerateAccountRights"

    /*
        68EE2CBCDC           | push 0xdcbc2cee
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ee 2c bc dc ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaEnumerateAccounts
{
    meta:
        desc = "Metasploit::API::advapi32::LsaEnumerateAccounts"

    /*
        684242B230           | push 0x30b24242
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 42 b2 30 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaEnumerateAccountsWithUserRight
{
    meta:
        desc = "Metasploit::API::advapi32::LsaEnumerateAccountsWithUserRight"

    /*
        68477311DE           | push 0xde117347
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 73 11 de ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaEnumeratePrivileges
{
    meta:
        desc = "Metasploit::API::advapi32::LsaEnumeratePrivileges"

    /*
        68A7E3491C           | push 0x1c49e3a7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a7 e3 49 1c ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaEnumeratePrivilegesOfAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaEnumeratePrivilegesOfAccount"

    /*
        68D13AFA7E           | push 0x7efa3ad1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 3a fa 7e ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaEnumerateTrustedDomains
{
    meta:
        desc = "Metasploit::API::advapi32::LsaEnumerateTrustedDomains"

    /*
        68AD60B805           | push 0x05b860ad
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ad 60 b8 05 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaEnumerateTrustedDomainsEx
{
    meta:
        desc = "Metasploit::API::advapi32::LsaEnumerateTrustedDomainsEx"

    /*
        6879ED29B0           | push 0xb029ed79
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 79 ed 29 b0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaFreeMemory
{
    meta:
        desc = "Metasploit::API::advapi32::LsaFreeMemory"

    /*
        68C68D5951           | push 0x51598dc6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 8d 59 51 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaGetAppliedCAPIDs
{
    meta:
        desc = "Metasploit::API::advapi32::LsaGetAppliedCAPIDs"

    /*
        6802D5A63C           | push 0x3ca6d502
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 d5 a6 3c ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaGetQuotasForAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaGetQuotasForAccount"

    /*
        680A5E7A48           | push 0x487a5e0a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 5e 7a 48 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaGetRemoteUserName
{
    meta:
        desc = "Metasploit::API::advapi32::LsaGetRemoteUserName"

    /*
        6843665A8A           | push 0x8a5a6643
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 43 66 5a 8a ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaGetSystemAccessAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaGetSystemAccessAccount"

    /*
        6817011791           | push 0x91170117
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 01 17 91 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaGetUserName
{
    meta:
        desc = "Metasploit::API::advapi32::LsaGetUserName"

    /*
        6834DD6478           | push 0x7864dd34
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 34 dd 64 78 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaICLookupNames
{
    meta:
        desc = "Metasploit::API::advapi32::LsaICLookupNames"

    /*
        6893355872           | push 0x72583593
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 35 58 72 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaICLookupNamesWithCreds
{
    meta:
        desc = "Metasploit::API::advapi32::LsaICLookupNamesWithCreds"

    /*
        68511196D4           | push 0xd4961151
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 11 96 d4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaICLookupSids
{
    meta:
        desc = "Metasploit::API::advapi32::LsaICLookupSids"

    /*
        68769C0DDA           | push 0xda0d9c76
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 76 9c 0d da ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaICLookupSidsWithCreds
{
    meta:
        desc = "Metasploit::API::advapi32::LsaICLookupSidsWithCreds"

    /*
        688F2CCD7F           | push 0x7fcd2c8f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8f 2c cd 7f ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaLookupNames
{
    meta:
        desc = "Metasploit::API::advapi32::LsaLookupNames"

    /*
        6865E30B27           | push 0x270be365
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 e3 0b 27 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaLookupNames2
{
    meta:
        desc = "Metasploit::API::advapi32::LsaLookupNames2"

    /*
        680821C315           | push 0x15c32108
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 21 c3 15 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaLookupPrivilegeDisplayName
{
    meta:
        desc = "Metasploit::API::advapi32::LsaLookupPrivilegeDisplayName"

    /*
        68F5B7D434           | push 0x34d4b7f5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 b7 d4 34 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaLookupPrivilegeName
{
    meta:
        desc = "Metasploit::API::advapi32::LsaLookupPrivilegeName"

    /*
        683F31960A           | push 0x0a96313f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3f 31 96 0a ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaLookupPrivilegeValue
{
    meta:
        desc = "Metasploit::API::advapi32::LsaLookupPrivilegeValue"

    /*
        685E412A84           | push 0x842a415e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 41 2a 84 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaLookupSids
{
    meta:
        desc = "Metasploit::API::advapi32::LsaLookupSids"

    /*
        680DD3C74F           | push 0x4fc7d30d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d d3 c7 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaLookupSids2
{
    meta:
        desc = "Metasploit::API::advapi32::LsaLookupSids2"

    /*
        68E7660493           | push 0x930466e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 66 04 93 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaManageSidNameMapping
{
    meta:
        desc = "Metasploit::API::advapi32::LsaManageSidNameMapping"

    /*
        68C8230D29           | push 0x290d23c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 23 0d 29 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaNtStatusToWinError
{
    meta:
        desc = "Metasploit::API::advapi32::LsaNtStatusToWinError"

    /*
        684F0FC5A1           | push 0xa1c50f4f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 0f c5 a1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaOpenAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaOpenAccount"

    /*
        68306FE6F9           | push 0xf9e66f30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 6f e6 f9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaOpenPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::LsaOpenPolicy"

    /*
        682D6B6585           | push 0x85656b2d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 6b 65 85 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaOpenPolicySce
{
    meta:
        desc = "Metasploit::API::advapi32::LsaOpenPolicySce"

    /*
        68CDBEFE84           | push 0x84febecd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd be fe 84 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaOpenSecret
{
    meta:
        desc = "Metasploit::API::advapi32::LsaOpenSecret"

    /*
        68A8DB4897           | push 0x9748dba8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 db 48 97 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaOpenTrustedDomain
{
    meta:
        desc = "Metasploit::API::advapi32::LsaOpenTrustedDomain"

    /*
        68F03BB8F1           | push 0xf1b83bf0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 3b b8 f1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaOpenTrustedDomainByName
{
    meta:
        desc = "Metasploit::API::advapi32::LsaOpenTrustedDomainByName"

    /*
        684B35C223           | push 0x23c2354b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 35 c2 23 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQueryCAPs
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQueryCAPs"

    /*
        68E6DADD9F           | push 0x9fdddae6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 da dd 9f ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQueryDomainInformationPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQueryDomainInformationPolicy"

    /*
        685DAF3F38           | push 0x383faf5d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5d af 3f 38 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQueryForestTrustInformation
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQueryForestTrustInformation"

    /*
        68B2AD6D4D           | push 0x4d6dadb2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b2 ad 6d 4d ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQueryInfoTrustedDomain
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQueryInfoTrustedDomain"

    /*
        6808321114           | push 0x14113208
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 32 11 14 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQueryInformationPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQueryInformationPolicy"

    /*
        6878C9707D           | push 0x7d70c978
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 78 c9 70 7d ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQuerySecret
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQuerySecret"

    /*
        68F2B3A937           | push 0x37a9b3f2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f2 b3 a9 37 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQuerySecurityObject
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQuerySecurityObject"

    /*
        68FD85CE26           | push 0x26ce85fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 85 ce 26 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQueryTrustedDomainInfo
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQueryTrustedDomainInfo"

    /*
        6866D88CE6           | push 0xe68cd866
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 d8 8c e6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaQueryTrustedDomainInfoByName
{
    meta:
        desc = "Metasploit::API::advapi32::LsaQueryTrustedDomainInfoByName"

    /*
        689D089A95           | push 0x959a089d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 08 9a 95 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaRemoveAccountRights
{
    meta:
        desc = "Metasploit::API::advapi32::LsaRemoveAccountRights"

    /*
        68DF03AC70           | push 0x70ac03df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 03 ac 70 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaRemovePrivilegesFromAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaRemovePrivilegesFromAccount"

    /*
        6869ECD3FC           | push 0xfcd3ec69
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 ec d3 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaRetrievePrivateData
{
    meta:
        desc = "Metasploit::API::advapi32::LsaRetrievePrivateData"

    /*
        68D471FEA4           | push 0xa4fe71d4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 71 fe a4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetCAPs
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetCAPs"

    /*
        68DEE3C4CA           | push 0xcac4e3de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de e3 c4 ca ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetDomainInformationPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetDomainInformationPolicy"

    /*
        68B39F5106           | push 0x06519fb3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 9f 51 06 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetForestTrustInformation
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetForestTrustInformation"

    /*
        687467788B           | push 0x8b786774
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 67 78 8b ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetInformationPolicy
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetInformationPolicy"

    /*
        68FD3C86F9           | push 0xf9863cfd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 3c 86 f9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetInformationTrustedDomain
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetInformationTrustedDomain"

    /*
        68DE75D275           | push 0x75d275de
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 75 d2 75 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetQuotasForAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetQuotasForAccount"

    /*
        680A767A48           | push 0x487a760a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a 76 7a 48 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetSecret
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetSecret"

    /*
        68FDF16BF1           | push 0xf16bf1fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd f1 6b f1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetSecurityObject
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetSecurityObject"

    /*
        683B488831           | push 0x3188483b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 48 88 31 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetSystemAccessAccount
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetSystemAccessAccount"

    /*
        6847011791           | push 0x91170147
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 47 01 17 91 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetTrustedDomainInfoByName
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetTrustedDomainInfoByName"

    /*
        68F3F8AB63           | push 0x63abf8f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 f8 ab 63 ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaSetTrustedDomainInformation
{
    meta:
        desc = "Metasploit::API::advapi32::LsaSetTrustedDomainInformation"

    /*
        68923EE63B           | push 0x3be63e92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 3e e6 3b ff d5 }

    condition:
        any of them
}

    
rule advapi32_LsaStorePrivateData
{
    meta:
        desc = "Metasploit::API::advapi32::LsaStorePrivateData"

    /*
        68080C26F6           | push 0xf6260c08
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 0c 26 f6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MD4Final
{
    meta:
        desc = "Metasploit::API::advapi32::MD4Final"

    /*
        6815AEC70F           | push 0x0fc7ae15
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 ae c7 0f ff d5 }

    condition:
        any of them
}

    
rule advapi32_MD4Init
{
    meta:
        desc = "Metasploit::API::advapi32::MD4Init"

    /*
        682BB145C3           | push 0xc345b12b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b b1 45 c3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MD4Update
{
    meta:
        desc = "Metasploit::API::advapi32::MD4Update"

    /*
        68EAC815ED           | push 0xed15c8ea
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ea c8 15 ed ff d5 }

    condition:
        any of them
}

    
rule advapi32_MD5Final
{
    meta:
        desc = "Metasploit::API::advapi32::MD5Final"

    /*
        6815AECB0F           | push 0x0fcbae15
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 ae cb 0f ff d5 }

    condition:
        any of them
}

    
rule advapi32_MD5Init
{
    meta:
        desc = "Metasploit::API::advapi32::MD5Init"

    /*
        682CB14543           | push 0x4345b12c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2c b1 45 43 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MD5Update
{
    meta:
        desc = "Metasploit::API::advapi32::MD5Update"

    /*
        680AC915ED           | push 0xed15c90a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0a c9 15 ed ff d5 }

    condition:
        any of them
}

    
rule advapi32_MIDL_user_free_Ext
{
    meta:
        desc = "Metasploit::API::advapi32::MIDL_user_free_Ext"

    /*
        6842979DA6           | push 0xa69d9742
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 97 9d a6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MSChapSrvChangePassword
{
    meta:
        desc = "Metasploit::API::advapi32::MSChapSrvChangePassword"

    /*
        682F1699F0           | push 0xf099162f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2f 16 99 f0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MSChapSrvChangePassword2
{
    meta:
        desc = "Metasploit::API::advapi32::MSChapSrvChangePassword2"

    /*
        68716D11AC           | push 0xac116d71
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 71 6d 11 ac ff d5 }

    condition:
        any of them
}

    
rule advapi32_MakeAbsoluteSD
{
    meta:
        desc = "Metasploit::API::advapi32::MakeAbsoluteSD"

    /*
        68CDAAB614           | push 0x14b6aacd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cd aa b6 14 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MakeAbsoluteSD2
{
    meta:
        desc = "Metasploit::API::advapi32::MakeAbsoluteSD2"

    /*
        685E8E0251           | push 0x51028e5e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 8e 02 51 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MakeSelfRelativeSD
{
    meta:
        desc = "Metasploit::API::advapi32::MakeSelfRelativeSD"

    /*
        6830FC8303           | push 0x0383fc30
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 30 fc 83 03 ff d5 }

    condition:
        any of them
}

    
rule advapi32_MapGenericMask
{
    meta:
        desc = "Metasploit::API::advapi32::MapGenericMask"

    /*
        687DA3A4FF           | push 0xffa4a37d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d a3 a4 ff ff d5 }

    condition:
        any of them
}

    
rule advapi32_NotifyBootConfigStatus
{
    meta:
        desc = "Metasploit::API::advapi32::NotifyBootConfigStatus"

    /*
        68ED7E582D           | push 0x2d587eed
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ed 7e 58 2d ff d5 }

    condition:
        any of them
}

    
rule advapi32_NotifyChangeEventLog
{
    meta:
        desc = "Metasploit::API::advapi32::NotifyChangeEventLog"

    /*
        686E83ABD6           | push 0xd6ab836e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e 83 ab d6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_NotifyServiceStatusChange
{
    meta:
        desc = "Metasploit::API::advapi32::NotifyServiceStatusChange"

    /*
        681A81A2F3           | push 0xf3a2811a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 81 a2 f3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_NotifyServiceStatusChangeA
{
    meta:
        desc = "Metasploit::API::advapi32::NotifyServiceStatusChangeA"

    /*
        68BD85E103           | push 0x03e185bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 85 e1 03 ff d5 }

    condition:
        any of them
}

    
rule advapi32_NotifyServiceStatusChangeW
{
    meta:
        desc = "Metasploit::API::advapi32::NotifyServiceStatusChangeW"

    /*
        68BD859104           | push 0x049185bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 85 91 04 ff d5 }

    condition:
        any of them
}

    
rule advapi32_NpGetUserName
{
    meta:
        desc = "Metasploit::API::advapi32::NpGetUserName"

    /*
        6824AEE365           | push 0x65e3ae24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 ae e3 65 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectCloseAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectCloseAuditAlarmA"

    /*
        6886E8DEE5           | push 0xe5dee886
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 e8 de e5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectCloseAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectCloseAuditAlarmW"

    /*
        6886E88EE6           | push 0xe68ee886
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 86 e8 8e e6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectDeleteAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectDeleteAuditAlarmA"

    /*
        6851BBA4A4           | push 0xa4a4bb51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 bb a4 a4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectDeleteAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectDeleteAuditAlarmW"

    /*
        6851BB54A5           | push 0xa554bb51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 bb 54 a5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectOpenAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectOpenAuditAlarmA"

    /*
        684D7586BF           | push 0xbf86754d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 75 86 bf ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectOpenAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectOpenAuditAlarmW"

    /*
        684D7536C0           | push 0xc036754d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4d 75 36 c0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectPrivilegeAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectPrivilegeAuditAlarmA"

    /*
        68E704425E           | push 0x5e4204e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 04 42 5e ff d5 }

    condition:
        any of them
}

    
rule advapi32_ObjectPrivilegeAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::ObjectPrivilegeAuditAlarmW"

    /*
        68E704F25E           | push 0x5ef204e7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 04 f2 5e ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenBackupEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::OpenBackupEventLogA"

    /*
        68C83732C9           | push 0xc93237c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 37 32 c9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenBackupEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::OpenBackupEventLogW"

    /*
        68C837E2C9           | push 0xc9e237c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 37 e2 c9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenEncryptedFileRawA
{
    meta:
        desc = "Metasploit::API::advapi32::OpenEncryptedFileRawA"

    /*
        689983D167           | push 0x67d18399
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 83 d1 67 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenEncryptedFileRawW
{
    meta:
        desc = "Metasploit::API::advapi32::OpenEncryptedFileRawW"

    /*
        6899838168           | push 0x68818399
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 99 83 81 68 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::OpenEventLogA"

    /*
        68E812A2E2           | push 0xe2a212e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 12 a2 e2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::OpenEventLogW"

    /*
        68E81252E3           | push 0xe35212e8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 12 52 e3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenProcessToken
{
    meta:
        desc = "Metasploit::API::advapi32::OpenProcessToken"

    /*
        6826C60B1B           | push 0x1b0bc626
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 26 c6 0b 1b ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenSCManagerA
{
    meta:
        desc = "Metasploit::API::advapi32::OpenSCManagerA"

    /*
        6867F03676           | push 0x7636f067
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 f0 36 76 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenSCManagerW
{
    meta:
        desc = "Metasploit::API::advapi32::OpenSCManagerW"

    /*
        6867F0E676           | push 0x76e6f067
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 67 f0 e6 76 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenServiceA
{
    meta:
        desc = "Metasploit::API::advapi32::OpenServiceA"

    /*
        6856284B40           | push 0x404b2856
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 28 4b 40 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenServiceW
{
    meta:
        desc = "Metasploit::API::advapi32::OpenServiceW"

    /*
        685628FB40           | push 0x40fb2856
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 28 fb 40 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenThreadToken
{
    meta:
        desc = "Metasploit::API::advapi32::OpenThreadToken"

    /*
        68C069C535           | push 0x35c569c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 69 c5 35 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenThreadWaitChainSession
{
    meta:
        desc = "Metasploit::API::advapi32::OpenThreadWaitChainSession"

    /*
        685B371109           | push 0x0911375b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b 37 11 09 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenTraceA
{
    meta:
        desc = "Metasploit::API::advapi32::OpenTraceA"

    /*
        687EB4F2D0           | push 0xd0f2b47e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e b4 f2 d0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OpenTraceW
{
    meta:
        desc = "Metasploit::API::advapi32::OpenTraceW"

    /*
        687EB4A2D1           | push 0xd1a2b47e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e b4 a2 d1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OperationEnd
{
    meta:
        desc = "Metasploit::API::advapi32::OperationEnd"

    /*
        68729C3F93           | push 0x933f9c72
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 9c 3f 93 ff d5 }

    condition:
        any of them
}

    
rule advapi32_OperationStart
{
    meta:
        desc = "Metasploit::API::advapi32::OperationStart"

    /*
        68244AD90B           | push 0x0bd94a24
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 24 4a d9 0b ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfAddCounters
{
    meta:
        desc = "Metasploit::API::advapi32::PerfAddCounters"

    /*
        684C228B2E           | push 0x2e8b224c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c 22 8b 2e ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfCloseQueryHandle
{
    meta:
        desc = "Metasploit::API::advapi32::PerfCloseQueryHandle"

    /*
        6832BFCAB7           | push 0xb7cabf32
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 32 bf ca b7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfCreateInstance
{
    meta:
        desc = "Metasploit::API::advapi32::PerfCreateInstance"

    /*
        688E71C31A           | push 0x1ac3718e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e 71 c3 1a ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfDecrementULongCounterValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfDecrementULongCounterValue"

    /*
        682B5ADF72           | push 0x72df5a2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 5a df 72 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfDecrementULongLongCounterValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfDecrementULongLongCounterValue"

    /*
        68807320F3           | push 0xf3207380
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 80 73 20 f3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfDeleteCounters
{
    meta:
        desc = "Metasploit::API::advapi32::PerfDeleteCounters"

    /*
        68DBA9C4FC           | push 0xfcc4a9db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db a9 c4 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfDeleteInstance
{
    meta:
        desc = "Metasploit::API::advapi32::PerfDeleteInstance"

    /*
        68FE754B14           | push 0x144b75fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 75 4b 14 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfEnumerateCounterSet
{
    meta:
        desc = "Metasploit::API::advapi32::PerfEnumerateCounterSet"

    /*
        68041B7E9A           | push 0x9a7e1b04
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 1b 7e 9a ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfEnumerateCounterSetInstances
{
    meta:
        desc = "Metasploit::API::advapi32::PerfEnumerateCounterSetInstances"

    /*
        68C2EAF004           | push 0x04f0eac2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 ea f0 04 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfIncrementULongCounterValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfIncrementULongCounterValue"

    /*
        682B9AE0BA           | push 0xbae09a2b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b 9a e0 ba ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfIncrementULongLongCounterValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfIncrementULongLongCounterValue"

    /*
        6800782007           | push 0x07207800
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 78 20 07 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfOpenQueryHandle
{
    meta:
        desc = "Metasploit::API::advapi32::PerfOpenQueryHandle"

    /*
        681A9AAD0D           | push 0x0dad9a1a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a 9a ad 0d ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfQueryCounterData
{
    meta:
        desc = "Metasploit::API::advapi32::PerfQueryCounterData"

    /*
        68DA798ECD           | push 0xcd8e79da
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 da 79 8e cd ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfQueryCounterInfo
{
    meta:
        desc = "Metasploit::API::advapi32::PerfQueryCounterInfo"

    /*
        685BC6FEE7           | push 0xe7fec65b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5b c6 fe e7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfQueryCounterSetRegistrationInfo
{
    meta:
        desc = "Metasploit::API::advapi32::PerfQueryCounterSetRegistrationInfo"

    /*
        68F72C87CB           | push 0xcb872cf7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 2c 87 cb ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfQueryInstance
{
    meta:
        desc = "Metasploit::API::advapi32::PerfQueryInstance"

    /*
        68E79D3FF6           | push 0xf63f9de7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e7 9d 3f f6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfRegCloseKey
{
    meta:
        desc = "Metasploit::API::advapi32::PerfRegCloseKey"

    /*
        68AE46C4BA           | push 0xbac446ae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae 46 c4 ba ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfRegEnumKey
{
    meta:
        desc = "Metasploit::API::advapi32::PerfRegEnumKey"

    /*
        68815E6818           | push 0x18685e81
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 5e 68 18 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfRegEnumValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfRegEnumValue"

    /*
        68832E91C1           | push 0xc1912e83
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 83 2e 91 c1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfRegQueryInfoKey
{
    meta:
        desc = "Metasploit::API::advapi32::PerfRegQueryInfoKey"

    /*
        6888DC2DC5           | push 0xc52ddc88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 dc 2d c5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfRegQueryValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfRegQueryValue"

    /*
        68CF81DBCE           | push 0xcedb81cf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cf 81 db ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfRegSetValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfRegSetValue"

    /*
        68C009388C           | push 0x8c3809c0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c0 09 38 8c ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfSetCounterRefValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfSetCounterRefValue"

    /*
        68AEDA2B22           | push 0x222bdaae
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ae da 2b 22 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfSetCounterSetInfo
{
    meta:
        desc = "Metasploit::API::advapi32::PerfSetCounterSetInfo"

    /*
        6866D30F58           | push 0x580fd366
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 66 d3 0f 58 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfSetULongCounterValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfSetULongCounterValue"

    /*
        680D820AE2           | push 0xe20a820d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0d 82 0a e2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfSetULongLongCounterValue
{
    meta:
        desc = "Metasploit::API::advapi32::PerfSetULongLongCounterValue"

    /*
        68729A9EA5           | push 0xa59e9a72
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 72 9a 9e a5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfStartProvider
{
    meta:
        desc = "Metasploit::API::advapi32::PerfStartProvider"

    /*
        68D8F68FEA           | push 0xea8ff6d8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d8 f6 8f ea ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfStartProviderEx
{
    meta:
        desc = "Metasploit::API::advapi32::PerfStartProviderEx"

    /*
        6833780FE6           | push 0xe60f7833
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 33 78 0f e6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PerfStopProvider
{
    meta:
        desc = "Metasploit::API::advapi32::PerfStopProvider"

    /*
        6845022194           | push 0x94210245
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 45 02 21 94 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PrivilegeCheck
{
    meta:
        desc = "Metasploit::API::advapi32::PrivilegeCheck"

    /*
        689E497410           | push 0x1074499e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9e 49 74 10 ff d5 }

    condition:
        any of them
}

    
rule advapi32_PrivilegedServiceAuditAlarmA
{
    meta:
        desc = "Metasploit::API::advapi32::PrivilegedServiceAuditAlarmA"

    /*
        684EF8AA8C           | push 0x8caaf84e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e f8 aa 8c ff d5 }

    condition:
        any of them
}

    
rule advapi32_PrivilegedServiceAuditAlarmW
{
    meta:
        desc = "Metasploit::API::advapi32::PrivilegedServiceAuditAlarmW"

    /*
        684EF85A8D           | push 0x8d5af84e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e f8 5a 8d ff d5 }

    condition:
        any of them
}

    
rule advapi32_ProcessIdleTasks
{
    meta:
        desc = "Metasploit::API::advapi32::ProcessIdleTasks"

    /*
        6817407D64           | push 0x647d4017
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 17 40 7d 64 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ProcessIdleTasksW
{
    meta:
        desc = "Metasploit::API::advapi32::ProcessIdleTasksW"

    /*
        68930C7DFC           | push 0xfc7d0c93
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 93 0c 7d fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_ProcessTrace
{
    meta:
        desc = "Metasploit::API::advapi32::ProcessTrace"

    /*
        68976173CF           | push 0xcf736197
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 97 61 73 cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryAllTracesA
{
    meta:
        desc = "Metasploit::API::advapi32::QueryAllTracesA"

    /*
        68DD8FDE2F           | push 0x2fde8fdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 8f de 2f ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryAllTracesW
{
    meta:
        desc = "Metasploit::API::advapi32::QueryAllTracesW"

    /*
        68DD8F8E30           | push 0x308e8fdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 8f 8e 30 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryLocalUserServiceName
{
    meta:
        desc = "Metasploit::API::advapi32::QueryLocalUserServiceName"

    /*
        68E0407F20           | push 0x207f40e0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e0 40 7f 20 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryRecoveryAgentsOnEncryptedFile
{
    meta:
        desc = "Metasploit::API::advapi32::QueryRecoveryAgentsOnEncryptedFile"

    /*
        68E60014E5           | push 0xe51400e6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 00 14 e5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QuerySecurityAccessMask
{
    meta:
        desc = "Metasploit::API::advapi32::QuerySecurityAccessMask"

    /*
        682D55A7E1           | push 0xe1a7552d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2d 55 a7 e1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceConfig2A
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceConfig2A"

    /*
        68DD58E87A           | push 0x7ae858dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 58 e8 7a ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceConfig2W
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceConfig2W"

    /*
        68DD58987B           | push 0x7b9858dd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 58 98 7b ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceConfigA
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceConfigA"

    /*
        68FA8F7ECE           | push 0xce7e8ffa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 8f 7e ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceConfigW
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceConfigW"

    /*
        68FA8F2ECF           | push 0xcf2e8ffa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 8f 2e cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceDynamicInformation
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceDynamicInformation"

    /*
        68C88125B0           | push 0xb02581c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 81 25 b0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceLockStatusA
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceLockStatusA"

    /*
        68009E12AD           | push 0xad129e00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 9e 12 ad ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceLockStatusW
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceLockStatusW"

    /*
        68009EC2AD           | push 0xadc29e00
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 00 9e c2 ad ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceObjectSecurity"

    /*
        6808381D43           | push 0x431d3808
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 38 1d 43 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceStatus
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceStatus"

    /*
        68706D8931           | push 0x31896d70
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 70 6d 89 31 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryServiceStatusEx
{
    meta:
        desc = "Metasploit::API::advapi32::QueryServiceStatusEx"

    /*
        68441E6DA4           | push 0xa46d1e44
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 1e 6d a4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryTraceA
{
    meta:
        desc = "Metasploit::API::advapi32::QueryTraceA"

    /*
        68E85D945E           | push 0x5e945de8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 5d 94 5e ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryTraceProcessingHandle
{
    meta:
        desc = "Metasploit::API::advapi32::QueryTraceProcessingHandle"

    /*
        68D47BDABE           | push 0xbeda7bd4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d4 7b da be ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryTraceW
{
    meta:
        desc = "Metasploit::API::advapi32::QueryTraceW"

    /*
        68E85D445F           | push 0x5f445de8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e8 5d 44 5f ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryUserServiceName
{
    meta:
        desc = "Metasploit::API::advapi32::QueryUserServiceName"

    /*
        689D562FDC           | push 0xdc2f569d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 56 2f dc ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryUserServiceNameForContext
{
    meta:
        desc = "Metasploit::API::advapi32::QueryUserServiceNameForContext"

    /*
        6835725FE2           | push 0xe25f7235
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 72 5f e2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_QueryUsersOnEncryptedFile
{
    meta:
        desc = "Metasploit::API::advapi32::QueryUsersOnEncryptedFile"

    /*
        684AEE2DAB           | push 0xab2dee4a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4a ee 2d ab ff d5 }

    condition:
        any of them
}

    
rule advapi32_ReadEncryptedFileRaw
{
    meta:
        desc = "Metasploit::API::advapi32::ReadEncryptedFileRaw"

    /*
        6848F75D22           | push 0x225df748
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 f7 5d 22 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ReadEventLogA
{
    meta:
        desc = "Metasploit::API::advapi32::ReadEventLogA"

    /*
        6835121A64           | push 0x641a1235
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 12 1a 64 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ReadEventLogW
{
    meta:
        desc = "Metasploit::API::advapi32::ReadEventLogW"

    /*
        683512CA64           | push 0x64ca1235
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 35 12 ca 64 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCloseKey
{
    meta:
        desc = "Metasploit::API::advapi32::RegCloseKey"

    /*
        6844ACC281           | push 0x81c2ac44
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 ac c2 81 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegConnectRegistryA
{
    meta:
        desc = "Metasploit::API::advapi32::RegConnectRegistryA"

    /*
        683E5E92E0           | push 0xe0925e3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 5e 92 e0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegConnectRegistryExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegConnectRegistryExA"

    /*
        68B05EF16C           | push 0x6cf15eb0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 5e f1 6c ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegConnectRegistryExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegConnectRegistryExW"

    /*
        68B05EA16D           | push 0x6da15eb0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b0 5e a1 6d ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegConnectRegistryW
{
    meta:
        desc = "Metasploit::API::advapi32::RegConnectRegistryW"

    /*
        683E5E42E1           | push 0xe1425e3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 5e 42 e1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCopyTreeA
{
    meta:
        desc = "Metasploit::API::advapi32::RegCopyTreeA"

    /*
        68D56150E0           | push 0xe05061d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 61 50 e0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCopyTreeW
{
    meta:
        desc = "Metasploit::API::advapi32::RegCopyTreeW"

    /*
        68D56100E1           | push 0xe10061d5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d5 61 00 e1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCreateKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegCreateKeyA"

    /*
        68256E3F7F           | push 0x7f3f6e25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 6e 3f 7f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCreateKeyExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegCreateKeyExA"

    /*
        6858583518           | push 0x18355858
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 58 35 18 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCreateKeyExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegCreateKeyExW"

    /*
        685858E518           | push 0x18e55858
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 58 58 e5 18 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCreateKeyTransactedA
{
    meta:
        desc = "Metasploit::API::advapi32::RegCreateKeyTransactedA"

    /*
        681D097945           | push 0x4579091d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 09 79 45 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCreateKeyTransactedW
{
    meta:
        desc = "Metasploit::API::advapi32::RegCreateKeyTransactedW"

    /*
        681D092946           | push 0x4629091d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d 09 29 46 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegCreateKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegCreateKeyW"

    /*
        68256EEF7F           | push 0x7fef6e25
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 6e ef 7f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyA"

    /*
        68A5063FC6           | push 0xc63f06a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 06 3f c6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyExA"

    /*
        6869781BD8           | push 0xd81b7869
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 78 1b d8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyExW"

    /*
        686978CBD8           | push 0xd8cb7869
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 78 cb d8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyTransactedA
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyTransactedA"

    /*
        683DEF3857           | push 0x5738ef3d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d ef 38 57 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyTransactedW
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyTransactedW"

    /*
        683DEFE857           | push 0x57e8ef3d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d ef e8 57 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyValueA
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyValueA"

    /*
        685CDBCAC0           | push 0xc0cadb5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c db ca c0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyValueW
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyValueW"

    /*
        685CDB7AC1           | push 0xc17adb5c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c db 7a c1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteKeyW"

    /*
        68A506EFC6           | push 0xc6ef06a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 06 ef c6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteTreeA
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteTreeA"

    /*
        68A5F34088           | push 0x8840f3a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 f3 40 88 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteTreeW
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteTreeW"

    /*
        68A5F3F088           | push 0x88f0f3a5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a5 f3 f0 88 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteValueA
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteValueA"

    /*
        68A8A34638           | push 0x3846a3a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 a3 46 38 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDeleteValueW
{
    meta:
        desc = "Metasploit::API::advapi32::RegDeleteValueW"

    /*
        68A8A3F638           | push 0x38f6a3a8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a8 a3 f6 38 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDisablePredefinedCache
{
    meta:
        desc = "Metasploit::API::advapi32::RegDisablePredefinedCache"

    /*
        68D1F59834           | push 0x3498f5d1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 f5 98 34 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDisablePredefinedCacheEx
{
    meta:
        desc = "Metasploit::API::advapi32::RegDisablePredefinedCacheEx"

    /*
        6885364F68           | push 0x684f3685
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 85 36 4f 68 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegDisableReflectionKey
{
    meta:
        desc = "Metasploit::API::advapi32::RegDisableReflectionKey"

    /*
        68421E6B72           | push 0x726b1e42
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 42 1e 6b 72 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegEnableReflectionKey
{
    meta:
        desc = "Metasploit::API::advapi32::RegEnableReflectionKey"

    /*
        68F8D5E996           | push 0x96e9d5f8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f8 d5 e9 96 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegEnumKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegEnumKeyA"

    /*
        68811119B6           | push 0xb6191181
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 11 19 b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegEnumKeyExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegEnumKeyExA"

    /*
        68652F9ECE           | push 0xce9e2f65
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 2f 9e ce ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegEnumKeyExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegEnumKeyExW"

    /*
        68652F4ECF           | push 0xcf4e2f65
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 65 2f 4e cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegEnumKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegEnumKeyW"

    /*
        688111C9B6           | push 0xb6c91181
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 81 11 c9 b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegEnumValueA
{
    meta:
        desc = "Metasploit::API::advapi32::RegEnumValueA"

    /*
        68A45AC92E           | push 0x2ec95aa4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 5a c9 2e ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegEnumValueW
{
    meta:
        desc = "Metasploit::API::advapi32::RegEnumValueW"

    /*
        68A45A792F           | push 0x2f795aa4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a4 5a 79 2f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegFlushKey
{
    meta:
        desc = "Metasploit::API::advapi32::RegFlushKey"

    /*
        6844DCDA84           | push 0x84dadc44
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 44 dc da 84 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegGetKeySecurity
{
    meta:
        desc = "Metasploit::API::advapi32::RegGetKeySecurity"

    /*
        6802356CE0           | push 0xe06c3502
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 35 6c e0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegGetValueA
{
    meta:
        desc = "Metasploit::API::advapi32::RegGetValueA"

    /*
        685C22C475           | push 0x75c4225c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 22 c4 75 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegGetValueW
{
    meta:
        desc = "Metasploit::API::advapi32::RegGetValueW"

    /*
        685C227476           | push 0x7674225c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 22 74 76 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegLoadAppKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegLoadAppKeyA"

    /*
        68562A7A07           | push 0x077a2a56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 2a 7a 07 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegLoadAppKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegLoadAppKeyW"

    /*
        68562A2A08           | push 0x082a2a56
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 56 2a 2a 08 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegLoadKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegLoadKeyA"

    /*
        689D11C93C           | push 0x3cc9119d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 11 c9 3c ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegLoadKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegLoadKeyW"

    /*
        689D11793D           | push 0x3d79119d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9d 11 79 3d ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegLoadMUIStringA
{
    meta:
        desc = "Metasploit::API::advapi32::RegLoadMUIStringA"

    /*
        684B922064           | push 0x6420924b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 92 20 64 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegLoadMUIStringW
{
    meta:
        desc = "Metasploit::API::advapi32::RegLoadMUIStringW"

    /*
        684B92D064           | push 0x64d0924b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4b 92 d0 64 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegNotifyChangeKeyValue
{
    meta:
        desc = "Metasploit::API::advapi32::RegNotifyChangeKeyValue"

    /*
        6857D45D27           | push 0x275dd457
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 57 d4 5d 27 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenCurrentUser
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenCurrentUser"

    /*
        687BCDD0A7           | push 0xa7d0cd7b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7b cd d0 a7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenKeyA"

    /*
        68C211D93F           | push 0x3fd911c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 11 d9 3f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenKeyExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenKeyExA"

    /*
        68883F9E3E           | push 0x3e9e3f88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 3f 9e 3e ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenKeyExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenKeyExW"

    /*
        68883F4E3F           | push 0x3f4e3f88
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 88 3f 4e 3f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenKeyTransactedA
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenKeyTransactedA"

    /*
        6804729F75           | push 0x759f7204
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 72 9f 75 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenKeyTransactedW
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenKeyTransactedW"

    /*
        6804724F76           | push 0x764f7204
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 72 4f 76 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenKeyW"

    /*
        68C2118940           | push 0x408911c2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c2 11 89 40 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOpenUserClassesRoot
{
    meta:
        desc = "Metasploit::API::advapi32::RegOpenUserClassesRoot"

    /*
        6848457618           | push 0x18764548
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 45 76 18 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegOverridePredefKey
{
    meta:
        desc = "Metasploit::API::advapi32::RegOverridePredefKey"

    /*
        68779EF2C3           | push 0xc3f29e77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 9e f2 c3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryInfoKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryInfoKeyA"

    /*
        68E244D7C2           | push 0xc2d744e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 44 d7 c2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryInfoKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryInfoKeyW"

    /*
        68E24487C3           | push 0xc38744e2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e2 44 87 c3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryMultipleValuesA
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryMultipleValuesA"

    /*
        68771F2920           | push 0x20291f77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 1f 29 20 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryMultipleValuesW
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryMultipleValuesW"

    /*
        68771FD920           | push 0x20d91f77
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 77 1f d9 20 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryReflectionKey
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryReflectionKey"

    /*
        6851E9A32F           | push 0x2fa3e951
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 e9 a3 2f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryValueA
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryValueA"

    /*
        68505C1E35           | push 0x351e5c50
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 5c 1e 35 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryValueExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryValueExA"

    /*
        6805E3F08F           | push 0x8ff0e305
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 e3 f0 8f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryValueExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryValueExW"

    /*
        6805E3A090           | push 0x90a0e305
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 05 e3 a0 90 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegQueryValueW
{
    meta:
        desc = "Metasploit::API::advapi32::RegQueryValueW"

    /*
        68505CCE35           | push 0x35ce5c50
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 50 5c ce 35 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegRenameKey
{
    meta:
        desc = "Metasploit::API::advapi32::RegRenameKey"

    /*
        68A209B023           | push 0x23b009a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 09 b0 23 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegReplaceKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegReplaceKeyA"

    /*
        684EA6520F           | push 0x0f52a64e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e a6 52 0f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegReplaceKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegReplaceKeyW"

    /*
        684EA60210           | push 0x1002a64e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4e a6 02 10 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegRestoreKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegRestoreKeyA"

    /*
        680EC08E17           | push 0x178ec00e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e c0 8e 17 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegRestoreKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegRestoreKeyW"

    /*
        680EC03E18           | push 0x183ec00e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0e c0 3e 18 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSaveKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegSaveKeyA"

    /*
        68DD0F1DC4           | push 0xc41d0fdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 0f 1d c4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSaveKeyExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegSaveKeyExA"

    /*
        6869C69D4F           | push 0x4f9dc669
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 c6 9d 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSaveKeyExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegSaveKeyExW"

    /*
        6869C64D50           | push 0x504dc669
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 69 c6 4d 50 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSaveKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegSaveKeyW"

    /*
        68DD0FCDC4           | push 0xc4cd0fdd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 dd 0f cd c4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSetKeySecurity
{
    meta:
        desc = "Metasploit::API::advapi32::RegSetKeySecurity"

    /*
        6802656CE0           | push 0xe06c6502
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 02 65 6c e0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSetKeyValueA
{
    meta:
        desc = "Metasploit::API::advapi32::RegSetKeyValueA"

    /*
        681AD74529           | push 0x2945d71a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a d7 45 29 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSetKeyValueW
{
    meta:
        desc = "Metasploit::API::advapi32::RegSetKeyValueW"

    /*
        681AD7F529           | push 0x29f5d71a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1a d7 f5 29 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSetValueA
{
    meta:
        desc = "Metasploit::API::advapi32::RegSetValueA"

    /*
        685C82C475           | push 0x75c4825c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 82 c4 75 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSetValueExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegSetValueExA"

    /*
        6815667AB9           | push 0xb97a6615
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 66 7a b9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSetValueExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegSetValueExW"

    /*
        6815662ABA           | push 0xba2a6615
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 15 66 2a ba ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegSetValueW
{
    meta:
        desc = "Metasploit::API::advapi32::RegSetValueW"

    /*
        685C827476           | push 0x7674825c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5c 82 74 76 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegUnLoadKeyA
{
    meta:
        desc = "Metasploit::API::advapi32::RegUnLoadKeyA"

    /*
        68E94FF365           | push 0x65f34fe9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 4f f3 65 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegUnLoadKeyW
{
    meta:
        desc = "Metasploit::API::advapi32::RegUnLoadKeyW"

    /*
        68E94FA366           | push 0x66a34fe9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e9 4f a3 66 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterEventSourceA
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterEventSourceA"

    /*
        68D11681D4           | push 0xd48116d1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 16 81 d4 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterEventSourceW
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterEventSourceW"

    /*
        68D11631D5           | push 0xd53116d1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d1 16 31 d5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterIdleTask
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterIdleTask"

    /*
        68FA995D88           | push 0x885d99fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa 99 5d 88 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterServiceCtrlHandlerA
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterServiceCtrlHandlerA"

    /*
        686CAB274C           | push 0x4c27ab6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c ab 27 4c ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterServiceCtrlHandlerExA
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterServiceCtrlHandlerExA"

    /*
        680BAA4452           | push 0x5244aa0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b aa 44 52 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterServiceCtrlHandlerExW
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterServiceCtrlHandlerExW"

    /*
        680BAAF452           | push 0x52f4aa0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b aa f4 52 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterServiceCtrlHandlerW
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterServiceCtrlHandlerW"

    /*
        686CABD74C           | push 0x4cd7ab6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c ab d7 4c ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterTraceGuidsA
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterTraceGuidsA"

    /*
        684F3D92BD           | push 0xbd923d4f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 3d 92 bd ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterTraceGuidsW
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterTraceGuidsW"

    /*
        684F3D42BE           | push 0xbe423d4f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 3d 42 be ff d5 }

    condition:
        any of them
}

    
rule advapi32_RegisterWaitChainCOMCallback
{
    meta:
        desc = "Metasploit::API::advapi32::RegisterWaitChainCOMCallback"

    /*
        684F3020C8           | push 0xc820304f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4f 30 20 c8 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoteRegEnumKeyWrapper
{
    meta:
        desc = "Metasploit::API::advapi32::RemoteRegEnumKeyWrapper"

    /*
        681DD1EAAC           | push 0xacead11d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1d d1 ea ac ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoteRegEnumValueWrapper
{
    meta:
        desc = "Metasploit::API::advapi32::RemoteRegEnumValueWrapper"

    /*
        6808B197AB           | push 0xab97b108
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 08 b1 97 ab ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoteRegQueryInfoKeyWrapper
{
    meta:
        desc = "Metasploit::API::advapi32::RemoteRegQueryInfoKeyWrapper"

    /*
        68494F93F0           | push 0xf0934f49
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 4f 93 f0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoteRegQueryMultipleValues2Wrapper
{
    meta:
        desc = "Metasploit::API::advapi32::RemoteRegQueryMultipleValues2Wrapper"

    /*
        68FE457EB9           | push 0xb97e45fe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 45 7e b9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoteRegQueryMultipleValuesWrapper
{
    meta:
        desc = "Metasploit::API::advapi32::RemoteRegQueryMultipleValuesWrapper"

    /*
        6874A97F0C           | push 0x0c7fa974
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 74 a9 7f 0c ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoteRegQueryValueWrapper
{
    meta:
        desc = "Metasploit::API::advapi32::RemoteRegQueryValueWrapper"

    /*
        686BD294FA           | push 0xfa94d26b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6b d2 94 fa ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoveTraceCallback
{
    meta:
        desc = "Metasploit::API::advapi32::RemoveTraceCallback"

    /*
        68F7AC15B1           | push 0xb115acf7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f7 ac 15 b1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RemoveUsersFromEncryptedFile
{
    meta:
        desc = "Metasploit::API::advapi32::RemoveUsersFromEncryptedFile"

    /*
        684628E5A3           | push 0xa3e52846
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 46 28 e5 a3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ReportEventA
{
    meta:
        desc = "Metasploit::API::advapi32::ReportEventA"

    /*
        6829F68034           | push 0x3480f629
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 f6 80 34 ff d5 }

    condition:
        any of them
}

    
rule advapi32_ReportEventW
{
    meta:
        desc = "Metasploit::API::advapi32::ReportEventW"

    /*
        6829F63035           | push 0x3530f629
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 29 f6 30 35 ff d5 }

    condition:
        any of them
}

    
rule advapi32_RevertToSelf
{
    meta:
        desc = "Metasploit::API::advapi32::RevertToSelf"

    /*
        682784E323           | push 0x23e38427
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 27 84 e3 23 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SafeBaseRegGetKeySecurity
{
    meta:
        desc = "Metasploit::API::advapi32::SafeBaseRegGetKeySecurity"

    /*
        689F7D8EAE           | push 0xae8e7d9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f 7d 8e ae ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferCloseLevel
{
    meta:
        desc = "Metasploit::API::advapi32::SaferCloseLevel"

    /*
        68635F7496           | push 0x96745f63
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 63 5f 74 96 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferComputeTokenFromLevel
{
    meta:
        desc = "Metasploit::API::advapi32::SaferComputeTokenFromLevel"

    /*
        68CA8044BF           | push 0xbf4480ca
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ca 80 44 bf ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferCreateLevel
{
    meta:
        desc = "Metasploit::API::advapi32::SaferCreateLevel"

    /*
        68613CE907           | push 0x07e93c61
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 61 3c e9 07 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferGetLevelInformation
{
    meta:
        desc = "Metasploit::API::advapi32::SaferGetLevelInformation"

    /*
        688ADCB241           | push 0x41b2dc8a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a dc b2 41 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferGetPolicyInformation
{
    meta:
        desc = "Metasploit::API::advapi32::SaferGetPolicyInformation"

    /*
        6837723C0D           | push 0x0d3c7237
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 72 3c 0d ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferIdentifyLevel
{
    meta:
        desc = "Metasploit::API::advapi32::SaferIdentifyLevel"

    /*
        68C8E45097           | push 0x9750e4c8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c8 e4 50 97 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferRecordEventLogEntry
{
    meta:
        desc = "Metasploit::API::advapi32::SaferRecordEventLogEntry"

    /*
        68F5BA4DC5           | push 0xc54dbaf5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f5 ba 4d c5 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferSetLevelInformation
{
    meta:
        desc = "Metasploit::API::advapi32::SaferSetLevelInformation"

    /*
        688AF4B241           | push 0x41b2f48a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8a f4 b2 41 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferSetPolicyInformation
{
    meta:
        desc = "Metasploit::API::advapi32::SaferSetPolicyInformation"

    /*
        6837723CCD           | push 0xcd3c7237
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 37 72 3c cd ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferiChangeRegistryScope
{
    meta:
        desc = "Metasploit::API::advapi32::SaferiChangeRegistryScope"

    /*
        68B875DE52           | push 0x52de75b8
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b8 75 de 52 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferiCompareTokenLevels
{
    meta:
        desc = "Metasploit::API::advapi32::SaferiCompareTokenLevels"

    /*
        68B5128ECD           | push 0xcd8e12b5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 12 8e cd ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferiIsDllAllowed
{
    meta:
        desc = "Metasploit::API::advapi32::SaferiIsDllAllowed"

    /*
        687E3EF92B           | push 0x2bf93e7e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7e 3e f9 2b ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferiIsExecutableFileType
{
    meta:
        desc = "Metasploit::API::advapi32::SaferiIsExecutableFileType"

    /*
        684CFAC6F0           | push 0xf0c6fa4c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c fa c6 f0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferiPopulateDefaultsInRegistry
{
    meta:
        desc = "Metasploit::API::advapi32::SaferiPopulateDefaultsInRegistry"

    /*
        686EB45FB0           | push 0xb05fb46e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6e b4 5f b0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferiRecordEventLogEntry
{
    meta:
        desc = "Metasploit::API::advapi32::SaferiRecordEventLogEntry"

    /*
        68F348F4CD           | push 0xcdf448f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 48 f4 cd ff d5 }

    condition:
        any of them
}

    
rule advapi32_SaferiSearchMatchingHashRules
{
    meta:
        desc = "Metasploit::API::advapi32::SaferiSearchMatchingHashRules"

    /*
        680665CC70           | push 0x70cc6506
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 06 65 cc 70 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetAclInformation
{
    meta:
        desc = "Metasploit::API::advapi32::SetAclInformation"

    /*
        68E4A437DB           | push 0xdb37a4e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 a4 37 db ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetEncryptedFileMetadata
{
    meta:
        desc = "Metasploit::API::advapi32::SetEncryptedFileMetadata"

    /*
        682BC6F932           | push 0x32f9c62b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2b c6 f9 32 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetEntriesInAccessListA
{
    meta:
        desc = "Metasploit::API::advapi32::SetEntriesInAccessListA"

    /*
        68E684762E           | push 0x2e7684e6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 84 76 2e ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetEntriesInAccessListW
{
    meta:
        desc = "Metasploit::API::advapi32::SetEntriesInAccessListW"

    /*
        68E684262F           | push 0x2f2684e6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e6 84 26 2f ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetEntriesInAclA
{
    meta:
        desc = "Metasploit::API::advapi32::SetEntriesInAclA"

    /*
        68D2558154           | push 0x548155d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 55 81 54 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetEntriesInAclW
{
    meta:
        desc = "Metasploit::API::advapi32::SetEntriesInAclW"

    /*
        68D2553155           | push 0x553155d2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d2 55 31 55 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetEntriesInAuditListA
{
    meta:
        desc = "Metasploit::API::advapi32::SetEntriesInAuditListA"

    /*
        681907F626           | push 0x26f60719
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 07 f6 26 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetEntriesInAuditListW
{
    meta:
        desc = "Metasploit::API::advapi32::SetEntriesInAuditListW"

    /*
        681907A627           | push 0x27a60719
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 19 07 a6 27 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetFileSecurityA
{
    meta:
        desc = "Metasploit::API::advapi32::SetFileSecurityA"

    /*
        68C126A337           | push 0x37a326c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 26 a3 37 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetFileSecurityW
{
    meta:
        desc = "Metasploit::API::advapi32::SetFileSecurityW"

    /*
        68C1265338           | push 0x385326c1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c1 26 53 38 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetInformationCodeAuthzLevelW
{
    meta:
        desc = "Metasploit::API::advapi32::SetInformationCodeAuthzLevelW"

    /*
        68CC27301A           | push 0x1a3027cc
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cc 27 30 1a ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetInformationCodeAuthzPolicyW
{
    meta:
        desc = "Metasploit::API::advapi32::SetInformationCodeAuthzPolicyW"

    /*
        6825034B28           | push 0x284b0325
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 25 03 4b 28 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetKernelObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::SetKernelObjectSecurity"

    /*
        68DBF83AD6           | push 0xd63af8db
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 db f8 3a d6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetNamedSecurityInfoA
{
    meta:
        desc = "Metasploit::API::advapi32::SetNamedSecurityInfoA"

    /*
        681F99E609           | push 0x09e6991f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 99 e6 09 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetNamedSecurityInfoExA
{
    meta:
        desc = "Metasploit::API::advapi32::SetNamedSecurityInfoExA"

    /*
        68BA1600C2           | push 0xc20016ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 16 00 c2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetNamedSecurityInfoExW
{
    meta:
        desc = "Metasploit::API::advapi32::SetNamedSecurityInfoExW"

    /*
        68BA16B0C2           | push 0xc2b016ba
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 ba 16 b0 c2 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetNamedSecurityInfoW
{
    meta:
        desc = "Metasploit::API::advapi32::SetNamedSecurityInfoW"

    /*
        681F99960A           | push 0x0a96991f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 1f 99 96 0a ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetPrivateObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::SetPrivateObjectSecurity"

    /*
        68B1537869           | push 0x697853b1
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b1 53 78 69 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetPrivateObjectSecurityEx
{
    meta:
        desc = "Metasploit::API::advapi32::SetPrivateObjectSecurityEx"

    /*
        6892AE26A0           | push 0xa026ae92
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 92 ae 26 a0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityAccessMask
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityAccessMask"

    /*
        6859497E07           | push 0x077e4959
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 59 49 7e 07 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityDescriptorControl
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityDescriptorControl"

    /*
        680CBE2530           | push 0x3025be0c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c be 25 30 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityDescriptorDacl
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityDescriptorDacl"

    /*
        68A397A3E0           | push 0xe0a397a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 97 a3 e0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityDescriptorGroup
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityDescriptorGroup"

    /*
        680700AA51           | push 0x51aa0007
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 07 00 aa 51 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityDescriptorOwner
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityDescriptorOwner"

    /*
        680B4CBA4F           | push 0x4fba4c0b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0b 4c ba 4f ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityDescriptorRMControl
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityDescriptorRMControl"

    /*
        6862120E35           | push 0x350e1262
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 12 0e 35 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityDescriptorSacl
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityDescriptorSacl"

    /*
        68A387A4E0           | push 0xe0a487a3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a3 87 a4 e0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityInfo
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityInfo"

    /*
        6862F5AC10           | push 0x10acf562
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 62 f5 ac 10 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityInfoExA
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityInfoExA"

    /*
        682153F5D0           | push 0xd0f55321
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 53 f5 d0 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetSecurityInfoExW
{
    meta:
        desc = "Metasploit::API::advapi32::SetSecurityInfoExW"

    /*
        682153A5D1           | push 0xd1a55321
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 21 53 a5 d1 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetServiceBits
{
    meta:
        desc = "Metasploit::API::advapi32::SetServiceBits"

    /*
        68DE2AE422           | push 0x22e42ade
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 de 2a e4 22 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetServiceObjectSecurity
{
    meta:
        desc = "Metasploit::API::advapi32::SetServiceObjectSecurity"

    /*
        68F0E56899           | push 0x9968e5f0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f0 e5 68 99 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetServiceStatus
{
    meta:
        desc = "Metasploit::API::advapi32::SetServiceStatus"

    /*
        68C655377D           | push 0x7d3755c6
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c6 55 37 7d ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetThreadToken
{
    meta:
        desc = "Metasploit::API::advapi32::SetThreadToken"

    /*
        6816F6C455           | push 0x55c4f616
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 16 f6 c4 55 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetTokenInformation
{
    meta:
        desc = "Metasploit::API::advapi32::SetTokenInformation"

    /*
        680CF46755           | push 0x5567f40c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 0c f4 67 55 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetTraceCallback
{
    meta:
        desc = "Metasploit::API::advapi32::SetTraceCallback"

    /*
        688D41B977           | push 0x77b9418d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8d 41 b9 77 ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetUserFileEncryptionKey
{
    meta:
        desc = "Metasploit::API::advapi32::SetUserFileEncryptionKey"

    /*
        683B0904EB           | push 0xeb04093b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 09 04 eb ff d5 }

    condition:
        any of them
}

    
rule advapi32_SetUserFileEncryptionKeyEx
{
    meta:
        desc = "Metasploit::API::advapi32::SetUserFileEncryptionKeyEx"

    /*
        68F3101403           | push 0x031410f3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 f3 10 14 03 ff d5 }

    condition:
        any of them
}

    
rule advapi32_StartServiceA
{
    meta:
        desc = "Metasploit::API::advapi32::StartServiceA"

    /*
        68A95AADA9           | push 0xa9ad5aa9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 5a ad a9 ff d5 }

    condition:
        any of them
}

    
rule advapi32_StartServiceCtrlDispatcherA
{
    meta:
        desc = "Metasploit::API::advapi32::StartServiceCtrlDispatcherA"

    /*
        68FAF772CB           | push 0xcb72f7fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa f7 72 cb ff d5 }

    condition:
        any of them
}

    
rule advapi32_StartServiceCtrlDispatcherW
{
    meta:
        desc = "Metasploit::API::advapi32::StartServiceCtrlDispatcherW"

    /*
        68FAF722CC           | push 0xcc22f7fa
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fa f7 22 cc ff d5 }

    condition:
        any of them
}

    
rule advapi32_StartServiceW
{
    meta:
        desc = "Metasploit::API::advapi32::StartServiceW"

    /*
        68A95A5DAA           | push 0xaa5d5aa9
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a9 5a 5d aa ff d5 }

    condition:
        any of them
}

    
rule advapi32_StartTraceA
{
    meta:
        desc = "Metasploit::API::advapi32::StartTraceA"

    /*
        68483D981E           | push 0x1e983d48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 3d 98 1e ff d5 }

    condition:
        any of them
}

    
rule advapi32_StartTraceW
{
    meta:
        desc = "Metasploit::API::advapi32::StartTraceW"

    /*
        68483D481F           | push 0x1f483d48
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 48 3d 48 1f ff d5 }

    condition:
        any of them
}

    
rule advapi32_StopTraceA
{
    meta:
        desc = "Metasploit::API::advapi32::StopTraceA"

    /*
        68BFD4F2DA           | push 0xdaf2d4bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf d4 f2 da ff d5 }

    condition:
        any of them
}

    
rule advapi32_StopTraceW
{
    meta:
        desc = "Metasploit::API::advapi32::StopTraceW"

    /*
        68BFD4A2DB           | push 0xdba2d4bf
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bf d4 a2 db ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction001
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction001"

    /*
        687D414EFC           | push 0xfc4e417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 4e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction002
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction002"

    /*
        687D4156FC           | push 0xfc56417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 56 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction003
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction003"

    /*
        687D415EFC           | push 0xfc5e417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 5e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction004
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction004"

    /*
        687D4166FC           | push 0xfc66417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 66 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction005
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction005"

    /*
        687D416EFC           | push 0xfc6e417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 6e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction006
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction006"

    /*
        687D4176FC           | push 0xfc76417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 76 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction007
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction007"

    /*
        687D417EFC           | push 0xfc7e417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 7e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction008
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction008"

    /*
        687D4186FC           | push 0xfc86417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 86 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction009
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction009"

    /*
        687D418EFC           | push 0xfc8e417d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 41 8e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction010
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction010"

    /*
        68BD4146FC           | push 0xfc4641bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 46 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction011
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction011"

    /*
        68BD414EFC           | push 0xfc4e41bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 4e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction012
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction012"

    /*
        68BD4156FC           | push 0xfc5641bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 56 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction013
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction013"

    /*
        68BD415EFC           | push 0xfc5e41bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 5e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction014
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction014"

    /*
        68BD4166FC           | push 0xfc6641bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 66 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction015
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction015"

    /*
        68BD416EFC           | push 0xfc6e41bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 6e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction016
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction016"

    /*
        68BD4176FC           | push 0xfc7641bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 76 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction017
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction017"

    /*
        68BD417EFC           | push 0xfc7e41bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 7e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction018
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction018"

    /*
        68BD4186FC           | push 0xfc8641bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 86 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction019
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction019"

    /*
        68BD418EFC           | push 0xfc8e41bd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 bd 41 8e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction020
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction020"

    /*
        68FD4146FC           | push 0xfc4641fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 46 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction021
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction021"

    /*
        68FD414EFC           | push 0xfc4e41fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 4e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction022
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction022"

    /*
        68FD4156FC           | push 0xfc5641fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 56 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction023
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction023"

    /*
        68FD415EFC           | push 0xfc5e41fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 5e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction024
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction024"

    /*
        68FD4166FC           | push 0xfc6641fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 66 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction025
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction025"

    /*
        68FD416EFC           | push 0xfc6e41fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 6e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction026
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction026"

    /*
        68FD4176FC           | push 0xfc7641fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 76 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction027
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction027"

    /*
        68FD417EFC           | push 0xfc7e41fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 7e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction028
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction028"

    /*
        68FD4186FC           | push 0xfc8641fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 86 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction029
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction029"

    /*
        68FD418EFC           | push 0xfc8e41fd
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fd 41 8e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction030
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction030"

    /*
        683D4246FC           | push 0xfc46423d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 42 46 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction031
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction031"

    /*
        683D424EFC           | push 0xfc4e423d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 42 4e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction032
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction032"

    /*
        683D4256FC           | push 0xfc56423d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 42 56 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction033
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction033"

    /*
        683D425EFC           | push 0xfc5e423d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 42 5e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction034
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction034"

    /*
        683D4266FC           | push 0xfc66423d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 42 66 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction035
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction035"

    /*
        683D426EFC           | push 0xfc6e423d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 42 6e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction036
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction036"

    /*
        683D4276FC           | push 0xfc76423d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 42 76 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction040
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction040"

    /*
        687D4246FC           | push 0xfc46427d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 42 46 fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_SystemFunction041
{
    meta:
        desc = "Metasploit::API::advapi32::SystemFunction041"

    /*
        687D424EFC           | push 0xfc4e427d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 7d 42 4e fc ff d5 }

    condition:
        any of them
}

    
rule advapi32_TraceEvent
{
    meta:
        desc = "Metasploit::API::advapi32::TraceEvent"

    /*
        684915D092           | push 0x92d01549
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 49 15 d0 92 ff d5 }

    condition:
        any of them
}

    
rule advapi32_TraceEventInstance
{
    meta:
        desc = "Metasploit::API::advapi32::TraceEventInstance"

    /*
        6804733B25           | push 0x253b7304
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 73 3b 25 ff d5 }

    condition:
        any of them
}

    
rule advapi32_TraceMessage
{
    meta:
        desc = "Metasploit::API::advapi32::TraceMessage"

    /*
        68236E3BCF           | push 0xcf3b6e23
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 23 6e 3b cf ff d5 }

    condition:
        any of them
}

    
rule advapi32_TraceMessageVa
{
    meta:
        desc = "Metasploit::API::advapi32::TraceMessageVa"

    /*
        686C4F3510           | push 0x10354f6c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6c 4f 35 10 ff d5 }

    condition:
        any of them
}

    
rule advapi32_TraceQueryInformation
{
    meta:
        desc = "Metasploit::API::advapi32::TraceQueryInformation"

    /*
        684CF88E3B           | push 0x3b8ef84c
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 4c f8 8e 3b ff d5 }

    condition:
        any of them
}

    
rule advapi32_TraceSetInformation
{
    meta:
        desc = "Metasploit::API::advapi32::TraceSetInformation"

    /*
        68D395B618           | push 0x18b695d3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d3 95 b6 18 ff d5 }

    condition:
        any of them
}

    
rule advapi32_TreeResetNamedSecurityInfoA
{
    meta:
        desc = "Metasploit::API::advapi32::TreeResetNamedSecurityInfoA"

    /*
        685E80533C           | push 0x3c53805e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 80 53 3c ff d5 }

    condition:
        any of them
}

    
rule advapi32_TreeResetNamedSecurityInfoW
{
    meta:
        desc = "Metasploit::API::advapi32::TreeResetNamedSecurityInfoW"

    /*
        685E80033D           | push 0x3d03805e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 5e 80 03 3d ff d5 }

    condition:
        any of them
}

    
rule advapi32_TreeSetNamedSecurityInfoA
{
    meta:
        desc = "Metasploit::API::advapi32::TreeSetNamedSecurityInfoA"

    /*
        68B50C87B6           | push 0xb6870cb5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 0c 87 b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_TreeSetNamedSecurityInfoW
{
    meta:
        desc = "Metasploit::API::advapi32::TreeSetNamedSecurityInfoW"

    /*
        68B50C37B7           | push 0xb7370cb5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b5 0c 37 b7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_TrusteeAccessToObjectA
{
    meta:
        desc = "Metasploit::API::advapi32::TrusteeAccessToObjectA"

    /*
        683B91309B           | push 0x9b30913b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 91 30 9b ff d5 }

    condition:
        any of them
}

    
rule advapi32_TrusteeAccessToObjectW
{
    meta:
        desc = "Metasploit::API::advapi32::TrusteeAccessToObjectW"

    /*
        683B91E09B           | push 0x9be0913b
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3b 91 e0 9b ff d5 }

    condition:
        any of them
}

    
rule advapi32_UninstallApplication
{
    meta:
        desc = "Metasploit::API::advapi32::UninstallApplication"

    /*
        68A250CFC6           | push 0xc6cf50a2
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 a2 50 cf c6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_UnlockServiceDatabase
{
    meta:
        desc = "Metasploit::API::advapi32::UnlockServiceDatabase"

    /*
        68E464BCC3           | push 0xc3bc64e4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 e4 64 bc c3 ff d5 }

    condition:
        any of them
}

    
rule advapi32_UnregisterIdleTask
{
    meta:
        desc = "Metasploit::API::advapi32::UnregisterIdleTask"

    /*
        686A9DBD9D           | push 0x9dbd9d6a
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 6a 9d bd 9d ff d5 }

    condition:
        any of them
}

    
rule advapi32_UnregisterTraceGuids
{
    meta:
        desc = "Metasploit::API::advapi32::UnregisterTraceGuids"

    /*
        6855B49562           | push 0x6295b455
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 55 b4 95 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_UpdateTraceA
{
    meta:
        desc = "Metasploit::API::advapi32::UpdateTraceA"

    /*
        68B440D220           | push 0x20d240b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 40 d2 20 ff d5 }

    condition:
        any of them
}

    
rule advapi32_UpdateTraceW
{
    meta:
        desc = "Metasploit::API::advapi32::UpdateTraceW"

    /*
        68B4408221           | push 0x218240b4
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b4 40 82 21 ff d5 }

    condition:
        any of them
}

    
rule advapi32_UsePinForEncryptedFilesA
{
    meta:
        desc = "Metasploit::API::advapi32::UsePinForEncryptedFilesA"

    /*
        68FE7BAA17           | push 0x17aa7bfe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 7b aa 17 ff d5 }

    condition:
        any of them
}

    
rule advapi32_UsePinForEncryptedFilesW
{
    meta:
        desc = "Metasploit::API::advapi32::UsePinForEncryptedFilesW"

    /*
        68FE7B5A18           | push 0x185a7bfe
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 fe 7b 5a 18 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WaitServiceState
{
    meta:
        desc = "Metasploit::API::advapi32::WaitServiceState"

    /*
        6814C07A6D           | push 0x6d7ac014
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 14 c0 7a 6d ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiCloseBlock
{
    meta:
        desc = "Metasploit::API::advapi32::WmiCloseBlock"

    /*
        68544BD920           | push 0x20d94b54
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 54 4b d9 20 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiDevInstToInstanceNameA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiDevInstToInstanceNameA"

    /*
        68B381E514           | push 0x14e581b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 81 e5 14 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiDevInstToInstanceNameW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiDevInstToInstanceNameW"

    /*
        68B3819515           | push 0x159581b3
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 b3 81 95 15 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiEnumerateGuids
{
    meta:
        desc = "Metasploit::API::advapi32::WmiEnumerateGuids"

    /*
        6804231033           | push 0x33102304
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 04 23 10 33 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiExecuteMethodA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiExecuteMethodA"

    /*
        683E5D6BC6           | push 0xc66b5d3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 5d 6b c6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiExecuteMethodW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiExecuteMethodW"

    /*
        683E5D1BC7           | push 0xc71b5d3e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3e 5d 1b c7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiFileHandleToInstanceNameA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiFileHandleToInstanceNameA"

    /*
        68D7883240           | push 0x403288d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 88 32 40 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiFileHandleToInstanceNameW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiFileHandleToInstanceNameW"

    /*
        68D788E240           | push 0x40e288d7
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d7 88 e2 40 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiFreeBuffer
{
    meta:
        desc = "Metasploit::API::advapi32::WmiFreeBuffer"

    /*
        682E1A8544           | push 0x44851a2e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 2e 1a 85 44 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiMofEnumerateResourcesA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiMofEnumerateResourcesA"

    /*
        6851CB07B6           | push 0xb607cb51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 cb 07 b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiMofEnumerateResourcesW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiMofEnumerateResourcesW"

    /*
        6851CBB7B6           | push 0xb6b7cb51
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 51 cb b7 b6 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiNotificationRegistrationA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiNotificationRegistrationA"

    /*
        68CB88DEAE           | push 0xaede88cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 88 de ae ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiNotificationRegistrationW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiNotificationRegistrationW"

    /*
        68CB888EAF           | push 0xaf8e88cb
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 cb 88 8e af ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiOpenBlock
{
    meta:
        desc = "Metasploit::API::advapi32::WmiOpenBlock"

    /*
        683D608476           | push 0x7684603d
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 3d 60 84 76 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQueryAllDataA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQueryAllDataA"

    /*
        688EA6F558           | push 0x58f5a68e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e a6 f5 58 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQueryAllDataMultipleA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQueryAllDataMultipleA"

    /*
        68D0E8E610           | push 0x10e6e8d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 e8 e6 10 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQueryAllDataMultipleW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQueryAllDataMultipleW"

    /*
        68D0E89611           | push 0x1196e8d0
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 d0 e8 96 11 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQueryAllDataW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQueryAllDataW"

    /*
        688EA6A559           | push 0x59a5a68e
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 8e a6 a5 59 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQueryGuidInformation
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQueryGuidInformation"

    /*
        6810E1A172           | push 0x72a1e110
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 10 e1 a1 72 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQuerySingleInstanceA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQuerySingleInstanceA"

    /*
        68DF661AA7           | push 0xa71a66df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 66 1a a7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQuerySingleInstanceMultipleA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQuerySingleInstanceMultipleA"

    /*
        68900D3562           | push 0x62350d90
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 0d 35 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQuerySingleInstanceMultipleW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQuerySingleInstanceMultipleW"

    /*
        68900DE562           | push 0x62e50d90
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 90 0d e5 62 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiQuerySingleInstanceW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiQuerySingleInstanceW"

    /*
        68DF66CAA7           | push 0xa7ca66df
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 df 66 ca a7 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiReceiveNotificationsA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiReceiveNotificationsA"

    /*
        689FBF4675           | push 0x7546bf9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f bf 46 75 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiReceiveNotificationsW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiReceiveNotificationsW"

    /*
        689FBFF675           | push 0x75f6bf9f
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 9f bf f6 75 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiSetSingleInstanceA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiSetSingleInstanceA"

    /*
        68C54CAC57           | push 0x57ac4cc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 4c ac 57 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiSetSingleInstanceW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiSetSingleInstanceW"

    /*
        68C54C5C58           | push 0x585c4cc5
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 c5 4c 5c 58 ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiSetSingleItemA
{
    meta:
        desc = "Metasploit::API::advapi32::WmiSetSingleItemA"

    /*
        68362CCC2A           | push 0x2acc2c36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 2c cc 2a ff d5 }

    condition:
        any of them
}

    
rule advapi32_WmiSetSingleItemW
{
    meta:
        desc = "Metasploit::API::advapi32::WmiSetSingleItemW"

    /*
        68362C7C2B           | push 0x2b7c2c36
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 36 2c 7c 2b ff d5 }

    condition:
        any of them
}

    
rule advapi32_WriteEncryptedFileRaw
{
    meta:
        desc = "Metasploit::API::advapi32::WriteEncryptedFileRaw"

    /*
        68527F4927           | push 0x27497f52
        FFD5                 | call ebp
    */

    strings:
        $a   = { 68 52 7f 49 27 ff d5 }

    condition:
        any of them
}

    