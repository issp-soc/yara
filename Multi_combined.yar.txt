rule Multi_Trojan_Coreimpact_37703dc3 {
    meta:
        author = "Elastic Security"
        id = "37703dc3-9485-4026-a8b7-82e753993757"
        fingerprint = "5a4d7af7d0fecc05f87ba51f976d78e77622f8afb1eafc175444f45839490109"
        creation_date = "2022-08-10"
        last_modified = "2022-09-29"
        threat_name = "Multi.Trojan.Coreimpact"
        reference_sample = "2d954908da9f63cd3942c0df2e8bb5fe861ac5a336ddef2bd0a977cebe030ad7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str1 = "Uh, oh, exit() failed" fullword
        $str2 = "agent_recv" fullword
        $str3 = "needroot" fullword
        $str4 = "time is running backwards, corrected" fullword
        $str5 = "junk pointer, too low to make sense" fullword
    condition:
        3 of them
}

rule Multi_Trojan_EmpirGo_38a23b2c {
    meta:
        author = "Elastic Security"
        id = "38a23b2c-574b-40a4-9cc7-b25e64ca83fa"
        fingerprint = "856d1a8ac1c5d117656a1ad1f47cba379fa1612252d6e3900fed8103474db8a3"
        creation_date = "2025-04-23"
        last_modified = "2025-05-27"
        threat_name = "Multi.Trojan.EmpirGo"
        reference_sample = "c233aa4d7a672f08f6375f68e1f153d11e8e73df5adf72325a2e1a272f0428fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "EmpirGo/agent.(*MainAgent)."
        $b1 = "MissedCheckins"
        $b2 = "ReadDataDirBaseRels"
        $b3 = "getRandomSleepTime"
    condition:
        $a1 or all of ($b*)
}


rule Multi_Trojan_FinalDraft_81975d51 {
    meta:
        author = "Elastic Security"
        id = "81975d51-96e9-4a49-97ee-56e2c60e9702"
        fingerprint = "a2d5e2f472499ad6c5ff052eded73fa182bb20cecb9c3921f37bd779a2a77c9b"
        creation_date = "2024-12-03"
        last_modified = "2025-02-04"
        threat_name = "Multi.Trojan.FinalDraft"
        reference_sample = "fa2a6dbc83fe55df848dfcaaf3163f8aaefe0c9727b3ead1da6b9fa78b598f2b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "[-] socket() failed!"
        $a2 = "MailFolders/drafts/messages?$filter=Subject"
        $a3 = "{\"subject\":\"p_%llu\",\"body\":"
        $a4 = "COutLookTransChannel"
        $a5 = "CTransChannel"
        $a6 = "Chrome/40.0.2214.85 Safari/537.36"
    condition:
        3 of them
}

rule Multi_Trojan_FinalDraft_69deb8cd {
    meta:
        author = "Elastic Security"
        id = "69deb8cd-050b-4b92-86c2-ea54f836ce72"
        fingerprint = "3e48740092918896132e801ae4d850ef804f9dd6c8db96b80065224566c17819"
        creation_date = "2024-12-03"
        last_modified = "2025-02-04"
        threat_name = "Multi.Trojan.FinalDraft"
        reference_sample = "fa2a6dbc83fe55df848dfcaaf3163f8aaefe0c9727b3ead1da6b9fa78b598f2b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { 33 FF C7 44 24 20 3A 00 77 00 4C 8B F1 C7 44 24 24 74 00 66 00 48 83 C8 FF C7 44 24 28 62 00 62 00 C7 44 24 2C 71 00 00 00 48 8D 4C 24 20 }
        $a2 = { 48 81 EC B0 00 00 00 48 8B 05 00 5B 05 00 48 33 C4 48 89 84 24 A0 00 00 00 0F 57 C0 0F 11 44 24 48 4C 8B C2 48 8D 54 24 48 E8 00 0B 00 00 90 48 83 7C 24 50 00 0F 84 31 01 00 00 48 8B 7C 24 48 }
        $a3 = { 48 8D 7C 24 48 C6 43 40 00 48 C7 43 48 00 00 00 00 48 C7 43 50 00 00 00 00 48 89 43 68 48 8B ?? ?? ?? ?? 00 48 C7 43 58 00 00 00 00 C7 43 60 00 00 00 00 48 C7 43 70 00 00 00 00 C6 43 78 00 48 8D B0 FD 00 00 00 }
        $a4 = { 48 83 EC 58 B9 0D 00 00 00 BE 1E 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 44 24 48 31 C0 48 8D 7C 24 14 48 C7 44 24 08 00 00 00 00 F3 AB 48 8D 7C 24 14 E8 }
    condition:
        any of them
}

rule Multi_Trojan_Goffloader_d1f4201e {
    meta:
        author = "Elastic Security"
        id = "d1f4201e-74ce-4f72-a661-47c2fb993623"
        fingerprint = "f8457fca4d8307639839199ef5fd01c8a5ad425dd341b3a5f8e5a6a9fad16329"
        creation_date = "2025-04-23"
        last_modified = "2025-05-27"
        threat_name = "Multi.Trojan.Goffloader"
        reference_sample = "c233aa4d7a672f08f6375f68e1f153d11e8e73df5adf72325a2e1a272f0428fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "praetorian-inc/goffloader/src/memory.ReadUIntFromPtr"
    condition:
        all of them
}

rule Multi_Trojan_Gosar_31dba745 {
    meta:
        author = "Elastic Security"
        id = "31dba745-8079-4161-9299-84a4c33b95c8"
        fingerprint = "87e44b3050eb33edb24ad8aa8923ed91124f2e92e4eae42e94decefc49ccbf4c"
        creation_date = "2024-11-05"
        last_modified = "2024-12-04"
        threat_name = "Multi.Trojan.Gosar"
        reference_sample = "4caf4b280e61745ce53f96f48a74dea3b69df299c3b9de78ba4731b83c76c334"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "GetRecoverAccounts"
        $a2 = "GetIsFirstScreen"
        $a3 = "DoWebcamStop"
        $a4 = "DoAskElevate"
        $a5 = "vibrant/proto/pb"
        $a6 = "vibrant/network/sender"
        $a7 = "vibrant/pkg/helpers"
    condition:
        3 of them
}

rule Multi_Trojan_Merlin_32643f4c {
    meta:
        author = "Elastic Security"
        id = "32643f4c-ee47-4ed2-9807-7b85d3f4e095"
        fingerprint = "bce277ef43c67be52b67c4495652e99d4707975c79cb30b54283db56545278ae"
        creation_date = "2024-03-01"
        last_modified = "2024-05-23"
        threat_name = "Multi.Trojan.Merlin"
        reference_sample = "84b988c4656677bc021e23df2a81258212d9ceba13be204867ac1d9d706404e2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "json:\"killdate,omitempty\""
        $a2 = "json:\"maxretry,omitempty\""
        $a3 = "json:\"waittime,omitempty\""
        $a4 = "json:\"payload,omitempty\""
        $a5 = "json:\"skew,omitempty\""
        $a6 = "json:\"command\""
        $a7 = "json:\"pid,omitempty\""
        $b1 = "/merlin-agent/commands"
        $b2 = "/merlin/pkg/jobs"
        $b3 = "github.com/Ne0nd0g/merlin"
    condition:
        all of ($a*) or all of ($b*)
}

rule Multi_Trojan_Mythic_4beb7e17 {
    meta:
        author = "Elastic Security"
        id = "4beb7e17-34c2-4f5c-a668-e54512175f53"
        fingerprint = "0b25c5b069cec31e9af31b7822ea19b813fe1882dfaa584661ff14414ae41df5"
        creation_date = "2023-08-01"
        last_modified = "2023-09-20"
        threat_name = "Multi.Trojan.Mythic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "task_id"
        $a2 = "post_response"
        $a3 = "c2_profile"
        $a4 = "get_tasking"
        $a5 = "tasking_size"
        $a6 = "get_delegate_tasks"
        $a7 = "total_chunks"
        $a8 = "is_screenshot"
        $a9 = "file_browser"
        $a10 = "is_file"
        $a11 = "access_time"
    condition:
        7 of them
}

rule Multi_Trojan_Mythic_e0ea7ef9 {
    meta:
        author = "Elastic Security"
        id = "e0ea7ef9-452c-404c-95ba-4057ec40ef4b"
        fingerprint = "57afe989db139314a7505a2ccc01367cdd13132318dc19b57d4b79f65bfe982c"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "e091d63c8e8b0a32a3d25cffdf02419fdbec714f31e4061bafd80b1971831c5f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $profile1 = "src/profiles/mod.rs"
        $profile2 = "src/profiles/http.rs"
        $rs_ssh1 = "src/ssh/spawn.rs"
        $rs_ssh2 = "src/ssh/agent.rs"
        $rs_ssh3 = "src/ssh/cat.rs"
        $rs_ssh4 = "src/ssh/upload.rs"
        $rs_ssh5 = "src/ssh/exec.rs"
        $rs_ssh6 = "src/ssh/download.rs"
        $rs_ssh7 = "src/ssh/rm.rs"
        $rs_ssh8 = "src/ssh/ls.rs"
        $rs_misc1 = "src/utils/linux.rs"
        $rs_misc2 = "src/portscan.rs"
        $rs_misc3 = "src/payloadvars.rs"
        $rs_misc4 = "src/getprivs.rs"
    condition:
        all of ($profile*) and 8 of ($rs*)
}

rule Multi_Trojan_Mythic_528324b4 {
    meta:
        author = "Elastic Security"
        id = "528324b4-822d-4e48-b4ab-f5b234348773"
        fingerprint = "5188aa792c02acf7a6346f395389390ae187cb08083bfca27283a4f4dd4d7206"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "2cd883eab722a5eacbca7fa82e0eebb5f6c30cffa955abcb1ab8cf169af97202"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $import1 = "Autofac"
        $import2 = "Obfuscar"
        $import3 = "Agent.Profiles.Http"
        $import4 = "Agent.Managers.Linux"
        $import5 = "Agent.Managers.Reflection"
        $athena1 = "Athena.Commands.dll"
        $athena2 = "Athena.Handler.Linux.dll"
        $athena3 = "Athena.dll"
        $athena4 = "Athena.Profiles.HTTP.dll"
    condition:
        (2 of ($import*)) or (2 of ($athena*))
}

rule Multi_Trojan_Sliver_42298c4a {
    meta:
        author = "Elastic Security"
        id = "42298c4a-fcea-4c5a-b213-32db00e4eb5a"
        fingerprint = "0734b090ea10abedef4d9ed48d45c834dd5cf8e424886a5be98e484f69c5e12a"
        creation_date = "2021-10-20"
        last_modified = "2022-01-14"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "3b45aae401ac64c055982b5f3782a3c4c892bdb9f9a5531657d50c27497c8007"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = ").RequestResend"
        $a2 = ").GetPrivInfo"
        $a3 = ").GetReconnectIntervalSeconds"
        $a4 = ").GetPivotID"
        $a5 = "name=PrivInfo"
        $a6 = "name=ReconnectIntervalSeconds"
        $a7 = "name=PivotID"
    condition:
        2 of them
}

rule Multi_Trojan_Sliver_3bde542d {
    meta:
        author = "Elastic Security"
        id = "3bde542d-df52-4f05-84ff-de67e90592a9"
        fingerprint = "e52e39644274e3077769da4d04488963c85a0b691dc9973ad12d51eb34ba388b"
        creation_date = "2022-08-31"
        last_modified = "2022-09-29"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "05461e1c2a2e581a7c30e14d04bd3d09670e281f9f7c60f4169e9614d22ce1b3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb" ascii fullword
        $b1 = "InvokeSpawnDllReq" ascii fullword
        $b2 = "NetstatReq" ascii fullword
        $b3 = "HTTPSessionInit" ascii fullword
        $b4 = "ScreenshotReq" ascii fullword
        $b5 = "RegistryReadReq" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Multi_Trojan_Sliver_3d6b7cd3 {
    meta:
        author = "Elastic Security"
        id = "3d6b7cd3-f702-470c-819c-8750ec040083"
        fingerprint = "46d5388bd1fe767a4852c9e35420985d5011368dac6545fd57fbb256de9a94e9"
        creation_date = "2022-12-01"
        last_modified = "2023-09-20"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "9846124cfd124eed466465d187eeacb4d405c558dd84ba8e575d8a7b3290403e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $session_start_x86_1 = { 89 4C 24 ?? 89 44 24 ?? 8D 4C 24 ?? 89 4C 24 ?? C6 44 24 ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? }
        $session_start_x86_2 = { FF 05 ?? ?? ?? ?? 8D 05 ?? ?? ?? ?? 89 04 24 C7 44 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 85 C9 74 ?? B8 ?? ?? ?? ?? }
        $session_start_x86_3 = { E8 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 74 ?? FF 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 04 24 39 05 ?? ?? ?? ?? 7E ?? C6 44 24 ?? ?? 8B 54 24 ?? 8B 02 FF D0 83 C4 ?? }
        $session_start_x64_1 = { 44 0F 11 7C 24 ?? 48 8D 0D ?? ?? ?? ?? 48 89 4C 24 ?? 48 89 44 24 ?? 48 8D 4C 24 ?? 48 89 4C 24 ?? C6 44 24 ?? ?? 0F 1F 00 E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? EB ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $session_start_x64_2 = { E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 FF 05 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 DB B9 ?? ?? ?? ?? 48 0F 45 C1 48 39 05 ?? ?? ?? ?? 7E ?? C6 44 24 ?? ?? 48 8B 54 24 ?? 48 8B 02 FF D0 }
        $session_start_x64_3 = { 48 89 6C 24 ?? 48 8D 6C 24 ?? 49 C7 C5 ?? ?? ?? ?? 4C 89 6C 24 ?? C6 44 24 ?? ?? 48 8D 05 ?? ?? ?? ?? 31 DB E8 ?? ?? ?? ?? 44 0F 11 7C 24 ?? 48 8D 0D ?? ?? ?? ?? 48 89 4C 24 ?? 48 89 44 24 ?? 48 8D 4C 24 ?? 48 89 4C 24 ?? C6 44 24 ?? ?? 0F 1F 00 }
        $register_x64_1 = { 48 81 EC ?? ?? ?? ?? 48 89 AC 24 ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ?? 90 E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 89 5C 24 ?? 48 89 4C 24 ?? 0F 1F 44 00 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 85 C9 48 8B 4C 24 ?? BA ?? ?? ?? ?? 48 0F 45 CA 48 89 4C 24 ?? 48 8B 54 24 ?? BE ?? ?? ?? ?? 48 0F 45 D6 48 89 54 24 ?? }
        $register_x64_2 = { 48 8D 1D ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 84 24 ?? ?? ?? ?? }
        $register_x64_3 = { E8 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 89 5C 24 ?? 48 89 4C 24 ?? 66 90 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 85 C9 48 8B 8C 24 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 45 CA 48 8B 54 24 ?? BE ?? ?? ?? ?? 48 0F 45 D6 48 85 DB 74 ?? 48 8D BC 24 ?? ?? ?? ?? 48 8D 7F ?? 0F 1F 00 48 89 6C 24 ?? 48 8D 6C 24 ?? }
        $register_x64_4 = { 48 89 84 24 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 89 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 8C 24 ?? ?? ?? ?? 48 85 C9 48 8B 8C 24 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 45 CA 48 89 8C 24 ?? ?? ?? ?? 48 8B B4 24 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 0F 45 F7 48 89 B4 24 ?? ?? ?? ?? }
        $register_x64_5 = { 48 89 84 24 ?? ?? ?? ?? 48 89 5C 24 ?? 48 89 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 85 C9 48 8B 8C 24 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 45 CA 48 89 8C 24 ?? ?? ?? ?? 48 8B 54 24 ?? BE ?? ?? ?? ?? 48 0F 45 D6 48 89 54 24 ?? }
        $register_x64_6 = { E8 ?? ?? ?? ?? 48 8B 6D ?? 48 8B 94 24 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 8B 94 24 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 8B 94 24 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 8B 54 24 ?? 48 89 94 24 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 84 24 ?? ?? ?? ?? }
        $register_x64_7 = { E8 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 48 8B 4C 24 ?? 48 89 48 ?? 48 8B 4C 24 ?? 48 89 48 ?? 83 3D ?? ?? ?? ?? ?? 75 ?? }
        $register_x64_8 = { 48 8D 7F ?? 0F 1F 00 48 89 6C 24 ?? 48 8D 6C 24 ?? E8 ?? ?? ?? ?? 48 8B 6D ?? 4C 8D 15 ?? ?? ?? ?? 4C 89 94 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 4C 89 94 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 4C 89 94 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 84 24 ?? ?? ?? ?? }
        $register_x86_1 = { E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 0C 24 8B 54 24 ?? 85 C0 74 ?? 31 C9 31 D2 89 54 24 ?? 89 4C 24 ?? E8 ?? ?? ?? ?? 8B 04 24 8B 4C 24 ?? 85 C9 74 ?? 8D 7C 24 ?? }
        $register_x86_2 = { 8D 0D ?? ?? ?? ?? 89 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 44 24 ?? }
        $register_x86_3 = { C7 40 ?? ?? ?? ?? ?? 8D 0D ?? ?? ?? ?? 89 48 ?? 8B 4C 24 ?? 89 48 ?? 8B 4C 24 ?? 89 48 ?? 8B 0D ?? ?? ?? ?? 85 C9 75 ?? }
        $register_x86_4 = { E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 0C 24 8B 54 24 ?? 85 C0 74 ?? 31 C9 31 D2 89 54 24 ?? 89 ?? 24 }
        $register_x86_5 = { 8B 04 24 89 84 24 ?? ?? ?? ?? 8B 4C 24 ?? 89 4C 24 ?? E8 ?? ?? ?? ?? 8B 04 24 8B 4C 24 ?? 8B 54 24 ?? 85 D2 74 ?? 31 C0 31 C9 89 4C 24 ?? 89 84 24 ?? ?? ?? ?? 8D 15 ?? ?? ?? ?? 89 14 24 E8 ?? ?? ?? ?? }
    condition:
        1 of ($session_start_*) and 1 of ($register_*)
}

rule Multi_Trojan_SparkRat_9a21e541 {
    meta:
        author = "Elastic Security"
        id = "9a21e541-886c-4d7f-8602-832862121730"
        fingerprint = "2691da3a037b651d0f7f6d7be767c34845c3b9a642f4a2fb1c54f391f08089b6"
        creation_date = "2023-11-13"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.SparkRat"
        reference_sample = "23efecc03506a9428175546a4b7d40c8a943c252110e83dec132c6a5db8c4dd6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "Spark/client/service/file" ascii wide
        $a2 = "Spark/client/service/desktop" ascii wide
        $a3 = "Spark/utils.Encrypt" ascii wide
    condition:
        all of them
}

rule Multi_AttackSimulation_Blindspot_d93f54c5 {
    meta:
        author = "Elastic Security"
        id = "d93f54c5-6574-4999-a3c0-39ef688b28dc"
        fingerprint = "4ec38f841aa4dfe32b1f6b6cd2e361c7298839ef1e983061cb90827135f34a58"
        creation_date = "2022-05-23"
        last_modified = "2022-08-16"
        threat_name = "Multi.AttackSimulation.Blindspot"
        severity = 1
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "\\\\.\\pipe\\blindspot-%d."
    condition:
        all of them
}

rule Multi_Cryptominer_Xmrig_f9516741 {
    meta:
        author = "Elastic Security"
        id = "f9516741-aac1-4c67-ad63-3d222814864e"
        fingerprint = "14eef95b5a008e644c2fe2d600c1a883d018c1ab085f4496a3e2211329362d31"
        creation_date = "2025-02-21"
        last_modified = "2025-03-07"
        threat_name = "Multi.Cryptominer.Xmrig"
        reference_sample = "104f839b5da7bd77804ca5ec252d78dccb52800a2ef4fd1179db6deb764af42f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str_1 = "no valid configuration found, try https://xmrig.com/wizard"
        $str_2 = "xmrig-"
        $str_3 = "XMRig "
        $str_4 = "--donate-level=N"
        $str_5 = "--coin=COIN"
        $str_6 = "--algo=ALGO"
        $str_7 = "hwloc topology successfully exported to \"%s\"\n"
    condition:
        6 of them
}

rule Multi_EICAR_ac8f42d6 {
    meta:
        author = "Elastic Security"
        id = "ac8f42d6-52da-46ec-8db1-5a5f69222a38"
        fingerprint = "bb0e0bdf70ec65d98f652e2428e3567013d5413f2725a2905b372fd18da8b9dd"
        creation_date = "2021-01-21"
        last_modified = "2022-01-13"
        threat_name = "Multi.EICAR.Not-a-virus"
        severity = 1
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword
    condition:
        all of them
}

rule Multi_Generic_Threat_19854dc2 {
    meta:
        author = "Elastic Security"
        id = "19854dc2-a568-4f6c-bd47-bcae9976c66f"
        fingerprint = "64d3803490fa71f720678ca2989cc698ea9b1a398d02d6d671fa01e0ff42f8b5"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Multi.Generic.Threat"
        reference_sample = "be216fa9cbf0b64d769d1e8ecddcfc3319c7ca8e610e438dcdfefc491730d208"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { 26 2A 73 74 72 75 63 74 20 7B 20 45 6E 74 72 79 53 61 6C 74 20 5B 5D 75 69 6E 74 38 3B 20 4C 65 6E 20 69 6E 74 20 7D }
    condition:
        all of them
}

rule Multi_Hacktool_Gsocket_761d3a0f {
    meta:
        author = "Elastic Security"
        id = "761d3a0f-e2e8-4a8a-99f6-7356555a517d"
        fingerprint = "e4426c5faa5775bcfdfbe01c3d6a2b4042aa9bf942883b104c241d0734b272c9"
        creation_date = "2024-09-20"
        last_modified = "2024-11-04"
        threat_name = "Multi.Hacktool.Gsocket"
        reference_sample = "193efd61ae10f286d06390968537fa85e4df40995fd424d1afe426c089d172ab"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str1 = "gsocket: gs_funcs not found"
        $str2 = "/share/gsocket/gs_funcs"
        $str3 = "$GSOCKET_ARGS"
        $str4 = "GSOCKET_SECRET"
        $str5 = "GS_HIJACK_PORTS"
        $str6 = "sftp -D gs-netcat"
        $str7 = "GS_NETCAT_BIN"
        $str8 = "GSOCKET_NO_GREETINGS"
        $str9 = "GS-NETCAT(1)"
        $str10 = "GSOCKET_SOCKS_IP"
        $str11 = "GSOCKET_SOCKS_PORT"
        $str12 = "gsocket(1)"
        $str13 = "gs-sftp(1)"
        $str14 = "gs-mount(1)"
    condition:
        3 of them
}

rule Multi_Hacktool_Nps_c6eb4a27 {
    meta:
        author = "Elastic Security"
        id = "c6eb4a27-c481-41b4-914d-a27d10672d30"
        fingerprint = "1386e4cef0f347b38a4614311d585b0b83cb9526b19215392aee893e594950de"
        creation_date = "2024-01-24"
        last_modified = "2024-01-29"
        threat_name = "Multi.Hacktool.Nps"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        reference_sample = "4714e8ad9c625070ca0a151ffc98d87d8e5da7c8ef42037ca5f43baede6cfac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str_info0 = "Reconnecting..."
        $str_info1 = "Loading configuration file %s successfully"
        $str_info2 = "successful start-up of local socks5 monitoring, port"
        $str_info3 = "successful start-up of local tcp monitoring, port"
        $str_info4 = "start local file system, local path %s, strip prefix %s ,remote port %"
        $str_info5 = "start local file system, local path %s, strip prefix %s ,remote port %s"
    condition:
        all of them
}

rule Multi_Hacktool_Nps_f76f257d {
    meta:
        author = "Elastic Security"
        id = "f76f257d-0286-4b4d-9f73-2add23cfd07e"
        fingerprint = "4aaa270129ce0c8fdd40aae2ebc4f6595aec91cbfea9e0188542e9c3f38eedee"
        creation_date = "2024-01-24"
        last_modified = "2024-01-29"
        threat_name = "Multi.Hacktool.Nps"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        reference_sample = "80721b20a8667536a33fca50236f5c8e0c0d07aa7805b980e40818ab92cd9f4a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $string_decrypt_add = { 0F B6 BC 34 ?? ?? ?? ?? 44 0F B6 84 34 ?? ?? ?? ?? 44 01 C7 40 88 BC 34 ?? ?? ?? ?? 48 FF C6 }
        $string_decrypt_xor = { 0F B6 54 ?? ?? 0F B6 74 ?? ?? 31 D6 40 88 74 ?? ?? 48 FF C0 }
        $string_decrypt_sub = { 0F B6 94 04 ?? ?? ?? ?? 0F B6 B4 04 ?? ?? ?? ?? 29 D6 40 88 B4 04 ?? ?? ?? ?? 48 FF C0 }
        $NewJsonDb_str0 = { 63 6C 69 65 6E 74 73 2E 6A 73 6F 6E }
        $NewJsonDb_str1 = { 68 6F 73 74 73 2E 6A 73 6F 6E }
    condition:
        all of them
}

rule Multi_Hacktool_Rakshasa_d5d3ef21 {
    meta:
        author = "Elastic Security"
        id = "d5d3ef21-e004-4cb4-8f9f-541e831c8e08"
        fingerprint = "bd25f85a419679d2278e2e3951531950296785ac888bc69b513bab0a9936eacf"
        creation_date = "2024-01-24"
        last_modified = "2024-01-29"
        threat_name = "Multi.Hacktool.Rakshasa"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        reference_sample = "ccfa30a40445d5237aaee1e015ecfcd9bdbe7665a6dc2736b28e5ebf07ec4597"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { 35 B8 00 00 00 48 89 74 24 38 48 89 5C 24 40 48 89 4C 24 48 48 89 54 }
        $a2 = "rakshasa/server.init.4.func2" ascii fullword
        $a3 = "type..eq.rakshasa/server.Conn" ascii fullword
        $a4 = "rakshasa_lite/aes.Str2bytes" ascii fullword
        $a5 = "rakshasa_lite/server.doShellcode" ascii fullword
    condition:
        2 of them
}

rule Multi_Hacktool_Stowaway_89f1d452 {
    meta:
        author = "Elastic Security"
        id = "89f1d452-f40b-47da-ba75-10c90d67c13b"
        fingerprint = "313e22009ad758c0dd0977c274eb165511591e3d99a8e2dd4be00622668981da"
        creation_date = "2024-06-28"
        last_modified = "2024-07-26"
        threat_name = "Multi.Hacktool.Stowaway"
        reference_sample = "c073d3be469c8eea0f007bb37c722bad30e06dc994d3a59773838ed8be154c95"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "Stowaway/share.ActivePreAuth" ascii fullword
        $a2 = "Stowaway/agent/handler" ascii fullword
        $a3 = "Origin: http://stowaway:22" ascii fullword
        $a4 = "Stowaway/admin.NewAdmin" ascii fullword
        $a5 = "Stowaway/global/global.go" ascii fullword
        $a6 = "Stowaway/crypto.AESDecrypt" ascii fullword
        $a7 = "Stowaway/utils.CheckIfIP4" ascii fullword
        $a8 = "Exit Stowaway"
        $a9 = "Stowaway/protocol.ConstructMessage" ascii fullword
    condition:
        3 of them
}

rule Multi_Hacktool_SuperShell_f7486598 {
    meta:
        author = "Elastic Security"
        id = "f7486598-0b60-4b40-932e-6abfba279b76"
        fingerprint = "116f89157bfe0d80ddcb8f55984169fa611a51a3d562ef719b13ef2ddd50c432"
        creation_date = "2024-09-12"
        last_modified = "2024-09-30"
        threat_name = "Multi.Hacktool.SuperShell"
        reference_sample = "18556a794f5d47f93d375e257fa94b9fb1088f3021cf79cc955eb4c1813a95da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "NHAS/reverse_ssh/internal/terminal"
        $b1 = "foreground|fingerprint|proxy|process_name"
        $b2 = "Failed to kill shell"
        $b3 = "Missing listening address"
    condition:
        $a and 1 of ($b*)
}

rule Multi_Ransomware_Akira_21842eb3 {
    meta:
        author = "Elastic Security"
        id = "21842eb3-9ccc-4dec-9536-37791ef79714"
        fingerprint = "62f1a985bb718fa27c56d2f23d4f36a5b90b35626f0ef5def83441d27122a503"
        creation_date = "2024-11-21"
        last_modified = "2024-11-22"
        threat_name = "Multi.Ransomware.Akira"
        reference_sample = "3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "Well, for now let's keep all the tears and resentment to ourselves"
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_aaf312c3 {
    meta:
        author = "Elastic Security"
        id = "aaf312c3-47b4-4dab-b7fc-8a2ac9883772"
        fingerprint = "577c7f24a7ecf89a542e9a63a1744a129c96c32e8dccfbf779dd9fc6c0194930"
        creation_date = "2022-02-02"
        last_modified = "2023-09-20"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $chacha20_enc = { EF D9 F3 0F 7F 14 3B F3 0F 7F 5C 3B 10 83 C7 20 39 F8 75 D0 8B }
        $crc32_imp = { F3 0F 6F 02 66 0F 6F D1 66 0F 3A 44 CD 11 83 C0 F0 83 C2 10 66 0F 3A 44 D4 00 83 F8 0F 66 0F EF C8 66 0F EF CA }
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_00e525d7 {
    meta:
        author = "Elastic Security"
        id = "00e525d7-a8a6-475f-89ad-607c452aea1e"
        fingerprint = "631e30b8b51a5c0a0e91e8c09968663192569005b8bffff9f0474749788e9d57"
        creation_date = "2022-02-02"
        last_modified = "2022-08-16"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "ata\",\"boot\",\"config.msi\",\"google\",\"perflogs\",\"appdata\",\"windows.old\"],\"exclude_file_names\":[\"desktop.ini\",\"aut"
        $a2 = "locker::core::windows::processvssadmin.exe delete shadows /all /quietshadow_copy::remove_all=" ascii fullword
        $a3 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." ascii fullword
        $a4 = "--bypass-p-p--bypass-path-path --no-prop-servers \\\\" ascii fullword
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_c4b043e6 {
    meta:
        author = "Elastic Security"
        id = "c4b043e6-ff5f-4492-94e3-fd688d690738"
        fingerprint = "3e89858e90632ad5f4831427bd630252113b735c51f7a1aa1eab8ba6e4c16f18"
        creation_date = "2022-09-12"
        last_modified = "2022-09-29"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = { 28 4C 8B 60 08 4C 8B 68 10 0F 10 40 28 0F 29 44 24 10 0F 10 }
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_70171625 {
    meta:
        author = "Elastic Security"
        id = "70171625-c29b-47c1-b572-2e6dc846a907"
        fingerprint = "f3f70f92fe9c044f4565fca519cb04a3a54536985c2614077ef92c3193fff9c1"
        creation_date = "2023-01-05"
        last_modified = "2023-09-20"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str0 = "}RECOVER-${EXTENSION}-FILES.txt"
        $str1 = "?access-key=${ACCESS_KEY}"
        $str2 = "${NOTE_FILE_NAME}"
        $str3 = "enable_network_discovery"
        $str4 = "enable_set_wallpaper"
        $str5 = "enable_esxi_vm_kill"
        $str6 = "strict_include_paths"
        $str7 = "exclude_file_path_wildcard"
        $str8 = "${ACCESS_KEY}${EXTENSION}"
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_e066d802 {
    meta:
        author = "Elastic Security"
        id = "e066d802-b803-4e35-9b53-ae1823662483"
        fingerprint = "05037af3395b682d1831443757376064c873815ac4b6d1c09116715570f51f5d"
        creation_date = "2023-07-27"
        last_modified = "2023-09-20"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "00360830bf5886288f23784b8df82804bf6f22258e410740db481df8a7701525"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "esxcli vm process kill --type=force --world-id=Killing"
        $a2 = "vim-cmd vmsvc/snapshot.removeall $i"
        $a3 = "File already has encrypted extension"
    condition:
        2 of them
}

rule Multi_Ransomware_BlackCat_0ffb0a37 {
    meta:
        author = "Elastic Security"
        id = "0ffb0a37-e4c3-45be-bd4d-7033e88635aa"
        fingerprint = "319b956ddd57bea22cbee7e521649969c5b1f42ee4af49ad6f25847fb8ee9559"
        creation_date = "2023-07-29"
        last_modified = "2024-06-12"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "57136b118a0d6d3c71e522ea53e3305dae58b51f06c29cd01c0c28fa0fa34287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { C8 C8 00 00 00 89 20 00 00 45 01 00 00 32 22 08 0A 20 64 85 }
        $a2 = { 67 69 74 68 75 62 2E 63 6F 6D 2D 31 65 63 63 36 32 39 39 64 62 39 65 63 38 32 33 2F 73 69 6D 70 6C 65 6C 6F 67 2D }
    condition:
        all of them
}

rule Multi_Ransomware_Luna_8614d3d7 {
    meta:
        author = "Elastic Security"
        id = "8614d3d7-7fd2-4cf9-aa97-48a8d9333f38"
        fingerprint = "90c97ecfce451e1373af0d7538cf12991cc844d05c99ee18570e176143ccd899"
        creation_date = "2022-08-02"
        last_modified = "2022-08-16"
        threat_name = "Multi.Ransomware.Luna"
        reference = "https://www.elastic.co/security-labs/luna-ransomware-attack-pattern"
        reference_sample = "1cbbf108f44c8f4babde546d26425ca5340dccf878d306b90eb0fbec2f83ab51"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str_extensions = ".ini.exe.dll.lnk"
        $str_ransomnote_bs64 = "W1dIQVQgSEFQUEVORUQ/XQ0KDQpBbGwgeW91ciBmaWxlcyB3ZXJlIG1vdmVkIHRvIHNlY3VyZSBzdG9yYWdlLg0KTm9ib"
        $str_path = "/home/username/"
        $str_error1 = "Error while writing encrypted data to:"
        $str_error2 = "Error while writing public key to:"
        $str_error3 = "Error while renaming file:"
        $chunk_calculation0 = { 48 8D ?? 00 00 48 F4 48 B9 8B 3D 10 B6 9A 5A B4 36 48 F7 E1 48 }
        $chunk_calculation1 = { 48 C1 EA 12 48 89 D0 48 C1 E0 05 48 29 D0 48 29 D0 48 3D C4 EA 00 00 }
    condition:
        5 of ($str_*) or all of ($chunk_*)
}

rule Multi_Ransomware_RansomHub_4a8a07cd {
    meta:
        author = "Elastic Security"
        id = "4a8a07cd-700b-4514-a808-334c0a7641de"
        fingerprint = "c66b9c6889d0c4598bf2baa99a5d137a2e2ffd06dcd2141b08a6c1eec772a87c"
        creation_date = "2024-09-05"
        last_modified = "2024-09-30"
        threat_name = "Multi.Ransomware.RansomHub"
        reference_sample = "bfbbba7d18be1aa2e85390fa69a761302756ee9348b7343af6f42f3b5d0a939c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "white_files" ascii fullword
        $a2 = "note_file_name" ascii fullword
        $a3 = "note_short_text" ascii fullword
        $a4 = "set_wallpaper" ascii fullword
        $a5 = "local_disks" ascii fullword
        $a6 = "running_one" ascii fullword
        $a7 = "net_spread" ascii fullword
        $a8 = "kill_processes" ascii fullword
    condition:
        5 of them
}

