// from MacOS_Backdoor_Applejeus.yar
rule MacOS_Backdoor_Applejeus_31872ae2 {
    meta:
        author = "Elastic Security"
        id = "31872ae2-f6df-4079-89c2-866cb2e62ec8"
        fingerprint = "24b78b736f691e6b84ba88b0bb47aaba84aad0c0e45cf70f2fa8c455291517df"
        creation_date = "2021-10-18"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Backdoor.Applejeus"
        reference_sample = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { FF CE 74 12 89 F0 31 C9 80 34 0F 63 48 FF C1 48 39 C8 75 F4 }
    condition:
        all of them
}



// from MacOS_Backdoor_Fakeflashlxk.yar
rule MacOS_Backdoor_Fakeflashlxk_06fd8071 {
    meta:
        author = "Elastic Security"
        id = "06fd8071-0370-4ae8-819a-846fa0a79b3d"
        fingerprint = "a0e6763428616b46536c6a4eb080bae0cc58ef27678616aa432eb43a3d9c77a1"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Fakeflashlxk"
        reference_sample = "107f844f19e638866d8249e6f735daf650168a48a322d39e39d5e36cfc1c8659"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "/Users/lxk/Library/Developer/Xcode/DerivedData"
        $s2 = "Desktop/SafariFlashActivity/SafariFlashActivity/SafariFlashActivity/"
        $s3 = "/Debug/SafariFlashActivity.build/Objects-normal/x86_64/AppDelegate.o"
    condition:
        2 of them
}



// from MacOS_Backdoor_Kagent.yar
rule MacOS_Backdoor_Kagent_64ca1865 {
    meta:
        author = "Elastic Security"
        id = "64ca1865-0a99-49dc-b138-02b17ed47f60"
        fingerprint = "b8086b08a019a733bee38cebdc4e25cdae9d3c238cfe7b341d8f0cd4db204d27"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Kagent"
        reference_sample = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "save saveCaptureInfo"
        $s2 = "savephoto success screenCaptureInfo"
        $s3 = "no auto bbbbbaaend:%d path %s"
        $s4 = "../screencapture/screen_capture_thread.cpp"
        $s5 = "%s:%d, m_autoScreenCaptureQueue: %x"
        $s6 = "auto bbbbbaaend:%d path %s"
        $s7 = "auto aaaaaaaastartTime:%d path %s"
    condition:
        4 of them
}



// from MacOS_Backdoor_Keyboardrecord.yar
rule MacOS_Backdoor_Keyboardrecord_832f7bac {
    meta:
        author = "Elastic Security"
        id = "832f7bac-3896-4934-b05f-8215a41cca74"
        fingerprint = "27aa4380bda0335c672e957ba2ce6fd1f42ccf0acd2eff757e30210c3b4fb2fa"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Keyboardrecord"
        reference_sample = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "com.ccc.keyboardrecord"
        $s2 = "com.ccc.write_queue"
        $s3 = "ps -p %s > /dev/null"
        $s4 = "useage %s path useragentpid"
        $s5 = "keyboardRecorderStartPKc"
    condition:
        3 of them
}



// from MacOS_Backdoor_Useragent.yar
rule MacOS_Backdoor_Useragent_1a02fc3a {
    meta:
        author = "Elastic Security"
        id = "1a02fc3a-a394-457b-8af5-99f7f22b0a3b"
        fingerprint = "22afa14a3dc6f8053b93bf3e971d57808a9cc19e676f9ed358ba5f1db9292ba4"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Useragent"
        reference_sample = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "/Library/LaunchAgents/com.UserAgent.va.plist"
        $s2 = "this is not root"
        $s3 = "rm -Rf "
        $s4 = "/start.sh"
        $s5 = ".killchecker_"
    condition:
        4 of them
}



// from MacOS_Creddump_KeychainAccess.yar
rule MacOS_Creddump_KeychainAccess_535c1511 {
    meta:
        author = "Elastic Security"
        id = "535c1511-5b45-4845-85c1-ec53f9787b96"
        fingerprint = "7c103fa75b24cdf322f6c7cf3ec56e8cc2b14666c9d9fb56a4b1a735efaf1b5b"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "Macos.Creddump.KeychainAccess"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $strings1 = "uploadkeychain" ascii wide nocase
        $strings2 = "decryptkeychain" ascii wide nocase
        $strings3 = "dump-generic-password" ascii wide nocase
        $strings4 = "keychain_extract" ascii wide nocase
        $strings5 = "chainbreaker" ascii wide nocase
        $strings6 = "SecKeychainItemCopyContent" ascii wide nocase
        $strings7 = "SecKeychainItemCopyAccess" ascii wide nocase
        $strings8 = "Failed to get password" ascii wide nocase
    condition:
        all of ($strings1, $strings2) or $strings4 or all of ($strings3, $strings5) or all of ($strings6, $strings7, $strings8)
}



// from MacOS_Cryptominer_Generic.yar
rule MacOS_Cryptominer_Generic_d3f68e29 {
    meta:
        author = "Elastic Security"
        id = "d3f68e29-830d-4d40-a285-ac29aed732fa"
        fingerprint = "733dadf5a09f4972629f331682fca167ebf9a438004cb686d032f69e32971bd4"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "d9c78c822dfd29a1d9b1909bf95cab2a9550903e8f5f178edeb7a5a80129fbdb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "command line argument. See 'ethminer -H misc' for details." ascii fullword
        $a2 = "Ethminer - GPU ethash miner" ascii fullword
        $a3 = "StratumClient"
    condition:
        all of them
}

rule MacOS_Cryptominer_Generic_365ecbb9 {
    meta:
        author = "Elastic Security"
        id = "365ecbb9-586e-4962-a5a8-05e871f54eff"
        fingerprint = "5ff82ab60f8d028c9e4d3dd95609f92cfec5f465c721d96947b490691d325484"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 55 6E 6B 6E 6F 77 6E 20 6E 65 74 77 6F 72 6B 20 73 70 65 63 69 66 69 65 64 20 }
    condition:
        all of them
}

rule MacOS_Cryptominer_Generic_4e7d4488 {
    meta:
        author = "Elastic Security"
        id = "4e7d4488-2e0c-4c74-84f9-00da103e162a"
        fingerprint = "4e7f22e8084734aeded9b1202c30e6a170a6a38f2e486098b4027e239ffed2f6"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 69 73 20 66 69 65 6C 64 20 74 6F 20 73 68 6F 77 20 6E 75 6D 62 65 72 20 6F 66 }
    condition:
        all of them
}



// from MacOS_Cryptominer_Xmrig.yar
rule MacOS_Cryptominer_Xmrig_241780a1 {
    meta:
        author = "Elastic Security"
        id = "241780a1-ad50-4ded-b85a-26339ae5a632"
        fingerprint = "be9c56f18e0f0bdc8c46544039b9cb0bbba595c1912d089b2bcc7a7768ac04a8"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Xmrig"
        reference_sample = "2e94fa6ac4045292bf04070a372a03df804fa96c3b0cb4ac637eeeb67531a32f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "mining.set_target" ascii fullword
        $a2 = "XMRIG_HOSTNAME" ascii fullword
        $a3 = "Usage: xmrig [OPTIONS]" ascii fullword
        $a4 = "XMRIG_VERSION" ascii fullword
    condition:
        all of them
}



// from MacOS_Exploit_Log4j.yar
rule MacOS_Exploit_Log4j_75a13888 {
    meta:
        author = "Elastic Security"
        id = "75a13888-7650-4ef3-adec-15378c8479bd"
        fingerprint = "cd06db6f5bebf0412d056017259b5451184d5ba5b2976efd18fa8f96dba6a159"
        creation_date = "2021-12-13"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Exploit.Log4j"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $jndi1 = "jndi.ldap.LdapCtx.c_lookup"
        $jndi2 = "logging.log4j.core.lookup.JndiLookup.lookup"
        $jndi3 = "com.sun.jndi.url.ldap.ldapURLContext.lookup"
        $exp1 = "Basic/Command/Base64/"
        $exp2 = "java.lang.ClassCastException: Exploit"
        $exp3 = "WEB-INF/classes/Exploit"
        $exp4 = "Exploit.java"
    condition:
        2 of ($jndi*) and 1 of ($exp*)
}



// from MacOS_Hacktool_Bifrost.yar
rule MacOS_Hacktool_Bifrost_39bcbdf8 {
    meta:
        author = "Elastic Security"
        id = "39bcbdf8-86dc-480e-8822-dc9832bb9b55"
        fingerprint = "e11f6f3a847817644d40fee863e168cd2a18e8e0452482c1e652c11fe8dd769e"
        creation_date = "2021-10-12"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Hacktool.Bifrost"
        reference_sample = "e2b64df0add316240b010db7d34d83fc9ac7001233259193e5a72b6e04aece46"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "[dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]" fullword
        $s2 = "[-] Error in parseKirbi: %s"
        $s3 = "[-] Error in parseTGSREP: %s"
        $s4 = "genPasswordHashPassword:Length:Enc:Username:Domain:Pretty:"
        $s5 = "storeLKDCConfDataFriendlyName:Hostname:Password:CCacheName:"
        $s6 = "bifrostconsole-"
        $s7 = "-kerberoast"
        $s8 = "asklkdcdomain"
        $s9 = "askhash"
    condition:
        3 of them
}



// from Macos_Hacktool_JokerSpy.yar
rule Macos_Hacktool_JokerSpy_58a6b26d {
    meta:
        author = "Elastic Security"
        id = "58a6b26d-13dd-485a-bac3-77a1053c3a02"
        fingerprint = "71423d5c4c917917281b7e0f644142a0570df7a5a7ea568506753cb6eabef1c0"
        creation_date = "2023-06-19"
        last_modified = "2023-06-19"
        threat_name = "Macos.Hacktool.JokerSpy"
        reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
        reference_sample = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str1 = "ScreenRecording: NO" fullword
        $str2 = "Accessibility: NO" fullword
        $str3 = "Accessibility: YES" fullword
        $str4 = "eck13XProtectCheck"
        $str5 = "Accessibility: NO" fullword
        $str6 = "kMDItemDisplayName = *TCC.db" fullword
    condition:
        5 of them
}



// from MacOS_Hacktool_Swiftbelt.yar
rule MacOS_Hacktool_Swiftbelt_bc62ede6 {
    meta:
        author = "Elastic Security"
        id = "bc62ede6-e6f1-4c9e-bff2-ef55a5d12ba1"
        fingerprint = "98d14dba562ad68c8ecc00780ab7ee2ecbe912cd00603fff0eb887df1cd12fdb"
        creation_date = "2021-10-12"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Hacktool.Swiftbelt"
        reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
        reference_sample = "452c832a17436f61ad5f32ee1c97db05575160105ed1dcd0d3c6db9fb5a9aea1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $dbg1 = "SwiftBelt/Sources/SwiftBelt"
        $dbg2 = "[-] Firefox places.sqlite database not found for user"
        $dbg3 = "[-] No security products found"
        $dbg4 = "SSH/AWS/gcloud Credentials Search:"
        $dbg5 = "[-] Could not open the Slack Cookies database"
        $sec1 = "[+] Malwarebytes A/V found on this host"
        $sec2 = "[+] Cisco AMP for endpoints found"
        $sec3 = "[+] SentinelOne agent running"
        $sec4 = "[+] Crowdstrike Falcon agent found"
        $sec5 = "[+] FireEye HX agent installed"
        $sec6 = "[+] Little snitch firewall found"
        $sec7 = "[+] ESET A/V installed"
        $sec8 = "[+] Carbon Black OSX Sensor installed"
        $sec9 = "/Library/Little Snitch"
        $sec10 = "/Library/FireEye/xagt"
        $sec11 = "/Library/CS/falcond"
        $sec12 = "/Library/Logs/PaloAltoNetworks/GlobalProtect"
        $sec13 = "/Library/Application Support/Malwarebytes"
        $sec14 = "/usr/local/bin/osqueryi"
        $sec15 = "/Library/Sophos Anti-Virus"
        $sec16 = "/Library/Objective-See/Lulu"
        $sec17 = "com.eset.remoteadministrator.agent"
        $sec18 = "/Applications/CarbonBlack/CbOsxSensorService"
        $sec19 = "/Applications/BlockBlock Helper.app"
        $sec20 = "/Applications/KextViewr.app"
    condition:
        6 of them
}



// from Macos_Infostealer_EncodedOsascript.yar
rule Macos_Infostealer_EncodedOsascript_eeb54a7e {
    meta:
        author = "Elastic Security"
        id = "eeb54a7e-ebb3-4bf9-8538-2dbad9e514b9"
        fingerprint = "7b9d3cc64f3cfbdf1f9938ab923ff06eb6aef78fce633af891f5dd6a6b38dd2d"
        creation_date = "2024-08-19"
        last_modified = "2024-08-26"
        threat_name = "Macos.Infostealer.EncodedOsascript"
        reference_sample = "c1693ee747e31541919f84dfa89e36ca5b74074044b181656d95d7f40af34a05"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $xor_encoded_osascript = "osascript" xor(64)
        $base32_encoded_osascript = { 4E 35 5A 57 43 34 33 44 4F 4A 55 58 41 35 }
        $hex_encoded_osascript = "6f7361736372697074" ascii wide nocase
    condition:
        any of them
}



// from MacOS_Infostealer_MdQueryPassw.yar
rule MacOS_Infostealer_MdQueryPassw_6125f987 {
    meta:
        author = "Elastic Security"
        id = "6125f987-b5a4-4999-ab39-ff312a43f6d9"
        fingerprint = "744e5e82bd90dc75031c2ce8208e9b8d10f062a57666f7e7be9428321f2929cc"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQueryPassw"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}passw/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}passw\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}



// from MacOS_Infostealer_MdQuerySecret.yar
rule MacOS_Infostealer_MdQuerySecret_5535ab96 {
    meta:
        author = "Elastic Security"
        id = "5535ab96-36aa-42ed-ab85-d8fd7fa6a368"
        fingerprint = "4fdad65ffdce106e837bbec747e63269f782a9b1ab2cfa9d2db204d252960ab4"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQuerySecret"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}secret/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}secret\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}



// from MacOS_Infostealer_MdQueryTCC.yar
rule MacOS_Infostealer_MdQueryTCC_142313cb {
    meta:
        author = "Elastic Security"
        id = "142313cb-4726-442d-957c-5078440b8940"
        fingerprint = "280fa2c49461d0b53425768b9114696104c3ed0241ed157c22e36cdbaa334ac9"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQueryTCC"
        reference_sample = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = { 6B 4D 44 49 74 65 6D 44 69 73 70 6C 61 79 4E 61 6D 65 20 ( 3D | 3D ) 20 2A 54 43 43 2E 64 62 }
    condition:
        any of them
}



// from MacOS_Infostealer_MdQueryToken.yar
rule MacOS_Infostealer_MdQueryToken_1c52d574 {
    meta:
        author = "Elastic Security"
        id = "1c52d574-4fb7-4f14-b100-291e3f296c94"
        fingerprint = "f603e5383d08050cd84949fb60ce5618c4dfff54bcb3f035290adc1c1cc0e0e1"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQueryToken"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}token/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}token\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}



// from Macos_Infostealer_Wallets.yar
rule Macos_Infostealer_Wallets_8e469ea0 {
    meta:
        author = "Elastic Security"
        id = "8e469ea0-0c68-444b-b19a-4e1ab89f94b2"
        fingerprint = "ef913d90c42c8ed1ac47a0057e5e1cb7d5b2de66fe13b088724e87e223d6c377"
        creation_date = "2024-03-06"
        last_modified = "2024-08-26"
        threat_name = "Macos.Infostealer.Wallets"
        reference_sample = "0e649facc5c82f7112997c7629bd114e63acc1c8dc9ede646214243ace9b9c1d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "Ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide nocase
        $s2 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii wide nocase
        $s3 = "ffnbelfdoeiohenkjibnmadjiehjhajb" ascii wide nocase
        $s4 = "jbdaocneiiinmjbjlgalhcelgbejmnid" ascii wide nocase
        $s5 = "afbcbjpbpfadlkmhmclhkeeodmamcflc" ascii wide nocase
        $s6 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii wide nocase
        $s7 = "hpglfhgfnhbgpjdenjgmdgoeiappafln" ascii wide nocase
        $s8 = "blnieiiffboillknjnepogjhkgnoapac" ascii wide nocase
        $s9 = "cjelfplplebdjjenllpjcblmjkfcffne" ascii wide nocase
        $s10 = "fihkakfobkmkjojpchpfgcmhfjnmnfpi" ascii wide nocase
        $s11 = "kncchdigobghenbbaddojjnnaogfppfj" ascii wide nocase
        $s12 = "amkmjjmmflddogmhpjloimipbofnfjih" ascii wide nocase
        $s13 = "nlbmnnijcnlegkjjpcfjclmcfggfefdm" ascii wide nocase
        $s14 = "nanjmdknhkinifnkgdcggcfnhdaammmj" ascii wide nocase
        $s15 = "nkddgncdjgjfcddamfgcmfnlhccnimig" ascii wide nocase
        $s16 = "fnjhmkhhmkbjkkabndcnnogagogbneec" ascii wide nocase
        $s17 = "cphhlgmgameodnhkjdmkpanlelnlohao" ascii wide nocase
        $s18 = "nhnkbkgjikgcigadomkphalanndcapjk" ascii wide nocase
        $s19 = "kpfopkelmapcoipemfendmdcghnegimn" ascii wide nocase
        $s20 = "aiifbnbfobpmeekipheeijimdpnlpgpp" ascii wide nocase
        $s21 = "dmkamcknogkgcdfhhbddcghachkejeap" ascii wide nocase
        $s22 = "fhmfendgdocmcbmfikdcogofphimnkno" ascii wide nocase
        $s23 = "cnmamaachppnkjgnildpdmkaakejnhae" ascii wide nocase
        $s24 = "jojhfeoedkpkglbfimdfabpdfjaoolaf" ascii wide nocase
        $s25 = "flpiciilemghbmfalicajoolhkkenfel" ascii wide nocase
        $s26 = "nknhiehlklippafakaeklbeglecifhad" ascii wide nocase
        $s27 = "hcflpincpppdclinealmandijcmnkbgn" ascii wide nocase
        $s28 = "ookjlbkiijinhpmnjffcofjonbfbgaoc" ascii wide nocase
        $s29 = "mnfifefkajgofkcjkemidiaecocnkjeh" ascii wide nocase
        $s30 = "lodccjjbdhfakaekdiahmedfbieldgik" ascii wide nocase
        $s31 = "Ijmpgkjfkbfhoebgogflfebnmejmfbml" ascii wide nocase
        $s32 = "lkcjlnjfpbikmcmbachjpdbijejflpcm" ascii wide nocase
        $s33 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide nocase
        $s34 = "bcopgchhojmggmffilplmbdicgaihlkp" ascii wide nocase
        $s35 = "klnaejjgbibmhlephnhpmaofohgkpgkd" ascii wide nocase
        $s36 = "aeachknmefphepccionboohckonoeemg" ascii wide nocase
        $s37 = "dkdedlpgdmmkkfjabffeganieamfklkm" ascii wide nocase
        $s38 = "nlgbhdfgdhgbiamfdfmbikcdghidoadd" ascii wide nocase
        $s39 = "onofpnbbkehpmmoabgpcpmigafmmnjhl" ascii wide nocase
        $s40 = "cihmoadaighcejopammfbmddcmdekcje" ascii wide nocase
        $s41 = "cgeeodpfagjceefieflmdfphplkenlfk" ascii wide nocase
        $s42 = "pdadjkfkgcafgbceimcpbkalnfnepbnk" ascii wide nocase
        $s43 = "acmacodkjbdgmoleebolmdjonilkdbch" ascii wide nocase
        $s44 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide nocase
        $s45 = "fhilaheimglignddkjgofkcbgekhenbh" ascii wide nocase
        $s46 = "mgffkfbidihjpoaomajlbgchddlicgpn" ascii wide nocase
        $s47 = "hmeobnfnfcmdkdcmlblgagmfpfboieaf" ascii wide nocase
        $s48 = "lpfcbjknijpeeillifnkikgncikgfhdo" ascii wide nocase
        $s49 = "dngmlblcodfobpdpecaadgfbcggfjfnm" ascii wide nocase
        $s50 = "bhhhlbepdkbapadjdnnojkbgioiodbic" ascii wide nocase
        $s51 = "jnkelfanjkeadonecabehalmbgpfodjm" ascii wide nocase
        $s52 = "jhgnbkkipaallpehbohjmkbjofjdmeid" ascii wide nocase
        $s53 = "jnlgamecbpmbajjfhmmmlhejkemejdma" ascii wide nocase
        $s54 = "kkpllkodjeloidieedojogacfhpaihoh" ascii wide nocase
        $s55 = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii wide nocase
        $s56 = "gjagmgiddbbciopjhllkdnddhcglnemk" ascii wide nocase
        $s57 = "kmhcihpebfmpgmihbkipmjlmmioameka" ascii wide nocase
        $s58 = "phkbamefinggmakgklpkljjmgibohnba" ascii wide nocase
        $s59 = "lpilbniiabackdjcionkobglmddfbcjo" ascii wide nocase
        $s60 = "cjmkndjhnagcfbpiemnkdpomccnjblmj" ascii wide nocase
        $s61 = "aijcbedoijmgnlmjeegjaglmepbmpkpi" ascii wide nocase
        $s62 = "efbglgofoippbgcjepnhiblaibcnclgk" ascii wide nocase
        $s63 = "odbfpeeihdkbihmopkbjmoonfanlbfcl" ascii wide nocase
        $s64 = "fnnegphlobjdpkhecapkijjdkgcjhkib" ascii wide nocase
        $s65 = "aodkkagnadcbobfpggfnjeongemjbjca" ascii wide nocase
        $s66 = "akoiaibnepcedcplijmiamnaigbepmcb" ascii wide nocase
        $s67 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii wide nocase
        $s68 = "dfeccadlilpndjjohbjdblepmjeahlmm" ascii wide nocase
        $s69 = "kjmoohlgokccodicjjfebfomlbljgfhk" ascii wide nocase
        $s70 = "ajkhoeiiokighlmdnlakpjfoobnjinie" ascii wide nocase
        $s71 = "fplfipmamcjaknpgnipjeaeeidnjooao" ascii wide nocase
        $s72 = "niihfokdlimbddhfmngnplgfcgpmlido" ascii wide nocase
        $s73 = "obffkkagpmohennipjokmpllocnlndac" ascii wide nocase
        $s74 = "kfocnlddfahihoalinnfbnfmopjokmhl" ascii wide nocase
        $s75 = "infeboajgfhgbjpjbeppbkgnabfdkdaf" ascii wide nocase
        $s76 = "{530f7c6c-6077-4703-8f71-cb368c663e35}.xpi" ascii wide nocase
        $s77 = "ronin-wallet@axieinfinity.com.xpi" ascii wide nocase
        $s78 = "webextension@metamask.io.xpi" ascii wide nocase
        $s79 = "{5799d9b6-8343-4c26-9ab6-5d2ad39884ce}.xpi" ascii wide nocase
        $s80 = "{aa812bee-9e92-48ba-9570-5faf0cfe2578}.xpi" ascii wide nocase
        $s81 = "{59ea5f29-6ea9-40b5-83cd-937249b001e1}.xpi" ascii wide nocase
        $s82 = "{d8ddfc2a-97d9-4c60-8b53-5edd299b6674}.xpi" ascii wide nocase
        $s83 = "{7c42eea1-b3e4-4be4-a56f-82a5852b12dc}.xpi" ascii wide nocase
        $s84 = "{b3e96b5f-b5bf-8b48-846b-52f430365e80}.xpi" ascii wide nocase
        $s85 = "{eb1fb57b-ca3d-4624-a841-728fdb28455f}.xpi" ascii wide nocase
        $s86 = "{76596e30-ecdb-477a-91fd-c08f2018df1a}.xpi" ascii wide nocase
        $s87 = "ejjladinnckdgjemekebdpeokbikhfci" ascii wide nocase
        $s88 = "bgpipimickeadkjlklgciifhnalhdjhe" ascii wide nocase
        $s89 = "epapihdplajcdnnkdeiahlgigofloibg" ascii wide nocase
        $s90 = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii wide nocase
        $s91 = "egjidjbpglichdcondbcbdnbeeppgdph" ascii wide nocase
        $s92 = "pnndplcbkakcplkjnolgbkdgjikjednm" ascii wide nocase
        $s93 = "gojhcdgcpbpfigcaejpfhfegekdgiblk" ascii wide nocase
    condition:
        6 of them
}



// from MacOS_Trojan_Adload.yar
rule MacOS_Trojan_Adload_4995469f {
    meta:
        author = "Elastic Security"
        id = "4995469f-9810-4c1f-b9bc-97e951fe9256"
        fingerprint = "9b7e7c76177cc8ca727df5039a5748282f5914f2625ec1f54d67d444f92f0ee5"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "6464ca7b36197cccf0dac00f21c43f0cb09f900006b1934e2b3667b367114de5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 49 8B 77 08 49 8B 4F 20 48 BF 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E7 48 C1 }
    condition:
        all of them
}

rule MacOS_Trojan_Adload_9b9f86c7 {
    meta:
        author = "Elastic Security"
        id = "9b9f86c7-e74c-4fc2-bb64-f87473a4b820"
        fingerprint = "7e70d5574907261e73d746a4ad0b7bce319a9bb3b39a7f1df326284960a7fa38"
        creation_date = "2021-10-04"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "952e6004ce164ba607ac7fddc1df3d0d6cac07d271d90be02d790c52e49cb73c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 44 65 6C 65 67 61 74 65 43 35 73 68 6F 77 6E 53 62 76 70 57 76 64 }
    condition:
        all of them
}

rule MacOS_Trojan_Adload_f6b18a0a {
    meta:
        author = "Elastic Security"
        id = "f6b18a0a-7593-430f-904b-8d416861d165"
        fingerprint = "f33275481b0bf4f4e57c7ad757f1e22d35742fc3d0ffa3983321f03170b5100e"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Adload"
        reference_sample = "06f38bb811e6a6c38b5e2db708d4063f4aea27fcd193d57c60594f25a86488c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 10 49 8B 4E 20 48 BE 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E6 49 39 DC 0F 84 }
    condition:
        all of them
}



// from MacOS_Trojan_Amcleaner.yar
rule MacOS_Trojan_Amcleaner_445bb666 {
    meta:
        author = "Elastic Security"
        id = "445bb666-1707-4ad9-a409-4a21de352957"
        fingerprint = "355c7298a4148be3b80fd841b483421bde28085c21c00d5e4a42949fd8026f5b"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 10 A0 5B 15 57 A8 8B 17 02 F9 A8 9B E8 D5 8C 96 A7 48 42 91 E5 EC 3D C8 AC 52 }
    condition:
        all of them
}

rule MacOS_Trojan_Amcleaner_a91d3907 {
    meta:
        author = "Elastic Security"
        id = "a91d3907-5e24-46c0-90ef-ed7f46ad8792"
        fingerprint = "c020567fde77a72d27c9c06f6ebb103f910321cc7a1c3b227e0965b079085b49"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "dc9c700f3f6a03ecb6e3f2801d4269599c32abce7bc5e6a1b7e6a64b0e025f58"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 40 22 4E 53 49 6D 61 67 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6A 76 64 69 5A }
    condition:
        all of them
}

rule MacOS_Trojan_Amcleaner_8ce3fea8 {
    meta:
        author = "Elastic Security"
        id = "8ce3fea8-3cc7-4c59-b07c-a6dda0bb6b85"
        fingerprint = "e156d3c7a55cae84481df644569d1c5760e016ddcc7fd05d0f88fa8f9f9ffdae"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 54 40 22 4E 53 54 61 62 6C 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6B 54 70 51 }
    condition:
        all of them
}



// from MacOS_Trojan_Aobokeylogger.yar
rule MacOS_Trojan_Aobokeylogger_bd960f34 {
    meta:
        author = "Elastic Security"
        id = "bd960f34-1932-41be-ac0a-f45ada22c560"
        fingerprint = "ae26a03d1973669cbeaabade8f3fd09ef2842b9617fa38e7b66dc4726b992a81"
        creation_date = "2021-10-18"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Aobokeylogger"
        reference_sample = "2b50146c20621741642d039f1e3218ff68e5dbfde8bb9edaa0a560ca890f0970"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 20 74 68 61 6E 20 32 30 30 20 6B 65 79 73 74 72 6F 6B 65 73 20 }
    condition:
        all of them
}



// from MacOS_Trojan_Bundlore.yar
rule MacOS_Trojan_Bundlore_28b13e67 {
    meta:
        author = "Elastic Security"
        id = "28b13e67-e01c-45eb-aae6-ecd02b017a44"
        fingerprint = "1e85be4432b87214d61e675174f117e36baa8ab949701ee1d980ad5dd8454bac"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "0b50a38749ea8faf571169ebcfce3dfd668eaefeb9a91d25a96e6b3881e4a3e8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 05 A5 A3 A9 37 D2 05 13 E9 3E D6 EA 6A EC 9B DC 36 E5 76 A7 53 B3 0F 06 46 D1 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_75c8cb4e {
    meta:
        author = "Elastic Security"
        id = "75c8cb4e-f8bd-4a2c-8a5e-8500e12a9030"
        fingerprint = "db68c315dba62f81168579aead9c5827f7bf1df4a3c2e557b920fa8fbbd6f3c2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "3d69912e19758958e1ebdef5e12c70c705d7911c3b9df03348c5d02dd06ebe4e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 EE 19 00 00 EA 80 35 E8 19 00 00 3B 80 35 E2 19 00 00 A4 80 35 DC 19 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_17b564b4 {
    meta:
        author = "Elastic Security"
        id = "17b564b4-7452-473f-873f-f907b5b8ebc4"
        fingerprint = "7701fab23d59b8c0db381a1140c4e350e2ce24b8114adbdbf3c382c6d82ea531"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "94f6e5ee6eb3a191faaf332ea948301bbb919f4ec6725b258e4f8e07b6a7881d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 D9 11 00 00 05 80 35 D3 11 00 00 2B 80 35 CD 11 00 00 F6 80 35 C7 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_c90c088a {
    meta:
        author = "Elastic Security"
        id = "c90c088a-abf5-4e52-a69e-5a4fd4b5cf15"
        fingerprint = "c2300895f8ff5ae13bc0ed93653afc69b30d1d01f5ce882bd20f2b65426ecb47"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "875513f4ebeb63b9e4d82fb5bff2b2dc75b69c0bfa5dd8d2895f22eaa783f372"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 E1 11 00 00 92 80 35 DB 11 00 00 2A 80 35 D5 11 00 00 7F 80 35 CF 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_3965578d {
    meta:
        author = "Elastic Security"
        id = "3965578d-3180-48e4-b5be-532e880b1df9"
        fingerprint = "e41f08618db822ba5185e5dc3f932a72e1070fbb424ff2c097cab5e58ad9e2db"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "d72543505e36db40e0ccbf14f4ce3853b1022a8aeadd96d173d84e068b4f68fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 33 2A 00 00 60 80 35 2D 2A 00 00 D0 80 35 27 2A 00 00 54 80 35 21 2A 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_00d9d0e9 {
    meta:
        author = "Elastic Security"
        id = "00d9d0e9-28d8-4c32-bc6f-52008ee69b07"
        fingerprint = "7dcc6b124d631767c259101f36b4bbd6b9d27b2da474d90e31447ea03a2711a6"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "73069b34e513ff1b742b03fed427dc947c22681f30cf46288a08ca545fc7d7dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 8E 11 00 00 55 80 35 88 11 00 00 BC 80 35 82 11 00 00 72 80 35 7C 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_650b8ff4 {
    meta:
        author = "Elastic Security"
        id = "650b8ff4-6cc8-4bfc-ba01-ac9c86410ecc"
        fingerprint = "4f4691f6830684a71e7b3ab322bf6ec4638bf0035adf3177dbd0f02e54b3fd80"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "78fd2c4afd7e810d93d91811888172c4788a0a2af0b88008573ce8b6b819ae5a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 8B 11 00 00 60 80 35 85 11 00 00 12 80 35 7F 11 00 00 8C 80 35 79 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_c8ad7edd {
    meta:
        author = "Elastic Security"
        id = "c8ad7edd-4233-44ce-a4e5-96dfc3504f8a"
        fingerprint = "c6a8a1d9951863d4277d297dd6ff8ad7b758ca2dfe16740265456bb7bb0fd7d0"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "d4915473e1096a82afdaee405189a0d0ae961bd11a9e5e9adc420dd64cb48c24"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 74 11 00 00 D5 80 35 6E 11 00 00 57 80 35 68 11 00 00 4C 80 35 62 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_cb7344eb {
    meta:
        author = "Elastic Security"
        id = "cb7344eb-51e6-4f17-a5d4-eea98938945b"
        fingerprint = "6041c50c9eefe9cafb8768141cd7692540f6af2cdd6e0a763b7d7e50b8586999"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "53373668d8c5dc17f58768bf59fb5ab6d261a62d0950037f0605f289102e3e56"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 ED 09 00 00 92 80 35 E7 09 00 00 93 80 35 E1 09 00 00 16 80 35 DB 09 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_753e5738 {
    meta:
        author = "Elastic Security"
        id = "753e5738-0c72-4178-9396-d1950e868104"
        fingerprint = "c0a41a8bc7fbf994d3f5a5d6c836db3596b1401b0e209a081354af2190fcb3c2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "42aeea232b28724d1fa6e30b1aeb8f8b8c22e1bc8afd1bbb4f90e445e31bdfe9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 9A 11 00 00 96 80 35 94 11 00 00 68 80 35 8E 11 00 00 38 80 35 88 11 00 00 }
    condition:
        all of them
}

rule MacOS_Trojan_Bundlore_7b9f0c28 {
    meta:
        author = "Elastic Security"
        id = "7b9f0c28-181d-4fdc-8a57-467d5105129a"
        fingerprint = "dde16fdd37a16fa4dae24324283cd4b36ed2eb78f486cedd1a6c7bef7cde7370"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Bundlore"
        reference_sample = "fc4da125fed359d3e1740dafaa06f4db1ffc91dbf22fd5e7993acf8597c4c283"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 B6 15 00 00 81 80 35 B0 15 00 00 14 80 35 AA 15 00 00 BC 80 35 A4 15 00 00 }
    condition:
        all of them
}



// from MacOS_Trojan_Eggshell.yar
rule MacOS_Trojan_Eggshell_ddacf7b9 {
    meta:
        author = "Elastic Security"
        id = "ddacf7b9-8479-47ef-9df2-17060578a8e5"
        fingerprint = "2e6284c8e44809d5f88781dcf7779d1e24ce3aedd5e8db8598e49c01da63fe62"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Eggshell"
        reference_sample = "6d93a714dd008746569c0fbd00fadccbd5f15eef06b200a4e831df0dc8f3d05b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "ScreenshotThread" ascii fullword
        $a2 = "KeylogThread" ascii fullword
        $a3 = "GetClipboardThread" ascii fullword
        $a4 = "_uploadProgress" ascii fullword
        $a5 = "killTask:" ascii fullword
    condition:
        all of them
}



// from MacOS_Trojan_Electrorat.yar
rule MacOS_Trojan_Electrorat_b4dbfd1d {
    meta:
        author = "Elastic Security"
        id = "b4dbfd1d-4968-4121-a4c2-5935b7f76fc1"
        fingerprint = "fa65fc0a8f5b1f63957c586e6ca8e8fbdb811970f25a378a4ff6edf5e5c44da7"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Electrorat"
        reference_sample = "b1028b38fcce0d54f2013c89a9c0605ccb316c36c27faf3a35adf435837025a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "_TtC9Keylogger9Keylogger" ascii fullword
        $a2 = "_TtC9Keylogger17CallBackFunctions" ascii fullword
        $a3 = "\\DELETE-FORWARD" ascii fullword
        $a4 = "\\CAPSLOCK" ascii fullword
    condition:
        all of them
}



// from MacOS_Trojan_Fplayer.yar
rule MacOS_Trojan_Fplayer_1c1fae37 {
    meta:
        author = "Elastic Security"
        id = "1c1fae37-8d19-4129-a715-b78163f93fd2"
        fingerprint = "abeb3cd51c0ff2e3173739c423778defb9a77bc49b30ea8442e6ec93a2d2d8d2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Fplayer"
        reference_sample = "f57e651088dee2236328d09705cef5e98461e97d1eb2150c372d00ca7c685725"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 56 41 55 41 54 53 48 83 EC 48 4D 89 C4 48 89 C8 48 89 D1 49 89 F6 49 89 FD 49 }
    condition:
        all of them
}



// from MacOS_Trojan_Generic.yar
rule MacOS_Trojan_Generic_a829d361 {
    meta:
        author = "Elastic Security"
        id = "a829d361-ac57-4615-b8e9-16089c44d7af"
        fingerprint = "5dba43dbc5f4d5ee295e65d66dd4e7adbdb7953232faf630b602e6d093f69584"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Generic"
        reference_sample = "5b2a1cd801ae68a890b40dbd1601cdfeb5085574637ae8658417d0975be8acb5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { E7 81 6A 12 EA A8 56 6C 86 94 ED F6 E8 D7 35 E1 EC 65 47 BA 8E 46 2C A6 14 5F }
    condition:
        all of them
}



// from MacOS_Trojan_Genieo.yar
rule MacOS_Trojan_Genieo_5e0f8980 {
    meta:
        author = "Elastic Security"
        id = "5e0f8980-1789-4763-9e41-a521bdb3ff34"
        fingerprint = "f0b5198ce85d19889052a7e33fb7cf32a7725c4fdb384ffa7d60d209a7157092"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "6c698bac178892dfe03624905256a7d9abe468121163d7507cade48cf2131170"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 00 CD 01 1E 68 57 58 D7 56 7C 62 C9 27 3C C6 15 A9 3D 01 02 2F E1 69 B5 4A 11 }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_37878473 {
    meta:
        author = "Elastic Security"
        id = "37878473-b6f8-4cbe-ba70-31ecddf41c82"
        fingerprint = "e9760bda6da453f75e543c919c260a4560989f62f3332f28296283d4c01b62a2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "0fadd926f8d763f7f15e64f857e77f44a492dcf5dc82ae965d3ddf80cd9c7a0d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 65 72 6E 61 6C 44 6F 77 6E 4C 6F 61 64 55 72 6C 46 6F 72 42 72 61 6E 64 3A 5D }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_0d003634 {
    meta:
        author = "Elastic Security"
        id = "0d003634-8b17-4e26-b4a2-4bfce2e64dde"
        fingerprint = "6f38b7fc403184482449957aff51d54ac9ea431190c6f42c7a5420efbfdb8f7d"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "bcd391b58338efec4769e876bd510d0c4b156a7830bab56c3b56585974435d70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 75 69 6C 64 2F 41 6E 61 62 65 6C 50 61 63 6B 61 67 65 2F 62 75 69 6C 64 2F 73 }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_9e178c0b {
    meta:
        author = "Elastic Security"
        id = "9e178c0b-02ca-499b-93d1-2b6951d41435"
        fingerprint = "b00bffbdac79c5022648bf8ca5a238db7e71f3865a309f07d068ee80ba283b82"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "b7760e73195c3ea8566f3ff0427d85d6f35c6eec7ee9184f3aceab06da8845d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 4D 49 70 67 41 59 4B 6B 42 5A 59 53 65 4D 6B 61 70 41 42 48 4D 5A 43 63 44 44 }
    condition:
        all of them
}



// from MacOS_Trojan_Getshell.yar
rule MacOS_Trojan_Getshell_f339d74c {
    meta:
        author = "Elastic Security"
        id = "f339d74c-36f1-46e5-bf7d-22f49a0948a5"
        fingerprint = "fad5ca4f345c2c01a3d222f59bac8d5dacf818d4e018c8d411d86266a481a1a1"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Getshell"
        reference_sample = "b2199c15500728a522c04320aee000938f7eb69d751a55d7e51a2806d8cd0fe7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 00 00 FF E0 E8 00 00 00 00 58 8B 80 4B 22 00 00 FF E0 55 89 E5 53 83 EC 04 E8 }
    condition:
        all of them
}



// from MacOS_Trojan_HLoader.yar
rule MacOS_Trojan_HLoader_a3945baf {
    meta:
        author = "Elastic Security"
        id = "a3945baf-4708-4a0b-8a9b-1a5448ee4bc7"
        fingerprint = "a48ec79f07a6a53611b1d1e8fe938513ec0ea19344126e07331b48b028cb877e"
        creation_date = "2023-10-23"
        last_modified = "2023-10-23"
        threat_name = "MacOS.Trojan.HLoader"
        reference_sample = "2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $seq_main = { 74 ?? 49 89 C7 48 89 D8 4C 89 FF E8 ?? ?? ?? ?? 48 89 DF 31 F6 BA ?? ?? ?? ?? 4C 89 65 ?? 4D 89 F4 4C 89 F1 4C 8B 75 ?? 41 FF 56 ?? }
        $seq_exec = { 48 B8 00 00 00 00 00 00 00 E0 48 89 45 ?? 4C 8D 6D ?? BF 11 00 00 00 E8 ?? ?? ?? ?? 0F 10 45 ?? 0F 11 45 ?? 48 BF 65 78 65 63 46 69 6C 65 48 BE 20 65 72 72 6F 72 20 EF }
        $seq_rename = { 41 89 DE 84 DB 74 ?? 48 8B 7D ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? }
    condition:
        2 of ($seq*)
}



// from MacOS_Trojan_KandyKorn.yar
rule MacOS_Trojan_KandyKorn_a7bb6944 {
    meta:
        author = "Elastic Security"
        id = "a7bb6944-90fa-40ba-840c-f044f12dcb39"
        fingerprint = "f2b2ebc056c79448b077dce140b2a73d6791b61ddc8bf21d4c565c95f5de49e7"
        creation_date = "2023-10-23"
        last_modified = "2023-10-23"
        threat_name = "MacOS.Trojan.KandyKorn"
        reference = "https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn"
        reference_sample = "51dd4efcf714e64b4ad472ea556bf1a017f40a193a647b9e28bf356979651077"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str_1 = "resp_file_dir"
        $str_2 = "resp_cfg_set"
        $str_3 = "resp_proc_kill"
        $str_4 = "/com.apple.safari.ck" ascii fullword
        $str_5 = "/chkupdate.XXX" ascii fullword
        $seq_file_dir = { 83 7D ?? ?? 0F 8E ?? ?? ?? ?? 48 63 45 ?? 48 83 C0 ?? 48 8B 4D ?? 0F B7 49 ?? 48 01 C8 48 83 C0 01 48 3D 00 00 0A 00 0F 86 ?? ?? ?? ?? }
        $seq_cmd_send = { 8B 45 ?? 83 F8 ?? 0F 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 78 ?? 48 8B 70 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $seq_cfg_get = { 8B 45 ?? 83 F8 ?? 0F 8C ?? ?? ?? ?? 48 8B 45 ?? 48 8B 38 48 8B 70 ?? 8B 55 ?? E8 ?? ?? ?? ?? 89 45 ?? E9 ?? ?? ?? ?? }
        $seq_proc_list = { 48 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? 89 48 ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? 89 48 ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? }
        $rc4_key = { D9 F9 36 CE 62 8C 3E 5D 9B 36 95 69 4D 1C DE 79 E4 70 E9 38 06 4D 98 FB F4 EF 98 0A 55 58 D1 C9 0C 7E 65 0C 23 62 A2 1B 91 4A BD 17 3A BA 5C 0E 58 37 C4 7B 89 F7 4C 5B 23 A7 29 4C C1 CF D1 1B }
    condition:
        4 of ($str*) or 3 of ($seq*) or $rc4_key
}



// from MacOS_Trojan_Metasploit.yar
rule MacOS_Trojan_Metasploit_6cab0ec0 {
    meta:
        author = "Elastic Security"
        id = "6cab0ec0-0ac5-4f43-8a10-1f46822a152b"
        fingerprint = "e13c605d8f16b2b2e65c717a4716c25b3adaec069926385aff88b37e3db6e767"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = "mettlesploit! " ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_293bfea9 {
    meta:
        author = "Elastic Security"
        id = "293bfea9-c5cf-4711-bec0-17a02ddae6f2"
        fingerprint = "d47e8083268190465124585412aaa2b30da126083f26f3eda4620682afd1d66e"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "_webcam_get_frame" ascii fullword
        $a2 = "_get_process_info" ascii fullword
        $a3 = "process_new: got %zd byte executable to run in memory" ascii fullword
        $a4 = "Dumping cert info:" ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_448fa81d {
    meta:
        author = "Elastic Security"
        id = "448fa81d-14c7-479b-8d1e-c245ee261ef6"
        fingerprint = "ff040211f664f3f35cd4f4da0e5eb607ae3e490aae75ee97a8fb3cb0b08ecc1f"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "/Users/vagrant/mettle/mettle/src/process.c" ascii fullword
        $a2 = "/Users/vagrant/mettle/mettle/src/c2_http.c" ascii fullword
        $a3 = "/Users/vagrant/mettle/mettle/src/mettle.c" ascii fullword
    condition:
        any of them
}

rule MacOS_Trojan_Metasploit_768df39d {
    meta:
        author = "Elastic Security"
        id = "768df39d-7ee9-454e-82f8-5c7bd733c61a"
        fingerprint = "d45230c1111bda417228e193c8657d2318b1d2cddfbd01c5c6f2ea1d0be27a46"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit shell_reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_reverse_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { FF 4F E8 79 F6 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_7ce0b709 {
    meta:
        author = "Elastic Security"
        id = "7ce0b709-1d96-407c-8eca-6af64e5bdeef"
        fingerprint = "3eb7f78d2671e16c16a6d9783995ebb32e748612d32ed4f2442e9f9c1efc1698"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit shell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { FF 4F E4 79 F6 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_f11ccdac {
    meta:
        author = "Elastic Security"
        id = "f11ccdac-be75-4ba8-800a-179297a40792"
        fingerprint = "fbc1a5b77ed485706ae38f996cd086253ea1d43d963cb497446e5b0f3d0f3f11"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit shell_find_port.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_find_port.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 50 6A 1F 58 CD 80 66 81 7F 02 04 D2 75 EE 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_d9b16f4c {
    meta:
        author = "Elastic Security"
        id = "d9b16f4c-8cc9-42ce-95fa-8db06df9d582"
        fingerprint = "cf5cfc372008ae98a0958722a7b23f576d6be3b5b07214d21594a48a87d92fca"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit vforkshell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7E 00 00 00 89 C6 52 52 52 68 00 02 34 12 89 E3 6A }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_2992b917 {
    meta:
        author = "Elastic Security"
        id = "2992b917-32bd-4fd8-8221-0d061239673d"
        fingerprint = "055129bc7931d0334928be00134c109ab36825997b2877958e0ca9006b55575e"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit vforkshell_reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_reverse_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 6D 89 C7 52 52 68 7F 00 00 01 68 00 02 34 12 89 E3 6A }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_27d409f1 {
    meta:
        author = "Elastic Security"
        id = "27d409f1-80fd-4d07-815a-4741c48e0bf6"
        fingerprint = "43be41784449fc414c3e3bc7f4ca5827190fa10ac4cdd8500517e2aa6cce2a56"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit x64 shell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x64/shell_bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { B8 61 00 00 02 6A 02 5F 6A 01 5E 48 31 D2 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_65a2394b {
    meta:
        author = "Elastic Security"
        id = "65a2394b-0e66-4cb5-b6aa-3909120f0a94"
        fingerprint = "082da76eb8da9315d495b79466366367f19170f93c0a29966858cb92145e38d7"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stages vforkshell.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/osx/x86/vforkshell.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 DB 83 EB 01 43 53 57 53 B0 5A CD 80 72 43 83 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_c7b7a90b {
    meta:
        author = "Elastic Security"
        id = "c7b7a90b-aaf2-482d-bb95-dee20a75379e"
        fingerprint = "c4b2711417f5616ca462149882a7f33ce53dd1b8947be62fe0b818c51e4f4b2f"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stager reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/reverse_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_4bd6aaca {
    meta:
        author = "Elastic Security"
        id = "4bd6aaca-f519-4d20-b3af-d376e0322a7e"
        fingerprint = "f4957b565d2b86c79281a0d3b2515b9a0c72f9c9c7b03dae18a3619d7e2fc3dc"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stager x86 bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7D }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_5e5b685f {
    meta:
        author = "Elastic Security"
        id = "5e5b685f-1b6b-4102-b54d-91318e418c6c"
        fingerprint = "52c41d4fc4d195e702523dd2b65e4078dd967f9c4e4b1c081bc04d88c9e4804f"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "cdf0a3c07ef1479b53d49b8f22a9f93adcedeea3b869ef954cc043e54f65c3d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 00 00 F4 90 90 90 90 55 48 89 E5 48 81 EC 60 20 00 00 89 F8 48 8B 0D 74 23 00 }
    condition:
        all of them
}



// from MacOS_Trojan_RustBucket.yar
rule MacOS_Trojan_RustBucket_e64f7a92 {
    meta:
        author = "Elastic Security"
        id = "e64f7a92-e530-4d0b-8ecb-fe5756ad648c"
        fingerprint = "f9907f46c345a874b683809f155691723e3a6df7c48f6f4e6eb627fb3dd7904d"
        creation_date = "2023-06-26"
        last_modified = "2023-06-29"
        threat_name = "MacOS.Trojan.RustBucket"
        reference = "https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket"
        reference_sample = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $user_agent = "User-AgentMozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"
        $install_log = "/var/log/install.log"
        $timestamp = "%Y-%m-%d %H:%M:%S"
    condition:
        all of them
}



// from MacOS_Trojan_SugarLoader.yar
rule MacOS_Trojan_SugarLoader_e7e1d99c {
    meta:
        author = "Elastic Security"
        id = "e7e1d99c-355e-4672-9176-d9eb5d2729c4"
        fingerprint = "cfffdab1e603518df48719266f0a2e91763e5ae7c033d4bf7a4c37232aa8eb04"
        creation_date = "2023-10-24"
        last_modified = "2023-10-24"
        description = "Identifies unpacked SugarLoader sample"
        threat_name = "MacOS.Trojan.SugarLoader"
        reference_sample = "3ea2ead8f3cec030906dcbffe3efd5c5d77d5d375d4a54cca03bfe8a6cb59940"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $seq_process_key = { 44 0F B6 0C 0F 89 C8 99 F7 BF ?? ?? ?? ?? 0F B6 84 17 ?? ?? ?? ?? 4C 21 C6 4C 01 CE 48 01 C6 }
        $seq_handshake = { E8 ?? ?? ?? ?? 4C 8D 75 ?? 48 89 DF 4C 89 F6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 8B 06 C1 C0 ?? 44 21 F8 4C 8D 75 ?? 41 89 06 48 89 DF 4C 89 F6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $seq_config = { 48 89 F7 48 C1 E7 05 48 29 F7 48 0F BE D1 48 01 FA 89 D6 8A 08 48 FF C0 84 C9 75 ?? EB ?? }
        $seq_recieve_msg = { 45 85 FF 74 ?? 45 39 EF BA ?? ?? ?? ?? 41 0F 42 D7 41 8B 3C 24 48 89 DE 31 C9 E8 ?? ?? ?? ?? 41 29 C7 48 01 C3 48 85 C0 7F ?? B8 ?? ?? ?? ?? EB ?? }
    condition:
        3 of ($seq*)
}



// from MacOS_Trojan_Thiefquest.yar
rule MacOS_Trojan_Thiefquest_9130c0f3 {
    meta:
        author = "Elastic Security"
        id = "9130c0f3-5926-4153-87d8-85a591eed929"
        fingerprint = "38916235c68a329eea6d41dbfba466367ecc9aad2b8ae324da682a9970ec4930"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "bed3561210e44c290cd410adadcdc58462816a03c15d20b5be45d227cd7dca6b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "heck_if_targeted" ascii fullword
        $a2 = "check_command" ascii fullword
        $a3 = "askroot" ascii fullword
        $a4 = "iv_rescue_data" ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_fc2e1271 {
    meta:
        author = "Elastic Security"
        id = "fc2e1271-3c96-4c93-9e3d-212782928e6e"
        fingerprint = "195e8f65e4ea722f0e1ba171f2ad4ded97d4bc97da38ef8ac8e54b8719e4c5ae"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 30 30 30 42 67 7B 30 30 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_86f9ef0c {
    meta:
        author = "Elastic Security"
        id = "86f9ef0c-832e-4e4a-bd39-c80c1d064dbe"
        fingerprint = "e8849628ee5449c461f1170c07b6d2ebf4f75d48136f26b52bee9bcf4e164d5b"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "59fb018e338908eb69be72ab11837baebf8d96cdb289757f1f4977228e7640a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 6C 65 31 6A 6F 57 4E 33 30 30 30 30 30 33 33 00 30 72 7A 41 43 47 33 57 72 7C }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_40f9c1c3 {
    meta:
        author = "Elastic Security"
        id = "40f9c1c3-29f8-4699-8f66-9b7ddb08f92d"
        fingerprint = "27ec200781541d5b1abc96ffbb54c428b773bffa0744551bbacd605c745b6657"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "e402063ca317867de71e8e3189de67988e2be28d5d773bbaf75618202e80f9f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 7C 49 56 7C 6A 30 30 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_0f9fe37c {
    meta:
        author = "Elastic Security"
        id = "0f9fe37c-77df-4d3d-be8a-c62ea0f6863c"
        fingerprint = "2e809d95981f0ff813947f3be22ab3d3c000a0d348131d5d6c8522447818196d"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 71 6B 6E 6C 55 30 55 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_1f4bac78 {
    meta:
        author = "Elastic Security"
        id = "1f4bac78-ef2b-49cd-8852-e84d792f6e57"
        fingerprint = "e7d1e2009ff9b33d2d237068e2af41a8aa9bd44a446a2840c34955594f060120"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 32 33 4F 65 49 66 31 68 }
    condition:
        all of them
}



// from MacOS_Virus_Maxofferdeal.yar
rule MacOS_Virus_Maxofferdeal_53df500f {
    meta:
        author = "Elastic Security"
        id = "53df500f-3add-4d3d-aec3-35b7b5aa5b35"
        fingerprint = "2f41de7b8e55ef8db39bf84c0f01f8d34d67b087769b84381f2ccc3778e13b08"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_f4681eba {
    meta:
        author = "Elastic Security"
        id = "f4681eba-20f5-4e92-9f99-00cd57412c45"
        fingerprint = "b6663c326e9504510b804bd9ff0e8ace5d98826af2bb2fa2429b37171b7f399d"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { BA A4 C8 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_4091e373 {
    meta:
        author = "Elastic Security"
        id = "4091e373-c3a9-41c8-a1d8-3a77585ff850"
        fingerprint = "3d8e7db6c39286d9626c6be8bfb5da177a6a4f8ffcec83975a644aaac164a8c7"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "c38c4bdd3c1fa16fd32db06d44d0db1b25bb099462f8d2936dbdd42af325b37c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { B8 F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 8B 8E 8A BD A6 AC A4 }
    condition:
        all of them
}

rule MacOS_Virus_Maxofferdeal_20a0091e {
    meta:
        author = "Elastic Security"
        id = "20a0091e-a3ef-4a13-ba92-700f3583e06d"
        fingerprint = "1629b34b424816040066122592e56e317b204f3d5de2f5e7f68114c7a48d99cb"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Maxofferdeal"
        reference_sample = "b00a61c908cd06dbc26bee059ba290e7ce2ad6b66c453ea272c7287ffa29c5ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 A0 BC BC B8 F2 E7 E7 BF }
    condition:
        all of them
}



// from MacOS_Virus_Pirrit.yar
rule MacOS_Virus_Pirrit_271b8ed0 {
    meta:
        author = "Elastic Security"
        id = "271b8ed0-937a-4be6-aecb-62535b5aeda7"
        fingerprint = "12b09b2e3a43905db2cfe96d0fd0e735cfc7784ee7b03586c5d437d7c6a1b422"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Pirrit"
        reference_sample = "7feda05d41b09c06a08c167c7f4dde597ac775c54bf0d74a82aa533644035177"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 4A 6A 00 00 32 80 35 44 6A 00 00 75 80 35 3E 6A 00 00 1F 80 35 38 6A 00 00 }
    condition:
        all of them
}



// from MacOS_Virus_Vsearch.yar
rule MacOS_Virus_Vsearch_0dd3ec6f {
    meta:
        author = "Elastic Security"
        id = "0dd3ec6f-815f-40e1-bd53-495e0eae8196"
        fingerprint = "8adbd06894e81dc09e46d8257d4e5fcd99e714f54ffb36d5a8d6268ea25d0bd6"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Vsearch"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 2F 00 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6D 00 2F 4D 61 63 69 6E 74 6F 73 }
    condition:
        all of them
}

rule MacOS_Virus_Vsearch_2a0419f8 {
    meta:
        author = "Elastic Security"
        id = "2a0419f8-95b2-4f87-a37a-ee0b65e344e9"
        fingerprint = "2da9f0fc05bc8e23feb33b27142f46fb437af77766e39889a02ea843d52d17eb"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Vsearch"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 6F 72 6D 61 6C 2F 69 33 38 36 2F 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6F 00 }
    condition:
        all of them
}



