// from Linux_Backdoor_Bash.yar
rule Linux_Backdoor_Bash_e427876d {
    meta:
        author = "Elastic Security"
        id = "e427876d-c7c5-447a-ad6d-5cbc12d9dacf"
        fingerprint = "6cc13bb2591d896affc58f4a22b3463a72f6c9d896594fe1714b825e064b0956"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Backdoor.Bash"
        reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 67 65 44 6F 6B 4B 47 6C 6B 49 43 31 31 4B 54 6F 67 4C 32 56 }
    condition:
        all of them
}



// from Linux_Backdoor_Fontonlake.yar
rule Linux_Backdoor_Fontonlake_fe916a45 {
    meta:
        author = "Elastic Security"
        id = "fe916a45-75cc-40e4-94ad-6ac0f5d815b9"
        fingerprint = "85f16dd4a127737501863ccba006a444d899c6edc6ab03af5dddef2d39edc483"
        creation_date = "2021-10-12"
        last_modified = "2022-01-26"
        threat_name = "Linux.Backdoor.Fontonlake"
        reference_sample = "8a0a9740cf928b3bd1157a9044c6aced0dfeef3aa25e9ff9c93e113cbc1117ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = ".cmd.Upload_Passwd.PasswordInfo" fullword
        $a2 = "Upload_Passwd" fullword
        $a3 = "upload_file_beg" fullword
        $a4 = "upload_file_ing" fullword
        $a5 = "upload_file_end" fullword
        $a6 = "modify_file_attr" fullword
        $a7 = "modify_file_time" fullword
        $a8 = "import platform;print(platform.linux_distribution()[0]);print(platform.linux_distribution()[1]);print(platform.release())" fullword
        $a9 = "inject.so" fullword
        $a10 = "rm -f /tmp/%s" fullword
        $a11 = "/proc/.dot3" fullword
    condition:
        4 of them
}



// from Linux_Backdoor_Generic.yar
rule Linux_Backdoor_Generic_babf9101 {
    meta:
        author = "Elastic Security"
        id = "babf9101-1e6e-4268-a530-e99e2c905b0d"
        fingerprint = "a578b052910962523f26f14f0d0494481fe0777c01d9f6816c7ab53083a47adc"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Backdoor.Generic"
        reference_sample = "9ea73d2c2a5f480ae343846e2b6dd791937577cb2b3d8358f5b6ede8f3696b86"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 10 89 45 F4 83 7D F4 00 79 1F 83 EC 0C 68 22 }
    condition:
        all of them
}

rule Linux_Backdoor_Generic_5776ae49 {
    meta:
        author = "Elastic Security"
        id = "5776ae49-64e9-46a0-a0bb-b0226eb9a8bd"
        fingerprint = "2d36fbe1820805c8fd41b2b34a2a2b950fc003ae4f177042dc0d2568925c5b76"
        creation_date = "2021-04-06"
        last_modified = "2022-01-26"
        threat_name = "Linux.Backdoor.Generic"
        reference_sample = "e247a5decb5184fd5dee0d209018e402c053f4a950dae23be59b71c082eb910c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 18 C1 E8 08 88 47 12 8B 46 18 88 47 13 83 C4 1C 5B 5E 5F 5D }
    condition:
        all of them
}



// from Linux_Backdoor_Python.yar
rule Linux_Backdoor_Python_00606bac {
    meta:
        author = "Elastic Security"
        id = "00606bac-83eb-4a58-82d2-e4fd16d30846"
        fingerprint = "cce1d0e7395a74c04f15ff95f6de7fd7d5f46ede83322b832df74133912c0b17"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Backdoor.Python"
        reference_sample = "b3e3728d43535f47a1c15b915c2d29835d9769a9dc69eb1b16e40d5ba1b98460"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 01 83 45 F8 01 8B 45 F8 0F B6 00 84 C0 75 F2 83 45 F8 01 8B }
    condition:
        all of them
}



// from Linux_Backdoor_Tinyshell.yar
rule Linux_Backdoor_Tinyshell_67ee6fae {
    meta:
        author = "Elastic Security"
        id = "67ee6fae-304b-47f5-93b6-4086a864d433"
        fingerprint = "f71ce364fb607ee6f4422864674ae3d053453b488c139679aa485466893c563d"
        creation_date = "2021-10-12"
        last_modified = "2022-01-26"
        threat_name = "Linux.Backdoor.Tinyshell"
        reference_sample = "9d2e25ec0208a55fba97ac70b23d3d3753e9b906b4546d1b14d8c92f8d8eb03d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]" fullword
        $a2 = "s:p:c::" fullword
        $b1 = "Usage: %s [ -s secret ] [ -p port ] [command]" fullword
        $b2 = "<hostname|cb> get <source-file> <dest-dir>" fullword
    condition:
        (all of ($a*)) or (all of ($b*))
}



// from Linux_Cryptominer_Attribute.yar
rule Linux_Cryptominer_Attribute_3683d149 {
    meta:
        author = "Elastic Security"
        id = "3683d149-fa9c-4dbb-85b9-8ce2b1d1d128"
        fingerprint = "31f45578eab3c94cff52056a723773d41aaad46d529b1a2063a0610d5948a633"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Attribute"
        reference_sample = "ec9e74d52d745275718fe272bfd755335739ad5f680f73f5a4e66df6eb141a63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 74 6F 20 66 61 73 74 29 20 6F 72 20 39 20 28 61 75 74 6F }
    condition:
        all of them
}



// from Linux_Cryptominer_Bscope.yar
rule Linux_Cryptominer_Bscope_348b7fa0 {
    meta:
        author = "Elastic Security"
        id = "348b7fa0-e226-4350-8697-345ae39fa0f6"
        fingerprint = "caae9d3938f9269f8bc30e4837021513ca6e4e2edd1117d235b0d25474df5357"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Bscope"
        reference_sample = "a6fb80d77986e00a6b861585bd4e573a927e970fb0061bf5516f83400ad7c0db"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 8B 00 03 45 C0 89 02 8B 45 08 8D 50 08 8B 45 08 83 C0 08 }
    condition:
        all of them
}



// from Linux_Cryptominer_Bulz.yar
rule Linux_Cryptominer_Bulz_2aa8fbb5 {
    meta:
        author = "Elastic Security"
        id = "2aa8fbb5-b392-49fc-8f0f-12cd06d534e2"
        fingerprint = "c8fbeae6cf935fe629c37abc4fdcda2c80c1b19fc8b6185a58decead781e1321"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Bulz"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FE D7 C5 D9 72 F2 09 C5 E9 72 D2 17 C5 E9 EF D4 C5 E9 EF D6 C5 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Bulz_0998f811 {
    meta:
        author = "Elastic Security"
        id = "0998f811-7be3-4d46-9dcb-1e8a0f19bab5"
        fingerprint = "c8a83bc305998cb6256b004e9d8ce6d5d1618b107e42be139b73807462b53c31"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Bulz"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 79 70 E4 39 C5 F9 70 C9 4E C5 91 72 F0 12 C5 F9 72 D0 0E C5 91 }
    condition:
        all of them
}



// from Linux_Cryptominer_Camelot.yar
rule Linux_Cryptominer_Camelot_9ac1654b {
    meta:
        author = "Elastic Security"
        id = "9ac1654b-f2f0-4d32-8e2a-be30b3e61bb0"
        fingerprint = "156c60ee17e9b39cb231d5f0703b6e2a7e18247484f35e11d3756a025873c954"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CD 41 C1 CC 0B 31 D1 31 E9 44 89 D5 44 31 CD C1 C9 07 41 89 E8 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_dd167aa0 {
    meta:
        author = "Elastic Security"
        id = "dd167aa0-80e0-46dc-80d1-9ce9f6984860"
        fingerprint = "2642e4c4c58d95cd6ed6d38bf89b108dc978a865473af92494b6cb89f4f877e2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E7 F2 AE 4C 89 EF 48 F7 D1 48 89 CE 48 89 D1 F2 AE 48 89 C8 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_b25398dd {
    meta:
        author = "Elastic Security"
        id = "b25398dd-33cc-4ad8-b943-cd06ff7811fb"
        fingerprint = "6bdcefe93b1c36848b79cdc6b2ff79deb04012a030e5d92e725c87e520c15554"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "6fb3b77be0a66a10124a82f9ec6ad22247d7865a4d26aa49c5d602320318ce3c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 76 48 8B 44 07 23 48 33 82 C0 00 00 00 48 89 44 24 50 49 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_6a279f19 {
    meta:
        author = "Elastic Security"
        id = "6a279f19-3c9e-424b-b89e-8807f40b89eb"
        fingerprint = "1c0ead7a7f7232edab86d2ef023c853332254ce1dffe1556c821605c0a83d826"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "5b01f72b2c53db9b8f253bb98c6584581ebd1af1b1aaee62659f54193c269fca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 F3 89 D6 48 83 EC 30 48 89 E2 64 48 8B 04 25 28 00 00 00 48 89 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_4e7945a4 {
    meta:
        author = "Elastic Security"
        id = "4e7945a4-b827-4496-89d8-e63c3141c773"
        fingerprint = "bb2885705404c7d49491ab39fa8f50d85c354a43b4662b948c30635030feee74"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "b7504ce57787956e486d951b4ff78d73807fcc2a7958b172febc6d914e7a23a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 81 EC A0 00 00 00 48 89 7D F0 48 8B 7D F0 48 89 F8 48 05 80 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_29c1c386 {
    meta:
        author = "Elastic Security"
        id = "29c1c386-c09c-4a58-b454-fc8feb78051d"
        fingerprint = "2ad8d0d00002c969c50fde6482d797d76d60572db5935990649054b5a103c5d1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 65 20 62 72 61 6E 63 68 00 00 00 49 67 6E 6F 72 69 6E 67 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_25b63f54 {
    meta:
        author = "Elastic Security"
        id = "25b63f54-8a32-4866-8f90-b2949f5e7539"
        fingerprint = "c0bc4f5fc0ad846a90e214dfca8252bf096463163940930636c1693c7f3833fa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 6F 39 66 41 0F 6F 32 66 4D 0F 7E C3 66 44 0F D4 CB 66 45 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_73e2373e {
    meta:
        author = "Elastic Security"
        id = "73e2373e-75ac-4385-b663-a50423626fc8"
        fingerprint = "6ce73e55565e9119a355b91ec16c2147cc698b1a57cc29be22639b34ba39eea9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 83 7D F8 00 74 4D 48 8B 55 80 48 8D 45 A0 48 89 D6 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_b8552fff {
    meta:
        author = "Elastic Security"
        id = "b8552fff-29a9-4e09-810a-b4b52a7a3fb4"
        fingerprint = "d5998e0bf7df96dd21d404658589fb37b405398bd3585275419169b30c72ce62"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 18 8B 44 24 1C 8B 50 0C 83 E8 04 8B 0A FF 74 24 28 FF 74 24 28 FF 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_83550472 {
    meta:
        author = "Elastic Security"
        id = "83550472-4c97-4afc-b187-1a7ffc9acbbc"
        fingerprint = "63cf1cf09ad06364e1b1f15774400e0544dbb0f38051fc795b4fc58bd08262d1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FA 48 8D 4A 01 48 D1 E9 48 01 CA 48 29 F8 48 01 C3 49 89 C4 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_8799d8d6 {
    meta:
        author = "Elastic Security"
        id = "8799d8d6-714b-4837-be60-884d78e3b8f3"
        fingerprint = "05c8d7c1d11352f2ec0b5d96a7b2378391ad9f8ae285a1299111aca38352f707"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "4a6d98eae8951e5b9e0a226f1197732d6d14ed45c1b1534d3cdb4413261eb352"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 56 66 48 32 37 48 4D 5A 75 6D 74 46 75 4A 72 6D 48 47 38 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_0f7c5375 {
    meta:
        author = "Elastic Security"
        id = "0f7c5375-99dc-4204-833a-9128798ed2e9"
        fingerprint = "53bb31c6ba477ed86e55ce31844055c26d7ab7392d78158d3f236d621181ca10"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "e75be5377ad65abdc69e6c7f9fe17429a98188a217d0ca3a6f40e75c4f0c07e8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 7F 48 89 85 C0 00 00 00 77 08 48 83 85 C8 00 00 00 01 31 F6 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_87639dbd {
    meta:
        author = "Elastic Security"
        id = "87639dbd-da2d-4cf9-a058-16f4620a5a7f"
        fingerprint = "c145df0a671691ef2bf17644ec7c33ebb5826d330ffa35120d4ba9e0cb486282"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 00 48 83 C2 01 48 89 EF 48 89 53 38 FF 50 18 48 8D 7C 24 30 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_cdd631c1 {
    meta:
        author = "Elastic Security"
        id = "cdd631c1-2c03-47dd-b50a-e8c0b9f67271"
        fingerprint = "fa174ac25467ab6e0f11cf1f0a5c6bf653737e9bbdc9411aabeae460a33faa5e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "91549c171ae7f43c1a85a303be30169932a071b5c2b6cf3f4913f20073c97897"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 5F 5A 4E 35 78 6D 72 69 67 35 50 6F 6F 6C 73 }
    condition:
        all of them
}

rule Linux_Cryptominer_Camelot_209b02dd {
    meta:
        author = "Elastic Security"
        id = "209b02dd-3087-475b-8d28-baa18647685b"
        fingerprint = "5829daea974d581bb49ac08150b63b7b24e6fae68f669b6b7ab48418560894d4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Camelot"
        reference_sample = "60d33d1fdabc6b10f7bb304f4937051a53d63f39613853836e6c4d095343092e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 31 F5 44 0B 5C 24 F4 41 C1 EA 10 44 0B 54 24 }
    condition:
        all of them
}



// from Linux_Cryptominer_Casdet.yar
rule Linux_Cryptominer_Casdet_5d0d33be {
    meta:
        author = "Elastic Security"
        id = "5d0d33be-e53e-4188-9957-e1af2a802867"
        fingerprint = "2d584f6815093d37bd45a01146034d910b95be51462f01f0d4fc4a70881dfda6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Casdet"
        reference_sample = "4b09115c876a8b610e1941c768100e03c963c76b250fdd5b12a74253ef9e5fb6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 EB 05 48 89 C3 EB CF 48 8B BC 24 A0 00 00 00 48 85 FF 74 D7 48 }
    condition:
        all of them
}



// from Linux_Cryptominer_Ccminer.yar
rule Linux_Cryptominer_Ccminer_18fc60e5 {
    meta:
        author = "Elastic Security"
        id = "18fc60e5-680c-4ff6-8a76-12cc3ae9cd3d"
        fingerprint = "461e942fcaf5faba60c3dc39d8089f9d506ff2daacb2a22573fb35bcfee9b6f1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Ccminer"
        reference_sample = "dbb403a00c75ef2a74b41b8b58d08a6749f37f922de6cc19127a8f244d901c60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 68 27 52 22 02 02 32 22 22 03 5C 8B AE 00 00 00 48 03 5C }
    condition:
        all of them
}

rule Linux_Cryptominer_Ccminer_3c593bc3 {
    meta:
        author = "Elastic Security"
        id = "3c593bc3-cb67-41da-bef1-aad9e73c34f7"
        fingerprint = "0a382ef73d3b5d1b1ad223c66fc367cc5b6f2b23a9758002045076234f257dfe"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Ccminer"
        reference_sample = "dbb403a00c75ef2a74b41b8b58d08a6749f37f922de6cc19127a8f244d901c60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 83 5C DE C2 00 00 00 68 03 5C EB EA 00 00 00 48 03 1C DC }
    condition:
        all of them
}



// from Linux_Cryptominer_Flystudio.yar
rule Linux_Cryptominer_Flystudio_579a3a4d {
    meta:
        author = "Elastic Security"
        id = "579a3a4d-ddb0-4f73-9224-16fba973d624"
        fingerprint = "148b27046f72a7645ebced9f76424ffd7b368347311b04c9357d5d4ea8d373fb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Flystudio"
        reference_sample = "84afc47554cf42e76ef8d28f2d29c28f3d35c2876cec2fb1581b0ac7cfe719dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EF C1 66 0F 72 F1 05 66 0F EF C2 66 0F EF C1 66 0F 6F CD 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Flystudio_0a370634 {
    meta:
        author = "Elastic Security"
        id = "0a370634-51de-46bf-9397-c41ef08a7b83"
        fingerprint = "6613ddd986e2bf4b306cd1a5c28952da8068f1bb533c53557e2e2add5c2dbd1f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Flystudio"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 D7 19 66 41 0F EF E9 66 0F EF EF 66 0F 6F FD 66 41 0F FE FD 66 44 0F }
    condition:
        all of them
}



// from Linux_Cryptominer_Generic.yar
rule Linux_Cryptominer_Generic_d7bd0e5d {
    meta:
        author = "Elastic Security"
        id = "d7bd0e5d-3528-4648-aaa5-6cf44d22c0d5"
        fingerprint = "fbc06c7603aa436df807ad3f77d5ba783c4d33f61b06a69e8641741068f3a543"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "afcfd67af99e437f553029ccf97b91ed0ca891f9bcc01c148c2b38c75482d671"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CF 99 67 D8 37 AA 24 80 F2 F3 47 6A A5 5E 88 50 F1 28 61 18 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_69e1a763 {
    meta:
        author = "Elastic Security"
        id = "69e1a763-1e0d-4448-9bc4-769f3a36ac10"
        fingerprint = "9007ab73902ef9bfa69e4ddc29513316cb6aa7185986cdb10fd833157cd7d434"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b04d9fabd1e8fc42d1fa8e90a3299a3c36e6f05d858dfbed9f5e90a84b68bcbb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 43 08 49 89 46 08 48 8B 43 10 49 89 46 10 48 85 C0 74 8A F0 83 40 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_397a86bd {
    meta:
        author = "Elastic Security"
        id = "397a86bd-6d66-4db0-ad41-d0ae3dbbeb21"
        fingerprint = "0bad343f28180822bcb45b0a84d69b40e26e5eedb650db1599514020b6736dd0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "79c47a80ecc6e0f5f87749319f6d5d6a3f0fbff7c34082d747155b9b20510cde"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 4F 48 8B 75 00 48 8B 4D 08 4C 89 F7 48 8B 55 10 48 8B 45 18 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_37c3f8d3 {
    meta:
        author = "Elastic Security"
        id = "37c3f8d3-9d79-434c-b0e8-252122ebc62a"
        fingerprint = "6ba0bae987db369ec6cdadf685b8c7184e6c916111743f1f2b43ead8d028338c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "efbddf1020d0845b7a524da357893730981b9ee65a90e54976d7289d46d0ffd4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 4C 01 F0 49 8B 75 08 48 01 C3 49 39 F4 74 29 48 89 DA 4C }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_28a80546 {
    meta:
        author = "Elastic Security"
        id = "28a80546-ae74-4616-8896-50f54da66650"
        fingerprint = "7f49f04ba36e7ff38d313930c469d64337203a60792f935a3548cee176ae9523"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "96cc225cf20240592e1dcc8a13a69f2f97637ed8bc89e30a78b8b2423991d850"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 59 D4 B5 63 E2 4D B6 08 EF E8 0A 3A B1 AD 1B 61 6E 7C 65 D1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9d531f70 {
    meta:
        author = "Elastic Security"
        id = "9d531f70-c42f-4e1a-956a-f9ac43751e73"
        fingerprint = "2c6019f7bc2fc47d7002e0ba6e35513950260b558f1fdc732d3556dabbaaa93d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 10 58 00 10 D4 34 80 08 30 01 20 02 00 B1 00 83 49 23 16 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_23a5c29a {
    meta:
        author = "Elastic Security"
        id = "23a5c29a-6a8f-46f4-87ba-2a60139450ce"
        fingerprint = "1a7a86ff6e1666c2da6e6f65074bb1db2fe1c97d1ad42d1f670dd5c88023eecf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 48 29 D0 48 01 C0 4D 8B 39 48 29 C1 49 29 F8 48 8D 04 C9 4D 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_ea5703ce {
    meta:
        author = "Elastic Security"
        id = "ea5703ce-4ad4-46cc-b253-8d022ca385a3"
        fingerprint = "a58a41ab4602380c0989659127d099add042413f11e3815a5e1007a44effaa68"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "bec6eea63025e2afa5940d27ead403bfda3a7b95caac979079cabef88af5ee0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 94 C0 EB 05 B8 01 00 00 00 44 21 E8 48 8B 4C 24 08 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_6a4f4255 {
    meta:
        author = "Elastic Security"
        id = "6a4f4255-d202-48b7-96ae-cb7211dcbea3"
        fingerprint = "0ed37d7eccd4e36b954824614b976e1371c3b2ffe318345d247198d387a13de6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 48 8D 5D 01 4C 8D 14 1B 48 C1 E3 05 4C 01 EB 4D 8D 7A FF F2 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9088d00b {
    meta:
        author = "Elastic Security"
        id = "9088d00b-622a-4cbf-9600-6dfcf2fc0c2c"
        fingerprint = "85cbe86b9f96fc1b6899b35cc4aa16b66a91dc1239ed5f5cf3609322cec30f30"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "8abb2b058ec475b0b6fd0c994685db72e98d87ee3eec58e29cf5c324672df04a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2C 1C 77 16 48 8B 44 24 08 64 48 33 04 25 28 00 00 00 75 24 48 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_71024c4a {
    meta:
        author = "Elastic Security"
        id = "71024c4a-e8da-44fc-9cf9-c71829dfe87a"
        fingerprint = "dbbb74ec687e8e9293dfa2272d55b81ef863a50b0ff87daf15aaf6cee473efe6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "afe81c84dcb693326ee207ccd8aeed6ed62603ad3c8d361e8d75035f6ce7c80f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 08 48 89 45 08 48 8B 46 10 48 85 C0 48 89 45 10 74 BC F0 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_d81368a3 {
    meta:
        author = "Elastic Security"
        id = "d81368a3-00ca-44cf-b009-718272d389eb"
        fingerprint = "dd463df2c03389af3e7723fda684b0f42342817b3a76664d131cf03542837b8a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "71225e4702f2e0a0ecf79f7ec6c6a1efc95caf665fda93a646519f6f5744990b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CB 49 C1 E3 04 49 01 FB 41 8B 13 39 D1 7F 3F 7C 06 4D 3B 43 08 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_97e9cebe {
    meta:
        author = "Elastic Security"
        id = "97e9cebe-d30b-49f6-95f4-fd551e7a42e4"
        fingerprint = "61bef39d174d97897ac0820b624b1afbfe73206208db420ae40269967213ebed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b4ff62d92bd4d423379f26b37530776b3f4d927cc8a22bd9504ef6f457de4b7a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 04 25 28 00 00 00 48 89 44 24 58 31 C0 49 83 FF 3F 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_98ff0f36 {
    meta:
        author = "Elastic Security"
        id = "98ff0f36-5faf-417a-9431-8a44e9f088f4"
        fingerprint = "b25420dfc32522a060dc8470315409280e3c03de0b347e92a5bc6c1a921af94a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "4c14aaf05149bb38bbff041432bf9574dd38e851038638aeb121b464a1e60dcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 A8 8B 00 89 C2 48 8B 45 C8 48 01 C2 8B 45 90 48 39 C2 7E 08 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1512cf40 {
    meta:
        author = "Elastic Security"
        id = "1512cf40-ae62-40cf-935d-589be4fe3d93"
        fingerprint = "f9800996d2e6d9ea8641d51aedc554aa732ebff871f0f607bb3fe664914efd5a"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "fc063a0e763894e86cdfcd2b1c73d588ae6ecb411c97df2a7a802cd85ee3f46d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 10 5B C3 E8 35 A7 F6 FF 0F 1F 44 00 00 53 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_0d6005a1 {
    meta:
        author = "Elastic Security"
        id = "0d6005a1-a481-4679-a214-f1e3ef8bf1d0"
        fingerprint = "435040ec452d337c60435b07622d3a8af8e3b7e8eb6ec2791da6aae504cc2266"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "230d46b39b036552e8ca6525a0d2f7faadbf4246cdb5e0ac9a8569584ef295d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 79 73 00 6E 6F 5F 6D 6C 63 6B 00 77 61 72 6E 00 6E 65 76 65 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e1ff020a {
    meta:
        author = "Elastic Security"
        id = "e1ff020a-446c-4537-8cc3-3bcc56ba5a99"
        fingerprint = "363872fe6ef89a0f4c920b1db4ac480a6ae70e80211200b73a804b43377fff01"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "5b611898f1605751a3d518173b5b3d4864b4bb4d1f8d9064cc90ad836dd61812"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F B6 4F 3D 0B 5C 24 F4 41 C1 EB 10 44 0B 5C 24 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_102d6f7c {
    meta:
        author = "Elastic Security"
        id = "102d6f7c-0e77-4b23-9e84-756aba929d83"
        fingerprint = "037b1da31ffe66015c959af94d89eef2f7f846e1649e4415c31deaa81945aea9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "bd40c2fbf775e3c8cb4de4a1c7c02bc4bcfa5b459855b2e5f1a8ab40f2fb1f9e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 70 D2 AA C5 F9 EF D2 C5 F1 EF CB C5 E1 73 FB 04 C4 E3 79 DF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_9c8f3b1a {
    meta:
        author = "Elastic Security"
        id = "9c8f3b1a-0273-4164-ba48-b0bc090adf9e"
        fingerprint = "a35efe6bad4e0906032ab2fd7c776758e71caed8be402948f39682cf1f858005"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "74d8344139c5deea854d8f82970e06fc6a51a6bf845e763de603bde7b8aa80ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F 67 31 70 00 6C 6F 67 32 66 00 6C 6C 72 6F 75 6E 64 00 73 71 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_76cb94a9 {
    meta:
        author = "Elastic Security"
        id = "76cb94a9-5a3f-483c-91f3-aa0e3c27f7ba"
        fingerprint = "623a33cc95af46b8f0d557c69f8bf72db7c57fe2018b7a911733be4ddd71f073"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "1320d7a2b5e3b65fe974a95374b4ea7ed1a5aa27d76cd3d9517d3a271121103f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8C 24 98 00 00 00 31 C9 80 7A 4A 00 48 89 74 24 18 48 89 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_616afaa1 {
    meta:
        author = "Elastic Security"
        id = "616afaa1-7679-4198-9e80-c3f044b3c07d"
        fingerprint = "fd6afad9f318ce00b0f0f8be3a431a2c7b4395dd69f82328f4555b3715a8b298"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "0901672d2688660baa26fdaac05082c9e199c06337871d2ae40f369f5d575f71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4B 04 31 C0 41 8B 14 07 89 14 01 48 83 C0 04 48 83 F8 14 75 EF 4C 8D 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_18af74b2 {
    meta:
        author = "Elastic Security"
        id = "18af74b2-99fe-42fc-aacd-7887116530a8"
        fingerprint = "07a6b44ff1ba6143c76e7ccb3885bd04e968508e93c5f8bff9bc5efc42a16a96"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "52707aa413c488693da32bf2705d4ac702af34faee3f605b207db55cdcc66318"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 70 6F 77 00 6C 6F 67 31 70 00 6C 6F 67 32 66 00 63 65 69 6C 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1b76c066 {
    meta:
        author = "Elastic Security"
        id = "1b76c066-463c-46e5-8a08-ccfc80e3f399"
        fingerprint = "e33937322a1a2325539d7cdb1df13295e5ca041a513afe1d5e0941f0c66347dd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "f60302de1a0e756e3af9da2547a28da5f57864191f448e341af1911d64e5bc8b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 14 89 0C 10 48 83 C2 04 48 83 FA 20 75 EF 48 8D 8C 24 F0 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b6ea5ee1 {
    meta:
        author = "Elastic Security"
        id = "b6ea5ee1-ede5-4fa3-a065-99219b3530da"
        fingerprint = "07c2f1fcb50ce5bcdebfc03fca4aaacdbabab42a857d7cc8f008712ca576b871"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 20 49 8D 77 20 4C 89 74 24 10 4C 89 6C 24 18 4C 89 64 24 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_050ac14c {
    meta:
        author = "Elastic Security"
        id = "050ac14c-9aef-4212-97fd-e2a21c2f62e2"
        fingerprint = "6f0a5a5d3cece7ae8db47ef5e1bbbea02b886e865f23b0061c2d346feb351663"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "36f2ce4e34faf42741f0a15f62e8b3477d69193bf289818e22d0e3ee3e906eb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 08 49 3B 47 10 74 3C 48 85 C0 74 16 48 8B 13 48 89 10 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_df937caa {
    meta:
        author = "Elastic Security"
        id = "df937caa-ca6c-4a80-a68c-c265dab7c02c"
        fingerprint = "963642e141db6c55bd8251ede57b38792278ded736833564ae455cc553ab7d24"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "19b442c9aa229cd724ed9cbaa73f9dfaf0ed61aa3fd1bee7bf8ba964fc23a2b8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 62 20 0A 10 02 0A 14 60 29 00 02 0C 24 14 60 7D 44 01 70 01 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e9ff82a8 {
    meta:
        author = "Elastic Security"
        id = "e9ff82a8-b8ca-45fb-9738-3ce0c452044f"
        fingerprint = "91e78b1777a0580f25f7796aa6d9bcbe2cbad257576924aecfe513b1e1206915"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "62ea137e42ce32680066693f02f57a0fb03483f78c365dffcebc1f992bb49c7a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D9 4D 01 CA 4C 89 74 24 D0 4C 8B 74 24 E8 4D 31 D4 49 C1 C4 20 48 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_a5267ea3 {
    meta:
        author = "Elastic Security"
        id = "a5267ea3-b98c-49e9-8051-e33a101f12d3"
        fingerprint = "8391a4dbc361eec2877852acdc77681b3a15922d9a047d7ad12d06271d53f540"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "b342ceeef58b3eeb7a312038622bcce4d76fc112b9925379566b24f45390be7d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EE 6A 00 41 B9 01 00 00 00 48 8D 4A 13 4C 89 E7 88 85 40 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_4e9075e6 {
    meta:
        author = "Elastic Security"
        id = "4e9075e6-3ca9-459e-9f5f-3e614fd4f1c8"
        fingerprint = "70d8c4ecb185b8817558ad9d26a47c340c977abb6abfca8efe1ff99efb43c579"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "098bf2f1ce9d7f125e1c9618f349ae798a987316e95345c037a744964277f0fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2C 24 74 67 48 89 5C 24 18 4C 89 6C 24 20 4C 89 FB 4D 89 E5 4C 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_3a8d0974 {
    meta:
        author = "Elastic Security"
        id = "3a8d0974-384e-4d62-9aa8-0bd8f7d50206"
        fingerprint = "60cb81033461e73fcb0fb8cafd228e2c9478c132f49e115c5e55d5579500caa2"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference = "193fe9ea690759f8e155458ef8f8e9efe9efc8c22ec8073bbb760e4f96b5aef7"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 07 41 89 34 06 48 83 C0 04 48 83 F8 20 75 EF 8B 42 D4 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b9e6ffdf {
    meta:
        author = "Elastic Security"
        id = "b9e6ffdf-4b2b-4052-9c91-a06f43a2e7b8"
        fingerprint = "fdd91d5802d5807d52f4c9635e325fc0765bb54cf51305c7477d2b791f393f3e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "c0f3200a93f1be4589eec562c4f688e379e687d09c03d1d8850cc4b5f90f192a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D8 48 83 C4 20 5B C3 0F 1F 00 BF ?? ?? 40 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_7ef74003 {
    meta:
        author = "Elastic Security"
        id = "7ef74003-cd1f-4f2f-9c96-4dbcabaa36e4"
        fingerprint = "187fd82b91ae6eadc786cadac75de5d919a2b8a592037a5bf8da2efa2539f507"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "a172cfecdec8ebd365603ae094a16e247846fdbb47ba7fd79564091b7e8942a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 45 31 F6 41 55 49 89 F5 41 54 44 8D 67 01 55 4D 63 E4 53 49 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_1d0700b8 {
    meta:
        author = "Elastic Security"
        id = "1d0700b8-1bc0-4da2-a903-9d78e79e71d8"
        fingerprint = "19853be803f82e6758554a57981e1b52c43a017ab88242c42a7c39f6ead01cf3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 30 42 30 42 00 22 22 03 5C DA 10 00 C0 00 60 43 9C 64 48 00 00 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_55beb2ee {
    meta:
        author = "Elastic Security"
        id = "55beb2ee-7306-4134-a512-840671cc4490"
        fingerprint = "707a1478f86da2ec72580cfe4715b466e44c345deb6382b8dc3ece4e3935514d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "edda1c6b3395e7f14dd201095c1e9303968d02c127ff9bf6c76af6b3d02e80ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 FC 00 00 00 8B 84 24 C0 00 00 00 0F 29 84 24 80 00 00 00 0F 11 94 24 C4 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_fdd7340f {
    meta:
        author = "Elastic Security"
        id = "fdd7340f-49d6-4770-afac-24104a3c2f86"
        fingerprint = "cc302eb6c133901cc3aa78e6ca0af16a620eb4dabb16b21d9322c4533f11d25f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EA 48 89 DE 48 8D 7C 24 08 FF 53 18 48 8B 44 24 08 48 83 78 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e36a35b0 {
    meta:
        author = "Elastic Security"
        id = "e36a35b0-cb38-4d2d-bca2-f3734637faa8"
        fingerprint = "0ee42ff704c82ee6c2bc0408cccb77bcbae8d4405bb1f405ee09b093e7a626c0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "ab6d8f09df67a86fed4faabe4127cc65570dbb9ec56a1bdc484e72b72476f5a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 71 F2 08 66 0F EF C1 66 0F EF D3 66 0F 7F 44 24 60 66 0F 7F 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_6dad0380 {
    meta:
        author = "Elastic Security"
        id = "6dad0380-7771-4fb9-a7e5-176eeb6fcfd7"
        fingerprint = "ffe022f42e98c9c1eeb3aead0aca9d795200b4b22f89e7f3b03baf96f18c9473"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "628b1cc8ccdbe2ae0d4ef621da047e07e2532d00fe3d4da65f0a0bcab20fb546"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 C1 E6 05 48 01 C6 48 39 F1 74 05 49 89 74 24 08 44 89 E9 48 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e73f501e {
    meta:
        author = "Elastic Security"
        id = "e73f501e-019c-4281-ae93-acde7ad421af"
        fingerprint = "bd9e6f2548c918b2c439a047410b6b239c3993a3dbd85bfd70980c64d11a6c5c"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "2f646ced4d05ba1807f8e08a46ae92ae3eea7199e4a58daf27f9bd0f63108266"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 51 8A 92 FF F3 20 01 DE 63 AF 8B 54 73 0A 65 83 64 88 60 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_5e56d076 {
    meta:
        author = "Elastic Security"
        id = "5e56d076-0d6d-4979-8ebc-52607dcdb42d"
        fingerprint = "e9ca9b9faee091afed534b89313d644a52476b4757663e1cdfbcbca379857740"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "32e1cb0369803f817a0c61f25ca410774b4f37882cab966133b4f3e9c74fac09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 71 18 4C 89 FF FF D0 48 8B 84 24 A0 00 00 00 48 89 43 60 48 8B 84 24 98 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_54357231 {
    meta:
        author = "Elastic Security"
        id = "54357231-23d8-44f5-94d7-71da02a8ba38"
        fingerprint = "8bbba49c863bc3d53903b1a204851dc656f3e3d68d3c8d5a975ed2dc9e797e13"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 F2 06 C5 F9 EB C2 C4 E3 79 16 E0 02 C4 E3 79 16 E2 03 C5 F9 70 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_467c4d46 {
    meta:
        author = "Elastic Security"
        id = "467c4d46-3272-452c-9251-3599d16fc916"
        fingerprint = "cbde94513576fdb7cabf568bd8439f0194d6800373c3735844e26d262c8bc1cc"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 8B 77 08 48 21 DE 4C 39 EE 75 CE 66 41 83 7F 1E 04 4C 89 F5 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_e0cca9dc {
    meta:
        author = "Elastic Security"
        id = "e0cca9dc-0f3e-42d8-bb43-0625f4f9bfe1"
        fingerprint = "e7bc17ba356774ed10e65c95a8db3b09d3b9be72703e6daa9b601ea820481db7"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 40 48 8D 94 24 C0 00 00 00 F3 41 0F 6F 01 48 89 7C 24 50 48 89 74 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_36e404e2 {
    meta:
        author = "Elastic Security"
        id = "36e404e2-be7c-40dc-b861-8ab929cad019"
        fingerprint = "7268b94d67f586ded78ad3a52b23a81fd4edb866fedd0ab1e55997f1bbce4c72"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 61 6C 73 65 20 70 6F 73 69 74 69 76 65 29 1B 5B 30 6D 00 44 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_947dcc5e {
    meta:
        author = "Elastic Security"
        id = "947dcc5e-be4c-4d31-936f-63d466db2934"
        fingerprint = "f6087a90a9064b505b60a1c53af008b025064f4a823501cae5f00bbe5157d67b"
        creation_date = "2024-04-19"
        last_modified = "2024-06-12"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "7c5a6ac425abe60e8ea5df5dfa8211a7c34a307048b4e677336b735237dcd8fd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 28 00 00 0A 30 51 9F E5 04 20 94 E5 04 30 A0 E1 38 00 44 E2 00 40 94 E5 00 40 82 E5 04 20 93 E5 04 20 84 E5 0C 20 13 E5 00 30 83 E5 04 00 12 E3 04 30 83 E5 06 00 00 0A 04 10 C2 E3 08 00 12 E3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Generic_b4c2d007 {
    meta:
        author = "Elastic Security"
        id = "b4c2d007-9464-4b72-ae2d-b0f1aeaa6fca"
        fingerprint = "364fa077b99cd32d790399fd9f06f99ffef19c37487ef8a4fd81bf36988ecaa6"
        creation_date = "2024-04-19"
        last_modified = "2024-06-12"
        threat_name = "Linux.Cryptominer.Generic"
        reference_sample = "e1e518ba226d30869e404b92bfa810bae27c8b1476766934961e80c44e39c738"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 03 00 91 F3 53 01 A9 F4 03 00 AA 20 74 40 F9 60 17 00 B4 20 10 42 79 F3 03 01 AA F9 6B 04 A9 40 17 00 34 62 62 40 39 F5 5B 02 A9 26 10 40 39 F7 63 03 A9 63 12 40 B9 FB 73 05 A9 3B A0 03 91 }
    condition:
        all of them
}



// from Linux_Cryptominer_Ksmdbot.yar
rule Linux_Cryptominer_Ksmdbot_ebeedb3c {
    meta:
        author = "Elastic Security"
        id = "ebeedb3c-adc3-4df8-a8bf-5120802fa3c2"
        fingerprint = "c6b678a94e45441ef960bc7119e2b9742ce8aab7e463897bf4a14aa0c57d507c"
        creation_date = "2022-12-14"
        last_modified = "2024-02-13"
        threat_name = "Linux.Cryptominer.Ksmdbot"
        reference_sample = "b927e0fe58219305d86df8b3e44493a7c854a6ea4f76d1ebe531a7bfd4365b54"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 BA 74 63 70 66 69 76 65 6D 4? 8B ?? 24 }
        $a2 = { 48 B9 FF FF FF FF 67 65 74 73 48 89 08 48 B9 65 74 73 74 61 74 75 73 48 89 48 }
        $a3 = { 48 B? 73 74 61 72 74 6D 69 6E 49 39 ?3 }
        $a4 = { 48 BA 6C 6F 61 64 63 6C 69 65 48 8B B4 24 }
        $a5 = { 48 BA 73 74 6? 7? 7? 6? 6? 6E 49 39 13 }
    condition:
        3 of them
}



// from Linux_Cryptominer_Loudminer.yar
rule Linux_Cryptominer_Loudminer_581f57a9 {
    meta:
        author = "Elastic Security"
        id = "581f57a9-36e0-4b95-9a1e-837bdd4aceab"
        fingerprint = "1013e6e11ea2a30ecf9226ea2618a59fb08588cdc893053430e969fbdf6eb675"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 44 24 08 48 8B 70 20 48 8B 3B 48 83 C3 08 48 89 EA 48 8B 07 FF }
    condition:
        all of them
}

rule Linux_Cryptominer_Loudminer_f2298a50 {
    meta:
        author = "Elastic Security"
        id = "f2298a50-7bd4-43d8-ac84-b36489405f2e"
        fingerprint = "8eafc1c995c0efb81d9ce6bcc107b102551371f3fb8efdf8261ce32631947e03"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B6 04 07 41 8D 40 D0 3C 09 76 AD 41 8D 40 9F 3C 05 76 A1 41 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Loudminer_851fc7aa {
    meta:
        author = "Elastic Security"
        id = "851fc7aa-6514-4f47-b6b5-a1e730b5d460"
        fingerprint = "e4d78229c1877a023802d7d99eca48bffc55d986af436c8a1df7c6c4e5e435ba"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Loudminer"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 8B 45 00 4C 8B 40 08 49 8D 78 18 49 89 FA 49 29 D2 49 01 C2 4C }
    condition:
        all of them
}



// from Linux_Cryptominer_Malxmr.yar
rule Linux_Cryptominer_Malxmr_d13544d7 {
    meta:
        author = "Elastic Security"
        id = "d13544d7-4834-4ce7-9339-9c933ee51b2c"
        fingerprint = "02e1be4a7073e849b183851994c83f1f2077fe74cbcdd0b3066999d0c9499a09"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 51 50 4D 21 EB 4B 8D 0C 24 4C 89 54 24 90 4C 89 DD 48 BA AA AA AA AA AA AA }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_ad09e090 {
    meta:
        author = "Elastic Security"
        id = "ad09e090-098e-461d-b967-e45654b902bb"
        fingerprint = "a62729bbe04eca01dbb3c56de63466ed115f30926fc5d203c9bae75a93227e09"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 50 8B 44 24 64 89 54 24 54 39 C3 77 0E 72 08 8B 44 24 60 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_12299814 {
    meta:
        author = "Elastic Security"
        id = "12299814-c916-4cad-a627-f8b082f5643d"
        fingerprint = "b626f04a8648b0f42564df9c2ef3989e602d1307b18256e028450c495dc15260"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "eb3802496bd2fef72bd2a07e32ea753f69f1c2cc0b5a605e480f3bbb80b22676"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3C 40 00 83 C4 10 89 44 24 04 80 7D 00 00 74 97 83 EC 0C 89 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_a47b77e4 {
    meta:
        author = "Elastic Security"
        id = "a47b77e4-0d8d-4714-8527-7b783f0f27b8"
        fingerprint = "635a35defde186972cd6626bd75a1e557a1a9008ab93b38ef1a3635b3210354b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "995b43ccb20343494e314824343a567fd85f430e241fdeb43704d9d4937d76cc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D 48 49 5E 97 87 DC 73 86 19 51 B3 36 1A 6E FC 8C CC 2C 6E 0B }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_21d0550b {
    meta:
        author = "Elastic Security"
        id = "21d0550b-4f15-4481-ba9c-2be26ea8f81a"
        fingerprint = "5b556d2e3e48fda57c741c4c7b9efb72aad579e5055df366cdb9cfa38e496494"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3B 31 C0 48 83 C9 FF 48 89 EE F2 AE 48 8B 3B 48 F7 D1 48 FF C9 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_c8adb449 {
    meta:
        author = "Elastic Security"
        id = "c8adb449-3de5-4cdd-9b62-fe4bcbe82394"
        fingerprint = "838950826835e811eb7ea3af7a612b4263d171ded4761d2b547a4012adba4028"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "00ec7a6e9611b5c0e26c148ae5ebfedc57cf52b21e93c2fe3eac85bf88edc7ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D2 4C 89 54 24 A0 4C 89 FA 48 F7 D2 48 23 54 24 88 49 89 D2 48 8B 54 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_bcab1e8f {
    meta:
        author = "Elastic Security"
        id = "bcab1e8f-8a8f-4309-8e47-416861d1894c"
        fingerprint = "2106f2ba97c75468a2f25d1266053791034ff9a15d57df1ba3caf21f74b812f7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "19df7fd22051abe3f782432398ea30f8be88cf42ef14bc301b1676f35b37cd7e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EB D9 D3 0B EB D5 29 0B EB D1 03 48 6C 01 0B EB CA 0F AF 0B }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_6671f33a {
    meta:
        author = "Elastic Security"
        id = "6671f33a-03bb-40d8-b439-64a66082457d"
        fingerprint = "cb178050ee351059b083c6a71b5b1b6a9e0aa733598a05b3571701949b4e6b28"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "85fa30ba59602199fd99463acf50bd607e755c2e18cd8843ffcfb6b1aca24bb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4D 18 48 01 4B 18 5A 5B 5D C3 83 C8 FF C3 48 85 FF 49 89 F8 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_74418ec5 {
    meta:
        author = "Elastic Security"
        id = "74418ec5-f84a-4d79-b1b0-c1d579ad7b97"
        fingerprint = "ec14cac86b2b0f75f1d01b7fb4b57bfa3365f8e4d11bfed2707b0174875d1234"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "d79ad967ac9fc0b1b6d54e844de60d7ba3eaad673ee69d30f9f804e5ccbf2880"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 75 7A A8 8A 65 FC 5C E0 6E 09 4B 8F AA B3 A4 66 44 B1 D1 13 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_979160f6 {
    meta:
        author = "Elastic Security"
        id = "979160f6-402a-4e4b-858a-374c9415493b"
        fingerprint = "fb933702578e2cf7e8ad74554ef93c07b610d6da8bc5743cbf86c363c1615f40"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 08 C1 ED 10 41 31 C3 89 D8 45 09 D0 C1 E8 10 C1 E3 10 41 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_fe7139e5 {
    meta:
        author = "Elastic Security"
        id = "fe7139e5-3c8e-422c-aaf7-e683369d23d4"
        fingerprint = "4af38ca3ec66ca86190e6196a9a4ba81a0a2b77f88695957137f6cda8fafdec9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "8b13dc59db58b6c4cd51abf9c1d6f350fa2cb0dbb44b387d3e171eacc82a04de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 74 5B 48 29 F9 49 89 DC 4C 8D 69 01 49 D1 ED 4C 01 E9 4D 8D 6C }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_f35a670c {
    meta:
        author = "Elastic Security"
        id = "f35a670c-7599-4c93-b08b-463c4a93808a"
        fingerprint = "9064024118d30d89bdc093d5372a0d9fefd43eb1ac6359dbedcf3b73ba93f312"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "a73808211ba00b92f8d0027831b3aa74db15f068c53dd7f20fcadb294224f480"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 01 CD 48 0F AF D6 48 8D 54 55 00 89 DD 48 31 D7 48 C1 C7 20 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_70e5946e {
    meta:
        author = "Elastic Security"
        id = "70e5946e-3e73-4b07-9e7d-af036a3242f9"
        fingerprint = "ced6885fda17c862753232fde3e7e8797f5a900ebab7570b78aa7138a0068eb9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "2c2729395805fc9d3c1e654c9a065bbafc4f28d8ab235afaae8d2c484060596b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4F 70 48 8D B4 24 B0 00 00 00 48 89 34 CA 49 8B 57 68 48 89 C8 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_033f06dd {
    meta:
        author = "Elastic Security"
        id = "033f06dd-f3ed-4140-bbff-138ed2d8378c"
        fingerprint = "2f1f39e10df0ca6c133237b6d92afcb8a9c23de511120e8860c1e6ed571252ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 68 63 33 4E 33 5A 48 78 6A 64 58 51 67 4C 57 51 36 49 43 31 }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_ce0c185f {
    meta:
        author = "Elastic Security"
        id = "ce0c185f-fca2-47d3-9e7c-57b541af98a5"
        fingerprint = "0d2e3e2b04e93f25c500677482e15d92408cb1da2a5e3c5a13dc71e52d140f85"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "cdd3d567fbcbdd6799afad241ae29acbe4ab549445e5c4fc0678d16e75b40dfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EF E5 66 0F 6F AC 24 80 00 00 00 66 0F EB E8 66 0F EF D5 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Malxmr_da08e491 {
    meta:
        author = "Elastic Security"
        id = "da08e491-c6fa-4228-8b6a-8adae2f0324a"
        fingerprint = "c4911fdeece4c3f97bbc9ef4da478c5f5363ab71a70b0767edec0f94b87fd939"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Malxmr"
        reference_sample = "4638d9ece32cd1385121146378772d487666548066aecd7e40c3ba5231f54cc0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 48 31 CD 48 89 F9 48 F7 D1 4C 21 F9 48 21 DA 49 31 CA 48 }
    condition:
        all of them
}



// from Linux_Cryptominer_Miancha.yar
rule Linux_Cryptominer_Miancha_646803ef {
    meta:
        author = "Elastic Security"
        id = "646803ef-e8a5-46e2-94a5-dcc6cb41cead"
        fingerprint = "b22f87b60c19855c3ac622bc557655915441f5e12c7d7c27c51c05e12c743ee5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Miancha"
        reference_sample = "4c7761c9376ed065887dc6ce852491641419eb2d1f393c37ed0a5cb29bd108d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F DC 66 0F 73 FB 04 66 0F EF C1 66 0F 6F D3 66 0F EF C7 66 0F 6F }
    condition:
        all of them
}



// from Linux_Cryptominer_Minertr.yar
rule Linux_Cryptominer_Minertr_9901e275 {
    meta:
        author = "Elastic Security"
        id = "9901e275-3053-47ea-8c36-6c9271923b64"
        fingerprint = "f27e404d545f3876963fd6174c4235a4fe4f69d53fe30a2d29df9dad6d97b7f7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Minertr"
        reference_sample = "f77246a93782fd8ee40f12659f41fccc5012a429a8600f332c67a7c2669e4e8f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 41 55 41 54 55 53 48 83 EC 78 48 89 3C 24 89 F3 89 74 }
    condition:
        all of them
}



// from Linux_Cryptominer_Pgminer.yar
rule Linux_Cryptominer_Pgminer_ccf88a37 {
    meta:
        author = "Elastic Security"
        id = "ccf88a37-2a58-40f9-8c13-f1ce218a2ec4"
        fingerprint = "dc82b841a7e72687921c9b14bc86218c3377f939166d11a7cccd885dad4a06e7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Pgminer"
        reference_sample = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F6 41 83 C5 02 48 8B 5D 00 8A 0B 80 F9 2F 76 7E 41 83 FF 0A B8 0A 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Pgminer_5fb2efd5 {
    meta:
        author = "Elastic Security"
        id = "5fb2efd5-4adc-4285-bef1-6e4987066944"
        fingerprint = "8ac56b60418e3f3f4d1f52c7a58d0b7c1f374611d45e560452c75a01c092a59b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Pgminer"
        reference_sample = "6d296648fdbc693e604f6375eaf7e28b87a73b8405dc8cd3147663b5e8b96ff0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 16 00 00 00 0E 00 00 00 18 03 00 7F EB 28 33 C5 56 5D F2 50 67 C5 6F }
    condition:
        all of them
}



// from Linux_Cryptominer_Presenoker.yar
rule Linux_Cryptominer_Presenoker_3bb5533d {
    meta:
        author = "Elastic Security"
        id = "3bb5533d-4722-4801-9fbb-dd2c916cffc6"
        fingerprint = "a3005a07901953ae8def7bd9d9ec96874da0a8aedbebde536504abed9d4191fd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Presenoker"
        reference_sample = "bbc155c610c7aa439f98e32f97895d7eeaef06dab7cca05a5179b0eb3ba3cc00"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 10 74 72 F3 0F 6F 00 66 0F 7E C2 0F 29 04 24 85 D2 F3 0F 6F }
    condition:
        all of them
}



// from Linux_Cryptominer_Roboto.yar
rule Linux_Cryptominer_Roboto_0b6807f8 {
    meta:
        author = "Elastic Security"
        id = "0b6807f8-49c1-485f-9233-1a14f98935bc"
        fingerprint = "65f373b6e820c2a1fa555182b8e4547bf5853326bdf3746c7592d018dc2ed89f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Roboto"
        reference_sample = "c2542e399f865b5c490ee66b882f5ff246786b3f004abb7489ec433c11007dda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FB 49 89 CF 4D 0F AF FC 4D 01 DF 4D 89 CB 4C 0F AF D8 4D 01 FB 4D }
    condition:
        all of them
}

rule Linux_Cryptominer_Roboto_1f1cfe9a {
    meta:
        author = "Elastic Security"
        id = "1f1cfe9a-ab4a-423c-a62b-ead6901e2a86"
        fingerprint = "8dd9f4a091713b8992abd97474f66fdc7d34b0124f06022ab82942f88f3b330c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Roboto"
        reference_sample = "497a6d426ff93d5cd18cea623074fb209d4f407a02ef8f382f089f1ed3f108c5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 20 85 FF 74 0D 39 FE 73 13 83 FE 0F 77 0E 01 F6 EB F3 BF 01 00 }
    condition:
        all of them
}



// from Linux_Cryptominer_Stak.yar
rule Linux_Cryptominer_Stak_05088561 {
    meta:
        author = "Elastic Security"
        id = "05088561-ec73-4068-a7f3-3eff612ecd28"
        fingerprint = "dfcfa99a2924eb9e8bc0e7b51db6d1b633e742e34add40dc5d1bb90375f85f6e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CD 49 8D 4D 07 48 83 E1 F8 48 39 CD 73 55 49 8B 06 48 8B 50 08 48 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_ae8b98a9 {
    meta:
        author = "Elastic Security"
        id = "ae8b98a9-cc25-4606-a775-1129e0f08c3b"
        fingerprint = "0b5da501c97f53ecd79d708d898d4f5baae3c5fd80a4c39b891a952c0bcc86e5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D1 73 5A 49 8B 06 48 8B 78 08 4C 8B 10 4C 8D 4F 18 4D 89 CB 49 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_d707fd3a {
    meta:
        author = "Elastic Security"
        id = "d707fd3a-41ce-4f88-ad42-d663094db5fb"
        fingerprint = "c218a3c637f58a6e0dc2aa774eb681757c94e1d34f622b4ee5520985b893f631"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C2 01 48 89 10 49 8B 55 00 48 8B 02 48 8B 4A 10 48 39 C8 74 9E 80 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_52dc7af3 {
    meta:
        author = "Elastic Security"
        id = "52dc7af3-a742-4307-a5ae-c929fede1cc4"
        fingerprint = "330262703d3fcdd8b2c217db552f07e19f5df4d6bf115bfa291bb1c7f802ad97"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "a9c14b51f95d0c368bf90fb10e7d821a2fbcc79df32fd9f068a7fc053cbd7e83"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 48 89 D3 4D 8B 74 24 20 48 8D 41 01 4C 29 FB 4C 8D 6B 10 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_bb3153ac {
    meta:
        author = "Elastic Security"
        id = "bb3153ac-b11b-4e84-afab-05dab61424ae"
        fingerprint = "c4c33125a1fad9ff393138b333a8cebfd67217e90780c45f73f660ed1fd02753"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "5b974b6e6a239bcdc067c53cc8a6180c900052d7874075244dc49aaaa9414cca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6C 77 61 79 73 22 2C 20 22 6E 6F 5F 6D 6C 63 6B 22 2C 20 22 }
    condition:
        all of them
}



// from Linux_Cryptominer_Ursu.yar
rule Linux_Cryptominer_Ursu_3c05f8ab {
    meta:
        author = "Elastic Security"
        id = "3c05f8ab-d1b8-424b-99b7-1fe292ae68ff"
        fingerprint = "463d4f675589e00284103ef53d0749539152bbc3772423f89a788042805b3a21"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Ursu"
        reference_sample = "d72361010184f5a48386860918052dbb8726d40e860ea0287994936702577956"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 55 4C 2C 20 0A 09 30 78 33 30 32 38 36 30 37 38 32 38 37 38 }
    condition:
        all of them
}



// from Linux_Cryptominer_Uwamson.yar
rule Linux_Cryptominer_Uwamson_c42fd06d {
    meta:
        author = "Elastic Security"
        id = "c42fd06d-b9ab-4f1f-bb59-e7b49355115c"
        fingerprint = "dac171e66289e2222cd631d616f31829f31dfeeffb34f0e1dcdd687d294f117c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 4C 89 F3 48 8B 34 24 48 C1 E0 04 48 C1 E3 07 48 8B 7C 24 10 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_d08b1d2e {
    meta:
        author = "Elastic Security"
        id = "d08b1d2e-cbd5-420e-8f36-22b9efb5f12c"
        fingerprint = "1e55dc81a44af9c15b7a803e72681b5c24030d34705219f83ca4779fd885098c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "4f7ad24b53b8e255710e4080d55f797564aa8c270bf100129bdbe52a29906b78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4F F8 49 8D 7D 18 89 D9 49 83 C5 20 48 89 FE 41 83 E1 0F 4D 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_0797de34 {
    meta:
        author = "Elastic Security"
        id = "0797de34-9181-4f28-a4b0-eafa67e20b41"
        fingerprint = "b6a210c23f09ffa0114f12aa741be50f234b8798a3275ac300aa17da29b8727c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "e4699e35ce8091f97decbeebff63d7fa8c868172a79f9d9d52b6778c3faab8f2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 43 20 48 B9 AB AA AA AA AA AA AA AA 88 44 24 30 8B 43 24 89 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Uwamson_41e36585 {
    meta:
        author = "Elastic Security"
        id = "41e36585-0ef1-4896-a887-dac437c716a5"
        fingerprint = "ad2d4a46b9378c09b1aef0f2bf67a990b3bacaba65a5b8c55c2edb0c9a63470d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Uwamson"
        reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 03 48 C1 FF 03 4F 8D 44 40 FD 48 0F AF FE 49 01 F8 4C 01 C2 4C }
    condition:
        all of them
}



// from Linux_Cryptominer_Xmrig.yar
rule Linux_Cryptominer_Xmrig_57c0c6d7 {
    meta:
        author = "Elastic Security"
        id = "57c0c6d7-ded1-4a3e-9877-4003ab46d4a6"
        fingerprint = "b36ef33a052cdbda0db0048fc9da4ae4b4208c0fa944bc9322f029d4dfef35b8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "100dc1ede4c0832a729d77725784d9deb358b3a768dfaf7ff9e96535f5b5a361"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 01 66 0F EF C9 49 89 38 0F BE 00 83 E8 30 F2 0F 2A C8 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_7e42bf80 {
    meta:
        author = "Elastic Security"
        id = "7e42bf80-60a4-4d45-bf07-b96a188c6e6b"
        fingerprint = "cf3b74ae6ff38b0131763fbcf65fa21fb6fd4462d2571b298c77a43184ac5415"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "551b6e6617fa3f438ec1b3bd558b3cbc981141904cab261c0ac082a697e5b07d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 70 F8 FF 66 0F 73 FD 04 66 44 0F EF ED 66 41 0F 73 FE 04 66 41 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_271121fb {
    meta:
        author = "Elastic Security"
        id = "271121fb-47cf-47a7-9e90-8565d4694c9e"
        fingerprint = "e0968731b0e006f3db92762822e4a3509d800e8f270b1c38303814fd672377a2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "19aeafb63430b5ac98e93dfd6469c20b9c1145e6b5b86202553bd7bd9e118842"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 18 41 C1 E4 10 C1 E1 08 41 C1 EA 10 44 89 CB 41 C1 E9 18 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_e7e64fb7 {
    meta:
        author = "Elastic Security"
        id = "e7e64fb7-e07c-4184-86bd-db491a2a11e0"
        fingerprint = "444240375f4b9c6948907c7e338764ac8221e5fcbbc2684bbd0a1102fef45e06"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 48 89 74 24 48 77 05 48 8B 5C C4 30 4C 8B 0A 48 8B 0F 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_79b42b21 {
    meta:
        author = "Elastic Security"
        id = "79b42b21-1408-4837-8f1f-6de30d7f5777"
        fingerprint = "4cd0481edd1263accdac3ff941df4e31ef748bded0fba5fe55a9cffa8a37b372"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 00 79 0A 8B 45 B8 83 E0 04 85 C0 75 38 8B 45 EC 83 C0 01 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_77fbc695 {
    meta:
        author = "Elastic Security"
        id = "77fbc695-6fe3-4e30-bb2f-f64379ec4efd"
        fingerprint = "e0c6cb7a05c622aa40dfe2167099c496b714a3db4e9b92001bbe6928c3774c85"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "e723a2b976adddb01abb1101f2d3407b783067bec042a135b21b14d63bc18a68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F2 0F 58 44 24 08 F2 0F 11 44 24 08 8B 7B 08 41 8D 76 01 49 83 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_403b0a12 {
    meta:
        author = "Elastic Security"
        id = "403b0a12-8475-4e28-960b-ef33eabf0fcf"
        fingerprint = "785ac520b9f2fd9c6b49d8a485118eee7707f0fa0400b3db99eb7dfb1e14e350"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "54d806b3060404ccde80d9f3153eebe8fdda49b6e8cdba197df0659c6724a52d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 28 03 1C C3 0C 00 C0 00 60 83 1C A7 71 00 00 00 68 83 5C D7 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_bffa106b {
    meta:
        author = "Elastic Security"
        id = "bffa106b-0a9a-4433-b9ac-ae41a020e7e0"
        fingerprint = "665b5684c55c88e55bcdb8761305d6428c6a8e810043bf9df0ba567faea4c435"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 9C 44 0F B6 94 24 BC 00 00 00 89 5C 24 A0 46 8B 0C 8A 66 0F 6E 5C }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_73faf972 {
    meta:
        author = "Elastic Security"
        id = "73faf972-43e4-448d-bdfd-cda9be15fce6"
        fingerprint = "f31c2658acd6d13ae000426d3845bcec7a8a587bbaed75173baa84b2871b0b42"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F C4 83 E0 01 83 E1 06 09 C1 44 89 E8 01 C9 D3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_af809eea {
    meta:
        author = "Elastic Security"
        id = "af809eea-fe42-4495-b7e5-c22b39102fcd"
        fingerprint = "373d2f57aede0b41296011d12b59ac006f6cf0e2bd95163f518e6e252459411b"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 E0 01 83 E1 06 09 C1 44 89 ?? 01 C9 D3 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_9f6ac00f {
    meta:
        author = "Elastic Security"
        id = "9f6ac00f-1562-4be1-8b54-bf9a89672b0e"
        fingerprint = "77b171a3099327a5edb59b8f1b17fb3f415ab7fd15beabcd3b53916cde206568"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "9cd58c1759056c0c5bbd78248b9192c4f8c568ed89894aff3724fdb2be44ca43"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B8 31 75 00 00 83 E3 06 09 D9 01 C9 D3 F8 89 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrig_dbcc9d87 {
    meta:
        author = "Elastic Security"
        id = "dbcc9d87-5064-446d-9581-b14cf183ec3f"
        fingerprint = "ebb6d184d7470437aace81d55ada5083e55c0de67e566b052245665aeda96d69"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Cryptominer.Xmrig"
        reference_sample = "da9b8fb5c26e81fb3aed3b0bc95d855339fced303aae2af281daf0f1a873e585"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 72 47 47 58 34 53 58 5F 34 74 43 41 66 30 5A 57 73 00 64 48 8B 0C 25 F8 FF }
    condition:
        all of them
}



// from Linux_Cryptominer_Xmrminer.yar
rule Linux_Cryptominer_Xmrminer_70c153b5 {
    meta:
        author = "Elastic Security"
        id = "70c153b5-2628-4504-8f21-2c7f0201b133"
        fingerprint = "51d304812e72045387b002824fdc9231d64bf4e8437c70150625c4b2aa292284"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "55b133ba805bb691dc27a5d16d3473650360c988e48af8adc017377eed07935b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 18 BA 08 00 00 00 48 8D 4C 24 08 48 89 74 24 08 BE 02 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_98b00f9c {
    meta:
        author = "Elastic Security"
        id = "98b00f9c-354a-47dd-8546-a2842559d247"
        fingerprint = "8d231a490e818614141d6805a9e7328dc4b116b34fd027d5806043628b347141"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "c01b88c5d3df7ce828e567bd8d639b135c48106e388cd81497fcbd5dcf30f332"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 38 DC DF 49 89 D4 66 0F 7F 24 1A 66 0F EF C3 66 42 0F 7F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_2b250178 {
    meta:
        author = "Elastic Security"
        id = "2b250178-3f9a-4aeb-819a-970b5ef9c98a"
        fingerprint = "e297a790a78d32b973d6a028a09c96186c3971279b5c5eea4ff6409f12308e67"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "636605cf63d3e335fe9481d4d110c43572e9ab365edfa2b6d16d96b52d6283ef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 7E 11 8B 44 24 38 89 EF 31 D2 89 06 8B 44 24 3C 89 46 04 F7 C7 02 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_67bf4b54 {
    meta:
        author = "Elastic Security"
        id = "67bf4b54-aa02-4f4c-ba70-3f2db1418c7e"
        fingerprint = "5f2fae0eee79dac3c202796d987ad139520fadae145c84ab5769d46afb2518c2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "9d33fba4fda6831d22afc72bf3d6d5349c5393abb3823dfa2a5c9e391d2b9ddf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 70 4A 8B 2C E0 83 7D 00 03 74 DA 8B 4D 68 85 C9 74 DC 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_504b42ca {
    meta:
        author = "Elastic Security"
        id = "504b42ca-00a7-4917-8bb1-1957838a1d27"
        fingerprint = "265a3cb860e1f0ddafbe5658fa3a341d7419c89eecc350f8fc16e7a1e05a7673"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D7 8B 04 8C 44 8D 50 FF 4C 89 04 C6 44 89 14 8C 75 D7 48 8B 2E 45 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d1bb752f {
    meta:
        author = "Elastic Security"
        id = "d1bb752f-f5d6-4d93-96af-d977b501776a"
        fingerprint = "0f2455a4e80d93e7f1e420dc2f36e89c28ecb495879bca2e683a131b2770c3ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 12 48 29 C8 48 2B 83 B0 00 00 00 48 C1 E8 03 48 F7 E2 48 8B }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d625fcd2 {
    meta:
        author = "Elastic Security"
        id = "d625fcd2-2951-4ecf-91cd-d58e16c33c65"
        fingerprint = "08c8d00e38fbf62cbf0aa329d6293fba302c3c76aee8c33341260329c14a58aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 00 00 40 00 0C C0 5C 02 60 01 02 03 12 00 40 04 50 09 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_02d19c01 {
    meta:
        author = "Elastic Security"
        id = "02d19c01-51e9-4a46-a06b-d5f7e97285d9"
        fingerprint = "724bbc2910217bcac457e6ba0c0848caf38e12f272b0104ade1c7bc57dc85c27"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "b6df662f5f7566851b95884c0058e7476e49aeb7a96d2aa203393d88e584972f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 8D 7E 15 41 56 41 55 41 54 41 BB 03 00 00 00 55 53 48 89 FB 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_d1a814b0 {
    meta:
        author = "Elastic Security"
        id = "d1a814b0-38a6-4469-a29b-75787f52d789"
        fingerprint = "1746bc1d96207bd1bb44e9ff248b76245feb76c1d965400c3abd3b9116ea8455"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "bea55bc9495ee51c78ceedadf3a685ea9d6dd428170888c67276c100d4d94beb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 48 8B 44 24 58 49 89 41 08 8B 01 48 C1 E0 05 4D 8D 04 07 48 8B 44 }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_c6218e30 {
    meta:
        author = "Elastic Security"
        id = "c6218e30-1a49-46ea-aac8-5f0f652156c5"
        fingerprint = "c3171cf17ff3b0ca3d5d62fd4c2bd02a4e0a8616a84ea5ef9e78307283e4a360"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "b43ddd8e355b0c538c123c43832e7c8c557e4aee9e914baaed0866ee5d68ee55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AC 24 B0 00 00 00 48 89 FA 66 0F EF DD 48 C1 E2 20 66 41 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Xmrminer_b17a7888 {
    meta:
        author = "Elastic Security"
        id = "b17a7888-dc12-4bb4-bc77-558223814e8b"
        fingerprint = "2b11457488e6098d777fb0d8f401cf10af5cd48e05248b89cb9e377d781b516c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xmrminer"
        reference_sample = "65c9fdd7c559554af06cd394dcebece1bc0fdc7dd861929a35c74547376324a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D4 FF C5 55 F4 C9 C5 F5 D4 CD C4 41 35 D4 C9 C5 B5 D4 C9 C5 C5 }
    condition:
        all of them
}



// from Linux_Cryptominer_Xpaj.yar
rule Linux_Cryptominer_Xpaj_fdbd614e {
    meta:
        author = "Elastic Security"
        id = "fdbd614e-e628-43ff-86d4-1057f9d544ac"
        fingerprint = "456b69d4035aa2d682ba081c2f7b24c696f655ec164645f83c9aef5bd262f510"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xpaj"
        reference_sample = "3e2b1b36981713217301dd02db33fb01458b3ff47f28dfdc795d8d1d332f13ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 72 6F 72 3A 20 47 65 74 25 73 20 74 65 6D 70 20 72 65 74 75 }
    condition:
        all of them
}



// from Linux_Cryptominer_Zexaf.yar
rule Linux_Cryptominer_Zexaf_b90e7683 {
    meta:
        author = "Elastic Security"
        id = "b90e7683-84bf-4c07-b6ef-54c631280217"
        fingerprint = "4ca9fad98bdde19f71c117af9cb87007dc46494666e7664af111beded1100ae4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Zexaf"
        reference_sample = "98650ebb7e463a06e737bcea4fd2b0f9036fafb0638ba8f002e6fe141b9fecfe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 F2 C1 E7 18 C1 E2 18 C1 ED 08 09 D5 C1 EE 08 8B 14 24 09 FE }
    condition:
        all of them
}



// from Linux_Downloader_Generic.yar
rule Linux_Downloader_Generic_0bd15ae0 {
    meta:
        author = "Elastic Security"
        id = "0bd15ae0-e4fe-48a9-84a6-f8447b467651"
        fingerprint = "67e14ea693baee8437157f6e450ac5e469b1bab7d9ff401493220575aae9bc91"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Downloader.Generic"
        reference_sample = "e511efb068e76a4a939c2ce2f2f0a089ef55ca56ee5f2ba922828d23e6181f09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D0 83 C0 01 EB 05 B8 FF FF FF FF 48 8B 5D E8 64 48 33 1C 25 28 00 }
    condition:
        all of them
}



// from Linux_Exploit_Abrox.yar
rule Linux_Exploit_Abrox_5641ba81 {
    meta:
        author = "Elastic Security"
        id = "5641ba81-2c37-4dd1-82d8-532182e8ed15"
        fingerprint = "d2abedb6182f86982ebe283215331ce238fda3964535047768f2ea55719b052f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Abrox"
        reference_sample = "8de96c8e61536cae870f4a24127d28b86bd8122428bf13965c596f92182625aa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 58 CD 80 6A 17 58 31 DB CD 80 31 D2 52 68 2E }
    condition:
        all of them
}



// from Linux_Exploit_Alie.yar
rule Linux_Exploit_Alie_e69de1ee {
    meta:
        author = "Elastic Security"
        id = "e69de1ee-294d-437e-a943-abb731842523"
        fingerprint = "01fa5343fa0fb60c320f9fa49beb9c7a8a821ace7f1d6e48ea103e746b3f27a2"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Alie"
        reference_sample = "882839549f062ab4cbe6df91336ed320eaf6c2300fc2ed64d1877426a0da567d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 8D 4B 08 8D 53 0C B0 0B CD 80 89 C3 31 C0 B0 }
    condition:
        all of them
}



// from Linux_Exploit_Cornelgen.yar
rule Linux_Exploit_Cornelgen_584a227a {
    meta:
        author = "Elastic Security"
        id = "584a227a-bf17-4620-8b10-97676f12ea5b"
        fingerprint = "65a23e20166b99544b2d0b4969240618d50e80a53a69829756721e19e4e6899f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Cornelgen"
        reference_sample = "c823cb669f1d6cb9258d6f0b187609c226af23396f9c5be26eb479e5722a9d97"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 89 E3 52 53 89 E1 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

rule Linux_Exploit_Cornelgen_be0bc02d {
    meta:
        author = "Elastic Security"
        id = "be0bc02d-2d9d-4cbe-9d6a-3a88ffa1234b"
        fingerprint = "6b57eb6fd3c8e28cbff5e7cc51246de74ca7111a9cd1c795b21aa89142a693b4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Cornelgen"
        reference_sample = "24c0ba8ad4f543f9b0aff0d0b66537137bc78606b47ced9b6d08039bbae78d80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 44 24 08 A3 B8 9F 04 08 0F B7 05 04 A1 04 08 }
    condition:
        all of them
}

rule Linux_Exploit_Cornelgen_03ee53d3 {
    meta:
        author = "Elastic Security"
        id = "03ee53d3-4f03-4c5e-9187-45e0e33584b4"
        fingerprint = "f2a8ecfffb0328c309a3a5db7e62fae56bf168806a1db961a57effdebba7645e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Cornelgen"
        reference_sample = "711eafd09d4e5433be142d54db153993ee55b6c53779d8ec7e76ca534b4f81a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C9 B0 27 CD 80 31 C0 B0 3D CD 80 31 C0 8D 5E 02 }
    condition:
        all of them
}



// from Linux_Exploit_Courier.yar
rule Linux_Exploit_Courier_190258dd {
    meta:
        author = "Elastic Security"
        id = "190258dd-1384-4144-aa05-7957ca0b464b"
        fingerprint = "4ba94b87847a76df80200d40383d2d289dc463faa609237dbc43f317db45074d"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Courier"
        reference_sample = "349866d0fb81d07a35b53eac6f11176721629bbd692526851e483eaa83d690c3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 31 C0 50 54 53 50 B0 3B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}



// from Linux_Exploit_Criscras.yar
rule Linux_Exploit_Criscras_fc505c1d {
    meta:
        author = "Elastic Security"
        id = "fc505c1d-f77d-48cc-b8fe-7b24b9cc6a97"
        fingerprint = "bc5e980599c4c8fc3c9b560738d7187a0c91e2813c64b3ad0ff014230100c8d8"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Criscras"
        reference_sample = "7399f6b8fbd6d6c6fb56ab350c84910fe19cc5da67e4de37065ff3d4648078ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 89 21 89 E3 31 C0 B0 0B CD 80 31 C0 FE C0 CD }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2009_1897.yar
rule Linux_Exploit_CVE_2009_1897_6cf0a073 {
    meta:
        author = "Elastic Security"
        id = "6cf0a073-571e-48ef-be58-807bff1a5e97"
        fingerprint = "8fcb3687d4ec5dd467d937787f0659448a91446f92a476ff7ba471a02d6b07a9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2009-1897"
        reference_sample = "85f371bf73ee6d8fcb6fa9a8a68b38c5e023151257fd549855c4c290cc340724"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 C0 85 DB 78 28 45 31 C9 41 89 D8 B9 02 00 00 00 BA 01 00 }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2009_2698.yar
rule Linux_Exploit_CVE_2009_2698_12374e97 {
    meta:
        author = "Elastic Security"
        id = "12374e97-385e-4b3a-9d50-39f35ad4f6dd"
        fingerprint = "2c669220ac8909e2336bbf9c38489c8e32d573ab6c29fa1e2e0c1fe69f7441ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2009-2698"
        reference_sample = "656fddc1bf4743a08a455628b6151076b81e604ff49c93d797fa49b1f7d09c2f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 64 6F 75 74 00 66 77 72 69 74 65 00 64 65 73 63 00 63 76 65 00 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2009_2698_cc04dddd {
    meta:
        author = "Elastic Security"
        id = "cc04dddd-91d0-4c5f-a0ac-01787da7f369"
        fingerprint = "d3fdd66e486cb06bd63f6d8e471e66bc80990c4f0729eea16b47adc4cac80538"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2009-2698"
        reference_sample = "502b73ea04095e8a7ec4e8d7cc306242b45850ad28690156754beac8cd8d7b2d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 10 89 45 F4 83 7D F4 FF 75 1F 83 EC 0C 68 }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2009_2908.yar
rule Linux_Exploit_CVE_2009_2908_406c2fef {
    meta:
        author = "Elastic Security"
        id = "406c2fef-0f1a-441a-96b9-e4168c283c90"
        fingerprint = "94a94217823a8d682ba27889ba2b53fef7b18ae14d75a73456f21184e51581cf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2009-2908"
        reference_sample = "1e05a23f5b3b9cfde183aec26b723147e1816b95dc0fb7f9ac57376efcb22fcd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 00 66 70 72 69 6E 74 66 00 66 77 72 69 74 65 00 64 65 73 }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2010_3301.yar
rule Linux_Exploit_CVE_2010_3301_79d52efd {
    meta:
        author = "Elastic Security"
        id = "79d52efd-7955-4aa3-afbe-b7d172c30f34"
        fingerprint = "22235427bc621e07c16c365ddbf22a4e1c04d7a0f23c3e4c46d967d908256567"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2010-3301"
        reference_sample = "53a2163ad17a414d9db95f5287d9981c9410e7eaeea096610ba622eb763a6970"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 3B F9 FF FF 83 7D D4 FF 75 16 48 8D 3D 35 03 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2010_3301_d0eb0924 {
    meta:
        author = "Elastic Security"
        id = "d0eb0924-dae1-46f9-a4d0-c9e69f781a22"
        fingerprint = "bb288a990938aa21aba087a0400d6f4765a622f8ed36d1dd7953d09cbb09ff83"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2010-3301"
        reference_sample = "907995e90a80d3ace862f2ffdf13fd361762b5acc5397e14135d85ca6a61619b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 3C FA FF FF 83 7D EC FF 75 19 BF 20 13 40 00 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2010_3301_a5828970 {
    meta:
        author = "Elastic Security"
        id = "a5828970-7a30-421c-be92-5659c18b88d1"
        fingerprint = "72223f502b2a129380ab011b785f6589986d2eb177580339755d12840617ce5f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2010-3301"
        reference_sample = "4fc781f765a65b714ec27080f25c03f20e06830216506e06325240068ba62d83"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 7C FC FF FF 83 7D EC FF 75 19 BF 40 0E 40 00 }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2012_0056.yar
rule Linux_Exploit_CVE_2012_0056_06b2dff5 {
    meta:
        author = "Elastic Security"
        id = "06b2dff5-250a-46e0-b763-8e6b04498fe2"
        fingerprint = "82b200deae93c8fa376d670f5091d9a63730a6f5b5e8a0567fe9c283075d57c0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2012-0056"
        reference_sample = "168b3fb1c675ab76224c641e228434495160502a738b64172c679e8ce791ac17"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 66 64 20 69 6E 20 70 61 72 65 6E 74 2E 00 5B 2B 5D 20 52 65 63 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2012_0056_b39839f4 {
    meta:
        author = "Elastic Security"
        id = "b39839f4-e6f4-44bd-a636-ce355f3c5c6a"
        fingerprint = "f269c4aecbb55e24d9081d7a1e4bd6cfa9799409b3a3d7a6f9bf127f7468dedc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2012-0056"
        reference_sample = "cf569647759e011ff31d8626cea65ed506e8d0ef1d26f3bbb7c02a4060ce58dc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 08 02 7E 3E 8B 45 0C 83 C0 04 8B 00 0F B6 00 3C 2D 75 2F 8B }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2012_0056_a1e53450 {
    meta:
        author = "Elastic Security"
        id = "a1e53450-036e-4ae3-bfe4-64a6c7239a04"
        fingerprint = "d0a0635fb356ccedb1448082cc63748d49d45f8a25e43eab7ac1d67e87062b8f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2012-0056"
        reference_sample = "15a4d149e935758199f6df946ff889e12097f5fec4ef450e9cbd554d1efbd5e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 80 31 C9 B3 ?? B1 02 B0 3F CD 80 31 C0 50 68 6E }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2014_3153.yar
rule Linux_Exploit_CVE_2014_3153_1c1e02ad {
    meta:
        author = "Elastic Security"
        id = "1c1e02ad-eb06-4eb6-a424-0f1dd6eebb2a"
        fingerprint = "a0a82cd15713be3f262021d6ed6572a0d4763ccfd0499e6b9374764c89705c2a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2014-3153"
        reference_sample = "64b8c61b73f0c0c0bd44ea5c2bcfb7b665fcca219dbe074a4a16ae20cd565812"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 40 48 89 7D C8 48 8D 4D D0 48 8B 45 C8 BA 24 00 }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2016_4557.yar
rule Linux_Exploit_CVE_2016_4557_b7e15f5e {
    meta:
        author = "Elastic Security"
        id = "b7e15f5e-73d2-4718-8fac-e6a285b0c73c"
        fingerprint = "14baf456521fd7357a70ddde9da11f27d17a45d7d12c70a0101d6bdc45e30c74"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Exploit.CVE-2016-4557"
        reference_sample = "bbed2f81104b5eb4a8475deff73b29a350dc8b0f96dcc4987d0112b993675271"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2E 20 69 66 20 74 68 69 73 20 77 6F 72 6B 65 64 2C 20 79 6F }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2016_5195.yar
rule Linux_Exploit_CVE_2016_5195_364f3b7b {
    meta:
        author = "Elastic Security"
        id = "364f3b7b-4361-44ca-bf49-e26c123ae4bd"
        fingerprint = "ec6cf1d090cd57434c4d3c1c3511fd4b683ff109bfd0ce859552d58cbb83984a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "0d4c43bf0cdd6486a4bcab988517e58b8c15d276f41600e596ecc28b0b728e69"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 9C 01 7E 24 48 8B 45 90 48 8B 40 08 48 89 45 F8 48 8B 45 F8 48 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_3a2ed31b {
    meta:
        author = "Elastic Security"
        id = "3a2ed31b-a8be-4aff-af5e-e1ff2676f3f9"
        fingerprint = "0e8e0f58deadf4838464c2f2bc860013e6d47c3d770d0ef743b5dd9021832cae"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "ebbf3bc39ec661e2029d88960a5608e348de92089099019348bc0e891841690f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 30 48 89 7D D8 48 8B 45 D8 48 89 45 F0 BE 02 00 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_7448814c {
    meta:
        author = "Elastic Security"
        id = "7448814c-1685-45a9-9a00-039b30485545"
        fingerprint = "25ffa8f3b2356deebc88d8831bc8664edd6543a7d722d6ddd72e89fad18c66e7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "e95d0783b635e34743109d090af17aef2e507e8c90060d171e71d9ac79e083ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 9C 01 7E 24 48 8B 45 90 48 8B 40 08 48 89 45 C0 48 8B 45 C0 48 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_2fa988e3 {
    meta:
        author = "Elastic Security"
        id = "2fa988e3-dfaf-44c8-bfaa-889778858e22"
        fingerprint = "a841f4b929c79eadfa8deeb3a6f410056aec94dd1e0d9c8e5dc31675de936403"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "679392e78d4abefc05b885e43aaccc2da235bd7f2a267c6ecfbe2cf824776993"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 20 89 7D EC 89 75 E8 8B 45 E8 48 C1 E0 05 48 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_ea8801ac {
    meta:
        author = "Elastic Security"
        id = "ea8801ac-ee95-4294-9cfa-99c773a04183"
        fingerprint = "aa191347bdf2e9fdcf6f9591c370b85208a1c46a329bc648268447dbb5ea898f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "7acccfd8c2e5555a3e3bf979ad2314c12a939c1ef32b66e61e30a712f07164fd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 30 89 7D DC 48 89 75 D0 83 7D DC 02 7F 0A B8 01 00 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_b2ebdebd {
    meta:
        author = "Elastic Security"
        id = "b2ebdebd-0110-46b4-a97f-27c4c495b23d"
        fingerprint = "2a98a2d1be205145eb2d30a57aaa547b30281b31981f0872ba3f7e1d684a0cc2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "dee49d4b7f406fd1728dad4dc217484ced2586e014e2cd265ea64eff70a2633d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 30 48 89 7D D8 48 8B 45 D8 48 89 45 F8 BE 02 00 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_9190d516 {
    meta:
        author = "Elastic Security"
        id = "9190d516-dea0-4d74-9f2c-bd2337538258"
        fingerprint = "977bafd175a994edaef5f3fa19d19fe161cebb2447ee32fd5d4b0a3b93fb51fa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "837ffed1f23293dc9c7cb994601488fc121751a249ffde51326947c33c5fca7f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4D 18 48 8B 55 10 48 8B 75 F0 48 8B 45 F8 48 83 EC 08 41 51 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_3b460716 {
    meta:
        author = "Elastic Security"
        id = "3b460716-812e-4884-ab66-e01f2e61996d"
        fingerprint = "900e22d1a157677698a47d49d2deeb52c938e3a790aba689b920ba1bbd7ed39d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "8c4d49d4881ebdab1bd0e083d4e644cfc8eb7af3b96664598526ab3d175fc420"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 30 48 89 7D D8 48 8B 45 D8 48 89 45 E8 BE 02 00 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_ccfd7518 {
    meta:
        author = "Elastic Security"
        id = "ccfd7518-af6c-4378-bd9c-7267a7f0dab4"
        fingerprint = "4797064d6416f2799691ae7df956d0383dfe6094de29fb03fc8233ad89149942"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "b1017db71cf195aa565c57fed91ff1cdfcce344dc76526256d5817018f1351bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 FC 01 81 7D FC FF E0 F5 05 7F 0A 8B 05 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_d41c2c63 {
    meta:
        author = "Elastic Security"
        id = "d41c2c63-1af7-47c9-88a0-16454c9583db"
        fingerprint = "77fb7e9911d1037bba0a718d8983a42ad1877c13d865ce415351d599064ea7ea"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "a4e5751b4e8fa2e9b70e1e234f435a03290c414f9547dc7709ce2ee4263a35f1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 83 45 F0 01 81 7D F0 FF C1 EB 0B 7E D3 C9 C3 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_ffa7f059 {
    meta:
        author = "Elastic Security"
        id = "ffa7f059-b825-4dd6-b10d-e57549a2704f"
        fingerprint = "c451689042d9290d1bb5b931e002237584217bbddfc0d96c2486a61cb5c37d31"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "a073c6be047ea7b4500b1ffdc8bdadd9a06f9efccd38c88e0fc976b97b2b2df5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 83 45 FC 01 81 7D FC FF C1 EB 0B 7E D7 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_fb24c7e4 {
    meta:
        author = "Elastic Security"
        id = "fb24c7e4-db4f-405e-8e88-bc313b9a0358"
        fingerprint = "0a5f15ddb425a6e00f6c3964b4dbdc91a856fd06b6e45dfd4fded8ed97f21ae8"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "a073c6be047ea7b4500b1ffdc8bdadd9a06f9efccd38c88e0fc976b97b2b2df5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 83 45 FC 01 81 7D FC FF C1 EB 0B 7E ?? 8B 45 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_b45098df {
    meta:
        author = "Elastic Security"
        id = "b45098df-7f26-44a9-8078-f1c05d15cc38"
        fingerprint = "ed32e66f2c18b16a6f00d6a696a32cdb1b0b18413b4c1af059097f5d301ee084"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "e053aca86570b3781b3e08daab51382712270d2a375257c8b5789d3d87149314"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 83 45 F8 01 81 7D F8 FF C1 EB 0B 7E D7 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_9c67a994 {
    meta:
        author = "Elastic Security"
        id = "9c67a994-dabf-4cb7-95d7-4cc47402be28"
        fingerprint = "fc6690eef99dd9f84f62444d7a7e1b52dc7f46e831a5ab3e87d4282bba979fde"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "70429d67402a43ed801e295b1ae1757e4fccd5d786c09ee054591ae51dfc1b25"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 83 45 F8 01 81 7D F8 FF C1 EB 0B 7E ?? 8B }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_ab87c1ed {
    meta:
        author = "Elastic Security"
        id = "ab87c1ed-f538-4785-b7ae-5333a7ff2808"
        fingerprint = "3bf2be85120ef3711dd3508bf8fcd573a70c7ad4a5066be1b60d777a53cd37b6"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "c13c32d3a14cbc9c2580b1c76625cce8d48c5ae683230149a3f41640655e7f28"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF 88 45 EF 80 7D EF FF 75 D6 B8 ?? ?? 04 08 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2016_5195_f1c0482a {
    meta:
        author = "Elastic Security"
        id = "f1c0482a-fe88-4777-8d49-aa782bf25a98"
        fingerprint = "96d1ed843aeb59dd43dd76f4edd9e9928dd29f86df87b70d875473b9d908e75c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2016-5195"
        reference_sample = "a12a1e8253ee1244b018fd3bdcb6b7729dfe16e06aed470f6b08344a110a4061"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF 88 45 F7 80 7D F7 FF 75 D6 B8 ?? ?? 04 08 }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2017_100011.yar
rule Linux_Exploit_CVE_2017_100011_21025f50 {
    meta:
        author = "Elastic Security"
        id = "21025f50-93af-4ea7-bdcb-ab4e210b8ac6"
        fingerprint = "a50c81daf4f081d7ddf61d05ab64d8fada5c4d6cdf8d28eb30c689e868d905aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2017-100011"
        reference_sample = "32db88b2c964ce48e6d1397ca655075ea54ce298340af55ea890a2411a67d554"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5D 20 64 6F 6E 65 2C 20 6B 65 72 6E 65 6C 20 74 65 78 74 3A }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2017_16995.yar
rule Linux_Exploit_CVE_2017_16995_0c81a317 {
    meta:
        author = "Elastic Security"
        id = "0c81a317-b296-4cda-839c-a37903e86786"
        fingerprint = "40d192607a7237c41c35d90a48cbcfd95a79c0fe7c8017d41389f15a78d620f5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2017-16995"
        reference_sample = "48d927b4b18a03dfbce54bb5f4518869773737e449301ba2477eb797afbb9972"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 89 7D F8 48 8B 45 F8 48 25 00 C0 FF FF 5D C3 55 48 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2017_16995_82816caa {
    meta:
        author = "Elastic Security"
        id = "82816caa-2fff-4b71-9544-443e611aacbf"
        fingerprint = "1a716566946fdd368230c02e2c749b6ce371fa6211be6b3db137af9b117bec87"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Exploit.CVE-2017-16995"
        reference_sample = "14e6b788db0db57067d9885ab5ff3d3a5749639549d82abd98fa4fcf27000f34"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { BC 89 45 C0 8B 45 B8 48 98 48 C1 E8 03 89 45 C4 48 8B 45 B0 48 }
    condition:
        all of them
}

rule Linux_Exploit_CVE_2017_16995_5edb0181 {
    meta:
        author = "Elastic Security"
        id = "5edb0181-dfb1-47e2-873b-0fa3043bee67"
        fingerprint = "804635a4922830b894ed38f58751f481d389e5bfbea7a50912763952971844e6"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Exploit.CVE-2017-16995"
        reference_sample = "e4df84e1dffbad217d07222314a7e13fd74771a9111d07adc467a89d8ba81127"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 2F 77 0F 45 89 C2 49 89 D1 41 83 C0 08 4A 8D 54 15 D0 48 }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2018_10561.yar
rule Linux_Exploit_CVE_2018_10561_0f246e33 {
    meta:
        author = "Elastic Security"
        id = "0f246e33-0e98-4778-8a2f-14876d1a0efe"
        fingerprint = "718b66d3d65d31f0908c8f7d7aee8113e9b51cb576cd725bbca1a23d3ccd4d72"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2018-10561"
        reference_sample = "eac08c105495e6fadd8651d2e9e650b6feba601ec78f537b17fb0e73f2973a1c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0B DF 0B 75 87 8C 5C 03 03 7A 4B 7A 95 4A A5 D2 13 6A 6A 5A 5A }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2019_13272.yar
rule Linux_Exploit_CVE_2019_13272_583dd2c0 {
    meta:
        author = "Elastic Security"
        id = "583dd2c0-9e94-4d38-bdff-e6c3b7c7d594"
        fingerprint = "afc96d47ad2564f69d2fb9a39e882bfc5b4879f0a8abbf36d5e3af6a52dccd63"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2019-13272"
        reference_sample = "3191b9473f3e59f55e062e6bdcfe61b88974602c36477bfa6855ccd92ff7ca83"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 89 85 40 FF FF FF 48 8B 45 D8 48 83 C0 20 48 89 85 38 FF }
    condition:
        all of them
}



// from Linux_Exploit_CVE_2021_3156.yar
rule Linux_Exploit_CVE_2021_3156_f3fb10cd {
    meta:
        author = "Elastic Security"
        id = "f3fb10cd-1d49-420f-8740-5c8990560943"
        fingerprint = "66aca7d13fb9c5495f17b7891e388db0a746d8827c8ae302a6cb8d86f7630bbb"
        creation_date = "2021-09-15"
        last_modified = "2021-09-21"
        threat_name = "Linux.Exploit.CVE-2021-3156"
        reference_sample = "65fb8baa5ec3bfb4473e4b2f565b461dd59989d43c72b1c5ec2e1a68baa8b51a"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "/usr/bin/sudoedit" fullword
        $a2 = "<smash_len_a>" fullword
    condition:
        all of them
}

rule Linux_Exploit_CVE_2021_3156_7f5672d0 {
    meta:
        author = "Elastic Security"
        id = "7f5672d0-73f1-4143-b3e2-3aed110779e3"
        fingerprint = "71e90dd36342686bb4be7ef86e1ceb2e915c70f437f4733ddcc5175860ca4084"
        creation_date = "2021-09-15"
        last_modified = "2021-09-21"
        threat_name = "Linux.Exploit.CVE-2021-3156"
        reference_sample = "1a4517d2582ac97b88ae568c23e75beba93daf8518bd3971985d6a798049fd61"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "/tmp/gogogo123456789012345678901234567890go" fullword
        $a2 = "gg:$5$a$gemgwVPxLx/tdtByhncd4joKlMRYQ3IVwdoBXPACCL2:0:0:gg:/root:/bin/bash" fullword
        $sudo = "sudoedit" fullword
        $msg1 = "succes with sleep time %d us" fullword
        $msg2 = "[+] Success with %d attempts" fullword
        $msg3 = "symlink 2nd time success at: %d" fullword
    condition:
        (any of ($a*)) or ($sudo and 2 of ($msg*))
}



// from Linux_Exploit_CVE_2021_3490.yar
rule Linux_Exploit_CVE_2021_3490_d369d615 {
    meta:
        author = "Elastic Security"
        id = "d369d615-d2a3-4f9d-b5c7-eb0fac5d43e7"
        fingerprint = "4f8f4c7fabe32a023f8aafb817e2c27c5a5e0e9246ddccacf99a47f2ab850014"
        creation_date = "2021-11-12"
        last_modified = "2022-01-26"
        threat_name = "Linux.Exploit.CVE-2021-3490"
        reference_sample = "e65ba616942fd1e893e10898d546fe54458debbc42e0d6826aff7a4bb4b2cf19"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $c1 = "frame_dummy_init_array_entry"
        $c2 = "leak_oob_map_ptr"
        $c3 = "overwrite_cred"
        $c4 = "obj_get_info_by_fd"
        $c5 = "kernel_write_uint"
        $c6 = "search_init_pid_ns_kstrtab"
        $c7 = "search_init_pid_ns_ksymtab"
        $msg1 = "failed to leak ptr to BPF map"
        $msg2 = "preparing to overwrite creds..."
        $msg3 = "success! enjoy r00t"
        $msg4 = "Useage: %s <path to program to execute as root>"
        $msg5 = "searching for init_pid_ns in ksymtab"
    condition:
        4 of them
}



// from Linux_Exploit_CVE_2021_4034.yar
rule Linux_Exploit_CVE_2021_4034_1c8f235d {
    meta:
        author = "Elastic Security"
        id = "1c8f235d-1345-4d5f-a5db-427dbbe6fc9a"
        fingerprint = "b145df35499a55e3e920f7701aab3b2f19af9fafbb2e0c1af53cb0b318ad06a6"
        creation_date = "2022-01-26"
        last_modified = "2022-07-22"
        threat_name = "Linux.Exploit.CVE-2021-4034"
        reference_sample = "94052c42aa41d0911e4b425dcfd6b829cec8f673bf1245af4050ef9c257f6c4b"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "PATH=GCONV_PATH="
        $s2 = "pkexec"
    condition:
        all of them
}



// from Linux_Exploit_CVE_2022_0847.yar
rule Linux_Exploit_CVE_2022_0847_e831c285 {
    meta:
        author = "Elastic Security"
        id = "e831c285-b2b9-49f3-a87c-3deb806e31e4"
        fingerprint = "376b791f9bb5f48d0f41ead4e48b5bcc74cb68002bb7c170760428ace169457e"
        creation_date = "2022-03-10"
        last_modified = "2022-03-14"
        threat_name = "Linux.Exploit.CVE-2022-0847"
        reference_sample = "c6b2cef2f2bc04e3ae33e0d368eb39eb5ea38d1bca390df47f7096117c1aecca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $pp = "prepare_pipe"
        $s1 = "splice failed"
        $s2 = "short splice"
        $s3 = "short write"
        $s4 = "hijacking suid binary"
        $s5 = "Usage: %s TARGETFILE OFFSET DATA"
        $s6 = "Usage: %s SUID"
        $bs1 = { B8 00 10 00 00 81 7D EC 00 10 00 00 0F 46 45 EC 89 45 FC 8B 55 FC 48 8B 45 D8 48 83 C0 04 8B 00 48 8D 35 }
        $bs2 = { B8 00 10 00 00 81 7D F0 00 10 00 00 0F 46 45 F0 89 45 F8 8B 55 F8 48 8B 45 D8 8B 00 48 }
    condition:
        ($pp and 2 of ($s*)) or (all of ($bs*))
}



// from Linux_Exploit_Dirtycow.yar
rule Linux_Exploit_Dirtycow_8555f149 {
    meta:
        author = "Elastic Security"
        id = "8555f149-0c91-4384-9199-8250c0fd74fd"
        fingerprint = "3d607c7ba6667c375eaab454debf8745746230d08a00499395a275e5bd05b3e4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Dirtycow"
        reference_sample = "0fd66e120f97100e48c65322b946b812fa9df4cfb533fb327760a999e4d43945"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 F8 01 81 7D F8 FF E0 F5 05 7E ?? 8B 45 }
    condition:
        all of them
}



// from Linux_Exploit_Enoket.yar
rule Linux_Exploit_Enoket_79b52a4c {
    meta:
        author = "Elastic Security"
        id = "79b52a4c-80cd-4fe1-aa6c-463e2cdd64ac"
        fingerprint = "84be6877d6b1eb091de9817a5cf0ecba5e0e82089a6dd1dc0af2e91b01fe4003"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Enoket"
        reference_sample = "3ae8f7e7df62316400d0c5fe0139d7a48c9f184e92706b552aad3d827d3dbbbf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 66 6F 75 6E 64 20 61 74 20 30 78 25 30 34 78 20 69 6E 20 74 }
    condition:
        all of them
}

rule Linux_Exploit_Enoket_5969a348 {
    meta:
        author = "Elastic Security"
        id = "5969a348-6573-4cb3-b81e-db455ff7b484"
        fingerprint = "7e9b9ba6146754857632451be2f98a5008268091ae1cfab1a87322b6fe30097c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Enoket"
        reference_sample = "4b4d7ca9e1ffa2c46cb097d4a014c59b1a9feb93b3adcb5936ef6a1dfef9b0ae"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 83 7D FC FF 75 07 B8 FF FF FF FF EB 0F 8B 45 FC 01 45 F0 83 7D }
    condition:
        all of them
}

rule Linux_Exploit_Enoket_80fac3e9 {
    meta:
        author = "Elastic Security"
        id = "80fac3e9-bf77-46d1-8d9b-25f3cf06a3b7"
        fingerprint = "627418bfe84af36e9b34d42aa42cb6d793e6bc41aa555a77e4f9389a9407d6f2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Enoket"
        reference_sample = "3355ad81c566914a7d7734b40c46ded0cfa53aa22c6e834d42e185bf8bbe6128"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 4C 45 20 54 4F 20 4D 41 50 20 5A 45 52 4F 20 50 41 47 45 }
    condition:
        all of them
}

rule Linux_Exploit_Enoket_7da5f86a {
    meta:
        author = "Elastic Security"
        id = "7da5f86a-c177-47c9-a82e-50648c84174a"
        fingerprint = "cf9a703969e3f9a3cd20119fc0a24fa2d16bec5ea7e3b1a8df763872625c90fc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Enoket"
        reference_sample = "406b003978d79d453d3e2c21b991b113bf2fc53ffbf3a1724c5b97a4903ef550"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 75 F2 80 7D 94 00 74 23 0F B6 0F B8 01 00 00 00 3A 4D 94 }
    condition:
        all of them
}

rule Linux_Exploit_Enoket_c77c0d6d {
    meta:
        author = "Elastic Security"
        id = "c77c0d6d-7f5c-4618-b6f6-3c1ddc70783c"
        fingerprint = "739e23abbd2971d6ff24c94a87d7aab082aec85f9cd7eb3a168b35fa22f32eb9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Enoket"
        reference_sample = "3ae8f7e7df62316400d0c5fe0139d7a48c9f184e92706b552aad3d827d3dbbbf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 64 20 74 68 65 20 77 6F 72 6C 64 2C 20 6F 6E 65 20 68 61 }
    condition:
        all of them
}

rule Linux_Exploit_Enoket_fbf508e1 {
    meta:
        author = "Elastic Security"
        id = "fbf508e1-2a44-417e-a2e4-8d43c2b64017"
        fingerprint = "4909d3a04b820547fbff774c64c112b8a6a5e95452992639296a220776826d98"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Enoket"
        reference_sample = "d1fa8520d3c3811d29c3d5702e7e0e7296b3faef0553835c495223a2bc015214"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 E8 76 0F 48 8B 45 E8 48 83 E8 01 0F B6 00 3C 5F 74 DF 48 8B }
    condition:
        all of them
}



// from Linux_Exploit_Foda.yar
rule Linux_Exploit_Foda_f41e9ef9 {
    meta:
        author = "Elastic Security"
        id = "f41e9ef9-b280-44cb-b877-ac998eea84d3"
        fingerprint = "d24064932ef3a972970ce446d465c28379bf83b1b72f5bf77d1def3074747a8e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Foda"
        reference_sample = "6059a6dd039b5efa36ce97acbb01406128aaf6062429474e422624ee69783ca8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 50 89 E2 53 89 E1 B0 0B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}



// from Linux_Exploit_Intfour.yar
rule Linux_Exploit_Intfour_0ca45cd3 {
    meta:
        author = "Elastic Security"
        id = "0ca45cd3-089c-4d7f-9088-dc972c14bd9d"
        fingerprint = "8926a8cfd7f3adf29e399a945592063039b80dcc0545b133b453aaf198d31461"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Intfour"
        reference_sample = "9d32c5447aa5182b4be66b7a283616cf531a2fd3ba3dde1bc363b24d8b22682f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6D 28 63 6F 64 65 2C 20 31 30 32 34 2C 20 26 6E 65 65 64 6C 65 }
    condition:
        all of them
}



// from Linux_Exploit_IOUring.yar
rule Linux_Exploit_IOUring_d04c1c19 {
    meta:
        author = "Elastic Security"
        id = "d04c1c19-9303-41cd-ae9c-149bb137e6cc"
        fingerprint = "0e50d858b8e5428a964dc70b0132659defd61e8965331fa327b1f454bf922162"
        creation_date = "2024-04-07"
        last_modified = "2024-06-12"
        threat_name = "Linux.Exploit.IOUring"
        reference_sample = "29e6a5f7b36e271219601528f3fd70831aacb8b9f05722779faa40afc97b3b60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "io_uring_"
        $s2 = "kaslr_leak: 0x%llx"
        $s3 = "kaslr_base: 0x%llx"
    condition:
        all of them
}



// from Linux_Exploit_Local.yar
rule Linux_Exploit_Local_47c64fb6 {
    meta:
        author = "Elastic Security"
        id = "47c64fb6-cfa6-4350-a41f-870b87116b32"
        fingerprint = "aa286440061fb31167f314111dde7c2f596357b41fb6a5656216892fee6bf56e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "0caa9035027ff88788e6b8e43bfc012a367a12148be809555c025942054a6360"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 C6 00 FF 8B 45 F4 40 C6 00 25 8B 45 F4 83 C0 02 C7 00 08 00 }
    condition:
        all of them
}

rule Linux_Exploit_Local_76c24b62 {
    meta:
        author = "Elastic Security"
        id = "76c24b62-e04f-410d-b7cb-668daa9aea20"
        fingerprint = "907cb776c9200b715c5b20475c2d4b16cb55c607dfb4b57bd3bd95368ce66257"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "330de2ca1add7e06389d94dfc541c367a484394c51663b26d27d89346b08ad1b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 31 DB 89 D8 B0 17 CD 80 31 C0 50 50 B0 }
    condition:
        all of them
}

rule Linux_Exploit_Local_30c21b03 {
    meta:
        author = "Elastic Security"
        id = "30c21b03-22fc-4ec8-8b65-084e98da8d8d"
        fingerprint = "8112c4a9bce4b4c9407e851849a5850fa36591570694950a4b53e8a09a1dd92b"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "a09c81f185a4ceed134406fa7fefdfa7d8dfc10d639dd044c94fbb6d570fa029"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1B CD 80 31 DB 89 D8 B0 17 CD 80 31 C0 50 50 B0 }
    condition:
        all of them
}

rule Linux_Exploit_Local_9ace9649 {
    meta:
        author = "Elastic Security"
        id = "9ace9649-c74a-4b27-a147-d14123104c0a"
        fingerprint = "2e526d7ec47a30c7683725c2d2c3db0a8267630bb0f270599325d50227f6ae29"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "b38869605521531153cfd8077f05e0d6b52dca0fffbc627a4d5eaa84855a491c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 C0 31 DB 31 C9 B0 46 CD 80 31 C0 50 68 2F }
    condition:
        all of them
}

rule Linux_Exploit_Local_705c9589 {
    meta:
        author = "Elastic Security"
        id = "705c9589-f735-45ef-8cf0-b99a05905a9f"
        fingerprint = "d75edca622f0ab8a0b60c4ba5c1026c89d3613c0e101c5c12c03ee08cb7c576e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "845727ea46491b46a665d4e1a3a9dbbe6cd0536d070f1c1efd533b91b75cdc88"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 51 53 8D 0C 24 31 C0 B0 0B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}

rule Linux_Exploit_Local_a677fb9c {
    meta:
        author = "Elastic Security"
        id = "a677fb9c-0271-4491-a7c7-48504b6ec389"
        fingerprint = "b7916eefad806131b39af5f9bef27648e2444c9a9c95216b520d73e64fa734f0"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "d20b260c7485173264e3e674adc7563ea3891224a3dc98bdd342ebac4a1349e8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 EC 83 7D EC FF 75 1A 83 EC 0C 68 }
    condition:
        all of them
}

rule Linux_Exploit_Local_78e50162 {
    meta:
        author = "Elastic Security"
        id = "78e50162-8f1e-4c78-94fe-9b793b006269"
        fingerprint = "a5771dad186d0c23d25efb7b22b11aa0a67148cf6efb9657b09ca6e160c192aa"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "706c865257d5e1f5f434ae0f31e11dfc7e16423c4c639cb2763ec0f51bc73300"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 90 90 90 31 C0 31 DB B0 17 CD 80 31 C0 B0 2E CD }
    condition:
        all of them
}

rule Linux_Exploit_Local_3b767a1f {
    meta:
        author = "Elastic Security"
        id = "3b767a1f-5844-4742-a5fd-ef8a3ddb6c12"
        fingerprint = "2bc0dc4de92306076cda6f2d069855b85861375c8b7eb5324f915a1ed10c39e5"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "e05fed9e514cccbdb775f295327d8f8838b73ad12f25e7bb0b9d607ff3d0511c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 50 53 89 E1 89 C2 B0 0B CD 80 89 C3 31 C0 40 }
    condition:
        all of them
}

rule Linux_Exploit_Local_2535c9b6 {
    meta:
        author = "Elastic Security"
        id = "2535c9b6-a575-4190-8e33-88758675e5b4"
        fingerprint = "4ec419bfd0ac83da2f826ba4cbd6a4b05bbd7b6f6cc077529ec4667b7d2f761a"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "d0f9cc114f6a1f788f36e359e03a9bbf89c075f41aec006229b6ad20ebbfba0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 63 F9 FF FF 83 7D D8 FF 75 14 BF 47 12 40 00 }
    condition:
        all of them
}

rule Linux_Exploit_Local_6a9b5d50 {
    meta:
        author = "Elastic Security"
        id = "6a9b5d50-3cd4-4b64-9a52-713e1a8f02b2"
        fingerprint = "7eea1345492359984e9be089c3e7339b79927abcff0ae4a40a713e956bb25919"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "80ab71dc9ed2131b08b5b75b5a4a12719d499c6b6ee6819ad5a6626df4a1b862"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 ?? F9 FF FF 83 7D D8 FF 75 14 BF ?? 13 40 00 }
    condition:
        all of them
}

rule Linux_Exploit_Local_66557224 {
    meta:
        author = "Elastic Security"
        id = "66557224-2c7a-4770-8333-8984d4a7b3f7"
        fingerprint = "88503c2e1e389866962704a8b19a47c22f758bb2cee9b76600e5d9bab125d4ca"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "f58151a2f653972e744822cdc420ab1c2b8b642877d3dfa2e8b2b6915e8edf40"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF 83 BD E4 FB FF FF FF 75 1A 83 EC 0C 68 24 }
    condition:
        all of them
}

rule Linux_Exploit_Local_6229602f {
    meta:
        author = "Elastic Security"
        id = "6229602f-1c88-46fa-8fae-a6268ed6d632"
        fingerprint = "b26b21518fd436d79d6a23dbf3d7056b7c056e4df6639718e285de096476f61d"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Local"
        reference_sample = "4fdb15663a405f6fc4379aad9a5021040d7063b8bb82403bedb9578d45d428fa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 FC 83 7D FC 00 7D 17 68 ?? ?? 04 08 }
    condition:
        all of them
}



// from Linux_Exploit_Log4j.yar
rule Linux_Exploit_Log4j_7fc4d480 {
    meta:
        author = "Elastic Security"
        id = "7fc4d480-5354-4b0b-93ee-2937ddd1565c"
        fingerprint = "cd06db6f5bebf0412d056017259b5451184d5ba5b2976efd18fa8f96dba6a159"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Exploit.Log4j"
        reference = "https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
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



// from Linux_Exploit_Lotoor.yar
rule Linux_Exploit_Lotoor_03c81bd9 {
    meta:
        author = "Elastic Security"
        id = "03c81bd9-c7d1-4044-9cce-951637b2b523"
        fingerprint = "329dc1e21088c87095ee030c597a3340f838c338403ae64aec574e0086281461"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "3fc701a2caab0297112501f55eaeb05264c5e4099c411dcadc7095627e19837a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 65 00 65 78 70 5F 73 74 61 74 65 00 6D 65 6D 73 65 74 00 70 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_757637d9 {
    meta:
        author = "Elastic Security"
        id = "757637d9-6171-4e2a-bf7c-3ee2c71066a7"
        fingerprint = "7fa3e2432ddd696b5d40aafbde1e026e74294d31c9201800ce66b343a3724c6e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "0762fa4e0d74e3c21b2afc8e4c28e2292d1c3de3683c46b5b77f0f9fe1faeec7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 00 73 70 72 69 6E 74 66 00 6F 70 65 6E 00 69 73 5F 6F 6C }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_78543893 {
    meta:
        author = "Elastic Security"
        id = "78543893-7180-4857-8951-4190ca4602f1"
        fingerprint = "b581e0820d7895021841d67e4e9dc40cec8f5ae5ba4dbc0585abcb76f97c9a2f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "ff5b02d2b4dfa9c3d53e7218533f3c57e82315be8f62aa17e26eda55a3b53479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 48 8B 48 08 48 8B 54 24 F0 48 63 C6 48 89 8C C2 88 00 00 00 83 44 24 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_4f8d83d2 {
    meta:
        author = "Elastic Security"
        id = "4f8d83d2-4f7b-4a55-9d08-f7bc84263302"
        fingerprint = "1a4e2746eb1da2a841c08ea44c6d0476c02dae5b4fbbe17926433bdb8c4e6df5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "d78128eca706557eeab8a454cf875362a097459347ddc32118f71bd6c73d5bbd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 75 6E 61 6D 65 00 73 74 64 6F 75 74 00 66 77 72 69 74 65 00 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_f4afd230 {
    meta:
        author = "Elastic Security"
        id = "f4afd230-6c9f-49e8-8f13-429635b38eb5"
        fingerprint = "1709244fdc1e2d9d7fba01743b0cf87de7b940d2b25a0016e021b7e9696525bc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "805e900ffc9edb9f550dcbc938a3b06d28e9e7d3fb604ff68a311a0accbcd2b1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 20 FF FF FF 85 C0 74 25 8B 83 F8 FF FF FF 85 C0 74 1B 83 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_bb384bc9 {
    meta:
        author = "Elastic Security"
        id = "bb384bc9-fcda-4ad4-82ad-b95de750d31c"
        fingerprint = "6878670c1fa154f5c4a845a824c63d0a900359b6e122b3fa759077c6a7e33e4c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "ecc6635117b99419255af5d292a7af3887b06d5f3b0f59d158281eebfe606445"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C2 75 64 4C 8B 45 F0 49 83 C0 04 4C 8B 4D F0 49 83 C1 08 48 8B }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_b293f6ec {
    meta:
        author = "Elastic Security"
        id = "b293f6ec-0342-4727-b2a1-bd60be11ef74"
        fingerprint = "42c95bdd82e398bceeb985cff50f4613596b71024c052487f5b337bb35489594"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "d1fa8520d3c3811d29c3d5702e7e0e7296b3faef0553835c495223a2bc015214"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B8 89 45 A8 8B 45 A8 83 C0 64 89 45 B4 EB 2A 8B 45 A8 48 98 48 C1 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_c5983669 {
    meta:
        author = "Elastic Security"
        id = "c5983669-67d6-4a9e-945f-aae383211872"
        fingerprint = "1d74ddacc623a433f84b1ab6e74bcfc0e69afb29f40a8b2d660d96a88610c3b2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "d08be92a484991afae3567256b6cec60a53400e0e9b6f6b4d5c416a22ccca1cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 83 C0 58 48 89 44 24 20 48 8B 44 24 18 48 89 C7 BA 60 00 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_fbff22da {
    meta:
        author = "Elastic Security"
        id = "fbff22da-2f31-416c-8aa0-1003e3be8baa"
        fingerprint = "b649b172fad3e3b085cbf250bd17dbea4c409a7337914c63230d188f9b8135fa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "0762fa4e0d74e3c21b2afc8e4c28e2292d1c3de3683c46b5b77f0f9fe1faeec7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 75 6E 61 6D 65 00 73 74 72 6C 65 6E 00 73 74 64 6F 75 74 00 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_e2d5fad8 {
    meta:
        author = "Elastic Security"
        id = "e2d5fad8-45b6-4d65-826d-b909230e2b69"
        fingerprint = "ec64f2c3ca5ec2bfc2146159dab3258e389be5962bdddf4c6db5975cc730a231"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "7e54e57db3de32555c15e529c04b35f52d75af630e45b5f8d6c21149866b6929"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 E4 8B 00 89 45 E8 8B 45 E8 8B 00 85 C0 75 08 8B 45 E8 89 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_f2f8eb6b {
    meta:
        author = "Elastic Security"
        id = "f2f8eb6b-1fc3-4fca-b58d-d71ad932e1a7"
        fingerprint = "881e2cd5b644c2511306b3670320224810de369971278516f7562076226fa5b7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "01721b9c024ca943f42c402a57f45bd4c77203a604c5c2cd26e5670df76a95b2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 14 40 00 00 00 EB 38 8B 44 24 14 48 98 83 E0 3F 48 85 C0 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_f8e9f93c {
    meta:
        author = "Elastic Security"
        id = "f8e9f93c-78ad-4ca5-a210-e62072e6f8c8"
        fingerprint = "bdf87b68d1101cd3fcbc505de0d2e9b2aed9535aaafa9f746f7a3c4fba03b464"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "50a6d546d4c45dc33c5ece3c09dbc850b469b9b8deeb7181a45ba84459cb24c9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 61 ?? 3A 20 4C 69 6E 75 78 20 32 2E 36 2E 33 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_89671b03 {
    meta:
        author = "Elastic Security"
        id = "89671b03-5bd4-481b-9304-2655ea689c5f"
        fingerprint = "e8b9631e5d4d8db559615504cc3f6fbd8a81bfbdb9e570113f20d006c44c8a9c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "001098473574cfac1edaca9f1180ab2005569e094be63186c45b48c18f880cf8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 62 65 6C 3A 20 4C 69 6E 75 78 20 3C 20 32 2E 36 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_dbc73db0 {
    meta:
        author = "Elastic Security"
        id = "dbc73db0-527c-436f-afdc-bc3750f10ea0"
        fingerprint = "2f6ad833b84f00be1d385de686a979d3738147c38b4126506e56225080ee81ef"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "9fe78e4dd7975856a74d8dfd83e69793a769143e0fe6994cbc3ef28ea37d6cf8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 63 75 73 3A 20 4C 69 6E 75 78 20 32 2E 36 2E 33 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_ec339160 {
    meta:
        author = "Elastic Security"
        id = "ec339160-5f25-495c-8e48-4683ad2fcca0"
        fingerprint = "24a3630fd49860104c60c4f4d0ef03bd17c124383a0b5d027a06c7ca6cb9cbba"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "0002b469972f5c77a29e2a2719186059a3e96a6f4b1ef2d18a68fee3205ea0ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 75 6D 3A 20 4C 69 6E 75 78 20 32 2E 58 20 73 }
    condition:
        all of them
}

rule Linux_Exploit_Lotoor_7cd57e18 {
    meta:
        author = "Elastic Security"
        id = "7cd57e18-2315-419b-b373-ea801181232c"
        fingerprint = "a7d3183de1bccd816bcd2346e9754aaf6e7eb124d7416d79bdbe422b33035414"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Lotoor"
        reference_sample = "1eecf16dae302ae788d1bc81278139cd9f6af52d7bed48b8677b35ba5eb14e30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 76 65 3A 20 4C 69 6E 75 78 20 32 2E 36 2E }
    condition:
        all of them
}



// from Linux_Exploit_Moogrey.yar
rule Linux_Exploit_Moogrey_81131b66 {
    meta:
        author = "Elastic Security"
        id = "81131b66-788e-4456-9cb4-ffade713e8d4"
        fingerprint = "d21e48c7afe580a764153ca489c24a7039ae663ebb281a4605f3a230a963e33e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Moogrey"
        reference_sample = "cc27b9755bd9feb1fb2c510f66e36c20a1503e6769cdaeee2bea7fe962d22ccc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 D4 83 7D D4 00 79 1A 83 EC 0C 68 50 }
    condition:
        all of them
}



// from Linux_Exploit_Openssl.yar
rule Linux_Exploit_Openssl_47c6fad7 {
    meta:
        author = "Elastic Security"
        id = "47c6fad7-0582-4a7a-9c51-68830e6b6132"
        fingerprint = "bde819830cc991269275ce5de2db50489368c821271aaa397ab914011f2fcb91"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Openssl"
        reference_sample = "8024af0931dff24b5444f0b06a27366a776014358aa0b7fc073030958f863ef8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 C9 F7 E1 51 5B B0 A4 CD 80 31 C0 50 68 2F }
    condition:
        all of them
}



// from Linux_Exploit_Perl.yar
rule Linux_Exploit_Perl_4a4b8a42 {
    meta:
        author = "Elastic Security"
        id = "4a4b8a42-bf26-4323-a12d-06360cd88aa3"
        fingerprint = "70ae986009e1d375a0322bf31fbae2090b7c0b6051ddd850e103e654d7b237b2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Perl"
        reference_sample = "d1fa8520d3c3811d29c3d5702e7e0e7296b3faef0553835c495223a2bc015214"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 73 65 65 6B 69 6E 67 20 6F 75 74 20 74 68 65 20 73 6D 61 }
    condition:
        all of them
}

rule Linux_Exploit_Perl_982bb709 {
    meta:
        author = "Elastic Security"
        id = "982bb709-beec-4f7f-b249-44b1fb46c3be"
        fingerprint = "a2f68acb31b84e93f902aeb838ad550e1644c20e1c8060bb8de8ad57fa4ba4bb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Perl"
        reference_sample = "f3e4e2b5af9d0c72aae83cec57e5c091a95c549f826e8f13559aaf7d300f6e13"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 75 65 20 53 65 70 20 32 31 20 31 36 3A 34 38 3A 31 32 20 }
    condition:
        all of them
}



// from Linux_Exploit_Pulse.yar
rule Linux_Exploit_Pulse_2bea17e8 {
    meta:
        author = "Elastic Security"
        id = "2bea17e8-2324-4502-9ced-7a45d94099ec"
        fingerprint = "4d57fb355e7d68ad3da26ff3bade291ebbfa8df5f0727579787e33ebee888d41"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Pulse"
        reference_sample = "c29cb4c2d83127cf4731573a7fac531f90f27799857f5e250b9f71362108f559"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 8D 45 F8 48 89 45 F8 48 8B 45 F8 48 25 00 F0 FF FF 48 }
    condition:
        all of them
}

rule Linux_Exploit_Pulse_246e6f31 {
    meta:
        author = "Elastic Security"
        id = "246e6f31-fcfb-474e-9709-a5d7ea6586fd"
        fingerprint = "e98007a2fa62576e1847cf350283f60f1e4e49585574601ab44b304f391240db"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Pulse"
        reference_sample = "c29cb4c2d83127cf4731573a7fac531f90f27799857f5e250b9f71362108f559"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 8D 45 F8 48 89 45 F8 48 8B 45 F8 48 25 00 E0 FF FF 48 8B 00 48 89 }
    condition:
        all of them
}



// from Linux_Exploit_Race.yar
rule Linux_Exploit_Race_758a0884 {
    meta:
        author = "Elastic Security"
        id = "758a0884-0174-46c8-a57a-980fc04360d0"
        fingerprint = "3516086ae773ec1c1de75a54bafbb72ad49b4c7f1661961d5613462b53f26c43"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Race"
        reference_sample = "a4966baaa34b05cb782071ef114a53cac164e6dece275c862fe96a2cff4a6f06"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 22 00 00 00 36 00 00 00 18 85 04 08 34 00 00 00 12 00 00 }
    condition:
        all of them
}



// from Linux_Exploit_Ramen.yar
rule Linux_Exploit_Ramen_01b205eb {
    meta:
        author = "Elastic Security"
        id = "01b205eb-4718-4ffd-9fdc-b9de567c4603"
        fingerprint = "a39afcf7cec82dc511fd39b4a019ef161250afe7cb0880e488badb56d021cc9f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Ramen"
        reference_sample = "c0b6303300f38013840abe17abe192db6a99ace78c83bc7ef705f5c568bc98fd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 31 C0 31 DB 31 C9 B0 46 CD 80 31 C0 31 DB 43 }
    condition:
        all of them
}



// from Linux_Exploit_Sorso.yar
rule Linux_Exploit_Sorso_ecf99f8f {
    meta:
        author = "Elastic Security"
        id = "ecf99f8f-1692-41ee-a70d-8c868e269529"
        fingerprint = "d2c0ccceed8a76d13c8b388e5c3b560f23ecff2b1b9c90d18e5e0d0bbdc91364"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Sorso"
        reference_sample = "c0f0a7b45fb91bc18264d901c20539dd32bc03fa5b7d839a0ef5012fb0d895cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 89 E3 50 54 53 50 B0 3B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}

rule Linux_Exploit_Sorso_91a4d487 {
    meta:
        author = "Elastic Security"
        id = "91a4d487-cbb6-4805-a4fc-5f4ff3b0e22b"
        fingerprint = "4965d806fa46b74023791ca17a90031753fbbe6094d25868e8d93e720f61d4c0"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Sorso"
        reference_sample = "c0f0a7b45fb91bc18264d901c20539dd32bc03fa5b7d839a0ef5012fb0d895cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 80 31 C0 43 53 56 50 B0 5A CD 80 31 C0 50 68 2F }
    condition:
        all of them
}

rule Linux_Exploit_Sorso_61eae7dd {
    meta:
        author = "Elastic Security"
        id = "61eae7dd-3335-4a50-b70b-c7c5657fc540"
        fingerprint = "8ada74a60e30a26f7789bfdf00b3373843f39dc7d71bd6e1b603a7a41b5a63e9"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Sorso"
        reference_sample = "c0f0a7b45fb91bc18264d901c20539dd32bc03fa5b7d839a0ef5012fb0d895cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 89 E3 50 53 89 E1 B0 0B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}



// from Linux_Exploit_Vmsplice.yar
rule Linux_Exploit_Vmsplice_cfa94001 {
    meta:
        author = "Elastic Security"
        id = "cfa94001-6000-4633-9af2-efabfaa96f94"
        fingerprint = "3fb484112484e2afc04a88d50326312af950605c61f258651479427b7bae300a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Vmsplice"
        reference_sample = "0a26e67692605253819c489cd4793a57e86089d50150124394c30a8801bf33e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7A 00 21 40 23 24 00 6D 6D 61 70 00 5B 2B 5D 20 6D 6D 61 70 3A }
    condition:
        all of them
}

rule Linux_Exploit_Vmsplice_a000f267 {
    meta:
        author = "Elastic Security"
        id = "a000f267-b4d7-46e9-ab61-818633083ba2"
        fingerprint = "0753ef1bc3e151fd6d4773967b5cde6ad789df593e7d8b9ed08052151a1a1849"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Vmsplice"
        reference_sample = "c85cc6768a28fb7de16f1cad8d3c69d8f0b4aa01e00c8e48759d27092747ca6f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 73 00 00 00 89 44 24 00 CF 83 C4 10 5B C9 C3 55 89 E5 83 }
    condition:
        all of them
}

rule Linux_Exploit_Vmsplice_8b9e4f9f {
    meta:
        author = "Elastic Security"
        id = "8b9e4f9f-7903-4aa5-9098-766f4311a22b"
        fingerprint = "585b16ad3e4489a17610f0a226be428def33e411886f273d0c1db45b3819ba3f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Vmsplice"
        reference_sample = "0230c81ba747e588cd9b6113df6e1867dcabf9d8ada0c1921d1bffa9c1b9c75d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 00 20 4C 69 6E 75 78 20 76 6D 73 70 6C }
    condition:
        all of them
}

rule Linux_Exploit_Vmsplice_055f88b8 {
    meta:
        author = "Elastic Security"
        id = "055f88b8-b1b0-4b02-8fc5-97804b564d27"
        fingerprint = "38f7d6c56ee1cd465062b5c82320710c4d0393a3b33f5586b6c0c0c778e5d3b2"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Vmsplice"
        reference_sample = "607c8c5edc8cbbd79a40ce4a0eccf46e01447985d9415d1eff6a91bf64074507"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2D 2D 2D 00 20 4C 69 6E 75 78 20 76 6D 73 70 6C }
    condition:
        all of them
}

rule Linux_Exploit_Vmsplice_431e689d {
    meta:
        author = "Elastic Security"
        id = "431e689d-0c41-4c92-98b0-0dac529d8328"
        fingerprint = "1e8aee445a3adef6ccbd2d25f7b38202bef98a99b828eda56fb8b9269b6316b4"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Vmsplice"
        reference = "1cbb09223f16af4cd13545d72dbeeb996900535b1e279e4bcf447670728de1e1"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 6F 6E 00 70 75 74 65 6E 76 00 73 74 64 6F 75 74 00 73 65 }
    condition:
        all of them
}



// from Linux_Exploit_Wuftpd.yar
rule Linux_Exploit_Wuftpd_0991e62f {
    meta:
        author = "Elastic Security"
        id = "0991e62f-af72-416a-b88b-6bc8a501b8bb"
        fingerprint = "642c7b059fa604a0a5110372e2247da9625b07008b012fd498670a6dd1b29974"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.Wuftpd"
        reference_sample = "c0b6303300f38013840abe17abe192db6a99ace78c83bc7ef705f5c568bc98fd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F3 8D 4E 08 8D 56 0C B0 0B CD 80 31 C0 31 DB }
    condition:
        all of them
}



// from Linux_Generic_Threat.yar
rule Linux_Generic_Threat_a658b75f {
    meta:
        author = "Elastic Security"
        id = "a658b75f-3520-4ec6-b3d4-674bc22380b3"
        fingerprint = "112be9d42b300ce4c2e0d50c9e853d3bdab5d030a12d87aa9bae9affc67cd6cd"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "df430ab9f5084a3e62a6c97c6c6279f2461618f038832305057c51b441c648d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6D 61 69 6E 2E 45 6E 63 72 79 70 74 46 69 6C 65 52 65 61 64 57 72 69 74 65 }
        $a2 = { 6D 61 69 6E 2E 53 63 61 6E 57 61 6C 6B 65 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_ea5ade9a {
    meta:
        author = "Elastic Security"
        id = "ea5ade9a-101e-49df-b0e8-45a04320950b"
        fingerprint = "fedf3b94c22a1dab3916b7bc6a1b88768c0debd6d628b78d8a6610b636f3c652"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d75189d883b739d9fe558637b1fab7f41e414937a8bae7a9d58347c223a1fcaa"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 53 8B 5D 08 B8 0D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 B8 2D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 8B 4D 0C B8 6C 00 00 00 CD 80 8B 5D FC 89 EC }
    condition:
        all of them
}

rule Linux_Generic_Threat_80aea077 {
    meta:
        author = "Elastic Security"
        id = "80aea077-c94f-4c95-83a5-967cc16df2a8"
        fingerprint = "702953af345afb999691906807066d58b9ec055d814fc6fe351e59ac5193e31f"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "002827c41bc93772cd2832bc08dfc413302b1a29008adbb6822343861b9818f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 38 49 89 FE 0F B6 0E 48 C1 E1 18 0F B6 6E 01 48 C1 E5 10 48 09 E9 0F B6 6E 03 48 09 E9 0F B6 6E 02 48 C1 E5 08 48 09 CD 0F B6 56 04 48 C1 E2 18 44 0F B6 7E 05 49 C1 E7 10 4C 09 FA 44 }
    condition:
        all of them
}

rule Linux_Generic_Threat_2e214a04 {
    meta:
        author = "Elastic Security"
        id = "2e214a04-43a4-4c26-8737-e089fbf6eecd"
        fingerprint = "0937f7c5bcfd6f2b327981367684cff5a53d35c87eaa360e90afc9fce1aec070"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cad65816cc1a83c131fad63a545a4bd0bdaa45ea8cf039cbc6191e3c9f19dead"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 49 6E 73 65 72 74 20 76 69 63 74 69 6D 20 49 50 3A 20 }
        $a2 = { 49 6E 73 65 72 74 20 75 6E 75 73 65 64 20 49 50 3A 20 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0b770605 {
    meta:
        author = "Elastic Security"
        id = "0b770605-db33-4028-b186-b1284da3e3fe"
        fingerprint = "d771f9329fec5e70b515512b58d77bb82b3c472cd0608901a6e6f606762d2d7e"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "99418cbe1496d5cd4177a341e6121411bc1fab600d192a3c9772e8e6cd3c4e88"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 68 65 79 20 73 63 61 6E 20 72 65 74 61 72 64 }
        $a2 = { 5B 62 6F 74 70 6B 74 5D 20 43 6F 6D 6D 69 74 74 69 6E 67 20 53 75 69 63 69 64 65 }
    condition:
        all of them
}

rule Linux_Generic_Threat_92064b27 {
    meta:
        author = "Elastic Security"
        id = "92064b27-f1c7-4b86-afc9-3dcfab69fe0d"
        fingerprint = "7a465615646184f5ab30d9b9b286f6e8a95cfbfa0ee780915983ec1200fd2553"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "8e5cfcda52656a98105a48783b9362bad22f61bcb6a12a27207a08de826432d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 53 8B 4D 10 8B 5D 08 85 C9 74 0D 8A 55 0C 31 C0 88 14 18 40 39 C1 75 F8 5B 5D C3 90 90 55 89 E5 8B 4D 08 8B 55 0C 85 C9 74 0F 85 D2 74 0B 31 C0 C6 04 08 00 40 39 C2 75 F7 5D C3 90 90 }
    condition:
        all of them
}

rule Linux_Generic_Threat_de6be095 {
    meta:
        author = "Elastic Security"
        id = "de6be095-93b6-45da-b9e2-682cea7a6488"
        fingerprint = "8f2d682401b4941615ecdc8483ff461c86a12c585483e00d025a1b898321a585"
        creation_date = "2024-01-17"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2431239d6e60ca24a5440e6c92da62b723a7e35c805f04db6b80f96c8cf9fee6"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2D 2D 66 61 72 6D 2D 66 61 69 6C 6F 76 65 72 }
        $a2 = { 2D 2D 73 74 72 61 74 75 6D 2D 66 61 69 6C 6F 76 65 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_898d9308 {
    meta:
        author = "Elastic Security"
        id = "898d9308-86d1-4b73-ae6c-c24716466f60"
        fingerprint = "fe860a6283aff8581b73440f9afbd807bb03b86dd9387b0b4ee5842a39ed7b03"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "ce89863a16787a6f39c25fd15ee48c4d196223668a264217f5d1cea31f8dc8ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 65 63 66 61 66 65 61 62 36 65 65 37 64 36 34 32 }
        $a2 = { 3D 3D 3D 3D 65 6E 64 20 64 75 6D 70 20 70 6C 75 67 69 6E 20 69 6E 66 6F 3D 3D 3D 3D }
    condition:
        all of them
}

rule Linux_Generic_Threat_23d54a0e {
    meta:
        author = "Elastic Security"
        id = "23d54a0e-f2e2-443e-832c-d57146350eb6"
        fingerprint = "4ff521192e2061af868b9403479680fd77d1dc71f181877a36329f63e91b7c66"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 29 2B 2F 30 31 3C 3D 43 4C 4D 50 53 5A 5B }
        $a2 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }
    condition:
        all of them
}

rule Linux_Generic_Threat_d7802b0a {
    meta:
        author = "Elastic Security"
        id = "d7802b0a-2286-48c8-a0b5-96af896b384e"
        fingerprint = "105112354dea4db98d295965d4816c219b049fe7b8b714f8dc3d428058a41a32"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC 88 00 00 00 48 89 AC 24 80 00 00 00 48 8D AC 24 80 00 00 00 49 C7 C5 00 00 00 00 4C 89 6C 24 78 88 8C 24 A8 00 00 00 48 89 9C 24 A0 00 00 00 48 89 84 24 98 00 00 00 C6 44 24 27 00 90 }
    condition:
        all of them
}

rule Linux_Generic_Threat_08e4ee8c {
    meta:
        author = "Elastic Security"
        id = "08e4ee8c-4dfd-4bb8-9406-dce6fb7bc9ee"
        fingerprint = "5e71d8515def09e95866a08951dd06bb84d327489f000e1c2326448faad15753"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "35eeba173fb481ac30c40c1659ccc129eae2d4d922e27cf071047698e8d95aea"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 78 63 72 79 70 74 6F 67 72 61 70 68 79 2D 32 2E 31 2E 34 2D 70 79 32 2E 37 2E 65 67 67 2D 69 6E 66 6F 2F 50 4B 47 2D 49 4E 46 4F }
    condition:
        all of them
}

rule Linux_Generic_Threat_d60e5924 {
    meta:
        author = "Elastic Security"
        id = "d60e5924-c216-4780-ba61-101abfd94b9d"
        fingerprint = "e5c5833e193c93191783b6b5c7687f5606b1bbe2e7892086246ed883e57c5d15"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "fdcc2366033541053a7c2994e1789f049e9e6579226478e2b420ebe8a7cebcd3"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2E 2F 6F 76 6C 63 61 70 2F 6D 65 72 67 65 2F 6D 61 67 69 63 }
        $a2 = { 65 78 65 63 6C 20 2F 62 69 6E 2F 62 61 73 68 }
    condition:
        all of them
}

rule Linux_Generic_Threat_6bed4416 {
    meta:
        author = "Elastic Security"
        id = "6bed4416-18fe-4416-a6ee-89d269922347"
        fingerprint = "f9d39e6aa9f8b005ff156923c68d215dabf2db79bd7d4a3dccb9ead8f1a28d88"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }
    condition:
        all of them
}

rule Linux_Generic_Threat_fc5b5b86 {
    meta:
        author = "Elastic Security"
        id = "fc5b5b86-fa68-428d-ba31-67057380a10b"
        fingerprint = "bae66e297c19cf9c278eaefcd3cc8b3c972381effd160ee99e6f04f4ac74389d"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "134b063d9b5faed11c6db6848f800b63748ca81aeca46caa0a7c447d07a9cd9b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 74 1D 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 92 98 05 00 8B 44 24 }
    condition:
        all of them
}

rule Linux_Generic_Threat_2c8d824c {
    meta:
        author = "Elastic Security"
        id = "2c8d824c-4791-46a6-ba4d-5dcc09fdc638"
        fingerprint = "8e54bf3f6b7b563d773a1f5de0b37b8bec455c44f8af57fde9a9b684bb6f5044"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "9106bdd27e67d6eebfaec5b1482069285949de10afb28a538804ce64add88890"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 38 48 89 5C 24 50 48 89 7C 24 60 48 89 4C 24 58 48 8B 10 48 8B 40 08 48 8B 52 28 FF D2 48 89 44 24 28 48 89 5C 24 18 48 8B 4C 24 50 31 D2 90 EB 03 48 FF C2 48 39 D3 7E 6C 48 8B 34 D0 }
    condition:
        all of them
}

rule Linux_Generic_Threat_936b24d5 {
    meta:
        author = "Elastic Security"
        id = "936b24d5-f8d7-44f1-a541-94c30a514a11"
        fingerprint = "087f31195b3eaf51cd03167a877e54a5ba3ca9941145d8125c823100ba6401c4"
        creation_date = "2024-01-18"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "fb8eb0c876148a4199cc873b84fd9c1c6abc1341e02d118f72ffb0dae37592a4"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 66 73 65 65 6B 6F 28 6F 70 74 2E 64 69 63 74 2C 20 30 4C 2C 20 53 45 45 4B 5F 45 4E 44 29 20 21 3D 20 2D 31 }
    condition:
        all of them
}

rule Linux_Generic_Threat_98bbca63 {
    meta:
        author = "Elastic Security"
        id = "98bbca63-68c4-4b32-8cb6-50f9dad0a8f2"
        fingerprint = "d10317a1a09e86b55eb7b00a87cb010e0d2f11ade2dccc896aaeba9819bd6ca5"
        creation_date = "2024-01-22"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "1d4d3d8e089dcca348bb4a5115ee2991575c70584dce674da13b738dd0d6ff98"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 64 65 73 63 72 69 70 74 69 6F 6E 3D 4C 4B 4D 20 72 6F 6F 74 6B 69 74 }
        $a2 = { 61 75 74 68 6F 72 3D 6D 30 6E 61 64 }
    condition:
        all of them
}

rule Linux_Generic_Threat_9aaf894f {
    meta:
        author = "Elastic Security"
        id = "9aaf894f-d3f0-460d-82f8-831fecdf8b09"
        fingerprint = "15518c7e99ed1f39db2fe21578c08aadf8553fdb9cb44e4342bf117e613c6c12"
        creation_date = "2024-01-22"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "467ac05956eec6c74217112721b3008186b2802af2cafed6d2038c79621bcb08"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2F 62 69 6E 2F 63 70 20 2F 74 6D 70 2F 70 61 6E 77 74 65 73 74 20 2F 75 73 72 2F 62 69 6E 2F 70 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_ba3a047d {
    meta:
        author = "Elastic Security"
        id = "ba3a047d-effc-444b-85b7-d31815e61dfb"
        fingerprint = "3f43a4e73a857d07c3623cf0278eecf26ef51f4a75b7913a72472ba6738adeac"
        creation_date = "2024-01-22"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3064e89f3585f7f5b69852f1502e34a8423edf5b7da89b93fb8bd0bef0a28b8b"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 52 65 61 64 69 6E 67 20 61 74 20 6D 61 6C 69 63 69 6F 75 73 5F 78 20 3D 20 25 70 2E 2E 2E 20 }
        $a2 = { 28 73 65 63 6F 6E 64 20 62 65 73 74 3A 20 30 78 25 30 32 58 20 73 63 6F 72 65 3D 25 64 29 }
    condition:
        all of them
}

rule Linux_Generic_Threat_902cfdc5 {
    meta:
        author = "Elastic Security"
        id = "902cfdc5-7f71-4661-af17-9f3dd9b21daa"
        fingerprint = "d692401d70f20648e9bb063fc8f0e750349671e56a53c33991672d29eededcb4"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 54 65 67 73 6B 54 47 66 42 7A 4C 35 5A 58 56 65 41 54 4A 5A 2F 4B 67 34 67 47 77 5A 4E 48 76 69 5A 49 4E 50 49 56 70 36 4B 2F 2D 61 77 33 78 34 61 6D 4F 57 33 66 65 79 54 6F 6D 6C 71 37 2F 57 58 6B 4F 4A 50 68 41 68 56 50 74 67 6B 70 47 74 6C 68 48 }
    condition:
        all of them
}

rule Linux_Generic_Threat_094c1238 {
    meta:
        author = "Elastic Security"
        id = "094c1238-32e7-43b8-bf5e-187cf3a28c9f"
        fingerprint = "1b36f7415f215c6e39e9702ae6793fffd7c7ecce1884767b5c24a1e086101faf"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2bfe7d51d59901af345ef06dafd8f0e950dcf8461922999670182bfc7082befd"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC 18 01 00 00 48 89 D3 41 89 F6 49 89 FF 64 48 8B 04 25 28 00 00 00 48 89 84 24 10 01 00 00 49 89 E4 4C 89 E7 E8 FD 08 00 00 48 89 DF E8 75 08 00 00 4C 89 E7 48 89 DE 89 C2 E8 F8 08 00 }
    condition:
        all of them
}

rule Linux_Generic_Threat_a8faf785 {
    meta:
        author = "Elastic Security"
        id = "a8faf785-997d-4be8-9d10-c6e7050c257b"
        fingerprint = "c393af7d7fb92446019eed23bbf216d941a9598dd52ccb610432985d0da5ce04"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "6028562baf0a7dd27329c8926585007ba3e0648da25088204ebab2ac8f723e70"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 53 57 56 83 E4 F0 83 EC 10 E8 00 00 00 00 5B 81 C3 53 50 00 00 8B 45 0C 8B 4D 10 8B 55 08 65 8B 35 14 00 00 00 89 74 24 08 8D 75 14 89 74 24 04 8B 3A 56 51 50 52 FF 97 CC 01 00 00 83 }
    condition:
        all of them
}

rule Linux_Generic_Threat_04e8e4a5 {
    meta:
        author = "Elastic Security"
        id = "04e8e4a5-a1e1-4850-914a-d7e583d052a3"
        fingerprint = "08e48ddeffa8617e7848731b54a17983104240249cddccc5372c16b5d74a1ce4"
        creation_date = "2024-01-23"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "248f010f18962c8d1cc4587e6c8b683a120a1e838d091284ba141566a8a01b92"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC F8 01 00 00 48 8D 7C 24 10 E8 60 13 00 00 48 8D 7C 24 10 E8 12 07 00 00 85 ED 74 30 48 8B 3B 48 8D 54 24 02 48 B8 5B 6B 77 6F 72 6B 65 72 BE 0D 00 00 00 48 89 44 24 02 C7 44 24 0A 2F }
    condition:
        all of them
}

rule Linux_Generic_Threat_47b147ec {
    meta:
        author = "Elastic Security"
        id = "47b147ec-bcd2-423a-bc67-a85712d135eb"
        fingerprint = "38f55b825bbd1fa837b2b9903d01141a071539502fe21b874948dbc5ac215ae8"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cc7734a10998a4878b8f0c362971243ea051ce6c1689444ba6e71aea297fb70d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 50 41 54 48 3D 2F 62 69 6E 3A 2F 73 62 69 6E 3A 2F 75 73 72 2F 73 62 69 6E 3A 2F 75 73 72 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 73 62 69 6E }
    condition:
        all of them
}

rule Linux_Generic_Threat_887671e9 {
    meta:
        author = "Elastic Security"
        id = "887671e9-1e93-42d9-afb8-a96d1a87c572"
        fingerprint = "55cbfbd761e2000492059909199d16faf6839d3d893e29987b73087942c9de78"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "701c7c75ed6a7aaf59f5a1f04192a1f7d49d73c1bd36453aed703ad5560606dc"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 57 56 53 83 E4 F0 83 EC 40 8B 45 0C E8 DC 04 00 00 81 C3 AC F7 0B 00 89 44 24 04 8B 45 08 89 04 24 E8 A7 67 00 00 85 C0 0F 88 40 04 00 00 C7 04 24 00 00 00 00 E8 03 F5 FF FF 8B 93 34 }
    condition:
        all of them
}

rule Linux_Generic_Threat_9cf10f10 {
    meta:
        author = "Elastic Security"
        id = "9cf10f10-9a5b-46b5-ae25-7239b8f1434a"
        fingerprint = "88b3122e747e685187a7b7268e22d12fbd16a24c7c2edb6f7e09c86327fc2f0e"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d07c9be37dc37f43a54c8249fe887dbc4058708f238ff3d95ed21f874cbb84e8"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 14 8B 44 24 18 8B 08 89 0C 24 89 44 24 04 C6 44 24 08 00 E8 84 1E 00 00 8B 44 24 0C 89 44 24 10 8B 4C 24 18 8B 09 89 04 24 8B 54 24 1C 89 54 24 04 89 4C 24 08 E8 52 C7 05 00 8B 44 24 }
    condition:
        all of them
}

rule Linux_Generic_Threat_75813ab2 {
    meta:
        author = "Elastic Security"
        id = "75813ab2-47f5-40ad-b512-9aa081abdc03"
        fingerprint = "e5b985f588cf6d1580b8e5dc85350fd0e1ca22ca810b1eca8d2bed774237c930"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5819eb73254fd2a698eb71bd738cf3df7beb65e8fb5e866151e8135865e3fd9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 5B 2B 5D 20 6D 6D 61 70 3A 20 30 78 25 6C 78 20 2E 2E 20 30 78 25 6C 78 }
        $a2 = { 5B 2B 5D 20 70 61 67 65 3A 20 30 78 25 6C 78 }
    condition:
        all of them
}

rule Linux_Generic_Threat_11041685 {
    meta:
        author = "Elastic Security"
        id = "11041685-8c0d-4de0-ba43-b8f676882857"
        fingerprint = "d446fd63eb9a036a722d76183866114ab0c11c245d1f47f8949b0241d5a79e40"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "296440107afb1c8c03e5efaf862f2e8cc6b5d2cf979f2c73ccac859d4b78865a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 72 65 73 6F 6C 76 65 64 20 73 79 6D 62 6F 6C 20 25 73 20 74 6F 20 25 70 }
        $a2 = { 73 79 6D 62 6F 6C 20 74 61 62 6C 65 20 6E 6F 74 20 61 76 61 69 6C 61 62 6C 65 2C 20 61 62 6F 72 74 69 6E 67 21 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0d22f19c {
    meta:
        author = "Elastic Security"
        id = "0d22f19c-5724-480b-95de-ef2609896c52"
        fingerprint = "c1899febb7bf6717bc330577a4baae4b4e81d69c4b3660944a6d8f708652d230"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "da5a204af600e73184455d44aa6e01d82be8b480aa787b28a1df88bb281eb4db"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 49 44 20 25 64 2C 20 45 55 49 44 3A 25 64 20 47 49 44 3A 25 64 2C 20 45 47 49 44 3A 25 64 }
        $a2 = { 50 54 52 41 43 45 5F 50 4F 4B 45 55 53 45 52 20 66 61 75 6C 74 }
    condition:
        all of them
}

rule Linux_Generic_Threat_4a46b0e1 {
    meta:
        author = "Elastic Security"
        id = "4a46b0e1-b0d4-423c-9600-f594d3a48a33"
        fingerprint = "2ae70fc399a228284a3827137db2a5b65180811caa809288df44e5b484eb1966"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "3ba47ba830ab8deebd9bb906ea45c7df1f7a281277b44d43c588c55c11eba34a"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 20 28 76 69 61 20 53 79 73 74 65 6D 2E 6D 61 70 29 }
        $a2 = { 20 5B 2B 5D 20 52 65 73 6F 6C 76 65 64 20 25 73 20 74 6F 20 25 70 25 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_0a02156c {
    meta:
        author = "Elastic Security"
        id = "0a02156c-2958-44c5-9dbd-a70d528e507d"
        fingerprint = "aa7a34e72e03b70f2f73ae319e2cc9866fbf2eddd4e6a8a2835f9b7c400831cd"
        creation_date = "2024-02-01"
        last_modified = "2024-02-13"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "f23d4b1fd10e3cdd5499a12f426e72cdf0a098617e6b178401441f249836371e"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 72 65 71 75 69 72 65 73 5F 6E 75 6C 6C 5F 70 61 67 65 }
        $a2 = { 67 65 74 5F 65 78 70 6C 6F 69 74 5F 73 74 61 74 65 5F 70 74 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_6d7ec30a {
    meta:
        author = "Elastic Security"
        id = "6d7ec30a-5c9f-4d82-8191-b26eb2f40799"
        fingerprint = "7d547a73a44eab080dde9cd3ff87d75cf39d2ae71d84a3daaa6e6828e057f134"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "1cad1ddad84cdd8788478c529ed4a5f25911fb98d0a6241dcf5f32b0cdfc3eb0"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2F 74 6D 70 2F 73 6F 63 6B 73 35 2E 73 68 }
        $a2 = { 63 61 74 20 3C 28 65 63 68 6F 20 27 40 72 65 62 6F 6F 74 20 65 63 68 6F 20 73 6F 63 6B 73 35 5F 62 61 63 6B 63 6F 6E 6E 65 63 74 36 36 36 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 7C 20 28 63 64 20 20 26 26 20 29 27 29 20 3C 28 73 65 64 20 27 2F 73 6F 63 6B 73 35 5F 62 61 63 6B 63 6F 6E 6E 65 63 74 36 36 36 2F 64 27 20 3C 28 63 72 6F 6E 74 61 62 20 2D 6C 20 32 3E 2F 64 65 76 2F 6E 75 6C 6C 29 29 20 7C 20 63 72 6F 6E 74 61 62 20 2D }
    condition:
        all of them
}

rule Linux_Generic_Threat_900ffdd4 {
    meta:
        author = "Elastic Security"
        id = "900ffdd4-085e-4d6b-af7b-2972157dcefd"
        fingerprint = "f03d39e53b06dd896bfaff7c94beaa113df1831dc397ef0ea8bea63156316a1b"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "a3e1a1f22f6d32931d3f72c35a5ee50092b5492b3874e9e6309d015d82bddc5d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 20 48 89 7D E8 89 75 E4 48 83 7D E8 00 74 5C C7 45 FC 00 00 00 00 EB 3D 8B 45 FC 48 98 48 C1 E0 04 48 89 C2 48 8B 45 E8 48 01 D0 48 8B 00 48 85 C0 74 1E 8B 45 FC 48 98 48 C1 E0 04 48 }
    condition:
        all of them
}

rule Linux_Generic_Threat_cb825102 {
    meta:
        author = "Elastic Security"
        id = "cb825102-0b03-4885-9f73-44dd0cf2d45c"
        fingerprint = "e23ac81c245de350514c54f91e8171c8c4274d76c1679500d6d2b105f473bdfc"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "4e24b72b24026e3dfbd65ddab9194bd03d09446f9ff0b3bcec76efbb5c096584"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 5B 2B 5D 20 72 65 73 6F 6C 76 69 6E 67 20 72 65 71 75 69 72 65 64 20 73 79 6D 62 6F 6C 73 2E 2E 2E }
    condition:
        all of them
}

rule Linux_Generic_Threat_3bcc1630 {
    meta:
        author = "Elastic Security"
        id = "3bcc1630-cfa4-4f2e-b129-f0150595dbc3"
        fingerprint = "0e4fe564c5c3c04e4b40af2bebb091589fb52292bd16a78b733c67968fa166e7"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "62a6866e924af2e2f5c8c1f5009ce64000acf700bb5351a47c7cfce6a4b2ffeb"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2F 72 6F 6F 74 2F 64 76 72 5F 67 75 69 2F }
        $a2 = { 2F 72 6F 6F 74 2F 64 76 72 5F 61 70 70 2F }
        $a3 = { 73 74 6D 5F 68 69 33 35 31 31 5F 64 76 72 }
    condition:
        all of them
}

rule Linux_Generic_Threat_5d5fd28e {
    meta:
        author = "Elastic Security"
        id = "5d5fd28e-ae8f-4b6f-ad95-57725550fcef"
        fingerprint = "3a24edfbafc0abee418998d3a6355f4aa2659d68e27db502149a34266076ed15"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5b179a117e946ce639e99ff42ab70616ed9f3953ff90b131b4b3063f970fa955"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2F 75 73 72 2F 62 69 6E 2F 77 64 31 }
        $a2 = { 2F 75 73 72 2F 62 69 6E 2F 63 64 31 }
        $a3 = { 2F 75 73 72 2F 62 69 6E 2F 63 64 74 }
    condition:
        all of them
}

rule Linux_Generic_Threat_b0b891fb {
    meta:
        author = "Elastic Security"
        id = "b0b891fb-f262-4a06-aa3c-be0baeb53172"
        fingerprint = "c6e4f7bcc94b584f8537724d3ecd9f83e6c3981cdc35d5cdc691730ed0e435ef"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "d666bc0600075f01d8139f8b09c5f4e4da17fa06a86ebb3fa0dc478562e541ae"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 5F 66 69 6C 65 }
        $a2 = { 2F 64 65 76 2F 75 72 61 6E 64 6F 6D 2F 6D 6E 74 2F 65 78 74 2F 6F 70 74 31 35 32 35 38 37 38 39 30 36 32 35 37 36 32 39 33 39 34 35 33 31 32 35 42 69 64 69 5F 43 6F 6E 74 72 6F 6C 4A 6F 69 6E 5F 43 6F 6E 74 72 6F 6C 4D 65 65 74 65 69 5F 4D 61 79 65 6B 50 61 68 61 77 68 5F 48 6D 6F 6E 67 53 6F 72 61 5F 53 6F 6D 70 65 6E 67 53 79 6C 6F 74 69 5F 4E 61 67 72 69 61 62 69 20 6D 69 73 6D 61 74 63 68 62 61 64 20 66 6C 75 73 68 47 65 6E 62 61 64 20 67 20 73 74 61 74 75 73 62 61 64 20 72 65 63 6F 76 65 72 79 63 61 6E 27 74 20 68 61 70 70 65 6E 63 61 73 36 34 20 66 61 69 6C 65 64 63 68 61 6E 20 72 65 63 65 69 76 65 64 75 6D 70 69 6E 67 20 68 65 61 70 65 6E 64 20 74 72 61 63 65 67 63 }
    condition:
        all of them
}

rule Linux_Generic_Threat_cd9ce063 {
    meta:
        author = "Elastic Security"
        id = "cd9ce063-a33b-4771-b7c0-7342d486e15a"
        fingerprint = "e090bd44440e912d04de390c240ca18265bcf49e34f6689b3162e74d2fd31ba4"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "485581520dd73429b662b73083d504aa8118e01c5d37c1c08b21a5db0341a19d"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 2C 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 2E 61 75 74 6F 74 6D 70 5F 32 36 20 2A 74 6C 73 2E 43 6F 6E 6E 20 7D }
    condition:
        all of them
}

rule Linux_Generic_Threat_b8b076f4 {
    meta:
        author = "Elastic Security"
        id = "b8b076f4-c64a-400b-80cb-5793c97ad033"
        fingerprint = "f9c6c055e098164d0add87029d03aec049c4bed2c4643f9b4e32dd82f596455c"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "4496e77ff00ad49a32e090750cb10c55e773752f4a50be05e3c7faacc97d2677"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 44 0F 11 7C 24 2E 44 0F 11 7C 24 2F 44 0F 11 7C 24 3F 44 0F 11 7C 24 4F 44 0F 11 7C 24 5F 48 8B 94 24 C8 00 00 00 48 89 54 }
    condition:
        all of them
}

rule Linux_Generic_Threat_1ac392ca {
    meta:
        author = "Elastic Security"
        id = "1ac392ca-d428-47ef-98af-d02d8305ae67"
        fingerprint = "e21805cc2d548c940b0cefa8ee99bd55c5599840e32b8341a4ef5dfb0bc679ff"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "dca2d035b1f7191f7876eb727b13c308f63fe8f899cab643526f9492ec0fa16f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 53 4F 41 50 41 63 74 69 6F 6E 3A 20 75 72 6E 3A 73 63 68 65 6D 61 73 2D 75 70 6E 70 2D 6F 72 67 3A 73 65 72 76 69 63 65 3A 57 41 4E 49 50 43 6F 6E 6E 65 63 74 69 6F 6E 3A 31 23 41 64 64 50 6F 72 74 4D 61 70 70 69 6E 67 }
    condition:
        all of them
}

rule Linux_Generic_Threat_949bf68c {
    meta:
        author = "Elastic Security"
        id = "949bf68c-e6a0-451d-9e49-4515954aabc8"
        fingerprint = "e478c8befed6da3cdd9985515e4650a8b7dad1ea28292c2cf91069856155facd"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cc1b339ff6b33912a8713c192e8743d1207917825b62b6f585ab7c8d6ab4c044"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 55 89 E5 57 56 53 81 EC 58 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 85 B4 FE FF FF 89 95 AC FE FF FF 8D B5 C4 FE FF FF 56 ?? ?? ?? ?? ?? 58 5A 6A 01 56 }
    condition:
        all of them
}

rule Linux_Generic_Threat_bd35454b {
    meta:
        author = "Elastic Security"
        id = "bd35454b-a0dd-4925-afae-6416f3695826"
        fingerprint = "721aa441a2567eab29c9bc76f12d0fdde8b8a124ca5a3693fbf9821f5b347825"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "cd729507d2e17aea23a56a56e0c593214dbda4197e8a353abe4ed0c5fbc4799c"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 5F 66 69 6C 65 }
        $a2 = { 57 68 61 74 20 67 75 61 72 61 6E 74 65 65 73 3F }
    condition:
        all of them
}

rule Linux_Generic_Threat_1e047045 {
    meta:
        author = "Elastic Security"
        id = "1e047045-e08b-4ecb-8892-90a1ab94f8b1"
        fingerprint = "aa99b16f175649c251cb299537baf8bded37d85af8b2539b4aba4ffd634b3f66"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "2c49772d89bcc4ad4ed0cc130f91ed0ce1e625262762a4e9279058f36f4f5841"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 18 48 89 FB 48 89 F5 64 48 8B 04 25 28 00 00 00 48 89 44 24 08 31 C0 48 8B 47 08 48 89 C2 48 C1 EA 18 88 14 24 48 89 C2 48 C1 EA 10 88 54 24 01 48 89 C2 48 C1 EA 08 88 54 24 02 88 44 }
    condition:
        all of them
}

rule Linux_Generic_Threat_1973391f {
    meta:
        author = "Elastic Security"
        id = "1973391f-b9a2-465d-8990-51c6e9fab84b"
        fingerprint = "90a261afd81993057b084c607e27843ff69649b3d90f4d0b52464e87fdf2654d"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "7bd76010f18061aeaf612ad96d7c03341519d85f6a1683fc4b2c74ea0508fe1f"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 70 69 63 6B 75 70 20 2D 6C 20 2D 74 20 66 69 66 6F 20 2D 75 }
        $a2 = { 5B 2D 5D 20 43 6F 6E 6E 65 63 74 20 66 61 69 6C 65 64 2E }
    condition:
        all of them
}

rule Linux_Generic_Threat_66d00a84 {
    meta:
        author = "Elastic Security"
        id = "66d00a84-c148-4a82-8da5-955787c103a4"
        fingerprint = "1b6c635dc149780691f292014f3dbc20755d26935b7ae0b3d8f250c10668e28a"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "464e144bcbb54fc34262b4d81143f4e69e350fb526c803ebea1fdcfc8e57bf33"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 81 EC 10 04 00 00 4C 89 E7 49 8D 8C 24 FF 03 00 00 49 89 E0 48 89 E0 8A 17 84 D2 74 14 80 7F 01 00 88 10 74 05 48 FF C0 EB 07 88 58 01 48 83 C0 02 48 FF C7 48 39 F9 75 DE 4C 39 C0 74 06 C6 }
    condition:
        all of them
}

rule Linux_Generic_Threat_d2dca9e7 {
    meta:
        author = "Elastic Security"
        id = "d2dca9e7-6ce6-49b9-92a8-f0149f2deb42"
        fingerprint = "2a1182f380b07d7ad1f46514200e33ea364711073023ad05f4d82b210e43cfed"
        creation_date = "2024-05-20"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "9b10bb3773011c4da44bf3a0f05b83079e4ad30f0b1eb2636a6025b927e03c7f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { D0 4D E2 00 50 A0 E1 06 60 8F E0 08 00 00 0A 10 20 90 E5 18 30 90 E5 03 00 52 E1 01 40 D2 34 10 20 80 35 1F 00 00 3A 3B 01 00 EB 00 40 A0 E1 1C 00 00 EA 80 30 9F E5 38 40 80 E2 04 20 A0 E1 03 }
    condition:
        all of them
}

rule Linux_Generic_Threat_1f5d056b {
    meta:
        author = "Elastic Security"
        id = "1f5d056b-1e9c-47f6-a63c-752f4cf130a1"
        fingerprint = "b44a383deaa361db02b342ea52b4f3db9a604bf8b66203fefa5c5d68c361a1d0"
        creation_date = "2024-05-20"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "99d982701b156fe3523b359498c2d03899ea9805d6349416c9702b1067293471"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 30 31 32 33 34 35 36 37 38 }
        $a2 = { 47 45 54 20 2F 63 6F 6E 66 69 67 20 48 54 54 50 2F 31 2E 30 }
    condition:
        all of them
}

rule Linux_Generic_Threat_d94e1020 {
    meta:
        author = "Elastic Security"
        id = "d94e1020-ff66-4501-95e1-45ab552b1c18"
        fingerprint = "c291c07b6225c8ce94f38ad7cb8bb908039abfc43333c6524df776b28c79452a"
        creation_date = "2024-05-20"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "96a2bfbb55250b784e94b1006391cc51e4adecbdde1fe450eab53353186f6ff0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { D0 4D E2 0C C0 9D E5 0C 30 4C E2 02 00 53 E3 14 30 8D E2 00 30 8D E5 10 30 9D E5 0C 10 A0 E1 03 20 A0 E1 01 00 00 8A 0F 00 00 EB 0A 00 00 EA 03 20 A0 E1 0C 10 A0 E1 37 00 90 EF 01 0A 70 E3 00 }
    condition:
        all of them
}

rule Linux_Generic_Threat_aa0c23d5 {
    meta:
        author = "Elastic Security"
        id = "aa0c23d5-e633-4898-91f8-3cf84c9dd6af"
        fingerprint = "acd33e82bcefde691df1cf2739518018f05e0f03ef2da692f3ccca810c2ef361"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "8314290b81b827e1a1d157c41916a41a1c033e4f74876acc6806ed79ebbcc13d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F }
        $a2 = { 77 66 6F 66 60 6C 6E 62 67 6E 6A 6D }
        $a3 = { 62 67 6E 6A 6D 77 66 6F 66 60 6C 6E }
    condition:
        all of them
}

rule Linux_Generic_Threat_8299c877 {
    meta:
        author = "Elastic Security"
        id = "8299c877-a0c3-4673-96c7-58c80062e316"
        fingerprint = "bae38e2a147dc82ffd66e89214d12c639c690f3d2e701335969f090a21bf0ba7"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "60c486049ec82b4fa2e0a53293ae6476216b76e2c23238ef1c723ac0a2ae070c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { D0 4D E2 0D 10 A0 E1 07 00 A0 E3 1E 00 00 EB 00 00 50 E3 00 00 9D A5 01 0C A0 B3 0C D0 8D E2 04 E0 9D E4 1E FF 2F E1 04 70 2D E5 CA 70 A0 E3 00 00 00 EF 80 00 BD E8 1E FF 2F E1 04 70 2D E5 C9 }
    condition:
        all of them
}

rule Linux_Generic_Threat_81aa5579 {
    meta:
        author = "Elastic Security"
        id = "81aa5579-6d94-42a7-9103-de3972dfe141"
        fingerprint = "60492dca0e33e2700c25502292e6ec54609b83c7616a96ae4731f4a1cd9e2f41"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "6be0e2c98ba5255b76c31f689432a9de83a0d76a898c28dbed0ba11354fec6c2"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { D0 4D E2 07 00 8D E8 03 10 A0 E3 0D 20 A0 E1 08 00 9F E5 84 00 00 EB 0C D0 8D E2 00 80 BD E8 66 00 90 00 01 C0 A0 E1 00 10 A0 E1 08 00 9F E5 02 30 A0 E1 0C 20 A0 E1 7B 00 00 EA 04 00 90 00 01 }
    condition:
        all of them
}

rule Linux_Generic_Threat_f2452362 {
    meta:
        author = "Elastic Security"
        id = "f2452362-dc55-452f-9e93-e6a6b74d8ebd"
        fingerprint = "cc293c87513ca1332e5ec13c9ce47efbe5e9c48c0cece435ac3c8bdbc822ea82"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5ff46c27b5823e55f25c9567d687529a24a0d52dea5bc2423b36345782e6b8f6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6F 72 69 67 69 6E 61 6C 5F 72 65 61 64 64 69 72 }
        $a2 = { 45 72 72 6F 72 20 69 6E 20 64 6C 73 79 6D 3A 20 25 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_da28eb8b {
    meta:
        author = "Elastic Security"
        id = "da28eb8b-7176-4415-9c58-5f74da70f53d"
        fingerprint = "490b6a89ea704a25d0e21dfb9833d56bc26f93c788efb7fcbfe38544696d0dfd"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "b3b4fcd19d71814d3b4899528ee9c3c2188e4a7a4d8ddb88859b1a6868e8433f"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 4A 66 67 67 6C 6A 7D 60 66 67 33 29 62 6C 6C 79 24 68 65 60 }
        $a2 = { 48 6A 6A 6C 79 7D 33 29 7D 6C 71 7D 26 61 7D 64 65 25 68 79 79 65 60 6A 68 7D 60 66 67 26 71 61 7D 64 65 22 71 64 65 25 68 79 79 65 60 6A 68 7D 60 66 67 26 71 64 65 32 78 34 39 27 30 25 60 64 68 6E 6C 26 7E 6C 6B 79 25 23 26 23 32 78 34 39 27 31 }
    condition:
        all of them
}

rule Linux_Generic_Threat_a40aaa96 {
    meta:
        author = "Elastic Security"
        id = "a40aaa96-4dcf-45b8-a95e-7ed7f27a31b6"
        fingerprint = "ce2da00db88bba513f910bdb00e1c935d1d972fe20558e2ec8e3c57cdbd5b7be"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "6f965252141084524f85d94169b13938721bce24cc986bf870473566b7cfd81b"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6D 61 69 6E 2E 55 69 6E 74 33 32 6E }
        $a2 = { 6D 61 69 6E 2E 47 65 74 72 61 6E 64 }
        $a3 = { 6D 61 69 6E 2E 28 2A 52 4E 47 29 2E 55 69 6E 74 33 32 }
    condition:
        all of them
}

rule Linux_Generic_Threat_e24558e1 {
    meta:
        author = "Elastic Security"
        id = "e24558e1-1337-4566-8816-9b83cbaccbf6"
        fingerprint = "04ca7e3775e3830a3388a4ad83a5e0256992c9f7beb4b59defcfb684d8471122"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "9f483ddd8971cad4b25bb36a5a0cfb95c35a12c7d5cb9124ef0cfd020da63e99"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 77 66 6F 66 60 6C 6E 62 67 6E 6A 6D }
        $a2 = { 62 67 6E 6A 6D 77 66 6F 66 60 6C 6E }
        $a3 = { 77 62 59 79 43 31 30 37 3A 36 3B 36 3A }
    condition:
        all of them
}

rule Linux_Generic_Threat_ace836f1 {
    meta:
        author = "Elastic Security"
        id = "ace836f1-74f0-4031-903b-ec5b95a40d46"
        fingerprint = "907b40e66d5da2faf142917304406d0a8abc7356d73b2a6a6789be22b4daf4ab"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "116aaba80e2f303206d0ba84c8c58a4e3e34b70a8ca2717fa9cf1aa414d5ffcc"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 4E 54 4C 4D 53 53 50 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 73 25 73 }
    condition:
        all of them
}

rule Linux_Generic_Threat_e9aef030 {
    meta:
        author = "Elastic Security"
        id = "e9aef030-7d8c-4e9d-a364-178c717516f0"
        fingerprint = "50ae1497132a9f1afc6af5bf96a0a49ca00023d5f0837cb8d67b4fd8b0864cc7"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "5ab72be12cca8275d95a90188a1584d67f95d43a7903987e734002983b5a3925"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { D0 4D E2 00 50 A0 E1 0A 00 00 0A 38 40 80 E2 28 31 9F E5 10 00 8D E2 24 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 40 00 13 E2 05 }
    condition:
        all of them
}

rule Linux_Generic_Threat_a3c5f3bd {
    meta:
        author = "Elastic Security"
        id = "a3c5f3bd-9afe-44f4-98da-6ad704d0dee1"
        fingerprint = "f86d540c4e884a9c893471cf08db86c9bf34162fe9970411f8e56917fd9d3d8f"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "8c093bcf3d83545ec442519637c956d2af62193ea6fd2769925cacda54e672b6"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 66 68 5F 72 65 6D 6F 76 65 5F 68 6F 6F 6B }
        $a2 = { 66 68 5F 66 74 72 61 63 65 5F 74 68 75 6E 6B }
        $a3 = { 66 68 5F 69 6E 73 74 61 6C 6C 5F 68 6F 6F 6B }
    condition:
        all of them
}

rule Linux_Generic_Threat_3fa2df51 {
    meta:
        author = "Elastic Security"
        id = "3fa2df51-fa0e-4149-8631-fa4bfb2fe66e"
        fingerprint = "3aa2bbc4e177574fa2ae737e6f27b92caa9a83e6e9a1704599be67e2c3482f6a"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "89ec224db6b63936e8bc772415d785ef063bfd9343319892e832034696ff6f15"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 5B 6B 77 6F 72 6B 65 72 2F 30 3A 32 5D }
        $a2 = { 2F 74 6D 70 2F 6C 6F 67 5F 64 65 2E 6C 6F 67 }
    condition:
        all of them
}

rule Linux_Generic_Threat_be02b1c9 {
    meta:
        author = "Elastic Security"
        id = "be02b1c9-fb48-434c-a0ee-a1a87938992c"
        fingerprint = "c803bfffa481ad01bbfe490f9732748f8988669eab6bdf9f1e0e55f5ba8917a3"
        creation_date = "2024-05-21"
        last_modified = "2024-06-12"
        threat_name = "Linux.Generic.Threat"
        reference_sample = "ef6d47ed26f9ac96836f112f1085656cf73fc445c8bacdb737b8be34d8e3bcd2"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 18 48 89 FB 48 89 F5 48 8B 47 08 48 89 C2 48 C1 EA 18 88 14 24 48 89 C2 48 C1 EA 10 88 54 24 01 48 89 C2 48 C1 EA 08 88 54 24 02 88 44 24 03 48 8B 07 48 89 C2 48 C1 EA 18 88 54 24 04 }
    condition:
        all of them
}



// from Linux_Hacktool_Aduh.yar
rule Linux_Hacktool_Aduh_6cae7c78 {
    meta:
        author = "Elastic Security"
        id = "6cae7c78-a4b4-4096-9f7c-746b1e5a1e38"
        fingerprint = "8d7b0c1a95ec15c7d1ede5670ccd448b166467ed8eb2b4f38ebbb2c8bc323cdc"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Aduh"
        reference_sample = "9c67207546ad274dc78a0819444d1c8805537f9ac36d3c53eba9278ed44b360c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 51 89 E2 51 89 E1 B0 0B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}



// from Linux_Hacktool_Bruteforce.yar
rule Linux_Hacktool_Bruteforce_bad95bd6 {
    meta:
        author = "Elastic Security"
        id = "bad95bd6-94a9-4abf-9d3b-781f0b79c5ce"
        fingerprint = "10698122ff9fe06b398307ec15ad4f5bb519285e1eaad97011abf0914f1e7afd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "8e8be482357ebddc6ac3ea9ee60241d011063f7e558a59e6bd119e72e4862024"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 65 6E 64 6D 6D 73 67 00 66 70 75 74 73 00 6D 65 6D 63 70 79 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Bruteforce_66a14c03 {
    meta:
        author = "Elastic Security"
        id = "66a14c03-f4a3-4b24-a5db-5a9235334e37"
        fingerprint = "255c1a2e781ff7f330c09b3c82f08db110579f77ccef8780d03e9aa3eec86607"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "a2d8e2c34ae95243477820583c0b00dfe3f475811d57ffb95a557a227f94cd55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 8B 4C 24 08 78 3D 48 8B 44 24 30 48 29 C8 48 89 4D 08 48 89 }
    condition:
        all of them
}

rule Linux_Hacktool_Bruteforce_eb83b6aa {
    meta:
        author = "Elastic Security"
        id = "eb83b6aa-d7b5-4d10-9258-4bf619fc6582"
        fingerprint = "7767bf57c57d398f27646f5ae2bcda07d6c62959becb31a5186ff0b027ff02b4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "8dec88576f61f37fbaece3c30e71d338c340c8fb9c231f9d7b1c32510d2c3167"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 89 45 EC EB 04 83 6D EC 01 83 7D EC 00 74 12 8B 45 EC 8D }
    condition:
        all of them
}



// from Linux_Hacktool_Cleanlog.yar
rule Linux_Hacktool_Cleanlog_c2907d77 {
    meta:
        author = "Elastic Security"
        id = "c2907d77-6ea9-493f-a7b3-4a0795da0a1d"
        fingerprint = "131c71086c30ab22ca16b3020470561fa3d32c7ece9a8faa399a733e8894da30"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "613ac236130ab1654f051d6f0661fa62414f3bef036ea4cc585b4b21a4bb9d2b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 10 89 7D FC 83 7D FC 00 7E 11 8B 45 FC BE 09 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Cleanlog_3eb725d1 {
    meta:
        author = "Elastic Security"
        id = "3eb725d1-24de-427a-b6ed-3ca03c0716df"
        fingerprint = "54d3c59ba5ca16fbe99a4629f4fe7464d13f781985a7f35d05604165f9284483"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 E0 83 45 C0 01 EB 11 83 45 DC 01 EB 0B 83 45 D8 01 EB 05 83 45 }
    condition:
        all of them
}

rule Linux_Hacktool_Cleanlog_400b7595 {
    meta:
        author = "Elastic Security"
        id = "400b7595-c3c4-4999-b3b9-dcfe9b5df3f6"
        fingerprint = "4423f1597b199046bfc87923e3e229520daa2da68c4c4a3ac69127ace518f19a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 20 65 6E 74 72 79 20 28 64 65 66 61 75 6C 74 3A 20 31 73 74 20 }
    condition:
        all of them
}



// from Linux_Hacktool_Earthworm.yar
rule Linux_Hacktool_Earthworm_4de7b584 {
    meta:
        author = "Elastic Security"
        id = "4de7b584-d25f-414b-bdd5-45f3672a62d8"
        fingerprint = "af2dc166ad5bbd3e312338a3932134c33c33c124551e7828eeef299d89419d21"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "9d61aabcf935121b4f7fc6b0d082d7d6c31cb43bf253a8603dd46435e66b7955"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 6F 63 6B 73 64 20 2C 20 72 63 73 6F 63 6B 73 20 2C 20 72 73 }
    condition:
        all of them
}

rule Linux_Hacktool_Earthworm_82d5c4cf {
    meta:
        author = "Elastic Security"
        id = "82d5c4cf-ab96-4644-b1f3-2e95f1b49e7c"
        fingerprint = "400342ab702de1a7ec4dd7e9b415b8823512f74a9abe578f08f7d79265bef385"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 20 31 C0 89 C1 48 8D 55 F0 48 89 7D F8 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Earthworm_4ec2ec63 {
    meta:
        author = "Elastic Security"
        id = "4ec2ec63-6b22-404f-a217-4e7d32bfbe9f"
        fingerprint = "1dfb594e369ca92a9e3f193499708c4992f6497ff1aa74ae0d6c2475a7e87641"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 20 BA 04 00 00 00 48 8D 45 F0 48 89 7D F8 89 }
    condition:
        all of them
}



// from Linux_Hacktool_Exploitscan.yar
rule Linux_Hacktool_Exploitscan_4327f817 {
    meta:
        author = "Elastic Security"
        id = "4327f817-cb11-480f-aba7-4d5170c77758"
        fingerprint = "3f70c8ef8f20f763dcada4353c254fe1df238829ce590fb87c279d8a892cf9c4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Exploitscan"
        reference_sample = "66c6d0e58916d863a1a973b4f5cb7d691fbd01d26b408dbc8c74f0f1e4088dfb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 08 8B 4C 24 0C 85 C0 74 20 8B 58 20 84 03 83 C3 10 8B 68 24 89 9C 24 DC 00 }
    condition:
        all of them
}



// from Linux_Hacktool_Flooder.yar
rule Linux_Hacktool_Flooder_825b6808 {
    meta:
        author = "Elastic Security"
        id = "825b6808-9b23-4a55-9f26-a34cab6ea92b"
        fingerprint = "e2db86e614b9bc0de06daf626abe652cc6385cca8ba96a2f2e394cf82be7a29b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "7db9a0760dd16e23cb299559a0e31a431b836a105d5309a9880fa4b821937659"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 83 EC 04 8B 45 E4 FF 70 0C 8D 45 E8 83 C0 04 50 8B 45 E4 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a44ab8cd {
    meta:
        author = "Elastic Security"
        id = "a44ab8cd-c45e-4fe8-b96d-d4fe227f3107"
        fingerprint = "0d77547064aeca6714ede98df686011c139ca720a71bcac23e40b0c02d302d6a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "4b2068a4a666b0279358b8eb4f480d2df4c518a8b4518d0d77c6687c3bff0a32"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 03 48 89 45 A8 8B 45 BC 48 63 D0 48 83 EA 01 48 89 55 A0 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_7026f674 {
    meta:
        author = "Elastic Security"
        id = "7026f674-83b7-432b-9197-2d71abdb9579"
        fingerprint = "acf93628ecbda544c6c5d88388ac85bb2755c71544a0980ee1b2854c6bdb7c77"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "b7a77ebb66664c54d01a57abed5bb034ef2933a9590b595bba0566938b099438"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 08 1E 77 DA 00 43 6F 75 6C 64 20 6E 6F 74 20 6F 70 65 6E 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_761ad88e {
    meta:
        author = "Elastic Security"
        id = "761ad88e-1667-4253-81f6-52c92e0ccd68"
        fingerprint = "14e701abdef422dcde869a2278ec6e1fb7889dcd9681a224b29a00bcb365e391"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2E 31 36 38 2E 33 2E 31 30 30 00 43 6F 75 6C 64 20 6E 6F 74 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_b93655d3 {
    meta:
        author = "Elastic Security"
        id = "b93655d3-1d3f-42f4-a47f-a69624e90da5"
        fingerprint = "55119467cb5f9789b74064e63c1e7d905457b54f6e4da1a83c498313d6c90b5b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 49 89 C5 74 45 45 85 F6 7E 28 48 89 C3 41 8D 46 FF 4D 8D 64 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_af9f75e6 {
    meta:
        author = "Elastic Security"
        id = "af9f75e6-9a9b-4e03-9c76-8c0c9f07c8b1"
        fingerprint = "f6e7d6e9c03c8ce3e14b214fe268e7aab2e15c1b4378fe253021497fb9a884e6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 C0 C7 45 B4 14 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1bf0e994 {
    meta:
        author = "Elastic Security"
        id = "1bf0e994-2648-4dbb-9b9c-b86b9a347700"
        fingerprint = "1f844c349b47dd49a75d50e43b6664e9d2b95c362efb730448934788b6bddb79"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1ea2dc13eec0d7a8ec20307f5afac8e9344d827a6037bb96a54ad7b12f65b59c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 10 48 8B 45 B8 0F B6 10 83 E2 0F 83 CA 40 88 10 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_d710a5da {
    meta:
        author = "Elastic Security"
        id = "d710a5da-26bf-4f6a-bf51-9cdac1f83aa3"
        fingerprint = "e673aa8785c7076f4cced9f12b284a2927b762fe1066aba8d6a5ace775f3480c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 24 48 8B 45 E0 48 83 C0 10 48 8B 08 48 8B 45 E0 48 83 C0 08 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_f434a3fb {
    meta:
        author = "Elastic Security"
        id = "f434a3fb-e5fd-4749-8e53-fc6c80ee5406"
        fingerprint = "b74e55c56a063e14608f7e8f578cc3c74ec57954df39e63e49b60c0055725d51"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 48 01 45 F8 48 83 45 E8 02 83 6D E4 01 83 7D E4 00 7F E3 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a2795a4c {
    meta:
        author = "Elastic Security"
        id = "a2795a4c-16c0-4237-a014-3570d1edb287"
        fingerprint = "7c8bf248b159f3a140f10cd40d182fa84f334555b92306e6f44e746711b184cc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 8B 45 D8 66 89 50 04 48 8B 45 D8 0F B7 40 02 66 D1 E8 0F }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_678c1145 {
    meta:
        author = "Elastic Security"
        id = "678c1145-cc41-4e83-bc88-30f64da46dd3"
        fingerprint = "f4f66668b45f520bc107b7f671f8c7f42073d7ff28863e846a74fbd6cac03e87"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "559793b9cb5340478f76aaf5f81c8dbfbcfa826657713d5257dac3c496b243a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C8 48 BA AB AA AA AA AA AA AA AA 48 89 C8 48 F7 E2 48 C1 EA 05 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_3cbdfb1f {
    meta:
        author = "Elastic Security"
        id = "3cbdfb1f-6c66-48be-931e-3ae609c46ff4"
        fingerprint = "c7f5d7641ea6e780bc3045181c929be73621acfe6aec4d157f6a9e0334ba7fb9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bd40ac964f3ad2011841c7eb4bf7cab332d4d95191122e830ab031dc9511c079"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5B 53 54 44 32 2E 43 20 42 59 20 53 54 41 43 4B 44 5D 20 53 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_8b63ff02 {
    meta:
        author = "Elastic Security"
        id = "8b63ff02-be86-4c63-8f7b-4c70fbd8a83a"
        fingerprint = "af7a4df7e707c1b70fb2b29efe2492e6f77cdde5e8d1e6bfdf141acabc8759eb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DC 02 83 7D DC 01 0F 9F C0 84 C0 75 DF 83 7D DC 01 75 1D 66 C7 45 F6 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_30973084 {
    meta:
        author = "Elastic Security"
        id = "30973084-60d2-494d-a3c6-2a015a9459a0"
        fingerprint = "44fc236199ccf53107f1a617ac872f51d58a99ec242fe97b913e55b3ec9638e2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "a22ffa748bcaaed801f48f38b26a9cfdd5e62183a9f6f31c8a1d4a8443bf62a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 69 73 74 20 49 6D 70 6F 72 74 20 46 6F 72 20 53 6F 75 72 63 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1cfa95dd {
    meta:
        author = "Elastic Security"
        id = "1cfa95dd-e768-4071-9038-389c580741f9"
        fingerprint = "6ec21acb987464613830b3bbe1e2396093d269dae138c68fe77f35d88796001e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7D EC 00 7E 0F 48 8B 45 F0 0F B6 00 0F B6 C0 48 01 C3 EB 10 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_25c48456 {
    meta:
        author = "Elastic Security"
        id = "25c48456-2f83-41a8-ba37-b557014d1d86"
        fingerprint = "0c79f8eaacd2aa1fa60d5bfb7b567a9fc3e65068be1516ca723cb1394bb564ce"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "eba6f3e4f7b53e22522d82bdbdf5271c3fc701cbe07e9ecb7b4c0b85adc9d6b4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 83 6D E0 01 48 83 7D E0 00 75 DD 48 8B 45 F0 C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_b1ca2abd {
    meta:
        author = "Elastic Security"
        id = "b1ca2abd-b8ab-435d-85b6-a1c93212e492"
        fingerprint = "214c9dedf34b2c8502c6ef14aff5727ac5a2941e1a8278a48d34fea14d584a1a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 B0 C7 45 AC 14 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_cce8c792 {
    meta:
        author = "Elastic Security"
        id = "cce8c792-ef3e-43c2-b4ad-343de6a69cc7"
        fingerprint = "03541eb8a293e88c0b8e6509310f8c57f2cd16b5ff76783a73bde2b614b607fc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 48 89 51 08 48 8B 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_4bcea1c4 {
    meta:
        author = "Elastic Security"
        id = "4bcea1c4-de08-4526-8d31-89c5512f07af"
        fingerprint = "e859966e8281e024c82dedd5bd237ab53af28a0cb21d24daa456e5cd1186c352"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 FF 48 8B 45 C0 48 01 D0 0F B6 00 3C 0A 74 22 48 8B 45 C0 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_ab561a1b {
    meta:
        author = "Elastic Security"
        id = "ab561a1b-d8dd-4768-9b4c-07ef4777b252"
        fingerprint = "081dd5eb061c8023756e413420241e20a2c86097f95859181ca5d6b1d24fdd76"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "1b7df0d491974bead05d04ede6cf763ecac30ecff4d27bb4097c90cc9c3f4155"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B5 50 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 83 BD 5C FF FF }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_1a4eb229 {
    meta:
        author = "Elastic Security"
        id = "1a4eb229-a194-46a5-8e93-370a40ba999b"
        fingerprint = "de076ef23c2669512efc00ddfe926ef04f8ad939061c69131a0ef9a743639371"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 8B 45 E8 83 C0 01 89 45 F8 EB 0F 8B 45 E8 83 C0 01 89 45 F4 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_51ef0659 {
    meta:
        author = "Elastic Security"
        id = "51ef0659-2691-4558-bff8-fce614f10ab9"
        fingerprint = "41f517a19a3c4dc412200b683f4902a656f3dcfdead8b8292e309413577c3850"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "b7a2bc75dd9c44c38b2a6e4e7e579142ece92a75b8a3f815940c5aa31470be2b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 03 48 89 45 B0 8B 45 9C 48 63 D0 48 83 EA 01 48 89 55 B8 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_d90c4cbe {
    meta:
        author = "Elastic Security"
        id = "d90c4cbe-4d0a-4341-a58b-a472b67282d6"
        fingerprint = "64796aa7faa2e945b5c856c1c913cb62175413dc1df88505dececcfbd2878cb1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D8 F7 D0 5B 5D C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 48 89 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_c680c9fd {
    meta:
        author = "Elastic Security"
        id = "c680c9fd-34ad-4d92-b8d6-1b511c7c07a3"
        fingerprint = "5cb5b36d3ae5525b992a9d395b54429f52b11ea229e0cecbd62317af7b5faf84"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 01 D0 48 8D 48 10 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_e63396f4 {
    meta:
        author = "Elastic Security"
        id = "e63396f4-a297-4d99-b341-34cb22498078"
        fingerprint = "269285d03ea1a3b41ff134ab2cf5e22502626c72401b83add6c1e165f4dd83f8"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference_sample = "913e6d2538bd7eed3a8f3d958cf445fe11c5c299a70e5385e0df6a9b2f638323"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 83 45 FC 01 81 7D FC FF 0F 00 00 7E ?? 90 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_7d5355da {
    meta:
        author = "Elastic Security"
        id = "7d5355da-5fbd-46c0-8bd2-33a27cbcca63"
        fingerprint = "52882595f28e1778ee3b0e6bda94319f5c348523f16566833281f19912360270"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "03397525f90c8c2242058d2f6afc81ceab199c5abcab8fd460fabb6b083d8d20"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 60 64 48 8B 04 25 28 00 00 00 48 89 45 F8 31 C0 BF 0A 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a9e8a90f {
    meta:
        author = "Elastic Security"
        id = "a9e8a90f-5d95-4f4e-a9e0-c595be3729dd"
        fingerprint = "a06bbcbc09e5e44447b458d302c47e4f18438be8d57687700cb4bf3f3630fba8"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "0558cf8cab0ba1515b3b69ac32975e5e18d754874e7a54d19098e7240ebf44e4"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 D8 48 89 45 F0 66 C7 45 EE 00 00 EB 19 48 8B 45 F0 48 8D }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_a598192a {
    meta:
        author = "Elastic Security"
        id = "a598192a-c804-4c57-9cc3-c2205cb431d3"
        fingerprint = "61cb72180283746ebbd82047baffc4bf2384658019970c4dceadfb5c946abcd2"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D 65 D8 5B 5E 5F C9 C3 8D 36 55 89 E5 83 EC 18 57 56 53 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_53bf4e37 {
    meta:
        author = "Elastic Security"
        id = "53bf4e37-e043-4cf2-ad2a-bc63d69585ae"
        fingerprint = "83e804640b0848caa532dadc33923c226a34e0272457bde00325069ded55f256"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 00 49 50 5F 48 44 52 49 4E 43 4C 00 57 68 61 74 20 74 68 65 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_50158a6e {
    meta:
        author = "Elastic Security"
        id = "50158a6e-d412-4e37-a8b5-c7c79a2a5393"
        fingerprint = "f6286d1fd84aad72cdb8c655814a9df1848fae94ae931ccf62187c100b27a349"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "1e0cdb655e48d21a6b02d2e1e62052ffaaec9fdfe65a3d180fc8afabc249e1d8"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 01 D0 48 89 45 D8 0F B7 45 E6 48 8D 50 33 48 8B 45 F8 48 }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_f454ec10 {
    meta:
        author = "Elastic Security"
        id = "f454ec10-7a67-4717-9e95-fecb7c357566"
        fingerprint = "2ae5e2c3190a4ce5d238efdb10ac0520987425fb7af52246b6bf948abd0259da"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "0297e1ad6e180af85256a175183102776212d324a2ce0c4f32e8a44a2e2e9dad"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 EC 48 63 D0 48 8B 45 D0 48 01 D0 0F B6 00 3C 2E 75 4D 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Flooder_9417f77b {
    meta:
        author = "Elastic Security"
        id = "9417f77b-190b-4834-b57a-08a7cbfac884"
        fingerprint = "d321ea7aeb293f8f50236bddeee99802225b70e8695bb3527a89beea51e3ffb3"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Hacktool.Flooder"
        reference = "60ff13e27dad5e6eadb04011aa653a15e1a07200b6630fdd0d0d72a9ba797d68"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F B7 45 F6 0F B7 C0 48 01 C3 48 89 DA 48 C1 FA 10 0F B7 C3 48 8D }
    condition:
        all of them
}



// from Linux_Hacktool_Fontonlake.yar
rule Linux_Hacktool_Fontonlake_68ad8568 {
    meta:
        author = "Elastic Security"
        id = "68ad8568-2b00-4680-a83f-1689eff6099c"
        fingerprint = "81936e696a525cf02070fa7cfa27574cdad37e1b3d8f278950390a1945c21611"
        creation_date = "2021-10-12"
        last_modified = "2022-01-26"
        threat_name = "Linux.Hacktool.Fontonlake"
        reference_sample = "717953f52318e7687fc95626561cc607d4875d77ff7e3cf5c7b21cf91f576fa4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "run_in_bash"
        $s2 = "run_in_ss"
        $s3 = "real_bash_fork"
        $s4 = "fake_bash_add_history"
        $s5 = "hook_bash_add_history"
        $s6 = "real_bash_add_history"
        $s7 = "real_current_user.5417"
        $s8 = "real_bash_execve"
        $s9 = "inject_so_symbol.c"
        $s10 = "/root/rmgr_ko/subhook-0.5/subhook_x86.c"
        $s11 = "|1|%ld|%d|%d|%d|%d|%s|%s"
        $s12 = "/proc/.dot3"
    condition:
        4 of them
}



// from Linux_Hacktool_Infectionmonkey.yar
rule Linux_Hacktool_Infectionmonkey_6c84537b {
    meta:
        author = "Elastic Security"
        id = "6c84537b-6aa1-40d5-b14c-f78d7e67823d"
        fingerprint = "e9275f5fd8df389a4c99f69c09df1e3e515d8b958616e6d4d2c82d693deb4908"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Hacktool.Infectionmonkey"
        reference_sample = "d941943046db48cf0eb7f11e144a79749848ae6b50014833c5390936e829f6c3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 14 8B 54 24 0C 83 FA FF 0F 44 D0 83 C4 1C 89 D0 C3 8D 74 }
    condition:
        all of them
}



// from Linux_Hacktool_Lightning.yar
rule Linux_Hacktool_Lightning_d9a9173a {
    meta:
        author = "Elastic Security"
        id = "d9a9173a-6372-4892-8913-77f5749aa045"
        fingerprint = "f6e9d662f22b6f08c5e6d32994d6ed933c6863870352dfb76e1540676663e7e0"
        creation_date = "2022-11-08"
        last_modified = "2024-02-13"
        threat_name = "Linux.Hacktool.Lightning"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        reference_sample = "48f9471c20316b295704e6f8feb2196dd619799edec5835734fc24051f45c5b7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "cat /sys/class/net/%s/address" ascii fullword
        $a2 = "{\"ComputerName\":\"%s\",\"Guid\":\"%s\",\"RequestName\":\"%s\",\"Licence\":\"%s\"}" ascii fullword
        $a3 = "sleep 60 && ./%s &" ascii fullword
        $a4 = "Lightning.Core" ascii fullword
    condition:
        all of them
}

rule Linux_Hacktool_Lightning_e87c9d50 {
    meta:
        author = "Elastic Security"
        id = "e87c9d50-dafc-45bd-8786-5df646108c8a"
        fingerprint = "22b982866241d50b6e5d964ee190f6d07982a5d3f0b2352d863c20432d5f785e"
        creation_date = "2022-11-08"
        last_modified = "2024-02-13"
        threat_name = "Linux.Hacktool.Lightning"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        reference_sample = "fd285c2fb4d42dde23590118dba016bf5b846625da3abdbe48773530a07bcd1e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "Execute %s Faild." ascii fullword
        $a2 = "Lightning.Downloader" ascii fullword
        $a3 = "Execute %s Success." ascii fullword
        $a4 = "[-] Socks5 are Running!" ascii fullword
        $a5 = "[-] Get FileInfo(%s) Faild!" ascii fullword
    condition:
        all of them
}

rule Linux_Hacktool_Lightning_3bcac358 {
    meta:
        author = "Elastic Security"
        id = "3bcac358-b4b9-43ae-b173-bebe0c9ff899"
        fingerprint = "7108fab0ed64416cf16134475972f99c24aaaf8a4165b83287f9bdbf5050933b"
        creation_date = "2022-11-08"
        last_modified = "2024-02-13"
        threat_name = "Linux.Hacktool.Lightning"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        reference_sample = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[+] %s:%s %d,ntop:%s,strport:%s" ascii fullword
        $a2 = "%s: reading file \"%s\"" ascii fullword
        $a3 = "%s: kill(%d): %s" ascii fullword
        $a4 = "%s exec \"%s\": %s" ascii fullword
    condition:
        all of them
}



// from Linux_Hacktool_LigoloNG.yar
rule Linux_Hacktool_LigoloNG_027c0134 {
    meta:
        author = "Elastic Security"
        id = "027c0134-f3f6-448f-9f44-e0ead39fce9b"
        fingerprint = "3f1662ab5723eb2e50ea468129d1bd817f77e0df1b4565d242a3fcb1225b3360"
        creation_date = "2024-09-20"
        last_modified = "2024-11-04"
        threat_name = "Linux.Hacktool.LigoloNG"
        reference_sample = "eda6037bda3ccf6bbbaf105be0826669d5c4ac205273fefe103d8c648271de54"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = "https://github.com/nicocha30/ligolo-ng"
        $b = "@Nicocha30!"
        $c = "Ligolo-ng %s / %s / %s"
    condition:
        all of them
}



// from Linux_Hacktool_Outlaw.yar
rule Linux_Hacktool_Outlaw_cf069e73 {
    meta:
        author = "Elastic Security"
        id = "cf069e73-21f8-494c-b60e-286c033d2d55"
        fingerprint = "25169be28aa92f36a6d7cb803056efe1b7892a78120b648dc81887bc66eae89d"
        creation_date = "2025-02-21"
        last_modified = "2025-03-07"
        description = "Outlaw SSH bruteforce component fom the Dota3 package"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "c3efbd6b5e512e36123f7b24da9d83f11fffaf3023d5677d37731ebaa959dd27"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $ssh_key_1 = "MIIJrTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI8vKBZRGKsHoCAggA"
        $ssh_key_2 = "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBBC3juWsJ7DsDd2wH2XI+vUBIIJ"
        $ssh_key_3 = "UCQ2viiVV8pk3QSUOiwionAoe4j4cBP3Ly4TQmpbLge9zRfYEUVe4LmlytlidI7H"
        $ssh_key_4 = "O+bWbjqkvRXT9g/SELQofRrjw/W2ZqXuWUjhuI9Ruq0qYKxCgG2DR3AcqlmOv54g"
        $path_1 = "/home/eax/up"
        $path_2 = "/var/tmp/dota"
        $path_3 = "/dev/shm/ip"
        $path_4 = "/dev/shm/p"
        $path_5 = "/var/tmp/.systemcache"
        $cmd_1 = "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'"
        $cmd_2 = "cd ~; chattr -ia .ssh; lockr -ia .ssh"
        $cmd_3 = "sort -R b | awk '{ if ( NF == 2 ) print } '> p || cat b | awk '{ if ( NF == 2 ) print } '> p; sort -R a"
        $cmd_4 = "rm -rf /var/tmp/dota*"
        $cmd_5 = "rm -rf a b c d p ip ab.tar.gz"
    condition:
        (all of ($ssh_key*)) or (3 of ($path*) and 3 of ($cmd*))
}

rule Linux_Hacktool_Outlaw_bc128a02 {
    meta:
        author = "Elastic Security"
        id = "bc128a02-ee4e-484d-ae94-9e5cf1d26e94"
        fingerprint = "7dbce4ec62eac61115a98bcf0703bfddf684e54adef2b17d31a88cdfbf52e23c"
        creation_date = "2025-02-21"
        last_modified = "2025-03-07"
        description = "Socat wrapper found in one of the versions of the outlaw Dota3 package"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "008eadac3de35c5d4cd46ec00eb3997ff4c2fe864232fff5320b2697de7116cd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_1 = ".templock"
        $str_2 = "Selected IP: %s\n"
        $str_3 = "Connection is working! #########"
        $str_4 = "Killed all socat processes using 'pkill -9 socat'."
        $str_5 = "socat process is running! (PID: %d)\n"
        $str_6 = "Connection to %s:%d is working!\n"
    condition:
        5 of them
}

rule Linux_Hacktool_Outlaw_2f007b58 {
    meta:
        author = "Elastic Security"
        id = "2f007b58-2041-4ef8-8bd5-3a76a6e86ece"
        fingerprint = "7fc8a66712a147a1006e053b9e957b4e6029a793850e187ec8e1c4921f454462"
        creation_date = "2025-02-28"
        last_modified = "2025-03-07"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "008eadac3de35c5d4cd46ec00eb3997ff4c2fe864232fff5320b2697de7116cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $x64_start_thread = { 31 DB B9 10 00 00 00 4C 8B 44 24 10 48 89 D8 48 89 EF BE 7F 00 00 00 F3 48 AB 48 8B 4C 24 08 }
        $x64_main = { 4B 8B 04 F7 48 89 42 10 4B 8B 44 F7 10 48 89 42 18 4B 8B 44 F7 20 48 89 42 20 4B 8B 44 F7 08 48 89 42 28 4B 8B 44 F7 18 48 89 42 30 4B 8B 44 F7 28 48 89 42 38 4D 85 F6 74 7B }
        $x64_main_getopt = { 4C 89 EE 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 11 83 E8 48 83 F8 2E 77 E2 49 63 04 84 4C 01 E0 FF E0 }
        $x64_ip_select = { 89 C2 48 98 48 69 C0 AB AA AA 2A 89 D1 C1 F9 1F 48 C1 E8 20 29 C8 8D 0C 40 89 D0 01 C9 29 C8 83 F8 02 }
        $x86_main = { 83 C4 10 C6 04 06 00 8B 85 00 C2 FC FF 89 34 B8 83 C7 01 8B 85 10 C2 FC FF 83 EC 08 01 F8 89 85 04 C2 FC FF 89 85 0C C2 FC FF FF B5 08 C2 FC FF 6A 00 }
        $x86_main_getopt = { 83 C4 10 83 F8 FF 74 13 83 E8 48 83 F8 2E 8B 8C 83 ?? ?? ?? ?? 01 D9 FF E1 }
        $x86_ip_select = { BA AB AA AA 2A 83 C4 10 89 C1 F7 EA 89 C8 C1 F8 1F 29 C2 8D 04 52 01 C0 29 C1 83 F9 02 }
        $x86_worker = { 83 C4 10 8D 7C 24 10 90 8B 46 04 85 C0 74 4F 8B 6E 74 83 EC 0C 55 }
    condition:
        3 of ($x64*) or 3 of ($x86*)
}



// from Linux_Hacktool_Portscan.yar
rule Linux_Hacktool_Portscan_a40c7ef0 {
    meta:
        author = "Elastic Security"
        id = "a40c7ef0-627c-4965-b4d3-b05b79586170"
        fingerprint = "bf686c3c313936a144265cbf75850c8aee3af3ae36cb571050c7fceed385451d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "c389c42bac5d4261dbca50c848f22c701df4c9a2c5877dc01e2eaa81300bdc29"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 50 44 00 52 65 73 70 6F 6E 73 65 20 77 61 73 20 4E 54 50 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_6c6000c2 {
    meta:
        author = "Elastic Security"
        id = "6c6000c2-7e9a-457c-a745-00a3ac83a4bc"
        fingerprint = "3c893aebe688d70aebcb15fdc0d2780d2ec0589084c915ff71519ec29e5017f1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "8877009fc8ee27ba3b35a7680b80d21c84ee7296bcabe1de51aeeafcc8978da7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 30 B9 0E 00 00 00 4C 89 D7 F3 A6 0F 97 C2 80 DA 00 84 D2 45 0F }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_e191222d {
    meta:
        author = "Elastic Security"
        id = "e191222d-633a-4408-9a54-a70bb9e89cc0"
        fingerprint = "5580dd8b9180b8ff36c7d08a134b1b3782b41054d8b29b23fc5a79e7b0059fd1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "e2f4313538c3ef23adbfc50f37451c318bfd1ffd0e5aaa346cce4cc37417f812"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 4F 55 4E 44 00 56 41 4C 55 45 00 44 45 4C 45 54 45 44 00 54 }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_e57b0a0c {
    meta:
        author = "Elastic Security"
        id = "e57b0a0c-66b8-488b-b19d-ae06623645fd"
        fingerprint = "829c7d271ae475ef06d583148bbdf91af67ce4c7a831da73cc52e8406e7e8f9e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "f8ee385316b60ee551565876287c06d76ac5765f005ca584d1ca6da13a6eb619"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 83 7D 08 03 75 2B 83 EC 0C 8B 45 0C 83 C0 08 FF 30 8B 45 0C 83 }
    condition:
        all of them
}



// from Linux_Hacktool_Prochide.yar
rule Linux_Hacktool_Prochide_7333221a {
    meta:
        author = "Elastic Security"
        id = "7333221a-b3dc-4b26-8ec7-7e4f5405e228"
        fingerprint = "e3aa99d48a8554dfaf9f7d947170e6e169b99bf5b6347d4832181e80cc2845cf"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Prochide"
        reference_sample = "fad956a6a38abac8a8a0f14cc50f473ec6fc1c9fd204e235b89523183931090b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF 83 BD 9C FC FF FF FF 75 14 BF 7F 22 40 00 }
    condition:
        all of them
}



// from Linux_Hacktool_Tcpscan.yar
rule Linux_Hacktool_Tcpscan_334d0ca5 {
    meta:
        author = "Elastic Security"
        id = "334d0ca5-d143-4a32-8632-9fbdd2d96987"
        fingerprint = "1f8fc064770bd76577b9455ae858d8a98b573e01a199adf2928d8433d990eaa7"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Tcpscan"
        reference_sample = "62de04185c2e3c22af349479a68ad53c31b3874794e7c4f0f33e8d125c37f6b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 10 89 45 D4 83 7D D4 00 79 1A 83 EC 0C 68 13 }
    condition:
        all of them
}



// from Linux_Hacktool_Wipelog.yar
rule Linux_Hacktool_Wipelog_daea1aa4 {
    meta:
        author = "Elastic Security"
        id = "daea1aa4-0df7-4308-83e1-0707dcda2e54"
        fingerprint = "93f899e14e6331c2149ba5c0c1e9dd8def5a7d1b6d2a7af66eade991dea77b3c"
        creation_date = "2022-03-17"
        last_modified = "2022-07-22"
        threat_name = "Linux.Hacktool.Wipelog"
        reference_sample = "39b3a95928326012c3b2f64e2663663adde4b028d940c7e804ac4d3953677ea6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "Erase one username on tty"
        $s2 = "wipe_utmp"
        $s3 = "wipe_acct"
        $s4 = "wipe_lastlog"
        $s5 = "wipe_wtmp"
        $s6 = "getpwnam"
        $s7 = "ERROR: Can't find user in passwd"
        $s8 = "ERROR: Opening tmp ACCT file"
        $s9 = "/var/log/wtmp"
        $s10 = "/var/log/lastlog"
        $s11 = "Patching %s ...."
    condition:
        4 of them
}



// from Linux_Packer_Patched_UPX.yar
rule Linux_Packer_Patched_UPX_62e11c64 {
    meta:
        author = "Elastic Security"
        id = "62e11c64-fc7d-4a0a-9d72-ad53ec3987ff"
        fingerprint = "3297b5c63e70c557e71b739428b453039b142e1e04c2ab15eea4627d023b686d"
        creation_date = "2021-06-08"
        last_modified = "2021-07-28"
        threat_name = "Linux.Packer.Patched_UPX"
        reference = "https://cujo.com/upx-anti-unpacking-techniques-in-iot-malware/"
        reference_sample = "02f81a1e1edcb9032a1d7256a002b11e1e864b2e9989f5d24ea1c9b507895669"
        severity = 60
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 50 58 21 [4] 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        all of them and $a in (0 .. 255)
}



// from Linux_Proxy_Frp.yar
rule Linux_Proxy_Frp_4213778f {
    meta:
        author = "Elastic Security"
        id = "4213778f-d05e-4af8-9650-2d813d5a64e5"
        fingerprint = "70bb186a9719767a9a60786fbe10bf4cc2f04c19ea58aaaa90018ec89a9f9b84"
        creation_date = "2021-10-20"
        last_modified = "2022-01-26"
        threat_name = "Linux.Proxy.Frp"
        reference_sample = "16294086be1cc853f75e864a405f31e2da621cb9d6a59f2a71a2fca4e268b6c2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "github.com/fatedier/frp/client/proxy.TcpProxy"
        $s2 = "frp/cmd/frpc/sub/xtcp.go"
        $s3 = "frp/client/proxy/proxy_manager.go"
        $s4 = "fatedier/frp/models/config/proxy.go"
        $s5 = "github.com/fatedier/frp/server/proxy"
        $s6 = "frp/cmd/frps/main.go"
        $p1 = "json:\"remote_port\""
        $p2 = "remote_port"
        $p3 = "remote_addr"
        $p4 = "range section [%s] local_port and remote_port is necessary[ERR]"
    condition:
        2 of ($s*) and 2 of ($p*)
}



// from Linux_Ransomware_Agenda.yar
rule Linux_Ransomware_Agenda_4562a654 {
    meta:
        author = "Elastic Security"
        id = "4562a654-a595-4480-a095-bd89ec907529"
        fingerprint = "b290b47e0839a5563b86d9d7dfbdc7fb2efa5669ede07f3710031f251b82ed6b"
        creation_date = "2024-09-12"
        last_modified = "2024-11-22"
        threat_name = "Linux.Ransomware.Agenda"
        reference_sample = "cd27a31e618fe93df37603e5ece3352a91f27671ee73bdc8ce9ad793cad72a0f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $ = "%s_RECOVER.txt"
        $ = "-- Qilin"
        $ = "no-vm-kill"
        $ = "File extensions blacklist: [%s]"
    condition:
        3 of them
}



// from Linux_Ransomware_Akira.yar
rule Linux_Ransomware_Akira_02237952 {
    meta:
        author = "Elastic Security"
        id = "02237952-b9ac-44e5-a32f-f3cc8f28a89b"
        fingerprint = "7fcfac47be082441f6df149d0615a9d2020ac1e9023eabfcf10db4fe400cd474"
        creation_date = "2023-07-28"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Akira"
        reference_sample = "1d3b5c650533d13c81e325972a912e3ff8776e36e18bca966dae50735f8ab296"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "No path to encrypt" fullword
        $a2 = "--encryption_percent" fullword
        $a3 = "Failed to import public key" fullword
        $a4 = "akira_readme.txt" fullword
    condition:
        3 of them
}

rule Linux_Ransomware_Akira_27440619 {
    meta:
        author = "Elastic Security"
        id = "27440619-50de-4103-b961-6b66cf9001f9"
        fingerprint = "611b051982db94dc83a875b3e5ae20177690fda16ead5b8591cb12d0e899712b"
        creation_date = "2024-11-21"
        last_modified = "2024-11-22"
        threat_name = "Linux.Ransomware.Akira"
        reference_sample = "3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 83 A7 00 01 00 00 00 31 C0 41 88 87 04 01 00 00 6A 08 5B 49 89 9F 08 01 00 00 0F 57 C0 41 0F 29 87 10 01 00 00 49 89 9F 20 01 00 00 41 0F 11 87 28 01 00 00 41 C6 87 38 01 00 00 01 6A 01 41 5E }
    condition:
        all of them
}



// from Linux_Ransomware_Babuk.yar
rule Linux_Ransomware_Babuk_bd216cab {
    meta:
        author = "Elastic Security"
        id = "bd216cab-6532-4a71-9353-8ad692550b97"
        fingerprint = "c7517a40759de20edf7851d164c0e4ba71de049f8ea964f15ab5db12c35352ad"
        creation_date = "2024-05-09"
        last_modified = "2024-06-12"
        threat_name = "Linux.Ransomware.Babuk"
        reference_sample = "d305a30017baef4f08cee38a851b57869676e45c66e64bb7cc58d40bf0142fe0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "Whole files count: %d"
        $a2 = "Doesn't encrypted files: %d"
    condition:
        all of them
}



// from Linux_Ransomware_BlackBasta.yar
rule Linux_Ransomware_BlackBasta_96eb3f20 {
    meta:
        author = "Elastic Security"
        id = "96eb3f20-9c40-4d40-8a6c-568a51c52d4d"
        fingerprint = "5146ad9def7ccaba4b4896f345b0950c587ad5f96a106ec461caeb028d809ead"
        creation_date = "2022-08-06"
        last_modified = "2022-08-16"
        threat_name = "Linux.Ransomware.BlackBasta"
        reference_sample = "96339a7e87ffce6ced247feb9b4cb7c05b83ca315976a9522155bad726b8e5be"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii fullword
        $a2 = "Your data are stolen and encrypted" ascii fullword
        $a3 = "fileEncryptionPercent" ascii fullword
        $a4 = "fileQueueLocker" ascii fullword
        $a5 = "totalBytesEncrypted" ascii fullword
        $seq_encrypt_block = { 41 56 31 D2 41 55 41 54 49 89 FE 55 53 48 89 F5 49 63 D8 4C }
        $seq_encrypt_thread = { 4C 8B 74 24 ?? 31 DB 45 31 FF 4D 8B 6E ?? 49 83 FD ?? 0F 87 ?? ?? ?? ?? 31 C0 4D 39 EF 0F 82 ?? ?? ?? ?? 48 01 C3 4C 39 EB 0F 83 ?? ?? ?? ?? }
    condition:
        3 of ($a*) and 1 of ($seq*)
}



// from Linux_Ransomware_BlackSuit.yar
rule Linux_Ransomware_BlackSuit_9f53e7e5 {
    meta:
        author = "Elastic Security"
        id = "9f53e7e5-7177-4e17-ac12-9214c4deddf2"
        fingerprint = "34355cb1731fe6c8fa684a484943127f8fdf3814d45025e29bdf25a08b4890fd"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.BlackSuit"
        reference_sample = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "esxcli vm process list > list_" fullword
        $a2 = "Drop readme failed: %s(%d)" fullword
        $a3 = "README.BlackSuit.txt" fullword
    condition:
        2 of them
}



// from Linux_Ransomware_Clop.yar
rule Linux_Ransomware_Clop_728cf32a {
    meta:
        author = "Elastic Security"
        id = "728cf32a-94c1-4979-b092-6851649946be"
        fingerprint = "86644f9f1e9f0b69896cd05ae1442a3b99483cc0ff15773c0c3403e59b6d5c97"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Clop"
        reference_sample = "09d6dab9b70a74f61c41eaa485b37de9a40c86b6d2eae7413db11b4e6a8256ef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "CONTACT US BY EMAIL:"
        $a2 = "OR WRITE TO THE CHAT AT->"
        $a3 = "(use TOR browser)"
        $a4 = ".onion/"
    condition:
        3 of them
}



// from Linux_Ransomware_Conti.yar
rule Linux_Ransomware_Conti_53a640f4 {
    meta:
        author = "Elastic Security"
        id = "53a640f4-905c-4b0d-ac4a-9ffdffd74253"
        fingerprint = "d81309f83494b0635444234c514fda0edc05a11ac861c769a007f9f558def148"
        creation_date = "2022-09-22"
        last_modified = "2022-10-18"
        threat_name = "Linux.Ransomware.Conti"
        reference_sample = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 D3 EA 48 89 D0 83 E0 01 48 85 C0 0F 95 C0 84 C0 74 0B 8B }
    condition:
        all of them
}

rule Linux_Ransomware_Conti_a89c26cf {
    meta:
        author = "Elastic Security"
        id = "a89c26cf-ccec-40ca-85d3-d014b767fd6a"
        fingerprint = "c29bb1bbbd76712bbc3ddd1dfeeec40b230677339dea7441b1f34159ccbbdf9f"
        creation_date = "2023-07-30"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Conti"
        reference_sample = "95776f31cbcac08eb3f3e9235d07513a6d7a6bf9f1b7f3d400b2cf0afdb088a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "paremeter --size cannot be %d" fullword
        $a2 = "--vmkiller" fullword
        $a3 = ".conti" fullword
        $a4 = "Cannot create file vm-list.txt" fullword
    condition:
        3 of them
}



// from Linux_Ransomware_EchoRaix.yar
rule Linux_Ransomware_EchoRaix_ea9532df {
    meta:
        author = "Elastic Security"
        id = "ea9532df-1136-4b11-bf4f-8838074f4e66"
        fingerprint = "f28b340b99ec2b96ee78da50b3fc455c87dca1e898abf008c16ac192556939c5"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.EchoRaix"
        reference_sample = "dfe32d97eb48fb2afc295eecfda3196cba5d27ced6217532d119a764071c6297"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 43 58 68 64 4B 74 7A 65 42 59 6C 48 65 58 79 5A 52 62 61 30 2F 6E 65 46 7A 34 49 7A 67 53 38 4C 68 75 36 38 5A 75 4C 4C 52 2F 66 67 6E 72 34 79 54 72 5A 54 6B 43 36 31 62 2D 59 6F 6C 49 2F 32 4C 36 66 53 55 46 52 72 55 70 49 34 6D 4E 53 41 4F 62 5F }
    condition:
        all of them
}

rule Linux_Ransomware_EchoRaix_ee0c719a {
    meta:
        author = "Elastic Security"
        id = "ee0c719a-1f04-45ff-9e49-38028b138fd0"
        fingerprint = "073d62ce55b1940774ffadeb5b76343aa49bd0a36cf82d50e2bae44f6049a1e8"
        creation_date = "2023-07-29"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.EchoRaix"
        reference_sample = "e711b2d9323582aa390cf34846a2064457ae065c7d2ee1a78f5ed0859b40f9c0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 24 10 89 44 24 68 8B 4C 24 14 8B 54 24 18 85 C9 74 57 74 03 8B }
        $a2 = { 6D 61 69 6E 2E 43 68 65 63 6B 49 73 52 75 6E 6E 69 6E 67 }
    condition:
        all of them
}



// from Linux_Ransomware_Erebus.yar
rule Linux_Ransomware_Erebus_ead4f55b {
    meta:
        author = "Elastic Security"
        id = "ead4f55b-a4c6-46ff-bc8e-03831a17df9c"
        fingerprint = "571832cc76322a95244b042ab9b358755a1be19260410658dc32c03c5cae7638"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Erebus"
        reference_sample = "6558330f07a7c90c40006346ed09e859b588d031193f8a9679fe11a85c8ccb37"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "important files have been encrypted"
        $a2 = "max_size_mb"
        $a3 = "EREBUS IS BEST."
    condition:
        2 of them
}



// from Linux_Ransomware_Esxiargs.yar
rule Linux_Ransomware_Esxiargs_75a8ec04 {
    meta:
        author = "Elastic Security"
        id = "75a8ec04-c41d-4702-94fa-976870762aaf"
        fingerprint = "279259c7ca41331b09842c2221139d249d6dfe2e2cb6b27eb50af7be75120ce4"
        creation_date = "2023-02-09"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Esxiargs"
        reference_sample = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "number of MB in encryption block"
        $s2 = "number of MB to skip while encryption"
        $s3 = "get_pk_data: key file is empty"
        $s4 = { 6F 70 65 6E 00 6C 73 65 65 6B 20 5B 65 6E 64 5D 00 6F 70 65 6E 5F 70 6B 5F 66 69 6C 65 }
        $s5 = "[<enc_step>] [<enc_size>] [<file_size>]"
    condition:
        3 of them
}



// from Linux_Ransomware_Gonnacry.yar
rule Linux_Ransomware_Gonnacry_53c3832d {
    meta:
        author = "Elastic Security"
        id = "53c3832d-ceff-407d-920b-7b6442688fa9"
        fingerprint = "7d93c26c9e069af5cef964f5747104ba6d1d0d030a1f6b1c377355223c5359a1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Ransomware.Gonnacry"
        reference_sample = "f5de75a6db591fe6bb6b656aa1dcfc8f7fe0686869c34192bfa4ec092554a4ac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 10 48 89 7D F8 EB 56 48 8B 45 F8 48 8B }
    condition:
        all of them
}



// from Linux_Ransomware_Hellokitty.yar
rule Linux_Ransomware_Hellokitty_35731270 {
    meta:
        author = "Elastic Security"
        id = "35731270-b283-4dff-8316-6a541ff1d4d5"
        fingerprint = "1945bfcbe084f8f6671c73e74679fb2933d2ebea54479fdf348d4804a614279a"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Hellokitty"
        reference_sample = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "File Locked:%s PID:%d" fullword
        $a2 = "error encrypt: %s rename back:%s" fullword
        $a3 = "esxcli vm process kill -t=soft -w=%d" fullword
    condition:
        2 of them
}



// from Linux_Ransomware_Hive.yar
rule Linux_Ransomware_Hive_bdc7de59 {
    meta:
        author = "Elastic Security"
        id = "bdc7de59-bf12-461f-99e0-ec2532ace4e9"
        fingerprint = "415ef589a1c2da6b16ab30fb68f938a9ee7917f5509f73aa90aeec51c10dc1ff"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Ransomware.Hive"
        reference_sample = "713b699c04f21000fca981e698e1046d4595f423bd5741d712fd7e0bc358c771"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 40 03 4C 39 C1 73 3A 4C 89 84 24 F0 00 00 00 48 89 D3 48 89 CF 4C }
    condition:
        all of them
}



// from Linux_Ransomware_ItsSoEasy.yar
rule Linux_Ransomware_ItsSoEasy_30bd68e0 {
    meta:
        author = "Elastic Security"
        id = "30bd68e0-3050-4aaf-b1bb-3ae10b6bd6dd"
        fingerprint = "33170bbe6d182b36c77d732c283377f6f84cf82bd8d28cc4c3aef4d0914a0ae8"
        creation_date = "2023-07-28"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.ItsSoEasy"
        reference_sample = "efb1024654e86c0c30d2ac5f97d27f5f27b4dd3f7f6ada65d58691f0d703461c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 44 61 74 61 2E 66 75 6E 63 31 }
        $a2 = { 6D 61 69 6E 2E 6D 61 6B 65 41 75 74 6F 52 75 6E }
    condition:
        all of them
}



// from Linux_Ransomware_LimpDemon.yar
rule Linux_Ransomware_LimpDemon_95c748e0 {
    meta:
        author = "Elastic Security"
        id = "95c748e0-e2f5-4997-a69d-dbc8885e6f18"
        fingerprint = "20527c2e0d2e577c17da7184193ba372027cedb075f78bb75aff9d218c2d660b"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.LimpDemon"
        reference_sample = "a4200e90a821a2f2eb3056872f06cf5b057be154dcc410274955b2aaca831651"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[-] You have to pass access key to start process" fullword
        $a2 = "[+] Shutting down VMWare ESXi servers..." fullword
        $a3 = "%s --daemon (start as a service)" fullword
        $a4 = "%s --access-key <key> (key for decryption config)" fullword
    condition:
        2 of them
}



// from Linux_Ransomware_Lockbit.yar
rule Linux_Ransomware_Lockbit_d248e80e {
    meta:
        author = "Elastic Security"
        id = "d248e80e-3e2f-4957-adc3-0c912b0cd386"
        fingerprint = "417ecf5a0b6030ed5b973186efa1e72dfa56886ba6cfc5fbf615e0814c24992f"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Lockbit"
        reference_sample = "4800a67ceff340d2ab4f79406a01f58e5a97d589b29b35394b2a82a299b19745"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "restore-my-files.txt" fullword
        $b1 = "xkeyboard-config" fullword
        $b2 = "bootsect.bak" fullword
        $b3 = "lockbit" fullword
        $b4 = "Error: %s" fullword
        $b5 = "crypto_generichash_blake2b_final" fullword
    condition:
        $a1 and 2 of ($b*)
}

rule Linux_Ransomware_Lockbit_5b30a04b {
    meta:
        author = "Elastic Security"
        id = "5b30a04b-d618-4698-a797-30bf6d4a001c"
        fingerprint = "99bf6afb1554ec3b3b82389c93ca87018c51f7a80270d64007a5f5fc59715c45"
        creation_date = "2023-07-29"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Lockbit"
        reference_sample = "41cbb7d79388eaa4d6e704bd4a8bf8f34d486d27277001c343ea3ce112f4fb0d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 5D 50 4A 49 55 58 40 77 58 54 5C }
        $a2 = { 33 6B 5C 5A 4C 4B 4A 50 4F 5C 55 40 }
        $a3 = { 5E 4C 58 4B 58 57 4D 5C 5C 5D }
    condition:
        all of them
}



// from Linux_Ransomware_Monti.yar
rule Linux_Ransomware_Monti_9c64f016 {
    meta:
        author = "Elastic Security"
        id = "9c64f016-0fd9-41bf-8916-cdf3a35efdd6"
        fingerprint = "af28cc97eed328f3b2b0181784545e41a521e9dfff09a504177cb56929606b84"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Monti"
        reference_sample = "ad8d1b28405d9aebae6f42db1a09daec471bf342e9e0a10ab4e0a258a7fa8713"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[%s] Flag doesn't equal MONTI."
        $a2 = "--vmkill Whether to kill the virtual machine"
        $a3 = "MONTI strain."
        $a4 = "http://monti"
    condition:
        2 of them
}



// from Linux_Ransomware_NoEscape.yar
rule Linux_Ransomware_NoEscape_6de58e0c {
    meta:
        author = "Elastic Security"
        id = "6de58e0c-67f9-4344-9fe9-26bfc37e537e"
        fingerprint = "60a160abcbb6d93d9ee167663e419047f3297d549c534cbe66d035a0aa36d806"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.NoEscape"
        reference_sample = "46f1a4c77896f38a387f785b2af535f8c29d40a105b63a259d295cb14d36a561"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "HOW_TO_RECOVER_FILES.txt"
        $a2 = "large_file_size_mb"
        $a3 = "note_text"
    condition:
        all of them
}



// from Linux_Ransomware_Quantum.yar
rule Linux_Ransomware_Quantum_8513fb8b {
    meta:
        author = "Elastic Security"
        id = "8513fb8b-43f7-46b1-8318-5549a7609d3b"
        fingerprint = "1c1af76ab5df8243b8e25555f1762749ca60da56fecea9d4131c612358244525"
        creation_date = "2023-07-28"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Quantum"
        reference_sample = "3bcb9ad92fdca53195f390fc4d8d721b504b38deeda25c1189a909a7011406c9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "All your files are encrypted on all devices across the network"
        $a2 = "process with pid %d is blocking %s, going to kill it"
    condition:
        all of them
}



// from Linux_Ransomware_RagnarLocker.yar
rule Linux_Ransomware_RagnarLocker_9f5982b8 {
    meta:
        author = "Elastic Security"
        id = "9f5982b8-98db-42d1-b987-451d3cb7fc4b"
        fingerprint = "782d9225a6060c23484a285f7492bb45f21c37597ea82e4ca309aedbb1c30223"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.RagnarLocker"
        reference_sample = "f668f74d8808f5658153ff3e6aee8653b6324ada70a4aa2034dfa20d96875836"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = ".README_TO_RESTORE"
        $a2 = "If WE MAKE A DEAL:"
        $a3 = "Unable to rename file from: %s to: %s"
    condition:
        2 of them
}



// from Linux_Ransomware_RedAlert.yar
rule Linux_Ransomware_RedAlert_39642d52 {
    meta:
        author = "Elastic Security"
        id = "39642d52-0a4b-48d5-bb62-8f37beb4dc6a"
        fingerprint = "744524ee2ae9e3e232f15b0576cdab836ac0fe3c9925eab66ed8c6b0be3f23d7"
        creation_date = "2022-07-06"
        last_modified = "2022-08-16"
        threat_name = "Linux.Ransomware.RedAlert"
        reference_sample = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_ransomnote = "\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\% REDALERT UNIQUE IDENTIFIER START \\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%" ascii fullword
        $str_print = "\t\t\t########\n\t\t\t[ N13V ]\n\t\t\t########\n\n" ascii fullword
        $str_arg = "[info] Catch -t argument. Check encryption time" ascii fullword
        $str_ext = ".crypt658" ascii fullword
        $byte_checkvm = { 48 8B 14 DD ?? ?? ?? ?? 31 C0 48 83 C9 FF FC 48 89 EE 48 89 D7 F2 AE 4C 89 E7 48 F7 D1 E8 }
    condition:
        3 of ($str_*) or ($byte_checkvm and $str_print)
}



// from Linux_Ransomware_RoyalPest.yar
rule Linux_Ransomware_RoyalPest_502a3db6 {
    meta:
        author = "Elastic Security"
        id = "502a3db6-4711-42c7-8178-c3150f184fc6"
        fingerprint = "4bde7998f41ef3d0f2769078cf56e03d36eacf503f859a23fc442ced95d839cb"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.RoyalPest"
        reference_sample = "09a79e5e20fa4f5aae610c8ce3fe954029a91972b56c6576035ff7e0ec4c1d14"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "hit by Royal ransomware."
        $a2 = "Please contact us via :"
        $a3 = ".onion/%s"
        $a4 = "esxcli vm process list > list"
    condition:
        3 of them
}



// from Linux_Ransomware_SFile.yar
rule Linux_Ransomware_SFile_9e347b52 {
    meta:
        author = "Elastic Security"
        id = "9e347b52-233a-4956-9f1f-7600c482e280"
        fingerprint = "094af0030d51d1e28405fc02a51ccc1bedf9e083b3d24b82c36f4b397eefbb0b"
        creation_date = "2023-07-29"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.SFile"
        reference_sample = "49473adedc4ee9b1252f120ad8a69e165dc62eabfa794370408ae055ec65db9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 49 74 27 73 20 6A 75 73 74 20 61 20 62 75 73 69 6E 65 73 73 2E }
        $a2 = { 41 6C 6C 20 64 61 74 61 20 69 73 20 70 72 6F 70 65 72 6C 79 20 70 72 6F 74 65 63 74 65 64 20 61 67 61 69 6E 73 74 20 75 6E 61 75 74 68 6F 72 69 7A 65 64 20 61 63 63 65 73 73 20 62 79 20 73 74 65 61 64 79 20 65 6E 63 72 79 70 74 69 6F 6E 20 74 65 63 68 6E 6F 6C 6F 67 79 2E }
    condition:
        all of them
}



// from Linux_Ransomware_Sodinokibi.yar
rule Linux_Ransomware_Sodinokibi_2883d7cd {
    meta:
        author = "Elastic Security"
        id = "2883d7cd-fd3b-47a5-9283-a40335172c62"
        fingerprint = "d6570a8e9358cef95388a72b2e7f747ee5092620c4f92a4b4e6c1bb277e1cb36"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Ransomware.Sodinokibi"
        reference_sample = "a322b230a3451fd11dcfe72af4da1df07183d6aaf1ab9e062f0e6b14cf6d23cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 08 FF FF FF 48 01 85 28 FF FF FF 48 8B 85 08 FF FF FF 48 29 85 20 FF }
    condition:
        all of them
}



// from Linux_Rootkit_Adore.yar
rule Linux_Rootkit_Adore_fe3fd09f {
    meta:
        author = "Elastic Security"
        id = "fe3fd09f-d170-4bb0-bc8d-6d61bdc22164"
        fingerprint = "2bab2a4391359c6a7148417b010887d0754b91ac99820258e849e81f7752069f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Rootkit.Adore"
        reference_sample = "f4e532b840e279daf3d206e9214a1b065f97deb7c1487a34ac5cbd7cbbf33e1a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 00 75 17 68 E4 A1 04 08 }
    condition:
        all of them
}



// from Linux_Rootkit_Arkd.yar
rule Linux_Rootkit_Arkd_bbd56917 {
    meta:
        author = "Elastic Security"
        id = "bbd56917-aeab-4e73-b85b-adc41fc7ffe4"
        fingerprint = "73c8b2685b6b568575afca3c3c2fe2095d94f2040f4a1207974fe77bbb657163"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Rootkit.Arkd"
        reference_sample = "e0765f0e90839b551778214c2f9ae567dd44838516a3df2c73396a488227a600"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7D 0B B8 FF FF FF FF EB 11 8D 74 26 00 39 C1 7F 04 31 C0 EB 05 B8 01 00 }
    condition:
        all of them
}



// from Linux_Rootkit_Bedevil.yar
rule Linux_Rootkit_Bedevil_2af79cea {
    meta:
        author = "Elastic Security"
        id = "2af79cea-f861-4db6-9036-ee6aeb96acd6"
        fingerprint = "293f3a8a126f2f271f8ecc9dcb3a9d19338f79aeec2d9d5fdc66e198b1e45298"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Bedevil"
        reference_sample = "8f8c598350632b32e72cd6af3a0ca93c05b4d9100fd03e2ae1aec97a946eb347"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "bdvinstall"
        $str2 = "putbdvlenv"
        $str3 = "bdvprep"
        $str4 = "bdvcleanse"
        $str5 = "dobdvutil"
        $str6 = "forge_maps"
        $str7 = "forge_smaps"
        $str8 = "forge_numamaps"
        $str9 = "forge_procnet"
        $str10 = "secret_connection"
        $str11 = "dropshell"
    condition:
        4 of ($str*)
}



// from Linux_Rootkit_BrokePKG.yar
rule Linux_Rootkit_BrokePKG_7b7d4581 {
    meta:
        author = "Elastic Security"
        id = "7b7d4581-ee4d-48c3-81e4-4264d68e8fe9"
        fingerprint = "5d771035e2bc4ffea1b9fd6f29c76ff5d9278db42167d3dab90eb0ac8d4bdd78"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.BrokePKG"
        reference_sample = "97c5e011c7315a05c470eef4032030e461ec2a596513703beedeec0b0c6ed2da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $license1 = "author=R3tr074"
        $license2 = "name=brokepkg"
        $license3 = "description=Rootkit"
        $license4 = "license=GPL"
        $str1 = "brokepkg"
        $str2 = "brokepkg: module revealed"
        $str3 = "brokepkg: hidden module"
        $str4 = "brokepkg: given away root"
        $str5 = "brokepkg unloaded, my work has completed"
        $str6 = "br0k3_n0w_h1dd3n"
        $hook1 = "nf_inet_hooks"
        $hook2 = "ftrace_hook"
        $hook3 = "hook_getdents"
        $hook4 = "hook_kill"
        $hook5 = "hook_tcp4_seq_show"
        $hook6 = "hook_tcp6_seq_show"
        $hook7 = "orig_tcp6_seq_show"
        $hook8 = "orig_tcp4_seq_show"
        $hook9 = "orig_kill"
        $hook10 = "orig_getdents"
    condition:
        3 of ($license*) or 2 of ($str*) or 4 of ($hook*)
}



// from Linux_Rootkit_Dakkatoni.yar
rule Linux_Rootkit_Dakkatoni_010d3ac2 {
    meta:
        author = "Elastic Security"
        id = "010d3ac2-0bb2-4966-bf5f-fd040ba07311"
        fingerprint = "2c7935079dc971d2b8a64c512ad677e946ff45f7f1d1b62c3ca011ebde82f13b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Rootkit.Dakkatoni"
        reference_sample = "38b2d033eb5ce87faa4faa7fcac943d9373e432e0d45e741a0c01d714ee9d4d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C8 C1 E0 0D 31 C1 89 CE 83 E6 03 83 C6 05 89 C8 31 D2 C1 }
    condition:
        all of them
}



// from Linux_Rootkit_Diamorphine.yar
rule Linux_Rootkit_Diamorphine_716c7ffa {
    meta:
        author = "Elastic Security"
        id = "716c7ffa-ea57-4ac2-9d23-9873bc8f83bd"
        fingerprint = "59f9657c8ee1f6d05020a3565d08230d10185968c8b064f462ee54a4db8db3d6"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Diamorphine"
        reference_sample = "01fb490fbe2c2b5368cc227abd97e011e83b5e99bb80945ef599fc80e85f8545"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "author=m0nad"
        $str2 = "description=LKM rootkit"
        $str3 = "name=diamorphine"
        $license1 = "license=Dual BSD/GPL"
        $license2 = "license=GPL"
    condition:
        2 of ($str*) and 1 of ($license*)
}

rule Linux_Rootkit_Diamorphine_66eb93c7 {
    meta:
        author = "Elastic Security"
        id = "66eb93c7-3f26-43ce-b43e-550c6fd44927"
        fingerprint = "e045a6f3359443a11fa609eefedb0aa92f035e91e087e3472461c10bb28f0cc1"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Diamorphine"
        reference_sample = "01fb490fbe2c2b5368cc227abd97e011e83b5e99bb80945ef599fc80e85f8545"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $rk1 = "sys_call_table"
        $rk2 = "kallsyms_lookup_name"
        $rk3 = "retpoline=Y"
        $func1 = "get_syscall_table_bf"
        $func2 = "is_invisible"
        $func3 = "hacked_getdents64"
        $func4 = "orig_getdents64"
        $func5 = "give_root"
        $func6 = "module_show"
        $func7 = "module_hide"
        $func8 = "hacked_kill"
        $func9 = "write_cr0_forced"
    condition:
        1 of ($rk*) and 3 of ($func*)
}



// from Linux_Rootkit_Fontonlake.yar
rule Linux_Rootkit_Fontonlake_8fa41f5e {
    meta:
        author = "Elastic Security"
        id = "8fa41f5e-d03d-4647-86fb-335e056c1c0d"
        fingerprint = "187aae8e659061a06b44e0d353e35e22ada9076c78d8a7e4493e1e4cc600bc9d"
        creation_date = "2021-10-12"
        last_modified = "2022-01-26"
        threat_name = "Linux.Rootkit.Fontonlake"
        reference_sample = "826222d399e2fb17ae6bc6a4e1493003881b1406154c4b817f0216249d04a234"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "kernel_write" fullword
        $a2 = "/proc/.dot3" fullword
        $a3 = "hide_pid" fullword
        $h2 = "s_hide_pids" fullword
        $h3 = "s_hide_tcp4_ports" fullword
        $h4 = "s_hide_strs" fullword
        $tmp1 = "/tmp/.tmH" fullword
        $tmp2 = "/tmp/.tmp_" fullword
    condition:
        (all of ($a*) and 1 of ($tmp*)) or (all of ($h*))
}



// from Linux_Rootkit_Generic.yar
rule Linux_Rootkit_Generic_61229bdf {
    meta:
        author = "Elastic Security"
        id = "61229bdf-0b78-48b1-8a4d-09836dd2bcac"
        fingerprint = "8180ee7a04fd5ba23700e77ad3be7f30d592e77cffa8ebee8de7094627446335"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "dropshell"
        $str2 = "fake_account_user_time"
        $str3 = "fake_bpf_trace_printk"
        $str4 = "fake_crash_kexec"
        $str5 = "fake_loadavg_proc_show"
        $str6 = "fake_sched_debug_show"
        $str7 = "fake_seq_show_ipv4_tcp"
        $str8 = "fake_seq_show_ipv4_udp"
        $str9 = "fake_seq_show_ipv6_tcp"
        $str10 = "fake_seq_show_ipv6_udp"
        $str11 = "fake_trace_printk"
        $str12 = "give_root"
        $str13 = "hack_getdents"
        $str14 = "hacked_getdents64"
        $str15 = "hacked_kill"
        $str16 = "hideModule"
        $str17 = "hide_module"
        $str18 = "hide_tcp4_port"
        $str19 = "hide_tcp6_port"
        $str20 = "hidden_tcp4_ports"
        $str21 = "hidden_tcp6_ports"
        $str22 = "hidden_udp4_ports"
        $str23 = "hidden_udp6_ports"
        $str24 = "hook_getdents"
        $str25 = "hook_kill"
        $str26 = "hook_local_in_func"
        $str27 = "hook_local_out_func"
        $str28 = "hook_tcp4_seq_show"
        $str29 = "hook_tcp6_seq_show"
        $str30 = "hooked_tcp6_seq_show"
        $str31 = "hooked_udp4_seq_show"
        $str32 = "hooked_udp6_seq_show"
        $str33 = "is_invisible"
        $str34 = "module_hide"
        $str35 = "module_show"
        $str36 = "nf_inet_hooks"
        $str37 = "old_access"
        $str38 = "old_fopen"
        $str39 = "old_lxstat"
        $str40 = "old_open"
        $str41 = "old_opendir"
        $str42 = "old_readdir"
        $str43 = "old_rmdir"
        $str44 = "old_unlink"
        $str45 = "old_xstat"
        $str46 = "orig_getdents"
        $str47 = "orig_getdents64"
        $str48 = "orig_kill"
        $str49 = "orig_tcp4_seq_show"
        $str50 = "orig_tcp6_seq_show"
        $str51 = "secret_connection"
        $str52 = "unhide_file"
        $str53 = "unhide_proc"
        $str54 = "unhide_tcp4_port"
        $str55 = "unhide_tcp6_port"
        $str56 = "unhide_udp4_port"
        $str57 = "unhide_udp6_port"
    condition:
        4 of ($str*)
}

rule Linux_Rootkit_Generic_482bca48 {
    meta:
        author = "Elastic Security"
        id = "482bca48-c337-45d9-9513-301909cbda73"
        fingerprint = "a2a005777e1bc236a30f3efff8d85af360665bd9418b77aa8d0aaf72a72df88a"
        creation_date = "2024-11-14"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "sys_call_table"
        $str2 = "kallsyms_lookup_name"
        $str3 = "retpoline=Y"
        $str4 = "kprobe"
        $rk1 = "rootkit"
        $rk2 = "hide_"
        $rk3 = "hacked_"
        $rk4 = "fake_"
        $rk5 = "hooked_"
        $hook1 = "_getdents"
        $hook2 = "_kill"
        $hook3 = "_seq_show_ipv4_tcp"
        $hook4 = "_seq_show_ipv4_udp"
        $hook5 = "_seq_show_ipv6_tcp"
        $hook6 = "_seq_show_ipv6_udp"
        $hook7 = "_tcp4_port"
        $hook8 = "_tcp4_seq_show"
        $hook9 = "_tcp6_port"
        $hook10 = "_tcp6_seq_show"
        $hook11 = "_udp4_port"
        $hook12 = "_udp4_seq_show"
        $hook13 = "_udp6_port"
        $hook14 = "_udp6_seq_show"
        $hook15 = "_unlink"
    condition:
        3 of ($str*) and ((all of ($rk*)) or (3 of ($rk*) and 5 of ($hook*)))
}

rule Linux_Rootkit_Generic_d0c5cfe0 {
    meta:
        author = "Elastic Security"
        id = "d0c5cfe0-850b-432c-924d-547252ca0dd0"
        fingerprint = "6c005d7126485220c8ea1a7fb2a3215ade16f1b9dda7b89daf7a8cc408288efa"
        creation_date = "2024-11-14"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "sys_call_table"
        $str2 = "kallsyms_lookup_name"
        $str3 = "retpoline=Y"
        $str4 = "kprobe"
        $init1 = "init_module"
        $init2 = "finit_module"
        $hook1 = "getdents"
        $hook2 = "seq_show_ipv4_tcp"
        $hook3 = "seq_show_ipv4_udp"
        $hook4 = "seq_show_ipv6_tcp"
        $hook5 = "seq_show_ipv6_udp"
        $hook6 = "sys_kill"
        $hook7 = "tcp4_port"
        $hook8 = "tcp4_seq_show"
        $hook9 = "tcp6_port"
        $hook10 = "tcp6_seq_show"
        $hook11 = "udp4_port"
        $hook12 = "udp4_seq_show"
        $hook13 = "udp6_port"
        $hook14 = "udp6_seq_show"
        $rk1 = "rootkit"
        $rk2 = "dropper"
        $rk3 = "hide"
        $rk4 = "hook"
        $rk5 = "hacked"
    condition:
        2 of ($str*) and 1 of ($init*) and 3 of ($hook*) and 3 of ($rk*)
}

rule Linux_Rootkit_Generic_f07bcabe {
    meta:
        author = "Elastic Security"
        id = "f07bcabe-f91e-4872-8677-dee6307e79d0"
        fingerprint = "7335426e705383ff6f62299943a139390b83ce2af4cbfc145cfe78c0f0015a26"
        creation_date = "2024-12-02"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "fh_install_hook"
        $str2 = "fh_remove_hook"
        $str3 = "fh_resolve_hook_address"
    condition:
        2 of them
}



// from Linux_Rootkit_HiddenWasp.yar
rule Linux_Rootkit_HiddenWasp_8408057b {
    meta:
        author = "Elastic Security"
        id = "8408057b-4cfa-4712-b69a-201561690c2d"
        fingerprint = "18171748d498def35fd97e342785ee13e02b0ff926defc50705d56372b62b5f2"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.HiddenWasp"
        reference_sample = "7c5e20872bc0ac5cce83d4c68485743cd16a818cd1e495f97438caad0399c847"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "HIDE_THIS_SHELL"
        $str2 = "I_AM_HIDDEN"
        $func1 = "hiding_hideproc"
        $func2 = "hiding_unhidefile"
        $func3 = "hiding_hidefile"
        $func4 = "hiding_unhideproc"
        $func5 = "/proc/hide-%d"
        $func6 = "hiding_disable_logging"
        $func7 = "hiding_init"
        $func8 = "hiding_uninstall"
        $func9 = "hiding_removeproc"
        $func10 = "hiding_makeroot"
        $func11 = "hiding_free"
        $func12 = "hiding_enable_logging"
        $func13 = "hiding_getvers"
        $func14 = "hidden_services"
    condition:
        all of ($str*) or 5 of ($func*)
}



// from Linux_Rootkit_Jynx.yar
rule Linux_Rootkit_Jynx_c470eaff {
    meta:
        author = "Elastic Security"
        id = "c470eaff-20f2-430f-988f-15a4b7bd75f8"
        fingerprint = "337087ba691d4f535e7ee160efb60ca5b71c79504297f6e711bcaf058fdb7a36"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Jynx"
        reference_sample = "79c2ae1a95b44f3df42d669cb44db606d2088c5c393e7de5af875f255865ecb4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $hook1 = "old_access"
        $hook2 = "old_lxstat"
        $hook3 = "old_open"
        $hook4 = "old_rmdir"
        $hook5 = "old_unlink"
        $hook6 = "old_xstat"
        $hook7 = "old_fopen"
        $hook8 = "old_opendir"
        $hook9 = "old_readdir"
        $hook10 = "forge_proc_net_tcp"
        $hook11 = "forge_proc_cpu"
    condition:
        4 of ($hook*)
}



// from Linux_Rootkit_Kovid.yar
rule Linux_Rootkit_Kovid_b77dc7f4 {
    meta:
        author = "Elastic Security"
        id = "b77dc7f4-fef1-4256-ac34-677ad1c5b618"
        fingerprint = "29ae4fc448eb746b7d6ec192befd03977e83a1ad5b4d1369621d6d42b482ae50"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Kovid"
        reference_sample = "933273ff95a57dfe0162175dc6143395e23c69e36d8ca366481b795deaab4fd0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "name=kovid"
        $str2 = "kovid.ko"
        $str3 = "dontblink"
        $str4 = "author=whatever coorp"
        $str5 = "Your module 'unhide' magic word is: '%s'"
        $str6 = ".sshd_orig"
        $str7 = ".lm.sh"
        $str8 = ".kv.ko"
        $str9 = "whitenose"
        $str10 = "pinknose"
        $str11 = "rednose"
        $str12 = "blacknose"
        $str13 = "greynose"
        $str14 = "purplenose"
        $str15 = "fh_remove_hook"
        $str16 = "backdoor can only be unhidden either by exit or rmmod: %d"
        $str17 = "get_unhide_magic_word"
        $str18 = "invalid data: syscall hook setreuid will not work"
        $str19 = "Fuck-off"
        $str20 = "/KoviD/src/sys.c"
        $func1 = "kv_find_hidden_task"
        $func2 = "kv_for_each_hidden_backdoor_data"
        $func3 = "kv_bd_search_iph_source"
        $func4 = "kv_check_cursing"
        $func5 = "kv_for_each_hidden_backdoor_task"
        $func6 = "kv_find_hidden_pid"
        $func7 = "kv_hide_task_by_pid"
        $func8 = "kv_unhide_task_by_pid_exit_group"
        $func9 = "kv_util_random_AZ_string"
    condition:
        4 of ($str*) or 4 of ($func*)
}



// from Linux_Rootkit_Melofee.yar
rule Linux_Rootkit_Melofee_25d42bdd {
    meta:
        author = "Elastic Security"
        id = "25d42bdd-f6ee-458c-a102-7123225f0be2"
        fingerprint = "964cf1d468b829064c681c6b22bce00c4ef3536243fc5d1bac16879e0b68d9b2"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Melofee"
        reference_sample = "5830862707711a032728dfa6a85c904020766fa316ea85b3eef9c017f0e898cc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "hide_proc"
        $str2 = "find_hide_name"
        $str3 = "hide_module"
        $str4 = "unhide_chdir"
        $str5 = "hide_content"
        $str6 = "hidden_chdirs"
        $str7 = "hidden_tcp_conn"
        $str8 = "HIDETAGOUT"
        $str9 = "HIDETAGIN"
    condition:
        4 of them
}



// from Linux_Rootkit_Mobkit.yar
rule Linux_Rootkit_Mobkit_335e48bc {
    meta:
        author = "Elastic Security"
        id = "335e48bc-03e2-486e-a8e8-bcf1aaf9302d"
        fingerprint = "226fbd5530634622c2fb8d9e08d29d184c5c01aea6140e08b8be2f11b78b34b6"
        creation_date = "2025-03-11"
        last_modified = "2025-03-19"
        threat_name = "Linux.Rootkit.Mobkit"
        reference_sample = "aa62bbf83a54b5c908609e69cfee37dfeb9c5f2f75529f2d1009a6dba9e87b9f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $meta1 = "name=mob"
        $meta2 = "author=shv-om"
        $meta3 = "description=MobKit"
        $meta4 = "license=GPL"
        $hook1 = "real_kallsyms_lookup_name"
        $hook2 = "unregister_kprobe"
        $hook3 = "ftrace_set_filter_ip"
        $hook4 = "unregister_ftrace_function"
        $hook5 = "orig_kill"
        $hook6 = "call_usermodehelper"
        $str1 = "mob.mod.c"
        $str2 = "mob_drivers"
        $str3 = "mob: Prevented direct recursion via parent_ip check"
        $str4 = "mob: Hooking %s at address: %px with handler %px"
        $str5 = "mob: [INFO] Module unloaded -> Work Queue Destroyed"
    condition:
        (3 of ($meta*)) or (4 of ($str*)) or (all of ($hook*)) or ((3 of ($hook*) and 3 of ($str*)))
}



// from Linux_Rootkit_Perfctl.yar
rule Linux_Rootkit_Perfctl_ce456896 {
    meta:
        author = "Elastic Security"
        id = "ce456896-1a13-4e31-8913-55f5b49badcb"
        fingerprint = "feda52cd93fa66194b030d5cb759ceef9b97073bb765349e8f06af6f37b547bc"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Perfctl"
        reference_sample = "69de4c062eebb13bf2ee3ee0febfd4a621f2a17c3048416d897aecf14503213a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 01 D0 48 89 45 F0 48 8B 45 F0 48 89 C6 48 C7 C7 FF FF FF FF }
        $a2 = { BF 5E F8 00 00 E8 ?? ?? FF FF 66 89 85 52 FF FF FF BF 01 00 00 7F E8 ?? ?? FF FF 89 85 54 FF FF FF }
        $str1 = "r;rr" wide
        $str2 = { 0D 0A 25 73 0D 0A }
        $str3 = "rrr01" wide
    condition:
        any of ($a*) or 2 of ($str*)
}



// from Linux_Rootkit_Reptile.yar
rule Linux_Rootkit_Reptile_b2ccf852 {
    meta:
        author = "Elastic Security"
        id = "b2ccf852-1b85-4fe1-b0a7-7d39f91fee1b"
        fingerprint = "77d591ebe07ffe1eada48b3c071b1c7c21f6cc16f15eb117e7bbd8fd256e9726"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $func1 = "reptile_shell"
        $func2 = "reptile_start"
        $func3 = "reptile_module"
        $func4 = "reptile_init"
        $func5 = "reptile_exit"
    condition:
        2 of ($func*)
}

rule Linux_Rootkit_Reptile_c9f8806d {
    meta:
        author = "Elastic Security"
        id = "c9f8806d-102a-41d6-82bb-a2a136f51e67"
        fingerprint = "765329c644a95224493dcef81186504013ee5c1cda0860e4f5b31eab9857623f"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "parasite_loader"
        $str2 = "parasite_loader/encrypt"
        $str3 = "kmatryoshka.c"
        $str4 = "parasite_loader.mod.c"
        $str5 = "reptile.mod.c"
        $str6 = "parasite_blob"
        $str7 = "name=reptile"
        $loader1 = "loader.c"
        $loader2 = "custom_rol32"
        $loader3 = "do_encode"
        $blob = "_blob"
    condition:
        ((3 of ($str*)) or (all of ($loader*))) and $blob
}

rule Linux_Rootkit_Reptile_eb201301 {
    meta:
        author = "Elastic Security"
        id = "eb201301-b10b-4c88-ae45-6cceb2f6ef6e"
        fingerprint = "7f1948a9e08c3ad9db3492112590bf5f10eb7b992fe3ab5cc5fc52bf81897378"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "Reptile Packet Sender"
        $str2 = "Written by F0rb1dd3n"
        $str3 = "Reptile Wins"
        $str4 = "Written by: F0rb1dd3n"
        $opt1 = "-r Remote port from magic packets (only for tcp/udp)"
        $opt2 = "-x Magic Packet protocol (tcp/icmp/udp)"
        $opt3 = "-s Source IP address to spoof"
        $opt4 = "-q Source port from magic packets (only for tcp/udp)"
        $opt5 = "-l Host to receive the reverse shell"
        $opt6 = "-p Host port to receive the reverse shell"
        $opt7 = "-k Token to trigger the port-knocking"
        $help1 = "Run the listener and send the magic packet"
        $help2 = "Local host to receive the shell"
        $help3 = "Local port to receive the shell"
        $help4 = "Source host on magic packets (spoof)"
        $help5 = "Source port on magic packets (only for TCP/UDP)"
        $help6 = "Remote port (only for TCP/UDP)"
        $help7 = "Protocol to send magic packet (ICMP/TCP/UDP)"
        $rep1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]"
        $rep2 = "S3cr3tP@ss"
    condition:
        all of ($rep*) or (1 of ($str*) and (4 of ($opt*) or 4 of ($help*)))
}

rule Linux_Rootkit_Reptile_85abf958 {
    meta:
        author = "Elastic Security"
        id = "85abf958-1c81-4b65-ae5c-49f3e5137f07"
        fingerprint = "db0f0398bb25e96f2b46d3836fbcc056dc3ac90cfbe6ba6318fd6fa48315432b"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $byte1 = { C7 06 65 78 65 63 C7 46 04 20 62 61 73 C7 46 08 68 20 2D 2D C7 46 0C 72 63 66 69 C7 46 10 6C 65 20 00 }
        $byte2 = { C7 07 59 6F 75 20 C7 47 04 61 72 65 20 C7 47 08 61 6C 72 65 C7 47 0C 61 64 79 20 C7 47 10 72 6F 6F 74 C7 47 14 21 20 3A 29 C7 47 18 0A 0A 00 00 }
        $byte3 = { C7 47 08 59 6F 75 20 C7 47 0C 68 61 76 65 C7 47 10 20 6E 6F 20 C7 47 14 70 6F 77 65 C7 47 18 72 20 68 65 C7 47 1C 72 65 21 20 C7 47 20 3A 28 20 1B }
        $byte4 = { C7 47 08 59 6F 75 20 C7 47 0C 67 6F 74 20 C7 47 10 73 75 70 65 C7 47 14 72 20 70 6F C7 47 18 77 65 72 73 C7 47 1C 21 1B 5B 30 C7 47 20 30 6D 0A 0A }
        $byte5 = { C7 06 66 69 6C 65 C7 46 04 2D 74 61 6D C7 46 08 70 65 72 69 C7 46 0C 6E 67 00 00 }
        $str1 = "reptile"
        $str2 = "exec bash --rcfi"
    condition:
        any of ($byte*) or all of ($str*)
}



// from Linux_Rootkit_Snapekit.yar
rule Linux_Rootkit_Snapekit_01205a75 {
    meta:
        author = "Elastic Security"
        id = "01205a75-f40a-4f01-9519-19b801ec2aef"
        fingerprint = "9316cdd987f5d13fc73707d508fab08cad5d47a4d8346ba0c364514cab146d11"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Snapekit"
        reference_sample = "58d1e56fff04affb4c8cbb5fc3ea848e88d1f05c07e6f730e1cf17100ef1b666"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "author=Humzak711"
        $str2 = "name=snapekit"
        $str3 = "description=snapekit"
        $str4 = "license=GPL"
        $str5 = "snapekit"
        $func1 = "snapekit_filepath"
        $func2 = "additional_hidden_filepaths"
        $func3 = "snapekit_persistence_config_files"
        $func4 = "snapekit_persistence_config_dirs"
        $func5 = "snapekit_C2_ips_ipv4"
        $func6 = "snapekit_C2_ips_ipv6"
        $func7 = "unpack_rootkit"
        $hook1 = "getdents64_snape"
        $hook2 = "kill_snape"
        $hook3 = "load_userspace_payload"
        $hook4 = "lstat_snape"
        $hook5 = "open_snape"
        $hook6 = "openat2_snape"
        $hook7 = "openat_snape"
        $hook8 = "pread64_snape"
        $hook9 = "ptrace_snape"
        $hook10 = "pwrite64_snape"
        $hook11 = "read_snape"
        $hook12 = "stat_snape"
        $hook13 = "statfs_snape"
        $hook14 = "statx_snape"
        $hook15 = "tcp4_seq_show_snape"
        $hook16 = "tcp6_seq_show_snape"
        $hook17 = "udp4_seq_show_snape"
        $hook18 = "udp6_seq_show_snape"
        $hook19 = "unhook_kernelAPI"
        $hook20 = "unlink_snape"
        $hook21 = "unlinkat_snape"
        $hook22 = "write_snape"
        $hook23 = "sys_call_table_snape"
        $hook24 = "hooked_tcp6_seq_show"
        $hook25 = "hooked_udp4_seq_show"
        $hook26 = "hooked_udp6_seq_show"
    condition:
        3 of ($str*) or 3 of ($func*) or 5 of ($hook*)
}



// from Linux_Rootkit_Suterusu.yar
rule Linux_Rootkit_Suterusu_94667bf2 {
    meta:
        author = "Elastic Security"
        id = "94667bf2-7875-40c1-85fe-4b3421f3dc73"
        fingerprint = "e3b93c3a0ba94b657d71843eff9eef174f7a11abc4f43925ec70b844bc9b951f"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Suterusu"
        reference_sample = "753fd579a684e09a70ae0fd147441c45d24a5acae94a78a92e393058c3b69506"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "Hiding PID %hu"
        $str2 = "Unhiding PID %hu"
        $str3 = "Hiding TCPv4 port %hu"
        $str4 = "Unhiding TCPv4 port %hu"
        $str5 = "Hiding TCPv6 port %hu"
        $str6 = "Unhiding TCPv6 port %hu"
        $str7 = "Hiding UDPv4 port %hu"
        $str8 = "Unhiding UDPv4 port %hu"
        $str9 = "Hiding UDPv6 port %hu"
        $str10 = "Unhiding UDPv6 port %hu"
        $str11 = "Hiding file/dir %s"
        $str12 = "Unhiding file/dir %s"
        $func1 = "hide_promisc"
        $func2 = "hidden_tcp6_ports"
        $func3 = "hide_udp4_port"
        $func4 = "unhide_udp6_port"
        $func5 = "hide_tcp4_port"
        $func6 = "hide_tcp6_port"
        $func7 = "hidden_udp4_ports"
        $func8 = "unhide_tcp4_port"
        $func9 = "unhide_file"
        $func10 = "hijack_stop"
        $func11 = "hooked_syms"
        $func12 = "hidden_tcp4_ports"
        $func13 = "unhide_proc"
        $func14 = "unhide_udp4_port"
        $func15 = "unhide_tcp6_port"
        $func16 = "hidden_udp6_ports"
        $func17 = "hijack_pause"
        $func18 = "hijack_start"
        $menu1 = "Hide process with pid [ARG]"
        $menu2 = "Unhide process with pid [ARG]"
        $menu3 = "Hide TCP 4 port [ARG]"
        $menu4 = "Unhide TCP 4 port [ARG]"
        $menu5 = "Hide UDPv4 port [ARG]"
        $menu6 = "Unhide UDPv4 port [ARG]"
        $menu7 = "Hide TCPv6 port [ARG]"
        $menu8 = "Unhide TCPv6 port [ARG]"
        $menu9 = "Hide UDPv4 port [ARG]"
        $menu10 = "Unhide UDPv6 port [ARG]"
        $menu11 = "Hide file/directory named [ARG]"
        $menu12 = "Unhide file/directory named [ARG]"
    condition:
        4 of ($str*) or 6 of ($func*) or 4 of ($menu*)
}



// from Linux_Shellcode_Generic.yar
rule Linux_Shellcode_Generic_5669055f {
    meta:
        author = "Elastic Security"
        id = "5669055f-8ce7-4163-af06-cb265fde3eef"
        fingerprint = "616fe440ff330a1d22cacbdc2592c99328ea028700447724d2d5b930554a22f4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "87ef4def16d956cdfecaea899cbb55ff59a6739bbb438bf44a8b5fec7fcfd85b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 51 B1 06 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_d2c96b1d {
    meta:
        author = "Elastic Security"
        id = "d2c96b1d-f424-476c-9463-dd34a1da524e"
        fingerprint = "ee042895d863310ff493fdd33721571edd322e764a735381d236b2c0a7077cfa"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "403d53a65bd77856f7c565307af5003b07413f2aba50869655cdd88ce15b0c82"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E1 8D 54 24 04 5B B0 0B CD 80 31 C0 B0 01 31 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_30c70926 {
    meta:
        author = "Elastic Security"
        id = "30c70926-9414-499a-a4db-7c3bb902dd82"
        fingerprint = "4af586211c56e92b1c60fcd09b4def9801086fbe633418459dc07839fe9c735a"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "a742e23f26726293b1bff3db72864471d6bb4062db1cc6e1c4241f51ec0e21b1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 52 53 89 E1 31 C0 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_224bdcc4 {
    meta:
        author = "Elastic Security"
        id = "224bdcc4-4b38-44b5-96c6-d3b378628fa4"
        fingerprint = "e23b239775c321d4326eff2a7edf0787116dd6d8a9e279657e4b2b01b33e72aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "bd22648babbee04555cef52bfe3e0285d33852e85d254b8ebc847e4e841b447e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E6 6A 10 5A 6A 2A 58 0F 05 48 85 C0 79 1B 49 FF C9 74 22 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_99b991cd {
    meta:
        author = "Elastic Security"
        id = "99b991cd-a5ca-475c-8c10-e43b9d22d26e"
        fingerprint = "ed904a3214ccf43482e3ddf75f3683fea45f7c43a2f1860bac427d7d15d8c399"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "954b5a073ce99075b60beec72936975e48787bea936b4c5f13e254496a20d81d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 89 E3 50 53 89 E1 B0 0B CD 80 00 4C 65 6E 67 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_24b9aa12 {
    meta:
        author = "Elastic Security"
        id = "24b9aa12-92b2-492d-9a0e-078cdab5830a"
        fingerprint = "0ded0ad2fdfff464bf9a0b5a59b8edfe1151a513203386daae6f9f166fd48e5c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "24b2c1ccbbbe135d40597fbd23f7951d93260d0039e0281919de60fa74eb5977"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 89 E3 89 C1 89 C2 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_8ac37612 {
    meta:
        author = "Elastic Security"
        id = "8ac37612-aec8-4376-8269-2594152ced8a"
        fingerprint = "97a3d3e7ff4c9ae31f71e609d10b3b848cb0390ae2d1d738ef53fd23ff0621bc"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "c199b902fa4b0fcf54dc6bf3e25ad16c12f862b47e055863a5e9e1f98c6bd6ca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E3 ?? 53 89 E1 B0 0B CD 80 00 47 43 43 3A }
    condition:
        all of them
}

rule Linux_Shellcode_Generic_932ed0f0 {
    meta:
        author = "Elastic Security"
        id = "932ed0f0-bd43-4367-bcc3-ecd8f65b52ee"
        fingerprint = "7aa4619d2629b5d795e675d17a6e962c6d66a75e11fa884c0b195cb566090070"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Shellcode.Generic"
        reference_sample = "f357597f718f86258e7a640250f2e9cf1c3363ab5af8ddbbabb10ebfa3c91251"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 50 89 E2 53 89 E1 B0 0B CD 80 31 C0 40 CD 80 }
    condition:
        all of them
}



// from Linux_Trojan_Adlibrary.yar
rule Linux_Trojan_Adlibrary_2e908e5f {
    meta:
        author = "Elastic Security"
        id = "2e908e5f-f79e-491f-8959-86b7cffd35c0"
        fingerprint = "27ea79ad607f0dbd3d7892e27be9c142b0ac3a2b56f952f58663ff1fe68d6c88"
        creation_date = "2022-08-23"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Adlibrary"
        reference_sample = "acb22b88ecfb31664dc07b2cb3490b78d949cd35a67f3fdcd65b1a4335f728f1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 32 04 39 83 C7 01 0F BE C0 89 04 24 E8 ?? ?? ?? ?? 3B 7C 24 ?? B8 00 00 00 00 0F 44 F8 83 C5 01 81 FD }
    condition:
        all of them
}



// from Linux_Trojan_Asacub.yar
rule Linux_Trojan_Asacub_d3c4aa41 {
    meta:
        author = "Elastic Security"
        id = "d3c4aa41-faae-4c85-bdc5-9e09483e92fb"
        fingerprint = "4961023c719599bd8da6b8a17dbe409911334c21b45d62385dd02a6dd35fd2be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Asacub"
        reference_sample = "15044273a506f825859e287689a57c6249b01bb0a848f113c946056163b7e5f1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 8B 0F 83 EC 08 50 57 FF 51 54 83 C4 10 8B 8B DC FF FF FF 89 4C }
    condition:
        all of them
}



// from Linux_Trojan_Autocolor.yar
rule Linux_Trojan_Autocolor_18203450 {
    meta:
        author = "Elastic Security"
        id = "18203450-339b-4f21-8f22-72fdc6fa02da"
        fingerprint = "0aa1c8156590617aa60e855be214c443ac9c0dc7633950b206fc8f2ab2d3d86a"
        creation_date = "2025-03-11"
        last_modified = "2025-03-19"
        threat_name = "Linux.Trojan.Autocolor"
        reference_sample = "a492f6d4183a8809c69e415be5d241f227f6b6a56e0ab43738fd36e435116aa0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "auto-color"
        $str2 = "/var/log/cross"
        $str3 = "/tmp/cross"
        $str4 = "/proc/self/fd/%d"
        $str5 = "/www/wwwlogs/%s"
        $str6 = "/door-%d.log"
        $str7 = "/etc/ld.so.preload.real"
        $str8 = "ad.real"
        $str9 = "/tmp/config-err-"
    condition:
        5 of ($str*)
}



// from Linux_Trojan_Azeela.yar
rule Linux_Trojan_Azeela_aad9d6cc {
    meta:
        author = "Elastic Security"
        id = "aad9d6cc-32ff-431a-9914-01c7adc80877"
        fingerprint = "437bfcae2916ad88d4f03f3ca5378df1ac1cac624b0aabc1be13f64aa9c26560"
        creation_date = "2021-01-12"
        last_modified = "2024-11-22"
        threat_name = "Linux.Trojan.Azeela"
        reference_sample = "6c476a7457ae07eca3d3d19eda6bb6b6b3fa61fa72722958b5a77caff899aaa6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { C0 74 07 B8 01 00 00 00 EB 31 48 8B 45 F8 0F B6 00 3C FF 74 21 48 83 45 }
        $a2 = "The whole earth has been corrupted through the works that were taught by Azazel: to him ascribe all sin."
    condition:
        any of ($a*)
}



// from Linux_Trojan_Backconnect.yar
rule Linux_Trojan_Backconnect_c6803b39 {
    meta:
        author = "Elastic Security"
        id = "c6803b39-e2e0-4ab8-9ead-e53eab26bb53"
        fingerprint = "1dfb097c90b0cf008dc9d3ae624e08504755222f68ee23ed98d0fa8803cff91a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Backconnect"
        reference_sample = "a5e6b084cdabe9a4557b5ff8b2313db6c3bb4ba424d107474024030115eeaa0f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 3A 48 98 48 01 C3 49 01 C5 48 83 FB 33 76 DC 31 C9 BA 10 00 }
    condition:
        all of them
}



// from Linux_Trojan_Backegmm.yar
rule Linux_Trojan_Backegmm_b59712e6 {
    meta:
        author = "Elastic Security"
        id = "b59712e6-d14d-4a57-a3d6-2dc323bf840d"
        fingerprint = "61b2f0c7cb98439b05776edeaf06b114d364119ebe733d924158792110c5e21c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Backegmm"
        reference_sample = "d6c8e15cb65102b442b7ee42186c58fa69cd0cb68f4fd47eb5ad23763371e0be"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 73 74 65 6E 00 66 6F 72 6B 00 73 70 72 69 6E 74 66 00 68 }
    condition:
        all of them
}



// from Linux_Trojan_Badbee.yar
rule Linux_Trojan_Badbee_231cb054 {
    meta:
        author = "Elastic Security"
        id = "231cb054-36a9-434f-8254-17fee38e5275"
        fingerprint = "ebe789fc467daf9276f72210f94e87b7fa79fc92a72740de49e47b71f123ed5c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Badbee"
        reference_sample = "832ba859c3030e58b94398ff663ddfe27078946a83dcfc81a5ef88351d41f4e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D B4 41 31 44 97 10 83 F9 10 75 E4 89 DE C1 FE 14 F7 C6 01 00 }
    condition:
        all of them
}



// from Linux_Trojan_Banload.yar
rule Linux_Trojan_Banload_d5e1c189 {
    meta:
        author = "Elastic Security"
        id = "d5e1c189-7d19-4f03-a4f3-a0aaf6d499dc"
        fingerprint = "4aa04f08005b1b7ed941dbfc563737728099e35e3f0f025532921b91b79c967c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Banload"
        reference_sample = "48bf0403f777db5da9c6a7eada17ad4ddf471bd73ea6cf02817dd202b49204f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 E4 E4 58 88 60 90 E4 E4 E4 E4 68 98 70 A0 E4 E4 E4 E4 78 }
    condition:
        all of them
}



// from Linux_Trojan_Bedevil.yar
rule Linux_Trojan_Bedevil_a1a72c39 {
    meta:
        author = "Elastic Security"
        id = "a1a72c39-c8a3-4372-bd1d-de6360c9c19e"
        fingerprint = "ea4762d6ba0b88017feda1ed68d70bedd1438bb853b8ee1f83cbca2276bfbd1e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Bedevil"
        reference_sample = "017a9d7290cf327444d23227518ab612111ca148da7225e64a9f6ebd253449ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 3A 20 1B 5B 31 3B 33 31 6D 25 64 1B 5B 30 6D 0A 00 1B 5B }
    condition:
        all of them
}



// from Linux_Trojan_Bish.yar
rule Linux_Trojan_Bish_974b4b47 {
    meta:
        author = "Elastic Security"
        id = "974b4b47-38cf-4460-8ff3-e066e5c8a5fc"
        fingerprint = "8858f99934e367b7489d60bfaa74ab57e2ae507a8c06fb29693197792f6f5069"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Bish"
        reference_sample = "9171fd2bbe182f0a3cd35937f3ee0076c9358f52f5bc047498dd9e233ae11757"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 50 68 6E }
    condition:
        all of them
}



// from Linux_Trojan_Bluez.yar
rule Linux_Trojan_Bluez_50e87fa9 {
    meta:
        author = "Elastic Security"
        id = "50e87fa9-f053-4507-ae10-b5d33b693bb3"
        fingerprint = "67855d65973d0bbdad90299f1432e7f0b4b8b1e6dfd0737ee5bee89161f2a890"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Bluez"
        reference = "1e526b6e3be273489afa8f0a3d50be233b97dc07f85815cc2231a87f5a651ef1"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 63 68 72 00 6B 69 6C 6C 00 73 74 72 6C 65 6E 00 62 69 6E 64 00 }
    condition:
        all of them
}



// from Linux_Trojan_BPFDoor.yar
rule Linux_Trojan_BPFDoor_59e029c3 {
    meta:
        author = "Elastic Security"
        id = "59e029c3-a57c-44ad-a554-432efc6b591a"
        fingerprint = "cc9b75b1f1230e3e2ed289ef5b8fa2deec51197e270ec5d64ff73722c43bb4e8"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii fullword
        $a3 = "avahi-daemon: chroot helper" ascii fullword
        $a4 = "/sbin/mingetty /dev/tty6" ascii fullword
        $a5 = "ttcompat" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_0f768f60 {
    meta:
        author = "Elastic Security"
        id = "0f768f60-1d6c-4af9-8ae3-c1c8fbbd32f4"
        fingerprint = "55097020a70d792e480542da40b91fd9ab0cc23f8736427f398998962e22348e"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "3a1b174f0c19c28f71e1babde01982c56d38d3672ea14d47c35ae3062e49b155"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/mingetty /dev/tty7" ascii fullword
        $a3 = "pickup -l -t fifo -u" ascii fullword
        $a4 = "kdmtmpflush" ascii fullword
        $a5 = "avahi-daemon: chroot helper" ascii fullword
        $a6 = "/sbin/auditd -n" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_8453771b {
    meta:
        author = "Elastic Security"
        id = "8453771b-a78f-439d-be36-60439051586a"
        fingerprint = "b9d07bda8909e7afb1a1411a3bad1e6cffec4a81eb47d42f2292a2c4c0d97fa7"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[-] Spawn shell failed." ascii fullword
        $a2 = "[+] Packet Successfuly Sending %d Size." ascii fullword
        $a3 = "[+] Monitor packet send." ascii fullword
        $a4 = "[+] Using port %d"
        $a5 = "decrypt_ctx" ascii fullword
        $a6 = "getshell" ascii fullword
        $a7 = "getpassw" ascii fullword
        $a8 = "export %s=%s" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_f690fe3b {
    meta:
        author = "Elastic Security"
        id = "f690fe3b-1b3f-4101-931b-10932596f546"
        fingerprint = "504bfe57dcc3689881bdd0af55aab9a28dcd98e44b5a9255d2c60d9bc021130b"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 45 D8 0F B6 10 0F B6 45 FF 48 03 45 F0 0F B6 00 8D 04 02 00 }
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_1a7d804b {
    meta:
        author = "Elastic Security"
        id = "1a7d804b-9d39-4855-abe9-47b72bd28f07"
        fingerprint = "e7f92df3e3929b8296320300bb341ccc69e00d89e0d503a41190d7c84a29bce2"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "getshell" ascii fullword
        $a2 = "/sbin/agetty --noclear tty1 linux" ascii fullword
        $a3 = "packet_loop" ascii fullword
        $a4 = "godpid" ascii fullword
        $a5 = "ttcompat" ascii fullword
        $a6 = "decrypt_ctx" ascii fullword
        $a7 = "rc4_init" ascii fullword
        $b1 = { D0 48 89 45 F8 48 8B 45 F8 0F B6 40 0C C0 E8 04 0F B6 C0 C1 }
    condition:
        all of ($a*) or 1 of ($b*)
}

rule Linux_Trojan_BPFDoor_e14b0b79 {
    meta:
        author = "Elastic Security"
        id = "e14b0b79-a6f3-4fb3-a314-0ec20dcd242c"
        fingerprint = "1c4cb6c8a255840c5a2cb7674283678686e228dc2f2a9304fa118bb5bdc73968"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "getpassw" ascii fullword
        $a2 = "(udp[8:2]=0x7255) or (icmp[8:2]=0x7255) or (tcp[((tcp[12]&0xf0)>>2):2]=0x5293)" ascii fullword
        $a3 = "/var/run/haldrund.pid" ascii fullword
        $a4 = "Couldn't install filter %s: %s" ascii fullword
        $a5 = "godpid" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_f1cd26ad {
    meta:
        author = "Elastic Security"
        id = "f1cd26ad-dffb-421f-88f1-a812769d70ff"
        fingerprint = "fb70740218e4b06c3f34cef2d3b02e67172900e067723408bcd41d4d6ca7c399"
        creation_date = "2023-05-11"
        last_modified = "2023-05-16"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $magic_bytes_check = { 0F C8 0F CA 3D 9F CD 30 44 ?? ?? ?? ?? ?? ?? 81 FA 66 27 14 5E }
        $seq_binary = { 48 C1 E6 08 48 C1 E0 14 48 01 F0 48 01 C8 89 E9 48 C1 E8 20 29 C1 D1 E9 01 C8 C1 E8 0B 83 C0 01 89 C6 C1 E6 0C }
        $signals_setup = { BE 01 00 00 00 BF 02 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 01 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 03 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 0D 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 16 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 15 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 11 00 00 00 ?? ?? ?? ?? ?? BF 0A 00 00 00 }
    condition:
        ($magic_bytes_check and $seq_binary) or $signals_setup
}



// from Linux_Trojan_Cerbu.yar
rule Linux_Trojan_Cerbu_69d5657e {
    meta:
        author = "Elastic Security"
        id = "69d5657e-1fe9-4367-b478-218c278c7fbc"
        fingerprint = "7dfaebc6934c8fa97509831e0011f2befd0dbc24a68e4a07bc1ee0decae45a42"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Cerbu"
        reference_sample = "f10bf3cf2fdfbd365d3c2d8dedb2d01b85236eaa97d15370dbcb5166149d70e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 5B 5E C9 C3 55 89 E5 83 EC 08 83 C4 FC FF 75 0C 6A 05 FF }
    condition:
        all of them
}



// from Linux_Trojan_Chinaz.yar
rule Linux_Trojan_Chinaz_a2140ca1 {
    meta:
        author = "Elastic Security"
        id = "a2140ca1-0a72-4dcb-bf7c-2f51e84a996b"
        fingerprint = "ac620f3617ea448b2ad62f06490c37200fa0af8a6fe75a6a2a294a7b5b4a634a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Chinaz"
        reference_sample = "7c44c2ca77ef7a62446f6266a757817a6c9af5e010a219a43a1905e2bc5725b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 53 8B 74 24 0C 8B 5C 24 10 8D 74 26 00 89 C2 89 C1 C1 FA 03 83 }
    condition:
        all of them
}



// from Linux_Trojan_Connectback.yar
rule Linux_Trojan_Connectback_bf194c93 {
    meta:
        author = "Elastic Security"
        id = "bf194c93-92d8-4eba-99c4-326a5ea76d0d"
        fingerprint = "6e72b14be0a0a6e42813fa82ee77d057246ccba4774897b38acf2dc30c894023"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Connectback"
        reference_sample = "6784cb86460bddf1226f71f5f5361463cbda487f813d19cd88e8a4a1eb1a417b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B6 0C B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}



// from Linux_Trojan_Ddostf.yar
rule Linux_Trojan_Ddostf_e4874cd4 {
    meta:
        author = "Elastic Security"
        id = "e4874cd4-50e3-4a4c-b14c-976e29aaaaae"
        fingerprint = "dfbf7476794611718a1cd2c837560423e3a6c8b454a5d9eecb9c6f9d31d01889"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 01 8B 45 F0 2B 45 F4 89 C2 8B 45 E4 39 C2 73 82 8B 45 EC }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_32c35334 {
    meta:
        author = "Elastic Security"
        id = "32c35334-f264-4509-b5c4-b07e477bd07d"
        fingerprint = "f71d1e9188f67147de8808d65374b4e34915e9d60ff475f7fc519c8918c75724"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0E 18 41 0E 1C 41 0E 20 48 0E 10 00 4C 00 00 00 64 4B 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_6dc1caab {
    meta:
        author = "Elastic Security"
        id = "6dc1caab-be84-4f27-a059-2acffc20ca2c"
        fingerprint = "43bcb29d92e0ed2dfd0ff182991864f8efabd16a0f87e8c3bb453b47bd8e272b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "f4587bd45e57d4106ebe502d2eaa1d97fd68613095234038d67490e74c62ba70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 01 83 45 F8 01 83 7D F8 5A 7E E6 C7 45 F8 61 00 00 00 EB 14 8B }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_dc47a873 {
    meta:
        author = "Elastic Security"
        id = "dc47a873-65a0-430d-a598-95be7134f207"
        fingerprint = "f103490a9dedc0197f50ca2b412cf18d2749c8d6025fd557f1686bc38f32db52"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 10 8B 45 08 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 08 C6 40 }
    condition:
        all of them
}

rule Linux_Trojan_Ddostf_cb0358a0 {
    meta:
        author = "Elastic Security"
        id = "cb0358a0-5303-4860-89ac-7dae037f5f0b"
        fingerprint = "f97c96d457532f2af5fb0e1b40ad13dcfba2479c651266b4bdd1ab2a01c0360f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ddostf"
        reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 66 C7 45 F2 00 00 8D 45 F2 8B 55 E4 0F B6 12 88 10 0F B7 45 F2 0F }
    condition:
        all of them
}



// from Linux_Trojan_DinodasRAT.yar
rule Linux_Trojan_DinodasRAT_1d371d10 {
    meta:
        author = "Elastic Security"
        id = "1d371d10-b2ae-4ea0-ad37-f5a5a571a6fc"
        fingerprint = "a53bf582ad95320dd6f432cb7290ce604aa558e4ecf6ae4e11d7985183969db1"
        creation_date = "2024-04-02"
        last_modified = "2024-06-12"
        threat_name = "Linux.Trojan.DinodasRAT"
        reference_sample = "bf830191215e0c8db207ea320d8e795990cf6b3e6698932e6e0c9c0588fc9eff"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "int MyShell::createsh()"
        $s2 = "/src/myshell.cpp"
        $s3 = "/src/inifile.cpp"
        $s4 = "Linux_%s_%s_%u_V"
        $s5 = "/home/soft/mm/rootkit/"
        $s6 = "IniFile::load_ini_file"
    condition:
        4 of them
}



// from Linux_Trojan_Dnsamp.yar
rule Linux_Trojan_Dnsamp_c31eebd4 {
    meta:
        author = "Elastic Security"
        id = "c31eebd4-7709-440d-95d1-f9a3071cc5ca"
        fingerprint = "220b656a51b3041ede4ffe8f509657c393ff100c88b401c802079aae5804dacd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dnsamp"
        reference_sample = "4b86de97819a49a90961d59f9c3ab9f8e57e19add9fe1237d2a2948b4ff22de6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 8B 40 14 48 63 D0 48 8D 45 E0 48 8D 70 04 48 8B 45 F8 48 8B }
    condition:
        all of them
}



// from Linux_Trojan_Dofloo.yar
rule Linux_Trojan_Dofloo_be1973ed {
    meta:
        author = "Elastic Security"
        id = "be1973ed-a0ee-41ca-a752-fb5f990e2096"
        fingerprint = "f032f072fd5da9ec4d8d3953bea0f2a236219b99ecfa67e3fac44f2e73f33e9c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { A8 8B 45 A8 89 45 A4 83 7D A4 00 79 04 83 45 A4 03 8B 45 A4 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Dofloo_1d057993 {
    meta:
        author = "Elastic Security"
        id = "1d057993-0a46-4014-8ab6-aa9e9d93dfa1"
        fingerprint = "c4bb948b85777b1f5df89fafba0674bc245bbda1962c576abaf0752f49c747d0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 88 45 DB 83 EC 04 8B 45 F8 83 C0 03 89 45 D4 8B 45 D4 89 }
    condition:
        all of them
}

rule Linux_Trojan_Dofloo_29c12775 {
    meta:
        author = "Elastic Security"
        id = "29c12775-b7e5-417d-9789-90b9bd4529dd"
        fingerprint = "fbf49f0904e22c4d788f151096f9b1d80aa8c739b31705e6046d17029a6a7a4f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dofloo"
        reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 2F 7E 49 00 64 80 49 00 34 7F 49 00 04 7F 49 00 24 80 49 }
    condition:
        all of them
}



// from Linux_Trojan_Dropperl.yar
rule Linux_Trojan_Dropperl_b97baf37 {
    meta:
        author = "Elastic Security"
        id = "b97baf37-48db-4eb7-85c7-08e75054bea7"
        fingerprint = "0852f1afa6162d14b076a3fc1f56e4d365b5d0e8932bae6ab055000cca7d1fba"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 12 48 89 10 83 45 DC 01 83 45 D8 01 8B 45 D8 3B 45 BC 7C CF 8B }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_e2443be5 {
    meta:
        author = "Elastic Security"
        id = "e2443be5-da15-4af2-b090-bf5accf2a844"
        fingerprint = "e49acaa476bd669b40ccc82a7d3a01e9c421e6709ecbfe8d0e24219677c96339"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F0 75 DB EB 17 48 8B 45 F8 48 83 C0 08 48 8B 10 48 8B 45 F8 48 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_683c2ba1 {
    meta:
        author = "Elastic Security"
        id = "683c2ba1-fe4a-44e4-b176-8d5d5788e1a4"
        fingerprint = "42dcea472417140d0f7768e8189ac3a8a46aaeff039be1efd36f8d50f81e347c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "a02e166fbf002dd4217c012f24bb3a8dbe310a9f0b0635eb20a7d315049367e1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_8bca73f6 {
    meta:
        author = "Elastic Security"
        id = "8bca73f6-c3ec-45a3-a5ae-67c871aaf9df"
        fingerprint = "36df2fd9746da80697ef675f84f47efb3cb90e9757677e4f565a7576966eb169"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "e7c17b7916b38494b9a07c249acb99499808959ba67125c29afec194ca4ae36c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 62 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_c4018572 {
    meta:
        author = "Elastic Security"
        id = "c4018572-a8af-4204-bc19-284a2a27dfdd"
        fingerprint = "f2ede50ea639af593211c9ef03ee2847a32cf3eb155db4e2ca302f3508bf2a45"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "c1515b3a7a91650948af7577b613ee019166f116729b7ff6309b218047141f6d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 97 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_733c0330 {
    meta:
        author = "Elastic Security"
        id = "733c0330-3163-48f3-a780-49be80a3387f"
        fingerprint = "ee233c875dd3879b4973953a1f2074cd77abf86382019eeb72da069e1fd03e1c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "b303f241a2687dba8d7b4987b7a46b5569bd2272e2da3e0c5e597b342d4561b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 A0 FB FF FF 83 7D DC 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_39f4cd0d {
    meta:
        author = "Elastic Security"
        id = "39f4cd0d-4261-4d62-a527-f403edadbd0c"
        fingerprint = "e1cdd678a1f46a3c6d26d53dd96ba6c6a45f97e743765c534f644af7c6450f8e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "c08e1347877dc77ad73c1e017f928c69c8c78a0e3c16ac5455668d2ad22500f3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 ?? FA FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}



// from Linux_Trojan_Ebury.yar
rule Linux_Trojan_Ebury_7b13e9b6 {
    meta:
        author = "Elastic Security"
        id = "7b13e9b6-ce96-4bd3-8196-83420280bd1f"
        fingerprint = "a891724ce36e86637540f722bc13b44984771f709219976168f12fe782f08306"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ebury"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 44 24 10 4C 8B 54 24 18 4C 8B 5C 24 20 8B 5C 24 28 74 04 }
    condition:
        all of them
}



// from Linux_Trojan_FinalDraft.yar
rule Linux_Trojan_FinalDraft_4ea5a204 {
    meta:
        author = "Elastic Security"
        id = "4ea5a204-5136-42c2-80f0-634368936296"
        fingerprint = "86cc29da59c8801d7443851e2c16f04d187de9705b16cc7fca553ea09baf0eb8"
        creation_date = "2025-01-23"
        last_modified = "2025-02-04"
        threat_name = "Linux.Trojan.FinalDraft"
        reference_sample = "83406905710e52f6af35b4b3c27549a12c28a628c492429d3a411fdb2d28cc8c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_comm_option_1 = "CBindTcpTransChannel"
        $str_comm_option_2 = "CDnsTransChannel"
        $str_comm_option_3 = "CHttpTransChannel"
        $str_comm_option_4 = "CIcmpTransChannel"
        $str_comm_option_5 = "COutLookTransChannel"
        $str_comm_option_6 = "CReverseTcpTransChannel"
        $str_comm_option_7 = "CReverseUdpTransChannel"
        $str_comm_option_8 = "CWebTransChannel"
        $str_feature_1 = "%s?type=del&id=%s" fullword
        $str_feature_2 = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&grant_type=refresh_token" fullword
        $str_feature_3 = "/var/log/installlog.log.%s" fullword
        $str_feature_4 = "/mnt/hgfsdisk.log.%s" fullword
        $str_feature_5 = "%-10s %-25s %-25s %-15s" fullword
        $str_feature_6 = "%-20s %-10s %-10s %-10s %-30s" fullword
        $str_feature_7 = { 48 39 F2 74 ?? 48 0F BE 0A 48 FF C2 48 6B C0 ?? 48 01 C8 EB ?? }
    condition:
        (1 of ($str_comm_option*)) and (3 of ($str_feature_*))
}



// from Linux_Trojan_Gafgyt.yar
rule Linux_Trojan_Gafgyt_83715433 {
    meta:
        author = "Elastic Security"
        id = "83715433-3dff-4238-8cdb-c51279565e05"
        fingerprint = "25ac15f4b903d9e28653dad0db399ebd20d4e9baabf5078fbc33d3cd838dd7e9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "3648a407224634d76e82eceec84250a7506720a7f43a6ccf5873f478408fedba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 08 88 10 FF 45 08 8B 45 08 0F B6 00 84 C0 75 DB C9 C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_28a2fe0c {
    meta:
        author = "Elastic Security"
        id = "28a2fe0c-eed5-4c79-81e6-3b11b73a4ebd"
        fingerprint = "a2c6beaec18ca876e8487c11bcc7a29279669588aacb7d3027d8d8df8f5bcead"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 2F 78 33 38 2F 78 46 4A 2F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_eb96cc26 {
    meta:
        author = "Elastic Security"
        id = "eb96cc26-e6d6-4388-a5da-2501e6e2ea32"
        fingerprint = "73967a3499d5dce61735aa2d352c1db48bb1d965b2934bb924209d729b5eb162"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "440318179ba2419cfa34ea199b49ee6bdecd076883d26329bbca6dca9d39c500"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 6E 66 6F 3A 20 0A 00 5E 6A 02 5F 6A 01 58 0F 05 6A 7F 5F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_5008aee6 {
    meta:
        author = "Elastic Security"
        id = "5008aee6-3866-4f0a-89bf-bde740baee5c"
        fingerprint = "6876a6c1333993c4349e459d4d13c11be1b0f78311274c0f778e65d0fabeeaa7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b32cd71fcfda0a2fcddad49d8c5ba8d4d68867b2ff2cb3b49d1a0e358346620c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 16 B4 87 58 83 00 21 84 51 FD 13 4E 79 28 57 C3 8B 30 55 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6321b565 {
    meta:
        author = "Elastic Security"
        id = "6321b565-ed25-4bf2-be4f-3ffa0e643085"
        fingerprint = "c1d286e82426cbf19fc52836ef9a6b88c1f6e144967f43760df93cf1ab497d07"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "cd48addd392e7912ab15a5464c710055f696990fab564f29f13121e7a5e93730"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D8 89 D0 01 C0 01 D0 C1 E0 03 8B 04 08 83 E0 1F 0F AB 84 9D 58 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a6a2adb9 {
    meta:
        author = "Elastic Security"
        id = "a6a2adb9-9d54-42d4-abed-5b30d8062e97"
        fingerprint = "cdd0bb9ce40a000bb86b0c76616fe71fb7dbb87a044ddd778b7a07fdf804b877"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CC 01 C2 89 55 B4 8B 45 B4 C9 C3 55 48 89 E5 48 81 EC 90 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_c573932b {
    meta:
        author = "Elastic Security"
        id = "c573932b-9b3f-4ab7-a6b6-32dcc7473790"
        fingerprint = "18a3025ebb8af46605970ee8d7d18214854b86200001d576553e102cb71df266"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7D 18 00 74 22 8B 45 1C 83 E0 02 85 C0 74 18 83 EC 08 6A 2D FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a10161ce {
    meta:
        author = "Elastic Security"
        id = "a10161ce-62e0-4f60-9de7-bd8caf8618be"
        fingerprint = "77e89011a67a539954358118d41ad3dabde0e69bac2bbb2b2da18eaad427d935"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 B0 8B 45 BC 48 63 D0 48 89 D0 48 C1 E0 02 48 8D 14 10 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ae01d978 {
    meta:
        author = "Elastic Security"
        id = "ae01d978-d07d-4813-a22b-5d172c477d08"
        fingerprint = "2d937c6009cfd53e11af52482a7418546ae87b047deabcebf3759e257cd89ce1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 2C 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9e9530a7 {
    meta:
        author = "Elastic Security"
        id = "9e9530a7-ad4d-4a44-b764-437b7621052f"
        fingerprint = "d6ad6512051e87c8c35dc168d82edd071b122d026dce21d39b9782b3d6a01e50"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F6 48 63 FF B8 36 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_5bf62ce4 {
    meta:
        author = "Elastic Security"
        id = "5bf62ce4-619b-4d46-b221-c5bf552474bb"
        fingerprint = "3ffc398303f7208e77c4fbdfb50ac896e531b7cee3be2fa820bc8d70cfb20af3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 56 53 31 F6 8D 45 10 83 EC 10 89 45 F4 8B 55 F4 46 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f3d83a74 {
    meta:
        author = "Elastic Security"
        id = "f3d83a74-2888-435a-9a3c-b7de25084e9a"
        fingerprint = "1c5df68501b688905484ed47dc588306828aa7c114644428e22e5021bb39bd4a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DC 00 74 1B 83 7D E0 0A 75 15 83 7D E4 00 79 0F C7 45 C8 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_807911a2 {
    meta:
        author = "Elastic Security"
        id = "807911a2-f6ec-4e65-924f-61cb065dafc6"
        fingerprint = "f409037091b7372f5a42bbe437316bd11c655e7a5fe1fcf83d1981cb5c4a389f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FE 48 39 F3 0F 94 C2 48 83 F9 FF 0F 94 C0 84 D0 74 16 4B 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9c18716c {
    meta:
        author = "Elastic Security"
        id = "9c18716c-e5cd-4b4f-98e2-0daed77f34cd"
        fingerprint = "351772d2936ec1a14ee7e2f2b79a8fde62d02097ae6a5304c67e00ad1b11085a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FC 80 F6 FE 59 21 EC 75 10 26 CF DC 7B 5A 5B 4D 24 C9 C0 F3 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fbed4652 {
    meta:
        author = "Elastic Security"
        id = "fbed4652-2c68-45c6-8116-e3fe7d0a28b8"
        fingerprint = "a08bcc7d0999562b4ef2d8e0bdcfa111fe0f76fc0d3b14d42c8e93b7b90abdca"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "2ea21358205612f5dc0d5f417c498b236c070509531621650b8c215c98c49467"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 00 00 2B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e0673a90 {
    meta:
        author = "Elastic Security"
        id = "e0673a90-165e-4347-a965-e8d14fdf684b"
        fingerprint = "6834f65d54bbfb926f986fe2dd72cd30bf9804ed65fcc71c2c848e72350f386a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 E8 0F B6 00 84 C0 74 17 48 8B 75 E8 48 FF C6 48 8B 7D F0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_821173df {
    meta:
        author = "Elastic Security"
        id = "821173df-6835-41e1-a662-a432abf23431"
        fingerprint = "c311789e1370227f7be1d87da0c370a905b7f5b4c55cdee0f0474060cc0fc5e4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "de7d1aff222c7d474e1a42b2368885ef16317e8da1ca3a63009bf06376026163"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D0 48 FF C8 48 03 45 F8 48 FF C8 C6 00 00 48 8B 45 F8 48 C7 C1 FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_31796a40 {
    meta:
        author = "Elastic Security"
        id = "31796a40-1cbe-4d0c-a785-d16f40765f4a"
        fingerprint = "0a6c56eeed58a1a100c9b981157bb864904ffddb3a0c4cb61ec4cc0d770d68ae"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "227c7f13f7bdadf6a14cc85e8d2106b9d69ab80abe6fc0056af5edef3621d4fb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 14 48 63 D0 48 8D 45 C0 48 8D 70 04 48 8B 45 E8 48 8B 40 18 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_750fe002 {
    meta:
        author = "Elastic Security"
        id = "750fe002-cac1-4832-94d2-212aa5ec17e3"
        fingerprint = "f51347158a6477b0da4ed4df3374fbad92b6ac137aa4775f83035d1e30cba7dc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 8B 45 0C 40 8A 00 3C FC 75 06 C6 45 FF FE EB 50 8B 45 0C 40 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6122acdf {
    meta:
        author = "Elastic Security"
        id = "6122acdf-1eef-45ea-83ea-699d21c2dc20"
        fingerprint = "283275705c729be23d7dc75056388ecae00390bd25ee7b66b0cfc9b85feee212"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 B0 00 FC 8B 7D E8 F2 AE 89 C8 F7 D0 48 48 89 45 F8 EB 03 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a0a4de11 {
    meta:
        author = "Elastic Security"
        id = "a0a4de11-fe65-449f-a990-ad5f18ac66f0"
        fingerprint = "891cfc6a4c38fb257ada29050e0047bd1301e8f0a6a1a919685b1fcc2960b047"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 0D 83 C8 10 88 42 0D 48 8B 55 D8 0F B6 42 0D 83 C8 08 88 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a473dcb6 {
    meta:
        author = "Elastic Security"
        id = "a473dcb6-887e-4a9a-a1f2-df094f1575b9"
        fingerprint = "6119a43aa5c9f61249083290293f15696b54b012cdf92553fd49736d40c433f9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "7ba74e3cb0d633de0e8dbe6cfc49d4fc77dd0c02a5f1867cc4a1f1d575def97d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 56 04 0B 1E 46 1E B0 EB 10 18 38 38 D7 80 4D 2D 03 29 62 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_30444846 {
    meta:
        author = "Elastic Security"
        id = "30444846-439f-41e1-b0b4-c12da774a228"
        fingerprint = "3c74db508de7c8c1c190d5569e0a2c2b806f72045e7b74d44bfbaed20ecb956b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c84b81d79d437bb9b8a6bad3646aef646f2a8e1f1554501139648d2f9de561da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 20 2B 78 20 74 66 74 70 31 2E 73 68 3B 20 73 68 20 74 66 74 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ea92cca8 {
    meta:
        author = "Elastic Security"
        id = "ea92cca8-bba7-4a1c-9b88-a2d051ad0021"
        fingerprint = "aa4aee9f3d6bedd8234eaf8778895a0f5d71c42b21f2a428f01f121e85704e8e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 65 6C 66 20 52 65 70 20 46 75 63 6B 69 6E 67 20 4E 65 54 69 53 20 61 6E 64 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d4227dbf {
    meta:
        author = "Elastic Security"
        id = "d4227dbf-6ab4-4637-a6ba-0e604acaafb4"
        fingerprint = "58c4b1d4d167876b64cfa10f609911a80284180e4db093917fea16fae8ccd4e3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 54 24 30 C7 04 24 18 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_09c3070e {
    meta:
        author = "Elastic Security"
        id = "09c3070e-4b71-45a0-aa62-0cc6e496644a"
        fingerprint = "84fad96b60b297736c149e14de12671ff778bff427ab7684df2c541a6f6d7e7d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 C1 E8 06 48 89 C6 48 8B 94 C5 50 FF FF FF 8B 8D 2C FF FF FF 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fa19b8fc {
    meta:
        author = "Elastic Security"
        id = "fa19b8fc-6035-4415-842f-4993411ab43e"
        fingerprint = "4f213d5d1b4a0b832ed7a6fac91bef7c29117259b775b85409e9e4c8aec2ad10"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "a7cfc16ec33ec633cbdcbff3c4cefeed84d7cbe9ca1f4e2a3b3e43d39291cd6b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 63 10 01 0F 4B 85 14 36 B0 60 53 03 4F 0D B2 05 76 02 B7 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_eaa9a668 {
    meta:
        author = "Elastic Security"
        id = "eaa9a668-e3b9-4657-81bf-1c6456e2053a"
        fingerprint = "bee2744457164e5747575a101026c7862474154d82f52151ac0d77fb278d9405"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 C0 0F B6 00 3C 2F 76 0B 48 8B 45 C0 0F B6 00 3C 39 76 C7 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_46eec778 {
    meta:
        author = "Elastic Security"
        id = "46eec778-7342-4ef7-adac-35bc0cdb9867"
        fingerprint = "2602371a40171870b1cf024f262e95a2853de53de39c3a6cd3de811e81dd3518"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 01 45 F8 48 83 45 E8 02 83 6D C8 02 83 7D C8 01 7F E4 83 7D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f51c5ac3 {
    meta:
        author = "Elastic Security"
        id = "f51c5ac3-ade9-4d01-b578-3473a2b116db"
        fingerprint = "34f254afdf94b1eb29bae4eb8e3864ea49e918a5dbe6e4c9d06a4292c104a792"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 2A 8B 45 0C 0F B6 00 84 C0 74 17 8B 45 0C 40 89 44 24 04 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_71e487ea {
    meta:
        author = "Elastic Security"
        id = "71e487ea-a592-469c-a03e-0c64d2549e74"
        fingerprint = "8df69968ddfec5821500949015192b6cdbc188c74f785a272effd7bc9707f661"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b8d044f2de21d20c7e4b43a2baf5d8cdb97fba95c3b99816848c0f214515295b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E0 8B 45 D8 8B 04 D0 8D 50 01 83 EC 0C 8D 85 40 FF FF FF 50 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6620ec67 {
    meta:
        author = "Elastic Security"
        id = "6620ec67-8f12-435b-963c-b44a02f43ef1"
        fingerprint = "9d68db5b3779bb5abe078f9e36dd9a09d4d3ad9274a3a50bdfa0e444a7e46623"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b91eb196605c155c98f824abf8afe122f113d1fed254074117652f93d0c9d6b2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AF 93 64 1A D8 0B 48 93 64 0B 48 A3 64 11 D1 0B 41 05 E4 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d996d335 {
    meta:
        author = "Elastic Security"
        id = "d996d335-e049-4052-bf36-6cd07c911a8b"
        fingerprint = "e9ccb8412f32187c309b0e9afcc3a6da21ad2f1ffa251c27f9f720ccb284e3ac"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "b511eacd4b44744c8cf82d1b4a9bc6f1022fe6be7c5d17356b171f727ddc6eda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D0 EB 0F 40 38 37 75 04 48 89 F8 C3 49 FF C8 48 FF C7 4D 85 C0 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d0c57a2e {
    meta:
        author = "Elastic Security"
        id = "d0c57a2e-c10c-436c-be13-50a269326cf2"
        fingerprint = "3ee7d3a33575ed3aa7431489a8fb18bf30cfd5d6c776066ab2a27f93303124b6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_751acb94 {
    meta:
        author = "Elastic Security"
        id = "751acb94-cb23-4949-a4dd-87985c47379e"
        fingerprint = "dbdfdb455868332e9fbadd36c084d0927a3dd8ab844f0b1866e914914084cd4b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 54 6F 20 43 6F 6E 6E 65 63 74 21 20 00 53 75 63 63 65 73 66 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_656bf077 {
    meta:
        author = "Elastic Security"
        id = "656bf077-ca0c-4d28-9daa-eb6baafaf467"
        fingerprint = "3ea8ed60190198d5887bb7093975d648a9fd78234827d648a8258008c965b1c1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 28 48 8B 45 E8 0F B6 00 84 C0 74 14 48 8B 75 E8 48 FF C6 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e6d75e6f {
    meta:
        author = "Elastic Security"
        id = "e6d75e6f-aa04-4767-8730-6909958044a7"
        fingerprint = "e99805e8917d6526031270b6da5c2f3cc1c8235fed1d47134835a107d0df497c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "48b15093f33c18778724c48c34199a420be4beb0d794e36034097806e1521eb8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 CD 80 C3 8B 54 24 04 8B 4C 24 08 87 D3 B8 5B 00 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_7167d08f {
    meta:
        author = "Elastic Security"
        id = "7167d08f-bfeb-4d78-9783-3a1df2ef0ed3"
        fingerprint = "b9df4ab322a2a329168f684b07b7b05ee3d03165c5b9050a4710eae7aeca6cd9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 8A 00 3C 2D 75 13 FF 45 0C C7 45 E4 01 00 00 00 EB 07 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_27de1106 {
    meta:
        author = "Elastic Security"
        id = "27de1106-497d-40a0-8fc4-929f7a927628"
        fingerprint = "9a747f0fc7ccc55f24f2654344484f643103da709270a45de4c1174d8e4101cc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 0F B6 00 84 C0 74 18 8B 45 0C 40 8B 55 08 42 89 44 24 04 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_148b91a2 {
    meta:
        author = "Elastic Security"
        id = "148b91a2-ed51-4c2d-9d15-6a48d9ea3e0a"
        fingerprint = "0f75090ed840f4601df4e43a2f49f2b32585213f3d86d19fb255d79c21086ba3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "d5b2bde0749ff482dc2389971e2ac76c4b1e7b887208a538d5555f0fe6984825"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C6 45 DB FC EB 04 C6 45 DB FE 0F B6 45 DB 88 45 FF 48 8D 75 FF 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_20f5e74f {
    meta:
        author = "Elastic Security"
        id = "20f5e74f-9f94-431b-877c-9b0d78a1d4eb"
        fingerprint = "070fe0d678612b4ec8447a07ead0990a0abd908ce714388720e7fd7055bf1175"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9084b00f9bb71524987dc000fb2bc6f38e722e2be2832589ca4bb1671e852f5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D8 8B 45 D0 8B 04 D0 8D 50 01 83 EC 0C 8D 85 38 FF FF FF 50 8D 85 40 FF }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_1b2e2a3a {
    meta:
        author = "Elastic Security"
        id = "1b2e2a3a-1302-41c7-be99-43edb5563294"
        fingerprint = "6f24b67d0a6a4fc4e1cfea5a5414b82af1332a3e6074eb2178aee6b27702b407"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7D 18 00 74 25 8B 45 1C 83 E0 02 85 C0 74 1B C7 44 24 04 2D 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_620087b9 {
    meta:
        author = "Elastic Security"
        id = "620087b9-c87d-4752-89e8-ca1c16486b28"
        fingerprint = "06cd7e6eb62352ec2ccb9ed48e58c0583c02fefd137cd048d053ab30b5330307"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 89 D8 48 83 C8 01 EB 04 48 8B 76 10 48 3B 46 08 72 F6 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_dd0d6173 {
    meta:
        author = "Elastic Security"
        id = "dd0d6173-b863-45cf-9348-3375a4e624cf"
        fingerprint = "5e2cb111c2b712951b71166111d339724b4f52b93f90cb474f1e67598212605f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "c5a317d0d8470814ff343ce78ad2428ebb3f036763fcf703a589b6c4d33a3ec6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 F8 8B 45 F0 89 42 0C 48 8B 55 F8 8B 45 F4 89 42 10 C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_779e142f {
    meta:
        author = "Elastic Security"
        id = "779e142f-b867-46e6-b1fb-9105976f42fd"
        fingerprint = "83377b6fa77fda4544c409487d2d2c1ddcef8f7d4120f49a18888c7536f3969f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_cf84c9f2 {
    meta:
        author = "Elastic Security"
        id = "cf84c9f2-7435-4faf-8c5f-d14945ffad7a"
        fingerprint = "bb766b356c3e8706740e3bb9b4a7171d8eb5137e09fc7ab6952412fa55e2dcfc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 30 48 89 7D E8 89 75 E4 89 55 E0 C7 45 F8 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0cd591cd {
    meta:
        author = "Elastic Security"
        id = "0cd591cd-c348-4c3a-a895-2063cf892cda"
        fingerprint = "96c4ff70729ddb981adafd8c8277649a88a87e380d2f321dff53f0741675fb1b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4E F8 48 8D 4E D8 49 8D 42 E0 48 83 C7 03 EB 6B 4C 8B 46 F8 48 8D }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_33b4111a {
    meta:
        author = "Elastic Security"
        id = "33b4111a-e59e-48db-9d74-34ca44fcd9f5"
        fingerprint = "9c3b63b9a0f54006bae12abcefdb518904a85f78be573f0780f0a265b12d2d6e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "01da73e0d425b4d97c5ad75c49657f95618b394d09bd6be644eb968a3b894961"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 83 E1 0F 74 1A B8 10 00 00 00 48 29 C8 48 8D 0C 02 48 89 DA 48 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_4f43b164 {
    meta:
        author = "Elastic Security"
        id = "4f43b164-686d-4b73-b532-45e2df992b33"
        fingerprint = "35a885850a06e7991c3a8612bbcdfc279b87e4ca549723192d3011a1e0a81640"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "f0fdb3de75f85e199766bbb39722865cac578cde754afa2d2f065ef028eec788"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 00 4B 49 4C 4C 53 55 42 00 4B 49 4C 4C 53 55 42 20 3C 73 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e4a1982b {
    meta:
        author = "Elastic Security"
        id = "e4a1982b-928a-4da5-b497-cedc1d26e845"
        fingerprint = "d9f852c28433128b0fd330bee35f7bd4aada5226e9ca865fe5cd8cca52b2a622"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 EC F7 D0 21 D0 33 45 FC C9 C3 55 48 89 E5 48 83 EC 30 48 89 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_862c4e0e {
    meta:
        author = "Elastic Security"
        id = "862c4e0e-83a4-458b-8c00-f2f3cf0bf9db"
        fingerprint = "2a6b4f8d8fb4703ed26bdcfbbb5c539dc451c8b90649bee80015c164eae4c281"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "9526277255a8d632355bfe54d53154c9c54a4ab75e3ba24333c73ad0ed7cadb1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 02 89 45 F8 8B 45 F8 C1 E8 10 85 C0 75 E6 8B 45 F8 F7 D0 0F }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9127f7be {
    meta:
        author = "Elastic Security"
        id = "9127f7be-6e82-46a1-9f11-0b3570b0cd76"
        fingerprint = "72c742cb8b11ddf030e10f67e13c0392748dcd970394ec77ace3d2baa705a375"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 F7 E1 89 D0 C1 E8 03 89 45 E8 8B 45 E8 01 C0 03 45 E8 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0e03b7d3 {
    meta:
        author = "Elastic Security"
        id = "0e03b7d3-a6b0-46a0-920e-c15ee7e723f7"
        fingerprint = "1bf1f271005328669b3eb4940e2b75eff9fc47208d79a12196fd7ce04bc4dbe8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F5 74 84 32 63 29 5A B2 78 FF F7 FA 0E 51 B3 2F CD 7F 10 FA }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_32eb0c81 {
    meta:
        author = "Elastic Security"
        id = "32eb0c81-25af-4670-ab77-07ea7ce1874a"
        fingerprint = "7c50ed29e2dd75a6a85afc43f8452794cb787ecd2061f4bf415d7038c14c523f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D4 48 FF 45 F0 48 8B 45 F0 0F B6 00 84 C0 75 DB EB 12 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9abf7e0c {
    meta:
        author = "Elastic Security"
        id = "9abf7e0c-5076-4881-a488-f0f62810f843"
        fingerprint = "7d02513aaef250091a58db58435a1381974e55c2ed695c194b6b7b83c235f848"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 E0 0F B6 42 0D 83 C8 01 88 42 0D 48 8B 55 E0 0F B6 42 0D 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_33801844 {
    meta:
        author = "Elastic Security"
        id = "33801844-50b1-4968-a1b7-d106f16519ee"
        fingerprint = "36218345b9ce4aaf50b5df1642c00ac5caa744069e952eb6008a9a57a37dbbdc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "2ceff60e88c30c02c1c7b12a224aba1895669aad7316a40b575579275b3edbb3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 48 83 E8 01 0F B6 00 3C 0D 75 0B 48 8B 45 F8 0F B6 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_a33a8363 {
    meta:
        author = "Elastic Security"
        id = "a33a8363-5511-4fe1-a0d8-75156b9ccfc7"
        fingerprint = "74f964eaadbf8f30d40cdec40b603c5141135d2e658e7ce217d0d6c62e18dd08"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 88 02 48 85 D2 75 ED 5A 5B 5D 41 5C 41 5D 4C 89 F0 41 5E }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_9a62845f {
    meta:
        author = "Elastic Security"
        id = "9a62845f-6311-49ae-beac-f446b2909d9c"
        fingerprint = "2ccc813c5efed35308eb2422239b5b83d051eca64b7c785e66d602b13f8bd9b4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "f67f8566beab9d7494350923aceb0e76cd28173bdf2c4256e9d45eff7fc8cb41"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 83 F8 20 7F 1E 83 7D 08 07 75 33 8B 45 0C 83 C0 18 8B 00 83 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_4d81ad42 {
    meta:
        author = "Elastic Security"
        id = "4d81ad42-bf08-48a9-9a93-85cb491257b3"
        fingerprint = "f285683c3b145990e1b6d31d3c9d09177ebf76f183d0fa336e8df3dbcba24366"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "3021a861e6f03df3e7e3919e6255bdae6e48163b9a8ba4f1a5c5dced3e3e368b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 44 C8 07 0B BF F1 1B 7E 83 CD FF 31 DB 2E 22 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6a510422 {
    meta:
        author = "Elastic Security"
        id = "6a510422-3662-4fdb-9c03-0101f16e87cd"
        fingerprint = "8ee116ff41236771cdc8dc4b796c3b211502413ae631d5b5aedbbaa2eccc3b75"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0B E5 24 30 1B E5 2C 30 0B E5 1C 00 00 EA 18 30 1B E5 00 30 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d2953f92 {
    meta:
        author = "Elastic Security"
        id = "d2953f92-62ee-428d-88c5-723914c88c6e"
        fingerprint = "276c6d62a8a335d0e2421b6b5b90c2c0eb69eec294bc9fcdeb7743abbf08d8bc"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1B E5 2A 00 53 E3 0A 00 00 0A 30 30 1B E5 3F 00 53 E3 23 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_6ae4b580 {
    meta:
        author = "Elastic Security"
        id = "6ae4b580-f7cf-4318-b584-7ea15f10f5ea"
        fingerprint = "279e344d6da518980631e70d7b1ded4ff1b034d24e4b4fe01b36ed62f5c1176c"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 30 0B E5 3C 20 1B E5 6C 32 1B E5 03 00 52 E1 01 00 00 DA 6C }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d608cf3b {
    meta:
        author = "Elastic Security"
        id = "d608cf3b-c255-4a8d-9bf1-66f92eacd751"
        fingerprint = "3825aa1c9cddb46fdef6abc0503b42acbca8744dd89b981a3eea8db2f86a8a76"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 2F E1 7E 03 00 00 78 D8 00 00 24 00 00 00 28 00 00 00 4C }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_3f8cf56e {
    meta:
        author = "Elastic Security"
        id = "3f8cf56e-a8cb-4c03-8829-f1daa3dc64a8"
        fingerprint = "77306f0610515434371f70f2b42c895cdc5bbae2ef6919cf835b3cfe2e4e4976"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "1878f0783085cc6beb2b81cfda304ec983374264ce54b6b98a51c09aea9f750d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 2F DA E8 E9 CC E4 F4 39 55 E2 9E 33 0E C0 F0 FB 26 93 31 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_fb14e81f {
    meta:
        author = "Elastic Security"
        id = "fb14e81f-be2a-4428-9877-958e394a7ae2"
        fingerprint = "12b430108256bd0f57f48b9dbbea12eba7405c0b3b66a1c4b882647051f1ec52"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "0fd07e6068a721774716eb4940e2c19faef02d5bdacf3b018bf5995fa98a3a27"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4E 45 52 00 53 43 41 4E 4E 45 52 20 4F 4E 20 7C 20 4F 46 46 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_e09726dc {
    meta:
        author = "Elastic Security"
        id = "e09726dc-4e6d-4115-b178-d20375c09e04"
        fingerprint = "614d54b3346835cd5c2a36a54cae917299b1a1ae0d057e3fa1bb7dddefc1490f"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "1e64187b5e3b5fe71d34ea555ff31961404adad83f8e0bd1ce0aad056a878d73"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 48 83 EC 08 48 83 C4 08 C3 00 00 00 01 00 02 00 50 49 4E 47 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_ad12b9b6 {
    meta:
        author = "Elastic Security"
        id = "ad12b9b6-2e66-4647-8bf3-0300f2124a97"
        fingerprint = "46d86406f7fb25f0e240abc13e86291c56eb7468d0128fdff181f28d4f978058"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Gafgyt"
        reference = "f0411131acfddb40ac8069164ce2808e9c8928709898d3fb5dc88036003fe9c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 52 46 00 4B 45 46 31 4A 43 53 00 4B 45 46 31 51 45 42 00 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_0535ebf7 {
    meta:
        author = "Elastic Security"
        id = "0535ebf7-844f-4207-82ef-e155ceff7a3e"
        fingerprint = "2b9b17dad296c0a58a7efa1fb3f71c62bf849f00deb978c1103ab8a480290024"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "77e18bb5479b644ba01d074057c9e2bd532717f6ab3bb88ad2b7497b85d2a5de"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 48 8B 04 24 6A 18 48 F7 14 24 48 FF 04 24 48 03 24 24 48 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_32a7edd2 {
    meta:
        author = "Elastic Security"
        id = "32a7edd2-175f-45b3-bf3d-8c842e4ae7e7"
        fingerprint = "d59183e8833272440a12b96de82866171f7ea0212cee0e2629c169fdde4da2a5"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 FD 48 FD 45 FD 0F FD 00 FD FD 0F FD FD 02 00 00 48 FD 45 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_d7f35b54 {
    meta:
        author = "Elastic Security"
        id = "d7f35b54-82a8-4ef0-8c8c-30a6734223e1"
        fingerprint = "d01db0f6a169d82d921c76801738108a2f0ef4ef65ea2e104fb80188a3bb73b8"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 48 FD 45 FD 48 FD FD FD FD FD FD FD FD FD 48 FD 45 FD 66 }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_f11e98be {
    meta:
        author = "Elastic Security"
        id = "f11e98be-bf81-480e-b2d1-dcc748c6869d"
        fingerprint = "8cdf2acffd0cdce48ceaffa6682d2f505c557b873e4f418f4712dfa281a3095a"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 40 00 09 FD 21 FD FD 08 48 FD 80 3E 00 75 FD FD 4C 24 48 0F FD }
    condition:
        all of them
}

rule Linux_Trojan_Gafgyt_8d4e4f4a {
    meta:
        author = "Elastic Security"
        id = "8d4e4f4a-b3ea-4f93-ada2-2c88bb5d806d"
        fingerprint = "9601c7cf7f2b234bc30d00e1fc0217b5fa615c369e790f5ff9ca42bcd85aea12"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Gafgyt"
        reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 00 FD FD 00 00 00 31 FD 48 FD FD 01 00 00 00 49 FD FD 04 }
    condition:
        all of them
}



// from Linux_Trojan_Ganiw.yar
rule Linux_Trojan_Ganiw_99349371 {
    meta:
        author = "Elastic Security"
        id = "99349371-644e-4954-9b7d-f2f579922565"
        fingerprint = "6b0cbea419915567c2ecd84bfcb2c7f7301435ee953f16c6dcba826802637551"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ganiw"
        reference_sample = "e8dbb246fdd1a50226a36c407ac90eb44b0cf5e92bf0b92c89218f474f9c2afb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 66 89 43 02 8B 5D FC C9 C3 55 89 E5 53 83 EC 04 8B 45 14 8B }
    condition:
        all of them
}

rule Linux_Trojan_Ganiw_b9f045aa {
    meta:
        author = "Elastic Security"
        id = "b9f045aa-99fa-47e9-b179-ac62158b3fe2"
        fingerprint = "0aaec92ca1c622df848bba80a2f1e4646252625d58e28269965b13d65158f238"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ganiw"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E5 57 8B 55 0C 85 D2 74 21 FC 31 C0 8B 7D 08 AB AB AB AB AB AB }
    condition:
        all of them
}



// from Linux_Trojan_Generic.yar
rule Linux_Trojan_Generic_402be6c5 {
    meta:
        author = "Elastic Security"
        id = "402be6c5-a1d8-4d7a-88ba-b852e0db1098"
        fingerprint = "1e906f5a06f688084edf537ead0b7e887bd9e0fcc39990c976ea8c136dc52624"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "d30a8f5971763831f92d9a6dd4720f52a1638054672a74fdb59357ae1c9e6deb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 52 4C 95 42 11 01 64 E9 D7 39 E4 89 34 FA 48 01 02 C1 3B 39 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5420d3e7 {
    meta:
        author = "Elastic Security"
        id = "5420d3e7-012f-4ce0-bb13-9e5221efa73e"
        fingerprint = "e81615b5756c2789b9be8fb10420461d5260914e16ba320cbab552d654bbbd8a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "103b8fced0aebd73cb8ba9eff1a55e6b6fa13bb0a099c9234521f298ee8d2f9f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 63 00 5F 5A 4E 34 41 52 43 34 37 65 6E 63 72 79 70 74 45 50 63 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_4f4cc3ea {
    meta:
        author = "Elastic Security"
        id = "4f4cc3ea-a906-4fce-a482-d762ab8995b8"
        fingerprint = "d85dac2bd81925f5d8c90c11047c631c1046767cb6649cd266c3a143353b6c12"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "32e25641360dbfd50125c43754cd327cf024f1b3bfd75b617cdf8a17024e2da5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4A 4E 49 20 55 4E 50 41 43 4B 20 44 45 58 20 53 54 41 52 54 20 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_703a0258 {
    meta:
        author = "Elastic Security"
        id = "703a0258-8d28-483e-a679-21d9ef1917b4"
        fingerprint = "796c2283eb14057081409800480b74ab684413f8f63a9db8704f5057026fb556"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b086d0119042fc960fe540c23d0a274dd0fb6f3570607823895c9158d4f75974"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C2 F7 89 76 7E 86 87 F6 2B A3 2C 94 61 36 BE B6 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_378765e4 {
    meta:
        author = "Elastic Security"
        id = "378765e4-c0f2-42ad-a42b-b992d3b866f4"
        fingerprint = "60f259ba5ffe607b594c2744b9b30c35beab9683f4cd83c2e31556a387138923"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? 22 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_f657fb4f {
    meta:
        author = "Elastic Security"
        id = "f657fb4f-a065-4d51-bead-fd28f8053418"
        fingerprint = "8c15d5e53b95002f569d63c91db7858c4ca8f26c441cb348a1b34f3b26d02468"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_be1757ef {
    meta:
        author = "Elastic Security"
        id = "be1757ef-cf45-4c00-8d6c-dbb0f44f6efb"
        fingerprint = "0af6b01197b63259d9ecbc24f95b183abe7c60e3bf37ca6ac1b9bc25696aae77"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "f3e4e2b5af9d0c72aae83cec57e5c091a95c549f826e8f13559aaf7d300f6e13"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 54 68 75 20 4D 61 72 20 31 20 31 34 3A 34 34 3A 30 38 20 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_7a95ef79 {
    meta:
        author = "Elastic Security"
        id = "7a95ef79-3df5-4f7a-a8ba-00577473b288"
        fingerprint = "aadec0fa964f94afb725a568dacf21e80b80d359cc5dfdd8d028aaece04c7012"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "f59340a740af8f7f4b96e3ea46d38dbe81f2b776820b6f53b7028119c5db4355"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1C 8B 54 24 20 8B 74 24 24 CD 80 5E 5A 59 5B C3 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_1c5e42b7 {
    meta:
        author = "Elastic Security"
        id = "1c5e42b7-b873-443e-a30c-66a75fc39b21"
        fingerprint = "b64284e1220ec9abc9b233e513020f8b486c76f91e4c3f2a0a6fb003330c2535"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 FF 75 1C 83 EC 0C 68 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_8ca4b663 {
    meta:
        author = "Elastic Security"
        id = "8ca4b663-b282-4322-833a-4c0143f63634"
        fingerprint = "34e04e32ee493643cc37ff0cfb94dcbc91202f651bc2560e9c259b53a9d6acfc"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "1ddf479e504867dfa27a2f23809e6255089fa0e2e7dcf31b6ce7d08f8d88947e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 28 60 DF F2 FB B7 E7 EB 96 D1 E6 96 88 12 96 EB 8C 94 EB C7 4E }
    condition:
        all of them
}

rule Linux_Trojan_Generic_d3fe3fae {
    meta:
        author = "Elastic Security"
        id = "d3fe3fae-f7ec-48d5-8b17-9ab11a5b689f"
        fingerprint = "1773a3e22cb44fe0b3e68d343a92939a955027e735c60b48cf3b7312ce3a6415"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "2a2542142adb05bff753e0652e119c1d49232d61c49134f13192425653332dc3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 47 53 45 54 2C 20 70 69 64 2C 20 4E 54 5F 50 52 53 54 41 54 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5e981634 {
    meta:
        author = "Elastic Security"
        id = "5e981634-e34e-4943-bf8f-86cfd9fffc85"
        fingerprint = "57f1e8fa41f6577f41a73e3460ef0c6c5b0a65567ae0962b080dfc8ab18364f5"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "448e8d71e335cabf5c4e9e8d2d31e6b52f620dbf408d8cc9a6232a81c051441b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 1D 8B 44 24 68 89 84 24 A4 00 00 00 8B 44 24 6C 89 84 24 A8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_d8953ca0 {
    meta:
        author = "Elastic Security"
        id = "d8953ca0-f1f1-4d76-8c80-06f16998ba03"
        fingerprint = "16ab55f99be8ed2a47618978a335a8c68369563c0a4d0a7ff716b5d4c9e0785c"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "552753661c3cc7b3a4326721789808482a4591cb662bc813ee50d95f101a3501"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5B 9C 9C 9C 9C 5C 5D 5E 5F 9C 9C 9C 9C B1 B2 B3 B4 9C 9C 9C 9C }
    condition:
        all of them
}

rule Linux_Trojan_Generic_181054af {
    meta:
        author = "Elastic Security"
        id = "181054af-dc05-4981-8a57-ea17ffd6241f"
        fingerprint = "8ef033ac0fccd10cdf2e66446461b7c8b29574e5869440a1972dbe4bb5fbed89"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "e677f1eed0dbb4c680549e0bf86d92b0a28a85c6d571417baaba0d0719da5f93"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6D 6F 64 00 73 65 74 75 74 78 65 6E 74 00 67 6D 74 69 6D 65 00 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_c3d529a2 {
    meta:
        author = "Elastic Security"
        id = "c3d529a2-f2c7-41de-ba2a-2cbf2eb4222c"
        fingerprint = "72ef5b28489e01c3f2413b9a907cda544fc3f60e00451382e239b55ec982f187"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "b46135ae52db6399b680e5c53f891d101228de5cd6c06b6ae115e4a763a5fb22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1C 31 C0 5B 5E 5F 5D C3 8B 1C 24 C3 8D 64 24 04 53 8B DA 5B }
    condition:
        all of them
}

rule Linux_Trojan_Generic_4675dffa {
    meta:
        author = "Elastic Security"
        id = "4675dffa-0536-4a4d-bedb-f8c7fa076168"
        fingerprint = "7aa556e481694679ce0065bcaaa4d35e2c2382326681f03202b68b1634db08ab"
        creation_date = "2023-07-28"
        last_modified = "2024-02-13"
        threat_name = "Linux.Trojan.Generic"
        reference_sample = "43e14c9713b1ca1f3a7f4bcb57dd3959d3a964be5121eb5aba312de41e2fb7a6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = ", i = , not , val ./zzzz.local.onion"
        $a2 = { 61 74 20 20 25 76 3D 25 76 2C 20 28 63 6F 6E 6E 29 20 28 73 63 61 6E 20 20 28 73 63 }
    condition:
        all of them
}

rule Linux_Trojan_Generic_5e3bc3b3 {
    meta:
        author = "Elastic Security"
        id = "5e3bc3b3-c708-49dd-80c6-0d353acb4b53"
        fingerprint = "cf1c66af92607d0ec76ec1db0292fcb8035bdc85117dc714bdade32740d5a835"
        creation_date = "2024-09-20"
        description = "Rule for custom Trojan found in Linux REF6138."
        last_modified = "2024-11-04"
        threat_name = "Linux.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $enc1 = { 74 73 0A 1C 1A 54 1A 11 54 0C 18 43 59 5B 3A 11 0B 16 14 10 0C 14 5B }
        $enc2 = { 18 1A 1A 1C 09 0D 43 59 0D 1C 01 0D 56 11 0D 14 15 55 18 09 09 15 10 }
        $enc3 = { 18 1A 1A 1C 09 0D 54 15 18 17 1E 0C 18 1E 1C 43 59 0B 0C }
        $enc4 = { 34 16 03 10 15 15 18 56 4C 57 49 59 51 2E 10 17 1D 16 0E 0A 59 37 }
        $key = "yyyyyyyy"
    condition:
        1 of ($enc*) and $key
}



// from Linux_Trojan_Getshell.yar
rule Linux_Trojan_Getshell_98d002bf {
    meta:
        author = "Elastic Security"
        id = "98d002bf-63b7-4d11-98ef-c3127e68d59c"
        fingerprint = "b7bfec0a3cfc05b87fefac6b10673491b611400edacf9519cbcc1a71842e9fa3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference_sample = "97b7650ab083f7ba23417e6d5d9c1d133b9158e2c10427d1f1e50dfe6c0e7541"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B2 6A B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_213d4d69 {
    meta:
        author = "Elastic Security"
        id = "213d4d69-5660-468d-a98c-ff3eef604b1e"
        fingerprint = "60e385e4c5eb189785bc14d39bf8a22c179e4be861ce3453fbcf4d367fc87c90"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference = "05fc4dcce9e9e1e627ebf051a190bd1f73bc83d876c78c6b3d86fc97b0dfd8e8"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 01 00 00 00 EB 3C 8B 45 EC 48 98 48 C1 E0 03 48 03 45 D0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_3cf5480b {
    meta:
        author = "Elastic Security"
        id = "3cf5480b-bb21-4a6e-a078-4b145d22c79f"
        fingerprint = "3ef0817445c54994d5a6792ec0e6c93f8a51689030b368eb482f5ffab4761dd2"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference = "0e41c0d6286fb7cd3288892286548eaebf67c16f1a50a69924f39127eb73ff38"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B2 24 B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Getshell_8a79b859 {
    meta:
        author = "Elastic Security"
        id = "8a79b859-654c-4082-8cfc-61a143671457"
        fingerprint = "5a95d1df94791c8484d783da975bec984fb11653d1f81f6397efd734a042272b"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Getshell"
        reference = "1154ba394176730e51c7c7094ff3274e9f68aaa2ed323040a94e1c6f7fb976a2"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0A 00 89 E1 6A 1C 51 56 89 E1 43 6A 66 58 CD 80 B0 66 B3 04 }
    condition:
        all of them
}



// from Linux_Trojan_Godlua.yar
rule Linux_Trojan_Godlua_ed8e6228 {
    meta:
        author = "Elastic Security"
        id = "ed8e6228-d5be-4b8e-8dc2-7072b1236bfa"
        fingerprint = "9b73c2bbbe1bc43ae692f03b19cd23ad701f0120dff0201dd2a6722c44ea51ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Godlua"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 18 48 89 45 E8 EB 60 48 8B 85 58 FF FF FF 48 83 C0 20 48 89 }
    condition:
        all of them
}



// from Linux_Trojan_Godropper.yar
rule Linux_Trojan_Godropper_bae099bd {
    meta:
        author = "Elastic Security"
        id = "bae099bd-c19a-4893-96e8-63132dabce39"
        fingerprint = "5a7b0906ebc47130aefa868643e1e0a40508fe7a25bc55e5c41ff284ca2751e5"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Godropper"
        reference_sample = "704643f3fd11cda1d52260285bf2a03bccafe59cfba4466427646c1baf93881e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF FF 88 DB A2 31 03 A3 5A 5C 9A 19 0E DB }
    condition:
        all of them
}



// from Linux_Trojan_Gognt.yar
rule Linux_Trojan_Gognt_50c3d9da {
    meta:
        author = "Elastic Security"
        id = "50c3d9da-0392-4379-aafe-cfe63ade3314"
        fingerprint = "a4b7e0c7c2f1b0634f82106ec0625bcdde02296b3e72c9c3aa9c16e40d770b43"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gognt"
        reference_sample = "79602bc786edda7017c5f576814b683fba41e4cb4cf3f837e963c6d0d42c50ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 47 6F 00 00 51 76 46 5F 6F 30 59 36 55 72 5F 6C 63 44 }
    condition:
        all of them
}

rule Linux_Trojan_Gognt_05b10f4b {
    meta:
        author = "Elastic Security"
        id = "05b10f4b-7434-457a-9e8e-d898bb839dce"
        fingerprint = "fdf7b65f812c17c7f30b3095f237173475cdfb0c10a4b187f751c0599f6b5729"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gognt"
        reference_sample = "e43aaf2345dbb5c303d5a5e53cd2e2e84338d12f69ad809865f20fd1a5c2716f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7C 24 78 4C 89 84 24 A8 00 00 00 48 29 D7 49 89 F9 48 F7 DF 48 C1 }
    condition:
        all of them
}



// from Linux_Trojan_Hiddad.yar
rule Linux_Trojan_Hiddad_e35bff7b {
    meta:
        author = "Elastic Security"
        id = "e35bff7b-1a93-4cfd-a4b6-1e994c0afa98"
        fingerprint = "0ed46ca8a8bd567acf59d8a15a9597d7087975e608f42af57d36c31e777bb816"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Hiddad"
        reference_sample = "22a418e660b5a7a2e0cc1c1f3fe1d150831d75c4fedeed9817a221194522efcf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3C 14 48 63 CF 89 FE 48 69 C9 81 80 80 80 C1 FE 1F 48 C1 E9 20 }
    condition:
        all of them
}



// from Linux_Trojan_Ipstorm.yar
rule Linux_Trojan_Ipstorm_3c43d4a7 {
    meta:
        author = "Elastic Security"
        id = "3c43d4a7-185a-468b-a73d-82f579de98c1"
        fingerprint = "cf6812f8f0ee7951a70bec3839b798a574d536baae4cf37cda6eebf570cab0be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 8D 54 24 58 31 F6 EB 11 48 8B 84 24 88 00 00 00 48 89 F1 48 }
    condition:
        all of them
}

rule Linux_Trojan_Ipstorm_f9269f00 {
    meta:
        author = "Elastic Security"
        id = "f9269f00-4664-47a4-9148-fa74e2cfee7c"
        fingerprint = "509de41454bcc60dad0d96448592aa20fb997ce46ad8fed5d4bbdbe2ede588d6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 B8 69 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ipstorm_08bcf61c {
    meta:
        author = "Elastic Security"
        id = "08bcf61c-baef-4320-885c-8f8949684dde"
        fingerprint = "348295602b1582839f6acc603832f09e9afab71731bc21742d1a638e41df6e7c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "503f293d84de4f2c826f81a68180ad869e0d1448ea6c0dbf09a7b23801e1a9b9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8C 24 98 00 00 00 31 D2 31 DB EB 04 48 83 C1 18 48 8B 31 48 83 79 }
    condition:
        all of them
}



// from Linux_Trojan_Ircbot.yar
rule Linux_Trojan_Ircbot_bb204b81 {
    meta:
        author = "Elastic Security"
        id = "bb204b81-db58-434f-b834-672cdc25e56c"
        fingerprint = "66f9a8a31653a5e480f427d2d6a25b934c2c53752308eedb57eaa7b7cb7dde2e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ircbot"
        reference_sample = "6147481d083c707dc98905a1286827a6e7009e08490e7d7c280ed5a6356527ad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 44 C8 4C 5E F8 8D EF 80 83 CD FF 31 DB 30 22 }
    condition:
        all of them
}

rule Linux_Trojan_Ircbot_7c60454d {
    meta:
        author = "Elastic Security"
        id = "7c60454d-8290-4e91-9b0a-2392aebe1bec"
        fingerprint = "4f14dcca5704c2ef32caaed1c048a5fb14095f31be8630676c07cbc8b22e6c4d"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Ircbot"
        reference_sample = "14eeff3516de6d2cb11d6ada4026e3dcee1402940e3a0fb4fa224a5c030049d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 49 89 F0 41 54 55 48 89 CD 53 48 89 FB 48 83 EC 58 48 85 D2 }
    condition:
        all of them
}



// from Linux_Trojan_Iroffer.yar
rule Linux_Trojan_Iroffer_53692410 {
    meta:
        author = "Elastic Security"
        id = "53692410-4213-4550-890e-4c62867937bc"
        fingerprint = "f070ee35ad42d9d30021cc2796cfd2859007201c638f98f42fdbec25c53194fb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 69 6E 67 20 55 6E 6B 6E 6F 77 6E 20 4D 73 67 6C 6F 67 20 54 61 67 }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_013e07de {
    meta:
        author = "Elastic Security"
        id = "013e07de-95bd-4774-a14f-0a10f911a2dd"
        fingerprint = "92dde62076acec29a637b63a35f00c35f706df84d6ee9cabda0c6f63d01a13c4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 49 67 6E 6F 72 69 6E 67 20 42 61 64 20 58 44 43 43 20 4E 6F }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_0de95cab {
    meta:
        author = "Elastic Security"
        id = "0de95cab-c671-44f0-a85e-5a5634e906f7"
        fingerprint = "42c1ab8af313ec3c475535151ee67cac93ab6a25252b52b1e09c166065fb2760"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "717bea3902109d1b1d57e57c26b81442c0705af774139cd73105b2994ab89514"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 41 52 52 45 43 4F 52 44 53 00 53 68 6F 77 20 49 6E 66 6F }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_711259e4 {
    meta:
        author = "Elastic Security"
        id = "711259e4-f081-4d81-8257-60ba733354c5"
        fingerprint = "aca63ef57ab6cb5579a2a5fea6095d88a3a4fb8347353febb3d02cc88a241b78"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "e76508141970efb3e4709bcff83772da9b10169c599e13e58432257a7bb2defa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 7E 2B 8B 45 C8 3D FF 00 00 00 77 21 8B 55 CC 81 FA FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Iroffer_7478ddd9 {
    meta:
        author = "Elastic Security"
        id = "7478ddd9-ebb6-4bd4-a1ad-d0bf8f99ab1d"
        fingerprint = "b497ee116b77e2ba1fedfad90894d956806a2ffa19cadc33a916513199b0a381"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Iroffer"
        reference_sample = "20e1509c23d7ef14b15823e4c56b9a590e70c5b7960a04e94b662fc34152266c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 80 FA 0F 74 10 80 FA 16 74 0B 80 FA 1F 74 06 C6 04 1E 2E 89 }
    condition:
        all of them
}



// from Linux_Trojan_Kaiji.yar
rule Linux_Trojan_Kaiji_253c44de {
    meta:
        author = "Elastic Security"
        id = "253c44de-3f48-49f9-998d-1dec2981108c"
        fingerprint = "f390a16ca4270dc38ce1a52bbdc1ac57155f369a74005ff2a4e46c6d043b869e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "e31eb8880bb084b4c642eba127e64ce99435ea8299a98c183a63a2e6a139d926"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EB 27 0F B6 1C 10 48 8B 74 24 40 48 8B BC 24 90 00 00 00 88 }
    condition:
        all of them
}

rule Linux_Trojan_Kaiji_535f07ac {
    meta:
        author = "Elastic Security"
        id = "535f07ac-d727-4866-aaed-74d297a1092c"
        fingerprint = "8853b2a1d5852e436cab2e3402a5ca13839b3cae6fbb56a74b047234b8c1233b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "28b2993d7c8c1d8dfce9cd2206b4a3971d0705fd797b9fde05211686297f6bb0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 44 24 10 48 8B 4C 24 08 48 83 7C 24 18 00 74 26 C6 44 24 57 00 48 8B 84 24 98 00 }
    condition:
        all of them
}

rule Linux_Trojan_Kaiji_dcf6565e {
    meta:
        author = "Elastic Security"
        id = "dcf6565e-8287-4d78-b103-53cfab192025"
        fingerprint = "381d6b8f6a95800fe0d20039f991ce82317f60aef100487f3786e6c1e63376e1"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "49f3086105bdc160248e66334db00ce37cdc9167a98faac98800b2c97515b6e7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 69 D2 9B 00 00 00 48 C1 EA 20 83 C2 64 48 8B 9C 24 B8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Kaiji_91091be3 {
    meta:
        author = "Elastic Security"
        id = "91091be3-8c9e-4d7a-8ca6-cd422afe0aa5"
        fingerprint = "f583bbef07f41e74ba9646a3e97ef114eb34b1ae820ed499dffaad90db227ca6"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Kaiji"
        reference_sample = "dca574d13fcbd7d244d434fcbca68136e0097fefc5f131bec36e329448f9a202"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 18 83 7C 24 1C 02 75 9E 8B 4C 24 64 8B 51 1C 89 54 24 5C }
    condition:
        all of them
}



// from Linux_Trojan_Kinsing.yar
rule Linux_Trojan_Kinsing_196523fa {
    meta:
        author = "Elastic Security"
        id = "196523fa-2bb5-4ada-b929-ddc3d5505b73"
        fingerprint = "29fa6e4fe5cbcd5c927e6b065f3354e4e9015e65814400687b2361fc9a951c74"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Kinsing"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 65 38 5F 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 35 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_7cdbe9fa {
    meta:
        author = "Elastic Security"
        id = "7cdbe9fa-39a3-43a0-853a-16f41e20f304"
        fingerprint = "2452c2821b4ca104a18d3733ee8f6744a738aca197aa35392c480e224a5f8175"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 2E 72 75 22 20 7C 20 61 77 6B 20 27 7B 70 72 69 6E 74 20 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_2c1ffe78 {
    meta:
        author = "Elastic Security"
        id = "2c1ffe78-a965-4a70-8a9c-2cad705f8be7"
        fingerprint = "6701b007ee14a022525301d53af0f4254bc26fdfbe27d3d5cebc2d40e8536ed6"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 74 73 20 22 24 42 49 4E 5F 46 55 4C 4C 5F 50 41 54 48 22 20 22 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_85276fb4 {
    meta:
        author = "Elastic Security"
        id = "85276fb4-11f4-4265-9533-a96b42247f96"
        fingerprint = "966d53d8fc0e241250a861107317266ad87205d25466a4e6cdb27c3e4e613d92"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 65 5F 76 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 38 48 83 }
    condition:
        all of them
}



// from Linux_Trojan_Ladvix.yar
rule Linux_Trojan_Ladvix_db41f9d2 {
    meta:
        author = "Elastic Security"
        id = "db41f9d2-aa5c-4d26-b8ba-cece44eddca8"
        fingerprint = "d0aaa680e81f44cc555bf7799d33fce66f172563788afb2ad0fb16d3e460e8c6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 49 89 C4 74 45 45 85 ED 7E 26 48 89 C3 41 8D 45 FF 4D 8D 7C }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_77d184fd {
    meta:
        author = "Elastic Security"
        id = "77d184fd-a15e-40e5-ac7e-0d914cc009fe"
        fingerprint = "21361ca7c26c98903626d1167747c6fd11a5ae0d6298d2ef86430ce5be0ecd1a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        reference_sample = "1bb44b567b3c82f7ee0e08b16f7326d1af57efe77d608a96b2df43aab5faa9f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 40 10 48 89 45 80 8B 85 64 FF FF FF 48 89 E2 48 89 D3 48 63 D0 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_c9888edb {
    meta:
        author = "Elastic Security"
        id = "c9888edb-0f82-4c7a-b501-4e4d3c9c64e3"
        fingerprint = "e0e0d75a6de7a11b2391f4a8610a6d7c385df64d43fa1741d7fe14b279e1a29a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        reference_sample = "1d798e9f15645de89d73e2c9d142189d2eaf81f94ecf247876b0b865be081dca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 01 83 45 E4 01 8B 45 E4 83 F8 57 76 B5 83 45 EC 01 8B 45 EC 48 }
    condition:
        all of them
}

rule Linux_Trojan_Ladvix_81fccd74 {
    meta:
        author = "Elastic Security"
        id = "81fccd74-465d-4f2e-b879-987bc47828dd"
        fingerprint = "0e983107f38a6b2a739a44ab4d37c35c5a7d8217713b280a1786511089084a95"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ladvix"
        reference = "2a183f613fca5ec30dfd82c9abf72ab88a2c57d2dd6f6483375913f81aa1c5af"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 EA 00 00 48 8D 45 EA 48 8B 55 F0 0F B6 12 88 10 0F B7 45 EA 0F }
    condition:
        all of them
}



// from Linux_Trojan_Lady.yar
rule Linux_Trojan_Lady_75f6392c {
    meta:
        author = "Elastic Security"
        id = "75f6392c-fc13-4abb-a391-b5f1ea1039d8"
        fingerprint = "da6d4dff230120eed94e04b0e6060713c2bc17da54c098e9a9f3ec7a8200b9bf"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Lady"
        reference_sample = "c257ac7bd3a9639e0d67a7db603d5bc8d8505f6f2107a26c2615c5838cf11826"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 57 72 69 00 49 3B 66 10 76 38 48 83 EC 18 48 89 6C 24 10 48 8D 6C }
    condition:
        all of them
}



// from Linux_Trojan_Lala.yar
rule Linux_Trojan_Lala_51deb1f9 {
    meta:
        author = "Elastic Security"
        id = "51deb1f9-2d5f-4c41-99f3-138c15c35804"
        fingerprint = "220bcaa4f18b9474ddd3da921e1189d17330f0eb98fa55a193127413492fb604"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Lala"
        reference_sample = "f3af65d3307fbdc2e8ce6e1358d1413ebff5eeb5dbedc051394377a4dabffa82"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D9 7C F3 89 D8 83 7D FC 00 7D 02 F7 D8 8B 55 08 }
    condition:
        all of them
}



// from Linux_Trojan_Malxmr.yar
rule Linux_Trojan_Malxmr_7054a0d0 {
    meta:
        author = "Elastic Security"
        id = "7054a0d0-11d4-4671-a88d-ea933e73fe11"
        fingerprint = "9661cc2b7a1d7b882ca39307adc927f5fb73d59f3771a8b456c2cf2ff3d801e9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Malxmr"
        reference_sample = "3a6b3552ffac13aa70e24fef72b69f683ac221105415efb294fb9a2fc81c260a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 64 47 56 7A 64 48 52 6C 63 33 52 30 5A 58 4E 30 64 47 56 }
    condition:
        all of them
}

rule Linux_Trojan_Malxmr_144994a5 {
    meta:
        author = "Elastic Security"
        id = "144994a5-1e37-4913-b7aa-deed638b1a79"
        fingerprint = "473e686a74e76bb879b3e34eb207d966171f3e11cf68bde364316c2ae5cd3dc3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Malxmr"
        reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 71 51 58 5A 5A 4D 31 5A 35 59 6B 4D 78 61 47 4A 58 55 54 4A }
    condition:
        all of them
}



// from Linux_Trojan_Marut.yar
rule Linux_Trojan_Marut_47af730d {
    meta:
        author = "Elastic Security"
        id = "47af730d-1e03-4d27-9661-84fb12b593bd"
        fingerprint = "4429ef9925aff797ab973f9a5b0efc160a516f425e3b024f22e5a5ddad26c341"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Marut"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 89 34 24 FF D1 8B 44 24 0C 0F B6 4C 24 04 8B 54 24 08 85 D2 }
    condition:
        all of them
}



// from Linux_Trojan_Masan.yar
rule Linux_Trojan_Masan_5369c678 {
    meta:
        author = "Elastic Security"
        id = "5369c678-9a74-42fe-a4b3-b4d48126bb22"
        fingerprint = "5fd243bf05cafd7db33d6c0167f77148ae53983906e917e174978130ae08062a"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Masan"
        reference_sample = "f2de9f39ca3910d5b383c245d8ca3c1bdf98e2309553599e0283062e0aeff17f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 E4 83 7D E4 FF 75 ?? 68 ?? 90 04 08 }
    condition:
        all of them
}



// from Linux_Trojan_Mech.yar
rule Linux_Trojan_Mech_d30ec0a0 {
    meta:
        author = "Elastic Security"
        id = "d30ec0a0-3fd6-4d83-ad29-9d45704bc8ce"
        fingerprint = "061e9f1aade510132674d87ab5981e5b6b0ae3a2782a97d8cc6c2be7b26c6454"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mech"
        reference_sample = "710d1a0a8c7eecc6d793933c8a97cec66d284b3687efee7655a2dc31d15c0593"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6E 63 20 2D 20 4C 69 6E 75 78 20 32 2E 32 2E 31 }
    condition:
        all of them
}



// from Linux_Trojan_Mechbot.yar
rule Linux_Trojan_Mechbot_f2e1c5aa {
    meta:
        author = "Elastic Security"
        id = "f2e1c5aa-3318-4665-bee4-34a4afcf60bd"
        fingerprint = "4b663b0756f2ae9b43eae29cd0225ad75517ef345982e8fdafa61f3c3db2d9f5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mechbot"
        reference_sample = "5f8e80e6877ff2de09a12135ee1fc17bee8eb6d811a65495bcbcddf14ecb44a3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 52 56 45 52 00 42 41 4E 4C 49 53 54 00 42 4F 4F 54 00 42 }
    condition:
        all of them
}



// from Linux_Trojan_Melofee.yar
rule Linux_Trojan_Melofee_c23d18f3 {
    meta:
        author = "Elastic Security"
        id = "c23d18f3-caac-4d8a-8ecd-d1b831723648"
        fingerprint = "95bd1092104aa028b65b92d3dcf6af6deb019d00ef09e9c6570da39737fe3525"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Trojan.Melofee"
        reference_sample = "b0abf6691e769ead1f11cfdcd300f8cd5291f19059be6bb40d556f793b1bc21e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "hide ok"
        $str2 = "show ok"
        $str3 = "kill ok"
        $str4 = "wwwwwww"
        $str5 = "[md]"
        $str6 = "87JoENDi"
    condition:
        4 of them
}



// from Linux_Trojan_Merlin.yar
rule Linux_Trojan_Merlin_55beddd3 {
    meta:
        author = "Elastic Security"
        id = "55beddd3-735b-4e0c-a387-e6a981cd42a3"
        fingerprint = "54e03337930d74568a91e797cfda3b7bfbce3aad29be2543ed58c51728d8e185"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "15ccdf2b948fe6bd3d3a7f5370e72cf3badec83f0ec7f47cdf116990fb551adf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }
    condition:
        all of them
}

rule Linux_Trojan_Merlin_bbad69b8 {
    meta:
        author = "Elastic Security"
        id = "bbad69b8-e8fc-43ce-a620-793c059536fd"
        fingerprint = "594f385556978ef1029755cea53c3cf89ff4d6697be8769fe1977b14bbdb46d1"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DA 31 C0 BB 1F 00 00 00 EB 12 0F B6 3C 13 40 88 3C 02 40 88 }
    condition:
        all of them
}

rule Linux_Trojan_Merlin_c6097296 {
    meta:
        author = "Elastic Security"
        id = "c6097296-c518-4541-99b2-e2f6d3e4610b"
        fingerprint = "8496ec66e276304108184db36add64936500f1f0dd74120e03b78c64ac7b5ba1"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Merlin"
        reference_sample = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 38 48 89 5C 24 48 48 85 C9 75 62 48 85 D2 75 30 48 89 9C 24 C8 00 }
    condition:
        all of them
}



// from Linux_Trojan_Metasploit.yar
rule Linux_Trojan_Metasploit_69e20012 {
    meta:
        author = "Elastic Security"
        id = "69e20012-4f5d-42ce-9913-8bf793d2a695"
        fingerprint = "263efec478e54c025ed35bba18a0678ceba36c90f42ccca825f2ba1202e58248"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "debb5d12c1b876f47a0057aad19b897c21f17de7b02c0e42f4cce478970f0120"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $mmap = { 31 FF 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A 6A 07 5A 0F 05 48 85 C0 78 }
        $socket = { 41 59 50 6A 29 58 99 6A 02 5F 6A 01 5E [0-6] 0F 05 48 85 C0 78 }
        $connect = { 51 48 89 E6 6A 10 5A 6A 2A 58 0F 05 59 48 85 C0 79 }
        $failure_handler = { 57 6A 23 58 6A 00 6A 05 48 89 E7 48 31 F6 0F 05 59 59 5F 48 85 C0 79 }
        $exit = { 6A 3C 58 6A 01 5F 0F 05 }
        $receive = { 5A 0F 05 48 85 C0 78 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_0c629849 {
    meta:
        author = "Elastic Security"
        id = "0c629849-8127-4fec-a225-da29bf41435e"
        fingerprint = "3e98ffa46e438421056bf4424382baa6fbe30e5fc16dbd227bceb834873dbe41"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "ad070542729f3c80d6a981b351095ab8ac836b89a5c788dff367760a2d8b1dbb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $socket_call = { 6A 29 58 6A 0A 5F 6A 01 5E 31 D2 0F 05 50 5F }
        $populate_sockaddr_in6 = { 99 52 52 52 66 68 }
        $calls = { 6A 31 58 6A 1C 5A 0F 05 6A 32 58 6A 01 5E 0F 05 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 }
        $dup2 = { 48 97 6A 03 5E 6A 21 58 FF CE 0F 05 E0 F7 }
        $exec_call = { 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 54 5F 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_849cc5d5 {
    meta:
        author = "Elastic Security"
        id = "849cc5d5-737a-4ea4-9bb6-cec26b132ff2"
        fingerprint = "859638998983b9dc0cffc204985b2c4db8a4fb2a97ff4e791fd6762ff6b1f5da"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "42d734dbd33295bd68e5a545a29303a2104a5a92e5fee31d645e2a6410cc03e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $init1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $init2 = { 6A 10 5A 6A ?? 58 0F }
        $shell1 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
        $shell2 = { 48 96 6A 2B 58 0F 05 50 56 5F 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 97 5F 0F 05 FF E6 }
    condition:
        all of ($init*) and 1 of ($shell*)
}

rule Linux_Trojan_Metasploit_da378432 {
    meta:
        author = "Elastic Security"
        id = "da378432-d549-4ba8-9e33-a0d0656fc032"
        fingerprint = "db6e226c18211d845c3495bb39472646e64842d4e4dd02d9aad29178fd22ea95"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "277499da700e0dbe27269c7cfb1fc385313c4483912a9a3f0c15adba33ecd0bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $str2 = { 6A 10 5A 6A ?? 58 0F }
        $str3 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_b957e45d {
    meta:
        author = "Elastic Security"
        id = "b957e45d-0eb6-4580-af84-98608bbc34ef"
        fingerprint = "ac71352e2b4c8ee8917b1469cd33e6b54eb4cdcd96f02414465127c5cad6b710"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom nonx TCP reverse shells"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "78af84bad4934283024f4bf72dfbf9cc081d2b92a9de32cc36e1289131c783ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 43 53 6A 02 6A 66 58 89 E1 CD 80 97 5B }
        $str2 = { 66 53 89 E1 6A 66 58 50 51 57 89 E1 43 CD 80 5B 99 B6 0C B0 03 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_1a98f2e2 {
    meta:
        author = "Elastic Security"
        id = "1a98f2e2-9354-4d04-b1c0-d3998e54e2c4"
        fingerprint = "b9865aad13b4d837e7541fe6a501405aa7d694c8fefd96633c0239031ebec17a"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom nonx TCP bind shells"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "89be4507c9c24c4ec9a7282f197a9a6819e696d2832df81f7e544095d048fc22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 43 53 6A 02 6A 66 58 99 89 E1 CD 80 96 43 52 }
        $str2 = { 66 53 89 E1 6A 66 58 50 51 56 89 E1 CD 80 B0 66 D1 E3 CD 80 52 52 56 43 89 E1 B0 66 CD 80 93 B6 0C B0 03 CD 80 89 DF }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_d74153f6 {
    meta:
        author = "Elastic Security"
        id = "d74153f6-0047-4576-8c3e-db0525bb3a92"
        fingerprint = "824baa1ee7fda8074d76e167d3c5cc1911c7224bb72b1add5e360f26689b48c2"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom IPv6 TCP reverse shells"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "2823d27492e2e7a95b67a08cb269eb6f4175451d58b098ae429330913397d40a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 43 53 6A 0A 89 E1 6A 66 58 CD 80 96 99 }
        $str2 = { 89 E1 6A 1C 51 56 89 E1 43 43 6A 66 58 CD 80 89 F3 B6 0C B0 03 CD 80 89 DF }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_f7a31e87 {
    meta:
        author = "Elastic Security"
        id = "f7a31e87-c3d7-4a26-9879-68893780283e"
        fingerprint = "7171cb9989405be295479275d8824ced7e3616097db88e3b0f8f1ef6798607e2"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom shell find tag payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "82b55d8c0f0175d02399aaf88ad9e92e2e37ef27d52c7f71271f3516ba884847"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $setup = { 31 DB 53 89 E6 6A 40 B7 0A 53 56 53 89 E1 86 FB 66 FF 01 6A 66 58 CD 80 81 3E }
        $payload1 = { 5F FC AD FF }
        $payload2 = { 5F 89 FB 6A 02 59 6A 3F 58 CD 80 49 79 ?? 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80 }
    condition:
        $setup and 1 of ($payload*)
}

rule Linux_Trojan_Metasploit_b0d2d4a4 {
    meta:
        author = "Elastic Security"
        id = "b0d2d4a4-4fd6-4fc0-959b-89d6969215ed"
        fingerprint = "f6d2e001d8cfb6f086327ddb457a964932a8200ff60ea973b26ac9fb909b4a9c"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom shell find port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "a37c888875e84069763303476f0df6769df6015b33aded59fc1e23eb604f2163"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 89 E7 6A 10 54 57 53 89 E1 B3 07 FF 01 6A 66 58 CD 80 }
        $str2 = { 5B 6A 02 59 B0 3F CD 80 49 }
        $str3 = { 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 99 B0 0B CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_5d26689f {
    meta:
        author = "Elastic Security"
        id = "5d26689f-3d3a-41f1-ac32-161b3b312b74"
        fingerprint = "b78fda9794dc24507405fc04bdc0a3e8abfcdc5c757787b7d9822f4ea2190120"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom bind TCP random port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "dafefb4d79d848384442a697b1316d93fef2741fca854be744896ce1d7f82073"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $tiny_bind = { 31 D2 52 68 2F 2F 73 68 68 2F 62 69 6E 68 2D 6C 65 2F 89 E7 52 68 2F 2F 6E 63 68 2F 62 69 6E 89 E3 52 57 53 89 E1 31 C0 B0 0B CD 80 }
        $reg_bind_setup = { 31 DB F7 E3 B0 66 43 52 53 6A 02 89 E1 CD 80 52 50 89 E1 B0 66 B3 04 CD 80 B0 66 43 CD 80 59 93 }
        $reg_bind_dup_loop = { 6A 3F 58 CD 80 49 79 }
        $reg_bind_execve = { B0 0B 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 41 CD 80 }
    condition:
        ($tiny_bind) or (all of ($reg_bind*))
}

rule Linux_Trojan_Metasploit_1c8c98ae {
    meta:
        author = "Elastic Security"
        id = "1c8c98ae-46c8-45fe-ab42-7b053f0357ed"
        fingerprint = "a3b592cc6d9b00f76a1084c7c124cc199149ada5b8dc206cff3133718f045c9d"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom add user payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "1a2c40531584ed485f3ff532f4269241a76ff171956d03e4f0d3f9c950f186d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 C9 89 CB 6A 46 58 CD 80 6A 05 58 31 C9 51 68 73 73 77 64 68 2F 2F 70 61 68 2F 65 74 63 89 E3 41 B5 04 CD 80 93 }
        $str2 = { 59 8B 51 FC 6A 04 58 CD 80 6A 01 58 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_47f4b334 {
    meta:
        author = "Elastic Security"
        id = "47f4b334-619b-4b9c-841d-b00c09dd98e5"
        fingerprint = "955d65f1097ec9183db8bd3da43090f579a27461ba345bb74f62426734731184"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom exec payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "c3821f63a7ec8861a6168b4bb494bf8cbac436b3abf5eaffbc6907fd68ebedb8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $payload1 = { 31 C9 F7 E1 B0 0B [0-1] 68 2F ?? ?? ?? 68 2F 62 69 6E 89 E3 CD 80 }
        $payload2a = { 31 DB F7 E3 B0 0B 52 }
        $payload2b = { 88 14 1E 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 56 57 53 89 E1 CD 80 }
        $payload3a = { 6A 0B 58 99 52 }
        $payload3b = { 89 E7 68 2F 73 68 00 68 2F 62 69 6E 89 E3 52 E8 }
        $payload3c = { 57 53 89 E1 CD 80 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_0b014e0e {
    meta:
        author = "Elastic Security"
        id = "0b014e0e-3f5a-4dcc-8860-eb101281b8a5"
        fingerprint = "7a61a0e169bf6aa8760b42c5b260dee453ea6a85fe9e5da46fb7598994904747"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom exec payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "a24443331508cc72b3391353f91cd009cafcc223ac5939eab12faf57447e3162"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $payload1 = { 48 B8 2F [0-1] 62 69 6E 2F 73 68 ?? ?? 50 54 5F 52 5E 6A 3B 58 0F 05 }
        $payload2a = { 48 B8 2F 2F 62 69 6E 2F 73 68 99 EB ?? 5D 52 5B }
        $payload2b = { 54 5E 52 50 54 5F 52 55 56 57 54 5E 6A 3B 58 0F 05 }
        $payload3a = { 48 B8 2F 62 69 6E 2F 73 68 00 99 50 54 5F 52 }
        $payload3b = { 54 5E 52 E8 }
        $payload3c = { 56 57 54 5E 6A 3B 58 0F 05 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_ccc99be1 {
    meta:
        author = "Elastic Security"
        id = "ccc99be1-6ea9-4090-acba-3bbe82b127c1"
        fingerprint = "88e30402974b853e5f83a3033129d99e7dd1f6b31b5855b1602ef2659a0f7f56"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom pingback bind shell payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "0e9f52d7aa6bff33bfbdba6513d402db3913d4036a5e1c1c83f4ccd5cc8107c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 56 50 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 85 C0 }
        $str2 = { 51 48 89 E6 54 5E 6A 31 58 6A 10 5A 0F 05 6A 32 58 6A 01 5E 0F 05 }
        $str3 = { 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 48 97 }
        $str4 = { 5E 48 31 C0 48 FF C0 0F 05 6A 3C 58 6A 01 5F 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_ed4b2c85 {
    meta:
        author = "Elastic Security"
        id = "ed4b2c85-730f-4a77-97ed-5439a0493a4a"
        fingerprint = "c38513fa6b1ed23ec91ae316af9793c5c01ac94b43ba5502f9c32a0854aec96f"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom bind TCP random port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "0709a60149ca110f6e016a257f9ac35c6f64f50cfbd71075c4ca8bfe843c3211"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str = { 6A 29 58 99 6A 01 5E 6A 02 5F 0F 05 97 B0 32 0F 05 96 B0 2B 0F 05 97 96 FF CE 6A 21 58 0F 05 75 ?? 52 48 BF 2F 2F 62 69 6E 2F 73 68 57 54 5F B0 3B 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_2b0ad6f0 {
    meta:
        author = "Elastic Security"
        id = "2b0ad6f0-44d2-4e7e-8cca-2b0ae1b88d48"
        fingerprint = "b15da42f957107d54bfad78eff3a703cc2a54afcef8207d42292f2520690d585"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom find TCP port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "aa2bce61511c72ac03562b5178aad57bce8b46916160689ed07693790cbfbeec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 48 31 FF 48 31 DB B3 18 48 29 DC 48 8D 14 24 48 C7 02 10 00 00 00 48 8D 74 24 08 6A 34 58 0F 05 48 FF C7 }
        $str2 = { 48 FF CF 6A 02 5E 6A 21 58 0F 05 48 FF CE 79 }
        $str3 = { 48 89 F3 BB 41 2F 73 68 B8 2F 62 69 6E 48 C1 EB 08 48 C1 E3 20 48 09 D8 50 48 89 E7 48 31 F6 48 89 F2 6A 3B 58 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_bf205d5a {
    meta:
        author = "Elastic Security"
        id = "bf205d5a-2bba-497a-8d40-58422e91fe45"
        fingerprint = "91ac22c6302de26717f0666c59fa3765144df2d22d0c3a311a106bc1d9d2ae70"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom bind IPv6 TCP shell payloads "
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "2162a89f70edd7a7f93f8972c6a13782fb466cdada41f255f0511730ec20d037"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 6A 7D 58 99 B2 07 B9 00 10 00 00 89 E3 66 81 E3 00 F0 CD 80 31 DB F7 E3 53 43 53 6A ?? 89 E1 B0 66 CD 80 }
        $str2 = { 51 6A 04 54 6A 02 6A 01 50 }
        $str3 = { 6A 0E 5B 6A 66 58 CD 80 89 F8 83 C4 14 59 5B 5E }
        $str4 = { CD 80 93 B6 0C B0 03 CD 80 87 DF 5B B0 06 CD 80 }
        $ipv6 = { 6A 02 5B 52 52 52 52 52 52 ?? ?? ?? ?? ?? 89 E1 6A 1C }
        $socket = { 51 50 89 E1 6A 66 58 CD 80 D1 E3 B0 66 CD 80 57 43 B0 66 89 51 04 CD 80 }
    condition:
        3 of ($str*) and $ipv6 and $socket
}

rule Linux_Trojan_Metasploit_e5b61173 {
    meta:
        author = "Elastic Security"
        id = "e5b61173-cf1c-4176-bc43-550c0213ce98"
        fingerprint = "7052cce595dbbf36aed5e1edab12a75f06059e6267c859516011d8feb9e328e6"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom stageless TCP reverse shell payload"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "8032a7a320102c8e038db16d51b8615ee49f04dab1444326463f75ce0c5947a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 93 59 B0 3F CD 80 49 79 }
        $str2 = { 89 E1 B0 66 50 51 53 B3 03 89 E1 CD 80 52 }
        $str3 = { 89 E3 52 53 89 E1 B0 0B CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_dd5fd075 {
    meta:
        author = "Elastic Security"
        id = "dd5fd075-bd52-47a9-b737-e55ab10a071d"
        fingerprint = "df2a4f90ec3227555671136c18931118fc9df32340d87aeb3f3fa7fdf2ba6179"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom TCP bind shell payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "b47132a92b66c32c88f39fe36d0287c6b864043273939116225235d4c5b4043a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 5B 5E 52 }
        $str2 = { 6A 10 51 50 89 E1 6A 66 58 CD 80 89 41 04 B3 04 B0 66 CD 80 43 B0 66 CD 80 93 59 }
        $str3 = { 6A 3F 58 CD 80 49 79 F8 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 B0 0B CD 80 }
    condition:
        all of them
}



// from Linux_Trojan_Meterpreter.yar
rule Linux_Trojan_Meterpreter_a82f5d21 {
    meta:
        author = "Elastic Security"
        id = "a82f5d21-3b01-4a05-a34a-6985c1f3b460"
        fingerprint = "b0adb928731dc489a615fa86e46cc19de05e251eef2e02eb02f478ed1ca01ec5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 02 74 22 77 08 66 83 F8 01 74 20 EB 24 66 83 F8 03 74 0C 66 83 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_383c6708 {
    meta:
        author = "Elastic Security"
        id = "383c6708-0861-4089-93c3-4320bc1e7cfc"
        fingerprint = "6e9da04c91b5846b3b1109f9d907d9afa917fb7dfe9f77780e745d17b799b540"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Meterpreter"
        reference_sample = "d9d607f0bbc101f7f6dc0f16328bdd8f6ddb8ae83107b7eee34e1cc02072cb15"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_621054fe {
    meta:
        author = "Elastic Security"
        id = "621054fe-bbdf-445c-a503-ccba82b88243"
        fingerprint = "13cb03783b1d5f14cadfaa9b938646d5edb30ea83702991a81cc4ca82e4637dc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 28 85 D2 75 0A 8B 50 2C 83 C8 FF 85 D2 74 03 8B 42 64 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Meterpreter_1bda891e {
    meta:
        author = "Elastic Security"
        id = "1bda891e-a031-4254-9d0b-dc590023d436"
        fingerprint = "fc3f5afb9b90bbf3b61f144f90b02ff712f60fbf62fb0c79c5eaa808627aa0a1"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Meterpreter"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 11 62 08 F2 0F 5E D0 F2 0F 58 CB F2 0F 11 5A 10 F2 44 0F 5E C0 F2 0F }
    condition:
        all of them
}



// from Linux_Trojan_Mettle.yar
rule Linux_Trojan_Mettle_e8fdbcbd {
    meta:
        author = "Elastic Security"
        id = "e8fdbcbd-84d3-4c42-986b-c8d5d940a96a"
        fingerprint = "2038686308a77286ed5d13b408962075933da7ca5772d46b65e5f247193036b5"
        creation_date = "2024-05-06"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Mettle"
        reference_sample = "864eae4f27648b8a9d9b0eb1894169aa739311cdd02b1435a34881acf7059d58"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $mettle1 = "mettlesploit!"
        $mettle2 = "/mettle/mettle/src/"
        $mettle3 = "mettle_get_c2"
        $mettle4 = "mettle_console_start_interactive"
        $mettle5 = "mettle_get_machine_id"
    condition:
        2 of ($mettle*)
}

rule Linux_Trojan_Mettle_813b9b6c {
    meta:
        author = "Elastic Security"
        id = "813b9b6c-946d-46f0-a255-d06ab78347d4"
        fingerprint = "6b350abfda820ee4c6e7aa84f732ab4527c454b93ae13363747f024bb8c5e3b4"
        creation_date = "2024-05-06"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Mettle"
        reference_sample = "bb651d974ca3f349858db7b5a86f03a8d47d668294f27e709a823fa11e6963d7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $process_set_nonblocking_stdio = { 55 89 E5 53 83 EC 08 E8 ?? ?? ?? ?? 81 C3 3D 32 0D 00 6A 00 6A 03 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 6A 03 6A 01 E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 6A 01 E8 }
        $process_create = { 55 89 E5 57 56 53 81 EC 98 00 00 00 E8 ?? ?? ?? ?? 81 C3 A6 3B 0D 00 89 45 84 89 95 78 FF FF FF 89 4D 80 8B 7D 0C 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 10 40 0F ?? ?? ?? ?? ?? 50 50 68 B4 00 00 00 6A 01 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F ?? ?? ?? ?? ?? F6 47 14 80 74 ?? 6A 00 6A 00 6A 00 8D 45 ?? 50 E8 ?? ?? ?? ?? 89 85 7C FF FF FF }
        $process_read = { 55 89 E5 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 81 C3 90 30 0D 00 8B 4D 08 8B 7D 0C 8B 75 10 83 C8 FF 85 C9 74 ?? 52 56 57 FF 71 24 89 4D E4 E8 ?? ?? ?? ?? 89 C2 83 C4 10 39 C6 8B 4D E4 76 ?? 50 29 D6 56 01 D7 89 55 E4 57 FF 71 48 E8 ?? ?? ?? ?? 8B 55 E4 01 C2 83 C4 10 89 D0 8D 65 ?? 5B 5E 5F 5D C3 }
        $file_new = { 83 C4 10 52 52 50 FF 76 0C E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 8D 65 ?? 5B 5E 5F 5D C3 }
        $file_read = { 55 89 E5 53 83 EC 10 E8 ?? ?? ?? ?? 81 C3 41 A7 0D 00 FF 75 08 E8 ?? ?? ?? ?? 50 FF 75 10 6A 01 FF 75 0C E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
        $file_seek = { 55 89 E5 53 83 EC 10 E8 ?? ?? ?? ?? 81 C3 C0 A6 0D 00 FF 75 08 E8 ?? ?? ?? ?? 83 C4 0C FF 75 10 FF 75 0C 50 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
        $func_write_audio_file = { 55 89 E5 57 56 53 83 EC 18 E8 ?? ?? ?? ?? 81 C3 D8 23 0D 00 FF 75 08 E8 ?? ?? ?? ?? 89 C6 8B 45 10 03 06 89 06 5A 59 50 FF 76 04 E8 ?? ?? ?? ?? 89 C7 89 46 04 83 C4 10 83 C8 FF 85 FF 74 ?? 2B 7D 10 8B 06 01 F8 89 C7 8B 75 0C 8B 4D 10 F3 ?? 8B 45 10 8D 65 ?? 5B 5E 5F 5D C3 }
        $func_is_compatible_elf = { 55 89 E5 56 53 E8 ?? ?? ?? ?? 81 C3 CF AB 05 00 8B 55 08 31 C0 81 3A 7F 45 4C 46 75 ?? 80 7A 04 01 75 ?? 0F B6 72 05 83 EC 0C 6A 01 E8 ?? ?? ?? ?? 83 C4 10 48 0F 94 C0 0F B6 C0 40 39 C6 0F 94 C0 0F B6 C0 83 E0 01 8D 65 ?? 5B 5E 5D C3 }
        $func_stack_setup = { 89 DA 31 C0 8B 0C 86 85 C9 8D 40 ?? 74 ?? 89 0A 83 C2 04 EB ?? C7 02 00 00 00 00 C7 04 83 00 00 00 00 EB ?? 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 8B 45 DC 89 45 10 8B 45 E0 89 45 0C 89 5D 08 8D 65 ?? 5B 5E 5F 5D }
        $func_c2_new_struct = { C7 46 14 00 00 00 00 C7 46 10 00 00 00 00 C7 46 18 00 00 00 00 8D 83 ?? ?? ?? ?? 89 46 20 C7 46 24 00 00 00 00 C7 46 28 00 00 00 00 C7 46 2C 00 00 00 00 C7 46 30 00 00 F0 3F 89 76 1C 83 EC 0C 56 E8 }
    condition:
        2 of ($process*) and 2 of ($file*) and 2 of ($func*)
}

rule Linux_Trojan_Mettle_78aead1c {
    meta:
        author = "Elastic Security"
        id = "78aead1c-7dc2-4db0-a0b8-cccf2d583c67"
        fingerprint = "bf2b8bd0e12905ab4bed94c70dbd854a482446909ba255fceaee309efd69b835"
        creation_date = "2024-05-06"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Mettle"
        reference_sample = "864eae4f27648b8a9d9b0eb1894169aa739311cdd02b1435a34881acf7059d58"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $process_set_nonblocking_stdio = { 48 83 EC 08 31 D2 BE 03 00 00 00 31 FF 31 C0 E8 ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 31 FF 89 C2 31 C0 E8 ?? ?? ?? ?? 31 D2 BE 03 00 00 00 BF 01 00 00 00 31 C0 E8 ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 BF 01 00 00 00 89 C2 31 C0 E8 }
        $process_create = { 41 57 41 56 49 89 CE 41 55 41 54 4D 89 C5 55 53 48 89 FB 48 89 D5 48 81 EC 88 00 00 00 48 8D ?? ?? ?? 48 89 34 24 E8 ?? ?? ?? ?? FF C0 0F ?? ?? ?? ?? ?? BE 20 01 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C7 0F ?? ?? ?? ?? ?? 41 F6 45 28 80 74 ?? 48 8D ?? ?? ?? 31 C9 31 D2 31 F6 E8 ?? ?? ?? ?? 85 C0 }
        $process_read = { 48 85 FF 74 ?? 41 55 41 54 49 89 FD 55 53 48 89 D5 49 89 F4 48 83 EC 08 48 8B 7F 38 E8 ?? ?? ?? ?? 48 39 C5 48 89 C3 76 ?? 49 8B 7D 70 48 89 EA 49 8D ?? ?? 48 29 C2 E8 ?? ?? ?? ?? 48 01 C3 5A 48 89 D8 5B 5D 41 5C 41 5D C3 }
        $file_new = { 41 54 55 48 89 F5 53 48 89 FB 48 8B 7F 10 BE B2 04 01 00 E8 ?? ?? ?? ?? 48 8B 7B 10 BE B3 04 01 00 49 89 C4 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 48 8D ?? ?? ?? ?? ?? 48 89 C6 4C 89 E7 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 ?? 48 89 C6 48 89 EF E8 ?? ?? ?? ?? 31 D2 5B 89 D0 5D 41 5C C3 }
        $file_read = { 53 48 89 F3 48 83 EC 10 48 89 54 24 08 E8 ?? ?? ?? ?? 48 8B 54 24 08 48 83 C4 10 48 89 DF 5B 48 89 C1 BE 01 00 00 00 E9 }
        $file_seek = { 48 83 EC 18 48 89 74 24 08 89 54 24 04 E8 ?? ?? ?? ?? 8B 54 24 04 48 8B 74 24 08 48 89 C7 48 83 C4 18 E9 }
        $func_write_audio_file = { 41 54 55 49 89 F4 53 48 89 D3 E8 ?? ?? ?? ?? 48 8B 30 48 8B 78 08 48 89 C5 48 01 DE 48 89 30 E8 ?? ?? ?? ?? 48 89 C7 48 89 45 08 48 83 C8 FF 48 85 FF 74 ?? 48 8B 45 00 48 29 DF 4C 89 E6 48 89 D9 48 01 F8 48 89 C7 48 89 D8 F3 ?? 5B 5D 41 5C C3 }
        $func_is_compatible_elf = { 31 C0 81 3F 7F 45 4C 46 75 ?? 80 7F 04 02 75 ?? 53 0F B6 5F 05 BF 01 00 00 00 E8 ?? ?? ?? ?? FF C8 0F 94 C0 0F B6 C0 FF C0 39 C3 0F 94 C0 0F B6 C0 83 E0 01 5B C3 83 E0 01 C3 }
        $func_stack_setup = { 48 89 EA 31 C0 49 8B 0C C0 48 FF C0 48 85 C9 74 ?? 48 89 0A 48 83 C2 08 EB ?? 48 C7 02 00 00 00 00 48 C7 44 C5 00 00 00 00 00 EB ?? 48 89 EF 4C 89 4C 24 08 E8 ?? ?? ?? ?? 4C 8B 4C 24 08 48 83 C4 10 48 89 DA 48 89 EF 5B 5D 41 5C 4C 89 CE }
        $func_c2_new_struct = { 48 89 DF 48 C7 43 20 00 00 00 00 C7 43 28 00 00 00 00 48 C7 43 40 00 00 00 00 48 89 43 38 48 8B 05 D1 BE 09 00 48 89 5B 30 48 89 43 48 E8 }
    condition:
        2 of ($process*) and 2 of ($file*) and 2 of ($func*)
}



// from Linux_Trojan_Mirai.yar
rule Linux_Trojan_Mirai_268aac0b {
    meta:
        author = "Elastic Security"
        id = "268aac0b-c5c7-4035-8381-4e182de91e32"
        fingerprint = "9c581721bf82af7dc6482a2c41af5fb3404e01c82545c7b2b29230f707014781"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 18 0F B7 44 24 20 8B 54 24 1C 83 F9 01 8B 7E 0C 89 04 24 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5f2abe2 {
    meta:
        author = "Elastic Security"
        id = "d5f2abe2-511f-474d-9292-39060bbf6feb"
        fingerprint = "475a1c92c0a938196a5a4bca708b338a62119a2adf36cabf7bc99893fee49f2a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 41 89 FE 40 0F B6 FF 41 55 49 89 F5 BE 08 00 00 00 41 54 41 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1cb033f3 {
    meta:
        author = "Elastic Security"
        id = "1cb033f3-68c1-4fe5-9cd1-b5d066c1d86e"
        fingerprint = "49201ab37ff0b5cdfa9b0b34b6faa170bd25f04df51c24b0b558b7534fecc358"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 EB 06 8A 46 FF 88 47 FF FF CA 48 FF C7 48 FF C6 83 FA FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fa3ad9d0 {
    meta:
        author = "Elastic Security"
        id = "fa3ad9d0-7c55-4621-90fc-6b154c44a67b"
        fingerprint = "fe93a3552b72b107f95cc5a7e59da64fe84d31df833bf36c81d8f31d8d79d7ca"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CB 08 C1 CB 10 66 C1 CB 08 31 C9 8A 4F 14 D3 E8 01 D8 66 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0cb1699c {
    meta:
        author = "Elastic Security"
        id = "0cb1699c-9a08-4885-aa7f-0f1ee2543cac"
        fingerprint = "6e44c68bba8c9fb53ac85080b9ad765579f027cabfea5055a0bb3a85b8671089"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 10 0F B7 02 83 E9 02 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6f021787 {
    meta:
        author = "Elastic Security"
        id = "6f021787-9c2d-4536-bd90-5230c85a8718"
        fingerprint = "33ba39b77e55b1a2624e7846e06b2a820de9a8a581a7eec57e35b3a1636b8b0d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "88183d71359c16d91a3252085ad5a270ad3e196fe431e3019b0810ecfd85ae10"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 D4 66 89 14 01 0F B6 45 D0 48 63 D0 48 89 D0 48 01 C0 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1e0c5ce0 {
    meta:
        author = "Elastic Security"
        id = "1e0c5ce0-3b76-4da4-8bed-2e5036b6ce79"
        fingerprint = "8e45538b59f9c9b8bc49661069044900c8199e487714c715c1b1f970fd528e3b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5b1f95840caebf9721bf318126be27085ec08cf7881ec64a884211a934351c2d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 24 54 31 F6 41 B8 04 00 00 00 BA 03 00 00 00 C7 44 24 54 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_22965a6d {
    meta:
        author = "Elastic Security"
        id = "22965a6d-85d3-4f7c-be4a-581044581b77"
        fingerprint = "a34bcba23cde4a2a49ef8192fa2283ce03c75b2d1d08f1fea477932d4b9f5135"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "09c821aa8977f67878f8769f717c792d69436a951bb5ac06ce5052f46da80a48"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E6 4A 64 2B E4 82 D1 E3 F6 5E 88 34 DA 36 30 CE 4E 83 EC F1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_4032ade1 {
    meta:
        author = "Elastic Security"
        id = "4032ade1-4864-4637-ae73-867cd5fb7378"
        fingerprint = "2b150a6571f5a2475d0b4a2ddb75623d6fa1c861f5385a5c42af24db77573480"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "6150fbbefb916583a0e888dee8ed3df8ec197ba7c04f89fb24f31de50226e688"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 0C 67 56 55 4C 06 87 DE B2 C0 79 AE 88 73 79 0C 7E F8 87 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b14f4c5d {
    meta:
        author = "Elastic Security"
        id = "b14f4c5d-054f-46e6-9fa8-3588f1ef68b7"
        fingerprint = "a70d052918dd2fbc66db241da6438015130f0fb6929229bfe573546fe98da817"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 31 DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 15 66 8B 02 83 E9 02 25 FF FF 00 00 83 C2 02 01 C3 83 F9 01 77 EB 49 75 05 0F BE 02 01 C3 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c8385b81 {
    meta:
        author = "Elastic Security"
        id = "c8385b81-0f5b-41c3-94bb-265ede946a84"
        fingerprint = "dfdbd4dbfe16bcf779adb16352d5e57e3950e449e96c10bf33a91efee7c085e5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "3d27736caccdd3199a14ce29d91b1812d1d597a4fa8472698e6df6ef716f5ce9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D 74 26 00 89 C2 83 ED 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_122ff2e6 {
    meta:
        author = "Elastic Security"
        id = "122ff2e6-56e6-4aa8-a3ec-c19d31eb1f80"
        fingerprint = "3c9ffd7537e30a21eefa6c174f801264b92a85a1bc73e34e6dc9e29f84658348"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c7dd999a033fa3edc1936785b87cd69ce2f5cac5a084ddfaf527a1094e718bc4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 EB 15 89 F0 83 C8 01 EB 03 8B 5B 08 3B 43 04 72 F8 8B 4B 0C 89 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_26cba88c {
    meta:
        author = "Elastic Security"
        id = "26cba88c-7bd4-4fac-b395-04c4745fee43"
        fingerprint = "358dd5d916fec3e1407c490ce0289886985be8fabee49581afbc01dcf941733e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4b4758bff3dcaa5640e340d27abba5c2e2b02c3c4a582374e183986375e49be8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F6 41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_93fc3657 {
    meta:
        author = "Elastic Security"
        id = "93fc3657-fd21-4e93-a728-c084fc0a6a4a"
        fingerprint = "d01a9e85a01fad913ca048b60bda1e5a2762f534e5308132c1d3098ac3f561ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 89 44 24 60 89 D1 31 C0 8B 7C 24 28 FC F3 AB 89 D1 8B 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7c88acbc {
    meta:
        author = "Elastic Security"
        id = "7c88acbc-8b98-4508-ac53-ab8af858660d"
        fingerprint = "e2ef1c60e21f18e54694bcfc874094a941e5f61fa6144c5a0e44548dafa315be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = "[Cobalt][%s][%s][%s][%s]"
    condition:
        all of them
}

rule Linux_Trojan_Mirai_804f8e7c {
    meta:
        author = "Elastic Security"
        id = "804f8e7c-4786-42bc-92e4-c68c24ca530e"
        fingerprint = "1080d8502848d532a0b38861437485d98a41d945acaf3cb676a7a2a2f6793ac6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 ED 81 E1 FF 00 00 00 89 4C 24 58 89 EA C6 46 04 00 C1 FA 1F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a2d2e15a {
    meta:
        author = "Elastic Security"
        id = "a2d2e15a-a2eb-43c6-a43d-094ee9739749"
        fingerprint = "0e57d17f5c0cd876248a32d4c9cbe69b5103899af36e72e4ec3119fa48e68de2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "567c3ce9bbbda760be81c286bfb2252418f551a64ba1189f6c0ec8ec059cee49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 F0 41 83 F8 01 76 5F 44 0F B7 41 10 4C 01 C0 44 8D 42 EE 41 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5946f41b {
    meta:
        author = "Elastic Security"
        id = "5946f41b-594c-4fde-827c-616a99f6fc1b"
        fingerprint = "f28b9b311296fc587eced94ca0d80fc60ee22344e5c38520ab161d9f1273e328"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f0b6bf8a683f8692973ea8291129c9764269a6739650ec3f9ee50d222df0a38a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 59 08 AA 3A 4C D3 6C 2E 6E F7 24 54 32 7C 61 39 65 21 66 74 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_da4aa3b3 {
    meta:
        author = "Elastic Security"
        id = "da4aa3b3-521d-4fde-b1be-c381d28c701c"
        fingerprint = "8b004abc37f47de6e4ed35284c23db0f6617eec037a71ce92c10aa8efc3bdca5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "dbc246032d432318f23a4c1e5b6fcd787df29da3bf418613f588f758dcd80617"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 D0 C1 E0 03 89 C2 8B 45 A0 01 D0 0F B6 40 14 3C 1F 77 65 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_70ef58f1 {
    meta:
        author = "Elastic Security"
        id = "70ef58f1-ac74-4e33-ae03-e68d1d5a4379"
        fingerprint = "c46eac9185e5f396456004d1e0c42b54a9318e0450f797c55703122cfb8fea89"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D0 8B 19 01 D8 0F B6 5C 24 10 30 18 89 D0 8B 19 01 D8 0F B6 5C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ea584243 {
    meta:
        author = "Elastic Security"
        id = "ea584243-6ead-4b96-9a5c-5b5dee12fd57"
        fingerprint = "cbcabf4cba48152b3599570ef84503bfb8486db022a2b10df7544d4384023355"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C 81 FA }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_564b8eda {
    meta:
        author = "Elastic Security"
        id = "564b8eda-6f0e-45b8-bef6-d61b0f090a36"
        fingerprint = "63a9e43902e7db0b7a20498b5a860e36201bacc407e9e336faca0b7cfbc37819"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "ff04921d7bf9ca01ae33a9fc0743dce9ca250e42a33547c5665b1c9a0b5260ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C1 83 FE 01 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7e9f85fb {
    meta:
        author = "Elastic Security"
        id = "7e9f85fb-bfc4-4af6-9315-f6e43fefc4ff"
        fingerprint = "ef420ec934e3fd07d5c154a727ed5c4689648eb9ccef494056fed1dea7aa5f9c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4333e80fd311b28c948bab7fb3f5efb40adda766f1ea4bed96a8db5fe0d80ea1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 50 FF FF FF 0F B6 40 04 3C 07 75 79 48 8B 85 50 FF FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3a85a418 {
    meta:
        author = "Elastic Security"
        id = "3a85a418-2bd9-445a-86cb-657ca7edf566"
        fingerprint = "554aff5770bfe8fdeae94f5f5a0fd7f7786340a95633433d8e686af1c25b8cec"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "86a43b39b157f47ab12e9dc1013b4eec0e1792092d4cef2772a21a9bf4fc518a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 D8 66 C1 C8 08 C1 C8 10 66 C1 C8 08 66 83 7C 24 2C FF 89 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_24c5b7d6 {
    meta:
        author = "Elastic Security"
        id = "24c5b7d6-1aa8-4d8e-9983-c7234f57c3de"
        fingerprint = "3411b624f02dd1c7a0e663f1f119c8d5e47a81892bb7c445b7695c605b0b8ee2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7c2f8ba2d6f1e67d1b4a3a737a449429c322d945d49dafb9e8c66608ab2154c4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 38 1C 80 FA 3E 74 25 80 FA 3A 74 20 80 FA 24 74 1B 80 FA 23 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_99d78950 {
    meta:
        author = "Elastic Security"
        id = "99d78950-ea23-4166-a85a-7a029209f5b1"
        fingerprint = "3008edc4e7a099b64139a77d15ec0e2c3c1b55fc23ab156304571c4d14bc654c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 89 C3 80 BC 04 83 00 00 00 20 0F 94 C0 8D B4 24 83 00 00 00 25 FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3fe3c668 {
    meta:
        author = "Elastic Security"
        id = "3fe3c668-89f4-4601-a167-f41bbd984ae5"
        fingerprint = "2a79caea707eb0ecd740106ea4bed2918e7592c1e5ad6050f6f0992cf31ba5ec"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 84 C0 0F 95 C0 48 FF 45 E8 84 C0 75 E9 8B 45 FC C9 C3 55 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_eedfbfc6 {
    meta:
        author = "Elastic Security"
        id = "eedfbfc6-98a4-4817-a0d6-dcb065307f5c"
        fingerprint = "c79058b4a40630cb4142493062318cdfda881259ac95b70d977816f85b82bb36"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "b7342f7437a3a16805a7a8d4a667e0e018584f9a99591413650e05d21d3e6da6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7C 39 57 52 AC 57 A8 CE A8 8C FC 53 A8 A8 0E 33 C2 AA 38 14 FB 29 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6d96ae91 {
    meta:
        author = "Elastic Security"
        id = "6d96ae91-9d5c-48f1-928b-1562b120a74d"
        fingerprint = "fdbeaae0a96f3950d19aed497fae3e7a5517db141f53a1a6315b38b1d53d678b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "e3a1d92df6fb566e09c389cfb085126d2ea0f51a776ec099afb8913ef5e96f9b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 00 00 C1 00 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d8779a57 {
    meta:
        author = "Elastic Security"
        id = "d8779a57-c6ee-4627-9eb0-ab9305bd2454"
        fingerprint = "6c7a18cc03cacef5186d4c1f6ce05203cf8914c09798e345b41ce0dcee1ca9a6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B6 FF 41 89 D0 85 FF 74 29 38 56 08 74 28 48 83 C6 10 31 D2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3e72e107 {
    meta:
        author = "Elastic Security"
        id = "3e72e107-3647-4afd-a556-3c49dae7eb0c"
        fingerprint = "3bca41fd44e5e9d8cdfb806fbfcaab3cc18baa268985b95e2f6d06ecdb58741a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "57d04035b68950246dd152054e949008dafb810f3705710d09911876cd44aec7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 85 C0 BA FF FF FF FF 74 14 8D 65 F4 5B 5E 5F 89 D0 5D C3 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5c62e6b2 {
    meta:
        author = "Elastic Security"
        id = "5c62e6b2-9f6a-4c6d-b3fc-c6cbc8cf0b4b"
        fingerprint = "39501003c45c89d6a08f71fbf9c442bcc952afc5f1a1eb7b5af2d4b7633698a8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF C1 83 F9 05 7F 14 48 63 C1 48 89 94 C4 00 01 00 00 FF C6 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c5430ff9 {
    meta:
        author = "Elastic Security"
        id = "c5430ff9-af40-4653-94c3-4651a5e9331e"
        fingerprint = "a19dcb00fc5553d41978184cc53ef93c36eb9541ea19c6c50496b4e346aaf240"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5676773882a84d0efc220dd7595c4594bc824cbe3eeddfadc00ac3c8e899aa77"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 FC F3 A6 0F 97 C2 0F 92 C0 38 C2 75 29 83 EC 08 8B }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_402adc45 {
    meta:
        author = "Elastic Security"
        id = "402adc45-6279-44a6-b766-24706b0328fe"
        fingerprint = "01b88411c40abc65c24d7a335027888c0cf48ad190dd3fa1b8e17d086a9b80a0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 EB DF 5A 5B 5D 41 5C 41 5D C3 41 57 41 56 41 55 41 54 55 53 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a39dfaa7 {
    meta:
        author = "Elastic Security"
        id = "a39dfaa7-7d2c-4d40-bea5-bbebad522fa4"
        fingerprint = "95d12cb127c088d55fb0090a1cb0af8e0a02944ff56fd18bcb0834b148c17ad7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 6C 72 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e3e6d768 {
    meta:
        author = "Elastic Security"
        id = "e3e6d768-6510-4eb2-a5ec-8cb8eead13f2"
        fingerprint = "ce11f9c038c31440bcdf7f9d194d1a82be5d283b875cc6170a140c398747ff8c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "b505cb26d3ead5a0ef82d2c87a9b352cc0268ef0571f5e28defca7131065545e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7E 14 48 89 DF 48 63 C8 4C 89 E6 FC F3 A4 41 01 C5 48 89 FB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_520deeb8 {
    meta:
        author = "Elastic Security"
        id = "520deeb8-cbc0-4225-8d23-adba5e040471"
        fingerprint = "f4dfd1d76e07ff875eedfe0ef4f861bee1e4d8e66d68385f602f29cc35e30cca"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { ED 48 89 44 24 30 44 89 6C 24 10 7E 47 48 89 C1 44 89 E8 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_77137320 {
    meta:
        author = "Elastic Security"
        id = "77137320-6c7e-4bb8-81a4-bd422049c309"
        fingerprint = "afeedf7fb287320c70a2889f43bc36a3047528204e1de45c4ac07898187d136b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 01 89 C7 31 F6 31 C9 48 89 A4 24 00 01 00 00 EB 1D 80 7A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a6a81f9c {
    meta:
        author = "Elastic Security"
        id = "a6a81f9c-b43b-4ec3-8b0b-94c1cfee4f08"
        fingerprint = "e1ec5725b75e4bb3eefe34a17ced900a16af9329a07a99f18f88aaef2678bfc1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 57 00 54 43 50 00 47 52 45 00 4B 54 00 73 68 65 6C 6C 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_485c4b13 {
    meta:
        author = "Elastic Security"
        id = "485c4b13-3c7c-47a7-b926-8237cb759ad7"
        fingerprint = "28f3e8982cee2836a59721c88ee0a9159ad6fdfc27c0091927f5286f3a731e9a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7E 1F 8B 4C 24 4C 01 D1 0F B6 11 88 D0 2C 61 3C 19 77 05 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7146e518 {
    meta:
        author = "Elastic Security"
        id = "7146e518-f6f4-425d-bac8-b31edc0ac559"
        fingerprint = "334ef623a8dadd33594e86caca1c95db060361c65bf366bacb9bc3d93ba90c4f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 82 11 79 AF 20 C2 7A 9E 18 6C A9 00 21 E2 6A C6 D5 59 B4 E8 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6a77af0f {
    meta:
        author = "Elastic Security"
        id = "6a77af0f-31fa-4793-82aa-10b065ba1ec0"
        fingerprint = "4e436f509e7e732e3d0326bcbdde555bba0653213ddf31b43cfdfbe16abb0016"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 D1 89 0F 48 83 C7 04 85 F6 7E 3B 44 89 C8 45 89 D1 45 89 C2 41 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_5f7b67b8 {
    meta:
        author = "Elastic Security"
        id = "5f7b67b8-3d7b-48a4-8f03-b6f2c92be92e"
        fingerprint = "6cb5fb0b7c132e9c11ac72da43278025b60810ea3733c9c6d6ca966163185940"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 38 83 CF FF 89 F8 5A 59 5F C3 57 56 83 EC 04 8B 7C 24 10 8B 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a3cedc45 {
    meta:
        author = "Elastic Security"
        id = "a3cedc45-962d-44b5-bf0e-67166fa6c1a4"
        fingerprint = "8335e540adfeacdf8f45c9cb36b08fea7a06017bb69aa264dc29647e7ca4a541"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1ae0cd7e5bac967e31771873b4b41a1887abddfcdfcc76fa9149bb2054b03ca4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 2C 48 8B 03 48 83 E0 FE 48 29 C3 48 8B 43 08 48 83 E0 FE 4A 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_7d05725e {
    meta:
        author = "Elastic Security"
        id = "7d05725e-db59-42a7-99aa-99de79728126"
        fingerprint = "7fcd34cb7c37836a1fa8eb9375a80da01bda0e98c568422255d83c840acc0714"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 97 00 00 00 89 6C 24 08 89 74 24 04 89 14 24 0F B7 C0 89 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fa48b592 {
    meta:
        author = "Elastic Security"
        id = "fa48b592-8d80-45af-a3e4-232695b8f5dd"
        fingerprint = "8838d2752b310dbf7d12f6cf023244aaff4fdf5b55cf1e3b71843210df0fcf88"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c9e33befeec133720b3ba40bb3cd7f636aad80f72f324c5fe65ac7af271c49ee"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 C0 BA 01 00 00 00 B9 01 00 00 00 03 04 24 89 D7 31 D2 F7 F7 0F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b9a9d04b {
    meta:
        author = "Elastic Security"
        id = "b9a9d04b-a997-46c4-b893-e89a3813efd3"
        fingerprint = "874249d8ad391be97466c0259ae020cc0564788a6770bb0f07dd0653721f48b1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = "nexuszetaisacrackaddict"
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d2205527 {
    meta:
        author = "Elastic Security"
        id = "d2205527-0545-462b-b3c9-3bf2bdc44c6c"
        fingerprint = "01d937fe8823e5f4764dea9dfe2d8d789187dcd6592413ea48e13f41943d67fd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "e4f584d1f75f0d7c98b325adc55025304d55907e8eb77b328c007600180d6f06"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CA B8 37 00 00 00 0F 05 48 3D 01 F0 FF FF 73 01 C3 48 C7 C1 C0 FF }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ab073861 {
    meta:
        author = "Elastic Security"
        id = "ab073861-38df-4a39-ab81-8451b6fab30c"
        fingerprint = "37ab5e3ccc9a91c885bff2b1b612efbde06999e83ff5c5cd330bd3a709a831f5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "175444a9c9ca78565de4b2eabe341f51b55e59dec00090574ee0f1875422cbac"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { AC 00 00 00 54 60 00 00 50 E8 4E 0C 00 00 EB 0E 5A 58 59 97 60 8A 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_637f2c04 {
    meta:
        author = "Elastic Security"
        id = "637f2c04-98e4-45aa-b60a-14a96c6cebb7"
        fingerprint = "7af3d573af8b7f8252590a53adda52ecf53bdaf9a86b52ef50702f048e08ba8c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 48 8B 45 E0 0F B6 00 38 C2 0F 95 C0 48 FF 45 E8 48 FF 45 E0 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_aa39fb02 {
    meta:
        author = "Elastic Security"
        id = "aa39fb02-ca7e-4809-ab5d-00e92763f7ec"
        fingerprint = "b136ba6496816ba9737a3eb0e633c28a337511a97505f06e52f37b38599587cb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 DE 8D 40 F1 3C 01 76 D7 80 FA 38 74 D2 80 FA 0A 74 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0bce98a2 {
    meta:
        author = "Elastic Security"
        id = "0bce98a2-113e-41e1-95c9-9e1852b26142"
        fingerprint = "993d0d2e24152d0fb72cc5d5add395bed26671c3935f73386341398b91cb0e6e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1b20df8df7f84ad29d81ccbe276f49a6488c2214077b13da858656c027531c80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4B 52 41 00 46 47 44 43 57 4E 56 00 48 57 43 4C 56 47 41 4A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3a56423b {
    meta:
        author = "Elastic Security"
        id = "3a56423b-c0cf-4483-87e3-552beb40563a"
        fingerprint = "117d6eb47f000c9d475119ca0e6a1b49a91bbbece858758aaa3d7f30d0777d75"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 1C 8B 44 24 20 0F B6 D0 C1 E8 08 89 54 24 24 89 44 24 20 BA 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d18b3463 {
    meta:
        author = "Elastic Security"
        id = "d18b3463-1b5e-49e1-9ae8-1d63a10a1ccc"
        fingerprint = "4b3d3bb65db2cdb768d91c50928081780f206208e952c74f191d8bc481ce19c6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "cd86534d709877ec737ceb016b2a5889d2e3562ffa45a278bc615838c2e9ebc3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DF 77 95 8D 42 FA 3C 01 76 8E 80 FA 0B 74 89 80 FA 15 74 84 80 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_fe721dc5 {
    meta:
        author = "Elastic Security"
        id = "fe721dc5-c2bc-4fa6-bdbc-589c6e033e6b"
        fingerprint = "ab7f571a3a3f6b50b9e120612b3cc34d654fc824429a2971054ca0d078ecb983"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 18 EB E1 57 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_575f5bc8 {
    meta:
        author = "Elastic Security"
        id = "575f5bc8-b848-4db4-a99c-132d4d2bc8a4"
        fingerprint = "58e22a2acd002b07e1b1c546e8dfe9885d5dfd2092d4044630064078038e314f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5A 56 5B 5B 55 42 44 5E 59 52 44 44 00 5E 73 5E 45 52 54 43 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_449937aa {
    meta:
        author = "Elastic Security"
        id = "449937aa-682a-4906-89ab-80d7127e461e"
        fingerprint = "cf2c6b86830099f039b41aeaafbffedfb8294a1124c499e99a11f48a06cd1dfd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "6f27766534445cffb097c7c52db1fca53b2210c1b10b75594f77c34dc8b994fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 5B 72 65 73 6F 6C 76 5D 20 46 6F 75 6E 64 20 49 50 20 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_2e3f67a9 {
    meta:
        author = "Elastic Security"
        id = "2e3f67a9-6fd5-4457-a626-3a9015bdb401"
        fingerprint = "6a06815f3d2e5f1a7a67f4264953dbb2e9d14e5f3486b178da845eab5b922d4f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 83 EC 04 0F B6 74 24 14 8B 5C 24 18 8B 7C 24 20 0F B6 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_01e4a728 {
    meta:
        author = "Elastic Security"
        id = "01e4a728-7c1c-479b-aed0-cb76d64dbb02"
        fingerprint = "d90477364982bdc6cd22079c245d866454475749f762620273091f2fab73c196"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 44 24 23 48 8B 6C 24 28 83 F9 01 4A 8D 14 20 0F B6 02 88 45 08 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_64d5cde2 {
    meta:
        author = "Elastic Security"
        id = "64d5cde2-e4b1-425b-8af3-314a5bf519a9"
        fingerprint = "1a69f91b096816973ce0c2e775bcf2a54734fa8fbbe6ea1ffcf634ce2be41767"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "caf2a8c199156db2f39dbb0a303db56040f615c4410e074ef56be2662752ca9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 35 7E B3 02 00 D0 02 00 00 07 01 00 00 0E 00 00 00 18 03 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0d73971c {
    meta:
        author = "Elastic Security"
        id = "0d73971c-4253-4e7d-b1e1-20b031197f9e"
        fingerprint = "95279bc45936ca867efb30040354c8ff81de31dccda051cfd40b4fb268c228c5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "49c94d184d7e387c3efe34ae6f021e011c3046ae631c9733ab0a230d5fe28ead"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C2 83 EB 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 31 F0 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_82c361d4 {
    meta:
        author = "Elastic Security"
        id = "82c361d4-2adf-48f2-a9be-677676d7451f"
        fingerprint = "a8a4252c6f7006181bdb328d496e0e29522f87e55229147bc6cf4d496f5828fb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f8dbcf0fc52f0c717c8680cb5171a8c6c395f14fd40a2af75efc9ba5684a5b49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 23 CB 67 4C 94 11 6E 75 EC A6 76 98 23 CC 80 CF AE 3E A6 0C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ec591e81 {
    meta:
        author = "Elastic Security"
        id = "ec591e81-8594-4317-89b0-0fb4d43e14c1"
        fingerprint = "fe3d305202ca5376be7103d0b40f746fc26f8e442f8337a1e7c6d658b00fc4aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7d45a4a128c25f317020b5d042ab893e9875b6ff0ef17482b984f5b3fe87e451"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 22 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0eba3f5a {
    meta:
        author = "Elastic Security"
        id = "0eba3f5a-1aa8-4dc8-9f63-01bc4959792a"
        fingerprint = "c0f4f9a93672bce63c9e3cfc389c73922c1c24a2db7728ad7ebc1d69b4db150f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 89 F0 66 89 45 C4 C7 45 DC 01 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e43a8744 {
    meta:
        author = "Elastic Security"
        id = "e43a8744-1c52-4f95-bd16-be6722bc4d1a"
        fingerprint = "e7ead3d1a51f0d7435a6964293a45cb8fadd739afb23dc48c1d81fbc593b23ef"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 23 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_6e8e9257 {
    meta:
        author = "Elastic Security"
        id = "6e8e9257-a6d5-407a-a584-4656816a3ddc"
        fingerprint = "4bad14aebb0b8c7aa414f38866baaf1f4b350b2026735de24bcf2014ff4b0a6a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 83 EC 04 8B 5C 24 18 8B 7C 24 20 8A 44 24 14 8A 54 24 1C 88 54 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ac253e4f {
    meta:
        author = "Elastic Security"
        id = "ac253e4f-b628-4dd0-91f1-f19099286992"
        fingerprint = "e2eee1f72b8c2dbf68e57b721c481a5cd85296e844059decc3548e7a6dc28fea"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 31 C9 EB 0A 6B C1 0A 0F BE D2 8D 4C 02 D0 8A 17 48 FF C7 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_994535c4 {
    meta:
        author = "Elastic Security"
        id = "994535c4-77a6-4cc6-b673-ce120be8d0f4"
        fingerprint = "a3753e29ecf64bef21e062b8dec96ba9066f665919d60976657b0991c55b827b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "376a2771a2a973628e22379b3dbb9a8015c828505bbe18a0c027b5d513c9e90d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 74 07 31 C0 48 FF C3 EB EA FF C0 83 F8 08 75 F4 48 8D 73 03 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_a68e498c {
    meta:
        author = "Elastic Security"
        id = "a68e498c-0768-4321-ab65-42dd6ef85323"
        fingerprint = "951c9dfcba531e5112c872395f6c144c4bc8b71c666d2c7d9d8574a23c163883"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 39 D0 7E 25 8B 4C 24 38 01 D1 8A 11 8D 42 9F 3C 19 77 05 8D }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_88de437f {
    meta:
        author = "Elastic Security"
        id = "88de437f-9c98-4e1d-96c0-7b433c99886a"
        fingerprint = "c19eb595c2b444a809bef8500c20342c9f46694d3018e268833f9b884133a1ea"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 08 8B 4C 24 04 85 D2 74 0D 31 C0 89 F6 C6 04 08 00 40 39 D0 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_95e0056c {
    meta:
        author = "Elastic Security"
        id = "95e0056c-bc07-42cf-89ab-6c0cde3ccc8a"
        fingerprint = "a2550fdd2625f85050cfe53159858207a79e8337412872aaa7b4627b13cb6c94"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "45f67d4c18abc1bad9a9cc6305983abf3234cd955d2177f1a72c146ced50a380"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 50 46 00 13 10 11 16 17 00 57 51 47 50 00 52 43 51 51 00 43 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_b548632d {
    meta:
        author = "Elastic Security"
        id = "b548632d-7916-444a-aa68-4b3e38251905"
        fingerprint = "8b355e9c1150d43f52e6e9e052eda87ba158041f7b645f4f67c32dd549c09f28"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "639d9d6da22e84fb6b6fc676a1c4cfd74a8ed546ce8661500ab2ef971242df07"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 0B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_e0cf29e2 {
    meta:
        author = "Elastic Security"
        id = "e0cf29e2-88d7-4aa4-b60a-c24626f2b246"
        fingerprint = "3f124c3c9f124264dfbbcca1e4b4d7cfcf3274170d4bf8966b6559045873948f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C2 83 FE 01 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1754b331 {
    meta:
        author = "Elastic Security"
        id = "1754b331-5704-43c1-91be-89c7a0dd29a4"
        fingerprint = "35db945d116a4c9264af44a9947a5e831ea655044728dc78770085c7959a678e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "0d89fc59d0de2584af0e4614a1561d1d343faa766edfef27d1ea96790ac7014b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CF 07 66 5F 10 F0 EB 0C 42 0B 2F 0B 0B 43 C1 42 E4 C2 7C 85 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3278f1b8 {
    meta:
        author = "Elastic Security"
        id = "3278f1b8-f208-42c8-a851-d22413f74dea"
        fingerprint = "7e9fc284c9c920ac2752911d6aacbc3c2bf1b053aa35c22d83bab0089290778d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D2 0F B6 C3 C1 E0 10 0F B6 C9 C1 E2 18 09 C2 0F B6 44 24 40 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ab804bb7 {
    meta:
        author = "Elastic Security"
        id = "ab804bb7-57ab-48db-85cc-a6d88de0c84a"
        fingerprint = "b9716aa7be1b0e4c966a25a40521114e33c21c7ec3c4468afc1bf8378dd11932"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "8f0cc764729498b4cb9c5446f1a84cde54e828e913dc78faf537004a7df21b20"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4A 75 05 0F BE 11 01 D0 89 C2 0F B7 C0 C1 FA 10 01 C2 89 D0 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_dca3b9b4 {
    meta:
        author = "Elastic Security"
        id = "dca3b9b4-62f3-41ed-a3b3-80dd0990f8c5"
        fingerprint = "b0471831229be1bcbcf6834e2d1a5b85ed66fb612868c2c207fe009ae2a0e799"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "a839437deba6d30e7a22104561e38f60776729199a96a71da3a88a7c7990246a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 F4 01 8B 45 F4 3B 45 F0 75 11 48 8B 45 F8 48 2B 45 D8 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ae9d0fa6 {
    meta:
        author = "Elastic Security"
        id = "ae9d0fa6-be06-4656-9b13-8edfc0ee9e71"
        fingerprint = "ca2bf2771844bec95563800d19a35dd230413f8eff0bd44c8ab0b4c596f81bfc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 EC 04 8A 44 24 18 8B 5C 24 14 88 44 24 03 8A 44 24 10 25 FF 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_612b407c {
    meta:
        author = "Elastic Security"
        id = "612b407c-fceb-4a19-8905-2f5b822f62cc"
        fingerprint = "c48c26b1052ef832d4d6a106db186bf20c503bdf38392a1661eb2d3c3ec010cd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "7833bc89778461a9f46cc47a78c67dda48b498ee40b09a80a21e67cb70c6add1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 11 B2 73 45 2B 7A 57 E2 F9 77 A2 23 EC 7C 0C 29 FE 3F B2 DE 28 6C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5da717f {
    meta:
        author = "Elastic Security"
        id = "d5da717f-3344-41a8-884e-8944172ea370"
        fingerprint = "c3674075a435ef1cd9e568486daa2960450aa7ffa8e5dbf440a50e01803ea2f3"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 66 83 7C 24 34 FF 66 89 46 2C 0F 85 C2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d33095d4 {
    meta:
        author = "Elastic Security"
        id = "d33095d4-ea02-4588-9852-7493f6781bb4"
        fingerprint = "20c0faab6aef6e0f15fd34f9bd173547f3195c096eb34c4316144b19d2ab1dc4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "72326a3a9160e9481dd6fc87159f7ebf8a358f52bf0c17fbc3df80217d032635"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 66 83 7C 24 54 FF 66 89 46 04 0F 85 CB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_4e2246fb {
    meta:
        author = "Elastic Security"
        id = "4e2246fb-5f9a-4dea-8041-51758920d0b9"
        fingerprint = "23b0cfabc2db26153c02a7dc81e2006b28bfc9667526185b2071b34d2fb073c4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 B8 01 00 00 00 31 DB CD 80 EB FA 8D 8B 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_d5981806 {
    meta:
        author = "Elastic Security"
        id = "d5981806-0db8-4422-ad57-5d1c0f7464c3"
        fingerprint = "b0fd8632505252315ba551bb3680fa8dc51038be17609018bf9d92c3e1c43ede"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "784f2005853b5375efaf3995208e4611b81b8c52f67b6dc139fd9fec7b49d9dc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3F 00 00 66 83 7C 24 38 FF 66 89 46 04 0F 85 EA }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_c6055dc9 {
    meta:
        author = "Elastic Security"
        id = "c6055dc9-316b-478d-9997-1dbf455cafcc"
        fingerprint = "b95f582edf2504089ddd29ef1a0daf30644b364f3d90ede413a2aa777c205070"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "c1718d7fdeef886caa33951e75cbd9139467fa1724605fdf76c8cdb1ec20e024"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 7F 43 80 77 39 CF 7E 09 83 C8 FF 5A 5D 8A 0E }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3b9675fd {
    meta:
        author = "Elastic Security"
        id = "3b9675fd-1fa1-4e15-9472-64cb93315d63"
        fingerprint = "40a154bafa72c5aa0c085ac2b92b5777d1acecfd28d28b15c7229ba5c59435f2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "4ec4bc88156bd51451fdaf0550c21c799c6adacbfc654c8ec634ebca3383bd66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 10 85 C9 75 65 48 8B 8C 24 A0 00 00 00 48 89 48 10 0F B6 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1c0d246d {
    meta:
        author = "Elastic Security"
        id = "1c0d246d-dc23-48d6-accb-1e1db1eba49b"
        fingerprint = "b6b6991e016419b1ddf22822ce76401370471f852866f0da25c7b0f4bec530ee"
        creation_date = "2021-04-13"
        last_modified = "2021-09-16"
        description = "Based off community provided sample"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "211cfe9d158c8a6840a53f2d1db2bf94ae689946fffb791eed3acceef7f0e3dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E7 C0 00 51 78 0F 1B FF 8A 7C 18 27 83 2F 85 2E CB 14 50 2E }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_ad337d2f {
    meta:
        author = "Elastic Security"
        id = "ad337d2f-d4ac-42a7-9d2e-576fe633fa16"
        fingerprint = "67cbcb8288fe319c3b8f961210748f7cea49c2f64fc2f1f55614d7ed97a86238"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference = "012b717909a8b251ec1e0c284b3c795865a32a1f4b79706d2254a4eb289c30a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 75 14 80 78 FF 2F 48 8D 40 FF 0F 94 C2 48 39 D8 77 EB 84 D2 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_88a1b067 {
    meta:
        author = "Elastic Security"
        id = "88a1b067-11d5-4128-b763-2d1747c95eef"
        fingerprint = "b32b42975297aed7cef72668ee272a5cfb753dce7813583f0c3ec91e52f8601f"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference = "1a62db02343edda916cbbf463d8e07ec2ad4509fd0f15a5f6946d0ec6c332dd9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 55 89 E5 0F B6 55 08 0F B6 45 0C C1 E2 18 C1 E0 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_76bbc4ca {
    meta:
        author = "Elastic Security"
        id = "76bbc4ca-e6da-40f7-8ba6-139ec8393f35"
        fingerprint = "4206c56b538eb1dd97e8ba58c5bab6e21ad22a0f8c11a72f82493c619d22d9b7"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mirai"
        reference = "1a9ff86a66d417678c387102932a71fd879972173901c04f3462de0e519c3b51"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 40 2D E9 00 40 A0 E1 28 20 84 E2 0C 00 92 E8 3B F1 FF EB }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_0bfc17bd {
    meta:
        author = "Elastic Security"
        id = "0bfc17bd-49bb-4721-9653-0920b631b1de"
        fingerprint = "d67e4e12e74cbd31037fae52cf7bad8d8d5b4240d79449fa1ebf9a271af008e1"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "1cdd94f2a1cb2b93134646c171d947e325a498f7a13db021e88c05a4cbb68903"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 64 0F CD 48 8D 14 52 41 0F B6 4C D7 14 D3 E8 01 C5 83 7C 24 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_389ee3e9 {
    meta:
        author = "Elastic Security"
        id = "389ee3e9-70c1-4c93-a999-292cf6ff1652"
        fingerprint = "59f2359dc1f41d385d639d157b4cd9fc73d76d8abb7cc09d47632bb4c9a39e6e"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 45 00 EB 2C 8B 4B 04 8B 13 8B 7B 18 8B 01 01 02 8B 02 83 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_cc93863b {
    meta:
        author = "Elastic Security"
        id = "cc93863b-1050-40ba-9d02-5ec9ce6a3a28"
        fingerprint = "f3ecd30f0b511a8e92cfa642409d559e7612c3f57a1659ca46c77aca809a00ac"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 57 8B 44 24 0C 8B 4C 24 10 8B 7C 24 08 F3 AA 8B 44 24 08 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_8aa7b5d3 {
    meta:
        author = "Elastic Security"
        id = "8aa7b5d3-e1eb-4b55-b36a-0d3a242c06e9"
        fingerprint = "02a2c18c362df4b1fceb33f3b605586514ba9a00c7afedf71c04fa54d8146444"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 4C 24 14 8B 74 24 0C 8B 5C 24 10 85 C9 74 0D 31 D2 8A 04 1A 88 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_76908c99 {
    meta:
        author = "Elastic Security"
        id = "76908c99-e350-4dbb-9559-27cbe05f55f9"
        fingerprint = "1741b0c2121e3f73bf7e4f505c4661c95753cbf7e0b7a1106dc4ea4d4dd73d6c"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "533a90959bfb337fd7532fb844501fd568f5f4a49998d5d479daf5dfbd01abb2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 24 F8 48 89 04 24 48 8B C6 48 8B 34 24 48 87 CF 48 8B 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_1538ce1a {
    meta:
        author = "Elastic Security"
        id = "1538ce1a-7078-4be3-bd69-7e692a1237f5"
        fingerprint = "f3d82cae74db83b7a49c5ec04d1a95c3b17ab1b935de24ca5c34e9b99db36803"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 00 00 00 FD 34 FD FD 04 40 FD 04 FD FD 7E 14 FD 78 14 1F 0F }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_07b1f4f6 {
    meta:
        author = "Elastic Security"
        id = "07b1f4f6-9324-48ab-9086-b738fdaf47c3"
        fingerprint = "bebafc3c8e68b36c04dc9af630b81f9d56939818d448759fdd83067e4c97e87a"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FD 08 FD 5C 24 48 66 FD 07 66 FD 44 24 2E 66 FD FD 08 66 FD 47 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_feaa98ff {
    meta:
        author = "Elastic Security"
        id = "feaa98ff-6cd9-40bb-8c4f-ea7c79b272f3"
        fingerprint = "0bc8ba390a11e205624bc8035b1d1e22337a5179a81d354178fa2546c61cdeb0"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2382996a8fd44111376253da227120649a1a94b5c61739e87a4e8acc1130e662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F FD FD FD FD FD FD 7A 03 41 74 5E 42 31 FD FD 6E FD FD FD FD }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_3acd6ed4 {
    meta:
        author = "Elastic Security"
        id = "3acd6ed4-6d62-47af-8d80-d5465abce38a"
        fingerprint = "e787989c37c26d4bb79c235150a08bbf3c4c963e2bc000f9a243a09bbf1f59cb"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "2644447de8befa1b4fe39b2117d49754718a2f230d6d5f977166386aa88e7b84"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E5 7E 44 4C 89 E3 31 FF 48 C1 E3 05 48 03 5D 38 48 89 2B 44 88 }
    condition:
        all of them
}

rule Linux_Trojan_Mirai_eb940856 {
    meta:
        author = "Elastic Security"
        id = "eb940856-60d2-4148-9126-aac79a24828e"
        fingerprint = "01532c6feda3487829ad005232d30fe7dde5e37fd7cecd2bb9586206554c90a7"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Mirai"
        reference_sample = "fbf814c04234fc95b6a288b62fb9513d6bbad2e601b96db14bb65ab153e65fef"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 84 24 80 00 00 00 31 C9 EB 23 48 89 4C 24 38 48 8D 84 24 C8 00 }
    condition:
        all of them
}



// from Linux_Trojan_Mobidash.yar
rule Linux_Trojan_Mobidash_52a15a93 {
    meta:
        author = "Elastic Security"
        id = "52a15a93-0574-44bb-83c9-793558432553"
        fingerprint = "a7ceff3bbd61929ab000d18ffdf2e8d1753ecea123e26cd626e3af64341effe6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 89 CE 41 55 41 54 49 89 F4 55 48 89 D5 53 48 89 FB 48 8B 07 FF 90 F8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_d0ad9c82 {
    meta:
        author = "Elastic Security"
        id = "d0ad9c82-718f-43d1-a764-9be83893f9b8"
        fingerprint = "ef6b2f9383c137eb4adfe0a6322a0e5d71cb4a5712f1be26fe687144933cbbc8"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 48 8D 64 24 F8 48 8B 07 FF 90 F8 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_e2c89606 {
    meta:
        author = "Elastic Security"
        id = "e2c89606-511c-403a-a4eb-d18dc7aca444"
        fingerprint = "91c51f6af18389f2efb0032e0b775df68f34b66795c05623dccb67266c04214b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 13 49 89 C7 4C 89 E6 48 89 DF FF 92 B8 00 00 00 31 C9 4C 89 FA 4C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_82b4e3f3 {
    meta:
        author = "Elastic Security"
        id = "82b4e3f3-a9ba-477c-8eef-6010767be52f"
        fingerprint = "a01f5ba8b3e8e82ff46cb748fd90a103009318a25f8532fb014722c96f0392db"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C6 74 2E 89 44 24 0C 8B 44 24 24 C7 44 24 08 01 00 00 00 89 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_601352dc {
    meta:
        author = "Elastic Security"
        id = "601352dc-13b6-4c3f-a013-c54a50e46820"
        fingerprint = "acfca9259360641018d2bf9ba454fd5b65224361933557e007ab5cfb12186cd7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "5714e130075f4780e025fb3810f58a63e618659ac34d12abe211a1b6f2f80269"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F6 74 14 48 8B BC 24 D0 00 00 00 48 8B 07 48 8B 80 B8 00 00 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_ddca1181 {
    meta:
        author = "Elastic Security"
        id = "ddca1181-91ca-4e5d-953f-be85838d3cb9"
        fingerprint = "c8374ff2a85f90f153bcd2451109a65d3757eb7cef21abef69f7c6a4f214b051"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 84 C0 75 1E 8B 44 24 2C 89 7C 24 04 89 34 24 89 44 24 0C 8B 44 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_65e666c0 {
    meta:
        author = "Elastic Security"
        id = "65e666c0-4eb7-4411-8743-053b6c0ec1d6"
        fingerprint = "92b7de293a7e368d0e92a6e2061e9277e7b285851322357808a04f8c203b20d0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "19f9b5382d3e8e604be321aefd47cb72c2337a170403613b853307c266d065dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 8B 44 24 08 48 89 DF 48 8B 14 24 48 8D 64 24 18 5B 4C 89 E6 48 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_494d5b0f {
    meta:
        author = "Elastic Security"
        id = "494d5b0f-09c7-4fcb-90e9-1efc57c45082"
        fingerprint = "e3316257592dc9654a5e63cf33c862ea1298af7a893e9175e1a15c7aaa595f6a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "7e08df5279f4d22f1f27553946b0dadd60bb8242d522a8dceb45ab7636433c2f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 18 00 00 00 40 04 00 00 01 5B 00 00 00 3A 00 00 00 54 04 00 00 05 A1 00 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_bb4f7f39 {
    meta:
        author = "Elastic Security"
        id = "bb4f7f39-1f1c-4a2d-a480-3e1d2b6967b7"
        fingerprint = "b7e96ff17a19ffcbfc87cdba3f86216271ff01c460ff7564f6af6b40c21a530b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 1F 48 8D 64 24 08 48 89 DF 5B 48 89 EA 4C 89 E1 4C 89 EE 5D }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_8679e1cb {
    meta:
        author = "Elastic Security"
        id = "8679e1cb-407e-4554-8ef5-ece5110735c6"
        fingerprint = "7e517bf9e036410acf696c85bd39c720234b64aab8c5b329920a64f910c72c92"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 1C 89 F0 5B 5E 5F 5D C3 8D 76 00 8B 44 24 34 83 C6 01 8D 7C }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_29b86e6a {
    meta:
        author = "Elastic Security"
        id = "29b86e6a-fcad-49ac-ae78-ce28987f7363"
        fingerprint = "5d7d930f39e435fc22921571fe96db912eed79ec630d4ed60da6f007073b7362"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2E 10 73 2E 10 02 47 2E 10 56 2E 10 5C 2E 10 4E 2E 10 49 2E 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_e3086563 {
    meta:
        author = "Elastic Security"
        id = "e3086563-346d-43f1-89eb-42693dc17195"
        fingerprint = "8fc223f3850994479a70358da66fb31b610e00c9cbc3a94fd7323780383d738e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 48 8B 4C 24 08 49 8B 55 00 48 39 D1 75 16 48 8D 64 24 10 }
    condition:
        all of them
}

rule Linux_Trojan_Mobidash_2f114992 {
    meta:
        author = "Elastic Security"
        id = "2f114992-36a7-430c-8bd9-5661814d95a8"
        fingerprint = "2371fc5ba1e279a77496328d3a39342408609f04f1a8947e84e734d28d874416"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mobidash"
        reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DF 4C 89 F6 48 8B 80 B8 00 00 00 48 8D 64 24 58 5B 5D 41 5C }
    condition:
        all of them
}



// from Linux_Trojan_Mumblehard.yar
rule Linux_Trojan_Mumblehard_523450aa {
    meta:
        author = "Elastic Security"
        id = "523450aa-6bb4-4863-9656-81a6e6cb7d88"
        fingerprint = "783f07e4f4625c061309af2d89e9ece0ba4a8ce21a7d93ce19cd32bcd6ad38e9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mumblehard"
        reference_sample = "a637ea8f070e1edf2c9c81450e83934c177696171b24b4dff32dfb23cefa56d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 09 75 05 89 03 89 53 04 B8 02 00 00 00 50 80 F9 09 75 0B CD 80 }
    condition:
        all of them
}



// from Linux_Trojan_Ngioweb.yar
rule Linux_Trojan_Ngioweb_8bd3002c {
    meta:
        author = "Elastic Security"
        id = "8bd3002c-d9c7-4f93-b7f0-4cb9ba131338"
        fingerprint = "2ee5432cf6ead4eca3aad70e40fac7e182bdcc74dc22dc91a12946ae4182f1ab"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 18 67 8A 09 84 C9 74 0D 80 F9 2E 75 02 FF C0 FF 44 24 18 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_a592a280 {
    meta:
        author = "Elastic Security"
        id = "a592a280-053f-47bc-8d74-3fa5d74bd072"
        fingerprint = "60f5ddd115fa1abac804d2978bbb8d70572de0df9da80686b5652520c03bd1ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 06 8B 7C 24 2C EB 2C 83 FD 01 75 06 8B 7C 24 3C EB 21 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d57aa841 {
    meta:
        author = "Elastic Security"
        id = "d57aa841-8eb5-4765-9434-233ab119015f"
        fingerprint = "83a4eb7c8ac42097d3483bcf918823105b4ea4291a566b4184eacc2a0f3aa3a4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 0C 48 89 4C 24 10 4C 89 44 24 18 66 83 F8 02 74 10 BB 10 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_b97e0253 {
    meta:
        author = "Elastic Security"
        id = "b97e0253-497f-4c2c-9d4c-ad89af64847f"
        fingerprint = "859f29acec8bb05b8a8e827af91e927db0b2390410179a0f5b03e7f71af64949"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "5480bc02aeebd3062e6d19e50a5540536ce140d950327cce937ff7e71ebd15e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 5C 41 5D 41 5E 41 5F C3 67 0F BE 17 39 F2 74 12 84 D2 74 04 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_66c465a0 {
    meta:
        author = "Elastic Security"
        id = "66c465a0-821d-43ea-82f5-fe787720bfbf"
        fingerprint = "e26071afff71506236b261a44e8f1903d348dd33b95597458649f377710492f4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 E6 B2 07 FE C0 EB DE 83 EC 10 6A 00 6A 00 6A 00 6A 00 FF 74 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_d8573802 {
    meta:
        author = "Elastic Security"
        id = "d8573802-f141-4fd1-b06a-605451a72465"
        fingerprint = "0052566dda66ae0dfa54d68f4ce03b5a2e2a442c4a18d70f16fd02303a446e66"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 40 74 38 51 51 6A 02 FF 74 24 18 FF 93 C8 00 00 00 83 C4 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_7926bc8e {
    meta:
        author = "Elastic Security"
        id = "7926bc8e-110f-4b8a-8cc5-003732b6fcfd"
        fingerprint = "246e06d73a3a61ade6ac5634378489890a5585e84be086e0a81eb7586802e98f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { ED 74 31 48 8B 5B 10 4A 8D 6C 3B FC 48 39 EB 77 23 8B 3B 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_e2377400 {
    meta:
        author = "Elastic Security"
        id = "e2377400-8884-42fb-b524-9cdf836dac3a"
        fingerprint = "531a8fcb1c097f72cb9876a35ada622dd1129f90515d84b4c245920602419698"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        reference_sample = "b88daf00a0e890b6750e691856b0fe7428d90d417d9503f62a917053e340228b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 08 8B 5C 24 10 8B 43 20 85 C0 74 72 83 7B 28 00 74 6C 83 7B }
    condition:
        all of them
}

rule Linux_Trojan_Ngioweb_994f1e97 {
    meta:
        author = "Elastic Security"
        id = "994f1e97-c370-4eb2-ac93-b5ebf112f55d"
        fingerprint = "6cc0ace6beb6c1bf4e10f9781bb551c10f48cc23efe9529d92b432b0ff88f245"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ngioweb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C6 44 24 16 68 C6 44 24 15 63 C6 44 24 14 74 C6 44 24 13 61 C6 44 24 12 77 C6 44 24 11 2F C6 44 24 10 76 C6 44 24 0F 65 C6 44 24 0E 64 C6 44 24 0D 2F }
    condition:
        all of them
}



// from Linux_Trojan_Nuker.yar
rule Linux_Trojan_Nuker_12f26779 {
    meta:
        author = "Elastic Security"
        id = "12f26779-bda5-45b1-925f-75c620d7d840"
        fingerprint = "9093a96321ad912f2bb953cce460d0945c1c4e5aacd8431f343498203b85bb9b"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Nuker"
        reference_sample = "440105a62c75dea5575a1660fe217c9104dc19fb5a9238707fe40803715392bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 18 89 45 D8 83 7D D8 FF 75 17 68 ?? ?? 04 08 }
    condition:
        all of them
}



// from Linux_Trojan_Orbit.yar
rule Linux_Trojan_Orbit_57c23178 {
    meta:
        author = "Elastic Security"
        id = "57c23178-1345-47b7-97b1-aa2075d9d69d"
        fingerprint = "0bb1c74f872ea8778a442aafc2c6f3f04e331b7f743ba726257e36b09ef33da4"
        creation_date = "2022-07-20"
        last_modified = "2022-08-16"
        threat_name = "Linux.Trojan.Orbit"
        reference_sample = "40b5127c8cf9d6bec4dbeb61ba766a95c7b2d0cafafcb82ede5a3a679a3e3020"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $loaderstrings0 = "shred"
        $loaderstrings1 = "newpath" fullword
        $loaderstrings2 = "shm update" fullword
        $loaderstrings3 = "cp -p %s /dev/shm/ldx/.backup_ld.so" fullword
        $loaderstrings4 = "/dev/shm/ldx/libdl.so\n" fullword
        $loaderstrings5 = "oldpath: %s newpath: %s\n" fullword
        $loaderstrings6 = "can't locate oldpath" fullword
        $loaderstrings7 = "specify dir" fullword
        $loaderstrings8 = "/sshpass.txt"
        $loaderstrings9 = "/sshpass2.txt"
        $loaderstrings10 = "/.logpam"
        $loaderstrings11 = "/.boot.sh"
        $tmppath = "/tmp/.orbit" fullword
        $functionName0 = "tcp_port_hidden" fullword
        $functionName1 = "clean_ports" fullword
        $functionName2 = "remove_port" fullword
        $execvStrings0 = "[%s] [%s] [BLOCKED] %s " fullword
        $execvStrings1 = "[%s] [%s] %s " fullword
        $execvStrings2 = "%m-%d %H:%M:%S" fullword
        $pam_log_password = { 8B 45 F8 48 98 C6 84 05 F0 FE FF FF 00 48 8D 85 F0 FE FF FF B9 A4 01 00 00 BA 42 04 00 00 48 89 C6 BF 02 00 00 00 B8 00 00 00 00 E8 B6 C2 FE FF 89 45 F4 48 8B 8D E0 FE FF FF 48 8B 95 E8 FE FF FF 48 8D 85 F0 FE FF FF }
        $load_hidden_ports = { 48 8B 45 ?? BE 0A 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? 00 75 }
        $hosts_access = { 8B 45 ?? 48 98 C6 84 05 D0 EF FF FF 00 48 8B 05 ?? ?? ?? ?? 48 8B 80 ?? ?? 00 00 48 8B 95 C8 EF FF FF 48 89 D7 FF D0 89 45 ?? 48 8D 85 D0 EF FF FF 48 89 45 ?? EB }
    condition:
        7 of ($loaderstrings*) or (all of ($functionName*) and $tmppath and all of ($execvStrings*)) or 2 of ($pam_log_password, $load_hidden_ports, $hosts_access)
}



// from Linux_Trojan_Patpooty.yar
rule Linux_Trojan_Patpooty_e2e0dff1 {
    meta:
        author = "Elastic Security"
        id = "e2e0dff1-bb01-437e-b138-7da3954dc473"
        fingerprint = "275ff92c5de2d2183ea8870b7353d24f026f358dc7d30d1a35d508a158787719"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Patpooty"
        reference_sample = "d38b9e76cbc863f69b29fc47262ceafd26ac476b0ae6283d3fa50985f93bedf3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 8B 45 E4 8B 34 88 8D 7E 01 FC 31 C0 83 C9 FF F2 AE F7 D1 83 }
    condition:
        all of them
}

rule Linux_Trojan_Patpooty_f90c7e43 {
    meta:
        author = "Elastic Security"
        id = "f90c7e43-0c32-487f-a7c2-8290b341019c"
        fingerprint = "b0b0fd8da224bcd1c048c5578ed487d119f9bff4fb465f77d3043cf77d904f3d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Patpooty"
        reference_sample = "79475a66be8741d9884bc60f593c81a44bdb212592cd1a7b6130166a724cb3d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C2 48 39 C2 75 F1 C7 43 58 01 00 00 00 C7 43 54 01 00 00 00 C7 43 50 01 00 }
    condition:
        all of them
}



// from Linux_Trojan_Pnscan.yar
rule Linux_Trojan_Pnscan_20e34e35 {
    meta:
        author = "Elastic Security"
        id = "20e34e35-8639-4a0d-bfe3-6bfa1570f14d"
        fingerprint = "07678bd23ae697d42e2c7337675f7a50034b10ec7a749a8802820904a943641a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Pnscan"
        reference_sample = "7dbd5b709f16296ba7dac66dc35b9c3373cf88452396d79d0c92d7502c1b0005"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 00 54 45 4C 20 3A 20 00 3C 49 41 43 3E 00 3C 44 4F 4E 54 3E 00 }
    condition:
        all of them
}



// from Linux_Trojan_Pornoasset.yar
rule Linux_Trojan_Pornoasset_927f314f {
    meta:
        author = "Elastic Security"
        id = "927f314f-2cbb-4f87-b75c-9aa5ef758599"
        fingerprint = "7214d3132fc606482e3f6236d291082a3abc0359c80255048045dba6e60ec7bf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Pornoasset"
        reference_sample = "d653598df857535c354ba21d96358d4767d6ada137ee32ce5eb4972363b35f93"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 D3 CB D3 C3 48 31 C3 48 0F AF F0 48 0F AF F0 48 0F AF F0 48 }
    condition:
        all of them
}



// from Linux_Trojan_Psybnc.yar
rule Linux_Trojan_Psybnc_563ecb11 {
    meta:
        author = "Elastic Security"
        id = "563ecb11-e215-411f-8583-7cb7b2956252"
        fingerprint = "1e7a2a6240d6f7396505cc2203c03d4ae93a7ef0c0c956cef7a390b4303a2cbe"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5F 65 6E 00 6B 6F 5F 65 6E 00 72 75 5F 65 6E 00 65 73 5F 65 6E 00 44 }
    condition:
        all of them
}

rule Linux_Trojan_Psybnc_ab3396d5 {
    meta:
        author = "Elastic Security"
        id = "ab3396d5-388b-4730-9a55-581c327a2769"
        fingerprint = "1180e02d3516466457f48dc614611a6949a4bf21f6a294f6384892db30dc4171"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "c5ec84e7cc891af25d6319abb07b1cedd90b04cbb6c8656c60bcb07e60f0b620"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 54 00 55 53 45 52 4F 4E 00 30 00 50 25 64 00 58 30 31 00 }
    condition:
        all of them
}

rule Linux_Trojan_Psybnc_f07357f1 {
    meta:
        author = "Elastic Security"
        id = "f07357f1-1a92-4bd7-a43d-7a75fb90ac83"
        fingerprint = "f0f1008fec444ce25d80f9878a04d9ebe9a76f792f4be8747292ee7b133ea05c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Psybnc"
        reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F7 EA 89 D0 C1 F8 02 89 CF C1 FF 1F 29 F8 8D 04 80 01 C0 29 C1 8D }
    condition:
        all of them
}



// from Linux_Trojan_Pumakit.yar
rule Linux_Trojan_Pumakit_b86138c3 {
    meta:
        author = "Elastic Security"
        id = "b86138c3-c7b3-4f86-a695-bf8195f2458c"
        fingerprint = "c5cba5975be26ebcb14871527533d1f8f082b37f2d8b509904b608569fdb8b24"
        creation_date = "2024-12-09"
        last_modified = "2024-12-11"
        threat_name = "Linux.Trojan.Pumakit"
        reference_sample = "30b26707d5fb407ef39ebee37ded7edeea2890fb5ec1ebfa09a3b3edfc80db1f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "PUMA %s"
        $str2 = "Kitsune PID %ld"
        $str3 = "/usr/share/zov_f"
        $str4 = "zarya"
        $str5 = ".puma-config"
        $str6 = "ping_interval_s"
        $str7 = "session_timeout_s"
        $str8 = "c2_timeout_s"
        $str9 = "LD_PRELOAD=/lib64/libs.so"
        $str10 = "kit_so_len"
        $str11 = "opsecurity1.art"
        $str12 = "89.23.113.204"
    condition:
        4 of them
}



// from Linux_Trojan_Rbot.yar
rule Linux_Trojan_Rbot_c69475e3 {
    meta:
        author = "Elastic Security"
        id = "c69475e3-59eb-4d3c-9ee6-01ae7a3973d3"
        fingerprint = "593ff388ba10d66b97b5dfc9220bbda6b1584fe73d6bf7c1aa0f5391bb87e939"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "9d97c69b65d2900c39ca012fe0486e6a6abceebb890cbb6d2e091bb90f6b9690"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 56 8B 76 20 03 F5 33 C9 49 41 AD 33 DB 36 0F BE 14 28 38 F2 }
    condition:
        all of them
}

rule Linux_Trojan_Rbot_96625c8c {
    meta:
        author = "Elastic Security"
        id = "96625c8c-897c-4bf0-97e7-0dc04595cb94"
        fingerprint = "5dfabf693c87742ffa212573dded84a2c341628b79c7d11c16be493957c71a69"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "a052cfad3034d851c6fad62cc8f9c65bceedc73f3e6a37c9befe52720fd0890e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 28 8B 45 3C 8B 54 05 78 01 EA 8B 4A 18 8B 5A 20 01 EB E3 38 49 8B }
    condition:
        all of them
}

rule Linux_Trojan_Rbot_366f1599 {
    meta:
        author = "Elastic Security"
        id = "366f1599-a287-44e6-bc2c-d835b2c2c024"
        fingerprint = "27166c9dab20d40c10a4f0ea5d0084be63fef48748395dd55c7a13ab6468e16d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "5553d154a0e02e7f97415299eeae78e5bb0ecfbf5454e3933d6fd9675d78b3eb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B }
    condition:
        all of them
}



// from Linux_Trojan_Rekoobe.yar
rule Linux_Trojan_Rekoobe_e75472fa {
    meta:
        author = "Elastic Security"
        id = "e75472fa-0263-4a47-a3bd-2d1bb14df177"
        fingerprint = "4e7605685ba7ba53afeafdef7e46bdca76109bd4d8b9116a93c301edeff606ee"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "8d2a9e363752839a09001a9e3044ab7919daffd9d9aee42d936bc97394164a88"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 83 F8 01 74 1F 89 D0 48 8B 4C 24 08 64 48 33 0C 25 28 00 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_52462fe8 {
    meta:
        author = "Elastic Security"
        id = "52462fe8-a40c-4620-b539-d0c1f9d2ceee"
        fingerprint = "e09e8e023b3142610844bf7783c5472a32f63c77f9a46edc028e860da63e6eeb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "c1d8c64105caecbd90c6e19cf89301a4dc091c44ab108e780bdc8791a94caaad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 1C D8 48 8B 5A E8 4A 33 0C DE 48 89 4A E0 89 D9 C1 E9 18 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_de9e7bdf {
    meta:
        author = "Elastic Security"
        id = "de9e7bdf-c515-4af8-957a-e489b7cb9716"
        fingerprint = "ab3f0b9179a136f7c1df43234ba3635284663dee89f4e48d9dfc762fb762f0db"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "447da7bee72c98c2202f1919561543e54ec1b9b67bd67e639b9fb6e42172d951"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F5 48 89 D6 48 C1 EE 18 40 0F B6 F6 48 33 2C F1 48 89 D6 48 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_b41f70c2 {
    meta:
        author = "Elastic Security"
        id = "b41f70c2-abe4-425a-952f-5e0c9e572a76"
        fingerprint = "396fcb4333abe90f4c228d06c20eeff40f91e25fde312cc7760d999da0aa1027"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "19c1a54279be1710724fc75a112741575936fe70379d166effc557420da714cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E2 10 4D 31 D1 0F B6 D6 48 8B 14 D1 48 C1 E2 08 4C 31 CA 48 89 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_1d307d7c {
    meta:
        author = "Elastic Security"
        id = "1d307d7c-cc84-44e5-8fa0-eda9fffb3964"
        fingerprint = "11b1474dbdc376830bca50dbeea7f7f786c8a9b2ac51a139c4e06bed7c867121"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "00bc669f79b2903c5d9e6412050655486111647c646698f9a789e481a7c98662"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 01 75 56 83 7C 24 3C 10 75 1C BE ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_7f7aba78 {
    meta:
        author = "Elastic Security"
        id = "7f7aba78-6e64-41c4-a542-088a8270a941"
        fingerprint = "acb8f0fb7a7b0c5329afeadb70fc46ab72a7704cdeef64e7575fbf2c2dd3dbe2"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "50b73742726b0b7e00856e288e758412c74371ea2f0eaf75b957d73dfb396fd7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 89 D0 31 D8 21 F0 31 D8 03 45 F0 89 CF C1 CF 1B 01 F8 C1 }
    condition:
        all of them
}

rule Linux_Trojan_Rekoobe_ab8ba790 {
    meta:
        author = "Elastic Security"
        id = "ab8ba790-d2dd-4756-af5c-6f78ba10c92d"
        fingerprint = "decdd02a583562380eda405dcb892d38558eb868743ebc44be592f4ae95b5971"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Rekoobe"
        reference_sample = "2aee0c74d9642ffab1f313179c26400acf60d7cbd2188bade28534d403f468d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { DB F9 66 0F 71 D1 08 66 0F 67 DD 66 0F DB E3 66 0F 71 D3 08 66 0F }
    condition:
        all of them
}



// from Linux_Trojan_Roopre.yar
rule Linux_Trojan_Roopre_b6b9e71d {
    meta:
        author = "Elastic Security"
        id = "b6b9e71d-7f1c-4827-b659-f9dad5667d69"
        fingerprint = "1a87cccd06b99e0375ffef17d4b3c5fd8957013ab8de7507e9b8d1174573a6cf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Roopre"
        reference_sample = "36ae2bf773135fdb0ead7fbbd46f90fd41d6f973569de1941c8723158fc6cfcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 24 08 48 C7 C6 18 FC FF FF 49 8B 4A 08 48 89 C8 48 99 48 }
    condition:
        all of them
}

rule Linux_Trojan_Roopre_05f7f237 {
    meta:
        author = "Elastic Security"
        id = "05f7f237-dcc5-4f0d-8baa-290137eea9c5"
        fingerprint = "2f1d7fd2d0104be63180003ae225eafa95f9d967154d3972782502742bbedf43"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Roopre"
        reference_sample = "36ae2bf773135fdb0ead7fbbd46f90fd41d6f973569de1941c8723158fc6cfcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 01 3A 74 06 80 7F 02 5C 75 1F 48 83 C7 03 B2 5C EB E8 38 D1 48 8D }
    condition:
        all of them
}



// from Linux_Trojan_Rooter.yar
rule Linux_Trojan_Rooter_c8d08d3a {
    meta:
        author = "Elastic Security"
        id = "c8d08d3a-ff9c-4545-9f09-45fbe5b534f3"
        fingerprint = "2a09f9fabfefcf44c71ee17b823396991940bedd7a481198683ee3e88979edf4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rooter"
        reference_sample = "f55e3aa4d875d8322cdd7caa17aa56e620473fe73c9b5ae0e18da5fbc602a6ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D8 DC 04 08 BB 44 C3 04 08 CD 80 C7 05 48 FB 04 }
    condition:
        all of them
}



// from Linux_Trojan_Rotajakiro.yar
rule Linux_Trojan_Rotajakiro_fb24f399 {
    meta:
        author = "Elastic Security"
        id = "fb24f399-d2bc-4cca-a3b8-4d924f11c83e"
        fingerprint = "6b19a49c93a0d3eb380c78ca21ce4f4d2991c35e68d2b75e173dc25118ba2c20"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rotajakiro"
        reference = "023a7f9ed082d9dd7be6eba5942bfa77f8e618c2d15a8bc384d85223c5b91a0c"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 41 55 41 54 49 89 FD 55 53 48 63 DE 48 83 EC 08 0F B6 17 80 }
    condition:
        all of them
}



// from Linux_Trojan_Rozena.yar
rule Linux_Trojan_Rozena_56651c1d {
    meta:
        author = "Elastic Security"
        id = "56651c1d-548e-4a51-8f1c-e4add55ec14f"
        fingerprint = "a86abe550b5c698a244e1c0721cded8df17d2c9ed0ee764d6dea36acf62393de"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rozena"
        reference_sample = "997684fb438af3f5530b0066d2c9e0d066263ca9da269d6a7e160fa757a51e04"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E1 95 68 A4 1A 70 C7 57 FF D6 6A 10 51 55 FF D0 68 A4 AD }
    condition:
        all of them
}



// from Linux_Trojan_Sambashell.yar
rule Linux_Trojan_Sambashell_f423755d {
    meta:
        author = "Elastic Security"
        id = "f423755d-60ec-4442-beb1-0820df0fe00b"
        fingerprint = "ea13320c358cadc8187592de73ceb260a00f28907567002d4f093be21f111f74"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sambashell"
        reference_sample = "bd8a3728a59afbf433799578ef597b9a7211c8d62e87a25209398814851a77ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 01 00 00 00 FC 0E 00 00 FC 1E 00 00 FC 1E 00 00 74 28 00 00 }
    condition:
        all of them
}



// from Linux_Trojan_Sckit.yar
rule Linux_Trojan_Sckit_a244328f {
    meta:
        author = "Elastic Security"
        id = "a244328f-1e12-4ae6-b583-ecf14a4b9d82"
        fingerprint = "eca152c730ecabbc9fe49173273199cb37b343d038084965ad880ddba3173f50"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sckit"
        reference_sample = "685da66303a007322d235b7808190c3ea78a828679277e8e03e6d8d511df0a30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 34 D0 04 08 BB 24 C3 04 08 CD 80 C7 05 A0 EE 04 }
    condition:
        all of them
}



// from Linux_Trojan_Sdbot.yar
rule Linux_Trojan_Sdbot_98628ea1 {
    meta:
        author = "Elastic Security"
        id = "98628ea1-40d8-4a05-835f-a5a5f83637cb"
        fingerprint = "15cf6b916dd87915738f3aa05a2955c78a357935a183c0f88092d808535625a5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sdbot"
        reference_sample = "5568ae1f8a1eb879eb4705db5b3820e36c5ecea41eb54a8eef5b742f477cbdd8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 00 3C 08 54 00 02 00 26 00 00 40 4D 08 00 5C 00 50 00 49 00 }
    condition:
        all of them
}



// from Linux_Trojan_Setag.yar
rule Linux_Trojan_Setag_351eeb76 {
    meta:
        author = "Elastic Security"
        id = "351eeb76-ccca-40d5-8ee3-e8daf6494dda"
        fingerprint = "c6edc7ae898831e9cc3c92fcdce4cd5b4412de061575e6da2f4e07776e0885f5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Setag"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 8B 45 F8 C1 E0 02 01 C2 8B 45 EC 89 02 8D 45 F8 FF 00 8B }
    condition:
        all of them
}

rule Linux_Trojan_Setag_01e2f79b {
    meta:
        author = "Elastic Security"
        id = "01e2f79b-fcbc-41d0-a68b-3a692b893f26"
        fingerprint = "4ea87a6ccf907babdebbbb07b9bc32a5437d0213f1580ea4b4b3f44ce543a5bd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Setag"
        reference_sample = "5b5e8486174026491341a750f6367959999bbacd3689215f59a62dbb13a45fcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 8B 45 EC 89 45 FC 8D 55 E8 83 EC 04 8D 45 F8 50 8D 45 FC }
    condition:
        all of them
}



// from Linux_Trojan_Sfloost.yar
rule Linux_Trojan_Sfloost_69a5343a {
    meta:
        author = "Elastic Security"
        id = "69a5343a-4885-4d88-9eaf-ddfcc95e1f39"
        fingerprint = "c19368bf04e4b67537a8573b5beba56bab8bcfdf870640ef5bd46d40735ee539"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sfloost"
        reference_sample = "c0cd73db5165671c7bbd9493c34d693d25b845a9a21706081e1bf44bf0312ef9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 83 C8 50 88 43 0C 0F B6 45 F0 66 C7 43 10 00 00 66 C7 43 12 }
    condition:
        all of them
}



// from Linux_Trojan_Shark.yar
rule Linux_Trojan_Shark_b918ab75 {
    meta:
        author = "Elastic Security"
        id = "b918ab75-0701-4865-b798-521fdd2ffc28"
        fingerprint = "15205d58af99b8eae14de2d5762fdc710ef682839967dd56f6d65bd3deaa7981"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Shark"
        reference_sample = "8b6fe9f496996784e42b75fb42702aa47aefe32eac6f63dd16a0eb55358b6054"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 26 00 C7 46 14 0A 00 00 00 C7 46 18 15 00 00 00 EB 30 C7 46 14 04 00 }
    condition:
        all of them
}



// from Linux_Trojan_Shellbot.yar
rule Linux_Trojan_Shellbot_65aa6568 {
    meta:
        author = "Elastic Security"
        id = "65aa6568-491a-4a51-b921-c6c228cfca11"
        fingerprint = "2cd606ecaf17322788a5ee3b6bd663bed376cef131e768bbf623c402664e9270"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Shellbot"
        reference_sample = "457d1f4e1db41a9bdbfad78a6815f42e45da16ad0252673b9a2b5dcefc02c47b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 00 73 74 72 63 6D 70 00 70 61 6D 5F 70 72 6F 6D 70 74 00 }
    condition:
        all of them
}



// from Linux_Trojan_Skidmap.yar
rule Linux_Trojan_Skidmap_aa7b661d {
    meta:
        author = "Elastic Security"
        id = "aa7b661d-0ecc-4171-a0c2-a6c0c91b6d27"
        fingerprint = "0bd6bec14d4b0205b04c6b4f34988ad95161f954a1f0319dd33513cb2c7e5f59"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Skidmap"
        reference_sample = "4282ba9b7bee69d42bfff129fff45494fb8f7db0e1897fc5aa1e4265cb6831d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 41 41 80 F8 1A 41 0F 43 C1 88 04 0E 48 83 C1 01 0F B6 04 0F }
    condition:
        all of them
}

rule Linux_Trojan_Skidmap_52fb8489 {
    meta:
        author = "Elastic Security"
        id = "52fb8489-4877-4543-8d7a-03f7cad50b0a"
        fingerprint = "44ba77d99648660bd1091cb47fad42422a5cd26b9df848f1f9febdfd4d764540"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Trojan.Skidmap"
        reference_sample = "4282ba9b7bee69d42bfff129fff45494fb8f7db0e1897fc5aa1e4265cb6831d9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $func1 = "hideModule"
        $func2 = "hook_local_out_func"
        $func3 = "hook_local_in_func"
        $func4 = "orig_getdents"
        $func5 = "hacked_getdents"
        $hook1 = "fake_seq_show_ipv4_udp"
        $hook2 = "fake_seq_show_ipv6_tcp"
        $hook3 = "fake_seq_show_ipv6_udp"
        $hook4 = "fake_seq_show_ipv4_tcp"
        $hook5 = "fake_account_user_time"
        $hook6 = "fake_loadavg_proc_show"
        $hook7 = "fake_trace_printk"
        $hook8 = "fake_bpf_trace_printk"
        $hook9 = "fake_crash_kexec"
        $hook10 = "fake_sched_debug_show"
        $str1 = "pamdicks"
        $str2 = "netlink"
        $str3 = "kaudited"
        $str4 = "kswaped"
    condition:
        3 of ($func*) or 4 of ($hook*) or 3 of ($str*)
}



// from Linux_Trojan_Snessik.yar
rule Linux_Trojan_Snessik_d166f98c {
    meta:
        author = "Elastic Security"
        id = "d166f98c-0fa3-4a1b-a6d2-7fbe4e338fc7"
        fingerprint = "6247d59326ea71426862e1b242c7354ee369fbe6ea766e40736e2f5a6410c8d7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Snessik"
        reference_sample = "f3ececc2edfff2f92d80ed3a5140af55b6bebf7cae8642a0d46843162eeddddd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D2 74 3B 83 CA FF F0 0F C1 57 10 85 D2 7F 9F 48 8D 74 24 2E 89 44 }
    condition:
        all of them
}

rule Linux_Trojan_Snessik_e435a79c {
    meta:
        author = "Elastic Security"
        id = "e435a79c-4b8e-42de-8d78-51b684eba178"
        fingerprint = "bd9f81d03812e49323b86b2ea59bf5f08021d0b43f7629eb4d59e75eccb7dcf1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Snessik"
        reference_sample = "e24749b07f824a4839b462ec4e086a4064b29069e7224c24564e2ad7028d5d60"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C6 75 38 31 C0 48 8B 5C 24 68 48 8B 6C 24 70 4C 8B 64 24 78 4C 8B AC 24 80 00 }
    condition:
        all of them
}



// from Linux_Trojan_Snowlight.yar
rule Linux_Trojan_Snowlight_f5c83d35 {
    meta:
        author = "Elastic Security"
        id = "f5c83d35-aaa5-4356-b4e7-93dc19c0c6b1"
        fingerprint = "89adbef703bec7c41350e97141d414535f5935c6c6957a0f8b25e07f405ea70e"
        creation_date = "2024-05-16"
        last_modified = "2024-06-12"
        threat_name = "Linux.Trojan.Snowlight"
        reference = "https://www.mandiant.com/resources/blog/initial-access-brokers-exploit-f5-screenconnect"
        reference_sample = "7d6652d8fa3748d7f58d7e15cefee5a48126d0209cf674818f55e9a68248be01"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 83 EC 08 48 8B 05 A5 07 20 00 48 85 C0 74 05 E8 BB 00 00 00 48 83 C4 08 C3 00 00 00 00 00 00 FF 35 9A 07 20 00 FF 25 9C 07 20 00 0F 1F 40 00 FF 25 9A 07 20 00 68 00 00 00 00 E9 E0 FF FF FF }
    condition:
        all of them
}



// from Linux_Trojan_Springtail.yar
rule Linux_Trojan_Springtail_35d5b90b {
    meta:
        author = "Elastic Security"
        id = "35d5b90b-f81d-4a10-828b-8315f8e87ca7"
        fingerprint = "ca2d3ea7b23c0fc21afb9cfd2d6561727780bda65d2db1a5780b627ac7b07e66"
        creation_date = "2024-05-18"
        last_modified = "2024-06-12"
        threat_name = "Linux.Trojan.Springtail"
        reference_sample = "30584f13c0a9d0c86562c803de350432d5a0607a06b24481ad4d92cdf7288213"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $systemd1 = "Description=syslogd"
        $systemd2 = "ExecStart=/bin/sh -c \"/var/log/syslogd\""
        $cron1 = "cron.txt@reboot"
        $cron2 = "/bin/shcrontab"
        $cron3 = "type/var/log/syslogdcrontab cron.txt"
        $uri = "/mir/index.php"
    condition:
        all of them
}



// from Linux_Trojan_Sqlexp.yar
rule Linux_Trojan_Sqlexp_1aa5001e {
    meta:
        author = "Elastic Security"
        id = "1aa5001e-0609-4830-9c6f-675985fa50cf"
        fingerprint = "afce33f5bf064afcbd8b1639755733c99171074457272bf08f0c948d67427808"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sqlexp"
        reference_sample = "714a520fc69c54bcd422e75f4c3b71ce636cfae7fcec3c5c413d1294747d2dd6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E3 52 53 89 E1 B0 0B CD 80 00 00 ?? 00 }
    condition:
        all of them
}



// from Linux_Trojan_Sshdkit.yar
rule Linux_Trojan_Sshdkit_18a0b82a {
    meta:
        author = "Elastic Security"
        id = "18a0b82a-94ff-4328-bfa7-25034f170522"
        fingerprint = "9bd28a490607b75848611389b39cf77229cfdd1e885f23c5439d49773924ce16"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sshdkit"
        reference_sample = "003245047359e17706e4504f8988905a219fcb48865afea934e6aafa7f97cef6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 06 2A CA 37 F2 31 18 0E 2F 47 CD 87 9D 16 3F 6D }
    condition:
        all of them
}



// from Linux_Trojan_Sshdoor.yar
rule Linux_Trojan_Sshdoor_5b78aa01 {
    meta:
        author = "Elastic Security"
        id = "5b78aa01-c5d4-4281-9a2e-e3f0d3df31d3"
        fingerprint = "19369c825bc8052bfc234a457ee4029cf48bf3b5b9a008a1a6c2680b97ae6284"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "2e1d909e4a6ba843194f9912826728bd2639b0f34ee512e0c3c9e5ce4d27828e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 11 75 39 41 0F B6 77 01 4C 89 E2 40 84 F6 74 2C 40 80 FE 5A }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_1b443a9b {
    meta:
        author = "Elastic Security"
        id = "1b443a9b-2bd2-4b63-baaa-d66ca43ba521"
        fingerprint = "ff44d7b3c8db5cd0d12a99c2aafb1831f63c6253fe0e63fb7d2503bc74e6fca9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "a33112daa5a7d31ea1a1ca9b910475843b7d8c84d4658ccc00bafee044382709"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 10 44 39 F8 7F B4 3B 44 24 04 7C AE 3B 44 24 0C 7E 10 41 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_7c36d3dd {
    meta:
        author = "Elastic Security"
        id = "7c36d3dd-734f-4485-85c5-906c5ecade77"
        fingerprint = "a644708905c97c784f394ebbd0020dd3b20b52b4f536c844ca860dabea36ceb7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 20 48 89 E7 C1 EE 03 83 E6 01 FF D3 8B 54 24 20 31 C0 BE 20 00 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_3e81b1b7 {
    meta:
        author = "Elastic Security"
        id = "3e81b1b7-71bd-4876-a616-ca49ce73c2da"
        fingerprint = "7849bb7283adb25c2ee492efd8d9b2c63de7ae701a69e1892cdc25175996b227"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 24 48 89 E7 C1 EE 05 83 E6 01 FF D3 8B 54 24 28 31 C0 BE 5A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_cde7cfd4 {
    meta:
        author = "Elastic Security"
        id = "cde7cfd4-a664-481d-8865-d44332c7f243"
        fingerprint = "65bf31705755b19b1c01bd2bcc00525469c8cd35eaeff51d546a1d0667d8a615"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "cd646a1d59c99b9e038098b91cdb63c3fe9b35bb10583bef0ab07260dbd4d23d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 CC 8B 73 08 48 8B 54 24 08 48 83 C4 18 5B 5D 41 5C 41 5D 4C }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_32d9fb1b {
    meta:
        author = "Elastic Security"
        id = "32d9fb1b-79d7-4bd1-bbe5-345550591367"
        fingerprint = "fa28250df6960ee54de7b0bacb437b543615a241267e34b5a422f231f5088f10"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 04 25 28 00 00 00 48 89 44 24 08 31 C0 66 0F EF C0 48 85 F6 }
    condition:
        all of them
}

rule Linux_Trojan_Sshdoor_7c3cfc62 {
    meta:
        author = "Elastic Security"
        id = "7c3cfc62-aa90-4c28-b428-e2133a3f10f8"
        fingerprint = "8085c47704b4d6cabad9d1dd48034dc224f725ba22a7872db50c709108bf575d"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Sshdoor"
        reference_sample = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 8D 6F 50 53 49 89 FC 48 89 FB 48 83 EC 10 64 48 8B 04 25 28 00 }
    condition:
        all of them
}



// from Linux_Trojan_Subsevux.yar
rule Linux_Trojan_Subsevux_e9e80c1e {
    meta:
        author = "Elastic Security"
        id = "e9e80c1e-c064-47cf-91f2-0561dd5c9bcd"
        fingerprint = "bbd7a2d80e545d0cae7705a53600f6b729918a3d655bc86b2db83f15d4e550e3"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Subsevux"
        reference_sample = "a4ccd399ea99d4e31fbf2bbf8017c5368d29e630dc2985e90f07c10c980fa084"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 00 79 1C 83 EC 0C 68 }
    condition:
        all of them
}



// from Linux_Trojan_Swrort.yar
rule Linux_Trojan_Swrort_5ad1a4f9 {
    meta:
        author = "Elastic Security"
        id = "5ad1a4f9-bfe5-4e5f-94e9-4983c93a1c1f"
        fingerprint = "a91458dd4bcd082506c554ca8479e1b0d23598e0e9a0e44ae1afb2651ce38dce"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "fa5695c355a6dc1f368a4b36a45e8f18958dacdbe0eac80c618fbec976bac8fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 53 57 68 B7 E9 38 FF FF D5 53 53 57 68 74 EC 3B E1 FF D5 57 }
    condition:
        all of them
}

rule Linux_Trojan_Swrort_4cb5b116 {
    meta:
        author = "Elastic Security"
        id = "4cb5b116-5e90-4e5f-a62f-bfe616cab5db"
        fingerprint = "cb783f69b4074264a75894dd85459529a172404a6901a1f5753a2f9197bfca58"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "703c16d4fcc6f815f540d50d8408ea00b4cf8060cc5f6f3ba21be047e32758e0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 04 6A 10 89 E1 6A 00 }
    condition:
        all of them
}

rule Linux_Trojan_Swrort_22c2d6b6 {
    meta:
        author = "Elastic Security"
        id = "22c2d6b6-d100-4310-87c4-3912a86bdd40"
        fingerprint = "d2b16da002cb708cb82f8b96c7d31f15c9afca69e89502b1970758294e91f9a4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Swrort"
        reference_sample = "6df073767f48dd79f98e60aa1079f3ab0b89e4f13eedc1af3c2c073e5e235bbc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 51 6A 04 54 6A 02 }
    condition:
        all of them
}



// from Linux_Trojan_Sysrv.yar
rule Linux_Trojan_Sysrv_85097f24 {
    meta:
        author = "Elastic Security"
        id = "85097f24-2e2e-41e4-8769-dca7451649cc"
        fingerprint = "1cad651c92a163238f8d60d2e3670f229b4aafd6509892b9dcefe014b39c6f7d"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sysrv"
        reference = "17fbc8e10dea69b29093fcf2aa018be4d58fe5462c5a0363a0adde60f448fb26"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 32 26 02 0F 80 0C 0A FF 0B 02 02 22 04 2B 02 16 02 1C 01 0C 09 }
    condition:
        all of them
}



// from Linux_Trojan_Truncpx.yar
rule Linux_Trojan_Truncpx_894d60f8 {
    meta:
        author = "Elastic Security"
        id = "894d60f8-bea6-4b09-b8ab-526308575a01"
        fingerprint = "440ce5902642aeef56b6989df4462d01faadc479f1362c0ed90d1011e8737bc3"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Truncpx"
        reference_sample = "2f09f2884fd5d3f5193bfc392656005bce6b935c12b3049ac8eb96862e4645ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B9 51 FE 88 63 A1 08 08 09 C5 1A FF D3 AB B2 28 }
    condition:
        all of them
}



// from Linux_Trojan_Tsunami.yar
rule Linux_Trojan_Tsunami_d9e6b88e {
    meta:
        author = "Elastic Security"
        id = "d9e6b88e-256c-4e9d-a411-60b477b70446"
        fingerprint = "8fc61c0754d1a8b44cefaf2dbd937ffa0bb177d98b071347d2f9022181555b7a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "a4ac275275e7be694a200fe6c5c5746256398c109cf54f45220637fe5d9e26ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 02 01 20 03 20 02 C9 07 40 4E 00 60 01 C0 04 17 B6 92 07 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_30c039e2 {
    meta:
        author = "Elastic Security"
        id = "30c039e2-1c51-4309-9165-e3f2ce79cd6e"
        fingerprint = "4c97fed719ecfc68e7d67268f19aff545447b4447a69814470fe676d4178c0ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b494ca3b7bae2ab9a5197b81e928baae5b8eac77dfdc7fe1223fee8f27024772"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 E0 0F B6 00 84 C0 74 1F 48 8B 45 E0 48 8D 50 01 48 8B 45 E8 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_c94eec37 {
    meta:
        author = "Elastic Security"
        id = "c94eec37-8ae1-48d2-8c75-36f2582a2742"
        fingerprint = "c692073af446327f739e1c81f4e3b56d812c00c556e882fe77bfdff522082db4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "294fcdd57fc0a53e2d63b620e85fa65c00942db2163921719d052d341aa2dc30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 10 8B 45 E4 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 E4 C6 40 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_f806d5d9 {
    meta:
        author = "Elastic Security"
        id = "f806d5d9-0bf6-4da7-80fb-b1612f2ddd5b"
        fingerprint = "f4f838fcd1fe7f85e435225f3e34b77b848246b2b9618b47125a611c8d282347"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 54 45 48 54 54 50 20 3C 68 6F 73 74 3E 20 3C 73 72 63 3A }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0fa3a6e9 {
    meta:
        author = "Elastic Security"
        id = "0fa3a6e9-89f3-4bc8-8dc1-e9ccbeeb836d"
        fingerprint = "fed796c5275e2e91c75dcdbf73d0c0ab37591115989312c6f6c5adcd138bc91f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "40a15a186373a062bfb476b37a73c61e1ba84e5fa57282a7f9ec0481860f372a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 8B 55 EC C1 FA 10 0F B7 45 EC 01 C2 89 55 EC 8B 45 EC C1 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_36a98405 {
    meta:
        author = "Elastic Security"
        id = "36a98405-8b95-49cb-98c5-df4a445d9d39"
        fingerprint = "c76ca23eece4c2d4ec6656ffb40d6e6ea7777d8a904f4775913fe60ebd606cd6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 85 50 FF FF FF 0F B6 85 50 FF FF FF 83 E0 0F 83 C8 40 88 85 50 FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0c6686b8 {
    meta:
        author = "Elastic Security"
        id = "0c6686b8-8880-4a2c-ba70-9a9840a618b0"
        fingerprint = "7bab1c0cf4fb79c50369f991373178ef3b5d3f7afd765dac06e86ac0c27e0c83"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 31 C0 48 8B 45 C8 0F B7 40 02 66 89 45 D0 48 8B 45 C8 8B }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_9ce5b69f {
    meta:
        author = "Elastic Security"
        id = "9ce5b69f-4938-4576-89da-8dcd492708ed"
        fingerprint = "90fece6c2950467d78c8a9f1d72054adf854f19cdb33e71db0234a7b0aebef47"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "ad63fbd15b7de4da0db1b38609b7481253c100e3028c19831a5d5c1926351829"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 8B 54 85 B4 8B 45 E4 8D 04 02 C6 00 00 FF 45 F4 8B 45 E4 01 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_55a80ab6 {
    meta:
        author = "Elastic Security"
        id = "55a80ab6-3de4-48e1-a9de-28dc3edaa104"
        fingerprint = "2fe3a9e1115d8c2269fe090c57ee3d5b2cd52b4ba1d020cec0135e2f8bbcb50e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 68 65 20 63 75 72 72 65 6E 74 20 73 70 6F 6F 66 69 6E 67 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_e98b83ee {
    meta:
        author = "Elastic Security"
        id = "e98b83ee-0533-481a-9947-538bd2f99b6b"
        fingerprint = "b5440c783bc18e23f27a3131ccce4629f8d0ceea031971cbcdb69370ab52e935"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 FE 00 00 EB 16 48 8B 55 D8 0F B7 02 0F B7 C0 01 45 E0 48 83 45 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_8a11f9be {
    meta:
        author = "Elastic Security"
        id = "8a11f9be-dc85-4695-9f38-80ca0304780e"
        fingerprint = "91e2572a3bb8583e20042578e95e1746501c6a71ef7635af2c982a05b18d7c6d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "1f773d0e00d40eecde9e3ab80438698923a2620036c2fc33315ef95229e98571"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3E 20 3C 70 6F 72 74 3E 20 3C 72 65 66 6C 65 63 74 69 6F 6E 20 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_2462067e {
    meta:
        author = "Elastic Security"
        id = "2462067e-06cf-409c-8184-86bd7a772690"
        fingerprint = "f84d62ad2d6f907a47ea9ff565619648564b7003003dc8f20e28a582a8331e6b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "3847f1c7c15ce771613079419de3d5e8adc07208e1fefa23f7dd416b532853a1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 F4 8B 40 0C 89 C1 8B 45 F4 8B 40 10 8B 10 8D 45 E4 89 C7 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0a028640 {
    meta:
        author = "Elastic Security"
        id = "0a028640-581f-4183-9313-e36c5812e217"
        fingerprint = "1b296e8baffbe3e0e49aee23632afbfab75147f31561d73eb0c82f909c5ec718"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "e36081f0dbd6d523c9378cdd312e117642b0359b545b29a61d8f9027d8c0f2f0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 85 C0 74 2D 8B 45 0C 0F B6 00 84 C0 74 19 8B 45 0C 83 C0 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_47f93be2 {
    meta:
        author = "Elastic Security"
        id = "47f93be2-687c-42d2-9627-29f114beb234"
        fingerprint = "f4a2262cfa0f0db37e15149cf33e639fd2cd6d58f4b89efe7860f73014b47c4e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FA 48 63 C6 48 89 94 C5 70 FF FF FF 8B 85 5C FF FF FF 8D 78 01 48 8D 95 60 FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_6b3974b2 {
    meta:
        author = "Elastic Security"
        id = "6b3974b2-fd7f-4ebf-8aba-217761e7b846"
        fingerprint = "942a35f7acacf1d07577fe159a34dc7b04e5d07ff32ea13be975cfeea23e34be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "2216776ba5c6495d86a13f6a3ce61b655b72a328ca05b3678d1abb7a20829d04"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 89 45 EC 8B 45 EC C9 C3 55 89 E5 57 83 EC 0C EB 1F 8B 45 08 B9 FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_87bcb848 {
    meta:
        author = "Elastic Security"
        id = "87bcb848-cd8b-478c-87de-5df8c457024c"
        fingerprint = "ffd1a95ba4801bb51ce9b688bdb9787d4a8e3bc3a60ad0f52073f5c531bc6df7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 65 6D 6F 74 65 00 52 65 6D 6F 74 65 20 49 52 43 20 42 6F 74 00 23 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_ad60d7e8 {
    meta:
        author = "Elastic Security"
        id = "ad60d7e8-0823-4bfa-b823-681c554bf297"
        fingerprint = "e1ca4c566307238a5d8cd16db8d0d528626e0b92379177b167ce25b4c88d10ce"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4E 4F 54 49 43 45 20 25 73 20 3A 53 70 6F 6F 66 73 3A 20 25 64 2E 25 64 2E 25 64 2E 25 64 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_22646c0d {
    meta:
        author = "Elastic Security"
        id = "22646c0d-785c-4cf2-b8c8-289189ae14d0"
        fingerprint = "0b1dce4e74536d4d06430aefd0127c740574dcc9a0e5ada42f3d51d97437720f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "20439a8fc21a94c194888725fbbb7a7fbeef5faf4b0f704559d89f1cd2e57d9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CB 01 00 00 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_019f0e75 {
    meta:
        author = "Elastic Security"
        id = "019f0e75-a766-4778-8337-c5bce478ecd9"
        fingerprint = "3b66dcdd89ce564cf81689ace33ee91682972421a9926efa1985118cefebdddc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2E 0A 00 2B 73 74 64 00 2B 73 74 6F 70 00 2B 75 6E 6B 6E 6F }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_7c545abf {
    meta:
        author = "Elastic Security"
        id = "7c545abf-822d-44bb-8ac9-1b7e4f27698d"
        fingerprint = "4141069d6c41c0c26b53a8a86fd675f09982ca6e99757a04ef95b9ad0b8efefa"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "95691c7ad1d80f7f1b5541e1d1a1dbeba30a26702a4080d256f14edb75851c5d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 FC DF 40 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_32c0b950 {
    meta:
        author = "Elastic Security"
        id = "32c0b950-0636-42bb-bc67-1b727985625f"
        fingerprint = "e438287517c3492fa87115a3aa5402fd05f9745b7aed8e251fb3ed9d653984bb"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "214c1caf20ceae579476d3bf97f489484df4c5f1c0c44d37ff9b9066072cd83c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 20 BC F8 41 B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_cbf50d9c {
    meta:
        author = "Elastic Security"
        id = "cbf50d9c-2893-48c9-a2a9-45053f0a174b"
        fingerprint = "acb32177d07df40112d99ed0a2b7ed01fbca63df1f63387cf939caa4cf1cf83b"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b64d0cf4fc4149aa4f63900e61b6739e154d328ea1eb31f4c231016679fc4aa5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 07 F8 BF 81 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_40c25a06 {
    meta:
        author = "Elastic Security"
        id = "40c25a06-5f3c-42c1-9a8c-5c4a1568ff9a"
        fingerprint = "b45d666e2e7d571e95806a1a2c8e01cd5cd0d71160cbb06b268110d459ee252d"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "61af6bb7be25465e7d469953763be5671f33c197d4b005e4a78227da11ae91e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 74 13 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_35806adc {
    meta:
        author = "Elastic Security"
        id = "35806adc-9bac-4481-80c8-a673730d5179"
        fingerprint = "f0b4686087ddda1070b62ade7ad7eb69d712e15f5645aaba24c0f5b124a283ac"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "15e7942ebf88a51346d3a5975bb1c2d87996799e6255db9e92aed798d279b36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 3C 93 48 1F 03 36 84 C0 4B 28 7F 18 86 13 08 10 1F EC B0 73 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_d74d7f0c {
    meta:
        author = "Elastic Security"
        id = "d74d7f0c-70f8-4dd7-aaf4-fd5ab94bb8b2"
        fingerprint = "0a175d0ff64186d35b64277381f47dfafe559a42a3296a162a951f1b2add1344"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b0a8b2259c00d563aa387d7e1a1f1527405da19bf4741053f5822071699795e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 79 6F 2C 0A 59 6A 02 5B 6A 04 58 CD 80 B3 7F 6A 01 58 CD }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_71d31510 {
    meta:
        author = "Elastic Security"
        id = "71d31510-cd2c-4b61-b2cf-975d5ed70c93"
        fingerprint = "6c9f3f31e9dcdcd4b414e79e06f0ae633e50ef3e19a437c1b964b40cc74a57cb"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "33dd6c0af99455a0ca3908c0117e16a513b39fabbf9c52ba24c7b09226ad8626"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5C B3 C0 19 17 5E 7B 8B 22 16 17 E0 DE 6E 21 46 FB DD 17 67 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_97288af8 {
    meta:
        author = "Elastic Security"
        id = "97288af8-f447-48ba-9df3-4e90f1420249"
        fingerprint = "a1e20b699822b47359c8585ff01da06f585b9d7187a433fe0151394b16aa8113"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "c39eb055c5f71ebfd6881ff04e876f49495c0be5560687586fc47bf5faee0c84"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 61 6E 64 65 6D 6F 20 73 68 69 72 61 6E 61 69 20 77 61 20 79 6F 2C }
    condition:
        all of them
}



// from Linux_Trojan_Winnti.yar
rule Linux_Trojan_Winnti_61215d98 {
    meta:
        author = "Elastic Security"
        id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
        fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_4c5a1865 {
    meta:
        author = "Elastic Security"
        id = "4c5a1865-ff41-445b-8616-c83b87498c2b"
        fingerprint = "685fe603e04ff123b3472293d3d83e2dc833effd1a7e6c616ff17ed61df0004c"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference = "0d963a713093fc8e5928141f5747640c9b43f3aadc8a5478c949f7ec364b28ad"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 E8 1F 84 C0 75 7B 85 D2 89 D5 7E 75 8B 47 0C 39 C6 7D 6E 44 8D }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_6f4ca425 {
    meta:
        author = "Elastic Security"
        id = "6f4ca425-5cd2-4c22-b017-b5fc02b3abc2"
        fingerprint = "dec25af33fc004de3a1f53e0c3006ff052f7c51c95f90be323b281590da7d924"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "161af780209aa24845863f7a8120aa982aa811f16ec04bcd797ed165955a09c1"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 89 7D D8 48 8B 45 D8 0F B6 40 27 0F BE C0 89 45 F8 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_de4b0f6e {
    meta:
        author = "Elastic Security"
        id = "de4b0f6e-0183-4ea8-9c03-f716a25f1884"
        fingerprint = "c72eddc2d72ea979ad4f680d060aac129f1cd61dbdf3b0b5a74f5d35a9fe69d7"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "a6b9b3ea19eaddd4d90e58c372c10bbe37dbfced638d167182be2c940e615710"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 30 FF FF FF 02 00 48 8D 85 30 FF FF FF 48 8D 50 02 0F B7 85 28 FF }
    condition:
        all of them
}



// from Linux_Trojan_Xhide.yar
rule Linux_Trojan_Xhide_7f0a131b {
    meta:
        author = "Elastic Security"
        id = "7f0a131b-c305-4a08-91cc-ac2de4d95b19"
        fingerprint = "767f2ea258cccc9f9b6673219d83e74da1d59f6847161791c9be04845f17d8cb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 85 68 FF FF FF 83 E0 40 85 C0 75 1A 8B 85 68 FF FF FF 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xhide_cd8489f7 {
    meta:
        author = "Elastic Security"
        id = "cd8489f7-795f-4fd5-b9a6-03ddd0f3bad4"
        fingerprint = "30b2e0a8ad2fdaa040d748d8660477ae93a6ebc89a186029ff20392f6c968578"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F 74 2E 63 6F 6E 66 0A 0A 00 46 75 6C 6C 20 70 61 74 68 20 }
    condition:
        all of them
}

rule Linux_Trojan_Xhide_840b27c7 {
    meta:
        author = "Elastic Security"
        id = "840b27c7-191f-4d31-9b46-f22be634b2af"
        fingerprint = "f1281db9a49986e23ef1fd9a97785d3bd7c9b3b855cf7e51744487242dd395a3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 98 83 E0 40 85 C0 75 16 8B 45 98 83 E0 08 85 C0 75 0C 8B }
    condition:
        all of them
}



// from Linux_Trojan_Xorddos.yar
rule Linux_Trojan_Xorddos_2aef46a6 {
    meta:
        author = "Elastic Security"
        id = "2aef46a6-6daf-4f02-b1b4-e512cea12e53"
        fingerprint = "e583729c686b80e5da8e828a846cbd5218a4d787eff1fb2ce84a775ad67a1c4d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 25 64 2D 2D 25 73 5F 25 64 3A 25 73 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_a6572d63 {
    meta:
        author = "Elastic Security"
        id = "a6572d63-f9f3-4dfb-87e6-3b0bafd68a79"
        fingerprint = "fd32a773785f847cdd59d41786a8d8a7ba800a71d40d804aca51286d9bb1e1f0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2ff33adb421a166895c3816d506a63dff4e1e8fa91f2ac8fb763dc6e8df59d6e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C8 0F B6 46 04 0F B6 56 05 C1 E0 08 09 D0 89 45 CC 0F B6 46 06 0F B6 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e41143e1 {
    meta:
        author = "Elastic Security"
        id = "e41143e1-52d9-45c7-b19f-a5475b18a510"
        fingerprint = "f621a2e8c289772990093762f371bb6d5736085695881e728a0d2c013c2ad1d4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 1E 80 3C 06 00 8D 14 30 8D 4C 37 FF 74 0D EB 36 0F B6 42 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_0eb147ca {
    meta:
        author = "Elastic Security"
        id = "0eb147ca-ec6d-4a6d-b807-4de8c1eff875"
        fingerprint = "6a1667f585a7bee05d5aece397a22e376562d2b264d3f287874e5a1843e67955"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 F0 01 8B 45 F0 89 45 E8 8B 45 E8 83 C4 18 5F 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ba961ed2 {
    meta:
        author = "Elastic Security"
        id = "ba961ed2-b410-4da5-8452-a03cf5f59808"
        fingerprint = "fff4804164fb9ff1f667d619b6078b00a782b81716e217ad2c11df80cb8677aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 C9 C3 55 89 E5 83 EC 38 C7 45 F8 FF FF FF FF C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2084099a {
    meta:
        author = "Elastic Security"
        id = "2084099a-1df6-4481-9d13-3a5bd6a53817"
        fingerprint = "dfb813a5713f0e7bdb5afd500f1e84c6f042c8b1a1d27dd6511dca7f2107c13b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 FC 8B 50 18 8B 45 08 89 50 18 8B 45 FC 8B 40 08 85 C0 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_61c88137 {
    meta:
        author = "Elastic Security"
        id = "61c88137-02f6-4339-b8fc-04c72a5023aa"
        fingerprint = "c09b31424a54e485fe5f89b4ab0a008df6e563a75191f19de12113890a4faa39"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "479ef38fa00bb13a3aa8448aa4a4434613c6729975e193eec29fc5047f339111"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8B C1 8B 0C 24 8D 64 24 FC 89 0C 24 8B 4D E8 87 0C 24 96 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_debb98a1 {
    meta:
        author = "Elastic Security"
        id = "debb98a1-c861-4458-8bff-fae4f00a17dc"
        fingerprint = "2c5688a82f7d39b0fceaf4458856549b1bce695a160a864f41b12b42e86e3745"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "494f549e3dd144e8bcb230dd7b3faa8ff5107d86d9548b21b619a0318e362cad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 87 5D F4 5B 9C 51 8B 4C 24 04 8D 49 2A 87 4C 24 04 89 4C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1d6e10fd {
    meta:
        author = "Elastic Security"
        id = "1d6e10fd-7404-4597-a97d-cc92849d84f4"
        fingerprint = "bf9d971a13983f1d0fdc8277e76cd1929523e239ce961316fe1f44cbdf0638a8"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "4c7851316f01ae84ee64165be3ba910ab9b415d7f0e2f5b7e5c5a0eaefa3c287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 9C 83 C5 7B 9D 8D 6D 85 87 54 24 00 9C 83 C5 26 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e3ffbbcc {
    meta:
        author = "Elastic Security"
        id = "e3ffbbcc-7751-4d96-abec-22dd9618cab1"
        fingerprint = "d5d5117a31da1a0ac3ef4043092eed47e2844938da9d03e2b68a66658e300175"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "28b7ddf2548411910af033b41982cdc74efd8a6ef059a54fda1b6cbd59faa8f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 10 52 FB FF D0 52 FB FF 00 52 FB FF D0 52 FB FF F0 51 FB }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_30f3b4d4 {
    meta:
        author = "Elastic Security"
        id = "30f3b4d4-e634-418e-a9d5-7f12ef22f9ac"
        fingerprint = "de1002eb8e9aae984ee5fe2a6c1f91845dab4861e09e01d644248cff8c590e5b"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "5b15d43d3535965ec9b84334cf9def0e8c3d064ffc022f6890320cd6045175bc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 70 9C 83 C5 17 9D 8D 6D E9 0F 10 74 24 60 8B F6 0F 10 6C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ca75589c {
    meta:
        author = "Elastic Security"
        id = "ca75589c-6354-411b-b0a5-8400e657f956"
        fingerprint = "0bcaeae9ec0f5de241a05c77aadb5c3f2e39c84d03236971a0640ebae528a496"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0448c1b2c7c738404ba11ff4b38cdc8f865ccf1e202f6711345da53ce46e7e16"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6D E0 25 01 00 00 00 55 8B EC C9 87 D1 87 0C 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_7909cdd2 {
    meta:
        author = "Elastic Security"
        id = "7909cdd2-8a49-4f51-ae16-1ffe321a29d4"
        fingerprint = "5c982596276c8587a88bd910bb2e75a7f72ea7a57c401ffa387aced33f9ac2b9"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0a4a5874f43adbe71da88dc0ef124f1bf2f4e70d0b1b5461b2788587445f79d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { A5 07 00 EC C5 19 08 EC C5 19 08 18 06 00 00 18 06 00 00 06 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2522d611 {
    meta:
        author = "Elastic Security"
        id = "2522d611-4ce3-4583-87d6-e5631b62d562"
        fingerprint = "985885a6b5f01e8816027f92148d2496a5535f3c15de151f05f69ec273291506"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0c2be53e298c285db8b028f563e97bf1cdced0c4564a34e740289b340db2aac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 57 8B 7C 24 02 5F 87 44 24 00 50 8B 44 24 04 8D 40 42 87 44 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_56bd04d3 {
    meta:
        author = "Elastic Security"
        id = "56bd04d3-6b52-43f4-b170-637feb86397a"
        fingerprint = "25cd85e8e65362a993a314f2fc500266fce2f343d21a2e91b146dafbbe8186db"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0d2ce3891851808fb36779a348a83bf4aa9de1a2b2684fd0692434682afac5ec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5C 87 5C 24 04 89 5C 24 04 8B 1C 24 8D 64 24 04 8B 00 8B F6 87 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_f412e4b4 {
    meta:
        author = "Elastic Security"
        id = "f412e4b4-adec-4011-b4b5-f5bb77b65d84"
        fingerprint = "deb9f80d032c4b3c591935c474523fd6912d7bd2c4f498ec772991504720e683"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0e3a3f7973f747fcb23c72289116659c7f158c604d937d6ca7302fbab71851e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 C1 E2 05 8B C0 03 C2 9C 83 C5 0F 9D 8D 6D F1 05 0C 00 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_71f8e26c {
    meta:
        author = "Elastic Security"
        id = "71f8e26c-d0ff-49e8-9c20-8df9149e8843"
        fingerprint = "dbd1275bd01fb08342e60cb0c20adaf42971ed6ee0f679fedec9bc6967ecc015"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "13f873f83b84a0d38eb3437102f174f24a0ad3c5a53b83f0ee51c62c29fb1465"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8D 64 24 04 1B 07 87 DA 8B 5D F4 52 87 DA 5B 83 C2 03 52 8B 54 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1a562d3b {
    meta:
        author = "Elastic Security"
        id = "1a562d3b-bc59-4cb7-9ac1-7a4a79232869"
        fingerprint = "e052e99f15f5a0f704c04cae412cf4b1f01a8ee6e4ce880aedc79cf5aee9631a"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15731db615b32c49c34f41fe84944eeaf2fc79dafaaa9ad6bf1b07d26482f055"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 87 1C 24 91 8D 64 24 FC 89 0C 24 8B C8 8B 04 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_410256ac {
    meta:
        author = "Elastic Security"
        id = "410256ac-fc7d-47f1-b7b8-82f1ee9f2bfb"
        fingerprint = "aa7f1d915e55c3ef178565ed12668ddd71bf3e982dba1f2436c98cceef2c376d"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15f44e10ece90dec1a6104d5be1effefa17614d9f0cfb2784305dab85367b741"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 87 CA 8B 4D 0C 52 87 CA 59 03 D1 55 8B EC C9 6A 08 F7 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_93fa87f1 {
    meta:
        author = "Elastic Security"
        id = "93fa87f1-ec9d-4b3b-9c9a-a0b80963f41f"
        fingerprint = "3b53e54dfea89258a116dcdf4dde0b6ad583aff08d626c02a6f1bf0c76164ac7"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "165b4a28fd6335d4e4dfefb6c40f41f16d8c7d9ab0941ccd23e36cda931f715e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 87 44 24 04 89 44 24 04 8B 04 24 8D 64 24 04 8B 00 9C 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_8677dca3 {
    meta:
        author = "Elastic Security"
        id = "8677dca3-e36b-439f-bc55-76d951114020"
        fingerprint = "4d276b225f412b3879db19546c09d1dea2ee417c61ab6942c411bc392fee8e26"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "23813dc4aa56683e1426e5823adc3aab854469c9c0f3ec1a3fad40fa906929f2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F2 5E 83 C2 03 8B FF C1 E2 05 9C 83 C5 69 9D 8D 6D 97 03 C2 56 8B 74 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ebce4304 {
    meta:
        author = "Elastic Security"
        id = "ebce4304-0a06-454f-ad08-98b323e5b23a"
        fingerprint = "20f0346bf021e3d2a0e25bbb3ed5b9c0a45798d0d5b2516b679f7bf17d1b040d"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8D 64 24 04 87 54 24 00 56 8B 74 24 04 5E 9D 9C 83 C5 1E 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_073e6161 {
    meta:
        author = "Elastic Security"
        id = "073e6161-35a3-4e5e-a310-8cc50cb28edf"
        fingerprint = "12d04597fd60ed143a1b256889eefee1f5a8c77f4f300e72743e3cfa98ba8e99"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 83 F8 1F 77 33 80 BC 35 B9 FF FF FF 63 76 29 8B 44 24 14 40 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_bef22375 {
    meta:
        author = "Elastic Security"
        id = "bef22375-0a71-4f5b-bfd1-e2e718b5c36f"
        fingerprint = "0128e8725a0949dd23c23addc1158d28c334cfb040aad2b8f8d58f39720c41ef"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "f47baf48deb71910716beab9da1b1e24dc6de9575963e238735b6bcedfe73122"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C5 35 9D 8D 6D CB 8B 12 9C 83 C5 17 9D 8D 6D E9 6A 04 F7 14 24 FF }
    condition:
        all of them
}



// from Linux_Trojan_Xpmmap.yar
rule Linux_Trojan_Xpmmap_7dcc3534 {
    meta:
        author = "Elastic Security"
        id = "7dcc3534-e94c-4c92-ac9b-a82b00fb045b"
        fingerprint = "397618543390fb8fd8b198f63034fe88b640408d75b769fb337433138dafcf66"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xpmmap"
        reference_sample = "765546a981921187a4a2bed9904fbc2ccb2a5876e0d45c72e79f04a517c1bda3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 89 45 F8 48 83 7D F8 FF 75 14 BF 10 0C 40 00 }
    condition:
        all of them
}



// from Linux_Trojan_XZBackdoor.yar
rule Linux_Trojan_XZBackdoor_74e87a9d {
    meta:
        author = "Elastic Security"
        id = "74e87a9d-11c1-4e86-bb3c-63a3c51c50df"
        fingerprint = "6ec0ee53f66167f7f2bbe5420aa474681701ed8f889aaad99e3990ecc4fb6716"
        creation_date = "2024-03-30"
        last_modified = "2024-04-03"
        threat_name = "Linux.Trojan.XZBackdoor"
        reference_sample = "5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj"
        $a2 = { 0A 31 FD 3B 2F 1F C6 92 92 68 32 52 C8 C1 AC 28 34 D1 F2 C9 75 C4 76 5E B1 F6 88 58 88 93 3E 48 10 0C B0 6C 3A BE 14 EE 89 55 D2 45 00 C7 7F 6E 20 D3 2C 60 2B 2C 6D 31 00 }
        $b1 = { 48 8D 7C 24 08 F3 AB 48 8D 44 24 08 48 89 D1 4C 89 C7 48 89 C2 E8 ?? ?? ?? ?? 89 C2 }
        $b2 = { 31 C0 49 89 FF B9 16 00 00 00 4D 89 C5 48 8D 7C 24 48 4D 89 CE F3 AB 48 8D 44 24 48 }
        $b3 = { 4D 8B 6C 24 08 45 8B 3C 24 4C 8B 63 10 89 85 78 F1 FF FF 31 C0 83 BD 78 F1 FF FF 00 F3 AB 79 07 }
    condition:
        1 of ($a*) or all of ($b*)
}



// from Linux_Trojan_Zerobot.yar
rule Linux_Trojan_Zerobot_185e2396 {
    meta:
        author = "Elastic Security"
        id = "185e2396-f9eb-42e6-b78b-f8c01dbd3fd8"
        fingerprint = "f7ce4eebd5f13af3a480dfe23d86394c7e0f85f284a7c2900ab3fad944b08752"
        creation_date = "2022-12-16"
        last_modified = "2024-02-13"
        description = "Strings found in the zerobot startup / persistanse functions"
        threat_name = "Linux.Trojan.Zerobot"
        reference_sample = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $startup_method_1_0 = "/usr/bin/sshf"
        $startup_method_1_1 = "start on filesystem"
        $startup_method_1_2 = "exec /usr/bin/sshf"
        $startup_method_2_0 = "Description=Hehehe"
        $startup_method_2_1 = "/lib/systemd/system/sshf.service"
        $start_service_0 = "service enable sshf"
        $start_service_1 = "systemctl enable sshf"
    condition:
        (all of ($startup_method_1_*) or all of ($startup_method_2_*)) and 1 of ($start_service_*)
}

rule Linux_Trojan_Zerobot_3a5b56dd {
    meta:
        author = "Elastic Security"
        id = "3a5b56dd-e829-44bb-ae70-d7001addd057"
        fingerprint = "9800a241ab602434426830110ce244cdfd0023176e5fa64e2b8761234ed6f529"
        creation_date = "2022-12-16"
        last_modified = "2024-02-13"
        description = "Strings found in the Zerobot Spoofed Header method"
        threat_name = "Linux.Trojan.Zerobot"
        reference_sample = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $HootSpoofHeader_0 = "X-Forwarded-Proto: Http"
        $HootSpoofHeader_1 = "X-Forwarded-Host: %s, 1.1.1.1"
        $HootSpoofHeader_2 = "Client-IP: %s"
        $HootSpoofHeader_3 = "Real-IP: %s"
        $HootSpoofHeader_4 = "X-Forwarded-For: %s"
    condition:
        3 of them
}



// from Linux_Trojan_Zpevdo.yar
rule Linux_Trojan_Zpevdo_7f563544 {
    meta:
        author = "Elastic Security"
        id = "7f563544-4ef3-460f-9a36-23d086f9c421"
        fingerprint = "a2113b38c27ee7e22313bd0ffbcabadfbf7f3f33d241a97db2dc86299775afd6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Zpevdo"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 20 89 7D EC 48 89 75 E0 BE 01 00 00 00 BF 11 00 }
    condition:
        all of them
}



// from Linux_Virus_Gmon.yar
rule Linux_Virus_Gmon_e544d891 {
    meta:
        author = "Elastic Security"
        id = "e544d891-3f6d-4da2-be86-e4ab58c66465"
        fingerprint = "269f0777f846f9fc8fe56ea7436bddb155cde8c9a4bf9070f46db0081caef718"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Gmon"
        reference_sample = "d0fe377664aa0bc0d1fd3a307650f211dd3ef2e2f04597abee465e836e6a6f32"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E5 53 51 52 8B 44 24 14 8B 5C 24 18 8B 4C 24 1C 8B 54 24 20 }
    condition:
        all of them
}

rule Linux_Virus_Gmon_192bd9b3 {
    meta:
        author = "Elastic Security"
        id = "192bd9b3-230a-4f07-b4f9-06213a6b6f47"
        fingerprint = "532055052554ed9a38b16f764d3fbae0efd333f5b2254b9a1e3f6d656d77f1e4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Gmon"
        reference_sample = "d0fe377664aa0bc0d1fd3a307650f211dd3ef2e2f04597abee465e836e6a6f32"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E5 56 53 8B 75 08 8B 5D 0C 8B 4D 10 31 D2 39 CA 7D 11 8A 04 1A 38 }
    condition:
        all of them
}



// from Linux_Virus_Rst.yar
rule Linux_Virus_Rst_1214e2ae {
    meta:
        author = "Elastic Security"
        id = "1214e2ae-90e4-425e-b47f-0a0981623236"
        fingerprint = "a13a9825815a417be991db57f80dac4d0c541e303e4a4e6bd03c46ece73703ea"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Rst"
        reference_sample = "b0e4f44d2456960bb6b20cb468c4ca1390338b83774b7af783c3d03e49eebe44"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 53 89 F3 CD 80 5B 58 5F 5E 5A 59 5B C3 }
    condition:
        all of them
}



// from Linux_Virus_Staffcounter.yar
rule Linux_Virus_Staffcounter_d2d608a8 {
    meta:
        author = "Elastic Security"
        id = "d2d608a8-2d65-4b10-be71-0a0a6a027920"
        fingerprint = "a791024dc3064ed2e485e5c57d7ab77fc1ec14665c9302b8b572ac4d9d5d2f93"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Staffcounter"
        reference = "06e562b54b7ee2ffee229c2410c9e2c42090e77f6211ce4b9fa26459ff310315"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 22 00 20 4C 69 6E 75 78 22 20 3C 00 54 6F 3A 20 22 00 20 }
    condition:
        all of them
}



// from Linux_Virus_Thebe.yar
rule Linux_Virus_Thebe_1eb5985a {
    meta:
        author = "Elastic Security"
        id = "1eb5985a-2b35-434f-81d9-f502dff25397"
        fingerprint = "5cf9aa9a31c36028025d5038c98d56aef32c9e8952aa5cd4152fbd811231769e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Thebe"
        reference_sample = "30af289be070f4e0f8761f04fb44193a037ec1aab9cc029343a1a1f2a8d67670"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 31 C9 31 DB 31 F6 B0 1A CD 80 85 C0 0F 85 83 }
    condition:
        all of them
}



// from Linux_Webshell_Generic.yar
rule Linux_Webshell_Generic_e80ff633 {
    meta:
        author = "Elastic Security"
        id = "e80ff633-990e-4e2e-ac80-2e61685ab8b0"
        fingerprint = "dcca52dce2d50b0aa6cf0132348ce9dc234b985ae683b896d9971d409f109849"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Webshell.Generic"
        reference_sample = "7640ba6f2417931ef901044152d5bfe1b266219d13b5983d92ddbdf644de5818"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 A8 00 00 00 89 1C 24 83 3C 24 00 74 23 83 04 24 24 8D B4 24 AC 00 }
    condition:
        all of them
}

rule Linux_Webshell_Generic_41a5fa40 {
    meta:
        author = "Elastic Security"
        id = "41a5fa40-a4e7-4c97-a3b9-3700743265df"
        fingerprint = "49e0d55579453ec37c6757ddb16143d8e86ad7c7c4634487a1bd2215cd22df83"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Webshell.Generic"
        reference = "18ac7fbc3d8d3bb8581139a20a7fee8ea5b7fcfea4a9373e3d22c71bae3c9de0"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5A 46 55 6C 73 6E 55 6B 56 52 56 55 56 54 56 46 39 56 55 6B 6B }
    condition:
        all of them
}



// from Linux_Worm_Generic.yar
rule Linux_Worm_Generic_920d273f {
    meta:
        author = "Elastic Security"
        id = "920d273f-5b2b-4eec-a2b3-8d411f2ea181"
        fingerprint = "3d4dd13b715249710bc2a02b1628fb68bcccebab876ff6674cad713e93ac53d2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "04a65bc73fab91f654d448b2d7f8f15ac782965dcdeec586e20b5c7a8cc42d73"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E9 E5 49 86 49 A4 1A 70 C7 A4 AD 2E E9 D9 09 F5 AD CB ED FC 3B }
    condition:
        all of them
}

rule Linux_Worm_Generic_98efcd38 {
    meta:
        author = "Elastic Security"
        id = "98efcd38-d579-46f7-a8f8-360f799a5078"
        fingerprint = "d6cec73bb6093dbc6d26566c174d0d0f6448f431429edef0528c9ec1c83177fa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "87507f5cd73fffdb264d76db9b75f30fe21cc113bcf82c524c5386b5a380d4bb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 14 75 E1 8B 5A 24 01 EB 66 8B 0C 4B 8B 5A 1C 01 EB 8B 04 8B }
    condition:
        all of them
}

rule Linux_Worm_Generic_bd64472e {
    meta:
        author = "Elastic Security"
        id = "bd64472e-92a2-4d64-8008-b82d7ca33b1d"
        fingerprint = "1978baa7ff5457e06433fd45db098aefd39ea53d3f29e541eef54890a25a9dce"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "b3334a3b61b1a3fc14763dc3d590100ed5e85a97493c89b499b02b76f7a0a7d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 EC 83 7D EC FF 75 38 68 54 90 04 08 }
    condition:
        all of them
}

rule Linux_Worm_Generic_3ff8f75b {
    meta:
        author = "Elastic Security"
        id = "3ff8f75b-619e-4090-8ea4-aedc8bdf61a4"
        fingerprint = "011f0cd72ebb428775305c84eac69c5ff4800de6e1d8b4d2110d5445b1aae10f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "991175a96b719982f3a846df4a66161a02225c21b12a879e233e19124e90bd35"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3A DF FE 00 66 0F 73 FB 04 66 0F 6F D3 66 0F EF D9 66 0F 6F EE 66 0F 70 }
    condition:
        all of them
}



