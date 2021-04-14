rule Ryuk_CXYIJLO {
       meta:
               description = "Detects CXYIJLO.exe of RYUK ransomeware"
               author = "Sakahwat"
       strings:
              $s1 = "SYSTEM\CurrentControlSet\Control\Nls\Language\
InstallLanguage
0412" ascii wide
              $s2 = "Wow64DisableWow64FsRedirection" ascii wide
              $s3 = "vssadmin Delete Shadows /all /quiet"ascii wide
              $s4 = "vssadmin resize shadowstorage "ascii wide
              $s5 = "@protonmail.com"
       conditions:
             2 of them

}