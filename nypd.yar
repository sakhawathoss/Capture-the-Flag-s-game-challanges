rule Ryuk_NYPD {
       meta:
               description = "Detects NYPD.exe of RYUK ransomeware"
               author = "Sakahwat"
       strings:
              $s1 = "vssadmin Delete Shadows /all /quiet" ascii wide
              $s2 = "vssadmin resize Shadows shadowstorage" ascii wide
              $s3 = "@protonmail.com"
       conditions:
              3 of them

}
