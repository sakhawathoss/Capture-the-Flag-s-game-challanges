rule Ryuk_conhost {
       meta:
               description = "Detects conhost.exe of RYUK ransomeware"
               author = "Sakahwat"
       strings:
              $s1 = "API-MS-Win-Core-LocalRegistry-L1-1-0.dll" ascii wide
              $s2 = "VDM converting to fullscreen twice" ascii wide
              $s3 = "Finding Font file failed due to an error or insufficient buffer" ascii wide
              $s4 = "Finding Font file failed due to an error or insufficient buffer"
       conditions:
              any 2 of them

}