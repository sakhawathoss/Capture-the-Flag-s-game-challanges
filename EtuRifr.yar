rule Ryuk_EtuRifr {
       meta:
               description = "Detects EtuRifr.exe of RYUK ransomeware"
               author = "Sakahwat"
       strings:
              $s1 = "ReCreateDbcsScreenBuffer failed. Restoring to CP=%d" ascii wide
              $s2 = "Console init failed with status 0x%x" ascii wide
              $s3 = "vInvalid Parameter: 0x%x, 0x%x, 0x%x"
              $s4 = "RtlIntegerToUnicodeString"
              $s5 = "RtlIntegerToUnicodeString"
              $s6 = "RtlConsoleMultiByteToUnicodeN"
       conditions:
              all of them

}