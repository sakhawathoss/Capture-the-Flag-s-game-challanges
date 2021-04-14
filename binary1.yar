rule Ryuk_binary1 {
       meta:
               description = "Detects binary1.exe of RYUK ransomeware"
               author = "Sakahwat"
       strings:
              $s1 = "7S \i|9#X" ascii wide
              $s2 = "4Y6OjTi" ascii wide
              $s3 = "%\Y0aheA"
       conditions:
              any 1 of them

}