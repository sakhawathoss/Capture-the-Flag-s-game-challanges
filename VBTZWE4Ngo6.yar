rule Ryuk_4VBTZWE4Ngo6 {
       meta:
               description = "4VBTZWE4Ngo6.exe of RYUK ransomeware"
               author = "Sakahwat"
       strings:
              $s1 = "runtime.(*gcControllerState).findRunnableGCWorker" ascii wide
              $s2 = "type..hash.struct { reflect.b bool; reflect.x interface {} }" ascii wide
              $s3 = "Token=b77a5c561934e089#~"ascii wide
              $s4 = "crypto/tls.(*clientHandshakeState).handshake" ascii wide
              $s5 = "SkipVerification" ascii wide

        conditions:
              any 1 of them

}