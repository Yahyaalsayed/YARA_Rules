rule rhadamanthys
{
    meta:
		    author = "Yahya Alsify"
        	description = "Detects Rhadamanthya loader"
        	hash1 = "ee3fe7d514c1c8612015a0a9b6a4b504c2bedbd7050b401636f8c0eaef4ac0b3"
			hash2 = "cf1c65dbc78752ec240cc82b8630dec062d91ed939e68db068993c5b1023071e"
			hash3 = "cf1c65dbc78752ec240cc82b8630dec062d91ed939e68db068993c5b1023071e"
			hash4 = "1f42c9d833bf800b384a80424dd05f50d597dc3566856f245156fb266a40c797"

    strings:
          $s1 = {81 3E 21 52 48 59}   // "YHR!"
          $s2 = "CSRF-TOKEN=%s; LANG=%s"
          $s3 = "HTTP/1.1\r\nHost:"
          $s4 = "prepare.bin"
          $s5 = "xss-protection"

          $s6 = {25 00 25 00 54 00 45 00 4D 00 50 00 25 00 25 00}    // "%%TEMP%%\nsis_uns%04x.dll"
          $s7 = {20 00 22 00 25 00 73 00 22 00 2C 00 50 00 72 00}    // "PrintUIEntry"
          $s8 = "keep-alive"
          $s9 = "User-Agent"
          $s10 = "GET"
          $s11 = {25 00 53 00 79 00 73 00 74 00 65 00 6D 00 72 00}    // "%Systemroot%\\system32\\rundll32.exe"

          $enable_dispacher = {
          	85 C0                // 85C0                          test eax, eax
          	75 ??                // 7509                          jne 0x5e47
          	83 7D ?? 22          // 837D0C22                      cmp dword ptr [ebp + 0xc], 0x22
          	75 ??                // 7503                          jne 0x5e47
          	83 0E 20             // 830E20                        or dword ptr [esi], 0x20
          }

          $call_opcode = {
          	83 F8 ??               //   83F805                        cmp eax, 5
          	59                     //   59                            pop ecx
          	75 ??                  //   7505                          jne 0x5ebb
          	80 3F E8               //   803FE8                        cmp byte ptr [edi], 0xe8
          	74 ??                  //   7404                          je 0x5ebf
          	03 F8                  //   03F8                          add edi, eax
          	EB ??                  //   EBE1                          jmp 0x5ea0
          }


          $cmplx_ops = {			
          	8B CE                             // 8BCE                          mov ecx, esi
          	8B B4 88 ?? ?? ?? ??              // 8BB48820500000                mov esi, dword ptr [eax + ecx*4 + 0x5020]
          	3B F2                             // 3BF2                          cmp esi, edx
          	75 ??                             // 75F3                          jne 0x5a33
          	8B BC 88 ?? ?? ?? ??              // 8BBC8824940000                mov edi, dword ptr [eax + ecx*4 + 0x9424]
          	8B 9C 88 ?? ?? ?? ??              // 8B9C881C100000                mov ebx, dword ptr [eax + ecx*4 + 0x101c]
          	8D B4 88 ?? ?? ?? ??              // 8DB4881C100000                lea esi, [eax + ecx*4 + 0x101c]
          	89 9C B8 ?? ?? ?? ??              // 899CB820500000                mov dword ptr [eax + edi*4 + 0x5020], ebx
          	8B 9C 88 ?? ?? ?? ??              // 8B9C8824940000                mov ebx, dword ptr [eax + ecx*4 + 0x9424]
          	8B 3E                             // 8B3E                          mov edi, dword ptr [esi]
          	89 9C B8 ?? ?? ?? ??              // 899CB824940000                mov dword ptr [eax + edi*4 + 0x9424], ebx
          	8B 7C 24 ??                       // 8B7C2414                      mov edi, dword ptr [esp + 0x14]
          	8B 9C B8 ?? ?? ?? ??              // 8B9CB81C100000                mov ebx, dword ptr [eax + edi*4 + 0x101c]
          	89 1E                             // 891E                          mov dword ptr [esi], ebx
          	8B B4 B8 ?? ?? ?? ??              // 8BB4B81C100000                mov esi, dword ptr [eax + edi*4 + 0x101c]
          	89 8C B0 ?? ?? ?? ??              // 898CB024940000                mov dword ptr [eax + esi*4 + 0x9424], ecx
          }

    condition:
          8 of ($s*) and 2 of ($cmplx_ops ,$call_opcode , $enable_dispacher)
}
