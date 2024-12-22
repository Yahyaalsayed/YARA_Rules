rule rhadamanthys_init_stage
{
    meta:
		author = "Yahya Alsify"
        description = "Detects Initial Stage of Rhadamanthya loader"
        hash = "dca16a0e7bdc4968f1988c2d38db133a0e742edf702c923b4f4a3c2f3bdaacf5"
		hash = "9917b5f66784e134129291999ae0d33dcd80930a0a70a4fbada1a3b70a53ba91"
		hash = "3300206b9867c6d9515ad09191e7bf793ad1b42d688b2dbd73ce8d900477392e"
    strings:
		$mz = {4D 5A} //PE File
		$shellcode_hex = {37 41 52 51 41 41 41 41 53 43 49 4a 41 51 41 45 41 41 41 50 4a 38 59 41 41 42 53 4d 47 41 49 41 4b 54 46 4b 39 45 4e 4d 47 4d 44 41 48 38 55 58 41 4a 47 50 4e 34 56 34 4c 53 49 4a 42 45 45 51 4c}
		$shellcode_a = "7ARQAAAASCIJAQAEAAAN79YAADSMUAIAKTFK9ENMGMDAH8UXAJGPN4V4LSIJBEEQL"
		$s2 = "GetQueuedCompletionStatus"
		$s3 = "GetSystemInfo"
		$s4 = "VirtualQuery"
		$s5 = "IsBadCodePtr"
		$s6 = "DispatchMessage"

		$stor_struct_addr = {
					8B ?? ??			// mov eax, dword ptr [ebp - 0x14]
					8B ?? ??			// mov ecx, dword ptr [ebp - 0x10]
					89 ?? ?? ?? ?? ??	// mov dword ptr [eax + 0xa4], ecx
					8B 45 ??			// mov eax, dword ptr [ebp - 0x14]
					8B 4D ??			// mov ecx, dword ptr [ebp - 0x14]
					89 48 ??			// mov dword ptr [eax + 4], ecx
					8B ?? ??			// mov eax, dword ptr [ebp - 0x14]
					83 ?? ??			// add eax, 0x50
					8B ?? ??			// mov ecx, dword ptr [ebp - 0x14]
					89 ?? ??			// mov dword ptr [ecx + 0x50], eax
					8B ?? ??			// mov eax, dword ptr [ebp - 0x14]
					83 C? ??			// add eax, 0x50
					8B ?? ??			// mov ecx, dword ptr [ebp - 0x14]
					89 4? ??			// mov dword ptr [ecx + 0x54], eax
					33 C0				// xor eax, eax
					75 ??				// jne 0x403ca9
					8B 4? ??			// mov eax, dword ptr [ebp - 0x14]
					83 C? ??			// add eax, 0x58
					8B ?? ??			// mov ecx, dword ptr [ebp - 0x14]
					89 4? ??			// mov dword ptr [ecx + 0x58], eax
					8B 45 ??			// mov eax, dword ptr [ebp - 0x14]
					83 C0 ??			// add eax, 0x58
					8B 4D ??			// mov ecx, dword ptr [ebp - 0x14]
					89 41 ??			// mov dword ptr [ecx + 0x5c], eax
		}

		$cpy_structs = {
					8B 44 24 ??						// mov eax, dword ptr [esp + 8]
					8B 4C 24 ??						// mov ecx, dword ptr [esp + 4]
					89 48 ??						// mov dword ptr [eax + 8], ecx
					83 C1 ??						// add ecx, 8
					C7 40 ?? ?? ?? ?? ??			// mov dword ptr [eax + 0xc], 3
					C7 40 ?? ?? ?? ?? ??			// mov dword ptr [eax + 0x1c], 0x20
					8D 50 ??						// lea edx, [eax + 0x10]
					56								// push esi
					8B 31							// mov esi, dword ptr [ecx]
					89 32							// mov dword ptr [edx], esi
					89 56 ??						// mov dword ptr [esi + 4], edx
					89 48 ??						// mov dword ptr [eax + 0x14], ecx
					89 11							// mov dword ptr [ecx], edx
					33 C9							// xor ecx, ecx
					89 48 ??						// mov dword ptr [eax + 0x48], ecx
					89 48 ??						// mov dword ptr [eax + 0x38], ecx
					89 48 ??						// mov dword ptr [eax + 0x3c], ecx
					33 C0							// xor eax, eax
					5E								// pop esi
					C3								// ret 
		}
		$math_ops = {
					74 ??				 	 // je 0x401fef
					83 E0 ??				 // and eax, 0xffffffbf
		}
    condition:
		($mz at 0) and ($shellcode_a or $shellcode_hex) and 2 of ($stor_struct_addr , $cpy_structs , $math_ops) and 3 of ($s*)
}
