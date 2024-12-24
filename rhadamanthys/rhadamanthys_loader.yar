rule rhadamanthys
{
    meta:
	author = "Yahya Alsify"
        description = "Detects Rhadamanthya loader"
        hash = "ee3fe7d514c1c8612015a0a9b6a4b504c2bedbd7050b401636f8c0eaef4ac0b3"
        hash2 = "cf1c65dbc78752ec240cc82b8630dec062d91ed939e68db068993c5b1023071e"
	hash3 = "cf1c65dbc78752ec240cc82b8630dec062d91ed939e68db068993c5b1023071e"
	hash4 = "1f42c9d833bf800b384a80424dd05f50d597dc3566856f245156fb266a40c797"
    strings:
    	$s1 = "prepare.bin"
	$s2 = "CSRF-TOKEN=%s; LANG=%s" 
	$s3 = "nsis_uns%04x.dll" wide
	$s4 = "Global\\MSCTF.Asm.{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide

	$chk_mgc_bytes = {
		81 ?? 21 52 48 59                 					// cmp     dword ptr [esi], 59485221h
		75 ??                             					// jnz     short loc_42EB
	}	

    condition:
	all of them 
}
