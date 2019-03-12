from __future__ import print_function
import binascii
import time
import datetime
import struct

def config_decompile(data):
	result = []

	VM_DATA = []
	VM_DATATABLE = [
		0xD3955141, # part of an array that seems to be never initialized
	]
	VM_CALLTABLE = []
	VM_CODE = []

	CONST_XOR_KEY = 0xDDFCB5FE

	DB_STRINGS = {
		0x01EE31CC : "msiexec.exe", 0x08245A25 : "dwm.exe", 0x08EC6E05 : "dism.exe", 0x0BC65973 : "regsvr32.exe", 
		0x0BEFE2F4 : "msaccess.exe", 0x0BF26394 : "taskmgr.exe", 0x1BC03B9D : "avastsvc.exe", 0x29C2024E : "avastui.exe", 
		0x29C80A35 : "avpui.exe", 0x2BC41E48 : "sysprep.exe", 0x45C44594 : "msmpeng.exe", 0x4BF60999 : "cliconfg.exe", 
		0x54F4AC92 : "winlogon.exe", 0x5BF243DD : "taskeng.exe", 0x60C076C4 : "chrome.exe", 0x61C20ECB : "mysqld.exe", 
		0x68E67595 : "mspaint.exe", 0x6BE2700F : "jusched.exe", 0x6CC263AC : "certutil.exe", 0x6CCD959F : "onedrive.exe", 
		0x6CEE1122 : "notepad.exe", 0x71F4763D : "sihost.exe", 0x71F806AF : "winsat.exe", 0x73FAEE7D : "taskhost.exe", 
		0x75F8EC7D : "dismhost.exe", 0x76CA6BF9 : "winword.exe", 0x76F46EF3 : "conhost.exe", 0x76F66F20 : "wininit.exe", 
		0x78E1F6C7 : "mcupdate.exe", 0x78EC4E07 : "update.exe", 0x7BC073E5 : "wscript.exe", 0x7BC076E5 : "cscript.exe", 
		0x7BCC5E95 : "steam.exe", 0x7BDB9539 : "solitaire.exe", 0x7DCA7F6F : "setupsqm.exe", 0x7DCE1117 : "powerpnt.exe", 
		0x7DD446B5 : "excel.exe", 0x85C21A05 : "mstsc.exe", 0x8BC20204 : "csrss.exe", 0x91722D02 : "aswidsagenta.exe", 
		0x94F6BC8C : "explorer.exe", 0x97CC60F9 : "acrord32.exe", 0x982446F5 : "cmd.exe", 0x98247E0C : "mrt.exe", 
		0x98FE06BC : "msdt.exe", 0x9CF22577 : "rundll32.exe", 0x9CFC6D1F : "outlook.exe", 0x9DCC64D3 : "inetmgr.exe", 
		0x9EF83FCD : "services.exe", 0xA5C26A3D : "mshta.exe", 0xA7C45E0D : "opera.exe", 0xAAEE4B50 : "firefox.exe", 
		0xC2E61294 : "javaw.exe", 0xC8F04E2D : "java.exe", 0xD5E1BE04 : "mpcmdrun.exe", 0xD7FA66FC : "spoolsv.exe", 
		0xD8244E2C : "avp.exe", 0xE82412BC : "vds.exe", 0xE8247EF5 : "mmc.exe", 0xE8C27E04 : "smss.exe", 
		0xE8E24EFD : "calc.exe", 0xED0AA787 : "powershell.exe", 0xEFF4681E : "splwow64.exe", 0xF4F46F32 : "dllhost.exe", 
		0xF7F4A17F : "vmtoolsd.exe", 0xF8F14F71 : "iexplore.exe", 0xFBF22E1D : "skype.exe", 0xFBF46AFF : "svchost.exe",
		0x08247A05 : "lsm.exe", 0x0AA0FB44 : "searchindexer.exe", 0x4381848C : "system", 0x4CF66EC7 : "audiodg.exe", 
		0x84C24E04 : "lsass.exe", 0x85C25A3D : "msdtc.exe", 0xB9CF3304 : "searchprotocolhost.exe", 0x70FBE604 : "mcshield.exe",
		0xF9EA465E : "bdagent.exe", 0x1AC4A245 : "seccenter.exe", 0x4BB01F3C : "updatesrv.exe", 0xCBC25E37 : "vsserv.exe",
		0x48EE5635 : "egui.exe", 0x38EE660D : "ekrn.exe", 0xEBE26AB5 : "sched.exe", 0xF9C856EC : "avgnt.exe",
		0xFFCE5676 : "avguard.exe", 0x01FE1A14 : "psimsvc.exe", 0x06E61D5C : "mcnasvc.exe", 0x0BCC1EC5 : "psctrls.exe",
		0x0BCDAE41 : "msksrver.exe", 0x16FE1DDD : "msnmsgr.exe", 0x1BEE5DCD : "msseces.exe", 0x1BEFBEDB : "mcmscsvc.exe",
		0x1CC21A1C : "pctssvc.exe", 0x1FE03B9E : "avgwdsvc.exe", 0x235D0076 : "engineserver.exe", 0x23CC1AEF : "avktray.exe",
		0x2ACC2F0E : "fpavserver.exe", 0x2B10FECE : "vmwareuser.exe", 0x2FCC1AEF : "avgtray.exe", 0x37C45BDD : "dropbox.exe",
		0x40E02AEE : "apvxdwin.exe", 0x45D44697 : "umxcfg.exe", 0x48E8063A : "mpfsrv.exe", 0x4DC415E1 : "pavsrvx86.exe",
		0x503C21C5 : "pchooklaunch32.exe", 0x5AFE1B3A : "tmbmsrv.exe", 0x66E6535F : "avengine.exe", 0x66FA023F : "runouce.exe",
		0x69EFCEF4 : "mcsacore.exe", 0x6EEE12FD : "ccsvchst.exe", 0x70C21AAD : "shstat.exe", 0x75A51274 : "avkservice.exe",
		0x79C802E4 : "cavrid.exe", 0x79EA459D : "mcagent.exe", 0x7DE8EF55 : "ufseagnt.exe", 0x8AE1A6DC : "naprdmgr.exe",
		0x8BE07E5A : "sqlservr.exe", 0x8BFCA25E : "vstskmgr.exe", 0x9ACBA2F7 : "tscfplatformcomsvr.exe", 0x9B12FAEE : "vmwaretray.exe",
		0x9BE806A6 : "pctsauxs.exe", 0x9BF20615 : "psksvc.exe", 0x9EF61E57 : "pavfnsvr.exe", 0xAAF66AFC : "ccprovsp.exe",
		0xABCC02A2 : "mctray.exe", 0xAEEA0234 : "avgrsx.exe", 0xAEEA7234 : "avgnsx.exe", 0xB508D574 : "frameworkservice.exe",
		0xB8C06B6A : "tmproxy.exe", 0xB8C06D2D : "mcproxy.exe", 0xB8CC4BE9 : "avkproxy.exe", 0xBBCE3F9F : "avgcsrvx.exe",
		0xBCC24A04 : "pctsgui.exe", 0xBCE0BB05 : "udaterui.exe", 0xC1CFC61C : "mcsysmon.exe", 0xC45393B8 : "swi_service.exe",
		0xC8CE1E77 : "pavprsrv.exe", 0xCDCC7E3E : "vetmsg.exe", 0xDCC246A6 : "gdscan.exe", 0xE4A371F8 : "savadminservice.exe",
		0xE4D6B274 : "savservice.exe", 0xE6F7E107 : "onenotem.exe", 0xEBF4458C : "mcshell.exe", 0xF5D40ADF : "umxpol.exe",
		0xF9E4E590 : "umxagent.exe", 0xF9E6259E : "cmdagent.exe", 0xFCF23F54 : "sfctlcom.exe", 0xA934A324 : "protoolbarupdate.exe",

		# The following checksums are obtained through permutation bruteforce
		0x59FC7EE5 : "almon.exe", # Sophos AutoUpdate
		0x5EC416D5 : "fpwin.exe", # F-PROT Antivirus for Windows
		0x88FA768D : "oobe.exe", # Microsoft Windows Vista Promotional Pack
		0x89FC062D : "alsvc.exe", # Sophos Anti-Virus by Sophos
		0xB8E24E94 : "caav.exe", # CA Anti-Virus
		0xC8CA0205 : "wrsa.exe", # Webroot SecureAnywhere
		0xD82446AC : "cfp.exe", # COMODO Internet Security / COMODO Firewall Pro
		0xDCFE0AAC : "tmpfw.exe", # Trend Micro Internet Security
		0xE8E24E05 : "casc.exe", # CA Security Suite
		0xE8EA5A05 : "gdsc.exe", # G Data SecurityCenter / Ad-Aware Total Security
	}

	DB_VARIABLES = {
		# Virtual machine blocks
		0xB2564545 : 'CPU',		# CPU
		0x06C742A3 : 'TIME',	# TIME
		0x5878305F : 'FLAG',	# FLAG
		# Stack
		0xC3AB60F9 : 'SP_00',
		0x22484B04 : 'SP_04',
		0xB1C01A4B : 'SP_08',
		0xB1C01A4D : 'SP_0C',
		0xB1C01A41 : 'SP_10',
		0xC3AB6EFA : 'SP_14',
		0xC3AB6EFE : 'SP_18',
		0x2BA9620A : 'SP_1C',
		0xA2F4B104 : 'SP_20',
		0x56101E48 : 'SP_24',
		0x56101E44 : 'SP_28',
		0x2BA96C09 : 'SP_2C',
		0x2BA96C0D : 'SP_30',
		0x5D9FE05B : 'SP_34',
		0x3DB1E23A : 'SP_38',
		0x4EE3E12E : 'SP_3C',
		0x4FE6E3AE : 'SP_40',
		0xBAE2E057 : 'SP_44',
		0xBBE7E2D7 : 'SP_48',
		0xD9089263 : 'SP_4C',
		# General purpose register set
		0xDDFCB617 : 'R0',
		0xDDFCB614 : 'R1',
		0xDDFCB615 : 'R2',
		0xDDFCB612 : 'R3',
		0xDDFCB613 : 'R4',
		0xDDFCB610 : 'R5',
		# Local variables
		0x11C7AFA3 : 'LOC_00',
		# Data entries
		0xAE97A09A : "DATA_PROCLIST_EXCLUDE",
		0x913A66EC : "DATA_PROCLIST_EXCLUDE_EXT",
		0xD3955140 : "DATA_PAYLOAD_TARGET_ENUMERATOR",
		0xC4B21945 : "DATA_GOOGLE_DNS",
	}

	dex = lambda val: val ^ CONST_XOR_KEY
	decode_crc = lambda crc: DB_STRINGS[crc] if crc in DB_STRINGS else None
	fmt_var = lambda id: DB_VARIABLES[dex(id)] if dex(id) in DB_VARIABLES else None
	fmt_val = lambda value: "&"+fmt_var(value) if fmt_var(value) is not None else "0x%08X"%value
	fmt_addr = lambda i: "&ADDR:%04X"%i

	def get_label(req_xref):
		for i, entry in enumerate(VM_CODE):
			if dex(entry['id']) == 0xCA57746D:
				(res_xref, ) = struct.unpack_from("<L", entry['data'], 0)
				if res_xref == req_xref:
					return i
		return None

	def format_crclist(data):
		result = []
		for offset in range(0, len(data), 4):
			(crc, ) = struct.unpack_from("<L", data, offset)

			crc = dex(crc)
			if decode_crc(crc) is None:
				result.append("0x%08X"%crc)
			else:
				result.append("\""+decode_crc(crc)+"\"")

		return result

	offset = 0
	while (offset < len(data)):
		
		(entry_id, entry_len) = struct.unpack_from('<LL', data, offset)
		offset += 8

		entry_data = data[offset:offset+entry_len]
		offset += len(entry_data)

		VM_CODE.append({'id':entry_id, 'data':entry_data})

	"""
	# VM CPU @ B2564545
		0x00 # 0x00000016)	# Hardcoded
		0x04 # 0x00000014)	# Hardcoded
		0x08 # 0x000138A0)	# Hardcoded
		0x0C # 0x00000040)	# Hardcoded
		# BOF: OSVERSIONINFOEXW structure (not complete)
		0x10 # dwMajorVersion
		0x14 # dwMinorVersion
		0x18 # dwBuildNumber
		0x1C # dwPlatformId
		0x20 # wServicePackMajor
		0x24 # wServicePackMinor
		0x28 # wSuiteMask
		0x2C # wProductType
		# EOF
		0x30 # SubAuthID = 0x2000
		0x34 # another flag, set at 00433F76
		0x38 # CheckSID; IsUserAdmin flag?
		0x3C # flag set at 00433F87
		0x40 # 0x00000020 ?
		0x44 # Locale "US" taken by GetLocaleInfoA
		0x48 # address to PEB (VA 7EFDE000)
		0x4C # init to 0
		0x50 # 0x00000001
		0x54 # 0x00000001
		0x58 # 0x00000000)	# set at 00433F8F
		# BOF : entries init to zero
		0x5C # 0x00000000)	# 
		0x60 # 0x00000000)	# 
		0x64 # 0x00000000)	# 
		0x68 # 0x00000000)	# 
		0x6C # 0x00000000)	# 
		# EOF
		# BOF : Flags
		0x70 # 0x00000000 flag set at 00433FBA and taken from 00440EF8
		0x74 # 0x00000001 flag set at 00433FC2 and taken from 004409E4
		0x78 # 0x00000001 flag set at 00433FCD and taken from 004408F4
		0x7C # 0x00000000 flag set at 00433FD8 and taken from 004411A8
		0x80 # 0x00000001 local event set
		# EOF

	# VM TIME @ 06C742A3 (struct SYSTEMTIME)
		0x00 # wYear
		0x02 # wMonth
		0x04 # wDayOfWeek
		0x06 # wDay
		0x08 # wHour
		0x0A # wMinute
		0x0C # wSecond
		0x10 # wMilliseconds

	# VM FLAG @ 5878305F
		0x00 # ERROR_CODE
		0x04 # A0
		0x08 # A1
		0x0C # A2
	"""

	result.append("// VM &CPU @ B2564545")
	result.append("// VM &TIME @ 06C742A3")
	result.append("// VM &FLAG @ 5878305F")
	for VM_EIP, entry in enumerate(VM_CODE):
		id = dex(entry['id'])

		line = fmt_addr(VM_EIP)+"   "
		if id == 0x9452FF46: # Compile FILETIME
			""" first instruction from the config is a FILETIME structure
			"""

			(ms, ) = struct.unpack_from("<Q", entry['data'], 0)

			line += "// compile timestamp: %s"%(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=(ms // 10))).isoformat()

			pass
		elif id == 0x49DCBE49: # Version ?
			""" Version ?
			"""

			line += "// version: %d.%d.%d.%d"%struct.unpack_from("<LLLL", entry['data'], 0)
			
			pass
		elif id == 0x3B0B5D73: # Expiration date
			""" Expiration date
			"""
			(d1, d2, d3) = struct.unpack_from("<LLL", entry['data'], 0)
			
			line += "// expiration date: %s"%time.strftime("%d %B %Y", (d3, d2, d1, 0, 0, 0, 0, 0, 0))

			pass
		elif id == 0x47FC87E2: # Variable assignment
			""" Variable assignment
			"""
			(d1, d2, d3, d4) = struct.unpack_from("<LLLL", entry['data'], 0)

			line += "%s = %s;"%(fmt_var(d3), fmt_val(d4))

			pass
		elif id == 0x39549CAE: # Initalize data entries
			""" Initalize data entries
			"""
			(d1, d2, d3, xref_a, xref_b) = struct.unpack_from("<LLLLL", entry['data'], 0)
		
			array_range = {
				'start': get_label(xref_a),
				'end': get_label(xref_b)
			}

			for data_i in range(array_range['start']+1, array_range['end']):
				VM_DATATABLE.append(dex(VM_CODE[data_i]["id"]))

			line += "InitData(start=%s, end=%s);"%("LABEL_%02X"%array_range['start'], "LABEL_%02X"%array_range['end'])

			pass
		elif id == 0x8E223809: # If-Then-Goto (args from registers)
			""" CMP from registers
			"""
			(d1, d2, d3) = struct.unpack_from("<LLL", entry['data'], 0)

			# A and B are taken from the general purpose Registers R0 and R3
			line += "IF &R0[R1] == &R3[R4] GOTO LABEL_%02X;"%(get_label(d3))

			pass
		elif id == 0x5F3C31A8: # If-True-Goto (args from memory/mixed)
			""" JMP
				Depending on the previous CMP result, either jumps to xref or continues down
				match - continue
				don't match - jump to Xref
			"""
			(mode, xref) = struct.unpack_from("<LL", entry["data"], 0)

			line += "IF True GOTO LABEL_%02X;"%get_label(xref)

			pass
		elif id == 0xC45DB8E2: # Debug messages
			""" Debug messages are ignored
			"""
			line += "DebugMessage(\"%s\"); // not processed in any way"%entry["data"].decode("utf-8")

			pass
		elif id == 0x4E7016FB: # CALL procedure
			""" CALL / EXEC
			the Xref is pointing to a CA57746D entry
			the next entry (after the matched CA57746D) is the procedure that is going to get executed
			"""

			(xref, ) = struct.unpack_from("<L", entry["data"], 0)

			xref = get_label(xref)

			VM_CALLTABLE.append(xref)

			line += "CALL PROC_%02X;"%xref

			pass
		elif id == 0x5F3E76BB: # Value comparision
			""" CMP
				arg1 takes the EIP from the Register set and arg2 takes a stored value from the Memory set
				the two values are compared and a flag is set to True if they match
			"""

			(
				flag_enabled, 
				arg1_varID_A, 
				arg1_varID_B, 
				arg1_d3, 
				arg2_varID_A, 
				arg2_varID_B, 
				arg2_d3) = struct.unpack_from("<LLLLLLL", entry["data"], 0)

			line += "TEST &%s == &%s;"%(fmt_var(arg1_varID_A), fmt_var(arg2_varID_A))

			pass
		elif id == 0x4EDFEEA0: # Return from procedure
			""" RET
				Return to the last EIP from the CALLSTACK
			"""
			line += "RETURN;"
		elif id == 0xBC455183: # Procedure: Antivirus check
			"""	When a listed in the CRC table AV is found 
			the CRC and the PID of the running AV are set
			to the Registers R0 and R1 (in that order)
			"""

			line += "IsProcessRunning(%s);"%(", ".join(format_crclist(entry["data"][4:])))

			(flag_enabled, ) = struct.unpack_from("<L", entry["data"], 0)
			if flag_enabled == 0:
				line += " // Disabled"
			elif flag_enabled == 1:
				line += " // Enabled"
			else:
				line += " // Unknown flag value: %08X"%flag_enabled

			pass
		elif id == 0x99D8387F: # Procedure: Environment strings
			""" Check for environment string
			"""

			line += "IsEnvStringSet(%s);"%(", ".join(format_crclist(entry["data"])))

			pass
		elif id == 0x9F541597: # Procedure: Anti debug
			""" Anti debug checks
			Depending on the passed flags, there are multiple anti-debugging checks:
				- blacklisted MAC addresses;
				- blacklisted loaded libraries;
				- blacklisted user names;
				- blacklisted computer names;
			"""
			
			(d1, d2, d3, d4) = struct.unpack_from("<LLLL", entry["data"])

			line += "IsSandboxed(TODO flags); // %08X %08X %08X %08X"%(d1, d2, d3, d4)

			pass
		elif id == 0xA6D5DF10: # Decoy message box
			""" Decoy message
			Some samples use a decoy message box that should fool the user
			"""
			
			(msg_title, msg_text) = entry["data"][0x0C:].decode("utf-8", "ignore").split("\x00")
			line += "MessageBox(title=\"%s\", text=\"%s\");"%(msg_title, msg_text)

			pass
		elif id == 0xCA57746D: # Label / Procedure
			""" Label / Procedure
			"""

			if VM_EIP in VM_CALLTABLE:
				line += "PROC_%02X:"%VM_EIP
			else:
				line += "LABEL_%02X:"%VM_EIP

			pass
		elif id == 0x87094E88: # End of file
			""" EOF
			"""

			line += "END;"

			pass
		elif id == 0xCFE807BD: # Signal event
			""" flag check, and event set depending on the flag
			"""
			line += "SignalEvent(); // pre-process termination"

			pass
		elif id == 0x4C755767: # Exit
			(exit_code, ) = struct.unpack_from("<L", entry["data"], 0)
			line += "Exit(%d); // Exit process"%exit_code

			pass
		elif id == 0xBD5E1577: # OR and var assign
			(d1, d2) = struct.unpack_from("<LL", entry["data"], 0)
			line += "%s = &R0[R1] & &R3[R4];"%(fmt_var(0xCC3B1A5D))

			pass
		elif id == 0x4ED9EAA4: # GOTO
			(d1, ) = struct.unpack_from("<L", entry['data'], 0)

			line += "GOTO LABEL_%02X;"%(get_label(d1))

			pass
		elif id == 0x7DD14382:
			"""
			"""
			# TODO
			line += "// TODO ID:%08X DATA:%s"%(id, binascii.hexlify(entry["data"]).upper())

			pass
		elif id in VM_DATATABLE:
			""" Data entry
			TODO: additional parsing of the data
			"""

			var_name = fmt_var(dex(id))
			if var_name is None:
				var_name = "DATA_%08X"%id
			var_value = ""

			# String data
			if id in [0xBF147713, 0x01444ED1, 0xFFF28C72, 0xC9393B40]:
				var_value = "\"%s\""%entry['data'].decode('utf-8')

				pass
			# Array of CRCs
			elif id in [0x913A66EC, 0x56B437D3, 0xDBED7DFB, 0xAE97A09A, 0x5DD00BF4, 0x87045172]:

				var_value = "[%s]"%(", ".join(format_crclist(entry['data'])))

				pass
			# Array of bytes
			elif id == 0x14A8D56E:
				var_value = "["
				for b in bytearray(entry['data']):
					var_value += "0x%02X, "%b

				var_value = var_value.strip(", ") + "]"

				pass
			# Array of DWORDS
			elif id in [0xDFE8715B, 0x97AC42CB, 0xBB98FAB8, 0x3FEF1B94, 0x8568A01D, 0x0B7EEE53, 0x8DB1E244]:
				data_array = []
				for offset in range(0, len(entry['data']), 4):
					val, = struct.unpack_from("<L", entry['data'], offset)
					data_array.append("0x%08X"%val)
				
				var_value = "[%s]"%(", ".join(data_array))

				pass
			# Mixed array A
			elif id in [0xD3955140, 0xD3955141]:
				(d1, d2) = struct.unpack_from("<LL", entry['data'], 0)

				var_value = "[0x%08X, 0x%08X, \"%s\"]"%(d1, d2, entry['data'][0x08:].decode("utf-8"))

				pass
			# Mixed array B
			elif id in [0xF50DF89A, ]:
				(d1, d2, d3, d4) = struct.unpack_from("<LLLL", entry['data'], 0)

				var_value = "[0x%08X, 0x%08X, 0x%08X, 0x%08X, \"%s\"]"%(d1, d2, d3, d4, entry['data'][0x10:].decode("utf-8"))

				pass
			# Mixed array C
			elif id in [0xC4B21945, ]:
				(d1, d2, d3, d4, d5) = struct.unpack_from("<LLLLL", entry['data'], 0)

				var_value = "[0x%08X, timeout_write=%d, timeout_read=%d, 0x%08X, 0x%08X, \"%s\"]"%(d1, d2, d3, d4, d5, entry['data'][0x14:].decode("utf-8"))

				pass
			# Mixed array D
			elif id in [0x992CC894, ]:
				(d1, d2, d3, d4, d5, d6, d7, d8, d9, d10) = struct.unpack_from("<LLLLLLLLLL", entry['data'], 0)

				var_value = "[0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, \"%s\"]"%(d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, entry['data'][0x28:].decode("utf-8"))

				pass
			else:
				var_value = binascii.hexlify(entry['data']).upper()

				pass

			line += "%s = %s;"%(var_name, var_value)
			pass
		else:
			line += "%02X %08X [XOR:%08X] LEN:%08X [%s]"%(VM_EIP, entry['id'], id, len(entry['data']), binascii.hexlify(entry['data']))
			pass

		result.append(line)

	return result

filename_config = "config.bin"

data = open(filename_config, "rb").read()

print("\n".join(config_decompile(data)))