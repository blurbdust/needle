#!/usr/bin/env python3

'''
+--556317 lines: 00000000  72 65 67 66 41 03 00 00  41 03 00 00 1b 6c f6 44  |regfA...A....l.D|-----|+ +--556317 lines: 00000000  72 65 67 66 41 03 00 00  41 03 00 00 1b 6c f6 44  |regfA...A....l.D|----
  00893fa0  00 00 00 00 00 00 00 00  08 00 00 00 04 00 00 00  |................|                      |  00893fa0  00 00 00 00 00 00 00 00  08 00 00 00 04 00 00 00  |................|
  00893fb0  00 00 00 00 08 00 00 00  30 30 30 30 30 30 30 30  |........00000000|                      |  00893fb0  00 00 00 00 08 00 00 00  30 30 30 30 30 30 30 30  |........00000000|
  00893fc0  f0 ff ff ff 6c 68 01 00  68 2f 89 00 80 6e c9 6a  |....lh..h/...n.j|                      |  00893fc0  f0 ff ff ff 6c 68 01 00  68 2f 89 00 80 6e c9 6a  |....lh..h/...n.j|
  00893fd0  e0 ff ff ff 76 6b 04 00  04 00 00 80 07 00 00 00  |....vk..........|                      |  00893fd0  e0 ff ff ff 76 6b 04 00  04 00 00 80 07 00 00 00  |....vk..........|
  00893fe0  03 00 00 00 01 00 00 00  54 79 70 65 00 00 00 00  |........Type....|                      |  00893fe0  03 00 00 00 01 00 00 00  54 79 70 65 00 00 00 00  |........Type....|
  00893ff0  f0 ff ff ff d0 2f 89 00  20 30 89 00 00 00 00 00  |...../.. 0......|                      |  00893ff0  f0 ff ff ff d0 2f 89 00  20 30 89 00 00 00 00 00  |...../.. 0......|
  00894000  68 62 69 6e 00 30 89 00  00 10 00 00 00 00 00 00  |hbin.0..........|                      |  00894000  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|                     
  00894010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                      |  *                                                                                                  
  00894020  e0 ff ff ff 76 6b 04 00  04 00 00 80 01 00 ff 00  |....vk..........|                      |  00894200  68 62 69 6e 00 30 89 00  00 10 00 00 00 00 00 00  |hbin.0..........|                     
  00894030  03 00 00 00 01 00 00 00  44 61 74 61 00 00 00 00  |........Data....|                      |  00894210  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                 
'''


import os, sys, uuid
import hexdump, re

SAM_pattern		= b"\\\x00S\x00y\x00s\x00t\x00e\x00m\x00R\x00o\x00o\x00t\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00C\x00o\x00n\x00f\x00i\x00g\x00\\\x00S\x00A\x00M"
SYSTEM_pattern		= b"\x00\x00\x00S\x00Y\x00S\x00T\x00E\x00M\x00\x00\x00\x00\x00"
SECURITY_pattern	= b"e\x00m\x00R\x00o\x00o\x00t\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00C\x00o\x00n\x00f\x00i\x00g\x00\\\x00S\x00E\x00C\x00U\x00R\x00I\x00T\x00Y"
NTDS_pattern 		= b"\x20\x06\x00\x00\x00\x00\x00\x00"
SAM_filenames		= []
SYSTEM_filenames	= []
SECURITY_filenames	= []
NTDS_filenames		= []

#	 SAM, SYSTEM, SECURITY, NTDS
found = [False, False, False, False]

if (len(sys.argv) < 2):
	print("Please provide a filename to run on")
if (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
	print("Useage: ")
	print("python3 {} /path/to/filename/to/search".format(sys.argv[0]))

filename = sys.argv[1]

f = open(filename, 'rb')
f_size = os.stat(filename).st_size

# https://stackoverflow.com/questions/4664850/how-to-find-all-occurrences-of-a-substring
def cust_findall(string, substring):
	substring_length = len(substring)
	def recurse(locations_found, start):
		location = string.find(substring, start)
		if location != -1:
			return recurse(locations_found + [location], location+substring_length)
		else:
			return locations_found
	return recurse([], 0)

def autodump(sam, system, security, ntds):
	# no need to keep scanning as we found all three
	# check which reg hives are valid by trying to import secretsdump or pypykatz
	# if none are installed, output commands to do so
	try:
		# https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py#L58
		from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets, NTDSHashes
		print("")
		print("impacket is installed, trying to autodump SAM and LSA Secrets using secretsdump...")

		for _system in SYSTEM_filenames:
			try:
				# https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py#L118
				localOperations = LocalOperations(_system)
				# https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py#L119
				bootKey = localOperations.getBootKey()
			except:
				continue

		if sam and system:
			for _sam in SAM_filenames:
				# https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py#L119
				__SAMHashes = SAMHashes(_sam, bootKey, isRemote=False)
				print("")
				# https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py#L169
				__SAMHashes.dump()
		if security and system:
			for _security in SECURITY_filenames:
				print("")
				__LSASecrets = LSASecrets(_security, bootKey, None, isRemote=False, history=False)
				__LSASecrets.dumpSecrets()
	except NameError:
		print("Not able to auto parse hives using existing tools. Please install impacket or manually check and dump the registry hives.")
	except:
		pass
	#sys.exit(0)


def search_chunk(chunk, chunk_num, chunk_size, misaligned):
	_temp_SAM = cust_findall(chunk, SAM_pattern)
	_temp_SYSTEM = cust_findall(chunk, SYSTEM_pattern)
	_temp_SECURITY = cust_findall(chunk, SECURITY_pattern)
#	_temp_NTDS = cust_findall(chunk, NTDS_pattern)

	for temp_SAM in _temp_SAM:
		# potential SAM found
		# print(hexdump.hexdump(chunk[temp_SAM - 0x30 : temp_SAM + len(SAM_pattern)]))
		if (b"regf" in chunk[temp_SAM - 0x30 : temp_SAM - 0x30 + 0x4]):
			tmp_name = str(uuid.uuid4()) + "_SAM"
			SAM_filenames.append(tmp_name)
			print("Potentially found SAM at offset {} within searched chunk {}. Writing to {}".format(temp_SAM, chunk_num, tmp_name))
			with open(tmp_name, "wb") as SAM:
				g = open(filename, 'rb')
				if misaligned:
					g.seek((chunk_size) + ((chunk_num - 1) * chunk_size) + (temp_SAM - 0x30))
				else:
					g.seek(((chunk_num - 1) * chunk_size) + (temp_SAM - 0x30))
				# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
				SAM.write(g.read(min(f_size, 2800000)))
				g.close()
			found[0] = True
	for temp_SYSTEM in _temp_SYSTEM:
		# potential SYSTEM found; 0x2F since we search by \x00\x00\x00S to rule out false positives
#		print(hexdump.hexdump(chunk[temp_SYSTEM - 0x2F : temp_SYSTEM + len(SYSTEM_pattern)]))
		if (b"regf" in chunk[temp_SYSTEM - 0x2D : temp_SYSTEM - 0x2D + 0x4 ]):
			tmp_name = str(uuid.uuid4()) + "_SYSTEM"
			SYSTEM_filenames.append(tmp_name)
			print("Potentially found SYSTEM at offset {} within searched chunk {}. Writing to {}".format(temp_SYSTEM, chunk_num, tmp_name))
			#print(hexdump.hexdump(chunk[temp_SYSTEM - 0x2F : temp_SYSTEM + len(SYSTEM_pattern)]))
			with open(tmp_name, "wb") as SYSTEM:
				g = open(filename, 'rb')
				if misaligned:
					g.seek((chunk_size) + ((chunk_num - 1) * chunk_size) + (temp_SYSTEM - 0x2D))
				else:
					g.seek(((chunk_num - 1) * chunk_size) + (temp_SYSTEM - 0x2D))
				# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
				# try and fix up dirty registry hives
				small_chunk = g.read(min(f_size, 17000000))
				last_yeet = 0
				to_write = b""
				for yeet in cust_findall(small_chunk, b"\xFF"*0x200):
					if small_chunk[ yeet - 0x1 ] == b"\xFF":
						to_write += small_chunk[ last_yeet : yeet ]
						last_yeet = yeet
					elif small_chunk[ yeet + 0x200 : yeet + 0x205 ] == b"hbin\x00":
						# trim
						to_write += small_chunk[ last_yeet : yeet ]
						last_yeet = yeet + 0x200
				to_write += small_chunk[ yeet : ]
				SYSTEM.write(to_write)
				g.close()
			found[1] = True
	for temp_SECURITY in _temp_SECURITY:
		# potential SECURITY found
		# print(hexdump.hexdump(chunk[temp_SECURITY - 0x30 : temp_SECURITY + len(SECURITY_pattern)]))
		if (b"regf" in chunk[temp_SECURITY - 0x30 : temp_SECURITY - 0x30 + 0x4]):
			tmp_name = str(uuid.uuid4()) + "_SECURITY"
			SECURITY_filenames.append(tmp_name)
			print("Potentially found SECURITY at offset {} within searched chunk {}. Writing to {}".format(temp_SECURITY, chunk_num, tmp_name))
			with open(tmp_name, "wb") as SECURITY:
				g = open(filename, 'rb')
				if misaligned:
					g.seek((chunk_size) + ((chunk_num - 1) * chunk_size) + (temp_SECURITY - 0x30))
				else:
					g.seek(((chunk_num - 1) * chunk_size) + (temp_SECURITY - 0x30))
				# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
				SECURITY.write(g.read(min(f_size, 16000000)))
				g.close()
			found[2] = True
#	for temp_NTDS in _temp_NTDS:
#		# potential NTDS found
#		if (b"\x00\x00\x00\x00\x00" in chunk[temp_NTDS + 8 + 3 : temp_NTDS + 11 + 5]):
#			if (b"\x00\x00\x00" not in chunk[temp_NTDS + 8 : temp_NTDS + 8 + 3]):
#				if (b"\x00\x00\x00\x00\x00\x00\x00\x00" not in chunk[temp_NTDS + 0x10 : temp_NTDS + 0x18]):
#					if (b"\x00"*0x11 in chunk[temp_NTDS + 0x20 - 0x5  : temp_NTDS + 0x20 - 0x5 + 0x11]):
#						if (b"\x00"*(0xd0 - 0xa0) in chunk[temp_NTDS - 0x8 + 0xa0 : temp_NTDS - 0x8 + 0xd0]):
#							print(hexdump.hexdump(chunk[temp_NTDS - 8 : temp_NTDS + len(NTDS_pattern) + 0x80]))
#							tmp_name = str(uuid.uuid4()) + "_NTDS"
#							NTDS_filenames.append(tmp_name)
#							print("Potentially found Microsoft ESEDB, treating as NTDS at offset {} within searched chunk {}. Writing to {}".format(temp_NTDS - 8, chunk_num, tmp_name))
#							with open(tmp_name, "wb") as NTDS:
#								g = open(filename, 'rb')
#								g.seek(((chunk_num - 1) * chunk_size) + (temp_NTDS - 0x8))
#								# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
#								NTDS.write(g.read(min(f_size, 16 * 1024 * 1024)))
#								g.close()
#							found[3] = True

def check():
	# shoutout to @knavesec for this monstrosity, summing across a list of bools hurts me
	if ((found[1] == True) and (sum(found) >= 2)):
		autodump(found[0], found[1], found[2], found[3])


def main():
	# reading in chunks and scanning through the chunks, if we don't find anything, maybe our chunks were too small and the pattern was at the boundry of chunks so we need to seek by chunk / 2 and scan again

	chunk_size = 4 * 1024 * 1024 # 4MiB
	start = 0
	end = chunk_size
	chunk_num = 0

	while (end < f_size):
		f.seek(start)
		chunk = f.read(chunk_size)
		chunk_num += 1
		if (search_chunk(chunk, chunk_num, chunk_size, False) == True):
			break
		start = end
		end += chunk_size

	# finish last partial chunk just in case
	f.seek(start)
	chunk = f.read(f_size - start)
	search_chunk(chunk, chunk_num, chunk_size, False)

	check()

	# misalign and search the new chunks in case the \x00S\x00A\x00M and regf are across chunk boundries
	chunk_size = chunk_size // 4
	start = chunk_size
	end = start + chunk_size
	chunk_num = 0
	while (end < f_size):
		f.seek(start)
		chunk = f.read(chunk_size)
		chunk_num += 1
		if (search_chunk(chunk, chunk_num, chunk_size, True) == True):
			break
		start = end
		end += chunk_size

	check()
main()
