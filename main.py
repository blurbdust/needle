#!/usr/bin/env python3

import os, sys, uuid
#import hexdump, re

SAM_pattern		= b"\\\x00S\x00y\x00s\x00t\x00e\x00m\x00R\x00o\x00o\x00t\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00C\x00o\x00n\x00f\x00i\x00g\x00\\\x00S\x00A\x00M"
SYSTEM_pattern		= b"\x00S\x00Y\x00S\x00T\x00E\x00M\x00\x00\x00\x00\x00"
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
		print("impacket not installed")
		print("Not able to auto parse hives using existing tools. Please install impacket or manually check and dump the registry hives.")
	except:
		pass
	sys.exit(0)


def search_chunk(chunk, chunk_num, chunk_size):
	temp_SAM = chunk.find(SAM_pattern)
	temp_SYSTEM = chunk.find(SYSTEM_pattern)
	temp_SECURITY = chunk.find(SECURITY_pattern)
	temp_NTDS = chunk.find(NTDS_pattern)

	if (temp_SAM > -1):
		# potential SAM found
		# print(hexdump.hexdump(chunk[temp_SAM - 0x30 : temp_SAM + len(SAM_pattern)]))
		if (b"regf" in chunk[temp_SAM - 0x30 : temp_SAM - 0x30 + 0x4]):
			tmp_name = str(uuid.uuid4()) + "_SAM"
			SAM_filenames.append(tmp_name)
			print("Potentially found SAM at offset {} within searched chunk {}. Writing to {}".format(temp_SAM, chunk_num, tmp_name))
			with open(tmp_name, "wb") as SAM:
				g = open(filename, 'rb')
				g.seek(((chunk_num - 1) * chunk_size) + (temp_SAM - 0x30))
				# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
				SAM.write(g.read(min(f_size, 2800000)))
				g.close()
			found[0] = True
	if (temp_SYSTEM > -1):
		# potential SYSTEM found; 0x2F since we search by \x00S to rule out false positives
		# print(hexdump.hexdump(chunk[temp_SYSTEM - 0x2F : temp_SYSTEM + len(SYSTEM_pattern)]))
		if (b"regf" in chunk[temp_SYSTEM - 0x2F : temp_SYSTEM - 0x2F + 0x4 ]):
			tmp_name = str(uuid.uuid4()) + "_SYSTEM"
			SYSTEM_filenames.append(tmp_name)
			print("Potentially found SYSTEM at offset {} within searched chunk {}. Writing to {}".format(temp_SYSTEM, chunk_num, tmp_name))
			with open(tmp_name, "wb") as SYSTEM:
				g = open(filename, 'rb')
				g.seek(((chunk_num - 1) * chunk_size) + (temp_SYSTEM - 0x2F))
				# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
				SYSTEM.write(g.read(min(f_size, 16000000)))
				g.close()
			found[1] = True
	if (temp_SECURITY > -1):
		# potential SECURITY found
		# print(hexdump.hexdump(chunk[temp_SECURITY - 0x30 : temp_SECURITY + len(SECURITY_pattern)]))
		if (b"regf" in chunk[temp_SECURITY - 0x30 : temp_SECURITY - 0x30 + 0x4]):
			tmp_name = str(uuid.uuid4()) + "_SECURITY"
			SECURITY_filenames.append(tmp_name)
			print("Potentially found SECURITY at offset {} within searched chunk {}. Writing to {}".format(temp_SECURITY, chunk_num, tmp_name))
			with open(tmp_name, "wb") as SECURITY:
				g = open(filename, 'rb')
				g.seek(((chunk_num - 1) * chunk_size) + (temp_SECURITY - 0x30))
				# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
				SECURITY.write(g.read(min(f_size, 16000000)))
				g.close()
			found[2] = True
#	if (temp_NTDS > -1):
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
		if (search_chunk(chunk, chunk_num, chunk_size) == True):
			break
		start = end
		end += chunk_size

	# finish last partial chunk just in case
	f.seek(start)
	chunk = f.read(f_size - start)
	search_chunk(chunk, chunk_num, chunk_size)

	# shoutout to @knavesec for this monstrosity, summing across a list of bools hurts me
	if ((found[1] == True) and (sum(found) >= 2)):
		autodump(found[0], found[1], found[2], found[3])

	# misalign and search the new chunks in case the \x00S\x00A\x00M and regf are across chunk boundries

	start = chunk_size // 2
	end = start + chunk_size
	while (end < f_size):
		f.seek(start)
		chunk = f.read(chunk_size)
		chunk_num += 1
		if (search_chunk(chunk, chunk_num, chunk_size) == True):
			break
		start = end
		end += chunk_size

main()
