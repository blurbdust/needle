#!/usr/bin/env python3

import os, sys, uuid, argparse, textwrap
#import hexdump, re

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


def init(haystack, clean, no_auto_dump):

#if (len(sys.argv) < 2):
#	print("Please provide a filename to run on")
#if (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
#	print("Useage: ")
#	print("python3 {} /path/to/filename/to/search".format(sys.argv[0]))

#	filename = sys.argv[1]

	f = open(haystack, 'rb')
	f_size = os.stat(haystack).st_size
	main(f, f_size, clean, no_auto_dump)

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
				try:
					__SAMHashes.dump()
				except:
					pass

		if security and system:
			for _security in SECURITY_filenames:
				# sometimes this isn't hit and idk why. future nic here, it's because of the cleaning, 
				# it caused an exception and we'd skip to the end without dumping LSA
				__LSASecrets = LSASecrets(_security, bootKey, None, isRemote=False, history=False)
				try:
					__LSASecrets.dumpSecrets()
					print("")
				except:
					pass
	except NameError:
		print("Not able to auto parse hives using existing tools. Please install impacket or manually check and dump the registry hives.")
	except:
		pass

def search_chunk(chunk, chunk_num, chunk_size, haystack, f_size, misaligned, clean):
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
				g = open(haystack, 'rb')
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
				g = open(haystack, 'rb')
				if misaligned:
					g.seek((chunk_size) + ((chunk_num - 1) * chunk_size) + (temp_SYSTEM - 0x2D))
				else:
					g.seek(((chunk_num - 1) * chunk_size) + (temp_SYSTEM - 0x2D))
				# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
				# try and fix up dirty registry hives
				small_chunk = g.read(min(f_size, 17000000))
				last_yeet = 0
				to_write = b""
				if (clean):
					for yeet in cust_findall(small_chunk, b"\xFF"*0x200):
						if small_chunk[ yeet - 0x1 ] == b"\xFF":
							to_write += small_chunk[ last_yeet : yeet ]
							last_yeet = yeet
						elif small_chunk[ yeet + 0x200 : yeet + 0x205 ] == b"hbin\x00":
							# trim
							to_write += small_chunk[ last_yeet : yeet ]
							last_yeet = yeet + 0x200
				to_write += small_chunk[ last_yeet : ]
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
				g = open(haystack, 'rb')
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
#								g = open(haystack, 'rb')
#								g.seek(((chunk_num - 1) * chunk_size) + (temp_NTDS - 0x8))
#								# 16MB is supposedly max size of registry hives on disk; impacket doesn't seem to have a problem with extra data at the end of the registry hives.
#								NTDS.write(g.read(min(f_size, 16 * 1024 * 1024)))
#								g.close()
#							found[3] = True

def check(no_auto_dump):
	# shoutout to @knavesec for this monstrosity, summing across a list of bools hurts me
	if ((not no_auto_dump) and ((found[1] == True) and (sum(found) >= 2))):
		autodump(found[0], found[1], found[2], found[3])


def main(f, f_size, clean, no_auto_dump):
	# reading in chunks and scanning through the chunks, if we don't find anything, maybe our chunks were too small and the pattern was at the boundry of chunks so we need to seek by chunk / 2 and scan again

	chunk_size = 4 * 1024 * 1024 # 4MiB
	start = 0
	end = chunk_size
	chunk_num = 0

	while (end < f_size):
		f.seek(start)
		chunk = f.read(chunk_size)
		chunk_num += 1
		if (search_chunk(chunk, chunk_num, chunk_size, haystack, f_size, False, clean) == True):
			break
		start = end
		end += chunk_size

	# finish last partial chunk just in case
	f.seek(start)
	chunk = f.read(f_size - start)
	search_chunk(chunk, chunk_num, chunk_size, haystack, f_size, False, clean)

	check(no_auto_dump)

	# misalign and search the new chunks in case the \x00S\x00A\x00M and regf are across chunk boundries
	chunk_size = chunk_size // 4
	start = chunk_size
	end = start + chunk_size
	chunk_num = 0
	while (end < f_size):
		f.seek(start)
		chunk = f.read(chunk_size)
		chunk_num += 1
		if (search_chunk(chunk, chunk_num, chunk_size, haystack, f_size, False, clean) == True):
			break
		start = end
		end += chunk_size

	check(no_auto_dump)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
			formatter_class=argparse.RawDescriptionHelpFormatter,
			description='Process a large haystack looking for high value files from Windows. Specifically SAM, SECURITY, and SYSTEM hives.',
			epilog=textwrap.dedent('''Examples:\npython3 needle.py /mnt/HTB/Bastion/file.vhd --hacky-clean\npython3 needle.py /mnt/VeritasNetbackup/dc.tar''')
	)
	# https://stackoverflow.com/questions/15008758/parsing-boolean-values-with-argparse
	parser.add_argument('--clean', action='store_true', default=False, help="Clean dirty on disk registry keys in a very hacky way that somehow works (usually needed for vhd)")
	parser.add_argument('--no-auto-dump', action='store_true', default=False, help="Try to automatically use secretsdump if SAM and SYSTEM or SYSTEM and SECURITY are found")
	parser.add_argument('haystack', metavar='haystack', type=str, nargs='*', help='Haystack to parse')

	args = parser.parse_args()

	if (args.haystack != None):
		#do things
		for haystack in args.haystack:
			init(haystack, args.clean, args.no_auto_dump)
	else:
		parser.print_help()
