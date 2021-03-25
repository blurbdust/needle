# Needle

Needle is a file carving utility that works very well for finding Windows centric high value files within a given haystack. This specifically was targeting Veritas NetBackup files but it works for any large block of data such as a tar or VHD file.

It specifically looks for the on disk versions of SAM, SECURITY, and SYSTEM registry hives and carve those files out of the blob of data. If impacket is installed, it will utilize secretsdump to automatically dump secrets from the hives. 

## Why?
We were on an Internal pen test where the client had unauthenticated access to a NFS share which contained backups of several High Value Targets including their DC. The backup images were created by NetBackup and were a non-standard tar file that we were unable to easily extract or exfiltrate due to the large size of the image (130+ GB). We created this tool to automate a process done manually during the test in order to gain access to the machine account in order to DCSYNC the DC and get DA. 

Also Bastion on Hack The Box is a thing. 

#### No, why isn't this a PR to foremost or binwalk?
...good question

## Notes
If the haystack is a true backup of a Windows computer, it is very likely there will be multiple copies of the registry hive on disk due to Windows keeping a copy for recovery purposes. If local or LSA secrets is output multiple times with the same data, this is likely the reasoning. 

## Usage
```
usage: needle.py [-h] [-c] [-n] [-o OUTPUT] [haystack [haystack ...]]

Process a large haystack looking for high value files from Windows. Specifically SAM, SECURITY, and SYSTEM hives.

positional arguments:
  haystack              Haystack to parse

optional arguments:
  -h, --help            show this help message and exit
  -c, --clean           Clean dirty on disk registry keys in a very hacky way
                        that somehow works (usually needed for vhd)
  -n, --no-auto-dump    Try to automatically use secretsdump if SAM and SYSTEM
                        or SYSTEM and SECURITY are found
  -o OUTPUT, --output OUTPUT
                        Output Directory for registry hives, default: current
                        directory

Examples:
python3 needle.py /mnt/HTB/Bastion/file.vhd --clean
python3 needle.py /mnt/VeritasNetbackup/dc.tar
```

## Expected Output
`python3 needle.py /mnt/large.vm.backup.tar`
```
Potentially found SAM at offset 2170928 within searched chunk 977. Writing to 905b5cd4-f9bf-421f-916c-531ad97b5d34_SAM
Potentially found SECURITY at offset 2461744 within searched chunk 977. Writing to de639e0e-a5ad-4d2e-aff2-b415c0087604_SECURITY
Potentially found SYSTEM at offset 3129391 within searched chunk 984. Writing to d20cc9ed-25ec-4f48-9a5d-f009ec73ccd2_SYSTEM
Potentially found SYSTEM at offset 2609199 within searched chunk 986. Writing to b0c4826a-6ffb-4464-b760-210f0b94f9be_SYSTEM
Potentially found SECURITY at offset 1708080 within searched chunk 1165. Writing to 82d5e5d4-79ca-46f6-8a5d-9a017b920b6f_SECURITY
Potentially found SAM at offset 2125872 within searched chunk 3397. Writing to de0c2e6b-6f86-431d-a8bd-5e3e8c0c53c3_SAM
Potentially found SECURITY at offset 364592 within searched chunk 24271. Writing to a134d5bb-d583-4c97-9926-7fa68367a788_SECURITY
Potentially found SYSTEM at offset 1966127 within searched chunk 33848. Writing to ccf58b55-3cef-4764-acf2-772c2c575cda_SYSTEM

impacket is installed, trying to autodump SAM and LSA Secrets using secretsdump...

Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

$MACHINE.ACC:plain_password_hex:6e88709fade737b4ee7667c0a1749d8a68db0966aea6ae6fc1a8ffb77109c53e408de50c5f80ca41baaa35ee6b224ea0e24687b3c056c260e84913e74c8db0137fa1418ccae2db1e18c245dd23fafa1fc8b1b208ae79ff95938196f2f3f0858703351c3a62910edb25072e59859961131a7323494a4f431e48e6dacf6ab0194dfe3b4c09a5d57abc6c61c2537a54a7b30d4a0a37e9bd8bbbe9907ce9c07b417bace4f7b730a0711bff10ddf977eff11be0e13c69dd4e03416949b3d5ba3e1d1276a0defc42888857de878934f6b284a4f3524b24b4cfa68993b0e396955259b1a2ae2f3e07449ff84410fd227650a39f
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:86d57971204ad7503e3fb1da9d03cb14
dpapi_machinekey:0x4cdc855cea4c0aad4b8d624c7416e3c2efcd4ed3
dpapi_userkey:0x8f57b3cd3705ed348056220254b0c4896eeacce8
NL$KM
 0000   6E 0E 6B 09 C1 58 FA 85  E3 AD 46 4F 21 94 4D DA   n.k..X....FO!.M.
 0010   6A 1E 23 7B 67 BB D3 02  F9 6C CC AB E3 DC 15 8E   j.#{g....l......
 0020   EE F2 BB 65 36 B1 FF 29  34 74 BE 69 02 0C 9A AA   ...e6..)4t.i....
 0030   9F 40 5B F9 22 E8 0F 72  81 0F A7 21 4F BE 4F 29   .@[."..r...!O.O)
NL$KM:6e0e6b09c158fa85e3ad464f21944dda6a1e237b67bbd302f96cccabe3dc158eeef2bb6536b1ff293474be69020c9aaa9f405bf922e80f72810fa7214fbe4f29
```

## TODO
- [x] Find SAM in haystack and write to file
- [x] Find SYSTEM in haystack and write to file
- [x] Dump local hashes using secretsdump
- [x] Find SECURITY in haystack and write to file
- [x] Expand dumping to include Machine Account
- [x] Refactor to use argparse
- [ ] Refactor patterns into a list for easier expandability
- [ ] Add ability to skip to certain chunks if ran before
- [ ] Add flag to only look for system, sam, security, etc 
- [x] Add flag to change output directory
- [ ] Add flag to only search misaligned (debug)
- [x] Add in ability to find multiple copies within given chunk
- [x] Find ESE DBs if haystack is from DC
- [ ] Check if ESE DB is NTDS.dit if haystack is from DC
