# needle

Needle is a file carving utility that works very well for finding Windows centric high value files within a given haystack. This specifically was targeting Veritas NetBackup files but it works for any large block of data.
It specifically looks for the on disk versions of SAM, SECURITY, and SYSTEM registry hives and carve those files out of the blob of data. If impacket is installed, it will utilize secretsdump to sutomatically dump secrets from the hives. 
