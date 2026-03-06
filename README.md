# Linux Scripts
#### Authors: Fletcher Meyer and Claude Sonnet 4.6

##  Tools
Note: Not all malicious or unusual modules are caught with this. Only those with relatively recent modification time. If the attacker has a way of modifying the mtime for a file, this is harder on the administrator's end for identification. 
These commands require a human in the loop to parse because of the variable nature and necessity of modules.

### beacon_monitor.sh
Actively watches network traffic for any unusual activity. All ports are monitored, but this can be cut down. Encouraged to cut down on unnecessary public facing applications regardless.

### flush_finder.sh
Find *most* files with iptable/nft flushing. This script should be modified to include more common directories.

### large_finder.sh
Searches passed directories for large files. The default is 100MB, but 10MB is a better threshold for C2 binaries.

### ldd_report.sh
Pass a command or path as a parameter. Runs a check on all loaded modules for the system. These can be viewed along side their mtime, ctime, and atime. This can be useful for troubleshooting why binaries are not working as expected.

### lsmod_report.sh
Runs a check on all loaded modules for the system. These can be viewed along side their atime, ctime, or mtime. This can identify unusual modules that were recently loaded in. 

### recent_finder.sh
Searches passed directories for recent files. The time can be added in as a parameter, along side a flag for atime, ctime, or mtime.

### suid_finder.sh
Searches passed directories for SUID files. These allow for privilege escalation and should be monitored. The time can be viewed with a flag for atime, ctime, or mtime. Ensure all trusted SUID files have been reviewed for potential tampering.


## Mail/Splunk/Web
### strong_nft.sh
Runs an NFT script with all necessary ports for scoring inbound allowed and everything else blocked. This allows for scoring and contains potential beacons on a system.

### weak_nft.sh
Runs an NFT script with all necessary ports for scoring inbound and DNS/HTTP/HTTPS outbound. This is weak as beacons will not be blocked.
