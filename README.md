# Linux Scripts
#### Authors: Fletcher Meyer and Claude Sonnet 4.6

##  Tools
Note: Not all malicious or unusual modules are caught with this. Only those with relatively recent modification time. If the attacker has a way of modifying the mtime for a file, this is harder on the administrator's end for identification. 
These commands require a human in the loop to parse because of the variable nature and necessity of modules.

### layla.sh
Actively watches network traffic for any unusual activity. Name comes from "Layla" by Derek and the Dominoe.

### ldd_report.sh
Pass a command or path as a parameter. This runs a check on all of the loaded modules for their last modification time. This is useful for identification of newer, unusual modules. 

### lsmod_report.sh
Runs a check on all loaded modules for the system for their latest modification time. This is useful for identification of newer, unusual modules.

### flush_finder.sh
Find all files with iptable/nft flushing.

## Mail/Splunk/Web
### strong_nft.sh
Runs an NFT script with all necessary ports for scoring inbound allowed and everything else blocked. This allows for scoring and contains potential beacons on a system.

### weak_nft.sh
Runs an NFT script with all necessary ports for scoring inbound and DNS/HTTP/HTTPS outbound. This is weak as beacons will not be blocked.
