0000000000000000000000000000000000000000000000000000000000000000000000
`n00                                                   00
`n00 Total number of signatures produced by the script 00 $TotalSigs
`n00                                                   00
`n0000000000000000000000000000000000000000000000000000000000000000000000
`n00 Total hash signatures produced by the script      00 $TotalHashes
`n0000000000000000000000000000000000000000000000000000000000000000000000
`n00 Total IP signatures produced by the script        00 $TotalIPs
`n0000000000000000000000000000000000000000000000000000000000000000000000
`n00 Total indicators not processed by the script      00 $TotalSkips
`n0000000000000000000000000000000000000000000000000000000000000000000000
`n00 The Suricata SID range used is: $FirstSID - $LastSID
`n0000000000000000000000000000000000000000000000000000000000000000000000
`n00
`n0000 Instructions 00000
`n     Inside of the Signature Builder folder, a new folder called Results has been produced. This is where you will find the various types of signature files produced by the scripts.
`n
`n$OutputName.rules - This is the Suricata ruleset
`nYara_$OutputName - This is the Yara ruleset
`n$OutputName.extra - These are rules or input types that were not understood by the script. They can potentially be used elsewhere in your system.
`n
`nSURICATA
`n     1.) Copy the $OutputName.rules file into the /etc/suricata/rules/ directory on your Sensor
`n     2.) Navigate into the directory /etc/suricata/rules/ on your Sensor
`n     3.) Run the command:
`n          suricata-update --local $OutputName.rules
`n     4.) Run this command to restart the suricata service:
`n          systemctl restart suricata  
`n     5.) Run this command to test the ruleset:
`n          suricata -T
