######################################################################
##                                                   ##
## Total number of signatures produced by the script ## $TotalSigs
##                                                   ##
######################################################################
## Total hash signatures produced by the script      ## $TotalHashes
######################################################################
## Total IP signatures produced by the script        ## $TotalIPs
######################################################################
## Total indicators not processed by the script      ## $TotalSkips
######################################################################
## The Suricata SID range used is: $FirstSID - $LastSID
######################################################################
##
#### Instructions #####
     Inside of the Signature Builder folder, a new folder called “Results” has been produced. This is where you will find the various types of signature files produced by the scripts.


$OutputName.rules - This is the Suricata ruleset
Yara_$OutputName - This is the Yara ruleset
$OutputName.extra - These are rules or input types that were not understood by the script. They can potentially be used elsewhere in your system.


SURICATA
     1.) Copy the $OutputName.rules file into the /etc/suricata/rules/ directory on your Sensor
     2.) Navigate into the directory /etc/suricata/rules/ on your Sensor
     3.) Run the command:
          suricata-update --local $OutputName.rules
     4.) Run this command to restart the suricata service:
          systemctl restart suricata  
     5.) Run this command to test the ruleset:
          suricata -T