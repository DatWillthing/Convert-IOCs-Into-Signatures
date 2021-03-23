##Roadmap for the working script, use as a framework to build upon##

##Import functions module##
Import-Module -force -name 'C:\users\William\Desktop\Signature Script\SignatureModule.psm1'

$filepath = 'C:\users\William\Desktop\Signature Script\test.csv' #read-host "Input the full path to the signature file: "
$file = import-csv $filepath 

##Convert invalid filetypes to csv##
#Detect-Filetype

##Variable Declaration##
$count = 0
$length = $file.length
$savedrules = 'C:\Users\William\Desktop\Signature Script'

##Counters##
$SID = 1000000
$TotalSigs = 0
$TotalHashes = 0
$TotalIPs = 0
$TotalSkips = 0
$FirstSID = 700000
$LastSID = 700000
$OutputName = "NotSureYet"

function Detect-Type{
       
  if ($file[$count].type -eq "ip-src"){
    $IPSRC = "ANY" 
    $IPDST = "ANY"
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    #$Content += $file[$count].indicator
    $Content += $file[$count].value
    $Message += $file[$count].type 
    #$Message += $file[$count].actors
    #$Reference += $file[$count].malware_families
    #$Reference += $file[$count].published_date
    #$Reference += $file[$count].reports  
    $Reference += $file[$count].attribute_tag
    #$Classtype += $file[$count].malicious_confidence
    #$Classtype += $file[$count].label
    #echo $content >> 'C:\Users\William\Desktop\Signature Script\test.txt'
    $IPSRC = $Content
    echo $content >> 'C:\Users\William\Desktop\Signature Script\test.txt'
    echo "alert $IPSRC ANY <> $IPDST ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
   if ($file[$count].type -eq "ip-dst"){
    $IPSRC = "ANY" 
    $IPDST = "ANY"
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    #$Content += $file[$count].indicator
    $Content += $file[$count].value
    $Message += $file[$count].type 
    #$Message += $file[$count].actors
    #$Reference += $file[$count].malware_families
    #$Reference += $file[$count].published_date
    #$Reference += $file[$count].reports  
    $Reference += $file[$count].attribute_tag
    #$Classtype += $file[$count].malicious_confidence
    #$Classtype += $file[$count].label
    #echo $content >> 'C:\Users\William\Desktop\Signature Script\test.txt'
    $IPDST = $Content
    echo "alert $IPSRC ANY <> $IPDST ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
   
}

##Iterates through the file and writes pertinent info to suricata rules##
while ($count -lt $length){
 
  Detect-Type
  
  $SID += 10
  $count += 1
}
