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
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    $IPSRC = $Content
    echo "alert $IPSRC ANY <> $IPDST ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
   if ($file[$count].type -eq "ip-dst"){
    $IPSRC = "ANY" 
    $IPDST = "ANY"
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    $IPDST = $Content
    echo "alert $IPSRC ANY <> $IPDST ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }

    ##Hash Statements

   if ($file[$count].type -eq "sha1"){
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    echo "alert ANY ANY <> ANY ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
   if ($file[$count].type -eq "sha256"){
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    echo "alert ANY ANY <> ANY ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
    if ($file[$count].type -eq "sha384"){
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    echo "alert ANY ANY <> ANY ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
    if ($file[$count].type -eq "sha512"){
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    echo "alert ANY ANY <> ANY ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
    if ($file[$count].type -eq "authentihash"){
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    echo "alert ANY ANY <> ANY ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
   }
    if ($file[$count].type -eq "ssdeep"){
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    echo "alert ANY ANY <> ANY ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
    }
     if ($file[$count].type -eq "md5"){
    $Type = @()
    $Content = @()
    $Message = @()
    $Type += $file[$count].type
    $Content += $file[$count].value
    $Message += $file[$count].type 
    $Reference += $file[$count].attribute_tag
    echo "alert ANY ANY <> ANY ANY (msg:`"$Message`"; content:`"$Content`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $savedrules\rules.txt
    }
}

##Iterates through the file and writes pertinent info to suricata rules##
while ($count -lt $length){
 
  Detect-Type
  
  $SID += 10
  $count += 1
}


