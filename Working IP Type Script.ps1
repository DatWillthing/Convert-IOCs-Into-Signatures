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
