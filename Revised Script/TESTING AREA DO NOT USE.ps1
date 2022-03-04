
$FileContent = Import-Csv -Path $File

$Global:IPField = "ip"
$Global:type = "Type"
$global:MessageField = "itype"
$Global:IOCField = "IOC"

$Global:MessageList = @($filecontent | select-object -expandproperty "$global:MessageField")
$Global:typearray2 = @($filecontent | select-object -expandproperty "$global:type")
$Global:IOCList = @($filecontent | select-object -expandproperty "$global:IOCField")
$Global:Count3 = 0
while ($Count3 -lt $typearray2.count){
    if ($Global:typearray2[$Count3] -eq $Global:IPField){
        $Global:typearray2[$Count3] = $Global:IPField           
    }
    else {
        $Global:typearray2[$Count3] = "Content"
    }
    $Global:Count3 += 1
}

#$FinalMessage = "msg`:`"$MessageList[Count10]`"`;"

$Global:Count10 = 0
while ($Count10 -lt $filecontent.count){
    
    if ($Global:typearray2[$Global:Count10] -eq $Global:IPField){
        write-host "alert ip"$IOCList[$Global:Count10]"ANY <> ANY ANY (msg:`""$Global:MessageList[$Global:Count10]"`";)"
        #write-host "alert ip"$IOCList[$Global:Count10]"ANY <> ANY ANY ($FinalMessage)"
    }
    else {
        #write-host "alert ip ANY ANY <> ANY ANY (msg:`""$Global:MessageList[$Global:Count10]"`";content:)"
        #write-host "alert ip ANY ANY <> ANY ANY ($finalmessage)"
    }
    
    $Count10 += 1
}