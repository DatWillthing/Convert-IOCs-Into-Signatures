﻿##Get CSV Filepath
#$global:File = Read-Host "Input the full path to the signature file: "

$FileContent = Import-Csv -Path $File

##Detect Headers
$Header = @($filecontent | get-member -MemberType NoteProperty | select-object -expandproperty name)

##Read user input
$Global:InputGlobal = ""
$Global:Count1 = 0
while ($Count1 -lt $Header.count){
    if ($InputGlobal -eq ""){
        write-host "Header:" $Header[$Count1]
        $Input1 = (read-host "Is this the IOC Type Header? Y or N: ")
        
        if ($Input1 -eq "Y"){
            $Global:InputGlobal = "Y"
            $Global:Type = $Header[$Count1]
            $Global:typearray = @($filecontent | sort-object $global:type -unique | select-object -expandproperty $global:type)
            $Global:Count2 = 0
            while ($Count2 -lt $typearray.count){
                $Input3 = (read-host "Is this IOC type an Ip or Content? -" $global:typearray[$Count2])
                if ($Input3 -eq "Ip"){
                    $Global:IPField = $typearray[$Count2]
                }
                if ($Input3 -eq "Content"){
                    $Global:ContentField = $typearray[$Count2]
                }
                $Global:count2 += 1
            }
            $global:Count1 += 1
            continue
        }
    }
    
    $Input3 = (read-host "What Suricata field does this header correlate to? `n 1: Message: A short description of what you are looking for. `n 2: Content: The values that you are actually trying to match. `n 3: References: Directs to places where information about the signature can be found (Ex:"reference: url, https://suricata.io") `n 4: Threat Confidence `n" $Header[$Count1])
    
    if ($Input3 -eq "1"){
        $MessageField = $Header[$Count1]
    }
   # else {
   #     write-host "Invalid input, only use numbers 1-10"
   #     Continue
   # }
    $global:Count1 += 1
}

##Process User Input
$Global:MessageList = @($filecontent | sort-object $global:MessageField | select-object -expandproperty $global:MessageField)
$Global:typearray2 = @($filecontent | sort-object $global:Type | select-object -expandproperty $global:type)

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



$Global:Count10 = 0
while ($Count10 -lt $filecontent.count){
    if ($Global:typearray2[$Global:Count10] -eq $Global:IPField){
        echo "alert $IOCField[$Global:Count10] ANY <> ANY ANY (msg:"$Global:MessageList[$Global:Count10]"; $ReferenceField[$Global:Count10] $FinalClasstype[$Global:Count10] $FinalSID)" >> $OutputFile`.rules
    }
    else {
        echo "ANY ANY <> ANY ANY (msg"$Global:MessageList[$Global:Count10]"; $IOCField[$Global:Count10] $ReferenceField[$Global:Count10] $FinalClasstype[$Global:Count10] $FinalSID)" >> $OutputFile`.rules
    }
    
    $Count10 += 1
}
