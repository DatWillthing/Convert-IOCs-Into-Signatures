##Get CSV Filepath
#$global:File = Read-Host "Input the full path to the signature file: "
$File = "C:\users\dmss-n\Desktop\Script\IOC.csv"
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
    
    $Input3 = (read-host "What would you like to do with this header? -" $Header[$Count1])
    
   # if ($Input3 -eq "1"){
   #     $MessageField = $Header[$Count1]
   # }
   # else {
   #     write-host "Invalid input, only use numbers 1-10"
   #     Continue
   # }
    $global:Count1 += 1
}

##Process User Input
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

$Global:Count4 = 0
while ($Count4 -lt $filecontent.count){
    
    
    $Count4 += 1
}