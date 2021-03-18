Set-Variable -Name "File" -Value "$args" -Scope global
Set-Variable -Name "TotalSigs" -Value "0" -Scope global
Set-Variable -Name "TotalHashes" -Value "0" -Scope global
Set-Variable -Name "TotalIPs" -Value "0" -Scope global
Set-Variable -Name "TotalSkips" -Value "0" -Scope global
Set-Variable -Name "FirstSID" -Value "700000" -Scope global
Set-Variable -Name "LastSID" -Value "700000" -Scope global
Set-Variable -Name "OutputName" -Value "NotSureYet" -Scope global
$FileExten=[System.IO.Path]::GetExtension("$File")
$FileName=[System.IO.Path]::GetFileNameWithoutExtension("$File")
$FilePath=[System.IO.Path]::GetDirectoryName("$File")
$ResultsPath=Join-Path -Path $PSScriptRoot -ChildPath "Results"
$LibsPath=Join-Path -Path $PSScriptRoot -ChildPath "Libs"
$TempReadmePath=Join-Path -Path $LibsPath -ChildPath "TemplateReadme.txt"
$ReadmePath=Join-Path -Path $ResultsPath -ChildPath "Readme.txt"
Function Detect-Filetype {
    if ($FileExten -eq ".xlsx") {
        write-host "Excel!!"
        #Excel-File($File)
    }
    elseif ($FileExten -eq ".csv") {
        write-host "CSV yes, please!!"
        #Check-Headers
    }
    elseif ($FileExten -eq "") {
        write-host "I did not detect a file extension..."
    }
    else {
        write-host "Something didn't work..."
    }
}

Function Excel-File ($File) {
    #Ensure the naming scheme is right...
    $Excel = New-Object -ComObject Excel.Application
    $wb = $Excel.Workbooks.Open($File)
    foreach ($ws in $wb.Worksheets) {
        $ws.SaveAs($FilePath + "\" + $FileName + ".csv", 6)
    ###Use a Join-Path here if possible...
       $File = "$FilePath" + "\" + "$FileName" + ".csv"
       write-host="$File"
    }
    $Excel.Quit()
    write-host "`$File = $File"
    Detect-Filetype
}

Function Build-Results {
    New-Item -Name "Results" -ItemType Directory -Path $PSScriptRoot
    #Edit permissions?
    New-Item -Name "Readme.txt" -ItemType File -Path $ResultsPath
    $TemplateContent = get-content -path $TempReadmePath
    Invoke-expression """$TemplateContent""" | set-content -path $ReadmePath
}
#Detect-Filetype
Build-Results
write-host "done"
