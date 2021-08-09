##Initial definitions for the Results Readme
$Today=Get-Date -Format "yyyy-MM-dd"

Function Input-File {
    ##Breaks up the input file into parts
    if ($File -eq "") {
        $global:File = read-host "Input the full path to the signature file: "
    }
    ##System.IO.Path detects the filesystem of the host so that the script can run on either Windows or Linux
    $global:FileExten=[System.IO.Path]::GetExtension("$File")
    $global:FileName=[System.IO.Path]::GetFileNameWithoutExtension("$File")
    $global:FilePath=[System.IO.Path]::GetDirectoryName("$File")
    Set-Variable -Name "OutputName" -Value "$FileName`_$Today" -Scope global
    $global:OutputFile=Join-Path -Path $ResultsPath -ChildPath "$OutputName"
}

##Detects the Filetype and changes if need be. It should loop if it hits an excel file. This should move directly into the next function based on its output.
Function Detect-Filetype {
    if ($FileExten -eq ".xlsx") {
        write-host "Excel!!"
        Excel-File($File)
    }
    elseif ($FileExten -eq ".csv") {
        write-host "CSV yes, please!!"
        #Check-Headers
    }
    elseif ($FileExten -eq "") {
        write-host "I did not detect a file extension. I need to know the file extension so that I can know what to work with. CSV is the easiest format for me."
	Input-File
	}
    else {
        write-host "Something didn't work..."
    }
}

##Opens the Excel File, saves it as a new CSV, and continues working with the new CSV.
Function Excel-File ($File) {
    $Excel = New-Object -ComObject Excel.Application
    $wb = $Excel.Workbooks.Open($File)
    $global:CSVFile=Join-Path -Path $FilePath -ChildPath $FileName".csv"
    foreach ($ws in $wb.Worksheets) {
        $ws.SaveAs($CSVFile, 6)
        $File = $CSVFile
    }
    $Excel.Quit()
    Detect-Filetype
}

##Takes all of the counters of each type running throughout the whole files and records them into the Results Readme.
Function Build-Results {
    $LastSID = $SID
    $TotalSigs = $LastSID - $FirstSID
    New-Item -Name "Readme.txt" -ItemType File -Path $ResultsPath -erroraction 'silentlycontinue'
    $TemplateContent = get-content -path $TempReadmePath
    Invoke-expression """$TemplateContent""" | set-content -path $ReadmePath
}

