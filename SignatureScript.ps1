##Initial definitions for the Results Readme
Set-Variable -Name "File" -Value "$args" -Scope global
Set-Variable -Name "TotalSigs" -Value 0 -Scope global
Set-Variable -Name "TotalHashes" -Value 0 -Scope global
Set-Variable -Name "TotalIPs" -Value 0 -Scope global
Set-Variable -Name "TotalSkips" -Value 0 -Scope global
Set-Variable -Name "FirstSID" -Value 700000 -Scope global
Set-Variable -Name "LastSID" -Value 0 -Scope global
$global:SID = $FirstSID
$Today=Get-Date -Format "yyyy-MM-dd"

##Define localized paths
New-Item -Name "Results" -ItemType Directory -Path $PSScriptRoot -erroraction 'silentlycontinue'
$global:ResultsPath=Join-Path -Path $PSScriptRoot -ChildPath "Results"
$global:LibsPath=Join-Path -Path $PSScriptRoot -ChildPath "Libs"
$global:TempReadmePath=Join-Path -Path $LibsPath -ChildPath "TemplateReadme.txt"
$global:ReadmePath=Join-Path -Path $ResultsPath -ChildPath "Readme.txt"
$global:ModulePath=Join-Path -Path $LibsPath -ChildPath "Add-Features.psm1"
New-Item -Name "$OutputName`.rules" -ItemType File -Path $ResultsPath -erroraction 'silentlycontinue'

##Import functions module##
Import-Module -force -name "$ModulePath"

Input-File
$StartTime = $(get-date)
Detect-Filetype

$FileContent = import-csv -Path $File

##Variable Declaration##
$Count = 0
$length = $FileContent.length
####################
function Indicator-Hash {
        $Type = @()
        $Content = @()
        $Message = @()
        $Reference = @()
        $Classtype = @()
        $Type += $FileContent[$Count].type
        $Content += $FileContent[$Count].indicator
        if ($Content -ne $null){
            $FinalContent = " content`:`"$Content`"`;"
        }
        $Message += $FileContent[$Count].type
        $Message += $FileContent[$Count].labels
        if ($Message -ne $null){
            $FinalMessage = " msg`:`"$Message`"`;"
        }
        $Reference += $FileContent[$Count].actors
        $Reference += $FileContent[$Count].reports
        if ($Reference -ne $null){
            $FinalReference = " reference`:`"$Reference`"`;"
        }
        $Classtype += $Classtype[$Count].malicous_confidence
        $Classtype += $Classtype[$Count].malware_families
        $Classtype += $Classtype[$Count].kill_chains
        if ($Classtype -ne $null){
            $FinalClasstype = " classtype`:`"$Classtype`"`;"
        }
        echo "alert ANY ANY <> ANY ANY ($FinalMessage $FinalContent $FinalReference $FinalClasstype sid:$SID; rev:1;)" `n  >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalHashes += 1
}
function Value-Hash {
        $Type = @()
        $Content = @()
        $Message = @()
        $Type += $FileContent[$Count].type
        $Content += $FileContent[$Count].value
        if ($Content -ne $null){
            $FinalContent = " content`:`"$Content`"`;"
        }
        $Message += $FileContent[$Count].type
        $Message += $FileContent[$Count].message
        if ($Message -ne $null){
            $FinalMessage = " msg`:`"$Message`"`;"
        }
        $Reference += $FileContent[$Count].attribute_tag
        if ($Reference -ne $null){
            $FinalReference = " reference`:`"$Reference`"`;"
        }
        echo "alert ANY ANY <> ANY ANY ($FinalMessage $FinalContent $FinalReference sid:$SID; rev:1;)" `n  >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalHashes += 1
}
function Indicator-Domain {
        $Type = @()
        $Content = @()
        $Message = @()
        $Reference = @()
        $Classtype = @()
        $Type += $FileContent[$Count].type
        $Content += $FileContent[$Count].indicator
	$Content += $FileContent[$Count].value
        if ($Content -ne $null){
            $FinalContent = " content`:`"$Content`"`;"
            $FinalContent = $FinalContent.Trim( )
        }
        $Message += $FileContent[$Count].type
        $Message += $FileContent[$Count].labels
        if ($Message -ne $null){
            $FinalMessage = " msg`:`"$Message`"`;"
            $FinalMessage = $FinalMessage.Trim( )
            $FinalMessage = $FinalMessage.Trim( )
        }
        $Reference += $FileContent[$Count].actors
        $Reference += $FileContent[$Count].reports
        if ($Reference -ne $null){
            $FinalReference = " reference`:`"$Reference`"`;"
            $FinalReference = $FinalReference.Trim( )
        }

        $Classtype += $Classtype[$Count].malicous_confidence
        $Classtype += $Classtype[$Count].malware_families
        $Classtype += $Classtype[$Count].kill_chains
        if ($Classtype -ne $null){
            $FinalClasstype = " classtype`:`"$Classtype`"`;"
            $FinalClasstype = $FinalClasstype.Trim( )
        }
        echo "alert ANY ANY <> ANY ANY ($FinalMessage $FinalContent $FinalReference $FinalClasstype sid:$SID; rev:1;)" `n  >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalDomains += 1
}
####################

function Detect-Type {
    ####Hash Statements
    if ($FileContent[$Count].type -eq "hash_sha1"){
        Indicator-Hash
    }
    if ($FileContent[$Count].type -eq "hash_sha256"){
        Indicator-Hash
    }
    if ($FileContent[$Count].type -eq "hash_md5"){
        Indicator-Hash
    }
    if ($FileContent[$Count].type -eq "sha1"){
        Value-Hash
   }
    if ($FileContent[$Count].type -eq "sha256"){
        Value-Hash
    }
    if ($FileContent[$Count].type -eq "sha384"){
        Value-Hash
    }
    if ($FileContent[$Count].type -eq "sha512"){
        Value-Hash
    }
    if ($FileContent[$Count].type -eq "authentihash"){
        Value-Hash
    }
    if ($FileContent[$Count].type -eq "ssdeep"){
        Value-Hash
    }
    if ($FileContent[$Count].type -eq "md5"){
        Value-Hash
    }
    ####IP Statements
    if ($FileContent[$Count].type -eq "ip-src") {
        $IPSRC = "ANY"
        $IPDST = "ANY"
        $Type = @()
        $Content = @()
        $Message = @()
        $Type += $FileContent[$Count].type
        $Content += $FileContent[$Count].value
        $Content += $FileContent[$Count].indicator
        $Message += $FileContent[$Count].type
        $Reference += $FileContent[$Count].attribute_tag
        $IPSRC = $Content
        echo "alert $IPSRC ANY <> $IPDST ANY (msg:`"$Message`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalIPs += 1
    }
    if ($FileContent[$Count].type -eq "ip-dst"){
        $IPSRC = "ANY"
        $IPDST = "ANY"
        $Type = @()
        $Content = @()
        $Message = @()
        $Type += $FileContent[$Count].type
        $Content += $FileContent[$Count].value
        $Message += $FileContent[$Count].type
        $Reference += $FileContent[$Count].attribute_tag
        $IPDST = $Content
        echo "alert $IPSRC ANY <> $IPDST ANY (msg:`"$Message`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalIPs += 1
    }
    if ($FileContent[$Count].type -eq "ip_address"){
        $Type = @()
        $Content = @()
        $Message = @()
        $Type += $FileContent[$Count].type
        $Content += $FileContent[$Count].indicator
        $Message += $FileContent[$Count].type
        $Reference += $FileContent[$Count].attribute_tag
        $IPADDR = $Content
        echo "alert ANY ANY <> $IPADDR ANY (msg:`"$Message`"; reference:$Reference; classtype:$Classtype; sid:$SID; rev:1;)" `n  >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalIPs += 1
    }
    ####Domain Statements
    if ($FileContent[$Count].type -eq "domain"){
        Indicator-Domain
    }
    if ($FileContent[$Count].type -eq "url"){
        Indicator-Domain
    }
    if ($FileContent[$Count].type -eq "email_address"){
        Indicator-Domain
    }
    <# This statement is getting hit every loop... Not sure why
    else {
        $global:TotalSkips += 1
    }
    #>
}

##Iterates through the file and writes pertinent info to suricata rules##
while ($Count -lt $length){
    Detect-Type
    $Count += 1
}

Build-Results
$elapsedTime = $(get-date) - $StartTime
$totalTime = "{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)
write-host "Complete! Total time: $totalTime"
