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

Function Check-Header {
    #File-Unformatted-Content and File Header are created to make sure the correct values are grabbed...
    $FileUnforContent = Get-Content $File
    $FileHeader = Get-Content $File | select -First 1
    if ($FileHeader -match "^column.*") {
        $FileUnforContent = $FileUnforContent | Select-String -Pattern "$FileHeader" -NotMatch
        $FileUnforContent | Out-File $File
        get-content $File | Where { $_.Replace("\S","") -ne "" } | Set-content $File
        Check-Header
    }
    elseif ($FileHeader -match ".*value.*") {
        $FileHeader = $FileHeader.Replace('value','indicator')
        $FileUnforContent[0] = $FileHeader
        $FileUnforContent | Out-File $File
    }
}

Check-Header

$FileContent = import-csv -Path $File
##Variable Declaration##
$Count = 0
$length = $FileContent.length
####################
function Content-Hash {
        $Content = @()
        $Message = @()
        $Reference = @()
        $Classtype = @()
        $Content += $FileContent[$Count].indicator
        if ($Content -ne $null){
            $FinalContent = "content`:`"$Content`"`;"
            $FinalContent = $FinalContent.Trim( )
        }
        if ($FileContent[$Count].type -ne $null){$Message += $FileContent[$Count].type}
        if ($FileContent[$Count].labels -ne $null){$Message += $FileContent[$Count].labels}
        if ($FileContent[$Count].message -ne $null){$Message += $FileContent[$Count].message}
        if ($Message -ne $null){
            $FinalMessage = "msg`:`"$Message`"`;"
            $FinalMessage = $FinalMessage.Trim( )
        }
        if ($FileContent[$Count].attribute_tag -ne $null){$Reference += $FileContent[$Count].attribute_tag}
        if ($FileContent[$Count].actors -ne $null){$Reference += $FileContent[$Count].actors}
        if ($FileContent[$Count].reports -ne $null){$Reference += $FileContent[$Count].reports}
        if ($Reference -ne $null){
            $FinalReference = "reference`:`"$Reference`"`;"
            $FinalReference = $FinalReference.Trim( )
        }
        if ($FileContent[$Count].malicious_confidence -ne $null){$Classtype += $FileContent[$Count].malicious_confidence}
        if ($FileContent[$Count].malware_families -ne $null){$Classtype += $FileContent[$Count].malware_families}
        if ($FileContent[$Count].kill_chains -ne $null){$Classtype += $FileContent[$Count].kill_chains}
        if ($Classtype -ne $null){
            $FinalClasstype = "classtype`:`"$Classtype`"`;"
            $FinalClasstype = $FinalClasstype.Trim( )
        }
        $FinalSID = "sid`:`"$global:SID`"`;rev`:1`;"
        echo "alert ANY ANY <> ANY ANY ($FinalMessage$FinalContent$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalHashes += 1
}
function Content-Domain {
        $Content = @()
        $Message = @()
        $Reference = @()
        $Classtype = @()
        $Content += $FileContent[$Count].indicator
        if ($Content -ne $null){
            $FinalContent = "content`:`"$Content`"`;"
            $FinalContent = $FinalContent.Trim( )
        }
        if ($FileContent[$Count].type -ne $null){$Message += $FileContent[$Count].type}
        if ($FileContent[$Count].labels -ne $null){$Message += $FileContent[$Count].labels}
        if ($FileContent[$Count].message -ne $null){$Message += $FileContent[$Count].message}
        if ($Message -ne $null){
            $FinalMessage = "msg`:`"$Message`"`;"
            $FinalMessage = $FinalMessage.Trim( )
        }
        if ($FileContent[$Count].attribute_tag -ne $null){$Reference += $FileContent[$Count].attribute_tag}
        if ($FileContent[$Count].actors -ne $null){$Reference += $FileContent[$Count].actors}
        if ($FileContent[$Count].reports -ne $null){$Reference += $FileContent[$Count].reports}
        if ($Reference -ne $null){
            $FinalReference = "reference`:`"$Reference`"`;"
            $FinalReference = $FinalReference.Trim( )
        }
        if ($FileContent[$Count].malicious_confidence -ne $null){$Classtype += $FileContent[$Count].malicious_confidence}
        if ($FileContent[$Count].malware_families -ne $null){$Classtype += $FileContent[$Count].malware_families}
        if ($FileContent[$Count].kill_chains -ne $null){$Classtype += $FileContent[$Count].kill_chains}
        if ($Classtype -ne $null){
            $FinalClasstype = "classtype`:`"$Classtype`"`;"
            $FinalClasstype = $FinalClasstype.Trim( )
        }
        $FinalSID = "sid`:`"$global:SID`"`;rev`:1`;"
        echo "alert ANY ANY <> ANY ANY ($FinalMessage$FinalContent$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalDomains += 1
}

function Source-Ip {
        $Message = @()
        $Reference = @()
        $Classtype = @()
        if ($FileContent[$Count].type -ne $null){$Message += $FileContent[$Count].type}
        if ($FileContent[$Count].labels -ne $null){$Message += $FileContent[$Count].labels}
        if ($FileContent[$Count].message -ne $null){$Message += $FileContent[$Count].message}
        if ($Message -ne $null){
            $FinalMessage = "msg`:`"$Message`"`;"
            $FinalMessage = $FinalMessage.Trim( )
        }
        if ($FileContent[$Count].attribute_tag -ne $null){$Reference += $FileContent[$Count].attribute_tag}
        if ($FileContent[$Count].actors -ne $null){$Reference += $FileContent[$Count].actors}
        if ($FileContent[$Count].reports -ne $null){$Reference += $FileContent[$Count].reports}
        if ($Reference -ne $null){
            $FinalReference = "reference`:`"$Reference`"`;"
            $FinalReference = $FinalReference.Trim( )
        }
        if ($FileContent[$Count].malicious_confidence -ne $null){$Classtype += $FileContent[$Count].malicious_confidence}
        if ($FileContent[$Count].malware_families -ne $null){$Classtype += $FileContent[$Count].malware_families}
        if ($FileContent[$Count].kill_chains -ne $null){$Classtype += $FileContent[$Count].kill_chains}
        if ($Classtype -ne $null){
            $FinalClasstype = "classtype`:`"$Classtype`"`;"
            $FinalClasstype = $FinalClasstype.Trim( )
        }
        $FinalSID = "sid`:`"$global:SID`"`;rev`:1`;"
        $IPSRC = $FileContent[$Count].indicator
        echo "alert $IPSRC ANY <> ANY ANY ($FinalMessage$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalIPs += 1
}

function Destination-Ip {
        $Message = @()
        $Reference = @()
        $Classtype = @()
        if ($FileContent[$Count].type -ne $null){$Message += $FileContent[$Count].type}
        if ($FileContent[$Count].labels -ne $null){$Message += $FileContent[$Count].labels}
        if ($FileContent[$Count].message -ne $null){$Message += $FileContent[$Count].message}
        if ($Message -ne $null){
            $FinalMessage = "msg`:`"$Message`"`;"
            $FinalMessage = $FinalMessage.Trim( )
        }
        if ($FileContent[$Count].attribute_tag -ne $null){$Reference += $FileContent[$Count].attribute_tag}
        if ($FileContent[$Count].actors -ne $null){$Reference += $FileContent[$Count].actors}
        if ($FileContent[$Count].reports -ne $null){$Reference += $FileContent[$Count].reports}
        if ($Reference -ne $null){
            $FinalReference = "reference`:`"$Reference`"`;"
            $FinalReference = $FinalReference.Trim( )
        }
        if ($FileContent[$Count].malicious_confidence -ne $null){$Classtype += $FileContent[$Count].malicious_confidence}
        if ($FileContent[$Count].malware_families -ne $null){$Classtype += $FileContent[$Count].malware_families}
        if ($FileContent[$Count].kill_chains -ne $null){$Classtype += $FileContent[$Count].kill_chains}
        if ($Classtype -ne $null){
            $FinalClasstype = "classtype`:`"$Classtype`"`;"
            $FinalClasstype = $FinalClasstype.Trim( )
        }
        $FinalSID = "sid`:`"$global:SID`"`;rev`:1`;"
        $IPDST = $FileContent[$Count].indicator
        echo "alert ANY ANY <> $IPDST ANY ($FinalMessage$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
        $global:SID += 1
        $global:TotalIPs += 1
}

####################

function Detect-Type {
    ####Hash Statements
    if ($FileContent[$Count].type -eq "hash_sha1"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "hash_sha256"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "hash_md5"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "sha1"){
        Content-Hash
   }
    if ($FileContent[$Count].type -eq "sha256"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "sha384"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "sha512"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "authentihash"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "ssdeep"){
        Content-Hash
    }
    if ($FileContent[$Count].type -eq "md5"){
        Content-Hash
    }
    ####IP Statements
    if ($FileContent[$Count].type -eq "ip-src") {
        Source-Ip
    }
    if ($FileContent[$Count].type -eq "ip-dst"){
        Destination-Ip
    }
    if ($FileContent[$Count].type -eq "ip_address"){
        Destination-Ip
    }
    ####Domain Statements
    if ($FileContent[$Count].type -eq "domain"){
        Content-Domain
    }
    if ($FileContent[$Count].type -eq "url"){
        Content-Domain
    }
    if ($FileContent[$Count].type -eq "email_address"){
        Content-Domain
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
