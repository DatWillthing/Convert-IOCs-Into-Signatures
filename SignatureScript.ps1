##Initial definitions for the Results Readme
$global:WarningPreference = 'SilentlyContinue'
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
        write-host "first if"
        $FileUnforContent = $FileUnforContent | Select-String -Pattern "$FileHeader" -NotMatch
        $FileUnforContent | Out-File $File
        get-content $File | Where { $_.Replace("\S","") -ne "" } | Set-content $File
        Check-Header
    }
    elseif ($FileHeader -eq "") {
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
$global:TypesSkipped = @()
####################

function Unprocessed-Types {
    if ($global:TypesSkipped -notcontains $FileContent[$Count].type){
        $global:TypesSkipped += $FileContent[$Count].type
    }
    $global:TotalSkips += 1
}

function Final-Message {
    if ($FileContent[$Count].type -ne $null){$Message += $FileContent[$Count].type}
    if ($FileContent[$Count].labels -ne $null){$Message += $FileContent[$Count].labels}
    if ($FileContent[$Count].message -ne $null){$Message += $FileContent[$Count].message}
    if ($Message -ne $null){
        $Message = $Message.Replace(', ',',')
        $FinalMessage = "msg`:`"$Message`"`;"
        $global:FinalMessage = $FinalMessage.Trim( )
    }
}
function Final-Reference {
    if ($FileContent[$Count].attribute_tag -ne $null){$Reference += $FileContent[$Count].attribute_tag}
    if ($FileContent[$Count].actors -ne $null){$Reference += $FileContent[$Count].actors}
    if ($FileContent[$Count].reports -ne $null){$Reference += $FileContent[$Count].reports}
    if ($Reference -ne $null){
        $Reference = $Reference.Replace('"','')
        $FinalReference = "reference`:`"$Reference`"`;"
        $global:FinalReference = $FinalReference.Trim( )
    }
}
function Final-Classtype {
    if ($FileContent[$Count].malicious_confidence -ne $null){$Classtype += $FileContent[$Count].malicious_confidence}
    if ($FileContent[$Count].malware_families -ne $null){$Classtype += $FileContent[$Count].malware_families}
    if ($FileContent[$Count].kill_chains -ne $null){$Classtype += $FileContent[$Count].kill_chains}
    if ($Classtype -ne $null){
        $FinalClasstype = "classtype`:`"$Classtype`"`;"
        $global:FinalClasstype = $FinalClasstype.Trim( )
    }
}

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
    Final-Message
    Final-Reference
    Final-Classtype
    $FinalSID = "sid`:$global:SID`;rev`:1`;"
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
    Final-Message
    Final-Reference
    Final-Classtype
    $FinalSID = "sid`:$global:SID`;rev`:1`;"
    echo "alert ANY ANY <> ANY ANY ($FinalMessage$FinalContent$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
    $global:SID += 1
    $global:TotalDomains += 1
}

function Source-Ip {
    $Message = @()
    $Reference = @()
    $Classtype = @()
    Final-Message
    Final-Reference
    Final-Classtype
    $FinalSID = "sid`:$global:SID`;rev`:1`;"
    $SrcIP = $FileContent[$Count].indicator
    echo "alert $SrcIP ANY <> ANY ANY ($FinalMessage$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
    $global:SID += 1
    $global:TotalIPs += 1
}

function Destination-Ip {
    $Message = @()
    $Reference = @()
    $Classtype = @()
    Final-Message
    Final-Reference
    Final-Classtype
    $FinalSID = "sid`:$global:SID`;rev`:1`;"
    $DstIP = $FileContent[$Count].indicator
    echo "alert ANY ANY <> $DstIP ANY ($FinalMessage$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
    $global:SID += 1
    $global:TotalIPs += 1
}
function Source-IpAndPort {
    $Message = @()
    $Reference = @()
    $Classtype = @()
    Final-Message
    Final-Reference
    Final-Classtype
    $FinalSID = "sid`:$global:SID`;rev`:1`;"
    $SrcIPAndPort = $FileContent[$Count].indicator
    $found = $SrcIPAndPort -match '^([a-zA-Z0-9.$_]{3,15})\|([a-zA-Z0-9,\[\]]+)$'
    if ($found) {
        $SrcIP = $matches[1]
        $DstPo = $matches[2]
    }
    echo "alert $SrcIP ANY <> ANY $DstPo ($FinalMessage$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
    $global:SID += 1
    $global:TotalIPs += 1
}
function Destination-IpAndPort {
    $Message = @()
    $Reference = @()
    $Classtype = @()
    Final-Message
    Final-Reference
    Final-Classtype
    $FinalSID = "sid`:$global:SID`;rev`:1`;"
    $DstIPAndPort = $FileContent[$Count].indicator
    $found = $DstIPAndPort -match '^([a-zA-Z0-9.$_]{3,15})\|([a-zA-Z0-9,\[\]]+)$'
    if ($found) {
        $DstIP = $matches[1]
        $DstPo = $matches[2]
    }
    echo "alert ANY ANY <> $DstIP $DstPo ($FinalMessage$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
    $global:SID += 1
    $global:TotalIPs += 1
}
function Destination-IpAndDomain {
    $Message = @()
    $Reference = @()
    $Classtype = @()
    Final-Message
    Final-Reference
    Final-Classtype
    $FinalSID = "sid`:$global:SID`;rev`:1`;"
    $DstIPAndDomain = $FileContent[$Count].indicator
    $found = $DstIPAndDomain -match '^([^|]+)\|([a-zA-Z0-9.$_]{3,15})$'
    if ($found) {
        $Content = $matches[1]
        $DstIP = $matches[2]
    }
    elseif ($Content -ne $null){
        $FinalContent = "content`:`"$Content`"`;"
        $FinalContent = $FinalContent.Trim( )
    }
    echo "alert ANY ANY <> $DstIP ANY ($FinalMessage$FinalContent$FinalReference$FinalClasstype$FinalSID)" >> $OutputFile`.rules
    $global:SID += 1
    $global:TotalIPs += 1
}

<#
function Content-Snort {
    $found = $null
    $Message = @()
    $Reference = @()
    $Classtype = @()
    $Content = @()
    Final-Message
    Final-Reference
    Final-Classtype
    $SnortRuleUnfor = $FileContent[$Count].indicator
    $found = $SnortRuleUnfor -match '^alert\s([a-z]{2,3})\s([a-zA-Z0-9.$_]{3,15})\s([a-zA-Z0-9,\[\]]+)\s(->|<>)\s([a-zA-Z0-9.$_]{3,15})\s([a-zA-Z0-9,\[\]]+)\s'
    if ($found) {
        $Proto = $matches[1]
        $SrcIP = $matches[2]
        $SrcPo = $matches[3]
        $Direc = $matches[4]
        $DstIP = $matches[5]
        #write-host "alert $Proto $SrcIP $SrcPo $Direc $DstIP $DstPo"
    }
    $SnortRuleUnfor = $SnortRuleUnfor -replace '^alert\s([a-z]{2,3})\s([a-zA-Z0-9.$_]{3,15})\s([a-zA-Z0-9,\[\]]+)\s(->|<>)\s([a-zA-Z0-9.$_]{3,15})\s([a-zA-Z0-9,\[\]]+)\s',''
    #write-host $SnortRuleUnfor
    $found = $SnortRuleUnfor -match 'content:'
    if ($found) {
        $Content = $matches[1]
        write-host "Content is $matches[1]"
        #Results in "Content is System.Collections.Hashtable[1]"
    }
    $FinalSID = "sid`:$global:SID`;rev`:1`;"    
    $SnortRule = $SnortRuleUnfor
    #echo $SnortRule >> $OutputFile`.rules
    echo $Content >> $OutputFile`.rules
    $global:SID += 1
    $global:TotalIPs += 1
}
#>
####################

function Detect-Type {
    ####Hash Statements
    if ($FileContent[$Count].type -eq "hash_sha1"){
        Content-Hash
    }
    elseif ($FileContent[$Count].type -eq "hash_sha256"){
        Content-Hash
    }
    elseif ($FileContent[$Count].type -eq "hash_md5"){
        Content-Hash
    }
    elseif ($FileContent[$Count].type -eq "sha1"){
        Content-Hash
   }
    elseif ($FileContent[$Count].type -eq "sha256"){
        Content-Hash
    }
    elseif ($FileContent[$Count].type -eq "sha384"){
        Content-Hash
    }
    elseif ($FileContent[$Count].type -eq "sha512"){
        Content-Hash
    }
    elseif ($FileContent[$Count].type -eq "authentihash"){
        Content-Hash
    }
    <#
    elseif ($FileContent[$Count].type -eq "ssdeep"){
        Content-Hash
    }
    #>
    elseif ($FileContent[$Count].type -eq "md5"){
        Content-Hash
    }
    ####IP Statements
    elseif ($FileContent[$Count].type -eq "ip-src") {
        Source-Ip
    }
    elseif ($FileContent[$Count].type -eq "ip-dst"){
        Destination-Ip
    }
    elseif ($FileContent[$Count].type -eq "ip_address"){
        Destination-Ip
    }
    ####Domain Statements
    elseif ($FileContent[$Count].type -eq "domain"){
        Content-Domain
    }
    elseif ($FileContent[$Count].type -eq "url"){
        Content-Domain
    }
    elseif ($FileContent[$Count].type -eq "email_address"){
        Content-Domain
    }
    elseif ($FileContent[$Count].type -eq "hostname"){
        Content-Domain
    }
    elseif ($FileContent[$Count].type -eq "uri"){
        Content-Domain
    }
    elseif ($FileContent[$Count].type -eq "ip-dst|port"){
        Destination-IpAndPort
    }
    elseif ($FileContent[$Count].type -eq "ip-src|port"){
        Source-IpAndPort
    }
    elseif ($FileContent[$Count].type -eq "domain|ip"){
        Destination-IpAndDomain
    }
    <#
    elseif ($FileContent[$Count].type -eq "snort"){
        #Snort rules have too much variety in makeup
        Content-Snort
    }
    #>
    else {
        Unprocessed-Types
    }
}

##Iterates through the file and writes pertinent info to suricata rules##
while ($Count -lt $length){
    $global:FinalReference = $null
    $global:FinalClasstype = $null
    $global:FinalMessage = $null
    $global:FinalContent = $null
    Detect-Type
    $Count += 1
}

Build-Results
$elapsedTime = $(get-date) - $StartTime
$totalTime = "{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)
write-host "Complete! Total time: $totalTime"
