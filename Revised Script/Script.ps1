$csv = read-host "Input CSV Name"
$mem = import-csv $csv

$count = 0
$sid = 30000001
while ($count -lt $mem.count){
    if ($mem[$count].type -eq "FQDN") {
        $Value = $mem[$count].Value
        add-content -path .\apt29.rules -value "alert ip any any <> any any (msg:`"$Value`";content:`"$Value`";rev:1;sid:$sid;)"
    }
    if ($mem[$count].type -eq "IPV4") {
        $Value = $mem[$count].Value
        add-content -path .\apt29.rules -value "alert ip $Value any <> any any (msg:`"$Value`";rev:1;sid:$sid;)"
    }
    ##MD5 Rule needs proper rule field
    if ($mem[$count].type -eq "MD5") {
        $Value = $mem[$count].Value
        add-content -path .\ioc.rules -value "alert ip any any <> any any (msg:`"MD5: $Value`";rev:1;sid:$sid;)"
    }
     if ($mem[$count].type -eq "URL") {
        $Initial = $mem[$count].Value
        $Value = $Initial.replace(':','|3A|')
        add-content -path .\apt29.rules -value "alert ip any any <> any any (msg:`"URL: $Value`";content:`"$Value`"rev:1; sid:$sid;)"
    }
    $count += 1
    $sid += 1
    #write-host $sid
}
exit
