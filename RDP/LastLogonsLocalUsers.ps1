$Days = 1
$events = @()
$events += Get-WinEvent -FilterHashtable @{ 
    LogName='Security'
    Id=@(4800,4801)
    StartTime=(Get-Date).AddDays(-$Days) 
}
$events += Get-WinEvent -FilterHashtable @{ 
    LogName='System'
    Id=@(7000,7001)
    StartTime=(Get-Date).AddDays(-$Days) 
}

$type_lu = @{
    7001 = 'Logon'
    7002 = 'Logoff'
    4800 = 'Lock'
    4801 = 'UnLock'
}

$ns = @{'ns'='http://schemas.microsoft.com/win/2004/08/events/event'}
$target_xpath = "//ns:Data[@Name='TargetUserName']"
$usersid_xpath = "//ns:Data[@Name='UserSid']"

If($events) {
    $results = ForEach($event in $events) {
        $xml = $event.ToXml()
        Switch -Regex ($event.Id) {
            '4...' {
                $user = (
                    Select-Xml -Content $xml -Namespace $ns -XPath $target_xpath
                ).Node.'#text'
                Break            
            }
            '7...' {
                $sid = (
                    Select-Xml -Content $xml -Namespace $ns -XPath $usersid_xpath
                ).Node.'#text'
                $user = (
                    New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList $sid
                ).Translate([System.Security.Principal.NTAccount]).Value
                Break
            }
        }
        New-Object -TypeName PSObject -Property @{
            Time = $event.TimeCreated
            Id = $event.Id
            Type = $type_lu[$event.Id]
            User = $user
        }
    }
    If($results) {
        $results
    }
}


# https://gist.github.com/S3cur3Th1sSh1t/ad6f55d317b28230f129d856dccb1c0c