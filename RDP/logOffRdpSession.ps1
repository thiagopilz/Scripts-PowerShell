#PowerShell: How to Logoff an User RDP Session

#--
$servername='SERVER'
$userName='uSERNAME'
  
function logOffRdpSession{
    param(
      $serverName=$env:computername,
      $username
    )
    $username=if($username -match '\\'){[regex]::match($username,'\\(.*)$').captures.groups.value[1]
      }else{
        $username.tostring()
      }
    $sessions=qwinsta /server:$serverName
    $sessionId=.{
        $sessionMatch=$sessions|?{$_ -match $username}
        if($sessionMatch){
            $array=$sessionMatch -replace '(^\s+|\s+$)','' -replace '\s+',' ' -split ' '
            return $array|?{$_.tostring() -match '\d+'}
        }else{
            return $null  
        }
    }
    if($sessionId){
      $sessionId|%{rwinsta $_ /SERVER:$serverName}
      $sessions=qwinsta /server:$serverName
      $newSessionId=.{
          $sessionMatch=$sessions|?{$_ -match $username}
          if($sessionMatch){
              $array=$sessionMatch -replace '(^\s+|\s+$)','' -replace '\s+',' ' -split ' '
              return $array[2]
          }else{
              return $null  
          }
      }
      if(!$newSessionId){
        write-host "$username RDP session ID $sessionId on $serverName has been forcefully disconnected."
      }else{
        write-warning "$username RDP session ID $sessionId still exists on $serverName"
      }      
    }else{
      write-host "$username doesn't have an RDP session on $serverName"
    }
}
  
logoffRdpSession $servername $username
#--


#.\logOffRdpSession.ps1

#PS C:\tmp\PowerView-master\test> .\logOffRdpSession.ps1
#tpilz RDP session ID 2 on 172.X.X.X has been forcefully disconnected.
#PS C:\tmp\PowerView-master\test>
#PS C:\tmp\PowerView-master\test>

# quser /server:HOSTNAME
