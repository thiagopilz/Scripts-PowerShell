# 
#RODAR COMANDO
# . .\Get-LogonHistory.ps1

# CHECK LOGS HISTORY LOCAL
# Get-LogonHistory

# Get-LogonHistory -Newest 30
# Get-LogonHistory -ComputerName swsc01
# Get-LogonHistory -ComputerName swmtts001
# Get-LogonHistory -ComputerName swmtbd004 -Newest 30
# Get-LogonHistory -ComputerName swmtts001 -Newest 30
#ComputerName
# Get-LogonHistory -ComputerName SWMTTS001 -Credentials Get-Credential -Newst
# Get-LogonHistory -ComputerName SWMTTS001 -Credentials compus\tpilz

Function Get-LogonHistory
{
<#
.SYNOPSIS
    Retrieves history of last logged on users with usernames and respective logoff/logon times.
  
.DESCRIPTION
    Retrieves history of last logged on users with usernames and respective logoff/logon times.
 
.PARAMETER Newest
    This command gets the most recent entries from the event log according to its value.
  
.PARAMETER ComputerName
    A single Computer or an array of computer names. The default is localhost ($env:COMPUTERNAME).
  
.PARAMETER Credentials
    Commit Credentials for a different domain.
  
.PARAMETER Verbose
    Run in Verbose Mode.
  
.EXAMPLE
    PS C:\> Get-LogonHistory -ComputerName SERVER1 -Credentials Get-Credential -Newst
  
.NOTES
    Author:  Sebastian Gräf
    Email:   ps@graef.io
    Date:    April 15, 2017
    PSVer:   2.0/3.0/4.0/5.0
#>      
     
    [Cmdletbinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]]$ComputerName = $Env:COMPUTERNAME,
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string]$Newest = 10,
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential][System.Management.Automation.Credential()]
        $Credentials = [System.Management.Automation.PSCredential]::Empty
    )
     
    Begin
    {
        Write-Verbose " [$($MyInvocation.InvocationName)] :: Start Process"
        $Results = @()
        $ProgressCounter = 0
    }
     
     
    Process
    {
        foreach ($Computer in $ComputerName)
        {
            $ProgressCounter++
            Write-Progress -activity "Running on $Computer" -status "Please wait ..." -PercentComplete (($ProgressCounter / $ComputerName.length) * 100)
            if (Test-Connection $Computer -Count 1 -Quiet)
            {
                Write-Verbose " [$($MyInvocation.InvocationName)] :: Processing $Computer"
                try
                {
                    $ELogs = Get-EventLog System -Source Microsoft-Windows-WinLogon -ComputerName $Computer -Newest $Newest
                    #$ELogs = Invoke-Command { param ($Newest) Get-EventLog System -Source Microsoft-Windows-WinLogon -Newest $Newest } -ArgumentList $Newest -ComputerName $Computer
                    ForEach ($Log in $ELogs)
                    {
                        If ($Log.InstanceId -eq 7001)
                        {
                            $EventType = "Logon"
                        }
                        ElseIf ($Log.InstanceId -eq 7002)
                        {
                            $EventType = "Logoff"
                        }
                        Else
                        {
                            Continue
                        }
                        $Results += New-Object PSObject -Property @{
                            User = (New-Object System.Security.Principal.SecurityIdentifier $Log.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])
                            Time = $Log.TimeWritten
                            'Event Type' = $EventType
                        }
                    }
                    $Results
                }
                catch
                {
                    Write-Verbose " Host [$Computer] Failed with Error: $($Error[0])"
                }
            }
            else
            {
                Write-Verbose " Host [$Computer] Failed Connectivity Test"
            }
        }
        $result | Select User, Time, "Event Type" | Sort Time -Descending
    }
    End
    {
        Write-Progress -activity "Running on $Computer" -Status "Completed." -Completed
        Write-Verbose " [$($MyInvocation.InvocationName)] :: End Process"
    }
}