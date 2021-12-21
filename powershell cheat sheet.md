==========================================================================================================
$PSVersionTable.PSVersion
pwsh #linux macos windows
==========================================================================================================
Get-Help Get-NetIpConfiguration
Get-Help XXX (cmdlet)

To see the examples, type: "get-help Get-NetIPConfiguration -examples".
For more information, type: "get-help Get-NetIPConfiguration -detailed".
For technical information, type: "get-help Get-NetIPConfiguration -full".
For online help, type: "get-help Get-NetIPConfiguration -online"
==========================================================================================================
#multi-line command

#Pipeline Operator: |
Get-Widget |
    Where-Object {$_.Height -gt 20 -and $_.Width -gt 20 -and -$_.Depth -gt 20} |
    Sort-Object -Property Price |
    Select-Object -First 100 |
    Select-Object -Property Name, Price, Height, Width, Depth, Description |
    Format-Table -AutoSize
    
&&  run the second command only if the first one succeeds.
|| run the second command only if the first one fails.

==========================================================================================================
#break command into multi lines, backtick sign
choco install `
 vagrant packer
==========================================================================================================
#auto confirm

still prompts target;
    is a directory
    and it is not empty
    and the -Recurse parameter is not specified.

Remove-Item -Recurse -Force -Confirm:$false- # enable it with -Confirm,disable it with -Confirm:$false
Remove-Item .\foldertodelete -Force -Recurse
#add a /A 
get-childitem C:\temp\ -exclude *.svn-base,".svn" -recurse | foreach ($_) {remove-item $_.fullname} /A
==========================================================================================================
Get-InstalledModule # list of modules on the computer that were installed by PowerShellGet
Get-InstalledModule -Name "AzureRM.Automation" -MinimumVersion 1.0 -MaximumVersion 2.0
==========================================================================================================
#Collecting Information About Computers, computer name/device name/machine name
#pws
Get-CimInstance -ClassName Win32_Desktop #username etc
Get-CimInstance -ClassName Win32_BIOS #complete information about the system BIOS on the local computer
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property SystemType #Listing Processor Information
Get-CimInstance -ClassName Win32_ComputerSystem #Listing Computer Manufacturer and Model
Get-CimInstance -ClassName Win32_QuickFixEngineering #Listing Installed Hotfixes
Get-CimInstance -ClassName Win32_QuickFixEngineering -Property HotFixID
"Get-CimInstance -ClassName Win32_QuickFixEngineering -Property HotFixId |
    Select-Object -Property HotFixId"

#Listing Operating System Version Information
"Get-CimInstance -ClassName Win32_OperatingSystem |
  Select-Object -Property BuildNumber,BuildType,OSType,ServicePackMajorVersion,ServicePackMinorVersion"
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Build*,OSType,ServicePack* 

#Listing Local Users and Owner
Get-CimInstance -ClassName Win32_OperatingSystem |
  Select-Object -Property NumberOfLicensedUsers,NumberOfUsers,RegisteredUser

#Getting Available Disk Space
Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" |
  Measure-Object -Property FreeSpace,Size -Sum |
    Select-Object -Property Property,Sum
    
#Getting Logon Session Information    
Get-CimInstance -ClassName Win32_LogonSession   
#Getting the User Logged on to a Computer
Get-CimInstance -ClassName Win32_ComputerSystem -Property UserName
#Getting Local Time from a Computer
Get-CimInstance -ClassName Win32_LocalTime
#Displaying Service Status, view the status of all services on a specific computer,
Get-CimInstance -ClassName Win32_Service |
    Select-Object -Property Status,Name,DisplayName

#find remote computer name
Resolve-DnsName 10.1.1.1
#Find computer name from IP address
$ipAddress= "192.168.1.54"
[System.Net.Dns]::GetHostByAddress($ipAddress).Hostname
#Resolve computer name to IP Address
$machineName= "DC1"
$hostEntry= [System.Net.Dns]::GetHostByName($machineName)
$hostEntry.AddressList[0].IPAddressToString
==========================================================================================================
#script,Resolve Hostname for set of IP addresses from text file,find computer name for multiple IP addresses
#create the text file ip-addresses.txt which includes one IP address in each line
#get the machinename list in the txt file machinenames.txt
Get-Content C:ip-addresses.txt | ForEach-Object{
$hostname = ([System.Net.Dns]::GetHostByAddress($_)).Hostname
if($? -eq $True) {
  $_ +": "+ $hostname >> "C:\machinenames.txt"
}
else {
   $_ +": Cannot resolve hostname" >> "C:\machinenames.txt"
}}
==========================================================================================================
==========================================================================================================
#script,Find Computer name for set of IP addresses from CSV
#create the csv file ip-addresses.csv which includes the column IPAddress in the csv file
#get the machinename list in the txt file machinenames.txt
#get the hostname and IP address list in the csv file machinenames.csv
Import-Csv C:ip-Addresses.csv | ForEach-Object{
$hostname = ([System.Net.Dns]::GetHostByAddress($_.IPAddress)).Hostname
if($? -eq $False){
$hostname="Cannot resolve hostname"
}
New-Object -TypeName PSObject -Property @{
      IPAddress = $_.IPAddress
      HostName = $hostname
}} | Export-Csv C:machinenames.csv -NoTypeInformation -Encoding UTF8
==========================================================================================================
#(requires administrator PowerShell)
PS C:\> Get-WinEvent -LogName system
PS C:\> Get-WinEvent -LogName security
PS C:\> Get-WinEvent -Path example.evtx | fl
PS C:\> Get-WinEvent -Path example.evtx | Out-GridView
PS C:\> Get-WinEvent -Path example.evtx | Group-Object id -NoElement | sort count
PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"; ID=7030,7045}
PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"} | fl | findstr /i USB
PS C:\> Get-WinEvent -FilterHashtable @{logname="system"; id=7030,7045}
PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"} | Where {$_.Message -like "*USB*"}
PS C:\> Get-WinEvent -FilterHashtable @{Path="application.evtx"; level=2}
PS C:\> Get-WinEvent -FilterHashtable @{Path="application.evtx";  level=2} | Measure-Object -Line
PS C:\> Get-WinEvent -logname "Microsoft-Windows-AppLocker/EXE and DLL"
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Applocker/EXE and DLL"; id=8004}
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Applocker/EXE and DLL"; id=8003}
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"}
==========================================================================================================
Get-EventLog -List
Get-EventLog -LogName System -Newest 5
Get-EventLog -LogName System -EntryType Error
Get-EventLog -LogName System -InstanceId 10016 -Source DCOM
Get-EventLog -LogName System -ComputerName Server01, Server02, Server03
Get-EventLog -LogName System -Message *description* #include a specific word in the message
#from an event log using a source and event ID
Get-EventLog -LogName Application -Source Outlook | Where-Object {$_.EventID -eq 63} |
              Select-Object -Property Source, EventID, InstanceId, Message
#
Get-EventLog -LogName System -UserName NT* | Group-Object -Property UserName -NoElement |
              Select-Object -Property Count, Name
              
#Shutdown Logs in Event Viewer
PS C:\> Get-EventLog System -Newest 10000 | `
        Where EventId -in 41,1074,1076,6005,6006,6008,6009,6013 | `
        Format-Table TimeGenerated,EventId,UserName,Message -AutoSize -wrap

> $Events = Get-EventLog -LogName System -Newest 5
> $Events | Group-Object -Property Source -NoElement | Sort-Object -Property Count -Descending

#Display the property values of an event
$A = Get-EventLog -LogName System -Newest 1
$A | Select-Object -Property *

$Begin = Get-Date -Date '1/17/2019 08:00:00'
$End = Get-Date -Date '1/17/2019 17:00:00'
Get-EventLog -LogName System -EntryType Error -After $Begin -Before $End
==========================================================================================================
Get-NetAdapter | Where-Object -FilterScript {$_.LinkSpeed -eq "100 Mbps"} #display all network adapters on the server that have a link speed of 100 megabits per second (Mbps)
Get-NetAdapter –Physical #list of physical network adapters
Get-NetAdapter –IncludeHidden #show any hidden network adapters
Get-NetAdapter | Where {$_.Virtual –eq $True} #only the virtual network adapters
Get-NetAdapter -InterfaceDescription "*VMware*"
Get-NetAdapter | select name, drivername, majordriverversion, minordriverversion, driverinformation #the driver used by the adapter
Get-NetAdapter | select vlandid, promiscuousmode, portnumber, networkaddress, permanentaddress, mediatype 
Get-NetAdapter | select transmitlinkspeed, physicalmediatype, mediaconnectionstate, speed, requestedspeed, maxspeed, fullduplex, linkspeed

#The output of this command consists of objects that can be passed through the pipeline to other cmdlets
#pipe the output into the Set-NetIPInterface cmdlet to assign a metric value of 5 to all interfaces having a link speed of 100 Mbps
PS C:\> Get-NetAdapter | Where-Object -FilterScript {$_.LinkSpeed -eq "100 Mbps"} | `
Set-NetIPInterface -InterfaceMetric 5

Get-NetAdapterBinding -InterfaceAlias "Ethernet" #display the bindings for the specified interface
Disable-NetAdapterBinding -Name "Ethernet 2" -ComponentID ms_pacer #Disabling a binding on a network adapter
Disable-NetAdapter -Name "Ethernet 2" -Confirm:$false #disables the adapter named Ethernet 2 with no confirmation prompt 
==========================================================================================================
Get-NetIPAddress | where {$_.PrefixOrigin -eq "DHCP" -or $_.SuffixOrigin -eq "DHCP"} #whether the DNS client on a machine is configured as static or dynamic
==========================================================================================================
Get-NetIpConfiguration
Get-NetIpConfiguration | Select-Object interfaceindex, interfacealias, Ipv4address 
#display the IPv4DefaultGateway property
Get-NetIpConfiguration | Select-Object interfaceindex, interfacealias, Ipv4address, @{ Label="DefaultGateway"; Expression={ $_.IPv4DefaultGateway.NextHop } 
#include the DNSServer property
Get-NetIpConfiguration | Select-Object interfaceindex, interfacealias, Ipv4address, @{ Label="DefaultGateway"; Expression={ $_.IPv4DefaultGateway.NextHop } }, @{ Label="DnsServers"; Expression={ $_.DnsServer.ServerAddresses } }
#tabular
Get-NetIpConfiguration | format-table interfaceindex, interfacealias, Ipv4address, @{ Label="DefaultGateway"; Expression={ $_.IPv4DefaultGateway.NextHop } }, @{ Label="DnsServers"; Expression={ $_.DnsServer.ServerAddresses } }
#cvs output
Get-NetIpConfiguration | format-table interfaceindex, interfacealias, Ipv4address, @{ Label="DefaultGateway"; Expression={ $_.IPv4DefaultGateway.NextHop } }, @{ Label="DnsServers"; Expression={ $_.DnsServer.ServerAddresses } } | Export-CSV .\output.csv

==========================================================================================================
Get-DnsServerZone #view a list of zones on a DNS server that is also a domain controller
Get-DnsServerResourceRecord -ZoneName corp.contoso.com | Where-Object {$_.RecordType -eq "A"} #list of resource records of type A (address) in the corp.contoso.com zone

#add a new A resource record
Add-DnsServerResourceRecordA -IPv4Address 172.16.11.239 -Name SEA-TEST `
-ZoneName corp.contoso.com
==========================================================================================================
Get-DhcpServerInDC #DHCP server
Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com" -ScopeId 10.10.10.0 #Get all active leases in a scope
Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com" -ScopeId 192.168.0.0
Get-DhcpServerv4Filter -ComputerName <MyDHCP> #If a client isn't able to receive an address, you can check to see whether it appears on the deny list
Get-DhcpServerv4Reservation -ComputerName <MyDHCP> -ScopeId 192.168.0.0  #reserved for devices with a fixed IP
Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com" -IPAddress 10.10.10.10,10.20.20.20 #Get leases for specified addresses
Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com" -IPAddress 10.10.10.10
DhcpServerv4FreeIPAddress -ComputerName <MyDHCP> -ScopeId 192.168.0.0 -StartAddress 192.168.0.59 -NumAddress 20 # lists 20 free addresses, starting from 192.168.0.59

Get-DhcpServerv4ScopeStatistics -ComputerName <MyDHCP>
Get-DhcpServerv4ScopeStatistics -ComputerName <MyDHCP> | # press enter for cursor ">>"
>> select -Property *

Get-DhcpServerAuditLog -ComputerName <MyDHCP> #find out whether logging has been activated for the DHCP service and where the log file is stored
Get-DhcpServerSetting -ComputerName <MyDHCP>

Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com" -ScopeId 10.10.10.0 -BadLeases #Get declined leases
Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com" -ScopeId 10.10.10.0 -ClientId "F0-DE-F1-7A-00-5E", "00-24-D7-C5-25-B0" #Get leases for specified clients
Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com" -ScopeId 10.10.10.0 -AllLeases
#Get active leases from all scopes on a computer
Get-DhcpServerv4Scope -ComputerName "dhcpserver.contoso.com" | Get-DhcpServerv4Lease -ComputerName "dhcpserver.contoso.com"

Get-DhcpServerv4FreeIPAddress -ComputerName "dhcpserver.contoso.com" -ScopeId 10.10.10.0 #Get a free address
Get-DhcpServerv4FreeIPAddress -ComputerName "dhcpserver.contoso.com" -ScopeId 10.10.10.0 -NumAddress 10
#Get a free address from a range
Get-DhcpServerv4FreeIPAddress -ComputerName "dhcpserver.contoso.com" -ScopeId 10.10.10.0 -StartAddress 10.10.10.10 -EndAddress 10.10.10.50

#no pipe, new line
# add a scope for the IP address range 172.16.12.50 through 172.16.11.100. Leave the scope inactive
PS C:\> Add-DhcpServerv4Scope -EndRange 172.16.12.100 -Name test2 `
-StartRange 172.16.12.50 -SubnetMask 255.255.255.0 -State InActive

#exclude the range 172.16.12.70 through 172.16.12.75 from the new scope
PS C:\> Add-DhcpServerv4ExclusionRange -EndRange 172.16.12.75 -ScopeId 172.16.12.0 `
-StartRange 172.16.12.70

# add a reservation for a file server
PS C:\> Add-DhcpServerv4Reservation -ClientId EE-05-B0-DA-04-00 -IPAddress 172.16.12.88 `
-ScopeId 172.16.12.0 -Description "Reservation for file server"

Set-DhcpServerv4OptionValue -Router 172.16.12.1 -ScopeId 172.16.12.0 #configure a default gateway address for the new scope
Set-DhcpServerv4Scope -State Active #activate

#search DHCP logs
PS C:\Windows\System32\dhcp> Get-Content DhcpSrvLog-*.log | Select-String -Pattern "Update Failed"
PS C:\Windows\System32\dhcp> Get-Content DhcpSrvLog-Fri.log | Select-String -Pattern "Update Failed"
PS C:\Windows\System32\dhcp> Get-Content DhcpSrvLog-Fri.log | Select -Last 50 | Select-String -Pattern "Update Failed"
==========================================================================================================
#List all installed software
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize > C:\temp\AllInstalledPrograms.txt

Get-WmiObject -Class Win32_Product | Select-Object -Property Name
Get-WmiObject -Class Win32_Product | Select-Object -Property Name,InstallLocation

==========================================================================================================

#Find an username, MAC Address in Active Directory with the IP address
nbtstat -a IP_ADDRESS

#Find current user logged on a computer 
psloggedon \\testcomp
==========================================================================================================
#Find a computer in Active Directory with the IP address
Get-ADComputer -filter 'ipv4address -eq "192.168.1.23"'
get-adcomputer -filter 'ipv4address -eq "146.6.21.118"' -properties ipv4address | ft name, ipv4address -auto
==========================================================================================================
Get-Content -Path LineNumbers.txt -TotalCount 5 #gets the first five lines of a file
(Get-Content -Path .\LineNumbers.txt -TotalCount 25)[-1] #gets a specific number of lines from a file and then displays only the last line of that content.
Get-Item -Path .\LineNumbers.txt | Get-Content -Tail 1 #gets the last line of content from a file
Get-Content -Path C:\Temp\* -Filter *.log #gets the content of all *.log files in the C:\Temp directory
Get-Content -Path .\LineNumbers.txt -Raw #get the contents of a file as one string, instead of an array of strings
Get-Content -Path C:\temp\test.txt -AsByteStream -Raw #get the contents of a file as a [byte[]] as a single object
==========================================================================================================
Get-Host | Select-Object Version
$PSVersionTable 
==========================================================================================================
#zip the Invoices folder in the root C directory and create an archive called Invoices.zip in the Archives folder
Compress-Archive -Path C:\Invoices -DestinationPath C:\Archives\Invoices
#zip the files in the Invoices folder individually using -LiteralPath instead of –Path,creates an archive with just the two files explicitly listed in the –LiteralPath
Compress-Archive -LiteralPath C:\ Invoices\File1.txt, C:\Invoices\File2.txt -DestinationPath C:\Archives\Invoices -Force
#adds all the files in the Invoices folder to my existing Invoices.zip archive
Compress-Archive -Path C:\Invoices\* -Update -DestinationPath C:\Archives\Invoices

#extracts the contents of the Invoices.zip archive to a folder named InvoicesUnzipped using the Expand-Archive cmdlet
Expand-Archive -LiteralPath C:\Archives\Invoices.Zip -DestinationPath C:\ InvoicesUnzipped
==========================================================================================================
#cmdlet uses the Path parameter to specify the directory C:\Test. Get-ChildItem displays the files and directories in the PowerShell console.
Get-ChildItem -Path C:\Test
Get-ChildItem -Path C:\Test -Name
Get-ChildItem -Path C:\Test\*.txt -Recurse -Force #displays .txt files that are located in the current directory and its subdirectories
Get-ChildItem -Path C:\Parent -Depth 2 #The Depth parameter determines the number of subdirectory levels to include in the recursion
Get-ChildItem -Path C:\Test\* -Include *.txt
Get-ChildItem -Path C:\Test\Logs\* -Exclude A*
Get-ChildItem -Path HKLM:\HARDWARE #uses the Path parameter to specify the registry key HKLM:\HARDWARE
Get-ChildItem -Path Cert:\* -Recurse -CodeSigningCert #The CodeSigningCert parameter gets only certificates that have code-signing authority
Get-ChildItem -Path C:\PathContainingHardLink | Format-Table -View childrenWithHardLink # get hard link information

Get-ChildItem /etc/r* #on Unix systems, the Get-ChildItem provides Unix-like output

gci 'C:\' -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path
findstr /s /i /c:"JndiLookup.class" C:\*.jar
==========================================================================================================
Set-Location -Path "HKLM:\" #sets the current location to the root of the HKLM: drive
Set-Location C:
Set-Location -Path "Env:\" -PassThru

Join-Path -Path $(Get-Location) -ChildPath "\scripts\*.ps1"

Push-Location -Path 'C:\Program Files\PowerShell\' -StackName "Paths" #adds the current location to the Paths stack
Set-Location -StackName "Paths" #makes the Paths location stack the current location stack
Get-Location -Stack # displays the locations in the current location stack
Get-Location #displays your location in the current PowerShell drive.

$pwd #Print Current Directory
$curDir = Get-Location #Current Directory Variable
Write-Host "Current Working Directory: $curDir"
Split-Path -Path $curDir -Parent #parent working directory

Write-Host $PSScriptRoot #current directory of script (ps1) 

#PowerShell current directory structure as C:\Backup\01-Sept\sqlbackup.ps1
#gets the relative path from the PowerShell current directory as .\01-Sept\sqlbackup.ps1
$relativePath = Get-Item Backup\01-Sept\sqlbackup.ps1 | Resolve-Path -Relative 
==========================================================================================================
#https://en.wikipedia.org/wiki/Environment_variable#Windows
$env:UserName
$env:UserDomain
$env:ComputerName
==========================================================================================================
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
[String] ${stUserDomain},[String]  ${stUserAccount} = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.split("\")
$(Get-WMIObject -class Win32_ComputerSystem | select username).username
$username=( ( Get-WMIObject -class Win32_ComputerSystem | Select-Object -ExpandProperty username ) -split '\\' )[1]
==========================================================================================================
#Write-Host writes to the console itself. Think of it as a MsgBox in VBScript. 
#Write-Output , on the other hand, writes to the pipeline, so the next command can accept it as its input

Write-Host "current user:"
Write-Host $(whoami)
Write-Host "Red on white text." -ForegroundColor red -BackgroundColor white
Write-Host (2,4,6,8,10,12) -Separator ", -> " -ForegroundColor DarkGreen -BackgroundColor White
# The following two statements can be used to effectively suppress output from Write-Host
Write-Host "I won't print" -InformationAction Ignore
Write-Host "I won't print" 6>$null


Write-Host "no newline test " -NoNewline
Write-Host "second string"

Write-Output "Hello world!"
Write-Output $VerbosePreference
==========================================================================================================
#run a script as another user. 
$cred = Get-Credential UserTo.RunAs
Run-AsUser.ps1 "whoami; pause" $cred
Run-AsUser.ps1 "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; pause" $cred

param(
  [Parameter(Mandatory=$true)]
  [string]$script,
  [Parameter(Mandatory=$true)]
  [System.Management.Automation.PsCredential]$cred
)

Start-Process -Credential $cred -FilePath 'powershell.exe' -ArgumentList 'noprofile','-Command',"$script"
==========================================================================================================
# powershell 
$PSVersionTable #check the version of PowerShell
powershell_ise.exe #start The Windows PowerShell Integrated Scripting Environment (ISE) 
==========================================================================================================
Execute command2 after execution of command1 has finished
command1 -f & command2
Execute command2 only if execution of command1 has finished successfully
command1 -f && command2
Execute command2 only if execution of command1 has finished unsuccessfully
command1 -f || command2

& "C:\Users\username\Downloads\first_script.ps1" #runs a script stored in the Downloads folder
==========================================================================================================
Set-PSDebug -Trace 2; foreach ($i in 1..3) {$i} #Turns script debugging features on and off, sets the trace level
Set-PSDebug -Step; foreach ($i in 1..3) {$i}
Set-PSDebug -Strict; $NewVar # puts PowerShell in strict mode and attempts to access a variable that doesn't have an assigned valu
Set-PSDebug -Off; foreach ($i in 1..3) {$i}
==========================================================================================================
Get-Command #every command that PowerShell has
Get-Command –Name *IP* # find all cmdlets that contain the word “IP”
Get-Command –Module NetTCPIP –Name *IP*
Get-Command -Module Pester #all commands inside of the Pester module

Get-Help New-NetIPsecQuickModeCryptoProposal #the syntax and how you can use that specific cmdlet
Get-Help Write-Verbose -Online
Update-Help

Get-Process | Get-Member #see the methods and properties that pipe output to Get-Member
Get-Process | Where-Object {$_.Name –eq “iexplore”} #
==========================================================================================================
Get-Process | Out-File -Filepath \testfile.txt
Get-Process | Out-File -Filepath \testfile.txt -NoClobber #f another file exists with the same name and you don’t want your command to overwrite this file
==========================================================================================================
$VerbosePreference = "SilentlyContinue" #set to bypass verbose stream
$VerbosePreference = "Continue" #set to output verbose stream
==========================================================================================================
Get-Service -ComputerName computer -Name servicename
Get-Service -Name "osqueryd" | Restart-Service -Force
Get-Service -Name "osqueryd" | Stop-Service -Force

Get-Service -ComputerName computername -Name servicename | Restart-Service -Force
Get-Service -ComputerName computername -Name servicename | Stop-Service -Force
Get-Service -ComputerName computername -Name servicename | Start-Service

Get-Service "wmi*" #service names that begin with WMI 
"WinRM" | Get-Service #Get a service through the pipeline operator
Get-Service -Displayname "*network*"
Get-Service -Name "win*" -Exclude "WinRM"
Get-Service | Where-Object {$_.Status -eq "Running"} #displays only the services with a status of Running
Get-Service | Sort-Object status
Get-Service "s*" | Sort-Object status
Get-Service "WinRM" -RequiredServices #gets the services that the WinRM service requires
Get-Service | Where-Object {$_.name -eq “osqueryd”}

#services that have dependent services
Get-Service |
  Where-Object {$_.DependentServices} |
    Format-List -Property Name, DependentServices, @{
      Label="NoOfDependentServices"; Expression={$_.dependentservices.count}
    }

==========================================================================================================
Start-Service -Name "eventlog"
Start-Service -DisplayName *remote* -WhatIf #shows what would occur if you started the services that have a display name that includes "remote"

#Start a service and record the action in a text file
$s = Get-Service wmi
Start-Service -InputObject $s -PassThru | Format-List >> services.txt

#shows how to start a service when the start type of the service is Disabled
Get-CimInstance win32_service | Where-Object Name -eq "tlntsvr"
Set-Service tlntsvr -StartupType manual
Start-Service tlntsvr
==========================================================================================================
Get-WindowsCapability -Online -Name "SNMP*" #verify if the SNMP service is installed,the elevated PowerShell console 
==========================================================================================================
==========================================================================================================
powershell scripts
==========================================================================================================
==========================================================================================================
#the last logon times of each computer in the domain
$dcs = Get-ADComputer -Filter { OperatingSystem -NotLike '*Server*' } -Properties OperatingSystem
foreach($dc in $dcs) { 
    Get-ADComputer $dc.Name -Properties lastlogontimestamp | 
    Select-Object @{n="Computer";e={$_.Name}}, @{Name="Lastlogon"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}}
}
==========================================================================================================
#from bash to pwsh
pwsh -c " /path-to/script.ps1 -Param1 ABC -Param2 @{ 'key'='value' } "
==========================================================================================================
'{0:yyyy-MMM-dd}' -f $convertDate ## Convert datetime to yyyy-mmm-dd datetime format
==========================================================================================================