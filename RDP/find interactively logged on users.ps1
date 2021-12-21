#outra resposta
# If you want to find interactively logged on users, I found a great tip here :https://p0w3rsh3ll.wordpress.com/2012/02/03/get-logged-on-users/ (Win32_ComputerSystem did not help me)

$explorerprocesses = @(Get-WmiObject -Query "Select * FROM Win32_Process WHERE Name='explorer.exe'" -ErrorAction SilentlyContinue)
If ($explorerprocesses.Count -eq 0)
{
    "No explorer process found / Nobody interactively logged on"
}
Else
{
    ForEach ($i in $explorerprocesses)
    {
        $Username = $i.GetOwner().User
        $Domain = $i.GetOwner().Domain
        Write-Host "$Domain\$Username logged on since: $($i.ConvertToDateTime($i.CreationDate))"
    }
}
#----


# powershell-script-to-see-currently-logged-in-users-domain-and-machine-status
#PS C:\tmp> .\teste.ps1
#COMPUS\ncardoso logged on since: 08/05/2021 17:47:41
#COMPUS\postojb_01 logged on since: 08/06/2021 07:59:28
#COMPUS\sulsolo_02 logged on since: 08/06/2021 11:18:59
#COMPUS\postosbo_01 logged on since: 08/09/2021 09:33:42
#COMPUS\tpilz logged on since: 08/09/2021 18:40:54
#PS C:\tmp>
