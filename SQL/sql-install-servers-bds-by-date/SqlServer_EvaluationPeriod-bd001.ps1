
##POWERSHELL LIBERAR EXUÇÃO SCRIPTS
# Get-ExecutionPolicy -List
# Set-ExecutionPolicy Unrestricted
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned

##VERIFICAÇÃO DIAS A SEREM VOLTADOS PELO SCRIPTS
# 1) VER A DATA DE INSTALAÇÃO DO SQL SERVER PELO "PROGRAMAS E RECURSOS"
#ou PELOS ARQUIVOS QUE FORAM RESTAURADOS NO D:/SQLDADOS/
# 2) EXECUTAR NO QUERY DO SQL O COMANDO ABAIXO COM A DATA: ex: instalação sql dia "26/03/2020"
# select datediff(day, '26/03/2020', getdate())

$currentDate = Get-Date

$pastTime = $currentDate.AddDays(-356)

set-date $pastTime

Start-Service -Name "*sql*" -ErrorAction SilentlyContinue

$areServicesStopped = $true

while($areServicesStopped){

    $serviceStatus = get-service -Name "*sql*" | select status

    if ($serviceStatus -notlike "Stopped")    {

        $areServicesStopped = $false

    }

    Start-Sleep -Seconds 1

}

$currentDate = $pastTime.AddDays(356)

set-date $currentDate