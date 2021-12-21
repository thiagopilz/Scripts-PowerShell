#Start-Sql-ServerServices.ps1
#Start MSSQL (Full) Services with PowerShell script.
#--
Start-Service -DisplayName "SQL Server (MSSQLSERVER)"
Start-Service -DisplayName "SQL Server Browser"
Start-Service -DisplayName "SQL Server Agent (MSSQLSERVER)"
#--
