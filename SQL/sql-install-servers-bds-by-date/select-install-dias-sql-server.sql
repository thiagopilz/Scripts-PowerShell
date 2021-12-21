--Select dias de instalações sql server a voltar script evoltion version expiration!

--##POWERSHELL LIBERAR EXUÇÃO SCRIPTS
--# Get-ExecutionPolicy -List
--# Set-ExecutionPolicy Unrestricted
--# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned

--##VERIFICAÇÃO DIAS A SEREM VOLTADOS PELO SCRIPTS
--# 1) VER A DATA DE INSTALAÇÃO DO SQL SERVER PELO "PROGRAMAS E RECURSOS"
--#ou PELOS ARQUIVOS QUE FORAM RESTAURADOS NO D:/SQLDADOS/
--# 2) EXECUTAR NO QUERY DO SQL O COMANDO ABAIXO COM A DATA: ex: instalação sql dia "26/03/2020"
--# select datediff(day, '26/03/2020', getdate())

--#################################################################################
--Select dias de instalações sql server a voltar script evoltion version expiration!

--BD001
select datediff(day, '21/04/2020', getdate())

--BD003
select datediff(day, '26/03/2020', getdate())

--BD004
select datediff(day, '29/10/2019', getdate())

--BD005
select datediff(day, '30/04/2020', getdate())

--BD006
select datediff(day, '18/08/2019', getdate())

--BD007
select datediff(day, '24/01/2021', getdate())

--BD008
select datediff(day, '25/08/2019', getdate())

--BD011
select datediff(day, '01/10/2020', getdate())

--#################################################################################