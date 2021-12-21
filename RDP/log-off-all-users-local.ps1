# LOGOFF LOCAL USER
# Is there a way to log off all of the users in a single command?
# LOGOFF ALL USER LOCAL
# log-off-all-users-local
$sessions = query session | ?{ $_ -notmatch ‘^ SESSIONNAME’ } | %{
$userID = “” | Select “Id”
$userID = $_.Substring(39,9).Trim()
$userID
}

foreach ($session in $sessions)
{
logoff $session.Id
}