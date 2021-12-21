:: Entrar no pc q bugou o copiar e colar
:: executar o script
:: apenas desbuga para o user atual!!
:: testar copiar e colar via RDP apos rodar script!

taskkill /f /im rdpclip.exe /fi "username eq %USERNAME%"
start rdpclip.exe
exit
PAUSE