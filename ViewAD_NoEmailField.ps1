get-aduser -filter * -properties * | where {!$_.emailaddress} | select-object samaccountname | export-csv c:\noemailusers.csv
