$userArray = 1..3
for($i=1;$i -le $userArray.Count+1; $i++)
{
    $restPassword = Invoke-RestMethod -Uri "https://passwd.me/api/1.0/get_password.txt?length=16"
    New-Object psobject -Property @{User = $userArray[$i]; Password = $restPassword}
}