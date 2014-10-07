function Reset-ADAccountPassword
{
<#
    .SYNOPSIS
    Resets an AD user's password and unlocks the account.
    .DESCRIPTION
    Resets an AD user's password and unlocks the account with the option to have 
    the password changed at the users logon. The user You can identify a user by
    its distinguished name (DN), GUID, security identifier (SID) or
    Security Accounts Manager (SAM) account name.
    .EXAMPLE
    Reset-ADAccountPassword -User kjotaro -Password St@rDu$t86

    User                                                           New Password
    ----                                                           ------------
    kjotaro                                                        St@rDu$t86

    This will reset the user kjotaro's password to St@rDu$t86 however the password
    will not be required to be changed at logon.

    .EXAMPLE
    C:\PS> Reset-ADAccountPassword -User kjotaro -Password St@rDu$t86 -ChangePasswordAtLogon

    User                                                           New Password
    ----                                                           ------------
    kjotaro                                                        St@rDu$t86

    This will reset the user kjotaro's password to St@rDu$t86 and set the account
    to have the password changed at next logon.

    .EXAMPLE
    C:\PS> Reset-ADAccountPassword -User kjotaro

    User                                                           New Password
    ----                                                           ------------
    kjotaro                                                        h1HZwOag

    When a password is not specified a password will be generated for the account.

    .EXAMPLE
    C:\PS> Reset-ADAccountPassword -User kjotaro, jjoestar -Password St@rDu$t86 -ChangePasswordAtLogon

    User                                                           New Password
    ----                                                           ------------
    kjotaro                                                        St@rDu$t86
    jjoestar                                                       St@rDu$t86

    This command will reset all users to the password St@rDu$t86 and set the
    accounts to have their passwords changed at logon.

    .EXAMPLE
    C:\PS> Reset-ADAccountPassword -User kjotaro, jjoestar

    User                                                           New Password
    ----                                                           ------------
    kjotaro                                                        iLZt9NGh
    jjoestar                                                       TjI9WvUF

    When a password is not specified a unique password will be generated for each
    of the accounts.
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$True, 
                    Position=0,
                    ValueFromPipelinebyPropertyName=$True)]
        [Alias("Account","Name","UserName")]
        [String[]]$User,

        [Parameter(Mandatory=$false, Position=1)]
        [String]$Password,

        [Parameter(Mandatory=$false)]
        [Alias("ResetAtLogon")]
        [Switch]$ChangePasswordAtLogon
    )
    if(!$Password)
    {
        for($i=0;$i -le $User.length-1;$i++)
        {
            Write-Debug "Getting password from external address https://passwd.me/api/1.0/get_password.txt?length=8"
            $restPassword = Invoke-RestMethod -Uri "https://passwd.me/api/1.0/get_password.txt?length=8"
            Write-Debug "Attempting to change the user password and then unlock the account."
            Set-ADAccountPassword -Identity $User[$i] -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $restPassword -Force)
            Unlock-ADAccount $User[$i]
            $properties = @{'User'=$User[$i];'New Password'=$restPassword}
            $object = New-Object -TypeName PSOBject -Property $properties
            Write-Output $object
        }
    }
    else
    {
        for($i=0;$i -le $User.length-1;$i++)
        {
            Write-Debug "Attempting to change the user password and then unlock the account."
            Set-ADAccountPassword -Identity $User[$i] -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force)
            Unlock-ADAccount $User[$i]
            $properties = @{'User'=$User[$i];'New Password'=$Password}
            $object = New-Object -TypeName PSOBject -Property $properties
            Write-Output $object
        }

    }
    if($ChangePasswordAtLogon)
    {
        for($i=0;$i -le $User.length-1;$i++)
        {
            Write-Debug "Attempting to set the user account to change the password at logon."
            Set-ADuser $User[$i] -ChangePasswordAtLogon $true
        }
    }
}