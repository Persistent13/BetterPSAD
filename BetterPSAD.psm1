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

    This will reset the user kjotaro's password to St@rDu$t86 and set the account
    to have the password reset at next logon.

    .EXAMPLE
    C:\PS> Reset-ADAccountPassword -User kjotaro -Password St@rDu$t86 -ChangePasswordAtLogon $false

    This will reset the user kjotaro's password to St@rDu$t86 however the password
    will not be required to be changed at logon.
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, Position=0)]
        [Alias("Account","Name")]
        [String]$User,
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, Position=1)]
        [String]$Password,
        [Parameter(Mandatory=$false)]
        [Alias("ResetAtLogon")]
        [Switch]$ChangePasswordAtLogon
    )
    if($ChangePasswordAtLogon)
    {
        Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force)
        Set-ADuser $User -ChangePasswordAtLogon $true
        Unlock-ADAccount $User
    }
    else
    {
        Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force)
        Unlock-ADAccount $User
    }
}
