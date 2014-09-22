function Reset-ADAccountPassword
{
<#
    .SYNOPSIS
    Resets an AD user's password.
    .DESCRIPTION
    Resets an AD user's password.
    .EXAMPLE
    Reset-ADAccountPassword -User kjotaro -Password St@rDu$t86
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, Position=0)]
        [alias("Account")]
        [alias("Name")]
        [string]$User,
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, Position=1)]
        [string]$Password,
        [Parameter(Mandatory=$false)]
        [alias("ResetAtLogon")]
        [alias("ChangeAtLogon")]
        [switch]$ChangePasswordAtLogon
    )
    if($ChangePasswordAtLogon -eq $true)
    {
        Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -PassThru |
            Set-ADuser -ChangePasswordAtLogon $true
    }
    else
    {
        Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force)
    }
}
