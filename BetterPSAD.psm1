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

    This will reset the user kjotaro's password to St@rDu$t86 however the password
    will not be required to be changed at logon.

    .EXAMPLE
    C:\PS> Reset-ADAccountPassword -User kjotaro -Password St@rDu$t86 -ChangePasswordAtLogon

    This will reset the user kjotaro's password to St@rDu$t86 and set the account
    to have the password reset at next logon.

    .EXAMPLE
    C:\PS> Reset-ADAccountPassword -User kjotaro
    The password is now: h1HZwOag

    When a password is not specified a password will be generated for the account.
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
function Get-ADLockedAccount
{
<#
.SYNOPSIS
    Get-LockedOutUser.ps1 returns a list of users who were locked out in Active Directory.
 
.DESCRIPTION
    Get-LockedOutUser.ps1 is an advanced script that returns a list of users who were locked out in Active Directory
by querying the event logs on the PDC emulation in the domain.
 
.PARAMETER UserName
    The userid of the specific user you are looking for lockouts for. The default is all locked out users.
 
.PARAMETER StartTime
    The datetime to start searching from. The default is all datetimes that exist in the event logs.
 
.EXAMPLE
    Get-LockedOutUser.ps1
 
.EXAMPLE
    Get-LockedOutUser.ps1 -UserName 'mike'
 
.EXAMPLE
    Get-LockedOutUser.ps1 -StartTime (Get-Date).AddDays(-1)
 
.EXAMPLE
    Get-LockedOutUser.ps1 -UserName 'miker' -StartTime (Get-Date).AddDays(-1)
#>

[CmdletBinding()]
    param
    (
    [Parameter(Mandatory=$false,
                Position=1,
                ValueFromPipeline=$True,
                ValueFromPipelinebyPropertyName=$True)]
    [ValidateNotNullOrEmpty()]
    [Alias("Domain")]
    [string]$DomainName = $env:USERDOMAIN,

    [Parameter(Mandatory=$false,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelinebyPropertyName=$True)]
    [ValidateNotNullOrEmpty()]
    [Alias("Account","Name","User")]
    [string]$UserName = "*",

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [datetime]$StartTime = (Get-Date).AddDays(-3)
    )
    Invoke-Command -ComputerName ((Get-ADDomain).PDCRoleEmulator)`
        {Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740;StartTime=$Using:StartTime} | 
            Where-Object {$_.Properties[0].Value -like "$Using:UserName"} | 
                Select-Object -Property TimeCreated, @{Label='UserName';Expression={$_.Properties[0].Value}},`
                    @{Label='ClientName';Expression={$_.Properties[1].Value}}} -Credential (Get-Credential) | 
                        Select-Object -Property TimeCreated, 'UserName', 'ClientName'
}
