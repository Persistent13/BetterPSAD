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
    .PARAMETER User
    The array of users that will have their account passwords reset.
    .PARAMETER Password
    The password all users will recieve, if no password is specifed
    all users will recieve unique passwords.
    .PARAMETER ChangePasswordAtLogon
    If used all accounts specifed will recieve a prompt to have their passwords
    changed at logon.
    .INPUTS
    A user object is recieved by the User parameter.

    A password string is recieved by the Password parameter.
    .OUTPUTS
    Returns the user name and new password.
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
            Write-Debug "Getting password from function New-SWRandomPassword."
            $newPassword = New-SWRandomPassword
            Write-Debug "Attempting to change the user password and then unlock the account."
            Set-ADAccountPassword -Identity $User[$i] -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
            Unlock-ADAccount $User[$i]
            $properties = @{'User'=$User[$i];'New Password'=$newPassword}
            $object = New-Object -TypeName PSOBject -Property $properties
            Write-Output $object
        }
    }
    else
    {
        for($i=0;$i -le $User.length-1;$i++)
        {
            Write-Debug "Attempting to change the user password."
            Set-ADAccountPassword -Identity $User[$i] -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force)
            Write-Debug "Attemping to unlock the account."
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
function New-SWRandomPassword
{
    <#
    .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
       New-SWRandomPassword

       Will generate one password with a length of 8 chars.
    .EXAMPLE
       New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4

       Will generate four passwords with a length of between 8 and 12 chars.
    .OUTPUTS
       [String]
    .NOTES
       Written by Simon Wåhlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
       Generates random passwords
    .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
    #>
    [CmdletBinding(ConfirmImpact='Low')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [ValidateScript({$_ -gt 0})]
        [Alias("Min")] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1)]
        [ValidateScript({$_ -ge $MinPasswordLength})]
        [Alias("Max")]
        [int]$MaxPasswordLength = 12,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=2)]
        [String[]]$InputStrings = @('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789', '!"#%&'),
        
        # Specifies number of passwords to generate.
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=3)]
        [ValidateScript({$_ -gt 0})]
        [int]$Count = 1
    )
    Begin
    {
        Function Get-Seed
        {
            # Generate a seed for future randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToInt32($RandomBytes, 0)
        }
    }
    Process
    {
        For($iteration = 1;$iteration -le $Count; $iteration++)
        {
            # Create char arrays containing possible chars
            [char[][]]$CharGroups = $InputStrings

            # Set counter of used groups
            [int[]]$UsedGroups = for($i=0;$i -lt $CharGroups.Count;$i++){0}

            # Create new char-array to hold generated password
            if($MinPasswordLength -eq $MaxPasswordLength)
            {
                # If password length is set, use set length
                $password = New-Object -TypeName 'System.Char[]' $MinPasswordLength
            }
            else
            {
                # Otherwise randomize password length
                $password = New-Object -TypeName 'System.Char[]' `
                    (Get-Random -SetSeed $(Get-Seed) -Minimum $MinPasswordLength -Maximum $($MaxPasswordLength+1))
            }

            for($i=0;$i -lt $password.Length;$i++)
            {
                if($i -ge ($password.Length - ($UsedGroups | Where-Object {$_ -eq 0}).Count))
                {
                    # Check if number of unused groups are equal of less than remaining chars
                    # Select first unused CharGroup
                    $CharGroupIndex = 0
                    while(($UsedGroups[$CharGroupIndex] -ne 0) -and ($CharGroupIndex -lt $CharGroups.Length))
                    {
                        $CharGroupIndex++
                    }
                }
                else
                {
                    #Select Random Group
                    $CharGroupIndex = Get-Random -SetSeed $(Get-Seed) -Minimum 0 -Maximum $CharGroups.Length
                }

                # Set current position in password to random char from selected group using a random seed
                $password[$i] = Get-Random -SetSeed $(Get-Seed) -InputObject $CharGroups[$CharGroupIndex]
                # Update count of used groups.
                $UsedGroups[$CharGroupIndex] = $UsedGroups[$CharGroupIndex] + 1
            }
            Write-Output -InputObject $($password -join '')
        }
    }
}
