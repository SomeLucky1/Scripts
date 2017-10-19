Import-Module ActiveDirectory
Import-Module Jira

Function Get-Temppassword() {
#Generates a random password
	Param(
    	[int]$length=10,
	    [string[]]$sourcedata
	)

	For ($loop=1; $loop –le $length; $loop++) {
        $TempPassword+=($sourcedata | GET-RANDOM)
    }
		return $TempPassword 
}

function Toggle-Protected {
#Enables or disables the ProtectFromAccidentalDeletion flag from an object
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $ToggleUser,
        [string]$domain,
        [switch]$Unprotect,
        [switch]$Protect
    )

    Process
    {
        $RefreshUser=(Get-ADUser $ToggleUser -Server $domain).DistinguishedName
        if ($Unprotect){
            Set-ADObject -Server $domain -Identity $RefreshUser -ProtectedFromAccidentalDeletion $false
        }
        if ($Protect){
            Set-ADObject -Server $domain -Identity $RefreshUser -ProtectedFromAccidentalDeletion $true
        }
    }
}

#The Security provided account termination script
function Process-Term
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $tuser,
        $domain
    )

    Process
    {
        #Get AD user attributes
        $AccountToDisable = get-aduser $tuser -Properties MemberOf,EmployeeID -Server $domain

        #Set No Logon Hours
        $logonHoursHashTable = New-Object HashTable; $logonHoursHashTable.Add("logonHours", $NOLOGONHOURS )
        Set-ADUser -Identity $AccountToDisable.DistinguishedName -Server $domain -Replace $logonHoursHashTable -Confirm:$false

        #Set Random Password
        $randompassword=Get-Temppassword –length 20 –sourcedata $ascii
        $newpwd = ConvertTo-SecureString -String "$randompassword" -AsPlainText –Force
        Set-ADAccountPassword -Server $domain -Identity $AccountToDisable.DistinguishedName -NewPassword $newpwd

        #Disable Lync attributes
        Deactivate-Lync $AccountToDisable.SamAccountName

        #Hide Exchange Mailbox and set autoreply
        Hide-Mailbox $AccountToDisable.SamAccountName

        #Change Account Description
        $YearMonthDay=get-date -Format yyyy-MM-dd
        $DisabledDesc="Disabled " + $YearMonthDay
        Set-ADUser -Server $domain -Identity $AccountToDisable.SamAccountName -Description $DisabledDesc

        #Clear manager attribute
        #Set-ADUser $AccountToDisable.SamAccountName -Manager $null -Server $domain

        #Remove all group memberships
        $grouplist=$AccountToDisable.MemberOf
        foreach ($group in $grouplist) {
            Remove-ADGroupMember -Server $domain -Identity $group -Members $AccountToDisable.DistinguishedName -Confirm:$false
        }
    }
}

function Term-HoldUser
#Processes Terminated users on Litigation Hold
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$thuser,
        [string]$domain
    )
    Process
    {
    $RefreshUser=(Get-ADUser $thuser -Server $domain).DistinguishedName
    Toggle-Protected $thuser -Unprotect -Domain $domain
    Process-Term $thuser -domain $domain
    Move-ADObject -Server $domain -Identity $RefreshUser -TargetPath "OU=Exceptions,OU=People,DC=corp,DC=yp,DC=com" -ErrorAction Stop
    Toggle-Protected $thuser -Protect -Domain $domain
    Set-ADUser $thuser -Clear manager -Server $domain
    }
}

function Move-HoldUser
#Moves Terminated users on Litigation Hold
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$thuser,
        [string]$domain
    )
    Process
    {
    $RefreshUser=(Get-ADUser $thuser -Server $domain).DistinguishedName
    Toggle-Protected $thuser -Unprotect -Domain $domain
    Move-ADObject -Server $domain -Identity $RefreshUser -TargetPath "OU=Exceptions,OU=People,DC=corp,DC=yp,DC=com" -ErrorAction Stop
    Toggle-Protected $thuser -Protect -Domain $domain
    }
}

function Leave-User
#Moves a user account with the Leave status
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $luser
    )

    Process
    {
        $RefreshUser=(Get-ADUser $luser -Server $domain).DistinguishedName
        Toggle-Protected $luser -Unprotect -Domain $domain
        Move-ADObject -server $domain -Identity $RefreshUser -TargetPath "OU=Inactive,OU=People,DC=corp,DC=yp,DC=com" -ErrorAction Stop
        Toggle-Protected $luser -Protect -Domain $domain
    }
}

function ReinstateHold-User{
#Reinstates user returning from leave
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $ruser,
        [Switch]$Employee,
        [Switch]$Contractor
    )

    Process
    {
        $RefreshUser=(Get-ADUser $ruser -Server $domain).DistinguishedName
        Toggle-Protected $ruser -Unprotect -Domain $domain
        if ($Employee){
            Move-ADObject -server $domain -Identity $RefreshUser -TargetPath "OU=Employees,OU=People,DC=corp,DC=yp,DC=com" -ErrorAction Stop
        }
        if ($Contractor){
            Move-ADObject -server $domain -Identity $RefreshUser -TargetPath "OU=Contractors,OU=People,DC=corp,DC=yp,DC=com" -ErrorAction Stop
        }
        Toggle-Protected $ruser -Protect -Domain $domain
    }
}

function Reinstate-User{
#Reinstates re-hire user
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $ruser
    )

    Process
    {
        #Get AD user attributes
        $AccountToEnable = get-aduser $ruser -Properties MemberOf,EmployeeID,Description,logonHours -Server $domain

        #Set All Logon Hours
        $logonHoursHashTable = New-Object HashTable; $logonHoursHashTable.Add("logonHours", $ALLLOGONHOURS )
        Set-ADUser -Identity $AccountToEnable.DistinguishedName -Server $domain -Replace $logonHoursHashTable -Confirm:$false
        if ($AccountToEnable.Description -like "Disabled*"){
            Set-ADUser -Identity $AccountToEnable.Distinguishedname -Server $domain -Clear Description -Confirm:$false
        }

    }
}

function Disable-Lync {
#Disables user's Lync account
    Param (
        [string]$LyncUser 
    ) 
    Process {
        $user=Get-ADUser $LyncUser -properties *
        $CSPoolFQDN = "ca01-lyncfe01.corp.yp.com"
        $pos=($user.'msRTCSIP-PrimaryUserAddress').split(":")
        $LyncID=$pos[1]

        Invoke-Command -ConnectionUri https://$CSPoolFQDN/ocspowershell -Authentication NegotiateWithImplicitCredential -ScriptBlock {Disable-CsUser $using:LyncID}
    }
}

function Deactivate-Lync {
#Deactivates user's Lync account (preserves account settings)
    Param (
        [string]$LyncUser 
    ) 
    Process {
        $CSPoolFQDN = "ca01-lyncfe01.corp.yp.com"
        Invoke-Command -ConnectionUri https://$CSPoolFQDN/ocspowershell -Authentication NegotiateWithImplicitCredential -ScriptBlock {Set-CsUser $using:LyncUser -Enabled $false} -ErrorAction SilentlyContinue
    }
}

function Enable-Lync {
#Enables user's Lync account. Sets policy for SYKES users.
    Param (
        [string]$LyncUser
    )
    Process {
        $fullUser=get-aduser $LyncUser -Properties Company
        $LyncUser=$fullUser.samaccountname
        $CSPoolFQDN = "ca01-lyncfe01.corp.yp.com" 
        Invoke-Command -ConnectionUri https://$CSPoolFQDN/ocspowershell -Authentication NegotiateWithImplicitCredential -ScriptBlock {Enable-CsUser $using:LyncUser -RegistrarPool entpoolca01.corp.yp.com -SipDomain yp.com -SipAddressType SAMAccountName}
        if ($fulluser.Company -eq "SYKES") {
            Invoke-Command -ConnectionUri https://$CSPoolFQDN/ocspowershell -Authentication NegotiateWithImplicitCredential -ScriptBlock {Grant-CsExternalAccessPolicy $using:LyncUser -PolicyName 'Restricted External Access'} -ErrorAction SilentlyContinue}
    }
}

function Activate-Lync {
#Deactivates user's Lync account (preserves account settings)
    Param (
        [string]$LyncUser 
    ) 
    Process {        
        $CSPoolFQDN = "ca01-lyncfe01.corp.yp.com"
        Invoke-Command -ConnectionUri https://$CSPoolFQDN/ocspowershell -Authentication NegotiateWithImplicitCredential -ScriptBlock {Set-CsUser $using:LyncUser -Enabled $true} -ErrorAction SilentlyContinue
    }
}

function Get-GoodManager {
    Param (
        [string]$Manager
    )
    Process {
        $GoodManager=Get-ADUser -Identity $Manager -Properties manager | select -expand manager | get-aduser -Properties DisplayName,mail,extensionattribute6,EmployeeID
        if ($GoodManager.extensionattribute6 -eq "term" -or $GoodManager.extensionattribute6 -eq "leave") {
            Get-GoodManager $GoodManager
        }
        else {
            return $GoodManager
        }
    }
}

function Hide-Mailbox {
#Hides user's mailbox from the GAL
    Param (
        [string]$ExchangeUser,
        [string]$Manager
    )
    Process {
        $edate = (get-date -DisplayHint Date)
        $exchange = "ca01-exch04.corp.yp.com"
        $ExchangeUserFull = Get-aduser $ExchangeUser -properties DisplayName,manager,Division
        try {
            if ($manager -like $null) {
                $goodmanager = Get-GoodManager -Manager $ExchangeUser
            }
            else {
                $goodmanager=get-aduser $Manager -Properties DisplayName,mail,EmployeeID
            }

            $message = "As of " + $edate.DateTime + ", " + $ExchangeUserFull.DisplayName + " is no longer with DexYP. Please contact " + $goodmanager.DisplayName + " at " + $goodmanager.mail + " for any concerns that you may have. Thank you and have a great day."
        }
        catch {
            $message = "As of " + $edate.DateTime + ", " + $ExchangeUserFull.DisplayName + " is no longer with DexYP.  Sorry for the inconvenience.  Thank you and have a great day."
        }
        $externalmessage = $message
        $sb1={Set-Mailbox $using:ExchangeUserFull.samaccountname -HiddenFromAddressListsEnabled $true}
        $sb2={Set-MailboxAutoReplyConfiguration -Identity $using:ExchangeUserFull.samaccountname -AutoReplyState Enabled -InternalMessage $using:message -ExternalMessage $using:externalmessage}
        Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchange/powershell?SerializationLevel=Full -ScriptBlock $sb1
        Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchange/powershell?SerializationLevel=Full -ScriptBlock $sb2
                
    }
}

function Reinstate-Mailbox {
#Reinstate user's mailbox to the GAL and clears any office message.
    Param (
        [string]$ExchangeUser
    )
    Process {
        $message = ""
        $externalmessage = $message
        $exchange = "ca01-exch04.corp.yp.com"
        $ExchangeUserFull = Get-aduser $ExchangeUser -properties DisplayName,manager,Division
        $sb1={Set-Mailbox $using:ExchangeUserFull.samaccountname -HiddenFromAddressListsEnabled $false}
        $sb2={Set-MailboxAutoReplyConfiguration -Identity $using:ExchangeUserFull.samaccountname -AutoReplyState disabled -Internalmessage $using:message -ExternalMessage $using:externalmessage}
        Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchange/powershell?SerializationLevel=Full -ScriptBlock $sb1
        Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchange/powershell?SerializationLevel=Full -ScriptBlock $sb2
    }
}

function Set-TermDate {
#Sets Account Expiration Date from term date.
    Param (
        [string]$enduser
    )
    Process {
        Set-ADAccountExpiration -DateTime $date -Identity $enduser
    }
}

#Set date string
$date=(get-date -Format o)

#Set log file location
$logfile="C:\Temp\termusers.log"

#DC or domain to be used
$domain="va01-dc03.corp.yp.com"

#The logonHours attribute is a byte value
[byte[]]$NOLOGONHOURS = @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
[byte[]]$ALLLOGONHOURS = @(255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255)

#The source characters to be used in random password generation
$ascii=$NULL;For ($a=33;$a –le 126;$a++) {$ascii+=,[char][byte]$a }

#Obtain the list of users from the People OU excluding accounts already present in Exceptions
$users=get-aduser -Server $domain -Filter * -SearchBase "OU=People,DC=corp,DC=yp,DC=com" `
                                  -Properties EmployeeID,ExtensionAttribute6,ExtensionAttribute7,msExchLitigationHoldDate,msExchHomeServerName,Manager,logonHours,AccountExpires,msRTCSIP-UserEnabled,DisplayName,Description,msExchHideFromAddressLists | `
                                  Select-Object msExchHideFromAddressLists,msExchLitigationHoldDate,msExchHomeServerName,SamAccountName,ExtensionAttribute6,ExtensionAttribute7,DistinguishedName,Manager,logonHours,Enabled,AccountExpires,EmployeeID,msRTCSIP-UserEnabled,DisplayName,Description
                                  #Where-Object {$_.DistinguishedName -notmatch "OU=Exceptions"}

#Initialize user type arrays
$termholdusers=@()
$termusers=@()
$leaveholdusers=@()
$holdemployees=@()
$holdcontractors=@()
$provisionlyncusers=@()
$moveholdterms=@()
$deprovisionlyncusers=@()
$provisionrehires=@()

#Populate user type arrays using multiple filters
foreach ($user in $users) {
    [byte[]]$hours=@($user.logonHours)
    $logoncomp=Compare-Object $hours $NOLOGONHOURS
    #Build Deprovision Lync list (users that have already been disabled)
    if ($user.Description -like "Disabled*" -and `
        $user.ExtensionAttribute6 -eq "term" -and `
        $user."msRTCSIP-UserEnabled" -eq $true)
        {
        $deprovisionlyncusers += $user
        }
    #Build Move Hold Term'd users list (users that have already been disabled)
    elseif ($user.Description -like "Disabled*" -and `
            $user.msExchLitigationHoldDate -ne $null -and `
            $user.DistinguishedName -notmatch "OU=Exceptions")
        {
        $moveholdterms += $user
        }
    #Build Terminated users on litigation hold list
    elseif ($user.ExtensionAttribute6 -eq "term" -and `
        $user.msExchLitigationHoldDate -ne $null -and `
        $user.Description -notlike "Disabled*")
        {
        $termholdusers += $user
        }
    #Build Terminated to be fully processed list
    elseif ($user.ExtensionAttribute6 -eq "term" -and `
            $user.Description -notlike "Disabled*")
            {
        $termusers += $user
        }
    #Build Users on leave not in the Inactive OU on litigation hold list
    elseif ($user.ExtensionAttribute6 -eq "leave" -and `
            $user.DistinguishedName -notmatch "OU=Inactive" -and `
            $user.msExchLitigationHoldDate -ne $null ){
        $leaveholdusers += $user
        }
    #Build Enabled Contractors not in the Contractors OU on litigation hold list
    elseif ($user.Enabled -eq $true -and `
            $user.ExtensionAttribute6 -eq "active" -and `
            $user.ExtensionAttribute7 -eq "Contractor" -and `
            $user.DistinguishedName -notmatch "OU=Contractors" -and `
            $user.msExchLitigationHoldDate -ne $null )
            {
        $holdcontractors += $user
        }
    #Build Enabled Employees not in the Employees OU on litigation hold list
    elseif ($user.Enabled -eq $true -and `
            $user.ExtensionAttribute6 -eq "active" -and `
            $user.ExtensionAttribute7 -eq "Employee" -and `
            $user.DistinguishedName -notmatch "OU=Employees" -and `
            $user.msExchLitigationHoldDate -ne $null ) {
        $holdemployees += $user
        }
    #Build Rehires List
    elseif ($user.Extensionattribute6 -eq "active" -and `
            $user.Enabled -like $true -and `
            $user.Description -notlike "Emergency*" -and `
            ($user.msExchHideFromAddressLists -like $true -or `
            $logoncomp -like $null))
        {
        $provisionrehires += $user
        }
    #Provision Lync Users
    if ($user.ExtensionAttribute6 -eq "active" -and `
        $user."msRTCSIP-UserEnabled" -eq $null -and `
        $user."msExchHomeServerName" -notlike $null) {
        $provisionlyncusers += $user
        }
}
  
#Start processing user type lists
if ($termholdusers) {
    #Process Terminated accounts on litigation hold
    foreach ($termholduser in $termholdusers) {
            #Set-TermDate $termholduser.SamAccountName -domain $domain -ErrorAction Stop
            Deprovision-User $termholduser.EmployeeID
            Term-HoldUser $termholduser.SamAccountName -domain $domain
            Write-Output $date "Term'd Hold account " $termholduser.DistinguishedName | Out-File -Append $logfile
    }
}

if ($leaveholdusers) {
    #Process Users going on leave on litigation hold
    foreach ($leaveholduser in $leaveholdusers){
            Leave-User $leaveholduser.SamAccountName
            Write-Output $date "Moved to Leave" $leaveholduser.DistinguishedName | Out-File -Append $logfile
    }
}

if ($pretermusers) {
    #Set term'd user's account expiration date as end date.
    foreach ($pretermuser in $pretermusers) {
            #Set-TermDate $pretermuser.SamAccountName -domain $domain -ErrorAction Stop
            Write-Output $date "Set Expiration Date on user " $pretermuser.DistinguishedName | Out-File -Append $logfile
    }
}

if ($termusers) {
    #Process terminated users not on litigation hold
    foreach ($termuser in $termusers){
            Deprovision-User $termuser.EmployeeID
            Process-Term -tuser $termuser.SamAccountName -domain $domain
            Write-Output $date "Term'd user " $termuser.DistinguishedName | Out-File -Append $logfile
    }
}

if ($holdemployees) {
    #Process employees returning from leave on litigation hold.
    foreach ($holdemployee in $holdemployees){
            ReinstateHold-User $holdemployee.SamAccountName -Employee
            Write-Output $date "Reinstated Employee" $holdemployee.DistinguishedName | Out-File -Append $logfile
    }
}

if ($holdcontractors){
    #Process contractors returning from leave on litigation hold.
    foreach ($holdcontractor in $holdcontractors){
            ReinstateHold-User $holdcontractor.SamAccountName -Contractor
            Write-Output $date "Reinstated Contractor" $holdcontractor.DistinguishedName | Out-File -Append $logfile
    }
}

if ($provisionlyncusers){
    #Provision new users
    foreach ($provisionuser in $provisionlyncusers){
            Enable-Lync $provisionuser.SamAccountName | Out-File -Append $logfile
    }
}

if ($moveholdterms){
    #Process terms on litigation hold that were not disabled by the offboarding automation
    foreach ($moveholdterm in $moveholdterms){
            Move-HoldUser $moveholdterm.SamAccountName -domain $domain | Out-File -Append $logfile
    }
}

if ($deprovisionlyncusers){
    #Deprovision Lync accounts for users that have already been disabled
    foreach ($deprovisionlyncuser in $deprovisionlyncusers){
            Disable-Lync $deprovisionlyncuser.SamAccountName | Out-File -Append $logfile
    }
}

if ($provisionrehires){
    #Provision user accounts that have been rehired within 90 days
    foreach ($provisionrehire in $provisionrehires){
        if ($provisionrehire.msExchLitigationHoldDate -like $null){
        Reinstate-User $provisionrehire.samaccountname | Out-File -Append $logfile}
        else {ReinstateHold-User $provisionrehire.samaccountname | Out-File -Append $logfile}
        if ($provisionrehire.msExchHideFromAddressLists -like $true){
        Reinstate-Mailbox $provisionrehire.samaccountname | Out-File -Append $logfile}
    }
}