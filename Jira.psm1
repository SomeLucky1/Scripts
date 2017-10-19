#Module for creating offboarding tickets in Jira via REST API.

Import-Module HPAM
Import-Module Vault

#Set the initial global variables and Jira account used
$OpsJira = "http://opsjira.yp.com/rest/api/latest/"
$JiraEnduser = "http://jiraenduser.yp.com/rest/api/latest/"
$Jira = "http://jira.yp.com/rest/api/latest/"
$PSDefaultParameterValues=@{}
$VaultCredentials = Get-Content C:\Utils-sa\scripts\vault_creds.txt
$VaultGroup = "Jira"
$ValueName = "corpinf"
$YearMonthDay=get-date -Format yyyy-MM-dd

#Function defaults could be set here instead of being hard coded into the function
$PSDefaultParameterValues=@{
    'Create-WinTicket:IssueType'="Task"
    'Create-WinTicket:Priority'="2 - Fix Best Effort"
    'Create-SeparationTicket:DateRequested'="$YearMonthDay"
    'Create-SeparationTicket:EmployeeType'=$null
}

function Get-JiraSecureValue {
    <#
    .Synopsis
    Gets the credentials for jira api service account.
    #>
    $SecureValue=Get-SecureValue -VaultGroup $VaultGroup -ValueName $ValueName -VaultCredentials $VaultCredentials
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$ValueName`:$SecureValue")
    $encodedCredentials = [System.Convert]::ToBase64String($bytes)
    return $encodedCredentials
}

function Add-LocalLink (){
    <#
    .Synopsis
    Creates a Link between two tickets on the same JIRA instance.
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("Blocking", "Blocks","Plan","Relates","Root Cause")]
        [string]$Type,
        [Parameter(Mandatory=$True)]
        [string]$InwardIssue,
        [Parameter(Mandatory=$True)]
        [string]$OutwardIssue
    )

    $body='{
        "type":{"name":"'+$Type+'"},
        "inwardIssue":{"key":"'+$InwardIssue+'"},
        "outwardIssue":{"key":"'+$OutwardIssue+'"}
    }'

    $RestApiUri = $JiraEnduser + "issueLink/"
    $Credentials = Get-JiraSecureValue
    Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
}


function Add-RemoteLink (){
    <#
    .Synopsis
    Creates a link between two JIRA tickets on different instances.
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [string]$SourceTicket,
        [Parameter(Mandatory=$True)]
        [string]$LinkTicket,
        [Parameter(Mandatory=$True)]
        [ValidateSet("jiraenduser", "opsjira", "jira")]
        [string]$SourceInstance,
        [Parameter(Mandatory=$True)]
        [ValidateSet("jiraenduser", "opsjira", "jira")]
        [string]$LinkInstance,
        [Parameter(Mandatory=$True)]
        [string]$SourceIssueID,
        [Parameter(Mandatory=$True)]
        [string]$LinkIssueID
    )

    #Build the requried URI and URLs for the web request call
    $RestApiUri = "http://" + $SourceInstance + ".yp.com/rest/api/latest/issue/" + $SourceTicket + "/remotelink"
    $RecipRestApiUri = "http://" + $LinkInstance + ".yp.com/rest/api/latest/issue/" + $LinkTicket + "/remotelink"
    $LinkURL = "http://" + $LinkInstance + ".yp.com/browse/" + $LinkTicket
    $RecipURL = "http://" + $SourceInstance + ".yp.com/browse/" + $SourceTicket

    #These are the specific JIRA instance application IDs for linking tickets on different JIRA instances
    $OpsappID = "appId=0aea100a-5cd5-39ee-a095-1b954d1deeb8&issueId="
    $EndUserappID = "appId=58173a7f-1b54-3c2b-b28e-0fa1e363b036&issueId="
    $JiraappID = "appId=42726e86-fdfb-300c-8fb7-7cf53bbb078f&issueId="

    #This is the logic for creating the appropriate globalID used for linking remote issues.
    if ($LinkInstance -eq "jiraenduser") {
        $GlobalID = $EndUserappID + $LinkIssueID
        $Name="YP - JIRAENDUSER"
    }
    elseif ($LinkInstance -eq "opsjira") {
        $GlobalID = $OpsappID + $LinkIssueID
        $Name="YP TechOps JIRA"
    }
    elseif ($LinkInstance -eq "jira") {
        $GlobalID = $JiraappID + $LinkIssueID
        $Name="YP JIRA"
    }
    if ($SourceInstance -eq "opsjira") {
        $RecipGlobalID = $OpsappID + $SourceIssueID
        $RecipName="YP TechOps JIRA"
    }
    elseif ($SourceInstance -eq "jiraenduser") {
        $RecipGlobalID = $EndUserappID + $SourceIssueID
        $RecipName="YP - JIRAENDUSER"
    }
    elseif ($SourceInstance -eq "jira") {
        $RecipGlobalID = $JiraappID + $SourceIssueID
        $RecipName="YP JIRA"
    }

    #The required body formats using the appropriate globalIDs
    $body = '{
        "application":{
            "type":"com.atlassian.jira",
            "name":"'+$Name+'"
        },
        "globalId":"'+$GlobalID+'",
        "relationship":"Relates to",
        "object":{
            "url":"'+$LinkURL+'",
            "title":"'+$LinkTicket+'"
        }
    }'

    $Recipbody = '{
        "application":{
            "type":"com.atlassian.jira",
            "name":"'+$RecipName+'"
        },
        "globalId":"'+$RecipGlobalID+'",
        "relationship":"Related to",
        "object":{
            "url":"'+$RecipURL+'",
            "title":"'+$SourceTicket+'"
        }
    }'

    $Credentials = Get-JiraSecureValue
    Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RecipRestApiUri -Method post -Body $Recipbody
}

function Create-WinTicket (){
    <#
    .Synopsis
	Create New Windows Infrastructure Jira tickets.
    #>
    Param(
       [string]$Assignee,
       [string]$Description,
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [ValidateSet("Corporate Infrastructure", "End User Infrastructure", "Platform Infrastructure")]
       $Components,
       [Parameter(Mandatory=$True)]
       [ValidateSet("Task", "Issue", "Project")]
       $IssueType,
       [ValidateSet("0 - Fix Now", "1 - Fix ASAP", "2 - Fix Best Effort", "3 - Fix TBD")]
       $Priority
    )
    $body='{
        "fields":{
            "project":{"key":"WIN"},
            "description":"'+$Description+'",
            "summary":"'+$Summary+'",
            "issuetype":{"name":"'+$IssueType+'"},
            "priority":{"name":"'+$Priority+'"},
            "assignee":{"name":"'+$Assignee+'"},
            "components":[{"name":"'+$Components+'"}]
            }
    }'
    
    $RestApiUri = $OpsJira + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Create-ITRequest (){
    <#
    .Synopsis
	Create New IT Request Jira tickets.
    #>
    Param(
       [string]$Reporter,
       [string]$Assignee,
       [string]$Description,
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [ValidateSet("IT - User Boarding Request")]
       [string]$IssueType,
       [Parameter(Mandatory=$True)]
       [ValidateSet("it/user-offboarding---equipment-retrieval2","it/user-offboarding---remove-access2","it/user-offboarding---windows-vm2","it/user-offboarding---master-ticket","it/user-offboarding---reclaim-licenses")]
       [string]$RequestType,
       [ValidateSet("Standard")]
       [string]$Priority,
       [string]$Manager,
       [string]$UserYPUID,
       [string]$ManagerYPUID,
       [string]$WorkLocation,
       [string]$Division,
       [string]$Company,
       [string]$Cube,
       [string]$FirstName,
       [string]$LastName

    )
    $body='{
        "fields":{
            "project":{"key":"IT"},
            "customfield_13013":"'+$RequestType+'",
            "description":"'+$Description+'",
            "summary":"'+$Summary+'",
            "issuetype":{"name":"'+$IssueType+'"},
            "priority":{"name":"'+$Priority+'"},
            "assignee":{"name":"'+$Assignee+'"},
            "reporter":{"name":"'+$Reporter+'"},
            "customfield_11444":"'+$UserYPUID+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11902":"'+$WorkLocation+'",
            "customfield_11903":"'+$Division+'",
            "customfield_11904":"'+$Company+'",
            "customfield_11325":"'+$Cube+'",
            "customfield_11427":"'+$FirstName+'",
            "customfield_11432":"'+$LastName+'"
            }
    }'
    
    $RestApiUri = $JiraEnduser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Create-SeparationTicket (){
    <#
    .Synopsis
	Create YPSUP Jira ticket to be used as a master ticket in which all other tickets are linked.
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [string]$Description,
       [string]$UserYPUID,
       [string]$ManagerYPUID,
       [string]$WorkLocation,
       [string]$Division,
       [string]$Company,
       [string]$FirstName,
       [string]$LastName,
       [string]$OfficeCode,
       [Validateset("AMDOCS Contractor", "Contractor", "Consultant", "Sales Rep", $null)]
       [string]$EmployeeType
    )
    $body='{
        "fields":{
            "project":{"key":"YPSUP"},
            "issuetype":{"name":"Offboarding Master"},
            "description":"'+$Description+'",
            "customfield_10401":"'+$YearMonthDay+'",
            "summary":"'+$Summary+'",
            "customfield_11444":"'+$UserYPUID+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11902":"'+$WorkLocation+'",
            "customfield_11903":"'+$Division+'",
            "customfield_11904":"'+$Company+'",
            "customfield_11427":"'+$FirstName+'",
            "customfield_11432":"'+$LastName+'",
            "customfield_11800":"'+$OfficeCode+'"
            }
    }'
    $RestApiUri = $JiraEnduser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Disable-CiscoCMPhone {
    <#
    .Synopsis
    Creates a JiraEndUser TE ticket to disable and deprovision a Cisco CM Phone
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [string]$UserYPUID,
       [Parameter(Mandatory=$True)]
       [string]$ManagerYPUID,
       [Parameter(Mandatory=$True)]
       [string]$FirstName,
       [Parameter(Mandatory=$True)]
       [string]$LastName,
       [Parameter(Mandatory=$True)]
       [string]$DeskPhone,
       [string]$WorkLocation,
       [string]$Division,
       [string]$Company,
       [string]$Cube,
       [string]$Description,
       [string]$OfficeCode
    )
    $body='{
        "fields":{
            "project":{"key":"TE"},
            "issuetype":{"name":"Task"},
            "components":[{"name":"Offboarding"}],
            "summary":"'+$Summary+'",
            "customfield_11379":"'+$UserYPUID+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11444":"'+$UserYPUID+'",
            "customfield_11902":"'+$WorkLocation+'",
            "customfield_11903":"'+$Division+'",
            "customfield_11904":"'+$Company+'",
            "customfield_11427":"'+$FirstName+'",
            "customfield_11432":"'+$LastName+'",
            "customfield_11445":"'+$Cube+'",
            "customfield_11443":"'+$DeskPhone+'",
            "description":"'+$Description+'",
            "customfield_11800":"'+$OfficeCode+'"
            }
    }'

    $RestApiUri = $JiraEnduser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Disable-MobileDevice {
    <#
    .Synopsis
    Creates a JiraEndUser MDR ticket to disable and deprovision mobile phones.
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [string]$Reason,
       [Parameter(Mandatory=$True)]
       [Validateset("iPhone", "Android Phone", "iPad", "Laptop SIM")]
       [string]$Device,
       [string]$UserYPUID,
       [string]$ManagerYPUID,
       [string]$WorkLocation,
       [string]$Division,
       [string]$Company,
       [string]$MobileNumber
    )
    $body='{
        "fields":{
            "project":{"key":"MDR"},
            "issuetype":{"name":"Disable Mobile Device"},
            "summary":"'+$Summary+'",
            "customfield_10719":"'+$Reason+'",
            "customfield_10721":{"value":"'+$Device+'"},
            "customfield_11444":"'+$UserYPUID+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11902":"'+$WorkLocation+'",
            "customfield_11903":"'+$Division+'",
            "customfield_11904":"'+$Company+'",
            "customfield_10717":"'+$MobileNumber+'"
            }
    }'

    $RestApiUri = $JiraEnduser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Remove-HardwareSR {
    <#
    .Synopsis
    Creates a Service Request ticket to pickup hardware.
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [string]$Description,
       [Parameter(Mandatory=$True)]
       [string]$Cube,
       [Parameter(Mandatory=$True)]
       [string]$MachineName,
       [Parameter(Mandatory=$True)]
       [string]$ContactName,
       [Parameter(Mandatory=$True)]
       [string]$PCSerial,
       [Parameter(Mandatory=$True)]
       [string]$Justification,
       [Parameter(Mandatory=$True)]
       [decimal]$NumberOfUsers,
       [string]$UserYPUID,
       [string]$ManagerYPUID,
       [string]$WorkLocation,
       [string]$Division,
       [string]$Company
    )
    $body='{
        "fields":{
            "project":{"key":"SR"},
            "issuetype":{"name":"Remove Hardware"},
            "summary":"'+$Summary+'",
            "description":"'+$Description+'",
            "customfield_11325":"'+$Cube+'",
            "customfield_11323":"'+$MachineName+'",
            "customfield_11326":{"name":"'+$ContactName+'"},
            "customfield_11324":"'+$PCSerial+'",
            "customfield_11312":"'+$Justification+'",
            "customfield_11444":"'+$UserYPUID+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11902":"'+$WorkLocation+'",
            "customfield_11903":"'+$Division+'",
            "customfield_11904":"'+$Company+'",
            "customfield_11322":'+$NumberOfUsers+'
            }
    }'

    $RestApiUri = $JiraEnduser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Disable-WindowsVMs {
    <#
    .Synopsis
    Creates a Service Request ticket to disable Windows VMs if AMDOCS or TCS.
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Description,
       [Parameter(Mandatory=$True)]
       [string]$ContactName,
       [Parameter(Mandatory=$True)]
       [string]$Justification
    )
    $body='{
        "fields":{
            "project":{"key":"SR"},
            "issuetype":{"name":"Other - Employee Separation"},
            "summary":"Employee Separation - Windows VMs",
            "assignee":{"name":"HDVMDSSUPP"},
            "description":"'+$Description+'",
            "customfield_11325":"N/A",
            "customfield_11323":"N/A",
            "customfield_11326":{"name":"'+$ContactName+'"},
            "customfield_11324":"N/A",
            "customfield_11312":"'+$Justification+'",
            "customfield_11322":1
            }
    }'

    $RestApiUri = $JiraEnduser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Disable-UnixAccount (){
    <#
    .Synopsis
	Submit TWR to disable Unix account and related accesses.
    #>
    Param(
       [string]$Description,
       [Parameter(Mandatory=$True)]
       [string]$Summary
    )
    $body='{
        "fields":{
            "project":{"key":"TWR"},
            "description":"'+$Description+'",
            "summary":"'+$Summary+'",
            "issuetype":{"name":"Work Request"},
            "components":[{"name":"Unix/Linux"}]
            }
    }'
    
    $RestApiUri = $OpsJira + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Deactivate-CorporateCard {
    <#
    .Synopsis
    This function generates a jiraenduser CCCA Account Separation ticket to cancel a corporate card.
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [string]$UserYPUID,
       [Parameter(Mandatory=$True)]
       [string]$ManagerYPUID,
       [Parameter(Mandatory=$True)]
       [string]$FirstName,
       [Parameter(Mandatory=$True)]
       [string]$LastName
    )

    $body='{
        "fields":{
            "project":{"key":"CCCA"},
            "issuetype":{"name":"Account Separation"},
            "customfield_11375":{"value":"ASAP!"},
            "summary":"'+$Summary+'",
            "customfield_11444":"'+$UserYPUID+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11427":"'+$FirstName+'",
            "customfield_11432":"'+$LastName+'"
            }
    }'

    $RestApiUri = $JiraEndUser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Remove-OFAaccess {
    <#
    .Synopsis
    This function creates a FA jira ticket requesting that OFA access be removed for the user
    #>
    Param(
       [string]$Description,
       [Parameter(Mandatory=$True)]
       [string]$Summary
    )

    $body='{
        "fields":{
            "project":{"key":"FA"},
            "description":"'+$Description+'",
            "summary":"'+$Summary+'",
            "issuetype":{"name":"Change Request"},
            "components":[{"name":"Permissions/Security"}]
            }
    }'   

    $RestApiUri = $Jira + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Deactivate-BYOD {
    <#
    .Synopsis
    This function creates a BYOD jira ticket requesting that the user be unenrolled in the BYOD program.
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [string]$Description,
       [string]$UserYPUID,
       [string]$ManagerYPUID,
       [string]$WorkLocation,
       [string]$Division,
       [string]$Company
    )

    $body='{
        "fields":{
            "project":{"key":"BYOD"},
            "description":"'+$Description+'",
            "summary":"'+$Summary+'",
            "customfield_11444":"'+$UserYPUID+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11902":"'+$WorkLocation+'",
            "customfield_11903":"'+$Division+'",
            "customfield_11904":"'+$Company+'",
            "issuetype":{"name":"Leave program"}
            }
    }'

    $RestApiUri = $JiraEndUser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Create-SROB {
        <#
    .Synopsis
    This function creates a Sales Rep Offboarding jira ticket.
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$Summary,
       [Parameter(Mandatory=$True)]
       [string]$FirstName,
       [Parameter(Mandatory=$True)]
       [string]$LastName,
       [Parameter(Mandatory=$True)]
       [string]$Manager,
       [Parameter(Mandatory=$True)]
       [string]$YPUID,
       [string]$ManagerYPUID,
       [string]$WorkLocation,
       [string]$Division,
       [string]$Company
    )

    $body='{
        "fields":{
            "project":{"key":"SROB"},
            "summary":"'+$Summary+'",
            "issuetype":{"name":"Off Boarding"},
            "customfield_11427":"'+$FirstName+'",
            "customfield_11432":"'+$LastName+'",
            "customfield_11403":"'+$ManagerYPUID+'",
            "customfield_11902":"'+$WorkLocation+'",
            "customfield_11903":"'+$Division+'",
            "customfield_11904":"'+$Company+'",
            "customfield_11484":{"name":"'+$Manager+'"},
            "customfield_11444":"'+$YPUID+'"
            }
    }'

    $RestApiUri = $JiraEndUser + "issue/"
    $Credentials = Get-JiraSecureValue
    $Response=Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method post -Body $body
    return $Response
}

function Get-JiraUser {
        <#
    .Synopsis
    This function queries a Jira instance for a user
    #>
    Param(
       [Parameter(Mandatory=$True)]
       [string]$AccountName,
       [Parameter(Mandatory=$True)]
       [ValidateSet("jiraenduser","opsjira","jira")]
       [string]$JiraInstance
    )

    $Uri = "http://"+$JiraInstance+".yp.com/rest/api/latest/"
    $RestApiUri = $Uri + "user?username=" + $AccountName
    $Credentials = Get-JiraSecureValue
    $Response=(Invoke-WebRequest -TimeoutSec 90 -Headers @{"Authorization"="Basic $Credentials"} -ContentType application/json -uri $RestApiUri -Method get).content|ConvertFrom-Json
    return $Response
}

function Deprovision-User {
    <#
    .Synopsis
	This function calls all of the other functions to deprovision the user.
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [string]$EmployeeID
    )

    #Getting all user properties and built variables.
    $SepUser=get-aduser -Filter {EmployeeID -eq $EmployeeID} -SearchBase "OU=People,DC=corp,DC=yp,DC=com" -Properties *
    $SepUserManager=get-aduser $SepUser.manager -Properties EmployeeID,GivenName,SurName
    $SepUserAssets=Get-HPAMAssets $SepUser.EmployeeID
    $SepUserOffice=$SepUser.extensionattribute1 +" (" + $SepUser.StreetAddress + ", " + $SepUser.City + ", " + $SepUser.State +")"
    $Summary="Account Separation from IT (automatic ticket)"
    $MasterSummary="Separating User - Master Ticket - " + $SepUser.DisplayName
    #$MDRSummary="ACCT SEP- " + $SepUser.DisplayName + " - " + $SepUser.EmployeeID + " (separation ticket from IT)"
    $Justification="Separating User - Equipment Retrieval - " + $SepUser.GivenName + " " + $SepUser.Surname
    $AccessRemovalSummary="Separating User - Data Warehouse & Business Objects - " + $SepUser.GivenName + " " + $SepUser.Surname
    $WinVMJustification="Separating User - Disable Windows VM - " + $SepUser.GivenName + " " + $SepUser.Surname
    $Description='First Name= '+$SepUser.GivenName+'\nLast Name= '+$SepUser.Surname+'\nSeparating User YPUID= '+$SepUser.EmployeeID+'\nWork Location= '+$SepUserOffice+'\nManager YPUID= '+$SepUserManager.EmployeeID+'\nOffice.Floor.Cube= '+$SepUser.ExtensionAttribute2+'\nDivision= '+$SepUser.division
    $UnixDescription='Separating User= '+$SepUser.DisplayName+'\nSeparating User UID= '+$SepUser.uidNumber+'\nDate Requested= '+$YearMonthDay+'\nTime Requested=ASAP!'
    $UnixSummary="Account Deactivation - "+$SepUser.displayname+" (separation ticket from IT)"
    $CiscoCMSummary="Offboarding "+$SepUser.extensionattribute7+" "+$SepUser.DisplayName+" "+$SepUser.EmployeeID+" (separation ticket from IT)"
    $CiscoCMDescription='First Name= '+$SepUser.GivenName+'\nLast Name= '+$SepUser.Surname+'\nSeparating User YPUID= '+$SepUser.EmployeeID+'\nWork Location= '+$SepUserOffice+'\nManager YPUID= '+$SepUserManager.EmployeeID+'\nDivision= '+$SepUser.division
    $CCSummary='Account Deactivation - '+$SepUser.displayname+' - '+$SepUser.EmployeeID+' - '+$YearMonthDay
    $OFADescription='The following Oracle Users have been Termed and Oracle Access should be End Dated. \n\nUID : '+$SepUser.EmployeeID+'\nCompany: '+$Sepuser.Company+'\nTerm Date: '+$YearMonthDay+'\nLast Name: '+$Sepuser.Surname+'\nFirst Name: '+$Sepuser.GivenName+'\nE-Mail: '+$Sepuser.mail+'\nCity: '+$Sepuser.City+'\nState: '+$Sepuser.st+'\nSupervisor YPUID: '+$SepUserManager.EmployeeID+'\nSupervisor Last Name: '+$SepUserManager.Surname+'\nSupervisor First Name: '+$SepUserManager.GivenName+'\n'
    $BYODSummary=$SepUser.EmployeeID+' separated'
    $ReclaimSummary='Separating User - Reclaim Licenses - '+$SepUser.Displayname

    #Validate Manager to be Reporter for all Jira instances
    $EndUserReporter=Get-JiraUser -AccountName $SepUserManager.SamAccountName -JiraInstance jiraenduser
    $OpsJiraReporter=Get-JiraUser -AccountName $SepUserManager.SamAccountName -JiraInstance opsjira
    $JiraReporter=Get-JiraUser -AccountName $SepUserManager.SamAccountName -JiraInstance jira

    if ($EndUserReporter.active -eq "True" -and $EndUserReporter.name -eq $SepUserManager.SamAccountName){
        $EUReport = $EndUserReporter.name}
    else { $EUReport = "corpinf" }
    if ($OpsJiraReporter.name -eq $SepUserManager.SamAccountName -and $OpsJiraReporter.active -eq "True"){
        $OJReport = $OpsJiraReporter.name}
    else { $OJReport = "corpinf" }
    if ($JiraReporter.name -eq $SepUserManager.SamAccountName -and $OpsJiraReporter.active -eq "True"){
        $JiraReport = $JiraReporter.name}
    else { $JiraReport = "corpinf" }

    #Alter Hardware Pickup ticket summary for accounts on legal hold
    $JustificationHW=$Justification
    if ($SepUser.msexchlitigationholdDate -notlike $null) {
        $JustificationHW=$Justification+" - LEGAL HOLD"
    }

    #Perform these tasks if user is in the Revenue Division
    #-Create SROB ticket
    #-Change CiscoCMDescription
    if ($SepUser.division -eq "Revenue" -or $SepUser.division -eq "Sales") {
        $CreateSROB=Create-SROB -Summary $Summary -FirstName $SepUser.GivenName -LastName $SepUser.SurName -Manager $SepUserManager.SamAccountName -YPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company
        $CiscoCMDescription=$CiscoCMDescription+"\n-ENSURE SIMULTANEOUS RING IS DISABLED\n-ENABLE GENERIC SALES IVR\n-FORWARD THE PHONE EXTENSION"
    }


    #Setting required attributes to `"N/A`" if null.
    if ($SepUser.mobilephone -eq $null) {
        $SepUser.mobilephone="N/A"
    }
    If ($SepUser.extensionAttribute2 -eq $null) {
        $SepUser.extensionAttribute2="N/A"
    }
    if ($SepUserManager.EmployeeID -eq $null) {
        $SepUserManager.EmployeeID="N/A"
    }

    #Create the JIRA tickets by calling the functions
    #$MasterTicket=Create-SeparationTicket -Summary $Summary -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -FirstName $SepUser.GivenName -LastName $SepUser.SurName -OfficeCode $SepUserOffice -Description $Description
    $MasterTicket=Create-ITRequest -FirstName $SepUser.GivenName -LastName $SepUser.Surname -Reporter $EUReport -Assignee EnterpriseSystemsSupport -Description $Description -Summary $MasterSummary -IssueType 'IT - User Boarding Request' -RequestType 'it/user-offboarding---master-ticket' -Priority Standard -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -Cube $sepUser.extensionAttribute2
    #$MDRTicket=Disable-MobileDevice -Summary $MDRSummary -Reason "Employee Separation" -Device iPhone -MobileNumber $SepUser.mobilephone -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company
    
    #Create Hardware Removal Ticket if user has assets in HPAM
    if ($SepUserAssets) {
        $StringAssets=$SepUserAssets | Sort Status -Descending | ft -AutoSize | Out-String
        $FormattedAssets=$StringAssets -replace "`n","\n" -replace "`r","\r"
        $AssetDescription=$Description+"\nAssigned Assets:\n"+$FormattedAssets
        #$RemoveHardwareTicket=Remove-HardwareSR -Summary $Justification -Description $AssetDescription -MachineName "N/A" -PCSerial "N/A" -Cube $sepUser.extensionAttribute2 -ContactName $SepUserManager.SamAccountName -Justification $Justification -NumberOfUsers 1 -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company
        $RemoveHardwareTicket=Create-ITRequest -FirstName $SepUser.GivenName -LastName $SepUser.Surname -Reporter $EUReport -Assignee assetmanagement -Description $AssetDescription -Summary $JustificationHW -IssueType 'IT - User Boarding Request' -RequestType 'it/user-offboarding---equipment-retrieval2' -Priority Standard -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -Cube $sepUser.extensionAttribute2

    }
    else {
        $AssetDescription=$Description+"\nAssigned Assets:\nNo assets found in HPAM."
        #$RemoveHardwareTicket=Remove-HardwareSR -Summary $Justification -Description $AssetDescription -MachineName "N/A" -PCSerial "N/A" -Cube $sepUser.extensionAttribute2 -ContactName $SepUserManager.SamAccountName -Justification $Justification -NumberOfUsers 1 -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company
        $RemoveHardwareTicket=Create-ITRequest -FirstName $SepUser.GivenName -LastName $SepUser.Surname -Reporter $EUReport -Assignee assetmanagement -Description $AssetDescription -Summary $JustificationHW -IssueType 'IT - User Boarding Request' -RequestType 'it/user-offboarding---equipment-retrieval2' -Priority Standard -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -Cube $sepUser.extensionAttribute2
    }

    #Create Reclaim Licenses Ticket
    $ReclaimLicTicket=Create-ITRequest -FirstName $SepUser.GivenName -LastName $SepUser.Surname -Reporter $EUReport -Assignee assetmanagement -Description $AssetDescription -Summary $ReclaimSummary -IssueType 'IT - User Boarding Request' -RequestType 'it/user-offboarding---reclaim-licenses' -Priority Standard -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -Cube $sepUser.extensionAttribute2

    #Create Remove Access Ticket
    $RemoveAccessTicket=Create-ITRequest -FirstName $SepUser.GivenName -LastName $SepUser.Surname -Reporter $EUReport -Assignee datawarehousesupp -Description $Description -Summary $AccessRemovalSummary -IssueType 'IT - User Boarding Request' -Priority Standard -RequestType 'it/user-offboarding---remove-access2' -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -Cube $sepUser.extensionAttribute2

    #Create a Disable Windows VM Ticket if the user is an AMDOCS or TATACONS contractor
    if ($SepUser.Company -eq "AMDOCS" -or $SepUser.Company -eq "TATACONS"){
        #$DisableWinVMTicket=Disable-WindowsVMs -Description $Description -ContactName $SepUserManager.EmployeeID -Justification $WinVMJustification
        $DisableWinVMTicket=Create-ITRequest -Reporter $EUReport -Assignee hdvmdssupp -Description $Description -Summary $WinVMJustification -IssueType 'IT - User Boarding Request' -RequestType 'it/user-offboarding---windows-vm2' -Priority Standard -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -Cube $sepUser.extensionAttribute2
    }
    
    #Create a Disable Unix Account ticket if a user has a UnixID.
    if ($SepUser.uidNumber -notlike $null -and $SepUser.uidNumber -ne "0") {
        $DisableUnixAccountTicket=Disable-UnixAccount -Description $UnixDescription -Summary $UnixSummary
    }

    #Create a Disable CM Phone ticket if a user has a deskPhone. Enter in a fake number of 999-999-9999 if not.
    if ($SepUser.officephone -notlike $null -and $SepUser.officephone -ne "999-999-9999") {
        $DisableCMPhone=Disable-CiscoCMPhone -Summary $CiscoCMSummary -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -FirstName $SepUser.GivenName -LastName $SepUser.SurName -OfficeCode $SepUserOffice -DeskPhone $SepUser.officephone -Cube $SepUser.extensionattribute2 -Description $CiscoCMDescription
    }
    else {
        $DisableCMPhone=Disable-CiscoCMPhone -Summary $CiscoCMSummary -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company -FirstName $SepUser.GivenName -LastName $SepUser.SurName -OfficeCode $SepUserOffice -DeskPhone "999-999-9999" -Cube $SepUser.extensionattribute2 -Description $CiscoCMDescription
    }

    #Create a Deactivate Corporate Credit Card ticket if a user is an Employee.
    if ($SepUser.extensionAttribute7 -eq "Employee"){
        $DeactivateCC=Deactivate-CorporateCard -Summary $CCSummary -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -FirstName $SepUser.GivenName -LastName $SepUser.Surname
    }

    #Create a Deactivate BYOD ticket if a user is a member of the BYOD_Enrolled group
    #if ($SepUser.memberof -match "BYOD_Enrolled"){
    #    $DeactivateBYOD=Deactivate-BYOD -Summary $BYODSummary -Description $BYODSummary -UserYPUID $SepUser.EmployeeID -ManagerYPUID $SepUserManager.EmployeeID -WorkLocation $SepUserOffice -Division $SepUser.Division -Company $SepUser.Company
    #}

    #Gather information required to link tickets to the master ticket.
    $SourceTicket=$MasterTicket.Content|ConvertFrom-Json
    #$MDRLinkTicket=$MDRTicket.Content|ConvertFrom-Json
    $RemoveHardwareLinkTicket=$RemoveHardwareTicket.Content|ConvertFrom-Json
    $RemoveAccessLinkTicket=$RemoveAccessTicket.Content|ConvertFrom-Json
    $DisableWinVMLinkTicket=$DisableWinVMTicket.Content|ConvertFrom-Json
    $DisableUnixAccountLinkTicket=$DisableUnixAccountTicket.Content|ConvertFrom-Json
    $DisableCMPhoneLinkTicket=$DisableCMPhone.Content|ConvertFrom-Json
    $DeactivateCCLinkTicket=$DeactivateCC.Content|ConvertFrom-Json
    #$DeactivateBYODTicket=$DeactivateBYOD.Content|ConvertFrom-Json
    $CreateSROBTicket=$CreateSROB.Content|ConvertFrom-Json
    $ReclaimLicLinkTicket=$ReclaimLicTicket.Content|ConvertFrom-Json

    #Create the links to the master ticket.
    #Add-LocalLink -InwardIssue $SourceTicket.key -OutwardIssue $MDRLinkTicket.key -Type Relates
    Add-LocalLink -InwardIssue $SourceTicket.key -OutwardIssue $RemoveHardwareLinkTicket.key -Type Relates
    Add-LocalLink -InwardIssue $SourceTicket.key -OutwardIssue $RemoveAccessLinkTicket.key -Type Relates
    Add-LocalLink -InwardIssue $SourceTicket.key -OutwardIssue $DisableWinVMLinkTicket.key -Type Relates
    Add-LocalLink -InwardIssue $sourceTicket.key -OutwardIssue $DisableCMPhoneLinkTicket.key -Type Relates
    Add-LocalLink -InwardIssue $sourceTicket.key -OutwardIssue $DeactivateCCLinkTicket.key -Type Relates
    Add-LocalLink -InwardIssue $SourceTicket.key -OutwardIssue $DeactivateBYODTicket.key -Type Relates
    Add-LocalLink -InwardIssue $SourceTicket.key -OutwardIssue $CreateSROBTicket.key -Type Relates
    Add-LocalLink -InwardIssue $SourceTicket.key -OutwardIssue $ReclaimLicLinkTicket.key -Type Relates
    Add-RemoteLink -SourceTicket $SourceTicket.key -LinkTicket $DisableUnixAccountLinkTicket.key -SourceInstance jiraenduser -LinkInstance opsjira -SourceIssueID $SourceTicket.id -LinkIssueID $DisableUnixAccountLinkTicket.id
  
}