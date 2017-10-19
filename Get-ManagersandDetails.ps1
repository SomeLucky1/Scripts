Workflow Get-Managers {
    function Get-ManagerDetails ($managerdetails) {
    function Get-ADDirectReports
{
	[CmdletBinding()]
	PARAM (
		[Parameter(Mandatory)]
		[String[]]$Identity,
		[Switch]$Recurse
	)
	PROCESS
	{
		foreach ($Account in $Identity)
		{
			TRY
			{
				IF ($PSBoundParameters['Recurse'])
				{
					# Get the DirectReports
					Write-Verbose -Message "[PROCESS] Account: $Account (Recursive)"
					Get-Aduser -identity $Account -Properties directreports |
					ForEach-Object -Process {
						$_.directreports | ForEach-Object -Process {
							# Output the current object with the properties Name, SamAccountName, Mail and Manager
							Get-ADUser -Identity $PSItem -Properties mail, manager | Select-Object -Property Name, SamAccountName, Mail, @{ Name = "Manager"; Expression = { (Get-Aduser -identity $psitem.manager).samaccountname } }
							# Gather DirectReports under the current object and so on...
							Get-ADDirectReports -Identity $PSItem -Recurse
						}
					}
				}#IF($PSBoundParameters['Recurse'])
				IF (-not ($PSBoundParameters['Recurse']))
				{
					Write-Verbose -Message "[PROCESS] Account: $Account"
					# Get the DirectReports
					Get-Aduser -identity $Account -Properties directreports | Select-Object -ExpandProperty directReports |
					Get-ADUser -Properties mail, manager | Select-Object -Property Name, SamAccountName, Mail, @{ Name = "Manager"; Expression = { (Get-Aduser -identity $psitem.manager).samaccountname } }
				}#IF (-not($PSBoundParameters['Recurse']))
			}#TRY
			CATCH
			{
				Write-Verbose -Message "[PROCESS] Something wrong happened"
				Write-Verbose -Message $Error[0].Exception.Message
			}
		}
	}
}
    $CEO=""
            function Get-Manager {
        Param(
            $SamAccountName
        )
        $manager=Get-ADUser (Get-ADUser $SamAccountName -Properties manager).manager -Properties extensionattribute10
        return $manager
    }
    
    function Get-JobDepth {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
            $SamAccountName
        )
        Process {
            $count=1
            DO {
                try{
                    $Manager=Get-Manager $SamAccountName
                    $AccountName=$Manager.samaccountname
                    If ($AccountName -ne $CEO ) {
                        $SamAccountName = $Manager.SamAccountName
                        $count++
                    }
                }
                catch{return}
            } While ($AccountName -ne $CEO)
            Return $count
        }
    }
        $depth=Get-JobDepth $managerdetails.samaccountname
        $count=(Get-ADDirectReports $managerdetails.samaccountname -Recurse).count
        $managerdetails | Add-Member -MemberType NoteProperty -Name JobDepth -Value $depth -TypeName JobDepth
        $managerdetails | Add-Member -MemberType NoteProperty -Name Count -Value $count -TypeName Count
        return $managerdetails
    }
    
    $manager=$null
    $managerdetails=$null
    $managers=get-aduser -Filter * -SearchBase "OU=People,DC=corp,DC=yp,DC=com" -Properties directreports,displayname,extensionattribute9,extensionattribute6,extensionattribute7,extensionattribute10,canonicalname,manager,Division,title,department,streetaddress,city,state,EmployeeID | Where-Object {$_.directreports -notlike $null -and $_.EmployeeID -ne ""}
    foreach -parallel ($manager in $managers){
        Get-ManagerDetails $manager
    }
}

Get-Managers | Select-Object JobDepth,Count,CanonicalName,directreports,DisplayName,Enabled,extensionattribute10,extensionattribute6,extensionattribute7,extensionattribute9,Manager,Name,SamAccountName,Division,title,department,streetaddress,city,state | Export-CSV -NoTypeInformation allmanagers.csv