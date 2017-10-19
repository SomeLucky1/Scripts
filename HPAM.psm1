Import-Module Vault

$Assembly = [System.Reflection.Assembly]::LoadWithPartialName("System.Data.OracleClient")
$CID="PAMC"
$Server="10.125.50.132"
$VaultGroup="HPAM DB"
$ValueName="AMCADMIN"
$VaultCredentials=Get-Content c:\Utils-Sa\scripts\vault_creds.txt

function Get-HPAMAssets {
    <#
    .Synopsis
    Gets the In Use - Assigned assets in HPAM for the supplied YPUID.
    #>
    Param(
        $YPUID
    )

$DBPass=Get-SecureValue -VaultGroup $VaultGroup -ValueName $ValueName -VaultCredentials $VaultCredentials
$OracleConnectionString = "Data Source=(DESCRIPTION=(CID=$CID)(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=$Server)(PORT=1521)))(CONNECT_DATA=(SID=$CID)(SERVER=DEDICATED)));uid=$ValueName;pwd=$DBPass"
$OracleConnection = New-Object System.Data.OracleClient.OracleConnection($OracleConnectionString);
#$QueryString="SELECT A.SERIALNO, A.DOXCSRNO, A.DESCRIPTION, A.STATUS, E.IDNO, A.ASSETTAG FROM amasset A, amportfolio P, amempldept E WHERE A.SERIALNO = P.DOXSERIALNO and E.LEMPLDEPTID = P.LUSERID and A.STATUS = 'In Use - Assigned' and E.IDNO in ('"+$YPUID.toupper()+"')"
$QueryString="SELECT A.SERIALNO, A.DOXCSRNO, A.DESCRIPTION, A.STATUS, E.IDNO, A.ASSETTAG FROM amasset A, amportfolio P, amempldept E WHERE A.SERIALNO = P.DOXSERIALNO and E.LEMPLDEPTID = P.LUSERID  and A.STATUS IN ( 'In Use - Assigned' ,'In Use - Legal Hold') and E.IDNO in ('"+$YPUID.toupper()+"')"
$command = New-Object System.Data.OracleClient.OracleCommand($QueryString, $OracleConnection)
$OracleConnection.Open()
$Result = $command.ExecuteReader()
$table=@()

while ($Result.Read()) {
    $table += [pscustomobject]@{
        Status=$Result.GetString(3)
        Serial=$Result.GetString(0)  
        #SRNum=$Result.GetString(1)
        Description=$Result.GetString(2)
    }
}

$OracleConnection.Close()

Return $table
}