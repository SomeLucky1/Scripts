#Download IT Headers file and insert it into the staging table.

Import-Module Vault
Import-Module WinSCP
Import-Module C:\utils-sa\scripts\Out-DataTable.ps1

#Variables for downloading 
$password=Get-SecureValue -VaultGroup "HR Feed" -ValueName "HR Feed" -VaultCredentials (Get-Content c:\utils-sa\vault_creds.txt)
$sshhostkeyfingerprint="ssh-rsa 2048 "
$destination="C:\utils-sa\data\rcoithdr.txt"
$source="/rcoithdr.txt"
$server=""
$port=
$username = ""

#Variables for the database
$dataSource = ""
$database = "HR"
$table = "dbo.[Stg_rcoithdr]"
$sp = "dbo.[nsp_LoadHRData]"

try{
    $LocalWriteTime=(Get-Item $destination).LastWriteTime
    Write-Output "Local File Write Time: "$LocalWriteTime
}
catch{
    $LocalWriteTime=$null
}


#Check for the file write time
$RemoteWriteTime=CheckFile-SFTP -ComputerName $server `
                          -UserName $username `
                          -Password $password `
                          -SshHostKeyFingerprint $sshhostkeyfingerprint `
                          -Source $source `
                          -Port $port
Write-Output "Remote File Write Time: "$RemoteWriteTime

#Check if the remote file is newer than the local one. If so, download it and export it to the SQL table.
if (-Not ($RemoteWriteTime -le $LocalWriteTime)) {
    #Download the file
    Download-SFTP -ComputerName $server `
                -UserName $username `
                -Password $password `
                -SshHostKeyFingerprint $sshhostkeyfingerprint `
                -Source $source `
                -Destination $destination `
                -Port $port
    Write-Output "Downloading remove file: "$source
 
    #Create a connection to the SQL table dbo.Stg_rcoithdr in the HR database
    $query= "TRUNCATE TABLE dbo.[Stg_rcoithdr]"
    $exportconnection = New-Object System.Data.SqlClient.SqlConnection
    $exportconnection.ConnectionString = "Server=$dataSource;Database=$database;Integrated Security=True"
    $exportconnection.Open()
    $command = New-Object System.Data.SqlClient.SqlCommand ($query, $exportconnection)
    $command.ExecuteNonQuery()
    Write-Output "Clearing staging table."

    #Bulk copy PStable to sql table -exception: any listing that has a managerID and EmployeeID will have the manager ID Cleared
    $PSTable=Import-Csv $destination -Delimiter "|"
    $PSTable|?{$_.ManagerID -eq $_.EmployeeID}|%{$_.ManagerID = $null}
    $dtable=$PSTable|Out-DataTable
    $exporttable = new-object ("System.Data.SqlClient.SqlBulkCopy") $exportconnection
    $exporttable.DestinationTableName = $table
    $exporttable.WriteToServer($dtable)
    Write-Output "Inserting data into the staging table."

    #Run the stored procedure to move data to production table
    $SqlCommand = $exportconnection.CreateCommand()
    $SqlCommand.CommandText = $sp
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($SqlCommand)
    $dataset = New-Object System.Data.DataSet
    [void]$adapter.Fill($dataset)
    $exportconnection.Close()
    Write-Output "Running stored procedure to move data to production table."
}
else {
    Write-Output "No new file. Exiting."
}