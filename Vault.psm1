function Get-SecureValue (){
    <#
    .Synopsis
    Gets the secure value using supplied group and value name from the Vault.
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultGroup,
        [Parameter(Mandatory=$True)]
        [string]$ValueName,
        [Parameter(Mandatory=$True)]
        [string]$VaultCredentials
    )
    # Vault credentials must be supplied in base64 encoding
    $encodedVaultCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($VaultCredentials))
    #Modifying the header appropriately for Basic Authorization
    $basicAuthValue = "Basic $encodedVaultCredentials"
    $Headers = @{Authorization = $basicAuthValue}
    #Querying Vault for the desired secure value
    $SecureValue=(Invoke-WebRequest -Uri "https://vault.int.yp.com/values/$VaultGroup/$ValueName.txt" -Headers $Headers -UseBasicParsing).Content
    return $SecureValue
}