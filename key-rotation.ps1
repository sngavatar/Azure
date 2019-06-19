function Rotate-ServicePrincipalCred {
	Param (
		[string ][parameter(Mandatory=$true)] $servicePrincipalName,
		[string] [Parameter(Mandatory=$True)] $certName,
		[string] [Parameter(Mandatory=$True)] $keyVaultName
	)
	$sp = Get-AzADServicePrincipal -DisplayName $servicePrincipalName

	$policy = Get-AzKeyVaultCertificatePolicy -VaultName $keyVaultName -Name $certName

	if ($policy) {
		Write-Host "Creating Key Vault Self-Signed Certificate policy valid for 12 Months" -ForegroundColor Magenta
		$policy = New-AzKeyVaultCertificatePolicy -SubjectName "CN=${servicePrincipalName}.uksouth.cloudapp.azure.com" -IssuerName Self -ValidityInMonths 12
	}
	Else {	
		Write-Host "No existing policy present aborting."
		return
	}

	$azureKeyVaultCert = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certName
	if ($azureKeyVaultCert){
                Write-Host "Creating Key Vault Self-Signed Certificate valid for 12 Months" -ForegroundColor Magenta
                Add-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certName -CertificatePolicy $policy                
	}
	Else {
		Write-Host "No existing certificate present aborting."
                return
	}

	while (($null -eq $azureKeyVaultCert) -or ($null -eq $azureKeyVaultCert.Certificate)) {
                sleep 5
                $azureKeyVaultCert = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certName
        }

	Write-Host "Updating Service Principal Credential with Certificate from Key Vault" -ForegroundColor Magenta
	New-AzADSpCredential -CertValue $([System.Convert]::ToBase64String($azureKeyVaultCert.Certificate.GetRawCertData())) -ObjectId $sp.Id -EndDate $azureKeyVaultCert.Certificate.NotAfter

	$passwordCheck = $(Get-AzADSpCredential -ObjectId $sp.Id | ?{$_.Type -eq 'Password'}).KeyId
        if ($PasswordCheck) {
                Write-Host "Removing Password Auth" -ForegroundColor Magenta
                Remove-AzADSpCredential -ObjectId $sp.Id -KeyId $passwordCheck -Force
        }

	Write-Host "Service principal certificate and credential successfully updated"
	
}

Rotate-ServicePrincipalCred $Env:servicePrincipalName $Env:certName $Env:keyVaultName
