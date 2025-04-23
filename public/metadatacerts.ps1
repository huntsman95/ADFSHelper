class ADFSCertObject {
    [string]$CertType
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertData
    ADFSCertObject([string]$CertType, [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertData) {
        $this.CertType = $CertType
        $this.CertData = $CertData
    }
}

function Save-ADFSMetadataCert {
    [CmdletBinding()]
    param (
        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [ADFSCertObject[]]
        $ADFSCert
        ,
        [Parameter()]
        [ValidateScript({ Test-Path $_ })]
        [string]
        $Path

    )

    process {
        $_data = $ADFSCert.CertData.Export(1)
        $_filename = "$($ADFSCert.CertType)$($ADFSCert.CertData.NotAfter.ToString('_exp-MM_dd_yyyy')).cer"
        $_exportPath = Join-Path -Path $path -ChildPath $_filename
        [System.IO.File]::WriteAllBytes($_exportPath, $_data)
    }
}


function Get-ADFSCertsFromMetadataURL {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]
        $MetadataURL
        ,
        [Parameter()]
        [switch]
        $ExportCertsHere
    )

    $Metadata = Invoke-RestMethod -Uri $MetadataURL

    $_SigningCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Text.Encoding]::ASCII.GetBytes($metadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor.where({ $_.use -eq 'signing' }).KeyInfo.X509Data.X509Certificate))
    $_EncryptionCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Text.Encoding]::ASCII.GetBytes($metadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor.where({ $_.use -eq 'encryption' }).KeyInfo.X509Data.X509Certificate))

    $certs = @()
    $certs += [ADFSCertObject]::new('Signing', $_SigningCert)
    $certs += [ADFSCertObject]::new('Encryption', $_EncryptionCert)

    if ($ExportCertsHere) {
        $certs | Save-ADFSMetadataCert -Path ((Get-Location).Path)
    }
    else {
        return $certs
    }

}

function ConvertTo-ADFSBase64CertData {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [ADFSCertObject[]]
        $ADFSCert
        ,
        [Parameter()]
        [switch]
        $ASCIIArmor
        ,
        [Parameter()]
        [string]
        [ValidateSet('Signing', 'Encryption', 'All')]
        $CertType = 'All'
    )
    process {
        switch ($CertType) {
            'Signing' {
                if($ADFSCert.CertType -ne 'Signing') {return}
            }
            'Encryption' {
                if ($ADFSCert.CertType -ne 'Encryption') { return }
            }
        }
        $cert = $ADFSCert.CertData
        if ($ASCIIArmor.IsPresent) {
            $certBase64 = $cert.ExportCertificatePem()
        }
        else {
            $certBase64 = [System.Convert]::ToBase64String($cert.RawData)
        }
        $template = "{0}`r`n{1}`r`n`r`n{2}" -f $ADFSCert.CertType, $cert.Subject, $certBase64
        return $template
    }
}