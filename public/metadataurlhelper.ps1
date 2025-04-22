function Get-ADFSMetadataURL {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $FQDN
    )
    $url = "https://$FQDN/FederationMetadata/2007-06/FederationMetadata.xml"
    return [PSCustomObject]@{
        MetadataURL = $url
    }
}