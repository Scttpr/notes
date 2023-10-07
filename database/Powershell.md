- **URL :** https://learn.microsoft.com/fr-fr/powershell/
- **Description :** PowerShell est un interpréteur de commandes moderne qui comprend les meilleures fonctionnalités d'autres interpréteurs de commandes populaires.
- **Platforms :** [[Windows]]
- **Category :** [[Tools]] 
- **Tags :**
## Snippets

- Query entire domain looking for specific search terms/strings in the `Description` or `Info` fields:

```powershell
Function SearchUserClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}```

## Tools

- Renew `krbtgt` password : https://github.com/microsoft/New-KrbtgtKeys.ps1