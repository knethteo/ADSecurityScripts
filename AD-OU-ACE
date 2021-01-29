##This script was originally published here: https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989

$schemaIDGUID = @{}

$ErrorActionPreference = 'SilentlyContinue'

Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |

ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}

Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |

ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}

$ErrorActionPreference = 'Continue'

# Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).

$OUs  = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName

$OUs += Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName

# Loop through each of the OUs and retrieve their permissions.

# Add report columns to contain the OU path and string names of the ObjectTypes.

ForEach ($OU in $OUs) {

   # This array will hold the report output.

   $report = @()

   $report += Get-Acl -Path "AD:$OU" |

    Select-Object -ExpandProperty Access |

    Select-Object @{name='organizationalUnit';expression={$OU}}, `

                  @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `

                  @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, `

                  *

   # Dump the raw report out to a CSV file for analysis in Excel.

   $report | Export-Csv ".$OU.csv" -NoTypeInformation

}
