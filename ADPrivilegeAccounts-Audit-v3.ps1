###########################################################################
#
# NAME: Ad account auditing
#
# AUTHOR:  Arun Sabale
#
# COMMENT: 
#
# VERSION HISTORY:
# 1.0  - Initial release
#
###########################################################################
#https://gallery.technet.microsoft.com/scriptcenter/AD-account-Audit-find-bfcc60db

[CmdletBinding(DefaultParametersetName="CurrentForest")] 
param
(	
	[Parameter(ParameterSetName="Domain",Mandatory=$true)]
	[String] $Domain
		
					
)
$date = Get-Date -Format yyyy/MM/dd
$date1 = Get-Date -Format ddMMyyyy
#ipmo activedirectory
$outfile = @()
[int] $InactiveDays = 180

$hpa=0
$npa=0
$lpa=0
$sa=0
	
	# Connect to the specified domain if domain parameter used
	if ($Domain)
	{
		$DomainContext = new-object System.directoryServices.ActiveDirectory.DirectoryContext("Domain",$Domain)
		$ObjDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
		$PDCEmulators += $ObjDomain.PDCRoleOwner
	}
	elseif($PsCmdlet.ParameterSetName -match "CurrentForest")
	{
	$domain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
	}
	
	






Function Get-NETBiosName ( $dn, $ConfigurationNC )
{
	try
	{
		$Searcher = New-Object System.DirectoryServices.DirectorySearcher 
		$Searcher.SearchScope = "subtree" 
		$Searcher.PropertiesToLoad.Add("nETBIOSName")| Out-Null
		$Searcher.SearchRoot = "LDAP://cn=Partitions,$ConfigurationNC"
		$Searcher.Filter = "(nCName=$dn)"
		$NetBIOSName = ($Searcher.FindOne()).Properties.Item("nETBIOSName")
		Return $NetBIOSName
	}
	catch
	{
		Return $null
	}
}
$ADSearcher = New-Object System.DirectoryServices.DirectorySearcher
$ADSearcher.PageSize = 100000
$ADSearcher.Filter = "(&(objectCategory=person)(objectClass=user))"
$UserProperties = @("samaccountname","whenChanged","LastLogontimestamp","CanonicalName","DistinguishedName","MemberOf","Description","mail","whenCreated","isdisabled","lastlogondate","pwdLastSet","GivenName","userAccountControl","accountExpires","ispasswordnotrequired","isPasswordNeverExpires","accountExpirationdate","isCriticalSystemObject","isPreAuthNotRequired")
$ADSearcher.PropertiesToLoad.AddRange(@($UserProperties))

# Connect to the PDC Emulator
				$ObjDeDomain = [ADSI] "LDAP://$($domain)"
				$ADSearcher.SearchRoot = $ObjDeDomain
				
				# Get the domain NETBIOS name
				$DomainNameString = Get-NETBiosName $objDeDomain.distinguishedName $objRootDSE.configurationNamingContext
				
				# Collect user accounts
				$getalluser = $ADSearcher.FindAll()




	
	foreach ($getalluser1 in $getalluser)
	{

$getuser1 = $getalluser1.GetDirectoryEntry()

	[string]$accountExpires = $getuser1.accountExpires
		[string]$accountExpirationdate = $getuser1.accountExpirationdate
	[string]$userAccountControl = $getuser1.userAccountControl
	[string]$GivenName=$getuser1.GivenName
	[string]$samaccountname= $getuser1.samaccountname
	[string]$whenChanged= $getuser1.whenChanged
	[string]$CanonicalName= $getuser1.CanonicalName
	[string]$DistinguishedName= $getuser1.DistinguishedName
	[string]$MemberOf= $getuser1.MemberOf
	[string]$Description= $getuser1.Description
	[string]$mail= $getuser1.mail
	[string]$whenCreated= $getuser1.whenCreated
	
	
	
	if($userAccountControl -band 2 )
{
write-host "$samaccountname account is disabled"
[string]$isdisabled="Yes"
}
else
{
[string]$isdisabled="no"
}
	if($userAccountControl -band 8388608 )
{
[string]$ispasswordexpired="Yes"
}
else
{
[string]$ispasswordexpired="no"
}
	if($userAccountControl -band 16 )
{
[string]$islocked="Yes"
}
else
{
[string]$islocked="no"
}
   If($isdisabled -like "*Yes*" -or $islocked -like "*Yes*" -or $ispasswordexpired -like "*Yes*")
	{
	[string]$IsInactive="Yes"
	}
	else
	{
	[string]$IsInactive="No"
	}
 
 	If($MemberOf -like "*Domain Admin*" -or $MemberOf -like "*Administrators*" -or $MemberOf -like "*Enterprise Admin*" -or $MemberOf -like "*Schema Admin*")
	{
	$accountType = "High Privilege Account"
$hpa+=1
	}
	elseIf($MemberOf -like "*server operator*" -or $MemberOf -like "*backup operator*" )
	{
	$accountType = "Limited Privilege Account"
$lpa+=1
	}
	elseIf($Description -like "Built-in*")
	{
	$accountType = "System Account"
$sa+=1
	}
	else
	{
	$accountType = "Non privileged account"
$npa+=1
	}
	 
	

$object = new-object psobject

$object | add-member -membertype noteproperty -Name "SamAccountName" -Value $samaccountname
$object | add-member -membertype noteproperty -Name "GivenName" -Value $GivenName
$object | add-member -membertype noteproperty -Name "DistinguishedName" -Value $DistinguishedName
$object | add-member -membertype noteproperty -Name "UserAccountControl" -Value $userAccountControl
$object | add-member -membertype noteproperty -Name "Mail" -Value $mail
$object | add-member -membertype noteproperty -Name "WhenCreated" -Value $whenCreated
#$object | add-member -membertype noteproperty -Name "MemberOf" -Value $memberof
$object | add-member -membertype noteproperty -Name "Domain" -Value "$domain"
$object | add-member -membertype noteproperty -Name "Description" -Value $Description
$object | add-member -membertype noteproperty -Name "WhenChanged" -Value $whenChanged
$object | add-member -membertype noteproperty -Name "isdisabled" -Value $isdisabled
$object | add-member -membertype noteproperty -Name "ObjectType" -Value $accountType
$object | add-member -membertype noteproperty -Name "IsInactive" -Value $IsInactive
$object | add-member -membertype noteproperty -Name "IsLocked" -Value $islocked
$object | add-member -membertype noteproperty -Name "IsPasswordExpired" -Value $ispasswordexpired





#$object | add-member -membertype noteproperty -Name "pwdLastSet" -Value $pwdLastSet
$outfile+=$object 


$isPreAuthNotRequired=""
$isCriticalSystemObject=""
$passwordnotrequired = ""
	$PasswordNeverExpires = ""
	$accountExpires = ""
	$accountExpirationdate = ""
    $accountExpires = ""
	$userAccountControl = ""
	$GivenName=""
	$lastlogontimestamp1= ""
	$lastlogontimestamp = ""
	$samaccountname= ""
	$whenChanged= ""
	$CanonicalName= ""
	$DistinguishedName= ""
	$MemberOf= ""
	$Description= ""
	$mail= ""
	$whenCreated= ""
	$isdisabled= ""
	$LastLogon= ""
	$pwdLastSet= ""
	$IsInactive=""
	$accountType=""
$getuser1=""
} 
Write-host "High Privilege Account = $hpa"
Write-host "Limited Privilege Account = $lpa"
Write-host "System Accounts = $SA"
Write-host "Non privileged account = $npa"

$hpa=0
$npa=0
$lpa=0
$sa=0
$outfile |Export-Csv ".\$domain-AdaccountAudit-$date1.csv" -NoTypeInformation
