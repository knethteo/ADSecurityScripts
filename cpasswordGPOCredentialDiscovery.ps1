#Find potential password in cpassword read more here: https://adsecurity.org/?p=2288
#Negative result doesn't mean passwords do not exist in GPO files, it may be in other forms.
param
(	
	[Parameter(ParameterSetName="Domain",Mandatory=$true)]
	[String] $Domain
		
					
)

#Find a deprecated feature in AD GPO
findstr /S /I /c:"cpassword" /c:"password" \\$Domain\sysvol\$Domain\policies\*.xml | Out-File .\GPOPWD.txt 
