#Powershell script to fill out AD user's proxyaddress list with SMTP:<emailaddress> where the email address is pulled from the ad user properties
#For testing please modify the Get-ADUser -Filter * on line 7 to ensure successful execution in the enviorment before running against the entire directory.
#An example for such as modification is as follows Get-ADUser -Filter {sn -like "Engineering"} ... ensure that the account you are testing on have the sn attribute filled in as Engineering.

Import-Module ActiveDirectory

#Pulls all users in Active Directory and the properties (account name, Proxy address list, and email address)
$allusers = Get-ADUser -Filter * -Properties SamAccountName, ProxyAddresses, EmailAddress

$blncompare = $false

#This will chack each user in the AD to see if they have a SMTP entry in proxyaddresses and if they dont to add an entry with SMTP:<their email address>
Foreach ($user in $allusers) 
{
#Checks the proxyaddress entries for an entry that starts with SMTP for error checking.
   Foreach ($entry in $user.ProxyAddresses) {
    If ($entry.StartsWith("SMTP:")) {$blncompare = $true}
   }
#If there is an entry it skips the user and outputs "<user> already has an entry"
    If ($blncompare -eq $true) { Write-Host ($user.samaccountname + " already has an entry")
        $blncompare = $false}
#Now we will check if the user has an email address
    else {
        $newproxy = ("SMTP:"+$user.emailaddress)
#If no email address was pulled from the user then it will skip the user and output "<user> has no email...skipped"
        if ($newproxy -eq "SMTP:") { Write-Host ($user.samaccountname + "has no email...skipped")}
#If the user has an email in the email entry and has no SMTP entry this is where it will add the SMTP entry in the proxy address list.
        else {
            Set-ADUser -Identity $user.samaccountname -Add @{Proxyaddresses=$newproxy}
            Write-Host ("Added " + $newproxy) 
             }
         }
}  
