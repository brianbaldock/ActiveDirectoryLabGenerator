<#
    .DESCRIPTION
        This script will help you build out AGDLP managed groups and users in a freshly deployed Active Directory.
        Quick way to get users populated, assigned to groups and even have their images added to the thumbnailPhoto attribute!

        The sample scripts are not supported under any Microsoft standard support 
        program or service. The sample scripts are provided AS IS without warranty  
        of any kind. Microsoft further disclaims all implied warranties including,  
        without limitation, any implied warranties of merchantability or of fitness for 
        a particular purpose. The entire risk arising out of the use or performance of  
        the sample scripts and documentation remains with you. In no event shall 
        Microsoft, its authors, or anyone else involved in the creation, production, or 
        delivery of the scripts be liable for any damages whatsoever (including, 
        without limitation, damages for loss of business profits, business interruption, 
        loss of business information, or other pecuniary loss) arising out of the use 
        of or inability to use the sample scripts or documentation, even if Microsoft 
        has been advised of the possibility of such damages.

        Author: Brian Baldock - brian.baldock@microsoft.com

        Requirements: 
            Active Directory PowerShell Module
            You can run this from a domain joined workstation with the AD Powershell module installed or the domain controller itself

    .PARAMETER CompanyName
        Mandatory Parameter - What is the root level of the OU structure for the domain going to look like? Example: [Contoso Inc]
                                                                                                                    |- Users
                                                                                                                    |- Groups
                                                                                                                    |- Computes

    .PARAMETER CompanyDomain
        Mandatory Parameter - This is the publicly routable domain name that you will be using for email addresses for your users and distribution groups

    .PARAMETER ExportCSV
        Optional Parameter - Create AD Users and Groups and export the password list to a CSV file

    .PARAMETER SharePath
        Optional Parameter - Provide a path to create the shared folder architecture and ACLs based on users and groups

    .EXAMPLE
        Create AD Users and Groups and display the passwords generated for each user in the console
        .\New-LabConfiguration.ps1 -CompanyName "Contoso Inc" -CompanyDomain "contoso.com"

        Create AD Users and Groups and export the password list to a CSV file
        .\New-LabConfiguration.ps1 -CompanyName "Contoso Inc" -CompanyDomain "contoso.com" -ExportCSV

        Create personal and common shared folder structure and ACLs at specific path and export passwords as CSV
        .\New-LabConfiguration.ps1 -CompanyName "Contoso Inc" -CompanyDomain "contoso.com" -SharePath "C:\Shares" -ExportCSV 
#>

[CmdletBinding()]

# Parameters
param (
    [Parameter(Mandatory=$True,
    HelpMessage='Enter the name of the company here (This will be the root of the OU structure) Example: Contoso Inc')]
    [String]$CompanyName,

    [Parameter(Mandatory=$True,
    HelpMessage='Enter the routable domain name for email that will be used by this lab - Example: contoso.com')]
    [String]$CompanyDomain,
    
    [Parameter(Mandatory=$True,
    HelpMessage='Enter the location where you want to create the shared folders (Do not include trailing "\" - Example: C: or C:\Test')]
    [String]$SharePath,

    [Parameter(Mandatory=$False,
    HelpMessage='This will export the password list to a CSV file.')]
    [bool]$ExportCSV
)

begin{
    Write-Progress -Activity "Lookup" -Status "Getting domain distinguishedName" -PercentComplete 0
    $DomDN = Get-ADDomain | Select-Object DistinguishedName
    
    Write-Progress -Activity "Working" -Status "Creating global variables" -PercentComplete 10
    $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
    $OULayout = "Users", "Groups", "Computers"
}

process{
    try{
        #Test for existing OU structure, if exists end script
        Write-Progress -Activity "Working" -Status "Creating OU structure" -PercentComplete 20
        if(!(Get-ADOrganizationalUnit -Filter {Name -like $CompanyName})){
            #Create new OU Structure
            try{
                New-ADOrganizationalUnit -DisplayName "$($CompanyName)" -Name "$($CompanyName)" -Path $DomDN.DistinguishedName
                foreach($OU in $OULayout){
                    if(!(Get-ADOrganizationalUnit -Filter {Name -like $OU})){
                        New-ADOrganizationalUnit -DisplayName $OU -Name $OU -Path "OU=$($CompanyName),$($DomDn.DistinguishedName)"
                    }
                }
            }
            catch{
                Write-Output "Something went wrong while creating the OU Structure!"
                $_.Exception.Message
                break
            }
            #Import Users to the OU Structure
            Try{
                $usrOU = "OU=Users,OU=$($CompanyName),$($DomDn.DistinguishedName)"
                Write-Progress -Activity "Hydrating Active Directory" -Status "Creating users and adding pictures" -PercentComplete 25
                $users = Import-CSV -Path "$($ScriptDir)\labusers.csv"
                $PasswordList = @()
                foreach($User in $Users){

                    #Generate a random password:
                    [string]$Password = ""
                    $Password = Get-Random -Count 2 -InputObject ((65 .. 72) + (74 .. 75) + (77 .. 78) + (80 .. 90)) | % -begin { $UC = $null } -process { $UC += [char]$_ } -end { $UC }
                    $Password += Get-Random -Count 6 -InputObject (97 .. 122) | % -begin { $LC = $null } -process { $LC += [char]$_ } -end { $LC }
                    $Password += Get-Random -Count 3 -InputObject (48 .. 57) | % -begin { $NB = $null } -process { $NB += [char]$_ } -end { $NB }

                    #Create the users:
                    New-ADUser -Name $User.DisplayName -DisplayName $User.DisplayName -GivenName $User.GivenName -Surname $User.Surname -AccountPassword ($Password | ConvertTo-SecureString -AsPlainText -Force) -sAMAccountName $User.sAMAccountName -UserPrincipalName ($User.sAMAccountName + "@" + (Get-AdDomain).DNSRoot) -EmailAddress $User.EmailAddress -Title $User.Title -Description $User.Title -Department $User.Department -Company $User.Company -OfficePhone $User.OfficePhone -Office $User.physicalDeliveryOfficeName -StreetAddress $User.StreetAddress -City $User.City -State $User.State -PostalCode $User.PostalCode -Country $User.Country -Path $usrOU -PasswordNeverExpires $True -Enabled $True
                    Set-ADUser $User.sAMAccountName -Replace @{thumbnailPhoto=([byte[]](Get-Content "$Scriptdir\labusers\$($User.sAMAccountName).jpg" -Encoding byte))}
                    $Object = New-Object PSObject -Property @{
                        Name = $User.DisplayName
                        EmailAddress = $user.EmailAddress
                        Password = $Password
                    }
                    $PasswordList += $Object
                }
            }
            catch{
                Write-Output "Something went wrong while creating the user $User.sAMAccountName"
                $_.Exception.Message
                break
            }
            #Create the groups
            try{
                
                $grpOU = "OU=Groups,OU=$($CompanyName),$($DomDn.DistinguishedName)"
                Write-Progress -Activity "Hydrating Active Directory" -Status "Creating groups" -PercentComplete 30
                $Groups = Import-Csv -Path "$($ScriptDir)\labgroups.csv"
                $Groups | ForEach-Object {New-ADGroup -Name $_.Name -GroupScope $_.GroupScope -GroupCategory $_.GroupCategory -OtherAttributes @{'adminDescription'=$_.adminDescription} -Path $grpOU}

                #Hydrate the groups:
                Write-Progress -Activity "Hydrating Active Directory" -Status "Hydrating new groups" -PercentComplete 40
                foreach($Group in $Groups){
                    #Assign users to Global Security Groups according to Title
                    if($Group.GroupCategory -eq "Security" -and $Group.GroupScope -eq "Global"){ 
                        $UserMatch = Get-ADUser -Filter * -SearchBase $usrOU -Properties Title | Where-Object {($_.Title).Replace(" ","") -eq "$($Group.Name)".Replace("G-","")}
                        foreach($User in $UserMatch){
                            Add-ADGroupMember -Identity $Group.Name -Members $User.sAMAccountName
                        }
                    }
                    #Assign users to Distribution Groups according to Department
                    if($Group.GroupCategory -eq "Distribution"){
                        Set-ADGroup -Identity $Group.Name -Replace @{mail="$($Group.Name)@$($CompanyDomain)"}
                        $UserMatch = Get-ADUser -Filter * -SearchBase $usrOU -Properties Department| Where-Object {($_.Department) -eq "$($Group.Name)"}
                        foreach($User in $UserMatch){
                            Add-ADGroupMember -Identity $Group.Name -Members $User.sAMAccountName
                        }
                    }
                    #Assign Global Security Groups to Domain Local groups according to the adminDescription attribute used to associate job roles with departments
                    if($Group.GroupScope -eq "DomainLocal"){
                        $GlobGroups = Get-ADGroup -Filter {GroupScope -eq "Global" -and GroupCategory -eq "Security"} -SearchBase $grpOU -Properties adminDescription | Where-Object {$_.adminDescription -eq "$($Group.Name)".Replace("DL-","")}
                        foreach($GlobGroup in $GlobGroups){
                            Add-ADGroupMember -Identity $Group.Name -Members $GlobGroup.Name
                        }
                    } 
                }
                Write-Progress -Activity "Hydrating Active Directory" -Status "Finalizing" -PercentComplete 70
            }
            catch{
                Write-Output "Something went wrong while creating the groups! $_.Name"
                $_.Exception.Message
                break
            }
            #Create Folder tree and permission ACLs
            try{
                Write-Progress -Activity "Creating common shared folders @ $($SharePath)" -Status "Creating" -PercentComplete 80
                if($SharePath -ne ""){
                    #Create shared folders and set ACLs
                    try{
                        Write-Progress -Activity "Creating common shared folders @ $($SharePath)" -Status "Creating" -PercentComplete 85
                        New-Item -Path $SharePath -ItemType Directory -Name "\Shares"
                        New-Item -Path "$($SharePath)\Shares" -ItemType Directory -Name "Users"
                        $DLGroups = Get-ADGroup -Filter {GroupScope -eq "DomainLocal" -and GroupCategory -eq "Security"} -SearchBase $grpOU -Properties adminDescription
                        Write-Progress -Activity "Setting common shared folder permissions on @ $($SharePath)" -Status "Creating" -PercentComplete 90
                        foreach($Group in $DLGroups){
                            New-Item -Path "$($SharePath)\Shares" -ItemType Directory -Name $Group.adminDescription
                            $NewPath = "$($SharePath)\Shares\$($Group.adminDescription)"
                            $ACL = Get-Acl -Path $NewPath
                            $ACL.SetAccessRuleProtection($True, $True)
                            Set-Acl -Path $NewPath -AclObject $ACL

                            # Set group permission on new folder
                            $Permission = $Group.Name,"Modify","ContainerInherit,ObjectInherit","None","Allow"
                            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
                            $ACL.SetAccessRule($Rule)
                            $ACL | Set-Acl $NewPath

                            # Remove domain users group permission from the folder
                            $RACL = Get-ACL -Path $NewPath
                            $RPermission = "BUILTIN\Users","ReadAndExecute","Allow"
                            $RACLRules = New-Object System.Security.AccessControl.FileSystemAccessRule($RPermission)
                            $RACL.RemoveAccessRuleAll($RACLRules)
                            Set-ACL -Path $NewPath -AclObject $RACL
                        }
                    }
                    catch{
                        Write-Output "Something happened when creating common shares!"
                        $_.Exception.Message
                    }
                    #Create user personal shares and set ACLs
                    try{
                        Write-Progress -Activity "Creating user shared folder and assigning permissions on @ $($SharePath)\Shares\Users" -Status "Creating" -PercentComplete 95
                        $Users = Get-ADUser -SearchBase "OU=Users,OU=$($CompanyName),$($DomDn.DistinguishedName)" -Filter *
                        foreach($User in $Users){
                            New-Item -Path "$($SharePath)\Shares\Users" -ItemType Directory -Name $User.SamAccountName
                            $NewPath = "$($SharePath)\Shares\Users\$($User.SamAccountName)"
                            $ACL = Get-Acl -Path $NewPath
                            $ACL.SetAccessRuleProtection($True, $True)
                            Set-Acl -Path $NewPath -AclObject $ACL

                            # Set group permission on new folder
                            $Permission = $User.SamAccountName,"Modify","ContainerInherit,ObjectInherit","None","Allow"
                            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
                            $ACL.SetAccessRule($Rule)
                            $ACL | Set-Acl $NewPath

                            # Remove domain users group permission from the folder
                            $RACL = Get-ACL -Path $NewPath
                            $RPermission = "BUILTIN\Users","ReadAndExecute","Allow"
                            $RACLRules = New-Object System.Security.AccessControl.FileSystemAccessRule($RPermission)
                            $RACL.RemoveAccessRuleAll($RACLRules)
                            Set-ACL -Path $NewPath -AclObject $RACL
                        }
                        Write-Progress -Activity "Creating user shared folder and assigning permissions on @ $($SharePath)\Shares\Users" -Status "Finalizing" -PercentComplete 100
                    }
                    catch{
                        Write-Output "Something happened when creating user shares!"
                        $_.Exception.Message
                    }
                }
            }
            catch{
                $_.Exception.Message
            }
        }
        else{
            Write-Output "OU Structure already exists!"
            break
        }
    }
    catch{
        $_.Exception.Message
        break
    }

    if($ExportCSV){
        if(!(Test-Path -Path "$($ScriptDir)\PasswordList.csv")){
            $PasswordList | Export-Csv -Path "$($ScriptDir)\PasswordList.csv" -NoTypeInformation
        }
        else{
            Write-Output "PasswordList.csv already exists at path $($ScriptDir) please verify"
            $PasswordList
        }
    }
    else{
        $PasswordList
    }
}

end{
    Write-Output "Completed"
}