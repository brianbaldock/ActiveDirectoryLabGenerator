# Active Directory Lab Generator
This script will help you build out AGDLP managed groups and users in a freshly deployed Active Directory. Quick way to get users populated, assigned to groups and even have their images added to the thumbnailPhoto attribute!

## Author
Brian Baldock - brian.baldock@microsoft.com

## Requirements: 
- Active Directory PowerShell Module 
- You can run this from a domain joined workstation with the AD Powershell module installed or the domain controller itself

### PARAMETERS
- CompanyName
  - Mandatory Parameter (What do you wanbt the root level of the OU structure for the domain going to look like?)
    - Example:
      - ABC Company
        - Users
        - Groups
        - Computers

- CompanyDomain
  - Mandatory Parameter (This is the publicly routable domain name that you will be using for email addresses for your users and distribution groups.)

ExportCSV
: Optional Parameter (Create AD Users and Groups and export the user password list to a CSV file, otherwise will print passwords to console.)

SharePath
: Optional Parameter (Provide a path to create the shared folder architecture and ACLs based on users and groups.)

### EXAMPLES
- Create AD Users and Groups and display the passwords generated for each user in the console
- ```.\New-LabConfiguration.ps1 -CompanyName "Contoso Inc" -CompanyDomain "contoso.com"```

- Create AD Users and Groups and export the password list to a CSV file
- ```.\New-LabConfiguration.ps1 -CompanyName "Contoso Inc" -CompanyDomain "contoso.com" -ExportCSV```

- Create personal and common shared folder structure and ACLs at specific path and export passwords as CSV
- ```.\New-LabConfiguration.ps1 -CompanyName "Contoso Inc" -CompanyDomain "contoso.com" -SharePath "C:\Shares" -ExportCSV```
