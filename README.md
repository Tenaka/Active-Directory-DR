# Active-Directory-DR

Service account setup 

Create a service account named svc_Backup

Add the service account to both ‘DNSAdmins’ and ‘Group Policy Creator Owners’ Groups.

The service requires both User Rights Assignments ‘Logon as Batch’ and Logon as a Service’

Either add directly to URA via GPO Management or preferably create URA groups and assign to ‘Logon as Batch’ and ‘Logon as a Service’, then add the service account to the groups.
    
The service account will require Full NTFS permission on ‘C:\ADBackup\’ and ‘C:\Windows\System32\DNS\’ to create and delete files and directories.

Don’t allow the service account permissions to amend the backup script.
    
Ensure DNSAdmin has Server level and Zone level permissions. 

Do Not add the service account to Domain Admins.


