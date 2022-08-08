

#----------------------------------------------------------------------------
#- Created by:             David Rodriguez                                  -
#- Blog:                   www.sysadmintutorials.com                        -
#- Twitter:                @systutorials                                    -
#- Youtube:                https://www.youtube.com/user/sysadmintutorials   -
#- Version:                3.0                                              -
#----------------------------------------------------------------------------
# Change Log                                                                -
# 4th May 2020             Initial Script for Windows Server 2019           -
# 28th January 2022        Updated Script for Windows Server 2022           -     
# 20th July 2022           Updated Script for Windows Server 2022 2nd DC    -
#----------------------------------------------------------------------------

#-------------
#- Variables -                                         -
#-------------

# Network Variables
$ethipaddress = '192.168.1.223' # static IP Address of the server
$ethprefixlength = '24' # subnet mask - 24 = 255.255.255.0
$ethdefaultgw = '192.168.1.1' # default gateway
$ethdns = '192.168.1.222' # enter in your primary AD server's IP address

# Active Directory Variables
$domainname = 'vlab.local' # enter in your active directory domain
$sitename = 'Sydney-Site' # AD site name within AD Sites and Services

# Remote Desktop Variable
$enablerdp = 'yes' # to enable RDP, set this variable to yes. to disable RDP, set this variable to no

# Disable IE Enhanced Security Configuration Variable
$disableiesecconfig = 'yes' # to disable IE Enhanced Security Configuration, set this variable to yes. to leave enabled, set this variable to no

# Hostname Variables
$computername = 'SERVERDC2' # enter in your server name

# Timestamp
Function Timestamp
    {
    $Global:timestamp = Get-Date -Format "dd-MM-yyy_hh:mm:ss"
    }

# Log File Location
$logfile = "C:\SysadminTutorialsScript\Windows-2022-2nd-AD-Server-Deployment-log.txt"

# Create Log File
Write-Host "-= Get timestamp =-" -ForegroundColor Green

Timestamp

IF (Test-Path $logfile)
    {
    Write-Host "-= Logfile Exists =-" -ForegroundColor Yellow
    }

ELSE {

Write-Host "-= Creating Logfile =-" -ForegroundColor Green

Try{
   New-Item -Path 'C:\SysadminTutorialsScript' -ItemType Directory
   New-Item -ItemType File -Path $logfile -ErrorAction Stop | Out-Null
   Write-Host "-= The file $($logfile) has been created =-" -ForegroundColor Green
   }
Catch{
     Write-Warning -Message $("Could not create logfile. Error: "+ $_.Exception.Message)
     Break;
     }
}

# Check Script Progress via Logfile

$firstcheck = Select-String -Path $logfile -Pattern "1-Basic-Server-Config-Complete"

IF (!$firstcheck) {

# Add starting date and time
Write-Host "-= 1-Basic-Server-Config-Complete, does not exist =-" -ForegroundColor Yellow

Timestamp
Add-Content $logfile "$($Timestamp) - Starting Active Directory Script"

## 1-Basic-Server-Config ##

#------------
#- Settings -
#------------

# Set Network
Timestamp
Try{
    New-NetIPAddress -IPAddress $ethipaddress -PrefixLength $ethprefixlength -DefaultGateway $ethdefaultgw -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop | Out-Null
    Set-DNSClientServerAddress -ServerAddresses $ethdns -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop
    Write-Host "-= IP Address successfully set to $($ethipaddress), subnet $($ethprefixlength), default gateway $($ethdefaultgw) and DNS Server $($ethdns) =-" -ForegroundColor Green
    Add-Content $logfile "$($Timestamp) - IP Address successfully set to $($ethipaddress), subnet $($ethprefixlength), default gateway $($ethdefaultgw) and DNS Server $($ethdns)"
   }
Catch{
     Write-Warning -Message $("Failed to apply network settings. Error: "+ $_.Exception.Message)
     Break;
     }

# Set RDP
Timestamp
Try{
    IF ($enablerdp -eq "yes")
        {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0 -ErrorAction Stop
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
        Write-Host "-= RDP Successfully enabled =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - RDP Successfully enabled"
        }
    }
Catch{
     Write-Warning -Message $("Failed to enable RDP. Error: "+ $_.Exception.Message)
     Break;
     }

IF ($enablerdp -ne "yes")
    {
    Write-Host "-= RDP remains disabled =-" -ForegroundColor Green
    Add-Content $logfile "$($Timestamp) - RDP remains disabled"
    }

# Disable IE Enhanced Security Configuration
Timestamp 
Try{
    IF ($disableiesecconfig -eq "yes")
        {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0 -ErrorAction Stop
        Write-Host "-= IE Enhanced Security Configuration successfully disabled for Admin and User =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - IE Enhanced Security Configuration successfully disabled for Admin and User"
        }
    }
Catch{
     Write-Warning -Message $("Failed to disable Ie Security Configuration. Error: "+ $_.Exception.Message)
     Break;
     }

If ($disableiesecconfig -ne "yes")
    {
    Write-Host "-= IE Enhanced Security Configuration remains enabled =-" -ForegroundColor Green
    Add-Content $logfile "$($Timestamp) - IE Enhanced Security Configuration remains enabled"
    }

# Set Hostname
Timestamp
Try{
    Rename-Computer -ComputerName $env:computername -NewName $computername -ErrorAction Stop | Out-Null
    Write-Host "-= Computer name set to $($computername) =-" -ForegroundColor Green
    Add-Content $logfile "$($Timestamp) - Computer name set to $($computername)"
    }
Catch{
     Write-Warning -Message $("Failed to set new computer name. Error: "+ $_.Exception.Message)
     Break;
     }

# Add first script complete to logfile
Timestamp
Add-Content $logfile "$($Timestamp) - 1-Basic-Server-Config-Complete, starting script 2 =-"

# Reboot Computer to apply settings
Timestamp
Write-Host "-= Save all your work, computer rebooting in 30 seconds =-"  -ForegroundColor White -BackgroundColor Red
Sleep 30

Try{
    Restart-Computer -ComputerName $env:computername -ErrorAction Stop
    Write-Host "-= Rebooting Now!! =-" -ForegroundColor Green
    Add-Content $logfile "$($Timestamp) - Rebooting Now!!"
	Break;
    }
Catch{
     Write-Warning -Message $("Failed to restart computer $($env:computername). Error: "+ $_.Exception.Message)
     Break;
     }

} # Close 'IF (!$firstcheck)'

# Check Script Progress via Logfile
$secondcheck1 = Get-Content $logfile | Where-Object { $_.Contains("1-Basic-Server-Config-Complete") }

IF ($secondcheck1)
    {
    $secondcheck2 = Get-Content $logfile | Where-Object { $_.Contains("2-Build-Active-Directory-Complete") }

    IF (!$secondcheck2)
        {

        ## 2-Build-Active-Directory ##

        Timestamp
        
        #-------------
        #- Variables -                                         -
        #-------------

        # Active Directory Variables
        $safemodeadminpw = Read-Host "Enter Safe Mode Admin Password" -AsSecureString # this will prompt you for Disaster Recovery Management Password
		$creds = (Get-Credential -Message "Enter in your AD admin credentials to join this server to Active Directory. The format being username@domain.local") # enter in an admin AD credentials so we can join this server to AD

        #------------
        #- Settings -
        #------------

        # Install Active Directory Services
        Timestamp
        Try{
            Write-Host "-= Active Directory Domain Services installing =-" -ForegroundColor Yellow
            Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
            Write-Host "-= Active Directory Domain Services installed successfully =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Active Directory Domain Services installed successfully"
            }
        Catch{
            Write-Warning -Message $("Failed to install Active Directory Domain Services. Error: "+ $_.Exception.Message)
            Break;
            }

        # Configure Active Directory
        Timestamp
        Try{
            Write-Host "-= Configuring Active Directory Domain Services =-" -ForegroundColor Yellow
            Import-Module ADDSDeployment
            Install-ADDSDomainController -NoGlobalCatalog:$false -CreateDnsDelegation:$false -Credential $creds -SafeModeAdministratorPassword $safemodeadminpw -CriticalReplicationOnly:$false -DomainName $domainname -InstallDns:$true  -NoRebootOnCompletion:$false -SiteName $sitename -DatabasePath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -LogPath "C:\Windows\NTDS" -Force:$true
            Write-Host "-= Active Directory Domain Services configured successfully =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Active Directory Domain Services configured successfully"
            }
        Catch{
            Write-Warning -Message $("Failed to configure Active Directory Domain Services. Error: "+ $_.Exception.Message)
            Break;
            }

        # Add second script complete to logfile
        Timestamp
        Add-Content $logfile "$($Timestamp) - 2-Build-Active-Directory-Complete, starting script 3 =-"

        # Reboot Computer to apply settings
        Write-Host "-= Save all your work, computer rebooting in 30 seconds =-" -ForegroundColor White -BackgroundColor Red
        Sleep 30

        Try{
            Restart-Computer -ComputerName $env:computername -ErrorAction Stop
            Write-Host "Rebooting Now!!" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Rebooting Now!!"
            Break;
            }
        Catch{
            Write-Warning -Message $("Failed to restart computer $($env:computername). Error: "+ $_.Exception.Message)
            Break;
            }
        } # Close 'IF ($secondcheck2)'
    }# Close 'IF ($secondcheck1)'


# Add second script complete to logfile

# Check Script Progress via Logfile
$thirdcheck = Get-Content $logfile | Where-Object { $_.Contains("2-Build-Active-Directory-Complete") }

## 3-Configure-Active-Directory-Server ##

#------------
#- Settings -
#------------

# Add DNS Scavenging
Write-Host "-= Set DNS Scavenging =-" -ForegroundColor Yellow

Timestamp
Try{
    Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -Verbose -ErrorAction Stop
    Add-Content $logfile "$($Timestamp) - DNS Scavenging Complete"
    }
Catch{
     Write-Warning -Message $("Failed to DNS Scavenging. Error: "+ $_.Exception.Message)
     Break;
     }

Get-DnsServerScavenging

Write-Host "-= DNS Scavenging Complete =-" -ForegroundColor Green

# Script Finished

Timestamp
Write-Host "-= 3-Finalize-AD-Config Complete =-" -ForegroundColor Green
Add-Content $logfile "$($Timestamp) - 3-Finalize-AD-Config Complete"
Write-Host "-= Active Directory Script Complete =-" -ForegroundColor Green
Add-Content $logfile "$($Timestamp) - Active Directory Script Complete"
