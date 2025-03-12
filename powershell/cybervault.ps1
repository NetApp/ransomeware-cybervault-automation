# Copyright NetApp 2024. Developed by NetApp Solutions Engineering Team
# Authors : Pradeep Kumar (pradeep.kumar@netapp.com), Niyaz Mohamed (niyaz.mohamed@netapp.com)

# Title : Ransomware Protection with a Cyber Vault Using SnapLock Compliance Automation
# Description: This Powershell script can be used to 
#   - Automate the creation and configuration of NetApp ONTAP SnapLock Compliance volumes
#   - Configure SnapMirror relationship between the source volumes and destination SnapLock Compliance volumes
#   - Perform security hardening following ONTAP best practices
#   - Analyze the volumes, SnapMirror configuration and security settings
#   - Quiesce and resume SnapMirror relationships based on schedule
# Version : 1.0

# Pre-requisites for running this script
#   - Admin or equal privileges for ONTAP Clusters

# Instructions : This script has 3 modes
#   - configure : Creates, configures the cybervault volumes. Applies security best practices
#   - analyze : Analyzes cybervault volume configurations, check security best practices are applied
#   - cron : Used to resume, quiesce snapmirror relationships based on schedule

# Usage : Simply run the script and pass in the required parameters and credentials
<# Example : ./cybervault.ps1 `
    -SOURCE_ONTAP_CLUSTER_MGMT_IP "cluster1.demo.netapp.com" `
    -SOURCE_ONTAP_INTERCLUSTER_IPS "192.168.0.141/32,192.168.0.142/32" `
    -SOURCE_ONTAP_CLUSTER_NAME "cluster1" `
    -SOURCE_VSERVER "svm1" `
    -SOURCE_VOLUME_NAME "svm1_legal","svm1_marketing" `
    -DESTINATION_ONTAP_CLUSTER_MGMT_IP "cluster2.demo.netapp.com" `
    -DESTINATION_ONTAP_CLUSTER_NAME "cluster2" `
    -DESTINATION_VSERVER "svm2" `
    -DESTINATION_AGGREGATE_NAMES "cluster2_01_SSD_1","cluster2_01_SSD_1" `
    -AUDIT_LOG_AGGREGATE_NAME "cluster2_01_SSD_1" `
    -DESTINATION_VOLUME_NAME "cvault_legal","cvault_marketing" `
    -DESTINATION_VOLUME_SIZE "25g","5g" `
    -SNAPLOCK_MIN_RETENTION "15minutes" `
    -SNAPLOCK_MAX_RETENTION "30minutes" `
    -SNAPMIRROR_PROTECTION_POLICY "XDPDefault" `
    -SNAPMIRROR_SCHEDULE "5min" `
    -MULTI_ADMIN_APPROVAL_GROUP_NAME "vaultadmins" `
    -MULTI_ADMIN_APPROVAL_USERS "vaultadmin,vaultadmin2" `
    -MULTI_ADMIN_APPROVAL_EMAIL "vaultadmins@demo.netapp.com" `
    -ALLOWED_IPS_FOR_MANAGEMENT "192.168.0.5/32,192.168.0.6/32" `
    -CRON_SCHEDULE 5min `
    -SNAPMIRROR_RESUME_MINUTES_BOFORE_SM 2 `
    -SNAPMIRROR_QUIESCE_MINUTES_POST_SM 2 `
    -DOMAIN_ADMINISTRATOR_USERNAME "DEMO\Administrator" `
    -SCRIPT_MODE configure
#>

param (
    [Parameter(Mandatory=$True, HelpMessage="Source ONTAP Cluster IP Address")]
    [String]$SOURCE_ONTAP_CLUSTER_MGMT_IP,
    [Parameter(Mandatory=$True, HelpMessage="Source ONTAP Intercluster IPs")]
    [String[]]$SOURCE_ONTAP_INTERCLUSTER_IPS,
    [Parameter(Mandatory=$True, HelpMessage="Source ONTAP Cluster Name")]
    [String]$SOURCE_ONTAP_CLUSTER_NAME,
    [Parameter(Mandatory=$True, HelpMessage="Source VServer Name")]
    [String]$SOURCE_VSERVER,
    [Parameter(Mandatory=$True, HelpMessage="Source Volume Name")]
    [String[]]$SOURCE_VOLUME_NAMES,
    [Parameter(Mandatory=$True, HelpMessage="Destination ONTAP Cluster IP Address")]
    [String]$DESTINATION_ONTAP_CLUSTER_MGMT_IP,
    [Parameter(Mandatory=$True, HelpMessage="Destination ONTAP Cluster Name")]
    [String]$DESTINATION_ONTAP_CLUSTER_NAME,
    [Parameter(Mandatory=$True, HelpMessage="Destination VServer Name")]
    [String]$DESTINATION_VSERVER,
    [Parameter(Mandatory=$True, HelpMessage="Destination Volume Name")]
    [String[]]$DESTINATION_VOLUME_NAMES,
    [Parameter(Mandatory=$True, HelpMessage="Destination Aggregate Name")]
    [String[]]$DESTINATION_AGGREGATE_NAMES,
    [Parameter(Mandatory=$True, HelpMessage="Destination Audit log volume Aggregate Name")]
    [String]$AUDIT_LOG_AGGREGATE_NAME,
    [Parameter(Mandatory=$True, HelpMessage="Destination Volume Size")]
    [String[]]$DESTINATION_VOLUME_SIZES,
    [Parameter(Mandatory=$True, HelpMessage="SnapLock minimum retention period")]
    [String]$SNAPLOCK_MIN_RETENTION,
    [Parameter(Mandatory=$True, HelpMessage="SnapLock maximum retention period")]
    [String]$SNAPLOCK_MAX_RETENTION,
    [Parameter(Mandatory=$True, HelpMessage="SnapMirror data protection policy name")]
    [String]$SNAPMIRROR_PROTECTION_POLICY,
    [Parameter(Mandatory=$True, HelpMessage="SnapMirror schedule name")]
    [String]$SNAPMIRROR_SCHEDULE,
    [Parameter(Mandatory=$True, HelpMessage="Multi admin approval group name")]
    [String]$MULTI_ADMIN_APPROVAL_GROUP_NAME,
    [Parameter(Mandatory=$True, HelpMessage="Multi admin approval user")]
    [String]$MULTI_ADMIN_APPROVAL_USERS,
    [Parameter(Mandatory=$True, HelpMessage="Multi admin approval email")]
    [String]$MULTI_ADMIN_APPROVAL_EMAIL,
    [Parameter(Mandatory=$True, HelpMessage="Skip SnapLock compliance volume creation, snapmirror configuration")]
    [validateSet("configure", "analyze", "cron")]
    [String]$SCRIPT_MODE = "configure",
    [Parameter(Mandatory=$True, HelpMessage="Allowed IP address for the HTTPS Cluster management")]
    [String]$ALLOWED_IPS_FOR_MANAGEMENT,
    [Parameter(Mandatory=$True, HelpMessage="Cron schedule time")]
    [validateSet("5min", "10min", "20min", "hourly", "6-hourly", "8hour", "12-hourly", "daily", "monthly")]
    [String]$CRON_SCHEDULE = "5min",
    [Parameter(Mandatory=$True, HelpMessage="SnapMirror resume operation just before the snapmirror replication time")]
    [String]$SNAPMIRROR_RESUME_MINUTES_BOFORE_SM = 2,
    [Parameter(Mandatory=$True, HelpMessage="SnapMirror resume operation just before the snapmirror replication time")]
    [String]$SNAPMIRROR_QUIESCE_MINUTES_POST_SM = 2,
    [Parameter(Mandatory=$True, HelpMessage="Domain administrator username from where the script is run. This is required for the cron to run properly")]
    [String]$DOMAIN_ADMINISTRATOR_USERNAME = "DEMO\administrator",
    [Parameter(Mandatory=$True, HelpMessage="The Credential to connect to the Destination ONTAP Cluster")]
    [System.Management.Automation.PSCredential]$DESTINATION_ONTAP_CREDS
)

[string]$ontapModuleName = "NetApp.ONTAP"

$splitIPs = $ALLOWED_IPS_FOR_MANAGEMENT -split ','

$trimmedIPs = $splitIPs | ForEach-Object { $_.Trim() }
$ALLOWED_IPS = $trimmedIPs -join ", "

$splitIPs = $SOURCE_ONTAP_INTERCLUSTER_IPS -split ','

$trimmedIPs = $splitIPs | ForEach-Object { $_.Trim() }
$SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS = $trimmedIPs -join ", "

function main {

    [String[]]$DEFAULT_MANAGEMENT_SERVICES_TO_DISABLE = "management-snmp-server", "management-ntp-server", "management-log-forwarding", "management-nis-client", "management-ad-client", "management-autosupport", "management-ems", "management-ntp-client", "management-dns-client", "management-ldap-client", "management-http"

    if ($DESTINATION_ONTAP_CREDS.UserName -eq 'admin' -or $DESTINATION_ONTAP_CREDS.UserName -eq 'diag') {
        handleError -errorMessage "Do not use admin or diag user credentials. Recommended to create a new user with admin privileges for vault operations"
    }

    importModules

    connectONTAP -ClusterMgmtIP $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -VserverName $DESTINATION_VSERVER

    try {
        # Determine the script's running path
        $scriptPath = $PSScriptRoot
        if (-not $scriptPath) {
            $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
        }

        # Check if the script path is determined correctly
        if (-not $scriptPath) {
            throw "Unable to determine the script's running path."
        }

        # Create the logs folder within the script's running path
        $logsFolderPath = Join-Path -Path $scriptPath -ChildPath "logs"
        if (-not (Test-Path -Path $logsFolderPath)) {
            New-Item -Path $logsFolderPath -ItemType Directory | Out-Null
        }

        # Generate the log file name based on the variable value and the current timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "$SCRIPT_MODE`_$timestamp.log"
        $global:logFilePath = Join-Path -Path $logsFolderPath -ChildPath $logFileName
    }
    catch {
        handleError -errorMessage $_.Exception.Message
    }

    if($SCRIPT_MODE -eq "configure") {
        configure
    } elseif ($SCRIPT_MODE -eq "analyze") {
        analyze
    } elseif ($SCRIPT_MODE -eq "cron") {
        configureCron
    }

    logMessage -message "Logs available at : $logFilePath"
}

function configure {

    initializeSnapLockComplianceClock

    configureCyberVault
        
    removeSvmDataProtocols

    disableSvmDataLifs

    configureMultiAdminApproval

    additionalSecurityHardening

    initializeSnapmirror
}

# Function to log messages
function logMessage {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$type] $message"

    if ($type -eq "ERROR") {
        Write-Host $logEntry -ForegroundColor Red
        Write-Host "`n"
    } elseif ($type -eq "SUCCESS") {
        Write-Host $logEntry -ForegroundColor Green
        Write-Host "`n"
    } else {
        Write-Host $logEntry
    }

    # Write the log entry to the file
    Add-Content -Path $global:logFilePath -Value $logEntry
}

# Function to handle errors
function handleError {
    param (
        [string]$errorMessage
    )
    logMessage -message $errorMessage -type "ERROR"
    throw $errorMessage
}

function installModules {
    try {
        logMessage -message "Installing module $sshModuleName"
        Install-Module -Name $sshModuleName -Force -Scope CurrentUser -ErrorAction Stop
        logMessage -message "Installed module $sshModuleName" -type "SUCCESS"
    }
    catch {
        handleError -errorMessage "Failed to install module $sshModuleName. Error: $_"
    }
}

function importModules {

    try {
        logMessage -message "Importing module $ontapModuleName"
        Import-Module $ontapModuleName -ErrorAction SilentlyContinue
        logMessage -message "Imported module $ontapModuleName" -type "SUCCESS"
    } catch {
        handleError -errorMessage "Failed to import module $ontapModuleName. Error: $_"
    }
}

function connectONTAP {
    param (
        [string]$ClusterMgmtIP,
        [PSCredential]$Credential,
        [string]$VserverName
    )

    # Connect to the ONTAP Cluster
    try {
        logMessage -message "Connecting to ONTAP Cluster at $ClusterMgmtIP, VServer $VserverName"
        Connect-NcController -Name $ClusterMgmtIP -Credential $Credential -Vserver $VserverName -ErrorAction Stop
        logMessage -message "Connected to ONTAP Cluster at $ClusterMgmtIP" -type "SUCCESS"
    } catch {
        handleError -errorMessage "Failed to connect to ONTAP Cluster at $ClusterMgmtIP. Error: $_"
    }
}

function initializeSnapLockComplianceClock {
    try {
        $nodes = Get-NcNode

        $isInitialized = $false
        logMessage -message "Cheking if snaplock compliance clock is initialized"
        foreach($node in $nodes) {
            $check = Get-NcSnaplockComplianceClock -Node $node.Node
            if ($check.SnaplockComplianceClockSpecified -eq "True") {
                $isInitialized = $true
            }
        }

        if ($isInitialized) {
            logMessage -message "SnapLock Compliance clock already initialized" -type "SUCCESS"
        } else {
            logMessage -message "Initializing SnapLock compliance clock"
            foreach($node in $nodes) {
                Set-NcSnaplockComplianceClock -Node $node.Node
            }
            logMessage -message "Successfully initialized SnapLock Compliance clock" -type "SUCCESS"
        }
    } catch {
        handleError -errorMessage $_.Exception.Message
    }
}

function configureCyberVault {
    for($i = 0; $i -lt $DESTINATION_VOLUME_NAMES.Length; $i++) {
        try {
            # checking if the volume already exists and is of type snaplock compliance
            logMessage -message "Checking if SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i]) already exists in vServer $DESTINATION_VSERVER"
            $volume = Get-NcVol -Vserver $DESTINATION_VSERVER -Volume $DESTINATION_VOLUME_NAMES[$i] | Select-Object -Property Name, State, TotalSize, Aggregate, Vserver, Snaplock | Where-Object { $_.Snaplock.Type -eq "compliance" }
            if($volume) {
                $volume
                logMessage -message "SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i]) already exists in vServer $DESTINATION_VSERVER" -type "SUCCESS"
            } else {
                # Create SnapLock Compliance volume
                logMessage -message "Creating SnapLock Compliance volume: $($DESTINATION_VOLUME_NAMES[$i])"
                New-NcVol -Name $DESTINATION_VOLUME_NAMES[$i] -Aggregate $DESTINATION_AGGREGATE_NAMES[$i] -SnaplockType Compliance -Type DP -Size $DESTINATION_VOLUME_SIZES[$i] -ErrorAction Stop | Select-Object -Property Name, State, TotalSize, Aggregate, Vserver
                logMessage -message "Volume $($DESTINATION_VOLUME_NAMES[$i]) created successfully" -type "SUCCESS"
            }
        
            # Set SnapLock volume attributes
            logMessage -message "Setting SnapLock volume attributes for volume: $($DESTINATION_VOLUME_NAMES[$i])"
            Set-NcSnaplockVolAttr -Volume $DESTINATION_VOLUME_NAMES[$i] -MinimumRetentionPeriod $SNAPLOCK_MIN_RETENTION -MaximumRetentionPeriod $SNAPLOCK_MAX_RETENTION -ErrorAction Stop | Select-Object -Property Type, MinimumRetentionPeriod, MaximumRetentionPeriod
            logMessage -message "SnapLock volume attributes set successfully for volume: $($DESTINATION_VOLUME_NAMES[$i])" -type "SUCCESS"
            
            # checking snapmirror relationship
            logMessage -message "Checking if SnapMirror relationship exists between source volume $($SOURCE_VOLUME_NAMES[$i]) and destination SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i])"
            $snapmirror = Get-NcSnapmirror | Select-Object SourceCluster, SourceLocation, DestinationCluster, DestinationLocation, Status, MirrorState | Where-Object { $_.SourceCluster -eq $SOURCE_ONTAP_CLUSTER_NAME -and $_.SourceLocation -eq "$($SOURCE_VSERVER):$($SOURCE_VOLUME_NAMES[$i])" -and $_.DestinationCluster -eq $DESTINATION_ONTAP_CLUSTER_NAME -and $_.DestinationLocation -eq "$($DESTINATION_VSERVER):$($DESTINATION_VOLUME_NAMES[$i])" -and ($_.Status -eq "snapmirrored" -or $_.Status -eq "uninitialized") }
            if($snapmirror) {
                $snapmirror
                logMessage -message "SnapMirror relationship already exists for volume: $($DESTINATION_VOLUME_NAMES[$i])" -type "SUCCESS"
            } else {
                # Create SnapMirror relationship
                logMessage -message "Creating SnapMirror relationship for volume: $($DESTINATION_VOLUME_NAMES[$i])"
                New-NcSnapmirror -SourceCluster $SOURCE_ONTAP_CLUSTER_NAME -SourceVserver $SOURCE_VSERVER -SourceVolume $SOURCE_VOLUME_NAMES[$i] -DestinationCluster $DESTINATION_ONTAP_CLUSTER_NAME -DestinationVserver $DESTINATION_VSERVER -DestinationVolume $DESTINATION_VOLUME_NAMES[$i] -Policy $SNAPMIRROR_PROTECTION_POLICY -Schedule $SNAPMIRROR_SCHEDULE -ErrorAction Stop | Select-Object -Property SourceCluster, SourceLocation, DestinationCluster, DestinationLocation, Status, Policy, Schedule
                logMessage -message "SnapMirror relationship created successfully for volume: $($DESTINATION_VOLUME_NAMES[$i])" -type "SUCCESS"
            }
        
        } catch {
            handleError -errorMessage $_.Exception.Message
        }
    }
}

function initializeSnapmirror {
    for($i = 0; $i -lt $DESTINATION_VOLUME_NAMES.Length; $i++) {
        try {
            # Initialize SnapMirror relationship
            logMessage -message "Initializing SnapMirror relationship for volume: $($DESTINATION_VOLUME_NAMES[$i])"
            Invoke-NcSnapmirrorInitialize -DestinationCluster $DESTINATION_ONTAP_CLUSTER_NAME -DestinationVserver $DESTINATION_VSERVER -DestinationVolume $DESTINATION_VOLUME_NAMES[$i] -ErrorAction Stop | Select-Object -Property JobVserver, Uuid, Status
            logMessage -message "SnapMirror relationship initialized successfully for volume: $($DESTINATION_VOLUME_NAMES[$i])" -type "SUCCESS"
        }
        catch {
            handleError -errorMessage $_.Exception.Message
        }  
    }
}

function removeSvmDataProtocols {
    try {

        # checking NFS service is disabled
        logMessage -message "Checking if NFS service is disabled on vServer $DESTINATION_VSERVER"
        $nfsService = Get-NcNfsService 
        if($nfsService) {
            # Remove NFS
            logMessage -message "Removings NFS protocol on vServer : $DESTINATION_VSERVER"
            Remove-NcNfsService -VserverContext $DESTINATION_VSERVER -Confirm:$false
            logMessage -message "NFS protocol removed on vServer :  $DESTINATION_VSERVER" -type "SUCCESS"
        } else {
            logMessage -message "NFS service is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }

        # checking CIFS/SMB server is disabled
        logMessage -message "Checking if CIFS/SMB server is disabled on vServer $DESTINATION_VSERVER"
        $cifsServer = Get-NcCifsServer 
        if($cifsServer) {
            # Remove SMB/CIFS
            logMessage -message "Removing SMB/CIFS protocol on vServer : $DESTINATION_VSERVER"
            $domainAdministratorUsername = Read-Host -Prompt "Enter Domain administrator username"
            $domainAdministratorPassword = Read-Host -Prompt "Enter Domain administrator password" -AsSecureString
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($domainAdministratorPassword))
            Remove-NcCifsServer -VserverContext $DESTINATION_VSERVER -AdminUsername $domainAdministratorUsername -AdminPassword $plainPassword -Confirm:$false -ErrorAction Stop
            logMessage -message "SMB/CIFS protocol removed on vServer :  $DESTINATION_VSERVER" -type "SUCCESS"
        } else {
            logMessage -message "CIFS/SMB server is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }

        # checking iSCSI service is disabled
        logMessage -message "Checking if iSCSI service is disabled on vServer $DESTINATION_VSERVER"
        $iscsiService = Get-NcIscsiService 
        if($iscsiService) {
            # Remove iSCSI
            logMessage -message "Removings iSCSI protocol on vServer : $DESTINATION_VSERVER"
            Remove-NcIscsiService -VserverContext $DESTINATION_VSERVER -Confirm:$false
            logMessage -message "iSCSI protocol removed on vServer :  $DESTINATION_VSERVER" -type "SUCCESS"
        } else {
            logMessage -message "iSCSI service is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }

        # checking FCP service is disabled
        logMessage -message "Checking if FCP service is disabled on vServer $DESTINATION_VSERVER"
        $fcpService = Get-NcFcpService 
        if($fcpService) {
            # Remove FCP
            logMessage -message "Removings FC protocol on vServer : $DESTINATION_VSERVER"
            Remove-NcFcpService -VserverContext $DESTINATION_VSERVER -Confirm:$false
            logMessage -message "FC protocol removed on vServer :  $DESTINATION_VSERVER" -type "SUCCESS"
        } else {
            logMessage -message "FCP service is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }
    
    } catch {
        handleError -errorMessage $_.Exception.Message
    }
}

function disableSvmDataLifs {
    try {
        logMessage -message "Finding all data lifs on vServer : $DESTINATION_VSERVER"
        $dataLifs = Get-NcNetInterface -Vserver $DESTINATION_VSERVER | Where-Object { $_.Role -contains "data_core" }
        $dataLifs | Select-Object -Property InterfaceName, OpStatus, DataProtocols, Vserver, Address

        logMessage -message "Disabling all data lifs on vServer : $DESTINATION_VSERVER"
        # Disable the filtered data LIFs
        foreach ($lif in $dataLifs) {
            $disableLif = Set-NcNetInterface -Vserver $DESTINATION_VSERVER -Name $lif.InterfaceName -AdministrativeStatus down -ErrorAction Stop
            $disableLif | Select-Object -Property InterfaceName, OpStatus, DataProtocols, Vserver, Address
        }
        logMessage -message "Disabled all data lifs on vServer : $DESTINATION_VSERVER" -type "SUCCESS"
    
    } catch {
        handleError -errorMessage $_.Exception.Message
    }
}

function configureMultiAdminApproval {
    try {

        # check if multi admin approval is enabled
        logMessage -message "Checking if Multi-Admin Apporval is enabled"
        $maaConfig = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; security multi-admin-verify show"
        if ($maaConfig.Value -match "Enabled" -and $maaConfig.Value -match "true") {
            $maaConfig
            logMessage -message "Multi-Admin Approval is configured and enabled" -type "SUCCESS"
        } else {
            logMessage -message "Setting Multi-Admin approval rules"
            # Define the commands to be restricted
            $rules = @(
                "cluster peer delete",
                "vserver peer delete",
                "volume snapshot policy modify",
                "volume snapshot rename",
                "vserver audit modify",
                "vserver audit delete",
                "vserver audit disable"
            )
            foreach($rule in $rules) {
                Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "security multi-admin-verify rule create -operation `"$rule`""
            }

            logMessage -message "Creating multi admin approval group for ONTAP Cluster $DESTINATION_ONTAP_CLUSTER_MGMT_IP, Group name : $MULTI_ADMIN_APPROVAL_GROUP_NAME, Users : $MULTI_ADMIN_APPROVAL_USERS, Email : $MULTI_ADMIN_APPROVAL_EMAIL"
            Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "security multi-admin-verify approval-group create -name $MULTI_ADMIN_APPROVAL_GROUP_NAME -approvers $MULTI_ADMIN_APPROVAL_USERS -email `"$MULTI_ADMIN_APPROVAL_EMAIL`""
            logMessage -message "Created multi admin approval group for ONTAP Cluster $DESTINATION_ONTAP_CLUSTER_MGMT_IP, Group name : $MULTI_ADMIN_APPROVAL_GROUP_NAME, Users : $MULTI_ADMIN_APPROVAL_USERS, Email : $MULTI_ADMIN_APPROVAL_EMAIL" -type "SUCCESS"

            logMessage -message "Enabling multi admin approval group $MULTI_ADMIN_APPROVAL_GROUP_NAME"
            Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "security multi-admin-verify modify -approval-groups $MULTI_ADMIN_APPROVAL_GROUP_NAME -required-approvers 1 -enabled true"
            logMessage -message "Enabled multi admin approval group $MULTI_ADMIN_APPROVAL_GROUP_NAME" -type "SUCCESS"

            logMessage -message "Enabling multi admin approval for ONTAP Cluster $DESTINATION_ONTAP_CLUSTER_MGMT_IP"
            Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "security multi-admin-verify modify -enabled true"
            logMessage -message "Successfully enabled multi admin approval for ONTAP Cluster $DESTINATION_ONTAP_CLUSTER_MGMT_IP" -type "SUCCESS"

            logMessage -message "Enabling multi admin approval for ONTAP Cluster $DESTINATION_ONTAP_CLUSTER_MGMT_IP"
            Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "security multi-admin-verify modify -enabled true"
            logMessage -message "Successfully enabled multi admin approval for ONTAP Cluster $DESTINATION_ONTAP_CLUSTER_MGMT_IP" -type "SUCCESS"
        }
    
    } catch {
        handleError -errorMessage $_.Exception.Message
    }
}

function additionalSecurityHardening {

    try {
        $command = "set -privilege advanced -confirmations off;security protocol modify -application telnet -enabled false;"
        logMessage -message "Disabling Telnet"
        Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command
        logMessage -message "Disabled Telnet" -type "SUCCESS"

        # removing default intercluster services
        logMessage -message "Checking if service backup-ndmp-control exists in $DESTINATION_ONTAP_CLUSTER_NAME default intercluster"
        $networkServicePolicy = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; network interface service-policy show -vserver $DESTINATION_ONTAP_CLUSTER_NAME"
        if ($networkServicePolicy.Value -match "backup-ndmp-control:") {
            $command = "set -privilege advanced -confirmations off;remove-service -vserver $DESTINATION_ONTAP_CLUSTER_NAME -policy default-intercluster -service backup-ndmp-control"
            logMessage -message "Removing service backup-ndmp-control"
            Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command  -ErrorAction Stop
            logMessage -message "Sucessfully removed service backup-ndmp-control" -type "SUCCESS"
        } else {
            logMessage -message "Service backup-ndmp-control does not exists in $DESTINATION_ONTAP_CLUSTER_NAME default management" -type "SUCCESS"
        }

        $command = "set -privilege advanced -confirmations off;network interface service-policy modify-service -vserver $DESTINATION_ONTAP_CLUSTER_NAME -policy default-intercluster -service intercluster-core -allowed-addresses $SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS;"
        logMessage -message "Restricting IP addresses $SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS for intercluster-core"
        Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command -ErrorAction Stop
        logMessage -message "Sucessfully restricted IP addresses $SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS for intercluster-core" -type "SUCCESS"

        # removing default management services
        foreach($item in $DEFAULT_MANAGEMENT_SERVICES_TO_DISABLE) {
            logMessage -message "Checking if service $item exists in $DESTINATION_ONTAP_CLUSTER_NAME default management"
            $networkServicePolicy = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; network interface service-policy show -vserver $DESTINATION_ONTAP_CLUSTER_NAME"
            if ($networkServicePolicy.Value -match "$($item):") {
                $command = "set -privilege advanced -confirmations off;remove-service -vserver $DESTINATION_ONTAP_CLUSTER_NAME -policy default-management -service $item"
                logMessage -message "Removing service $item"
                Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command -ErrorAction Stop
                logMessage -message "Sucessfully removed service $item" -type "SUCCESS"
            } else {
                logMessage -message "Service $item does not exists in $DESTINATION_ONTAP_CLUSTER_NAME default management" -type "SUCCESS"
            }
        }

        $command = "set -privilege advanced -confirmations off;network interface service-policy modify-service -vserver $DESTINATION_ONTAP_CLUSTER_NAME -policy default-management -service management-core -allowed-addresses $ALLOWED_IPS;"
        logMessage -message "Restricting IP addresses $ALLOWED_IPS for Cluster management core"
        Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command -ErrorAction Stop
        logMessage -message "Sucessfully restricted IP addresses $ALLOWED_IPS for Cluster management core" -type "SUCCESS"

        $command = "set -privilege advanced -confirmations off;network interface service-policy modify-service -vserver $DESTINATION_ONTAP_CLUSTER_NAME -policy default-management -service management-https -allowed-addresses $ALLOWED_IPS;"
        logMessage -message "Restricting IP addresses $ALLOWED_IPS for Cluster management HTTPS"
        Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command -ErrorAction Stop
        logMessage -message "Sucessfully restricted IP addresses $ALLOWED_IPS for Cluster management HTTPS" -type "SUCCESS"

        $command = "set -privilege advanced -confirmations off;network interface service-policy modify-service -vserver $DESTINATION_ONTAP_CLUSTER_NAME -policy default-management -service management-ssh -allowed-addresses $ALLOWED_IPS;"
        logMessage -message "Restricting IP addresses $ALLOWED_IPS for Cluster management SSH"
        Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command -ErrorAction Stop
        logMessage -message "Sucessfully restricted IP addresses $ALLOWED_IPS for Cluster management SSH" -type "SUCCESS"

        logMessage -message "Checking if audit logs volume audit_logs exists"
        $volume = Get-NcVol -Vserver $DESTINATION_VSERVER -Name audit_logs -ErrorAction Stop

        if($volume) {
            logMessage -message "Volume audit_logs already exists! Skipping creation"
        } else {
            # Create audit logs volume
            logMessage -message "Creating audit logs volume : audit_logs"
            New-NcVol -Name audit_logs -Aggregate $AUDIT_LOG_AGGREGATE_NAME -Size 5g -ErrorAction Stop | Select-Object -Property Name, State, TotalSize, Aggregate, Vserver
            logMessage -message "Volume audit_logs created successfully" -type "SUCCESS"
        }

        # Mount audit logs volume to path /vol/audit_logs
        logMessage -message "Creating junction path for volume audit_logs at path /vol/audit_logs for vServer $DESTINATION_VSERVER"
        Mount-NcVol -VserverContext $DESTINATION_VSERVER -Name audit_logs -JunctionPath /audit_logs | Select-Object -Property Name, -JunctionPath
        logMessage -message "Created junction path for volume audit_logs at path /vol/audit_logs for vServer $DESTINATION_VSERVER" -type "SUCCESS"
    
        logMessage -message "Enabling audit logging for vServer $DESTINATION_VSERVER at path /vol/audit_logs"
        $command = "set -privilege advanced -confirmations off;vserver audit create -vserver $DESTINATION_VSERVER -destination /audit_logs -format xml;"
        Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command $command -ErrorAction Stop
        logMessage -message "Successfully enabled audit logging for vServer $DESTINATION_VSERVER at path /vol/audit_logs"
    
    } catch {
        handleError -errorMessage $_.Exception.Message
    }
}

function analyze {

    for($i = 0; $i -lt $DESTINATION_VOLUME_NAMES.Length; $i++) {
        try {
            # checking if volume is of type snaplock compliance
            logMessage -message "Checking if SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i]) exists in vServer $DESTINATION_VSERVER"
            $volume = Get-NcVol -Vserver $DESTINATION_VSERVER -Volume $DESTINATION_VOLUME_NAMES[$i] | Select-Object -Property Name, State, TotalSize, Aggregate, Vserver, Snaplock | Where-Object { $_.Snaplock.Type -eq "compliance" }
            if($volume) {
                $volume
                logMessage -message "SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i]) exists in vServer $DESTINATION_VSERVER" -type "SUCCESS"
            } else {
                handleError -errorMessage "SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i]) does not exist in vServer $DESTINATION_VSERVER. Recommendation : Run the script with SCRIPT_MODE `"configure`" to create and configure the Cyber Vault SnapLock Compliance volume"
            }

            # checking snapmirror relationship
            logMessage -message "Checking if SnapMirror relationship exists between source volume $($SOURCE_VOLUME_NAMES[$i]) and destination SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i])"
            $snapmirror = Get-NcSnapmirror | Select-Object SourceCluster, SourceLocation, DestinationCluster, DestinationLocation, Status, MirrorState | Where-Object { $_.SourceCluster -eq $SOURCE_ONTAP_CLUSTER_NAME -and $_.SourceLocation -eq "$($SOURCE_VSERVER):$($SOURCE_VOLUME_NAMES[$i])" -and $_.DestinationCluster -eq $DESTINATION_ONTAP_CLUSTER_NAME -and $_.DestinationLocation -eq "$($DESTINATION_VSERVER):$($DESTINATION_VOLUME_NAMES[$i])" -and $_.Status -eq "snapmirrored" }
            if($snapmirror) {
                $snapmirror
                logMessage -message "SnapMirror relationship successfully configured and in healthy state" -type "SUCCESS"
            } else {
                handleError -errorMessage "SnapMirror relationship does not exist between the source volume $($SOURCE_VOLUME_NAMES[$i]) and destination SnapLock Compliance volume $($DESTINATION_VOLUME_NAMES[$i]) (or) SnapMirror status uninitialized/unhealthy. Recommendation : Run the script with SCRIPT_MODE `"configure`" to create and configure the Cyber Vault SnapLock Compliance volume and configure the SnapMirror relationship"
            }
        }
        catch {
            handleError -errorMessage $_.Exception.Message
        }  
    }
    
    try {

        # checking NFS service is disabled
        logMessage -message "Checking if NFS service is disabled on vServer $DESTINATION_VSERVER"
        $nfsService = Get-NcNfsService 
        if($nfsService) {
            handleError -errorMessage "NFS service running on vServer $DESTINATION_VSERVER. Recommendation : Run the script with SCRIPT_MODE `"configure`" to disable NFS on vServer $DESTINATION_VSERVER"
        } else {
            logMessage -message "NFS service is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }

        # checking CIFS/SMB server is disabled
        logMessage -message "Checking if CIFS/SMB server is disabled on vServer $DESTINATION_VSERVER"
        $cifsServer = Get-NcCifsServer 
        if($cifsServer) {
            handleError -errorMessage "CIFS/SMB server running on vServer $DESTINATION_VSERVER. Recommendation : Run the script with SCRIPT_MODE `"configure`" to disable CIFS/SMB on vServer $DESTINATION_VSERVER"
        } else {
            logMessage -message "CIFS/SMB server is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }

        # checking iSCSI service is disabled
        logMessage -message "Checking if iSCSI service is disabled on vServer $DESTINATION_VSERVER"
        $iscsiService = Get-NcIscsiService 
        if($iscsiService) {
            handleError -errorMessage "iSCSI service running on vServer $DESTINATION_VSERVER. Recommendation : Run the script with SCRIPT_MODE `"configure`" to disable iSCSI on vServer $DESTINATION_VSERVER"
        } else {
            logMessage -message "iSCSI service is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }

        # checking FCP service is disabled
        logMessage -message "Checking if FCP service is disabled on vServer $DESTINATION_VSERVER"
        $fcpService = Get-NcFcpService 
        if($fcpService) {
            handleError -errorMessage "FCP service running on vServer $DESTINATION_VSERVER. Recommendation : Run the script with SCRIPT_MODE `"configure`" to disable FCP on vServer $DESTINATION_VSERVER"
        } else {
            logMessage -message "FCP service is disabled on vServer $DESTINATION_VSERVER" -type "SUCCESS"
        }

        # checking if all data lifs are disabled on vServer
        logMessage -message "Finding all data lifs on vServer : $DESTINATION_VSERVER"
        $dataLifs = Get-NcNetInterface -Vserver $DESTINATION_VSERVER | Where-Object { $_.Role -contains "data_core" }
        $dataLifs | Select-Object -Property InterfaceName, OpStatus, DataProtocols, Vserver, Address

        logMessage -message "Cheking if all data lifs are diabled for vServer : $DESTINATION_VSERVER"
        # Disable the filtered data LIFs
        foreach ($lif in $dataLifs) {
            $checkLif = Get-NcNetInterface -Vserver $DESTINATION_VSERVER -Name $lif.InterfaceName | Where-Object { $_.OpStatus -eq "down" }
            if($checkLif) {
                logMessage -message "Data lif $($lif.InterfaceName) disabled for vServer $DESTINATION_VSERVER" -type "SUCCESS"
            } else {
                handleError -errorMessage "Data lif $($lif.InterfaceName) is enabled. Recommendation : Run the script with SCRIPT_MODE `"configure`" to disable Data lifs for vServer $DESTINATION_VSERVER"
            }
        }
        logMessage -message "All data lifs are disabled for vServer : $DESTINATION_VSERVER" -type "SUCCESS"

        # check if multi admin approval is enabled
        logMessage -message "Checking if Multi-Admin Apporval is enabled"
        $maaConfig = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; security multi-admin-verify show"
        if ($maaConfig.Value -match "Enabled" -and $maaConfig.Value -match "true") {
            $maaConfig
            logMessage -message "Multi-Admin Approval is configured and enabled" -type "SUCCESS"
        } else {
            handleError -errorMessage "Multi-Admin Approval is not configured or not enabled.. Recommendation : Run the script with SCRIPT_MODE `"configure`" to enable and configure Multi-Admin Approval"
        }

        # check if telnet is disabled
        logMessage -message "Checking if telent is diabled"
        $telnetConfig = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; security protocol show -application telnet"
        if ($telnetConfig.Value -match "enabled" -and $telnetConfig.Value -match "false") {
            logMessage -message "Telnet is disabled" -type "SUCCESS"
        } else {
            handleError -errorMessage "Telnet is enabled. Recommendation : Run the script with SCRIPT_MODE `"configure`" to disable telnet"
        }

        # check if intercluster-core is restricted to allowed Intercluster IP addresses
        logMessage -message "Checking if intercluster-core is restricted to Source Intercluster IPs $SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS"
        $networkServicePolicy = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; network interface service-policy show -vserver $DESTINATION_ONTAP_CLUSTER_NAME"
        if ($networkServicePolicy.Value -match "intercluster-core: $($SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS)") {
            logMessage -message " intercluster-core is restricted to Source Intercluster IPs $SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS" -type "SUCCESS"
        } else {
            handleError -errorMessage " intercluster-core is not restricted to Source Intercluster IPs $SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS. Recommendation : Run the script with SCRIPT_MODE `"configure`" to restrict"
        }

        logMessage -message "Checking if service backup-ndmp-control exists in $DESTINATION_ONTAP_CLUSTER_NAME default intercluster"
        $networkServicePolicy = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; network interface service-policy show -vserver $DESTINATION_ONTAP_CLUSTER_NAME"
        if ($networkServicePolicy.Value -match "backup-ndmp-control:") {
            handleError -errorMessage "Service $item exists in $DESTINATION_ONTAP_CLUSTER_NAME default management. Recommendation : Run the script with SCRIPT_MODE `"configure`" to remove service"
        } else {
            logMessage -message "Service $item does not exists in $DESTINATION_ONTAP_CLUSTER_NAME default management"  -type "SUCCESS"
        }

        foreach($item in $DEFAULT_MANAGEMENT_SERVICES_TO_DISABLE) {
            logMessage -message "Checking if service $item exists in $DESTINATION_ONTAP_CLUSTER_NAME default management"
            $networkServicePolicy = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; network interface service-policy show -vserver $DESTINATION_ONTAP_CLUSTER_NAME"
            if ($networkServicePolicy.Value -match "$($item):") {
                handleError -errorMessage "Service $item does not exists in $DESTINATION_ONTAP_CLUSTER_NAME default management. Recommendation : Run the script with SCRIPT_MODE `"configure`" to remove service"
            } else {
                logMessage -message "Service $item does not exists in $DESTINATION_ONTAP_CLUSTER_NAME default management"  -type "SUCCESS"
            }
        }

         # check if network https is restricted to allowed IP addresses
         logMessage -message "Checking if HTTPS is restricted to allowed IP addresses $ALLOWED_IPS"
         $networkServicePolicy = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; network interface service-policy show -vserver $DESTINATION_ONTAP_CLUSTER_NAME"
         if ($networkServicePolicy.Value -match "management-https: $($ALLOWED_IPS)") {
             logMessage -message "HTTPS is restricted to allowed IP addresses $ALLOWED_IPS" -type "SUCCESS"
         } else {
             handleError -errorMessage "HTTPS is not restricted to allowed IP addresses $ALLOWED_IPS. Recommendation : Run the script with SCRIPT_MODE `"configure`" to restrict allowed IP addresses for HTTPS management"
         }
 
         # check if network ssh is restricted to allowed IP addresses
         logMessage -message "Checking if SSH is restricted to allowed IP addresses $ALLOWED_IPS"
         $networkServicePolicy = Invoke-NcSsh -Name $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $DESTINATION_ONTAP_CREDS -Command "set -privilege advanced; network interface service-policy show -vserver $DESTINATION_ONTAP_CLUSTER_NAME"
         if ($networkServicePolicy.Value -match "management-ssh: $($ALLOWED_IPS)") {
             logMessage -message "SSH is restricted to allowed IP addresses $ALLOWED_IPS" -type "SUCCESS"
         } else {
             handleError -errorMessage "SSH is not restricted to allowed IP addresses $ALLOWED_IPS. Recommendation : Run the script with SCRIPT_MODE `"configure`" to restrict allowed IP addresses for SSH management"
         }
    }
    catch {
        handleError -errorMessage $_.Exception.Message
    }
}

function Get-AdjustedTime {
    param (
        [datetime]$time,
        [int]$adjustment
    )
    return $time.AddMinutes($adjustment)
}

function configureCron {

    try {
        # Get the directory of the current script
        $scriptDirectory = $PSScriptRoot

        $credentialPath = Join-Path -Path $scriptDirectory -ChildPath "Credential.xml"

        $DESTINATION_ONTAP_CREDS | Export-Clixml -Path $credentialPath

        # Set permissions to allow SYSTEM account to read the file
        $acl = Get-Acl $scriptDirectory
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "Read", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl $scriptDirectory $acl

        # Combine the script directory with the filename to get the absolute path
        $snapmirrorResumeScriptPath = Join-Path -Path $scriptDirectory -ChildPath "snapmirror-resume.ps1"
        $snapmirrorQuiesceScriptPath = Join-Path -Path $scriptDirectory -ChildPath "snapmirror-quiesce.ps1"

        # Define the task name
        $snapmirrorResumeTaskName = "SnapmirrorResumeTask"
        $snapmirrorQuiesceTaskName = "SnapmirrorQuiesceTask"

        # Convert the array to a JSON string
        $jsonDestinationVolumeNames = $DESTINATION_VOLUME_NAMES | ConvertTo-Json -Compress

        # Define the action to run the PowerShell script
        $snapmirrorResumeAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$snapmirrorResumeScriptPath`" -DESTINATION_ONTAP_CLUSTER_MGMT_IP `"$DESTINATION_ONTAP_CLUSTER_MGMT_IP`" -DESTINATION_VSERVER `"$DESTINATION_VSERVER`" -DESTINATION_VOLUME_NAMES $jsonDestinationVolumeNames"
        $snapmirrorQuiesceAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$snapmirrorQuiesceScriptPath`" -DESTINATION_ONTAP_CLUSTER_MGMT_IP `"$DESTINATION_ONTAP_CLUSTER_MGMT_IP`" -DESTINATION_VSERVER $DESTINATION_VSERVER -DESTINATION_VOLUME_NAMES $jsonDestinationVolumeNames"

        # Define the principal (user) for the task
        $principal = New-ScheduledTaskPrincipal -UserId $DOMAIN_ADMINISTRATOR_USERNAME -LogonType ServiceAccount -RunLevel Highest

        # Register tasks based on the schedule
    if ($CRON_SCHEDULE -eq "5min") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule 5 min"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:00") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:00") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs every 5 minutes adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs every 5 minutes adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule 5 min" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "10min") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule 10 min"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:00") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:00") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs every 10 minutes adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs every 10 minutes adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule 10 min" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "20min") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule 20 min"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:00") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Minutes 20) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:00") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Minutes 20) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs every 20 minutes adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs every 20 minutes adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule 20 min" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "hourly") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule hourly"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:05") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:05") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs hourly adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs hourly adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule hourly" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "12-hourly") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule 12-hourly"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:15") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Hours 12) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:15") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Hours 12) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs every 12 hours adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs every 12 hours adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule 12-hourly" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "6-hourly") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule 6-hourly"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:15") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:15") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs every 6 hours adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs every 6 hours adjusted by afterRun" -ErrorAction Stop
    logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule 6-hourly" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "8hour") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule 8-hourly"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "02:15") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Hours 8) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "02:15") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Hours 8) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs every 8 hours adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs every 8 hours adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule 8-hourly" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "daily") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule daily"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:10") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Days 1) -RepetitionDuration (New-TimeSpan -Days 1)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "00:10") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Days 1) -RepetitionDuration (New-TimeSpan -Days 1)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs daily adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs daily adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule daily" -type "SUCCESS"
    } elseif ($CRON_SCHEDULE -eq "monthly") {
        logMessage -message "Configuring scheduled tasks for SnapMirror resume, quiesce for schedule monthly"
        $triggerBefore = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "01:00:20") -adjustment $SNAPMIRROR_RESUME_MINUTES_BEFORE_SM) -RepetitionInterval (New-TimeSpan -Days 30) -RepetitionDuration (New-TimeSpan -Days 365)
        $triggerAfter = New-ScheduledTaskTrigger -Once -At (Get-AdjustedTime -time (Get-Date "01:00:20") -adjustment $SNAPMIRROR_QUIESCE_MINUTES_POST_SM) -RepetitionInterval (New-TimeSpan -Days 30) -RepetitionDuration (New-TimeSpan -Days 365)
        Register-ScheduledTask -Action $snapmirrorResumeAction -Trigger $triggerBefore -Principal $principal -TaskName $snapmirrorResumeTaskName -Description "Runs monthly adjusted by beforeRun" -ErrorAction Stop
        Register-ScheduledTask -Action $snapmirrorQuiesceAction -Trigger $triggerAfter -Principal $principal -TaskName $snapmirrorQuiesceTaskName -Description "Runs monthly adjusted by afterRun" -ErrorAction Stop
        logMessage -message "Successfully configured scheduled tasks for SnapMirror resume, quiesce for schedule monthly" -type "SUCCESS"
    }
    }
    catch {
        handleError -errorMessage $_.Exception.Message
    }
}

main