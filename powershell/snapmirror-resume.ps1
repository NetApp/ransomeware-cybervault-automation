param (
    [Parameter(Mandatory=$True, HelpMessage="Destination ONTAP Cluster IP Address")]
    [String]$DESTINATION_ONTAP_CLUSTER_MGMT_IP,
    [Parameter(Mandatory=$True, HelpMessage="Destination VServer Name")]
    [String]$DESTINATION_VSERVER,
    [Parameter(Mandatory=$True, HelpMessage="Destination Volume Name")]
    [String[]]$DESTINATION_VOLUME_NAMES
)

[string]$ontapModuleName = "NetApp.ONTAP"

function main {
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
    
        # Create the snapmirror-resume subfolder within the logs folder
        $snapmirrorResumeFolderPath = Join-Path -Path $logsFolderPath -ChildPath "snapmirror-resume"
        if (-not (Test-Path -Path $snapmirrorResumeFolderPath)) {
            New-Item -Path $snapmirrorResumeFolderPath -ItemType Directory | Out-Null
        }
    
        # Generate the log file name based on the variable value and the current timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "logs`_$timestamp.log"
        $global:logFilePath = Join-Path -Path $snapmirrorResumeFolderPath -ChildPath $logFileName
    
        # Log the creation of the log file
        Add-Content -Path $global:logFilePath -Value "[$(Get-Date)] Log file created at $global:logFilePath"

        $credentialFilePath = Join-Path -Path $scriptPath -ChildPath "Credential.xml"
        # Log the paths being used
        Add-Content -Path $global:logFilePath -Value "[$(Get-Date)] Log file path: $global:logFilePath"
        Add-Content -Path $global:logFilePath -Value "[$(Get-Date)] Credential file path: $credentialFilePath"

        # Import the credential object from the encrypted file
        $credential = Import-Clixml -Path $credentialFilePath
    }
    catch {
        handleError -errorMessage $_.Exception.Message
    }

    importModules

    connectONTAP -ClusterMgmtIP $DESTINATION_ONTAP_CLUSTER_MGMT_IP -Credential $credential -VserverName $DESTINATION_VSERVER

    snapmirrorResume
}

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
function snapmirrorResume {

    # Add debugging information
    logMessage -message "Initial DESTINATION_VOLUME_NAMES: $($DESTINATION_VOLUME_NAMES -join ', ')"

    # Print the type of DESTINATION_VOLUME_NAMES
    $variableType = $DESTINATION_VOLUME_NAMES.GetType().FullName
    logMessage -message "The initial type of DESTINATION_VOLUME_NAMES is: $variableType"

    # Check if the array contains a single string element that looks like an array
    if ($DESTINATION_VOLUME_NAMES.Length -eq 1 -and $DESTINATION_VOLUME_NAMES[0] -match '^\[.*\]$') {
        logMessage -message "DESTINATION_VOLUME_NAMES contains a single string element that looks like an array"

        # Remove the square brackets and split the string into an array
        $DESTINATION_VOLUME_NAMES = $DESTINATION_VOLUME_NAMES[0].Trim('[', ']').Split(',') | ForEach-Object { $_.Trim() }

        logMessage -message "Converted DESTINATION_VOLUME_NAMES to array: $($DESTINATION_VOLUME_NAMES -join ', ')"
    } else {
        logMessage -message "DESTINATION_VOLUME_NAMES does not need conversion"
    }

    # Print the type of DESTINATION_VOLUME_NAMES after conversion
    $variableType = $DESTINATION_VOLUME_NAMES.GetType().FullName
    logMessage -message "The type of DESTINATION_VOLUME_NAMES after conversion is: $variableType"
    
    logMessage -message "Destination Volume Names: $($DESTINATION_VOLUME_NAMES -join ', ')"
    logMessage -message "Number of Destination Volumes: $($DESTINATION_VOLUME_NAMES.Length)"

    for($i = 0; $i -lt $DESTINATION_VOLUME_NAMES.Length; $i++) {
        try {
            logMessage -message "Resuming SnapMirror relationship $($DESTINATION_VSERVER):$($DESTINATION_VOLUME_NAMES[$i]) at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Invoke-NcSnapmirrorResume -DestinationLocation "$($DESTINATION_VSERVER):$($DESTINATION_VOLUME_NAMES[$i])" -ErrorAction Stop
            logMessage -message "Successfully resumed SnapMirror relationship $($DESTINATION_VSERVER):$($DESTINATION_VOLUME_NAMES[$i])" -type "SUCCESS"
        }
        catch {
            handleError -errorMessage $_.Exception.Message
        }  
    }
}

main