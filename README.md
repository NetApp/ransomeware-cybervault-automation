# Ransomeware Cybervault Automation

In today's digital landscape, safeguarding an organization's critical data assets is not just a best practice - it is a business imperative. Cyber threats are evolving at an unprecedented pace, and traditional data protection measures are no longer sufficient to keep sensitive information secure. That is where a cyber vault comes in. NetApp's cutting-edge ONTAP based solution combines advanced air-gapping techniques with robust data protection measures to create an impenetrable barrier against cyber threats. By isolating the most valuable data with secure hardening technology, a cyber vault minimizes the attack surface so that the most critical data remains confidential, intact, and readily available when needed.

A cyber vault is a secure storage facility that consists of multiple layers of protection, such as firewalls, networking, and storage. These components safeguard vital recovery data necessary for crucial business operations. The cyber vault's components regularly synchronize with the essential production data based on the vault policy, but otherwise remain inaccessible. This isolated and disconnected setup ensures that in the event of a cyber-attack compromising the production environment, a reliable and final recovery can easily be carried out from the cyber vault.

NetApp enables easy creation of an air-gap for cyber vault by configuring the network, disabling LIFs, updating firewall rules, and isolating the system from external networks and the internet. This robust approach effectively disconnects the system from external networks and the internet, providing unparalleled protection against remote cyber-attacks and unauthorized access attempts, making the system immune to network-based threats and intrusion.

Combining this with SnapLock Compliance protection, data cannot be modified or deleted, not even by ONTAP administrators or NetApp Support. SnapLock is regularly audited against SEC and FINRA regulations, ensuring that data resiliency meets these stringent WORM and data retention regulations of the banking industry. NetApp is the only enterprise storage validated by NSA CSfC to store top-secret data.

Air gapped ONTAP cyber vault with immutable and indelible SnapLock copies

![architecture-1](./assets/architecture-1.png)

This document describes the automated configuration of NetApp's cyber vault for on-premises ONTAP storage to another designated ONTAP storage with immutable snapshots adding an extra layer of protection from increasing cyber-attacks for rapid recovery. As part of this architecture, the entire configuration is applied as per ONTAP best practices. The last section has instructions for performing a recovery in case of an attack.

Note : The same solution is applicable to create the designated cyber vault in AWS using FSx ONTAP.

For detailed documentation, check [high-level-steps-to-create-a-ontap-cyber-vault](https://docs.netapp.com/us-en/netapp-solutions/cyber-vault/ontap-cyber-vault-powershell-overview.html#high-level-steps-to-create-a-ontap-cyber-vault)

## High level steps to create a ONTAP cyber vault
- Create peering relationship
    - Production site using ONTAP storage is peered with designated cyber vault ONTAP storage

- Create SnapLock Compliance volume

- Setup SnapMirror relationship and rule to set label
    - SnapMirror relationship and appropriate schedules are configured

- Set retentions prior to initiating the SnapMirror (vault) transfer
    - Retention lock is applied on the copied data, which further prevents the data from any insider or data failure. Using this, the data cannot be deleted before the retention period expires
    - Organizations can keep this data for few weeks/months depending upon their requirements

-   Initialize the SnapMirror relationship based on labels
    - Initial seeding and incremental forever transfer happens based on the SnapMirror schedule
    - Data is protected (immutable and indelible) with SnapLock compliance, and that the data is available for recovery

-   Implement strict data transfer controls
    -   Cyber vault is unlocked for a limited period with data from the production site and is synced with data in the vault. Once the transfer is complete, the connection is disconnected, closed, and locked again

- Quick recovery
    - If primary is affected in the production site, the data from the cyber vault is securely recovered to the original production or to another chosen environment

![architecture-2](./assets/architecture-2.png)

## Solution components
NetApp ONTAP running 9.15.1 on source and destination clusters.

ONTAP One: NetApp ONTAP's all-in-one license.

Capabilities used from ONTAP One license:

- SnapLock Compliance

- SnapMirror

- All hardening capabilities exposed by ONTAP

- Multi-admin verification

- Separate RBAC credentials for cyber vault

Note : All ONTAP unified physical arrays can be used for a cyber vault, however AFF C-series capacity based flash systems and FAS hybrid flash systems are the most cost-effective ideal platforms for this purpose. Please consult the ONTAP cyber vault sizing for sizing guidance.

## License
By accessing, downloading, installing or using the content in this repository, you agree the terms of the License laid out in License file.

Note that there are certain restrictions around producing and/or sharing any derivative works with the content in this repository. Please make sure you read the terms of the License before using the content. If you do not agree to all of the terms, do not access, download or use the content in this repository.

Copyright: 2024 NetApp Inc.

## Deployment Guide
There are 2 deployment options which are with Ansible and Powershell. The deployment steps are mentioned below

### Ansible Execution
#### Prerequisites:
- Ansible installed. This script was tested using "ansible [core 2.15.0]"
- NetApp ONTAP Ansible collection installed. This script was tested using "netapp.ontap collection (version 22.13.0)"
        ```
        ansible-galaxy collection install netapp.ontap
        ```
#### Step 1 : Clone the GitHub repository
Clone the GitHub repository in your local system
```
# git clone https://github.com/NetApp/ransomeware-cybervault-automation.git
```

#### Step 2: Go to "ansible" directory
```
# cd ansible
```

#### Step 3: Configure "vars.yml". Sample file is already provided, update values as needed
```
DESTINATION_ONTAP_CLUSTER_MGMT_IP: "10.10.10.101"
VALIDATE_CERTS: false
DESTINATION_ONTAP_CLUSTER_NAME: "NTAP915_Dest"
SOURCE_VSERVER: "svm_NFS"
SOURCE_VOLUME_NAMES:
  - "Demo_RP_Vol01"
  - "Demo_RP_Vol02"
DESTINATION_VSERVER: "SVM_File"
DESTINATION_VOLUME_NAMES:
  - "Demo_RP_Vol01_CyberVault"
  - "Demo_RP_Vol02_CyberVault"
DESTINATION_AGGREGATE_NAMES:
  - "NTAP915_Dest_01_VM_DISK_1"
  - "NTAP915_Dest_01_VM_DISK_1"
DESTINATION_VOLUME_SIZES_GB:
  - "1"
  - "1"
SNAPLOCK_MIN_RETENTION: "15minutes"
SNAPLOCK_MAX_RETENTION: "30minutes"
SNAPMIRROR_SCHEDULE: "5min"
SNAPMIRROR_POLICY: "XDPDefault"
# List of management services to disable
DEFAULT_MANAGEMENT_SERVICES_TO_DISABLE:
  - management-snmp-server
  - management-ntp-server
  - management-log-forwarding
  - management-nis-client
  - management-ad-client
  - management-autosupport
  - management-ems
  - management-ntp-client
  - management-dns-client
  - management-ldap-client
  - management-http
# ONTAP connection details (adjust as needed)
SOURCE_ONTAP_ALLOWED_INTERCLUSTER_IPS:
  - "172.21.166.101/32"
  - "172.21.166.102/32"
ALLOWED_IPS:
  - "10.10.10.11/32"
  - "10.10.10.12/32"
AUDIT_LOGS_VOLUME_SIZE_GB: "5"
AUDIT_LOGS_AGGREGATE_NAME: "NTAP915_Dest_01_VM_DISK_1"
# Multi-Admin Approval Variables
MULTI_ADMIN_APPROVAL_GROUP_NAME: "vaultadmins"
MULTI_ADMIN_APPROVAL_USERS: 
  - "vaultadmin1"
  - "vaultadmin2"
MULTI_ADMIN_APPROVAL_EMAIL: "vaultadmins@netapp.com"
```

#### Step 4: Configure "credentials.yml" and encrypt using ansible-vault. Sample file is already provided, update values as needed
```
DESTINATION_ONTAP_CREDS:
  username: ""
  password: ""
```
```
# ansible-vault encrypt credentials.yml
```

#### Step 5: Execute "playbook.yml" using ansible-playbook. Use the passphrase used to encrypt the credentials.yml when prompted
```
# ansible-playbook playbook.yml --ask-vault-pass
```

### Powershell Execution
#### Step 1 : Clone the GitHub repository
Clone the GitHub repository in your local system
```
# git clone https://github.com/NetApp/ransomeware-cybervault-automation.git
```

#### Step 2: Go to "powershell" directory
```
# cd powershell
```

#### Step 3 : Run powershell script "cybervault.ps1" with required inputs/parameters and specify the script mode to implement different functionalities
Example :
```
./cybervault.ps1 `
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
    -DOMAIN_ADMINISTRATOR_USERNAME "administrator@demo.netapp.com" `
    -SCRIPT_MODE configure
```
Note : Script to be executed with Administrator (or) other account with similar privileges

## Author Information

- [Pradeep Kumar](mailto:pradeep.kumar@netapp.com) - NetApp Solutions Engineering Team
- [Niyaz Mohamed](mailto:niyaz.mohamed@netapp.com) - NetApp Solutions Engineering Team
