# Remote PEM / PKCS12
## orchestrator

The remote PEM / PKCS12 Orchestrator allows for the remote management of PEM and PKCS12 based certificate stores. Discovery, Inventory, and Management functions are supported. The orchestrator performs operations by issuing remote commands over SSH to Linux based systems and via WinRM to Windows based systems.

<!-- add integration specific information below -->
*** 

## Use Cases

The PEM_PKCS12 Windows Orchestrator implements the following capabilities:

1. Create - Create either a PEM or PKCS12 certificate store.
2. Discovery - Discover all PEM or PKCS12 certificate stores in a set of paths based on optional list of file extensions and partial name matching.
3. Inventory - Return all certificates for a defined certificate store.
4. Management (Add) - Add a certificate to a defined certificate store.
5. Management (Remove) - Remove a certificate from a defined certificate store.

The PEM_PKCS12 Windows Orchestrator supports the following types of certificate stores:

1. PEM trust stores (multiple public (most likely CA) certificates with no private keys).
2. PEM certificate stores containing one public certificate and one private key.
3. PEM certificate stores containing one public certificate and an external private key stored in a separate file.
4. PKCS12 certificate stores containing one certificate with a private key.

## Versioning

The version number of a the PEM_PKCS12 Windows Orchestrator can be verified by right clicking on the PEMStoreSSH.dll file in the Plugins installation folder, selecting Properties, and then clicking on the Details tab.

## Keyfactor Version Supported

The PEM_PKCS12 Windows Orchestrator has been tested against Keyfactor version 8.1.1 but should work against earlier or later versions.

## Security Considerations

**For Linux orchestrated servers:**
1. The PEM-PKCS12 AnyAgent makes use of a few common Linux commands. If the credentials you will be connecting with will need elevated access to run these commands, you must set the id up as a sudoer with no password necessary and set the config.json "UseSudo" value to "Y" (See Section 4 regarding the config.json file). The full list of these commands below:
    * echo
    * grep
    * find
2. The PEM_PKCS12 AnyAgent makes use of SFTP to transfer files to and from the orchestrated server.  SFTP will not mske use of sudo, so all folders containing certificate stores will need to allow SFTP file transfer.  If this is not possible, set the values in the config.json apprpriately to use an alternative upload/download folder that does have SFTP file transfer (See Section 4 regarding the config.json file).

**For Windows orchestrated servers:**
1. Make sure that WinRM is set up on the orchestrated server and that the WinRM port is part of the certificate store path when setting up your certificate stores (See Section 3a below). 

## PEM_PKCS12 Orchestrator Configuration

**1. Create the New Certificate Store Type for the New PEM_PKCS12 Orchestrator**

In Keyfactor Command create a new Certificate Store Type similar to the one below:

![](Images/Image1.png)

- **Name** – Required. The display name of the new Certificate Store Type
- **Short Name** – Required. **MUST** be &quot;PEM-SSH&quot;
- **Needs Server, Blueprint Allowed, Requires Store Password, Supports Entry Password** – All checked/unchecked as shown
- **Supports Custom Alias** – Required. Select Forbidden. Aliases are not used for PEM and PKCS12 stores.
- **Use PowerShell** – Unchecked
- **Store PathType** – Freeform (user will enter the the location of the store)
- **Private Keys** – Optional (a certificate in a PEM/PKCS12 Keystore may or may not contain a private key)
- **PFX Password Style** – Select Custom.
- **Job Types** – Discovery, Inventory, Add, and Remove are the 3 job types implemented by this Orchestrator
- **Parameters** – Three custom parameters are used for this store type. They are:
  - **Type (Name MUST be &quot;type&quot;):**

![](Images/Image2.png)

  - **Separate Private Key File (Name MUST be &quot;separatePrivateKey:** Only applicable for Type=PEM stores, select if the store will contain a private key but the private key will reside in an separate file somewhere else on the server

![](Images/Image3.png)

  - **Path to Private Key File (Name MUST be &quot;pathToPrivateKey&quot;):** Only applicable for Type=PEM stores. If the PEM certificate store has a separate private key file, this is the FULL PATH and file name where the private key resides. File paths on Linux servers will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:\&quot;.

![](Images/Image4.png)

  - **Contains Single Certificate (Name MUST be &quot;isSingleCertificateStore&quot;):** Optional parameter, default value 'False'.  If set to 'True' this certificate store will be managed with the assumption that only one certificate can exist in the store.  All Managment-Add jobs against this store will completely replace the contents of the store with the added certificate, assuming overwrite is set to 'True' for the job.  If overwrite is not selected ('False'), the Management-Add job will complete with an error saying a certificate already exists.  No alias/thumbprint matching will be done when adding/renewing a certificate when this value is set to 'True'.

![](Images/Image14.png)


**2. Register the PEM_PKCS12 Orchestrator with Keyfactor**

Open the Keyfactor Windows Agent Configuration Wizard and perform the tasks as illustrated below:

![](Images/Image5.png)

- Click **\<Next\>**

![](Images/Image6.png)

- If you have configured the agent service previously, you should be able to skip to just click **\<Next\>.** Otherwise, enter the service account Username and Password you wish to run the Keyfactor Windows Agent Service under, click **\<Update Windows Service Account\>** and click **\<Next\>.**

![](Images/Image7.png)

- If you have configured the agent service previously, you should be able to skip to just re-enter the password to the service account the agent service will run under, click **\<Validate Keyfactor Connection\>** and then **\<Next\>.**

![](Images/Image8.png)

- Select the agent you are adding capabilities for (in this case, PEM SSH, and also select the specific capabilities (Discovery, Inventory and Management in this example). Click **\<Next\>**.

![](Images/Image9.png)

- For agent configuration purposes, this screen can be skipped by clicking **\<Next\>**.

![](Images/Image10.png)

- For each Orchestrator implementation, check **Load assemblies containing extension modules from other location** , browse to the location of the compiled Orchestrator dll, and click **\<Validate Capabilities\>**. Once all Orchestrators have been validated, click **\<Apply Configuration\>**.

![](Images/Image11.png)

- If the Keyfactor Agent Configuration Wizard configured everything correctly, you should see the dialog above.

**3a. (Optional) Create a PEM_PKCS12 Certificate Store within Keyfactor Command**

If you choose to manually create a PEM_PKCS12 store In Keyfactor Command rather than running a Discovery job to automatically find the store, you can navigate to Certificate Locations =\> Certificate Stores within Keyfactor Command to add the store. Below are the values that should be entered.

![](Images/Image12.png)

- **Category** – Required. The PEM SSH type name must be selected.
- **Container** – Optional. Select a container if utilized.
- **Client Machine &amp; Credentials** – Required. The server name or IP Address and login credentials for the server where the Certificate Store is located.When setting up a Windows server, the format of the machine name must be – [http://_ServerName_:5985](http://ServerName:5985/), where &quot;5985&quot; is the WinRM port number. 5985 is the standard, but if your organization uses a different, use that.
- **Store Path** – Required. The FULL PATH and file name of the PEM/PKCS12 store being managed. File paths on Linux servers will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:\&quot;.
- **Type** – Select either PEM or PKCS12
- **Separate Private Key File** – Check if the store has a separate private key file.
- **Path to Private Key File** – If Separate Private Key File is checked, enter the FULL PATH to the private key file. File paths on Linux servers will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:&quot;.
- **Orchestrator** – Select the orchestrator you wish to use to manage this store
- **Store Password** – Set the store password or set no password after clicking the supplied button.  If a store password is entered, this value will be used when encrypting private keys that get written to the certificate store during certificate add operations.  Selecting "No Password" will cause an unencrypted private key to be saved during add operations.
- **Inventory Schedule** – Set a schedule for running Inventory jobs or none, if you choose not to schedule Inventory at this time.

**3b. (Optional) Schedule a PEM_PKCS12 Discovery Job**

Rather than manually creating PEM_PKCS12 certificate stores, you can schedule a Discovery job to search an orchestrated server and find them.

First, in Keyfactor Command navigate to Certificate Locations =\> Certificate Stores. Select the Discover tab and then the Schedule button. Complete the dialog and click Done to schedule.

![](Images/Image13.png)

- **Category** – Required. The PEM SSH type name must be selected.
- **Orchestrator** – Select the orchestrator you wish to use to manage this store
- **Client Machine &amp; Credentials** – Required. The server name or IP Address and login credentials for the server where the Certificate Store is located. When setting up a Windows server, the format of the machine name must be – [http://_ServerName_:5985](http://ServerName:5985/), where &quot;5985&quot; is the WinRM port number. 5985 is the standard, but if your organization uses a different, use that.
- **When** – Required. The date and time when you would like this to execute.
- **Directories to search** – Required. A comma delimited list of the FULL PATHs and file names where you would like to recursively search for PEM/PKCS12 stores. File paths on Linux servers will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:\\&quot;.  Entering the string "fullscan" when Discovering against a Windows server will automatically do a recursive search on ALL local drives on the server.
- **Directories to ignore** – Optional. A comma delimited list of the FULL PATHs that should be recursively ignored when searching for PEM/PKCS12 stores. Linux file paths will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:\\&quot;.
- **Extensions** – Optional but suggested. A comma delimited list of the file extensions (no leading &quot;.&quot; should be included) the job should search for. If not included, only files in the searched paths that have **no file extension** will be returned. If providing a list of extensions, using &quot;noext&quot; as one of the extensions will also return files with no file extension. For example, providing an Extensions list of &quot;pem, noext&quot; would return all file locations within the paths being searched with a file extension of &quot;pem&quot; and files with no extensions.
- **File name patterns to match** – Optional. A comma delimited list of full or partial file names (NOT including extension) to match on.  Use "\*" as a wildcard for begins with or ends with.  Example: entering "ab\*, \*cd\*, \*ef, ghij" will return all stores with names that _**begin with**_ "ab" AND stores with names that _**contain**_ "cd" AND stores with names _**ending in**_ "ef" AND stores with the _**exact name**_ of "ghij".
- **Follow SymLinks** – NOT IMPLEMENTED. Leave unchecked.
- **Include PKCS12 Files** – Leave unchecked to validate that each certificate store returned is of type = PEM. Checking this box will return all found certificate stores without validation. Leave this selection unchecked when attempting to Discover PKCS12 stores.

Once the Discovery job has completed, a list of PEM/PKCS12 store locations should show in the Certificate Stores Discovery tab in Keyfactor Command. Right click on a store and select Approve to bring up a dialog that will ask for the Keystore Password. Enter the store password, click Save, and the Certificate Store should now show up in the list of stores in the Certificate Stores tab.

From the Certificate Store list, edit the newly added store to enter the PEM_PKCS12 store type (PEM or PKCS12), whether the store has a separate private key file, and if necessary, the FULL PATH to that file. **NOTE:** You will not be able to successfully process an Inventory or Management job for this store until this has been completed.

**4. Update Settings in config.json**

The PEM_PKCS12 Orchestrator uses a JSON config file:

{  
&quot;UseSudo&quot;: &quot;N&quot;,  
&quot;CreateStoreOnAddIfMissing&quot;: &quot;N&quot;,  
&quot;UseSeparateUploadFilePath&quot;: &quot;N&quot;,  
&quot;SeparateUploadFilePath&quot;: &quot;/path/to/upload/folder/&quot;,  
&quot;UseNegotiateAuth&quot;: &quot;N&quot;  
}

**UseSudo** - Y/N - Determines whether to prefix certain Linux command with &quot;sudo&quot;. This can be very helpful in ensuring that the user id running commands ssh uses &quot;least permissions necessary&quot; to process each task. Setting this value to &quot;Y&quot; will prefix all Linux commands with &quot;sudo&quot; with the expectation that the command being executed on the orchestrated Linux server will look in the sudoers file to determine whether the logged in ID has elevated permissions for that specific command. For orchestrated Windows servers, this setting has no effect. Setting this value to &quot;N&quot; will result in &quot;sudo&quot; not being added to Linux commands.  
**CreateStoreOnAddIfMissing** - Y/N - Determines if during a Management-Add job if a certificate store should be creaed if it does not already exist.  If set to "N", the job will return an error with a message stating that the store does not exist.  
**UseSeparateUploadFilePath** (Linux only) – When adding a certificate to a PEM or PKCS12 store, the PEM_PKCS12 Orchestrator must upload the certificate being deployed to the server where the certificate store resides. Setting this value to &quot;Y&quot; looks to the next setting, SeparateUploadFilePath, to determine where this file should be uploaded. Set this value to &quot;N&quot; to use the same path where the certificate store being managed resides.  
**SeparateUploadFilePath** (Linux only) – Only used when UseSeparateUploadFilePath is set to &quot;Y&quot;. Set this to the path you wish to use as the location to upload and later remove PEM/PKCS12 certificate store data before being moved to the final destination.  
**UseNegotiateAuth** (Windows only) – Y/N - Determines if WinRM should use Negotiate (Y) when connecting to the remote server.


***

### License
[Apache](https://apache.org/licenses/LICENSE-2.0)
