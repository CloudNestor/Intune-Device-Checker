<# 
=============================================================================================================================

 Script Name: Gui-GetDeviceInfo.ps1
 Description: Get Intune information for a device based on either the UPN, Device Name or Serial
 Notes      : 

 Based on a GUI Template by "By Hugo Gungormez AKA KamikazeAdmin ;)" from 21/10/2021!
 (https://hvtools.net/2021/10/21/how-to-build-a-colourful-gui-for-powershell-using-winforms-runspacepools-and-hash-tables/)

 Pre-req    : PowerShell 4.0 and up
              .Net framework 2.0 and up
              Reader permissions in Intune
              The following modules are needed:
                Microsoft.Graph.Intune
                Microsoft.Graph.Authentication

 Changes    :
 1.0.1 - Fixes Authentication issue MSAL (remove -Interactive switch)
 1.0.2 - Authentication method changed from msal to mggraph, added Application fails check, Added Remediation fails
       - Made the app sizable
 1.0.3 - Fixed bug of selecting additionaly device in case if Apps or Remediate info wanted to be additionaly collect if device.id is already known for specific UPN
       - Added Clear Output button in File ribbon
       - Changed Icon to coresponding one from Intune
 1.1.0 - Fixed dubbel compliance lines
       - Cleaned up
       - Builded APPS and Remediation functions to allow future extension
 1.1.1 - Added check for token expiration, reauthentication will be enforced if token lifetime is less than 5 minutes
 1.1.2 - Added fix for missing Graph authentication module     
 1.1.3 - Change the check for the missing Graph authentication module
 2.0.0 - Added hardware info (RAM, FWversion, TPM version OS edition)
       - Added "Enter"to start the search
       - Fixed issue with Remediation reporting
       - Fixed clear the screen when re-authenticating
       - Updated the error handling when service devices on UPN
       - Added search on serial
       - Added show AP info when device is not in user scope or not enrolled
       - Fixed compliance check
 2.1.0 - Fixed Remediation (>50 issue!)
       - Removed Remediation check function
       - Fixed Application check
       - Removed Application check function
       - Fixed disconnect (suppressed output)
 3.0.0 - Improved SN search
       - Added displaying information for non-Windows devices
       - Added Scope Tags
       - Added check on AzureID
       - Fixed Remediation (>50 issue!)
       - Added sign out in File Menu
       - Ajusted the size
=============================================================================================================================
#>
$Author = "Peter Rausch"
$contributors = "Peter Rausch / Michal Dmoch"
$AuthorDate = "April 21th 2025"
$Version = "3.0.0"

# Suppress Errors
$script:ErrorActionPreference = 'SilentlyContinue'
$script:ProgressPreference = 'SilentlyContinue'

# Hash table for runspaces
$hash= [hashtable]::Synchronized(@{})

# Working Path
$script:workingPath = Get-Location

# Date
$script:datestring = (Get-Date).ToString("s").Replace(":","-")

# Functions

Function Authenticate {

    $hash.token = Connect-MgGraph -NoWelcome
    $Parameters = @{Method = "GET"
                    URI = "/v1.0/me"
                    OutputType = "HttpResponseMessage"
                    }
    $hash.Response = Invoke-GraphRequest @Parameters
    $hash.token = $($hash.Response).RequestMessage.Headers.Authorization.Parameter
    $hash.AuthToken = @{"Authorization" = "Bearer $($hash.token)"}

    $Signedin.text = "User: " + (get-mgcontext).account
    $hash.domain = ((get-mgcontext).account).substring(((get-mgcontext).account).indexof("@"))
}

function Get-JWTDetails {
    <# 
         .SYNOPSIS   
         Converts encoded JWT to a hashtable
        .DESCRIPTION
         Converts encoded JWT to a hashtable
         .NOTES
         AUTHOR   : Ivo Uenk
         CREATED  : 11/12/2024
         .PARAMETER token
         Mandatory the token to convert
    #>
     
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$token
    )    
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
  
    # Token  
    foreach ($i in 0..1) {
        $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($data.Length % 4) {
            0 { break }
            2 { $data += '==' }
            3 { $data += '=' }
        }
    }
    $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json
   
    # Signature
    foreach ($i in 0..2) {
        $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($sig.Length % 4) {
            0 { break }
            2 { $sig += '==' }
            3 { $sig += '=' }
        }
    }
    $decodedToken | Add-Member -Type NoteProperty -Name "sig" -Value $sig
     
    # Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes # Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,
    $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime
    
    # Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry
    return $decodedToken
}

# Region Function SearchDevice
Function SearchDevice
{
    $hash.OutputBox.Clear()
    $hash.DeviceID = @()

    If(!($hash.AuthToken)){
        $hash.OutputBox.Selectioncolor = "Black"
        $hash.OutputBox.AppendText("`r`nAuthenticating")
        Authenticate
        $hash.OutputBox.Clear()
    }
    elseIf ((Get-JWTDetails -token $hash.token).timetoExpiry.minutes -lt "5"){
        Authenticate
    }


    If($($hash.textBox.Text) -like "*@*"){
        If(($($hash.textBox.Text).ToLower()).Substring($($hash.textBox.Text).Length - 8) -eq $Hash.domain){

            $hash.OutputBox.Selectioncolor = "Black"
            $hash.OutputBox.AppendText("`r`nGetting device(s) of user")
        
            $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userPrincipalName%20eq%20'$($hash.textBox.Text)'&`$select=deviceName,id,operatingSystem"     
            $hash.IntuneDevices = (ConvertFrom-Json((Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $($hash.authToken) -Method Get).content)).value
        
            $hash.OutputBox.Clear()
            
            If(($hash.IntuneDevices).count -gt 1){
                $select = New-Object System.Windows.Forms.Form
                $select.Text = 'Select a Computer'
                $select.Size = New-Object System.Drawing.Size(300,200)
                $select.StartPosition = 'CenterParent'
                $okButton = New-Object System.Windows.Forms.Button
                $okButton.Location = New-Object System.Drawing.Point(75,120)
                $okButton.Size = New-Object System.Drawing.Size(75,23)
                $okButton.Text = 'OK'
                $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $select.AcceptButton = $okButton
                $select.Controls.Add($okButton)

                $cancelButton = New-Object System.Windows.Forms.Button
                $cancelButton.Location = New-Object System.Drawing.Point(150,120)
                $cancelButton.Size = New-Object System.Drawing.Size(75,23)
                $cancelButton.Text = 'Cancel'
                $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                $select.CancelButton = $cancelButton
                $select.Controls.Add($cancelButton)

                $label = New-Object System.Windows.Forms.Label
                $label.Location = New-Object System.Drawing.Point(10,20)
                $label.Size = New-Object System.Drawing.Size(280,20)
                $label.Text = 'Please select a computer:'
                $select.Controls.Add($label)

                $listBox = New-Object System.Windows.Forms.ListBox
                $listBox.Location = New-Object System.Drawing.Point(10,40)
                $listBox.Size = New-Object System.Drawing.Size(260,20)
                $listBox.Font = "Verdana, 10"
                $listBox.Height = 80

                Foreach($Device in $hash.IntuneDevices){
                    [void] $listBox.Items.Add($($Device.DeviceName))
                }

                $select.Controls.Add($listBox)
                $select.Topmost = $true
                $result1 = $select.ShowDialog()

                if ($result1 -eq [System.Windows.Forms.DialogResult]::OK){
                    If($listBox.SelectedItem){
                        $hash.DeviceID = ($hash.IntuneDevices|Where-Object DeviceName -eq $listBox.SelectedItem).ID
                        $hash.OS = ($hash.IntuneDevices|Where-Object DeviceName -eq $listBox.SelectedItem).operatingSystem
                        DisplayData
                    }Else{
                        $hash.OutputBox.Selectioncolor = "Red"
                        $hash.OutputBox.AppendText("`r`nNo device was selected.")
                        $hash.OutputBox.AppendText("`r`n")
                        $hash.OutputBox.AppendText("`r`nPlease select a device and click OK the next time!")
                    }
                }
            }elseif(!($hash.IntuneDevices)){
                $hash.OutputBox.Selectioncolor = "Red"
                $hash.OutputBox.AppendText("`r`nDevice query failed.")
                $hash.OutputBox.AppendText("`r`n")
                $hash.OutputBox.AppendText("`r`nEither the UPN is incorrect, the user has no devices assigned or the device(s) are not managed in your management scope.")
            } else{
                $hash.DeviceID = $hash.IntuneDevices[0].ID
                $hash.OS = $hash.IntuneDevices[0].operatingSystem
                DisplayData
            }
        }else{
            $hash.OutputBox.Selectioncolor = "Red"
            $hash.OutputBox.AppendText("`r`nThe UPN entered is invalid!")
        }
    }else{
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName%20eq%20'$($hash.textBox.Text)'"
        $Result = ((ConvertFrom-Json((Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get).content)).value)     
        $hash.DeviceID = $Result.id
        $hash.OS = $Result.operatingSystem
        If($hash.DeviceID){
            If($($hash.DeviceID).Count -ge 2){
                $hash.OutputBox.Selectioncolor = "Red"
                $hash.OutputBox.AppendText("`r`nDevice query failed.")
                $hash.OutputBox.AppendText("`r`n")
                $hash.OutputBox.AppendText("`r`nThere are multiple devices with the same device name.")
            }else{
                DisplayData
            }
        }else{
            If(($($hash.textBox.Text)).Length -ge 8){
                $NoChar = ($hash.textBox.Text).Length
                while (($NoChar -ge 8) -and !($hash.DeviceID)) {
                    $hash.serialNumber = ($($hash.textBox.Text)).Substring(($($hash.textBox.Text)).Length -$($NoChar), $($NoChar))
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber%20eq%20'$($hash.serialNumber)'"     
                    $Result = ((ConvertFrom-Json((Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get).content)).value)     
                    $hash.DeviceID = $Result.id
                    $hash.OS = $Result.operatingSystem
                    $NoChar = $NoChar -1
                }
                If($hash.DeviceID){
                    If($($hash.DeviceID).Count -ge 2){
                        $hash.OutputBox.Selectioncolor = "Red"
                        $hash.OutputBox.AppendText("`r`nDevice query failed.")
                        $hash.OutputBox.AppendText("`r`n")
                        $hash.OutputBox.AppendText("`r`nThere are multiple devices with the same serial number.")
                    }else{
                        DisplayData
                    }
                } else {
                    $NoChar = ($hash.textBox.Text).Length
                    $AP = @()
                    while (($NoChar -ge 8) -and !($AP)) {
                        $hash.serialNumber = ($($hash.textBox.Text)).Substring(($($hash.textBox.Text)).Length -$($NoChar), $($NoChar))
                        $Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,%27$($hash.serialNumber)%27)"
                        $AP = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get
                        $AP = (ConvertFrom-Json $AP).value
                        $NoChar = $NoChar -1
                    }
                    If($AP){
                            If($AP.managedDeviceId -ne "00000000-0000-0000-0000-000000000000" -and $AP.enrollmentState -eq "enrolled"){

                                    $hash.OutputBox.Selectioncolor = "Red"
                                    $hash.OutputBox.AppendText("`r`nThe device is enrolled, but not not in your management scope.")
                                    $hash.OutputBox.AppendText("`r`n")
                                    $hash.OutputBox.AppendText("`r`nDevice ID`t`t: $($AP.managedDeviceId)")
                                    $hash.OutputBox.AppendText("`r`nSerial number`t`t: $($AP.serialNumber)")
                                    $hash.OutputBox.AppendText("`r`nModel`t`t`t: $($AP.model)")
                                    $hash.OutputBox.AppendText("`r`nEnrollment State`t: $($AP.enrollmentState)")
                                    $hash.OutputBox.AppendText("`r`nLast seen`t`t: $($AP.lastContactedDateTime)")
                                    # Group Tag 
                                    $hash.OutputBox.AppendText("`r`nGroup Tag`t`t: $($AP.grouptag)")
                            }else{
                                $hash.OutputBox.Selectioncolor = "Red"
                                $hash.OutputBox.AppendText("`r`nThe device is not enrolled.")
                                $hash.OutputBox.AppendText("`r`n")
                                $hash.OutputBox.AppendText("`r`nDevice ID`t`t: $($AP.managedDeviceId)")
                                $hash.OutputBox.AppendText("`r`nSerial number`t`t: $($AP.serialNumber)")
                                $hash.OutputBox.AppendText("`r`nModel`t`t`t: $($AP.model)")
                                $hash.OutputBox.AppendText("`r`nEnrollment State`t: $($AP.enrollmentState)")
                                $hash.OutputBox.AppendText("`r`nLast seen`t`t: $($AP.lastContactedDateTime)")
                                # Group Tag 
                                $hash.OutputBox.AppendText("`r`nGroup Tag`t`t: $($AP.grouptag)")
                            } 
                    }else{
                            $hash.OutputBox.Selectioncolor = "Red"
                            $hash.OutputBox.AppendText("`r`nDevice not found in Intune or Autopilot")
                            $hash.OutputBox.AppendText("`r`n")
                            $hash.OutputBox.AppendText("`r`nEither the device name or serial number is incorrect or the device is not imported into Autopilot")
                    }
                }
            } else {
                $hash.OutputBox.Selectioncolor = "Red"
                $hash.OutputBox.AppendText("`r`nDevice not found in Intune or Autopilot")
                $hash.OutputBox.AppendText("`r`n")
                $hash.OutputBox.AppendText("`r`nEither the device name or serial number is incorrect or the device is not imported into Autopilot")                
            }
        }
    }
}

# Region Function DisplayData
Function DisplayData{

    $scriptRun = {
        # Suppress Errors as to not interrupt the GUI experience. Comment these out when debugging.
        $script:ErrorActionPreference = 'SilentlyContinue'
        $script:ProgressPreference = 'SilentlyContinue'

        $Uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($hash.DeviceID)')?`$select=id,HardwareInformation,physicalMemoryInBytes,deviceName,ownerType,managementState,enrolledDateTime,lastSyncDateTime,chassisType,operatingSystem,deviceType,complianceState,jailBroken,managementAgent,osVersion,deviceEnrollmentType,lostModeState,isSupervised,isEncrypted,userPrincipalName,enrolledByUserPrincipalName,model,manufacturer,complianceGracePeriodExpirationDateTime,serialNumber,subscriberCarrier,managedDeviceName,partnerReportedThreatState,autopilotEnrolled,managementCertificateExpirationDate,joinType,skuFamily,securityPatchLevel,enrollmentProfileName,roleScopeTagIds,azureADDeviceId"
        $Device = convertfrom-json ((Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get).content)
        $Memory = $Device.physicalMemoryInBytes/1GB
        
        $Uri = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?"
        $ScopeTags = (convertfrom-json ((Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get).content)).value

        If($hash.OS -eq "Windows"){
            $Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$top=25&`$filter=contains(serialNumber,%27$($Device.serialNumber)%27)"
            $AP = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get
            $AP = (ConvertFrom-Json $AP).value
        }
    
        $hash.OutputBox.Selectioncolor = "Black"
        $hash.OutputBox.AppendText("`r`nDevice Name`t`t: $($Device.deviceName)")
        $hash.OutputBox.AppendText("`r`nDevice ID`t`t: $($Device.id)")
        $hash.OutputBox.AppendText("`r`nManagement name`t: $($Device.managedDeviceName)")
        $hash.OutputBox.AppendText("`r`nManagement state`t: $($Device.managementState)")
        $hash.OutputBox.AppendText("`r`nOwnership`t`t: $($Device.ownerType)")
        $hash.OutputBox.AppendText("`r`nJoin type`t`t: $($Device.joinType)")
        
        # Primary user and Enrolled by
        If($Device.hardwareinformation.model -like "*Cloud*"){
            $hash.OutputBox.AppendText("`r`nPrimary User`t`t: $($Device.userPrincipalName)")
        }elseif($AP.grouptag -like "*-M-*"){
           
            If($($Device.userPrincipalName) ){
                $hash.OutputBox.Selectioncolor = "Red"
                $hash.OutputBox.AppendText("`r`nA shared device should not have a Primary User!!")
                $hash.OutputBox.AppendText("`r`nPrimary User`t`t: $($Device.userPrincipalName)")
            }
    
            If($($Device.enrolledByUserPrincipalName) ){
                $hash.OutputBox.Selectioncolor = "Red"
                $hash.OutputBox.AppendText("`r`nA shared device should not have a Enrolled by user!!")
                $hash.OutputBox.AppendText("`r`nEnrolled by`t`t: $($Device.enrolledByUserPrincipalName)")
            }
        }else{            
            $hash.OutputBox.AppendText("`r`nPrimary User`t`t: $($Device.userPrincipalName)")
            $hash.OutputBox.AppendText("`r`nEnrolled by`t`t: $($Device.enrolledByUserPrincipalName)")
        }
        $hash.OutputBox.Selectioncolor = "Black"
        If(!($Device.hardwareinformation.model -like "*Link*")){
            $hash.OutputBox.AppendText("`r`nEnrollment profile`t: $($Device.enrollmentProfileName)")
        }
        $hash.OutputBox.AppendText("`r`nEnrollment Type`t: $($Device.deviceEnrollmentType)")
        $hash.OutputBox.AppendText("`r`nManagement Agent`t: $($Device.managementAgent)")
        IF(!($hash.OS -eq "Windows")){
            $hash.OutputBox.AppendText("`r`nEnrollment date`t: $($Device.enrolledDateTime)")
        }
        $hash.OutputBox.AppendText("`r`nMDM Expire date`t: $($Device.managementCertificateExpirationDate)")
        $hash.OutputBox.AppendText("`r`nLast synced`t`t: $($Device.lastSyncDateTime)")

        # Group Tag"
        If($hash.OS -eq "Windows"){
            $hash.OutputBox.AppendText("`r`nAutopilot Enrolled`t: $($Device.autopilotEnrolled)")
            If($Device.autopilotEnrolled){
                If(!($Device.hardwareinformation.model -like "*Cloud*" -or $Device.hardwareinformation.model -like "*Link*")){
                    If($Device.serialNumber -eq $AP.serialNumber){
                        $hash.OutputBox.AppendText("`r`nGroup Tag`t`t: $($AP.grouptag)")
                    }else{
                        $hash.OutputBox.Selectioncolor = "Red"
                        $hash.OutputBox.AppendText("`r`nGroup Tag`t`t: $($AP.grouptag) / $($AP.serialNumber) Device serial non-matching!")
                    }
                }
            }
        }
        $hash.OutputBox.AppendText("`r`Scope Tag(s)`t`t: ")
        $ScopeCount = 0
        ForEach($Scopetag in $Device.roleScopeTagIds){
            If($ScopeCount -eq 0){
                $hash.OutputBox.AppendText("$((($scopetags| where-object ID -eq $Scopetag).displayname))")
            }else{
                $hash.OutputBox.AppendText(" / $((($scopetags| where-object ID -eq $Scopetag).displayname))")
            }
            $ScopeCount = $ScopeCount + 1          
        }
        
        If(($Device.azureADDeviceId -ne $AP.azureAdDeviceId) -and ($Device.autopilotEnrolled)){
            $hash.OutputBox.AppendText("`r`n")
            $hash.OutputBox.Selectioncolor = "Red"
            $hash.OutputBox.AppendText("`r`nEntraID ObjectIDs Intune and Autopilot do not match!!")
            $hash.OutputBox.AppendText("`r`nObjectID Intune`t`t: $($Device.azureADDeviceId)")
            $hash.OutputBox.AppendText("`r`nObjectID Autopilot`t`t: $($AP.azureADDeviceId)")
        }

        $hash.OutputBox.AppendText("`r`n")
        $hash.OutputBox.Selectioncolor = "Black"
        $hash.OutputBox.AppendText("`r`nManufacturer`t`t: $($Device.hardwareinformation.manufacturer)")
        $hash.OutputBox.AppendText("`r`nDevice Model`t`t: $($Device.hardwareinformation.model)")

        If(!($Device.deviceType -eq "cloudPC")){
            $hash.OutputBox.AppendText("`r`nChassis Type`t`t: $($Device.chassisType)")
        }

        If(($Device.chassisType -eq "Phone") -or ($Device.deviceType -eq "cloudPC")){
            $hash.OutputBox.AppendText("`r`nDevice Type`t`t: $($Device.deviceType)")
        }
        $hash.OutputBox.AppendText("`r`nSerial`t`t`t: $($Device.hardwareinformation.serialNumber)")
        If(!($null -eq $Device.hardwareInformation.systemManagementBIOSVersion)){
            $hash.OutputBox.AppendText("`r`nBiosversion`t`t: $($Device.hardwareInformation.systemManagementBIOSVersion)")
        }
        If (!($Memory -eq "0")){
            $hash.OutputBox.AppendText("`r`nPhysical Memory`t: $($Memory.tostring("# ")) GB")
        }        
        If((($Device.hardwareinformation.model -like "*Link*") -or !($Device.hardwareInformation.totalStorageSpace -eq "0"))){
            $hash.OutputBox.AppendText("`r`nFree storage`t`t: $(($Device.hardwareinformation.freeStorageSpace/1GB).ToString("#.## ")) GB of $(($Device.hardwareinformation.totalStorageSpace/1GB).ToString("#.## ")) GB free ")
        }
        $hash.OutputBox.AppendText("`r`nEncrypted`t`t: $($Device.isEncrypted)")
        If(!($Device.chassisType -eq "Phone")){
            $hash.OutputBox.AppendText("`r`nTPM`t`t`t: $($Device.hardwareInformation.tpmManufacturer) $($Device.hardwareInformation.tpmVersion) ($($Device.hardwareInformation.tpmSpecificationVersion))") 
        }
        $hash.OutputBox.AppendText("`r`nOperating System`t: $($Device.operatingSystem)")
        $hash.OutputBox.AppendText("`r`nOS Version`t`t: $($Device.osVersion) $($Device.hardwareInformation.operatingSystemEdition)")
        If($hash.OS -eq "Android"){
            $hash.OutputBox.AppendText("`r`nPatch Level`t`t: $($Device.securityPatchLevel)")
        }
        If($Device.chassisType -eq "Phone"){
            $hash.OutputBox.AppendText("`r`nJail Broken`t`t: $($Device.jailBroken)")
            $hash.OutputBox.AppendText("`r`nLost Mode`t`t: $($Device.lostModeState)")
            $hash.OutputBox.AppendText("`r`nProvider`t`t: $($Device.subscriberCarrier)")
        }
        If($hash.OS -eq "iOS"){
            $hash.OutputBox.AppendText("`r`nSupervised`t`t: $($Device.isSupervised)")
        }
        $hash.OutputBox.AppendText("`r`n ")
        $hash.OutputBox.Selectioncolor = "Black"
        $hash.OutputBox.AppendText("`r`nCompliance state`t: $($Device.complianceState)")
 
        If($($Device.complianceState) -ne "Compliant"){
            $hash.OutputBox.AppendText("`r`nCompliance grace`t: $($Device.complianceGracePeriodExpirationDateTime)")
        }

        $hash.OutputBox.AppendText("`r`n ")

        # Compliance
        $Uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getDevicePoliciesComplianceReport"
        $Body = "{`"select`":[],`"skip`":0,`"top`":50,`"filter`":`"(DeviceId eq '$($hash.DeviceID)') and ((PolicyPlatformType eq '4') or (PolicyPlatformType eq '5') or (PolicyPlatformType eq '6') or (PolicyPlatformType eq '8') or (PolicyPlatformType eq '100'))`",`"orderBy`":[`"PolicyName asc`"],`"search`":`"`"}"
        $Compliance = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Post -Body $Body -ContentType "application/json"
        $Compliance = convertfrom-json $Compliance
        $Policies = $Compliance.Values | foreach-object `
                -Begin   {
                    $propertyNames = @($Compliance.Schema.Column)
                } `
                -Process {
                    $properties = [ordered] @{};
                    for( $i = 0; $i -lt $Compliance.Schema.Length; $i++ )
                    {
                        $properties[$propertyNames[$i]] = $_[$i];
                    }
        
                    new-object PSCustomObject -Property $properties
                }

        ForEach($Policy in $Policies){
            If(($Policy.PolicyStatus_loc -EQ "Not compliant") -or ($Policy.PolicyStatus_loc -EQ "Error")){
                $hash.OutputBox.Selectioncolor = "Red"
                $hash.OutputBox.AppendText("`r`n$($Policy.PolicyName) --> $($Policy.PolicyStatus_loc)")
            }elseif(($Policy.PolicyStatus_loc -EQ "Compliant")){
                $hash.OutputBox.Selectioncolor = "Green"
                $hash.OutputBox.AppendText("`r`n$($Policy.PolicyName) --> $($Policy.PolicyStatus_loc)")
            }else{
                $hash.OutputBox.Selectioncolor = "Black"
                $hash.OutputBox.AppendText("`r`n$($Policy.PolicyName) --> $($Policy.PolicyStatus_loc)")
            }            

            If (($Policy.PolicyStatus_loc -eq "Not compliant") -or ($Policy.PolicyStatus_loc -eq "Error")){
                $Uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getDevicePolicySettingsComplianceReport"
                $Body = "{`"select`":[],`"skip`":0,`"top`":50,`"filter`":`"(DeviceId eq '$($hash.DeviceID)') and (PolicyId eq '$($Policy.PolicyId)')`",`"orderBy`":[`"SettingName asc`"],`"search`":`"`"}"
                $ComplianceError = Invoke-WebRequest -Uri $Uri -Headers $hash.AuthToken -Method Post -Body $Body -ContentType "application/json"
                $ComplianceError = convertfrom-json $ComplianceError
                $CompErrors = $ComplianceError.Values | foreach-object `
                -Begin   {
                    $propertyNames = @($ComplianceError.Schema.Column)
                } `
                -Process {
                    $properties = [ordered] @{};
                    for( $i = 0; $i -lt $ComplianceError.Schema.Length; $i++ )
                    {
                        $properties[$propertyNames[$i]] = $_[$i];
                    }
        
                    new-object PSCustomObject -Property $properties
                }
                $CompErrors = $CompErrors|Select-Object SettingID,SettingInstanceId,SettingNm_loc, SettingStatus_loc,StateDetails_loc -Unique
                ForEach($name in (($CompErrors|Group-Object SettingNm_loc| Where-Object{$_.Count -gt 1}).name)){
                    $CompErrors = $CompErrors|where-object {($_.SettingNm_loc -NE $($name) -and $_.SettingStatus_loc -EQ "Compliant") -or ($_.SettingNm_loc -EQ $($name) -and $_.SettingStatus_loc -NE "Compliant") }
                }

                ForEach($errorline in $CompErrors){
                    If ($errorline.SettingStatus_loc -eq "Error"){
                            $hash.OutputBox.Selectioncolor = "Red"
                            If($($errorline.StateDetails_loc)){
                                $hash.OutputBox.AppendText("`r`n`t$($errorline.SettingNm_loc) --> $($errorline.SettingStatus_loc) --> $($errorline.StateDetails_loc)")
                            }else{
                                $hash.OutputBox.AppendText("`r`n`t$($errorline.SettingNm_loc) --> $($errorline.SettingStatus_loc)")
                            }
                    }elseif ($errorline.SettingStatus_loc -eq "Not compliant"){
                            $hash.OutputBox.Selectioncolor = "Red"
                            If($($StateDetails_loc)){
                                $hash.OutputBox.AppendText("`r`n`t$($errorline.SettingNm_loc) --> $($errorline.SettingStatus_loc) --> $($errorline.StateDetails_loc)")
                            }else{
                                $hash.OutputBox.AppendText("`r`n`t$($errorline.SettingNm_loc) --> $($errorline.SettingStatus_loc)")
                            }
                    }elseif ($errorline.SettingStatus_loc -eq "Compliant"){
                            $hash.OutputBox.Selectioncolor = "Green"
                            $hash.OutputBox.AppendText("`r`n`t$($errorline.SettingNm_loc) --> $($errorline.SettingStatus_loc)")
                    }elseif ($errorline.SettingStatus_loc -eq "Not applicable"){
                    }else{
                            $hash.OutputBox.Selectioncolor = "Green"
                            $hash.OutputBox.AppendText("`r`n`t$($errorline.SettingNm_loc) --> $($errorline.SettingStatus_loc)") 
                    }
                }
            }
        }
    } # Close the $scriptRun brackets for the runspace
    
    # Configure max thread count for RunspacePool.
    $maxthreads = [int]$env:NUMBER_OF_PROCESSORS
    
    # Create a new session state for parsing variables ie hashtable into our runspace.
    $hashVars = New-object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'hash',$hash,$Null
    $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    
    # Add the variable to the RunspacePool sessionstate
    $InitialSessionState.Variables.Add($hashVars)

    # Create our runspace pool. We are entering three parameters here min thread count, max thread count and host machine of where these runspaces should be made.
    $script:runspace = [runspacefactory]::CreateRunspacePool(1,$maxthreads,$InitialSessionState, $Host)

    # Crate a PowerShell instance.
    $script:powershell = [powershell]::Create()
    
    # Open a RunspacePool instance.
    $script:runspace.Open()
        
        # Add our main code to be run via $scriptRun within our RunspacePool.
        $script:powershell.AddScript($scriptRun)
        $script:powershell.RunspacePool = $script:runspace
        
        # Run our RunspacePool.
        $script:handle = $script:powershell.BeginInvoke()

        # Cleanup our RunspacePool threads when they are complete ie. GC.
        if ($script:handle.IsCompleted)
        {
            $script:powershell.EndInvoke($script:handle)
            $script:powershell.Dispose()
            $script:runspace.Dispose()
            $script:runspace.Close()
            [System.GC]::Collect()
        }
}

# Region Functions to check Apps and Healthscripts
Function Apps{
    If($hash.DeviceID){
        If(!($hash.AuthToken)){
            Authenticate
        }
        elseIf ((Get-JWTDetails -token $hash.token).timetoExpiry.minutes -lt "5"){
            Authenticate
        }

        $Uri = "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($hash.DeviceID)')"
        $Device = convertfrom-json ((Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get).content)
        $Uri = "https://graph.microsoft.com/beta/users('$($device.userid)')/mobileAppIntentAndStates/$($hash.DeviceID)"
        $Apps = Invoke-WebRequest -Uri $Uri -Headers $hash.AuthToken -Method Get
        $Apps = (ConvertFrom-Json $APPS).mobileAppList
            
        If($Apps.installState.Contains("failed")){
            $hash.OutputBox.Selectioncolor = "Black"
                $hash.OutputBox.AppendText("`r`n`nApplications Installation Failures:")
            Foreach ($Appstatus in $Apps){
                if ($Appstatus.installState -match "failed") {
                    $hash.OutputBox.Selectioncolor = "Red"
                    $hash.OutputBox.AppendText("`r`n`t$($Appstatus.displayName) --> App installation intended:$($Appstatus.mobileAppIntent) --> App installation state:$($Appstatus.installState)")
                }
            }
        }else{ 
            $hash.OutputBox.Selectioncolor = "Green"
            $hash.OutputBox.AppendText("`r`n`nNo Application Installation Failures Found")            
        }
    }else{
        $hash.OutputBox.AppendText("`r`n`nNo device selected")
    }
}

Function Remediations {
    If($hash.DeviceID){
        If(!($hash.AuthToken)){
            Authenticate
        }
        elseIf ((Get-JWTDetails -token $hash.token).timetoExpiry.minutes -lt "5"){
            Authenticate
        }

        $RemediationInfo = @()
                
        $Uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($hash.DeviceID)/deviceHealthScriptStates?`$filter=detectionState%20eq%20'fail'"
        $RemediationInfoResponse = (Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $hash.AuthToken -Method Get)
        $RemediationInfoResponse = convertfrom-json $RemediationInfoResponse.content
        $RemediationInfo += ($RemediationInfoResponse.value)
        $RemediationInfoNextLink = $RemediationInfoResponse."@odata.nextLink"
        $RemediationInfoResponse = @()
        
        while ($RemediationInfoNextLink){
            $RemediationInfoResponse = (Invoke-WebRequest  -Uri $RemediationInfoNextLink -Headers $hash.AuthToken -Method Get)
            $RemediationInfoResponse = convertfrom-json $RemediationInfoResponse.content
            If($RemediationInfoResponse){
                $RemediationInfo += ($RemediationInfoResponse.value)
            }
            $RemediationInfoNextLink = $RemediationInfoResponse."@odata.nextLink"
        }

        $RemediationInfo = $RemediationInfo| Select-Object policyName, remediationState, detectionState -Unique

        If($RemediationInfo.remediationState.Contains("scriptError") -or $RemediationInfo.remediationState.Contains("remediationFailed")){
            $hash.OutputBox.Selectioncolor = "Black"    
            $hash.OutputBox.AppendText("`r`n`nRemediations Issues:")
            foreach($remediations in $RemediationInfo){
                if(($remediations.detectionstate -eq "fail") -and ($remediations.remediationState -ne "Success")){
                    $hash.OutputBox.Selectioncolor = "Red"    
                    $hash.OutputBox.AppendText("`r`n`t$($remediations.PolicyName) --> DetectionState:$($remediations.detectionState) --> RemediationState:$($remediations.remediationState)")
                }
            }
        }else{
            $hash.OutputBox.Selectioncolor = "Green"    
            $hash.OutputBox.AppendText("`r`n`nNo Issues with Remediation Detected")
        }
    }else{
        $hash.OutputBox.AppendText("`r`n`nNo device selected")
    }
}

# Region Menu GUI begins.
# Install .Net Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Enable Visual Styles
[Windows.Forms.Application]::EnableVisualStyles()
 
# Main Form
$iconPath = ".\icon.ico"
$hash.Form = New-Object system.Windows.Forms.Form
$FormWidth = '800'
$FormHeight = '1000'
$hash.Form.Size = "$FormWidth,$FormHeight"
$hash.Form.StartPosition = 'CenterScreen'
$hash.Form.text = "Intune Device Checker"
$hash.Form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconPath)
$hash.Form.BackColor = 'Orange'
$hash.Form.Refresh()
# Disable windows maximize feature.
$hash.Form.MaximizeBox = $False
$hash.Form.FormBorderStyle='Sizable'
 
$Description = New-Object system.Windows.Forms.Label
$Description.text = "Intune Device Checker"
$Description.AutoSize = $false
$Description.width = 400
$Description.height = 30
$Description.location = New-Object System.Drawing.Point(20,40)
$Description.Font = 'Verdana,13'
$Description.Anchor = 'top, left'
 
# Bottom Area
# Close button
$exitButton = New-Object System.Windows.Forms.Button
$exitButton.Location = '650,900'
$exitButton.Size = '100,40'
$exitButton.FlatStyle = 'Flat'
$exitButton.BackColor = 'LightGray'
$exitButton.Font = 'Verdana, 10'
$exitButton.Anchor = 'bottom, right'

# Font styles are: Regular, Bold, Italic, Underline, Strikeout
$hash.Form.Controls.Add($exitButton)
$exitButton.Text = 'Close'
$exitButton.tabindex = 0
$exitButton.Add_Click({
    $hash.Form.Tag = $hash.Form.close()
    $script:powershell.EndInvoke($script:handle)
    $script:powershell.Close()
    $script:powershell.Dispose()
    $script:runspace.Close()
    $script:runspace.Dispose()
    [System.GC]::Collect()})
$hash.Form.CancelButton = $exitButton

# Apps button
$hash.buttonApps = New-Object System.Windows.Forms.Button
$hash.buttonApps.Location = '20,900'
$hash.buttonApps.Size = '110,40'
$hash.buttonApps.FlatStyle = 'Flat'
$hash.buttonApps.BackColor = 'LightGray'
$hash.buttonApps.Font = 'Verdana, 10'
$hash.buttonApps.Anchor = 'bottom, left'
# Font styles are: Regular, Bold, Italic, Underline, Strikeout
$hash.buttonApps.Text = 'Check Apps'
$hash.buttonApps.tabindex = 1
$hash.buttonApps.Add_Click({Apps})

# Remediations button
$hash.buttonRemediations = New-Object System.Windows.Forms.Button
$hash.buttonRemediations.Location = '150,900'
$hash.buttonRemediations.Size = '110,40'
$hash.buttonRemediations.FlatStyle = 'Flat'
$hash.buttonRemediations.BackColor = 'LightGray'
$hash.buttonRemediations.Font = 'Verdana, 10'
$hash.buttonRemediations.Anchor = 'bottom, left'
# Font styles are: Regular, Bold, Italic, Underline, Strikeout
$hash.buttonRemediations.Text = 'Check Remediations'
$hash.buttonRemediations.tabindex = 1
$hash.buttonRemediations.Add_Click({Remediations})

# Signed in user
$Signedin = New-Object system.Windows.Forms.Label
$Signedin.text = "User: " + (get-mgcontext).account
$Signedin.AutoSize = $false
$Signedin.width = 300
$Signedin.height = 30
$Signedin.location = New-Object System.Drawing.Point(400,915)
$Signedin.Font = 'Verdana,10'
$Signedin.Anchor = 'bottom, right'

# Top Area
$moto = New-Object system.Windows.Forms.Label
$moto.text = "Get Intune device info for ServiceNow ticket"
$moto.AutoSize = $false
$moto.width = 600
$moto.height = 20
$moto.location = New-Object System.Drawing.Point(20,70)
$moto.Font = 'Verdana,10'

# Input field 
$hash.textBox = New-Object System.Windows.Forms.TextBox
$hash.textBox.Location = New-Object System.Drawing.Point(20,100)
$hash.textBox.Size = New-Object System.Drawing.Size(570,30)
$hash.textBox.Anchor = 'top, left, right'
$WatermarkText = "Enter a UPN, Device name or serial"
$hash.textBox.BackColor = 'White'
$hash.textBox.ForeColor = 'Gray'
$hash.textBox.Font = "Verdana, 12"
$hash.textBox.Text = $WatermarkText
# If we have focus then clear out the text
$hash.textBox.Add_GotFocus(
    {
        If($hash.textBox.Text -eq $WatermarkText)
        {
            $hash.textBox.Text = ''
            $hash.textBox.ForeColor = 'WindowText'
        }
    }
)

# If we have lost focus and the field is empty, reset back to watermark.
$hash.textBox.Add_LostFocus(
    {
        If($hash.textBox.Text -eq '')
        {
            $hash.textBox.Text = $WatermarkText
            $hash.textBox.ForeColor = 'Gray'
        }
    }
)
 
# Search button
$hash.buttonsearch = New-Object System.Windows.Forms.Button
$hash.buttonsearch.Location = '600,100'
$hash.buttonsearch.Size = '80,30'
$hash.buttonsearch.FlatStyle = 'Flat'
$hash.buttonsearch.BackColor = 'LightGray'
$hash.buttonsearch.Font = 'Verdana, 10'
$hash.buttonsearch.Anchor = 'top, right'
 
# Font styles are: Regular, Bold, Italic, Underline, Strikeout
$hash.buttonsearch.Text = 'Search'
$hash.buttonsearch.tabindex = 1
$hash.buttonsearch.Add_Click({SearchDevice})

# Output Box which is below all other buttons and displays PS Output
$hash.outputBox = New-Object System.Windows.Forms.RichTextBox 
$hash.outputBox.Location = New-Object System.Drawing.Size(20,150) 
$hash.outputBox.Size = New-Object System.Drawing.Size(740,730)
$hash.outputBox.Font = "Verdana, 10"
$hash.outputBox.ReadOnly = $True
$hash.outputBox.MultiLine = $True
$hash.outputBox.ScrollBars = "Vertical"
$hash.outputBox.Anchor = 'top, bottom, left,right'
 
# File Menu
$menuClose = New-Object System.Windows.Forms.ToolStripMenuItem
$menuClose.Name = "Close"
$menuClose.Text = "Close"
$menuClose.Add_Click({$hash.Form.Close()
    $script:powershell.EndInvoke($script:handle)
    $script:powershell.Close()
    $script:powershell.Dispose()
    $script:runspace.Dispose()
    $script:runspace.Close()
    [System.GC]::Collect()})

$menuClear = New-Object System.Windows.Forms.ToolStripMenuItem
$menuClear.Name = "Clear Output"
$menuClear.Text = "Clear Output"
$menuClear.Add_Click({$hash.OutputBox.Clear()}) 
$menuSigOut = New-Object System.Windows.Forms.ToolStripMenuItem
$menuSigOut.Name = "Sign out"
$menuSigOut.Text = "Sign out"
$menuSigOut.Add_Click({Disconnect-MgGraph | Out-Null
$hash.Authtoken = @()
$Signedin.text = "User: " + (get-mgcontext).account})   
# File Menu continued
$menuFile = New-Object System.Windows.Forms.ToolStripMenuItem
$menuFile.Name = "File"
$menuFile.Text = "File"
$menuFile.DropDownItems.AddRange(@($menuClose))
$menuFile.DropDownItems.AddRange(@($menuClear))
$menuFile.DropDownItems.AddRange(@($menuSigOut))
 
# ABOUT FORM
$FormAbout = New-Object system.Windows.Forms.Form
$FormAboutWidth = '400'
$FormAboutHeight = '340'
$FormAbout.MinimumSize = "$FormAboutWidth,$FormAboutHeight"
$FormAbout.StartPosition = 'CenterParent'
$FormAbout.text = "About"
$FormAbout.Icon = [System.Drawing.SystemIcons]::Shield

# Autoscaling settings
$FormAbout.AutoScale = $true
$FormAbout.AutoScaleMode = "Font"
$ASsize = New-Object System.Drawing.SizeF(7,15)
$FormAbout.AutoScaleDimensions = $ASsize
$FormAbout.BackColor = 'CornflowerBlue'
$FormAbout.Refresh()
# Disable windows maximize feature.
$FormAbout.MaximizeBox = $False
 
$AboutHeading = New-Object system.Windows.Forms.Label
$AboutHeading.text = "Intune Device Checker"
$AboutHeading.AutoSize = $false
$AboutHeading.width = 300
$AboutHeading.height = 30
$AboutHeading.location = New-Object System.Drawing.Point(20,20)
$AboutHeading.Font = 'Verdana,14'
$AboutHeading.Anchor = 'top, left'
 
$AboutDescription = New-Object system.Windows.Forms.Label
$AboutDescription.text = "Author: $Author`r`nContributors: $contributors `r`nBuild date: $AuthorDate`r`nVersion: $Version"
$AboutDescription.AutoSize = $false
$AboutDescription.width = 500
$AboutDescription.height = 100
$AboutDescription.location = New-Object System.Drawing.Point(20,130)
$AboutDescription.Font = 'Verdana,10'
$AboutDescription.Anchor = 'bottom, left'
 
$Description2Heading = New-Object system.Windows.Forms.Label
$Description2Heading.text = "Get device info to copy"
$Description2Heading.AutoSize = $false
$Description2Heading.width = 450
$Description2Heading.height = 30
$Description2Heading.location = New-Object System.Drawing.Point(20,60)
$Description2Heading.Font = 'Verdana,12'
 
$AboutDescription2 = New-Object system.Windows.Forms.Label
$AboutDescription2.text = "https://peterrausch.nl"
$AboutDescription2.AutoSize = $false
$AboutDescription2.width = 620
$AboutDescription2.height = 30
$AboutDescription2.location = New-Object System.Drawing.Point(20,100)
$AboutDescription2.Font = 'Verdana,10'
 
$AboutLinkLabel = New-Object System.Windows.Forms.LinkLabel
$AboutLinkLabel.Location = New-Object System.Drawing.Size(20,230)
$AboutLinkLabel.Size = New-Object System.Drawing.Size(360,20)
$AboutLinkLabel.LinkColor = "BLUE"
$AboutLinkLabel.ActiveLinkColor = "RED"
$AboutLinkLabel.Text = "https://ing.sharepoint.com/sites/CDS_cs/SitePages/Home.aspx"
$AboutLinkLabel.Anchor = 'top, left'
$AboutLinkLabel.add_Click({[system.Diagnostics.Process]::start("https://ing.sharepoint.com/sites/CDS_cs/SitePages/Home.aspx")})

# About Close Button
$aboutClose = New-Object System.Windows.Forms.Button
$aboutClose.text = "Close"
$aboutClose.Size = '80,30'
$aboutClose.location = '260,260'
$aboutClose.Font = 'Verdana,9'
$aboutClose.Anchor = 'Bottom,Left'
$aboutClose.Add_Click({$FormAbout.Close()})
 
# Add our controls ie labels and buttons into our Abou form.
$FormAbout.Controls.AddRange(@($AboutHeading, $AboutDescription, $Description2Heading, $AboutDescription2, $AboutLinkLabel, $aboutClose))
 
# Help ToolStrip Menu
$helpAbout = New-Object System.Windows.Forms.ToolStripMenuItem
$helpAbout.Name = "About"
$helpAbout.Text = "About"
$helpAbout.Add_Click({$FormAbout.ShowDialog()})
 
$menuHelp = New-Object System.Windows.Forms.ToolStripMenuItem
$menuHelp.Name = "Help"
$menuHelp.Text = "Help"
$menuHelp.DropDownItems.AddRange(@($helpAbout))
 
$menuMain = New-Object System.Windows.Forms.MenuStrip
$menuMain.Items.AddRange(@($menuFile, $menuHelp))

if(!(Get-Module |Where-Object {$_.name -eq "Microsoft.Graph.Authentication"})){
    if(!(Get-Module -ListAvailable| Where-Object name -eq "Microsoft.Graph.Authentication")){
        # Display form
        $hash.Form.Controls.AddRange(@($menuMain,  $Description, $moto, $hash.outputBox, $StatusHeading ))
        $hash.OutputBox.AppendText("`r`n")
        $hash.OutputBox.AppendText("`r`nThe Powershell module Microsoft.Graph.Authentication is missing on your device")
        $hash.OutputBox.AppendText("`r`n")
        $hash.OutputBox.AppendText("`r`nPlease use Powershell with admin permissions to install the module")   
        $hash.OutputBox.AppendText("`r`nwith the command: Install-Module Microsoft.Graph.Authentication")
        $hash.OutputBox.Selectioncolor = "red"   
        $result = $hash.Form.ShowDialog()
     }else{
        try{
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            $import = "Ok"
        }catch{
            $Import = "Failed"
        }
    }
}

If($import -eq "Failed"){
    # Display form
    $hash.Form.Controls.AddRange(@($menuMain,  $Description, $Signedin, $moto, $hash.outputBox, $StatusHeading ))
    $hash.OutputBox.AppendText("`r`n")
    $hash.OutputBox.AppendText("`r`nThe Powershell module Microsoft.Graph.Authentication cannot be imported")
    $hash.OutputBox.Selectioncolor = "red"   
    $result = $hash.Form.ShowDialog()      
}else{
    # Display form
    $hash.form.Controls.Add($textBox)
    $hash.Form.Controls.Add($hash.buttonApps)
    $hash.Form.Controls.Add($hash.buttonsearch)
    $hash.Form.Controls.Add($hash.buttonRemediations)
    $hash.Form.AcceptButton = $hash.buttonsearch
    $hash.Form.Controls.AddRange(@($menuMain,  $Description, $Signedin, $moto, $hash.outputBox, $StatusHeading,$hash.textBox ))
    $result = $hash.Form.ShowDialog()
}

# Exit
if($result -eq [System.Windows.Forms.DialogResult]::Cancel)
    {
        Disconnect-MgGraph | Out-Null
        Exit
    }