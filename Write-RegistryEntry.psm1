<#
    .Synopsis 
    Write or update a registry entry with a specific value and type

    .Description
    Write a registry entry with a specific value and type. The function will
    change the owner of the registry key to Administrators and restore the
    original owner after the value has been set.

    .Parameter rootKey
    The root key of the registry entry. Can be one of the following:
    HKCU, HKEY_CURRENT_USER, HKLM, HKEY_LOCAL_MACHINE, HKCR, HKEY_CLASSES_ROOT,
    HKCC, HKEY_CURRENT_CONFIG, HKU, HKEY_USERS

    .Parameter key
    The registry key path

    .Parameter valueName
    The name of the registry value

    .Parameter value
    The value to set

    .Parameter valueType
    The type of the value to set. Can be one of the following:
    Binary, DWord, ExpandString, MultiString, QWord, String

    .Example
    Write-RegistryEntry -rootKey HKLM -key 'Software\Microsoft\Windows\CurrentVersion\Policies\System' -valueName ConsentPromptBehaviorAdmin -value 0 -valueType DWord

    .Example
    Write-RegistryEntry -rootKey HKLM -key 'Software\Microsoft\Windows\CurrentVersion\Policies\System' -valueName ConsentPromptBehaviorUser -value 0 -valueType DWord

    .Example
    Write-RegistryEntry -rootKey HKLM -key 'Software\Microsoft\Windows\CurrentVersion\Policies\System' -valueName EnableLUA -value 0 -valueType DWord

    .Example
    Write-RegistryEntry -rootKey HKLM -key 'Software\Microsoft\Windows\CurrentVersion\Policies\System' -valueName EnableSecureUIAPaths -value 0 -valueType DWord
#>

function Get-ObjectSid {
    param($obj)
    try {
        $object = New-Object System.Security.Principal.NTAccount($obj)
        $sidValue = $object.Translate([System.Security.Principal.SecurityIdentifier])
        return $sidValue.Value
    } catch {
        return $null
    }
}

function Set-Permissions {
    param(
        $rootKey,
        $key,
        [System.Security.Principal.SecurityIdentifier]$sid = 'S-1-5-32-545',
        $recurse = $false
    )

    $rootKeyMapping = @{
        'HKCU|HKEY_CURRENT_USER'    = 'CurrentUser'
        'HKLM|HKEY_LOCAL_MACHINE'   = 'LocalMachine'
        'HKCR|HKEY_CLASSES_ROOT'    = 'ClassesRoot'
        'HKCC|HKEY_CURRENT_CONFIG'  = 'CurrentConfig'
        'HKU|HKEY_USERS'            = 'Users'
    }

    foreach ($mapping in $rootKeyMapping.GetEnumerator()) {
        if ($rootKey -match $mapping.Key) {
            $rootKey = $mapping.Value
            break
        }
    }

    $import = '[DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(ulong a, bool b, bool c, ref bool d);'
    $ntdll = Add-Type -Member $import -Name NtDll -PassThru
    $privileges = @{ SeTakeOwnership = 9; SeBackup =  17; SeRestore = 18 }
    foreach ($i in $privileges.Values) {
        $null = $ntdll::RtlAdjustPrivilege($i, 1, 0, [ref]0)
    }

    function Set-KeyPermissions {
        param($rootKey, $key, $sid, $recurse, $recurseLevel = 0)

        $regKey = [Microsoft.Win32.Registry]::$rootKey.OpenSubKey($key, 'ReadWriteSubTree', 'TakeOwnership')
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        $acl.SetOwner($sid)
        $regKey.SetAccessControl($acl)

        $acl.SetAccessRuleProtection($false, $false)
        $regKey.SetAccessControl($acl)

        if ($recurseLevel -eq 0) {
            $regKey = $regKey.OpenSubKey('', 'ReadWriteSubTree', 'ChangePermissions')
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($sid, 'FullControl', 'ContainerInherit', 'None', 'Allow')
            $acl.ResetAccessRule($rule)
            $regKey.SetAccessControl($acl)
        }

        if ($recurse) {
            foreach($subKey in $regKey.OpenSubKey('').GetSubKeyNames()) {
                Set-KeyPermissions $rootKey ($key+'\'+$subKey) $sid $recurse ($recurseLevel+1)
            }
        }
    }

    Set-KeyPermissions $rootKey $key $sid $recurse
}


function Get-RegistryKeyPath {
    param($rootKey, $key)
    return ($rootKey + ':\' + $key)
}

function Get-RegistryAcl {
    param($rootKey, $key)
    $regKey = Get-RegistryKeyPath $rootKey $key
    Write-Output $regKey
    Get-Acl -Path $regKey
}

function Set-RegistryAcl {
    param($rootKey, $key, $acl)
    $regKey = Get-RegistryKeyPath $rootKey $key
    Set-Acl -Path $regKey -AclObject $acl
}

function Set-RegistryObjOwner {
    param($rootKey, $key, $sid)
    Take-Permissions $rootKey $key $sid $false
}

function Set-RegistryObjOwnerAdministators {
    param($rootKey, $key)
    $administratorSid = 'S-1-5-32-544'
    Set-RegistryObjOwner $rootKey $key $administratorSid
}

function Set-RegistryEntryValue {
    param($rootKey, $key, $valueName, $value, $valueType)
    $regKey = Get-RegistryKeyPath $rootKey $key
    if (Test-Path $regKey) {
        $currentVal = Get-ItemProperty -Path $regKey -Name $valueName
        try {
            Set-ItemProperty -Path $regKey -Name $valueName -Value $value -Type $valueType
            Write-Output "Changed value of $valueName from $($currentVal.$valueName) to $value"
        } catch {
            Write-Output "Failed to change value of $valueName from $($currentVal.$valueName) to $value"
        }
    } else {
        try {
            New-ItemProperty -Path $regKey -Name $valueName -Value $value -Type $valueType
            Write-Output "Created value $valueName with value $value"
        } catch {
            Write-Output "Failed to create value $valueName with value $value"
        }
    }
}

function Write-RegistryEntry {
    param($rootKey, $key, $valueName, $value, $valueType)
    
    $currentAcl = Get-RegistryAcl $rootKey $key

    # Set the owner to Administrators
    Set-RegistryObjOwnerAdministators $rootKey $key

    $tmpAcl = Get-RegistryAcl $rootKey $key
    Write-Output "Changed ACL Owner from $($currentAcl.Owner) to $($tmpAcl.Owner)"

    # Set the value
    Set-RegistryEntryValue $rootKey $key $valueName $value $valueType

    $newAcl = New-Object System.Security.AccessControl.RegistrySecurity
    $newAcl.SetSecurityDescriptorBinaryForm($($currentAcl.GetSecurityDescriptorBinaryForm()))

    # Restore the acl
    Set-RegistryAcl $rootKey $key $newAcl

    $currentAcl = Get-RegistryAcl $rootKey $key
    Write-Output "Changed ACL Owner from $($tmpAcl.Owner) to $($currentAcl.Owner)"
}

Export-ModuleMember -Function Write-RegistryEntry