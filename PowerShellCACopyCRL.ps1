<#
 .SYNOPSIS
    PowerShell CA Copy CRL

 .DESCRIPTION
    Copies CRL to configured CDPs
    Triggers on Security event 4872
    Finds local CRLs from event info
    Supports configuration of individual credentials for each CDP

 .NOTES
    AUTHOR Jonas Henriksson

 .LINK
    https://github.com/J0N7E

 .NOTES
    Register task in powershell with:

    @{
        TaskName    = "PowerShell CA Copy CRL"
        Description = 'Triggers on Security event 4872'
        TaskPath    = '\'
        Action      =
        @{
            Execute          = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
            Argument         = '-ExecutionPolicy RemoteSigned -NoProfile -File .\PowerShellCACopyCRL.ps1 -PublishURLs "$(PublishURLs)"'
            WorkingDirectory = "$($PWD.Path)"
        } | ForEach-Object {
            New-ScheduledTaskAction @_
        }
        Trigger     =
        @(
            @{
                Enabled = $true
                Subscription = @('<QueryList>',
                                 '  <Query Id="0" Path="Security">',
                                 '        <Select Path="Security">',
                                 '            *[System[EventID=4872]]',
                                 '        </Select>',
                                 '    </Query>',
                                 '</QueryList>') -join "`n"
                ValueQueries =
                @{
                    PublishURLs = 'Event/EventData/Data[@Name="PublishURLs"]'
                }.GetEnumerator() | ForEach-Object { $_2 = $_;
                    New-CimInstance -CimClass (
                        Get-CimClass -ClassName MSFT_TaskNamedValue `
                                     -Namespace Root/Microsoft/Windows/TaskScheduler
                    ) -ClientOnly | ForEach-Object {
                        $_.Name  = $_2.Name
                        $_.Value = $_2.Value
                        return $_
                    }
                }
            }
        ) | ForEach-Object { $_2 = $_;
            New-CimInstance -CimClass (
                Get-CimClass -ClassName MSFT_TaskEventTrigger `
                             -Namespace Root/Microsoft/Windows/TaskScheduler
            ) -ClientOnly | ForEach-Object {
                $_.Enabled      = $_2.Enabled
                $_.Subscription = $_2.Subscription
                $_.ValueQueries = $_2.ValueQueries
                return $_
            }
        }
        Principal   = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
        Settings    = New-ScheduledTaskSettingsSet -MultipleInstances Parallel `
                                                   -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    } | ForEach-Object {
        Register-ScheduledTask @_
    }

 .NOTES
    Register event source with:

    foreach ($EventSource in @('PowerShell CA Copy CRL'))
    {
        New-EventLog -LogName Application -Source $EventSource
    }

 .NOTES
    Debug event source:

    foreach ($EventSource in @('PowerShell CA Copy CRL'))
    {
        #Check registered event source exist with:
        [System.Diagnostics.EventLog]::SourceExists($EventSource)

        #Check which log registered event source is registered under
        [System.Diagnostics.EventLog]::LogNameFromSourceName($EventSource,'.')

        #Remove registered event with:
        #[System.Diagnostics.EventLog]::DeleteEventSource($EventSource)
    }
#>

param
(
    [String]$PublishURLs
)

try
{
    ############
    # Configure
    ############

    # CDP servers
    $CDPServers =
    @(
        <#
         Use:
            @{ Share = '<\\host\share>' }
            or
            @{ Share = '<\\host\share>';  Username = '<domain>\<username>';  Password = (ConvertTo-SecureString -String '<password>' -AsPlainText -Force) }
        #>

        @{ Share = '\\AS01\wwwroo$' }
    )

    ############
    # Functions
    ############

    function Copy-CRL
    {
        param
        (
            [Parameter(Mandatory=$true)]
            [String]$Path,

            [Parameter(Mandatory=$true)]
            [String]$Share,

            [PSCredential]$Credential,

            [String]$TargetName
        )

        begin
        {
            # Set credential splat
            $CredSplat = @{}

            if ($Credential)
            {
                $CredSplat.Add('Credential', $Credential);
            }

            # Get psdrive
            $CDPRoot = Get-PSDrive -Name CDPRoot -ErrorAction SilentlyContinue

            # Check if correct root
            if (-not ($CDPRoot | Where-Object { $_.Root -eq $Share }))
            {
                # Check if psdrive exist
                if ($CDPRoot)
                {
                    Remove-PSDrive -Name CDPRoot -Scope Global -Force
                }

                # Open new psdrive
                New-PSDrive @CredSplat -Name CDPRoot -PSProvider FileSystem -Root $Share -Scope Global > $null
            }
        }

        process
        {
            # Get source
            $SourceItem = Get-Item -Path $Path -ErrorAction SilentlyContinue
            $SourceHash = Get-FileHash -Path $Path -ErrorAction SilentlyContinue

            # Check targetname
            if (-not $TargetName)
            {
                # Set targetname
                $TargetName = $SourceItem.Name
            }

            # Get target
            $TargetItem = Get-Item -Path "CDPRoot:\\$TargetName" -ErrorAction SilentlyContinue
            $TargetHash = Get-FileHash -Path "CDPRoot:\\$TargetName" -ErrorAction SilentlyContinue

            # Compare file hash and last write time
            if ((($TargetHash.Hash -ne $SourceHash.Hash) -or
                 ($TargetItem.LastWriteTime -lt $SourceItem.LastWriteTime)))
            {
                Copy-Item -Path $Path -Destination "CDPRoot:\\$TargetName" -Force

                # Set original timestamps
                Set-ItemProperty -Path "CDPRoot:\\$TargetName" -Name CreationTime -Value $SourceItem.CreationTime
                Set-ItemProperty -Path "CDPRoot:\\$TargetName" -Name LastWriteTime -Value $SourceItem.LastWriteTime
                Set-ItemProperty -Path "CDPRoot:\\$TargetName" -Name LastAccessTime -Value $SourceItem.LastAccessTime

                Write-EventLog -LogName Application `
                               -Source "PowerShell CA Copy CRL" `
                               -EntryType Information `
                               -EventId 1234 `
                               -Message "Copied `"$Path`" to `"$Share\$TargetName`"" `
                               -Category 0
            }
        }

        end
        {
        }
    }

    #######
    # Main
    #######

    # Split to array
    $PublishURLs = $PublishURLs -split ';'

    # Initialize
    $LocalCRLs = @{}

    # Itterate published CRLs
    foreach ($Item in $PublishURLs)
    {
        # Remove padding
        $Item = $Item.Trim()

        # Match local files
        if($Item -match '^[A-Z]:')
        {
            # Get CRL file
            $File = Get-Item -Path $Item

            # Check if duplicate
            if(-not $LocalCRLs.ContainsKey($File.Name))
            {
                $LocalCRLs.Add($File.Name, $File)
            }
        }
    }

    # Itterate CDP servers
    foreach ($Server in $CDPServers)
    {
        # Check if CA allready published to configured share
        if ($PublishURLs.Contains($Server.Share))
        {
            Write-EventLog -LogName Application `
                           -Source 'PowerShell CA Copy CRL' `
                           -EntryType Information `
                           -EventId 1234 `
                           -Message "Skipping CRL copy to `"$($Server.Share)`", CA already publish to this location." `
                           -Category 0
        }
        # Publish CRLs to configured share
        else
        {
            # Itterate all found CRL files
            foreach ($file in $LocalCRLs.GetEnumerator())
            {
                @{
                    Path       = $file.Value.FullName
                    Share      = $Server.Share
                    Verbose    = $true
                    Credential =
                    (
                        Invoke-Command -ScriptBlock {

                            if ($Server.Username -and $Server.Password)
                            {
                                Write-Output -InputObject (
                                    New-Object -TypeName System.Management.Automation.PSCredential `
                                               -ArgumentList @(
                                                    $Server.Username,
                                                    $Server.Password
                                                )
                                )
                            }
                            else
                            {
                                Write-Output -InputObject $null
                            }
                        }
                    )
                } | ForEach-Object { Copy-CRL @_ }
            }

        }

    }

    ##########
    # Cleanup
    ##########

    if (Get-PSDrive -Name CDPRoot -ErrorAction SilentlyContinue)
    {
        Remove-PSDrive -Name CDPRoot
    }
}
catch [Exception]
{
    Write-EventLog -LogName Application `
                   -Source 'PowerShell CA Copy CRL' `
                   -EntryType Error `
                   -EventId 1234 `
                   -Message $_ `
                   -Category 0
    throw $_
}

# SIG # Begin signature block
# MIIe7wYJKoZIhvcNAQcCoIIe4DCCHtwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDGQ2+UPzRa/b7i
# yKVtg1LpbyDGL1VBto4aBkAxdPVqu6CCGEUwggUHMIIC76ADAgECAhB0XMs0val9
# mEnBo5ekK6KYMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNVBAMMBUowTjdFMB4XDTIz
# MDkwNzE4NTk0NVoXDTI4MDkwNzE5MDk0NFowEDEOMAwGA1UEAwwFSjBON0UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRw1gJO1wnpdRIbqVo1gfsnMV8
# kxOJBp/FDV1XxyN0njKwlcA6zyudii33AqXYWUojp4xPoXzBGkVuoqqZOkSXHMz5
# /OScP3fe4QEtIC6X9vSQuWvo9jaih0kLbRUEBTG2EVRiHsVyeLR3DPgSNckbGJ54
# MMtlhFPchHo/N7BpaGrUtdjd+F59hDVDaeoe6VVYPVaC5yAgUR9QkJZw69+YkET4
# S+Q09WgoCoXEnrVnnjPzLq0iN0rdSOrhuBE5CouwUwr6YgjU6pwtEoyBaRUhL2cd
# 8UXLzVUgy9+Bo6mhJUtq1ujECc6afx26wkDYMwfo4vTdIgFv8XATvrvWyO0a4ZGn
# 6eU+eS+hWoURP2iVlYPGUY555F1NzeOVwQ9v1cumIaOVB8x+TjJxLCtomqfVxgO9
# JeHcrqW/Q55Itr9VBGUSk6a20oEQj94UwrvoNmkbEW+/XE6DWmHf7TWEJug5d4+7
# 2pI2TmGcisERv16qSzevlkN+uUTCMVSF32Qt7ZQoRocrscj37fHVaFOA1EpbMrOp
# RwX1pWWkNBGmWptQwkTMzHNFQiTTU0OrDjqCNRh63pWcg+qdAB7ZstaoMx4vdfo/
# twAfHDTnI403nUyrIEV1gLUyJ5i5Tgw6gh8g3ozq8Qaftq+PD1rhel+ByG23LZ42
# AhGD4q4ndfG13VEONQIDAQABo10wWzAOBgNVHQ8BAf8EBAMCBaAwKgYDVR0lBCMw
# IQYIKwYBBQUHAwMGCSsGAQQBgjdQAQYKKwYBBAGCNwoDBDAdBgNVHQ4EFgQUWNAE
# eD3ij461l5HFCgfSYoXMwCkwDQYJKoZIhvcNAQELBQADggIBAFKCUuzQ8KfuDfqI
# ZG+peeD9+r7qcvdlIt4tRdIOgVcqEncrrAVKIcEm0Fi1Zzs6cchsiDUUUUCLkYg/
# nowzCY3g2hjQOsE3QaWHgmr+WG6JqHnOz/2/9pS+3C8EPg1VfQb/Am5G5fr3tRBm
# u2RaeKcHjoEw9T6ASDVy2fRXjNDd9rOtyYmoP3EjAqU5ey/E4A7k4nnW5x2y5sPp
# CQlr77hsZ3keGgLz87XybHPphhqA6ddYk5vJuTB2QML0xSPLnBk0C/jwORQz44Ct
# t8zdml9wBVOcOt+7Omg4pORx2Bs37hVckL+XLUP3x/4ikQ7DVQi1fweDrtZ9T2xd
# whj5+CHMc8cXzri+nYX8bvmLTYyip5Gl47eC7C6bcNsoKQq2zlLVBecTumZ6p7hT
# n3mMJWEQt4HqJ+u+PS6VKU5TkYS3A1jlUvRPdwd6AGa1BcV9ChPq9ugXqb0juRWU
# oZPhYjwz9RBgJDZk/cdON1Ie31RwmyUYyoPGFuQYsfj0RI/mCFtF12WXbh2zDR0X
# 3qU4gSaEHTVQ0jPjROietordyS4l2euH/Z8dhvJwYeOSjCIxQlBqKFtkFEq8EeGs
# zs65D3oz2DwaTZEIip1fSU7yfbJLx+fMShZ7wVXATluADk3CXqJh2izO5tiCH6yJ
# Ux7YQVpSHQNdeltDcnGMwZ7mpUrXMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0B
# AQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUg
# Q0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbA
# HKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8
# I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Ma
# l5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzW
# Ijk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IB
# ZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpL
# gIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKC
# z6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV
# /FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8
# M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1Nq
# zJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlY
# zyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaA
# FOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4
# oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqG
# SIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wG
# c/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F
# 448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8
# n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEB
# fHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdT
# SlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2
# p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy
# +GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm
# 4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0V
# rFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7
# Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCC
# Bu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAy
# MDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNl
# cnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/
# hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7
# zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0D
# vbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytxNM89PZXUP/5wWWURK+If
# xiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYev
# vOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZr
# eiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz
# 8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVC
# GZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi54wm0i2ePZD5pPIssosz
# QyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOz
# aQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlw
# CUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
# FgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQ
# VvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAy
# NUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIw
# MjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkq
# hkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+F
# ERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQ
# uPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9kt
# x0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xe
# jEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0
# fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu
# /3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTl
# QJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaeh
# r0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK
# +At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1
# Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcx
# ggYAMIIF/AIBATAkMBAxDjAMBgNVBAMMBUowTjdFAhB0XMs0val9mEnBo5ekK6KY
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIP0R/VKv1Pe1WZu14pDlnEuXX1C1vLG826Za
# zLJVzsiQMA0GCSqGSIb3DQEBAQUABIICAGGfSDcmIKk679W2I5bIq3sO54lQRAcO
# S3+qhiiVuhqyPHa8il99dh9Tzjeloeo1RK9dLK5gQzAPWTDLdnQ+NYsgGSFfjPGU
# 8rGS4qJVMsCkIe7d26w90EHK+I/2Foas44aSkNwLoB7auF3/Md/QlYJat2hz4Iep
# xJQcRYeURVB53O/81YcGvSaJgxP//qHIl7gA4Ur8lapZB/5dUIcLUmtaTx2BDS9I
# a9n5ySZ8KMY/8GA3Fg5bjccubDx9E7Lia0ZzgWBJQ75UjaLwwdvqikCyRgRsuILy
# aJID/FvoF5/UdbPWIKMZDAfb99RmpnE9riTq+bHrtqhpk98lTNpKX8Fqy81PAX50
# 1/j9ir+QZIKr12mU+RKPHlqxI2WqFAboaZUppc0WKs1n07Qyu8Fu94ySPBaVoOfC
# W4c3XwD8lYbz4PPLMZLl3tzDqgcYPc7dfNxNXQGrs9v8RTKVNx3Tk8N5fccul69b
# X5kwFUdSS9Ewuvm31DkSez39xVY5Fi+BdG3BO9j5+qs20aMtlhlO4MutK3eSNqTx
# WL+6LId+xhMxAaq41fli/J4oTs6yBD0WETXLOzLTLYnbNAHUYfs+m8zBpeRMcNrc
# KjDAb4iUW8sVkq79UcA8nfJsHz57TPEzZBLzrmnx3jEomzfPTydck29Qr4F8S5Uc
# iiKAhS0mkqKtoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdp
# Q2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1
# IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDcwMTAxMTA1NFow
# LwYJKoZIhvcNAQkEMSIEIE0T982mkkaktGqCfEExGazNDSReRgbZ3hfQeMFZuEvQ
# MA0GCSqGSIb3DQEBAQUABIICAAGZHddvClhjzyeXZbc9FxXrohOrylVIcZJG4fBX
# 5xr+4oXmgOQTN+9VcWvFYCyZsEE+yv2WUTllBc74BLMh1+0I81TAMnTxuhWyhMrA
# se+CdtuJIspr3qEmvgs7JFXXHv83XvlZIxQPb/F+Q5e3NbRa6KJKXkbyktuHu5IF
# ydg1lFZTbE29D8hkiDid5tUNPuLkeavltkZBJ2Buh1OSdX+XqXzMBdgk4dcoYDPQ
# 4hZt+7Y6sSP6NZinHS0GwV8nGC1hqOr4oiafQYfzPEGo3Qxk0pB1OLrixvXQWTjq
# P688KyJ542kUvJ7i84PK7QaoH1QKuWwbUEQ0aF7d21av2lkfIua2aGkv5fK4HOGk
# KBwSQSMbtiRPjvD0z3OUCf7x/DfC/eISpNRaa0MIAajGi9sYkrGx9Ns2bvQ/x/mN
# Y63Sppuvms43Xt1yf042sFEdXvFsuAEA4bkedjP5w16RfJmURzlMOF67/X8Rjdfe
# AVSZm5QxZRBg9sCqtkFhnGncriG6xBFsxFdyoXVF4lh1L03NzFnEAsMHDKvChpsw
# cHhlS0xa8/xJJfGYlfSPoghQS7gLHbPYZODF9IuPiBxJtmB+dlfQeSzvaUCpLNMH
# qIbKb2NvbXPRYNs3E/uItQknfVEA5f3gdMEhsOMFvj0YYOt4rPboiYJLM3jR+LDM
# yoWQ
# SIG # End signature block
