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
            WorkingDirectory = "$PWD"
            Execute  = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
            Argument = '-NoProfile -File .\PowerShellCACopyCRL.ps1 -PublishURLs "$(PublishURLs)"'
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

            [String]$TargetName,
            [PSCredential]$Credential
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
# MIIekQYJKoZIhvcNAQcCoIIegjCCHn4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXtbYAcGz0SC+feB4Iss9hcZO
# OxWgghgSMIIFBzCCAu+gAwIBAgIQJTSMe3EEUZZAAWO1zNUfWTANBgkqhkiG9w0B
# AQsFADAQMQ4wDAYDVQQDDAVKME43RTAeFw0yMTA2MDcxMjUwMzZaFw0yMzA2MDcx
# MzAwMzNaMBAxDjAMBgNVBAMMBUowTjdFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzdFz3tD9N0VebymwxbB7s+YMLFKK9LlPcOyyFbAoRnYKVuF7Q6Zi
# fFMWIopnRRq/YtahEtmakyLP1AmOtesOSL0NRE5DQNFyyk6D02/HFhpM0Hbg9qKp
# v/e3DD36uqv6DmwVyk0Ui9TCYZQbMDhha/SvT+IS4PBDwd3RTG6VH70jG/7lawAh
# mAE7/gj3Bd5pi7jMnaPaRHskogbAH/vRGzW+oueG3XV9E5PWWeRqg1bTXoIhBG1R
# oSWCXEpcHekFVSnatE1FGwoZHTDYcqNnUOQFx1GugZE7pmrZsdLvo/1gUCSdMFvT
# oU+UeurZI9SlfhPd6a1jYT/BcgsZdghWUO2M8SCuQ/S/NuotAZ3kZI/3y3T5JQnN
# 9l9wMUaoIoEMxNK6BmsSFgEkiQeQeU6I0YT5qhDukAZDoEEEHKl17x0Q6vxmiFr0
# 451UPxWZ19nPLccS3i3/kEQjVXc89j2vXnIW1r5UHGUB4NUdktaQ25hxc6c+/Tsx
# 968S+McqxF9RmRMp4g0kAFhBHKj7WhUVt2Z/bULSyb72OF4BC54CCSt1Q4eElh0C
# 1AudkZgj9CQKFIyveTBFsi+i2g6D5cIpl5fyQQnqDh/j+hN5QuI8D7poLe3MPNA5
# r5W1c60B8ngrDsJd7XnJrX6GdJd2wIPh1RmzDlmoUxVXrgnFtgzeTUUCAwEAAaNd
# MFswDgYDVR0PAQH/BAQDAgWgMCoGA1UdJQQjMCEGCCsGAQUFBwMDBgkrBgEEAYI3
# UAEGCisGAQQBgjcKAwQwHQYDVR0OBBYEFEPCLoNYgwyQVHRrBSI9l0nSMwnLMA0G
# CSqGSIb3DQEBCwUAA4ICAQBiMW8cSS4L1OVu4cRiaPriaqQdUukgkcT8iWGWrAHL
# TFPzivIPI5+7qKwzIJbagOM3fJjG0e6tghaSCPfVU+sPWvXIKF3ro5XLUfJut6j5
# qUqoQt/zNuWpI12D1gs1NROWnJgqe1ddmvoAOn5pZyFqooC4SnD1fT7Srs+G8Hs7
# Qd2j/1XYAphZfLXoiOFs7uzkQLJbhmikhEJQKzKE4i8dcsoucNhe2lvNDftJqaGl
# oALzu04y1LcpgCDRbvjU0YDStZwKSEj9jvz89xpl5tMrgGWIK8ghjRzGf0iPhqb/
# xFOFcKP2k43X/wXWa9W7PlO+NhIlZmTM/W+wlgrRfgkawy2WLpO8Vop+tvVwLdyp
# 5n4UxRDXBhYd78Jfscb0fwpsU+DzONLrJEwXjdj3W+vdEZs7YIwAnsCGf8NznXWp
# N9D7OzqV0PT2Szkao5hEp3nS6dOedw/0uKAz+l5s7WJOTLtFjDhUk62g5vIZvVK2
# E9TWAuViPmUkVugnu4kV4c870i5YgRZz9l4ih5vL9XMoc4/6gohLtUgT4FD0xKXn
# bwtl/LczkzDO9vKLbx93ICmNJuzLj+K8S4AAo8q6PTgLZyGlozmTWRa3SmGVqTNE
# suZR41hGNpjtNtIIiwdZ4QuP8cj64TikUIoGVNbCZgcPDHrrz84ZjAFlm7H9SfTK
# 8jCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUu
# ySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8
# Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0M
# G+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldX
# n1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVq
# GDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFE
# mjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6
# SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXf
# SwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b23
# 5kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ
# 6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRp
# L5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADAN
# BgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVe
# qRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3vot
# Vs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum
# 6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJ
# aISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/
# ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQIC
# EAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAw
# MDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQw
# OTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2
# EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuA
# hIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQ
# h0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7Le
# Sn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw5
# 4qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP2
# 9p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjF
# KfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHt
# Qr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpY
# PtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4J
# duyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2
# mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIB
# fmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb
# 122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+r
# T4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQ
# sl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsK
# RcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKn
# N36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSe
# reU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no
# 8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcW
# oWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInw
# AM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7
# qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkH
# gD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIx
# MjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNV
# BAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28
# klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2J
# U+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCD
# HufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCR
# RinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+
# nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf
# 7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+
# pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY
# /ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwY
# UWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiw
# bjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3
# AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYE
# FGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEy
# NTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4
# Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp
# +6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJ
# iXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6
# UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr
# 5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmI
# vxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nf
# J2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH
# 5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeX
# upYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP1
# 0Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8X
# TE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMYIF6TCCBeUCAQEwJDAQMQ4wDAYDVQQD
# DAVKME43RQIQJTSMe3EEUZZAAWO1zNUfWTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUidb9eI+6
# 9sIW607xI/I7O8/PzW4wDQYJKoZIhvcNAQEBBQAEggIASVd/JnHfwIuj6hPQspF7
# xbwvv9K1xJHJRhejYNCXYA8BMbTsr3v0Ayq9sQEFzhGZ7Wf9g9JOZF5BooJU33LJ
# 9iQhTlS3n7lWO5G0WhFWLGl/OVIY7l1pzBo1eKhBIHckTVIbwK/ncF0CL5o9eE3d
# jcem/gCZq7KKVymsCwGp62QRdQ+FdNlLjtnT1dzuEFONcmFtRJQqyupH1plQs8PI
# rPkHfzVC+gghOe8E0jXiPHztAzYfA4z3rwlWjY8usxUH0p09B4CqASuN9qELFBXU
# x3WqvPGKEY64yC1PRUiwxh1oJarqsxeyM7XKZM4U5ifPuvqpzQ5N8kzdziCQylvM
# Uyq7/MgiT8tyQ+aL0AoZoml0axOjBJUTq9t56sPDX/lZjaeraxzX5noOlIlMFQOE
# hfIpEsMq8vSB4Wql/ZLfXBCRNNyUZxsa+6d8YFQHLbEkilJtM/R8kCQTyz2A1ARB
# hNS5gaUoZb3+j4dbGUsjC6RKNMy7jSUH4WV0b8r4EsPQbLHlcqOGsnL/IJ7Jckkl
# JDai00PNf3TfZ+niss6JQ9zb05JHLd/IYdaWCbaSxrrJyWE5eGY6TM7S7TAyoLU6
# 2HzFu3y4BHn3ImNPtxL8J40blFSCP2HiL9lCAyPMpXwEvOZ6ORIuHxh2ugl9BXs0
# 7dVa8r+IJYKu12ONCSmjIxKhggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEw
# dzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1w
# aW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjMwMjAzMTUwMDAy
# WjAvBgkqhkiG9w0BCQQxIgQgO7J1vnXwjhBO6EWNpUjtXeNb6NVMsdOc2qHqTKPD
# 4zswDQYJKoZIhvcNAQEBBQAEggIAfUKKAvT1gAQXkUs71Wov9xmlW7+IF3Qo2RNq
# 3rFvIeZ2ZlGqTOJpG1ukInZ1JHOPBLQ0T7TTZlxFt1ackfDkE2zREitAcFZXJBMS
# iLrtvSzj8v7eR7ssYeoLx5ZU6L7ADm9q37bWTdGSA0pFUPEc0qtLmWxh723Yxllv
# M97KyAscmwtKlMSwM7hrNnvHI87X3ZGagLBUULblnA+9bXjmfjJ8YDXSV91jLSrz
# 2U2WIY2+JhykdGrJjzca9V/ynbpVxdZMIcGgseFO1OL4bRbz1DpikSxPTS5psY3D
# zEP05JCaKtSl0EAmr++Hgnlxa9Yx5+aqRWO8uYDBN0XmEwDQkupst1jpaRgmRJza
# oPHc+4Kxb74JJ4eBMJwHeawclKajRxqX9v+DrRQmyMFicVjkrKqz0Kx82vaEJHi2
# kg5bsXxC3HvaVpX7HqDbi1Hw/VM943N8lvKgiIxm5oL05Bm13EOBVOj9TZEofmUU
# tVmXRFKcyWc0TIgRoVyviJFfyFJzkrzsUP0lPhVB4rT8N/51fywsGHFw2QRB/eSm
# kK1NapUHxFexDfNc3lDD6vYtt9fN/9cO1u+SztNWX0r8D755qkgG8WNo6MwjKLmG
# RIRHUV76oL8DeN8WyyLz4OJTynFrmzfOKA1I6V2D2CEbILSk0wNCzCqfMcvunNno
# cB3r+/0=
# SIG # End signature block
