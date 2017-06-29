<#
    .Synopsis
    Rolling packet capture for investigating an intermittent issue

    .Description
    Requires Wireshark

    Starts a rolling packet capture which will not exceed 8MB on disk. Resource usage is pretty light (< 100MB memory, < 1% CPU on a 2x vCPU guest)

    Runs a loop which verifies the validity of a given certificate. If validation fails, stops capture, parses files, and dumps the error text and filtered capture to a subfolder.

    Then restarts capture.

    .Link
    https://wiki.wireshark.org/DisplayFilters
#>

function Start-TsharkCapture {
    <#
        .Synopsis
        Start a packet capture running in a new window

        .Description
        Requires Wireshark

        Starts a rolling packet capture which will not exceed 8MB on disk. Resource usage is light (< 40MB memory, < 1% CPU on a 2x vCPU guest)

        .Link
        https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection.html
    #>
    param (
        [string]$CaptureFilter = 'port 80'
    )
    
    Start-Process "C:\Program Files\Wireshark\tshark.exe" -ArgumentList (
        "--i", 'Public',
        "-f", ('"{0}"' -f $CaptureFilter),
        "-w rolling_capture.pcapng",
        "-b filesize:1000",
        "-b files:8"
    )
}

function Stop-TsharkCapture {
    <#
        .Synopsis
        Stops a running capture and parses the output

        .Description
        Places filtered packet capture in a subdirectory of $PSScriptRoot
    #>
    param (
        [uri]$Uri = 'http://comprivweb1.managed.entrust.com/CRLs/EMSComPrivCA1.crl',
        [uint16]$SecondsBefore = 60,    #previous seconds to include from capture
        [uint16]$SecondsAfter = 3       #following seconds to include from capture (if you run this function, it will capture another few seconds to ensure you include everything)
    )

    #bail if tshark is not running
    if ($null -eq (Get-Process tshark -ErrorAction SilentlyContinue)) {return}

    $Now = Get-Date
    $Start = $Now.AddSeconds(-$SecondsBefore)

    #Give it a moment to capture any final packets..?
    Start-Sleep -Seconds $SecondsAfter

    #kill
    try {
        Get-Process tshark | Stop-Process
    } catch {}

    #Give it a moment to close any capture files
    Start-Sleep -Seconds 1


    $Dir = New-Item ($Now.ToString("s") -replace ':', '-') -ItemType Directory -Force

    #Merge selected files into one unfiltered.pcapng
    $RollingFiles = Get-ChildItem $PSScriptRoot\rolling_capture*.pcapng | where {$_.LastWriteTime -ge $Start}
    & "C:\Program Files\Wireshark\mergecap.exe" -w $Dir\unfiltered.pcapng $($RollingFiles | select -ExpandProperty FullName)
    

    #Uncomment this to parse by IP address
    <#
    $Lines = & "C:\Program Files\Wireshark\tshark.exe" -r $Dir\unfiltered.pcapng -Y "http.request.full_uri == `"`"$Uri`"`""

    $Packets = $Lines | foreach {
        if ($_ -match '(?:\s*)(?<Number>\S*)(?:\s*)(?<Time>\S*)(?:\s*)(?<Source>\S*)(?:\s*)(?:\S*)(?:\s*)(?<Destination>\S*)(?:\s*)(?<Protocol>\S*)(?:\s*)(?<Length>\S*)(?:\s*)(?<Info>.*)') {
            $Matches.Remove(0)
            New-Object psobject -Property $Matches
        }
    }

    $IPs = $Packets | select -ExpandProperty Destination -Unique

    $DisplayFilter = (
        $IPs | foreach {"ip.addr == $_"}
    ) -join ' || '
    #>


    $TcpStreams = & "C:\Program Files\Wireshark\tshark.exe" -r $Dir\unfiltered.pcapng -Y "http.request.full_uri == `"`"$Uri`"`"" -T fields -e tcp.stream
    
    $DisplayFilter = (
        $TcpStreams | foreach {"tcp.stream == $_"}
    ) -join ' || '


    #Output to filtered file
    & "C:\Program Files\Wireshark\tshark.exe" -r $Dir\unfiltered.pcapng -Y $DisplayFilter -w $Dir\filtered.pcapng



    #Clean up rolling capture files
    Get-ChildItem $PSScriptRoot\rolling_capture*.pcapng | Remove-Item -Force   
}

function Test-X509Chain {
    <#
        .Synopsis
        Verifies a certificate chain

        .Description
        Expires the CRL cache, causing a web request to cehck for revocation

        Returns null if validation succeeds

        Returns error text if validation fails

        TODO: return boolean, capture output in alternate stream
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Thumbprint = 'deadbeefdeadbeefdeadbeefdeadbeef'  #I suggest editing this directly in this script and removing the Mandatory attribute
    )

    $Cert = Get-Item (Join-Path Cert:\LocalMachine\My $Thumbprint)

    #Invalidate CRL cache to force online check
    $null = & certutil --% -setreg chain\ChainCacheResyncFiletime @now

    #No real point in flushing as there isn't a good way to prevent the DNS server from caching anyway
    #$null = ipconfig /flushdns

    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    
    $Chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $Chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain

    $IsValid = $false
    try {
        $IsValid = $Chain.Build($Cert)
    } catch {}

    if (-not $IsValid) {
    
        foreach ($Element in $Chain.ChainElements) {
            $Element.ChainElementStatus
    
            for ($i=0; $i -lt $Chain.ChainStatus.Length; $i++) {
                $Chain.ChainStatus[$i].Status
                $Chain.ChainStatus[$i].StatusInformation
            }

        }

    }
}



Start-TsharkCapture

#loop
while ($true) {
    Start-Sleep -Seconds 1
    $X509Output = Test-X509Chain
    if ($null -ne $X509Output) {
        #Cert chain couldn't be validated
        Stop-TsharkCapture

        #Assume newest dir was created by Stop-TsharkCapture function
        $Dir = Get-ChildItem $PSScriptRoot -Directory | sort CreationTime | select -Last 1
        $X509Output | Out-File $Dir\error.txt

        #rinse and repeat
        Start-TsharkCapture
    }
}

