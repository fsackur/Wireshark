# Wireshark
PS Snippets for the use of wireshark

# X509.ps1
We had an intermittent issue caused, we suspected, by a dead CRL server in a load-balance pool. The provider requested a packet capture demonstrating the issue.

This script runs a rolling packet capture which never exceeds 8MB. It runs in a loop, verifying the certificate chain. When verification fails, it parses the rolling capture and drops it into a subfolder.

Parsing: first pass gets the tcp stream numbers for packets where the http request matches a specified uri. The second pass outputs the tcp conversations with those stream numbers.

# Install Wireshark
    Install-PackageProvider -Name NuGet -Force
    Install-PackageProvider -Name chocolatey -Force
    Register-PackageSource -Name chocolatey -ProviderName Chocolatey -Location http://chocolatey.org/api/v2/ -Force
    Find-Package nmap -Source chocolatey | Install-Package -Force
    Find-Package wireshark -Source chocolatey | Install-Package -Force
