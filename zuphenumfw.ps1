$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Black')
$Host.UI.RawUI.ForegroundColor = 'White'
$Host.PrivateData.ErrorForegroundColor = 'Red'
$Host.PrivateData.ErrorBackgroundColor = $bckgrnd
$Host.PrivateData.WarningForegroundColor = 'Magenta'
$Host.PrivateData.WarningBackgroundColor = $bckgrnd
$Host.PrivateData.DebugForegroundColor = 'Yellow'
$Host.PrivateData.DebugBackgroundColor = $bckgrnd
$Host.PrivateData.VerboseForegroundColor = 'Green'
$Host.PrivateData.VerboseBackgroundColor = $bckgrnd
$Host.PrivateData.ProgressForegroundColor = 'Cyan'
$Host.PrivateData.ProgressBackgroundColor = $bckgrnd
function mainMenu {
    $mainMenu = 'X'
    while($mainMenu -ne ''){
        Clear-Host
        Write-Host "KKK0KKKKKKKKK0x:..........',::;'.............''''.'''''''',,,,''..................''',''''..','...',,,.....',;cokKXNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXX
KKKKKKKKKKKK0xc'...........',::,................'''',,,'',,;,,,''.............'''''''',,,''''''''''''...',;coxOXNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXX
KKKKKKKKKKK0kc'..........''',;:;.......'''....'',,,,,;,,,,,;,,,,'...............'',,;,,,,,'''''',,'...',:oxOKXNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXK
KKKKKKKKKK0Oo,.......'',,,,'',;;'....''..'''',,,,,,,,;,,,,,;,,,'.................''';;;,,,,'',,,,,,'.';cd0NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXK
KKKKKKKKKKOd:'......'',''...',;,,'.';:,'.',,;;,;;;;,''''''''''..'..................'',,,,'''',,;,,,'',:xKNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXKK
KKKKKKKKK0x:'....',,,,,'...',;;;;,,;:;''',,,,;;,,,,''',:::;'...''''................''......'',,,,,,;:ld0NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXKKKKK
KKKKKKKK0kc'....',;:;;;'..,:c:::;;:c;,'''',,,,,'......''''''.';:;,,'..............',,;,'',,,'',;;:;;:oOKNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXKKKKK
KKKKKKK0Oo;''..',;;,,,'..';:cll:;;:;,','''''''......'........',,,;;,'........''...',,;;'''''...';:::coOKXNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXKKKKK
KKKKKKK0kc,,',;:cc;,''...',;clcc:c:,'''''''''.....';c:'.........',,''...''.'',''....''..........;;;:cd0XNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXKKKKK
KKKKKKKOdc;;,;cooc;,...',;:loollc:;,'...'...''''..';cc:'........'',,'.......'''...'........';;'';:;:cd0XNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXKKKKKK
KKKKKKKOdc;;;cllc;'..',;;:loolc:;,'''.....''',;;,'.';::;,,,'.....',;,'...........'''.....',::;',;;;;:ok0XNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXKKKKKKK
KKKKKKKOo:;;cooc;'',;;::clooll:;,'...'',,,,;::c:,'..,:cccccc:,....',,'..,,'.......'....,,;;:;,,;,;,,:oxOXNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXKKKKKKKK
KKKKKKKOo:;:lool:;;:ccccloolc:;,,'',,;:ccclodddoc;'..,,;;;:c:,''.....'',,,'..''.....'',:::cc;;::;;,,:ldkKXNNNNNNNNNNNNNNNNNNNNNNXNNXXXXXXXXXXXKKKKKKKK
KKKKKKKOo:;:coolc::::::clollc:,''';;:clllcoxkkxol:,'.....'''...',,'...';;,'..';:,.....',,;;;:lolc::;;cokXNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXKKKKKKKKKK
KKKKKKKOo:;:loool:;;;;:looool:,'.',,:clooodxkkdololc;'...'',;,;:cc;,'.''',''.',,'....'...',;oxdoollclox0XNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXKKKKKKKKKK
KKKKKK0ko:;cloollc::;:clloool:,,,,;:cclodxxxkxxolodxdoc::ccooooddddl:,,;;'','.''';;,,::,.':oxkxddooodkOKNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXKKKKKKKKKK
KKKKKKOdc;;:cooolccclllooolllc::::::clodxxxkkkxddxkOOOkxxxxkxdxxdoooo:';:;''..',,;:;;clc:ldxkkxxddooxOKNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXKKKKKKKKKKKK
KKKK0Odc;;;:loddolllllooolooollllc::clloddxkkkkkkkO0000KKK0OxxkOkdoodoc;,;,'''',,;,,:llodxkkkkxxddoox0XNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXKKKKKKKKKKKKK
KKK0ko:;;;::loddolcllooooolllcccccccccllldxxkkkOOO00000KK00OO0000OkxOkdc;,''...'''',coodddxkkxxdooodx0XNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXKKKKKKKKKKKKKK
KKKOo:;;;:cclodddlllooolollcccccllllccccccloddxkkO00000OO000000K0000Oo;,'''.........':odxxxkxxxdddxkOKNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXKKKKKKKKKKKKKK
KK0xc;;;:clllodkxolooolllccccccllcc:::;;,;cclloodkOO00OkkkOOO0KK00KOl'................;dOOkkxkkxxkO0KXNNNNNNNNNNNNNNNNNNXXNXXXXXXXXXXXKKKKKKKKKKKKKKKK
KKOo:;;;:clodxk0Oxdddollccccccllcc:;,,''',;:cloddddxkOOkdoxkOO00000x;.................'oOOkkOO00O00XNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXKKKKKKKKKKKKKKKKK
0Oxc;;;;:ldxO0KK0kxddollcc::ccclccc:;;,,'',:clddoooodxOOo;,:ldkOOOOd;.................'lkkk0KKXXXXXNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKK
Oxl:;::coxO0KKKK0Oxddollc:;::cclloolc:::;,;:cllllllllodkkc'.';okkkxdc,................;oxxOKXNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKK
xolccldxO0KKKKKK0Okdddoc:::;;:cloddoc:cccccc:::cc::cllcokd,...':ooolc:,.............,:lodxOKNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKK
cloodk00KKKKKKKKK0Oxdolccc;;;;:cooolllooololcccc::cllc:lxx;....''cc;,,'...........,;;:coxOKXNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKKKK
clodk0KKKKKKKKKKK0Oxdolllc:::;;:ccloddooollloolccccc::coxxl'...''oxc;,'...........',:coxOKXNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKKKKK
cldk0KKKKKKKKKKKKK0kxoooolcc:;;:cclooddoolllooollc:;:coddxx;...':x0xc;;,'.........';ldk0XNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKKKKKKK
lokO0KK0KKKKKKKKKKK0kdoollccccccccllodxxdooodddolc::cloddkkl'..'lOKd:dkc;'.......';oxOKXNNNNNNNNNNNNNNNNNNNXXXNXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKKKKKKK
oxO0000000000KKKKKK0Oxdlllooolcc:ccloddddddddddoooolodddxxxxl'..l0Kxodococ::::cccooxOKXNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKKKKKKKK
dO0000000000000000K00Oxollooolccccloodxdddddooodddddddxxxxddo:..;lkOl,..''',,,;;:clk0XNNNNNNNNNNNXXXXXXXXXXXXXXXXXXXXXXXXXXXKXXKKKKKKKKKKKKKKKKKKKKKKK
kO00000000000000000000kdlllllllcccloddddoooooddxxxxdddxxxxddo:'..,okd,..........,ldOKXNNXXNNNXXXXXXXXXXXXXXXXXXXXXXXXXXXXKXKKKKKKKKKKKKKKKKKKKKKKKKKKK
kO00000000000000000000kdllc::loolcclooolclodxddxkxxddxxxxdolc:,.',,;cc:,'...''';:;ckKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK
kOOOO00000000000OO000Okdolc;:cllc:::lolclodddddxxdxxxxxxdoolcc:::;'.',;;;,,,,;;,''cOKXXXXXXXXXXXXXXXX zuph's Enumeration Framework KKKKKKKKKKKKKKKKKKK
kOOOO000000000000O00OOxoool:::cc;;;;:clldxxxdddoodddddddooooolllllc;,'..........;oOKKXXXXXXXKKKKXXXXXXXXXXXXX @zuphzuph XKKKKKKKKKKKKKKKKKKKK000000000
kOOOO0000000000000000Okdoooolccc:;;;,;:odxxxxxddoodddddooooloooooooollc::;;;;coxOKKKKKKKKKKKKKKKKKKKKKXXXXXKKKKXXXXXXKKXXXXXXXKKKKKKKKKKKKKKKKKK000000
kO0000000000KKKKK00000Odoodddoolcccc::cloodxxddolloooodooooooooooooooddxxxkOO0KKKKKKKKKKKKKKKKKKKKKKKKKKKKKXXXKKXXXXXKKKKKKKKKKKKKKKKKKKKKKKKKKKK00000
00KKKKKKKKKKKKKKKKKKKK0kolodddddoooollclloddddllclloooooooooooooolloodkOO000KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKXXKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK00000
KKXXKKKKKKKXXXKKKKKKKKK0koloodxxxddoolllllodddoloooolllllllllcccccldxkO000000KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK0000000
XXXXKKKKKXXXXXKKKKKKKKKK0xllooddxddoolllodxkOkxdddddoollcccccc::codkOO00000000000KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK000000000
XXXXKXXXXXXKXXKKKXXXKKKK0kocllodddoollcldkOO0Okxxxxxdolcccccccc:cdkO0000000000000KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK000000000"
        Write-Host ""
        Write-Host -ForegroundColor Cyan "Main Menu"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Network Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Process Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Registry Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Service Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Update Sniff (KBs)"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "|2@|\|d0/\/\"
        $mainMenu = Read-Host "`nSelection (leave blank to quit)"
        # Launch submenu1
        if($mainMenu -eq 1){
            subMenu1
        }
        # Launch submenu2
        if($mainMenu -eq 2){
            subMenu2
        }
        #Launch submenu3
        if($mainMenu -eq 3){
            submenu3
        }
        #Launch submenu4
        if($mainMenu -eq 4){
            submenu4
        }
        #Launch submenu5
        if($mainMenu -eq 5){
            submenu5
        }
        #Launch submenu6
        if($mainMenu -eq 6){
            submenu6
        }
    }
}
Function Get-ListeningTCPConnections {            
[cmdletbinding()]            
param(
)                       
try {            
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpListeners()            
    foreach($Connection in $Connections) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
                    
        $OutputObj = New-Object -TypeName PSobject            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
        $OutputObj            
                                        }
} catch {            
    Write-Error "Failed to get listening connections. $_"            
    }                  
}
function subMenu1 {
    $subMenu1 = 'X'
    while($subMenu1 -ne ''){
        Clear-Host
        Write-Host "`n`t`t Network Menu`n"
        Write-Host -ForegroundColor Cyan "Network Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Network Adapter Info"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Listening TCP Ports"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Name Server Lookup"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "List Network Devices (Domain)"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Get Domain Info of Device"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Get DNS Records for FQDN Zone"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Get Mapped Drives w/ Local Ref"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "List DNS Cache"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Windows Firewall Status"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "10"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Trace Hops to DNS/IP (Public or Internal)"
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        # Option 1
        if($subMenu1 -eq 1){
            $IPs = Get-NetIPAddress | Sort-Object InterfaceIndex | Format-Table InterfaceIndex, InterfaceAlias, AddressFamily, IPAddress, PrefixLength -Autosize
            Write-Output $IPs
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu1 -eq 2){
            $ListeningTCP = Get-ListeningTCPConnections | Format-Table -Autosize
            Write-Output $ListeningTCP
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu1 -eq 3){
            $nslookup = Read-Host "Enter DNS Address"
            nslookup.exe $nslookup
            [void][System.Console]::ReadKey($true)
        }
        # Option 4
        if($subMenu1 -eq 4){
            $NetworkDevices = Get-ADComputer -Filter * -properties * | Select-Object Name, DNSHostName, OperatingSystem, LastLogonDate | Format-Table -AutoSize
            Write-Output $NetworkDevices
            [void][System.Console]::ReadKey($true)
        }
        # Option 5
        if($subMenu1 -eq 5){
            $DomainInfo = Get-ADDomain
            Write-Output $DomainInfo
            [void][System.Console]::ReadKey($true)
        }
        # Option 6
        if($subMenu1 -eq 6){
            $DumpDNS = Get-DnsServerResourceRecord -ZoneName
            Write-Output $DumpDNS
            [void][System.Console]::ReadKey($true)
        }
        # Option 7
        if($subMenu1 -eq 7){
            net use
            [void][System.Console]::ReadKey($true)
        }
        # Option 8
        if($subMenu1 -eq 8){
            Get-WmiObject -query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" | Select-Object Entry, Name, Data | Format-Table -AutoSize
            [void][System.Console]::ReadKey($true)
        }
        # Option 9
        if($subMenu1 -eq 9){
            Get-NetFirewallProfile | Format-Table
            [void][System.Console]::ReadKey($true)
        }
        # Option 10
        if($subMenu1 -eq 10){
            $traceroute = Read-Host "Address to Trace"
            tracert.exe $traceroute
            [void][System.Console]::ReadKey($true)
        }
    }
}
function subMenu2 {
    $subMenu2 = 'X'
    while($subMenu2 -ne ''){
        Clear-Host
        Write-Host "`n`t`t Process Menu`n"
        Write-Host -ForegroundColor Cyan "Process Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Processes w/ ID, User, Path & Start Time"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Sched Tasks w/ Path, Name & State"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Stop Running Process w/ PID"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Start Stopped Process w/ PID"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Disable Windows Defender"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Create Process"
        $subMenu2 = Read-Host "`nSelection (leave blank to quit)"
        # Option 1
        if($subMenu2 -eq 1){
            Get-Process -IncludeUserName | Where UserName | Select-Object Id,Name,UserName,Path,StartTime | Format-Table -Autosize
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu2 -eq 2){
            Get-ScheduledTask | Format-Table -Autosize
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu2 -eq 3){
            Stop-Process
            [void][System.Console]::ReadKey($true)
        }
        # Option 4
        if($subMenu2 -eq 4){
            Start-Process
            [void][System.Console]::ReadKey($true)
        }
        # Option 5
        if($subMenu2 -eq 5){
            Set-MpPreference -DisableRealtimeMonitoring $true
            [void][System.Console]::ReadKey($true)
        }
        # Option 6
        if($subMenu2 -eq 6){
            $pathtoexe = Read-Host "C:\path\thugcrowd.exe"
            Start-Process -FilePath "$pathtoexe"
            [void][System.Console]::ReadKey($true)
        }
    }
}
function subMenu3 {
    $subMenu3 = 'X'
    while($subMenu3 -ne ''){
        Clear-Host
        Write-Host "`n`t`t Registry Menu`n"
        Write-Host -ForegroundColor Cyan "Registry Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "RDP"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Firewall"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Putty Sessions"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Windows Policies"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Windows Update Policy"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "HKLM Key Names Containing (Password) : Return Path/Type/Name"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "HKCU Key Names Containing (Password) : Return Path/Type/Name"
        $subMenu3 = Read-Host "`nSelection (leave blank to quit)"
        # Option 1
        if($subMenu3 -eq 1){
            Get-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server' | Format-Table | Out-String
            Write-Host
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu3 -eq 2){
            Get-ItemProperty -Path "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy" | Format-Table | Out-String
            Write-Host
            [void][System.Console]::ReadKey($true)
        }
        if($subMenu3 -eq 3){
            Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" | Format-Table | Out-String
            Write-Host
            [void][System.Console]::ReadKey($true)
        }
        if($subMenu3 -eq 4){
            Get-ChildItem "HKLM:\Software\Policies\*" | Format-Table | Out-String
            Write-Host
            [void][System.Console]::ReadKey($true)
        }
        if($subMenu3 -eq 5){
            Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\*" | Format-Table | Out-String
            Write-Host
            [void][System.Console]::ReadKey($true)
        }
        if($subMenu3 -eq 6){
            reg.exe query HKLM /f password /t REG_SZ /s | Format-Table | Out-String
            [void][System.Console]::ReadKey($true)
        }
        if($subMenu3 -eq 7){
            reg.exe query HKCU /f password /t REG_SZ /s | Format-Table | Out-String
            [void][System.Console]::ReadKey($true)
        }
    }
}
function subMenu4 {
    while($subMenu4 -ne ''){
        Clear-Host
        Write-Host "`n`t`t Service Menu`n"
        Write-Host -ForegroundColor Cyan "Service Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Services w/ Name, User & Start Mode"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Start Service w/ Name"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Stop Service w/ Name"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Create Service w/ Name & Full .exe Path"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Delete Service w/ Name"
        $subMenu4 = Read-Host "`nSelection (leave blank to quit)"
        # Option 1
        if($subMenu4 -eq 1){
            Get-WmiObject win32_service | Format-Table Name, StartName, StartMode
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu4 -eq 2){
            Start-Service
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu4 -eq 3){
            Stop-Service
            [void][System.Console]::ReadKey($true)
        }
        # Option 4
        if($subMenu4 -eq 4){
            $servicename = Read-Host "Service Name"
            $pathtoexe = Read-Host "C:\path\thugcrowd.exe"
            New-Service -Name $servicename -BinaryPathName "$pathtoexe -k netsvcs"
            [void][System.Console]::ReadKey($true)
        }
        # Option 5
        if($subMenu4 -eq 5){
            $servicetodel = Read-Host "Service Name to Delete"
            sc.exe delete $servicetodel
            [void][System.Console]::ReadKey($true)
        }
    }
}
function subMenu5 {
    while($subMenu5 -ne ''){
        Clear-Host
        Write-Host "`n`t`t Update Menu`n"
        Write-Host -ForegroundColor Cyan "Update Sniff"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Get Installed CUs w/ Acct/Date"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Search for Installed Update by KB# (Blank = Not Installed)"
        $subMenu5 = Read-Host "`nSelection (leave blank to quit)"
        # Option 1
        if($subMenu5 -eq 1){
            Get-HotFix
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu5 -eq 2){
            $KB = Read-Host "Full KB+#"
            Get-HotFix -Id $KB 
            [void][System.Console]::ReadKey($true)
        }
    }
}
function Get-UserSession {
    param(
        [CmdletBinding()] 
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName
    )
    begin {
        $ErrorActionPreference = 'Stop'
    }
    
    process {
        foreach ($Computer in $ComputerName) {
            try {
                quser /server:$Computer 2>&1 | Select-Object -Skip 1 | ForEach-Object {
                    $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s'
                    $HashProps = @{
                        UserName = $CurrentLine[0]
                        ComputerName = $Computer
                    }
                    if ($CurrentLine[2] -eq 'Disc') {
                            $HashProps.SessionName = $null
                            $HashProps.Id = $CurrentLine[1]
                            $HashProps.State = $CurrentLine[2]
                            $HashProps.IdleTime = $CurrentLine[3]
                            $HashProps.LogonTime = $CurrentLine[4..6] -join ' '
                            $HashProps.LogonTime = $CurrentLine[4..($CurrentLine.GetUpperBound(0))] -join ' '
                    } else {
                            $HashProps.SessionName = $CurrentLine[1]
                            $HashProps.Id = $CurrentLine[2]
                            $HashProps.State = $CurrentLine[3]
                            $HashProps.IdleTime = $CurrentLine[4]
                            $HashProps.LogonTime = $CurrentLine[5..($CurrentLine.GetUpperBound(0))] -join ' '
                    }
                    New-Object -TypeName PSCustomObject -Property $HashProps |
                    Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
                }
            } catch {
                New-Object -TypeName PSCustomObject -Property @{
                    ComputerName = $Computer
                    Error = $_.Exception.Message
                } | Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
            }
        }
    }
}
function subMenu6 {
    while($subMenu6 -ne ''){
        Clear-Host
        Write-Host "`n`t`t Random Stuff`n"
        Write-Host -ForegroundColor Cyan "|2@|\|d0/\/\"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Idle/Session Time (Internal DNS/IP)"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Real Time Input Monitor"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Screen Cap"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Screen Cap Remote (Save on This PC) Must be Unlocked"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Clear PS Log (User)"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan "Find Accessible Dirs using Path/Username (CTRL+C to Stop Output)"
        $subMenu6 = Read-Host "`nSelection (leave blank to quit)"
        # Option 1
        if($subMenu6 -eq 1){
            $ComputerName = Read-Host "Enter DNS/IP Address"
            Get-UserSession -ComputerName $ComputerName
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu6 -eq 2){
        Add-Type @'
            using System;
            using System.Diagnostics;
            using System.Runtime.InteropServices;
            namespace PInvoke.Win32 {
                public static class UserInput {
                    [DllImport("user32.dll", SetLastError=false)]
                    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
                    [StructLayout(LayoutKind.Sequential)]
                    private struct LASTINPUTINFO {
                        public uint cbSize;
                            public int dwTime;
                    }
                        public static DateTime LastInput {
                        get {
                            DateTime bootTime = DateTime.UtcNow.AddMilliseconds(-Environment.TickCount);
                            DateTime lastInput = bootTime.AddMilliseconds(LastInputTicks);
                            return lastInput;
                        }
                    }
                        public static TimeSpan IdleTime {
                        get {
                            return DateTime.UtcNow.Subtract(LastInput);
                        }
                    }
                    public static int LastInputTicks {
                        get {
                            LASTINPUTINFO lii = new LASTINPUTINFO();
                            lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
                            GetLastInputInfo(ref lii);
                            return lii.dwTime;
                        }
                    }
                }
            }
'@
        foreach ($i in 0..9) {
            Write-Host ("Last input " + [PInvoke.Win32.UserInput]::LastInput)
            Write-Host ("Idle for " + [PInvoke.Win32.UserInput]::IdleTime)
            Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)
        }
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu6 -eq 3){
            $File = "C:\screenshot.png"
            Add-Type -AssemblyName System.Windows.Forms
            Add-type -AssemblyName System.Drawing
            $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
            $Width = $Screen.Width
            $Height = $Screen.Height
            $Left = $Screen.Left
            $Top = $Screen.Top
            $bitmap = New-Object System.Drawing.Bitmap $Width, $Height
            $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
            $bitmap.Save($File) 
            Write-Output "Capture saved to:"
            Write-Output $File
            [void][System.Console]::ReadKey($true)
        }
        # Option 4
        if($subMenu6 -eq 4){
            $ComputerName = Read-Host "DNS/IP to Capture on Domain/Workgroup"
            foreach ($Computer in $ComputerName) {
            $File = "C:\screenshot.png"
            Add-Type -AssemblyName System.Windows.Forms
            Add-type -AssemblyName System.Drawing
            $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
            $Width = $Screen.Width
            $Height = $Screen.Height
            $Left = $Screen.Left
            $Top = $Screen.Top
            $bitmap = New-Object System.Drawing.Bitmap $Width, $Height
            $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
            $bitmap.Save($File) 
            Write-Output "Capture saved to:"
            Write-Output $File
            }
            [void][System.Console]::ReadKey($true)
        }
        # Option 5
        if($subMenu6 -eq 5){
            Remove-Item (Get-PSReadlineOption).HistorySavePath
            Write-Host "Log Cleared."
            [void][System.Console]::ReadKey($true)
        }
        # Option 6
        if($subMenu6 -eq 6){
            Write-Host -ForegroundColor red "This Script Takes Sometime to Run."
            $basefolder = read-host "Enter Directory Tree Starting Point (script is recursive)"
            $usertocheck = read-host "Enter The Username To Check For Access"
            $ntaccount = [System.Security.Principal.NTAccount]$usertocheck
            $ErrorActionPreference = "SilentlyContinue"
            try
            {
                $sid = $ntaccount.Translate([System.Security.Principal.SecurityIdentifier])
            }
            catch
            {
                throw "Could not resolve $usertocheck to a SID"
            }
            Write-Progress -Activity "Enumerating folders" -Status "pending"
            $folders = Get-ChildItem $basefolder -Recurse | Where-Object { $_.PSIsContainer } | Select-Object FullName
            $acls = New-Object -TypeName System.Collections.ArrayList
            $iLoopA = 0
            foreach ($folder in $folders)
            {
                Write-Progress -Activity "Enumerating ACL for folders" -Status "checking $($folder.FullName)" -PercentComplete ($iLoopA/ $folders.count*100)
                $aclItem = Get-Acl -path $folder.FullName
                $aclObject = @{
                    AclObject = $aclItem
                    Folder    = $folder.FullName
                }
                $aclPSObject = New-Object PSObject -Property $aclObject
                $acls.Add($aclPSObject) | Out-Null
                $iLoopA++
            }
            $iLoopB = 0
            $accessibleItems = New-Object -TypeName System.Collections.ArrayList
            foreach ($acl in $acls)
            {   
                $folder = (convert-path $acl.Folder)
                Write-Progress -Activity "Getting Security" -Status "checking $folder" -PercentComplete ($iLoopB/ $acls.count*100)
                foreach($access in $acl.AclObject.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
                { 
                    if ($access.IdentityReference.Value -eq $sid.Value)
                    {
                        $itemFound = @{
                            Mode   = $access.AccessControlType
                            User   = $ntaccount.Value
                            Folder = $folder
                        }
                        $obj = New-Object PSObject -Property $itemFound
                        $accessibleItems.Add($obj)| Out-Null
                    }
                }
                $iLoopB++
            }
            Write-Progress -Activity "Getting Security" -Completed "Done"
            $accessibleItems | Write-Output | Format-Table -Autosize            
        [void][System.Console]::ReadKey($true)
        }
    }
}
mainMenu
