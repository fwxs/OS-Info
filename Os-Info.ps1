BEGIN
{
$is_admin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

# Map User account type to a readable name
$privileges = DATA {
    ConvertFrom-StringData -StringData @'
    0 = Guest
    1 = User
    2 = Administrator
'@
}
Function Get-WmiTime
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$time
    )

    If([String]::IsNullOrEmpty($time))
    {
        return "None"
    }

    $year = $time.Substring(0, 4)
    $month = $time.Substring(4, 2)
    $day = $time.Substring(6, 2)

    $hour = $time.Substring(8, 2)
    $minute = $time.Substring(10, 2)
    $second = $time.Substring(12, 2)

    return $year + "/" + $month + "/" + $day + " " + $hour + ":" + $minute + ":" + $second
}


#### System menu ####
Function List-Hardware
{
    # Map domain roles.
    $domain_role = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Standalone workstation
        1 = Member workstation
        2 = Standalone server
        3 = Member server
        4 = Backup domain controller
        5 = Primary domain controller
'@
    }
    
    $form_factor = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Unknown
        1 = Other
        2 = SIP
        3 = DIP
        4 = ZIP
        5 = SOJ
        6 = Proprietary
        7 = SIMM
        8 = DIMM
        9 = TSOP
        10 = PGA
        11 = RIMM
        12 = SODIMM
        13 = SRIMM
        14 = SMD
        15 = SSMP
        16 = QFP
        17 = TQFP
        18 = SOIC
        19 = LCC
        20 = PLCC
        21 = BGA
        22 = FPBGA
        23 = LGA
'@
    }
    
    $memory_type = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Unknown
        1 = Other
        2 = DRAM
        3 = Synchronous DRAM
        4 = Cache DRAM
        5 = EDO
        6 = EDRAM
        7 = VRAM
        8 = SRAM
        9 = RAM
        10 = ROM
        11 = Flash
        12 = EEPROM
        13 = FEPROM
        14 = EPROM
        15 = CDRAM
        16 = 3DRAM
        17 = SDRAM
        18 = SGRAM
        19 = RDRAM
        20 = DDR
        21 = DDR2
        22 = DDR2 FB-DIMM
        24 = DDR3
        25 = FBD2
'@
    }
    
    $type_detail = DATA {
        ConvertFrom-StringData -StringData @'
        1 = Reserved
        2 = Other
        4 = Unknown
        8 = Fast-Paged
        16 = Static column
        32 = Pseudo-static
        64 = RAMBUS
        128 = Synchronous
        256 = CMOS
        512 = EDO
        1024 = Window DRAM
        2048 = Cache DRAM
        4096 = Non-Volatile
'@
    }
    
    $architecture = DATA {
        ConvertFrom-StringData -StringData @'
        0 = x86
        1 = MIPS
        2 = Alpha
        3 = powerPC
        5 = ARM
        6 = ia64
        9 = x64
'@
    }

    $availability = DATA {
        ConvertFrom-StringData -StringData @'
        1 = Other
        2 = Unknown
        3 = Running/Full Power
        4 = Warning
        5 = In Test
        6 = Not available
        7 = Power off
        8 = Off line
        9 = Off duty
        10 = Degraded
        11 = Not installed
        12 = Install error
        13 = Power save - Unknown
        14 = Power save - Low Power mode
        15 = Power save - Standby
        16 = Power cycle
        17 = Power save - Warning
        18 = Paused
        19 = Not ready
        20 = Not configured
        21 = Quiesced
'@
    }

    $cpu_status = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Unknown
        1 = CPU Enabled
        2 = CPU disabled by user via BIOS setup
        3 = CPU disabled by BIOS (POST error)
        4 = CPU is IDLE
        5 = Reserved
        6 = Reserved
        7 = Other
'@
    }

    "############# Base board information #############"
    Get-WmiObject -Class Win32_BaseBoard | Format-List -Property Description, Manufacturer, Product, SerialNumber,
                                                                 Version, @{Name="ConfigOptions"; Expression=({ $($_.ConfigOptions -join " ") })},
                                                                 @{Name="Architecture"; Expression=({ $architecture["$($_.Architecture)"] })},
                                                                 @{Name="Availability"; Expression=({ $availability["$($_.Availability)"]})},
                                                                 @{Name="CpuStatus"; Expression=({ $cpu_status["$($_.CpuStatus)"] })}                                                                



    "############# CPU information #############"
    Get-WmiObject -Class Win32_Processor | Format-List -Property Name, Description, Manufacturer, Role,
                                                                 NumberOfCores, NumberOfEnabledCore, NumberOfLogicalProcessors


    "############# Device information #############"
    Get-WmiObject -Class Win32_ComputerSystem | Format-List -Property Name, Manufacturer, Model, SystemType,
                                                                      Description, NumberOfProcessors, NumberOfLogicalProcessors, Domain,
                                                                      @{Name="Domain role"; Expression={$domain_role["$($_.DomainRole)"]}},
                                                                      @{Name="RAM (GB)"; Expression=({[Math]::Round($($_.TotalPhysicalMemory / 1GB), 2)})}
    
    "############# Memory information #############"
    Get-WmiObject -Class Win32_PhysicalMemory | Format-List -Property Name, Description, Tag, DeviceLocator,
                                                                      BankLabel, PartNumber, SerialNumber,
                                                                      @{Name="Speed"; Expression=({ "{0} MHz" -f $_.Speed })},
                                                                      @{Name="Capacity"; Expression=({ "{0} GB" -f [Math]::Round($($_.Capacity / 1GB), 2) })},
                                                                      @{Name="ConfiguredVoltage"; Expression=({ "{0} V" -f $($_.ConfiguredVoltage / 1000) })},
                                                                      @{Name="FormFactor"; Expression=({ $form_factor["$($_.FormFactor)"] })},
                                                                      @{Name="MemoryType"; Expression=({ $memory_type["$($_.MemoryType)"] })},
                                                                      @{Name="TypeDetail"; Expression=({ $type_detail["$($_.TypeDetail)"] })},
                                                                      TotalWidth, DataWidth, Status
}


Function OS-Information
{
# Operating system information
    "############# OS information #############"
    Get-WmiObject -Class Win32_OperatingSystem  | Format-List -Property Caption, BuildNumber, OSArchitecture, BuildType,
                                                                   SystemDrive, @{Name="LastBootUpTime"; Expression=({Get-WmiTime -time $_.LastBootUpTime})}, SerialNumber, 
                                                                   @{Name="FreeVirtualMemory (GB)"; Expression=({[Math]::Round($($_.FreeVirtualMemory / 1MB), 2)})},
                                                                   @{Name="FreePhysicalMemory (GB)"; Expression=({[Math]::Round($($_.FreePhysicalMemory / 1MB), 2)})},
                                                                   @{Name="TotalVirtualMemorySize (GB)"; Expression=({[Math]::Round($($_.TotalVirtualMemorySize / 1MB), 2)})},
                                                                   @{Name="TotalVisibleMemorySize (GB)"; Expression=({[Math]::Round($($_.TotalVisibleMemorySize / 1MB), 2)})},
                                                                   NumberOfProcesses, RegisteredUser
}


Function List-Disk
{
    # Map ConfigManagerErrorCode
    $config_manager_error_code = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Device is working properly.
        1 = Device is not configured properly.
        2 = Windows cannot load the driver for this device.
        3 = Driver for this device might be corrupted, or the system may be low on memory or other resources.
        4 = Device is not working properly. One of its driver or the registry might be corrupted.
        5 = Driver for the device requires a resource that windows cannot manage.
        6 = Boot configuration for the device conflicts with other devices.
        7 = Cannot filter.
        8 = Driver loader for the device is missing.
        9 = The controlling firmware is incorrectly reporting resources for the device.
        10 = Device cannot start.
        11 = Device failed.
        12 = Device cannot find enough free resource to use.
        13 = Windows cannot verify the device's resources.
        14 = Device cannot work properly until the computer is restarted.
        15 = Device is not working properly due to a posible re-enumeration problem.
        16 = Windows cannot identify all of the resources that the device uses.
        17 = Device is requesting an unknown resource type.
        18 = Device drivers must be reinstalled.
        19 = Failed using the VxD loader.
        20 = Registry might be corrupted.
        21 = System failure: Try changing the driver for this device. If it doesn't work, see hardware docs. Windows is removing the device.
        22 = Device is disabled.
        23 = System failure: Try changing the driver for this device. If it doesn't work, see hardware docs.
        24 = Device is not present, is not working properly, or does not have all its drivers installed.
        25 = Windows is still setting up this device.
        26 = Windows is still setting up this device.
        27 = Device does not have a valid log configuration.
        28 = Device drivers are not installed.
        29 = Device is disabled. The device firmware did not provide the required resources.
        30 = Device is using an IRQ resource that another device is using.
        31 = evice is not working properly. Windows cannot load the required device drivers.
'@
    }

    
    "############# Disk drives #############"
    Get-WmiObject -Class Win32_DiskDrive | Format-List -Property Caption, Description, Manufacturer, Model,
                                                                 PNPDeviceID, FirmwareRevision, DeviceID,  LastErrorCode,
                                                                 SerialNumber, MediaType, Status, Partitions,
                                                                 @{Name="ConfigManagerErrorCode"; Expression=({ $config_manager_error_code["$($_.ConfigManagerErrorCode)"] })},
                                                                 InterfacetType, Index, BytesPerSEctor, NeedsCleaning,
                                                                 @{Name="Size"; Expression=({ "{0} GB" -f [Math]::Round($_.Size / 1GB, 2) })},
                                                                 @{Name="Capabilities"; Expression=({ $_.CapabilityDescriptions -join ", " })},
                                                                 TotalCylinders, TotalHeads, TotalSectors, TotalTracks,
                                                                 TracksPerCylinder, SectorsPerTrack
}


Function Get-BIOSInformation
{
    # Map BIOS Characteristics.
    $bios_characteristics = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Reserved
        1 = Reserved
        2 = Unknown
        3 = BIOS characteristics not supported
        4 = ISA
        5 = MCA
        6 = EISA
        7 = PCI
        8 = PCMCIA
        9 = PnP
        10 = APM
        11 = BIOS upgradeable (Flash)
        12 = BIOS shadowing supported
        13 = VL-VESA supported
        14 = ESCD available
        15 = Boot from CD
        16 = Selectable boot
        17 = BIOS ROM
        18 = Boot from PCMCIA
        19 = EDD supported
        20 = Japanese floppy NEC 9800
        21 = Japanese floppy Toshiba
        22 = 360KB Floppy services
        23 = 1.2MB Floppy services
        24 = 720KB Floppy services
        25 = 2.88MB Floppy services
        26 = Print screen service
        27 = 8042 keyboard services
        28 = Serial services
        29 = Printer services
        30 = CGA/Mono Video services
        31 = NEC PC-98
        32 = ACPI
        33 = USB legacy
        34 = AGP
        35 = I2O boot
        36 = LS-120 boot
        37 = ATAPI ZIP drive
        38 = 1394 boot
        39 = Smart battery
        40 = Reserved by manufacturer
        41 = Reserved by manufacturer
        42 = Reserved by manufacturer
        43 = Reserved by manufacturer
        44 = Reserved by manufacturer
        45 = Reserved by manufacturer
        46 = Reserved by manufacturer
        47 = Reserved by manufacturer
        48 = Reserved by manufacturer
        49 = Reserved by manufacturer
        50 = Reserved by manufacturer
        51 = Reserved by manufacturer
        52 = Reserved by manufacturer
        53 = Reserved by manufacturer
        54 = Reserved by manufacturer
        55 = Reserved by manufacturer
        56 = Reserved by manufacturer
        57 = Reserved by manufacturer
        58 = Reserved by manufacturer
        59 = Reserved by manufacturer
        60 = Reserved by manufacturer
        61 = Reserved by manufacturer
        62 = Reserved by manufacturer
        63 = Reserved by manufacturer
'@
    }
    $target_os = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Unknown
        1 = Other
        2 = MACOS
        3 = ATTUNIX
        4 = DGUX
        5 = DECNT
        6 = Digital Unix
        7 = OpenVMS
        8 = HPUX
        9 = AIX
        10 = MVS
        11 = OS400
        12 = OS/2
        13 = JavaVM
        14 = MSDOS
        15 = WIN3x
        16 = WIN95
        17 = WIN98
        18 = WINNT
        19 = WINCE
        20 = NCR3000
        21 = NetWare
        22 = OSF
        23 = DC/OS
        24 = Reliant UNIX
        25 = SCO UnixWare
        26 = SCO OpenServer
        27 = Sequent
        28 = IRIX
        29 = Solaris
        30 = SunOS
        31 = U6000
        32 = ASERIES
        33 = TandemNSK
        34 = TandemNT
        35 = BS2000
        36 = LINUX
        37 = Lynx
        38 = XENIX
        39 = VM/ESA
        40 = Interactive UNIX
        41 = BSDUNIX
        42 = FreeBSD
        43 = NetBSD
        44 = GNU Hurd
        45 = OS9
        46 = MACH Kernel
        47 = Inferno
        48 = QNX
        49 = EPOC
        50 = IxWorks
        51 = VxWorks
        52 = MiNT
        53 = BeOS
        54 = HP MPE
        55 = NextStep
        56 = PalmPilot
        57 = Rhapsody
        58 = Windows 2000
        59 = Dedicated
        60 = VSE
        61 = TPF
'@
    }
    $software_element_state = DATA {
        ConvertFrom-StringData -StringData @'
        0 = Deployable
        1 = Installable
        2 = Executable
        3 = Running
'@
    }

    $bios_information = Get-WmiObject -Class Win32_BIOS
    $characteristics = foreach($digit in $bios_information.BiosCharacteristics){ $bios_characteristics["$($digit)"] }
    
    "############# BIOS information #############"
    Format-List -InputObject $bios_information -Property Manufacturer, Version, Name, Description,
                                                         Serial, SMBIOSPresent, InstallableLanguages,
                                                         CurrentLanguage, PrimaryBIOs,
                                                         @{Name="BIOSCharacteristics"; Expression=({ $characteristics -join "`n " })},
                                                         @{Name="ListOfLanguages"; Expression=({ $_.ListOfLanguages -join ", " })},
                                                         @{Name="ReleaseDate"; Expression=({Get-WmiTime -time $_.ReleaseDate})},
                                                         @{Name="TargetOS"; Expression=({ $target_os["$($_.TargetOperatingSystem)"] })},
                                                         @{Name="SoftwareElementState"; Expression=({ $software_element_state["$($_.SoftwareElementState)"] })}
}


Function List-Qfe
{
    # Based on Tom Arbuthnot script.
    # http://tomtalks.uk/2013/09/list-all-microsoftwindows-updates-with-powershell-sorted-by-kbhotfixid-get-microsoftupdate/
    $updates = New-object -ComObject Microsoft.Update.Searcher

    $updates_collection = @()

    foreach($update in $updates.QueryHistory(0, $updates.GetTotalHistoryCount()))
    {
        $update_title = $update.Title

        $KB = $update_title | Select-String -Pattern "KB\d*" | Select-Object { $_.Matches }
        
        $output = New-Object -TypeName PSObject
        $output | Add-Member NoteProperty "HotFixID" -Value $KB.' $_.Matches '.Value
        $output | Add-Member NoteProperty "Title" -Value $update_title
        $output | Add-Member NoteProperty "Date" -Value $update.Date

        $updates_collection += $output
    }
    
     Format-Table -AutoSize -InputObject $updates_collection -Property HotFixID, Title, Date
}

Function List-Volumes
{
    Get-WmiObject -Class Win32_Volume | Format-Table -Property Name, FileSystem, BlockSize,
                                                               @{Name="Capacity"; Expression=({ "{0} GB" -f [Math]::Round($_.Capacity / 1GB, 2) })},
                                                               @{Name="FreeSpace"; Expression=({ "{0} MB" -f [Math]::Round($_.FreeSpace / 1MB, 2) })} -AutoSize
}


Function Describe-Volume
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$name
    )
    ## Remove the '\' in the last position.
    $volume_name = $name.Remove($name.Length - 1)
    Get-WmiObject -Class Win32_Volume -Filter "Name='$($volume_name)\\'" | Format-List -Property Name, Caption, Description, Label,
                                                                                                FileSystem, SerialNumber, SystemName, SystemVolume,
                                                                                                DriveLetter, Automount, Access, PNPDeviceID,
                                                                                                @{Name="Capacity"; Expression=({ "{0} GB" -f [Math]::Round($_.Capacity / 1GB, 2) })},
                                                                                                @{Name="FreeSpace"; Expression=({ "{0} MB" -f [Math]::Round($_.FreeSpace / 1MB, 2) })},
                                                                                                ErrorCleared, ErrorDescription, ErrorMethodology
}

#### End of system menu ####

#### Account menu ####
Function List-AllUsers
{
    $account_type = DATA {
        ConvertFrom-StringData -StringData @'
        256 = UF_TEMP_DUPLICATE_ACCOUNT
        512 = UF_NORMAL_ACCOUNT
        2048 = UF_INTERDOMAIN_TRUST_ACCOUNT
        4096 = UF_WORKSTATION_TRUST_ACCOUNT
        8192 = UF_SERVER_TRUST_ACCOUNT
'@
    }
    Get-WmiObject -Class Win32_UserAccount | Format-Table -AutoSize -Property Name, Domain, Disabled, LocalAccount,
                                                                              Lockout, PasswordChangeable, PasswordRequired,
                                                                              @{Name="AccountType"; Expression=({ $account_type["$($_.AccountType)"] })}
}


Function List-LogonUsers
{
    Get-WmiObject -Class Win32_NetworkLoginProfile | Format-Table -AutoSize -Property Caption, Name, UserType, UserId,
                                                                                      @{Name="Privileges"; Expression=({$privileges["$($_.Privileges)"]})}
}


Function Describe-User
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$name
    )

    Get-WmiObject -Class Win32_NetworkLoginProfile -Filter "Name LIKE '%$($name)%'"| Format-List -Property Name, Caption, FullName, UserType, 
                                                                                                           Description, ScriptPath, BadPasswordCount, HomeDirectory,
                                                                                                           HomeDirectoryDrive, LastLogon, LastLogoff, LogonServer,
                                                                                                           NumberOfLogons,
                                                                                                           @{Name="Privileges"; Expression=({$privileges["$($_.Privileges)"]})},
                                                                                                           @{Name="PasswordExpires"; Expression=({Get-WmiTime -time $_.PasswordExpires})}
}


Function List-Groups
{
    Get-WmiObject -Class Win32_Group | Format-Table -AutoSize
}
#### End of user menu ####

#### Network menu ####
Function List-ActiveInterfaces
{

    "############# Interface Information #############"
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where {$_.IPAddress -ne $null} | Format-List -Property Description, InterfaceIndex, IPEnabled,
                                                                                                                    @{Name="IPAddress"; Expression=({ $_.IPAddress -join ", " })},
                                                                                                                    @{Name="DefaultIPGateway"; Expression=({ $_.DefaultIPGateway -join " " })},
                                                                                                                    @{Name="IPSubnet"; Expression=({ $_.IPSubnet -join " " })}, MACAddress,
                                                                                                                    IPConnectionMetric, DHCPEnabled, DHCPServer, DNSDomain,
                                                                                                                    @{Name="DNSDomainSuffixSearchOrder"; Expression=({ $_.DNSDomainSuffixSearchOrder -join " " })},
                                                                                                                    @{Name="DNSServerSearchOrder"; Expression=({ $_.DNSServerSearchOrder -join " " })},
                                                                                                                    DNSHostName, ServiceName, TcpipNetbiosOptions, DatabasePath
}


Function List-NetworkRoutes
{
    # Map Route protocol
    $protocols = DATA {
        ConvertFrom-StringData -StringData @'
        1 = other
        2 = local
        3 = netmgmt
        4 = icmp
        5 = egp
        6 = ggp
        7 = hello
        8 = rip
        9 = is-is
        10 = es-is
        11 = ciscoIgrp
        12 = bbnSpfIgp
        13 = ospf
        14 = bgp
'@
    }

    # Map route type
    $types = DATA {
        ConvertFrom-StringData -StringData @'
        1 = other
        2 = invalid
        3 = direct
        4 = indirect
'@
    }
    
    "############# Network route Information #############"
    Get-WmiObject -Class Win32_IP4RouteTable | Format-Table -AutoSize -Property Destination, 
                                                                                @{Name="Age"; Expression=({"{0} secs" -f $_.Age})},
                                                                                InterfaceIndex, Mask, Metric1, NextHop,
                                                                                @{Name="Protocol"; Expression=({$protocols["$($_.Protocol)"]})},
                                                                                @{Name="Type"; Expression=({$types["$($_.Type)"]})}
}


Function List-DomainInformation
{
    "############# Domain information #############"
    Get-WmiObject -Class Win32_NTDomain | Format-List -Property DomainName, DomainControllerName, DomainControllerAddress,
                                                                DnsForestName, DcSiteName, Status,
                                                                Roles, PrimaryOwnerName, PrimaryOwnerContact
}

#### End of network menu ####

#### Processes group ####
Function List-Processes
{
    # Running process
    "############# Running processes #############"
    Get-WmiObject -Class Win32_Process | Format-Table -AutoSize -Property ProcessId, ProcessName,
                                                                    @{Name="Owner"; Expression=({$_.GetOwner().User})},
                                                                    @{Name="CreationDate"; Expression=({(Get-WmiTime -time $_.CreationDate)})}
}


Function Get-ProcessModules
{
    param
    (
        [Parameter(Mandatory=$true)]
        [UInt16]$process_id
    )
    Get-Process -Id $process_id -Module | Format-Table -AutoSize -Property ModuleName, FileName,
                                                                           @{Name="Size"; Expression=({ "{0} KB" -f [Math]::Round($_.ModuleMemorySize / 1KB, 2)})},
                                                                           @{Name="FileExists"; Expression=({[System.IO.File]::Exists($_.FileName)})},
                                                                           @{Name="FileCreationTime"; Expression=({[System.IO.File]::GetCreationTime($_.FileName)})},
                                                                           @{Name="FileLastWriteTime"; Expression=({[System.IO.File]::GetLastWriteTime($_.FileName)})},
                                                                           @{Name="FileAttributes"; Expression=({[System.IO.File]::GetAttributes($_.FileName)})}
}


Function Describe-Process
{
    param
    (
        [Parameter(Mandatory=$true)]
        [uint16]$process_id
    )
    $process_info = Get-WmiObject -Class Win32_Process -Filter "ProcessId='$process_id'"

    Format-List -InputObject $process_info -Property Name, CommandLine, Status, Priority,
                                                     Path, WindowsVersion, SessionId, OSName,
                                                     @{Name="CreationDate"; Expression=({Get-WmiTime -time $_.CreationDate})},
                                                     Handle, HandleCount, ThreadCount, ExecutionState,
                                                     @{Name="KernelModeTime (seconds)"; Expression=({$_.KernelModeTime})},
                                                     @{Name="UserModeTime (seconds)"; Expression=({$_.UserModeTime})},
                                                     @{Name="WorkingSetSize"; Expression=({ "{0} MB" -f [Math]::Round(($_.WorkingSetSize / 1MB), 3)})},
                                                     @{Name="PeakWorkingSetSize"; Expression=({ "{0} MB"-f $_.PeakWorkingSetSize})}

    If(($process_info.GetOwner().User -eq $env:USERNAME) -or ($is_admin))
    {
        Get-ProcessModules -process_id $process_id
    }
}

#### End of processes group ####

#### Services group ####
Function List-Services
{
    # List Services
    "############# Running services #############"
    Get-WmiObject -Class Win32_Service | Sort-Object -Property ProcessId | FT -Property Name, ProcessId, ServiceType, State, Status, SystemName
}


Function Describe-Service
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$service_name
    )
    $service_instance = New-Object -TypeName System.ServiceProcess.ServiceController($service_name)

    $service_wmi_data = Get-WmiObject -Class Win32_Service -Filter "Name='$service_name'" | Select -Property Name, Caption, Description, PathName,
                                                                                                             SystemName, ServiceType, ProcessId, State,
                                                                                                             ErrorControl, StartName, StartMode
    $service_information = New-Object -TypeName psobject -Property @{
                                                                     Name = $service_wmi_data.Name
                                                                     Caption = $service_wmi_data.Caption
                                                                     Description = $service_wmi_data.Description
                                                                     PathName = $service_wmi_data.PathName
                                                                     DependendsOn = $service_instance.DependentServices | foreach {$_.Name + " "}
                                                                     AssociatedServices = $service_instance.ServicesDependedOn | foreach {$_.Name + " "}
                                                                     SystemName = $service_wmi_data.SystemName
                                                                     ServiceType = $service_wmi_data.ServiceType
                                                                     ProcessId = $service_wmi_data.ProcessId
                                                                     ServiceState = $service_wmi_data.State
                                                                     ErrorControl = $service_wmi_data.ErrorControl
                                                                     StartedBy = $service_wmi_data.StartName
                                                                     StartMode = $service_wmi_data.StartMode
                                                                    }
    Format-List -InputObject $service_information
}

#### End of services group ####

#### Drivers group ####
Function List-Drivers
{
    # Windows drivers
    "############# Listing windows drivers #############"
    Get-WmiObject -Class Win32_SystemDriver | Sort-object -Property State | Format-Table -Property Name, ServiceType, State, PathName -AutoSize
}


Function Describe-Driver
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$driver_name
    )

    Get-WmiObject -Class Win32_SystemDriver -Filter "Name='$driver_name'" | Format-List -Property Name, Caption, Description, PathName,
                                                                                                  ServiceType, Started, StartMode, AcceptStop,
                                                                                                  AcceptPause, StartName, SystemName, Path
}

#### End of drivers group ####

#### Firewall group ####
Function List-FirewallProfiles
{
    "############# Firewall profiles #############"
    Get-NetFirewallProfile | Format-Table -AutoSize -Property Name, Enabled, LogFileName, LogMaxsizeKilobytes
}


Function List-InboundRules
{
    "############# Firewall inbound rules #############"
    Get-NetFirewallRule -Direction Inbound | Format-Table -Property @{Name="Name"; Expression=({$_.Name}); Width=30},
                                                                    @{Name="Enabled"; Expression=({$_.Enabled}); Width=10},
                                                                    @{Name="Profile"; Expression=({$_.Profile}); Width=30},
                                                                    @{Name="Action"; Expression=({$_.Action}); Width=10},
                                                                    @{Name="EdgeTraversalPolicy"; Expression=({$_.EdgeTraversalPolicy}); Width=20}
}


Function List-OutboundRules
{
    "############# Firewall outbound rules #############"
    Get-NetFirewallRule -Direction Outbound | Format-Table -Property @{Name="Name"; Expression=({$_.Name}); Width=30},
                                                                     @{Name="Enabled"; Expression=({$_.Enabled}); Width=10},
                                                                     @{Name="Profile"; Expression=({$_.Profile}); Width=30},
                                                                     @{Name="Action"; Expression=({$_.Action}); Width=10},
                                                                     @{Name="EdgeTraversalPolicy"; Expression=({$_.EdgeTraversalPolicy}); Width=20}
}

#### End of FW group ####

#### Scheduled Task group ####
Function List-ScheduledTasks
{
    Get-ScheduledTask | Format-Table -AutoSize -Property TaskName, TaskPath, Author
}


Function Describe-SC
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$task_name
    )
    $sched_task = Get-ScheduledTask -TaskName $task_name
    $task_principal = $sched_task.Principal
    $task_settings = $sched_task.Settings

    $sched_task_info = Get-ScheduledTaskInfo -TaskName "$task_name" -TaskPath "$sched_task.TaskPath"

    $task_information = New-Object -TypeName psobject -Property @{
                                                                    TaskName=$sched_task.TaskName
                                                                    TaskDescription=$sched_task.Description
                                                                    TaskDocumentation=$sched_task.Documentation
                                                                    LastRunDate=$sched_task_info.LastRunTime
                                                                    NextRunDate=$sched_task_info.NextRunTime
                                                                    LastTaskResult=$sched_task_info.LastTaskResult
                                                                    NumberOfMissedRuns=$sched_task_info.NumberOfMissedRuns
                                                                    Author=$sched_task.Author
                                                                    Source=$sched_task.Source
                                                                    GroupId=$task_principal.Id
                                                                    UserId=$task_principal.UserId
                                                                    RunLevel=$task_principal.RunLevel
                                                                    RequiredPrivilege=$task_principal.RequiredPrivilege
                                                                    TaskState=$sched_task.State
                                                                    TaskActions=$sched_task.Actions
                                                                    TaskTriggers=$sched_task.Triggers
                                                                    WakeToRun=$task_settings.WakeToRun
                                                                    RunOnlyIfNetworkAvailable=$task_settings.RunOnlyIfNetworkAvailable
                                                                    RunOnlyIfIdle=$task_settings.RunOnlyIfIdle
                                                                    Hidden=$task_settings.Hidden
                                                                    Enabled=$task_settings.Enabled
                                                                    RestartInterval=$task_settings.RestartInterval
                                                                 }
    Format-List -InputObject $task_information
}

#### End of scheduled task group ####

Function Print-Banner
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$banner
    )
$main = "
##############################################
##                  OS-Info                 ##
##############################################

[1] Go to system menu.
[2] Go to accounts menu.
[3] Go to network menu.
[4] Go to running processes menu.
[5] Go to services menu.
[6] Go to drivers menu.
[7] Go to firewall Menu
[8] Go to scheduled tasks menu.
[0] Exit.
"

$system = "
##############################################
##               System menu                ##
##############################################
[1] Print hardware information.
[2] Print OS information.
[3] Print disk information.
[4] Print installed KBs.
[5] Print volume information.
[6] Describe volume.
[9] Go back.
[0] Exit
"

$account = "
##############################################
##               Account menu               ##
##############################################
[1] List users.
[2] List logon users.
[3] Describe user.
[4] List groups.
[5] Describe group.
[9] Go back.
[0] Exit
"

$network =  "
##############################################
##               Network menu               ##
##############################################
[1] List active interfaces.
[2] List network routes.
[3] List domain information.
[4] List TCP connections.
[5] List UDP endpoints.
[9] Go back.
[0] Exit
"

$process = "
##############################################
##               Process menu               ##
##############################################
[1] List running processes.
[2] Describe process.
[9] Go back.
[0] Exit
"

$service = "
##############################################
##               Service menu               ##
##############################################
[1] List services.
[2] Describe service.
[9] Go back.
[0] Exit
"

$driver = "
##############################################
##               Drivers menu               ##
##############################################
[1] List drivers.
[2] Describe driver.
[9] Go back.
[0] Exit
"

$firewall = "
##############################################
##            Net Firewall menu             ##
##############################################
[1] To get inbound rules.
[2] To get outbound rules.
[3] List FW profiles.
[9] Go back.
[0] Exit.
"

$sched_task =  "
##############################################
##           Scheduled tasks menu           ##
##############################################
[1] List all tasks.
[2] Describe scheduled task.
[9] Go back.
[0] Exit.
"

    $print = $null

    Switch($banner)
    {
        'main' { $print = $main }
        'sys' { $print = $system }
        'account' { $print = $account }
        'network' { $print = $network }
        'process' { $print = $process }
        'service' { $print = $service }
        'drivers' { $print = $driver }
        'fw' { $print = $firewall }
        'sc' { $print = $sched_task }
    }

    Write-Host -Object $print
}


Function Sys-Information
{   
    Print-Banner -banner 'sys'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\System]"
        switch($option)
        {
            1 { List-Hardware }
            2 { OS-Information }
            3 { List-Disk }
            4 { List-Qfe }
            5 { List-Volumes }
            6
            {
                $volume_name = Read-Host -Prompt "Volume name"
                Describe-Volume -Name $volume_name
            }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'sys'
    }

}


Function Account-Menu
{
    Print-Banner -banner 'account'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\Accounts]"
        switch($option)
        {
            1 { List-AllUsers }
            2 { List-LogonUsers }
            3
            {
                $user_name = Read-Host "User name"
                Describe-User -name $user_name
            }
            4 { List-Groups }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'account'
    }
}


Function Net-Menu
{
    Print-Banner -banner 'network'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\Net]"
        switch($option)
        {
            1 { List-ActiveInterfaces }
            2 { List-NetworkRoutes }
            3 { List-DomainInformation }
            4
            { 
                "############# TCP network connections #############"
                Get-NetTCPConnection -State Established, Listen | Where {$_.RemoteAddress -ne "0.0.0.0"} | Format-Table -AutoSize
            }
            5
            {
                "############# UDP network connections #############"
                Get-NetUDPEndpoint | Format-Table -AutoSize -Property LocalAddress,  LocalPort, Status, CreationTime, OwningProcess
            }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'network'
    }
}


Function Process-Menu
{
    Print-Banner -banner 'process'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\Process]"
        switch($option)
        {
            1 { List-Processes }
            2
            {
                $process_id = Read-Host -Prompt "Process id"
                Describe-Process -process_id $process_id
            }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'process'
    }

}


Function Services-Menu
{
    Print-Banner -banner 'service'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\Service]"
        switch($option)
        {
            1 { List-Services }
            2
            {
                $service_name = Read-Host -Prompt "Service name"
                Describe-Service -service_name $service_name
            }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'service'
    }
}


Function Drivers-Menu
{
    Print-Banner -banner 'drivers'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\Drivers]"
        switch($option)
        {
            1 { List-Drivers }
            2
            {
                $driver_name = Read-Host -Prompt "Driver name"
                Describe-Driver -driver_name $driver_name
            }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'drivers'
    }
}


Function Firewall-Menu
{
    Print-Banner -banner 'fw'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\FW]"
        switch($option)
        {
            1 { List-InboundRules }
            2 { List-OutboundRules }
            3 { List-FirewallProfiles }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'fw'
    }
}


Function Sc-Menu
{
    Print-Banner -banner 'sc'
    while($true)
    {
        $option = Read-Host -Prompt "[OS-Info\SC]"
        switch($option)
        {
            1 { List-ScheduledTasks }
            2
            {
                $task_name = Read-Host -Prompt "Enter task name"
                Describe-SC -task_name $task_name
            }
            9 { Main-Menu }
            0 { exit }
        }
        Print-Banner -banner 'sc'
    }
}


Function Main-Menu
{
    Print-Banner -banner 'main'
    While ($true)
    {
        $option = Read-Host -Prompt "[OS-Info]"
        Switch($option)
        {
            1 { Sys-Information }
            2 { Account-Menu }
            3 { Net-Menu }
            4 { Process-Menu }
            5 { Services-Menu }
            6 { Drivers-Menu }
            7 { Firewall-Menu }
            8 { Sc-Menu }
            0 { exit }
        }
    }
}
}

PROCESS
{
    Main-Menu
}
