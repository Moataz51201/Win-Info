import platform
import psutil
import wmi
import socket
import ctypes
import subprocess
import GPUtil
import datetime
import win32evtlog
import argparse
from contextlib import redirect_stdout


# Function to check if the script has administrative privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Basic system information using platform and os
def basic_info():
        c=wmi.WMI()    
        print(f"Computer Name: {platform.node()}")
        print(f"Machine: {platform.machine()}, Processor: {platform.processor()}")
        print(f"Architecture: {platform.architecture()}")

        for cpu in c.Win32_Processor():
            print(f"CPU Name: {cpu.Name}")
            print(f"Number of Cores: {cpu.NumberOfCores}")
            print(f"Max Clock Speed: {cpu.MaxClockSpeed} MHz")

        for disk in c.Win32_DiskDrive():
            print(f"Model: {disk.Model}")
            print(f"Size: {int(disk.Size) / (1024**3)} GB")
            print(f"Interface Type: {disk.InterfaceType}")


        # Fetch operating system version
        for os in c.Win32_OperatingSystem():
            print(f"Operating System: {os.Caption}")
            print(f"Version: {os.Version}")
            print(f"Build Number: {os.BuildNumber}")


        # Fetch memory information
        for memory in c.Win32_ComputerSystem():
            print(f"Total Physical Memory: {int(memory.TotalPhysicalMemory) / (1024**3):.2f} GB")

        for partition in c.Win32_DiskPartition():
            print(f"Partition Name: {partition.Name}")
            print(f"Partition Size: {int(partition.Size) / (1024**3)} GB")
            print(f"Disk Index: {partition.DiskIndex}")
            print(f"Number of Blocks: {partition.NumberOfBlocks}")
        for logical_disk in c.Win32_LogicalDisk():
            print(f"Drive: {logical_disk.DeviceID}")
            print(f"File System: {logical_disk.FileSystem}")
            print(f"Free Space: {int(logical_disk.FreeSpace) / (1024**3)} GB")
            print(f"Total Size: {int(logical_disk.Size) / (1024**3)} GB")


        # Get information about system fans
        for fan in c.Win32_Fan():
            print(f"Fan Device ID: {fan.DeviceID}")
            print(f"Status: {fan.Status}")
            print(f"Desired Speed: {fan.DesiredSpeed}")
        for battery in c.Win32_Battery():
            print(f"Battery Status: {battery.BatteryStatus}")
            print(f"Estimated Charge Remaining: {battery.EstimatedChargeRemaining}%")
            print(f"Estimated Run Time: {battery.EstimatedRunTime} minutes")

        for bios in c.Win32_BIOS():
            print(f"BIOS Version: {bios.SMBIOSBIOSVersion}")
            print(f"Release Date: {bios.ReleaseDate}")
        for board in c.Win32_BaseBoard():
            print(f"Manufacturer: {board.Manufacturer}")
            print(f"Product: {board.Product}")
            print(f"Serial Number: {board.SerialNumber}")
        


# User Account Information
def user_accounts():
    w = wmi.WMI()
    print("\nUser Accounts Information:")
    for user in w.Win32_UserAccount():
        print(f"Username: {user.Name}, Domain: {user.Domain}, Status: {user.Status}")
        # To get last logon time, may use Win32_NetworkLoginProfile if available

# Windows Event Logs

def event_logs():
    log_types = ["Application", "System", "Security"]
    for log_type in log_types:
        # Check for admin privileges when accessing the Security Log
        if log_type == "Security" and not is_admin():
            print("\nERROR: This script needs to be run as administrator to retrieve Security Event Log entries.")
            continue  

        try:
            print(f"\n{log_type} Event Log (last 10 entries):")
            handle = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            for i, event in enumerate(events[:10]):
                print(f"Event ID: {event.EventID}, Source: {event.SourceName}, Time: {event.TimeGenerated}")
            win32evtlog.CloseEventLog(handle)
        except pywintypes.error as e:
            print(f"Failed to retrieve {log_type} logs: {e}")


# USB Device History
def usb_history():
    w = wmi.WMI()
    print("\nUSB Device History:")
    for usb in w.Win32_USBControllerDevice():
        print(f"USB Device: {usb.Dependent}")

# Scheduled Tasks
def scheduled_tasks():
    w = wmi.WMI()
    print("\nScheduled Tasks:")
    for task in w.Win32_ScheduledJob():
        print(f"Task Name: {task.Name}, Status: {task.Status}, Run Time: {task.RunTime}")


# Retrieve security-related services
def detailed_gpu_info():
    # Using WMI to gather static GPU information
    w = wmi.WMI()
    print("\nDetailed GPU Information :")
    for gpu in w.Win32_VideoController():
        print(f"Name: {gpu.Name}")
        print(f"Adapter RAM: {int(gpu.AdapterRAM) / 1024**2} MB")
        print(f"Driver Version: {gpu.DriverVersion}")
        print(f"Video Processor: {gpu.VideoProcessor}")
        print(f"Current Refresh Rate: {gpu.CurrentRefreshRate} Hz")
        print(f"Resolution: {gpu.CurrentHorizontalResolution}x{gpu.CurrentVerticalResolution}")
        print(f"Status: {gpu.Status}")
        print(f"Driver Date: {gpu.DriverDate}")
        print(f"Video Architecture: {gpu.VideoArchitecture}")
        print(f"Video Memory Type: {gpu.VideoMemoryType}")
        print(f"Current Bits Per Pixel: {gpu.CurrentBitsPerPixel}")
        print(f"Max Refresh Rate: {gpu.MaxRefreshRate} Hz")
        print(f"Min Refresh Rate: {gpu.MinRefreshRate} Hz")
        print(f"Availability: {gpu.Availability}\n")
    
    # Using GPUtil to gather real-time GPU usage and other metrics
    print("\nReal-Time GPU Information (GPUtil):")
    gpus = GPUtil.getGPUs()
    if not gpus:
        print("No GPU found by GPUtil.")
    for gpu in gpus:
        print(f"ID: {gpu.id}")
        print(f"Name: {gpu.name}")
        print(f"Load: {gpu.load * 100}%")
        print(f"Free Memory: {gpu.memoryFree} MB")
        print(f"Used Memory: {gpu.memoryUsed} MB")
        print(f"Total Memory: {gpu.memoryTotal} MB")
        print(f"Temperature: {gpu.temperature} °C")
        print(f"Driver: {gpu.driver}\n")

def security_services():
    w = wmi.WMI()
    print("\nSecurity-Related Services:")
    for service in w.Win32_Service(State="Running"):
        if any(keyword in service.Name.lower() for keyword in ['defender', 'firewall', 'antivirus', 'security', 'malware']):
            print(f"Service Name: {service.Name}, Display Name: {service.DisplayName}, Status: {service.State}")


# Retrieve Installed Drivers
def drivers_info():
    w = wmi.WMI()
    print("\nInstalled Drivers:")
    for driver in w.Win32_SystemDriver():
        print(f"Driver Name: {driver.Name}, State: {driver.State}, Description: {driver.Description}")

# Get Antivirus Information using WMI
def antivirus_info():
    w = wmi.WMI(namespace="root\\SecurityCenter2")
    try:
        av_products = w.AntiVirusProduct()
        print("\nAntivirus Products Installed:")
        for av in av_products:
            print(f"Antivirus: {av.displayName}, Version: {av.productState}")
    except Exception as e:
        print("Could not retrieve antivirus information. Exception:", e)

# Get Firewall status using subprocess
def firewall_status():
    print("\nFirewall Status:")
    result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
    print(result.stdout)

# Retrieve installed security software (manual filter for common security tools)
# Retrieve installed security software (manual filter for common security tools)
def security_software():
    w = wmi.WMI()
    print("\nInstalled Security Software:")
    for software in w.Win32_Product():
        if software.Name is not None:  # Check if software.Name is not None
            if any(keyword in software.Name.lower() for keyword in ['antivirus', 'security', 'firewall', 'malware', 'encryption']):
                print(f"Software Name: {software.Name}, Version: {software.Version}, Vendor: {software.Vendor}")
        else:
            print("Encountered software entry with no name.")


# Retrieve Startup Applications related to Security
def startup_apps():
    w = wmi.WMI()
    print("\nStartup Applications:")
    for startup in w.Win32_StartupCommand():
        print(f"Startup Name: {startup.Caption}, Command: {startup.Command}")


# Check BitLocker status using manage-bde command
def bitlocker_status(drive=None):
    if not is_admin():
        print("\nERROR: This script needs to be run as administrator to retrieve BitLocker status.")
        return
    
    if drive:
        print(f"\nBitLocker Status for Drive {drive.upper()}:")
        result = subprocess.run(['manage-bde', '-status', drive + ':'], capture_output=True, text=True)
    else:
        print("\nBitLocker Status for All Drives:")
        result = subprocess.run(['manage-bde', '-status'], capture_output=True, text=True)
    
    print(result.stdout)
# Check for installed security patches
def security_patches():
    w = wmi.WMI()
    print("\nInstalled Security Patches:")
    for patch in w.Win32_QuickFixEngineering():
        print(f"Patch ID: {patch.HotFixID}, Description: {patch.Description}, Installed On: {patch.InstalledOn}")

# Memory, CPU, and Disk information using psutil
def system_stats():
    print(f"CPU Cores: {psutil.cpu_count(logical=True)}")
    print(f"Memory: {psutil.virtual_memory()}")
    print(f"Disk Partitions: {psutil.disk_partitions()}")

# Execute systeminfo via subprocess and collect output
def extended_systeminfo():
    result = subprocess.run(['systeminfo'], capture_output=True, text=True)
    print(result.stdout)

# Combine and execute all functions
def gather_security_info():
    print(".......................")
    basic_info()
    detailed_gpu_info()
    print("\n.......................")
    drivers_info()
    print("\n........................")
    antivirus_info()
    print("\n............................")
    firewall_status()
    print("\n...............................")
    security_services()
    print("\n...............................")
    security_software()
    print("\n...............................")
    startup_apps()
    print("\n..................................")
    bitlocker_status()
    print("\n..............................")
    security_patches()
    print("\n...........................")
    system_stats()
    print("\n............................")
    user_accounts()
    print("\n............................")
    event_logs()
    print("\n............................")
    usb_history()
    print("\n............................")
    scheduled_tasks()
    print("\n............................")
    extended_systeminfo()

# Argument Parsing Setup
def parse_arguments():
    parser = argparse.ArgumentParser(description="Security Information Gathering Script")
    parser.add_argument("--basic-info", action="store_true", help="Display basic system information.")
    parser.add_argument("--user-accounts", action="store_true", help="Display user account information.")
    parser.add_argument("--event-logs", action="store_true", help="Display recent event logs.")
    parser.add_argument("--usb-history", action="store_true", help="Display USB device history.")
    parser.add_argument("--scheduled-tasks", action="store_true", help="Display scheduled tasks.")
    parser.add_argument("--gpu-info", action="store_true", help="Display detailed GPU information.")
    parser.add_argument("--security-services", action="store_true", help="Display security-related services.")
    parser.add_argument("--drivers-info", action="store_true", help="Display installed drivers.")
    parser.add_argument("--antivirus-info", action="store_true", help="Display antivirus information.")
    parser.add_argument("--firewall-status", action="store_true", help="Display firewall status.")
    parser.add_argument("--security-software", action="store_true", help="Display installed security software.")
    parser.add_argument("--startup-apps", action="store_true", help="Display startup applications.")
    parser.add_argument("--bitlocker-status", action="store_true", help="Display BitLocker status.")
    parser.add_argument("--security-patches", action="store_true", help="Display installed security patches.")
    parser.add_argument("--system-stats", action="store_true", help="Display memory, CPU, and disk stats.")
    parser.add_argument("--extended-systeminfo", action="store_true", help="Display extended system information.")
    parser.add_argument("--output", metavar="FILENAME", help="Redirect all output to the specified .txt file.")
    return parser.parse_args()

def run_selected_functions(args):
    if any(vars(args).values()):  # Check if any specific arguments were given
        if args.basic_info:
            print("\n[*] Gathering basic system information...")
            basic_info()
        if args.user_accounts:
            print("\n[*] Gathering User Accounts information...")
            user_accounts()
        if args.event_logs:
            print("\n[*] Gathering recent event logs ...")
            event_logs()
        if args.usb_history:
            print("\n[*] Gathering USB device history ..")
            usb_history()
        if args.scheduled_tasks:
            print("\n[*] Gathering scheduled tasks...")
            scheduled_tasks()
        if args.gpu_info:
            print("\n[*] Gathering detailed gpu information...")
            detailed_gpu_info()
        if args.security_services:
            print("\n[*] Gathering Security-related services ...")
            security_services()
        if args.drivers_info:
            print("\n[*] Gathering Installed Drivers...")
            drivers_info()
        if args.antivirus_info:
            print("\n[*] Gathering Antivirus information...")
            antivirus_info()
        if args.firewall_status:
            print("\n[*] Gathering Firewall status...")
            firewall_status()
        if args.security_software:
            print("\n[*] Gathering Installed security software...")
            security_software()
        if args.startup_apps:
            print("\n[*] Gathering Security-related startup applications...")
            startup_apps()
        if args.bitlocker_status:
            print("\n[*] Gathering BitLocker status...")
            bitlocker_status()
        if args.security_patches:
            print("\n[*] Gathering Installed security patches...")
            security_patches()
        if args.system_stats:
            print("\n[*] Gathering memory,Disk and disk status...")
            system_stats()
        if args.extended_systeminfo:
            print("\n[*] Gathering detailed System information...")
            extended_systeminfo()
    else:
        # If no arguments, run all functions
        gather_security_info()


# Main execution based on arguments
def main():
    args = parse_arguments()
    non_output_args = {k: v for k, v in vars(args).items() if k != "output"}
    has_flags = any(non_output_args.values())

    if args.output:
        with open(args.output, "w") as f, redirect_stdout(f):
            if has_flags:
                run_selected_functions(args)
            else:
                gather_security_info()
    else:
        if has_flags:
            run_selected_functions(args)
        else:
            gather_security_info()

if __name__ == "__main__":
    main()
