"""
╔══════════════════════════════════════════════════════════════╗
║       WINSHIELD — Advanced System Control Suite            ║
║   Privacy · Security · Optimization · Deep Clean · Monitor  ║
║                    Built by Gauravxo                         ║
╚══════════════════════════════════════════════════════════════╝
Run as Administrator for full functionality.
Requirements: pip install psutil
"""

import sys, os, threading, datetime, subprocess, ctypes, shutil, logging, time, queue
import json, glob, re, socket, platform, hashlib
from pathlib import Path
from tkinter import (Tk, Frame, Label, Button, Checkbutton, BooleanVar,
                     Scrollbar, messagebox, filedialog, Toplevel, Entry,
                     StringVar, OptionMenu, Text, Menu, IntVar, Canvas)
from tkinter import ttk, scrolledtext
import psutil

try:
    import winreg
except ImportError:
    winreg = None

# ─── PATHS ────────────────────────────────────────────────────
BASE = Path(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = BASE / "winshield_pro.log"
BACKUP_DIR = BASE / "backups"
QUARANTINE_DIR = BASE / "quarantine"
BLOCKED_PROGRAMS_FILE = BASE / "blocked_programs.json"
REMOVED_ITEMS_FILE = BASE / "removed_items.json"
MONITOR_RULES_FILE = BASE / "monitor_rules.json"
for _d in [BACKUP_DIR, QUARANTINE_DIR]:
    _d.mkdir(exist_ok=True)

logging.basicConfig(filename=str(LOG_FILE), level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")

FT  = ("Segoe UI", 9)
FTB = ("Segoe UI", 9, "bold")
FTH = ("Segoe UI", 11, "bold")
FTS = ("Segoe UI", 9)
FTM = ("Consolas", 9)
FTL = ("Segoe UI", 13, "bold")

# ─── UTILS ────────────────────────────────────────────────────
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def relaunch_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.executable,f'"{__file__}"',None,1)
    except Exception as e:
        logging.error(f"Relaunch: {e}")

def fmt_size(b):
    try:
        b = float(b)
        for u in ("B","KB","MB","GB","TB"):
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} PB"
    except: return "0 B"

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        return r.returncode == 0, r.stdout, r.stderr
    except Exception as e:
        logging.error(f"CMD error: {e}")
        return False, "", str(e)

def run_ps(script, timeout=30):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                          capture_output=True, text=True, timeout=timeout,
                          creationflags=subprocess.CREATE_NO_WINDOW)
        return r.returncode == 0, r.stdout, r.stderr
    except Exception as e:
        return False, "", str(e)

# ══════════════════════════════════════════════════════════════
#  PRIVACY SERVICE MANAGER
# ══════════════════════════════════════════════════════════════
class PrivacyServiceManager:
    CATEGORIES = {
        "🔴 Telemetry & Diagnostics": {
            "color": "#ff4444",
            "services": {
                "DiagTrack":          ("Connected User Experiences & Telemetry — main MS data engine",   "DISABLE", "CRITICAL"),
                "dmwappushservice":   ("Device Management WAP Push — mobile telemetry routing",           "DISABLE", "CRITICAL"),
                "DPS":                ("Diagnostic Policy Service — feeds telemetry pipeline",             "DISABLE", "HIGH"),
                "WdiSystemHost":      ("Diagnostic System Host — runs diagnostic collection",              "DISABLE", "HIGH"),
                "WdiServiceHost":     ("Diagnostic Service Host — uploads diagnostic data",                "DISABLE", "HIGH"),
                "diagsvc":            ("Diagnostic Execution Service — can upload to Microsoft",           "DISABLE", "HIGH"),
                "WerSvc":             ("Windows Error Reporting — sends crash dumps to Microsoft",         "DISABLE", "HIGH"),
                "wercplsupport":      ("Problem Reports Control Panel — error reporting UI",               "DISABLE", "MEDIUM"),
                "wuqisvc":            ("Microsoft Usage & Quality Insights — explicit usage telemetry",   "DISABLE", "CRITICAL"),
                "TroubleshootingSvc": ("Recommended Troubleshooting — phones home to Microsoft",          "DISABLE", "HIGH"),
                "PcaSvc":             ("Program Compatibility Assistant — reports app issues",             "DISABLE", "MEDIUM"),
                "MapsBroker":         ("Downloaded Maps Manager — location-based telemetry",               "DISABLE", "MEDIUM"),
            }
        },
        "🔴 Remote Access": {
            "color": "#ff4444",
            "services": {
                "RemoteRegistry":  ("Allows remote editing of your registry — major attack vector",   "DISABLE", "CRITICAL"),
                "TermService":     ("Remote Desktop Services — allows RDP connections to your PC",    "DISABLE", "CRITICAL"),
                "WinRM":           ("Windows Remote Management — remote PowerShell execution",        "DISABLE", "CRITICAL"),
                "RasAuto":         ("Remote Access Auto Connection Manager",                          "DISABLE", "HIGH"),
                "RasMan":          ("Remote Access Connection Manager",                               "DISABLE", "HIGH"),
                "RemoteAccess":    ("Routing & Remote Access — VPN/routing server",                   "DISABLE", "HIGH"),
                "UmRdpService":    ("Remote Desktop Services UserMode Port Redirector",               "DISABLE", "HIGH"),
                "SessionEnv":      ("Remote Desktop Configuration service",                           "DISABLE", "HIGH"),
                "ssh-agent":       ("OpenSSH Authentication Agent — not needed on personal PCs",     "DISABLE", "MEDIUM"),
            }
        },
        "🟠 Network Exposure": {
            "color": "#ff8c00",
            "services": {
                "LanmanServer":   ("Server (SMB) — enables inbound file/printer sharing",         "DISABLE", "HIGH"),
                "upnphost":       ("UPnP Device Host — advertises your PC to all network devices", "DISABLE", "HIGH"),
                "FDResPub":       ("Function Discovery Resource Publication — network visibility", "DISABLE", "MEDIUM"),
                "fdPHost":        ("Function Discovery Provider Host — network discovery",         "DISABLE", "MEDIUM"),
                "WMPNetworkSvc":  ("Windows Media Player Network Sharing",                        "DISABLE", "MEDIUM"),
                "lltdsvc":        ("Link-Layer Topology Discovery — maps your network topology",   "DISABLE", "MEDIUM"),
                "SharedAccess":   ("Internet Connection Sharing — unnecessary on personal PCs",   "DISABLE", "MEDIUM"),
                "WebClient":      ("WebDAV support — attack surface, not needed by most users",   "DISABLE", "MEDIUM"),
            }
        },
        "🟠 Sync & Cloud": {
            "color": "#ff8c00",
            "services": {
                "cbdhsvc":      ("Clipboard User Service — cross-device cloud clipboard sync",         "DISABLE", "HIGH"),
                "OneSyncSvc":   ("Sync Host — syncs mail/contacts/calendar to Microsoft",             "DISABLE", "HIGH"),
                "wlidsvc":      ("Microsoft Account Sign-in Assistant — MS account helper",           "DISABLE", "HIGH"),
                "CDPSvc":       ("Connected Devices Platform — cross-device Microsoft ecosystem",     "DISABLE", "HIGH"),
                "lfsvc":        ("Geolocation Service — location tracking",                           "DISABLE", "CRITICAL"),
                
                "SysMain":      ("Superfetch — prefetch telemetry, high disk usage on SSD",          "DISABLE", "MEDIUM"),
                "DusmSvc":      ("Data Usage service — monitors and reports network usage",           "DISABLE", "MEDIUM"),
            }
        },
        "🟡 OEM Telemetry (ASUS)": {
            "color": "#ffd700",
            "services": {
                "ASUSSystemAnalysis":  ("ASUS — analyzes and reports system data",                  "DISABLE", "HIGH"),
                "ASUSSystemDiagnosis": ("ASUS — sends hardware diagnostics externally",             "DISABLE", "HIGH"),
                "ASUSSoftwareManager": ("ASUS — phones home for updates",                           "DISABLE", "HIGH"),
                "vivoesService":       ("ASUS VivoBook service — syncs device data",                "DISABLE", "MEDIUM"),
                "vivoSyncService":     ("ASUS VivoBook sync — uploads device sync data",            "DISABLE", "MEDIUM"),
            }
        },
        "🟡 Intel Bloat": {
            "color": "#ffd700",
            "services": {
                "igccservice":               ("Intel Graphics Command Center — bloatware",                "DISABLE", "LOW"),
                "igfxCUIService1.0.0.0":     ("Intel HD Graphics Control Panel Service — telemetry/bloat","DISABLE", "LOW"),
                "WMIRegistrationService":    ("Intel ME WMI Provider — Intel telemetry",                  "DISABLE", "MEDIUM"),
            }
        },
        "🟠 Gaming & Xbox Bloat": {
            "color": "#ff8c00",
            "services": {
                "XblAuthManager":      ("Xbox Live Auth Manager — authorises Xbox apps",          "DISABLE", "HIGH"),
                "XblGameSave":         ("Xbox Live Game Save — syncs saved games to cloud",       "DISABLE", "HIGH"),
                "XboxNetApiSvc":       ("Xbox Live Networking Service — multiplayer connectivity", "DISABLE", "HIGH"),
                "XboxGipSvc":          ("Xbox Accessory Management Service — controller support",  "DISABLE", "MEDIUM"),
                "BcastDVRUserService":  ("GameDVR / Broadcast User Service — records gameplay",   "DISABLE", "HIGH"),
            }
        },
        "🔵 Set to Manual (On-Demand)": {
            "color": "#00d4ff",
            "services": {
                "ClickToRunSvc": ("Office ClickToRun — auto-starts when you open Office", "MANUAL", "INFO"),
            }
        },
        "🔵 Other Windows Bloat": {
            "color": "#00d4ff",
            "services": {
                "PhoneSvc":       ("Phone Link Service — syncs Android phone to Microsoft",      "DISABLE", "MEDIUM"),
                "WidgetsService": ("Windows Widgets — news/weather/traffic telemetry",           "DISABLE", "HIGH"),
                "RetailDemo":     ("Retail Demo Service — in‑store demo mode, useless at home", "DISABLE", "LOW"),
            }
        },
    }

    TELEMETRY_TASKS = [
        (r"\Microsoft\Windows\Feedback\Siuf\DmClient",                                        "DmClient",                          "CRITICAL"),
        (r"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",                      "DmClientOnScenarioDownload",        "CRITICAL"),
        (r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",     "Compatibility Appraiser",           "CRITICAL"),
        (r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",                     "Program Data Updater",              "HIGH"),
        (r"\Microsoft\Windows\Application Experience\StartupAppTask",                         "StartupAppTask",                    "MEDIUM"),
        (r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",           "CEIP Consolidator",                 "CRITICAL"),
        (r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",               "USB CEIP",                          "HIGH"),
        (r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",  "Disk Diagnostic Collector",         "MEDIUM"),
        (r"\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner",                   "RecommendedTroubleshootingScanner", "HIGH"),
        (r"\Microsoft\Windows\DiskFootprint\Diagnostics",                                     "DiskFootprint Diagnostics",         "MEDIUM"),
        (r"\Microsoft\Windows\WlanSvc\CDSSync",                                               "CDSSync",                           "HIGH"),
        (r"\Microsoft\Windows\Maps\MapsToastTask",                                            "MapsToastTask",                     "LOW"),
        (r"\Microsoft\Windows\Maps\MapsUpdateTask",                                           "MapsUpdateTask",                    "LOW"),
        (r"\Microsoft\Office\OfficeTelemetryAgentLogOn",                                      "Office Telemetry Logon",            "HIGH"),
        (r"\Microsoft\Office\OfficeTelemetryAgentFallBack",                                   "Office Telemetry Fallback",         "HIGH"),
        # Additional tasks
        (r"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing",                     "UsageDataFlushing",                 "CRITICAL"),
        (r"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver",                     "UsageDataReceiver",                 "CRITICAL"),
        (r"\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting",                    "UsageDataReporting",                "CRITICAL"),
        (r"\Microsoft\Windows\Flighting\FeatureConfig\GovernedFeatureUsageProcessing",        "GovernedFeatureUsageProcessing",    "HIGH"),
        (r"\Microsoft\Windows\Flighting\OneSettings\RefreshCache",                            "RefreshCache (OneSettings)",        "HIGH"),
        (r"\Microsoft\Windows\Sustainability\SustainabilityTelemetry",                        "SustainabilityTelemetry",           "HIGH"),
        (r"\Microsoft\Windows\Application Experience\AitAgent",                               "AIT Agent",                         "CRITICAL"),
        (r"\Microsoft\Windows\Application Experience\MareBackup",                             "MareBackup",                        "MEDIUM"),
        (r"\Microsoft\Windows\Application Experience\PcaPatchDbTask",                         "PcaPatchDbTask",                    "MEDIUM"),
        (r"\Microsoft\Windows\Application Experience\SdbinstMergeDbTask",                     "SdbinstMergeDbTask",                "MEDIUM"),
        (r"\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",                          "CloudExperienceHost Telemetry",     "HIGH"),
        (r"\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceLocation",                  "Device Location Registration",      "HIGH"),
        (r"\Microsoft\Windows\Location\Notifications",                                        "Location Notifications",            "HIGH"),
        (r"\Microsoft\Windows\Location\WindowsLocationProvider",                              "Windows Location Provider",         "HIGH"),
        (r"\Microsoft\Windows\NetTrace\GatherNetworkInfo",                                    "NetTrace Telemetry",                "MEDIUM"),
        (r"\Microsoft\Windows\NlaSvc\WiFiTask",                                               "WiFi Task (NlaSvc)",                "MEDIUM"),
        (r"\Microsoft\Windows\PI\SqmUploadTask",                                               "PI SQM Upload Task",                "CRITICAL"),
        (r"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",                   "Power Efficiency Diagnostics",      "MEDIUM"),
        (r"\Microsoft\Windows\Ras\MobilityManager",                                           "RAS Mobility Telemetry",            "MEDIUM"),
        (r"\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask",                         "Remote Assistance Telemetry",       "HIGH"),
        (r"\Microsoft\Windows\Speech\SpeechModelDownloadTask",                                "Speech Model Download (optional)",  "LOW"),
        (r"\Microsoft\Windows\Speech\SpeechToTextTraining",                                   "Speech Training Telemetry",         "MEDIUM"),
        (r"\Microsoft\Windows\UPnP\UPnPHostConfig",                                            "UPnP Host Configuration",           "LOW"),
        (r"\Microsoft\Windows\USB\Usb-Notifications",                                          "USB Notifications Telemetry",       "LOW"),
        (r"\Microsoft\Windows\Windows Error Reporting\QueueReporting",                        "Error Reporting Queue",             "HIGH"),
        (r"\Microsoft\Windows\Windows Media Sharing\UpdateLibrary",                           "Media Sharing Update Library",      "LOW"),
        (r"\Microsoft\Windows\WindowsColorSystem\CalibrationLoader",                          "Color System Telemetry",            "LOW"),
        (r"\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization",               "Work Folders Telemetry",            "MEDIUM"),
        (r"\Microsoft\Windows\Work Folders\Work Folders Maintenance Work",                    "Work Folders Maintenance",          "MEDIUM"),
        (r"\Microsoft\Office\OfficeTelemetry\AgentFallBack",                                  "Office Telemetry Agent Fallback",   "HIGH"),
    ]

    def __init__(self, on_log=None):
        self.on_log = on_log or print

    def get_service_status(self, name):
        ok, out, _ = run_cmd(["sc", "query", name], timeout=8)
        if not ok: return "NOT_FOUND", "Not Installed"
        state = "UNKNOWN"
        for line in out.splitlines():
            if "STATE" in line and ":" in line:
                parts = line.split(":", 1)[1].strip()
                state = parts.split()[1] if len(parts.split()) > 1 else parts.split()[0]
                break
        ok2, out2, _ = run_cmd(["sc", "qc", name], timeout=8)
        startup = "Unknown"
        if ok2:
            for line in out2.splitlines():
                if "START_TYPE" in line and ":" in line:
                    startup = line.split(":", 1)[1].strip()
                    break
        return state, startup

    def disable_service(self, name):
        run_cmd(["sc", "stop", name], timeout=15)
        ok, _, err = run_cmd(["sc", "config", name, "start=", "disabled"], timeout=10)
        if ok:
            self.on_log(f"✓ Disabled: {name}")
            return True
        else:
            run_cmd(["reg", "add", f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}",
                     "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"], timeout=10)
            self.on_log(f"✓ Disabled via registry: {name}")
            return True

    def enable_service(self, name):
        ok, _, _ = run_cmd(["sc", "config", name, "start=", "auto"], timeout=10)
        if ok: self.on_log(f"✓ Enabled (auto): {name}")
        return ok

    def set_manual(self, name):
        run_cmd(["sc", "config", name, "start=", "demand"], timeout=10)
        run_cmd(["sc", "stop", name], timeout=10)
        self.on_log(f"✓ Set to manual: {name}")

    def disable_task(self, task_path):
        ok, _, _ = run_cmd(["schtasks", "/Change", "/TN", task_path, "/DISABLE"], timeout=10)
        if ok: self.on_log(f"✓ Task disabled: {task_path}")
        return ok

    def enable_task(self, task_path):
        ok, _, _ = run_cmd(["schtasks", "/Change", "/TN", task_path, "/ENABLE"], timeout=10)
        return ok

    def get_task_status(self, task_path):
        ok, out, _ = run_cmd(["schtasks", "/Query", "/TN", task_path, "/FO", "CSV", "/NH"], timeout=8)
        if not ok: return "NOT_FOUND"
        if "Disabled" in out: return "Disabled"
        if "Ready" in out: return "Ready"
        if "Running" in out: return "Running"
        return "Unknown"

# ═══════════════════════ ENGINE CLASSES ═══════════════════
class AdvancedServiceManager:
    CRITICAL = {'WinDefend','wscsvc', 'SecurityHealthService','Dhcp','Dnscache','EventLog','PlugPlay',
                'RpcSs','SamSs','Themes','UserManager','Winmgmt','BFE','mpssvc',
                'AudioEndpointBuilder','Audiosrv'}
    def __init__(self, on_log=None):
        self.on_log = on_log or print
        self.services = []
    def get_all_services(self):
        self.services.clear()
        ok, out, _ = run_cmd(['sc', 'query', 'state=', 'all'])
        if not ok: return []
        cur = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('SERVICE_NAME:'):
                if cur: self.services.append(cur)
                cur = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('DISPLAY_NAME:'):
                cur['display'] = line.split(':', 1)[1].strip()
            elif line.startswith('STATE'):
                si = line.split(':', 1)[1].strip() if ':' in line else ''
                cur['state'] = si.split()[1] if len(si.split()) > 1 else si.split()[0] if si else 'UNKNOWN'
        if cur: self.services.append(cur)
        for svc in self.services: self._details(svc)
        return self.services
    def _details(self, svc):
        name = svc['name']
        svc['startup'] = 'Unknown'; svc['binary'] = ''
        svc['recommendation'] = ''; svc['category'] = 'System'
        ok, out, _ = run_cmd(['sc', 'qc', name], timeout=8)
        if ok:
            for line in out.splitlines():
                if 'START_TYPE' in line:
                    svc['startup'] = line.split(':', 1)[1].strip() if ':' in line else 'Unknown'
                elif 'BINARY_PATH_NAME' in line:
                    svc['binary'] = line.split(':', 1)[1].strip() if ':' in line else ''
        if name in self.CRITICAL:
            svc['recommendation'] = '⚠️ Critical — Keep Running'; svc['category'] = 'Critical'
    def stop_service(self, name): return run_cmd(['net', 'stop', name])[0]
    def start_service(self, name): return run_cmd(['net', 'start', name])[0]
    def disable_service(self, name): return run_cmd(['sc', 'config', name, 'start=', 'disabled'])[0]
    def enable_service(self, name): return run_cmd(['sc', 'config', name, 'start=', 'auto'])[0]

class StartupManager:
    def __init__(self, on_log=None):
        self.on_log = on_log or print
        self.items = []
    def get_startup_items(self):
        self.items.clear()
        if winreg: self._scan_reg()
        self._scan_folders()
        self._scan_tasks()
        return self.items
    def _scan_reg(self):
        for hive, path, loc in [
            (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM Run x86'),
            # RunOnce
            (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM RunOnce x86'),
            # Policies
            (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU Policies'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM Policies'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM Policies x86'),
            # NT Load/Run
            (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows NT\CurrentVersion\Windows\Load', 'HKCU NT Load'),
            (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows NT\CurrentVersion\Windows\Run', 'HKCU NT Run'),
            # SSODL
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad', 'HKLM SSODL'),
            (winreg.HKEY_CURRENT_USER,  r'Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad', 'HKCU SSODL'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad', 'HKLM SSODL x86'),
        ]:
            try:
                with winreg.OpenKey(hive, path) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                            exe = val.strip().strip('"').split('"')[0].split()[0] if val else ''
                            exists = os.path.exists(exe) if exe and '\\' in exe else True
                            self.items.append({'name': name, 'command': val, 'location': loc,
                                               'type': 'registry', 'enabled': True, 'exists': exists,
                                               'hive': hive, 'reg_path': path})
                            i += 1
                        except OSError: break
            except: pass
    def _scan_folders(self):
        for d in [Path(os.environ.get('APPDATA', '')) / 'Microsoft/Windows/Start Menu/Programs/Startup',
                  Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'Microsoft/Windows/Start Menu/Programs/StartUp']:
            if d.exists():
                for f in d.iterdir():
                    if f.is_file():
                        self.items.append({'name': f.name, 'command': str(f), 'location': str(d),
                                           'type': 'folder', 'enabled': True, 'exists': True})
    def _scan_tasks(self):
        try:
            ok, out, _ = run_cmd(['schtasks', '/Query', '/FO', 'CSV', '/NH'], timeout=20)
            if ok:
                for line in out.splitlines():
                    parts = line.strip('"').split('","')
                    if len(parts) >= 4:
                        path = parts[0]
                        if path.startswith('\\') and '\\Microsoft\\' not in path[:11]:
                            name = path.split('\\')[-1]
                            self.items.append({'name': name, 'command': path, 'location': 'Scheduled Task',
                                               'type': 'task', 'enabled': 'disabled' not in parts[3].lower(),
                                               'exists': True})
        except: pass
    def disable_item(self, item):
        try:
            if item['type'] == 'registry' and winreg:
                with winreg.OpenKey(item['hive'], item['reg_path'], 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, item['name'])
                self.on_log(f"✓ Disabled: {item['name']}")
                return True
            elif item['type'] == 'folder':
                dest = BACKUP_DIR / 'startup' / Path(item['command']).name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(item['command'], str(dest))
                self.on_log(f"✓ Disabled: {item['name']}")
                return True
            elif item['type'] == 'task':
                ok, _, _ = run_cmd(['schtasks', '/Change', '/TN', item['command'], '/DISABLE'], timeout=10)
                return ok
        except Exception as e:
            self.on_log(f"✗ Error: {item['name']}: {e}")
            return False

class PrivacyManager:
    SETTINGS = [
        {'name':'Telemetry Level','category':'System','description':'Block all Windows telemetry',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\DataCollection',
         'value_name':'AllowTelemetry','type':'DWORD','privacy_value':0,'default_value':3},
        {'name':'Advertising ID','category':'Privacy','description':'Stop apps using your ad ID',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo',
         'value_name':'Enabled','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'Cortana','category':'Assistant','description':'Disable Cortana completely',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\Windows Search',
         'value_name':'AllowCortana','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'Web Search in Start','category':'Search','description':'Disable Bing web search in Start Menu',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\Windows Search',
         'value_name':'DisableWebSearch','type':'DWORD','privacy_value':1,'default_value':0},
        {'name':'Activity History','category':'Privacy','description':'Stop sending activity to cloud',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\System',
         'value_name':'EnableActivityFeed','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'Cloud Clipboard','category':'Privacy','description':'Disable cross-device clipboard sync',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\System',
         'value_name':'AllowCrossDeviceClipboard','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'Location Services','category':'Location','description':'Disable location tracking',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
         'value_name':'DisableLocation','type':'DWORD','privacy_value':1,'default_value':0},
        {'name':'OneDrive Policy','category':'Cloud','description':'Block OneDrive via Group Policy',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\OneDrive',
         'value_name':'DisableFileSyncNGSC','type':'DWORD','privacy_value':1,'default_value':0},
        {'name':'Game DVR','category':'Privacy','description':'Disable Xbox Game DVR recording',
         'hive':winreg.HKEY_CURRENT_USER if winreg else None,'key':r'System\GameConfigStore',
         'value_name':'GameDVR_Enabled','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'Tailored Experiences','category':'Privacy','description':'Disable personalized tips from MS',
         'hive':winreg.HKEY_CURRENT_USER if winreg else None,'key':r'Software\Microsoft\Windows\CurrentVersion\Privacy',
         'value_name':'TailoredExperiencesWithDiagnosticDataEnabled','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'Feedback Requests','category':'System','description':'Set feedback frequency to never',
         'hive':winreg.HKEY_CURRENT_USER if winreg else None,'key':r'Software\Microsoft\Siuf\Rules',
         'value_name':'NumberOfSIUFInPeriod','type':'DWORD','privacy_value':0,'default_value':2},
        {'name':'Start Menu Ads','category':'Privacy','description':'Disable suggested apps in Start Menu',
         'hive':winreg.HKEY_CURRENT_USER if winreg else None,'key':r'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager',
         'value_name':'SystemPaneSuggestionsEnabled','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'Copilot','category':'Assistant','description':'Disable Windows Copilot completely',
         'hive':winreg.HKEY_LOCAL_MACHINE if winreg else None,'key':r'SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot',
         'value_name':'TurnOffWindowsCopilot','type':'DWORD','privacy_value':1,'default_value':0},
        {'name':'Lock Screen Ads','category':'Privacy','description':'Disable Windows Spotlight & ads',
         'hive':winreg.HKEY_CURRENT_USER if winreg else None,'key':r'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager',
         'value_name':'RotatingLockScreenOverlayEnabled','type':'DWORD','privacy_value':0,'default_value':1},
        {'name':'App Launch Tracking','category':'Privacy','description':'Disable Start Menu app tracking',
         'hive':winreg.HKEY_CURRENT_USER if winreg else None,'key':r'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
         'value_name':'Start_TrackProgs','type':'DWORD','privacy_value':0,'default_value':1},
    ] if winreg else []
    def __init__(self, on_log=None):
        self.on_log = on_log or print
    def get_all_status(self):
        result = []
        for s in self.SETTINGS:
            current = None
            try:
                with winreg.OpenKey(s['hive'], s['key'], 0, winreg.KEY_READ) as k:
                    val, _ = winreg.QueryValueEx(k, s['value_name'])
                    current = val
            except: current = 'Not Set'
            privacy_on = (current == s['privacy_value'])
            result.append({**s, 'current': current, 'privacy_on': privacy_on})
        return result
    def apply_setting(self, s, privacy_mode=True):
        target = s['privacy_value'] if privacy_mode else s['default_value']
        try:
            with winreg.CreateKeyEx(s['hive'], s['key']) as k:
                if s['type'] == 'DWORD':
                    winreg.SetValueEx(k, s['value_name'], 0, winreg.REG_DWORD, target)
                else:
                    winreg.SetValueEx(k, s['value_name'], 0, winreg.REG_SZ, str(target))
            self.on_log(f"✓ {s['name']} → {target}")
            return True
        except Exception as e:
            self.on_log(f"✗ {s['name']}: {e}")
            return False
    def apply_all_recommended(self):
        for s in self.SETTINGS: self.apply_setting(s, True)

class RegistryCleaner:
    def __init__(self, on_log=None):
        self.on_log = on_log or print
        self.issues = []
        self._raw = []
    def scan_registry(self):
        self.issues.clear(); self._raw.clear()
        if not winreg: return []
        self._scan_uninstall()
        self._scan_shared_dlls()
        self._scan_startup()
        self._scan_mui()
        return self.issues
    def _add(self, typ, desc, sev, fix):
        self.issues.append({'type': typ, 'description': desc, 'severity': sev})
        self._raw.append({'type': typ, 'description': desc, 'severity': sev, 'fix_info': fix})
    def _scan_uninstall(self):
        for p in [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                  r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall']:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p) as k:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(k, i)
                            with winreg.OpenKey(k, sub) as sk:
                                try:
                                    loc, _ = winreg.QueryValueEx(sk, 'InstallLocation')
                                    if loc and not os.path.exists(loc):
                                        try: name, _ = winreg.QueryValueEx(sk, 'DisplayName')
                                        except: name = sub
                                        self._add('Invalid Uninstall Entry', f"Missing folder: {name}", 'low', {'delete_key': f'HKLM\\{p}\\{sub}'})
                                except: pass
                            i += 1
                        except OSError: break
            except: pass
    def _scan_shared_dlls(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs') as k:
                i = 0
                while True:
                    try:
                        dll, _, _ = winreg.EnumValue(k, i)
                        if dll and not os.path.exists(dll):
                            self._add('Missing Shared DLL', f"Not found: {os.path.basename(dll)}", 'medium', {'delete_value': (r'SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs', dll)})
                        i += 1
                    except OSError: break
        except: pass
    def _scan_startup(self):
        for hive, path, loc in [(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU'),
                                 (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM')]:
            try:
                with winreg.OpenKey(hive, path) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                            exe = val.strip().strip('"').split('"')[0].split()[0] if val else ''
                            if exe and '\\' in exe and not os.path.exists(exe):
                                self._add('Invalid Startup Entry', f"Missing exe: {name}", 'low', {'delete_value': (f'{loc}\\{path}', name)})
                            i += 1
                        except OSError: break
            except: pass
    def _scan_mui(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r'Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache') as k:
                i = 0; count = 0
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(k, i)
                        exe = name.replace('.FriendlyAppName', '').replace('.ApplicationCompany', '')
                        if '\\' in exe and not os.path.exists(exe): count += 1
                        i += 1
                    except OSError: break
                if count > 0:
                    self._add('Stale MUI Cache', f'{count} entries for removed programs', 'low', {})
        except: pass
    def fix_issues(self, selected_indices):
        if not winreg: return 0, ["No registry access"]
        fixed = 0; errors = []
        for idx in selected_indices:
            if idx >= len(self._raw): continue
            iss = self._raw[idx]; fix = iss.get('fix_info')
            if not fix: continue
            try:
                if 'delete_key' in fix:
                    path = fix['delete_key']
                    hive = winreg.HKEY_LOCAL_MACHINE if path.startswith('HKLM') else winreg.HKEY_CURRENT_USER
                    full = path.split('\\', 1)[1]
                    parent = '\\'.join(full.split('\\')[:-1])
                    sub = full.split('\\')[-1]
                    with winreg.OpenKey(hive, parent, 0, winreg.KEY_ALL_ACCESS) as k:
                        winreg.DeleteKey(k, sub)
                    fixed += 1
                elif 'delete_value' in fix:
                    path, val = fix['delete_value']
                    hive = winreg.HKEY_LOCAL_MACHINE if path.startswith('HKLM') else winreg.HKEY_CURRENT_USER
                    full = path.split('\\', 1)[1] if '\\' in path else path
                    with winreg.OpenKey(hive, full, 0, winreg.KEY_ALL_ACCESS) as k:
                        winreg.DeleteValue(k, val)
                    fixed += 1
            except Exception as e:
                errors.append(f"{iss['description']}: {e}")
        return fixed, errors
    def backup_registry(self):
        try:
            fname = BACKUP_DIR / f"reg_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.reg"
            ok, _, _ = run_cmd(['reg', 'export', 'HKLM\\SOFTWARE', str(fname)], timeout=60)
            if ok:
                self.on_log(f"✓ Backed up to {fname.name}")
                return str(fname)
        except Exception as e: self.on_log(f"Backup error: {e}")
        return None

class RealtimeMonitor:
    def __init__(self, on_log=None, on_alert=None):
        self.on_log = on_log or print
        self.on_alert = on_alert or (lambda m: None)
        self.removed_items = self._load(REMOVED_ITEMS_FILE)
        self.monitor_rules = self._load(MONITOR_RULES_FILE)
        self._stop_event = threading.Event()
        self._alerts = []

    def _load(self, file):
        if file.exists():
            try:
                with open(file) as f: return json.load(f)
            except: return []
        return []

    def _save(self, data, file):
        try:
            with open(file, 'w') as f: json.dump(data, f, indent=2)
        except: pass

    def record_removed(self, t, ident, action='disabled'):
        self.removed_items.append({
            'type': t, 'id': ident, 'action': action,
            'date': datetime.datetime.now().isoformat()
        })
        self._save(self.removed_items, REMOVED_ITEMS_FILE)

    def remove_from_watchlist(self, idx):
        if 0 <= idx < len(self.removed_items):
            del self.removed_items[idx]
            self._save(self.removed_items, REMOVED_ITEMS_FILE)

    def check_now(self):
        alerts = []
        for item in self.removed_items:
            t = item['type']
            ident = item['id']
            if t == 'Service':
                ok, out, _ = run_cmd(['sc', 'query', ident], timeout=6)
                if ok and 'RUNNING' in out:
                    alerts.append({'type': 'Service', 'id': ident,
                                   'msg': f"Service '{ident}' is RUNNING (was disabled)",
                                   'severity': 'HIGH', 'item': item})
            elif t == 'Scheduled Task':
                ok, out, _ = run_cmd(['schtasks', '/Query', '/TN', ident, '/FO', 'CSV', '/NH'], timeout=6)
                if ok and 'Disabled' not in out and 'Ready' in out:
                    alerts.append({'type': 'Task', 'id': ident,
                                   'msg': f"Task '{ident}' is RE-ENABLED",
                                   'severity': 'HIGH', 'item': item})
            elif t == 'Program':
                if os.path.exists(ident):
                    alerts.append({'type': 'Program', 'id': ident,
                                   'msg': f"Program reappeared: {ident}",
                                   'severity': 'MEDIUM', 'item': item})
        for a in alerts:
            self._alerts.append({**a, 'time': datetime.datetime.now().isoformat()})
        if len(self._alerts) > 200:
            self._alerts = self._alerts[-200:]
        return alerts

    def take_action(self, alert):
        item = alert.get('item', {})
        t = item.get('type', '')
        ident = item.get('id', '')
        if t == 'Service':
            run_cmd(['sc', 'stop', ident], timeout=10)
            ok, _, _ = run_cmd(['sc', 'config', ident, 'start=', 'disabled'], timeout=10)
            if ok:
                self.on_log(f"✓ Re-disabled service: {ident}")
                return True
        elif t == 'Scheduled Task':
            ok, _, _ = run_cmd(['schtasks', '/Change', '/TN', ident, '/DISABLE'], timeout=10)
            if ok:
                self.on_log(f"✓ Re-disabled task: {ident}")
                return True
        elif t == 'Program':
            try:
                if os.path.isfile(ident):
                    os.remove(ident)
                    self.on_log(f"✓ Removed: {ident}")
                    return True
            except: pass
        return False

    def get_alerts(self): return list(self._alerts)

    def clear_alerts(self): self._alerts.clear()

    def start_background(self, interval=120, callback=None):
        def loop():
            while not self._stop_event.is_set():
                try:
                    alerts = self.check_now()
                    if alerts and callback:
                        callback(alerts)
                except: pass
                self._stop_event.wait(interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def stop(self): self._stop_event.set()

class DeepCleanEngine:
    PHASES = [
        ("Windows Temp & System Cache",     "_phase_temp"),
        ("Browser Deep Clean",              "_phase_browsers"),
        ("Application Caches & Telemetry",  "_phase_appcaches"),
        ("Windows Store & UWP Cache",       "_phase_uwp"),
        ("Network & DNS Cache",             "_phase_network"),
        ("Windows Event Logs",              "_phase_eventlogs"),
        ("Old Installations & Recycle Bin", "_phase_oldfiles"),
        ("Registry History Cleanup",        "_phase_registry"),
        ("GPU & Driver Caches",             "_phase_gpu"),
        ("Performance Optimization",        "_phase_perf"),
    ]
    def __init__(self, on_log=None, on_progress=None):
        self.on_log = on_log or print
        self.on_progress = on_progress or (lambda p, t: None)
        self.total_freed = 0
        self._stop = False
    def _sz(self, path):
        try: return sum(f.stat().st_size for f in Path(path).rglob('*') if f.is_file())
        except: return 0
    def _clean(self, path, pattern='*', recurse=True):
        freed = 0
        p = Path(path)
        if not p.exists(): return 0
        try:
            items = list(p.rglob(pattern)) if recurse else list(p.glob(pattern))
            for item in items:
                if self._stop: break
                try:
                    sz = item.stat().st_size if item.is_file() else 0
                    if item.is_file(): item.unlink(); freed += sz
                    elif item.is_dir(): shutil.rmtree(item, ignore_errors=True)
                except: pass
        except: pass
        self.total_freed += freed
        return freed
    def _clean_paths(self, paths):
        freed = 0
        for p in paths: freed += self._clean(p)
        return freed
    def run_all(self, options):
        self.total_freed = 0
        self._stop = False
        for i, (name, method) in enumerate(self.PHASES):
            if self._stop: break
            self.on_log(f"\n{'═'*50}")
            self.on_log(f"  [{i+1}/{len(self.PHASES)}] {name}")
            self.on_log(f"{'═'*50}")
            self.on_progress(int((i / len(self.PHASES)) * 100), f"Phase {i+1}: {name}")
            try: getattr(self, method)(options)
            except Exception as e: self.on_log(f"  ✗ Phase error: {e}")
        self.on_progress(100, "Complete")
        self.on_log(f"\n{'═'*50}")
        self.on_log(f"  ✅ TOTAL FREED: {fmt_size(self.total_freed)}")
        return self.total_freed
    def _phase_temp(self, opts):
        if not opts.get('temp', True): return
        self._clean(os.environ.get('TEMP', ''))
        self._clean(r'C:\Windows\Temp')
        if opts.get('prefetch', True): self._clean(r'C:\Windows\Prefetch')
        if opts.get('updates', True):
            try:
                run_cmd(["net", "stop", "wuauserv"], timeout=10)
                self._clean(r'C:\Windows\SoftwareDistribution\Download')
                run_cmd(["net", "start", "wuauserv"], timeout=10)
            except: pass
        if opts.get('dumps', True):
            for dp in [r'C:\Windows\Minidump', r'C:\Windows\MEMORY.DMP']: self._clean(dp)
        if opts.get('wer', True): self._clean_paths([r'C:\ProgramData\Microsoft\Windows\WER'])
    def _phase_browsers(self, opts):
        if not opts.get('browser', True): return
        local = os.environ.get('LOCALAPPDATA', '')
        browsers = {
            'Chrome':  os.path.join(local, 'Google\\Chrome\\User Data'),
            'Edge':    os.path.join(local, 'Microsoft\\Edge\\User Data'),
            'Brave':   os.path.join(local, 'BraveSoftware\\Brave-Browser\\User Data'),
        }
        for bname, bpath in browsers.items():
            if Path(bpath).exists(): self._clean(os.path.join(bpath, 'Default', 'Cache'))
        ff_path = os.path.join(local, 'Mozilla\\Firefox\\Profiles')
        if Path(ff_path).exists():
            for prof in Path(ff_path).iterdir():
                if prof.is_dir(): self._clean(str(prof / 'cache2'))
    def _phase_appcaches(self, opts):
        appdata = os.environ.get('APPDATA', '')
        self._clean(os.path.join(appdata, 'Microsoft\\Teams\\Cache'))
        self._clean(os.path.join(appdata, 'discord\\Cache'))
        if opts.get('telemetry', True):
            self._clean(os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft\\Windows\\DiagTrack'))
        if opts.get('logs', True):
            self._clean(r'C:\Windows\Logs\CBS')
    def _phase_uwp(self, opts):
        local = os.environ.get('LOCALAPPDATA', '')
        pkg_path = os.path.join(local, 'Packages')
        if Path(pkg_path).exists():
            for pkg in Path(pkg_path).iterdir():
                if pkg.is_dir(): self._clean(str(pkg / 'TempState'))
    def _phase_network(self, opts):
        run_cmd(['ipconfig', '/flushdns'], timeout=10)
        self._clean(os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft\\Windows\\INetCache'))
    def _phase_eventlogs(self, opts):
        if opts.get('eventlogs', False):
            run_cmd(['wevtutil', 'el'], timeout=15)
    def _phase_oldfiles(self, opts):
        try: ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 1)
        except: pass
    def _phase_registry(self, opts):
        if opts.get('reghistory', True):
            run_cmd(['reg', 'delete', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU', '/f'], timeout=5)
    def _phase_gpu(self, opts):
        local = os.environ.get('LOCALAPPDATA', '')
        self._clean(os.path.join(local, 'NVIDIA\\DXCache'))
    def _phase_perf(self, opts):
        if opts.get('trim', True):
            run_cmd(['powershell', '-Command', 'Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue'], timeout=60)
        if opts.get('dns_optimize', True): run_cmd(['ipconfig', '/registerdns'], timeout=10)

class AdvancedFirewall:
    def __init__(self, on_log=None):
        self.on_log = on_log or print
        self.blocked_programs = self._load()
    def _load(self):
        try:
            if BLOCKED_PROGRAMS_FILE.exists():
                with open(BLOCKED_PROGRAMS_FILE) as f: return json.load(f)
        except: pass
        return {}
    def _save(self):
        try:
            with open(BLOCKED_PROGRAMS_FILE, 'w') as f: json.dump(self.blocked_programs, f, indent=2)
        except: pass
    def active_connections(self):
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                try:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ''
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ''
                    proc = ''
                    if c.pid:
                        try: proc = psutil.Process(c.pid).name()
                        except: pass
                    conns.append({'process': proc, 'pid': c.pid, 'laddr': laddr, 'raddr': raddr, 'status': c.status})
                except: continue
        except: pass
        return conns
    def get_rules(self):
        rules = []
        try:
            ok, out, _ = run_ps("Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled, Profile | ConvertTo-Json -Compress", timeout=60)
            if ok and out.strip():
                data = json.loads(out)
                if isinstance(data, dict): data = [data]
                for r in data:
                    rules.append({'name': r.get('DisplayName', ''), 'direction': str(r.get('Direction', '')), 'action': str(r.get('Action', '')), 'program': ''})
        except: pass
        return rules
    def block_program(self, path, name=None):
        if not name: name = f"WinShield_Block_{Path(path).stem}"
        ok, _, _ = run_cmd(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                             f'name={name}_OUT', 'dir=out', 'action=block',
                             f'program={path}', 'enable=yes'], timeout=10)
        if ok:
            self.blocked_programs[path] = name; self._save()
            return True
        return False
    def unblock_program(self, path):
        name = self.blocked_programs.get(path, '')
        if name:
            run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}_OUT'], timeout=10)
            del self.blocked_programs[path]; self._save()
            return True
        return False
    def delete_rule(self, name):
        run_cmd(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}'], timeout=10)

class AdvancedUninstaller:
    KNOWN_BLOAT = {
        'candy crush', 'candy crush soda saga', 'farmville', 'solitaire', 'microsoft solitaire collection',
        'bubble witch', 'march of empires', 'netflix', 'spotify', 'disney',
        'xbox', 'xbox game bar', 'xbox live', 'minecraft',
        'bing', 'bing weather', 'bing news', 'bing sports', 'bing finance',
        'msn', 'msn money', 'msn sports', 'msn weather',
        'onenote', 'skype', 'microsoft teams', 'microsoft 365 (office)',
        'office', 'office hub', 'microsoft office',
        '3d viewer', 'mixed reality portal', 'paint 3d',
        'phone link', 'your phone', 'clipchamp',
        'cortana', 'feedback hub', 'tips', 'get help',
        'weather', 'news', 'maps', 'people', 'wallet',
        'mail and calendar', 'calendar', 'mail',
        'windows camera', 'windows maps', 'windows voice recorder',
        'groove music', 'microsoft to do',
        'films & tv', 'zune music', 'zune video',
        'windows media player',
        'power automate', 'power bi', 'microsoft whiteboard',
        'alarms & clock', 'calculator', 'sticky notes',
        'microsoft family', 'microsoft authenticator',
        'microsoft news', 'microsoft edge', 'edge',
        'onedrive', 'microsoft onedrive',
        'quick assist', 'remote desktop', 'windows terminal',
        'windows pc health check', 'surface', 'surface diagnostic toolkit',
        'asus', 'asus giftbox', 'asus splendid', 'asus battery health',
        'myasus', 'asus keyboard hotkeys', 'asus screenxpert',
        'dell supportassist', 'dell update', 'dell digital delivery',
        'hp support assistant', 'hp jumpstart', 'hp audio switch',
        'lenovo vantage', 'lenovo solution center', 'lenovo welcome',
        'acer care center', 'acer collection', 'quick access',
        'mcafee', 'norton', 'kaspersky', 'avast', 'avg', 'avira',
        'dropbox', 'amazon', 'ebay', 'tripadvisor', 'booking.com',
        'facebook', 'instagram', 'twitter', 'tiktok', 'pinterest',
        'linkedin', 'wunderlist', 'adobe', 'photoshop express',
        'wildtangent games', 'playrix', 'king.com',
        'dashlane', 'lastpass', 'evernote',
        'duolingo', 'translator', 'google', 'google drive',
    }
    def __init__(self, on_log=None): self.on_log = on_log or print
    def get_all_programs(self, show_hidden=False):
        programs = []
        if not winreg: return programs
        seen = set()
        for hive, path in [(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                           (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                           (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')]:
            try:
                with winreg.OpenKey(hive, path) as k:
                    for i in range(winreg.QueryInfoKey(k)[0]):
                        try:
                            sub = winreg.EnumKey(k, i)
                            with winreg.OpenKey(k, sub) as sk:
                                def gv(n, default=None):
                                    try: return winreg.QueryValueEx(sk, n)[0]
                                    except: return default
                                name = gv('DisplayName')
                                if not name and not show_hidden: continue
                                if not name: name = sub
                                if name in seen: continue
                                seen.add(name)
                                sz = gv('EstimatedSize', 0) or 0
                                programs.append({'name': name, 'publisher': gv('Publisher', '') or '', 'version': gv('DisplayVersion', '') or '', 'size': int(sz)*1024, 'date': gv('InstallDate', '') or '', 'uninstall': gv('UninstallString', '') or '', 'is_bloat': any(b in name.lower() for b in self.KNOWN_BLOAT), 'install_location': gv('InstallLocation', '') or ''})
                        except: continue
            except: continue
        return programs
    def uninstall_program(self, prog):
        cmd = prog.get('uninstall', '')
        if cmd:
            ok, _, _ = run_cmd(cmd, timeout=300)
            return ok
        return False
    def find_leftovers(self, prog):
        search_terms = set(w for w in re.sub(r'[^a-zA-Z0-9 ]', ' ', prog['name']).split() if len(w) > 3)
        leftovers = {'files': [], 'registry': []}
        local = os.environ.get('LOCALAPPDATA', '')
        for base in [local, os.environ.get('APPDATA', ''), r'C:\ProgramData', r'C:\Program Files', r'C:\Program Files (x86)']:
            if not os.path.isdir(base): continue
            for entry in os.listdir(base):
                full = os.path.join(base, entry)
                if any(tr in entry.lower() for tr in search_terms):
                    if os.path.isdir(full): leftovers['files'].append(full)
        return leftovers

class MemoryOptimizer:
    def __init__(self, on_log=None):
        self.on_log = on_log or print
    def boost(self):
        before = psutil.virtual_memory().used
        try:
            for p in psutil.process_iter(['pid']):
                try:
                    handle = ctypes.windll.kernel32.OpenProcess(0x001F0FFF, False, p.info['pid'])
                    if handle:
                        ctypes.windll.psapi.EmptyWorkingSet(handle)
                        ctypes.windll.kernel32.CloseHandle(handle)
                except: pass
        except: pass
        try:
            ctypes.windll.kernel32.SetSystemFileCacheSize(ctypes.c_uint64(-1), ctypes.c_uint64(-1), 0)
        except: pass
        try:
            SystemMemoryListInformation = 0x50
            MemoryPurgeStandbyList = 4
            class MEMORY_LIST_COMMAND(ctypes.Structure):
                _fields_ = [("command", ctypes.c_ulong), ("flags", ctypes.c_ulong)]
            ctypes.windll.ntdll.NtSetSystemInformation(
                ctypes.c_ulong(SystemMemoryListInformation),
                ctypes.byref(MEMORY_LIST_COMMAND(MemoryPurgeStandbyList, 0)),
                ctypes.c_ulong(ctypes.sizeof(MEMORY_LIST_COMMAND)))
        except: pass
        import gc; gc.collect()
        time.sleep(0.7)
        after = psutil.virtual_memory().used
        freed = max(0, before - after)
        self.on_log(f"✓ Memory boost — Freed: {fmt_size(freed)}")
        return freed

# ══════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════
class WinShieldPro(Tk):
    MALICIOUS_PORTS = (
        20, 21, 22, 23, 25, 53, 69, 110, 111, 135, 137, 138, 139, 143, 161, 162, 389,
        465, 500, 512, 513, 514, 873, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080,
        1433, 1434, 1521, 1701, 1723, 1748, 1754, 1808, 1809, 2082, 2083, 2222, 2375,
        2376, 3128, 3260, 3306, 3389, 4443, 4444, 4445, 4500, 4505, 4506, 5000, 5001,
        5060, 5061, 5432, 5555, 5800, 5900, 5901, 5985, 5986, 6379, 6666, 6667, 6668,
        6669, 7001, 7002, 7171, 8000, 8080, 8443, 8888, 9000, 9001, 9090, 9200, 9300,
        9999, 10000, 11211, 16992, 16993, 27017, 27018, 28888, 44818, 47001, 47002,
        49152, 49153, 49154, 49155, 49156, 49157
    )
    SUSPICIOUS_PREFIXES = (
        "13.", "20.", "40.", "52.", "104.",
        "3.", "18.", "34.", "35.", "44.", "50.", "54.",
        "8.", "23.", "98.", "99.",
        "31.", "45.", "46.", "51.", "64.", "65.",
        "74.", "84.", "91.", "92.", "94.", "95.",
        "100.", "101.", "102.", "103.", "107.",
        "136.", "138.", "139.", "140.", "141.", "142.",
        "185.", "194.", "195.", "198.", "199.",
        "205.", "206.", "207.", "208.", "209.",
    )
    TELEMETRY_HOSTS = {
        'vortex.data.microsoft.com','vortex-win.data.microsoft.com','settings-win.data.microsoft.com',
        'settings.data.microsoft.com','watson.telemetry.microsoft.com','watson.microsoft.com',
        'telemetry.microsoft.com','oca.telemetry.microsoft.com','sqm.telemetry.microsoft.com',
        'watson.ppe.telemetry.microsoft.com','telecommand.telemetry.microsoft.com',
        'www.bing.com','bing.com','search.msn.com','api.bing.com','th.bing.com','c.bing.com',
        'cortana.ai','www.cortana.ai','office.com','officeclient.microsoft.com','officecdn.microsoft.com',
        'officeapps.live.com','onedrive.live.com','skyapi.live.com','storage.live.com','onedrive.com',
        'xboxlive.com','xbox.com','xbox.gssv-play-prod.xboxlive.com','user.auth.xboxlive.com',
        'title.mgt.xboxlive.com','gameservices.xboxlive.com','storeedgefd.dsx.mp.microsoft.com',
        'licensing.mp.microsoft.com','displaycatalog.mp.microsoft.com','maps.windows.com',
        'dev.virtualearth.net','ecn.dev.virtualearth.net','tile-service.weather.microsoft.com',
        'www.clarity.ms','c.clarity.ms','analytics.microsoft.com','msftncsi.com',
        'telemetry.dropbox.com','pixel.facebook.com','analytics.twitter.com',
        'ads.linkedin.com','dc.services.visualstudio.com','mobile.pipe.aria.microsoft.com',
        'events.data.microsoft.com','stats.g.doubleclick.net','www.google-analytics.com',
        'ssl.google-analytics.com','sb.scorecardresearch.com',
    }
    BG="#06090e"; PANEL="#0a0f18"; CARD="#0d1520"; CARD2="#111e2e"; BORDER="#162236"; BORDER2="#1e3a5f"
    ACCENT="#00c8ff"; ACCENT2="#0099cc"; GREEN="#00e676"; GREEN2="#00b85c"; YELLOW="#ffd740"
    RED="#ff4444"; RED2="#cc2222"; ORANGE="#ff8c00"; PURPLE="#7c4dff"; BLUE="#2196f3"; TEAL="#00bcd4"
    TEXT="#d0e8ff"; TEXT2="#7a9cbf"; TEXT3="#3d5c7a"; SEL="#0d2840"; WHITE="#ffffff"
    RISK={"CRITICAL":"#ff4444","HIGH":"#ff8c00","MEDIUM":"#ffd740","LOW":"#00c8ff","INFO":"#7a9cbf"}

    PERF_SERVICES = {
        'DiagTrack':          'Connected User Experiences and Telemetry',
        'dmwappushservice':   'Device Management WAP Push Service',
        'DPS':                'Diagnostic Policy Service',
        'WdiSystemHost':      'Diagnostic System Host',
        'WdiServiceHost':     'Diagnostic Service Host',
        'diagsvc':            'Diagnostic Execution Service',
        'WerSvc':             'Windows Error Reporting',
        'wercplsupport':      'Problem Reports Control Panel',
        'wuqisvc':            'Windows Usage & Quality Insights',
        'TroubleshootingSvc': 'Recommended Troubleshooting Service',
        'PcaSvc':             'Program Compatibility Assistant',
        'MapsBroker':         'Downloaded Maps Manager',
        'RemoteRegistry':     'Remote Registry',
        'TermService':        'Remote Desktop Services',
        'WinRM':              'Windows Remote Management',
        'RasAuto':            'Remote Access Auto Connection Manager',
        'RasMan':             'Remote Access Connection Manager',
        'RemoteAccess':       'Routing & Remote Access',
        'UmRdpService':       'Remote Desktop UserMode Port Redirector',
        'SessionEnv':         'Remote Desktop Configuration',
        'ssh-agent':          'OpenSSH Authentication Agent',
        'LanmanServer':       'Server (SMB)',
        'upnphost':           'UPnP Device Host',
        'FDResPub':           'Function Discovery Resource Publication',
        'fdPHost':            'Function Discovery Provider Host',
        'WMPNetworkSvc':      'Windows Media Player Network Sharing',
        'lltdsvc':            'Link-Layer Topology Discovery',
        'SharedAccess':       'Internet Connection Sharing',
        'WebClient':          'WebDAV support',
        'cbdhsvc':            'Clipboard User Service',
        'OneSyncSvc':         'Sync Host',
        'wlidsvc':            'Microsoft Account Sign-in Assistant',
        'CDPSvc':             'Connected Devices Platform',
        'lfsvc':              'Geolocation Service',
       
        'SysMain':            'Superfetch',
        'DusmSvc':            'Data Usage service',
        'ASUSSystemAnalysis': 'ASUS system analysis',
        'ASUSSystemDiagnosis':'ASUS hardware diagnostics',
        'ASUSSoftwareManager':'ASUS software manager',
        'vivoesService':      'ASUS VivoBook service',
        'vivoSyncService':    'ASUS VivoBook sync',
        'igccservice':            'Intel Graphics Command Center',
        'igfxCUIService1.0.0.0':  'Intel HD Graphics Control Panel',
        'WMIRegistrationService': 'Intel ME WMI Provider',
        'XblAuthManager':      'Xbox Live Auth Manager',
        'XblGameSave':         'Xbox Live Game Save',
        'XboxNetApiSvc':       'Xbox Live Networking Service',
        'XboxGipSvc':          'Xbox Accessory Management',
        'BcastDVRUserService': 'Game DVR / Broadcast',
        'PhoneSvc':            'Phone Link Service',
        'WidgetsService':      'Windows Widgets',
        'RetailDemo':          'Retail Demo Service',
    }

    def __init__(self):
        super().__init__()
        self.title("WinShield — Advanced System Suite")
        self.geometry("1200x750")
        self.minsize(1000, 700)
        self.configure(bg=self.BG)
        self._is_admin = is_admin()
        self._ui_q = queue.Queue()

        self.svc_mgr = AdvancedServiceManager(on_log=self._log)
        self.privacy_svc = PrivacyServiceManager(on_log=self._log)
        self.deep_clean = DeepCleanEngine(on_log=self._log, on_progress=self._dc_progress)
        self.firewall_mgr = AdvancedFirewall(on_log=self._log)
        self.startup_mgr = StartupManager(on_log=self._log)
        self.mem_opt = MemoryOptimizer(on_log=self._log)
        self.privacy_mgr = PrivacyManager(on_log=self._log)
        self.reg_cleaner = RegistryCleaner(on_log=self._log)
        self.uninstaller = AdvancedUninstaller(on_log=self._log)
        self.monitor = RealtimeMonitor(on_log=self._log, on_alert=self._alert)

        self._dashboard_on = False
        self._svc_check_vars = {}
        self._task_check_vars = {}
        self._reg_issues = []
        self._perf_data = []
        self._startup_items = []
        self._uninst_data = []

        self._apply_styles()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._start_q()
        self.monitor.start_background(callback=self._monitor_alert_callback)
        logging.info("WinShield Pro v2.0 started")

    # ── UI building methods ──
    def _alert(self, msg): self.schedule_ui(lambda: messagebox.showwarning("Monitor Alert", msg))
    def _monitor_alert_callback(self, alerts):
        if not alerts: return
        self.schedule_ui(lambda: self._show_monitor_alert(alerts, "\n".join(f"• {a['msg']}" for a in alerts[:5])))
    def _show_monitor_alert(self, alerts, msg):
        if hasattr(self, '_monitor_status'):
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._monitor_status.config(text=f"⚠ {len(alerts)} alerts at {ts}", fg=self.RED)
    def _start_q(self):
        def process():
            try:
                while True: self._ui_q.get_nowait()()
            except queue.Empty: pass
            self.after(80, process)
        self.after(80, process)
    def schedule_ui(self, fn): self._ui_q.put(fn)
    def _log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        full = f"[{ts}] {msg}"
        logging.info(msg)
        self.schedule_ui(lambda: self._log_gui(full))
    def _log_gui(self, msg):
        try:
            self.log_txt.config(state="normal")
            self.log_txt.insert("end", msg + "\n")
            self.log_txt.see("end")
            self.log_txt.config(state="disabled")
        except: pass
    def _dc_progress(self, pct, label): self.schedule_ui(lambda: self._update_dc_bar(pct, label))
    def _update_dc_bar(self, pct, label):
        try: self.dc_bar['value'] = pct; self.dc_status.config(text=label)
        except: pass
    def _apply_styles(self):
        s = ttk.Style(self); s.theme_use('clam')
        s.configure(".", background=self.BG, foreground=self.TEXT, font=FT)
        s.configure("TNotebook", background=self.BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab", background="#0a1520", foreground="#5a7a9a", padding=(14, 8), font=("Segoe UI", 9))
        s.map("TNotebook.Tab", background=[("selected", "#111e2e"), ("active", "#0d1828")],
              foreground=[("selected", "#00c8ff"), ("active", "#8ac8e8")])
        s.configure("Treeview", background="#0d1520", foreground="#c8e0f0", fieldbackground="#0d1520",
                    rowheight=24, font=("Segoe UI", 9), borderwidth=0)
        s.configure("Treeview.Heading", background="#0a1528", foreground="#00c8ff", font=("Segoe UI", 9, "bold"), relief="flat", padding=(8, 5))
        s.map("Treeview", background=[("selected", "#0d2840")], foreground=[("selected", "#ffffff")])
        s.configure("TProgressbar", background="#00c8ff", troughcolor="#0d1520", borderwidth=0)
        s.configure("TScrollbar", background="#111e2e", troughcolor="#06090e", borderwidth=0, arrowcolor="#3d5c7a")
        s.configure("TCombobox", fieldbackground="#111e2e", background="#111e2e", foreground="#c8e0f0", arrowcolor="#00c8ff", borderwidth=1)
        s.map("TCombobox", fieldbackground=[("readonly", "#111e2e")])
    def _btn(self, parent, text, cmd, color=None, fg="#000000", padx=14, pady=7, font=None):
        c = color or self.ACCENT; f = font or FT
        b = Button(parent, text=text, command=cmd, bg=c, fg=fg, relief="flat", padx=padx, pady=pady, font=f, cursor="hand2",
                   activebackground=c, activeforeground=fg, bd=0)
        b.bind("<Enter>", lambda e: b.config(bg=self._lighten(c)))
        b.bind("<Leave>", lambda e: b.config(bg=c))
        return b
    def _lighten(self, hex_color):
        try:
            r=int(hex_color[1:3],16); g=int(hex_color[3:5],16); b=int(hex_color[5:7],16)
            r=min(255,r+30); g=min(255,g+30); b=min(255,b+30)
            return f"#{r:02x}{g:02x}{b:02x}"
        except: return hex_color
    def _make_tree(self, parent, cols, height=18, selectmode='extended'):
        frame = Frame(parent, bg=self.BG); frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", height=height, selectmode=selectmode)
        for cid, hd, w in cols: tree.heading(cid, text=hd, anchor="w"); tree.column(cid, width=w, anchor="w", minwidth=50)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        return tree

    def _build_ui(self):
        bar = Frame(self, bg=self.PANEL, height=52); bar.pack(fill="x"); bar.pack_propagate(False)
        lf = Frame(bar, bg=self.PANEL); lf.pack(side="left", padx=15, pady=8)
        Label(lf, text="🛡", font=("Segoe UI", 16), bg=self.PANEL, fg=self.ACCENT).pack(side="left", padx=(0, 8))
        nf = Frame(lf, bg=self.PANEL); nf.pack(side="left")
        Label(nf, text="WinShield- BY Gauravxo                                                          Privacy · Security · Optimization · Deep Clean",
              font=("Segoe UI", 14, "bold"), bg=self.PANEL, fg="#ffffff").pack(anchor="w")
        Label(nf, text="", font=("Segoe UI", 4), bg=self.PANEL, fg=self.TEXT2).pack(anchor="w")
        rf = Frame(bar, bg=self.PANEL); rf.pack(side="right", padx=20)
        admin_txt = "  🔐 Administrator  " if self._is_admin else "  ⚠️ Run as Admin  "
        admin_col = self.GREEN if self._is_admin else self.YELLOW
        Label(rf, text=admin_txt, font=FTB, bg=admin_col if self._is_admin else self.PANEL,
              fg=self.BG if self._is_admin else self.YELLOW).pack(side="right", padx=5)
        Label(rf, text="#Follow me on GitHub- Gauravxo", font=("Segoe UI", 10), bg=self.PANEL, fg=self.TEXT3).pack(side="right", padx=10)
        main = Frame(self, bg=self.BG); main.pack(fill="both", expand=True, padx=6, pady=(4, 6))
        self.nb = ttk.Notebook(main); self.nb.pack(fill="both", expand=True)
        tabs = [
            ("  📊 Dashboard  ", "_build_dashboard"), ("  🛡 Privacy Shield  ", "_build_privacy_services"),
            ("  🧹 Deep Clean  ", "_build_deep_clean"), ("  ⚙ Services  ", "_build_services"),
            ("  📅 Tasks  ", "_build_tasks"), ("  🔒 Privacy Reg  ", "_build_privacy_reg"),
            ("  🔧 Registry  ", "_build_registry_clean"), ("  ⚡ Performance  ", "_build_performance"),
            ("  👁 Monitor  ", "_build_monitor"), ("  🚀 Startup  ", "_build_startup"),
            ("  🌐 Firewall  ", "_build_firewall"), ("  🗑 Uninstaller  ", "_build_uninstall"),
            ("  🩺 System Repair  ", "_build_system_repair"),
            ("  📋 Logs  ", "_build_logs"),
        ]
        for title, method in tabs:
            frame = Frame(self.nb, bg=self.BG); self.nb.add(frame, text=title)
            try: getattr(self, method)(frame)
            except Exception as e:
                Label(frame, text=f"Load error: {e}", bg=self.BG, fg="#ff8c00", font=("Segoe UI", 9), justify="left").pack(padx=20, pady=20)
                logging.error(f"Tab {title}: {e}")

    # ── DASHBOARD ──
    def _build_dashboard(self, t):
        left = Frame(t, bg=self.BG); left.pack(side="left", fill="both", expand=True, padx=(10, 5), pady=10)
        right = Frame(t, bg=self.BG); right.pack(side="right", fill="both", expand=True, padx=(5, 10), pady=10)
        stats = Frame(left, bg=self.BG); stats.pack(fill="x", pady=(0, 8))
        self._stat_cards = {}
        for label, key, col in [("CPU Usage", "cpu", "#00c8ff"), ("RAM Usage", "mem", "#00e676"),
                                  ("Disk C:", "disk", "#ff8c00"), ("Network", "net", "#2196f3")]:
            card = Frame(stats, bg="#0d1520", highlightbackground="#1a3550", highlightthickness=1)
            card.pack(side="left", expand=True, fill="both", padx=3)
            Frame(card, bg=col, height=3).pack(fill="x")
            Label(card, text=label, font=("Segoe UI", 8), bg="#0d1520", fg="#5a7a9a", pady=3).pack()
            val = Label(card, text="—", font=("Segoe UI", 16, "bold"), bg="#0d1520", fg=col)
            val.pack(pady=1)
            sub = Label(card, text="", font=("Segoe UI", 7), bg="#0d1520", fg="#3d5c7a")
            sub.pack(pady=(0, 2))
            bar = ttk.Progressbar(card, length=100, mode='determinate')
            bar.pack(padx=8, pady=(0, 7))
            self._stat_cards[key] = (val, sub, bar, col)
        hsc = Frame(left, bg="#0d1520", highlightbackground="#1a3550", highlightthickness=1)
        hsc.pack(fill="x", pady=(0, 8)); Frame(hsc, bg="#7c4dff", height=2).pack(fill="x")
        hsh = Frame(hsc, bg="#0d1520"); hsh.pack(fill="x", padx=12, pady=6)
        Label(hsh, text="🛡 System Health Score", font=("Segoe UI", 10, "bold"), bg="#0d1520", fg="#7c4dff").pack(side="left")
        self._health_lbl = Label(hsh, text="—/100", font=("Segoe UI", 14, "bold"), bg="#0d1520", fg="#00e676")
        self._health_lbl.pack(side="right")
        self._health_bar = ttk.Progressbar(hsc, length=400, mode='determinate')
        self._health_bar.pack(fill="x", padx=12, pady=(0, 4))
        self._health_detail = Label(hsc, text="Run Privacy Shield scan to calculate score",
                                    font=("Segoe UI", 8), bg="#0d1520", fg="#3d5c7a", padx=12, pady=3)
        self._health_detail.pack(anchor="w")
        ph = Frame(left, bg="#0d1520", highlightbackground="#1a3550", highlightthickness=1)
        ph.pack(fill="both", expand=True)
        phh = Frame(ph, bg="#0d1520"); phh.pack(fill="x", padx=12, pady=7)
        Label(phh, text="⚙ Top Processes", font=("Segoe UI", 10, "bold"), bg="#0d1520", fg="#00c8ff").pack(side="left")
        self._btn(phh, "Kill", self._kill_proc, "#ff4444", "#fff", padx=9, pady=3).pack(side="right", padx=2)
        self._btn(phh, "Refresh", self._refresh_procs, "#2196f3", "#fff", padx=9, pady=3).pack(side="right", padx=2)
        self.proc_tree = self._make_tree(ph, [
            ('name', 'Process', 200), ('pid', 'PID', 52), ('cpu', 'CPU%', 62),
            ('mem', 'Memory', 88), ('conn', 'Conns', 52), ('status', 'Status', 68)
        ], 14)
        self.proc_tree.tag_configure("high_cpu", foreground="#ff4444")
        self.proc_tree.tag_configure("high_mem", foreground="#ff8c00")
        self.proc_tree.tag_configure("ok", foreground="#00e676")
        info = Frame(right, bg="#0d1520", highlightbackground="#1a3550", highlightthickness=1)
        info.pack(fill="x", pady=(0, 8)); Frame(info, bg="#00c8ff", height=2).pack(fill="x")
        Label(info, text="ℹ System Information", font=("Segoe UI", 10, "bold"), bg="#0d1520", fg="#00c8ff", padx=12, pady=6).pack(anchor="w")
        self.sysinfo_txt = Text(info, height=8, bg="#0d1520", fg="#c8e0f0", font=("Consolas", 9), relief="flat", state="disabled", wrap="word", padx=10)
        self.sysinfo_txt.pack(fill="x", padx=8, pady=(0, 8))
        ntf = Frame(right, bg="#0d1520", highlightbackground="#1a3550", highlightthickness=1)
        ntf.pack(fill="x", pady=(0, 8)); Frame(ntf, bg="#2196f3", height=2).pack(fill="x")
        nth = Frame(ntf, bg="#0d1520"); nth.pack(fill="x", padx=12, pady=6)
        Label(nth, text="🌐 Network Traffic", font=("Segoe UI", 10, "bold"), bg="#0d1520", fg="#2196f3").pack(side="left")
        self._btn(nth, "Scan", self._scan_net_anomaly, "#2196f3", "#fff", padx=8, pady=3).pack(side="right")
        self.net_tree = self._make_tree(ntf, [
            ('proc', 'Process', 130), ('raddr', 'Remote Address', 170),
            ('port', 'Port', 55), ('risk', 'Risk', 80)
        ], 6)
        self.net_tree.tag_configure("HIGH", foreground="#ff4444")
        self.net_tree.tag_configure("MEDIUM", foreground="#ff8c00")
        self.net_tree.tag_configure("LOW", foreground="#00e676")
        qa = Frame(right, bg="#0d1520", highlightbackground="#1a3550", highlightthickness=1)
        qa.pack(fill="x", pady=(0, 8)); Frame(qa, bg="#7c4dff", height=2).pack(fill="x")
        Label(qa, text="⚡ Quick Actions", font=("Segoe UI", 10, "bold"), bg="#0d1520", fg="#7c4dff", padx=12, pady=6).pack(anchor="w")
        qf = Frame(qa, bg="#0d1520"); qf.pack(fill="x", padx=10, pady=(0, 10))
        for i, (txt, cmd, col, fg) in enumerate([
            ("🧹 Quick Clean", self._quick_clean, "#00b85c", "#000"),
            ("⚡ Boost Memory", self._boost_mem, "#7c4dff", "#fff"),
            ("🔒 Apply Privacy", self._quick_privacy, "#00bcd4", "#000"),
            ("📋 Export Report", self._export_report, "#2196f3", "#fff"),
        ]):
            self._btn(qf, txt, cmd, col, fg, padx=10, pady=7, font=("Segoe UI", 9, "bold")).grid(row=i//2, column=i%2, padx=3, pady=3, sticky="ew")
        qf.columnconfigure(0, weight=1); qf.columnconfigure(1, weight=1)
        if not self._is_admin:
            wf = Frame(right, bg="#2d1a00", highlightbackground="#ff8c00", highlightthickness=1)
            wf.pack(fill="x", pady=(0, 8))
            Label(wf, text="⚠️  Run as Administrator for full functionality", font=("Segoe UI", 9, "bold"), bg="#2d1a00", fg="#ff8c00", padx=12, pady=8).pack()
            self._btn(wf, "Relaunch as Admin", relaunch_admin, "#ff8c00", "#000", padx=12, pady=5).pack(pady=(0, 8))
        self._start_dashboard()

    def _start_dashboard(self):
        self._dashboard_on = True; self._prev_net = psutil.net_io_counters()
        try:
            host = platform.node(); os_ver = platform.version()
            uptime = str(datetime.timedelta(seconds=int(time.time() - psutil.boot_time())))
            cpu_cnt = psutil.cpu_count(logical=False); cpu_log = psutil.cpu_count(logical=True)
            mem = psutil.virtual_memory(); dsk = psutil.disk_usage('C:')
            try: freq = f"{psutil.cpu_freq().current:.0f} MHz"
            except: freq = "N/A"
            info_txt = (f"🖥  Host: {host}\n💻  OS: Windows {platform.release()}  (Build {os_ver[:6]})\n"
                       f"⏱  Uptime: {uptime}\n⚙  CPU: {cpu_cnt} cores / {cpu_log} threads  @{freq}\n"
                       f"🧠  RAM: {fmt_size(mem.used)} / {fmt_size(mem.total)}  ({mem.percent:.0f}% used)\n"
                       f"💾  Disk C: {fmt_size(dsk.used)} / {fmt_size(dsk.total)}  ({dsk.percent:.0f}% used)\n"
                       f"🆓  Free Disk: {fmt_size(dsk.free)}\n📦  Python {platform.python_version()}  |  psutil {psutil.__version__}")
            self.sysinfo_txt.config(state="normal"); self.sysinfo_txt.delete(1.0, "end")
            self.sysinfo_txt.insert("end", info_txt); self.sysinfo_txt.config(state="disabled")
        except: pass
        def update():
            if not self._dashboard_on: return
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory(); dsk = psutil.disk_usage('C:')
                net = psutil.net_io_counters()
                sent_kb = (net.bytes_sent - self._prev_net.bytes_sent) / 1024
                recv_kb = (net.bytes_recv - self._prev_net.bytes_recv) / 1024
                self._prev_net = net
                def fkb(v): return f"{v/1024:.1f}MB/s" if v > 1024 else f"{v:.0f}KB/s"
                metrics = [
                    ("cpu", f"{cpu:.0f}%", f"Cores: {psutil.cpu_count()}", cpu,
                     "#00c8ff" if cpu < 70 else "#ff8c00" if cpu < 90 else "#ff4444"),
                    ("mem", f"{mem.percent:.0f}%", f"{fmt_size(mem.used)}/{fmt_size(mem.total)}", mem.percent,
                     "#00e676" if mem.percent < 70 else "#ff8c00" if mem.percent < 90 else "#ff4444"),
                    ("disk", f"{dsk.percent:.0f}%", f"Free: {fmt_size(dsk.free)}", dsk.percent,
                     "#ff8c00" if dsk.percent > 80 else "#00e676"),
                    ("net", f"↑{fkb(sent_kb)}", f"↓{fkb(recv_kb)}", min(100, (sent_kb + recv_kb) / 2), "#2196f3"),
                ]
                for key, text, sub, val, col in metrics:
                    lbl, slbl, bar, _ = self._stat_cards[key]
                    lbl.config(text=text, fg=col); slbl.config(text=sub); bar['value'] = val
                self._update_health_score()
                if self.nb.index(self.nb.select()) == 0: self._refresh_procs()
            except: pass
            self.after(2500, update)
        self.after(1500, update)

    def _update_health_score(self):
        try:
            total_svcs = 0
            disabled = 0
            for cat in PrivacyServiceManager.CATEGORIES.values():
                for svc, (desc, action, sev) in cat["services"].items():
                    if action != "DISABLE":
                        continue
                    # Check if service is actually installed
                    ok, out, _ = run_cmd(["sc", "qc", svc], timeout=3)
                    if not ok:      # service not installed → skip completely
                        continue
                    total_svcs += 1
                    if "DISABLED" in out.upper():
                        disabled += 1
            score = int((disabled / max(total_svcs, 1)) * 100)
            col = "#ff4444" if score < 40 else "#ff8c00" if score < 70 else "#ffd740" if score < 90 else "#00e676"
            self._health_bar['value'] = score
            self._health_lbl.config(text=f"{score}/100", fg=col)
            issues = total_svcs - disabled
            detail = ("🛡 Excellent — all installed privacy services disabled" if issues == 0
                      else f"⚠ {issues} installed privacy services still active — check Privacy Shield tab")
            self._health_detail.config(text=detail, fg=col)
        except:
            pass

    def _scan_net_anomaly(self):
        self.net_tree.delete(*self.net_tree.get_children())
        try:
            for c in psutil.net_connections(kind='inet'):
                if not c.raddr: continue
                try:
                    rip = c.raddr.ip; rport = c.raddr.port; proc = ""
                    if c.pid:
                        try: proc = psutil.Process(c.pid).name()
                        except: pass
                    risk = "LOW"
                    if rport in self.MALICIOUS_PORTS: risk = "HIGH"
                    import ipaddress
                    try:
                        if ipaddress.ip_address(rip).is_private: risk = "LOW"
                    except: pass
                    try:
                        hostname = socket.gethostbyaddr(rip)[0].lower()
                        if any(h in hostname for h in self.TELEMETRY_HOSTS): risk = "HIGH"
                    except: hostname = rip
                    if risk != "HIGH" and rip.startswith(self.SUSPICIOUS_PREFIXES): risk = "MEDIUM"
                    self.net_tree.insert('', 'end', values=(proc, hostname[:35], rport, risk), tags=(risk,))
                except: continue
        except: pass

    def _refresh_procs(self):
        try:
            conn_counts = {}
            try:
                for c in psutil.net_connections():
                    if c.pid: conn_counts[c.pid] = conn_counts.get(c.pid, 0) + 1
            except: pass
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
                try:
                    info = p.info
                    procs.append({'pid': info['pid'], 'name': info['name'],
                                  'cpu': info.get('cpu_percent', 0),
                                  'mem': info['memory_info'].rss if info.get('memory_info') else 0,
                                  'status': info.get('status', ''), 'conn': conn_counts.get(info['pid'], 0)})
                except: continue
            procs.sort(key=lambda x: (x['cpu'], x['mem']), reverse=True)
            self.proc_tree.delete(*self.proc_tree.get_children())
            for p in procs[:40]:
                tag = "high_cpu" if p['cpu'] > 50 else "high_mem" if p['mem'] > 300 * 1024 * 1024 else "ok"
                self.proc_tree.insert('', 'end', values=(p['name'], p['pid'], f"{p['cpu']:.1f}%",
                                                         fmt_size(p['mem']), p['conn'] or '', p['status']), tags=(tag,))
        except: pass

    def _kill_proc(self):
        sel = self.proc_tree.selection()
        if not sel: return
        vals = self.proc_tree.item(sel[0])['values']; pid, name = vals[1], vals[0]
        if messagebox.askyesno("Kill Process", f"Terminate '{name}' (PID:{pid})?"):
            try: psutil.Process(pid).terminate(); self._refresh_procs()
            except Exception as e: messagebox.showerror("Error", str(e))

    def _quick_clean(self):
        if messagebox.askyesno("Quick Clean", "Remove temp files and caches now?"):
            def task():
                opts = {'temp': 1, 'prefetch': 1, 'browser': 0, 'updates': 0, 'dumps': 1,
                        'wer': 1, 'telemetry': 1, 'logs': 0, 'network': 1,
                        'eventlogs': 0, 'reghistory': 0, 'gpu': 0, 'trim': 0, 'dns_optimize': 0}
                self.deep_clean.total_freed = 0; self.deep_clean._stop = False
                self.deep_clean._phase_temp(opts); self.deep_clean._phase_network(opts)
                self.schedule_ui(lambda: messagebox.showinfo("Done", f"Quick clean freed: {fmt_size(self.deep_clean.total_freed)}"))
            threading.Thread(target=task, daemon=True).start()

    def _boost_mem(self):
        if messagebox.askyesno("Memory Boost", "Optimize system memory now?"):
            def task():
                freed = self.mem_opt.boost()
                self.schedule_ui(lambda: messagebox.showinfo("Done", f"Memory optimized: {fmt_size(freed)}"))
            threading.Thread(target=task, daemon=True).start()

    def _quick_privacy(self):
        if messagebox.askyesno("Privacy Shield", "Apply all 15 recommended privacy registry settings?"):
            def task():
                self.privacy_mgr.apply_all_recommended()
                self.schedule_ui(lambda: messagebox.showinfo("Done", "All privacy settings applied!"))
            threading.Thread(target=task, daemon=True).start()

    def _export_report(self):
        fn = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")],
                                          initialfile=f"WinShield_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if fn:
            try:
                with open(fn, 'w', encoding='utf-8') as f:
                    f.write(f"WinShield Pro Report — {datetime.datetime.now()}\n" + "=" * 60 + "\n\n")
                    m = psutil.virtual_memory(); d = psutil.disk_usage('C:')
                    f.write(f"CPU: {psutil.cpu_percent()}%\nRAM: {m.percent}% ({fmt_size(m.used)}/{fmt_size(m.total)})\n")
                    f.write(f"Disk C: {d.percent}% ({fmt_size(d.used)}/{fmt_size(d.total)})\n\nLog:\n")
                    if LOG_FILE.exists():
                        with open(LOG_FILE, encoding='utf-8') as lf: f.write(lf.read())
                messagebox.showinfo("Exported", f"Report saved:\n{fn}")
            except Exception as e: messagebox.showerror("Error", str(e))

    # ── PRIVACY SHIELD ──
    def _build_privacy_services(self, t):
        tf = Frame(t, bg=self.BG); tf.pack(fill="x", padx=14, pady=(12, 6))
        Label(tf, text="🛡  Privacy Shield — Service & Task Control", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(tf, "✅ Apply All Selected", self._apply_privacy_svc, self.GREEN2, "#000", font=FTB).pack(side="right", padx=4)
        self._btn(tf, "🔍 Scan Status", self._scan_privacy_svc, self.PURPLE, "#fff").pack(side="right", padx=4)
        self._btn(tf, "☑ Select Recommended", self._select_rec_privacy, self.TEAL, "#000").pack(side="right", padx=4)
        sub = ttk.Notebook(t); sub.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        psvc_tab = Frame(sub, bg=self.BG); ptask_tab = Frame(sub, bg=self.BG)
        sub.add(psvc_tab, text="  ⚙ Services  "); sub.add(ptask_tab, text="  📅 Telemetry Tasks  ")
        self._build_privacy_svc_tab(psvc_tab); self._build_privacy_task_tab(ptask_tab)

    def _build_privacy_svc_tab(self, t):
        sf = Frame(t, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        sf.pack(fill="x", padx=10, pady=(8, 4))
        self._psvc_summary = Label(sf, text="Click 'Scan Status' to check current state",
                                   font=FT, bg=self.CARD, fg=self.TEXT2, padx=14, pady=8)
        self._psvc_summary.pack(side="left")
        outer = Frame(t, bg=self.BG); outer.pack(fill="both", expand=True, padx=10, pady=4)
        canvas = Canvas(outer, bg=self.BG, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = Frame(canvas, bg=self.BG); canvas_window = canvas.create_window((0, 0), window=inner, anchor="nw")
        def on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(canvas_window, width=canvas.winfo_width())
        inner.bind("<Configure>", on_configure)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_window, width=e.width))
        canvas.bind("<Enter>", lambda e: canvas.bind_all('<MouseWheel>', lambda ev, c=canvas: c.yview_scroll(int(-1 * (ev.delta / 120)), 'units')))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all('<MouseWheel>'))
        self._svc_check_vars = {}; self._svc_status_labels = {}
        for cat_name, cat_data in PrivacyServiceManager.CATEGORIES.items():
            col = cat_data["color"]
            ch = Frame(inner, bg=self.CARD2, highlightbackground=col, highlightthickness=1)
            ch.pack(fill="x", padx=0, pady=(8, 0)); Frame(ch, bg=col, width=5).pack(side="left", fill="y")
            Label(ch, text=cat_name, font=FTB, bg=self.CARD2, fg=col, padx=12, pady=8).pack(side="left")
            svcs = list(cat_data["services"].keys())
            Button(ch, text="☑ Select All in Category", font=("Segoe UI", 8, "bold"), bg="#1a3a5c", fg="#00c8ff",
                   relief="flat", padx=10, pady=3, cursor="hand2",
                   command=lambda s=list(svcs): self._cat_select_all(s)).pack(side="right", padx=8)
            for svc_name, (desc, action, severity) in cat_data["services"].items():
                row = Frame(inner, bg=self.CARD); row.pack(fill="x", padx=0, pady=0)
                Frame(row, bg=self.BORDER, height=1).pack(fill="x")
                rinner = Frame(row, bg=self.CARD); rinner.pack(fill="x", padx=6, pady=5)
                var = BooleanVar(self, value=False); self._svc_check_vars[svc_name] = var
                cb = Checkbutton(rinner, variable=var, bg=self.CARD, activebackground=self.CARD, selectcolor="#1a2a3a",
                                 fg=self.TEXT, cursor="hand2", bd=0, highlightthickness=0)
                cb.pack(side="left", padx=(4, 0))
                def toggle_var(v=var, e=None): v.set(not v.get())
                name_lbl = Label(rinner, text=svc_name, font=FTB, bg=self.CARD, fg="#ffffff", width=28, anchor="w", cursor="hand2")
                name_lbl.pack(side="left", padx=(4, 0)); name_lbl.bind("<Button-1>", toggle_var)
                desc_lbl = Label(rinner, text=desc, font=FTS, bg=self.CARD, fg=self.TEXT2, anchor="w", cursor="hand2")
                desc_lbl.pack(side="left", padx=8, expand=True, fill="x"); desc_lbl.bind("<Button-1>", toggle_var)
                sev_col = self.RISK.get(severity, self.TEXT3)
                Label(rinner, text=severity, font=("Segoe UI", 8, "bold"), bg=sev_col,
                      fg="#000000" if severity in ("MEDIUM", "LOW", "INFO") else "#ffffff", padx=6, pady=2).pack(side="right", padx=4)
                act_col = self.RED if action == "DISABLE" else self.ACCENT
                Label(rinner, text=action, font=("Segoe UI", 8, "bold"), bg=act_col, fg="#000", padx=6, pady=2).pack(side="right", padx=4)
                st_lbl = Label(rinner, text="?", font=("Segoe UI", 8), bg=self.CARD, fg=self.TEXT3, width=12, anchor="center")
                st_lbl.pack(side="right", padx=8); self._svc_status_labels[svc_name] = st_lbl

    def _cat_select_all(self, svc_names):
        all_selected = all(self._svc_check_vars[n].get() for n in svc_names if n in self._svc_check_vars)
        new_val = not all_selected
        for n in svc_names:
            if n in self._svc_check_vars: self._svc_check_vars[n].set(new_val)
        self._log(f"{'Selected' if new_val else 'Unselected'} {len(svc_names)} services in category")

    def _select_rec_privacy(self):
        count = 0
        for cat_data in PrivacyServiceManager.CATEGORIES.values():
            for svc_name, (desc, action, severity) in cat_data["services"].items():
                if svc_name in self._svc_check_vars:
                    val = action == "DISABLE"
                    self._svc_check_vars[svc_name].set(val)
                    if val: count += 1
        for var in self._task_check_vars.values(): var.set(True)
        task_count = len(self._task_check_vars)
        self._log(f"Selected {count} services + {task_count} tasks")
        messagebox.showinfo("Selected", f"Selected {count} services to disable\n{task_count} telemetry tasks selected\n\nClick 'Apply All Selected' to apply.")

    def _scan_privacy_svc(self):
        def task():
            ok_count = 0; warn_count = 0; not_found = 0
            for cat_data in PrivacyServiceManager.CATEGORIES.values():
                for svc_name, (desc, action, severity) in cat_data["services"].items():
                    state, startup = self.privacy_svc.get_service_status(svc_name)
                    if state == "NOT_FOUND":
                        status_text = "— Not installed"; color = self.TEXT3; not_found += 1
                    else:
                        is_disabled = "DISABLED" in startup.upper()
                        is_stopped = state in ("STOPPED", "1")
                        all_good = is_disabled or (action == "MANUAL" and "DEMAND" in startup.upper())
                        if all_good: color = self.GREEN; status_text = "✓ Secure"; ok_count += 1
                        elif is_stopped: color = self.ORANGE; status_text = "◌ Stopped"; warn_count += 1
                        else: color = self.RED; status_text = "⚠ Running"; warn_count += 1
                    def update_label(name=svc_name, txt=status_text, col=color):
                        if name in self._svc_status_labels: self._svc_status_labels[name].config(text=txt, fg=col)
                    self.schedule_ui(update_label)
            def update_summary():
                self._psvc_summary.config(
                    text=f"Scan complete — ✓ {ok_count} secure  |  ⚠ {warn_count} need attention  |  — {not_found} not installed",
                    fg=self.GREEN if warn_count == 0 else self.ORANGE)
            self.schedule_ui(update_summary)
        threading.Thread(target=task, daemon=True).start()

    def _apply_privacy_svc(self):
        selected_svc = [n for n, v in self._svc_check_vars.items() if v.get()]
        selected_tasks = [path for path, v in self._task_check_vars.items() if v.get()]
        if not selected_svc and not selected_tasks:
            messagebox.showinfo("Nothing Selected", "Check services or tasks to apply first.\n\nTip: Click 'Select Recommended' button to auto-select all.")
            return
        total = len(selected_svc) + len(selected_tasks)
        if not messagebox.askyesno("Confirm",
            f"Apply changes to {total} items?\n\n• {len(selected_svc)} services to disable/configure\n• {len(selected_tasks)} telemetry tasks to disable\n\nReboot recommended after completion."):
            return
        def task():
            done = 0; all_svcs = {}
            for cat_data in PrivacyServiceManager.CATEGORIES.values(): all_svcs.update(cat_data["services"])
            for svc_name in selected_svc:
                if svc_name in all_svcs:
                    _, action, _ = all_svcs[svc_name]
                    if action == "DISABLE": self.privacy_svc.disable_service(svc_name)
                    elif action == "MANUAL": self.privacy_svc.set_manual(svc_name)
                    done += 1
            for task_path in selected_tasks: self.privacy_svc.disable_task(task_path); done += 1
            self.schedule_ui(lambda: messagebox.showinfo("Done", f"✓ Applied {done} changes\n\nReboot to complete all changes."))
            self.schedule_ui(self._scan_privacy_svc)
        threading.Thread(target=task, daemon=True).start()

    def _build_privacy_task_tab(self, t):
        tf = Frame(t, bg=self.BG); tf.pack(fill="x", padx=14, pady=8)
        Label(tf, text="Telemetry & tracking tasks found during audit", font=FT, bg=self.BG, fg=self.TEXT2).pack(side="left")
        self._btn(tf, "☑ Select All", lambda: [v.set(True) for v in self._task_check_vars.values()], self.TEAL, "#000", padx=10, pady=4).pack(side="right")
        outer = Frame(t, bg=self.BG); outer.pack(fill="both", expand=True, padx=10, pady=4)
        canvas = Canvas(outer, bg=self.BG, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set); vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = Frame(canvas, bg=self.BG); cw = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: (canvas.configure(scrollregion=canvas.bbox("all")), canvas.itemconfig(cw, width=canvas.winfo_width())))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        canvas.bind("<Enter>", lambda e: canvas.bind_all('<MouseWheel>', lambda ev, c=canvas: c.yview_scroll(int(-1 * (ev.delta / 120)), 'units')))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all('<MouseWheel>'))
        self._task_check_vars = {}
        for task_path, task_name, severity in PrivacyServiceManager.TELEMETRY_TASKS:
            row = Frame(inner, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=0)
            row.pack(fill="x", pady=1); Frame(row, bg=self.BORDER, height=1).pack(fill="x")
            ri = Frame(row, bg=self.CARD); ri.pack(fill="x", padx=6, pady=5)
            var = BooleanVar(value=False); self._task_check_vars[task_path] = var
            Checkbutton(ri, variable=var, bg=self.CARD, activebackground=self.CARD, selectcolor="#1a2a3a", cursor="hand2", bd=0).pack(side="left", padx=4)
            Label(ri, text=task_name, font=FTB, bg=self.CARD, fg="#ffffff", width=38, anchor="w").pack(side="left", padx=4)
            Label(ri, text=task_path, font=FTM, bg=self.CARD, fg=self.TEXT3, anchor="w").pack(side="left", padx=4, expand=True, fill="x")
            sev_col = self.RISK.get(severity, self.TEXT3)
            Label(ri, text=severity, font=("Segoe UI", 8, "bold"), bg=sev_col, fg="#000" if severity in ("MEDIUM", "LOW", "INFO") else "#fff", padx=6, pady=2).pack(side="right", padx=6)

    # ── Deep Clean ──
    def _build_deep_clean(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="🧹  Deep System Cleaner — 10-Phase Engine", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🚀 Start Deep Clean", self._run_deep_clean, self.GREEN2, "#000", font=FTB).pack(side="right", padx=4)
        self._btn(hf, "🔍 Quick Scan", self._quick_scan, self.PURPLE, "#fff").pack(side="right", padx=4)
        self._btn(hf, "⏹ Stop", self._stop_deep_clean, self.RED2, "#fff").pack(side="right", padx=4)
        left = Frame(t, bg=self.BG); left.pack(side="left", fill="both", expand=True, padx=(10, 4), pady=8)
        right = Frame(t, bg=self.BG); right.pack(side="right", fill="y", padx=(4, 10), pady=8)
        opts_frame = Frame(left, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        opts_frame.pack(fill="x", pady=(0, 8)); Frame(opts_frame, bg=self.GREEN, height=2).pack(fill="x")
        Label(opts_frame, text="Cleaning Options", font=FTB, bg=self.CARD, fg=self.GREEN, padx=12, pady=6).pack(anchor="w")
        og = Frame(opts_frame, bg=self.CARD); og.pack(fill="x", padx=12, pady=(0, 10))
        self._dc_opts = {}
        dc_options = [
            ('temp', '🗑 Temp Files', True), ('prefetch', '⚡ Prefetch', True),
            ('browser', '🌐 Browser Cache', True), ('updates', '🔄 Update Cache', True),
            ('dumps', '💥 Memory Dumps', True), ('wer', '📋 Error Reports', True),
            ('telemetry', '👁 Telemetry Data', True), ('logs', '📝 System Logs', True),
            ('network', '🌐 DNS/Net Cache', True), ('eventlogs', '📋 Event Logs', False),
            ('reghistory', '🔑 Registry History', True), ('gpu', '🎮 GPU Cache', True),
            ('trim', '💾 SSD TRIM', True), ('dns_optimize', '🌐 DNS Optimize', True),
        ]
        for i, (k, label, default) in enumerate(dc_options):
            var = BooleanVar(value=default); self._dc_opts[k] = var
            Checkbutton(og, text=label, variable=var, font=FT, bg=self.CARD, fg=self.TEXT, selectcolor="#1a2a3a",
                        activebackground=self.CARD).grid(row=i//3, column=i%3, sticky="w", padx=8, pady=2)
        pf = Frame(left, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        pf.pack(fill="x", pady=(0, 8)); Frame(pf, bg=self.ACCENT, height=2).pack(fill="x")
        self.dc_status = Label(pf, text="Ready — Select options and click Start", font=FT, bg=self.CARD, fg=self.TEXT2, padx=12, pady=6)
        self.dc_status.pack(anchor="w")
        self.dc_bar = ttk.Progressbar(pf, length=400, mode='determinate'); self.dc_bar.pack(fill="x", padx=12, pady=(0, 10))
        lf = Frame(left, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        lf.pack(fill="both", expand=True); Frame(lf, bg=self.TEAL, height=2).pack(fill="x")
        lh = Frame(lf, bg=self.CARD); lh.pack(fill="x", padx=12, pady=6)
        Label(lh, text="Clean Log", font=FTB, bg=self.CARD, fg=self.TEAL).pack(side="left")
        self._btn(lh, "Clear", lambda: (self.dc_log.config(state="normal"), self.dc_log.delete(1.0, "end"), self.dc_log.config(state="disabled")),
                  self.BORDER2, self.TEXT, padx=8, pady=3).pack(side="right")
        self.dc_log = scrolledtext.ScrolledText(lf, height=14, bg=self.BG, fg=self.GREEN, font=FTM, relief="flat", state="disabled", wrap="word")
        self.dc_log.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        ph_frame = Frame(right, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1, width=220)
        ph_frame.pack(fill="both", expand=True); ph_frame.pack_propagate(False)
        Frame(ph_frame, bg=self.YELLOW, height=2).pack(fill="x")
        Label(ph_frame, text="Clean Phases", font=FTB, bg=self.CARD, fg=self.YELLOW, padx=12, pady=8).pack(anchor="w")
        self._phase_labels = []
        for i, (name, _) in enumerate(DeepCleanEngine.PHASES):
            prow = Frame(ph_frame, bg=self.CARD); prow.pack(fill="x", padx=8, pady=3)
            dot = Label(prow, text="○", font=FT, bg=self.CARD, fg=self.TEXT3, width=2); dot.pack(side="left")
            lbl = Label(prow, text=f"{i + 1}. {name[:28]}", font=("Segoe UI", 8), bg=self.CARD, fg=self.TEXT3, anchor="w")
            lbl.pack(side="left", fill="x", expand=True); self._phase_labels.append((dot, lbl))

    def _dc_log_write(self, msg): self.schedule_ui(lambda: self._dc_log_append(msg))
    def _dc_log_append(self, msg):
        try:
            self.dc_log.config(state="normal"); self.dc_log.insert("end", msg + "\n")
            self.dc_log.see("end"); self.dc_log.config(state="disabled")
        except: pass

    def _run_deep_clean(self):
        opts = {k: v.get() for k, v in self._dc_opts.items()}
        if not messagebox.askyesno("Deep Clean", "Start full 10-phase deep clean?\n\n• Close browsers before continuing\n• Process may take several minutes\n• Reboot recommended afterward"):
            return
        for dot, lbl in self._phase_labels: dot.config(text="○", fg=self.TEXT3); lbl.config(fg=self.TEXT3)
        self.dc_log.config(state="normal"); self.dc_log.delete(1.0, "end"); self.dc_log.config(state="disabled")
        self.dc_bar['value'] = 0; self.deep_clean._stop = False
        def log_fn(msg):
            self._dc_log_write(msg)
            for i, (name, _) in enumerate(DeepCleanEngine.PHASES):
                if f"[{i + 1}/" in msg:
                    def mark(idx=i):
                        for j in range(len(self._phase_labels)):
                            dot, lbl = self._phase_labels[j]
                            if j < idx: dot.config(text="✓", fg=self.GREEN); lbl.config(fg=self.GREEN2)
                            elif j == idx: dot.config(text="▶", fg=self.YELLOW); lbl.config(fg=self.YELLOW)
                    self.schedule_ui(mark)
        self.deep_clean.on_log = log_fn
        def task():
            freed = self.deep_clean.run_all(opts)
            def done():
                for dot, lbl in self._phase_labels: dot.config(text="✓", fg=self.GREEN); lbl.config(fg=self.GREEN2)
                self.dc_status.config(text=f"✅ Complete — {fmt_size(freed)} freed", fg=self.GREEN)
                messagebox.showinfo("Deep Clean Complete", f"✅ Deep clean finished!\n\nTotal freed: {fmt_size(freed)}\n\nReboot recommended.")
            self.schedule_ui(done)
        threading.Thread(target=task, daemon=True).start()

    def _stop_deep_clean(self):
        self.deep_clean._stop = True
        self.dc_status.config(text="⏹ Stopping...", fg=self.ORANGE)

    def _quick_scan(self):
        self.dc_log.config(state="normal"); self.dc_log.delete(1.0, "end"); self.dc_log.config(state="disabled")
        def task():
            c = DeepCleanEngine(on_log=self._dc_log_write)
            res = c.run_all({'temp': 1, 'prefetch': 1, 'browser': 0, 'updates': 0, 'dumps': 0, 'wer': 0,
                             'telemetry': 0, 'logs': 0, 'network': 0, 'eventlogs': 0, 'reghistory': 0,
                             'gpu': 0, 'trim': 0, 'dns_optimize': 0})
            self._dc_log_write(f"\n{'─'*40}\n  Quick scan freed: {fmt_size(res)}")
        threading.Thread(target=task, daemon=True).start()

    # ── Service Manager ──
    def _build_services(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="⚙  Service Manager", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄 Refresh", self._load_services, self.BLUE, "#fff").pack(side="right", padx=4)
        ff = Frame(t, bg=self.BG); ff.pack(fill="x", padx=14, pady=4)
        Label(ff, text="Filter:", font=FT, bg=self.BG, fg=self.TEXT2).pack(side="left")
        self._svc_filter = StringVar(value="All")
        cb = ttk.Combobox(ff, textvariable=self._svc_filter, state="readonly", width=18,
                          values=["All", "Running", "Stopped", "Auto Start", "Disabled"])
        cb.pack(side="left", padx=8); cb.bind("<<ComboboxSelected>>", lambda e: self._filter_services())
        Label(ff, text="Search:", font=FT, bg=self.BG, fg=self.TEXT2).pack(side="left", padx=(14, 4))
        self._svc_search = StringVar(); self._svc_search.trace('w', lambda *a: self._filter_services())
        Entry(ff, textvariable=self._svc_search, font=FT, width=28, bg=self.CARD2, fg=self.TEXT, insertbackground=self.TEXT, relief="flat").pack(side="left")
        cols = [('name', 'Service Name', 200), ('display', 'Display Name', 280), ('state', 'Status', 90),
                ('startup', 'Startup', 130), ('cat', 'Category', 110), ('rec', 'Recommended Action / Notes', 320)]
        self.svc_tree = self._make_tree(t, cols, 22)
        self.svc_tree.tag_configure("critical", foreground=self.RED)
        self.svc_tree.tag_configure("safe", foreground=self.GREEN)
        self.svc_tree.tag_configure("orphaned", foreground=self.ORANGE)
        self.svc_tree.bind("<Button-3>", self._svc_ctx_menu)
        bf = Frame(t, bg=self.BG); bf.pack(fill="x", padx=14, pady=6)
        for txt, cmd, col in [("▶ Start", lambda: self._svc_action('start'), self.GREEN),
                               ("⏹ Stop", lambda: self._svc_action('stop'), self.ORANGE),
                               ("✅ Enable", lambda: self._svc_action('enable'), self.BLUE),
                               ("🚫 Disable", lambda: self._svc_action('disable'), self.RED)]:
            self._btn(bf, txt, cmd, col, "#000" if col == self.GREEN else "#fff", padx=12, pady=6).pack(side="left", padx=3)
        self.all_services = []; self._load_services()

    def _enrich_recommendation(self, svc_name):
        for cat_data in PrivacyServiceManager.CATEGORIES.values():
            if svc_name in cat_data["services"]:
                desc, action, severity = cat_data["services"][svc_name]
                if action == "DISABLE": return f"Disable: {desc}"
                elif action == "MANUAL": return f"Set Manual: {desc}"
                else: return desc
        return "No specific recommendation — review manually"

    def _load_services(self):
        self.svc_tree.delete(*self.svc_tree.get_children())
        def task():
            self.all_services = self.svc_mgr.get_all_services()
            for s in self.all_services: s['recommendation'] = self._enrich_recommendation(s['name'])
            self.schedule_ui(self._filter_services)
        threading.Thread(target=task, daemon=True).start()

    def _filter_services(self):
        f = self._svc_filter.get(); q = self._svc_search.get().lower()
        self.svc_tree.delete(*self.svc_tree.get_children())
        for s in self.all_services:
            st = s.get('startup', '')
            if f == "Running" and s.get('state') != 'RUNNING': continue
            if f == "Stopped" and s.get('state') == 'RUNNING': continue
            if f == "Auto Start" and 'AUTO' not in st.upper(): continue
            if f == "Disabled" and 'DISABLED' not in st.upper(): continue
            if q and q not in s.get('name', '').lower() and q not in s.get('display', '').lower(): continue
            tag = s.get('category', 'System').lower()
            self.svc_tree.insert('', 'end', values=(s['name'], s.get('display', ''), s.get('state', ''),
                                                     st, s.get('category', ''), s.get('recommendation', '')), tags=(tag,))

    def _svc_action(self, act):
        sel = self.svc_tree.selection()
        if not sel: return
        name = self.svc_tree.item(sel[0])['values'][0]
        if act == 'start': self.svc_mgr.start_service(name)
        elif act == 'stop':
            if messagebox.askyesno("Confirm", f"Stop {name}?"): self.svc_mgr.stop_service(name)
        elif act == 'enable': self.svc_mgr.enable_service(name)
        elif act == 'disable':
            if messagebox.askyesno("Confirm", f"Disable {name}?"): self.svc_mgr.disable_service(name)
        self._load_services()

    def _svc_ctx_menu(self, event):
        sel = self.svc_tree.selection()
        if not sel: return
        name = self.svc_tree.item(sel[0])['values'][0]
        m = Menu(self, tearoff=0, bg=self.CARD2, fg=self.TEXT)
        m.add_command(label="▶ Start", command=lambda: (self.svc_mgr.start_service(name), self._load_services()))
        m.add_command(label="⏹ Stop", command=lambda: (self.svc_mgr.stop_service(name), self._load_services()))
        m.add_separator()
        m.add_command(label="✅ Enable Auto", command=lambda: (self.svc_mgr.enable_service(name), self._load_services()))
        m.add_command(label="🚫 Disable", command=lambda: (self.svc_mgr.disable_service(name), self._load_services()))
        m.post(event.x_root, event.y_root)

    # ── Tasks ──
    def _build_tasks(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="📅  Scheduled Task Manager", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄 Refresh", self._load_tasks, self.BLUE, "#fff").pack(side="right", padx=4)
        self._btn(hf, "🚫 Disable Selected", self._disable_tasks, self.RED, "#fff").pack(side="right", padx=4)
        self._btn(hf, "✅ Enable Selected", self._enable_tasks, self.GREEN2, "#000").pack(side="right", padx=4)
        cols = [('name', 'Task Name', 350), ('path', 'Path', 300), ('state', 'State', 100), ('next', 'Next Run', 160)]
        self.task_tree = self._make_tree(t, cols, 24)
        self.task_tree.tag_configure("disabled", foreground=self.TEXT3)
        self.task_tree.tag_configure("running", foreground=self.GREEN)
        self.task_tree.tag_configure("ready", foreground=self.ACCENT)
        self._load_tasks()

    def _load_tasks(self):
        self.task_tree.delete(*self.task_tree.get_children())
        def task():
            ok, out, _ = run_cmd(['schtasks', '/Query', '/FO', 'CSV', '/V', '/NH'], timeout=30)
            if ok:
                rows = []
                for line in out.splitlines():
                    parts = line.strip('"').split('","')
                    if len(parts) >= 4:
                        name = parts[0].split('\\')[-1]; path = parts[0]
                        status = parts[3] if len(parts) > 3 else ''
                        nxt = parts[7] if len(parts) > 7 else ''
                        rows.append((name, path, status, nxt))
                def fill():
                    for name, path, status, nxt in rows:
                        tag = ("disabled" if 'disabled' in status.lower()
                               else "running" if 'running' in status.lower() else "ready")
                        self.task_tree.insert('', 'end', values=(name, path, status, nxt), tags=(tag,))
                self.schedule_ui(fill)
        threading.Thread(target=task, daemon=True).start()

    def _disable_tasks(self):
        sel = self.task_tree.selection()
        if not sel: return
        if not messagebox.askyesno("Confirm", f"Disable {len(sel)} tasks?"): return
        for s in sel:
            path = self.task_tree.item(s)['values'][1]
            ok, _, _ = run_cmd(['schtasks', '/Change', '/TN', path, '/DISABLE'], timeout=10)
            self._log(f"{'✓' if ok else '✗'} Task {'disabled' if ok else 'failed'}: {path}")
        self._load_tasks()

    def _enable_tasks(self):
        sel = self.task_tree.selection()
        if not sel: return
        for s in sel:
            path = self.task_tree.item(s)['values'][1]
            run_cmd(['schtasks', '/Change', '/TN', path, '/ENABLE'], timeout=10)
        self._load_tasks()

    # ── Privacy Reg ──
    def _build_privacy_reg(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="🔒  Privacy Registry — Critical Settings", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "✅ Apply All Privacy", self._apply_all_priv_reg, self.GREEN2, "#000", font=FTB).pack(side="right", padx=4)
        self._btn(hf, "🔍 Scan Status", self._scan_priv_reg, self.PURPLE, "#fff").pack(side="right", padx=4)
        cols = [('name', 'Setting', 200), ('cat', 'Category', 110), ('current', 'Current Value', 120),
                ('privacy', 'Privacy Value', 120), ('status', 'Status', 100), ('desc', 'Description', 380)]
        self.priv_tree = self._make_tree(t, cols, 24)
        self.priv_tree.tag_configure("on", foreground=self.GREEN)
        self.priv_tree.tag_configure("off", foreground=self.ORANGE)
        self.priv_tree.tag_configure("err", foreground=self.TEXT3)
        self._scan_priv_reg()

    def _scan_priv_reg(self):
        self.priv_tree.delete(*self.priv_tree.get_children())
        def task():
            statuses = self.privacy_mgr.get_all_status()
            def fill():
                for s in statuses:
                    cur = str(s['current']); priv = str(s['privacy_value']); ok = s['privacy_on']
                    tag = "on" if ok else ("err" if s['current'] == 'Not Set' else "off")
                    status = "✓ Private" if ok else "✖ Exposed"
                    self.priv_tree.insert('', 'end', values=(s['name'], s['category'], cur, priv, status, s['description']), tags=(tag,))
            self.schedule_ui(fill)
        threading.Thread(target=task, daemon=True).start()

    def _apply_all_priv_reg(self):
        if messagebox.askyesno("Apply Privacy", "Set all privacy registry settings to recommended values?"):
            def task():
                self.privacy_mgr.apply_all_recommended()
                self.schedule_ui(lambda: messagebox.showinfo("Done", "All privacy settings applied!"))
                self.schedule_ui(self._scan_priv_reg)
            threading.Thread(target=task, daemon=True).start()

    # ── Registry Cleaner ──
    def _build_registry_clean(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="🔧  Registry Cleaner & Optimizer", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔍 Scan Registry", self._scan_registry, self.PURPLE, "#fff", font=FTB).pack(side="right", padx=4)
        self._btn(hf, "💾 Backup First", self._backup_registry, self.BLUE, "#fff").pack(side="right", padx=4)
        self._btn(hf, "🔧 Fix Selected", self._fix_registry, self.GREEN2, "#000").pack(side="right", padx=4)
        sf = Frame(t, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        sf.pack(fill="x", padx=14, pady=(4, 6)); Frame(sf, bg=self.PURPLE, height=2).pack(fill="x")
        self._reg_summary = Label(sf, text="Click 'Scan Registry' to find issues", font=FT, bg=self.CARD, fg=self.TEXT2, padx=14, pady=8)
        self._reg_summary.pack(side="left")
        cols = [('type', 'Issue Type', 200), ('desc', 'Description', 520), ('sev', 'Severity', 90)]
        self.reg_tree = self._make_tree(t, cols, 22)
        self.reg_tree.tag_configure("low", foreground=self.GREEN)
        self.reg_tree.tag_configure("medium", foreground=self.YELLOW)
        self.reg_tree.tag_configure("high", foreground=self.RED)
        bf = Frame(t, bg=self.BG); bf.pack(fill="x", padx=14, pady=6)
        Label(bf, text="Select issues then click Fix Selected", font=("Segoe UI", 8), bg=self.BG, fg=self.TEXT3).pack(side="left")
        self._btn(bf, "☑ Select All", self._reg_select_all, self.TEAL, "#000", padx=10, pady=4).pack(side="right")

    def _scan_registry(self):
        self._reg_summary.config(text="Scanning registry…", fg=self.YELLOW); self.reg_tree.delete(*self.reg_tree.get_children())
        def task():
            self._reg_issues = self.reg_cleaner.scan_registry()
            def done():
                for iss in self._reg_issues:
                    self.reg_tree.insert('', 'end', values=(iss['type'], iss['description'], iss['severity'].upper()), tags=(iss['severity'],))
                col = self.GREEN if not self._reg_issues else self.ORANGE
                self._reg_summary.config(text=f"Found {len(self._reg_issues)} issues — Select and fix", fg=col)
            self.schedule_ui(done)
        threading.Thread(target=task, daemon=True).start()

    def _fix_registry(self):
        sel = self.reg_tree.selection()
        if not sel: messagebox.showinfo("No Selection", "Select issues to fix first"); return
        indices = [self.reg_tree.index(s) for s in sel]
        if not messagebox.askyesno("Fix Registry", f"Fix {len(indices)} registry issues?\n\nRecommend backing up first."): return
        def task():
            fixed, errs = self.reg_cleaner.fix_issues(indices)
            def done():
                msg = f"✓ Fixed: {fixed} issues"
                if errs: msg += f"\n✗ Errors: {len(errs)}"
                messagebox.showinfo("Registry Fix Complete", msg); self._scan_registry()
            self.schedule_ui(done)
        threading.Thread(target=task, daemon=True).start()

    def _backup_registry(self):
        if messagebox.askyesno("Backup Registry", "Create a registry backup?\n\nThis exports HKLM\\SOFTWARE and may take a minute."):
            def task():
                result = self.reg_cleaner.backup_registry()
                self.schedule_ui(lambda: messagebox.showinfo("Backup Done", f"Saved:\n{result}" if result else "Backup failed"))
            threading.Thread(target=task, daemon=True).start()

    def _reg_select_all(self):
        for item in self.reg_tree.get_children(): self.reg_tree.selection_add(item)

    # ── Performance ──
    def _build_performance(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="⚡  Performance Boost", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔍 Scan", self._scan_performance, self.PURPLE, "#fff").pack(side="right", padx=4)
        self._btn(hf, "✅ Apply Selected", self._apply_performance, self.GREEN2, "#000", font=FTB).pack(side="right", padx=4)
        self._btn(hf, "☑ Select All", lambda: self._perf_select_all(True), self.TEAL, "#000").pack(side="right", padx=4)
        sf = Frame(t, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        sf.pack(fill="x", padx=14, pady=(0, 8)); Frame(sf, bg=self.YELLOW, height=2).pack(fill="x")
        sh = Frame(sf, bg=self.CARD); sh.pack(fill="x", padx=14, pady=8)
        Label(sh, text="⚡ Performance Score", font=FTB, bg=self.CARD, fg=self.YELLOW).pack(side="left")
        self._perf_score_lbl = Label(sh, text="Run scan to calculate", font=FT, bg=self.CARD, fg=self.TEXT2)
        self._perf_score_lbl.pack(side="left", padx=16)
        self._perf_bar = ttk.Progressbar(sh, length=300, mode='determinate'); self._perf_bar.pack(side="right", padx=10)
        cols = [('check', '✓', 30), ('type', 'Type', 110), ('name', 'Service', 260),
                ('reason', 'Reason', 360), ('impact', 'Impact', 80)]
        self.perf_tree = self._make_tree(t, cols, 20)
        self.perf_tree.tag_configure("service", foreground=self.ACCENT)
        self.perf_tree.bind("<Button-1>", self._perf_toggle)
        bf = Frame(t, bg=self.BG); bf.pack(fill="x", padx=14, pady=6)
        Label(bf, text="Click checkbox column to toggle.", font=("Segoe UI", 8), bg=self.BG, fg=self.TEXT3).pack(side="left")
        self._btn(bf, "☐ Clear All", lambda: self._perf_select_all(False), self.BORDER2, self.TEXT2, padx=10, pady=4).pack(side="right")
        self._scan_performance()

    def _scan_performance(self):
        self.perf_tree.delete(*self.perf_tree.get_children()); self._perf_data = []
        def task():
            rows = []
            ok, out, _ = run_cmd(['sc', 'query', 'state=', 'all'])
            running_svcs = set()
            if ok:
                cur_name = None
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'): cur_name = line.split(':', 1)[1].strip()
                    elif 'RUNNING' in line and cur_name: running_svcs.add(cur_name)
            for svc, reason in self.PERF_SERVICES.items():
                ok2, out2, _ = run_cmd(['sc', 'qc', svc], timeout=6)
                disabled = False
                if ok2:
                    for line in out2.splitlines():
                        if 'START_TYPE' in line and 'DISABLED' in line.upper(): disabled = True; break
                if not disabled:
                    impact = "HIGH" if svc in ('DiagTrack', 'dmwappushservice', 'SysMain') else "MEDIUM"
                    rows.append({'check': '☑', 'type': 'Service', 'name': svc, 'display': reason,
                                 'impact': impact, 'enabled': True, 'tag': 'service'})
            def fill():
                self._perf_data = rows
                for r in rows: self.perf_tree.insert('', 'end', values=(r['check'], r['type'], r['name'], r['display'], r['impact']), tags=(r['tag'],))
                score = max(0, 100 - len(rows) * 4); self._perf_bar['value'] = score
                col = self.RED if score < 50 else self.ORANGE if score < 75 else self.GREEN
                self._perf_score_lbl.config(text=f"Score: {score}/100 — {len(rows)} items can be optimized", fg=col)
            self.schedule_ui(fill)
        threading.Thread(target=task, daemon=True).start()

    def _perf_toggle(self, event):
        item = self.perf_tree.identify_row(event.y); col = self.perf_tree.identify_column(event.x)
        if item and col == '#1':
            idx = self.perf_tree.index(item)
            if idx < len(self._perf_data):
                self._perf_data[idx]['enabled'] ^= True
                vals = list(self.perf_tree.item(item, 'values'))
                vals[0] = '☑' if self._perf_data[idx]['enabled'] else '☐'
                self.perf_tree.item(item, values=vals)

    def _perf_select_all(self, select=True):
        for i, item in enumerate(self.perf_tree.get_children()):
            if i < len(self._perf_data):
                self._perf_data[i]['enabled'] = select
                vals = list(self.perf_tree.item(item, 'values'))
                vals[0] = '☑' if select else '☐'
                self.perf_tree.item(item, values=vals)

    def _apply_performance(self):
        selected = [r for r in self._perf_data if r.get('enabled')]
        if not selected: messagebox.showinfo("Nothing Selected", "Use checkboxes to select items first."); return
        svcs = [r for r in selected if r['type'] == 'Service']
        if not messagebox.askyesno("Apply Performance Tweaks",
                                    f"Apply {len(selected)} optimizations?\n\n• {len(svcs)} services will be disabled\n\nReboot recommended."):
            return
        def task():
            done = 0
            for r in svcs:
                name = r['name']; run_cmd(['sc', 'stop', name], timeout=10)
                ok, _, _ = run_cmd(['sc', 'config', name, 'start=', 'disabled'], timeout=10)
                if not ok:
                    run_cmd(['reg', 'add', f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}',
                             '/v', 'Start', '/t', 'REG_DWORD', '/d', '4', '/f'], timeout=8)
                self._log(f"✓ Disabled service: {name}"); done += 1
            def finish():
                messagebox.showinfo("Done", f"✅ Applied {done} performance tweaks!\n\nReboot to fully apply.")
                self._scan_performance()
            self.schedule_ui(finish)
        threading.Thread(target=task, daemon=True).start()

    # ── Monitor ──
    def _build_monitor(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="👁  Real-Time Protection Monitor", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄 Check Now", self._monitor_check_now, self.PURPLE, "#fff").pack(side="right", padx=4)
        self._btn(hf, "🗑 Clear History", self._clear_monitor, self.RED, "#fff").pack(side="right", padx=4)
        sb = Frame(t, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        sb.pack(fill="x", padx=14, pady=(0, 8)); Frame(sb, bg=self.GREEN, height=2).pack(fill="x")
        sh = Frame(sb, bg=self.CARD); sh.pack(fill="x", padx=14, pady=8)
        Label(sh, text="👁 Monitor Status", font=FTB, bg=self.CARD, fg=self.GREEN).pack(side="left")
        self._monitor_status = Label(sh, text="✓ Active — Checking every 2 minutes for re-enabled services and reinstalled apps",
                                     font=FT, bg=self.CARD, fg=self.TEXT2)
        self._monitor_status.pack(side="left", padx=14)
        wf = Frame(t, bg=self.BG); wf.pack(fill="x", padx=14, pady=(0, 8))
        for txt, col in [("🔴 Critical Services", "#ff4444"), ("🟡 Privacy Policies", "#ffd740"),
                          ("🟢 Blocked Apps", "#00e676"), ("🔵 Telemetry Tasks", "#00c8ff")]:
            card = Frame(wf, bg=self.CARD, highlightbackground=col, highlightthickness=1)
            card.pack(side="left", expand=True, fill="both", padx=4)
            Label(card, text=txt, font=FTB, bg=self.CARD, fg=col, padx=10, pady=12).pack()
            Label(card, text="Monitored", font=("Segoe UI", 8), bg=self.CARD, fg=self.TEXT3).pack(pady=(0, 8))
        Label(t, text="Removed Items Watch List", font=FTB, bg=self.BG, fg=self.TEXT2, padx=14).pack(anchor="w", pady=(4, 2))
        cols = [('type', 'Type', 120), ('id', 'Identifier', 450), ('date', 'Removal Date', 200)]
        self.monitor_tree = self._make_tree(t, cols, 14)
        af = Frame(t, bg=self.CARD, highlightbackground=self.BORDER, highlightthickness=1)
        af.pack(fill="x", padx=14, pady=(8, 4)); Frame(af, bg=self.ACCENT, height=2).pack(fill="x")
        ah = Frame(af, bg=self.CARD); ah.pack(fill="x", padx=14, pady=8)
        Label(ah, text="Track Item:", font=FTB, bg=self.CARD, fg=self.ACCENT).pack(side="left")
        self._mon_type_var = StringVar(value="Service")
        OptionMenu(ah, self._mon_type_var, "Service", "Program", "Scheduled Task").pack(side="left", padx=8)
        self._mon_id_var = StringVar()
        Entry(ah, textvariable=self._mon_id_var, font=FT, width=40, bg=self.CARD2, fg=self.TEXT, insertbackground=self.TEXT, relief="flat").pack(side="left", padx=4)
        self._btn(ah, "➕ Add", self._monitor_add_item, self.GREEN2, "#000", padx=10, pady=4).pack(side="left", padx=6)
        Label(t, text="Alert Log", font=FTB, bg=self.BG, fg=self.TEXT2, padx=14).pack(anchor="w", pady=(8, 2))
        self._alert_log = scrolledtext.ScrolledText(t, height=5, bg=self.BG, fg=self.ORANGE, font=FTM, relief="flat", state="disabled", wrap="word")
        self._alert_log.pack(fill="x", padx=14, pady=(0, 8)); self._refresh_monitor()

    def _refresh_monitor(self):
        self.monitor_tree.delete(*self.monitor_tree.get_children())
        for item in self.monitor.removed_items:
            self.monitor_tree.insert('', 'end', values=(item['type'], item['id'], item.get('date', '')))

    def _monitor_check_now(self):
        self._monitor_status.config(text="🔍 Checking now…", fg=self.YELLOW)
        def task():
            alerts = self.monitor.check_now()
            self.schedule_ui(lambda: self._monitor_status.config(
                text=f"✓ All clear" if not alerts else f"⚠ {len(alerts)} alerts",
                fg=self.GREEN if not alerts else self.RED))
        threading.Thread(target=task, daemon=True).start()

    def _monitor_add_item(self):
        typ = self._mon_type_var.get(); ident = self._mon_id_var.get().strip()
        if not ident: messagebox.showinfo("Empty", "Enter a service name, program path, or task name"); return
        self.monitor.record_removed(typ, ident); self._mon_id_var.set(""); self._refresh_monitor()

    def _clear_monitor(self):
        if messagebox.askyesno("Clear", "Remove all monitored items?\nAlerts for these will stop."):
            self.monitor.removed_items.clear(); self.monitor._save(self.monitor.removed_items, REMOVED_ITEMS_FILE)
            self._refresh_monitor()

    # ── Startup ──
    def _build_startup(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="🚀  Startup Manager", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄 Refresh", self._load_startup, self.BLUE, "#fff").pack(side="right", padx=4)
        self._btn(hf, "🚫 Disable", self._disable_startup, self.RED, "#fff").pack(side="right", padx=4)
        cols = [('name', 'Name', 250), ('loc', 'Location', 160), ('cmd', 'Command', 380),
                ('en', 'Enabled', 70), ('ex', 'Exists', 60)]
        self.start_tree = self._make_tree(t, cols, 24)
        self.start_tree.tag_configure("ok", foreground=self.GREEN)
        self.start_tree.tag_configure("disabled", foreground=self.ORANGE)
        self.start_tree.tag_configure("missing", foreground=self.RED)
        self._load_startup()

    def _load_startup(self):
        self.start_tree.delete(*self.start_tree.get_children())
        def task():
            self._startup_items = self.startup_mgr.get_startup_items()
            def fill():
                for it in self._startup_items:
                    tag = "missing" if not it.get('exists', True) else ("ok" if it.get('enabled', True) else "disabled")
                    cmd = it['command']
                    if len(cmd) > 60: cmd = cmd[:57] + "..."
                    self.start_tree.insert('', 'end', values=(it['name'], it.get('location', ''), cmd,
                                                               "YES" if it.get('enabled', True) else "NO",
                                                               "✓" if it.get('exists', True) else "✗"), tags=(tag,))
            self.schedule_ui(fill)
        threading.Thread(target=task, daemon=True).start()

    def _disable_startup(self):
        sel = self.start_tree.selection()
        if not sel: return
        if not messagebox.askyesno("Confirm", f"Disable {len(sel)} startup items?"): return
        for s in sel:
            idx = self.start_tree.index(s)
            if idx < len(self._startup_items): self.startup_mgr.disable_item(self._startup_items[idx])
        self._load_startup()

    # ── Firewall ──
    def _build_firewall(self, t):
        sub = ttk.Notebook(t); sub.pack(fill="both", expand=True, padx=8, pady=8)
        ct = Frame(sub, bg=self.BG); sub.add(ct, text="  Active Connections  ")
        pt = Frame(sub, bg=self.BG); sub.add(pt, text="  Listening Ports  ")
        rt = Frame(sub, bg=self.BG); sub.add(rt, text="  Firewall Rules  ")
        self._build_conn_tab(ct); self._build_ports_tab(pt); self._build_rules_tab(rt)

    def _build_conn_tab(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=12, pady=8)
        Label(hf, text="Active Connections", font=FTH, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄", self._refresh_conn, self.BLUE, "#fff", padx=10, pady=5).pack(side="right", padx=3)
        self._btn(hf, "🚫 Block", self._block_conn, self.RED, "#fff", padx=10, pady=5).pack(side="right", padx=3)
        cols = [('proc', 'Process', 150), ('pid', 'PID', 55), ('laddr', 'Local', 160),
                ('raddr', 'Remote', 180), ('status', 'Status', 80)]
        self.conn_tree = self._make_tree(t, cols, 20); self._refresh_conn()

    def _refresh_conn(self):
        self.conn_tree.delete(*self.conn_tree.get_children())
        for c in self.firewall_mgr.active_connections():
            self.conn_tree.insert('', 'end', values=(c['process'], c['pid'], c['laddr'], c['raddr'], c['status']))

    def _block_conn(self):
        sel = self.conn_tree.selection()
        if not sel: return
        proc = self.conn_tree.item(sel[0])['values'][0]
        for p in psutil.process_iter(['pid', 'name', 'exe']):
            if p.info['name'] == proc:
                exe = p.info['exe']
                if exe and messagebox.askyesno("Block", f"Block all network for '{proc}'?"):
                    if self.firewall_mgr.block_program(exe): messagebox.showinfo("Done", f"Blocked: {proc}"); self._refresh_conn()
                return

    def _build_ports_tab(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=12, pady=8)
        Label(hf, text="Listening Ports (netstat -ano)", font=FTH, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄", self._refresh_ports, self.BLUE, "#fff", padx=10, pady=5).pack(side="right", padx=3)
        cols = [('proto', 'Proto', 70), ('local', 'Local Address', 200), ('pid', 'PID', 60),
                ('process', 'Process', 180), ('action', 'Action', 120)]
        self.ports_tree = self._make_tree(t, cols, 20); self._refresh_ports()

    def _refresh_ports(self):
        self.ports_tree.delete(*self.ports_tree.get_children())
        ok, out, _ = run_cmd(['netstat', '-ano'], timeout=10)
        if not ok: return
        for line in out.splitlines():
            if 'LISTENING' in line.upper():
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]; local = parts[1]; pid = parts[4]
                    try: proc = psutil.Process(int(pid)).name()
                    except: proc = 'Unknown'
                    blocked = self.firewall_mgr.blocked_programs.get(proc, '')
                    action = 'Unblock' if not blocked else 'Blocked'
                    self.ports_tree.insert('', 'end', values=(proto, local, pid, proc, action))
        self.ports_tree.bind("<Button-3>", self._port_ctx_menu)

    def _port_ctx_menu(self, event):
        sel = self.ports_tree.selection()
        if not sel: return
        vals = self.ports_tree.item(sel[0])['values']; proc = vals[3]; pid = vals[2]
        m = Menu(self, tearoff=0, bg=self.CARD2, fg=self.TEXT)
        m.add_command(label="Block process", command=lambda: self._block_by_pid(pid))
        m.add_command(label="Unblock process", command=lambda: self._unblock_by_pid(pid))
        m.post(event.x_root, event.y_root)

    def _block_by_pid(self, pid):
        try:
            proc = psutil.Process(int(pid)); exe = proc.exe()
            if exe and self.firewall_mgr.block_program(exe, name=proc.name()):
                messagebox.showinfo("Blocked", f"Blocked {proc.name()}"); self._refresh_ports()
            else: messagebox.showwarning("Failed", "Could not block process.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def _unblock_by_pid(self, pid):
        try:
            proc = psutil.Process(int(pid)); exe = proc.exe()
            if exe and self.firewall_mgr.unblock_program(exe):
                messagebox.showinfo("Unblocked", f"Unblocked {proc.name()}"); self._refresh_ports()
            else: messagebox.showwarning("Failed", "Process not currently blocked.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def _build_rules_tab(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=12, pady=8)
        Label(hf, text="Firewall Rules", font=FTH, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄", self._refresh_rules, self.BLUE, "#fff", padx=10, pady=5).pack(side="right", padx=3)
        self._btn(hf, "🗑 Delete", self._del_rule, self.RED, "#fff", padx=10, pady=5).pack(side="right", padx=3)
        cols = [('name', 'Rule Name', 320), ('dir', 'Dir', 80), ('action', 'Action', 80), ('prog', 'Program', 400)]
        self.rules_tree = self._make_tree(t, cols, 22); self._refresh_rules()

    def _refresh_rules(self):
        self.rules_tree.delete(*self.rules_tree.get_children())
        for r in self.firewall_mgr.get_rules():
            self.rules_tree.insert('', 'end', values=(r.get('name', ''), r.get('direction', ''), r.get('action', ''), r.get('program', '')))

    def _del_rule(self):
        sel = self.rules_tree.selection()
        if not sel: return
        name = self.rules_tree.item(sel[0])['values'][0]
        if messagebox.askyesno("Delete", f"Delete rule '{name}'?"):
            self.firewall_mgr.delete_rule(name); self._refresh_rules()

    # ── Uninstaller + Destroy Bloat button ──
    def _build_uninstall(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="🗑  Software Uninstaller", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🔄 Refresh", self._refresh_uninstall, self.BLUE, "#fff").pack(side="right", padx=4)
        self._btn(hf, "🗑 Uninstall Selected", self._uninstall_prog, self.RED, "#fff", font=FTB).pack(side="right", padx=4)
        self._btn(hf, "🧹 Scan Leftovers", self._scan_leftovers, self.ORANGE, "#000").pack(side="right", padx=4)
        self._btn(hf, "🔥 Destroy Bloat", self._destroy_bloat, "#ff4444", "#fff", font=FTB).pack(side="right", padx=4)

        sf = Frame(t, bg=self.BG); sf.pack(fill="x", padx=14, pady=4)
        Label(sf, text="Search:", font=FT, bg=self.BG, fg=self.TEXT2).pack(side="left")
        self._uninst_search = StringVar(); self._uninst_search.trace('w', lambda *a: self._filter_uninstall())
        Entry(sf, textvariable=self._uninst_search, font=FT, width=35, bg=self.CARD2, fg=self.TEXT, insertbackground=self.TEXT, relief="flat").pack(side="left", padx=8)
        self._show_hidden = BooleanVar()
        Checkbutton(sf, text="Show hidden", variable=self._show_hidden, font=FT, bg=self.BG, fg=self.TEXT2,
                    selectcolor="#1a2a3a", activebackground=self.BG, command=self._refresh_uninstall).pack(side="left", padx=8)
        cols = [('name', 'Program', 290), ('pub', 'Publisher', 160), ('ver', 'Version', 100),
                ('size', 'Size', 90), ('date', 'Date', 100)]
        self.uninst_tree = self._make_tree(t, cols, 24)
        self.uninst_tree.tag_configure("bloat", foreground=self.RED)
        self._uninst_data = []; self._refresh_uninstall()

    def _refresh_uninstall(self):
        self._uninst_data = self.uninstaller.get_all_programs(self._show_hidden.get())
        self._filter_uninstall()

    def _filter_uninstall(self):
        self.uninst_tree.delete(*self.uninst_tree.get_children())
        q = self._uninst_search.get().lower()
        for p in self._uninst_data:
            if q and q not in p['name'].lower() and q not in p.get('publisher', '').lower(): continue
            self.uninst_tree.insert('', 'end', values=(p['name'], p.get('publisher', ''), p.get('version', ''),
                                                       fmt_size(p['size']), p.get('date', '')),
                                    tags=("bloat" if p.get('is_bloat') else "",))

    def _uninstall_prog(self):
        sel = self.uninst_tree.selection()
        if not sel: return
        for s in sel:
            name = self.uninst_tree.item(s)['values'][0]
            prog = next((p for p in self._uninst_data if p['name'] == name), None)
            if prog:
                if messagebox.askyesno("Uninstall", f"Uninstall '{name}'?"):
                    def task(p=prog):
                        ok = self.uninstaller.uninstall_program(p)
                        self.schedule_ui(lambda: messagebox.showinfo("Done", "Uninstall completed" if ok else "Uninstall may need manual step"))
                        self._refresh_uninstall()
                    threading.Thread(target=task, daemon=True).start()

    def _scan_leftovers(self):
        if messagebox.askyesno("Scan Leftovers", "Scan for leftover files/registry of all installed programs? This may take a moment."):
            def task():
                count = 0
                for p in self._uninst_data:
                    leftovers = self.uninstaller.find_leftovers(p)
                    files = leftovers.get('files', []); regs = leftovers.get('registry', [])
                    count += len(files) + len(regs)
                self.schedule_ui(lambda: messagebox.showinfo("Leftovers Scan", f"Found {count} potential leftover items. Check log for details."))
            threading.Thread(target=task, daemon=True).start()

    def _destroy_bloat(self):
        if not messagebox.askyesno("Destroy Bloat",
            "This will aggressively remove Edge, OneDrive, Cortana, WebView2 and their leftovers.\n\n"
            "A system restore point is created first. Continue?"):
            return
        def task():
            self._log("Creating restore point...")
            run_ps('Checkpoint-Computer -Description "Before WinShield Destroy Bloat" -RestorePointType "MODIFY_SETTINGS"')
            self._log("Killing bloat processes...")
            for proc in ["msedge", "MicrosoftEdge", "MicrosoftEdgeCP", "MicrosoftEdgeSH",
                         "OneDrive", "OneDriveSetup", "Cortana", "SearchUI",
                         "msedgewebview2", "MicrosoftEdgeUpdate", "MicrosoftEdgeElevationService"]:
                run_cmd(f'taskkill /F /IM "{proc}.exe"', timeout=10)
            self._log("Running official uninstallers...")
            odSetup = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64", "OneDriveSetup.exe")
            if os.path.exists(odSetup): run_cmd(f'"{odSetup}" /uninstall', timeout=60)
            edge_root = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "Edge", "Application")
            if os.path.isdir(edge_root):
                for ver_dir in os.listdir(edge_root):
                    setup_exe = os.path.join(edge_root, ver_dir, "Installer", "setup.exe")
                    if os.path.exists(setup_exe): run_cmd(f'"{setup_exe}" --uninstall --system-level --force-uninstall', timeout=120)
            edge_update_exe = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "EdgeUpdate", "MicrosoftEdgeUpdate.exe")
            if os.path.exists(edge_update_exe): run_cmd(f'"{edge_update_exe}" /uninstall', timeout=60)
            self._log("Deleting known bloat folders...")
            bloat_folders = [
                os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "Edge"),
                os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "EdgeUpdate"),
                os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "EdgeWebView"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "EdgeUpdate"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "OneDrive"),
                os.path.join(os.environ.get("USERPROFILE", ""), "OneDrive"),
                os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft OneDrive"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Packages", "Microsoft.549981C3F5F10_8wekyb3d8bbwe"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Packages", "Microsoft.Windows.Cortana_8wekyb3d8bbwe"),
            ]
            for folder in bloat_folders:
                if os.path.exists(folder):
                    run_cmd(f'takeown /F "{folder}" /R /D Y', timeout=30)
                    run_cmd(f'icacls "{folder}" /grant administrators:F /T /C', timeout=30)
                    try: shutil.rmtree(folder, ignore_errors=True); self._log(f"  Deleted: {folder}")
                    except Exception as e: self._log(f"  Failed: {folder} - {e}")
            self._log("Disabling bloat services...")
            for svc in ["edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService",
                         "OneDrive Updater Service", "SysMain", "Cortana"]:
                run_cmd(f'sc config {svc} start= disabled', timeout=10)
                run_cmd(f'sc stop {svc}', timeout=10)
            self._log("Adding firewall blocks...")
            block_exes = [
                os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "EdgeUpdate", "MicrosoftEdgeUpdate.exe"),
                os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Microsoft", "EdgeWebView", "Application", "msedgewebview2.exe"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "OneDrive", "OneDrive.exe"),
            ]
            for exe in block_exes:
                if os.path.exists(exe):
                    name = f"Block_{os.path.basename(exe)}"
                    run_cmd(f'netsh advfirewall firewall add rule name="{name}" dir=out action=block program="{exe}" enable=yes', timeout=10)
            self._log("Bloat destruction completed!")
            self.schedule_ui(lambda: messagebox.showinfo("Done", "Bloatware removed. Reboot recommended."))
        threading.Thread(target=task, daemon=True).start()

        # ── System Repair tab  ──
    def _build_system_repair(self, t):
        hf = Frame(t, bg=self.BG)
        hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="🩺  System Repair & Recovery", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "🚀 Run All Recommended", self._run_all_repairs,
                  self.GREEN2, "#000", font=FTB).pack(side="right", padx=4)

        # Horizontal button bar
        btn_bar = Frame(t, bg=self.BG)
        btn_bar.pack(fill="x", padx=14, pady=(0, 6))
        commands = [
            ("DISM Scan",         self._run_dism_scan),
            ("DISM Check",        self._run_dism_check),
            ("DISM RestoreHealth", self._run_dism_restore),
            ("SFC /ScanNow",      self._run_sfc),
            ("CHKDSK C: /F",      self._run_chkdsk),
            ("Create Restore Point", self._run_create_restore),
            ("Reset Window Update",          self._run_reset_wu),
            ("Reset Network",     self._run_reset_network),
        ]
        for cmd_text, cmd_func in commands:
            self._btn(btn_bar, cmd_text, cmd_func, self.BLUE, "#fff", padx=10, pady=5, font=("Segoe UI", 9)).pack(
                side="left", padx=3)

        # Central log frame (takes all remaining space)
        log_frame = Frame(t, bg=self.BG)
        log_frame.pack(fill="both", expand=True, padx=14, pady=(8, 10))

        lh = Frame(log_frame, bg=self.CARD)
        lh.pack(fill="x")
        Label(lh, text="Repair Log (live)", font=FTB, bg=self.CARD, fg=self.TEAL,
              padx=10, pady=4).pack(side="left")
        self._btn(lh, "Clear", lambda: (self.repair_log.config(state="normal"),
                                         self.repair_log.delete(1.0, "end"),
                                         self.repair_log.config(state="disabled")),
                  self.BORDER2, self.TEXT, padx=8, pady=3).pack(side="right")

        self.repair_log = scrolledtext.ScrolledText(log_frame, bg=self.BG, fg=self.GREEN,
                                                    font=FTB, relief="flat", state="disabled", wrap="word")
        self.repair_log.pack(fill="both", expand=True)

    # ── Individual repair commands ──
    def _run_dism_scan(self):
        self._run_repair_cmd_live("Dism /Online /Cleanup-Image /ScanHealth", "DISM ScanHealth")
    def _run_dism_check(self):
        self._run_repair_cmd_live("Dism /Online /Cleanup-Image /CheckHealth", "DISM CheckHealth")
    def _run_dism_restore(self):
        self._run_repair_cmd_live("Dism /Online /Cleanup-Image /RestoreHealth", "DISM RestoreHealth (may take minutes)")
    def _run_sfc(self):
        self._run_repair_cmd_live("sfc /scannow", "SFC /ScanNow")
    def _run_chkdsk(self):
        self._run_repair_cmd_live("chkdsk C: /F", "CHKDSK C: /F (requires reboot)", timeout=60)
    def _run_create_restore(self):
        self._run_repair_cmd_live(
            'powershell -NoProfile -Command "Checkpoint-Computer -Description \\"WinShield Repair\\" -RestorePointType \\"MODIFY_SETTINGS\\""',
            "Create Restore Point"
        )
    def _run_reset_wu(self):
        self._run_repair_cmd_live(
            "net stop wuauserv & net stop cryptSvc & net stop bits & net stop msiserver & "
            "ren C:\\Windows\\SoftwareDistribution SoftwareDistribution.old & "
            "ren C:\\Windows\\System32\\catroot2 catroot2.old & "
            "net start wuauserv & net start cryptSvc & net start bits & net start msiserver",
            "Reset Windows Update Components"
        )
    def _run_reset_network(self):
        self._run_repair_cmd_live(
            "netsh int ip reset & netsh winsock reset & ipconfig /flushdns & "
            "netsh int tcp set global autotuninglevel=normal",
            "Reset Network Stack"
        )

    # ── Live command runner ──
    def _run_repair_cmd_live(self, cmd, description, timeout=120):
        """Run a command and stream its output line‑by‑line into the repair log."""
        def task():
            self.schedule_ui(lambda: self._log_to_repair(
                f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Starting: {description}\n{'-'*50}\n"))
            try:
                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                for line in proc.stdout:
                    line = line.rstrip('\n\r')
                    self.schedule_ui(lambda l=line: self._log_to_repair(l + "\n"))
                proc.wait(timeout=timeout)
                result = "completed successfully" if proc.returncode == 0 else f"exited with code {proc.returncode}"
                self.schedule_ui(lambda r=result: self._log_to_repair(
                    f"\n{'✓' if 'successfully' in r else '✗'} {description} {r}.\n\n"))
            except Exception as e:
                self.schedule_ui(lambda: self._log_to_repair(f"✗ Error running {description}: {e}\n\n"))
        threading.Thread(target=task, daemon=True).start()

    def _log_to_repair(self, text):
        """Append text to the repair log Text widget."""
        try:
            self.repair_log.config(state="normal")
            self.repair_log.insert("end", text)
            self.repair_log.see("end")
            self.repair_log.config(state="disabled")
        except:
            pass

    # ── Run‑all helper ──
    def _run_all_repairs(self):
        if not messagebox.askyesno("Run All Repairs",
            "This will run DISM ScanHealth, SFC, Reset Windows Update, and Reset Network.\n"
            "RestoreHealth is skipped because it's slow – run it separately if needed.\n"
            "Proceed?"):
            return
        self._run_dism_scan()
        self.after(2000, self._run_sfc)
        self.after(4000, self._run_reset_wu)
        self.after(6000, self._run_reset_network)

    # ── Logs ──
    def _build_logs(self, t):
        hf = Frame(t, bg=self.BG); hf.pack(fill="x", padx=14, pady=(12, 6))
        Label(hf, text="📋  Activity Log", font=FTL, bg=self.BG, fg=self.TEXT).pack(side="left")
        self._btn(hf, "💾 Export", self._export_logs, self.GREEN2, "#000").pack(side="right", padx=4)
        self._btn(hf, "🗑 Clear", self._clear_logs, self.RED, "#fff").pack(side="right", padx=4)
        self._btn(hf, "🔄 Refresh", self._load_logs, self.BLUE, "#fff").pack(side="right", padx=4)
        Frame(t, bg=self.BORDER, height=1).pack(fill="x", padx=14)
        self.log_txt = scrolledtext.ScrolledText(t, bg=self.BG, fg=self.GREEN, font=FTM, relief="flat", state="disabled", wrap="word")
        self.log_txt.pack(fill="both", expand=True, padx=14, pady=10); self._load_logs()

    def _load_logs(self):
        self.log_txt.config(state="normal"); self.log_txt.delete(1.0, "end")
        try:
            if LOG_FILE.exists():
                with open(LOG_FILE, encoding='utf-8') as f: self.log_txt.insert(1.0, f.read())
        except Exception as e: self.log_txt.insert(1.0, f"Error: {e}")
        self.log_txt.config(state="disabled"); self.log_txt.see("end")

    def _clear_logs(self):
        if messagebox.askyesno("Clear", "Clear all logs?"):
            self.log_txt.config(state="normal"); self.log_txt.delete(1.0, "end")
            self.log_txt.config(state="disabled")
            with open(LOG_FILE, 'w'): pass

    def _export_logs(self):
        fn = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")],
                                          initialfile=f"WinShield_Log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if fn:
            try: shutil.copy(LOG_FILE, fn); messagebox.showinfo("Exported", f"Log saved:\n{fn}")
            except Exception as e: messagebox.showerror("Error", str(e))

    def _on_close(self):
        self._dashboard_on = False
        self.monitor.stop()
        logging.info("WinShield Pro v2.0 closed")
        self.destroy()

# ═══════════════════════ ENTRY POINT ═══════════════════════
if __name__ == "__main__":
    try:
        if not is_admin():
            r = Tk(); r.withdraw()
            if messagebox.askyesno("Admin Required",
                "WinShield Pro requires Administrator privileges.\n\nRestart as Administrator?"):
                r.destroy(); relaunch_admin(); sys.exit(0)
            r.destroy()
        app = WinShieldPro()
        app.mainloop()
    except Exception as e:
        logging.exception("Fatal error")
        try: messagebox.showerror("WinShield Pro Error", f"Fatal error:\n{str(e)}")
        except: print(f"Fatal error: {e}")