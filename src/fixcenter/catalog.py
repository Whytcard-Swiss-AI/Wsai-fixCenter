from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SUPPORTED_PLATFORMS = ("windows", "linux", "darwin")


@dataclass(frozen=True)
class ProbeSpec:
    argv: tuple[str, ...]
    timeout_seconds: int = 10


@dataclass(frozen=True)
class ControlSpec:
    id: str
    category: str
    title: str
    description: str
    probes: dict[str, ProbeSpec]

    def to_dict(self, include_commands: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if include_commands:
            data["probes"] = {
                name: {
                    "argv": list(probe.argv),
                    "timeout_seconds": probe.timeout_seconds,
                }
                for name, probe in self.probes.items()
            }
        else:
            data["probes"] = sorted(self.probes)
        return data


def _ps(script: str, timeout: int = 10) -> ProbeSpec:
    return ProbeSpec(
        (
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ),
        timeout,
    )


def _sh(script: str, timeout: int = 10) -> ProbeSpec:
    return ProbeSpec(("sh", "-c", script), timeout)


def _control(
    control_id: str,
    category: str,
    title: str,
    description: str,
    windows: str,
    linux: str,
    darwin: str,
    timeout: int = 10,
) -> ControlSpec:
    return ControlSpec(
        control_id,
        category,
        title,
        description,
        {
            "windows": _ps(windows, timeout),
            "linux": _sh(linux, timeout),
            "darwin": _sh(darwin, timeout),
        },
    )


CONTROL_CATALOG = (
    _control(
        "os.identity",
        "system",
        "OS and architecture",
        "Operating system, build, kernel and architecture.",
        "Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json -Compress",
        "uname -a; test -r /etc/os-release && sed -n '1,8p' /etc/os-release",
        "sw_vers; uname -m",
    ),
    _control(
        "hardware.compute",
        "hardware",
        "CPU and memory",
        "Processor and physical memory visibility.",
        "Get-CimInstance Win32_ComputerSystem | Select NumberOfLogicalProcessors,TotalPhysicalMemory | ConvertTo-Json -Compress",
        "getconf _NPROCESSORS_ONLN; grep -E 'MemTotal|MemAvailable' /proc/meminfo",
        "sysctl -n hw.logicalcpu hw.memsize",
    ),
    _control(
        "hardware.devices",
        "hardware",
        "Device health",
        "Attached device and driver health.",
        "Get-PnpDevice | Group-Object Status | Select Name,Count | ConvertTo-Json -Compress",
        "test -d /sys/class && find /sys/class -mindepth 1 -maxdepth 1 -type d | wc -l",
        "system_profiler SPHardwareDataType -detailLevel mini",
    ),
    _control(
        "storage.volumes",
        "storage",
        "Volumes and capacity",
        "Mounted volumes, capacity and free-space state.",
        "Get-Volume | Select DriveLetter,FileSystem,HealthStatus,SizeRemaining,Size | ConvertTo-Json -Compress",
        "df -P -T",
        "df -P",
    ),
    _control(
        "runtime.processes",
        "runtime",
        "Running processes",
        "Process inventory for conflict and crash diagnosis.",
        "Get-Process | Select ProcessName,Id | ConvertTo-Json -Compress",
        "ps -eo pid,comm,state --no-headers",
        "ps -axo pid,comm,state",
    ),
    _control(
        "runtime.services",
        "runtime",
        "System services",
        "Service availability and startup state.",
        "Get-Service | Select Name,Status,StartType | ConvertTo-Json -Compress",
        "command -v systemctl >/dev/null && systemctl list-units --type=service --all --no-pager || service --status-all",
        "launchctl list",
    ),
    _control(
        "runtime.startup",
        "runtime",
        "Startup items",
        "Programs configured to start automatically.",
        "Get-CimInstance Win32_StartupCommand | Select Name,Location | ConvertTo-Json -Compress",
        "find /etc/xdg/autostart ~/.config/autostart -maxdepth 1 -type f 2>/dev/null | sed 's#^.*/##'",
        "find /Library/LaunchAgents ~/Library/LaunchAgents -maxdepth 1 -type f 2>/dev/null | sed 's#^.*/##'",
    ),
    _control(
        "runtime.scheduled_tasks",
        "runtime",
        "Scheduled tasks",
        "Scheduled jobs that can affect agent execution.",
        "Get-ScheduledTask | Select TaskName,State,TaskPath | ConvertTo-Json -Compress",
        "(crontab -l 2>/dev/null || true); ls /etc/cron.d 2>/dev/null",
        "(crontab -l 2>/dev/null || true); launchctl list",
    ),
    _control(
        "environment.variables",
        "configuration",
        "Environment variables",
        "Variable names and configuration presence without exposing values.",
        "Get-ChildItem Env: | Select Name | ConvertTo-Json -Compress",
        "env | sed 's/=.*//' | sort",
        "env | sed 's/=.*//' | sort",
    ),
    _control(
        "environment.path",
        "configuration",
        "Executable search path",
        "PATH entries and executable resolution.",
        "$env:Path -split ';' | ForEach-Object { [pscustomobject]@{Path=$_;Exists=(Test-Path $_)} } | ConvertTo-Json -Compress",
        "printf '%s' \"$PATH\" | tr ':' '\n'",
        "printf '%s' \"$PATH\" | tr ':' '\n'",
    ),
    _control(
        "identity.permissions",
        "security",
        "Identity and permissions",
        "Current security groups and privilege context.",
        "whoami /groups",
        "id",
        "id",
    ),
    _control(
        "logs.system",
        "observability",
        "System log availability",
        "Log channels available for root-cause analysis without reading event contents.",
        "Get-WinEvent -ListLog * | Select LogName,IsEnabled,RecordCount | ConvertTo-Json -Compress",
        "journalctl --list-boots --no-pager 2>/dev/null || ls /var/log",
        "log show --last 1m --info --debug 2>/dev/null | head -n 20",
    ),
    _control(
        "network.adapters",
        "network",
        "Network adapters",
        "Interface link and address state.",
        "Get-NetAdapter | Select Name,Status,LinkSpeed | ConvertTo-Json -Compress",
        "ip -brief link 2>/dev/null || ifconfig -a",
        "ifconfig -a",
    ),
    _control(
        "network.dns",
        "network",
        "DNS configuration",
        "Resolver configuration and server reachability context.",
        "Get-DnsClientServerAddress | Select InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress",
        "cat /etc/resolv.conf",
        "scutil --dns",
    ),
    _control(
        "network.proxy",
        "network",
        "Proxy configuration",
        "System and environment proxy configuration.",
        "netsh winhttp show proxy; Get-ChildItem Env: | Where-Object Name -match 'proxy' | Select Name | ConvertTo-Json -Compress",
        "env | grep -iE '^(http|https|all|no)_proxy=' | sed 's/=.*$/=<REDACTED>/' || true",
        "scutil --proxy",
    ),
    _control(
        "network.listeners",
        "network",
        "Listening ports",
        "Local listeners and owning processes.",
        "Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress",
        "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null",
        "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || netstat -anv -p tcp",
    ),
    _control(
        "security.firewall",
        "security",
        "Firewall profiles",
        "Firewall enablement and active profiles.",
        "Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress",
        "(command -v ufw >/dev/null && ufw status) || (command -v firewall-cmd >/dev/null && firewall-cmd --state) || true",
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
    ),
    _control(
        "security.certificates",
        "security",
        "Trust stores",
        "Certificate trust-store availability and expiry metadata.",
        "Get-ChildItem Cert:\\LocalMachine\\Root | Select Subject,NotAfter | ConvertTo-Json -Compress",
        "find /etc/ssl/certs -maxdepth 1 -type l 2>/dev/null | wc -l",
        "security find-certificate -a -Z /System/Library/Keychains/SystemRootCertificates.keychain | grep -c SHA-256",
    ),
    _control(
        "security.protection",
        "security",
        "Security products",
        "Antivirus and endpoint protection state.",
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select displayName,productState | ConvertTo-Json -Compress",
        "(command -v systemctl >/dev/null && systemctl list-unit-files | grep -Ei 'clam|falcon|defender|sentinel' || true)",
        "systemextensionsctl list 2>/dev/null | head -n 80",
    ),
    _control(
        "security.policies",
        "security",
        "Execution policies",
        "Policies that can block scripts, tools or agent operations.",
        "Get-ExecutionPolicy -List | ConvertTo-Json -Compress",
        "(command -v getenforce >/dev/null && getenforce) || true; (command -v aa-status >/dev/null && aa-status --enabled) || true",
        "spctl --status",
    ),
    _control(
        "packages.managers",
        "tooling",
        "Package managers",
        "Availability of system and language package managers.",
        "Get-Command winget,choco,scoop,pip,npm -ErrorAction SilentlyContinue | Select Name,Source | ConvertTo-Json -Compress",
        "command -v apt dnf yum pacman zypper apk snap flatpak pip npm 2>/dev/null || true",
        "command -v brew port pip npm 2>/dev/null || true",
    ),
    _control(
        "tooling.runtimes",
        "tooling",
        "Language runtimes",
        "Installed development runtimes used by hooks and MCP servers.",
        "Get-Command python,node,dotnet,java,go,rustc -ErrorAction SilentlyContinue | Select Name,Source | ConvertTo-Json -Compress",
        "command -v python3 node dotnet java go rustc 2>/dev/null || true",
        "command -v python3 node dotnet java go rustc 2>/dev/null || true",
    ),
    _control(
        "tooling.shells",
        "tooling",
        "Shells",
        "Available command interpreters and host shells.",
        "Get-Command powershell,pwsh,cmd,wsl -ErrorAction SilentlyContinue | Select Name,Source | ConvertTo-Json -Compress",
        "cat /etc/shells 2>/dev/null",
        "cat /etc/shells",
    ),
    _control(
        "tooling.git",
        "tooling",
        "Version control",
        "Git availability and effective configuration origins.",
        "git --version; git config --list --show-origin",
        "git --version; git config --list --show-origin",
        "git --version; git config --list --show-origin",
    ),
    _control(
        "agents.mcp",
        "agents",
        "MCP clients",
        "Presence of common MCP-capable client configuration roots.",
        '$p=@("$env:USERPROFILE\\.codex","$env:APPDATA\\Claude","$env:USERPROFILE\\.cursor"); $p | ForEach-Object {[pscustomobject]@{Kind=(Split-Path $_ -Leaf);Exists=(Test-Path $_)}} | ConvertTo-Json -Compress',
        'for p in "$HOME/.codex" "$HOME/.config/Claude" "$HOME/.cursor"; do test -e "$p" && printf \'%s:present\n\' "${p##*/}" || true; done',
        'for p in "$HOME/.codex" "$HOME/Library/Application Support/Claude" "$HOME/.cursor"; do test -e "$p" && printf \'%s:present\n\' "${p##*/}" || true; done',
    ),
    _control(
        "agents.hooks",
        "agents",
        "Agent hooks",
        "Hook roots and registration surfaces.",
        '$p=@("$env:USERPROFILE\\.codex\\hooks","$env:USERPROFILE\\.config\\hooks"); $p | ForEach-Object {[pscustomobject]@{Exists=(Test-Path $_)}} | ConvertTo-Json -Compress',
        'find "$HOME/.codex" "$HOME/.config" -maxdepth 2 -type d -name hooks 2>/dev/null | sed \'s#^.*/#<PATH>/#\'',
        'find "$HOME/.codex" "$HOME/.config" -maxdepth 2 -type d -name hooks 2>/dev/null | sed \'s#^.*/#<PATH>/#\'',
    ),
    _control(
        "agents.plugins",
        "agents",
        "Agent plugins",
        "Plugin installation and cache roots.",
        '$p=@("$env:USERPROFILE\\.codex\\plugins","$env:USERPROFILE\\.cursor\\extensions"); $p | ForEach-Object {[pscustomobject]@{Exists=(Test-Path $_)}} | ConvertTo-Json -Compress',
        "find \"$HOME/.codex\" \"$HOME/.cursor\" -maxdepth 2 -type d -name 'plugin*' 2>/dev/null | sed 's#^.*/#<PATH>/#'",
        "find \"$HOME/.codex\" \"$HOME/.cursor\" -maxdepth 2 -type d -name 'plugin*' 2>/dev/null | sed 's#^.*/#<PATH>/#'",
    ),
    _control(
        "agents.skills",
        "agents",
        "Agent skills",
        "Skill discovery roots and manifests.",
        '$p=@("$env:USERPROFILE\\.agents\\skills","$env:USERPROFILE\\.codex\\skills"); $p | ForEach-Object {[pscustomobject]@{Exists=(Test-Path $_)}} | ConvertTo-Json -Compress',
        'find "$HOME/.agents" "$HOME/.codex" -maxdepth 3 -name SKILL.md 2>/dev/null | sed \'s#^.*/#<PATH>/#\'',
        'find "$HOME/.agents" "$HOME/.codex" -maxdepth 3 -name SKILL.md 2>/dev/null | sed \'s#^.*/#<PATH>/#\'',
    ),
    _control(
        "agents.codex_runtime",
        "agents",
        "Codex runtime",
        "Local Codex process presence and executable metadata without command-line contents.",
        "Get-Process Codex -ErrorAction SilentlyContinue | Select ProcessName,Id,StartTime | ConvertTo-Json -Compress",
        "pgrep -c -i codex 2>/dev/null || true",
        "pgrep -c -i codex 2>/dev/null || true",
    ),
    _control(
        "agents.remote_control",
        "agents",
        "Remote-control prerequisites",
        "Local Codex process and established-connection counts; this does not assert remote service health.",
        "$p=@(Get-Process Codex -ErrorAction SilentlyContinue); $ids=$p.Id; $n=if($ids){@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object OwningProcess -in $ids).Count}else{0}; [pscustomobject]@{ProcessCount=$p.Count;EstablishedConnections=$n} | ConvertTo-Json -Compress",
        "p=$(pgrep -i codex 2>/dev/null | head -n 1); if test -n \"$p\"; then printf 'process=present connections='; ss -tnp 2>/dev/null | grep -c \"pid=$p,\" || true; else printf 'process=absent connections=0'; fi",
        "p=$(pgrep -i codex 2>/dev/null | head -n 1); if test -n \"$p\"; then printf 'process=present connections='; lsof -nP -a -p \"$p\" -iTCP -sTCP:ESTABLISHED 2>/dev/null | tail -n +2 | wc -l; else printf 'process=absent connections=0'; fi",
    ),
    _control(
        "agents.chat_stream",
        "agents",
        "Chat-stream diagnostics",
        "Presence and file counts of local Codex diagnostic roots without reading file contents.",
        '$r=@("$env:LOCALAPPDATA\\Codex","$env:APPDATA\\Codex","$env:USERPROFILE\\.codex"); $r | ForEach-Object {[pscustomobject]@{Kind=(Split-Path $_ -Leaf);Exists=(Test-Path $_);FileCount=if(Test-Path $_){@(Get-ChildItem $_ -File -Recurse -ErrorAction SilentlyContinue).Count}else{0}}} | ConvertTo-Json -Compress',
        'for p in "$HOME/.codex" "$HOME/.config/Codex"; do if test -d "$p"; then printf \'%s files=\' "${p##*/}"; find "$p" -type f 2>/dev/null | wc -l; fi; done',
        'for p in "$HOME/.codex" "$HOME/Library/Application Support/Codex"; do if test -d "$p"; then printf \'%s files=\' "${p##*/}"; find "$p" -type f 2>/dev/null | wc -l; fi; done',
        20,
    ),
    _control(
        "agents.hook_health",
        "agents",
        "Hook source health",
        "Counts hook and plugin manifests across conventional configuration layers without reading contents.",
        '$r=@("$env:USERPROFILE\\.codex\\hooks","$env:USERPROFILE\\.codex\\plugins","$env:USERPROFILE\\.agents\\skills"); $r | ForEach-Object {[pscustomobject]@{Kind=(Split-Path $_ -Leaf);Exists=(Test-Path $_);Items=if(Test-Path $_){@(Get-ChildItem $_ -Force -ErrorAction SilentlyContinue).Count}else{0}}} | ConvertTo-Json -Compress',
        'for p in "$HOME/.codex/hooks" "$HOME/.codex/plugins" "$HOME/.agents/skills"; do if test -d "$p"; then printf \'%s items=\' "${p##*/}"; find "$p" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; fi; done',
        'for p in "$HOME/.codex/hooks" "$HOME/.codex/plugins" "$HOME/.agents/skills"; do if test -d "$p"; then printf \'%s items=\' "${p##*/}"; find "$p" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; fi; done',
    ),
    _control(
        "agents.configuration_layers",
        "agents",
        "Agent configuration layers",
        "Presence of user, project and plugin configuration roots without reading values.",
        '$r=@("$env:USERPROFILE\\.codex","$env:USERPROFILE\\.agents","$env:APPDATA\\Codex"); $r | ForEach-Object {[pscustomobject]@{Kind=(Split-Path $_ -Leaf);Exists=(Test-Path $_)}} | ConvertTo-Json -Compress',
        'for p in "$HOME/.codex" "$HOME/.agents" "$HOME/.config/Codex"; do test -d "$p" && printf \'%s:present\n\' "${p##*/}" || true; done',
        'for p in "$HOME/.codex" "$HOME/.agents" "$HOME/Library/Application Support/Codex"; do test -d "$p" && printf \'%s:present\n\' "${p##*/}" || true; done',
    ),
    _control(
        "tooling.editors",
        "tooling",
        "Editors and IDEs",
        "Availability of common editor command-line integrations.",
        "Get-Command code,cursor,devenv,idea -ErrorAction SilentlyContinue | Select Name,Source | ConvertTo-Json -Compress",
        "command -v code cursor idea 2>/dev/null || true",
        "command -v code cursor idea 2>/dev/null || true",
    ),
    _control(
        "virtualization.containers",
        "virtualization",
        "Containers",
        "Container engine and orchestration client availability.",
        "Get-Command docker,podman,kubectl -ErrorAction SilentlyContinue | Select Name,Source | ConvertTo-Json -Compress",
        "command -v docker podman kubectl 2>/dev/null || true",
        "command -v docker podman kubectl 2>/dev/null || true",
    ),
    _control(
        "virtualization.guests",
        "virtualization",
        "Virtualization and guests",
        "Guest environments such as WSL, Hyper-V or local VMs.",
        "Get-Command wsl,vmrun,VBoxManage -ErrorAction SilentlyContinue | Select Name,Source | ConvertTo-Json -Compress",
        "command -v virsh vboxmanage wsl 2>/dev/null || true",
        "command -v multipass VBoxManage vmrun 2>/dev/null || true",
    ),
    _control(
        "maintenance.updates",
        "maintenance",
        "System updates",
        "Update service and recent patch visibility.",
        "Get-Service wuauserv | Select Name,Status,StartType | ConvertTo-Json -Compress; Get-HotFix | Sort InstalledOn -Descending | Select -First 5 HotFixID,InstalledOn | ConvertTo-Json -Compress",
        "(command -v apt >/dev/null && apt list --upgradable 2>/dev/null | head -n 30) || true",
        "softwareupdate --list 2>&1 | head -n 30",
        30,
    ),
    _control(
        "system.time_locale",
        "system",
        "Time and locale",
        "Clock, timezone and locale context.",
        "Get-TimeZone | Select Id,DisplayName | ConvertTo-Json -Compress; Get-Culture | Select Name | ConvertTo-Json -Compress",
        "date --iso-8601=seconds; timedatectl 2>/dev/null | head -n 8; locale | head -n 8",
        "date -Iseconds; systemsetup -gettimezone 2>/dev/null; locale | head -n 8",
    ),
)

CONTROL_BY_ID = {control.id: control for control in CONTROL_CATALOG}


def coverage_report(platform_name: str) -> dict[str, Any]:
    platform_key = platform_name.lower()
    total = len(CONTROL_CATALOG)
    covered = sum(platform_key in control.probes for control in CONTROL_CATALOG)
    categories: dict[str, dict[str, int]] = {}
    for control in CONTROL_CATALOG:
        item = categories.setdefault(control.category, {"total": 0, "covered": 0})
        item["total"] += 1
        item["covered"] += int(platform_key in control.probes)
    return {
        "platform": platform_key,
        "catalog_version": "1.0",
        "total_controls": total,
        "covered_controls": covered,
        "design_coverage_percent": round(covered * 100 / total, 2) if total else 0.0,
        "categories": categories,
        "definition": "Percentage of declared controls with a read-only probe for this platform; not proof that a specific machine was observed.",
    }
