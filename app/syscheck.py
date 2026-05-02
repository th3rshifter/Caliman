#!/usr/bin/env python3

import datetime
import grp
import ipaddress
import json
import os
import platform
import pwd
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import psutil
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_COLORS = {
    "CRIT": "bold red",
    "WARN": "yellow",
    "INFO": "cyan",
    "OK": "green",
}

SEVERITY_ICONS = {
    "CRIT": "✗",
    "WARN": "⚠",
    "INFO": "·",
    "OK": "✓",
}

findings: list[tuple[str, str, str]] = []


def add_finding(severity: str, category: str, message: str) -> None:
    findings.append((severity, category, message))


# helpers

def run_shell(cmd: str, default: str = "n/a") -> str:
    """
    Используется только для статических команд.
    Для команд с пользовательскими или внешними значениями используй run_args().
    """
    try:
        return subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return default


def run_args(cmd: list[str], default: str = "n/a") -> str:
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return default


def run_ok(cmd: list[str]) -> bool:
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def bytes_fmt(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def pct_bar(pct: float, width: int = 20) -> Text:
    pct = max(0.0, min(100.0, float(pct)))
    filled = int(pct / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    color = "green" if pct < 60 else "yellow" if pct < 85 else "red"

    t = Text()
    t.append(f"[{bar}] ", style=color)
    t.append(f"{pct:5.1f}%", style=f"bold {color}")
    return t


def section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold white] {title} [/bold white]", style="bright_black"))


def file_mode(path: Path) -> str:
    try:
        return oct(path.stat().st_mode & 0o777)
    except Exception:
        return "n/a"


def get_os_pretty_name() -> str:
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return platform.platform()

    try:
        for line in os_release.read_text(errors="ignore").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass

    return platform.platform()


def get_package_updates_count() -> int:
    if shutil.which("apt"):
        return safe_int(
            run_shell("apt list --upgradable 2>/dev/null | grep -c upgradable", "0")
        )

    if shutil.which("dnf"):
        output = run_shell("dnf check-update --quiet 2>/dev/null | grep -E '^[a-zA-Z0-9_.+-]+' | wc -l", "0")
        return safe_int(output)

    if shutil.which("yum"):
        output = run_shell("yum check-update --quiet 2>/dev/null | grep -E '^[a-zA-Z0-9_.+-]+' | wc -l", "0")
        return safe_int(output)

    if shutil.which("zypper"):
        output = run_shell("zypper list-updates 2>/dev/null | grep -c '^v |'", "0")
        return safe_int(output)

    return 0


def get_sshd_value(key: str, fallback: str = "unknown") -> str:
    """
    sshd -T показывает итоговую effective-конфигурацию с учетом sshd_config.d/*.conf.
    """
    if shutil.which("sshd"):
        value = run_shell(f"sshd -T 2>/dev/null | awk '/^{key.lower()} / {{print $2; exit}}'", "")
        if value:
            return value

    value = run_shell(
        f"grep -Rih '^\\s*{key}\\s' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf "
        f"2>/dev/null | tail -1 | awk '{{print $2}}'",
        "",
    )

    return value or fallback


# 1. identity

def show_identity() -> None:
    section("IDENTITY")

    uid = os.getuid()
    gid = os.getgid()
    user = pwd.getpwuid(uid)

    groups = []
    for g in os.getgroups():
        try:
            groups.append(grp.getgrgid(g).gr_name)
        except KeyError:
            groups.append(str(g))

    is_root = uid == 0
    has_sudo = bool(shutil.which("sudo")) and run_ok(["sudo", "-n", "true"])
    in_docker = Path("/.dockerenv").exists()
    in_sudo_group = "sudo" in groups or "wheel" in groups

    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="bright_black", width=22)
    t.add_column()

    t.add_row("Username", f"[bold]{user.pw_name}[/bold]")
    t.add_row("UID / GID", f"{uid} / {gid}")
    t.add_row("Home", user.pw_dir)
    t.add_row("Shell", user.pw_shell)
    t.add_row("Groups", ", ".join(groups[:10]) + ("…" if len(groups) > 10 else ""))
    t.add_row("Root", "[bold red]YES[/bold red]" if is_root else "[green]no[/green]")
    t.add_row("Passwordless sudo", "[bold red]YES[/bold red]" if has_sudo else "[green]no[/green]")
    t.add_row("Inside Docker", "[yellow]yes[/yellow]" if in_docker else "no")

    console.print(t)

    if is_root:
        add_finding("CRIT", "Identity", "Процесс запущен от root - нарушение принципа least privilege")
    if has_sudo:
        add_finding("WARN", "Identity", "Текущий пользователь может выполнять sudo без пароля")
    if in_sudo_group and not is_root:
        add_finding("WARN", "Identity", f"Пользователь в группе sudo/wheel: {user.pw_name}")
    if user.pw_shell in ("/bin/bash", "/bin/sh") and uid == 0:
        add_finding("WARN", "Identity", "root использует интерактивный shell - рассмотрите /usr/sbin/nologin")


# 2. os & kernel

def show_os() -> None:
    section("OS / KERNEL")

    uname = platform.uname()
    uptime_s = time.time() - psutil.boot_time()
    uptime = str(datetime.timedelta(seconds=int(uptime_s)))
    distro = get_os_pretty_name()
    kernel = uname.release

    virt = run_args(["systemd-detect-virt"], "bare-metal") if shutil.which("systemd-detect-virt") else "unknown"

    selinux = run_args(["getenforce"], "disabled") if shutil.which("getenforce") else "disabled"
    apparmor = "enabled" if shutil.which("aa-status") and run_ok(["aa-status", "--enabled"]) else "disabled"

    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="bright_black", width=22)
    t.add_column()

    t.add_row("OS", distro)
    t.add_row("Kernel", kernel)
    t.add_row("Arch", uname.machine)
    t.add_row("Hostname", uname.node)
    t.add_row("Uptime", uptime)
    t.add_row("Virtualisation", virt)
    t.add_row("SELinux", selinux)
    t.add_row("AppArmor", apparmor)

    console.print(t)

    n_updates = get_package_updates_count()

    if n_updates > 0:
        severity = "CRIT" if n_updates > 20 else "WARN"
        add_finding(severity, "OS", f"Доступно обновлений пакетов: {n_updates}")
    else:
        add_finding("OK", "OS", "Обновления пакетов не обнаружены или пакетный менеджер не поддержан")

    if selinux.lower() in ("disabled", "permissive") and apparmor == "disabled":
        add_finding("WARN", "OS", "Ни SELinux enforcing, ни AppArmor не активны - нет полноценной MAC-защиты")

    try:
        major = int(kernel.split(".")[0])
        minor = int(kernel.split(".")[1])
        if major < 5 or (major == 5 and minor < 15):
            add_finding("WARN", "OS", f"Ядро {kernel} - рассмотрите обновление до актуального LTS")
    except Exception:
        add_finding("INFO", "OS", f"Не удалось разобрать версию ядра: {kernel}")


# 3. hardware

def show_hardware() -> None:
    section("HARDWARE / RESOURCES")

    cpu_count = psutil.cpu_count(logical=True) or 1
    cpu_phys = psutil.cpu_count(logical=False) or cpu_count
    cpu_freq = psutil.cpu_freq()
    cpu_pct = psutil.cpu_percent(interval=1)

    try:
        load1, load5, load15 = psutil.getloadavg()
    except Exception:
        load1, load5, load15 = 0.0, 0.0, 0.0

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="bright_black", width=22)
    t.add_column()

    freq_str = f"{cpu_freq.current:.0f} MHz (max {cpu_freq.max:.0f})" if cpu_freq else "n/a"
    cpu_model = run_shell("lscpu | grep 'Model name' | cut -d: -f2 | xargs", "n/a")

    t.add_row("CPU", cpu_model)
    t.add_row("Cores", f"{cpu_phys} physical / {cpu_count} logical")
    t.add_row("Frequency", freq_str)
    t.add_row("CPU usage", pct_bar(cpu_pct))
    t.add_row("Load avg", f"{load1:.2f}  {load5:.2f}  {load15:.2f}  (1/5/15 min)")
    t.add_row("RAM total", bytes_fmt(mem.total))
    t.add_row("RAM used", pct_bar(mem.percent))
    t.add_row("RAM available", bytes_fmt(mem.available))
    t.add_row("Swap total", bytes_fmt(swap.total))
    t.add_row("Swap used", pct_bar(swap.percent) if swap.total else Text("none", style="green"))

    console.print(t)

    console.print()
    dt = Table(title="Disks", box=box.SIMPLE_HEAD, show_edge=False)
    dt.add_column("Mount", style="bold")
    dt.add_column("FS")
    dt.add_column("Total", justify="right")
    dt.add_column("Used", justify="right")
    dt.add_column("Free", justify="right")
    dt.add_column("Usage")

    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue
        except Exception:
            continue

        dt.add_row(
            part.mountpoint,
            part.fstype,
            bytes_fmt(usage.total),
            bytes_fmt(usage.used),
            bytes_fmt(usage.free),
            pct_bar(usage.percent, 16),
        )

        if usage.percent > 90:
            add_finding("CRIT", "Disk", f"{part.mountpoint} заполнен на {usage.percent:.1f}%")
        elif usage.percent > 75:
            add_finding("WARN", "Disk", f"{part.mountpoint} заполнен на {usage.percent:.1f}%")

    console.print(dt)

    if mem.percent > 85:
        add_finding("CRIT", "Memory", f"RAM использована на {mem.percent:.1f}%")
    elif mem.percent > 70:
        add_finding("WARN", "Memory", f"RAM использована на {mem.percent:.1f}%")

    if swap.total and swap.percent > 50:
        add_finding("WARN", "Memory", f"Активное использование swap ({swap.percent:.1f}%) - возможен memory pressure")

    if load1 > cpu_count * 0.8:
        add_finding("WARN", "CPU", f"Load average ({load1:.2f}) близок к числу logical CPU ({cpu_count})")


# 4. network

def show_network() -> None:
    section("NETWORK")

    hostname = socket.getfqdn()
    ext_ip = run_args(["curl", "-s", "--max-time", "3", "https://api.ipify.org"], "unavailable") if shutil.which("curl") else "curl not installed"

    it = Table(title="Interfaces", box=box.SIMPLE_HEAD, show_edge=False)
    it.add_column("Interface", style="bold")
    it.add_column("Address")
    it.add_column("Netmask")
    it.add_column("Flags")

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family != socket.AF_INET:
                continue

            flags = []
            if iface in stats:
                s = stats[iface]
                if s.isup:
                    flags.append("[green]UP[/green]")
                if getattr(s.duplex, "name", "UNKNOWN") != "UNKNOWN":
                    flags.append(s.duplex.name)

            it.add_row(iface, addr.address, addr.netmask or "", " ".join(flags))

            try:
                ip = ipaddress.ip_address(addr.address)
                if not ip.is_loopback and not ip.is_private:
                    add_finding("WARN", "Network", f"Публичный IP на интерфейсе {iface}: {addr.address}")
            except ValueError:
                pass

    console.print(it)
    console.print(f"  [bright_black]Hostname:[/bright_black] {hostname}")
    console.print(f"  [bright_black]External IP:[/bright_black] {ext_ip}")

    console.print()
    pt = Table(title="Listening ports", box=box.SIMPLE_HEAD, show_edge=False)
    pt.add_column("Proto")
    pt.add_column("Address")
    pt.add_column("Port", justify="right")
    pt.add_column("PID")
    pt.add_column("Process")

    try:
        listening = [c for c in psutil.net_connections(kind="inet") if c.status == psutil.CONN_LISTEN]
    except Exception:
        listening = []

    listening.sort(key=lambda c: c.laddr.port if c.laddr else 0)

    exposed_ports = []

    for conn in listening:
        if not conn.laddr:
            continue

        try:
            proc = psutil.Process(conn.pid)
            pname = proc.name()
        except Exception:
            pname = "?"

        addr = conn.laddr.ip
        port = conn.laddr.port
        proto = "TCP"

        addr_style = "red bold" if addr in ("0.0.0.0", "::") else "default"
        pt.add_row(proto, Text(addr, style=addr_style), str(port), str(conn.pid or "?"), pname)

        if addr in ("0.0.0.0", "::"):
            exposed_ports.append(port)

    console.print(pt)

    if exposed_ports:
        ports = ", ".join(map(str, sorted(set(exposed_ports))))
        add_finding("WARN", "Network", f"Порты слушают на 0.0.0.0/:: : {ports} - проверьте необходимость внешнего доступа")


# 5. security

def show_security() -> None:
    section("SECURITY")

    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="bright_black", width=26)
    t.add_column()

    ssh_root = get_sshd_value("PermitRootLogin", "unknown")
    ssh_pw = get_sshd_value("PasswordAuthentication", "unknown")
    ssh_port = get_sshd_value("Port", "22")

    t.add_row(
        "SSH PermitRootLogin",
        "[red]yes[/red]" if ssh_root.lower() == "yes" else f"[green]{ssh_root}[/green]",
    )
    t.add_row(
        "SSH PasswordAuth",
        "[red]yes[/red]" if ssh_pw.lower() == "yes" else f"[green]{ssh_pw}[/green]",
    )
    t.add_row(
        "SSH Port",
        f"[yellow]{ssh_port}[/yellow]" if ssh_port == "22" else f"[green]{ssh_port}[/green]",
    )

    ufw_status = run_shell("ufw status 2>/dev/null | head -1", "Status: inactive")
    ufw_active = ufw_status.strip().lower() == "status: active"

    iptables_raw = run_shell("iptables -L INPUT --line-numbers 2>/dev/null | wc -l", "0")
    iptables_count = safe_int(iptables_raw, 0)

    t.add_row("UFW", f"[green]{ufw_status}[/green]" if ufw_active else f"[red]{ufw_status}[/red]")
    t.add_row("iptables rules (INPUT)", str(iptables_count))

    failed = run_shell("lastb 2>/dev/null | wc -l", "0")
    t.add_row("Failed logins (total)", failed)

    suid_count_raw = run_shell("find / -perm -4000 -type f 2>/dev/null | wc -l", "n/a")
    suid_count = safe_int(suid_count_raw, -1)
    t.add_row(
        "SUID binaries",
        f"[yellow]{suid_count_raw}[/yellow]" if suid_count > 10 else suid_count_raw,
    )

    ww = run_shell("find /tmp /var /etc -maxdepth 2 -perm -o+w -type d 2>/dev/null | wc -l", "0")
    t.add_row("World-writable dirs", ww)

    tmp_opts = run_shell("findmnt -no OPTIONS /tmp 2>/dev/null", "")
    tmp_noexec = "noexec" in tmp_opts.split(",")
    t.add_row("/tmp noexec", "[green]yes[/green]" if tmp_noexec else "[yellow]no[/yellow]")

    passwd_mode = file_mode(Path("/etc/passwd"))
    shadow_mode = file_mode(Path("/etc/shadow"))

    t.add_row("/etc/passwd mode", passwd_mode)
    t.add_row("/etc/shadow mode", shadow_mode)

    console.print(t)

    if ssh_root.lower() == "yes":
        add_finding("CRIT", "SSH", "PermitRootLogin yes - отключите немедленно")
    if ssh_pw.lower() == "yes":
        add_finding("WARN", "SSH", "PasswordAuthentication yes - используйте SSH-ключи")
    if ssh_port == "22":
        add_finding("INFO", "SSH", "SSH на стандартном порту 22 - допустимо, но требует защиты fail2ban/firewall")

    if not ufw_active and iptables_count < 5:
        add_finding("WARN", "Firewall", "Файрвол не настроен или неактивен")

    if not tmp_noexec:
        add_finding("INFO", "Security", "/tmp смонтирован без noexec")

    if suid_count > 15:
        add_finding("WARN", "Security", f"Много SUID-бинарников: {suid_count} - проверьте список")

    if passwd_mode != "0o644":
        add_finding("WARN", "Security", f"/etc/passwd имеет нестандартные права: {passwd_mode}")

    if shadow_mode not in ("0o600", "0o640"):
        add_finding("CRIT", "Security", f"/etc/shadow имеет небезопасные права: {shadow_mode}")


# 6. processes

def show_processes() -> None:
    section("TOP PROCESSES")

    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
        except Exception:
            pass

    time.sleep(0.5)

    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "memory_percent", "status"]):
        try:
            info = p.info
            info["cpu_percent"] = p.cpu_percent(None)
            procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    top_cpu = sorted(procs, key=lambda x: x.get("cpu_percent") or 0, reverse=True)[:8]
    top_mem = sorted(procs, key=lambda x: x.get("memory_percent") or 0, reverse=True)[:8]

    cpu_t = Table(title="By CPU", box=box.SIMPLE_HEAD, show_edge=False)
    cpu_t.add_column("PID", justify="right")
    cpu_t.add_column("Process", style="bold")
    cpu_t.add_column("User")
    cpu_t.add_column("CPU%", justify="right")

    for p in top_cpu:
        cpu_t.add_row(
            str(p.get("pid", "?")),
            str(p.get("name") or "?"),
            str(p.get("username") or "?"),
            f"{float(p.get('cpu_percent') or 0):.1f}",
        )

    mem_t = Table(title="By Memory", box=box.SIMPLE_HEAD, show_edge=False)
    mem_t.add_column("PID", justify="right")
    mem_t.add_column("Process", style="bold")
    mem_t.add_column("User")
    mem_t.add_column("MEM%", justify="right")

    for p in top_mem:
        mem_t.add_row(
            str(p.get("pid", "?")),
            str(p.get("name") or "?"),
            str(p.get("username") or "?"),
            f"{float(p.get('memory_percent') or 0):.1f}",
        )

    console.print(Columns([cpu_t, mem_t]))

    zombies = [p for p in procs if p.get("status") == psutil.STATUS_ZOMBIE]
    if zombies:
        add_finding("WARN", "Processes", f"Zombie-процессы: {len(zombies)} - проверьте родительские процессы")


# 7. docker

def docker_json(args: list[str], default=None):
    output = run_args(args, "")
    if not output:
        return default
    try:
        return json.loads(output)
    except Exception:
        return default


def show_docker() -> None:
    if not shutil.which("docker"):
        return

    section("DOCKER")

    version = run_args(["docker", "version", "--format", "{{.Server.Version}}"], "n/a")
    total = run_shell("docker ps -aq 2>/dev/null | wc -l", "0")
    running = run_shell("docker ps -q 2>/dev/null | wc -l", "0")
    images = run_shell("docker images -q 2>/dev/null | wc -l", "0")
    volumes = run_shell("docker volume ls -q 2>/dev/null | wc -l", "0")
    dangling = run_shell("docker images -f dangling=true -q 2>/dev/null | wc -l", "0")

    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="bright_black", width=22)
    t.add_column()

    t.add_row("Version", version)
    t.add_row("Containers total", total)
    t.add_row("Running", f"[green]{running}[/green]")
    t.add_row("Images", images)
    t.add_row("Volumes", volumes)
    t.add_row("Dangling images", f"[yellow]{dangling}[/yellow]" if dangling != "0" else "[green]0[/green]")

    console.print(t)

    ct = Table(title="Container audit", box=box.SIMPLE_HEAD, show_edge=False)
    ct.add_column("Name", style="bold")
    ct.add_column("Image")
    ct.add_column("Root?")
    ct.add_column("Privileged?")
    ct.add_column("Read-only?")
    ct.add_column("Health")

    containers_raw = run_args(["docker", "ps", "--format", "{{.Names}}"], "")

    for name in containers_raw.splitlines():
        name = name.strip()
        if not name:
            continue

        data = docker_json(["docker", "inspect", name], default=[])
        if not data:
            continue

        item = data[0]
        config = item.get("Config", {})
        host_config = item.get("HostConfig", {})
        state = item.get("State", {})

        image = config.get("Image", "n/a")
        user = config.get("User", "")
        privileged = bool(host_config.get("Privileged", False))
        readonly = bool(host_config.get("ReadonlyRootfs", False))

        health_obj = state.get("Health")
        health = health_obj.get("Status") if isinstance(health_obj, dict) else "none"

        is_root = user in ("", "0", "root")
        is_priv = privileged
        is_readonly = readonly

        if health == "healthy":
            health_cell = f"[green]{health}[/green]"
        elif health == "unhealthy":
            health_cell = f"[red]{health}[/red]"
        else:
            health_cell = f"[bright_black]{health}[/bright_black]"

        ct.add_row(
            name,
            image[:40],
            "[red]YES[/red]" if is_root else "[green]no[/green]",
            "[red]YES[/red]" if is_priv else "[green]no[/green]",
            "[green]yes[/green]" if is_readonly else "[yellow]no[/yellow]",
            health_cell,
        )

        if is_root:
            add_finding("WARN", "Docker", f"Контейнер {name} запущен от root")
        if is_priv:
            add_finding("CRIT", "Docker", f"Контейнер {name} запущен в privileged-режиме")
        if not is_readonly:
            add_finding("INFO", "Docker", f"Контейнер {name}: read-only rootfs не включен")
        if health == "unhealthy":
            add_finding("WARN", "Docker", f"Контейнер {name} unhealthy")
        elif health == "none":
            add_finding("INFO", "Docker", f"Контейнер {name}: healthcheck не настроен")

    console.print(ct)

    if safe_int(dangling, 0) > 0:
        add_finding("INFO", "Docker", f"{dangling} dangling-образов - запустите: docker image prune")


# 8. software versions

def show_software() -> None:
    section("INSTALLED TOOLS")

    tools = [
        ("python3", ["python3", "--version"]),
        ("pip", ["python3", "-m", "pip", "--version"]),
        ("docker", ["docker", "--version"]),
        ("kubectl", ["kubectl", "version", "--client", "--short"]),
        ("helm", ["helm", "version", "--short"]),
        ("terraform", ["terraform", "version"]),
        ("ansible", ["ansible", "--version"]),
        ("git", ["git", "--version"]),
        ("curl", ["curl", "--version"]),
        ("jq", ["jq", "--version"]),
        ("make", ["make", "--version"]),
        ("gcc", ["gcc", "--version"]),
    ]

    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="bright_black", width=14)
    t.add_column()

    for name, cmd in tools:
        if shutil.which(cmd[0]):
            output = run_args(cmd, "n/a").splitlines()
            ver = output[0] if output else "n/a"
            t.add_row(name, ver)
        else:
            t.add_row(name, "[bright_black]not installed[/bright_black]")

    console.print(t)


# 9. environment

def show_environment() -> None:
    section("ENVIRONMENT")

    sensitive_patterns = re.compile(
        r"(password|passwd|secret|token|api.?key|private.?key|auth|credential|access.?key)",
        re.IGNORECASE,
    )

    t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    t.add_column(style="bright_black", width=28)
    t.add_column()

    found_sensitive = []
    safe_keys = [
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "LANG",
        "TERM",
        "PWD",
        "LOGNAME",
        "HOSTNAME",
        "DISPLAY",
    ]

    for key in safe_keys:
        val = os.environ.get(key, "")
        if val:
            t.add_row(key, val[:120])

    for key in os.environ:
        if sensitive_patterns.search(key):
            found_sensitive.append(key)

    console.print(t)

    if found_sensitive:
        console.print("\n  [red]⚠  Потенциально чувствительные переменные окружения:[/red]")
        for k in sorted(found_sensitive):
            console.print(f"     [yellow]{k}[/yellow] = [bright_black]***[/bright_black]")

        add_finding(
            "WARN",
            "Environment",
            f"Найдены sensitive env vars: {', '.join(sorted(found_sensitive))} - используйте secrets manager",
        )


# 10. findings

def show_findings() -> None:
    console.print()
    console.print(Rule("[bold white] FINDINGS & RECOMMENDATIONS [/bold white]", style="bright_black"))
    console.print()

    if not findings:
        console.print("  [green]Проблем не обнаружено.[/green]")
        return

    order = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}
    sorted_findings = sorted(findings, key=lambda x: order.get(x[0], 99))

    counts = {s: 0 for s in ["CRIT", "WARN", "INFO", "OK"]}
    for sev, _, _ in sorted_findings:
        counts[sev] = counts.get(sev, 0) + 1

    badges = Text()
    for sev in ["CRIT", "WARN", "INFO", "OK"]:
        count = counts.get(sev, 0)
        if count:
            badges.append(f"  {SEVERITY_ICONS[sev]} {sev}: {count}  ", style=SEVERITY_COLORS[sev])

    console.print(badges)
    console.print()

    ft = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    ft.add_column("", width=4)
    ft.add_column("Severity", width=6)
    ft.add_column("Category", width=14, style="bright_black")
    ft.add_column("Finding")

    for sev, cat, msg in sorted_findings:
        color = SEVERITY_COLORS.get(sev, "white")
        ft.add_row(
            Text(SEVERITY_ICONS.get(sev, "?"), style=color),
            Text(sev, style=color),
            cat,
            msg,
        )

    console.print(ft)

    score = 100 - counts["CRIT"] * 20 - counts["WARN"] * 5 - counts["INFO"] * 1
    score = max(0, min(100, score))
    color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print()
    console.print(f"  Security score: [bold {color}]{score}/100[/bold {color}]")


# main

def main() -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    console.print()
    console.print(
        Panel(
            f"[bold white]System Audit Report[/bold white]\n"
            f"[bright_black]{now}  ·  {platform.node()}[/bright_black]",
            box=box.DOUBLE,
            expand=False,
            padding=(0, 4),
        )
    )

    show_identity()
    show_os()
    show_hardware()
    show_network()
    show_security()
    show_processes()
    show_docker()
    show_software()
    show_environment()
    show_findings()

    console.print()


if __name__ == "__main__":
    main()