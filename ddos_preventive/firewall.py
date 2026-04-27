import ipaddress
import subprocess


def block_ip(ip, backend="print"):
    address = ipaddress.ip_address(ip)

    if backend == "print":
        print(f"DRY-RUN block {address}")
        return

    if backend == "firewalld":
        family = "ipv6" if address.version == 6 else "ipv4"
        rule = f"rule family='{family}' source address='{address}' drop"
        subprocess.run(
            ["firewall-cmd", "--permanent", f"--add-rich-rule={rule}"], check=True
        )
        subprocess.run(["firewall-cmd", "--reload"], check=True)
        return

    if backend == "iptables":
        binary = "ip6tables" if address.version == 6 else "iptables"
        subprocess.run([binary, "-I", "INPUT", "-s", str(address), "-j", "DROP"], check=True)
        return

    if backend == "nft":
        family_field = "ip6" if address.version == 6 else "ip"
        subprocess.run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                family_field,
                "saddr",
                str(address),
                "drop",
            ],
            check=True,
        )
        return

    raise ValueError(f"Unsupported firewall backend: {backend}")


def block_ip_with_firewalld(ip):
    block_ip(ip, "firewalld")
