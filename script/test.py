import sys
import subprocess


LOCAL_NETWORK_INTERFACE: str = "wlp2s0" ## "enp0s3"


def run_command(cmd: str, std: bool = False) -> None:
    stdout = subprocess.DEVNULL
    if std:
        stdout = None

    reply = subprocess.run(
        cmd, shell=True, stdout=stdout,
    )
    if reply.returncode == 0:
        print(f"ok: {cmd}")
    else:
        print(f"error: {cmd}")


def main() -> None:

    stdOut: bool = False
    addList: list = [
        "",
        "brgaddwg -i wg0 -l /var/log -le",
        "brgaddwg -i wg1 -l /var/log -ld",
        "brgaddwg -i wg2 -l /var/log -le -js",
        "brgaddwg -i wg3 -m 1340 -l /var/log -ld -js",

        "brgaddawg -i awg0 -l /var/log -le",
        "brgaddawg -i awg1 -l /var/log -ld",
        "brgaddawg -i awg2 -l /var/log -le -js",
        "brgaddawg -i awg3 -m 1240 -l /var/log -ld -js",
        """brgaddawg -i awg4 -m 1240 -l /var/log -ld -js '{"jc":5,"jmin":10,"jmax":100,"s1":12,"s2":13,"s3":14,"s4":15,"h1":"1","h2":"2","h3":"3","h4":"4","header_protection_key":"aM4nrr/9JB0/0icSIxrCJnyZ8Ct0LSVpXEVBw1CUhH8=","content_padding_addition":"10","rekey_after_time":"30","rekey_timeout":"50","reject_after_time":"70","keepalive_timeout":"90","max_handshake_attempts":"2","random_trailers":true,"disable_cookies":true}'"""
    ]

    setList: list = [
        "",

        # Up/down network interface.
        "brgsetwg -i wg0 -up",
        "brgsetwg -i wg0 -dw",

        "brgsetwg -i awg0 -up",
        "brgsetwg -i awg0 -dw",

        # Port.
        "brgsetwg -i wg0 -u -p 51855",
        "brgsetwg -i awg0 -u -p 51355",

        # Update private key.
        "brgsetwg -i wg0 -u -pk",
        "brgsetwg -i wg0 -u -pk AAgUffqqXRCwO6M91FcZIhzyOIiYIwLcUFJEHSSu2k8=",

        "brgsetwg -i awg0 -u -pk",
        "brgsetwg -i awg0 -u -pk MLwC4x30d4y0pJz+JGSzgoIFiX7X1TsmeaNqXFI/tVo=",

        # Peer.
        "brgsetwg -i wg0 -pr lTREr8sjJxZQfIDJohjeWHnlhUt5k/r1fkGqRiY4ZRo="
        " -a 10.0.0.1/32",

        "brgsetwg -i awg0 -pr EP5tJlsAlGagiHNVhJnO3YYtC0PNQHUyfaF4DRrDhns="
        " -a 10.0.0.1/32",

        "brgsetwg -i wg0 -pr lTREr8sjJxZQfIDJohjeWHnlhUt5k/r1fkGqRiY4ZRo="
        " -a 10.0.0.2/32 -kp 10 -eh 172.168.85.1:65535",

        "brgsetwg -i awg0 -pr EP5tJlsAlGagiHNVhJnO3YYtC0PNQHUyfaF4DRrDhns="
        " -a 10.0.0.2/32 -kp 10 -eh 172.168.85.1:65535",

        "brgsetwg -i wg0 -pr lTREr8sjJxZQfIDJohjeWHnlhUt5k/r1fkGqRiY4ZRo= -d",
        "brgsetwg -i awg0 -pr EP5tJlsAlGagiHNVhJnO3YYtC0PNQHUyfaF4DRrDhns= -d",

        "brgsetwg -i wg0 -ip 10.10.10.254/24 -a",
        "brgsetwg -i wg0 -ip 10.10.10.254/24 -d",

        "brgsetwg -i awg0 -ip 10.10.5.254/24 -a",
        "brgsetwg -i awg0 -ip 10.10.5.254/24 -d",



        # NAT.
        "brgsetwg -i wg0 -ip 10.10.10.0/24 -a -n",
        "brgsetwg -i wg0 -ip 10.10.10.0/24 -d -n",
        f"brgsetwg -i wg0 -ip 10.10.10.0/24 -a -n {LOCAL_NETWORK_INTERFACE}",
        f"brgsetwg -i wg0 -ip 10.10.10.0/24 -d -n {LOCAL_NETWORK_INTERFACE}",

        "brgsetwg -i awg0 -ip 10.10.10.0/24 -a -n",
        "brgsetwg -i awg0 -ip 10.10.10.0/24 -d -n",
        f"brgsetwg -i awg0 -ip 10.10.10.0/24 -a -n {LOCAL_NETWORK_INTERFACE}",
        f"brgsetwg -i awg0 -ip 10.10.10.0/24 -d -n {LOCAL_NETWORK_INTERFACE}",

        # Firewall.
        "brgsetwg -i wg0 -ip 10.10.10.0/24 -d -fr",
        f"brgsetwg -i wg0 -ip 10.10.10.0/24 -d -fr {LOCAL_NETWORK_INTERFACE}",

        "brgsetwg -i awg0 -ip 10.10.10.0/24 -d -fr",
        f"brgsetwg -i awg0 -ip 10.10.10.0/24 -d -fr {LOCAL_NETWORK_INTERFACE}",

        # Forwarding: IPv4
        "brgsetwg -fw4 -a",
        "brgsetwg -fw4 -d",

        # Forwarding: IPv6
        "brgsetwg -fw6 -a",
        "brgsetwg -fw6 -d",

        # Firewall port: UDP
        "brgsetwg -fr -u -a 51820",
        "brgsetwg -fr -u -d 51820",

        # Del.
        "brgsetwg -i wg0 -d",
        "brgsetwg -i wg1 -d",
        "brgsetwg -i wg2 -d",
        "brgsetwg -i wg3 -d",

        "brgsetwg -i awg0 -d",
        "brgsetwg -i awg1 -d",
        "brgsetwg -i awg2 -d",
        "brgsetwg -i awg3 -d",
        "brgsetwg -i awg4 -d",

    ]

    getList: list = [
        "",
        "brggetwg -i wg0 -ip",
        "brggetwg -i wg0 -pr",
        "brggetwg -i awg0 -ip",
        "brggetwg -i awg0 -pr",
        "brggetwg -ip",
        "brggetwg -pr",
        "brggetwg -fw",
        "brggetwg -pk",
        "brggetwg -n",
        "brggetwg -fr",
    ]

    try:

        for cmd in addList:
            run_command(cmd, stdOut)

        for cmd in getList:
            run_command(cmd, stdOut)

        for cmd in setList:
            run_command(cmd, stdOut)

    except Exception as err:
        print(f"unexpected error: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
