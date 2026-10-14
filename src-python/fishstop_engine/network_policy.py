"""Process-wide analysis guard: only local model transports are allowed."""
import ipaddress
import socket


def install_local_only_guard():
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname
    original_gethostbyname_ex = socket.gethostbyname_ex
    original_gethostbyaddr = socket.gethostbyaddr

    def allowed(address):
        if not isinstance(address, tuple):
            return True  # Unix-domain model socket.
        host = str(address[0]).strip("[]")
        if host.lower() == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def check(address):
        if not allowed(address):
            raise OSError("External network access disabled by Local only")

    def connect(self, address):
        check(address)
        return original_connect(self, address)

    def connect_ex(self, address):
        check(address)
        return original_connect_ex(self, address)

    def sendto(self, data, *args):
        check(args[-1])
        return original_sendto(self, data, *args)

    def getaddrinfo(host, *args, **kwargs):
        if host is not None:
            check((host, 0))
        return original_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto
    socket.getaddrinfo = getaddrinfo
    def lookup(function):
        def guarded(host):
            check((host, 0))
            return function(host)
        return guarded
    socket.gethostbyname = lookup(original_gethostbyname)
    socket.gethostbyname_ex = lookup(original_gethostbyname_ex)
    socket.gethostbyaddr = lookup(original_gethostbyaddr)
