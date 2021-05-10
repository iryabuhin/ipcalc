from abc import ABC, abstractmethod
from ipcalc import (
    IPV4Address,
    IPV4_REGEX,
    IPV4_REGEX_WITH_PREFIX,
    IPV4AddressFormatError,
)
from colorama import Fore, Back, Style
import re


class Task(ABC):
    @abstractmethod
    def perform_task(self) -> None:
        pass

    @property
    @abstractmethod
    def _id(self) -> int:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass


class GetClassfulNetworkInfo(Task):

    _id = 1
    description = (
        "для введенного IP-адреса рассчитывать класс сети, IP-адрес сети, маску "
        "сети и IP-адрес широковещательной рассылки в данной сети"
    )

    def __init__(self):
        self.get_input()

    def get_input(self) -> None:
        ok = False
        while not ok:
            addr = input("Введите IP-адрес: ").strip()
            if not re.match(IPV4_REGEX, addr):
                print(Fore.RED, "Некорректный формат адреса!")
                print(Style.RESET_ALL)
                print("Попробуйте еще раз!")
            else:
                ok = True
                self.ip = IPV4Address(addr)

    def perform_task(self) -> None:
        class_A = IPV4Address("10.0.0.0/8")
        class_B = IPV4Address("172.16.0.0/12")
        class_C = IPV4Address("192.168.0.0/16")


class SubnetAddrAndBroadcastAddrTask(Task):

    _id = 2
    description = (
        "для введенного адреса рассчитать "
        "IP-адрес сети, маску сети и адрес шир. расс в данной сети"
    )

    def __init__(self):
        self.ip = None
        self.get_input()

    def get_input(self):
        ok = False
        while not ok:
            addr = input("Введите адрес (в формате CIDR): ").strip()
            if re.match(IPV4_REGEX_WITH_PREFIX, addr):
                ok = True
                self.ip = IPV4Address(addr)

    def perform_task(self) -> None:
        print("Адрес сети:", self.ip.network_address())
        print("Маска сети:", self.ip.mask)
        print("Адрес широковещательной рассылки:", self.ip.broadcast_ip())


class CheckSubnetMaskCorrectness(Task):

    _id = 3
    description = "для введенного IP-адреса проверить корректность маски сети и определить её длину в битах"

    def __init__(self):
        self.mask = None
        self.get_input()

    def get_input(self) -> None:
        ok = False
        while not ok:
            mask = input("Введите маску сети: ").strip()
            if not re.match(IPV4_REGEX, mask):
                print(Fore.RED, "Некорректный формат маски сети!", Style.RESET_ALL)
            else:
                ok = True
                self.mask = mask

    def perform_task(self) -> None:
        octets = [int(o) for o in self.mask.split(".")]

        print(
            "Маска сети (в двоичном представлении):",
            ".".join([bin(o)[2:].zfill(8) for o in octets]),
        )

        a, b, c, d = octets

        mask = a << 24 | b << 16 | c << 8 | d

        m = mask & -mask

        right_zero_bits = -1
        while m:
            m >>= 1
            right_zero_bits += 1

        # Verify that all the bits to the left are 1's
        if mask | ((1 << right_zero_bits) - 1) == 0xFFFFFFFF:
            print(Fore.GREEN, "Введенная маска сети корректна")
        else:
            print(Fore.RED, "Маска некорректна", Style.RESET_ALL)


class AddrIsSubnetAddrForGivenAddrTask(Task):

    _id = 4
    description = (
        "для введенного IP-адреса и длины маски сети (в формате CIDR, через «/») проверить, "
        "является ли данный IP-адрес адресом сети с указанной длиной маски сети"
    )

    def __init__(self):
        self.ip = None
        self.original_addr = None
        self.get_input()

    def get_input(self) -> None:
        ok = False
        while not ok:
            addr = input("Введите адрес (в формате CIDR): ").strip()
            if not re.match(IPV4_REGEX_WITH_PREFIX, addr):
                print(Fore.RED, "Некорретный формат адреса - ", addr, Style.RESET_ALL)
                print("Попробуйте еще раз")
            else:
                ok = True
                self.original_addr = addr
                self.ip = IPV4Address(addr)

    def perform_task(self) -> None:
        addr, cidr = self.original_addr.split("/")
        subnet_addr = self.ip.network_address()

        if addr == subnet_addr:
            print(f"{Fore.GREEN}Введенный адрес является адресом сети с указанной длиной маски сети")
        else:
            print(
                Fore.RED,
                "Адрес {} НЕ является адресом сети ({}) с указанной длиной маской сети ({})".format(
                    addr, self.ip.network_address(), cidr
                ),
                Style.RESET_ALL
            )


class TwoAddressesInOneSubnet(Task):

    _id = 5
    description = (
        "для двух введенных IP-адресов и длины маски сети (в формате CIDR, через «/») "
        "проверить, принадлежат ли указанные адреса к одной подсети"
    )

    def __init__(self):
        self.first_addr = None
        self.second_addr = None
        self.get_input()

    def get_input(self):
        ok = False
        while not ok:
            first_addr = input("Введите первый адрес (в формате CIDR): ")
            second_addr = input("Введите второй адрес (в формате CIDR): ")

            for addr in (first_addr, second_addr):
                if not re.match(IPV4_REGEX_WITH_PREFIX, addr):
                    print(Fore.RED, "Некорретный формат адреса - ", addr)
                    print("Попробуйте еще раз")
                    print(Style.RESET_ALL)
                    break
            else:
                ok = True
                self.first_addr = first_addr
                self.second_addr = second_addr

    def perform_task(self) -> None:
        first_ip = IPV4Address(self.first_addr)
        second_ip = IPV4Address(self.second_addr)

        if first_ip.network_address() == second_ip.network_address():
            print("Адреса находятся в одной подсети")
        else:
            print(
                "Адреса находятся в разных подсетях! ({} - адрес сети первого, {} - второго)".format(
                    first_ip.network_address(), second_ip.network_address()
                )
            )


class MaxMaskLenForTwoAddresses(Task):

    _id = 6
    description = (
        "для двух введенных IP-адресов определить максимальную длину маски "
        "сети, чтобы указанные IP-адреса находились в одной сети"
    )

    def __init__(self):
        self.first_addr = None
        self.second_addr = None
        self.get_input()

    def get_input(self):
        ok = False
        while not ok:
            first_addr = input("Введите первый адрес: ")
            second_addr = input("Введите второй адрес ")

            for addr in (first_addr, second_addr):
                if not re.match(IPV4_REGEX, addr):
                    print(Fore.RED, "Некорретный формат адреса - ", addr)
                    print("Попробуйте еще раз")
                    print(Style.RESET_ALL)
                    break
            else:
                ok = True
                self.first_addr = first_addr
                self.second_addr = second_addr

    def perform_task(self) -> None:
        first_addr_bin = "".join(
            [bin(octet)[2:] for octet in [int(i) for i in self.first_addr.split(".")]]
        ).ljust(32, "0")

        second_addr_bin = "".join(
            [bin(octet)[2:] for octet in [int(i) for i in self.second_addr.split(".")]]
        ).ljust(32, "0")

        i = 0
        while first_addr_bin[i] == second_addr_bin[i]:
            i += 1

        print(first_addr_bin, second_addr_bin, " " * i + "^", " " * i + "|", sep="\n")
        print("Макс. длина маски сети: ", i)
