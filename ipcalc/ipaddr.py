import functools
import re
from typing import Optional, List, Union, AnyStr


def octets_to_binary(octets: List[int]) -> List[str]:
    return list(map(lambda x: bin(x)[2:].zfill(8), octets))


def str_to_octets(address: str) -> List[int]:
    return list(map(int, address.split('.')))


IPV4_MAX = (1 << 32) - 1

IPV4_REGEX = r'^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$'
IPV4_REGEX_WITH_PREFIX = r'^(?P<address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\/(?P<prefix>[0-9]|1[0-9]|2[0-9]|3[0-2])$'


@functools.total_ordering
class IPV4Address:

    CLASSFULL_NETWORKS_BY_LEADING_BITS = {
        '0000': {'name': 'A', 'start': '0.0.0.0', 'end': '127.255.255.255', 'mask': '255.0.0.0'},
        '1000': {'name': 'B', 'start': '128.0.0.0', 'end': '191.255.255.255', 'mask': '255.255.0.0'},
        '1100': {'name': 'C', 'start': '192.0.0.0', 'end': '223.255.255.255', 'mask': '255.255.255.0'},
        '1110': {'name': 'D (multicast)', 'start': '224.0.0.0', 'end': '239.255.255.255', 'mask': '(не опредлено)'},
        '1111': {'name': 'E (reserved)', 'start': '240.0.0.0', 'end': '255.255.255.255', 'mask': '(не опредлено)'}
    }

    def __init__(self, addr: str, cidr: int = None):
        self.validate(addr, cidr)

        self.address: str = addr
        self.cidr: int = cidr

        if self.cidr is None and '/' in addr:
            ip, prefix = addr.split('/')
            self.cidr = int(prefix)
            self.address = ip

        self.address_octets: List[int] = str_to_octets(self.address)
        self.binary_address: str = octets_to_binary(self.address_octets)

        self.mask_octets: List[int] = self.__netmask_from_cidr()
        self.mask: str = '.'.join(map(str, self.mask_octets))

        self.network_class = None

        self.network_address()



    def validate(self, address: str, cidr: int = None):
        if cidr is None:
            if '/' in address:
                if not re.match(IPV4_REGEX_WITH_PREFIX, address):
                    raise ValueError('Incorrect address format!')
            else:
                raise ValueError('No CIDR prefix provided!')
        else:
            if not re.match(IPV4_REGEX, address) or not 0 < cidr < 32:
                raise ValueError('Incorrect address/CIDR format!')


    def __netmask_from_cidr(self) -> List[int]:
        mask = [0, 0, 0, 0]
        for i in range(int(self.cidr)):
            mask[i // 8] += 1 << (7 - i % 8)
        self.binary_mask = octets_to_binary(mask)
        self.negated_mask = octets_to_binary(self.__negate_mask(mask))

        return mask

    def __negate_mask(self, mask: List[int]):
        return map(lambda byte: 255 - int(byte), mask)

    def determine_network_class(self):
        first_four_bytes = bin(
            self.address_octets[0] & 0b1111
        )[2:]

    def network_address(self) -> str:
        """
        Возвращает адрес сети для данной подсети
        :return: str
        """
        net_addr = []
        for addr_byte, mask_byte in zip(self.binary_address, self.binary_mask):
            net_addr.append(
                int(addr_byte, 2) & int(mask_byte, 2)
            )

        self.network_addr_octets: List[int] = net_addr
        self.network_addr = '.'.join(map(str, self.network_addr_octets))

        return self.network_addr

    def broadcast_ip(self) -> str:
        """
        Возвращает адрес широковещательной рассылки в данной подсети
        :return: stw
        """
        broadcast = []
        for addr_byte, mask_byte in zip(self.binary_address, self.negated_mask):
            broadcast.append(
                int(addr_byte, 2) | int(mask_byte, 2)
            )

        return '.'.join(map(str, broadcast))

    def first_host_address(self) -> str:
        """
        Возвращает адрес первого узла в подсети
        :return: str
        """
        min_range = self.network_addr_octets
        min_range[-1] += 1
        return '.'.join(map(str, min_range))

    def last_host_address(self) -> str:
        """
        Возвращает адрес последнего узла в подсети
        :return: str
        """
        max_range = list(map(int, self.broadcast_ip().split('.')))
        max_range[-1] -= 1
        return '.'.join(map(str, max_range))

    def number_of_hosts(self) -> int:
        """
        Возвращает количество узловых адресов в подсети
        :return: int
        """
        host_bits = sum(map(
            lambda byte: sum(bit == '1' for bit in byte),
            self.negated_mask
        ))
        return (2 ** host_bits) - 2


    def __lt__(self, other):
        if not isinstance(other, IPV4Address):
            return NotImplemented
        
        if self.network_addr != other.network_addr:
            return self.network_addr < other.network_addr
        if self.mask != other.mask:
            return self.mask < other.mask
        return False


    def __eq__(self, other):
        try:
            return (self.network_addr == other.network_addr and
                    self.address == other.address
                    )
        except AttributeError:
            return NotImplemented

    def __contains__(self, other):
        """
        Принадлежит ли адрес other к данной подсети
        :param other: IPV4Address
        :return: bool
        """
        if not isinstance(other, IPV4Address):
            return NotImplemented
        else:
            return self.network_addr == other.network_addr

