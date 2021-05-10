import pytest

from ipcalc import IPV4Address

def test_contains():
    ip1 = IPV4Address('192.168.1.22/24')
    ip2 = IPV4Address('192.168.1.33/24')
    
    assert ip1 in ip2


def test_comapison_equals():
    ip1 = IPV4Address('192.168.1.1/24')
    ip2 = IPV4Address('192.168.1.1/24')

    assert ip1 == ip2

def test_comparison_gte():
    ip1 = IPV4Address('192.168.1.0/24')
    ip2 = IPV4Address('192.168.1.1/24')

    assert ip2 > ip1
    assert ip1 != ip2


def test_network_address():
    ip = IPV4Address('192.168.0.222/24')
    assert ip.network_address() == '192.168.0.0'

def test_last_and_first_host_addresses():
    ip = IPV4Address('192.168.0.222', cidr=30)
    assert ip.first_host_address() == '192.168.0.221'
    assert ip.last_host_address() == '192.168.0.222'


def test_incorrect_octet_value():
    with pytest.raises(ValueError):
        ip = IPV4Address('1.1.1.256/13')

def test_incorrect_cidr_prefix_length():
    with pytest.raises(ValueError):
        ip = IPV4Address('192.168.0.1/25')

def test_letters_in_octets():
    with pytest.raises(ValueError):
        ip = IPV4Address('0xff.abcde.nice.123', cidr=123)