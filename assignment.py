from typing import List, Union, Any
from math import *


def encode_BOOLEAN(data: bool) -> bytes:
    bool = [1, 1, data * 255]
    return bytes(bool)


def encode_INTEGER(value: int) -> bytes:
    if value < 0:
        value = -value
        negative = True
        limit = 0x80
    else:
        negative = False
        limit = 0x7f

    values = []
    while value > limit:
        values.append(value & 0xff)
        value >>= 8

    values.append(value & 0xff)

    if negative:
        for i in range(len(values)):
            values[i] = 0xff - values[i]
        for i in range(len(values)):
            values[i] += 1
            if values[i] <= 0xff:
                break
            assert i != len(values) - 1
            values[i] = 0x00

    if negative and values[len(values) - 1] == 0x7f:
        values.append(0xff)
    values.reverse()

    integer = [0x2, len(values)]
    integer.extend(values)

    return bytes(integer)


def encode_NULL(data: None) -> bytes:
    null = [5, 0]
    return bytes(null)


def encode_IA5String(data: str) -> bytes:
    string = [22, len(data)]

    for c in data:
        string.append(ord(c))

    return bytes(string)


AnyDERType = Union[int, str, None, List[Any]]


def encode_SEQUENCE(data: List[AnyDERType]) -> bytes:
    results = encode(data)
    sequence = [48, len(results)]

    sequence = list(bytes(sequence))
    sequence.extend(list(results))

    return bytes(sequence)


def encode_any(data: AnyDERType) -> bytes:
    if (data is None):
        return encode_NULL(None)

    if (type(data) == str):
        return encode_IA5String(data)

    if (type(data) == int):
        return encode_INTEGER(data)

    if (type(data) == bool):
        return encode_BOOLEAN(data)

    if (type(data) == list):
        return encode_SEQUENCE(data)

    raise Exception("Invalid type")


def encode(data: List[AnyDERType]) -> bytes:
    results = []

    for d in data:
        result = encode_any(d)
        results.extend(list(result))

    return bytes(results)


def main() -> None:
    print(encode_any(1))  # b'\x02\x01\x01'
    print(encode_any(-1))  # b'\x02\x01\xff'
    print(encode_any(0))  # b'\x02\x01\x00'
    print(encode_any(256))  # b'\x02\x02\x01\x00'
    print(encode_any(-255))  # b'\x02\x02\xff\x01'

    print(encode_any("A"))  # b'\x16\x01A'
    print(encode_any("Hello World!"))  # b'\x16\x0cHello World!'
    print(encode_any("Karlik <3"))  # b'\x16\tKarlik <3'

    print(encode_any([]))  # b'0\x00'
    print(encode_any([1]))  # b'0\x03\x02\x01\x01'
    print(encode_any([0, 1, 2]))  # b'0\t\x02\x01\x00\x02\x01\x01\x02\x01\x02'

    print(encode_any([True, None, "Hi", None, 1]))

    print(encode([None, 1, [[]], "YO"]))


if __name__ == '__main__':
    main()
