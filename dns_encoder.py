import struct
import binary_manipulator as binary
from functools import reduce
import ipaddress


class DNSEncoder:
    def __init__(self):
        return

    def encode_full_answer(self, identifier: int, domain: str, data_type: int, data_class: int, ttl: int, rdatas: list) -> bytes:
        header_section = self.encode_header(identifier, answers=len(rdatas))
        question_section = self.encode_question(domain, data_type, data_class)
        answer_section_list = []
        for rdata in rdatas:
            one_answer = self.encode_answer(domain, data_type, data_class, ttl, rdata)
            answer_section_list.append(one_answer)
        full_answer_section = reduce(lambda x, y: x + y, answer_section_list)
        return header_section + question_section + full_answer_section

    def __encode_opcode(self, data: int, OPCODE: int) -> int:
        return data | ((OPCODE & 0xF) << 11)

    def __encode_rcode(self, data: int, RCODE: int) -> int:
        return data | (RCODE & 0xF)

    def __encode_second_line(self, QR: int, OPCODE: int, AA: int, TC: int, RD: int, RA: int, Z: int, RCODE: int) -> int:
        res = 0
        res = binary.set_nth_bit(res, 15) if QR else res
        res = binary.set_nth_bit(res, 10) if AA else res
        res = binary.set_nth_bit(res, 9) if TC else res
        res = binary.set_nth_bit(res, 8) if RD else res
        res = binary.set_nth_bit(res, 7) if RA else res
        res = self.__encode_opcode(res, OPCODE)
        res = self.__encode_opcode(res, RCODE)
        return res & 0xFFFF

    def encode_header(self, iid, qr=1, opcode=0, authoritative=0, truncation=0,
                      recurs_desired=1, recurs_avail=0, z=0, rcode=0,
                      questions=1, answers=1, auth=0, additional=0) -> bytes:
        second_line = self.__encode_second_line(qr, opcode, authoritative, truncation, recurs_desired, recurs_avail, z,
                                                rcode)
        res = struct.pack("!HHHHHH", iid, second_line, questions, answers, auth, additional)
        return res

    def encode_domain(self, domain: str) -> bytes:
        split_domain = domain.split(".")
        binary_domain_parts = []
        for word in split_domain:
            if word != "":
                word_len = len(word)
                word_bytes = struct.pack("!B", word_len)
                word_bytes += struct.pack("!" + str(word_len) + "s", word.encode())
                binary_domain_parts.append(word_bytes)
        binary_domain_parts.append(struct.pack("!B", 0))
        return reduce(lambda x, y: x+y, binary_domain_parts)

    def encode_question(self, domain: str, data_type: int, data_class: int) -> bytes:
        encoded_domain = self.encode_domain(domain)
        the_rest = struct.pack("!HH", data_type, data_class)
        return encoded_domain + the_rest

    def encode_rdata(self, rdata: str or tuple, dtype: int) -> bytes:
        if dtype == 1:
            one, two, three, four = list(map(lambda x: int(x), rdata.split(".")))
            return struct.pack("!BBBB", one, two, three, four)
        elif dtype == 2 or dtype == 5:
            return self.encode_domain(rdata)
        elif dtype == 15:
            preference, domain = rdata
            return struct.pack("!h", preference) + self.encode_domain(domain)
        elif dtype == 16:
            return struct.pack("!B" + str(len(rdata)) + "s", len(rdata), rdata.encode())
        elif dtype == 28:
            return ipaddress.IPv6Address(rdata).packed
        elif dtype == 6:
            mname, rname, serial, refresh, retry, expire, minimum = rdata.split(" ")
            mname_binary, rname_binary = (self.encode_domain(mname), self.encode_domain(rname))
            the_rest_binary = struct.pack("!IIIII", int(serial), int(refresh), int(retry), int(expire), int(minimum))
            return mname_binary + rname_binary + the_rest_binary

    def encode_answer(self, name: str, data_type: int, data_class: int, ttl: int, rdata: str or tuple) -> bytes:
        encoded_domain = self.encode_domain(name)
        encoded_rdata = self.encode_rdata(rdata, data_type)
        encoded_type_class_ttl_rdlength = struct.pack("!HHIH", data_type, data_class, ttl, len(encoded_rdata))
        return encoded_domain + encoded_type_class_ttl_rdlength + encoded_rdata


