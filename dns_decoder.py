import struct
import binary_manipulator as binary
import ipaddress


class DNSDecoder:
    def __init__(self, dns_message: bytes):
        self.dns_packet = dns_message

    def decode_whole_message(self) -> dict:
        res = {"ANSWERS": [], "AUTHORITY": [], "ADDITIONAL": []}
        header = self.decode_header()
        res["HEADER"] = header
        question, length_of_question = self.decode_question()
        res["QUESTION"] = question
        curr_answer_offset = 12 + length_of_question
        for index in range(0, header["ANCOUNT"]):
            answer, length = self.decode_answer(self.dns_packet[curr_answer_offset:])
            res["ANSWERS"].append(answer)
            curr_answer_offset += length
        for index in range(0, header["NSCOUNT"]):
            answer, length = self.decode_answer(self.dns_packet[curr_answer_offset:])
            res["AUTHORITY"].append(answer)
            curr_answer_offset += length
        for index in range(0, header["ARCOUNT"]):
            answer, length = self.decode_answer(self.dns_packet[curr_answer_offset:])
            res["ADDITIONAL"].append(answer)
            curr_answer_offset += length
        return res


    def __decode_opcode(self, second_line: int) -> int:
        return (second_line >> 11) & 0xF

    def __decode_rcode(self, second_line: int) -> int:
        return second_line & 0xF

    def __decode_second_line(self, second_line: int) -> list:
        res = [binary.get_nth_bit(second_line, 15), self.__decode_opcode(second_line),
               binary.get_nth_bit(second_line, 10), binary.get_nth_bit(second_line, 10),
               binary.get_nth_bit(second_line, 10), binary.get_nth_bit(second_line, 10), 0,
               self.__decode_rcode(second_line)]
        return res

    def __build_header_dict(self, id, second_line, questions, answers, authority, additional):
        header_dict = {"ID": id,
                       "QR": second_line[0],
                       "OPCODE": second_line[1],
                       "AA": second_line[2],
                       "TC": second_line[3],
                       "RD": second_line[4],
                       "RA": second_line[5],
                       "Z": second_line[6],
                       "RCODE": second_line[7],
                       "QDCOUNT": questions,
                       "ANCOUNT": answers,
                       "NSCOUNT": authority,
                       "ARCOUNT": additional}
        return header_dict

    def decode_header(self) -> dict:
        id, second_line, questions, answers, authority, additional = struct.unpack("!HHHHHH", self.dns_packet[0:12])
        unpacked_second_line = self.__decode_second_line(second_line)
        return self.__build_header_dict(id, unpacked_second_line, questions, answers, authority, additional)

    def decode_domain(self, question_segment: bytes) -> tuple:
        current_index = 0
        length_of_domain_segment = 0
        domain = ""
        while True:
            length_octet, = struct.unpack("!B", question_segment[current_index: current_index + 1])
            if length_octet == 0:
                break
            if length_octet > 64:
                pointer, = struct.unpack("!H", question_segment[current_index: current_index + 2])
                pointer -= (pow(2, 15) + pow(2, 14))
                domain += self.decode_domain(self.dns_packet[pointer:])[0]
                return domain, length_of_domain_segment + 2
            current_index += 1
            word, = struct.unpack("!" + str(length_octet) + "s",
                                  question_segment[current_index: current_index + length_octet])
            domain += (word.decode() + ".")
            length_of_domain_segment += length_octet + 1
            current_index += length_octet
        return domain, length_of_domain_segment+1

    def __build_question_dict(self, domain: str, q_type: int, q_class: int) -> dict:
        return {"DOMAIN": domain, "TYPE": q_type, "CLASS": q_class}

    def decode_question(self):
        domain, length = self.decode_domain(self.dns_packet[12:])
        q_type, q_class = struct.unpack("!hh", self.dns_packet[12 + length: 12 + length + 4])
        return self.__build_question_dict(domain, q_type, q_class), length + 4

    def decode_rdata(self, binary_rdata: bytes, dtype: int, length: int) -> str or tuple:
        if dtype == 1:
            one, two, three, four = struct.unpack("!BBBB", binary_rdata[:4])
            return str(one) + "." + str(two) + "." + str(three) + "." + str(four)
        elif dtype == 2 or dtype == 5:
            result, length = self.decode_domain(binary_rdata)
            return result
        elif dtype == 15:
            preference, = struct.unpack("!h", binary_rdata[:2])
            domain, length = self.decode_domain(binary_rdata[2:])
            return preference, domain
        elif dtype == 16:
            result, = struct.unpack("!" + str(length) + "s", binary_rdata[:length])
            return result.decode()
        elif dtype == 28:
            return str(ipaddress.IPv6Address(binary_rdata[0:16]))
        elif dtype == 6:
            name_server, length1 = self.decode_domain(binary_rdata)
            mail_server, length2 = self.decode_domain(binary_rdata[length1:])
            serial, refresh, retry, expire, minimum = struct.unpack("!IiiiI", binary_rdata[length1 + length2:length1 + length2 + 20])
            return name_server + " " + mail_server + " " + str(serial) + " " + str(refresh) + " " + str(retry) + " " + str(
                expire) + " " + str(minimum)

    def __build_answer_dict(self, domain: str, q_type: int, q_class: int, ttl: int, rd_length: int, rdata: str or tuple) -> dict:
        return {"DOMAIN": domain, "TYPE": q_type, "CLASS": q_class, "TTL": ttl, "RDATALENGTH": rd_length, "RDATA": rdata}

    def decode_answer(self, answer_section: bytes) -> tuple:
        domain, length = self.decode_domain(answer_section)
        q_type, q_class, ttl, rd_length = struct.unpack("!HHIH", answer_section[length: length + 10])
        rdata = self.decode_rdata(answer_section[length + 10:], q_type, rd_length)
        return self.__build_answer_dict(domain, q_type, q_class, ttl, rd_length, rdata), (length + 10 + rd_length)