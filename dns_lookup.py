from socket import *
from typing import Optional
from cache import Cache
from dns_decoder import DNSDecoder
from dns_encoder import DNSEncoder


class DNSLookup:
    def __init__(self, c: Cache):
        self.__cache = c

    def find(self, request_question: dict, ip_addresses: list, already_visited: dict, authoritative_domains: list,
             str_offset: str) -> Optional[list]:
        domain, tp, cls = request_question["DOMAIN"], request_question["TYPE"], request_question["CLASS"]
        encoder = DNSEncoder()
        for ip_addr in ip_addresses:
            if ip_addr in already_visited:
                continue
            try:
                server_addr = (ip_addr, 53)
                send_sock = socket(AF_INET, SOCK_DGRAM)
                encoded_question = encoder.encode_question(domain, tp, cls)
                encoded_header = encoder.encode_header(5678, qr=0, answers=0)
                message = encoded_header + encoded_question
                send_sock.settimeout(0.2)
                send_sock.sendto(message, server_addr)
                response, addr = send_sock.recvfrom(4096)
                decoder = DNSDecoder(response)
                decoded_response = decoder.decode_whole_message()
                answers, authority, additional = decoded_response["ANSWERS"], decoded_response["AUTHORITY"], \
                                                 decoded_response["ADDITIONAL"]

                self.__cache.update_cache(answers)
                self.__cache.update_cache(authority)
                self.__cache.update_cache(additional)
                if len(answers) > 0:
                    res = list(map(lambda x: x["RDATA"], answers))
                    return res
                if len(authority) > 0:
                    self.__analyze_authority_section(authority, authoritative_domains, domain, str_offset)
                    if len(additional) > 0:
                        ns_server_addresses = self.__get_ns_server_addresses(authority, additional, str_offset)
                        answer = self.find(request_question, ns_server_addresses, already_visited,
                                           authoritative_domains, str_offset + "\t\t\t")
                        if answer is not None:
                            return answer
            except Exception as e:
                print("REQUEST TIMED OUT!!!!", e)
            already_visited[ip_addr] = ip_addr

    def __analyze_authority_section(self, authority_section: list, authoritative_domain: list, requested_domain: str,
                                    str_offset: str) -> None:
        for resource in authority_section:
            if resource["DOMAIN"] == requested_domain and resource["TYPE"] == 2:
                if resource["RDATA"] not in authoritative_domain:
                    authoritative_domain.append(resource["RDATA"])

    def __get_ns_server_addresses(self, authority: list, additional: list, str_offset: str) -> list:
        addresses = []
        for resource in additional:
            if resource["TYPE"] == 1:
                for authority_rr in authority:
                    if resource["DOMAIN"] == authority_rr["RDATA"]:
                        addresses.append(resource["RDATA"])
        return addresses


