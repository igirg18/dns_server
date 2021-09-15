import sys
from socket import *
from dns_decoder import DNSDecoder
from dns_encoder import DNSEncoder
from dns_lookup import DNSLookup
from zone_file_manipulator import get_resource_from_zone_file
from root_servers import root_server_addresses
from cache import Cache


def get_answer_using_authoritative_ns_domains(authoritative_ns_domains: list, message: bytes, my_cache: Cache) -> list:
    lookup_guy = DNSLookup(my_cache)
    for ns_domain in authoritative_ns_domains:
        q = (ns_domain, 1, 1)
        cached_answer = my_cache.get_rdatas_of_resource_records(q)
        addresses = None
        if cached_answer is not None and len(cached_answer) > 0:
            addresses = cached_answer
        else:
            authoritative_name_server_question = {"DOMAIN": ns_domain, "TYPE": 1, "CLASS": 1}
            addresses = lookup_guy.find(authoritative_name_server_question, root_server_addresses, {}, [], "")
        for name_server_addr in addresses:
            send_socket = socket(AF_INET, SOCK_DGRAM)
            send_socket.settimeout(5)
            try:
                send_socket.sendto(message, (name_server_addr, 53))
                rsp, addr = send_socket.recvfrom(4096)
                new_decoder = DNSDecoder(rsp)
                reply = new_decoder.decode_whole_message()
                answers, authority, additional = reply["ANSWERS"], reply["AUTHORITY"], reply["ADDITIONAL"]
                my_cache.update_cache(answers)
                my_cache.update_cache(authority)
                my_cache.update_cache(additional)
                if len(answers) > 0:
                    answer_records = list(map(lambda x: x["RDATA"], answers))
                    return answer_records
            except Exception as e:
                print("REQUEST TIMED OUT WHILE SEARCHING FOR FINAL ANSWER!!!", e)

def run_dns_server(CONFIG, IP, PORT):
    # your code here
    server_address = (IP, int(PORT))
    my_cache = Cache()
    dns_server_socket = socket(AF_INET, SOCK_DGRAM)
    dns_server_socket.bind(server_address)
    encoder = DNSEncoder()
    while True:
        print("waiting for data... ")
        message, client_address = dns_server_socket.recvfrom(2024)
        decoder = DNSDecoder(message)
        decoded_message = decoder.decode_whole_message()
        header, question = decoded_message["HEADER"], decoded_message["QUESTION"]
        question_list = [question["DOMAIN"], question["TYPE"], question["CLASS"]]
        resource = get_resource_from_zone_file(question_list, CONFIG)
        if resource is not None:
            respond(header["ID"], question["DOMAIN"], question["TYPE"], question["CLASS"], 500, resource, encoder, dns_server_socket, client_address)
        else:
            answer_records = my_cache.get_rdatas_of_resource_records(tuple(question_list))
            if answer_records is not None and len(answer_records) > 0:
                respond(header["ID"], question["DOMAIN"], question["TYPE"], question["CLASS"], 500, answer_records, encoder, dns_server_socket, client_address)
            else:
                authoritative_ns_domains = []
                lookup_guy = DNSLookup(my_cache)
                lookup_guy.find(question, root_server_addresses, {}, authoritative_ns_domains, "")
                answer_records = get_answer_using_authoritative_ns_domains(authoritative_ns_domains, message, my_cache)
                if answer_records is not None and len(answer_records) > 0:
                    respond(header["ID"], question["DOMAIN"], question["TYPE"], question["CLASS"], 500, answer_records, encoder, dns_server_socket, client_address)


def respond(idd: int, domain: str, tp: int, cls: int, ttl: int, resources: list, encoder: DNSEncoder, sock: socket, client_address: tuple) -> None:
    final_answer = encoder.encode_full_answer(idd, domain, tp, cls, ttl, resources)
    sock.sendto(final_answer, client_address)

# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = sys.argv[3]
    run_dns_server(CONFIG, IP, PORT)
