import time
from datetime import datetime
from typing import Optional


class Cache:
    def __init__(self):
        self.__cache_db = {}

    def add(self, dns_question: tuple, dns_record: tuple) -> None:
        if self.__cache_db.get(dns_question) is None:
            self.__cache_db[dns_question] = set()
        records = self.__cache_db.get(dns_question)
        for record in records:
            if record[0] == dns_record:
                return
        now = datetime.now()
        new_record = (dns_record, now)
        self.__cache_db[dns_question].add(new_record)

    def __is_not_outdated(self, record: tuple) -> bool:
        now = datetime.now()
        # datetime when record was cached
        then = record[1]
        difference = int((now - then).total_seconds())
        # ttl value of dns resource record
        ttl = record[0][3]
        return difference < ttl

    def get_whole_resource_records(self, dns_question: tuple) -> Optional[list]:
        records = self.__cache_db.get(dns_question)
        if records is None:
            return None
        result = filter(self.__is_not_outdated, list(records))
        return list(map(lambda x: x[0], result))

    def get_rdatas_of_resource_records(self, dns_question: tuple) -> Optional[list]:
        records = self.get_whole_resource_records(dns_question)
        if records is not None:
            return list(map(lambda x: x[5], records))
        else:
            return None

    def update_cache(self, resources: dict) -> None:
        for resource in resources:
            question = (resource["DOMAIN"], resource["TYPE"], resource["CLASS"])
            rr = (resource["DOMAIN"], resource["TYPE"], resource["CLASS"], resource["TTL"], resource["RDATALENGTH"],
                  resource["RDATA"])
            self.add(question, rr)

# my_cache = Cache()
# my_cache.add(("bla", 1, 1), ("exmple.com", 1, 1, 2, 50, "1.1.1.1"))
# my_cache.add(("bla", 1, 1), ("exmple.com", 1, 1, 2, 50, "1.1.1.1"))
# my_cache.add(("bla", 1, 1), ("exmple.com", 1, 1, 1, 50, "1.1.1.2"))
# time.sleep(1)
# print(my_cache.get(("bla", 1, 1)))
