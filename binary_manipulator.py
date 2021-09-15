def get_nth_bit(data, index):
    return 1 if (data & (pow(2, index)) > 0) else 0


def set_nth_bit(data, index):
    return data + (pow(2, index))


def get_binary_representation(data):
    binary_arr = []
    for i in range(31, -1, -1):
        binary_arr.append(get_nth_bit(data, i))
    return binary_arr


def DecimalToBinary(num):
    answer = ""
    if num >= 1:
        answer += DecimalToBinary(num // 2)
        answer += str(num % 2)
        return answer
    return answer


# returns integer, that has ones only on indexes given by "indexes" list
def set_bits(indexes: list):
    res = 0
    for index in indexes:
        res += pow(2, index)
    return res
