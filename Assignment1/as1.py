import os
import copy
import math
import sys
import matplotlib.pyplot as plt
import numpy as np
import random


def print_progress(progress, total):
    sys.stdout.flush()
    sys.stdout.write("\rProcessing: %d%%" % (100 * progress / total))


# def toggle_bits(key, b, i):
#     if b <= 8:
#         key[i] = key[i] ^ int("1" * b, 2)
#         return key
#     else:
#         num_byte = math.ceil(b / 8)
#         t = b
#         for j in range(num_byte):
#             if (t > 8):
#                 mask = '1' * 8
#                 t -= 8
#             else:
#                 mask = '1' * t
#
#             key[i + j] = key[i + j] ^ int(mask, 2)
#
#         return key


def toggle_bits(key, b):
    for i in range(b):
        byte = random.randrange(256)
        bit = random.randrange(8)
        key[byte] = key[byte] ^ (1 << bit)


p_lens = [2 ** i for i in range(1, 9)]
data = {}

print_progress(0, max(p_lens) + 1)
for plain_text_len in p_lens:
    data_item = {}

    # Generate a random key of size 256 bye
    # key = bytearray(os.urandom(key_len))

    with open("key", "rb") as f:
        key = bytearray(f.read())

    os.system(f"rc4.exe key {plain_text_len}")

    br = bytearray()

    with open("bytes", "rb") as f:
        br = bytearray(f.read())

    # Toggle 1 bit
    for b in range(1, 33):
        R = []

        for t in range(150):
            key2 = copy.copy(key)

            # toggle b bits in key
            toggle_bits(key2, b)

            with open("key2", "wb") as f:
                f.write(key2)

            os.system(f"rc4.exe key2 {plain_text_len}")

            br2 = bytearray()

            with open("bytes", "rb") as f:
                br2 = bytearray(f.read())

            bin_str = ''
            for i in range(len(br)):
                # br2[i] = br[i] ^ br2[i]
                bin_str += format(br[i] ^ br2[i], '08b')

            count = [0 for i in range(256)]
            for i in range(len(bin_str) - 7):
                count[int(bin_str[i:i + 8], 2)] += 1

            r = (np.std(count) * len(count)) / (len(bin_str))
            R.append(r)

        with open(f"result/data_{plain_text_len}", "a") as f:
            f.write(f'{b},{np.mean(R)}\n')
            data_item[b] = np.mean(R)

    data[plain_text_len] = data_item
    print_progress(plain_text_len, max(p_lens) + 1)

data_index = [data_index for data_index in data]
for index in data_index:
    plt.plot(list(data[index].keys()), list(
        data[index].values()), label=f"{index} Bytes")
    plt.xticks(list(data_item.keys()))

plt.ylabel('Randomness (smaller is better)', fontsize=14)
plt.xlabel('No. of bits toggled', fontsize=14)
plt.title('Randomness vs # bits toggled Plot', fontsize=16)
plt.legend()
plt.grid(True)
plt.show()
