from BitVector import *
import time

# listing essential tables, matrices, lists, and variables
# Sbox = byte substitution box (16x16 lookup table) for encryption subBytes
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

# InvSbox = byte inverse substitution box (16x16 lookup table) for decryption invSubBytes
InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

# Mixer = 4x4 matrix for finite field matrix multiplication in Galois field (for encryption mixColumns)
Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

# InvMixer = 4x4 matrix for finite field matrix multiplication in Galois field (for decryption invMixColumns)
InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

# roundkeys = a list containing all roundkeys for 11 cycles/rounds in AES symmetric key encryption algorithm for 128 bits key
roundkeys = []

# genSbox = generated Rijndael Sbox using multiplicative inverse and finite field mathematics
genSbox = []

# genInvSbox = generated Rijndael inverse Sbox using multiplicative inverse and finite field mathematics
genInvSbox = []

# AES_input = an ASCII/Hexadecimal text/string to be encrypted
AES_input = BitVector(size=0)

# pad_count_input = number of whitespaces padded after plaintext to make its character count a multiple of 16
pad_count_input = 0

# AES_modulus = a parameter required for finite field modular multiplication and determining multiplicative inverse of a bitvector in Galois field
AES_modulus = BitVector(bitstring="100011011")

# AES_output = a Hexadecimal text/string which is encrypted from AES_input
AES_output = BitVector(size=0)

# decipher_output = an ASCII/Hexadecimal text/string which is decrypted from AES_output
decipher_output = BitVector(size=0)

# key_scheduling_time = execution time for AES key scheduling
key_scheduling_time = 0

# encryption_time = execution time for AES encryption
encryption_time = 0

# decryption_time = execution time for AES decryption
decryption_time = 0

# input_filename = filename in case of file input for AES encryption-decryption
input_filename = ""

# defining auxiliary functions
def input_initial_roundkey(is_file_input):
    if is_file_input:
        roundkey_file = open("./inputs/roundkey.in", "r")
        initial_roundkey = roundkey_file.read()
        roundkey_file.close()
    else:
        initial_roundkey = input("Enter initial roundkey: ")

    if len(initial_roundkey) > 16:
        initial_roundkey = initial_roundkey[0: 16]
    elif len(initial_roundkey) < 16:
        initial_roundkey = initial_roundkey + '0' * (16 - len(initial_roundkey))

    roundkeys.append(BitVector(textstring=initial_roundkey))

def input_plaintext(is_file_input):
    global AES_input, pad_count_input

    if is_file_input:
        plaintext_file = open("./inputs/plaintext.in", "r")
        plaintext = plaintext_file.read()
        plaintext_file.close()
    else:
        plaintext = input("Enter plaintext: ")
        
    if (len(plaintext) % 16) != 0:
        pad_count_input = 16 - len(plaintext) % 16
        plaintext = plaintext + " " * pad_count_input
    elif len(plaintext) == 0:
        return False

    AES_input += BitVector(textstring=plaintext)
    return True

def input_file():
    global AES_input, pad_count_input, input_filename

    input_filename = input("Enter filename (inside ./res/): ")

    file = open("./res/{}".format(input_filename), "rb")
    file_content = bytes.hex(file.read())
    file.close()

    if (len(file_content) % 32) != 0:
        pad_count_input = 32 - len(file_content) % 32
        file_content = file_content + "0" * pad_count_input
    elif len(file_content) == 0:
        return False

    AES_input += BitVector(hexstring=file_content)
    return True

def output_file():
    global decipher_output

    file = open("./outputs/{}".format(input_filename), "wb+")
    file.write(bytes.fromhex(decipher_output.get_bitvector_in_hex()[: len(decipher_output.get_bitvector_in_hex()) - pad_count_input]))
    file.close()

def generate_sbox():
    global genSbox

    if genSbox:
        return

    for row in range(16):
        gensbox_row = []

        for column in range(16):
            gensbox_row.append(BitVector(intVal=(16 * row + column), size=8))

        genSbox.append(gensbox_row)

    for i in range(len(genSbox)):
        for j in range(len(genSbox[0])):
            if genSbox[i][j].get_bitvector_in_hex() == "00":
                multiplicative_inverse = BitVector(hexstring="00")
            else:
                multiplicative_inverse = genSbox[i][j].gf_MI(AES_modulus, 8)

            genSbox[i][j] = BitVector(hexstring=multiplicative_inverse.get_bitvector_in_hex())
            genSbox[i][j] ^= BitVector(hexstring=multiplicative_inverse.get_bitvector_in_hex()) << 1
            genSbox[i][j] ^= BitVector(hexstring=multiplicative_inverse.get_bitvector_in_hex()) << 2
            genSbox[i][j] ^= BitVector(hexstring=multiplicative_inverse.get_bitvector_in_hex()) << 3
            genSbox[i][j] ^= BitVector(hexstring=multiplicative_inverse.get_bitvector_in_hex()) << 4
            genSbox[i][j] ^= BitVector(hexstring="63")

def generate_invsbox():
    global genInvSbox

    if genInvSbox:
        return

    for row in range(16):
        geninvsbox_row = []

        for column in range(16):
            geninvsbox_row.append(BitVector(intVal=(16 * row + column), size=8))

        genInvSbox.append(geninvsbox_row)

    for i in range(len(genInvSbox)):
        for j in range(len(genInvSbox[0])):
            multiplicative_inverse = BitVector(hexstring=genInvSbox[i][j].get_bitvector_in_hex()) << 1
            multiplicative_inverse ^= BitVector(hexstring=genInvSbox[i][j].get_bitvector_in_hex()) << 3
            multiplicative_inverse ^= BitVector(hexstring=genInvSbox[i][j].get_bitvector_in_hex()) << 6
            multiplicative_inverse ^= BitVector(hexstring="05")

            if multiplicative_inverse.get_bitvector_in_hex() == "00":
                genInvSbox[i][j] = BitVector(hexstring="00")
            else:
                genInvSbox[i][j] = multiplicative_inverse.gf_MI(AES_modulus, 8)

def substitute_bytes_using_sbox(bitvector, will_use_genbox):
    sub_bitvector = BitVector(size=0)

    for i in range(0, bitvector.length(), 8):
        if will_use_genbox:
            sub_bitvector += genSbox[bitvector[i: i+8].intValue() // 16][bitvector[i: i+8].intValue() % 16]
        else:
            sub_bitvector += BitVector(intVal=Sbox[bitvector[i: i+8].intValue()], size=8)

    return sub_bitvector

def inverse_substitute_bytes_using_invsbox(bitvector, will_use_genbox):
    invsub_bitvector = BitVector(size=0)

    for i in range(0, bitvector.length(), 8):
        if will_use_genbox:
            invsub_bitvector += genInvSbox[bitvector[i: i+8].intValue() // 16][bitvector[i: i+8].intValue() % 16]
        else:
            invsub_bitvector += BitVector(intVal=InvSbox[bitvector[i: i+8].intValue()], size=8)

    return invsub_bitvector

def process_root_word(root_word, round_constant, will_use_genbox):
    # circular byte left shift of root_word
    root_word = root_word << 8

    # byte substitution of root_word using Sbox
    root_word = substitute_bytes_using_sbox(root_word, will_use_genbox)

    # adding round constant
    root_word = root_word ^ round_constant

    return root_word

def schedule_roundkeys(will_use_genbox):
    if not roundkeys:
        return

    rc = BitVector(hexstring="01")
    multiplier = BitVector(hexstring="02")

    for i in range(10):
        round_constant = BitVector(hexstring=rc.get_bitvector_in_hex())
        round_constant += BitVector(hexstring="000000")

        w_0 = roundkeys[i][0: 32] ^ process_root_word(roundkeys[i][96: 128], round_constant, will_use_genbox)
        w_1 = w_0 ^ roundkeys[i][32: 64]
        w_2 = w_1 ^ roundkeys[i][64: 96]
        w_3 = w_2 ^ roundkeys[i][96: 128]

        this_roundkey = w_0
        this_roundkey += w_1
        this_roundkey += w_2
        this_roundkey += w_3
        roundkeys.append(this_roundkey)

        rc = multiplier.gf_multiply_modular(rc, AES_modulus, 8)

def convert_bitvector_into_matrix(bitvector):
    # converting bitvector into a column major matrix
    state_matrix = []

    for i in range(4):
        state_matrix_row = []

        for j in range(bitvector.length() // (8 * 4)):
            state_matrix_row.append(bitvector[(i * 8 + j * 32): (i * 8 + j * 32) + 8])

        state_matrix.append(state_matrix_row)

    return state_matrix

def convert_matrix_into_bitvector(state_matrix):
    # converting matrix into a shifted bitvector
    shifted_bitvector = BitVector(size=0)

    for i in range(len(state_matrix[0])):
        for j in range(len(state_matrix)):
            shifted_bitvector += state_matrix[j][i]

    return shifted_bitvector

def shift_rows(bitvector):
    # converting bitvector into a column major matrix
    state_matrix = convert_bitvector_into_matrix(bitvector)

    # shifting/rotating each row of the matrix according to shiftRows operation
    for i in range(4):
        state_matrix[i] = state_matrix[i][i:] + state_matrix[i][: i]

    return convert_matrix_into_bitvector(state_matrix)

def inverse_shift_rows(bitvector):
    # converting bitvector into a column major matrix
    state_matrix = convert_bitvector_into_matrix(bitvector)

    # shifting/rotating each row of the matrix according to invShiftRows operation
    for i in range(4):
        state_matrix[i] = state_matrix[i][len(state_matrix[i]) - i:] + state_matrix[i][: len(state_matrix[i]) - i]

    return convert_matrix_into_bitvector(state_matrix)

def multiply_matrices(matrix1, matrix2):
    # finite field matrix multiplication in Galois field
    result_matrix = []

    for i in range(len(matrix1)):
        result_matrix_row = []

        for j in range(len(matrix2[0])):
            temp = matrix1[i][0].gf_multiply_modular(matrix2[0][j], AES_modulus, 8)
            temp ^= matrix1[i][1].gf_multiply_modular(matrix2[1][j], AES_modulus, 8)
            temp ^= matrix1[i][2].gf_multiply_modular(matrix2[2][j], AES_modulus, 8)
            temp ^= matrix1[i][3].gf_multiply_modular(matrix2[3][j], AES_modulus, 8)
            result_matrix_row.append(temp)

        result_matrix.append(result_matrix_row)

    return result_matrix

def mix_columns_using_mixer(bitvector):
    return convert_matrix_into_bitvector(multiply_matrices(Mixer, convert_bitvector_into_matrix(bitvector)))

def inverse_mix_columns_using_invmixer(bitvector):
    return convert_matrix_into_bitvector(multiply_matrices(InvMixer, convert_bitvector_into_matrix(bitvector)))

def encrypt(bitvector, is_debug, will_use_genbox):
    # round 0
    bitvector = bitvector ^ roundkeys[0]

    if is_debug:
        print("AES output after round {}: {}".format(0, bitvector.get_bitvector_in_hex()))

    # round 1-9
    for i in range(9):
        bitvector = mix_columns_using_mixer(shift_rows(substitute_bytes_using_sbox(bitvector, will_use_genbox))) ^ roundkeys[i+1]

        if is_debug:
            print("AES output after round {}: {}".format(i+1, bitvector.get_bitvector_in_hex()))

    # round 10
    bitvector = shift_rows(substitute_bytes_using_sbox(bitvector, will_use_genbox)) ^ roundkeys[10]

    if is_debug:
        print("AES output after round {}: {}".format(10, bitvector.get_bitvector_in_hex()))

    # returning ciphered bitvector
    return bitvector

def decrypt(bitvector, is_debug, will_use_genbox):
    # round 0
    bitvector = bitvector ^ roundkeys[10]

    if is_debug:
        print("Decryption output after round {}: {}".format(0, bitvector.get_bitvector_in_hex()))

    # round 1-9
    for i in range(9):
        bitvector = inverse_mix_columns_using_invmixer(inverse_substitute_bytes_using_invsbox(inverse_shift_rows(bitvector), will_use_genbox) ^ roundkeys[9 - i])

        if is_debug:
            print("Decryption output after round {}: {}".format(i+1, bitvector.get_bitvector_in_hex()))

    # round 10
    bitvector = inverse_substitute_bytes_using_invsbox(inverse_shift_rows(bitvector), will_use_genbox) ^ roundkeys[0]

    if is_debug:
        print("Decryption output after round {}: {}".format(10, bitvector.get_bitvector_in_hex()))

    # returning deciphered bitvector
    return bitvector

def generate_report(is_text_input):
    # reporting initial roundkey
    print("\nInitial roundkey [in ASCII]: {}".format(roundkeys[0].get_bitvector_in_ascii()))
    print("Initial roundkey [in Hex]: {}\n".format(roundkeys[0].get_bitvector_in_hex()))

    # reporting plaintext
    if is_text_input:
        print("Plaintext [in ASCII]: {}".format(AES_input.get_bitvector_in_ascii()[: len(AES_input.get_bitvector_in_ascii()) - pad_count_input]))
        print("Plaintext [in Hex]: {}\n".format(AES_input.get_bitvector_in_hex()[: len(AES_input.get_bitvector_in_hex()) - 2*pad_count_input]))

    # reporting ciphertext
    if is_text_input:
        print("Ciphertext [in ASCII]: {}".format(AES_output.get_bitvector_in_ascii()))
        print("Ciphertext [in Hex]: {}\n".format(AES_output.get_bitvector_in_hex()))

    # reporting deciphertext
    if is_text_input:
        print("Deciphered text [in ASCII]: {}".format(decipher_output.get_bitvector_in_ascii()[: len(decipher_output.get_bitvector_in_ascii()) - pad_count_input]))
        print("Deciphered text [in Hex]: {}\n".format(decipher_output.get_bitvector_in_hex()[: len(decipher_output.get_bitvector_in_hex()) - 2*pad_count_input]))

    # reporting execution time
    print("<Execution time>")
    print("Key scheduling time: {} seconds".format(key_scheduling_time))
    print("Encryption time: {} seconds".format(encryption_time))
    print("Decryption time: {} seconds".format(decryption_time))

# defining main functions
def do_task1(is_file_input, is_debug, will_use_genbox):
    global key_scheduling_time

    input_initial_roundkey(is_file_input)

    if will_use_genbox and not genSbox:
        generate_sbox()

    key_scheduling_time = time.time()
    schedule_roundkeys(will_use_genbox)
    key_scheduling_time = time.time() - key_scheduling_time

    if is_debug:
        print("Scheduled roundkeys:")

        for i in range(len(roundkeys)):
            print("Roundkey {}: {}".format(i, roundkeys[i].get_bitvector_in_hex()))

def do_task2(is_text_input, is_file_input, is_debug, will_use_genbox):
    if not roundkeys:
        print("ERROR: Do task1 first")
        return
    if is_text_input and not input_plaintext(is_file_input):
        print("ERROR: Empty input")
        return
    if not is_text_input and not input_file():
        print("ERROR: Empty input")
        return
    if will_use_genbox and not genSbox:
        generate_sbox()

    global AES_output, encryption_time

    encryption_time = time.time()

    for i in range(len(AES_input.get_bitvector_in_ascii()) // 16):
        AES_output += encrypt(BitVector(textstring=AES_input.get_bitvector_in_ascii()[i * 16: i * 16 + 16]), is_debug, will_use_genbox)

    encryption_time = time.time() - encryption_time

    if is_debug:
        print("Ciphered output: {}".format(AES_output.get_bitvector_in_hex()))

def do_task3(is_text_input, is_debug, will_use_genbox):
    if not roundkeys:
        print("ERROR: Do task1 first")
        return
    if AES_output.length() == 0:
        print("ERROR: Do task2 first")
        return
    if will_use_genbox and not genInvSbox:
        generate_invsbox()
    
    global decipher_output, decryption_time

    decryption_time = time.time()

    for i in range(len(AES_output.get_bitvector_in_hex()) // 32):
        decipher_output += decrypt(BitVector(hexstring=AES_output.get_bitvector_in_hex()[i * 32: i * 32 + 32]), is_debug, will_use_genbox)

    decryption_time = time.time() - decryption_time
        
    if is_text_input:
        if is_debug:
            print("Deciphered output: {}".format(decipher_output.get_bitvector_in_ascii()))
    else:
        output_file()

    generate_report(is_text_input)


"""
    This program implements Advanced Encryption Standard (AES) encryption-decryption algorithm for 128bits key.
    
    Inputs:
        1. `initial roundkey` to be used for key scheduling and subsequent encryption-decryption rounds (provided as user or file input).
        2. `AES input` to be encrypted and later decrypted. There are two types of input:
            - `plaintext` which is an ASCII text/string (provided as user or file input)
            - `file_content` which is byte/Hex string converted from a file (filename is provided by user).
            
    Outputs:
        1. a report is generated containing `initial roundkey`, `plaintext` (if applicable), `ciphertext`  (if applicable),
            `deciphered text` (if applicable), and execution times for key scheduling, encryption, and decryption stages.
        2. deciphered file is generated in case of file input (instead of text input).
    
    Caution:
        1. tasks should be done, that is, functions `do_task1`, `do_task2`, and `do_task3` should be called in order.
            Otherwise, no output will be generated.
        2. in case of file input, proper filename should be provided. Otherwise, error is generated.
        3. use condition variables (listed below) accordingly to generate expected output.
"""

# listing condition variables
# is_text_input => True: plaintext input; False: file input;
is_text_input = True

# is_file_input => True: file plaintext input; False: user plaintext input;
is_file_input = False

# is_debug => True: debugging messages will be printed; False: debugging messages will not be printed;
is_debug = False

# will_use_genbox => True: generated Sbox and InvSbox will be used; False: hardcoded Sbox and InvSbox will be used;
will_use_genbox = False

# key scheduling
do_task1(is_file_input, is_debug, will_use_genbox)

# encryption
do_task2(is_text_input, is_file_input, is_debug, will_use_genbox)

# decryption
do_task3(is_text_input, is_debug, will_use_genbox)
