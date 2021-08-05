from projectq import MainEngine
from projectq.ops import H, CNOT, Measure, Toffoli, X, All, Swap, Z
from projectq.backends import CircuitDrawer, ResourceCounter, CommandPrinter, ClassicalSimulator
from projectq.meta import Loop, Compute, Uncompute, Control

def DES(eng):

    plaintext = eng.allocate_qureg(64)
    key = eng.allocate_qureg(64)

    Round_constant_XOR(eng, plaintext, 0x10F10FECDECF0012)
    Round_constant_XOR(eng, key, 0x10F10FECDECF0012)

    P_table_1_1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
    P_table_1_2 = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

    C = []
    D = []

    for i in range(28):
        C.append(key[P_table_1_1[i]-1])
        D.append(key[P_table_1_2[i] - 1])

    plaintext = IP(eng, plaintext)

    L = []
    R = []
    for i in range(32):
        L.append(plaintext[i])
        R.append(plaintext[i+32])

    # 16-Round
    for i in range(16):

        C, D = LS(eng, C, D, i)
        temp = R
        R = F(eng, R, C, D)
        R = P(eng, R)
        XOR32(eng, R, L)

        #logical Swap
        R = L
        L = temp

    ciphertext = []
    for i in range(32):
        ciphertext.append(R[i])
    for i in range(32):
        ciphertext.append(L[i])

    ciphertext = Final(eng, ciphertext)

    print_cipher(eng, ciphertext)

def IP(eng, plaintext):

    index = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
          56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]

    new_p = []
    for i in range(64):
        new_p.append(plaintext[index[i]])

    return new_p

def Final(eng, plaintext):

    index = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33,  1, 41, 9, 49, 17, 57, 25]

    new_p = []
    for i in range(64):
        new_p.append(plaintext[index[i]-1])

    return new_p

def P(eng, plaintext):
    index = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

    new_p = []
    for i in range(32):
        new_p.append(plaintext[index[i]-1])

    return new_p

def F(eng, plaintext, C, D):

    result = []

    CNOT | (C[13], plaintext[31])
    CNOT | (C[16], plaintext[0])
    CNOT | (C[10], plaintext[1])
    CNOT | (C[23], plaintext[2])
    CNOT | (C[0], plaintext[3])
    CNOT | (C[4], plaintext[4])

    result[0:4] = S1(eng, plaintext)

    #reverse
    CNOT | (C[13], plaintext[31])
    CNOT | (C[16], plaintext[0])
    CNOT | (C[10], plaintext[1])
    CNOT | (C[23], plaintext[2])
    CNOT | (C[0], plaintext[3])
    CNOT | (C[4], plaintext[4])

    CNOT | (C[2], plaintext[3])
    CNOT | (C[27], plaintext[4])
    CNOT | (C[14], plaintext[5])
    CNOT | (C[5], plaintext[6])
    CNOT | (C[20], plaintext[7])
    CNOT | (C[9], plaintext[8])

    result[4:8] = S2(eng, plaintext)

    #reverse
    CNOT | (C[2], plaintext[3])
    CNOT | (C[27], plaintext[4])
    CNOT | (C[14], plaintext[5])
    CNOT | (C[5], plaintext[6])
    CNOT | (C[20], plaintext[7])
    CNOT | (C[9], plaintext[8])

    CNOT | (C[22], plaintext[7])
    CNOT | (C[18], plaintext[8])
    CNOT | (C[11], plaintext[9])
    CNOT | (C[3], plaintext[10])
    CNOT | (C[25], plaintext[11])
    CNOT | (C[7], plaintext[12])

    result[8:12] = S3(eng, plaintext)

    #reverse
    CNOT | (C[22], plaintext[7])
    CNOT | (C[18], plaintext[8])
    CNOT | (C[11], plaintext[9])
    CNOT | (C[3], plaintext[10])
    CNOT | (C[25], plaintext[11])
    CNOT | (C[7], plaintext[12])

    CNOT | (C[15], plaintext[11])
    CNOT | (C[6], plaintext[12])
    CNOT | (C[26], plaintext[13])
    CNOT | (C[19], plaintext[14])
    CNOT | (C[12], plaintext[15])
    CNOT | (C[1], plaintext[16])

    result[12:16] = S4(eng, plaintext)

    #reverse
    CNOT | (C[15], plaintext[11])
    CNOT | (C[6], plaintext[12])
    CNOT | (C[26], plaintext[13])
    CNOT | (C[19], plaintext[14])
    CNOT | (C[12], plaintext[15])
    CNOT | (C[1], plaintext[16])

    CNOT | (D[12], plaintext[15])
    CNOT | (D[23], plaintext[16])
    CNOT | (D[2], plaintext[17])
    CNOT | (D[8], plaintext[18])
    CNOT | (D[18], plaintext[19])
    CNOT | (D[26], plaintext[20])

    result[16:20] = S5(eng, plaintext)
    #reverse
    CNOT | (D[12], plaintext[15])
    CNOT | (D[23], plaintext[16])
    CNOT | (D[2], plaintext[17])
    CNOT | (D[8], plaintext[18])
    CNOT | (D[18], plaintext[19])
    CNOT | (D[26], plaintext[20])

    CNOT | (D[1], plaintext[19])
    CNOT | (D[11], plaintext[20])
    CNOT | (D[22], plaintext[21])
    CNOT | (D[16], plaintext[22])
    CNOT | (D[4], plaintext[23])
    CNOT | (D[19], plaintext[24])

    result[20:24] = S6(eng, plaintext)
    #reverse
    CNOT | (D[1], plaintext[19])
    CNOT | (D[11], plaintext[20])
    CNOT | (D[22], plaintext[21])
    CNOT | (D[16], plaintext[22])
    CNOT | (D[4], plaintext[23])
    CNOT | (D[19], plaintext[24])

    CNOT | (D[15], plaintext[23])
    CNOT | (D[20], plaintext[24])
    CNOT | (D[10], plaintext[25])
    CNOT | (D[27], plaintext[26])
    CNOT | (D[5], plaintext[27])
    CNOT | (D[24], plaintext[28])

    result[24:28] = S7(eng, plaintext)

    #reverse
    CNOT | (D[15], plaintext[23])
    CNOT | (D[20], plaintext[24])
    CNOT | (D[10], plaintext[25])
    CNOT | (D[27], plaintext[26])
    CNOT | (D[5], plaintext[27])
    CNOT | (D[24], plaintext[28])

    CNOT | (D[17], plaintext[27])
    CNOT | (D[13], plaintext[28])
    CNOT | (D[21], plaintext[29])
    CNOT | (D[7], plaintext[30])
    CNOT | (D[0], plaintext[31])
    CNOT | (D[3], plaintext[0])

    result[28:32] = S8(eng, plaintext)

    CNOT | (D[17], plaintext[27])
    CNOT | (D[13], plaintext[28])
    CNOT | (D[21], plaintext[29])
    CNOT | (D[7], plaintext[30])
    CNOT | (D[0], plaintext[31])
    CNOT | (D[3], plaintext[0])

    return result

def print_cipher(eng, x):

    All(Measure) | x
    print('\nCiphertext : \n')
    for i in range(16):
        for j in range(4):
            print(int(x[4*(i)+j]), end='')
        print(" ", end='')

def LS(eng, C, D, i):

    C_result = []
    D_result = []

    if(i==0 or i==1 or i==8 or i==15):

        for i in range(28):
            C_result.append(C[ (i+1) % 28])
        for i in range(28):
            D_result.append(D[ (i+1) % 28])

        return C_result, D_result

    else:

        for i in range(28):
            C_result.append(C[ (i+2) % 28])
        for i in range(28):
            D_result.append(D[ (i+2) % 28])

        return C_result, D_result


def S1(eng, plaintext):

    x = eng.allocate_qureg(56)
    a = []
    result = []
    a.append(plaintext[31])
    a.append(plaintext[0])
    a.append(plaintext[1])
    a.append(plaintext[2])
    a.append(plaintext[3])
    a.append(plaintext[4])

    TNOT(eng, a[2], a[4], x[0])
    CNOT2(eng, x[0], a[3], x[1])
    TNOT(eng, a[2], a[3], x[2])
    OR(eng, x[2], a[4], x[3])
    Toffoli | (a[5], x[3], x[4])
    CNOT2(eng, x[1], x[4], x[5])
    TNOT(eng, a[3], a[4], x[6])
    CNOT2(eng, a[2], a[3], x[7])
    TNOT(eng, a[5], x[7], x[8])
    CNOT2(eng, x[6], x[8], x[9])
    OR(eng, a[1], x[9], x[10])
    CNOT2(eng, x[5], x[10], x[11])
    CNOT2(eng, a[4], x[4], x[12])
    Toffoli | (x[12], x[7], x[13])
    TNOT(eng, a[4], a[3], x[14])
    CNOT2(eng, x[2], x[13], x[15])
    OR(eng, a[5], x[15], x[16])
    CNOT2(eng, x[14], x[16], x[17])
    OR(eng, a[1], x[17], x[18])
    CNOT2(eng, x[13], x[18], x[19])
    Toffoli | (a[0], x[19], x[20])
    XCNOT2(eng, x[11], x[20], x[21])
    #x[21] = result[1]

    OR(eng, x[0], x[4], x[22])
    CNOT2(eng, x[22], x[7], x[23])
    TNOT(eng, x[17], x[1], x[24])
    TNOT(eng, a[1], x[24], x[25])
    CNOT2(eng, x[23], x[25], x[26])
    OR(eng, x[5], x[6], x[27])
    CNOT2(eng, x[27], x[24], x[28])
    CNOT2(eng, x[8], x[23], x[29])
    TNOT(eng, x[17], x[29], x[30])
    Toffoli | (a[1], x[30], x[31])
    CNOT2(eng, x[28], x[31], x[32])
    Toffoli | (a[0], x[32], x[33])
    CNOT2(eng, x[26], x[33], x[34])
    #x[34] = result[3]

    Toffoli | (a[2], x[27], x[35])
    TNOT(eng, x[17], x[35], x[36])
    OR(eng, a[1], x[2], x[37])
    CNOT2(eng, x[36], x[37], x[38])
    OR(eng, a[2], x[30], x[39])
    TNOT(eng, x[23], x[36], x[40])
    OR(eng, x[40], x[2], x[41])
    TNOT(eng, x[41], a[1], x[42])
    CNOT2(eng, x[39], x[42], x[43])
    TNOT(eng, a[0], x[43], x[44])
    XCNOT2(eng, x[38], x[44], x[45])
    #x[45] = result[0]

    TNOT(eng, x[32], x[8], x[46])
    CNOT2(eng, x[46], x[38], x[47])
    CNOT2(eng, x[3], x[35], x[48])
    TNOT(eng, x[48], x[4], x[49])
    OR(eng, x[41], x[17], x[50])
    CNOT2(eng, x[50], a[4], x[51])
    TNOT(eng, a[1], x[51], x[52])
    CNOT2(eng, x[49], x[52], x[53])
    OR(eng, a[0], x[53], x[54])
    XCNOT2(eng, x[47], x[54], x[55])
    #x[55] = result[2]

    result.append(x[45])
    result.append(x[21])
    result.append(x[55])
    result.append(x[34])

    return result

def S2(eng, plaintext):

    x = eng.allocate_qureg(50)
    a = []
    result = []
    a.append(plaintext[3])
    a.append(plaintext[4])
    a.append(plaintext[5])
    a.append(plaintext[6])
    a.append(plaintext[7])
    a.append(plaintext[8])

    CNOT2(eng, a[0], a[5], x[0])
    CNOT2(eng, x[0], a[4], x[1])
    Toffoli | (a[5], a[4], x[2])
    TNOT(eng, a[0], x[2], x[3])
    TNOT(eng, a[1], x[3], x[4])
    CNOT2(eng, x[1], x[4], x[5])
    OR(eng, x[2], x[4], x[6])
    TNOT(eng, x[6], x[0], x[7])
    OR(eng, a[2], x[7], x[8])
    CNOT2(eng, x[5], x[8], x[9])
    TNOT(eng, a[4], x[3], x[10])
    OR(eng, x[10], a[1], x[11])
    Toffoli | (a[3], x[11], x[12])
    XCNOT2(eng, x[9], x[12], x[13])
    # result[0] = x[13]
    CNOT2(eng, x[3], x[13], x[14])
    TNOT(eng, x[14], a[1], x[15])
    CNOT2(eng, x[1], x[15], x[16])
    TNOT(eng, a[5], x[3], x[17])
    CNOT2(eng, x[5], x[10], x[18])
    Toffoli | (a[1], x[18], x[19])
    CNOT2(eng, x[17],x[19], x[20])
    Toffoli | (a[2], x[20], x[21])
    CNOT2(eng, x[16], x[21], x[22])
    CNOT2(eng, a[4], a[1], x[23])
    TNOT(eng, x[23], x[7], x[24])
    OR(eng, x[5], a[0], x[25])
    CNOT2(eng, x[25], a[1], x[26])
    TNOT(eng, a[2], x[26], x[27])
    CNOT2(eng, x[24], x[27], x[28])
    OR(eng, a[3], x[28], x[29])
    CNOT2(eng, x[22], x[29], x[30])
    # result[2], x[30]
    OR(eng, x[17], x[24], x[31])
    CNOT2(eng, x[31], x[9], x[32])
    OR(eng, x[26], x[19], x[33])
    Toffoli | (a[2], x[33], x[34])
    CNOT2(eng, x[32], x[34], x[35])
    Toffoli | (x[23], x[33], x[36])
    TNOT(eng, x[11], x[36], x[37])
    OR(eng, a[3], x[37], x[38])
    XCNOT2(eng, x[35], x[38], x[39])
    #result[3] = x[39]
    CNOT2(eng, a[1], x[1], x[40])
    TNOT(eng, x[40], x[32], x[41])
    CNOT2(eng, x[41], x[28], x[42])
    TNOT(eng, a[2], x[42], x[43])
    CNOT2(eng, x[40], x[43], x[44])
    OR(eng, x[2], x[19], x[45])
    Toffoli | (a[2], x[2], x[46])
    CNOT2(eng, x[45], x[46], x[47])
    TNOT(eng, a[3], x[47], x[48])
    XCNOT2(eng, x[44], x[48], x[49])
    # result[1] = x[49]

    result.append(x[13])
    result.append(x[49])
    result.append(x[30])
    result.append(x[39])

    return result

def S3(eng, plaintext):

    x = eng.allocate_qureg(54)
    a = []
    result = []

    a.append(3) # garbage
    a.append(plaintext[7])
    a.append(plaintext[8])
    a.append(plaintext[9])
    a.append(plaintext[10])
    a.append(plaintext[11])
    a.append(plaintext[12])

    CNOT2(eng, a[2], a[3], x[1])
    CNOT2(eng, x[1], a[6], x[2])
    Toffoli | (a[2], x[2], x[3])
    OR(eng, a[5], x[3], x[4])
    CNOT2(eng, x[2], x[4], x[5])
    CNOT2(eng, a[3], x[3], x[6])
    TNOT(eng, x[6], a[5], x[7])
    OR(eng, a[1], x[7], x[8])
    CNOT2(eng, x[5], x[8], x[9])
    TNOT(eng, a[6], x[3], x[10])
    CNOT2(eng, x[10], a[5], x[11])
    Toffoli | (a[1], x[11], x[12])
    CNOT2(eng, a[5], x[12], x[13])
    OR(eng, a[4], x[13], x[14])
    CNOT2(eng, x[9], x[14], x[15])
    # result[3] = x[15]
    Toffoli | (a[3], a[6], x[16])
    OR(eng, x[16], x[3], x[17])
    CNOT2(eng, x[17], a[5], x[18])
    TNOT(eng, x[2], x[7], x[19])
    CNOT2(eng, x[19], x[16], x[20])
    OR(eng, a[1], x[20], x[21])
    CNOT2(eng, x[18], x[21], x[22])
    OR(eng, a[2], x[7], x[23])
    CNOT2(eng, x[23], x[4], x[24])
    OR(eng, x[11], x[19], x[25])
    CNOT2(eng, x[25], x[17], x[26])
    OR(eng, a[1], x[26], x[27])
    CNOT2(eng, x[24], x[27], x[28])
    TNOT(eng, a[4], x[28], x[29])
    XCNOT2(eng, x[22], x[29], x[30])
    #result [2] = x[30]
    Toffoli | (a[3], a[5], x[31])
    CNOT2(eng, x[31], x[2], x[32])
    TNOT(eng, x[7], a[3], x[33])
    OR(eng, a[1], x[33], x[34])
    CNOT2(eng, x[32], x[34], x[35])
    OR(eng, x[10], x[26], x[36])
    CNOT2(eng, a[6], x[17], x[37])
    TNOT(eng, x[37], x[5], x[38])
    Toffoli | (a[1], x[38], x[39])
    CNOT2(eng, x[36], x[39], x[40])
    Toffoli | (a[4], x[40], x[41])
    CNOT2(eng, x[35], x[41], x[42])
    #result[1] = x[42]
    OR(eng, a[2], x[19], x[43])
    CNOT2(eng, x[43], x[18], x[44])
    Toffoli | (a[6], x[15], x[45])
    CNOT2(eng, x[45], x[6], x[46])
    TNOT(eng, x[46], a[1], x[47])
    CNOT2(eng, x[44], x[47], x[48])
    TNOT(eng, x[42], x[23], x[49])
    OR(eng, a[1], x[49], x[50])
    CNOT2(eng, x[47], x[50], x[51])
    Toffoli | (a[4], x[51], x[52])
    XCNOT2(eng, x[48], x[52], x[53])
    #result[0] = x[53]

    result.append(x[53])
    result.append(x[42])
    result.append(x[30])
    result.append(x[15])

    return result

def S4(eng, plaintext):

    x = eng.allocate_qureg(40)
    a = []
    result = []

    a.append(3) # garbage
    a.append(plaintext[11])
    a.append(plaintext[12])
    a.append(plaintext[13])
    a.append(plaintext[14])
    a.append(plaintext[15])
    a.append(plaintext[16])

    OR(eng, a[1], a[3], x[1])
    Toffoli |(a[5], x[1], x[2])
    CNOT2(eng, a[1], x[2], x[3])
    OR(eng, a[2], a[3], x[4])
    CNOT2(eng, x[3], x[4], x[5])
    TNOT(eng, a[3], a[1], x[6])
    OR(eng, x[6], x[3], x[7])
    Toffoli | (a[2], x[7], x[8])
    CNOT2(eng, a[5], x[8], x[9])
    Toffoli | (a[4], x[9], x[10])
    CNOT2(eng, x[5], x[10], x[11])
    CNOT2(eng, a[3], x[2], x[12])
    TNOT(eng, a[2], x[12], x[13])
    CNOT2(eng, x[7], x[13], x[14])
    OR(eng, x[12], x[3], x[15])
    CNOT2(eng, a[3], a[5], x[16])
    TNOT(eng, x[16], a[2], x[17])
    CNOT2(eng, x[15], x[17], x[18])
    OR(eng, a[4], x[18], x[19])
    CNOT2(eng, x[14], x[19], x[20])
    OR(eng, a[6], x[20], x[21])
    CNOT2(eng, x[11], x[21], x[22])
    #result[0] = x[22]
    Toffoli | (a[6], x[20], x[23])
    XCNOT2(eng, x[23], x[11], x[24])
    #reuslt[1] = x[24]
    Toffoli | (a[2], x[9], x[25])
    CNOT2(eng, x[25], x[15], x[26])
    CNOT2(eng, a[3], x[8], x[27])
    CNOT2(eng, x[27], x[17], x[28])
    TNOT(eng, a[4], x[28], x[29])
    CNOT2(eng, x[26], x[29], x[30])
    CNOT2(eng, x[11], x[30], x[31])
    TNOT(eng, a[2], x[31], x[32])
    CNOT2(eng, x[22], x[32], x[33])
    TNOT(eng, x[31], a[4], x[34])
    CNOT2(eng, x[33], x[34], x[35])
    OR(eng, a[6], x[35], x[36])
    XCNOT2(eng, x[30], x[36], x[37])
    #result[2] = x[37]
    CNOT2(eng, x[23], x[35], x[38])
    CNOT2(eng, x[38], x[37], x[39])


    result.append(x[22])
    result.append(x[24])
    result.append(x[37])
    result.append(x[39])

    return result

def S5(eng, plaintext):

    x = eng.allocate_qureg(57)
    a = []
    result = []


    a.append(3) # garbage
    a.append(plaintext[15])
    a.append(plaintext[16])
    a.append(plaintext[17])
    a.append(plaintext[18])
    a.append(plaintext[19])
    a.append(plaintext[20])

    TNOT(eng, a[3], a[4], x[1])
    CNOT2(eng, x[1], a[1], x[2])
    TNOT(eng, a[1], a[3], x[3])
    OR(eng, a[6], x[3], x[4])
    CNOT2(eng, x[2], x[4], x[5])
    CNOT2(eng, a[4], a[1], x[6])
    OR(eng, x[6], x[1], x[7])
    TNOT(eng, x[7], a[6], x[8])
    CNOT2(eng, a[3], x[8], x[9])
    OR(eng, a[5], x[9], x[10])
    CNOT2(eng, x[5], x[10], x[11])
    Toffoli | (a[3], x[7], x[12])
    CNOT2(eng, x[12], a[4], x[13])
    TNOT(eng, x[13], x[3], x[14])
    CNOT2(eng, a[4], x[3], x[15])
    OR(eng, a[6], x[15], x[16])
    CNOT2(eng, x[14], x[16], x[17])
    OR(eng, a[5], x[17], x[18])
    CNOT2(eng, x[13], x[18], x[19])
    TNOT(eng, x[19], a[2], x[20])
    CNOT2(eng, x[11], x[20], x[21])
    #result[3] = x[21]
    Toffoli | (a[4], x[4], x[22])
    CNOT2(eng, x[22], x[17], x[23])
    CNOT2(eng, a[1], x[9], x[24])
    Toffoli | (x[2], x[24], x[25])
    TNOT(eng, a[5], x[25], x[26])
    CNOT2(eng, x[23], x[26], x[27])
    OR(eng, a[4], x[24], x[28])
    TNOT(eng, x[28], a[2], x[29])
    CNOT2(eng, x[27], x[29], x[30])
    #result[1] = x[30]
    Toffoli | (x[17], x[5], x[31])
    TNOT(eng, x[7], x[31], x[32])
    TNOT(eng, x[8], a[4], x[33])
    CNOT2(eng, x[33], a[3], x[34])
    Toffoli | (a[5], x[34], x[35])
    CNOT2(eng, x[32], x[35], x[36])
    OR(eng, x[13], x[16], x[37])
    CNOT2(eng, x[9], x[31], x[38])
    OR(eng, a[5], x[38], x[39])
    CNOT2(eng, x[37], x[39], x[40])
    OR(eng, a[2], x[40], x[41])
    XCNOT2(eng, x[36], x[41], x[42])
    #result[2] = x[42]
    TNOT(eng, x[19], x[32], x[43])
    CNOT2(eng, x[43], x[24], x[44])
    OR(eng, x[27], x[43], x[45])
    CNOT2(eng, x[45], x[6], x[46])
    TNOT(eng, a[5], x[46], x[47])
    CNOT2(eng, x[44], x[47], x[48])
    Toffoli | (x[6], x[38], x[49])
    CNOT2(eng, x[49], x[34], x[50])
    CNOT2(eng, x[21], x[38], x[51])
    TNOT(eng, x[28], x[51], x[52])
    Toffoli | (a[5], x[52], x[53])
    CNOT2(eng, x[50], x[53], x[54])
    OR(eng, a[2], x[54], x[55])
    CNOT2(eng, x[48], x[55], x[56])
    #result[0] = x[56]

    result.append(x[56])
    result.append(x[30])
    result.append(x[42])
    result.append(x[21])

    return result

def S6(eng, plaintext):

    #110011
    x = eng.allocate_qureg(54)
    a = []
    result = []
    a.append(3) # garbage


    a.append(plaintext[19])
    a.append(plaintext[20])
    a.append(plaintext[21])
    a.append(plaintext[22])
    a.append(plaintext[23])
    a.append(plaintext[24])

    CNOT2(eng, a[5], a[1], x[1])
    CNOT2(eng, x[1], a[6], x[2])
    Toffoli | (a[1], a[6], x[3])
    TNOT(eng, x[3], a[5], x[4])
    TNOT(eng, a[4], x[4], x[5])
    CNOT2(eng, x[2], x[5], x[6])
    CNOT2(eng, a[6], x[3], x[7])
    OR(eng, x[4], x[7], x[8])
    TNOT(eng, x[8], a[4], x[9])
    CNOT2(eng, x[7], x[9], x[10])
    Toffoli | (a[2], x[10], x[11])
    CNOT2(eng, x[6], x[11], x[12])
    OR(eng, a[6], x[6], x[13])
    TNOT(eng, x[13], a[5], x[14])
    OR(eng, x[4], x[10], x[15])
    TNOT(eng, a[2], x[15], x[16])
    CNOT2(eng, x[14], x[16], x[17])
    TNOT(eng, x[17], a[3], x[18])
    XCNOT2(eng, x[12], x[18], x[19])
    #result[0] = x[19]
    TNOT(eng, x[19], x[1], x[20])
    CNOT2(eng, x[20], x[15], x[21])
    TNOT(eng, a[6], x[21], x[22])
    CNOT2(eng, x[22], x[6], x[23])
    TNOT(eng, a[2], x[23], x[24])
    CNOT2(eng, x[21], x[24], x[25])
    OR(eng, a[5], a[6], x[26])
    TNOT(eng, x[26], x[1], x[27])
    TNOT(eng, a[2], x[24], x[28])
    CNOT2(eng, x[27], x[28], x[29])
    TNOT(eng, a[3], x[29], x[30])
    XCNOT2(eng, x[25], x[30], x[31])
    #result[3] = x[31]
    CNOT2(eng, x[3], x[6], x[32])
    TNOT(eng, x[32], x[10], x[33])
    CNOT2(eng, a[6], x[25], x[34])
    TNOT(eng, a[5], x[34], x[35])
    TNOT(eng, a[2], x[35], x[36])
    CNOT2(eng, x[33], x[36], x[37])
    TNOT(eng, x[21], a[5], x[38])
    OR(eng, a[3], x[38], x[39])
    XCNOT2(eng, x[37], x[39], x[40])
    #result[2] = x[40]
    OR(eng, x[35], x[2], x[41])
    Toffoli | (a[5], x[7], x[42])
    TNOT(eng, a[4], x[42], x[43])
    OR(eng, a[2], x[43], x[44])
    CNOT2(eng, x[41], x[44], x[45])
    OR(eng, x[23], x[35], x[46])
    CNOT2(eng, x[46], x[5], x[47])
    Toffoli | (x[26], x[33], x[48])
    CNOT2(eng, x[48], x[2], x[49])
    Toffoli | (a[2], x[49], x[50])
    CNOT2(eng, x[47], x[50], x[51])
    TNOT(eng, a[3], x[51], x[52])
    XCNOT2(eng, x[45], x[52], x[53])

    #result[1] = x[53]

    result.append(x[19])
    result.append(x[53])
    result.append(x[40])
    result.append(x[31])

    return result

def S7(eng, plaintext):

    x = eng.allocate_qureg(52)
    a = []
    result = []

    a.append(3) # garbage
    a.append(plaintext[23])
    a.append(plaintext[24])
    a.append(plaintext[25])
    a.append(plaintext[26])
    a.append(plaintext[27])
    a.append(plaintext[28])

    # d 나왓음, F 나와야함
    Toffoli | (a[2], a[4], x[1])
    CNOT2(eng, x[1], a[5], x[2])
    Toffoli | (a[4], x[2], x[3])
    CNOT2(eng, x[3], a[2], x[4])
    TNOT(eng, a[3], x[4], x[5])
    CNOT2(eng, x[2], x[5], x[6])
    CNOT2(eng, a[3], x[5], x[7])
    TNOT(eng, a[6], x[7], x[8])
    CNOT2(eng, x[6], x[8], x[9])
    OR(eng, a[2], a[4], x[10])
    OR(eng, x[10], a[5], x[11])
    TNOT(eng, a[5], a[2], x[12])
    OR(eng, a[3], x[12], x[13])
    CNOT2(eng, x[11], x[13], x[14])
    CNOT2(eng, x[3], x[6], x[15])
    OR(eng, a[6], x[15], x[16])
    CNOT2(eng, x[14], x[16], x[17])
    Toffoli | (a[1], x[17], x[18])
    CNOT2(eng, x[9], x[18], x[19])
    #result[0] = x[19]
    TNOT(eng, a[4], a[3], x[20])
    TNOT(eng, a[2], x[20], x[21])
    Toffoli | (a[6], x[21], x[22])
    CNOT2(eng, x[9], x[22], x[23])
    CNOT2(eng, a[4], x[4], x[24])
    OR(eng, a[3], x[3], x[25])
    CNOT2(eng, x[24], x[25], x[26])
    CNOT2(eng, a[3], x[3], x[27])
    Toffoli | (x[27], a[2], x[28])
    TNOT(eng, a[6], x[28], x[29])
    CNOT2(eng, x[26], x[29], x[30])
    OR(eng, a[1], x[30], x[31])
    XCNOT2(eng, x[23], x[31], x[32])
    #result[1] = x[32]
    CNOT2(eng, x[7], x[30], x[33])
    OR(eng, a[2], x[24], x[34])
    CNOT2(eng, x[34], x[19], x[35])
    TNOT(eng, x[35], a[6], x[36])
    CNOT2(eng, x[33], x[36], x[37])
    TNOT(eng, x[26], a[3], x[38])
    OR(eng, x[38], x[30], x[39])
    TNOT(eng, x[39], a[1], x[40])
    CNOT2(eng, x[37], x[40], x[41])
    #result[2] = x[41]
    OR(eng, a[5], x[20], x[42])
    CNOT2(eng, x[42], x[33], x[43])
    CNOT2(eng, a[2], x[15], x[44])
    TNOT(eng, x[24], x[44], x[45])
    Toffoli | (a[6], x[45], x[46])
    CNOT2(eng, x[43], x[46], x[47])
    Toffoli | (a[3], x[22], x[48])
    CNOT2(eng, x[48], x[46], x[49])
    OR(eng, a[1], x[49], x[50])
    CNOT2(eng, x[47], x[50], x[51])
    #result[3] = x[51]

    result.append(x[19])
    result.append(x[32])
    result.append(x[41])
    result.append(x[51])


    return result

def S8(eng, plaintext):

    x = eng.allocate_qureg(51)
    a = []
    result = []

    a.append(3) # garbage
    a.append(plaintext[27])
    a.append(plaintext[28])
    a.append(plaintext[29])
    a.append(plaintext[30])
    a.append(plaintext[31])
    a.append(plaintext[0])


    CNOT2(eng, a[3], a[1], x[1])
    TNOT(eng, a[1], a[3], x[2])
    CNOT2(eng, x[2], a[4], x[3])
    OR(eng, a[5], x[3], x[4])
    CNOT2(eng, x[1], x[4], x[5])
    TNOT(eng, x[5], a[1], x[6])
    CNOT2(eng, x[6], a[3], x[7])
    TNOT(eng, x[7], a[5], x[8])
    CNOT2(eng, a[4], x[8], x[9])
    TNOT(eng, a[2], x[9], x[10])
    CNOT2(eng, x[5], x[10], x[11])
    OR(eng, x[6], a[4], x[12])
    CNOT2(eng, x[12], x[1], x[13])
    CNOT2(eng, x[13], a[5], x[14])
    TNOT(eng, x[3], x[14], x[15])
    CNOT2(eng, x[15], x[7], x[16])
    TNOT(eng, a[2], x[16], x[17])
    CNOT2(eng, x[14], x[17], x[18])
    OR(eng, a[6], x[18], x[19])
    XCNOT2(eng, x[11], x[19], x[20])
    #result[0] = x[20]
    OR(eng, x[5], a[5], x[21])
    CNOT2(eng, x[21], x[3], x[22])
    TNOT(eng, x[11], a[4], x[23])
    TNOT(eng, a[2], x[23], x[24])
    CNOT2(eng, x[22], x[24], x[25])
    Toffoli | (a[1], x[21], x[26])
    Toffoli | (a[5], x[2], x[27])
    CNOT2(eng, x[27], x[23], x[28])
    Toffoli | (a[2], x[28], x[29])
    CNOT2(eng, x[26], x[29], x[30])
    TNOT(eng, x[30], a[6], x[31])
    CNOT2(eng, x[25], x[31], x[32])
    #reulst[2] = x[32]
    TNOT(eng, a[3], x[16], x[33])
    OR(eng, x[9], x[33], x[34])
    OR(eng, a[2], x[6], x[35])
    CNOT2(eng, x[34], x[35], x[36])
    TNOT(eng, x[2], x[14], x[37])
    OR(eng, x[22], x[32], x[38])
    TNOT(eng, a[2], x[38], x[39])
    CNOT2(eng, x[37], x[39], x[40])
    OR(eng, a[6], x[40], x[41])
    XCNOT2(eng, x[36], x[41], x[42])
    #result[1] = x[42]
    TNOT(eng, x[1], a[5], x[43])
    OR(eng, x[43], a[4], x[44])
    CNOT2(eng, a[3], a[5], x[45])
    CNOT2(eng, x[45], x[37], x[46])
    TNOT(eng, x[46], a[2], x[47])
    CNOT2(eng, x[44], x[47], x[48])
    Toffoli | (a[6], x[48], x[49])
    XCNOT2(eng, x[11], x[49], x[50])
    #result[3] = x[50]

    result.append(x[20])
    result.append(x[42])
    result.append(x[32])
    result.append(x[50])

    return result


def OR(eng, a, b, c):
    X | a
    X | b
    Toffoli | (a, b, c)
    X | c
    X | a
    X | b

def CNOT2(eng, a, b, c):
    CNOT | (a, c)
    CNOT | (b, c)

def XCNOT2(eng, a, b, c):
    CNOT | (a, c)
    CNOT | (b, c)
    X | c

def TNOT(eng, a, b, c):
    X | b
    Toffoli | (a, b, c)
    X | b

def XOR32(eng, a, b):
    for i in range(32):
        CNOT | (a[i], b[i])


def Round_constant_XOR(eng, k, rc):
    for i in range(64):
        if((rc << i) & 0x8000000000000000):
             X | k[i]


###################
Engine = ClassicalSimulator()
eng = MainEngine(Engine)
DES(eng)
eng.flush()
print('\n')

Resource = ResourceCounter()
eng = MainEngine(Resource)
DES(eng)
print(Resource)
eng.flush()