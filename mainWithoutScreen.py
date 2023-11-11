alphabet = \
    {
        'а': 100, 'б': 101, 'в': 102, 'г': 103, 'д': 104, 'е': 105, 'є': 106, 'ж': 107, 'з': 108, 'и': 109, 'і': 110,
        'ї': 111, 'й': 112, 'к': 113, 'л': 114, 'м': 115, 'н': 116, 'о': 117, 'п': 118, 'р': 119, 'с': 120, 'т': 121,
        'у': 122, 'ф': 123, 'х': 124, 'ц': 125, 'ч': 126, 'ш': 127, 'щ': 128, 'ь': 129, 'ю': 130, 'я': 131, ' ': 132,
        '\n': 133, '.': 134, ',': 135, ':': 136, '!': 137, '?': 138, '%': 139, '#': 140, '@': 141, '№': 142, ';': 143,
        '^': 144, '*': 145, '(': 146, ')': 147, '-': 148, '+': 149, '=': 150, '_': 151, '<': 152, '>': 153, '{': 154,
        '}': 155, '[': 156, ']': 157, '|': 158, '/': 159, '`': 160, '~': 161, '\'': 162, '"': 163, '\\': 164, '$': 165,
        '&': 166, 'a': 167, 'b': 168, 'c': 169, 'd': 170, 'e': 171, 'f': 172, 'g': 173, 'h': 174, 'i': 175, 'j': 176,
        'k': 177, 'l': 178, 'm': 179, 'n': 180, 'o': 181, 'p': 182, 'q': 183, 'r': 184, 's': 185, 't': 186, 'u': 187,
        'v': 188, 'w': 189, 'x': 190, 'y': 191, 'z': 192, 'А': 193, 'Б': 194, 'В': 195, 'Г': 196, 'Ґ': 197, 'Д': 198,
        'Е': 199, 'Є': 200, 'Ж': 201, 'З': 202, 'И': 203, 'І': 204, 'Ї': 205, 'Й': 206, 'К': 207, 'Л': 208, 'М': 209,
        'Н': 210, 'О': 211, 'П': 212, 'Р': 213, 'С': 214, 'Т': 215, 'У': 216, 'Ф': 217, 'Х': 218, 'Ц': 219, 'Ч': 220,
        'Ш': 221, 'Щ': 222, 'Ь': 223, 'Ю': 224, 'A': 225, 'B': 226, 'C': 227, 'D': 228, 'E': 229, 'F': 230, 'G': 231,
        'H': 232, 'I': 233, 'J': 234, 'K': 235, 'L': 236, 'M': 237, 'N': 238, 'O': 239, 'P': 240, 'Q': 241, 'R': 242,
        'S': 243, 'T': 244, 'U': 245, 'V': 246, 'W': 247, 'X': 248, 'Y': 249, 'Z': 250, '1': 251, '2': 252, '3': 253,
        '4': 254, '5': 255, '6': 256, '7': 257, '8': 258, '9': 259, '0': 260, '—': 261, '−': 262, '«': 263, '»': 264,
        'ґ': 265, 'Я': 266
    }

decrypted_alphabet = \
    {
        '100': 'а', '101': 'б', '102': 'в', '103': 'г', '104': 'д', '105': 'е', '106': 'є', '107': 'ж', '108': 'з',
        '109': 'и', '110': 'і', '111': 'ї', '112': 'й', '113': 'к', '114': 'л', '115': 'м', '116': 'н', '117': 'о',
        '118': 'п', '119': 'р', '120': 'с', '121': 'т', '122': 'у', '123': 'ф', '124': 'х', '125': 'ц', '126': 'ч',
        '127': 'ш', '128': 'щ', '129': 'ь', '130': 'ю', '131': 'я', '132': ' ', '133': '\n', '134': '.', '135': ',',
        '136': ':', '137': '!', '138': '?', '139': '%', '140': '#', '141': '@', '142': '№', '143': ';', '144': '^',
        '145': '*', '146': '(', '147': ')', '148': '-', '149': '+', '150': '=', '151': '_', '152': '<', '153': '>',
        '154': '{', '155': '}', '156': '[', '157': ']', '158': '|', '159': '/', '160': '`', '161': '~', '162': '\'',
        '163': '"', '164': '\\', '165': '$', '166': '&', '167': 'a', '168': 'b', '169': 'c', '170': 'd', '171': 'e',
        '172': 'f', '173': 'g', '174': 'h', '175': 'i', '176': 'j', '177': 'k', '178': 'l', '179': 'm', '180': 'n',
        '181': 'o', '182': 'p', '183': 'q', '184': 'r', '185': 's', '186': 't', '187': 'u', '188': 'v', '189': 'w',
        '190': 'x', '191': 'y', '192': 'z', '193': 'А', '194': 'Б', '195': 'В', '196': 'Г', '197': 'ґ', '198': 'Д',
        '199': 'Е', '200': 'Є', '201': 'Ж', '202': 'З', '203': 'И', '204': 'І', '205': 'Ї', '206': 'Й', '207': 'К',
        '208': 'Л', '209': 'М', '210': 'Н', '211': 'О', '212': 'П', '213': 'Р', '214': 'С', '215': 'Т', '216': 'У',
        '217': 'Ф', '218': 'Х', '219': 'Ц', '220': 'Ч', '221': 'Ш', '222': 'Щ', '223': 'Ь', '224': 'Ю', '225': 'A',
        '226': 'B', '227': 'C', '228': 'D', '229': 'E', '230': 'F', '231': 'G', '232': 'H', '233': 'I', '234': 'J',
        '235': 'K', '236': 'L', '237': 'M', '238': 'N', '239': 'O', '240': 'P', '241': 'Q', '242': 'R', '243': 'S',
        '244': 'T', '245': 'U', '246': 'V', '247': 'W', '248': 'X', '249': 'Y', '250': 'Z', '251': '1', '252': '2',
        '253': '3', '254': '4', '255': '5', '256': '6', '257': '7', '258': '8', '259': '9', '260': '0', '261': '—',
        '262': '−', '263': '«', '264': '»', '265': 'ґ', '266': 'Я'
    }


def crypt(encrypted_string):
    cryptet_string = ""
    for char in encrypted_string:
        if char in alphabet:
            cryptet_string += str(alphabet[char])
        else:
            return "null"

    return cryptet_string


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def decrypt(crypted_text):
    encrypted_text = ""
    for i in range(0, len(crypted_text), 3):
        value_to_find = crypted_text[i: (i + 3)]
        encrypted_text += str(decrypted_alphabet[value_to_find])
    return encrypted_text


if __name__ == '__main__':
    type_of_work = input("Введіть тип роботи( 1 - кодування, 2 - декодування): ")
    if type_of_work == '1':
        user_input = input("Введіть рядок для шифрування: ")

        cryptet_text = crypt(user_input)
        if (len(cryptet_text) == 0 or len(cryptet_text) == 1 or cryptet_text == "null"):
            print(f"Введений рядок '{user_input}' не відповідає умовам шифрування")
            exit()

        p1 = int(input("Введіть p1 = "))
        p2 = int(input("Введіть p2 = "))
        p3 = int(input("Введіть p3 = "))
        # p1 = 135789
        # p2 = 195437
        # p3 = 3456785

        gcd_p1_p2_p3 = 0
        while gcd_p1_p2_p3 == 0:
            if (gcd(p1, p2) == 1 and gcd(p1, p3) == 1 and gcd(p2,
                                                              p3) == 1 and p1 > 100000 and p1 < 20000000 and p2 > 100000 and p2 < 20000000 and p3 > 100000 and p3 < 20000000):
                gcd_p1_p2_p3 = 1
                print(f"p1 = {p1}, p2 = {p2} і p3 = {p3} є старшими ключами і є взаємопростими числами.")
            elif p1 < 100000 or p1 > 20000000 or p2 < 100000 or p2 > 20000000 or p3 < 100000 or p3 > 20000000:
                print("Вони не входять в діапазон від 100000 до 20000000. Введіть наново")
                p1 = int(input("Введіть p1 = "))
                p2 = int(input("Введіть p2 = "))
                p3 = int(input("Введіть p3 = "))
                # p1 = 135789
                # p2 = 195437
                # p3 = 3456785
            else:
                print("Вони не є взаємопростими числами. Введіть наново")
                p1 = int(input("Введіть p1 = "))
                p2 = int(input("Введіть p2 = "))
                p3 = int(input("Введіть p3 = "))
                # p1 = 135789
                # p2 = 195437
                # p3 = 3456785

        q1 = int(input("Введіть q1 = "))
        q2 = int(input("Введіть q2 = "))
        q3 = int(input("Введіть q3 = "))
        # q1 = 187
        # q2 = 355
        # q3 = 489
        gcd_q1_q2_q3 = 0

        while gcd_q1_q2_q3 == 0:
            if (gcd(q1, q2) == 1 and gcd(q1, q3) == 1 and gcd(q2,
                                                              q3) == 1 and q1 > 100 and q1 < 900 and q2 > 100 and q2 < 900 and q3 > 100 and q3 < 900):
                gcd_q1_q2_q3 = 1
                print(f"q1 = {q1}, q2 = {q2} і q3 = {q3} є ключами другого рівня і є взаємопростими числами.")
            elif (q1 < 100 or q1 > 900 or q2 < 100 or q2 > 900 or q3 < 100 or q3 > 900):
                print("Вони не входять в діапазон від 100 до 900. Введіть наново")
                q1 = int(input("Введіть q1 = "))
                q2 = int(input("Введіть q2 = "))
                q3 = int(input("Введіть q3 = "))
                # q1 = 187
                # q2 = 355
                # q3 = 489
            else:
                print("Вони не є взаємопростими числами. Введіть наново")
                q1 = int(input("Введіть q1 = "))
                q2 = int(input("Введіть q2 = "))
                q3 = int(input("Введіть q3 = "))
                # q1 = 187
                # q2 = 355
                # q3 = 489

        q4 = int(input("Введіть q4 = "))
        q5 = int(input("Введіть q5 = "))
        q6 = int(input("Введіть q6 = "))
        # q4 = 731
        # q5 = 574
        # q6 = 199

        gcd_q4_q5_q5 = 0
        while gcd_q4_q5_q5 == 0:
            if gcd(q4, q5) == 1 and gcd(q4, q6) == 1 and gcd(q5,
                                                             q6) == 1 and q1 != q4 and q1 != q5 and q1 != q6 and q2 != q4 and q1 != q5 and q1 != q6 and q3 != q4 and q3 != q5 and q1 != q6 and q4 > 100 and q4 < 900 and q5 > 100 and q5 < 900 and q6 > 100 and q6 < 900:
                gcd_q4_q5_q5 = 1
                print(f"q4 = {q4}, q5 = {q5} і q6 = {q6} є ключами другого рівня і є взаємопростими числами.")
            elif q4 < 100 or q4 > 900 or q5 < 100 or q5 > 900 or q6 < 100 or q6 > 900:
                print("Вони не входять в діапазон від 100 до 900. Введіть наново")
                q4 = int(input("Введіть q4 = "))
                q5 = int(input("Введіть q5 = "))
                q6 = int(input("Введіть q6 = "))
                # q4 = 731
                # q5 = 574
                # q6 = 199
            else:
                print("Вони не є взаємопростими числами. Введіть наново")
                q4 = int(input("Введіть q4 = "))
                q5 = int(input("Введіть q5 = "))
                q6 = int(input("Введіть q6 = "))
                # q4 = 731
                # q5 = 574
                # q6 = 199

        q7 = int(input("Введіть q7 = "))
        q8 = int(input("Введіть q8 = "))
        q9 = int(input("Введіть q9 = "))
        # q7 = 389
        # q8 = 591
        # q9 = 292

        gcd_q7_q8_q9 = 0
        while gcd_q7_q8_q9 == 0:
            if gcd(q7, q8) == 1 and gcd(q7, q9) == 1 and gcd(q8,
                                                             q9) == 1 and q4 != q7 and q4 != q8 and q4 != q9 and q5 != q7 and q5 != q8 and q5 != q9 and q6 != q7 and q6 != q8 and q6 != q9 and q7 > 100 and q7 < 900 and q8 > 100 and q8 < 900 and q9 > 100 and q9 < 900:
                gcd_q7_q8_q9 = 1
                print(f"q7 = {q7}, q8 = {q8} і q9 = {q9} є ключами другого рівня і є взаємопростими числами.")
            elif q7 < 100 or q7 > 900 or q8 < 100 or q8 > 900 or q9 < 100 or q9 > 900:
                print("Вони не входять в діапазон від 100 до 900. Введіть наново")
                q7 = int(input("Введіть q7 = "))
                q8 = int(input("Введіть q8 = "))
                q9 = int(input("Введіть q9 = "))
                # q7 = 389
                # q8 = 591
                # q9 = 292
            else:
                print("Вони не є взаємопростими числами. Введіть наново")
                q7 = int(input("Введіть q7 = "))
                q8 = int(input("Введіть q8 = "))
                q9 = int(input("Введіть q9 = "))
                # q7 = 389
                # q8 = 591
                # q9 = 292

        list_of_list_of_b = []

        while (len(cryptet_text) > 0):
            b_cryptet_text = int(cryptet_text[0:15])
            b1 = int(b_cryptet_text) % p1
            b2 = int(b_cryptet_text) % p2
            b3 = int(b_cryptet_text) % p3

            b11 = b1 % q1
            b12 = b1 % q2
            b13 = b1 % q3

            b24 = b2 % q4
            b25 = b2 % q5
            b26 = b2 % q6

            b37 = b3 % q7
            b38 = b3 % q8
            b39 = b3 % q9
            list_of_b = [b11, b12, b13, b24, b25, b26, b37, b38, b39]
            cryptet_text = cryptet_text[15:]
            list_of_list_of_b.append(list_of_b)

        with open("crypted_text.txt", "w") as file:
            for i in range(len(list_of_list_of_b)):
                b11 = list_of_list_of_b[i][0]
                b12 = list_of_list_of_b[i][1]
                b13 = list_of_list_of_b[i][2]
                b24 = list_of_list_of_b[i][3]
                b25 = list_of_list_of_b[i][4]
                b26 = list_of_list_of_b[i][5]
                b37 = list_of_list_of_b[i][6]
                b38 = list_of_list_of_b[i][7]
                b39 = list_of_list_of_b[i][8]
                crypted_str = f"{b11}, {b12}, {b13}, {b24}, {b25}, {b26}, {b37}, {b38}, {b39}"
                if i != len(list_of_list_of_b) - 1:
                    file.write(crypted_str + ", ")
                else:
                    file.write(crypted_str)

        list_of_p = [p1, p2, p3]
        list_of_q = [q1, q2, q3, q4, q5, q6, q7, q8, q9]
        print("Зашифровані дані для передач: ")
        print(f"p1 = {p1}, p2 = {p2} і p3 = {p3}")
        print(f"q1 = {q1}, q2 = {q2} і q3 = {q3}, q4 = {q4}, q5 = {q5}, q6 = {q6}, q7 = {q7}, q8 = {q8} і q9 = {q9}")
        print(f"Криптотекст: {list_of_list_of_b}")

    elif type_of_work == '2':
        list_of_p = []
        for i in range(3):
            while True:
                try:
                    p_i = int(input(f"p{i + 1} = "))
                    if 100000 <= p_i <= 20000000:
                        list_of_p.append(p_i)
                        break
                    else:
                        print(
                            "Введене число не знаходиться в потрібному діапазоні(100000 - 20000000). Спробуйте ще раз.")
                except ValueError:
                    print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
        p1 = list_of_p[0]
        p2 = list_of_p[1]
        p3 = list_of_p[2]
        while (gcd(list_of_p[0], list_of_p[1]) != 1 and gcd(list_of_p[0], list_of_p[2]) != 1 and gcd(list_of_p[1],
                                                                                                     list_of_p[
                                                                                                         2]) != 1):
            print("Числа не взмаємопрості")
            for i in range(3):
                while True:
                    try:
                        p_i = int(input(f"p{i + 1} = "))
                        if 100000 <= p_i <= 20000000:
                            list_of_p.append(p_i)
                            break
                        else:
                            print(
                                "Введене число не знаходиться в потрібному діапазоні(100000 - 20000000). Спробуйте ще раз.")
                    except ValueError:
                        print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
            p1 = list_of_p[0]
            p2 = list_of_p[1]
            p3 = list_of_p[2]
        print(f"p1 = {p1}, p2 = {p2} і p3 = {p3}")

        list_of_q = []
        for i in range(3):
            while True:
                try:
                    q_i = int(input(f"q{i + 1} = "))
                    if 100 <= q_i <= 900:
                        list_of_q.append(q_i)
                        break
                    else:
                        print("Введене число не знаходиться в потрібному діапазоні(100 - 900). Спробуйте ще раз.")
                except ValueError:
                    print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
        q1 = list_of_q[0]
        q2 = list_of_q[1]
        q3 = list_of_q[2]
        while (gcd(list_of_q[0], list_of_q[1]) != 1 and gcd(list_of_q[0], list_of_q[2]) != 1 and gcd(list_of_q[1],
                                                                                                     list_of_q[
                                                                                                         2]) != 1):
            print("Числа не взмаємопрості")
            for i in range(3):
                while True:
                    try:
                        q_i = int(input(f"q{i + 1} = "))
                        if 100 <= q_i <= 900:
                            list_of_q.append(q_i)
                            break
                        else:
                            print("Введене число не знаходиться в потрібному діапазоні(100 - 900). Спробуйте ще раз.")
                    except ValueError:
                        print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
            q1 = list_of_q[0]
            q2 = list_of_q[1]
            q3 = list_of_q[2]
        print(f"q1 = {q1}, q2 = {q2} і q3 = {q3} є ключами другого порядку і є взаємопростими числами.")

        list_of_q = []
        for i in range(3):
            while True:
                try:
                    q_i = int(input(f"q{i + 4} = "))
                    if 100 <= q_i <= 900:
                        list_of_q.append(q_i)
                        break
                    else:
                        print("Введене число не знаходиться в потрібному діапазоні(100 - 900). Спробуйте ще раз.")
                except ValueError:
                    print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
        q4 = list_of_q[0]
        q5 = list_of_q[1]
        q6 = list_of_q[2]
        while (gcd(list_of_q[0], list_of_q[1]) != 1 and gcd(list_of_q[0], list_of_q[2]) != 1 and gcd(list_of_q[1],
                                                                                                     list_of_q[
                                                                                                         2]) != 1):
            print("Числа не взмаємопрості")
            for i in range(3):
                while True:
                    try:
                        q_i = int(input(f"q{i + 4} = "))
                        if 100 <= q_i <= 900:
                            list_of_q.append(q_i)
                            break
                        else:
                            print("Введене число не знаходиться в потрібному діапазоні(100 - 900). Спробуйте ще раз.")
                    except ValueError:
                        print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
            q4 = list_of_q[0]
            q5 = list_of_q[1]
            q6 = list_of_q[2]
        print(f"q4 = {q4}, q5 = {q5} і q6 = {q6} є ключами другого порядку і є взаємопростими числами.")

        list_of_q = []
        for i in range(3):
            while True:
                try:
                    q_i = int(input(f"q{i + 7} = "))
                    if 100 <= q_i <= 900:
                        list_of_q.append(q_i)
                        break
                    else:
                        print("Введене число не знаходиться в потрібному діапазоні(100 - 900). Спробуйте ще раз.")
                except ValueError:
                    print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
        q7 = list_of_q[0]
        q8 = list_of_q[1]
        q9 = list_of_q[2]
        while (gcd(list_of_q[0], list_of_q[1]) != 1 and gcd(list_of_q[0], list_of_q[2]) != 1 and gcd(list_of_q[1],
                                                                                                     list_of_q[
                                                                                                         2]) != 1):
            print("Числа не взмаємопрості")
            for i in range(3):
                while True:
                    try:
                        q_i = int(input(f"q{i + 7} = "))
                        if 100 <= q_i <= 900:
                            list_of_q.append(q_i)
                            break
                        else:
                            print("Введене число не знаходиться в потрібному діапазоні(100 - 900). Спробуйте ще раз.")
                    except ValueError:
                        print("Це не є числом, що задовільняє умову. Спробуйте ще раз.")
            q7 = list_of_q[0]
            q8 = list_of_q[1]
            q9 = list_of_q[2]
        print(f"q7 = {q7}, q8 = {q8} і q9 = {q9} є ключами другого порядку і є взаємопростими числами.")

        print(f"q1 = {q1}, q2 = {q2}, q3 = {q3}, q4 = {q4}, q5 = {q5}, q6 = {q6}, q7 = {q7}, q8 = {q8} і q9 = {q9}")
        decrypted_text = ""

        with open('crypted_text.txt', 'r') as file:
            data = file.read()

        numbers = [int(num) for num in data.split(', ')]

        for j in range(int(len(numbers) / 9)):
            b11 = numbers[j * 9]
            b12 = numbers[j * 9 + 1]
            b13 = numbers[j * 9 + 2]
            b24 = numbers[j * 9 + 3]
            b25 = numbers[j * 9 + 4]
            b26 = numbers[j * 9 + 5]
            b37 = numbers[j * 9 + 6]
            b38 = numbers[j * 9 + 7]
            b39 = numbers[j * 9 + 8]

            N11 = b11
            d11 = q1
            i = (b12 - N11) * pow(d11, -1, q2) % q2
            N21 = N11 + i * d11
            d21 = d11 * q2
            i = (b13 - N21) * pow(d21, -1, q3) % q3
            b1 = N21 + i * d21
            N12 = b24
            d12 = q4
            i = (b25 - N12) * pow(d12, -1, q5) % q5
            N22 = N12 + i * d12
            d22 = d12 * q5
            i = (b26 - N22) * pow(d22, -1, q6) % q6
            b2 = N22 + i * d22
            N13 = b37
            d13 = q7
            i = (b38 - N13) * pow(d13, -1, q8) % q8
            N23 = N13 + i * d13
            d23 = d13 * q8
            i = (b39 - N23) * pow(d23, -1, q9) % q9
            b3 = N23 + i * d23
            N1 = b1
            d1 = p1
            i = (b2 - N1) * pow(d1, -1, p2) % p2
            N2 = N1 + i * d1
            d2 = d1 * p2
            i = (b3 - N2) * pow(d2, -1, p3) % p3
            N3 = N2 + i * d2
            crypted_text = N3
            decrypted_text += decrypt(str(crypted_text))

        with open('decrypted_text.txt', 'w') as file:
            file.write(decrypted_text)
    else:
        print("Введено неправильний тип роботи")