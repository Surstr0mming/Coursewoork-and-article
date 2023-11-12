import tkinter as tk
from tkinter import ttk, scrolledtext
import pyperclip
alphabet = \
{
    'а': 100, 'б': 101, 'в': 102, 'г': 103, 'д': 104, 'е': 105, 'є': 106, 'ж': 107, 'з': 108, 'и': 109, 'і': 110, 'ї': 111, 'й': 112, 'к': 113, 'л': 114, 'м': 115, 'н': 116, 'о': 117, 'п': 118, 'р': 119, 'с': 120, 'т': 121, 'у': 122, 'ф': 123, 'х': 124, 'ц': 125, 'ч': 126, 'ш': 127, 'щ': 128, 'ь': 129, 'ю': 130, 'я': 131, ' ': 132, '\n': 133, '.': 134, ',': 135, ':': 136, '!': 137, '?': 138, '%': 139, '#': 140, '@': 141, '№': 142, ';': 143, '^': 144, '*': 145, '(': 146, ')': 147, '-': 148, '+': 149, '=': 150, '_': 151, '<': 152, '>': 153, '{': 154, '}': 155, '[': 156, ']': 157, '|': 158, '/': 159, '`': 160, '~': 161, '\'': 162, '"': 163, '\\': 164, '$': 165, '&': 166, 'a': 167, 'b': 168, 'c': 169, 'd': 170, 'e': 171, 'f': 172, 'g': 173, 'h': 174, 'i': 175, 'j': 176, 'k': 177, 'l': 178, 'm': 179, 'n': 180, 'o': 181, 'p': 182, 'q': 183, 'r': 184, 's': 185, 't': 186, 'u': 187, 'v': 188, 'w': 189, 'x': 190, 'y': 191, 'z': 192, 'А': 193, 'Б': 194, 'В': 195, 'Г': 196, 'Ґ': 197, 'Д': 198, 'Е': 199, 'Є': 200, 'Ж': 201, 'З': 202, 'И': 203, 'І': 204, 'Ї': 205, 'Й': 206, 'К': 207, 'Л': 208, 'М': 209, 'Н': 210, 'О': 211, 'П': 212, 'Р': 213, 'С': 214, 'Т': 215, 'У': 216, 'Ф': 217, 'Х': 218, 'Ц': 219, 'Ч': 220, 'Ш': 221, 'Щ': 222, 'Ь': 223, 'Ю': 224, 'A': 225, 'B': 226, 'C': 227, 'D': 228, 'E': 229, 'F': 230, 'G': 231, 'H': 232, 'I': 233, 'J': 234, 'K': 235, 'L': 236, 'M': 237, 'N': 238, 'O': 239, 'P': 240, 'Q': 241, 'R': 242, 'S': 243, 'T': 244, 'U': 245, 'V': 246, 'W': 247, 'X': 248, 'Y': 249, 'Z': 250, '1': 251, '2': 252, '3': 253, '4': 254, '5': 255, '6': 256, '7': 257, '8': 258, '9': 259, '0': 260, '—': 261, '−': 262, '«': 263, '»': 264, 'ґ': 265, 'Я' : 266
}


decrypted_alphabet = \
{
    '100': 'а', '101': 'б', '102': 'в', '103': 'г', '104': 'д', '105': 'е', '106': 'є', '107': 'ж', '108': 'з', '109': 'и', '110': 'і', '111': 'ї', '112': 'й', '113': 'к', '114': 'л', '115': 'м', '116': 'н', '117': 'о', '118': 'п', '119': 'р', '120': 'с', '121': 'т', '122': 'у', '123': 'ф', '124': 'х', '125': 'ц', '126': 'ч', '127': 'ш', '128': 'щ', '129': 'ь',  '130': 'ю', '131': 'я', '132': ' ', '133': '\n', '134': '.', '135': ',', '136': ':', '137': '!', '138': '?', '139': '%', '140': '#', '141': '@', '142': '№', '143': ';', '144': '^', '145': '*', '146': '(', '147': ')', '148': '-', '149': '+', '150': '=', '151': '_', '152': '<', '153': '>', '154': '{', '155': '}', '156': '[', '157': ']', '158': '|', '159': '/', '160': '`', '161': '~', '162': '\'', '163': '"', '164': '\\', '165': '$', '166': '&', '167': 'a', '168': 'b', '169': 'c', '170': 'd', '171': 'e', '172': 'f', '173': 'g', '174': 'h', '175': 'i', '176': 'j', '177': 'k', '178': 'l', '179': 'm', '180': 'n', '181': 'o', '182': 'p', '183': 'q', '184': 'r', '185': 's', '186': 't', '187': 'u', '188': 'v', '189': 'w', '190': 'x', '191': 'y', '192': 'z', '193': 'А', '194': 'Б', '195': 'В', '196': 'Г', '197': 'ґ', '198': 'Д', '199': 'Е', '200': 'Є', '201': 'Ж', '202': 'З', '203': 'И', '204': 'І', '205': 'Ї', '206': 'Й', '207': 'К', '208': 'Л', '209': 'М', '210': 'Н', '211': 'О', '212': 'П', '213': 'Р', '214': 'С', '215': 'Т', '216': 'У', '217': 'Ф', '218': 'Х', '219': 'Ц', '220': 'Ч', '221': 'Ш', '222': 'Щ', '223': 'Ь', '224': 'Ю', '225': 'A', '226': 'B', '227': 'C', '228': 'D', '229': 'E', '230': 'F', '231': 'G', '232': 'H', '233': 'I', '234': 'J', '235': 'K', '236': 'L', '237': 'M', '238': 'N', '239': 'O', '240': 'P', '241': 'Q', '242': 'R', '243': 'S', '244': 'T', '245': 'U', '246': 'V', '247': 'W', '248': 'X', '249': 'Y',  '250': 'Z', '251': '1', '252': '2', '253': '3', '254': '4', '255': '5', '256': '6', '257': '7', '258': '8', '259': '9', '260': '0', '261': '—', '262': '−', '263': '«', '264': '»', '265': 'ґ', '266' : 'Я'
}
result_numbers = []
type_of_work = '0'
entered_text = ''
cryptet_text = ''


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

def submit():
    global type_of_work
    job_type = job_type_var.get()
    type_of_work = str(job_type)
    window.destroy()


def display_text():
    global cryptet_text
    entered_text = entry.get()
    not_in_alphabet = []
    if len(entered_text) < 1:
        # Повідомлення про помилку, якщо довжина тексту менша за 1
        error_label.config(text="Текст не відповідає достатній довжині", fg="black")
    elif crypt(entered_text) == 'null':
        for char in entered_text:
            if char not in alphabet:
                if char not in not_in_alphabet:
                    not_in_alphabet.append(char)
        error_label.config(text=f"Текст містить символ(и), {not_in_alphabet}, яких нема у словнику", fg="black")
    else:
        cryptet_text = crypt(entered_text)
        root.destroy()

def check_p():
    global result_numbers
    try:
        p1 = int(entry1.get())
        p2 = int(entry2.get())
        p3 = int(entry3.get())

        valid_range = (100000, 20000000)
        out_of_bounds = []

        if not valid_range[0] < p1 < valid_range[1]:
            out_of_bounds.append("p1")
        if not valid_range[0] < p2 < valid_range[1]:
            out_of_bounds.append("p2")
        if not valid_range[0] < p3 < valid_range[1]:
            out_of_bounds.append("p3")

        if out_of_bounds:
            result_label.config(text=f"{', '.join(out_of_bounds)} {'is' if len(out_of_bounds) == 1 else 'are'} out of bounds ({valid_range[0]} - {valid_range[1]})")
        elif gcd(p1, p2) == 1 and gcd(p1, p3) == 1 and gcd(p2, p3) == 1:
            result_numbers = [p1, p2, p3]
            window.destroy()  # Close the window if numbers are correct
        else:
            non_coprime_pairs = []
            if gcd(p1, p2) != 1:
                non_coprime_pairs.append("(p1, p2)")
            if gcd(p1, p3) != 1:
                non_coprime_pairs.append("(p1, p3)")
            if gcd(p2, p3) != 1:
                non_coprime_pairs.append("(p2, p3)")

            result_label.config(text=f"{', '.join(non_coprime_pairs)} {'is' if len(non_coprime_pairs) == 1 else 'are'} not pairwise coprime")
    except ValueError:
        result_label.config(text="Please enter valid integers for p1, p2, and p3.")



def check_q_1_3():
    global result_numbers
    try:
        q1 = int(entry1.get())
        q2 = int(entry2.get())
        q3 = int(entry3.get())

        valid_range = (100, 900)
        out_of_bounds = []

        if not valid_range[0] < q1 < valid_range[1]:
            out_of_bounds.append("q1")
        if not valid_range[0] < q2 < valid_range[1]:
            out_of_bounds.append("q2")
        if not valid_range[0] < q3 < valid_range[1]:
            out_of_bounds.append("q3")

        if out_of_bounds:
            result_label.config(text=f"{', '.join(out_of_bounds)} {'is' if len(out_of_bounds) == 1 else 'are'} out of bounds ({valid_range[0]} - {valid_range[1]})")
        elif gcd(q1, q2) == 1 and gcd(q1, q3) == 1 and gcd(q2, q3) == 1:
            result_numbers = [q1, q2, q3]
            window.destroy()  # Close the window if numbers are correct
        else:
            non_coprime_pairs = []
            if gcd(q1, q2) != 1:
                non_coprime_pairs.append("(q1, q2)")
            if gcd(q1, q3) != 1:
                non_coprime_pairs.append("(q1, q3)")
            if gcd(q2, q3) != 1:
                non_coprime_pairs.append("(q2, q3)")

            result_label.config(text=f"{', '.join(non_coprime_pairs)} {'is' if len(non_coprime_pairs) == 1 else 'are'} not pairwise coprime")
    except ValueError:
        result_label.config(text="Please enter valid integers for q1, q2, and q3.")


def check_q_4_6():
    global result_numbers
    try:
        q4 = int(entry1.get())
        q5 = int(entry2.get())
        q6 = int(entry3.get())

        valid_range = (100, 900)
        out_of_bounds = []

        if not valid_range[0] < q4 < valid_range[1]:
            out_of_bounds.append("q4")
        if not valid_range[0] < q5 < valid_range[1]:
            out_of_bounds.append("q5")
        if not valid_range[0] < q6 < valid_range[1]:
            out_of_bounds.append("q6")

        if out_of_bounds:
            result_label.config(text=f"{', '.join(out_of_bounds)} {'is' if len(out_of_bounds) == 1 else 'are'} out of bounds ({valid_range[0]} - {valid_range[1]})")
        elif gcd(q4, q5) == 1 and gcd(q4, q6) == 1 and gcd(q5, q6) == 1:
            non_repeating_modules = [q4, q5, q6]
            if not any(module in [q1, q2, q3] for module in non_repeating_modules):
                result_numbers = non_repeating_modules
                window.destroy()  # Close the window if numbers are correct
            else:
                result_label.config(text=f"Modules should not repeat (q1 = {q1}, q2 = {q2}, q3 = {q3})")
        else:
            result_label.config(text="Modules are not pairwise coprime")
    except ValueError:
        result_label.config(text="Please enter valid integers for q4, q5, and q6.")


def check_q_7_9():
    global result_numbers

    try:
        q7 = int(entry1.get())
        q8 = int(entry2.get())
        q9 = int(entry3.get())

        valid_range = (100, 900)

        valid_range = (100, 900)
        out_of_bounds = []

        if not valid_range[0] < q7 < valid_range[1]:
            out_of_bounds.append("q4")
        if not valid_range[0] < q8 < valid_range[1]:
            out_of_bounds.append("q5")
        if not valid_range[0] < q9 < valid_range[1]:
            out_of_bounds.append("q6")

        if out_of_bounds:
            result_label.config(
                text=f"{', '.join(out_of_bounds)} {'is' if len(out_of_bounds) == 1 else 'are'} out of bounds ({valid_range[0]} - {valid_range[1]})")
        elif gcd(q7, q8) == 1 and gcd(q7, q9) == 1 and gcd(q8, q9) == 1:
            non_repeating_modules = [q7, q8, q9]
            if not any(module in [q1, q2, q3, q4, q5, q6] for module in non_repeating_modules):
                result_numbers = non_repeating_modules
                window.destroy()  # Close the window if numbers are correct
            else:
                result_label.config(text=f"Modules should not repeat (q1 = {q1}, q2 = {q2}, q3 = {q3}, q4 = {q4}, q5 = {q5}, q6 = {q6})")
        else:
            result_label.config(text="Modules are not pairwise coprime")
    except ValueError:
        result_label.config(text="Please enter valid integers for q7, q8, and q9.")

def toggle_fullscreen():
    root.attributes('-fullscreen', not root.attributes('-fullscreen'))

def copy_text():
    entire_text = text_area.get("1.0", "end-1c")  # Get the entire content of the text area
    pyperclip.copy(entire_text)

if __name__ == '__main__':
    # Створення головного вікна
    window = tk.Tk()
    window.title("Вибір типу роботи")

    # Додавання пояснення типу роботи
    label = tk.Label(window, text="Оберіть тип роботи:")
    label.pack()

    # Створення варіантів вибору
    job_type_var = tk.StringVar()
    job_type_var.set('1')  # За замовчуванням встановлюємо перший тип роботи

    # Радіокнопки для вибору типу роботи
    radio_button1 = tk.Radiobutton(window, text="Зашифрування", variable=job_type_var, value='1')
    radio_button2 = tk.Radiobutton(window, text="Розкодування", variable=job_type_var, value='2')

    radio_button1.pack()
    radio_button2.pack()

    # Кнопка підтвердження
    submit_button = tk.Button(window, text="Підтвердити", command=submit)
    submit_button.pack()
    window.mainloop()

    if type_of_work == '1':
        # Створити головне вікно
        root = tk.Tk()
        root.title("Введення тексту")

        # Створити елемент введення тексту
        entry = tk.Entry(root, width=90)
        entry.pack(pady=10)

        # Створити мітку для повідомлень про помилки
        error_label = tk.Label(root, text="", fg="red")
        error_label.pack()

        # Створити кнопку для виведення введеного тексту
        button = tk.Button(root, text="Вивести текст", command=display_text)
        button.pack()

        # Запустити головний цикл вікна
        root.mainloop()


        window = tk.Tk()
        window.title("Введення модулів першого порядку")

        # Створення та розміщення елементів у вікні
        label1 = ttk.Label(window, text="p1:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)  # Встановлюємо ширину в 20 символів
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="p2:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)  # Встановлюємо ширину в 20 символів
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="p3:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)  # Встановлюємо ширину в 20 символів
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_p)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            p1 = result_numbers[0]
            p2 = result_numbers[1]
            p3 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()



        print(f"p1 = {p1}, p2 = {p2}, p3 = {p3}")


        window = tk.Tk()
        window.title("Введення модулів другого порядку")
        label1 = ttk.Label(window, text="q1:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="q2:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="q3:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_q_1_3)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            q1 = result_numbers[0]
            q2 = result_numbers[1]
            q3 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()

        print(f"q1 = {q1}, q2 = {q2}, q3 = {q3}")


        window = tk.Tk()
        window.title("Введення модулів другого порядку")
        label1 = ttk.Label(window, text="q4:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="q5:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="q6:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_q_4_6)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            q4 = result_numbers[0]
            q5 = result_numbers[1]
            q6 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()

        print(f"q4 = {q4}, q5 = {q5}, q6 = {q6}")

        window = tk.Tk()
        window.title("Введення модулів другого порядку")
        label1 = ttk.Label(window, text="q7:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="q8:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="q9:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_q_7_9)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            q7 = result_numbers[0]
            q8 = result_numbers[1]
            q9 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()

        print(f"q7 = {q7}, q8 = {q8}, q9 = {q9}")





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

        # Створення головного вікна
        root = tk.Tk()
        root.title("Великий текст у віконному режимі")

        # Створення текстового поля з можливістю скролити
        text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        text_area.pack(fill=tk.BOTH, expand=True)

        # Додавання дуже великого тексту
        with open('crypted_text.txt', 'r') as file:
            # Читання строки з файлу
            cryptet_text_screen = file.readline()

        # Додавання дуже великого тексту
        very_large_text = cryptet_text_screen
        text_area.insert(tk.INSERT, very_large_text)

        # Встановлення розмірів вікна на весь екран
        root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))

        # Кнопка для включення та вимикання повноекранного режиму
        fullscreen_button = tk.Button(root, text="Toggle Fullscreen", command=toggle_fullscreen)
        fullscreen_button.pack()

        # Кнопка для копіювання виділеного тексту
        copy_button = tk.Button(root, text="Copy", command=copy_text)
        copy_button.pack()

        # Запуск головного циклу подій
        root.mainloop()
    elif type_of_work == '2':
        window = tk.Tk()
        window.title("Введення модулів першого порядку")

        # Створення та розміщення елементів у вікні
        label1 = ttk.Label(window, text="p1:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)  # Встановлюємо ширину в 20 символів
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="p2:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)  # Встановлюємо ширину в 20 символів
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="p3:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)  # Встановлюємо ширину в 20 символів
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_p)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            p1 = result_numbers[0]
            p2 = result_numbers[1]
            p3 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()

        print(f"p1 = {p1}, p2 = {p2}, p3 = {p3}")

        window = tk.Tk()
        window.title("Введення модулів другого порядку")
        label1 = ttk.Label(window, text="q1:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="q2:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="q3:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_q_1_3)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            q1 = result_numbers[0]
            q2 = result_numbers[1]
            q3 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()

        print(f"q1 = {q1}, q2 = {q2}, q3 = {q3}")

        window = tk.Tk()
        window.title("Введення модулів другого порядку")
        label1 = ttk.Label(window, text="q4:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="q5:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="q6:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_q_4_6)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            q4 = result_numbers[0]
            q5 = result_numbers[1]
            q6 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()

        print(f"q4 = {q4}, q5 = {q5}, q6 = {q6}")

        window = tk.Tk()
        window.title("Введення модулів другого порядку")
        label1 = ttk.Label(window, text="q7:")
        label1.grid(row=0, column=0, padx=10, pady=10)
        entry1 = ttk.Entry(window, width=60)
        entry1.grid(row=0, column=1, padx=10, pady=10)

        label2 = ttk.Label(window, text="q8:")
        label2.grid(row=1, column=0, padx=10, pady=10)
        entry2 = ttk.Entry(window, width=60)
        entry2.grid(row=1, column=1, padx=10, pady=10)

        label3 = ttk.Label(window, text="q9:")
        label3.grid(row=2, column=0, padx=10, pady=10)
        entry3 = ttk.Entry(window, width=60)
        entry3.grid(row=2, column=1, padx=10, pady=10)

        calculate_button = ttk.Button(window, text="задати модулі", command=check_q_7_9)
        calculate_button.grid(row=3, column=0, columnspan=2, pady=10)

        result_label = ttk.Label(window, text="")
        result_label.grid(row=4, column=0, columnspan=2, pady=10)

        window.mainloop()

        try:
            q7 = result_numbers[0]
            q8 = result_numbers[1]
            q9 = result_numbers[2]
            result_numbers = []
        except:
            print("Відбувся креш перезапустіть програму")
            exit()

        print(f"q7 = {q7}, q8 = {q8}, q9 = {q9}")


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

        # Створення головного вікна
        root = tk.Tk()
        root.title("Великий текст у віконному режимі")

        # Створення текстового поля з можливістю скролити
        text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        text_area.pack(fill=tk.BOTH, expand=True)

        # Додавання дуже великого тексту
        with open('decrypted_text.txt', 'r') as file:
            # Читання строки з файлу
            cryptet_text_screen = file.readline()

        # Додавання дуже великого тексту
        very_large_text = cryptet_text_screen
        text_area.insert(tk.INSERT, very_large_text)

        # Встановлення розмірів вікна на весь екран
        root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))

        # Кнопка для включення та вимикання повноекранного режиму
        fullscreen_button = tk.Button(root, text="Toggle Fullscreen", command=toggle_fullscreen)
        fullscreen_button.pack()

        # Кнопка для копіювання виділеного тексту
        copy_button = tk.Button(root, text="Copy", command=copy_text)
        copy_button.pack()

        # Запуск головного циклу подій
        root.mainloop()
    else:
        error_message = "You have not selected any type of work. Restart the program and select the type of operation, rather than closing the selection window again."
        error_window = tk.Tk()
        error_window.title("Error")

        label = tk.Label(error_window, text=error_message, padx=10, pady=10)
        label.pack()

        ok_button = tk.Button(error_window, text="OK", command=error_window.destroy)
        ok_button.pack(pady=10)

        error_window.mainloop()