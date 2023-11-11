import tkinter as tk
from tkinter import scrolledtext

def toggle_fullscreen():
    root.attributes('-fullscreen', not root.attributes('-fullscreen'))

# Створення головного вікна
root = tk.Tk()
root.title("Великий текст у віконному режимі")

# Створення текстового поля з можливістю скролити
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
text_area.pack(fill=tk.BOTH, expand=True)

# Додавання дуже великого тексту
very_large_text = "Тут ваш дуже великий текст..."
text_area.insert(tk.INSERT, very_large_text)

# Встановлення розмірів вікна на весь екран
root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))

# Кнопка для включення та вимикання повноекранного режиму
fullscreen_button = tk.Button(root, text="Toggle Fullscreen", command=toggle_fullscreen)
fullscreen_button.pack()

# Запуск головного циклу подій
root.mainloop()
