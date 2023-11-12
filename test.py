"""def check_q_7_9():
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
        result_label.config(text="Please enter valid integers for q7, q8, and q9.")"""