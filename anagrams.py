from itertools import permutations

word = "Бошлна"
permutations_list = list(permutations(word))

for perm in permutations_list:
    print(''.join(perm))
