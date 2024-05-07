for i in range(11):
    for j in range(16):
        print(hex(round_keys[i*16+j])[2:].zfill(2), end='')
        if (j+1) % 4 == 0:
            print(' ', end='')
    print()
