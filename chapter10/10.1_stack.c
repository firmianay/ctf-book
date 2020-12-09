int func(int arg1, int arg2, int arg3, int arg4,
         int arg5, int arg6, int arg7, int arg8) {
    int loc1 = arg1 + 1;
    int loc8 = arg8 + 8;
    return loc1 + loc8;
}

int main() {
    return func(11, 22, 33, 44, 55, 66, 77, 88);
}
