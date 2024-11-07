/**
    Too much time to analysis

    https://stackoverflow.com/questions/78603028/bpf-program-is-too-large-processed-1000001-insn

 */

while (i < MAX_BUF_LEN) {
    if (*fmt == '\0')
        break;
    if (*fmt == 'h') {
        fmt++;
        i++;
        continue;
    }

    i++;
    *msg++ = *fmt++;
}
