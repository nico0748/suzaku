// Intentionally vulnerable C++ fixture for Suzaku Compass tests.
// DO NOT use this code. It exists only as scanner bait.

#include <cstdio>
#include <cstring>

void unsafe_strcpy(char* dst, const char* src) {
    strcpy(dst, src);
}

void unsafe_strcat(char* dst, const char* src) {
    strcat(dst, src);
}

void unsafe_sprintf(char* buf, const char* fmt, int x) {
    sprintf(buf, fmt, x);
}

void unsafe_memcpy(char* dst, const char* src, size_t attacker_len) {
    memcpy(dst, src, attacker_len);
}

void unsafe_gets(char* buf) {
    gets(buf);
}

void unsafe_printf(char* user_input) {
    printf(user_input);
}
