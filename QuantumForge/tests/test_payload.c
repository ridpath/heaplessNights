#include <stdio.h>
#include <unistd.h>

int main() {
    printf("[TEST] ELF payload executed successfully\n");
    printf("[TEST] PID: %d\n", getpid());
    return 42;
}
