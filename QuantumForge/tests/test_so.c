#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
void so_constructor() {
    fprintf(stderr, "[TEST] SO constructor called\n");
    fprintf(stderr, "[TEST] SO PID: %d\n", getpid());
}

void entry() {
    fprintf(stderr, "[TEST] SO entry point called\n");
    fprintf(stderr, "[TEST] SO execution successful\n");
}
