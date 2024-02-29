#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "attestation.h"
#include "openssl/sm3.h"


#define KVM_HC_VM_ATTESTATION 12

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGEMAP_LEN 8

struct csv_attestation_user_data {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
};

static void gen_random_bytes(void *buf, uint32_t len)
{
    uint32_t i;
    uint8_t *buf_byte = (uint8_t *)buf;

    for (i = 0; i < len; i++) {
        buf_byte[i] = rand() & 0xFF;
    }
}

static void csv_data_dump(const char* name, uint8_t *data, uint32_t len)
{
    printf("%s:\n", name);
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        printf("%02hhx", c);
    }
    printf("\n");
}

static uint64_t va_to_pa(uint64_t va)
{
    FILE *pagemap;
    uint64_t offset, pfn;

    pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) {
        printf("open pagemap fail\n");
        return 0;
    }

    offset = va / PAGE_SIZE * PAGEMAP_LEN;
    if(fseek(pagemap, offset, SEEK_SET) != 0) {
        printf("seek pagemap fail\n");
        fclose(pagemap);
        return 0;
    }

    if (fread(&pfn, 1, PAGEMAP_LEN - 1, pagemap) != PAGEMAP_LEN - 1) {
        printf("read pagemap fail\n");
        fclose(pagemap);
        return 0;
    }

    pfn &= 0x7FFFFFFFFFFFFF;

    return pfn << PAGE_SHIFT;
}

static long hypercall(unsigned int nr, unsigned long p1, unsigned int len)
{
    long ret = 0;

    asm volatile("vmmcall"
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(len)
             : "memory");
    return ret;
}

static int get_attestation_report(struct csv_attestation_report *report)
{
    struct csv_attestation_user_data *user_data;
    uint64_t user_data_pa;
    long ret;

    if (!report) {
        printf("NULL pointer for report\n");
        return -1;
    }

    /* prepare user data */
    user_data = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (user_data == MAP_FAILED) {
        printf("mmap failed\n");
        return -1;
    }
    printf("mmap %p\n", user_data);

    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    gen_random_bytes(user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);

    // compute hash and save to the private page
    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);

    csv_data_dump("data", user_data->data, GUEST_ATTESTATION_DATA_SIZE);
    csv_data_dump("mnonce", user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    csv_data_dump("hash", (unsigned char *)&user_data->hash, sizeof(hash_block_u));
    printf("data: %s\n", user_data->data);

    /* call host to get attestation report */
    user_data_pa = va_to_pa((uint64_t)user_data);
    printf("user_data_pa: %lx\n", user_data_pa);

    ret = hypercall(KVM_HC_VM_ATTESTATION, user_data_pa, PAGE_SIZE);
    if (ret) {
        printf("hypercall fail: %ld\n", ret);
        munmap(user_data, PAGE_SIZE);
        return -1;
    }
    memcpy(report, user_data, sizeof(*report));
    munmap(user_data, PAGE_SIZE);

    return 0;
}

static int save_report_to_file(struct csv_attestation_report *report, const char *path)
{
    if (!report) {
        printf("no report\n");
        return -1;
    }
    if (!path || !*path) {
        printf("no file\n");
        return -1;
    }

    int fd = open(path, O_CREAT|O_WRONLY);
    if (fd < 0) {
        printf("open file %s fail %d\n", path, fd);
        return fd;
    }

    int len = 0, n;

    while (len < sizeof(*report)) {
        n = write(fd, report + len, sizeof(*report));
        if (n == -1) {
            printf("write file error\n");
            close(fd);
            return n;
        }
        len += n;
    }

    close(fd);

    return 0;
}

int main()
{
    int ret;
    struct csv_attestation_report report;

    printf("get attestation report & save to %s\n", ATTESTATION_REPORT_FILE);

    ret = get_attestation_report(&report);
    if (ret) {
        printf("get attestation report fail\n");
        return -1;
    }

    ret = save_report_to_file(&report, ATTESTATION_REPORT_FILE);
    if (ret) {
        printf("save report fail\n");
        return -1;
    }

    printf("done\n");

    return 0;
}
