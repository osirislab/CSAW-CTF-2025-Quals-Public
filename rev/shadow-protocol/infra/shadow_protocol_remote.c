#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Sends a uint64_t to localhost:<47831> as a string
// enables side channel attack route
void debug(uint64_t value) {
    char *msg = "sending super secret to secret operatives";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(47831);  // <-- change port if needed
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(sock);
        return;
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)value);
    send(sock, buf, strlen(buf), 0);

    close(sock);
}

// Space-themed protocol: multi-round Feistel-like structure with S-box, bitwise, and arithmetic ops
uint64_t shadow_protocol(uint64_t stardust) {
    uint32_t L = (uint32_t)(stardust >> 32);
    uint32_t R = (uint32_t)(stardust & 0xFFFFFFFF);
    uint32_t round_keys[4] = {0xA5A5C3C3, 0x5A5A9696, 0x3C3CA5A5, 0xC3C35A5A};
    for (int i = 0; i < 8; i++) {
        uint32_t F = R;
        
        F = (sbox[(F >> 24) & 0xFF] << 24) |
            (sbox[(F >> 16) & 0xFF] << 16) |
            (sbox[(F >> 8) & 0xFF] << 8) |
            (sbox[F & 0xFF]);
        F ^= round_keys[i % 4];
        F = ((F << (3 + i)) | (F >> (32 - (3 + i)))); // rotate left
        F += (L ^ (0x1337BEEF * (i + 1)));
        uint32_t tmp = L;
        L = R;
        R = F ^ tmp;
    }
    uint64_t out = ((uint64_t)L << 32) | R;
    
    out ^= 0xDEADBEEFCAFEBABEULL;
    out = ((out << 17) | (out >> (64 - 17))) + 0x1234567890ABCDEFULL;
    return out;
}

// Space-themed binary tree node for each 3 cosmic bits
typedef struct BitTreeNode {
    uint8_t bits; // 3 cosmic bits per node (lowest 3 bits used)
    struct BitTreeNode *left;
    struct BitTreeNode *right;
} BitTreeNode;

// Build a complete binary tree from 64 bits, grouping into 3-bit chunks (22 nodes, pad with 1s)
BitTreeNode* build_bittree(uint64_t num, int start, int end) {
    if (start > end) return NULL;
    if (start == end) {
        int shift = 63 - start * 3;
        uint8_t val = 0;
        if (shift >= 0) {
            if (shift >= 2) val = (num >> (shift - 2)) & 0x7;
            else if (shift == 1) val = ((num & 0x3) << 1) | 1; // pad 1
            else if (shift == 0) val = ((num & 0x1) << 2) | 0x3; // pad 11
            else val = 0x7; // pad 111
        } else {
            val = 0x7; // pad 111
        }
        BitTreeNode *node = malloc(sizeof(BitTreeNode));
        node->bits = val;
        node->left = node->right = NULL;
        return node;
    }
    int mid = (start + end) / 2;
    BitTreeNode *node = malloc(sizeof(BitTreeNode));
    node->bits = 0; // Internal nodes don't store bits
    node->left = build_bittree(num, start, mid);
    node->right = build_bittree(num, mid + 1, end);
    return node;
}

// Traverse tree in post-order to reconstruct 3-bit groups
void shadow_tree_mix(BitTreeNode *node, uint64_t *out, int *count) {
    if (!node) return;
    shadow_tree_mix(node->left, out, count);
    shadow_tree_mix(node->right, out, count);
    if (!node->left && !node->right) { // leaf
        *out = (*out << 3) | (node->bits & 0x7);
        (*count)++;
    }
}

// Free the binary tree
void free_bittree(BitTreeNode *node) {
    if (!node) return;
    free_bittree(node->left);
    free_bittree(node->right);
    free(node);
}

int main(){
    int dilation = 5 * 365 * 24 * 60 * 60; //five years
    time_t seed = ((time(NULL) + dilation) / 60) * 60; // Seed with cosmic timestamp (Dilating time to enforce kernel injection if using side channel attack route)
    srand(seed);  
    
    // Generate 8-byte cosmic random number
    uint64_t cosmic_seed = ((uint64_t)rand() << 32) | rand();
    
    // Debug prints (removed for release)
    // printf("[SPACE DEBUG] Cosmic seed: %llu\n", (unsigned long long)cosmic_seed);
    // printf("[SPACE DEBUG] Traversal (3-bit cosmic groups, post-order):\n");
    // Transform bits using binary tree (3 bits per node, 22 nodes)
    BitTreeNode *galaxy = build_bittree(cosmic_seed, 0, 21);
    uint64_t stardust = 0;
    int cosmic_count = 0;
    shadow_tree_mix(galaxy, &stardust, &cosmic_count);
    // printf("[SPACE DEBUG] Stardust value: %llu\n", (unsigned long long)stardust);
    free_bittree(galaxy);

    uint64_t star_key = shadow_protocol(stardust);
    debug(star_key);
    // printf("[SPACE DEBUG] Star key: %llu\n", (unsigned long long)star_key);

    // Read flag from file
    char flag[128];
    FILE *f = fopen("flag.txt", "r");
    if (!f) {
        strcpy(flag, "CSAW{f4k3_fl4g_4_t3st1ng}");
    } else {
        if (!fgets(flag, sizeof(flag), f)) {
            printf("Could not read flag, contact mission control.\n");
            fclose(f);
            return 1;
        }
        fclose(f);
        size_t flag_len = strlen(flag);
        if (flag_len > 0 && flag[flag_len-1] == '\n') flag[--flag_len] = '\0';
    }
    size_t flag_len = strlen(flag);

    // Encrypt flag with star_key (simple XOR with key, repeated)
    printf("        ✦         .       *        .      ✦\n");
    printf("   ✦        .     SHADOW PROTOCOL INITIATED     .       ✦\n");
    printf("        *        ✦       .       ✶        .\n\n");

    printf("[SPACE] A cosmic signal has been scrambled using the Shadow Protocol at time: %lld.\n", (long long)seed);
    printf("[SPACE] Encrypted message:\n");
    for (size_t i = 0; i < flag_len; ++i) {
        unsigned char enc = flag[i] ^ ((star_key >> (8 * (i % 8))) & 0xFF);
        printf("%02X", enc);
    }
    printf("\n");
    printf("\n[SPACE] Transmission complete.\n");
    getchar();
    return 0;
}