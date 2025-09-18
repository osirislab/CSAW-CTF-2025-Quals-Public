#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define DES_KEY_LEN 0x08
#define MSG_DIGEST_LEN 0x10
#define MSG_DATA_MAX_LEN 0x50
#define MAX_STRING_LEN 0x18
#define SIGNATURE_LEN 0x08

uint8_t des_key[DES_KEY_LEN] = {0};
uint16_t msg_cnt = 0;
char spaceship_name[MAX_STRING_LEN + 1] = {0};
char access_word[MAX_STRING_LEN + 1] = {0};
uint8_t wormhole_signature[SIGNATURE_LEN] = {0};

typedef struct __attribute__((packed)) {
    uint8_t  msg_version;
    uint8_t  msg_type;
    uint8_t  transmission_direction;
    uint16_t msg_id;
    uint16_t msg_data_len;
    uint8_t  transmission_noise;
    uint8_t  msg_digest[MSG_DIGEST_LEN];
} portal_msg_header_t;

typedef struct __attribute__((packed)) {
    portal_msg_header_t msg_header;
    uint8_t  msg_data[MSG_DATA_MAX_LEN];
} portal_msg_t;

void md5_hash(const uint8_t *data, size_t data_len, uint8_t *hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Error: EVP_MD_CTX_new failed\n");
        exit(1);
    }

    const EVP_MD *md = EVP_md5();
    if (!md) {
        fprintf(stderr, "Error: EVP_md5 failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    unsigned int hash_len;
    
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fprintf(stderr, "Error: EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    
    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        fprintf(stderr, "Error: EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "Error: EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    EVP_MD_CTX_free(mdctx);
}

void des_ecb_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, size_t data_len) {
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        fprintf(stderr, "Error: OSSL_PROVIDER_load failed\n");
        exit(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
        OSSL_PROVIDER_unload(legacy);
        exit(1);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, des_key, NULL) != 1) {
        fprintf(stderr, "Error: EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        exit(1);
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int len = 0;
    int total_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, data_len) != 1) {
        fprintf(stderr, "Error: EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        exit(1);
    }

    total_len += len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        fprintf(stderr, "Error: EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        exit(1);
    }

    total_len += len;
    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(legacy);
}

void des_ecb_decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t data_len) {
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        fprintf(stderr, "Error: OSSL_PROVIDER_load failed\n");
        exit(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
        OSSL_PROVIDER_unload(legacy);
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, des_key, NULL) != 1) {
        fprintf(stderr, "Error: EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        OSSL_PROVIDER_unload(legacy);
        exit(1);
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int len = 0;
    int total_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, data_len) != 1) {
        fprintf(stderr, "Error: EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    total_len += len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        fprintf(stderr, "Error: EVP_DecryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    total_len += len;
    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(legacy);
}

void unseal_portal_msg(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    uint8_t decrypted_msg_data[portal_msg->msg_header.msg_data_len];
    des_ecb_decrypt(portal_msg->msg_data, decrypted_msg_data, portal_msg->msg_header.msg_data_len);
    memcpy(portal_msg_buffer + sizeof(portal_msg_header_t), decrypted_msg_data, portal_msg->msg_header.msg_data_len);

    uint8_t msg_digest[MSG_DIGEST_LEN];
    md5_hash(portal_msg_buffer, sizeof(portal_msg_header_t) + portal_msg->msg_header.msg_data_len, msg_digest);
    memcpy(portal_msg_buffer + sizeof(portal_msg_header_t) - MSG_DIGEST_LEN, msg_digest, MSG_DIGEST_LEN);
}

void seal_portal_msg(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    uint8_t msg_digest[MSG_DIGEST_LEN];
    md5_hash(portal_msg_buffer, sizeof(portal_msg_header_t) + portal_msg->msg_header.msg_data_len, msg_digest);
    memcpy(portal_msg->msg_header.msg_digest, msg_digest, MSG_DIGEST_LEN);

    uint8_t encrypted_msg_data[portal_msg->msg_header.msg_data_len];
    des_ecb_encrypt(portal_msg->msg_data, encrypted_msg_data, portal_msg->msg_header.msg_data_len);
    memcpy(portal_msg->msg_data, encrypted_msg_data, portal_msg->msg_header.msg_data_len);
}

int verify_portal_msg(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    size_t bytes_read = read(0, portal_msg_buffer, sizeof(portal_msg_t));
    if (bytes_read < sizeof(portal_msg_header_t)) {
        return 0;
    }

    portal_msg->msg_header.msg_version = portal_msg_buffer[0];
    portal_msg->msg_header.msg_type = portal_msg_buffer[1];

    portal_msg->msg_header.transmission_direction = portal_msg_buffer[2];
    if (portal_msg->msg_header.transmission_direction != 0x01) {
        return 0;
    }

    portal_msg->msg_header.msg_id = (portal_msg_buffer[3] << 8) | portal_msg_buffer[4];
    if (portal_msg->msg_header.msg_id != msg_cnt) {
        return 0;
    }
    msg_cnt++;

    portal_msg->msg_header.msg_data_len = (portal_msg_buffer[5] << 8) | portal_msg_buffer[6];
    if (portal_msg->msg_header.msg_data_len % 8 != 0 || sizeof(portal_msg_header_t) + portal_msg->msg_header.msg_data_len != bytes_read) {
        return 0;
    }

    portal_msg->msg_header.transmission_noise = portal_msg_buffer[7];
    if (portal_msg->msg_header.transmission_noise != rand() % 256) {
        return 0;
    }

    memcpy(portal_msg->msg_header.msg_digest, portal_msg_buffer + sizeof(portal_msg_header_t) - MSG_DIGEST_LEN, MSG_DIGEST_LEN);
    memset(portal_msg_buffer + sizeof(portal_msg_header_t) - MSG_DIGEST_LEN, 0, MSG_DIGEST_LEN);

    memcpy(portal_msg->msg_data, portal_msg_buffer + sizeof(portal_msg_header_t), portal_msg->msg_header.msg_data_len);
    memset(portal_msg_buffer + sizeof(portal_msg_header_t), 0, portal_msg->msg_header.msg_data_len);

    if (portal_msg->msg_header.msg_version == 0x02) {
        unseal_portal_msg(portal_msg_buffer, portal_msg);
        if (memcmp(portal_msg->msg_header.msg_digest, portal_msg_buffer + sizeof(portal_msg_header_t) - MSG_DIGEST_LEN, MSG_DIGEST_LEN) != 0) {
            return 0;
        }
    }

    return 1;
}

void emit_portal_msg(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    portal_msg->msg_header.msg_version = 0x02;
    portal_msg->msg_header.transmission_direction = 0x00;
    portal_msg->msg_header.msg_id = msg_cnt++;
    portal_msg->msg_header.transmission_noise = rand() % 256;

    memcpy(portal_msg_buffer, portal_msg, sizeof(portal_msg_header_t) + portal_msg->msg_header.msg_data_len);
    portal_msg_buffer[3] = (portal_msg->msg_header.msg_id >> 8) & 0xFF;
    portal_msg_buffer[4] = portal_msg->msg_header.msg_id & 0xFF;
    portal_msg_buffer[5] = (portal_msg->msg_header.msg_data_len >> 8) & 0xFF;
    portal_msg_buffer[6] = portal_msg->msg_header.msg_data_len & 0xFF;

    seal_portal_msg(portal_msg_buffer, portal_msg);

    memcpy(portal_msg_buffer + sizeof(portal_msg_header_t) - MSG_DIGEST_LEN, portal_msg->msg_header.msg_digest, MSG_DIGEST_LEN);
    memcpy(portal_msg_buffer + sizeof(portal_msg_header_t), portal_msg->msg_data, portal_msg->msg_header.msg_data_len);

    write(1, portal_msg_buffer, sizeof(portal_msg_header_t) + portal_msg->msg_header.msg_data_len);
}

void clear_portal_cache(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    memset(portal_msg_buffer, 0, sizeof(portal_msg_t));
    memset(portal_msg, 0, sizeof(portal_msg_t));
}

int enroll_spaceship() {
    puts("Enrolling your spaceship...");

    puts("Please enter your spaceship name: ");
    if (fgets(spaceship_name, MAX_STRING_LEN + 1, stdin) == NULL) {
        fprintf(stderr, "Error: fgets failed\n");
        exit(1);
    }

    spaceship_name[strcspn(spaceship_name, "\n")] = '\0';
    if (strlen(spaceship_name) == 0) {
        puts("Your spaceship name is invalid.");
        return 0;
    }

    puts("Please enter your access code: ");
    if (fgets(access_word, MAX_STRING_LEN + 1, stdin) == NULL) {
        puts("Your access code is invalid.");
        return 0;
    }

    access_word[strcspn(access_word, "\n")] = '\0';
    if (strlen(access_word) == 0) {
        puts("Your access code is invalid.");
        return 0;
    }

    puts("Your spaceship is successfully enrolled!");
    return 1;
}

int authenticate_entry(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    puts("Authenticating your entry...");

    if (verify_portal_msg(portal_msg_buffer, portal_msg) == 0) {
        puts("You are not authorized to enter the portal.");
        return 0;
    }

    if (portal_msg->msg_header.msg_version != 0x01 || portal_msg->msg_header.msg_type != 0x05) {
        puts("You are not authorized to enter the portal.");
        return 0;
    }

    char str_concat[MAX_STRING_LEN * 2 + 1];
    strcpy(str_concat, spaceship_name);
    strcat(str_concat, access_word);

    if (strlen(str_concat) != portal_msg->msg_header.msg_data_len && memcmp(portal_msg->msg_data, str_concat, portal_msg->msg_header.msg_data_len) != 0) {
        puts("You are not authorized to enter the portal.");
        return 0;
    }

    uint8_t hash_value[MSG_DIGEST_LEN];
    md5_hash((uint8_t *)str_concat, strlen(str_concat), hash_value);
    memcpy(des_key, hash_value, DES_KEY_LEN);

    puts("You are successfully authenticated!");
    return 1;
}

void activate_wormhole() {
    puts("Activating wormhole...");

    if (getentropy(wormhole_signature, sizeof(wormhole_signature)) != 0) {
        fprintf(stderr, "Error: getentropy failed\n");
        exit(1);
    }

    puts("Wormhole activated!");
}

void leak_signature(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    puts("Leaking signature...");
    clear_portal_cache(portal_msg_buffer, portal_msg);

    portal_msg->msg_header.msg_type = 0x0d;
    portal_msg->msg_header.msg_data_len = sizeof(wormhole_signature);
    for (size_t i = 0; i < sizeof(wormhole_signature); i++) {
        portal_msg->msg_data[i] = ~wormhole_signature[sizeof(wormhole_signature) - 1 - i];
    }
    emit_portal_msg(portal_msg_buffer, portal_msg);

    puts("Signature leaked!");
}

int validate_signature(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    puts("Validating signature...");
    clear_portal_cache(portal_msg_buffer, portal_msg);

    if (verify_portal_msg(portal_msg_buffer, portal_msg) == 1 && portal_msg->msg_header.msg_type == 0x4c) {
        uint8_t received_signature[sizeof(wormhole_signature)];
        for (size_t i = 0; i < sizeof(wormhole_signature); i++) {
            received_signature[i] = portal_msg_buffer[sizeof(portal_msg_header_t) + i] ^ portal_msg->msg_header.transmission_noise;
        }
        if (memcmp(received_signature, wormhole_signature, sizeof(wormhole_signature)) == 0) {
            memcpy(des_key, received_signature, DES_KEY_LEN);
            puts("Your wormhole signature is valid!");
            return 1;
        }
    }

    puts("Your wormhole signature is invalid.");
    return 0;
}

void send_coordinate(uint8_t *portal_msg_buffer, portal_msg_t *portal_msg) {
    puts("Sending coordinate...");
    clear_portal_cache(portal_msg_buffer, portal_msg);

    char flag[0x100];
    memset(flag, 0, 0x100);
    FILE *fp = fopen("flag.txt", "r");
    if (!fp) {
        fprintf(stderr, "Error: fopen failed\n");
        exit(1);
    }
    if (fgets(flag, 0x100, fp) == NULL) {
        fprintf(stderr, "Error: fgets failed\n");
        fclose(fp);
        exit(1);
    }    
    fclose(fp);

    portal_msg->msg_header.msg_type = 0x42;
    portal_msg->msg_header.msg_data_len = strlen(flag) + (8 - strlen(flag) % 8) % 8;
    memcpy(portal_msg->msg_data, flag, portal_msg->msg_header.msg_data_len);
    emit_portal_msg(portal_msg_buffer, portal_msg);

    puts("Coordinate sent!");
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    srand(time(NULL));

    printf("Welcome to the intelligent portal in space!\n");

    while (1) {
        if (enroll_spaceship() == 0) {
            continue;
        }
        break;
    }

    printf("It will send you home without telling it the destination!\n");
    printf("You have to communicate with it in a special way!\n");

    uint8_t *portal_msg_buffer = malloc(sizeof(portal_msg_t));
    portal_msg_t *portal_msg = malloc(sizeof(portal_msg_t));

    while (1) {
        if (authenticate_entry(portal_msg_buffer, portal_msg) == 0) {
            continue;
        }
        break;
    }

    printf("Your spacehsip is now being teleported to the destination!\n");

    sleep(1);

    printf("Oops!!!\n");
    printf("The intelligent portal has been invaded by the aliens!\n");
    printf("You are trapped!\n");

    activate_wormhole();

    printf("The intelligent portal tried its best to open a wormhole for you before it lost its consciousness!\n");
    printf("But you have to escape by yourself with the leaked information!\n");

    leak_signature(portal_msg_buffer, portal_msg);

    while (1) {
        printf("👽👽👽👽\n");
        if (validate_signature(portal_msg_buffer, portal_msg) == 0) {
            continue;
        }
        printf("🛸🛸🛸🛸\n");
        break;
    }

    printf("Goodbye, alien!\n");
    printf("Escape is not the end!\n");
    printf("You are abandoned in unknown realms in the universe with the coordinate!\n");

    send_coordinate(portal_msg_buffer, portal_msg);

    return 0;
}