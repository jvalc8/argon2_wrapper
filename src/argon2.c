#include "argon2_wrapper.h"
#include <argon2.h>
#include <getopt.h>

const int MIN_PASSWD_LEN = 4;
const int MAX_PASSWD_LEN = 512;

const int DEFAULT_HASH_LEN = 32;


int argon2_hash_wrapper(const char *salt, int hash_len, int m_cost, int t_cost,
                        int parallelism, enum Argon2_type argon_type, int output_flag) {
    int s;
    char *passwd_buf = (char *)malloc(MAX_PASSWD_LEN);

    if (passwd_buf == NULL)
        return -2;

    s = getpasswd(passwd_buf, MAX_PASSWD_LEN);

    char *passwdbuf_eol = strchr(passwd_buf, '\n');

    if (passwdbuf_eol != NULL) {
        *passwdbuf_eol = '\0';
        s -= 1;
    }

    if (s < MIN_PASSWD_LEN || s >= MAX_PASSWD_LEN) {
        fprintf(stderr,
                "Error: Specified password must between 4 and %d characters "
                "long.\n",
                MAX_PASSWD_LEN);
        free(passwd_buf);
        return -3;
    }

    size_t encoded_len = argon2_encodedlen(t_cost, m_cost, parallelism,
                                           strlen(salt), hash_len, Argon2_id);

    char *hash_buf = (char *)malloc(hash_len + 1);
    if (hash_buf == NULL)
        return -3;

    char *encoded_hash = (char *)malloc(encoded_len);

    if (encoded_hash == NULL)
        return -3;

    s = argon2_hash(t_cost, m_cost, parallelism, passwd_buf, s, salt,
                    strlen(salt), hash_buf, hash_len, encoded_hash, encoded_len,
                    argon_type, ARGON2_VERSION_13);

    if (s != ARGON2_OK)
        fprintf(stderr, "argon2id err\n");


    if (output_flag == 0) {
        printf("hash_len: %d, memory_cost: %d, time_cost: %d, paralellism: %d\n",
               hash_len, m_cost, t_cost, parallelism);

        printf("Hash:\t\t");
        print_hex((uint8_t *)hash_buf, hash_len);
        printf("Encoded:\t%s\n", encoded_hash);
    } else {
        printf("%s\n", encoded_hash);
    }

    memset(passwd_buf, 0, MAX_PASSWD_LEN);
    memset(hash_buf, 0, hash_len + 1);
    memset(encoded_hash, 0, encoded_len);

    free(hash_buf);
    free(encoded_hash);
    free(passwd_buf);

    return 0;
}

int main(int argc, char *argv[]) {
    int opts;
    int hash_len = DEFAULT_HASH_LEN;
    int parallelism = ARGON2_MIN_THREADS;
    int time_cost = ARGON2_MIN_TIME;
    int memory_cost = ARGON2_MIN_MEMORY;
    int output_flag = 0;

    char *endptr;
    char *hash_salt = NULL;

    enum Argon2_type argon2_type = Argon2_i;

    while ((opts = getopt(argc, argv, "p:l:m:t:hide")) != -1) {
        switch (opts) {
        case 'p':
            parallelism = (int)strtol(optarg, &endptr, 10);

            if (*endptr != '\0') {
                fprintf(
                    stderr,
                    "Error: Specified THREADS argument is not an integer.\n");
                usage(argv[0]);
            }
            break;
        case 'l':
            hash_len = (int)strtol(optarg, &endptr, 10);

            if (*endptr != '\0') {
                fprintf(
                    stderr,
                    "Error: Specified HASH_LEN argument is not an integer.\n");
                usage(argv[0]);
            }
            break;
        case 'm':
            memory_cost = (int)strtol(optarg, &endptr, 10);

            if (*endptr != '\0') {
                fprintf(stderr, "Error: Specified MEMORY_COST argument is not "
                                "an integer.\n");
                usage(argv[0]);
            }
            break;
        case 't':
            time_cost = (int)strtol(optarg, &endptr, 10);

            if (*endptr != '\0') {
                fprintf(stderr, "Error: Specified ITERATIONS argument is not "
                                "an integer.\n");
                usage(argv[0]);
            }
            break;
        case 'i':
            argon2_type = Argon2_i;
            break;
        case 'd':
            argon2_type = Argon2_d;
            break;
        case 'e':
            output_flag = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    if (optind < argc)
        hash_salt = argv[optind];

    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], "-id") == 0)
            argon2_type = Argon2_id;

    if (hash_salt == NULL) {
        fprintf(stderr, "Error: Password SALT argument was not specified.\n");
        usage(argv[0]);
    }

    if (strlen(hash_salt) < ARGON2_MIN_SALT_LENGTH) {
        fprintf(stderr,
                "Error: Specified SALT argument is not longer than %d "
                "characters.\n",
                ARGON2_MIN_SALT_LENGTH);
        usage(argv[0]);
    }

    memory_cost = 1 << memory_cost;
    argon2_hash_wrapper((const char *)hash_salt, hash_len, memory_cost,
                        time_cost, parallelism, argon2_type, output_flag);
    return EXIT_SUCCESS;
}
