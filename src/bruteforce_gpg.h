#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <pthread.h>
#include <gpgme.h>

#include "log.h"

#define USAGE "%s [-h] [-v] [-t NUM_THREADS] -f WORDLIST GPG_SECRET_KEYFILE | FINGERPRINT\n"
#define ERR_BUF_LEN 500

struct callback_data {
  FILE *password_file;
  unsigned int *attempt;
  char *line;
  size_t line_length;
};

struct thread_args {
  FILE *wordlist;
  char *fingerprint;
  time_t end_time;
  pthread_t *workers;
  long num_workers;
  unsigned int attempt;
  char *passphrase;
};

char *bruteforce_gpg_import_secret_key(char *secret_key_filename, char **fingerprint);
bool bruteforce_gpg_delete_secret_key(char const *fingerprint);
void *bruteforce_gpg_crack_passphrase(void *args);
