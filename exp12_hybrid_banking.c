/*
 * ==================================================================
 *  Experiment 12 : RSA + AES Hybrid Encryption
 *  Secure transmission of online banking transaction data
 *  Computer Networks and Security Laboratory (PCEC402)
 *  Sanjivani College of Engineering, Kopargaon - Dept. of ECE
 * ==================================================================
 *  Compile : gcc exp12_hybrid_banking.c -o exp12
 *  Run     : exp12            (Windows - Command Prompt / VS Code)
 *            ./exp12          (Linux / macOS)
 *
 *  Demo login ->  Username : customer1
 *                 Password : Bank@123
 *
 *  NOTE: As in the lab manual, the "AES" step is a simplified
 *  XOR cipher with session key 45, used to illustrate symmetric
 *  encryption. Real AES-128 runs 10 rounds of SubBytes, ShiftRows,
 *  MixColumns and AddRoundKey on 128-bit blocks.
 * ==================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
  #include <conio.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

#define MAX_ATTEMPTS  3            /* login lockout threshold        */
#define AES_KEY       45           /* session key (from lab manual)  */
#define TXN_LIMIT     100000.0     /* per-transaction limit in Rs.   */

/* Stored credentials: the bank keeps only a HASH of the password,
   never the plain password. 0x97C8D397 = hash("Bank@123").
   (Real systems use salted bcrypt / Argon2.)                        */
static const char        *STORED_USER      = "customer1";
static const unsigned int STORED_PASS_HASH = 0x97C8D397u;

/* ======================= Display helpers ======================= */

static void line(void)
{
    printf("------------------------------------------------------\n");
}

static void heading(const char *title)
{
    printf("\n======================================================\n");
    printf(" %s\n", title);
    printf("======================================================\n");
}

/* Print bytes as hex - encrypted bytes are not printable text */
static void print_hex(const char *data, int len)
{
    int i;
    printf("    ");
    for (i = 0; i < len; i++) {
        printf("%02X ", (unsigned char)data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n    ");
    }
    printf("\n");
}

/* Print bytes as text, showing non-printable bytes as '.' */
static void print_safe(const char *data, int len)
{
    int i;
    printf("    ");
    for (i = 0; i < len; i++) {
        putchar(isprint((unsigned char)data[i]) ? data[i] : '.');
        if ((i + 1) % 48 == 0 && i + 1 < len) printf("\n    ");
    }
    printf("\n");
}

/* ======================= Input helpers ========================= */

/* Bounded line input - prevents buffer overflow */
static void read_line(char *buf, int size)
{
    char *nl;
    if (fgets(buf, size, stdin) == NULL) {
        printf("\nInput closed. Exiting.\n");
        exit(1);
    }
    nl = strchr(buf, '\n');
    if (nl) *nl = '\0';
    else { int c; while ((c = getchar()) != '\n' && c != EOF); }  /* drop extra */
}

/* Password input with masking (shows * instead of characters) */
static void read_password(char *buf, int size)
{
    int i = 0, ch;
#ifdef _WIN32
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == 0 || ch == 224) { _getch(); continue; }   /* arrow / F-keys */
        if (ch == '\b') { if (i > 0) { i--; printf("\b \b"); } }
        else if (i < size - 1 && isprint(ch)) { buf[i++] = (char)ch; printf("*"); }
    }
    buf[i] = '\0';
    printf("\n");
#else
    struct termios oldt, newt;
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &oldt) != 0) {
        read_line(buf, size);                       /* piped input */
        for (i = 0; buf[i]; i++) putchar('*');
        printf("\n");
        return;
    }
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 127 || ch == '\b') { if (i > 0) { i--; printf("\b \b"); } }
        else if (i < size - 1 && isprint(ch)) { buf[i++] = (char)ch; printf("*"); }
        fflush(stdout);
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    buf[i] = '\0';
    printf("\n");
#endif
}

/* Account number: 6 to 16 digits only */
static int valid_account(const char *s)
{
    int i, len = (int)strlen(s);
    if (len < 6 || len > 16) return 0;
    for (i = 0; i < len; i++)
        if (!isdigit((unsigned char)s[i])) return 0;
    return 1;
}

/* Amount: digits with at most one '.', > 0 and within the limit */
static int valid_amount(const char *s)
{
    int i, dots = 0, len = (int)strlen(s);
    double value;
    if (len == 0 || len > 12) return 0;
    for (i = 0; i < len; i++) {
        if (s[i] == '.') { if (++dots > 1) return 0; }
        else if (!isdigit((unsigned char)s[i])) return 0;
    }
    value = atof(s);
    return value > 0 && value <= TXN_LIMIT;
}

/* Show only last 4 digits: 123456789 -> XXXXX6789 */
static void mask_account(const char *acc, char *out)
{
    int i, len = (int)strlen(acc);
    for (i = 0; i < len; i++) out[i] = (i < len - 4) ? 'X' : acc[i];
    out[len] = '\0';
}

/* ================== Integrity: 32-bit hash (djb2) ============== */
/* Same input -> same hash. Any change in data -> different hash.  */
static unsigned int hash32(const char *s, int len)
{
    unsigned int h = 5381u;
    int i;
    for (i = 0; i < len; i++) h = h * 33u + (unsigned char)s[i];
    return h;
}

/* ==================== RSA (from lab manual) ==================== */

long long power(long long b, long long e, long long m)
{
    long long r = 1;
    b %= m;
    while (e > 0) {
        if (e % 2) r = (r * b) % m;
        b = (b * b) % m;
        e /= 2;
    }
    return r;
}

long long gcd(long long a, long long b)
{
    while (b) {
        long long t = b;
        b = a % b;
        a = t;
    }
    return a;
}

long long inverse(long long e, long long phi)
{
    long long d;
    for (d = 2; d < phi; d++)
        if ((e * d) % phi == 1) return d;
    return -1;
}

void rsa_keys(long long *e, long long *d, long long *n)
{
    int p = 61, q = 53;
    long long phi = (long long)(p - 1) * (q - 1);
    *n = (long long)p * q;
    for (*e = 2; *e < phi; (*e)++)
        if (gcd(*e, phi) == 1) break;
    *d = inverse(*e, phi);

    printf("p = %d, q = %d\n", p, q);
    printf("n = p x q           = %lld\n", *n);
    printf("phi(n) = (p-1)(q-1) = %lld\n", phi);
    printf("e (gcd(e,phi) = 1)  = %lld\n", *e);
    printf("d ((e x d) mod phi = 1) = %lld\n", *d);
    printf("Public Key  (e, n) = (%lld, %lld)\n", *e, *n);
    printf("Private Key (d, n) = (%lld, %lld)   [kept secret on server]\n", *d, *n);
}

/* ============== Simplified AES (XOR, as in lab manual) ========== */
/* Same function encrypts and decrypts (symmetric key).
   Length is passed explicitly because an encrypted byte can be 0. */
void aes_encrypt_decrypt(char *data, int len, int key)
{
    int i;
    for (i = 0; i < len; i++) data[i] ^= (char)key;
}

/* ========================= Part A : Login ====================== */

static int login(void)
{
    char user[32], pass[32];
    int attempt, ok;

    for (attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        printf("Username : ");
        read_line(user, sizeof user);
        printf("Password : ");
        read_password(pass, sizeof pass);

        ok = strcmp(user, STORED_USER) == 0 &&
             hash32(pass, (int)strlen(pass)) == STORED_PASS_HASH;
        memset(pass, 0, sizeof pass);           /* wipe password from memory */

        if (ok) {
            printf("\nLogin successful. Welcome, %s!\n", user);
            return 1;
        }
        printf("Invalid username or password. Attempts left: %d\n\n",
               MAX_ATTEMPTS - attempt);
    }
    printf("Account LOCKED after %d failed attempts.\n", MAX_ATTEMPTS);
    return 0;
}

/* ============================= main ============================ */

int main(void)
{
    long long e, d, n, enc_key, rec_key;
    char sender[24], receiver[24], amount[16], choice[8];
    char txn[256], packet[256], attacker[256];
    char masked_s[24], masked_r[24];
    unsigned int h_sender, h_server;
    int len, tamper, amt_pos;

    printf("\n  SECURE ONLINE BANKING  |  RSA + AES Hybrid Encryption\n");

    /* ---------------- Part A : Secure login ---------------- */
    heading("PART A : SECURE LOGIN");
    if (!login()) return 1;

    /* ---------------- RSA key generation (server) ---------- */
    heading("RSA KEY GENERATION  (Bank Server)");
    rsa_keys(&e, &d, &n);

    /* ---------------- Part B : Transaction ----------------- */
    heading("PART B : TRANSACTION DETAILS");
    for (;;) {
        printf("Sender Account No.   : ");
        read_line(sender, sizeof sender);
        if (valid_account(sender)) break;
        printf("  ! Invalid - enter 6 to 16 digits only\n");
    }
    for (;;) {
        printf("Receiver Account No. : ");
        read_line(receiver, sizeof receiver);
        if (!valid_account(receiver))
            printf("  ! Invalid - enter 6 to 16 digits only\n");
        else if (strcmp(sender, receiver) == 0)
            printf("  ! Receiver cannot be the same as sender\n");
        else break;
    }
    for (;;) {
        printf("Amount (Rs.)         : ");
        read_line(amount, sizeof amount);
        if (valid_amount(amount)) break;
        printf("  ! Invalid - enter a number between 1 and %.0f\n", TXN_LIMIT);
    }

    len = snprintf(txn, sizeof txn,
                   "ONLINE BANKING TRANSACTION\nSender:%s\nReceiver:%s\nAmount:%s",
                   sender, receiver, amount);

    printf("\nOriginal Transaction (plaintext):\n");
    line();
    printf("%s\n", txn);
    line();

    /* ---------------- Part C : Encryption ------------------ */
    heading("PART C : ENCRYPTION  (Customer side)");

    h_sender = hash32(txn, len);
    printf("[1] AES session key            : %d\n", AES_KEY);
    printf("[2] Integrity hash of data     : %08X\n", h_sender);

    memcpy(packet, txn, len);
    aes_encrypt_decrypt(packet, len, AES_KEY);
    printf("[3] AES-encrypted transaction  (%d bytes, hex):\n", len);
    print_hex(packet, len);

    enc_key = power(AES_KEY, e, n);
    printf("[4] AES key encrypted with RSA public key:\n");
    printf("    C = K^e mod n = %d^%lld mod %lld = %lld\n", AES_KEY, e, n, enc_key);

    /* ---------------- Transmission ------------------------- */
    heading("SECURE TRANSMISSION  -->  Bank Server");
    printf("Packet = [Encrypted data] + [Encrypted AES key: %lld] + [Hash: %08X]\n",
           enc_key, h_sender);

    printf("\nSimulate a hacker tampering with the packet? (y/n): ");
    read_line(choice, sizeof choice);
    tamper = (choice[0] == 'y' || choice[0] == 'Y');

    /* ---------------- Attacker's view ---------------------- */
    heading("ATTACKER'S VIEW  (Eavesdropper on the network)");
    printf("Intercepted encrypted key : %lld  (useless without private key d)\n",
           enc_key);
    memcpy(attacker, packet, len);
    aes_encrypt_decrypt(attacker, len, 100);       /* wrong key guess */
    printf("Decryption attempt with a guessed key (100):\n");
    print_safe(attacker, len);
    printf("Result: unreadable - data stays CONFIDENTIAL.\n");

    if (tamper) {
        amt_pos = (int)(strstr(txn, "Amount:") - txn) + 7;
        packet[amt_pos] ^= 0x01;                  /* flip 1 bit of amount */
        printf("\n!! Hacker flipped a bit in the encrypted amount field !!\n");
    }

    /* ---------------- Part D : Decryption ------------------ */
    heading("PART D : DECRYPTION  (Bank Server)");
    rec_key = power(enc_key, d, n);
    printf("[1] Recover AES key using private key d:\n");
    printf("    K = C^d mod n = %lld^%lld mod %lld = %lld\n", enc_key, d, n, rec_key);

    aes_encrypt_decrypt(packet, len, (int)rec_key);
    packet[len] = '\0';
    printf("[2] Decrypted transaction:\n");
    line();
    printf("%s\n", packet);
    line();

    /* ---------------- Verification ------------------------- */
    /* The server never has the original, so it compares hashes. */
    heading("TRANSACTION VERIFICATION");
    h_server = hash32(packet, len);
    printf("Hash sent by customer : %08X\n", h_sender);
    printf("Hash computed at bank : %08X\n", h_server);

    if (h_server == h_sender) {
        mask_account(sender, masked_s);
        mask_account(receiver, masked_r);
        printf("\n>>> Transaction Verified Successfully! <<<\n");
        printf("Rs. %s transferred from A/c %s to A/c %s\n",
               amount, masked_s, masked_r);
    } else {
        printf("\n>>> Transaction Verification Failed! <<<\n");
        printf("Data was modified in transit - transaction REJECTED.\n");
    }

    /* Wipe sensitive data from memory before exit */
    memset(txn, 0, sizeof txn);
    memset(packet, 0, sizeof packet);
    memset(attacker, 0, sizeof attacker);
    return 0;
}
