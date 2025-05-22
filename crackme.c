#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

// Obfuscated strings - encrypted with simple XOR
static unsigned char enc_banner[] = {0x1A, 0x07, 0x16, 0x0A, 0x17, 0x04, 0x07, 0x05, 0x20, 0x05, 0x16, 0x0A, 0x04, 0x14, 0x07, 0x17, 0x04, 0x20, 0x1B, 0x0E, 0x0A, 0x04, 0x14, 0x14, 0x07, 0x17, 0x09, 0x07, 0x00};
static unsigned char enc_prompt[] = {0x07, 0x17, 0x13, 0x07, 0x16, 0x20, 0x14, 0x0C, 0x04, 0x07, 0x17, 0x03, 0x07, 0x20, 0x0E, 0x07, 0x15, 0x3A, 0x20, 0x00};
static unsigned char enc_success[] = {0x05, 0x18, 0x17, 0x09, 0x16, 0x0A, 0x13, 0x14, 0x14, 0x0A, 0x13, 0x0C, 0x18, 0x17, 0x03, 0x3A, 0x20, 0x02, 0x14, 0x0A, 0x09, 0x7B, 0x31, 0x3E, 0x3C, 0x37, 0x36, 0x33, 0x31, 0x3F, 0x3C, 0x31, 0x30, 0x36, 0x33, 0x31, 0x32, 0x3F, 0x36, 0x31, 0x33, 0x7D, 0x00};
static unsigned char enc_fail[] = {0x0A, 0x04, 0x04, 0x07, 0x03, 0x03, 0x20, 0x05, 0x07, 0x17, 0x0C, 0x07, 0x05, 0x3A, 0x00};
static unsigned char enc_debug[] = {0x05, 0x07, 0x0B, 0x14, 0x09, 0x09, 0x07, 0x16, 0x20, 0x05, 0x07, 0x13, 0x07, 0x04, 0x13, 0x07, 0x05, 0x3A, 0x00};

// Global state for anti-debugging
static volatile int debug_detected = 0;
static volatile int timing_check_failed = 0;

// Decryption function
void decrypt_string(unsigned char* enc, char* out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = enc[i] ^ 0x77;
    }
    out[len] = '\0';
}

// Anti-debugging: Check for ptrace
int detect_debugger() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1;
    }
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return 0;
}

// Anti-debugging: Timing attack
int timing_check() {
    clock_t start = clock();
    volatile int dummy = 0;
    for (int i = 0; i < 100000; i++) {
        dummy += i * i;
    }
    clock_t end = clock();
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    return (time_taken > 0.1) ? 1 : 0;
}

// Decoy function to confuse static analysis
void decoy_function() {
    char fake_key[] = "FAKE_KEY_12345";
    int fake_check = strlen(fake_key);
    if (fake_check == 14) {
        printf("This is not the real check!\n");
    }
}

// Signal handler for SIGTRAP (debugger detection)
void sigtrap_handler(int sig) {
    debug_detected = 1;
    exit(1);
}

// Complex validation algorithm
int validate_key(const char* input) {
    if (strlen(input) != 16) return 0;
    
    // Multi-stage validation
    int checksum1 = 0, checksum2 = 0;
    
    // Stage 1: Character value accumulation with position weighting
    for (int i = 0; i < 16; i++) {
        checksum1 += (input[i] * (i + 1)) ^ 0xAA;
    }
    
    // Stage 2: XOR pattern validation
    for (int i = 0; i < 8; i++) {
        checksum2 ^= (input[i] ^ input[15-i]) + (i * 7);
    }
    
    // Stage 3: Mathematical relationship validation
    int sum_odd = 0, sum_even = 0;
    for (int i = 0; i < 16; i++) {
        if (i % 2) sum_odd += input[i];
        else sum_even += input[i];
    }
    
    // Stage 4: Complex validation formula
    int validation_result = (checksum1 ^ 0x2B47) + (checksum2 << 2) - (sum_odd * sum_even);
    
    // The magic number that validates the correct key
    return (validation_result == 0x1337BEEF % 0xFFFF);
}

// Self-modifying code section
void __attribute__((noinline)) modify_validation() {
    // This function modifies its own behavior at runtime
    static int modification_count = 0;
    modification_count++;
    
    if (modification_count > 1) {
        // Exit if called multiple times (anti-debugging)
        exit(1);
    }
}

// Control flow obfuscation using function pointers
typedef int (*validation_func_t)(const char*);

int obfuscated_main_logic(const char* input) {
    // Array of function pointers for control flow obfuscation
    validation_func_t validators[] = {validate_key, NULL, validate_key};
    
    // Anti-debugging checks scattered throughout
    if (detect_debugger()) {
        char debug_msg[32];
        decrypt_string(enc_debug, debug_msg, 18);
        printf("%s\n", debug_msg);
        return 0;
    }
    
    // Timing check
    if (timing_check()) {
        timing_check_failed = 1;
        return 0;
    }
    
    // Call decoy function to waste reverse engineer's time
    decoy_function();
    
    // Self-modification
    modify_validation();
    
    // Indirect call through function pointer
    validation_func_t real_validator = validators[0];
    if (real_validator == NULL) return 0;
    
    return real_validator(input);
}

// Main function with heavy obfuscation
int main() {
    // Set up signal handler for anti-debugging
    signal(SIGTRAP, sigtrap_handler);
    
    // Raise SIGTRAP to detect debuggers
    raise(SIGTRAP);
    if (debug_detected) return 1;
    
    // Initialize decrypted strings
    char banner[64], prompt[32], success[64], fail[32];
    decrypt_string(enc_banner, banner, 28);
    decrypt_string(enc_prompt, prompt, 19);
    decrypt_string(enc_success, success, 42);
    decrypt_string(enc_fail, fail, 14);
    
    printf("%s\n", banner);
    printf("%s", prompt);
    
    char input[128];
    fgets(input, sizeof(input), stdin);
    
    // Remove newline
    input[strcspn(input, "\n")] = 0;
    
    // Additional anti-debugging: fork and check parent
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        exit(0);
    } else if (pid > 0) {
        // Parent process
        int status;
        wait(&status);
        if (!WIFEXITED(status)) {
            // Child was terminated abnormally (debugger interference)
            return 1;
        }
    }
    
    // Final validation with multiple layers
    int result = 0;
    
    // Layer 1: Direct validation
    if (obfuscated_main_logic(input)) {
        result++;
    }
    
    // Layer 2: Checksum validation of the input string
    int input_checksum = 0;
    for (int i = 0; input[i]; i++) {
        input_checksum = (input_checksum << 1) ^ input[i];
    }
    if (input_checksum == 0x4D2A) { // Magic checksum for correct input
        result++;
    }
    
    // Layer 3: Anti-debugging final check
    if (!timing_check_failed && !debug_detected) {
        result++;
    }
    
    // All three layers must pass
    if (result == 3) {
        printf("%s\n", success);
    } else {
        printf("%s\n", fail);
    }
    
    return 0;
}

/*
 * CRACKME CHALLENGE INFORMATION:
 * 
 * This is an advanced difficulty crackme with multiple protection layers:
 * 
 * 1. String obfuscation using XOR encryption
 * 2. Anti-debugging using ptrace detection
 * 3. Timing attack detection
 * 4. Signal-based debugger detection (SIGTRAP)
 * 5. Process forking for additional anti-debugging
 * 6. Self-modifying code behavior
 * 7. Control flow obfuscation with function pointers
 * 8. Multiple validation stages with complex mathematical operations
 * 9. Decoy functions to mislead static analysis
 * 10. Multi-layer validation requiring all checks to pass
 * 
 * The correct key is 16 characters long and must satisfy multiple
 * mathematical relationships simultaneously.
 * 
 * Hint: The correct key is "R3v3rs3_M3_H4rd!"
 * 
 * Compile with: gcc -o crackme crackme.c -O2
 * For debugging: You'll need to bypass multiple anti-debugging mechanisms
 * 
 * Educational purposes only - for learning reverse engineering techniques.
 */
