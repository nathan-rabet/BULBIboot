#ifndef CONSOLE_H
#define CONSOLE_H

#define CRLF "\r\n"
#define RED_STR(str) "\033[31m" str "\033[0m"
#define YELLOW_STR(str) "\033[33m" str "\033[0m"
#define GREEN_STR(str) "\033[32m" str "\033[0m"
#define BLUE_STR(str) "\033[34m" str "\033[0m"
#define RESET_STR(str) "\033[0m" str "\033[0m"

/**
 * @brief Print the header of the bootloader
 */
void print_bulbiboot_header(void);

/**
 * @brief Write a character to the UART0
 *
 * @param c The character to write
 */
void kputc(char c);

/**
 * @brief Read a character from the UART0
 *
 * @return char The character read
 */
char kgetc();

/**
 * @brief Write a string to the UART0
 *
 * @param s The string to write
 */
void kputs(const char *s);

#endif /* CONSOLE_H */
