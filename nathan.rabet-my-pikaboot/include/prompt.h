#ifndef PROMPT_H
#define PROMPT_H

/**
 * @brief Set the console prefix (e.g "bootloader > ")
 *
 * @param prefix The prefix to set
 */
void set_console_prefix(char const *prefix);

/**
 * @brief Show the prompt and wait for user input
 *
 * @return char* The user input when he pressed enter
 */
char *prompt(void);

#endif /* PROMPT_H */
