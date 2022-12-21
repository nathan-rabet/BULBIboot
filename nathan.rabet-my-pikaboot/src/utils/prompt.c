#include "prompt.h"

#include <stdbool.h>

#include "console.h"
#include "int.h"
#include "kassert.h"
#include "kstring.h"
#include "uart.h"

#define BUF_SIZE 1024
#define NB_HISTORY 10

static u32 buf_i = 0;
static char buf[BUF_SIZE] = { 0 };

static u8 history_i = 0;
static u8 history_nb = 0;
static u8 up_key_counter = 0;
static char history[NB_HISTORY][BUF_SIZE] = { 0 };

static char const *prompt_text = NULL;

static void get_history_line(u8 up_key_counter)
{
    if (history[(history_i - up_key_counter) % history_nb][0] != '\0')
    {
        for (u32 i = 0; i < buf_i; i++)
            kputs("\b \b");
        kputs(history[(history_i - up_key_counter) % history_nb]);
        strcpy(buf, history[(history_i - up_key_counter) % history_nb]);

        buf_i = strlen(buf);
        up_key_counter++;
    }
}

void set_console_prefix(char const *prefix)
{
    prompt_text = prefix;
}

char *prompt(void)
{
    kassertm(prompt_text != NULL, "Prompt text not set");

    // Reset prompt buffer
    memset(buf, 0, BUF_SIZE);
    buf_i = 0;
    up_key_counter = 0;

    // Reset history
    for (u32 i = 0; i < NB_HISTORY; i++)
        memset(history[i], 0, BUF_SIZE);

    kputs(prompt_text);
    while (buf_i < sizeof(buf))
    {
        unsigned char typed[3] = { 0 };
        u8 read = 0;
        while ((read = uart_read(typed, sizeof(typed),
                                 (volatile uart_t *)UART0_ADDR))
               == 0)
            ;

        // In case of deletion character
        if (typed[0] == 0x7F)
        {
            if (buf_i > 0)
            {
                kputs("\b \b");
                buf[--buf_i] = '\0';
            }
        }

        // In case of left arrow
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x44)
        {
            if (buf_i > 0)
            {
                kputs("\b");
                buf_i--;
            }
        }

        // In case of right arrow
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x43)
        {
            if (buf_i < BUF_SIZE - 1 && buf[buf_i] != '\0')
                kputc(buf[buf_i++]);
        }

        // In case of up arrow (history up)
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x41)
        {
            if (up_key_counter + 1 <= history_nb)
                get_history_line(++up_key_counter);
        }

        // In case of down arrow (history down)
        else if (typed[0] == 0x1B && typed[1] == 0x5B && typed[2] == 0x42)
        {
            if (up_key_counter <= 1) // up_key_counter - 1 <= 0 (overflow safe)
            {
                for (u32 i = 0; i < buf_i; i++)
                    kputs("\b \b");
                memset(buf, 0, BUF_SIZE);
                buf_i = 0;
                up_key_counter = 0;
            }
            else
                get_history_line(--up_key_counter);
        }

        // In case of any other character
        else if (buf_i < BUF_SIZE - 1)
        {
            for (u32 i = 0; i < read && buf_i < sizeof(buf); i++)
            {
                // In case of newline
                if (typed[i] == '\r' || typed[i] == '\n')
                {
                    if (buf_i > 0)
                    {
                        history_nb = MIN(history_nb + 1, NB_HISTORY);
                        strcpy(history[history_i], buf);
                        history_i = (history_i + 1) % NB_HISTORY;
                    }
                    kputs(CRLF);
                    return buf;
                }

                // In case of any printable character
                else if (typed[0] >= 0x20 && typed[0] <= 0x7E)
                {
                    kputc(typed[i]);
                    buf[buf_i++] = typed[i];
                }
            }
        }
    }
    kputs(CRLF);
    return buf;
}
