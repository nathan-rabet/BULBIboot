#include "console.h"

#include "kstring.h"
#include "uart.h"

static const char bulbiboot_header[] =
BLUE_STR("                                           /") CRLF
BLUE_STR("                        _,.------....___,.' ',.-.") CRLF
BLUE_STR("                     ,-'          _,.--\"        |") CRLF
BLUE_STR("                   ,'         _.-'              .") CRLF
BLUE_STR("                  /   ,     ,'                   `") CRLF
BLUE_STR("                 .   /     /                     ``.") CRLF
BLUE_STR("                 |  |     .                       \\.\\") CRLF
BLUE_STR("       ____      |___._.  |       __               \\ `.") CRLF
GREEN_STR("     .'    `---\"\"       ``\"-.--\"'`  \\") BLUE_STR("               .  \\") CRLF
GREEN_STR("    .  ,            __               `") BLUE_STR("              |   .") CRLF
GREEN_STR("    `,'         ,-\"'  .               \\") BLUE_STR("             |    L") CRLF
GREEN_STR("   ,'          '    _.'                -._") BLUE_STR("          /    |") CRLF
GREEN_STR("  ,`-.    ,\".   `--'                      >.") BLUE_STR("      ,'     |") CRLF
GREEN_STR(" . .'\\'   `-'       __    ,  ,-.         /  `.") BLUE_STR("__.-      ,'") CRLF
GREEN_STR(" ||:, .           ,'  ;  /  / \\ `        `.    .") BLUE_STR("      .'/") CRLF
GREEN_STR(" j|:D  \\          `--'  ' ,'_  . .         `.__, \\") BLUE_STR("   , /") CRLF
GREEN_STR("/ L:_  |                 .  \"' :_;                `") BLUE_STR(".'.'") CRLF
GREEN_STR(".    \"\"'                  \"\"\"\"\"'                    ") BLUE_STR("V") CRLF
GREEN_STR(" `.                                 .    `.   _,..  `") CRLF
GREEN_STR("   `,_   .    .                _,-'/    .. `,'   __  `") CRLF
GREEN_STR("    ) \\`._        ___....----\"'  ,'   .'  \\ |   '  \\  .") CRLF
GREEN_STR("   /   `. \"`-.--\"'         _,' ,'     `---' |    `./  |") CRLF
GREEN_STR("  .   _  `\"\"'--.._____..--\"   ,             '         |") CRLF
GREEN_STR("  | .\" `. `-.                /-.           /          ,") CRLF
GREEN_STR("  | `._.'    `,_            ;  /         ,'          .") CRLF
GREEN_STR(" .'          /| `-.        . ,'         ,           ,") CRLF
GREEN_STR(" '-.__ __ _,','    '`-..___;-...__   ,.'\\ ____.___.'") CRLF
GREEN_STR(" `\"^--'..'   '-`-^-'\"--    `-^-'`.''\"\"\"\"\"`.,^.`.--'") CRLF;

void print_bulbiboot_header(void)
{
    kputs(bulbiboot_header);
}

void kputc(char c)
{
    if (uart_write((unsigned char *)&c, 1, (uart_t *)UART0_ADDR) == (u64)-1)
        return; // panic("UART0 is not working");
}

char kgetc()
{
    while (!check_uart_read_ready((volatile uart_t *)UART0_ADDR))
        ;

    char c = 0;
    if (uart_read((unsigned char *)&c, 1, (uart_t *)UART0_ADDR) == (u64)-1)
        return c; // panic("UART0 is not working");

    return c;
}

void kputs(const char *s)
{
    if (uart_write((unsigned char *)s, strlen(s), (uart_t *)UART0_ADDR)
        == (u64)-1)
        return; // panic("UART0 is not working");
}
