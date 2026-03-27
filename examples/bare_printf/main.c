/*
 * bare_printf — Hello World, bare-metal RISC-V for emuko.
 *
 * No libc, no OS.  Writes directly to the ns16550 UART at 0x10000000.
 * Prints a greeting every PRINT_EVERY loop iterations (compiled with -O0
 * so the loop body is never optimised away).
 */

#define UART_TX     ((volatile unsigned char *)0x10000000UL)
#define PRINT_EVERY 10000000UL

static void putc_(char c)
{
    *UART_TX = (unsigned char)c;
}

static void puts_(const char *s)
{
    while (*s)
        putc_(*s++);
}

static void putu_(unsigned long v)
{
    char buf[21];
    int  i = 20;
    buf[i] = '\0';
    if (v == 0) { putc_('0'); return; }
    while (v && i > 0) {
        buf[--i] = '0' + (int)(v % 10);
        v /= 10;
    }
    puts_(buf + i);
}

void main(void)
{
    unsigned long iter  = 0;
    unsigned long count = 0;

    puts_("bare_printf: Hello, RISC-V World!\r\n");

    for (;;) {
        iter++;
        if (iter >= PRINT_EVERY) {
            iter = 0;
            count++;
            puts_("Hello World #");
            putu_(count);
            puts_("\r\n");
        }
    }
}
