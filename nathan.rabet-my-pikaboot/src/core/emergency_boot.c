#include "emergency_boot.h"

#include "asm.h"
#include "debug.h"
#include "int.h"
#include "kermit.h"
#include "kstring.h"
#include "number.h"
#include "uart.h"
#include "kassert.h"
#include "virtboardio.h"

static int kermit_receive(unsigned char *const input_buffer,
                          int intput_buffer_size)
{
    struct k_data k; /* Kermit data structure */
    short r_slot; /* Kermit receive slot */

    k.xfermode = 0; /* Text/binary automatic/manual  */
    k.remote = 1; /* Remote vs local */
    k.binary = 1; /* 0 = text, 1 = binary */
    k.parity = P_PARITY; /* Communications parity */
    k.bct = 3; /* Block check type */
    k.ikeep = 0; /* Keep incompletely received files */
    k.filelist = NULL; /* List of files to send (if any) */
    k.cancel = 0; /* Not canceled yet */
    k.dbf = 0; /* Debugging flag */

    /*  Fill in the i/o pointers  */
    extern UCHAR o_buf[];
    k.zinbuf = input_buffer; /* File input buffer */
    k.zinlen = intput_buffer_size; /* File input buffer length */
    k.zincnt = 0; /* File input buffer position */
    k.obuf = o_buf; /* File output buffer */
    k.obuflen = OBUFLEN; /* File output buffer length */
    k.obufpos = 0; /* File output buffer position */

    /* Fill in function pointers */
    k.rxd = readpkt; /* for reading packets */
    k.txd = tx_data; /* for sending packets */
    k.ixd = inchk; /* for checking connection */
    k.openf = openfile; /* for opening files */
    k.finfo = fileinfo; /* for getting file info */
    k.readf = readfile; /* for reading files */
    k.writef = writefile; /* for writing to output file */
    k.closef = closefile; /* for closing files */
#ifdef DEBUG
    k.dbf = dodebug; /* for debugging */
#else
    k.dbf = 0;
#endif /* DEBUG */

    struct k_response r; /* Kermit response structure */
    int kermit_status = kermit(K_INIT, &k, 0, 0, "", &r);
    debug(DB_LOG, "init status:", 0, status);
    debug(DB_LOG, "version:", k.version, 0);

    if (kermit_status == X_ERROR)
        return FAILURE;

    while (kermit_status != X_DONE)
    {
        UCHAR *inbuf = getrslot(&k, &r_slot); /* Allocate a window slot */
        int rx_len = k.rxd(&k, inbuf, P_PKTLEN); /* Try to read a packet */
        debug(DB_PKT, "main packet", &(k.ipktbuf[0][r_slot]), rx_len);

        if (rx_len < 1)
        { /* No data was read */
            freerslot(&k, r_slot); /* So free the window slot */
            if (rx_len < 0) /* If there was a fatal error */
                return FAILURE; /* Return with error */
        }

        switch (kermit_status = kermit(K_RUN, &k, r_slot, rx_len, "", &r))
        {
        case X_OK:
            debug(DB_LOG, "NAME", r.filename ? (char *)r.filename : "(NULL)",
                  0);
            debug(DB_LOG, "DATE", r.filedate ? (char *)r.filedate : "(NULL)",
                  0);
            debug(DB_LOG, "SIZE", 0, r.filesize);
            debug(DB_LOG, "STATE", 0, r.status);
            debug(DB_LOG, "SOFAR", 0, r.sofar);
        case X_DONE:
            debug(DB_LOG, "DONE", 0, 0);
            return SUCCESS;
        case X_ERROR:
            debug(DB_LOG, "ERROR", 0, 0);
            return FAILURE;
        }
    }

    return SUCCESS;
}

void emergency_boot(void)
{
    volatile uart_t *emergency_uart = (volatile uart_t *)UART0_ADDR;
    unsigned char transfered_kernel[0x3200000] = {0};
    // Buffer of 50 MiB
    // Setup UART0 (in case of misconfiguration)
    pl011_setup(emergency_uart);

    // Start kermit
    kputs("Waiting for kermit transfer..." CRLF);
    switch (kermit_receive(transfered_kernel, sizeof(transfered_kernel)))
    {
    case SUCCESS:
        kputs("Kermit transfer successful" CRLF);
        kputs((char*)transfered_kernel);
        break;
    case FAILURE:
        kputs("Kermit transfer failed" CRLF);
        break;
    default:
        kassert(0);
    }
}
