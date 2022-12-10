/* Sample system-dependent communications i/o routines for embedded Kermit. */

/*
  Author: Frank da Cruz.
  Copyright (C) 1995, 2011.
  Trustees of Columbia University in the City of New York.
  All rights reserved.
  See kermit.c for license.
*/

/*
  The sample i/o routines for UNIX that provide packet i/o
  functions on the console (login) device.
  Copy this file, rename it appropriately, and replace the contents
  of each routine appropriately for your platform.

  Device i/o:

    int devopen()    Communications device - open
    int pktmode()    Communications device - enter/exit packet mode
    int readpkt()    Communications device - read a packet
    int tx_data()    Communications device - send data
    int devclose()   Communications device - close
    int inchk()      Communications device - check if bytes are ready to read

  File i/o:

    int openfile()   File - open for input or output
    ULONG fileinfo() Get input file modtime and size
    int readfile()   Input file - read data
    int writefile()  Output file - write data
    int closefile()  Input or output file - close

  Full definitions below, prototypes in kermit.h.

  These routines must handle speed setting, parity, flow control, file i/o,
  and similar items without the kermit() routine knowing anything about it.
  If parity is in effect, these routines must add it to outbound characters
  and strip it from inbound characters.
*/

#include <stddef.h>

#include "cdefs.h"
#include "debug.h"
#include "emergency_boot.h"
#include "kermit.h"
#include "kstring.h"
#include "uart.h"

UCHAR o_buf[OBUFLEN + 8]; /* File output buffer */
UCHAR i_buf[IBUFLEN + 8]; /* File output buffer */

/*
  In this example, the output file is unbuffered to ensure that every
  output byte is commited.  The input file, however, is buffered for speed.
  This is just one of many possible implmentation choices, invisible to the
  Kermit protocol module.
*/

/* Debugging */

#ifdef DEBUG
static int xdebug = 0; /* Debugging on/off */

void dodebug(int fc, UCHAR *label, UCHAR *sval, long nval)
{
    if (fc != DB_OPN && !xdebug)
        return;
    if (!label)
        label = "";

    switch (fc)
    { /* Function code */
    case DB_OPN: /* Open debug log */
        return;
    case DB_MSG: /* Write a message */
        kputs(label);
        kputs(CRLF);
        return;
    case DB_CHR: /* Write label and character */
        kputs(label);
        kputc('=');
        kputc(nval);
        return;
    case DB_PKT: /* Log a packet */
        /* (fill in later, fall thru for now...) */
    case DB_LOG: /* Write label and string or number */
        if (sval)
            fprintf(dp, "%s[%s]\n", label, sval);
        kputs(label);
        kputc('[');
        kputs(sval);
        kputc(']');
        kputs(CRLF);
        return;
    case DB_CLS: /* Close debug log */
        return;
    }
}
#endif /* DEBUG */

/*  D E V O P E N  --  Open communications device  */
/*

  Call with: string pointer to device name.  This routine should get the
  current device settings and save them so devclose() can restore them.
  It should open the device.  If the device is a serial port, devopen()
  set the speed, stop bits, flow control, etc.
  Returns: 0 on failure, 1 on success.
*/
int devopen(char *device)
{
    (void)device;
    return (1);
}

/*  P K T M O D E  --  Put communications device into or out of packet mode  */
/*
  Call with: 0 to put in normal (cooked) mode, 1 to put in packet (raw) mode.
  For a "dumb i/o device" like an i/o port that does not have a login attached
  to it, this routine can usually be a no-op.
  Returns: 0 on failure, 1 on success.
*/
int pktmode(short on)
{
    (void)on;
    return (1);
}

/*  D E V S E T T I N G S  */

int devsettings(char *s)
{
    (void)s;
    /* Get current device settings, save them for devrestore() */
    /* Parse string s, do whatever it says, e.g. "9600;8N1" */
    if (!pktmode(ON)) /* And put device in packet mode */
        return (0);
    return (1);
}

/*  D E V R E S T O R E  */

int devrestore(void)
{
    /* Put device back as we found it */
    pktmode(OFF);
    return (1);
}

/*  D E V C L O S E  --  Closes the current open communications device  */
/*
  Call with: nothing
  Closes the device and puts it back the way it was found by devopen().
  Returns: 0 on failure, 1 on success.
*/
int devclose(void)
{
    return (1);
}

/* I N C H K  --  Check if input waiting */

/*
  Check if input is waiting to be read, needed for sliding windows.  This
  sample version simply looks in the stdin buffer (which is not portable
  even among different Unixes).  If your platform does not provide a way to
  look at the device input buffer without blocking and without actually
  reading from it, make this routine return -1.  On success, returns the
  numbers of characters waiting to be read, i.e. that can be safely read
  without blocking.
*/
int inchk(struct k_data *k)
{
    (void)k;
    if (check_transmission_busy((volatile uart_t *)EMERGENCY_UART))
        return 0;
    else
        return check_uart_read_ready((volatile uart_t *)EMERGENCY_UART) ? 1 : 0;
}

/*  R E A D P K T  --  Read a Kermit packet from the communications device  */
/*
  Call with:
    k   - Kermit struct pointer
    p   - pointer to read buffer
    len - length of read buffer

  When reading a packet, this function looks for start of Kermit packet
  (k->r_soh), then reads everything between it and the end of the packet
  (k->r_eom) into the indicated buffer.  Returns the number of bytes read, or:
     0   - timeout or other possibly correctable error;
    -1   - fatal error, such as loss of connection, or no buffer to read into.
*/

int readpkt(struct k_data *k, UCHAR *p, int len, int fc)
{
    (void)len;
    (void)fc;

    unsigned char x, n;
    short flag;
    UCHAR c;
/*
  Timeout not implemented in this sample.
  It should not be needed.  All non-embedded Kermits that are capable of
  making connections are also capable of timing out, and only one Kermit
  needs to time out.  NOTE: This simple example waits for SOH and then
  reads everything up to the negotiated packet terminator.  A more robust
  version might be driven by the value of the packet-length field.
*/
#ifdef DEBUG
    char *p2;
#endif /* DEBUG */

#ifdef F_CTRLC
    short ccn;
    ccn = 0;
#endif /* F_CTRLC */

    if (!p)
    { /* Device not open or no buffer */
        debug(DB_MSG, "readpkt FAIL", 0, 0);
        return (-1);
    }
    flag = n = 0; /* Init local variables */

#ifdef DEBUG
    p2 = p;
#endif /* DEBUG */

    while (true)
    {
        u64 read_len = 0;
        if ((read_len = uart_read(&x, 1, (volatile uart_t *)EMERGENCY_UART))
            == (u64)-1)
        {
            debug(DB_MSG, "readpkt timeout", 0, 0);
            return (0);
        }
        c = (k->parity) ? x & 0x7f : x & 0xff; /* Strip parity */

#ifdef F_CTRLC
        /* In remote mode only: three consecutive ^C's to quit */
        if (k->remote && c == (UCHAR)3)
        {
            if (++ccn > 2)
            {
                debug(DB_MSG, "readpkt ^C^C^C", 0, 0);
                return (-1);
            }
        }
        else
        {
            ccn = 0;
        }
#endif /* F_CTRLC */

        if (!flag && c != k->r_soh) /* No start of packet yet */
            continue; /* so discard these bytes. */
        if (c == k->r_soh)
        { /* Start of packet */
            flag = 1; /* Remember */
            continue; /* But discard. */
        }
        else if (c == k->r_eom /* Packet terminator */
                 || c == '\012' /* 1.3: For HyperTerminal */
        )
        {
#ifdef DEBUG
            *p = NUL; /* Terminate for printing */
            debug(DB_PKT, "RPKT", p2, n);
#endif /* DEBUG */
            return (n);
        }
        else
        { /* Contents of packet */
            if (n++ > k->r_maxlen) /* Check length */
                return (0);
            else
                *p++ = x & 0xff;
        }
    }
    debug(DB_MSG, "READPKT FAIL (end)", 0, 0);
    return (-1);
}

/*  T X _ D A T A  --  Writes n bytes of data to communication device.  */
/*
  Call with:
    k = pointer to Kermit struct.
    p = pointer to data to transmit.
    n = length.
  Returns:
    X_OK on success.
    X_ERROR on failure to write - i/o error.
*/
int tx_data(struct k_data *k, UCHAR *p, int n)
{
    (void)k;

    int x;
    int max;

    max = 10; /* Loop breaker */

    while (n > 0)
    { /* Keep trying till done */
        x = uart_write(p, n, (volatile uart_t *)EMERGENCY_UART);
        debug(DB_MSG, "tx_data write", 0, x);
        if (x < 0 || --max < 1) /* Errors are fatal */
            return (X_ERROR);
        n -= x;
        p += x;
    }
    return (X_OK); /* Success */
}

/*  O P E N F I L E  --  Open output file  */
/*
  Call with:
    Pointer to filename.
    Size in bytes.
    Creation date in format yyyymmdd hh:mm:ss, e.g. 19950208 14:00:00
    Mode: 1 = read, 2 = create, 3 = append.
  Returns:
    X_OK on success.
    X_ERROR on failure, including rejection based on name, size, or date.
*/
int openfile(struct k_data *k, UCHAR *s, int mode)
{
    (void)k;
    (void)s;
    (void)mode;

    debug(DB_MSG, "OPENFILE unimplemented", s, mode);
    return (X_ERROR);
}

/*  F I L E I N F O  --  Get info about existing file  */
/*
  Call with:
    Pointer to filename
    Pointer to buffer for date-time string
    Length of date-time string buffer (must be at least 18 bytes)
    Pointer to int file type:
       0: Prevailing type is text.
       1: Prevailing type is binary.
    Transfer mode (0 = auto, 1 = manual):
       0: Figure out whether file is text or binary and return type.
       1: (nonzero) Don't try to figure out file type.
  Returns:
    X_ERROR on failure.
    0L or greater on success == file length.
    Date-time string set to yyyymmdd hh:mm:ss modtime of file.
    If date can't be determined, first byte of buffer is set to NUL.
    Type set to 0 (text) or 1 (binary) if mode == 0.
*/
#ifdef F_SCAN
#    define SCANBUF 1024
#    define SCANSIZ 49152
#endif /* F_SCAN */

ULONG
fileinfo(struct k_data *k, UCHAR *filename, UCHAR *buf, int buflen, short *type,
         short mode)
{
    (void)k;
    (void)filename;
    (void)buf;
    (void)buflen;
    (void)type;
    (void)mode;
    debug(DB_MSG, "FILEINFO unimplemented", filename, mode);
    return (X_ERROR);
}

/*  R E A D F I L E  --  Read data from a file  */

int readfile(struct k_data *k)
{
    if (!k->zinptr)
    {
#ifdef DEBUG
        debug(DB_MSG, "readfile no buffer", 0, 0);
#endif /* DEBUG */
        return (X_ERROR);
    }
    if (k->zincnt < 1)
    { /* Nothing in buffer - must refill */
        if (k->binary)
        { /* Binary - just read raw buffers */
            k->dummy = 0;
            k->zincnt = uart_read(k->zinbuf, k->zinlen,
                                  (volatile uart_t *)EMERGENCY_UART);
            debug(DB_LOG, "readfile binary ok zincnt", 0, k->zincnt);
        }
        else
        { /* Text mode needs LF/CRLF handling */
            unsigned char c; /* Current character */
            for (k->zincnt = 0; (k->zincnt < (k->zinlen - 2)); (k->zincnt)++)
            {
                if (uart_read(&c, 1, (volatile uart_t *)EMERGENCY_UART) < 1)
                    break;
                if (c == '\n') /* Have newline? */
                    k->zinbuf[(k->zincnt)++] = '\r'; /* Insert CR */
                k->zinbuf[k->zincnt] = c;
            }
#ifdef DEBUG
            k->zinbuf[k->zincnt] = '\0';
            debug(DB_LOG, "readfile text ok zincnt", 0, k->zincnt);
#endif /* DEBUG */
        }
        k->zinbuf[k->zincnt] = '\0'; /* Terminate. */
        if (k->zincnt == 0) /* Check for EOF */
            return (-1);
        k->zinptr = k->zinbuf; /* Not EOF - reset pointer */
    }
    (k->zincnt)--; /* Return first byte. */

    debug(DB_LOG, "readfile exit zincnt", 0, k->zincnt);
    debug(DB_LOG, "readfile exit zinptr", 0, k->zinptr);
    return (*(k->zinptr)++ & 0xff);
}

/*  W R I T E F I L E  --  Write data to file  */
/*
  Call with:
    Kermit struct
    String pointer
    Length
  Returns:
    X_OK on success
    X_ERROR on failure, such as i/o error, space used up, etc
*/
int writefile(struct k_data *k, UCHAR *s, int n)
{
    int rc;
    rc = X_OK;

    debug(DB_LOG, "writefile binary", 0, k->binary);

    if (k->binary)
    { /* Binary mode, just write it */
        if (uart_write(s, n, (volatile uart_t *)EMERGENCY_UART) != (u64)n)
            rc = X_ERROR;
    }
    else
    { /* Text mode, skip CRs */
        UCHAR *p, *q;
        int i;
        q = s;

        while (1)
        {
            for (p = q, i = 0; ((*p) && (*p != (UCHAR)13)); p++, i++)
                ;
            if (i > 0)
                if (uart_write(q, i, (volatile uart_t *)EMERGENCY_UART)
                    != (u64)i)
                    rc = X_ERROR;
            if (!*p)
                break;
            q = p + 1;
        }
    }
    return (rc);
}

/*  C L O S E F I L E  --  Close output file  */
/*
  Mode = 1 for input file, mode = 2 or 3 for output file.

  For output files, the character c is the character (if any) from the Z
  packet data field.  If it is D, it means the file transfer was canceled
  in midstream by the sender, and the file is therefore incomplete.  This
  routine should check for that and decide what to do.  It should be
  harmless to call this routine for a file that that is not open.
*/
int closefile(struct k_data *k, UCHAR c, int mode)
{
    (void)k;
    (void)c;
    (void)mode;
    debug(DB_MSG, "CLOSEFILE not needed", 0, mode);
    return (X_OK);
}

#ifdef DEBUG
int xerror()
{
    debug(DB_LOG, "xerror", 0, 0);
    return (X_ERROR);
}
#endif /* DEBUG */
