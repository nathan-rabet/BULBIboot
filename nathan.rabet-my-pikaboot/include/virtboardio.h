#ifndef VIRTBOARDIO_H
#define VIRTBOARDIO_H

int devopen(char *); /* Communications device/path */
int devsettings(char *);
int devrestore(void);
int devclose(void);
int pktmode(short);

int readpkt(struct k_data *, UCHAR *, int); /* Communications i/o functions */
int tx_data(struct k_data *, UCHAR *, int);
int inchk(struct k_data *);

int openfile(struct k_data *, UCHAR *, int); /* File i/o functions */
int writefile(struct k_data *, UCHAR *, int);
int readfile(struct k_data *);
int closefile(struct k_data *, UCHAR, int);
ULONG fileinfo(struct k_data *k, UCHAR *, UCHAR *, int, short *, short);

#endif /* VIRTBOARDIO_H */
