#include <stdio.h>

int main(void)
{
   char buf[4096];
   int x;
   
   while (fgets(buf, sizeof(buf)-2, stdin) != NULL) {
        for (x = 0; x < 128; ) {
            printf("0x%c%c, ", buf[x], buf[x+1]);
            if (!((x += 2) & 31)) printf("\n");
        }
   }
}


/* ref:         HEAD -> develop */
/* git commit:  29986d04f2dca985ee64fbca1c7431ea3e3422f4 */
/* commit time: 2022-11-15 16:23:23 +0100 */
