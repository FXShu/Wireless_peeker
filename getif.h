#ifndef GETIF_H
#define GETIF_H

#ifndef STRING_H
#define STRING_H
#include<string.h>
#endif /* STRING_H */

typedef unsigned char u_char;

void getAttackerMAC(char* dev,u_char* mac);
void getGatewayMAC();

#endif /* GETIF_H */
