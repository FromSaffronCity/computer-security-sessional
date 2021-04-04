/* stack.c */

/* this program has a buffer overflow vulnerability */
/* our task is to exploit this vulnerability */
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int buffer_overflow(char *str) {
    char buffer[24];

    /* the following statement has a buffer overflow problem */ 
    strcpy(buffer, str);

    printf("buffer_overflow(): returning to main()\n");
    return 1;
}

int secret_function() {
	printf("secret_function(): sensitive information leaked\n");
	return 1;
}

int main(int argc, char **argv) {
    char str[300];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    if(badfile == NULL) {
        perror("error: ");
        return EXIT_FAILURE;
    }
    fread(str, sizeof(char), sizeof(str), badfile);
    fclose(badfile);

    printf("main(): calling buffer_overflow()\n");
    buffer_overflow(str);

    printf("main(): returned properly from buffer_overflow()\n");
    return 0;
}
