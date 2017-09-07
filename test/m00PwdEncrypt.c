//
//		System Test Program
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 
int		i; 
char		*pwd_ptr, *salt_ptr, *buff;

int main() {
//
//		Compile Format : gcc -o m00PwdEncrypt m00PwdEncrypt.c -lcrypt
//
	pwd_ptr=calloc(20, sizeof(char));
	printf("\n>> key in the PW(qwer) : "); scanf("%s", pwd_ptr);
	salt_ptr=calloc(3,sizeof(char)); 
	printf(">> key in the Salt(j9) :  "); scanf("%s", salt_ptr);
	buff=calloc(20, sizeof(char)); 
	strcpy(buff, (char *)crypt(pwd_ptr, salt_ptr));
	printf(".. if password is 'qwer' and salt is 'j9', then encrypted : 'j9SfE6BM2kGeI'");
	printf("\n>> results :       %s               %s                     %s\n\n", pwd_ptr, salt_ptr, buff);
	return 0;
}
