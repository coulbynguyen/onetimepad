#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


int main(int argc, char *argv[]){
	if(argc == 1){
		exit(1);
	}
	else{
	   	srand(time(NULL));
	   	int length = atoi(argv[1]);
		int i;
		char* key = malloc(sizeof(char)*(length+2));
		for(i = 0; i < length; i++){
		   int x = rand()%27;
		   if(x == 26){
			key[i] = 32;
		   }
		   else{
			key[i] = x+65;
		   }
		}
		key[length] = '\n';
		key[length+1] = '\0';
		printf("%s", key);
	}
	return 0;
}
