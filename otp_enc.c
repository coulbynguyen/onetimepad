#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten = 0, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[256];
	char key[131072]; //2 ^ 17
	char plaintext[131072]; //2 ^ 17
	char cyphertext[131072]; //2 ^ 17
	char e_plain_key[262144]; //2^18 to hold key and plain text
	int z;
	int checkSend = -5;
	int badcharflag = 0;

	memset(cyphertext,'\0', sizeof(cyphertext));
    
	if (argc < 4) { fprintf(stderr,"USAGE: %s hostname port\n", argv[0]); exit(0); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
	        // Connect socket to address
		//error("CLIENT: ERROR connecting");
		fprintf(stderr, "could not contact otp_enc_d on port %s\n", argv[3]);
		exit(2);
		
	}

	// Get input message from user
	// printf("CLIENT: Enter text to send to the server, and then hit enter: ");
	//memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
	//fgets(buffer, sizeof(buffer) - 1, stdin); // Get input from the user, trunc to buffer - 1 chars, leaving \0
	//buffer[strcspn(buffer, "\n")] = '\0'; // Remove the trailing \n that fgets adds
	memset(buffer, '\0', sizeof(buffer));
	memset(e_plain_key,'\0', sizeof(e_plain_key));
	e_plain_key[0] = 'e';
	e_plain_key[1] = '#';
//	e_plain_key[2] = '#';
	
	FILE* text_file_descriptor = fopen(argv[1], "r");
	memset(plaintext,'\0', sizeof(plaintext));
	if(text_file_descriptor){
		fgets(plaintext, sizeof(plaintext)-1, text_file_descriptor);
		int x = strcspn(plaintext, "\n");
		plaintext[x] = '$';
//		plaintext[x+1] = '$';
	}
	else{
		fprintf(stderr, "bad plain text file\n");
		exit(1);
	}
	
	// get text from keygen
	FILE* key_file_descriptor = fopen(argv[2], "r");
	memset(key,'\0', sizeof(key));
	if(key_file_descriptor){
		fgets(key, sizeof(key)-1, key_file_descriptor);
		int x = strcspn(key, "\n");
		key[x] = '@';
//		key[x+1] = '@';
	}
	else{
		fprintf(stderr, "bad key file\n");
		exit(1);
	}
	if(strlen(key) < strlen(plaintext)){
		fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
		exit(1);
	}
	/* this section below checks to see if the characters are good or bad */
	int keyflag = 0;
	int plaintextflag = 0;
	for(z = 0; z < strlen(key)-1; z++){
		/*if((key[z] > 90 || key[z] < 65) && key[z] != 32){
			badcharflag = 1;
		}*/
		if(((key[z] >= 65) && (key[z] <= 90)) || (key[z] == 32)){
			//do nothing
		}
		else{
			badcharflag = 1;
			keyflag = 1;
		}
	}
	for(z = 0; z < strlen(plaintext)-1; z++){
		/*if((plaintext[z] > 90 || plaintext[z] < 65) && plaintext[z] != 32){
			badcharflag = 1;
		}*/
		if(((plaintext[z] >= 65) && (plaintext[z] <= 90)) || (plaintext[z] == 32)){
			//do nothing
		}
		else{
			badcharflag = 1;
			plaintextflag = 1;
		}
	}

	if(badcharflag == 1){
		fprintf(stderr, "otp_enc error: input contains bad characters\n");
		exit(1);
	}
	else{
		strcat(e_plain_key, plaintext);
		strcat(e_plain_key, key);
	}

	// Send message to server
	charsWritten += send(socketFD, e_plain_key, strlen(e_plain_key), 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	/*if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");*/
	do{
		ioctl(socketFD, TIOCOUTQ, &checkSend);
	}while(checkSend > 0);

	// Get return message from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	strcat(cyphertext, buffer);
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	while(strstr(cyphertext, "@") == NULL){
		if(strstr(buffer, "**") != NULL){
			fprintf(stderr, "could not contact otp_enc_d on port %s\n", argv[3]);
			exit(2);
		}
		memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
		charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
		strcat(cyphertext, buffer);


	}
	cyphertext[strcspn(cyphertext, "@")] = '\0';
	//printf("CLIENT: I received this from the server: \"%s\"\n", cyphertext);
	printf("%s\n", cyphertext);

	close(socketFD); // Close the socket
	return 0;
}
