#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
   int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
   socklen_t sizeOfClientInfo;
   char buffer[256];
   char key[131072]; // 2^17
   char plaintext[131072]; // 2^17
   char cyphertext[131072]; // 2^17
   char e_plain_key[262144]; // 2^17
   struct sockaddr_in serverAddress, clientAddress;
   char *token;
   int array_of_pids[100];
   int num_of_pids = 0;
   int checkSend = -5;
   int i;
   int active_connections = 0;
   int childExitMethod = 0;
   pid_t anyComplete;
// this section of code initializes all char variables so that they are filled with '\0'
   memset(key, '\0', sizeof(key));
   memset(plaintext, '\0', sizeof(plaintext));
   memset(cyphertext, '\0', sizeof(cyphertext));
   memset(e_plain_key, '\0', sizeof(e_plain_key));

   if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

   // Set up the address struct for this process (the server)
   memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
   portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
   serverAddress.sin_family = AF_INET; // Create a network-capable socket
   serverAddress.sin_port = htons(portNumber); // Store the port number
   serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

   // Set up the socket
   listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
   if (listenSocketFD < 0) error("ERROR opening socket");

   // Enable the socket to begin listening
   if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
      error("ERROR on binding");
   listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections


   //this while loop executes forever since it is a multiserver
   while(1){
      //this for loop waits for pids in the array and checks to see if any have completed with no hang
      //and then decrements the count of active connections if 1 has finished
      for(i = 0; i < num_of_pids; i++){
	 if(array_of_pids[i] != -1){
	    anyComplete = waitpid(array_of_pids[i], &childExitMethod, WNOHANG);
	    if(anyComplete != 0){
	       array_of_pids[i] = -1;
	       active_connections -= 1;
	    }
	 }
      }
      // Accept a connection, blocking if one is not available until one connects
      //this section of code only executes if there are 5 or less active processes
      if(active_connections < 5){
	 sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
	 establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
	 if (establishedConnectionFD < 0) error("ERROR on accept");

	//for each accept this spawns a child
	 pid_t spawnpid = fork();
	 if(spawnpid == 0){
	    //child
	    // Get the message from the client and display it
	 
	    //this section of code keeps reading input untill the @ symbol could be found in the received text
	    memset(buffer, '\0', 256);
	    charsRead = recv(establishedConnectionFD, buffer, 255, 0); // Read the client's message from the socket
	    strcat(e_plain_key, buffer);
	    if (charsRead < 0) error("ERROR reading from socket");
	    while(strstr(e_plain_key, "@") == NULL){
	       memset(buffer, '\0', 256);
	       charsRead += recv(establishedConnectionFD, buffer, 255, 0); // Read the client's message from the socket
	       strcat(e_plain_key, buffer);
	    }
	    // this function means that a decrypt function tried binding to it
	    if(e_plain_key[0] != 'e'){
	       charsRead = send(establishedConnectionFD, "*", 2, 0); // Send success back
	       if(charsRead < 0) error("SERVER: ERROR writing to socket");   
	    }

	    //printf("SERVER: I received this from the client: \"%s\"\n", e_plain_key);
	    token = strtok(e_plain_key, "#"); //get the e signifier
	    token = strtok(NULL, "$"); // get the plain text
	    strcpy(plaintext, token); // plain text is transferred to the plain text variable
	    token = strtok(NULL, "@"); // get the key text
	    strcpy(key, token); // key is transferred to the key variable

	    //printf("SERVER: PLAINTEXT: %s\n", plaintext);
	    //printf("SERVER: KEY: %s\n", key);

	    //this for loop does the arithmetic
	    //so it takes the characters ascii valu and subtract it from the key 
	    //ascii value and then if that value is less then 0 it adds 27
	    //and then sets that value into the cyphertext place
	    for(i = 0; i < strlen(plaintext); i++){
	       int x = 0;
	       int y = 0;
	       int z = 0;
	       if(plaintext[i] == 32){
		  x = 26;	
	       }
	       else{
		  x = plaintext[i] - 65;
	       }
	       if(key[i] == 32){
		  y = 26;
	       }
	       else{
		  y = key[i] - 65;
	       }
	       z = (x+y)%27;
	       if(z == 26){
		  z = 32;
	       }
	       else{
		  z += 65;
	       }
	       cyphertext[i] = z;

	    }
	    //printf("SERVER: CYPHERTEXT: %s\n", cyphertext);
	    strcat(cyphertext, "@");


	    // Send a Success message back to the client
	    //charsRead = send(establishedConnectionFD, "I am the server, and I got your message", 39, 0); // Send success back
	    charsRead = send(establishedConnectionFD, cyphertext, sizeof(cyphertext), 0); // Send success back
	    if (charsRead < 0) error("ERROR writing to socket");
	    exit(0);
	 }
	 else{
	    //parent
	    //put the spawnpid into array
	    array_of_pids[num_of_pids] = spawnpid;
	    num_of_pids++;
	    active_connections += 1;
	 }
	 close(establishedConnectionFD); // Close the existing socket which is connected to the client
      }
   }
   close(listenSocketFD); // Close the listening socket
   return 0; 
}





















