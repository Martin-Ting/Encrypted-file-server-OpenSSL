// C
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// openSSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/sha.h>

// network
#include <sys/socket.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>

void header(int numperiods, int wait, bool active);
void printLoading(int numperiods, int wait, bool active);

void connectToServer(char * serveraddress, char * port, char* transType, char * infile);
BIO* establishSSLConnection(char * serveraddress, char * port);
void performRSAChallenge(char * serveraddress, char * port, BIO* bio);
int verifyTransaction(char* serveraddress, char* port, char* transType, BIO* bio);

int getTransactionType(char * transType);
void sendFile(char* serveraddress, char* port, char* infile, BIO* bio);
void recieveFile(char* serveraddress, char* port, char*infile, BIO* bio);

int main( int argc, const char* argv[] )
{
    header(3, 1, false);
    //============================
    // SSL init 
	SSL_library_init(); 
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms(); 
	// ============== SSL init //
	
	// Verify args
	if (argc !=5)
	{
		printf("Usage:\n");
		printf("\t ./client --serverAddress=127.0.0.1 --port=1234 --send ./filename\n");
		printf("\t ./client --serverAddress=127.0.0.1 --port=1234 --recieve ./filename\n");
		exit(54);
	}

	char* serverhost = (char*) argv[1];
	char* port = (char*) argv[2];
	char* transType = (char*) argv[3];
	char* file = (char*) argv[4];
	serverhost = strrchr(serverhost, '=') + sizeof(char);
	port = strrchr(port, '=') + sizeof(char);
	transType = strrchr(transType, '-') + sizeof(char);
	printf("server: %s\n", serverhost);
	printf("port: %s\n", port);
	printf("transType: %s\n", transType);
	printf("file: %s\n", file);
	// seed for random numbers
 	srand(time(0));
 	
 	// connect to server
	connectToServer(serverhost,port,transType, file); 
	
	printf("Client application is exiting.\nGood Bye!\n");
	return 0;
}

void connectToServer(char * serveraddress, char * port, char* transType, char * infile){
    // SSL init 
	SSL_library_init(); 
	// ============== SSL init //
	
	// establish connection
	BIO* bio = establishSSLConnection(serveraddress, port);
	// ================ STEP 1 FINISHED ESTABLISHED AN SSL CONNECTION
 	// Verify client
 	performRSAChallenge(serveraddress, port, bio);
 	// ================ 
 	int transaction = verifyTransaction(serveraddress, port, transType, bio);
 	if(transaction == 1) //send
 	{
 		sendFile(serveraddress, port, infile, bio);
 	}
 	if(transaction == 2) //recieve
 	{
 		recieveFile(serveraddress, port, infile, bio);
 	}
 	if(transaction < 0) //error
 	{
 		printf("Something went wrong with determining transaction type.");
 	}
 	if(transaction < 0) //error
 	{
 		printf("Something went wrong with determining transaction type.");
 	}
	printf("SSL Connection closed.\n");
	BIO_free(bio);
}

BIO* establishSSLConnection(char * serveraddress, char * port){
	printf("Attempting to establish SSL Connection.\n");
    //============================
    // SSL init 
	SSL_library_init(); 
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	SSL *ssl;
	
	SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL); 
	
	// Establish an SSL Connection
    strcat(serveraddress, ":");
    strcat(serveraddress, port);
    char * concatenate = serveraddress;
    char * connection = malloc(sizeof(char) * (sizeof(concatenate) + 1));
	strcpy(connection, concatenate); 

	BIO* bio = BIO_new_connect(connection); 
	
	BIO_get_ssl(bio,&ssl); 
	SSL_set_mode(ssl,SSL_MODE_AUTO_RETRY); 
	if (BIO_do_connect(bio) <= 0){
		printf("Error: SSL connect failed.\n"); 
		BIO_free_all(bio);
		SSL_CTX_free(ctx); 
		exit(1); 
	}
	if (BIO_do_handshake(bio)<=0){
		printf("Error: SSL handshake failed.\n"); 
		SSL_CTX_free(ctx); 
		exit(1); 
	}
	// ============== SSL init //

	printf("SSL Connection has been established!\n");
	return bio;
}

void performRSAChallenge(char * serveraddress, char * port, BIO* bio){
	printf("Verifying client with RSA ============================ \n");
	
	int random = rand()%1000; 

	// SSL BIO and RSA init
	BIO *pubbp = BIO_new_file("rsapublickey.pem", "r"); 
	RSA *pubkey = PEM_read_bio_RSA_PUBKEY(pubbp,NULL,NULL,NULL); 
	int encryptsize = RSA_size(pubkey); 
	// ============== SSL init //
    
    char * message = malloc(sizeof(char) * encryptsize);
    snprintf(message,sizeof(char) * encryptsize, "%i", random);
    printf("Message: %s\n", message);
	
	printf("Encrypting message with random seed: %d\n",random); //==========================
	unsigned char encryptedSeed[encryptsize]; //encrypt the challenge using RSA public key and sent to server
	if (RSA_public_encrypt(sizeof message, (unsigned char*) message,(unsigned
	char*)encryptedSeed,
	pubkey,RSA_PKCS1_PADDING) < 0)
	{
		printf("Error: encrypting the seed challenge\n");
	}
	printf("Message has been encrypted using RSA public key\n");//=========================
	
	printf("Sending encryptedSeed to server and generating hash of message.\n");//------------
	if (BIO_write(bio, encryptedSeed, sizeof encryptedSeed) <=0)
	{	
		printf("Error: writing encrypted seed to server\n");
	}

	//SHA1 the unencrypted seed number
	unsigned char outbuf[20]; 
	unsigned char* message1 = (unsigned char*) message;
	SHA1((const unsigned char*)message1, sizeof message1, outbuf); 

	printf("Hash of message: %s \n",outbuf); //----------------------------------------------

	printf("Recieving signed hash from server.\n"); //=============================
	char signedhash[RSA_size(pubkey)];
	if (BIO_read(bio, (void *) signedhash, sizeof signedhash) <=0)
	{
		printf("Error reading\n");
	}
	printf("Got signed hash from server.\n"); //===================================

	printf("Recovering hash using public key.\n");//------------------------------
	unsigned char unsignhash[RSA_size(pubkey)]; 
	// decrypt the signed hash to get the SHA1 of unencrypted challenge
	if (RSA_public_decrypt(sizeof signedhash,(unsigned char*)
	signedhash,(unsigned char*)unsignhash,pubkey,RSA_PKCS1_PADDING) < 0)
	{
		printf("error : signed hash\n");
	}
	printf("Hash recovered from public key.\n");//-------------------------------
	
	printf("Comparing generated hash with recovered hash.\n");//==================
	//comparing two hash values
	if (strncmp((const char*) outbuf, (const char*) unsignhash, sizeof outbuf)
	== 0)
	{
		printf("Received correct SHA1!\n");
	}
	else {
		printf("Incorrect SHA1: Program will now exit. \n");
		exit(1); 
	}
	printf("Hash comparison was a success!\n");//=================================
}
void sendFile(char* serveraddress, char* port, char* infile, BIO* bio){
	printf("send filename for new file.\n");
	char filename[1024];
	strcpy(filename, infile);
	printf("Sending file name to server: %s\n", filename);
	if(BIO_write(bio, (unsigned char*)filename, sizeof(filename)) <= 0)
	{
		printf("Error writing filename to server.\n");
	}
	printf("Filename sent.\n");

	printf("count number of characters in the file\n");
	FILE *fp;
	fp = fopen(infile, "r");
	if(fp == NULL)
	{
		perror("Error while trying to open file\n");
		exit(1);
	}
	char ch;
	int numChar = 0;
	while((ch = fgetc(fp))!= EOF)
	{
		numChar++;
	}
	fclose(fp);
	printf("Counted: %i\n", numChar);
	
	printf("Reading file.\n");
	FILE* fileWriter = fopen(infile, "r");
	if(fileWriter == NULL)
	{
		perror("Error while trying to open file\n");
		exit(1);
	}
	int eofIndex = 0; 
	char* filebuf = malloc(sizeof(char) * numChar);
	while((ch = fgetc(fileWriter)) != EOF)
	{
		filebuf[eofIndex] = ch;
		eofIndex += 1;
	}
	printf("File read.\n");
	printf("Sending file.\n");
	if(BIO_write(bio, (unsigned char*)filebuf, eofIndex) <= 0)
	{
		printf("Error sending file to server.");
	}
	printf("File sent.\n");
}
void recieveFile(char* serveraddress, char* port, char*infile, BIO* bio){
	char filename[1024]; 
	strcpy(filename, infile); 
	printf("Sending file request to server for file: %s\n", infile);
	if (BIO_write(bio, (unsigned char*)filename, sizeof filename) <=0)
	{	
		printf("Error: could not write file to server\n"); 
	}
	printf("File name sent.\n");
	
	printf("Waiting for file to return\n");
	char receivedfile[20000]; 
	while (BIO_read(bio, receivedfile, 20000) <= 0) {}
	printf("File has been recieved.\n");
	printf("File recieved ====================================================\n");
	printf("%s\n" , receivedfile); 
	printf("==================================================== deveicer eliF\n");
}
int getTransactionType(char * transType){
	printf("getTransactionType got: %s\n", transType);
	if(strcmp(transType, "send") == 0){
		printf("returning send\n");
		return 1;
	}
	if(strcmp(transType, "recieve") == 0){
		printf("returning recieve\n");
		return 2;
	}
	printf("returning error.\n");
	return -1;
}

int verifyTransaction(char* serveraddress, char* port, char* transType, BIO* bio){
	char transferType[64];
	strcpy(transferType, transType);
	printf("Sending transfer type to server to notify: %s\n", transferType);
	if(BIO_write(bio, (unsigned char*)transferType, sizeof transferType) <= 0)
	{
		printf("Error: transferType could not be written to server.\n");
	}
	printf("Transfer type sent.\n");
	printf("Waiting for verify.\n");
	char recievedType[64];
	while(BIO_read(bio,recievedType, 64) <= 0) {}
	printf("Transfer type verified: %s | %i\n", recievedType, getTransactionType(transType));
	
	return getTransactionType(transType);
}


// Useless header stuff... ==============
void header(int numperiods, int wait, bool active){
	printf( "==============================================\n");
    printf( "\tWelcome to CS165 client application\n");
    printf( "==============================================\n");
    printf(" Loading"); 
    fflush(stdout);
	printLoading(numperiods, wait, active);
	printf("\n\n");
}
void printLoading(int numperiods, int wait, bool active){
	if(active){
    	for (int i = 0; i < numperiods; ++i){ //super functional loading - wait for server to init
    	    printf(". ");
    	    fflush(stdout);
    	    sleep(wait);
    	}
   	}
   	else{
   		printf(". . . . . . ");
    }
}
