// C
#include <stdio.h>

// openSSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// network
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <signal.h>
#include <fcntl.h>

#define loop_forever for(;;)

void acceptConnections(char * port);
BIO* preparePort(char* port);
void performRSAChallenge(BIO* clientbio);
int verifyTransaction(BIO* clientbio);

int getTransactionType(char * transType);
void recieveFile(BIO* clientbio);
void sendFile(BIO* clientbio);


int main( int argc, const char* argv[] )
{
    printf( "==========================================\n");
    printf( "Welcome to CS165 Crypto Server application\n");
    printf( "==========================================\n\n");

    //============================
    // SSL init 
    SSL_library_init(); 
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms(); 
	// ============== SSL init //
	
	// Verify args
	if(argc != 2){
		printf("Usage:\n");
		printf("\t ./server --port=1234");
		exit(54);
	}
	char* port = (char*) argv[1];
	port = strrchr(port, '=') + sizeof(char);
	
	acceptConnections(port); 
	
	printf("Server application is exiting.\nGoodBye!\n" ); 
    return 0;
}

void acceptConnections(char * port){
    //============================
    // SSL init 
	SSL_library_init(); 
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms(); 
	// ============== SSL init //
	
	BIO* clientbio = preparePort(port);
	loop_forever
	{
		printf( "Waiting for client request.\n" ); //===============================================
		if (BIO_do_accept(clientbio) <=0 )
		{
			printf( "error accepting \n" ); 
			exit(1); 
		}
		printf("Connection with client accepted. Connection Established\n");//=======================
		
		/*      Verifying Client      */
		performRSAChallenge(clientbio);
		
		int transaction = verifyTransaction(clientbio);
		if(transaction == 1) //send so recieveFile
 		{
 			recieveFile(clientbio);
 		}
 		if(transaction == 2) //recieve so sendFile
 		{
 			sendFile(clientbio);
 		}
 		if(transaction < 0) //error
 		{
 			printf("Something went wrong with determining transaction type.");
 		}
 		BIO_reset(clientbio);
		BIO_free(clientbio); 
		break; // comment out to do more!
	}
}

void performRSAChallenge(BIO* clientbio){
		BIO *pubbp = BIO_new_file("rsapublickey.pem", "r"); 
		RSA *pubkey = PEM_read_bio_RSA_PUBKEY(pubbp,NULL,NULL,NULL); 
		
		printf("Reading client encrypted key.");
		char buf[RSA_size(pubkey)]; //buffer to read in RSA public key. It will be filled with encrypted seed from client.
		int i = BIO_read(clientbio, (void *) buf,sizeof buf); 
		printf("Client encrypted key read.");
		
		BIO *privbp = BIO_new_file("rsaprivatekey.pem","r");
		RSA *prikey = PEM_read_bio_RSAPrivateKey(privbp,NULL,NULL,NULL);
	
		printf("Decrypting client's encrypted key.\n");
		char outfile[i]; // decrypted key from client
		RSA_private_decrypt(i , (unsigned char*) buf, (unsigned char*)outfile, prikey, RSA_PKCS1_PADDING); 
		printf("Decrypted client key: %s\n", outfile);
		
		unsigned char* outfile1 = (unsigned char*) outfile; 
		unsigned char outbuf[20]; // Sha1 of decrypted client key
		printf("Hashing decrypted client key\n");
		SHA1((const unsigned char*)outfile1, sizeof outfile1, outbuf); 
		printf("Hashed decrypted client key: %s\n", outbuf); 

		printf( "Signing the hash with RSA key and sending to client.\n" ); 
		unsigned char signHashbuf[RSA_size(pubkey)];
		if (RSA_private_encrypt(sizeof outbuf, (unsigned char*) outbuf,(unsigned char*) signHashbuf, prikey,RSA_PKCS1_PADDING) < 0)
		{
			printf( "Error signing hash file\n"  ); 
		}
		if (BIO_write(clientbio, (unsigned char*) signHashbuf, sizeof(signHashbuf)) <= 0 )
		{
			printf( "Error sending signed hash\n" ); 
		}
		printf("Signed hash has been sent.\n");
}

void recieveFile(BIO* clientbio){
	char filename[1024];
	printf("Getting filename from client.\n");
	while(BIO_read(clientbio, (void*) filename, sizeof(filename) ) <= 0 ) {}
	printf("Recieved filename from client.: %s\n", filename);
	/*
	char awk[3] = {'a','w','k'}
	if(BIO_write(clientbio, (unsigned char*) awk, sizeof(awk)) <= 0)
	{
		printf("Error sending awk.");
	}*/
	
	printf("Getting file from client.\n");
	char filebuf[20000];
	while(BIO_read(clientbio, (void*) filebuf, 20000) <= 0) {}
	printf("File recieved ====================================================\n");
	printf("%s\n" , filebuf); 
	printf("==================================================== deveicer eliF\n");
}

void sendFile(BIO* clientbio){
//read the client's request for filename
		printf("Get filename request from client\n");
		char fileinput[1024];
		while (BIO_read(clientbio,(void*) fileinput, sizeof(fileinput) ) <= 0 ) {}
		printf( "Recieved file request for file: %s\n", fileinput); 
		
		printf("count number of characters in the file\n");
        FILE *fp;
        fp = fopen(fileinput,"r");
        if(fp == NULL)
        {
            perror("Error while trying to open file\n");
            exit(1);
        }
        char ch;
        int numChar = 0; 
        while((ch = fgetc(fp)) !=  EOF)
        {
            numChar++;
            //printf("%c",ch);
        }
        fclose(fp);
        printf("Counted: %i\n", numChar);
        
        printf("Reading file.\n");
        FILE * fileReader = fopen(fileinput, "r");
        if(fileReader == NULL)
        {
            perror("Error while trying to open file\n");
            exit(1);
        }
        int eofIndex = 0;
        char* filebuf = malloc(sizeof(char) * numChar); // text file with data
        while((ch = fgetc(fileReader)) != EOF)
        {
            filebuf[eofIndex] = ch;
            eofIndex+=1;
        }
		fclose(fileReader);
        printf("File read.\n");
        printf("Sending file.\n");
		if (BIO_write(clientbio,  (unsigned char*)filebuf, eofIndex) <= 0 )
		{
			printf( "Error sending signed hash\n" ); 
		}
		printf("File sent.\n");
		printf("Closing connection to client.\n");
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

int verifyTransaction(BIO* clientbio){
	printf("Verifying transfer type from client.\n");
	char transferType[64];
	while(BIO_read(clientbio, (void*) transferType, sizeof(transferType) ) <= 0 ) {}
	printf("Transfer type recieved: %s\n", transferType);
	
	printf("Sending back transfer type.\n");
	if(BIO_write(clientbio, (unsigned char*)transferType, 64) <= 0)
	{
		printf("Error sending transfer Type\n");
	}
	printf("Transfer type verified.\n");
	return getTransactionType(transferType);
	
}

BIO* preparePort(char* port){
	printf("Opening port %s for connections.\n", port);
	char* inport = malloc( sizeof(port));
	strcpy(inport,port); 
	BIO* clientbio = BIO_new_accept(inport);
	if (BIO_do_accept(clientbio) <= 0 ) 
	{
		printf("error\n" ); 
		exit(1); 
	}
	printf("Ready for connections.\n");
	return clientbio;
}
