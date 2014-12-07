#include <curses.h>
#include <unistd.h> // For sleep()
#include <string.h> // For strlen()
#include <stdlib.h> // For malloc()

//#include <iostream>
//#include <fstream>

// cstdlib
#include <stdio.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
//#include <unistd>
#include <sys/socket.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
//#include <fstream>
//#include <cstdlib> //for rand and srand
//#include <ctime> //time 
#include <stdlib.h>
//#include <sstream>
#include <string.h>


void printIntro();
void printLoading();

int main( int argc, const char* argv[] )
{
    printIntro(5, 5);
    
    return 0;
}




// Useless introduction stuff... ==============
void printIntro(int numperiods, int wait){
	printf( "==============================================\n");
    printf( "\tWelcome to CS165 client application\n");
    printf( "==============================================\n");
    printf(" Loading"); 
    fflush(stdout);
	printLoading(numperiods, wait);
	printf("\n\n");
}
void printLoading(int numperiods, int wait){
    for (int i = 0; i < numperiods; ++i){ //super functional loading - wait for server to init
        printf(".");
        fflush(stdout);
        sleep(wait);
    }
}
