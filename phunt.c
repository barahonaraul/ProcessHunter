#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <stdbool.h>
#include <string.h>


void printDate(){
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	printf("now: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

bool foundFile(char* dir_path, char* file_name){
 int i=0;
   DIR *dir;
   struct dirent *direntry; //could be a file, or a directory
 
   dir = opendir(dir_path);
   if(!dir) {
      printf("Error: directory did not open!\n");
      return false;
   }
 
   while((direntry=readdir(dir))!=NULL) {
      if(++i < 20) 
         printf("%s\n",direntry->d_name);
      if((strcmp(direntry->d_name, file_name))==0) {
         printf("\nThe %s file has been found\n",direntry->d_name);
         i=-99;  //just a flag value to show the file was found
         break;
      }
 
   }
   if(i!=-99){
      printf("\nThe test.txt file was not found\n");
      closedir(dir);
      return false;
    }
 
   closedir(dir);
 
   printf("\n");
   return true;
}

int main( int argc, char *argv[]){

	printDate();

	if(foundFile(argv[1],argv[2]))	
	printf("This is Phunter!\n");
	return 0;
}
