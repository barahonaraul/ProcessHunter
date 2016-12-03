#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>


void printDate(){
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	printf("now: %d-%d-%d %d:%d:%d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void print_status(long tgid) {
	char path[40], line[100], *p;
	FILE* statusf;
	
	snprintf(path,40,"/proc/%ld/status",tgid);

	statusf =fopen(path,"r");
	if(!statusf)
	    return;
	
	while(fgets(line, 100, statusf)) {
		if(strncmp(line, "Uid:", 4))
		    continue;

		//Ignore "State:" and whitespace
		p = line + 5;
		while(isspace(*p)) {
		//printf("%c\n",p);
		++p;
		}

//printf("%c\n",p[1]);

		/*int count = 0;
		while(!isspace(*p)){
		printf("%c\n",p);		 
		++count;
		}

		char str[count];
		strncpy(str,p,count);*/
		//printf("done\n");
		printf("%6ld %s", tgid, p);
		break;
	}

	fclose(statusf);

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

void parse_command_line( int argc, char *argv[] )
{
printf("%d \n",argc);
  const char *usage = "Usage: phunt -l <log file> -c <config>";
  if (argc < 1 ) {
    printf( "%s\n\n", usage );
    exit(1);
  }

//Check to see that there are less than 5 args, anything over 5 means they put too many args
if(argc < 5){
//Check when they specify only the log or config file
if(argc == 1){
  printf("We want to use defaults for log and config!\n");
}
else if(argc == 3){
  if( strcmp(argv[1],"-l") == 0 ) {
    printf("We want the logfile %s \n",argv[2]);
  } else if ( strcmp(argv[1],"-c") == 0) {
    printf("We want the configfile %s \n",argv[2]);
  }else{
    printf( "%s\n\n", usage );
  }
} else if( argc == 5){
printf("use 5\n");
 if( strcmp(argv[1],"-l") == 0 && strcmp(argv[3],"-c") == 0 ) {
    printf("We want the logfile %s \n",argv[2]);
    printf("We want the configfile %s \n",argv[4]);
  }else{
    printf( "%s\n\n", usage );
  }
}else{
    printf( "%s\n\n", usage );
}



}else{
    printf( "%s\n\n", usage );
    exit(1);
}
  



}


int main( int argc, char *argv[]){

	parse_command_line(argc, argv);

	//printDate();

	//if(foundFile(argv[1],argv[2]))	
	//printf("This is Phunter!\n");
/*
	struct passwd *pwd;
	pwd = getpwuid(atoi("1000"));
	printf("username: %s\n",pwd->pw_name);

	DIR* proc = opendir("/proc");
	struct dirent* ent;
	long tgid;
	
	if(proc == NULL){
		perror("opendir(/proc)");
		return 1;
	}



	while( ent = readdir(proc)) {
		if(!isdigit(*ent->d_name))
			continue;

		tgid = strtol(ent->d_name, NULL, 10);
		print_status(tgid);
	}


*/




	return 0;
}
