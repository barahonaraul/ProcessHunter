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

		/* What to display on a usage error */
	  const char *usage = "Usage: phunt -l <log file> -c <config>";

	//Check to see that there are at most 5 args, anything over 5 means they put too many args, also check there is at least 1 arg
	if(argc <= 5 && argc >= 1){
		if(argc == 1){ //What to do when we want to use default log and config
			printf("We want to use defaults for log and config!\n");
			//get default descriptor for log and config here


		}else if(argc == 3){//What we want to do if they specify only the log or config file
			if( strcmp(argv[1],"-l") == 0 ) {
				printf("We want the logfile %s \n",argv[2]);
				//get the specified logfile descriptor we want here

				//get the default configfile descriptor here

		  } else if ( strcmp(argv[1],"-c") == 0) {
		    printf("We want the configfile %s \n",argv[2]);
				//get the default logfile descriptor here

				//get the specified configfile descriptor we want here


		  }else{
				//if our -l or -c was not our second argument
		    printf( "%s\n\n", usage );
				exit(1);
		  }
		}else if( argc == 5){ //Check when we specify log and config files
			 printf("use 5\n");
			 if( strcmp(argv[1],"-l") == 0 && strcmp(argv[3],"-c") == 0 ) {
			    printf("We want the logfile %s \n",argv[2]);
			    printf("We want the configfile %s \n",argv[4]);
					//get the specified logfile descriptor here

					//get the specified configfile descriptor we want here

			  }else{
					//if our -l or -c argurments were wrong
			    printf( "%s\n\n", usage );
					exit(1);
			  }
		}else{
			//Any other amount of args other than 1,3, or 5 is bad usage
		    printf( "%s\n\n", usage );
				exit(1);
		}

	}else{
		//any amount of args over 5 or less than 1 is bad usage
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
