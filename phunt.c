#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

FILE *logfp = NULL;
FILE *conf = NULL;
char d_conf_path[] = "/etc/phunt.conf";
char d_log_path[] = "/var/log/phunt.log";
char d_conf_dir[] = "/etc/";
char d_log_dir[] = "/var/log/";
char start_up[150];
int pid;

//Function used to print the timestamp to our log file!
void printDateLog(){
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	fprintf(logfp,"%d-%d-%d %d:%d:%d ", tm.tm_year + 1900, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

int doesFileExist(const char * filename){
struct stat st;
int result = stat(filename,&st);
return result == 0;
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

void getFileToRead(FILE **fp, char *p){
//First check to see if the file exists, if it doesn't abort
if(doesFileExist(p)){
	*fp = fopen(p,"r");//open file for reading

	if(fp == NULL){//if there was an issue with the pointer abort
		printf("Unable to open config file! Check permissions! Aborting!\n");
		printDateLog();
		fprintf(logfp,"ubuntu phunt: unable to open the config file, abort \n");
		exit(1);
	}else{//if not, print to log that we opened the config file
		printDateLog();
		fprintf(logfp,"ubuntu phunt: opened the config file %s\n",p);
	}
}else{//what to do if file does not exist
	printf("Unable to open config file! File does not exist! Aborting!\n");
	printDateLog();
	fprintf(logfp,"ubuntu phunt: unable to open the config file, abort \n");
	exit(1);
}

}

void getFileToAppend(FILE **fp, char *p){

if(doesFileExist(p)){//check existance
	*fp = fopen(p,"a+");//open file for appending (and reading but we won't be)

	if(fp == NULL){//if there is an issue with the pointer abort
		printf("Unable to open log file! Check permissions! Aborting!\n");
		exit(1);
	}else{// if not print startup message to log and print message that log file was opened
		fprintf(logfp,"%s",start_up);
		printDateLog();
		fprintf(logfp,"ubuntu phunt: opened the log file %s\n",p);
	}
}else{//what to do if file doesn't exist
	printf("Unable to open log file! File does not exist! Aborting!\n");
	exit(1);
}

}

char* concat(const char *s1, const char *s2)
{
    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);
    char *result = malloc(len1+len2+1);//+1 for terminator
    //check for errors in malloc here
		if(result){
    // value isn't null
		memcpy(result, s1, len1);
    memcpy(result+len1, s2, len2+1);//+1 to copy the null-terminator
		}
		else{
    // value is null
		printf("Error malloc failed for %s and %s \n",s1,s2 );
		}
    return result;
}

void parse_command_line( int argc, char *argv[], FILE **log, FILE **conf )
{
		/* What to display on a usage error */
	  const char *usage = "Usage: phunt -l <log file> -c <config>";

	//Check to see that there are at most 5 args, anything over 5 means they put too many args, also check there is at least 1 arg
	if(argc <= 5 && argc >= 1){
		if(argc == 1){ //What to do when we want to use default log and config
			printf("We want to use defaults for log and config!\n");
			//get default descriptor for log and config here
			getFileToAppend(log,d_log_path);
			getFileToRead(conf,d_conf_path);


		}else if(argc == 3){//What we want to do if they specify only the log or config file
			if( strcmp(argv[1],"-l") == 0 ) {
				//printf("We want the logfile %s \n",argv[2]);
				//get the specified logfile descriptor we want here
				char * spec_path = concat(d_log_dir,argv[2]);
				getFileToAppend(log,spec_path);
				free(spec_path);				
				
				//get the default configfile descriptor here
				getFileToRead(conf,d_conf_path);


		  } else if ( strcmp(argv[1],"-c") == 0) {
		    		//printf("We want the configfile %s \n",argv[2]);
				//get the default logfile descriptor here
				getFileToAppend(log,d_log_path);

				//get the specified configfile descriptor we want here
				char * spec_path = concat(d_conf_dir,argv[2]);
				getFileToRead(conf,spec_path);
				free(spec_path);

		  }else{
				//if our -l or -c was not our second argument
		    printf( "%s\n\n", usage );
				exit(1);
		  }
		}else if( argc == 5){ //Check when we specify log and config files
			 if( strcmp(argv[1],"-l") == 0 && strcmp(argv[3],"-c") == 0 ) {
			    printf("We want the logfile %s \n",argv[2]);
			    printf("We want the configfile %s \n",argv[4]);
					//get the specified logfile descriptor here
					char * spec_path = concat(d_log_dir,argv[2]);
					getFileToAppend(log,spec_path);
					free(spec_path);

					//get the specified configfile descriptor we want here
					spec_path = concat(d_conf_dir,argv[4]);
					getFileToRead(conf,spec_path);
					free(spec_path);

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

int is_empty(const char *s) {
  while (*s != '\0') {
    if (!isspace(*s))
      return 0;
    s++;
  }
  return 1;
}


/*
 * signal handler to catch CTRL-C and shut down things nicely
 */
void stop_and_exit( int signo )
{
  if( logfp != NULL ) {
    fclose( logfp );
  }
  if( conf != NULL ) {
    fclose(conf);
  }

 exit(0);

}

int main( int argc, char *argv[]){

/* set up signal handler to deal with CTRL-C */
  signal( SIGINT, stop_and_exit );

// Get the pid of our program, print error if we can't get it and exit
	pid = getpid();
	if(pid < 0){
		perror("Unable to get pid!");
		exit(1);
	}

// Build a string that will have the log message for when we start up the program
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);//Get values for our timestamp then build message
	snprintf(start_up,100,"%d-%d-%d %d:%d:%d ubuntu phunt: phunt startup (PID=%d)\n",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,pid);

// Parse the command line and set up the pointers to the log and config files
	parse_command_line(argc, argv, &logfp, &conf);
//while(1);
// Parse the config file and construct our rules here
	char line[100];
	while(fgets(line,sizeof(line), conf)){
	if(is_empty(line) || line[0] == '#')
	printf("Ignore this stuff\n");
	else
	printf("Line: %s",line);
	}


//Sample infinite loop
	while(1);

//If we get here lets close our files
	if(conf != NULL){
	printf("Closing conf file!\n");
	fclose(conf);
	}

	if(logfp != NULL){
	printf("Closing log!\n");
	fclose(logfp);
	}

	return 0;
/*
//How to get the username as a string (will use this later)
	struct passwd *pwd;
	pwd = getpwuid(atoi("1000"));
	printf("username: %s\n",pwd->pw_name);

//Reading the proc/ directory
//set up the DIR
	DIR* proc = opendir("/proc");
	struct dirent* ent;
	long tgid;

	if(proc == NULL){
		perror("opendir(/proc)");
		return 1;
	}

	while( ent = readdir(proc)) {
	//look if the folder being looked at is a digit (meaning its a process folder)
		if(!isdigit(*ent->d_name))
			continue; //If it is not we continue to the next file in the proc dir

		//If we didn't continue, then convert the name of the folder into a long which holds the pid
		tgid = strtol(ent->d_name, NULL, 10);
		//Pass it in our function to read the contents for that process
		print_status(tgid);
	}


*/


}
