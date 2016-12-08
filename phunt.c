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
#include <sys/resource.h>

FILE *logfp = NULL;
FILE *conf = NULL;
char d_conf_path[] = "/etc/phunt.conf";
char d_log_path[] = "/var/log/phunt.log";
char d_conf_dir[] = "/etc/";
char d_log_dir[] = "/var/log/";
char start_up[150];
int pid;
int rule_start = 1;

typedef struct RuleNode RuleNode;

struct RuleNode{

    char * action;
    char * type;
    char * param;
    struct RuleNode *next;

};

RuleNode *head = NULL;//Keep track of our head
RuleNode *curr = NULL;//Keep track of our last non null element

RuleNode* listAdd(char* action, char* type, char* param, bool addToEnd) {
//    printf("allocate memory for node\n");
    RuleNode *ptr = malloc(sizeof(RuleNode));

// Get copy the given action, type, and param for the rule into our pointer, set next to null
    //printf("Copy the current action: %s\n",action);
    ptr->action = strdup(action);
    //printf("Copy the current type: %s\n",type);
    ptr->type = strdup(type);
    //printf("Copy the current param: %s\n",param);
    ptr->param = strdup(param);
    ptr->next = NULL;

    if (addToEnd)//depending on given input, add to end or head of list
    {
	//printf("curr next is now pointer!\n");
        curr->next = ptr;
	//printf("curr is now ptr!\n");
        curr = ptr;
    }
    else//add as head if false
    {
	//printf("head time!\n");
	//This should only happen once. Here we add the first element, and set current = head
        ptr->next = head;
	//printf("head is now ptr!\n");
        head = ptr;
	//printf("curr is now head!\n");
	curr = head;
    }

    return ptr;
}

/* Print out all our rules from head to tail */
void printList() {
  RuleNode* ptr = head;
  while(ptr) {
    printf("%s %s %s\n", ptr->action,ptr->type,ptr->param);
    ptr = ptr->next;
  }
}

/* Free our rules list! */
void freeList() {
  RuleNode* ptr = head;
  RuleNode* tmp = 0;
  while(ptr) {
    tmp = ptr->next;
    free(ptr->action);
    free(ptr->type);
    free(ptr->param);
    free(ptr);
    ptr = tmp;
  }
}


//Function used to print the timestamp to our log file!
void printDateLog(){
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	fprintf(logfp,"%d-%d-%d %d:%d:%d ", tm.tm_year + 1900, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* Function that verifies if a file exists used to check existance of log and conf files*/
int doesFileExist(const char * filename){
struct stat st;
int result = stat(filename,&st);
return result == 0;
}

/*Function that checks if there is a file in the directory with the given tgid (ex. pid)
 used for verification of a kill */
int doesFileExistProc(long tgid){
char path[20];
snprintf(path,20,"/proc/%ld",tgid);
struct stat st;
int result = stat(path,&st);
return result == 0;
}

/* Function used mainly to get the username or status (running, sleeping etc.) of a process */
char * get_status(long tgid, char * stat_wanted) {
//Define some local variables for use as well as our result
	char path[40], line[100], *p, *token, *result;
	FILE* statusf;
//Build up the path to proc/pid/status using inputted tgid value
	snprintf(path,40,"/proc/%ld/status",tgid);
//Lets attempt to open that file for reading
	statusf =fopen(path,"r");
	if(!statusf){//If it failed, then print to our log and abort
		printDateLog();
		fprintf(logfp,"ubuntu phunt: unable to open /proc/%ld/status in order to get %s! ERROR aborting!\n",tgid,stat_wanted);
		exit(1);
	}
//If we can read, then lets look at our lines until we find the one that starts with our string stat_wanted
	while(fgets(line, 100, statusf)) {
    //Check if current line starts with string we want
		if(strncmp(line, stat_wanted, (int)strlen(stat_wanted)) == 0){
		//If it starts with it then ignore "stat_wanted:" portion and whitespace
		p = line + (int)strlen(stat_wanted) + 1;//skip "stat_wanted" portion
		while(isspace(*p)) {//take care of any lingering whitespace
		++p;
		}
    //Value p is the line after we get rid of the identifier text, but line may contain extra strings
    //Lets tokenize the line and get rid of the parts we don't need
		token = strtok(p," \t");//For the most part we only need the first value we see
		if(strncmp(stat_wanted,"Uid:",4) == 0){
    //If the stat we wanted was the Uid, we convert it to the username using getpwuid
		struct passwd *pwd;
		pwd = getpwuid(atoi(token));
		result = strdup(pwd->pw_name);//our result is not the username that matches the found uid
		}else{
    //If this was not a Uid lookup, then allocate memory and save the value
		result = malloc(strlen(token) + 1);
		strcpy(result, token);
		}
		break;//Break out of our while because we have a result by now
		}
	}
//Close our file and return our result
	fclose(statusf);
	return result;

}

/* Function used mainly to get the username or status (running, sleeping etc.) of a process */
int get_nice(long tgid) {
    
    char filename[100];
    sprintf(filename, "/proc/%ld/stat", tgid);
    FILE *f = fopen(filename, "r");

    int nice;
    fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %d ",&nice);
    //printf("nice of pid %ld is = %d\n", tgid,nice);

    
    fclose(f);

    return nice;

}

long get_memory(long tgid) {
    
    char filename[100];
    sprintf(filename, "/proc/%ld/statm", tgid);
    FILE *f = fopen(filename, "r");

    long memory;
    fscanf(f, "%ld",&memory);
    //printf("memory of pid %ld is = %ld\n", tgid, memory);

    
    fclose(f);

    return memory;

}

/* get the path of a process given it's id, if we are unable to read it, then return null and print an error message*/
char * get_path(long tgid) {
    char path[40];
    char* result;
    sprintf(path, "/proc/%ld/exe", tgid);
    char buf[PATH_MAX];
    int amount_read;
//printf("path being readlink from: %s\n",path);
    amount_read = readlink(path,buf,sizeof(buf)-1);
    if( amount_read != -1 ){
	buf[amount_read] = '\0';
printf("THIS IS IN tHE BUFFER: %s\n",buf);
	result = malloc( amount_read + 1);
        strcpy(result,buf);
    }else{
	fprintf(stderr,"Unable to read path for pid: %ld : ",tgid);
	perror("");	
	result = NULL;
    }
	
    printf("path for pid:%ld is : %s\n",tgid,result); 
    return result;
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
				free(spec_path);//free path once done using it
				//get the default configfile descriptor here
				getFileToRead(conf,d_conf_path);

		  } else if ( strcmp(argv[1],"-c") == 0) {
		    //printf("We want the configfile %s \n",argv[2]);
				//get the default logfile descriptor here
				getFileToAppend(log,d_log_path);
				//get the specified configfile descriptor we want here
				char * spec_path = concat(d_conf_dir,argv[2]);
				getFileToRead(conf,spec_path);
				free(spec_path);//free path once done using it

		  }else{
				//if our -l or -c was not our second argument
		    printf( "%s\n\n", usage );
				exit(1);
		  }
		}else if( argc == 5){ //Check when we specify log and config files
			 if( strcmp(argv[1],"-l") == 0 && strcmp(argv[3],"-c") == 0 ) {
			    //printf("We want the logfile %s \n",argv[2]);
			    //printf("We want the configfile %s \n",argv[4]);
					//get the specified logfile descriptor here
					char * spec_path = concat(d_log_dir,argv[2]);
					getFileToAppend(log,spec_path);
					free(spec_path);//free once done using it
					//get the specified configfile descriptor we want here
					spec_path = concat(d_conf_dir,argv[4]);
					getFileToRead(conf,spec_path);
					free(spec_path);//free again after use

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

/* Function that checks that a line consist of non non visible characters */
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
  //Close our log file
  if( logfp != NULL ) {
    fclose( logfp );
  }
  //close our configuration file
  if( conf != NULL ) {
    fclose(conf);
  }
  //free our rules list memory
 freeList();
//exit gracefully!
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
printf("pid %d\n",pid);
// Build a string that will have the log message for when we start up the program
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);//Get values for our timestamp then build message
	snprintf(start_up,100,"%d-%d-%d %d:%d:%d ubuntu phunt: phunt startup (PID=%d)\n",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,pid);

// Parse the command line and set up the pointers to the log and config files
	parse_command_line(argc, argv, &logfp, &conf);
// Parse the config file and construct our rules here
	char line[150];//local variable which will hold our line as we read
	while(fgets(line,sizeof(line), conf)){
		if(is_empty(line) || line[0] == '#'){//Ignore white lines or lines starting with #
		    //printf("Ignore this stuff\n");
		} else{
		    //printf("Line: %s",line);
		    /* Lets get our ACTION TYPE PARAM here! */
		    //First we need to split the line by white space to get our three arguments
		    char * token = strtok(line," \t\n");
		    //Then we save them into local char * so we can add a rule to our list
		    char * action = strdup(token);
			//printf("ACTITON: %s\n",action);
			token = strtok(NULL," \t\n");
		    char * type = strdup(token);
			//printf("TYPE: %s\n",type);
			token = strtok(NULL," \t\n");
		    char * param = strdup(token);
			//printf("PARAM: %s\n",param);

		    //Check rule start flag, if it is 1, add to head, and set flag as 0, else add to tail
		    if( rule_start == 1){
			listAdd(action,type,param,false);
			rule_start = 0;
		    }else{
			listAdd(action,type,param,true);
		    }
		    printDateLog();
		    fprintf(logfp,"ubuntu phunt: found and added rule < ACTION:%s\tTYPE:%s\tPARAM:%s >\n",action,type,param);
		    //Free memory used for local placeholders of action type param
		    free(action);
		    free(type);
		    free(param);
		}
	}

/*Lets print our rules on the cmd line!*/
printf("List after saving rules!\n");
printList();

/* Print to Log when we finished parsing the config file and have saved our rules */
printDateLog();
fprintf(logfp,"ubuntu phunt: finished parsing the config file!\n");
//Reading the proc/ directory
//set up the DIR
while(1){
	DIR* proc = opendir("/proc");
	struct dirent* ent;
	long tgid;

//Throw error and quit if we can open /proc
	if(proc == NULL){
		perror("opendir(/proc)");
		return 1;
	}

/* Lets read proc and find our processes */
	while( ent = readdir(proc)) {
	//look if the folder being looked at is a digit (meaning its a process folder)
		if(!isdigit(*ent->d_name))
			continue; //If it is not we continue to the next file in the proc dir
		RuleNode *iterator = head;//Start our rule iterator pointer at the head
		char * state;//a local value to hold the state of the process we are scanning
		char * username;//local value to hold the username of the owner of the process being scanned
    char * path;//value that holds path to process being scanned
    long memory;//value that holds memory use size of process being scanned
    int nice; //value that holds nice value
		//If we didn't continue, then convert the name of the folder into a long which holds the pid
		tgid = strtol(ent->d_name, NULL, 10); //tgid is our pid of the process being scanned
		//Get the values for the process status, username, path, and memory
		state = get_status(tgid,"State:");
		username = get_status(tgid,"Uid:");
		nice = get_nice(tgid);
		memory = get_memory(tgid);
		path = get_path(tgid);

		printf("pid: %ld\t\tuser:%s\t\tmem:%ld\t\tnice:%d\n",tgid,username,memory/1000,nice);
		int breaker = 0;

		//Print to log Scanning process (PID = pid)
    printDateLog();
    fprintf(logfp, "ubuntu phunt: scanning process with PID = %ld\n",tgid );
		/* Check all rules on this process here */
		while(iterator != NULL && breaker == 0) {
			  /* Code that checks for matches of type <user> */
    		if( strcmp(iterator->type,"user") == 0 && strcmp(iterator->param,username) == 0){
          if( strcmp(iterator->action,"kill") == 0){
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: killing process PID = %ld due to owner user being %s\n",tgid,username);
	    kill(tgid, SIGKILL);
            //wait a little maybe
	    usleep(10000);
            //check if killed and print confirmation status
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld should be terminated, verifying now\n",tgid);
	    if(!doesFileExistProc(tgid)){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld has been successfully terminated\n",tgid);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld MAY have terminated or another process has appeared with same PID\n",tgid);
	    }
            //break out of rule checking and move on to next process
            breaker = 1;
          }else if(strcmp(iterator->action,"suspend") == 0){
            //preform suspend
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: SUSPENDING process PID = %ld due to owner user being %s\n",tgid,username);
	    kill(tgid, SIGSTOP);
            //wait a little
	    usleep(10000);
            //check suspension and print confirmation status
	    char* t_s = get_status(tgid,"State:");
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld should be SUSPENDED, verifying now\n",tgid);
	    if(t_s[0] == 'T'){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld has been successfully SUSPENDED\n",tgid);
	    free(t_s);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: WARNING process PID = %ld did not SUSPEND\n",tgid);
	    free(t_s);
	    }
            //do not break
          }else if(strcmp(iterator->action,"nice") == 0){
            //preform nice
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: INCREASING PRIORITY of process PID = %ld due to owner user being %s\n",tgid,username);
	    int which = PRIO_PROCESS;
	    int ret = setpriority(which, tgid, -20);
            //wait a little
	    usleep(10000);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld should have priority of -20, verifying now\n",tgid);
            //check nice and print confirmation
	    if(get_nice(tgid) == -20){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld priority increase SUCCESSFUL\n",tgid);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: WARNING process PID = %ld priority increase UNSUCCESSFUL\n",tgid); 
	    }	
            //do not break
          }
    		}

			 /*Code that checks for matches of type <path> if the path was NULL or unreadable, we skip this check*/
    		if( path != NULL &&strcmp(iterator->type,"path") == 0 && strcmp(iterator->param,path) == 0){
          if( strcmp(iterator->action,"kill") == 0){
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: killing process PID = %ld due to path of process being %s\n",tgid,path);
	    kill(tgid, SIGKILL);
            //wait a little maybe
	    usleep(10000);
            //check if killed and print confirmation status
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld should be terminated, verifying now\n",tgid);
	    if(!doesFileExistProc(tgid)){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld has been successfully terminated\n",tgid);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld MAY have terminated or another process has appeared with same PID\n",tgid);
	    }
            //break out of rule checking and move on to next process
            breaker = 1;
          }else if(strcmp(iterator->action,"suspend") == 0){
            //preform suspend
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: SUSPENDING process PID = %ld due to path of process being %s\n",tgid,path);
	    kill(tgid, SIGSTOP);
            //wait a little
	    usleep(10000);
            //check suspension and print confirmation status
	    char* t_s = get_status(tgid,"State:");
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld should be SUSPENDED, verifying now\n",tgid);
	    if(t_s[0] == 'T'){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld has been successfully SUSPENDED\n",tgid);
	    free(t_s);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: WARNING process PID = %ld did not SUSPEND\n",tgid);
	    free(t_s);
	    }
            //do not break
          }else if(strcmp(iterator->action,"nice") == 0){
            //preform nice
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: INCREASING PRIORITY of process PID = %ld due to path of process being %s\n",tgid,path);
	    int which = PRIO_PROCESS;
	    int ret = setpriority(which, tgid, -20);
            //wait a little
	    usleep(10000);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld should have priority of -20, verifying now\n",tgid);
            //check nice and print confirmation
	    if(get_nice(tgid) == -20){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld priority increase SUCCESSFUL\n",tgid);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: WARNING process PID = %ld priority increase UNSUCCESSFUL\n",tgid); 
	    }	
            //do not break
          }
    		}

			 /*Code that checks for matches of type <memory>*/
    		if( strcmp(iterator->type,"memory") == 0){
          	int limit = atoi(iterator->param);
		//printf("LIMIT IS : %d CURRENT MEM IS:%d\n",limit,(int)(get_memory(tgid)/1000));
		//First check that process is over memory ceiling, we are given memory in KB so divde by 1000 to get MB		
		if( (int)(get_memory(tgid)/1000) >= limit){
			printf(" pid: %ld over limit!\n",tgid);
			printDateLog();
			fprintf(logfp,"ubuntu phunt: process PID = %ld over memory ceiling of %s MB !\n",tgid,iterator->param);
          if( strcmp(iterator->action,"kill") == 0){
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: killing process PID = %ld due to being over memory limit!\n",tgid);
	    kill(tgid, SIGKILL);
            //wait a little maybe
	    usleep(10000);
            //check if killed and print confirmation status
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld should be terminated, verifying now\n",tgid);
	    if(!doesFileExistProc(tgid)){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld has been successfully terminated\n",tgid);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt:process PID = %ld MAY have terminated or another process has appeared with same PID\n",tgid);
	    }
            //break out of rule checking and move on to next process
            breaker = 1;
          }else if(strcmp(iterator->action,"suspend") == 0){
            //preform suspend
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: SUSPENDING process PID = %ld due to being over memory limit %s\n",tgid,username);
	    kill(tgid, SIGSTOP);
            //wait a little
	    usleep(10000);
            //check suspension and print confirmation status
	    char* t_s = get_status(tgid,"State:");
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld should be SUSPENDED, verifying now\n",tgid);
	    if(t_s[0] == 'T'){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld has been successfully SUSPENDED\n",tgid);
	    free(t_s);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: WARNING process PID = %ld did not SUSPEND\n",tgid);
	    free(t_s);
	    }
            //do not break
          }else if(strcmp(iterator->action,"nice") == 0){
            //preform nice
            printf("Preform action %s:\n", iterator->action);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: INCREASING PRIORITY of process PID = %ld due to being over memory ceiling %s\n",tgid,username);
	    int which = PRIO_PROCESS;
	    int ret = setpriority(which, tgid, -20);
            //wait a little
	    usleep(10000);
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld should have priority of -20, verifying now\n",tgid);
            //check nice and print confirmation
	    if(get_nice(tgid) == -20){
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: process PID = %ld priority increase SUCCESSFUL\n",tgid);
	    }else{
	    printDateLog();
	    fprintf(logfp,"ubuntu phunt: WARNING process PID = %ld priority increase UNSUCCESSFUL\n",tgid); 
	    }	
            //do not break
          }
    		}
		}
		
			//Go to the next rule
			iterator = iterator->next;

  		}
		//Print to log done scanning process (PID = pid)
    printDateLog();
    fprintf(logfp, "ubuntu phunt: completed scanning for process PID = %ld\n",tgid);
		//printf("State %s and user %s:\n", state, username);
		free(state);
		free(username);
		if(path != NULL)		
		free(path);
	}
sleep(2);
}


//If we get here lets close our files and list, we never should though (in theory)
	if(conf != NULL){
	printf("Closing conf file!\n");
	fclose(conf);
	}

	if(logfp != NULL){
	printf("Closing log!\n");
	fclose(logfp);
	}

	freeList();

	return 0;
}
