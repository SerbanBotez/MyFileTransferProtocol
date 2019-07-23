#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <signal.h>
#include <wait.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <openssl/aes.h>

int clientNumber;
extern int errno;

static const unsigned char key[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

void handle()
{
    
    while(waitpid(-1, NULL, WNOHANG) > 0); 
}

int count_lines(char* name)
{
    FILE *f = fopen(name, "r");                
    int lines_number = 0;
    for(int i = getc(f); i != EOF; i = getc(f) )
        if(i == '\n')
            lines_number ++;
    fclose(f);
    return lines_number +1;
}

int login_validation(char username[], char password[])
{
    FILE *f = fopen("login.txt", "r");
    char temp_username[100];
    char temp_password[100];
    int lines_number = count_lines("login.txt");
    for (int i = 0; i < lines_number; i++)
    {
        memset(temp_username, 0, strlen(temp_username));
        memset(temp_password, 0, strlen(temp_password));
        fscanf(f, "%s %s", temp_username, temp_password);
        if(strcmp(username, temp_username) == 0 && strcmp(password, temp_password) == 0)
        {
            fclose(f); 
            return 1;
        }
    }
    fclose(f);
    return 0;
}

int is_blacklist(char username[])
{
    FILE *f = fopen("blacklist.txt", "r");
    char temp_username[100];
    int lines_number = count_lines("blacklist.txt");
    for(int i = 0; i < lines_number; i++)
        {
            memset(temp_username, 0, strlen(temp_username));
            fscanf(f, "%s", temp_username);
            if(strcmp(username, temp_username) == 0)
            {
                fclose(f);
                return 1;
            }
        }
    fclose(f);
    return 0;
}

char* get_valid_commands(char username[])
{
    FILE *f = fopen("whitelist.txt", "r");
    char temp_username[100];
    char temp_command[50];
    char temp_details[1000];
    char* ret_value = temp_details;
    int lines_number = count_lines("whitelist.txt");
    int lines = 0;                                     
    while(lines <= lines_number)
    {
        memset(temp_username, 0, strlen(temp_username));
        if(strcmp(temp_command, "end") == 0)
            strcat(temp_command, "e");
        memset(temp_details, 0, strlen(temp_details));
        fscanf(f, "%s", temp_username);

        if(strcmp(temp_username, username) == 0)
            lines = lines_number + 1;
        while(strcmp(temp_command, "end") != 0)
        {                                           
            memset(temp_command, 0, strlen(temp_command));
            fscanf(f, "%s", temp_command);
            if((strcmp(temp_command, "end") != 0))
            {
                strcat(temp_details, temp_command);
                strcat(temp_details, " ");
            } 
        }
        lines = lines + 1;
    }
    return ret_value;
}

int list(char path[], int clientSocket) 
{
    DIR *d;
    d = opendir(path);
    struct dirent *dir;
    char files[10000];
    int status = 0;
    int size = 0;
    struct stat fstat;
    char local_path[1000];
    char attributes[1000];

    if(d != NULL)
    {
        status = 1;
        write(clientSocket, &status, sizeof(int));

        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name,".") !=0 && strcmp(dir->d_name, "..")!=0)
            {   

                status = 1;
                memset(local_path, 0, strlen(local_path));
                strcpy(local_path, path);
                strcat(local_path, dir->d_name);

                stat(local_path, &fstat);
                if(S_ISDIR(fstat.st_mode) != 0)
                    status = 2;
                if(S_ISREG(fstat.st_mode) != 0)
                    status = 3;

                write(clientSocket, &status, sizeof(int));   

                memset(attributes, 0, strlen(attributes));

                if(S_ISDIR(fstat.st_mode) != 0)
                    strcat(attributes, "d");
                else
                    strcat(attributes, "-");   

                if(fstat.st_mode & S_IRUSR)
                    strcat(attributes, "r");
                else            
                    strcat(attributes, "-");

                if(fstat.st_mode & S_IWUSR)
                    strcat(attributes, "w");
                else            
                    strcat(attributes, "-");

                if(fstat.st_mode & S_IXUSR)
                    strcat(attributes, "x");
                else            
                    strcat(attributes, "-");

                if(fstat.st_mode & S_IRGRP) 
                    strcat(attributes, "r");
                else            
                    strcat(attributes, "-");

                if(fstat.st_mode & S_IWGRP) 
                    strcat(attributes, "w");
                else            
                    strcat(attributes, "-");

                if(fstat.st_mode & S_IXGRP) 
                    strcat(attributes, "x");
                else            
                    strcat(attributes, "-");

                if(fstat.st_mode & S_IROTH)
                    strcat(attributes, "r");
                else
                    strcat(attributes, "-"); 

                if(fstat.st_mode & S_IWOTH)
                    strcat(attributes, "w");
                else
                    strcat(attributes, "-");      
                
                if(fstat.st_mode & S_IXOTH)
                    strcat(attributes, "x");
                else
                    strcat(attributes, "-");    
                strcat(attributes, " ");

                size = strlen(attributes) + 1;
                write(clientSocket, &size, sizeof(int));            
                write(clientSocket, attributes, size);
         
                write(clientSocket, &fstat.st_nlink, sizeof(long));

                struct passwd *ps;
                ps = getpwuid(fstat.st_uid);
                size = strlen(ps->pw_name) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, ps->pw_name, size);

                struct group *gr;
                gr = getgrgid(fstat.st_uid);
                size = strlen(gr->gr_name) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, gr->gr_name, size);

                size = fstat.st_size;
                write(clientSocket, &size, sizeof(int));

                time_t  t = fstat.st_mtime;  //ca sa transform din secunde
                struct tm lt;
                localtime_r(&t, &lt);
                char ltime[100];
                strftime(ltime, sizeof(ltime), "%c", &lt);
                size = strlen(ltime) + 1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, ltime, size);

                size = strlen(dir->d_name) + 1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, dir->d_name, size);

                strcat(local_path, "/");
            }
        }
        status = 0;
        write(clientSocket, &status, sizeof(int));
        closedir(d);
        return 1;
    }
    return 0;
}

int create_directory(char path[], char message[])
{
    char local_path[1000];
    strcpy(local_path, path);
    strcat(local_path, message);
    strcat(local_path, "/");
    if(mkdir(local_path, 0777) == -1)
    {
        printf("%s\n", "Eroare la crearea directorului");
        return 0;
    }
    return 1;
}

char* change_directory(char message[], char path[], char username[])
{           
    char user_path[1000] = {0};
    strcat(user_path, "Home/");
    strcat(user_path, username);
    strcat(user_path, "/");
    char new_path[1000];
    char local_path[1000];
    strcpy(local_path, path);
    char *ret;
    char *ret_value = local_path;
    int number = 0;
    int i;
    int local_number = 0;
    struct stat filestat; 

    if(strcmp(message, ".") == 0)
    {
        strcpy(ret_value, "NuExista");
        return ret_value;
    }

    if(strcmp(message, "..") == 0)
    {
        memset(new_path, 0, strlen(new_path));
        if(strcmp(local_path, user_path) == 0)
        {
            strcpy(ret_value, "MaxHeight");
            return ret_value;
        }

        
        for(i=0; i< strlen(local_path); i++)
        {
            if(local_path[i] == '/')
                number++;
        }

        for(i=0; i< strlen(local_path); i++)
        {
            if(local_path[i] == '/')
                local_number++;
            if(local_number == number-1)
                break;
            new_path[i] = local_path[i];
        }
        new_path[i] = '/';
        new_path[i+1] = '\0';
        strcpy(ret_value, new_path);
        return ret_value;
    }

    strcat(local_path, message);     //tratez cazurile cand numele dat nu este de la un director    
    stat(local_path, &filestat);     //si cand directorul nu exista; 

    DIR *d;                    //incerc sa deschid directorul si daca nu se poate inseamna ca nu exista
    d = opendir(local_path);
    if(d == NULL)
    {
        strcpy(ret_value, "NuExista");
        return ret_value;
    }

    if(S_ISREG(filestat.st_mode) != 0)
    {
        strcpy(ret_value, "NuExista");
        return ret_value;
    }


    strcat(local_path, "/");
    return ret_value;
}

int delete_file(char path[], char message[])        
{
    char local_path[1000] = {0};
    strcpy(local_path, path);
    strcat(local_path, message);
    if(unlink(local_path) != 0)
    {
        return -1;
    }
    return 0;
}

int delete_subdirectory(char path[])
{
    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
                continue;
            struct stat fstat;
            char newpath[100];
            strcpy(newpath, path);
            strcat(newpath, "/");
            strcat(newpath, dir->d_name);
            stat(newpath, &fstat);

            if(S_ISREG(fstat.st_mode) != 0)
            {
                printf("%s\n", dir->d_name);
                remove(newpath);    //call unlink pentru fisier
            }
            
            if(S_ISDIR(fstat.st_mode) != 0)
            {
                printf("%s\n", dir->d_name);
                delete_subdirectory(newpath);
            }
        }
        remove(path);  //call rmdir pentru directoare
    }

}

int check_if_directory(char path[], char message[])
{
    DIR *dd;
    dd = opendir(path);
    struct dirent *dir;
    struct stat fstat;
    char local_path[1000] = "\0";
    if(dd == NULL)
    {
        return -1;
    }
    if( dd!= NULL)
    {
        while(dir = readdir(dd))
        {
            if(strcmp(dir->d_name, message) == 0)
            {
                strcat(local_path, path);
                strcat(local_path, "/");
                strcat(local_path, message);
                stat(local_path, &fstat);
                if(S_ISDIR(fstat.st_mode) != 0)
                {
                    closedir(dd);
                    return 0;
                }
                if(S_ISREG(fstat.st_mode) != 0)
                {
                    closedir(dd);
                    return 1;
                }   
            }
        }
    }
    closedir(dd);
    return 1;
}
                                                            
int delete_directory(char message[], char path[])           
{
    DIR *d;

    if(check_if_directory(path, message) == 1)
    {
        return -1;
    }

    char lmessage[1000];
    char local_path[1000];
    strcpy(local_path, path);
    strcpy(lmessage, message);  
    strcat(local_path, lmessage);

    d = opendir(local_path);
    struct dirent *dir;
    
    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
                continue;
            struct stat fstat;
            char newpath[100]= {0};
            strcat(newpath, local_path);
            strcat(newpath, "/");
            strcat(newpath, dir->d_name);
            stat(newpath, &fstat);
                
            if(S_ISREG(fstat.st_mode) != 0)        
            {
                remove(newpath);
            }
            
            if(S_ISDIR(fstat.st_mode) != 0)
            {
                delete_subdirectory(newpath);
            }
        }

        if(remove(local_path) == 0)
        {
            closedir(d);
            return 0;                      
        }
        else
            closedir(d);
            return -1;
    }

    return -1;
}

int renamefile(char message[], char message2[], char path[])
{
    char local_path[1000];
    char newpath[100];
    struct stat fstat;
    strcpy(newpath, path);
    strcpy(local_path, path);
    strcat(local_path, message);
    strcat(newpath, message2);
    stat(local_path, &fstat);

    if(S_ISDIR(fstat.st_mode) != 0)
    {
        return -1;
    }

    if(rename(local_path, newpath) < 0 )
    {
        return 0;
    }

    return 1;
}

int check_file(char path[], char message[])
{
    DIR *d;
    d = opendir(path);
    struct dirent *dir;
    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, message) == 0)
            {
                return 0;
            }
        }
        closedir(d);
    }
    return 1;
}

int file_exists(char path[], char message[])
{
    DIR *d;
    d = opendir(path);
    struct dirent *dir;
    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, message) == 0)
            {
                return 1;
            }
        }
        closedir(d);
    }
    return 0;
}


int move_file(char path[], char username[] , char message[], char message2[])
{
    char valid_path[30] = "\0";
    strcat(valid_path, "Home");
    strcat(valid_path, "/");
    strcat(valid_path, username);
    if(check_if_directory(message2, message) == 0)
        return -1;
    if(check_if_directory(path, message) == 0)
        return -3;
    if(strstr(message2, valid_path) == NULL)
        return -1;
    if(file_exists(path, message) == 0)
        return 0;
    if(file_exists(message2, message) == 1)
        return -2;
    if(file_exists(message2, message) == 1)
        return -2;
    
    int id;
    id = fork();
    if(id > 0)
    {
        return 1;
    }
    if(id < -1)
        return -4;
    if(id == 0)
    {
        FILE *f1;
        FILE *f2;
        char local_path[1000]="\0";
        strcpy(local_path, path);
        strcat(local_path, "/");
        strcat(local_path, message);
        strcat(message2, "/");
        strcat(message2, message);
        f1 = fopen(local_path, "rb");
        f2 = fopen(message2, "w");

        unsigned char data[1] = {0};
        int leng = 0;
        while(1)
        {
            leng = fread(data, 1, 1, f1);
            if(leng > 0)
            {
                fwrite(data, 1, leng, f2);
                continue;
            }
            if(leng < 0)
            {
                continue;
            }
            if(leng == 0)
            {
                if(feof(f1))
                {
                    fclose(f1);
                    fclose(f2);
                    unlink(local_path);
                    break;
                }

                if(ferror(f1))
                {
                    fclose(f1);
                    fclose(f2);
                    break;
                }
            }
        }
        exit(1);
    }
}

void add_to_blacklist(char username[])
{
    FILE *f;
    f = fopen("blacklist.txt", "a");
    if(f == NULL)
    {
        printf("%s\n", "Nu s-a putut adauga clientul in blacklist");
        return;
    }
    char umessage[100] = {0};
    strcat(umessage, username);
    fprintf(f, "\n%s", umessage);
    fclose(f);
}

int main()
{
    int serverSocket;   
    struct sockaddr_in serverAddr;
    struct sockaddr_in from;
    
    //creare socket
    if ((serverSocket = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      perror ("[server]Eroare la socket().\n");
      return 0;
    }

    //umplere structura socket
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(2030);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    //reutilizam adresa
    int enable=1 ;
    if(setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int) )< 0 )
    {
        perror ("[server]Eroare la reuse().\n");
        return 0;
    }

    //atasam socketul
    if (bind (serverSocket, (struct sockaddr *) &serverAddr, sizeof (struct sockaddr)) == -1)
    {
      perror ("[server]Eroare la bind().\n");
      return 0;
    }

    //punem serverul sa asculte
    if (listen (serverSocket, 5) == -1)
    {
      perror ("[server]Eroare la listen().\n");
      return 0;
    }

    printf ("[server]Asteptam la portul %d...\n", 2030);
    fflush (stdout);

    //se accepta clientii
    while(1)
    {
        int clientSocket;
        int length = sizeof(from);

        clientSocket = accept(serverSocket, (struct sockaddr *) &from, &length); //structura from contine informatii de la client
                                                                                 //facem fork dupa accept, ca serverul sa fie concurent
        if(clientSocket < 0)
        {
             perror ("[server]Eroare la accept().\n");
             continue;
        }


        int pid;
        pid = fork();

        if(pid == -1)
        {
            printf("%s", "Eroare la fork");
            return 0;
        }

        signal(SIGCHLD, handle);        
                                       
        clientNumber ++;
        if(pid > 0)
            {  ; }//parinte 

        else
        {
            //copil
            printf("%s", "A venit clientul numarul : ");
            printf("%d\n", clientNumber);

            char message[1000]; 
            char message2[1000];
            int size;
            int status;
            char response[1000];
            char username[100];
            char password[100];
            int logged = 0;
            int flag = 0;
            int blacklist = 0;
            char valid_commands[1000];
            char all_commands[1000] = "";
            char path[10000];
            memset(path, 0, strlen(path));
            strcpy(path, "Home\0");
            char oldpath[10000];
            char local_path[10000]; 

        while(1)                //cat timp clientul da comenzi
        {
            memset(message, 0, strlen(message));
            memset(response, 0, strlen(response));

            if (read(clientSocket, &size, sizeof(int)) == -1)
            {
                printf("%s\n", "Eroare le citirea dimensiunii comenzii");
                continue;
            }

            if (read(clientSocket, message, size) == -1)
            {
                printf("%s\n","Eroare la citirea comenzii");       //daca clientul se deconecteaza fara exit, va da eroare aici
                close(clientSocket);
                printf("%s", "A iesit clientul numarul : ");
                printf("%d\n", clientNumber);
                exit(1);
            }

            
            if(logged == 1 && strstr(valid_commands, message) == NULL && strstr(all_commands, message) != NULL)
            {
                if(blacklist == 0)
                    add_to_blacklist(username);
                memset(message, 0, strlen(message));
                strcpy(message, "exit\0");
            }

            if(strcmp(message, "help") == 0)
            {
                memset(response, 0, strlen(response));
                strcpy(response, "help");
                size = strlen(response) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                if(logged == 0)
                {
                    memset(response, 0, strlen(response));
                    strcpy(response, "help login exit");
                    size = strlen(response) +1;
                    write(clientSocket, &size, sizeof(int));
                    write(clientSocket, response, size);
                    continue;
                }
                memset(response, 0, strlen(response));
                strcpy(response, get_valid_commands(username));
                size = strlen(response) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                continue;
            }

            if(strcmp(message, "login") == 0 && logged == 0)
            {
                memset(response, 0, sizeof(response));
                memset(username, 0, sizeof(username));
                memset(password, 0, sizeof(password));
                strcpy(response, "login");
                       
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, username, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, password, size);

                memset(response, 0, sizeof(response));

                if(login_validation(username, password) == 1)
                    {
                        char response[] = "suc";
                        size = strlen(response);
                        write(clientSocket, &size, sizeof(int));
                        write(clientSocket, response, size);
                        logged = 1;
                        strcat(path, "/");
                        strcat(path, username);
                        strcat(path, "/");
                        if(is_blacklist(username) == 1)
                            {      
                                status = 1;
                                write(clientSocket, &status, sizeof(int));
                                printf("%s\n", "Clientul se afla in blacklist");
                                blacklist = 1;
                                memset(valid_commands, 0, strlen(valid_commands));
                                strcat(valid_commands, "disconnect");
                                strcat(valid_commands, " ");
                                strcat(valid_commands, "help");
                                strcat(valid_commands, " ");
                                strcat(valid_commands, "list");
                                strcat(valid_commands, " ");
                                strcat(valid_commands, "location");
                                strcat(valid_commands, " ");
                                strcat(valid_commands, "chdir");
                                strcat(valid_commands, " ");
                                strcat(valid_commands, "get");
                                strcat(valid_commands, " ");
                                strcat(valid_commands, "exit");
                                
                                size = strlen(valid_commands) + 1;
                                write(clientSocket, &size, sizeof(int));
                                write(clientSocket, valid_commands, size);
                            }
                        else
                            {
                                status = 0;
                                write(clientSocket, &status, sizeof(int));
                                memset(valid_commands, 0, strlen(valid_commands));
                                strcpy(valid_commands, get_valid_commands(username));
                                size = strlen(valid_commands) + 1;
                                write(clientSocket, &size, sizeof(int));
                                write(clientSocket, valid_commands, size);
                            }
                    }
                else
                    {
                        char response[] = "fail";                 //logarea a esuat
                        size = strlen(response);
                        write(clientSocket, &size, sizeof(int));
                        write(clientSocket, response, size);
                    }
                   continue;
            }

            if(strcmp(message, "exit") == 0)
            {
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, message, size);
                close(clientSocket);
                printf("%s", "A iesit clientul numarul : ");
                printf("%d\n", clientNumber);
                exit(1);
            }

            if(strcmp(message, "disconnect") == 0 && logged == 1)
            {
                memset(response, 0, strlen(response));
                strcpy(response, "disc");
                size = strlen(response) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                size = 0;
                logged = 0;
                blacklist = 0;
                memset(path, 0, strlen(path));
                memset(oldpath, 0, strlen(oldpath));
                memset(local_path, 0, strlen(local_path));
                memset(username, 0, strlen(username));
                memset(password, 0, strlen(password));
                memset(valid_commands, 0, strlen(valid_commands));
                strcpy(path, "Home\0");
                size = 1;
                write(clientSocket, &size, sizeof(int));
                continue;
            }

            if(strcmp(message, "location") == 0 && logged == 1)
            {
                memset(response, 0, strlen(response));
                strcpy(response, "location");
                size = strlen(response) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                size = strlen(path) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, path, size);
                continue;
            }

            if(strcmp(message, "list") == 0 && logged == 1)
            { 
                memset(response, 0, strlen(response));
                strcpy(response, "list");
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                memset(response, 0, strlen(response));
                status = list(path, clientSocket);
                if(status == 0)
                {
                    status = 0;
                    write(clientSocket, &status, sizeof(int));
                    memset(response, 0, strlen(response));
                    strcpy(response, "Nu s-a putut face listarea directorului curent");
                    size = strlen(response) +1;
                    write(clientSocket, &size, sizeof(int));
                    write(clientSocket, response, size);
                    continue;
                }
                continue;
            }

            if(strcmp(message, "crdir") == 0 && logged == 1)
            {
                memset(response, 0, strlen(response));
                memset(message, 0, strlen(message));
                strcpy(response, "crdir");   
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);
              
                status = create_directory(path, message);  
                
                write(clientSocket, &status, sizeof(int));
                continue;
            }

            if(strcmp(message, "chdir") == 0 && logged == 1) 
            {
                memset(response, 0, strlen(response));
                memset(message, 0, strlen(message));
                strcpy(response, "chdir");
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);
                memset(response, 0, strlen(response));
                memset(oldpath, 0, strlen(oldpath));
                memset(local_path, 0, strlen(local_path));
                strcpy(oldpath, path);
                strcpy(local_path, path);
                strcpy(response, change_directory(message, local_path, username));
                if(strcmp(response, "MaxHeight") == 0)
                {
                    size = strlen(response) +1;
                    write(clientSocket, &size, sizeof(int));
                    write(clientSocket, response, size);
                    continue;
                }
                if(strcmp(response, "NuExista") == 0)
                {
                    size = strlen(response) +1;
                    write(clientSocket, &size, sizeof(int));
                    write(clientSocket, response, size);
                    continue;
                }
                memset(local_path, 0,strlen(local_path));
                memset(path, 0, strlen(path));
                strcpy(path, response);
                size = strlen(response) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                continue;
            }

            if(strcmp(message, "mvfile") == 0)
            {
                memset(response, 0, strlen(response));
                memset(message, 0, strlen(message));
                memset(message2, 0, strlen(message2));
                strcpy(response, "mvfile");
                size = strlen(response) + 1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);

                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message2, size);

                // 1 daca s-a reusit, 0 fisierul nu exista, -1 path-ul nu e corect, -2 fisierul exista deja la destinatie
                status = move_file(path ,username ,message, message2);
                write(clientSocket, &status, sizeof(int));
                continue;
            }

            if(strcmp(message, "deldir") == 0)
            {
                memset(response, 0, strlen(response));
                memset(message, 0, strlen(message));
                strcpy(response, "deldir");
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);
                printf("%s\n", message);
                status = delete_directory(message, path);
                write(clientSocket, &status, sizeof(int));
                continue;
            }

            if(strcmp(message, "renamefile") == 0)
            {
                memset(response, 0, strlen(response));
                memset(message, 0, strlen(message));
                memset(message2, 0, strlen(message2));
                strcpy(response, "renamefile");
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message2, size);
                status = renamefile(message, message2, path);
                write(clientSocket, &status, sizeof(int));
                continue;
            }

            if(strcmp(message, "delfile") == 0)
            {
                memset(response, 0, strlen(response));
                memset(message, 0, strlen(message));
                strcpy(response, "delfile");
                size = strlen(response) +1;
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);
                status = delete_file(path, message);
                write(clientSocket, &status, sizeof(int));
                continue;
            }

            if(strcmp(message, "put") == 0)
            {
                memset(message, 0, strlen(message));
                memset(response, 0, strlen(response));
                strcpy(response, "put");
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);

              
                read(clientSocket, &status, sizeof(int));
                if(status == 0)
                    continue;

                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);
                status = check_file(path, message);
                write(clientSocket, &status, sizeof(int));
                if(status == 0)
                    continue;
               
                //incepe transferul
                memset(local_path, 0, strlen(local_path));
                strcpy(local_path, path);
                strcat(local_path, message);
                FILE *f;
                f = fopen(local_path, "w");
                if(f ==  NULL)
                {
                    //printf("%s\n", "Eroare la crearea fisierului pe server");
                    continue;
                }
            
                int leng;
                while(1)                         
                {
                    unsigned char data[1] = {0};
                    leng = 0;                             
                    read(clientSocket, &leng,  sizeof(int));
                    if(leng == -1)
                        break;
                    read(clientSocket, data, leng);
                    fwrite(data, 1, leng, f);
                }
                fclose(f);
                continue;
            }

            if(strcmp(message, "get") == 0)     
            {
                memset(message, 0, strlen(message));
                memset(response, 0, strlen(response));
                strcpy(response, "get");
                size = strlen(response);
                write(clientSocket, &size, sizeof(int));
                write(clientSocket, response, size);
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, message, size);

                read(clientSocket, &status, sizeof(int));
                if(status == 0)
                    continue;
                
                status = file_exists(path, message);

                write(clientSocket, &status, sizeof(int));
                if(status == 0)
                    continue;
                //incepe transferul

                memset(local_path, 0, strlen(local_path));
                strcpy(local_path, path);
                strcat(local_path, message);
                FILE *f;
                f = fopen(local_path, "rb");
                struct stat fstat;
                stat(local_path, &fstat);
                size = fstat.st_size;

                read(clientSocket, &status, sizeof(int));
                if(status == 0)
                    continue;

                while(1)
                {
                    unsigned char data[1] = {0};
                    int leng = 0;
                    leng = fread(data, 1, 1, f);
                    if(leng > 0)
                    {
                        write(clientSocket, &leng, sizeof(int));
                        write(clientSocket, data, leng);
                        continue;
                    }

                    if(leng == 0)
                    {
                        if(feof(f))
                            leng = -1;
                        if(ferror(f) != 0 )
                        {                        
                            leng = -2;
                        }
                        leng = -1;
                        write(clientSocket, &leng, sizeof(int));
                        break;
                    }
                }
                fclose(f);
                continue;
            }

            memset(response, 0, sizeof(response));
            strcpy(response, "necunoscut");
            size = strlen(response) + 1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, response, size);
        }
        }
    }
    return 0;
}