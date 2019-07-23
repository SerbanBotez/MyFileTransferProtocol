#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <stdlib.h>
#include <wait.h>
#include <signal.h>
#include <openssl/aes.h>

#define green "\x1b[32m"
#define yellow "\x1b[33m"
#define blue  "\x1b[34m"
#define reset "\x1b[0m"

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

void list(char path[]) 
{
    DIR *d;
    d = opendir(path);
    struct dirent *dir;
    struct stat filestat;
    char local_path[1000];

    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name,".") !=0 && strcmp(dir->d_name, "..")!=0)
            {
                memset(local_path, 0, strlen(local_path));
                strcpy(local_path, path);
                strcat(local_path, "/");
                strcat(local_path, dir->d_name);

                if(stat(local_path, &filestat) == -1)
                {
                    perror("Eroare la gasirea proprietatilor continutului directorului curent");
                    return;
                }

                printf( (S_ISDIR(filestat.st_mode)) ? "d" : "-");
                printf( (filestat.st_mode & S_IRUSR) ? "r" : "-");
                printf( (filestat.st_mode & S_IWUSR) ? "w" : "-");
                printf( (filestat.st_mode & S_IXUSR) ? "x" : "-");
                printf( (filestat.st_mode & S_IRGRP) ? "r" : "-");
                printf( (filestat.st_mode & S_IWGRP) ? "w" : "-");
                printf( (filestat.st_mode & S_IXGRP) ? "x" : "-");
                printf( (filestat.st_mode & S_IROTH) ? "r" : "-");
                printf( (filestat.st_mode & S_IWOTH) ? "w" : "-");
                printf( (filestat.st_mode & S_IXOTH) ? "x" : "-");
                printf("%s", " ");

                printf("%ld", filestat.st_nlink);
                printf("%s", " ");

                struct passwd *ps;
                ps = getpwuid(filestat.st_uid);

                printf("%s", ps->pw_name);
                printf("%s", " ");

                struct group *gr;
                gr = getgrgid(filestat.st_uid);
                printf("%s", gr->gr_name);
                printf("%s", " ");

                printf("%ld", filestat.st_size);
                printf("%s", " ");

                time_t  t = filestat.st_mtime;  //ca sa transform din secunde
                struct tm lt;
                localtime_r(&t, &lt);
                char ltime[100];
                strftime(ltime, sizeof(ltime), "%c", &lt);

                printf("%s", ltime);
                printf("%s", " ");

                if(S_ISREG(filestat.st_mode) != 0)
                    printf("%s%s%s%s\n",green, dir->d_name, reset, "  ");
                else
                    if(S_ISDIR(filestat.st_mode) != 0)
                        printf("%s%s%s%s\n",blue, dir->d_name, reset, "  ");
            }
        }
        closedir(d);
    }
    else
    {
        printf("%s\n", "Directorul curent nu s-a putut lista");
        perror("Eroare la stat citiread directorului");
        return;
    }

}

void change_directory(char path[], char msg[])
{
    int i;
    int number;
    int local_number;
    char new_path[1000];
    struct stat dirstat;
    memset(new_path, 0, strlen(new_path));          //daca nu puneam asta nu se updata path-ul

    if(strcmp(msg, ".") == 0)
    {
        printf("Directorul selectat nu exista.\n");
        return;
    }

    if(strcmp(msg, "..") == 0)
    {
        if(strcmp(path, "/") == 0)
        {
            printf("%s\n", "Nu se poate face schimbarea la un nivel superior, maximul a fost atins");
            return;
        }
        
        number = 0;
        local_number = 0;
        for(i=0; i < strlen(path); i++)
        {
            if(path[i] == '/')
                number++;
        }
        for(i=0; i< strlen(path); i++)
        {
            if(path[i] == '/')
                local_number++;
            if(local_number == number)
                break;
            new_path[i] = path[i];
        }
        new_path[i] = '\0'; 
        memset(path, 0, strlen(path));
        strcpy(path, new_path);

        if(strcmp(path, "") == 0)
            strcpy(path, "/");
        printf("%s%s\n", "Noua locatie este : ", path);
        return;
    }

    if(strcmp(path, "/") == 0)
        memset(path, 0, strlen(path));

    DIR *d;
    strcpy(new_path, path);
    strcat(new_path, "/");
    strcat(new_path, msg);
    d = opendir(new_path);

    if(d == NULL)
    {
        printf("%s\n", "Directorul selectat nu se poate dechide sau nu exista");
        return;
    }

    stat(new_path, &dirstat);
    if(S_ISREG(dirstat.st_mode) != 0)
    {
        printf("%s\n", "Numele introduc apartine unui fisier");
        return;
    }


    if(S_ISDIR(dirstat.st_mode) != 0)
    {
        memset(path, 0, strlen(path));
        strcpy(path, new_path);
        printf("%s%s\n", "Noua locatie este : ", path);
        return;
    }

}

void create_directory(char path[], char msg[])
{
    char local_path[1000];

    strcpy(local_path, path);
    strcat(local_path, "/");
    strcat(local_path, msg);

    if(mkdir(local_path, 0777) == -1)
    {
        printf("%s\n", "Eroare la crearea directorului");
        return;
    }

    printf("%s\n", "Directorul a fost creat cu succes");
}

void delete_file(char path[], char msg[]) 
{
    char local_path[1000];
    strcpy(local_path, path);
    strcat(local_path, "/");
    strcat(local_path, msg);
    struct stat filestat;

    stat(path, &filestat);
    if(S_ISREG(filestat.st_mode) != 0)
    {
        printf("%s\n", "Fisierul nu a putut fi sters, introduceti un nume de fisier");
        return;
    }

    if(remove(local_path) != 0)
    {
        printf("%s\n", "Fisierul nu a putut fi sters");
        return;
    }

    printf("%s\n", "Fisierul a fost sters cu succes");
}

void delete_subdirectory(char ppath[])
{
    DIR *d;
    struct dirent *dir;
    char oldpath[1000];
    d = opendir(ppath);

    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
                continue;
            struct stat fstat;
            strcpy(oldpath, ppath);
            strcat(ppath, "/");
            strcat(ppath, dir->d_name);
            stat(ppath, &fstat);

            if(S_ISREG(fstat.st_mode) != 0)
            {
                remove(ppath);
                memset(ppath, 0, strlen(ppath));
                strcpy(ppath, oldpath);  
            }

            if(S_ISDIR(fstat.st_mode) != 0)
            {
                delete_subdirectory(ppath);
                memset(ppath, 0, strlen(ppath));
                strcpy(ppath, oldpath);  
            }
        }
        remove(ppath);
    }
}

void delete_dir(char path[], char msg[])
{
    DIR *d;
    char local_path[1000];
    char old_path[1000];
    strcpy(local_path, path);
    strcat(local_path, "/");
    strcat(local_path, msg);

    printf("%s\n", local_path);
    d = opendir(local_path);
    struct dirent *dir;

    if(d == NULL)
    {
        printf("%s\n", "Nu s-a putut sterge directorul selectat");
        return;
    }

    while(dir = readdir(d))
    {
        if(strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
            continue;
        struct stat filestat;

        
        memset(old_path, 0, strlen(old_path));
        strcpy(old_path, local_path);
       
        strcat(local_path, "/");
        strcat(local_path, dir->d_name);
        stat(local_path, &filestat);

        if(S_ISREG(filestat.st_mode) != 0)
        {
            remove(local_path);
            memset(local_path, 0, strlen(local_path));
            strcpy(local_path, old_path);
        }

        
        if(S_ISDIR(filestat.st_mode) != 0)
        {
            delete_subdirectory(local_path);
            memset(local_path, 0, strlen(local_path));
            strcpy(local_path, old_path);
        }
    }

    if(remove(local_path) != 0)  //call rmdir pentru directoare
    {
        perror("Eroare la stergerea directorului\n");
        printf("%s\n", "Eroare la eliminarea directorului");
        return ;
    }

    printf("%s\n", "Directorul a fost sters cu succes");
}

void rename_file(char path[], char msg[], char msg2[])
{
    char local_path[1000];
    char new_path[1000];

    strcpy(local_path, path);
    strcat(local_path, "/");
    strcat(local_path, msg);
    strcpy(new_path, path);
    strcat(new_path, "/");
    strcat(new_path, msg2);

    if(rename(local_path, new_path) != 0 )
    {
        printf("%s\n", "Eroare la redenumirea fisierului");
        return;
    }

    printf("%s\n", "Fisierul a fost redenumit cu succes");
}

int viable(char path[], char msg[])
{
    char local_path[1000];
    DIR *d;
    struct dirent *dir;
    struct stat fstat;

    strcpy(local_path, path);
    strcat(local_path, "/");
    strcat(local_path, msg);
    d = opendir(path);

    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, msg) == 0)
            {
                stat(local_path, &fstat);
                if(S_ISDIR(fstat.st_mode) != 0)
                {
                    printf("%s\n", "Fisierul selectat este un director");
                    return 0;
                }

                FILE *f = fopen(local_path, "r");
                if(f == NULL)
                {
                    printf("%s\n", "Nu s-a putut deschide fisierul selectat");
                    return 0;
                }

                return 1;
                fclose(f);
            }
        }
        closedir(d);
        printf("%s\n", "Nu s-a putut gasi fisierul selectat");
        return 0;
    }   
    else
    {
        printf("%s\n", "Directorul nu s-a putut deschide");
        return 0;
    }
}

int exists(char path[], char msg[])
{
    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, msg) == 0)
            {
                return 0;
            }
        }
    }
    return 1;
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


void move_file(char path[], char msg[], char msg2[])
{
    //verificare daca fisier exista, daca e fisier, daca nu exista deja un fisier cu acelasi nume in msg2
    int ok = 0;
    DIR *d;
    char local_path[1000];
    char local_path2[1000];
    strcpy(local_path, path);
    strcat(local_path, "/");
    strcat(local_path, msg);

    strcpy(local_path2, msg2);
    strcat(local_path2, "/");
    strcat(local_path2, msg);

    d = opendir(path);
    struct dirent *dir;
    struct stat fstat;
    if(d != NULL)
    {
        while(dir = readdir(d))
        {
            if(strcmp(dir->d_name, msg) == 0)
            {
                ok = 1;
                break;
            }
        }
        if(ok == 0)
        {
            printf("%s\n", "Fisierul selectat nu exista in directorul local");
            closedir(d);
            return;
        }

        stat(local_path, &fstat);
        if(S_ISDIR(fstat.st_mode) != 0)
        {
            printf("%s\n", "Fisierul selectat este un director");
            closedir(d);
            return;
        }

        DIR *d2;
        d2 = opendir(msg2);
        struct dirent *dir2;
        if(d2 == NULL)
        {
            printf("%s\n", "Path-ul introdus nu este valid");
            return;
        }

        while(dir2 = readdir(d2))
        {
            if(strcmp(dir2->d_name, msg) == 0)
            {
                printf("%s\n", "Exista deja un fisier cu acelasi nume in locatia selectata");
                closedir(d2);
                return;
            }
        }
        //incepe transferul

        FILE *f;
        f = fopen(local_path, "r");

        FILE *f2;
        f2 = fopen(local_path2, "w");

        if(f == NULL)
        {
            printf("%s\n", "Eroare la deschiderea fisierului introdus");
            return;
        }

        if(f2 == NULL)
        {
            printf("%s\n", "Eroare la crearea fisierului in path-ul introdus");
            return;
        }
        
        printf("Fisierul se transfera in background\n");
        int id;
        id = fork();
        if(id < 0)
        {
            printf("Eroare la transferul fisierului.\n");
            return;
        }
        if(id > 0)
        {
               return;//parinte 
        }
        else
        {
        long double sentdata = 1;
        while(1)
        {
            unsigned char data[1] = {0};
            int leng = 0;
            leng = fread(data, 1, 1, f);
            sentdata ++;           
            if(leng > 0)
            {
                
                fwrite(data, 1, leng, f2);
                continue;
            }
            if(leng == 0)
            {
                if(feof(f))
                {
                    printf("\n");
                    printf("%s\n", "Fisierul s-a terminat de transferat");
                    fclose(f);
                    fclose(f2);
                    remove(local_path);
                    break;
                }
                if(ferror(f) != 0)
                {
                    printf("%s\n", "Eroare la transferul fisierului");
                    fclose(f);
                    fclose(f2);
                    break;
                }
            }
        }
        closedir(d2);
    closedir(d);
    exit(1);
    }
}
}

int main()
{
    int clientSocket;
    struct sockaddr_in serverAddr;
    

    //creare socket
    if ((clientSocket = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      perror ("Eroare la socket().\n");
      return 0;
    }

    //umplere structura socket
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(2030);                   // portul si ip-ul se hardcodeaza
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

    //conectare server
    if (connect (clientSocket, (struct sockaddr *) &serverAddr, sizeof (struct sockaddr)) == -1)
    {
      perror ("[client]Eroare la connect().\n");
      return 0;
    }

    char username[100];
    char password[100];
    char command[30];
    char sresponse[1000];
    char msg[100];
    char msg2[100];
    char msg6[100];
    char msg7[100];
    int size;
    int logged = 0;
    int status;
    char local_path[1000];
    char allowed_commands[] = {"exit login disconnect list help crdir chdir mvfile deldir delfile renamefile  mvfile  location put get\0"};
    int blacklist = 0;
    char path[1000];
    getcwd(path, sizeof(path));
    path[strlen(path)] = '\0';     
    while(1)
    {
        
        printf("%s", "introduceti o comanda : ");
        memset(command, 0, strlen(command));        
        memset(sresponse, 0, strlen(sresponse));   
        scanf("%s", command);
        //fgets(command, sizeof(command), stdin);
        //command[strcspn(command, "\n")] = '\0';


        //ca sa nu cer comenzile disponibile de la server, ele sunt salvate si local
        if(strcmp(command, "help") == 0 && logged == 1)    
        {
            if(blacklist == 1)
                printf("%s\n", "Anumite comenzi sunt restrictionate, va rugam contactati administratorul.");
            printf("%s%s\n", "Comenzi disponibile : " , allowed_commands);
            continue;
        }

        if(strcmp(command, "list") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "disconnect") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "location") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "chdir") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "crdir") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "deldir") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "delfile") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "renamefile") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "put") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        if(strcmp(command, "get") == 0 && logged == 0)
        {
            printf("%s\n", "Trebuie sa fii logat pentru a folosi acesta comanda");
            continue;
        }

        //Comenzi pe partea de client
        if(strcmp(command, "clocation") == 0)
        {
            printf("%s\n", path);
            continue;
        }

        if(strcmp(command, "clist") == 0)
        {
            list(path);
            continue;
        }

        if(strcmp(command, "chelp") == 0)
        {
            printf("%s\n", "Comnenzi disponibile local : clocation clist chelp cchdir ccrdir cdelfile cdeldir crenamefile cmvfile");
            continue;
        }
        

        if(strcmp(command, "cchdir") == 0)
        {
            memset(msg, 0, strlen(msg));
            printf("%s\n", "Introduceti '..' pentru a merge la nivelul superior sau numele unui director pentru a se deschide.");
            scanf("%s", msg);
            change_directory(path, msg);
            continue;
        }

        if(strcmp(command, "ccrdir") == 0)
        {
            printf("%s", "Introduceti numele directorului ce urmeaza a fi creat : ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            create_directory(path, msg);
            continue;
        }

        if(strcmp(command, "cdelfile") == 0)
        {
            printf("%s", "Introduceti numele fisierului ce urmeaza a fi sters : ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            delete_file(path, msg);
            continue;
        }

        if(strcmp(command, "cdeldir") == 0)
        {   
            printf("%s", "Introduceti numele directorului ce urmeaza a fi sters : ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            delete_dir(path, msg);
            continue;
        }


        if(strcmp(command, "crenamefile") == 0)
        {
            printf("%s\n", "Introduceti numele fisierului ce urmeaza a fi redenumit: ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            printf("%s\n", "Introduceti noul nume al fisierului: ");
            memset(msg2, 0, strlen(msg2));
            scanf("%s", msg2);
            rename_file(path, msg, msg2);
            continue;
        }

        signal(SIGCHLD, handle);
        if(strcmp(command, "cmvfile") == 0)
        {
            printf("%s\n", "Introduceti numele fisierului ce urmeaza a fi mutat: ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            printf("%s\n", "Introduceti noua destinatie a fisierlui: ");
            memset(msg2, 0, strlen(msg2));
            scanf("%s", msg2);
            move_file(path, msg, msg2);
            continue;
        
        }

        if(strcmp(command, "login") == 0  && logged == 1)
        {
            printf("%s\n", "Sunteti deja logat");
            continue;
        }
 
        
        if(strstr(allowed_commands, command) == NULL && logged == 1)      
        {
            //printf("%s\n", "Nu aveti dreptul sa executati aceasta comanda");
            printf("%s\n", "Comanda necunoscuta, introduceti alta comanda");
            continue;
        }
    
       

        //comenzi catre server
        size = strlen(command) +1;  

        if (write (clientSocket, &size ,sizeof(int)) <= 0)
        {
        perror ("[client]Eroare la write() spre server.\n");
        return 0;
        }

        if( write(clientSocket, command, size)  <= 0 )
        {
            printf(" %s\n","Eroare la trimiterea comenzii catre server");
            return 0;
        }   

        
        if (read(clientSocket, &size, sizeof(int)) <= 0 )
            printf("%s\n", "Eroare la citire lungime raspuns");

        if(read(clientSocket, sresponse, size) <= 0 )
            printf("%s\n", "Eroare la citire raspuns");



        //Comenzi pe partea de server
        if(strcmp(sresponse, "disc") == 0)      
        {
            logged = 0;
            memset(username, 0, strlen(username));
            memset(password, 0, strlen(password));
            read(clientSocket, &size, sizeof(int));
            if(size == 1)
            {
                printf("%s\n", "Ai fost deconectat cu succes");
            }
            else
            {
                printf("%s\n", "Eroare la deconectare");
            }
            continue;
        }

        if(strcmp(sresponse, "help") == 0)     
        {
            memset(msg, 0, strlen(msg));
            read(clientSocket, &size, sizeof(int));
            read(clientSocket, msg,size);
            printf("%s%s\n", "Comenzi disponibile : ", msg);
            printf("%s\n", "De asemenea sunt disponibile si comenzi locale ce nu necesita logare. Folositi comanda chelp pentru a afla mai multe detalii.");
        }

        if(strcmp(sresponse, "list") == 0)      
        {
            memset(msg, 0, strlen(msg));
            read(clientSocket, &status, sizeof(int));


            if(status == 0)
            {
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, msg,size);
                continue;
            }
            long lsize;
            while(1)
            {
                memset(msg, 0, strlen(msg));
                read(clientSocket, &status, sizeof(int));
                if(status == 0)
                    break;

                memset(msg7, 0,strlen(msg7));
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, msg7, size);
                printf("%s", msg7);

                read(clientSocket, &lsize, sizeof(long));
                printf("%ld ", lsize);

                memset(msg7, 0,strlen(msg7));
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, msg7, size);
                printf("%s ", msg7);

                memset(msg6, 0,strlen(msg6));
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, msg6, size);
                printf("%s ", msg6);

                read(clientSocket, &size, sizeof(int));
                printf("%d ", size);

                memset(msg, 0, strlen(msg));
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, msg, size);
                printf("%s ", msg);

                memset(msg, 0, strlen(msg));
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, msg, size);
                if(status == 3)
                {
                    printf("%s%s%s%s\n",green, msg, reset, "  ");
                    continue;
                }

                if(status == 2)
                {
                    printf("%s%s%s%s\n",blue, msg, reset, "  ");
                    continue;
                }

                printf("%s%s%s%s\n",yellow, msg, reset, "  ");
            }
            continue;
        }
        
        if(strcmp(sresponse, "login") == 0)    
        {
            memset(sresponse, 0, strlen(sresponse));
            printf("%s", "Introduceti username : ");
            scanf("%s", username);
            size = strlen(username) +1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, username ,size);
            
            printf("%s", "Introduceti parola : ");
            scanf("%s", password);

            char enc_password[100]={0};
            AES_KEY enc_key, dec_key;
            AES_set_encrypt_key(key, 128, &enc_key);
            AES_encrypt(password, enc_password, &enc_key);     
            enc_password[strlen(enc_password) +1] = '\0';

            size = strlen(enc_password) +1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, enc_password, size);

            read(clientSocket, &size, sizeof(int));
            read(clientSocket, sresponse, size);

            if(strcmp(sresponse, "suc") == 0)
            {
                printf("%s\n", "Logarea a avut succes");
                read(clientSocket, &status, sizeof(int));
                blacklist = status;
                if(status == 1)
                {
                    printf("%s\n", "Anumite comenzi sunt restrictionate. Contactati administratorul pentru mai multe detalii.");
                }
                memset(sresponse, 0, strlen(sresponse));
                read(clientSocket, &size, sizeof(int));
                read(clientSocket, sresponse, size);
                strcpy(allowed_commands, sresponse);
                printf("%s%s\n", "Comenzi disponibile : ", sresponse);
                logged = 1;
                continue;
            }

            if(strcmp(sresponse, "fail") == 0)
            {
                printf("%s\n", "Logarea a esuat");
            }

            if(strcmp(sresponse, "fail2") == 0)
            {
                printf("%s\n", "Logarea a esuat, acest cont este deja logat pe o alta masina");
            }
            continue;
        }

        if(strcmp(sresponse, "location") == 0) 
        {
            memset(msg, 0, strlen(msg));
            memset(sresponse, 0, strlen(sresponse));
            read(clientSocket, &size, sizeof(int));
            read(clientSocket, msg, size);
            strncpy(sresponse, msg, strlen(msg)-1);
            printf("%s\n", sresponse);
            continue;
        }

        if(strcmp(sresponse, "crdir") == 0)  
        {
            printf("%s", "Introduceti numele directorului ce urmeaza a fi creat : ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            size = strlen(msg) + 1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);
            read(clientSocket, &size, sizeof(int)); 
            if(size == 0)
                printf("%s\n", "Directorul nu s-a putut crea");
            else
                printf("%s\n", "Directorul s-a creat cu succes");
        }

        if(strcmp(sresponse, "chdir") == 0)   
        {
            printf("%s\n", "Introduceti '..' pentru a merge la nivelul superior sau numele unui director pentru a se deschide.");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            size = strlen(msg) + 1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);
            memset(msg, 0, strlen(msg));
            read(clientSocket, &size, sizeof(int));
            read(clientSocket, msg, size);

           
            if(strcmp(msg, "MaxHeight") == 0)
                printf("%s\n", "Nu se poate trece la un nivel superior, radacina a fost atinsa");
            else
                if(strcmp(msg, "NuExista") == 0)
                    printf("%s\n", "Directorul selectat nu exista");
                else
                {
                    memset(sresponse, 0, strlen(sresponse));
                    strncpy(sresponse,msg,strlen(msg)-1);
                    printf("%s%s\n","Noua locatie este : " , sresponse);
                }
            continue;
        }                                      

        if(strcmp(sresponse, "delfile") == 0)   
        {
            printf("%s\n", "Introduceti numele fisierului ce urmeaza a fi sters : ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            size = strlen(msg) + 1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);
            read(clientSocket, &size, sizeof(int));
            if(size == 0)
                printf("%s\n", "Fisierul s-a sters cu succes");  
            else if (size == -1)
                printf("%s\n", "Fisierul nu s-a putut sterge");   
            continue;
        }

        if(strcmp(sresponse, "deldir") == 0)
        {
            memset(msg, 0, strlen(msg));
            printf("%s", "Introduceti numele directorului ce urmeaza a fi sters : ");
            scanf("%s", msg);
            size = strlen(msg);
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);
            read(clientSocket, &size, sizeof(int));
            if(size == 0)
                printf("%s\n", "Directorul s-a sters cu succes");  
            else
                printf("%s\n", "Directorul nu s-a putut sterge");  
        }

        if(strcmp(sresponse, "renamefile") == 0) 
        {
            memset(msg, 0, strlen(msg));
            memset(msg2, 0, strlen(msg2));
            printf("%s\n", "Introduceti numele fisierului ce va fi redenumit :");
            scanf("%s", msg);
            printf("%s\n", "Introduceti noul nume al fisierlui:");
            scanf("%s", msg2);
            size = strlen(msg) +1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);
            size = strlen(msg2) +1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg2, size);
            read(clientSocket, &size, sizeof(int));
            if(size == -1)
            {
                printf("%s\n", "Eroare la redenumire, fisierul introdus este un director");
                continue;
            }
            if(size == 0)
            {
                printf("%s\n", "Eroare la redenumirea fisierlui");
                continue;
            }
            if(size == 1)
            {
                printf("%s\n", "Fisierul a fost redenumit cu succes");
                continue;
            }
            continue;
        }

        if(strcmp(sresponse, "mvfile") == 0)
        {
            printf("%s\n", "Introduceti numele fisierului ce urmeaza a fi mutat: ");
            memset(msg, 0, strlen(msg));
            scanf("%s", msg);
            printf("%s\n", "Introduceti noua destinatie a fisierlui: ");
            memset(msg2, 0, strlen(msg2));
            scanf("%s", msg2);
            size = strlen(msg) + 1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);
            size = strlen(msg2) + 1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg2, size);

            read(clientSocket, &status, sizeof(int));
            if(status == 0)
            {
                printf("%s\n", "Fisierul dat nu exista in directorul curent.");
                continue;
            }
            if(status == -1)
            {
                printf("%s\n", "Destinatia introdusa nu este corecta.");
                continue;
            }
            if(status == -2)
            {
                printf("%s\n", "Un fisier cu acest nume exista deja la destinatia introdusa");
                continue;
            }
            if(status == -3)
            {
                printf("%s\n", "Fisierul introdus este un director");
                continue;
            }
            if(status == -4)
            {
                printf("%s\n", "Fisierul nu s-a putut transfera.");
                continue;
            }
            if(status == 1)
            {
                printf("%s\n", "Fisierul se transfera in background.");  
            }
            printf("%s\n", "Fisierul s-a terminat de transferat.");   //mesajul asta nu trebuie sa apara instant 
            continue;
        }
        
        if(strcmp(sresponse, "put") == 0)
        {
            memset(msg, 0, strlen(msg));
            printf("%s\n", "Introduceti numele fisierului din directorul curent ce doriti sa fie trimis catre server : ");
            scanf("%s", msg);
            size = strlen(msg)+1;
            status = 1;
            status = viable(path, msg);
            if(status == 0)
            {
                write(clientSocket, &status, sizeof(int));
                continue;
            }
            write(clientSocket, &status, sizeof(int));
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);
            read(clientSocket, &status, sizeof(int));
            if(status == 0)
            {

                printf("%s\n", "Exista deja un fisier cu acest nume pe server");
                continue;
            }
            
            //incepe transferul

            memset(local_path, 0, strlen(local_path));
            strcpy(local_path, path);
            strcat(local_path, "/");
            strcat(local_path, msg);
            FILE *f;
            f = fopen(local_path, "r");
            struct stat fstat;
            stat(local_path, &fstat);
            size = fstat.st_size;
        
            int leng;
            while(1)                            
            {
                unsigned char data[1] = {0};
                leng = 0;
                leng = fread(data, 1, 1, f);
                if(leng > 0)
                {
                    write(clientSocket, &leng, sizeof(int));
                    write(clientSocket, data, leng);
                    continue;
                }
                if(leng  == 0)
                {
                    if(feof(f))
                    {
                        printf("%s\n", "Transferul s-a efectuat cu succes");
                        leng = -1;
                        write(clientSocket, &leng, sizeof(int));
                        break;
                    }
                    if(ferror(f) != 0 )
                    {
                        printf("%s\n", "Eroare la citiread fisierlui");
                        leng = -1;
                        write(clientSocket, &leng, sizeof(int));
                        break;
                    }
                }
            }
            fclose(f);
            continue;
        }

        if(strcmp(sresponse, "get") == 0)
        {
            memset(msg, 0, strlen(msg));
            printf("%s\n", "Introduceti numele fisierului ce va fi luat de pe server: ");
            scanf("%s", msg);
            size = strlen(msg)+1;
            write(clientSocket, &size, sizeof(int));
            write(clientSocket, msg, size);

    
            status = 1;
            status = exists(path, msg);
            write(clientSocket, &status, sizeof(int));
            if(status == 0)
            {
                printf("%s\n", "Exista deja un fisier cu acelasi nume in directorul curent");;
                continue;
            }

            status = 1;
            read(clientSocket, &status, sizeof(int));
            if(status == 0)
            {
                printf("%s\n", "Fisierul cerut nu exista pe server");
                continue;
            }

            //incepe transferul
            memset(local_path, 0, strlen(local_path));
            strcpy(local_path, path);
            strcat(local_path, "/");
            strcat(local_path, msg);
            FILE *f;
            f = fopen(local_path, "w");
            status = 1;
            if(f ==  NULL)
            {
                printf("%s\n", "Eroare la crearea noului fisierului");
                status = 0;
            }

            write(clientSocket, &status, sizeof(int));
            if(status == 0)
                continue;

            while(1)
                {
                    unsigned char data[1] = {0};
                    int leng = 0;
                    read(clientSocket, &leng,  sizeof(int));
                    if(leng == -1)
                    {
                        printf("%s\n", "Fisierul a fost primit cu succes");
                        break;
                    }
                    if(leng == -2)
                    {
                        printf("%s\n", "Eroare la citirea fisierlui pe server");
                        break;
                    }

                    read(clientSocket, data, leng);
                    if(leng > 0)
                    {
                       fwrite(data, 1, leng, f);
                    }
                }
                fclose(f);
                continue;
        }

        if(strcmp(sresponse, "necunoscut") == 0) 
        {
            printf("%s\n", "Comanda necunoscuta, introduceti alta comanda");
            continue;
        }

        if(strcmp(sresponse, "exit") == 0) 
        {   
            close (clientSocket);
            return(0);
        }
    }
    close (clientSocket);
    return 0;
}