#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

char* GetCurrentDateTimeLogPrefix()
{
    struct timeval tv;
    struct tm* ptm;
    char* time_string = ( char* )malloc( 80 * sizeof( char ) );

    gettimeofday( &tv, NULL );
    ptm = localtime( &tv.tv_sec );
    strftime( time_string, 80, "[%Y-%m-%d %H:%M:%S] ", ptm );

    return time_string;
}

void WriteStarterLog( const char* msg )
{
    const char STARTER_LOG_FILE_PATH[] = "/var/log/saby/saby_pam_starter.log";

    const char SABY_LOG_DIR_PATH[] = "/var/log/saby";
    mkdir( SABY_LOG_DIR_PATH, 0777 );

    char* date_time_prefix = GetCurrentDateTimeLogPrefix();

    FILE* out = fopen( STARTER_LOG_FILE_PATH, "a" );
    if( out )
    {
        fprintf( out, "%s%s\n", date_time_prefix, msg );
        fclose( out );
    }

    free( date_time_prefix );
}

void WriteWorkerLog( const char* home_dir, const char* msg )
{
    const char WORKER_LOG_FILE_PATH_PART[] = "/.Sbis3Plugin/logs/pam_worker.log";

    char* date_time_prefix = GetCurrentDateTimeLogPrefix();

    char log_file_path[ 256 ];
    memcpy( log_file_path, home_dir, strlen( home_dir ) + 1 );
    strcat( log_file_path, WORKER_LOG_FILE_PATH_PART );

    FILE* out = fopen( log_file_path, "a" );
    if( out )
    {
        fprintf( out, "%s%s\n", date_time_prefix, msg );
        fclose( out );
    }

    free( date_time_prefix );
}

char* ExtractSurroundedSubstring( const char* input, int start_delimeter_num, int end_delimeter_num )
{
    int count = 0;
    int start = -1;
    int end = -1;

    int i = 0;
    while( i < strlen( input ) )
    {
        if( input[ i ] == ':' )
        {
            ++count;
            if( count == start_delimeter_num )
            {
                start = i + 1;
            }
            else if( count == end_delimeter_num )
            {
                end = i;
                break;
            }
        }
        ++i;
    }
    if( start != -1 && end != -1 )
    {
        int length = end - start;
        char* result = ( char* )malloc( length + 1 );
        strncpy( result, input + start, length );
        result[ length ] = '\0';
        return result;
    }
    else
    {
        return NULL;
    }
}

char* FindSubstringInFile( const char* filename, const char* substring )
{
    FILE* file = fopen( filename, "r" );
    if( file == NULL )
    {
        return NULL;
    }

    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    while( ( read = getline( &line, &len, file ) ) != -1 )
    {
        if( strncmp( line, substring, strlen( substring ) ) == 0 )
        {
            fclose( file );
            return line;
        }
    }

    fclose( file );
    return NULL;
}

void GetUserInfoFromString( const char* user_name, int* user_id, int* group_id, char** home_dir )
{
    char* user_info_string = FindSubstringInFile( "/etc/passwd", user_name );

    char* user_id_str = ExtractSurroundedSubstring( user_info_string, 2, 3 );
    char* group_id_str = ExtractSurroundedSubstring( user_info_string, 3, 4 );
    *home_dir = ExtractSurroundedSubstring( user_info_string, 5, 6 );

    *user_id = atoi( user_id_str );
    *group_id = atoi( group_id_str );

    free( user_info_string );
    free( user_id_str );
    free( group_id_str );
}

void SplitEnvString( char* str, char** name, char** value )
{
    const char* delimiter = "=";
    char* token = strtok( str, delimiter );
    if( token != NULL )
    {
        *name = ( char* )malloc( strlen( token ) + 1 );
        strcpy( *name, token );
        token = strtok( NULL, delimiter );
        if( token != NULL )
        {
            *value = ( char* )malloc( strlen( token ) + 1 );
            strcpy( *value, token );
        }
    }
}

void RunPluginByFileData( const char* home_dir, const char* file_path )
{
    FILE* file = fopen( file_path, "r" );

    char* cmd_line = NULL;
    char* env_line = NULL;
    size_t len = 0;
    ssize_t read;

    read = getline( &cmd_line, &len, file );
    if( -1 == read )
    {
        WriteWorkerLog( home_dir, "[ProcessPluginDataFile] getline for cmd_line failed" );
        return;
    }

    clearenv();

    while( ( read = getline( &env_line, &len, file ) ) != -1 )
    {
        char* env_name = NULL;
        char* env_value = NULL;

        SplitEnvString( env_line, &env_name, &env_value );

        int pos = strcspn( env_value, "\r\n" );
        env_value[ pos ] = '\0';

        if( NULL != env_name && NULL != env_value )
        {
            setenv( env_name, env_value, 1 );
            free( env_name );
            free( env_value );
        }
        free( env_line );
        env_line = NULL;
    }

    fclose( file );

    int pos = strcspn( cmd_line, "\r\n" );
    cmd_line[ pos ] = '\0';

    char nohup_start[] = "nohup ";
    char nohup_end[] = " &";

    char final_cmd[ 256 ];

    memcpy( final_cmd, nohup_start, strlen( nohup_start ) + 1 );
    strcat( final_cmd, "/opt/sbis3plugin/sbis3plugin " );
    strcat( final_cmd, cmd_line );
    strcat( final_cmd, nohup_end );

    free( cmd_line );

    WriteWorkerLog( home_dir, final_cmd );

    system( final_cmd );
}

PAM_EXTERN int pam_sm_open_session( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
   (void)pamh;
   (void)flags;
   (void)argc;
   (void)argv;

   WriteStarterLog( "===========START===========" );

   const char* user;

   int ret = pam_get_user( pamh, &user, NULL );
   if( ret != PAM_SUCCESS || user == NULL )
   {
       WriteStarterLog( "pam_get_user failed" );
       return PAM_SUCCESS;
   }

   int user_id = 0;
   int user_group_id = 0;
   char* home_dir = NULL;
   GetUserInfoFromString( user, &user_id, &user_group_id, &home_dir );

   if( user_id <= 0 || user_group_id <= 0 )
   {
       WriteStarterLog( "User ids not found" );
       return PAM_SUCCESS;
   }

   if( NULL == home_dir || 0 >= strlen( home_dir ) )
   {
       WriteStarterLog( "User home_dir not found" );
       return PAM_SUCCESS;
   }

   WriteStarterLog( home_dir );

   auto pid = fork();

   if( 0 == pid )
   {
      setuid( user_id );
      setgid( user_group_id );

      WriteWorkerLog( home_dir, "===========START===========" );

      const char SBIS_USER_DIR[] = "/.Sbis3Plugin/";
      const char FIFO_FILE_NAME[] = "PamBrokerInput";

      char fifo_file_path[ 256 ];
      memcpy( fifo_file_path, home_dir, strlen( home_dir ) + 1 );
      strcat( fifo_file_path, SBIS_USER_DIR );
      strcat( fifo_file_path, FIFO_FILE_NAME );

      WriteWorkerLog( home_dir, fifo_file_path );

      remove( fifo_file_path );
      if( 0 != mkfifo( fifo_file_path, 0666 ) )
      {
          WriteWorkerLog( home_dir, "FIFO create failed" );
          return PAM_SUCCESS;
      }

      //Открываем имено на чтение и запись сразу. Иначе первый обработанный клиент сломает дальнейшую работу, т.к. сервер прочитает EOF.
      //Немного подробнее описано тут
      //https://stackoverflow.com/questions/23498654/read-from-a-named-pipe
      int fifo_file = open( fifo_file_path, O_RDWR );
      if( 0 > fifo_file )
      {
          WriteWorkerLog( home_dir, "FIFO open failed" );
          return PAM_SUCCESS;
      }

      while( 1 )
      {
          const int INPUT_FILE_SIZE = 8;
          char file_name[ INPUT_FILE_SIZE + 1 ];
          file_name[ INPUT_FILE_SIZE ] = '\0';

          if( INPUT_FILE_SIZE != read( fifo_file, file_name, INPUT_FILE_SIZE ) )
          {
              WriteWorkerLog( home_dir, "FIFO read incorrect" );
              sleep( 1 );
              continue;
          }

          WriteWorkerLog( home_dir, "FIFO input found" );
          WriteWorkerLog( home_dir, file_name );

          char file_path[ 256 ];
          memcpy( file_path, home_dir, strlen( home_dir ) + 1 );
          strcat( file_path, SBIS_USER_DIR );
          strcat( file_path, file_name );

          WriteWorkerLog( home_dir, file_path );

          FILE *file_test = fopen( file_path, "r" );

          if( file_test != NULL )
          {
              WriteWorkerLog( home_dir, "file found" );
              fclose( file_test );

              RunPluginByFileData( home_dir, file_path );

              remove( file_path );
          }
          else
          {
              WriteWorkerLog( home_dir, "file not found" );
              sleep( 1 );
          }
      }
   }

   free( home_dir );

   return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
   (void)pamh;
   (void)flags;
   (void)argc;
   (void)argv;

   return PAM_SUCCESS;
}
