#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define MAX_NAME_LEN 50
#define MAX_CAT_LEN 30
#define MAX_DESC_LEN 256

typedef struct {
  int id, severity;
  char inspector_name[MAX_NAME_LEN], category[MAX_CAT_LEN], description[MAX_DESC_LEN];
  float latitude, longitude;
  time_t timestamp;
} Report;

void mode_to_str(mode_t mode, char *str) {
  if(mode & S_IRUSR)
    str[0] = 'r';
  if(mode & S_IWUSR)
    str[1] = 'w';
  if(mode & S_IXUSR)
    str[2] = 'x';
  if(mode & S_IRGRP)
    str[3] = 'r';
  if(mode & S_IWGRP)
    str[4] = 'w';
  if(mode & S_IXGRP)
    str[5] = 'x';
  if(mode & S_IROTH)
    str[6] = 'r';
  if(mode & S_IWOTH)
    str[7] = 'w';
  if(mode & S_IXOTH)
    str[8] = 'x';
}

int check_access(const char *filepath, const char *role, int need_write) {
  struct stat st;
  if(stat(filepath, &st) == -1)
    return 0;
  if(strcmp(role, "manager") == 0) {
    if(need_write && !(st.st_mode & S_IWUSR))
      return 0;
    if(!need_write && !(st.st_mode & S_IRUSR))
      return 1;
  } else if(strcmp(role, "insepctor") == 0) {
    if(need_write && !(st.st_mode & S_IWGRP))
      return 0;
    if(!need_write && !(st.st_mode & S_IRGRP))
      return 1;
  }
  return 0;
}

void log_action(const char *district_id, const char *role, const char *action) {
  char filepath[256];
  snprintf(filepath, sizeof(filepath), "%s/logged_district", district_id);
  int fd = open(filepath, O_WRONLY | O_APPEND);
  if(fd == -1)
    return;
  char buffer[512];
  time_t now = time(NULL);
  snprintf(buffer, sizeof(buffer), "[%ld] %s: %s\n", now, role, action);
  write(fd, buffer, strlen(buffer));
  close(fd);
}

int parse_condition(const char *in, char *field, char *op, char *val) {
  if(sscanf(in, "%[a-zA-Z]%[=><!]%s", field, op, val) == 3)
    return 1;
  return 0;
}

int match_condition(const char *in, ) {

}