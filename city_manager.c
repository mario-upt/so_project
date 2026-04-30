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
    int id;
    char inspector_name[MAX_NAME_LEN];
    float latitude;
    float longitude;
    char category[MAX_CAT_LEN];
    int severity;
    time_t timestamp;
    char description[MAX_DESC_LEN];
} Report;

void mode_to_str(mode_t mode, char *str) {
    strcpy(str, "---------");
    if (mode & S_IRUSR) str[0] = 'r';
    if (mode & S_IWUSR) str[1] = 'w';
    if (mode & S_IXUSR) str[2] = 'x';
    if (mode & S_IRGRP) str[3] = 'r';
    if (mode & S_IWGRP) str[4] = 'w';
    if (mode & S_IXGRP) str[5] = 'x';
    if (mode & S_IROTH) str[6] = 'r';
    if (mode & S_IWOTH) str[7] = 'w';
    if (mode & S_IXOTH) str[8] = 'x';
}

int check_access(const char *filepath, const char *role, int need_write) {
    struct stat st;
    if (stat(filepath, &st) == -1) return 0;

    if (strcmp(role, "manager") == 0) {
        if (need_write && !(st.st_mode & S_IWUSR)) return 0;
        if (!need_write && !(st.st_mode & S_IRUSR)) return 0;
        return 1;
    } else if (strcmp(role, "inspector") == 0) {
        if (need_write && !(st.st_mode & S_IWGRP)) return 0;
        if (!need_write && !(st.st_mode & S_IRGRP)) return 0;
        return 1;
    }
    return 0;
}

void log_action(const char *district_id, const char *role, const char *action) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/logged_district", district_id);

    int fd = open(filepath, O_WRONLY | O_APPEND);
    if (fd == -1) return;

    char buffer[512];
    time_t now = time(NULL);
    snprintf(buffer, sizeof(buffer), "[%ld] %s: %s\n", now, role, action);
    write(fd, buffer, strlen(buffer));
    close(fd);
}

int parse_condition(const char *input, char *field, char *op, char *value) {
    if (sscanf(input, "%[a-zA-Z_]%[=><!]%s", field, op, value) == 3) return 1;
    return 0;
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {
    if (strcmp(field, "severity") == 0) {
        int val = atoi(value);
        if (strcmp(op, "==") == 0) return r->severity == val;
        if (strcmp(op, ">") == 0) return r->severity > val;
        if (strcmp(op, "<") == 0) return r->severity < val;
    } else if (strcmp(field, "category") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->category, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->category, value) != 0;
    } else if (strcmp(field, "inspector_name") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->inspector_name, value) == 0;
    }
    return 0;
}

void init_district(const char *district_id) {
    mkdir(district_id, 0750);
    char filepath[256];

    snprintf(filepath, sizeof(filepath), "%s/reports.dat", district_id);
    int fd = open(filepath, O_CREAT | O_RDWR, 0664);
    if (fd != -1) { fchmod(fd, 0664); close(fd); }

    snprintf(filepath, sizeof(filepath), "%s/district.cfg", district_id);
    fd = open(filepath, O_CREAT | O_RDWR, 0640);
    if (fd != -1) { fchmod(fd, 0640); close(fd); }

    snprintf(filepath, sizeof(filepath), "%s/logged_district", district_id);
    fd = open(filepath, O_CREAT | O_RDWR, 0644);
    if (fd != -1) { fchmod(fd, 0644); close(fd); }

    char symlink_name[256];
    snprintf(symlink_name, sizeof(symlink_name), "active_reports-%s", district_id);
    struct stat lst;
    if (lstat(symlink_name, &lst) == -1) {
        symlink(filepath, symlink_name);
    }
}

void cmd_add(const char *district_id, const char *role, const char *user) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", district_id);

    if (!check_access(filepath, role, 1)) {
        return;
    }

    Report r;
    memset(&r, 0, sizeof(Report));
    r.id = rand() % 10000;
    strncpy(r.inspector_name, user, MAX_NAME_LEN - 1);
    r.latitude = 45.0;
    r.longitude = 26.0;
    strcpy(r.category, "road");
    r.severity = 2;
    r.timestamp = time(NULL);
    strcpy(r.description, "Issue reported.");

    int fd = open(filepath, O_WRONLY | O_APPEND);
    if (fd != -1) {
        write(fd, &r, sizeof(Report));
        close(fd);
        log_action(district_id, role, "add report");
    }
}

void cmd_list(const char *district_id, const char *role) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", district_id);

    if (!check_access(filepath, role, 0)) {
        return;
    }

    struct stat st;
    if (stat(filepath, &st) == 0) {
        char perms[10];
        mode_to_str(st.st_mode, perms);
        printf("Size: %ld bytes, Mod Time: %ld, Perms: %s\n", st.st_size, st.st_mtime, perms);
    }

    int fd = open(filepath, O_RDONLY);
    if (fd != -1) {
        Report r;
        while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
            printf("ID: %d | Inspector: %s | Cat: %s | Sev: %d\n", r.id, r.inspector_name, r.category, r.severity);
        }
        close(fd);
        log_action(district_id, role, "list reports");
    }
}

void cmd_view(const char *district_id, const char *role, int report_id) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", district_id);

    if (!check_access(filepath, role, 0)) return;

    int fd = open(filepath, O_RDONLY);
    if (fd != -1) {
        Report r;
        while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
            if (r.id == report_id) {
                printf("ID: %d\nInspector: %s\nCoords: %f, %f\nCategory: %s\nSeverity: %d\nDesc: %s\n",
                       r.id, r.inspector_name, r.latitude, r.longitude, r.category, r.severity, r.description);
                break;
            }
        }
        close(fd);
        log_action(district_id, role, "view report");
    }
}

void cmd_remove_report(const char *district_id, const char *role, int report_id) {
    if (strcmp(role, "manager") != 0) return;

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", district_id);

    int fd = open(filepath, O_RDWR);
    if (fd == -1) return;

    Report r;
    off_t pos_to_overwrite = -1;
    off_t current_pos = 0;

    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        if (r.id == report_id && pos_to_overwrite == -1) {
            pos_to_overwrite = current_pos;
        } else if (pos_to_overwrite != -1) {
            lseek(fd, pos_to_overwrite, SEEK_SET);
            write(fd, &r, sizeof(Report));
            pos_to_overwrite += sizeof(Report);
            lseek(fd, current_pos + sizeof(Report), SEEK_SET);
        }
        current_pos += sizeof(Report);
    }

    if (pos_to_overwrite != -1) {
        ftruncate(fd, pos_to_overwrite);
        log_action(district_id, role, "remove report");
    }
    close(fd);
}

void cmd_update_threshold(const char *district_id, const char *role, int new_value) {
    if (strcmp(role, "manager") != 0) return;

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/district.cfg", district_id);

    struct stat st;
    if (stat(filepath, &st) == 0) {
        if ((st.st_mode & 0777) != 0640) {
            return;
        }
    }

    int fd = open(filepath, O_WRONLY | O_TRUNC);
    if (fd != -1) {
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "severity_threshold=%d\n", new_value);
        write(fd, buffer, strlen(buffer));
        close(fd);
        log_action(district_id, role, "update threshold");
    }
}

void cmd_filter(const char *district_id, const char *role, int filter_argc, char *filter_argv[]) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", district_id);

    if (!check_access(filepath, role, 0)) return;

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) return;

    Report r;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        int match_all = 1;
        for (int i = 0; i < filter_argc; i++) {
            char field[32], op[4], value[64];
            if (parse_condition(filter_argv[i], field, op, value)) {
                if (!match_condition(&r, field, op, value)) {
                    match_all = 0;
                    break;
                }
            }
        }
        if (match_all) {
            printf("ID: %d | Inspector: %s | Cat: %s | Sev: %d\n", r.id, r.inspector_name, r.category, r.severity);
        }
    }
    close(fd);
    log_action(district_id, role, "filter reports");
}

int main(int argc, char *argv[]) {
    srand(time(NULL));

    if (argc < 6) return 1;

    char *role = NULL;
    char *user = NULL;
    char *command = NULL;
    char *district_id = NULL;

    for (int i = 1; i < 5; i += 2) {
        if (strcmp(argv[i], "--role") == 0) {
            role = argv[i+1];
        } else if (strcmp(argv[i], "--user") == 0) {
            user = argv[i+1];
        }
    }

    if (!role || !user) return 1;

    command = argv[5];
    if (argc > 6) {
        district_id = argv[6];
    }

    if (strcmp(command, "add") == 0 && district_id) {
        init_district(district_id);
        cmd_add(district_id, role, user);
    }
    else if (strcmp(command, "list") == 0 && district_id) {
        cmd_list(district_id, role);
    }
    else if (strcmp(command, "view") == 0 && district_id && argc >= 8) {
        int report_id = atoi(argv[7]);
        cmd_view(district_id, role, report_id);
    }
    else if (strcmp(command, "remove_report") == 0 && district_id && argc >= 8) {
        int report_id = atoi(argv[7]);
        cmd_remove_report(district_id, role, report_id);
    }
    else if (strcmp(command, "update_threshold") == 0 && district_id && argc >= 8) {
        int new_value = atoi(argv[7]);
        cmd_update_threshold(district_id, role, new_value);
    }
    else if (strcmp(command, "filter") == 0 && district_id && argc >= 8) {
        cmd_filter(district_id, role, argc - 7, &argv[7]);
    }

    return 0;
}
