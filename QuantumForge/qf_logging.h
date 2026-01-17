#ifndef QF_LOGGING_H
#define QF_LOGGING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#define PATH_SEP "\\"
#else
#include <unistd.h>
#define PATH_SEP "/"
#endif

typedef enum {
    LOG_LEVEL_TRACE,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_SUCCESS
} log_level_t;

typedef struct {
    char *log_dir;
    char *log_file;
    FILE *fp;
    int enabled;
    int first_entry;
    log_level_t min_level;
} qf_logger_t;

static qf_logger_t g_logger = {NULL, NULL, NULL, 0, 1, LOG_LEVEL_INFO};

static const char* log_level_str(log_level_t level) {
    switch(level) {
        case LOG_LEVEL_TRACE: return "TRACE";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO: return "INFO";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_SUCCESS: return "SUCCESS";
        default: return "UNKNOWN";
    }
}

static void qf_logger_set_level(log_level_t level) {
    g_logger.min_level = level;
}

static void get_timestamp(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, len, "%Y%m%d_%H%M%S", tm_info);
}

static void ensure_log_dir(const char *dir) {
    struct stat st = {0};
    if (stat(dir, &st) == -1) {
        mkdir(dir, 0700);
    }
}

static int qf_logger_init(const char *platform) {
    if (g_logger.enabled) return 0;
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
#ifdef _WIN32
    char *temp_dir = getenv("TEMP");
    if (!temp_dir) temp_dir = getenv("TMP");
    if (!temp_dir) temp_dir = "C:\\Temp";
    
    size_t dir_len = strlen(temp_dir) + 16;
    g_logger.log_dir = (char*)malloc(dir_len);
    snprintf(g_logger.log_dir, dir_len, "%s%sqf_logs", temp_dir, PATH_SEP);
#else
    g_logger.log_dir = strdup("/tmp/qf_logs");
#endif
    
    ensure_log_dir(g_logger.log_dir);
    
    size_t file_len = strlen(g_logger.log_dir) + 64;
    g_logger.log_file = (char*)malloc(file_len);
    snprintf(g_logger.log_file, file_len, "%s%s%s_%s.json", 
             g_logger.log_dir, PATH_SEP, timestamp, platform);
    
    g_logger.fp = fopen(g_logger.log_file, "w");
    if (!g_logger.fp) {
        return -1;
    }
    
    fprintf(g_logger.fp, "{\n  \"platform\": \"%s\",\n  \"timestamp\": \"%s\",\n  \"events\": [\n", 
            platform, timestamp);
    fflush(g_logger.fp);
    
    g_logger.enabled = 1;
    g_logger.first_entry = 1;
    
    return 0;
}

static void qf_log(log_level_t level, const char *module, const char *message, const char *details) {
    if (!g_logger.enabled || !g_logger.fp) return;
    if (level < g_logger.min_level) return;
    
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    if (!g_logger.first_entry) {
        fprintf(g_logger.fp, ",\n");
    }
    g_logger.first_entry = 0;
    
    fprintf(g_logger.fp, "    {\n");
    fprintf(g_logger.fp, "      \"timestamp\": \"%s\",\n", timestamp);
    fprintf(g_logger.fp, "      \"level\": \"%s\",\n", log_level_str(level));
    fprintf(g_logger.fp, "      \"module\": \"%s\",\n", module);
    fprintf(g_logger.fp, "      \"message\": \"%s\"", message);
    
    if (details) {
        fprintf(g_logger.fp, ",\n      \"details\": \"%s\"\n", details);
    } else {
        fprintf(g_logger.fp, "\n");
    }
    
    fprintf(g_logger.fp, "    }");
    fflush(g_logger.fp);
}

static void qf_logger_close(int exit_code) {
    if (!g_logger.enabled || !g_logger.fp) return;
    
    fprintf(g_logger.fp, "\n  ],\n");
    fprintf(g_logger.fp, "  \"exit_code\": %d,\n", exit_code);
    fprintf(g_logger.fp, "  \"result\": \"%s\"\n", exit_code == 0 ? "SUCCESS" : "FAILURE");
    fprintf(g_logger.fp, "}\n");
    
    fclose(g_logger.fp);
    g_logger.fp = NULL;
    g_logger.enabled = 0;
    
    if (g_logger.log_dir) free(g_logger.log_dir);
    if (g_logger.log_file) free(g_logger.log_file);
    g_logger.log_dir = NULL;
    g_logger.log_file = NULL;
}

static const char* qf_logger_get_path() {
    return g_logger.log_file;
}

#define QF_LOG_TRACE(module, msg, details) qf_log(LOG_LEVEL_TRACE, module, msg, details)
#define QF_LOG_DEBUG(module, msg, details) qf_log(LOG_LEVEL_DEBUG, module, msg, details)
#define QF_LOG_INFO(module, msg, details) qf_log(LOG_LEVEL_INFO, module, msg, details)
#define QF_LOG_WARN(module, msg, details) qf_log(LOG_LEVEL_WARNING, module, msg, details)
#define QF_LOG_ERROR(module, msg, details) qf_log(LOG_LEVEL_ERROR, module, msg, details)
#define QF_LOG_SUCCESS(module, msg, details) qf_log(LOG_LEVEL_SUCCESS, module, msg, details)

#endif
