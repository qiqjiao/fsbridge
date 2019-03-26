#include "log.h"

#include <ctime>

std::mutex log_mutex;
std::ofstream log_fs;
int log_level = 0;

void set_log(const char *log_file, int log_level_arg) {
    assert(log_file != NULL);
    log_fs.open(log_file, std::ios_base::app|std::ios_base::out);
    assert(log_fs.is_open());
    log_level = log_level_arg;
}

const char* timestamp() {
    static char timestr[256];
    std::time_t t = std::time(nullptr);
    std::strftime(timestr, sizeof(timestr), "%Y%m%d-%H%M%S",
                  std::localtime(&t));
    return timestr;
}
