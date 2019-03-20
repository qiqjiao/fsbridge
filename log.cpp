#include "log.h"

#include <cassert>
#include <ctime>

std::mutex log_mutex;
std::ofstream log_fs;

void set_log_file(const char *log_file) {
    assert(log_file != NULL);
    log_fs.open(log_file, std::ios_base::app|std::ios_base::out);
    assert(log_fs.is_open());
}

const char* timestamp() {
    static char timestr[256];
    std::time_t t = std::time(nullptr);
    assert(std::strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S",
                         std::localtime(&t)) > 0);
    return timestr;
}
