#ifndef APGUI_H
#define APGUI_H

#include <string>

namespace apgui {

enum class category {
    ignored,
    guard,
    event,
    stats,
    degraded,
    error,
};

struct message {
    category kind = category::ignored;
    std::string text;
};

std::string field(const std::string& block, const std::string& key);
std::string label(const std::string& block);
std::string string_array(const std::string& block, const std::string& key);
message parse(const std::string& block);

}

#endif
