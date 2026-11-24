#include "apgui.h"

#include <cctype>

namespace apgui {
namespace {

void skip_space(const std::string& text, size_t& at) {
    while (at < text.size() && std::isspace(static_cast<unsigned char>(text[at]))) {
        ++at;
    }
}

std::string quoted(const std::string& text, size_t& at) {
    std::string out;
    if (at >= text.size() || text[at] != '"') {
        return out;
    }
    ++at;
    while (at < text.size()) {
        char ch = text[at++];
        if (ch == '"') {
            break;
        }
        if (ch == '\\' && at < text.size()) {
            char next = text[at++];
            if (next == 'n' || next == 'r' || next == 't') {
                out.push_back(' ');
            } else {
                out.push_back(next);
            }
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string token(const std::string& text, size_t& at) {
    size_t start = at;
    while (at < text.size() && text[at] != ',' && text[at] != '}' &&
           text[at] != '\n' && text[at] != '\r') {
        ++at;
    }
    size_t end = at;
    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
        --end;
    }
    return text.substr(start, end - start);
}

size_t key_at(const std::string& text, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    return text.find(needle);
}

void add(std::string& out, const char* key, const std::string& value) {
    if (value.empty()) {
        return;
    }
    if (!out.empty()) {
        out.push_back(' ');
    }
    out += key;
    out.push_back('=');
    out += value;
}

}

std::string field(const std::string& block, const std::string& key) {
    size_t at = key_at(block, key);
    if (at == std::string::npos) {
        return std::string();
    }
    at += key.size() + 2;
    skip_space(block, at);
    if (at >= block.size() || block[at] != ':') {
        return std::string();
    }
    ++at;
    skip_space(block, at);
    if (at < block.size() && block[at] == '"') {
        return quoted(block, at);
    }
    return token(block, at);
}

std::string label(const std::string& block) {
    size_t at = block.find('{');
    if (at == std::string::npos) {
        return std::string();
    }
    ++at;
    skip_space(block, at);
    return quoted(block, at);
}

std::string string_array(const std::string& block, const std::string& key) {
    size_t at = key_at(block, key);
    if (at == std::string::npos) {
        return std::string();
    }
    at += key.size() + 2;
    skip_space(block, at);
    if (at >= block.size() || block[at] != ':') {
        return std::string();
    }
    ++at;
    skip_space(block, at);
    if (at >= block.size() || block[at] != '[') {
        return std::string();
    }
    ++at;
    std::string out;
    while (at < block.size()) {
        skip_space(block, at);
        if (at >= block.size() || block[at] == ']') {
            break;
        }
        if (block[at] == '"') {
            std::string value = quoted(block, at);
            if (!out.empty()) {
                out.push_back(',');
            }
            out += value;
        } else {
            ++at;
        }
    }
    return out;
}

message parse(const std::string& block) {
    message result;
    std::string name = label(block);
    std::string text;

    if (name == "ap") {
        std::string state = field(block, "state");
        if (state == "stopped") {
            add(text, "reason", field(block, "reason"));
            add(text, "events", field(block, "events"));
            add(text, "findings", field(block, "findings"));
            result.text = "ap stopped " + text;
        } else {
            add(text, "mode", field(block, "mode"));
            add(text, "caps", field(block, "caps"));
            result.text = "ap active " + text;
        }
        result.kind = category::guard;
        return result;
    }

    if (name == "enforcement") {
        add(text, "backend", field(block, "backend"));
        add(text, "lsm", field(block, "lsm"));
        add(text, "kernel", field(block, "kernel_compromise"));
        result.text = "guard " + text;
        result.kind = category::guard;
        return result;
    }

    if (name == "summary") {
        add(text, "events", field(block, "events"));
        add(text, "findings", field(block, "findings"));
        add(text, "denials", field(block, "denials"));
        add(text, "detectors", field(block, "detectors"));
        result.text = "summary " + text;
        result.kind = category::guard;
        return result;
    }

    if (name == "event") {
        std::string rules = string_array(block, "rules");
        if (rules.empty()) {
            rules = field(block, "rule");
        }
        std::string action = field(block, "action");
        if (rules.empty() && (action.empty() || action == "observed")) {
            return result;
        }
        add(text, "type", field(block, "type"));
        add(text, "pid", field(block, "pid"));
        add(text, "action", action);
        add(text, "rules", rules);
        result.text = "event " + text;
        result.kind = category::event;
        return result;
    }

    if (name == "degraded") {
        add(text, "source", field(block, "source"));
        add(text, "state", field(block, "state"));
        add(text, "reason", field(block, "reason"));
        result.text = "degraded " + text;
        result.kind = category::degraded;
        return result;
    }

    if (name == "stats") {
        add(text, "events", field(block, "events"));
        add(text, "findings", field(block, "findings"));
        add(text, "destructive", field(block, "destructive_findings"));
        add(text, "chain", field(block, "chain_findings"));
        result.text = "stats " + text;
        result.kind = category::stats;
        return result;
    }

    if (name == "proc") {
        add(text, "scans", field(block, "scans"));
        add(text, "file_events", field(block, "file_events"));
        add(text, "file_errors", field(block, "file_errors"));
        result.text = "proc " + text;
        result.kind = category::stats;
        return result;
    }

    if (name == "detectors") {
        add(text, "total", field(block, "total"));
        add(text, "enabled", field(block, "enabled"));
        result.text = "detectors " + text;
        result.kind = category::stats;
        return result;
    }

    if (name == "sources") {
        add(text, "trace", field(block, "trace"));
        add(text, "ipc", field(block, "ipc"));
        add(text, "proc", field(block, "proc"));
        add(text, "ksensor", field(block, "ksensor"));
        result.text = "sources " + text;
        result.kind = category::stats;
        return result;
    }

    if (name == "audit") {
        add(text, "integrity", field(block, "integrity"));
        add(text, "backend", field(block, "backend"));
        result.text = "audit " + text;
        result.kind = category::stats;
        return result;
    }

    if (name == "capture" || name == "kernel") {
        add(text, "state", field(block, "state"));
        add(text, "events", field(block, "events"));
        result.text = name + " " + text;
        result.kind = category::stats;
        return result;
    }

    return result;
}

}
