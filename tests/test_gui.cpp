#include "apgui.h"

#include <cassert>
#include <string>

int main() {
    using apgui::category;

    std::string startup = "{\n  \"ap\": {\n    \"state\": \"active\",\n"
                          "    \"mode\": \"guard\",\n    \"abi\": 2,\n"
                          "    \"caps\": 7\n  }\n}";
    apgui::message active = apgui::parse(startup);
    assert(active.kind == category::guard);
    assert(active.text.find("mode=guard") != std::string::npos);
    assert(active.text.find("caps=7") != std::string::npos);

    std::string stopped = "{\"ap\":{\"state\":\"stopped\",\"reason\":\"signal\","
                          "\"events\":12,\"findings\":3}}";
    apgui::message done = apgui::parse(stopped);
    assert(done.kind == category::guard);
    assert(done.text.find("reason=signal") != std::string::npos);

    std::string quiet = "{\"event\":{\"type\":\"exec\",\"action\":\"observed\",\"pid\":42}}";
    assert(apgui::parse(quiet).kind == category::ignored);

    std::string finding = "{\n  \"event\": {\n    \"type\": \"exec\",\n"
                          "    \"action\": \"investigating\",\n    \"pid\": 42,\n"
                          "    \"rules\": [\"file_write_burst\", \"destructive_chain\"]\n  }\n}";
    apgui::message event = apgui::parse(finding);
    assert(event.kind == category::event);
    assert(event.text.find("rules=file_write_burst,destructive_chain") != std::string::npos);

    std::string degraded = "{\"degraded\":{\"source\":\"lsm\",\"state\":\"unavailable\","
                           "\"reason\":\"bpf denied\"}}";
    apgui::message low = apgui::parse(degraded);
    assert(low.kind == category::degraded);
    assert(low.text.find("source=lsm") != std::string::npos);

    std::string summary = "{\"summary\":{\"events\":9,\"findings\":2,\"denials\":1,"
                          "\"detectors\":\"32/32\"}}";
    apgui::message total = apgui::parse(summary);
    assert(total.kind == category::guard);
    assert(total.text.find("detectors=32/32") != std::string::npos);

    std::string escaped = "{\"degraded\":{\"source\":\"a\\\"b\",\"state\":\"unavailable\"}}";
    assert(apgui::field(escaped, "source") == "a\"b");
    assert(apgui::label(escaped) == "degraded");
    assert(apgui::string_array(finding, "rules") == "file_write_burst,destructive_chain");
    return 0;
}
