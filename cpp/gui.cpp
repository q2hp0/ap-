#include "apgui.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

const int kWidth = 920;
const int kHeight = 620;
const int kMargin = 24;
const int kButtonHeight = 34;
const size_t kMaxRows = 240;

enum class button_id {
    events,
    guard,
    stats,
    degraded,
    pause,
    clear,
    quit,
};

struct button {
    button_id id;
    std::string label;
    int x;
    int y;
    int w;
    int h;
};

struct row {
    apgui::category kind;
    std::string text;
};

struct state {
    Display* display = nullptr;
    Window window = 0;
    GC gc = nullptr;
    XFontStruct* font = nullptr;
    std::vector<row> rows;
    bool show_events = true;
    bool show_guard = true;
    bool show_stats = false;
    bool show_degraded = false;
    bool paused = false;
    bool running = true;
    bool dirty = true;
    int child_fd = -1;
    pid_t child_pid = -1;
    std::string pending;
};

void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

bool spawn_child(state& app, int argc, char** argv) {
    int pipes[2];
    if (pipe(pipes) != 0) {
        return false;
    }
    set_nonblock(pipes[0]);
    pid_t pid = fork();
    if (pid < 0) {
        close(pipes[0]);
        close(pipes[1]);
        return false;
    }
    if (pid == 0) {
        close(pipes[0]);
        dup2(pipes[1], STDOUT_FILENO);
        dup2(pipes[1], STDERR_FILENO);
        close(pipes[1]);

        std::vector<std::string> owned;
        owned.push_back("--json");
        if (argc <= 1) {
            const char* defaults[] = {
                "--guard", "--deny", "wx_transition",
                "--stop", "file_write_burst,destructive_chain,data_exfiltration",
                "--chain-guard", "--threshold", "10",
                "--kernel-sensor", "--lsm-enforce",
                "--socket", "/tmp/ap-gui.sock",
                "--store", "ap-gui.jsonl",
                "--trace", "/bin/tail", "-f", "/dev/null",
            };
            for (const char* value : defaults) {
                owned.push_back(value);
            }
        } else {
            for (int index = 1; index < argc; ++index) {
                owned.push_back(argv[index]);
            }
        }

        std::vector<char*> args;
        args.push_back(const_cast<char*>("./out/ap"));
        for (std::string& value : owned) {
            args.push_back(const_cast<char*>(value.c_str()));
        }
        args.push_back(nullptr);
        execvp("./out/ap", args.data());
        _exit(127);
    }

    close(pipes[1]);
    app.child_fd = pipes[0];
    app.child_pid = pid;
    return true;
}

bool enabled(const state& app, apgui::category kind) {
    switch (kind) {
        case apgui::category::guard:
            return app.show_guard;
        case apgui::category::event:
            return app.show_events;
        case apgui::category::stats:
            return app.show_stats;
        case apgui::category::degraded:
        case apgui::category::error:
            return app.show_degraded;
        default:
            return false;
    }
}

void append(state& app, apgui::category kind, const std::string& text) {
    if (kind == apgui::category::ignored || text.empty()) {
        return;
    }
    if (app.rows.size() == kMaxRows) {
        app.rows.erase(app.rows.begin());
    }
    app.rows.push_back({kind, text});
    if (!app.paused) {
        app.dirty = true;
    }
}

void append(state& app, const apgui::message& value) {
    append(app, value.kind, value.text);
}

void handle_block(state& app, const std::string& block) {
    append(app, apgui::parse(block));
}

void process_pending(state& app) {
    while (true) {
        size_t first = app.pending.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) {
            app.pending.clear();
            return;
        }
        if (first > 0) {
            app.pending.erase(0, first);
        }
        if (app.pending[0] != '{') {
            size_t end = app.pending.find('\n');
            if (end == std::string::npos) {
                return;
            }
            std::string line = app.pending.substr(0, end);
            app.pending.erase(0, end + 1);
            append(app, apgui::category::error, "error " + line);
            continue;
        }

        bool consumed = false;
        bool in_string = false;
        bool escaped = false;
        size_t start = std::string::npos;
        size_t depth = 0;
        for (size_t index = 0; index < app.pending.size(); ++index) {
            char ch = app.pending[index];
            if (in_string) {
                if (escaped) {
                    escaped = false;
                } else if (ch == '\\') {
                    escaped = true;
                } else if (ch == '"') {
                    in_string = false;
                }
                continue;
            }
            if (ch == '"') {
                in_string = true;
            } else if (ch == '{') {
                if (depth == 0) {
                    start = index;
                }
                ++depth;
            } else if (ch == '}' && depth > 0) {
                --depth;
                if (depth == 0 && start != std::string::npos) {
                    std::string block = app.pending.substr(start, index - start + 1);
                    app.pending.erase(0, index + 1);
                    handle_block(app, block);
                    consumed = true;
                    break;
                }
            }
        }
        if (!consumed) {
            return;
        }
    }
}

void read_child(state& app) {
    char buffer[4096];
    while (true) {
        ssize_t count = read(app.child_fd, buffer, sizeof(buffer));
        if (count > 0) {
            app.pending.append(buffer, static_cast<size_t>(count));
            process_pending(app);
            continue;
        }
        if (count == 0) {
            close(app.child_fd);
            app.child_fd = -1;
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        return;
    }
}

void wait_child(state& app) {
    if (app.child_pid <= 0) {
        return;
    }
    int status = 0;
    pid_t done = waitpid(app.child_pid, &status, WNOHANG);
    if (done != app.child_pid) {
        return;
    }
    int code = 0;
    if (WIFEXITED(status)) {
        code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        code = 128 + WTERMSIG(status);
    }
    append(app, apgui::category::guard, "ap exited code=" + std::to_string(code));
    app.child_pid = -1;
}

std::vector<button> make_buttons(int area_x, int area_w) {
    const char* names[] = {"events", "guard", "stats", "degraded", "pause", "clear", "quit"};
    const button_id ids[] = {
        button_id::events, button_id::guard, button_id::stats, button_id::degraded,
        button_id::pause, button_id::clear, button_id::quit,
    };
    const size_t count = sizeof(names) / sizeof(names[0]);
    const int gap = 8;
    int width = (area_w - gap * static_cast<int>(count - 1)) / static_cast<int>(count);
    int y = kHeight - kMargin - kButtonHeight;
    std::vector<button> result;
    for (size_t index = 0; index < count; ++index) {
        result.push_back({
            ids[index], names[index],
            area_x + static_cast<int>(index) * (width + gap),
            y, width, kButtonHeight,
        });
    }
    return result;
}

bool button_active(const state& app, button_id id) {
    switch (id) {
        case button_id::events:
            return app.show_events;
        case button_id::guard:
            return app.show_guard;
        case button_id::stats:
            return app.show_stats;
        case button_id::degraded:
            return app.show_degraded;
        case button_id::pause:
            return app.paused;
        default:
            return false;
    }
}

std::string fit(const state& app, const std::string& text, int max_width) {
    std::string out = text;
    while (!out.empty() && XTextWidth(app.font, out.c_str(), static_cast<int>(out.size())) > max_width) {
        out.pop_back();
    }
    return out;
}

void draw(state& app) {
    Display* display = app.display;
    int screen = DefaultScreen(display);
    XSetForeground(display, app.gc, WhitePixel(display, screen));
    XFillRectangle(display, app.window, app.gc, 0, 0, kWidth, kHeight);

    int area_x = kMargin;
    int area_y = kMargin;
    int area_w = kWidth - 2 * kMargin;
    int area_h = kHeight - 2 * kMargin - kButtonHeight - 12;
    XSetForeground(display, app.gc, BlackPixel(display, screen));
    XFillRectangle(display, app.window, app.gc, area_x, area_y, area_w, area_h);

    std::vector<const row*> shown;
    for (const row& item : app.rows) {
        if (enabled(app, item.kind)) {
            shown.push_back(&item);
        }
    }
    int line_h = app.font->ascent + app.font->descent + 4;
    int max_lines = area_h / line_h;
    if (max_lines > 0 && !shown.empty()) {
        size_t start = shown.size() > static_cast<size_t>(max_lines)
            ? shown.size() - static_cast<size_t>(max_lines) : 0;
        XSetForeground(display, app.gc, WhitePixel(display, screen));
        int line = 0;
        for (size_t index = start; index < shown.size(); ++index) {
            int y = area_y + app.font->ascent + 3 + line * line_h;
            if (y > area_y + area_h - app.font->descent) {
                break;
            }
            std::string text = fit(app, shown[index]->text, area_w - 16);
            XDrawImageString(display, app.window, app.gc, area_x + 8, y,
                             text.c_str(), static_cast<int>(text.size()));
            ++line;
        }
    }

    std::vector<button> buttons = make_buttons(area_x, area_w);
    for (const button& item : buttons) {
        bool active = button_active(app, item.id);
        XSetForeground(display, app.gc, active ? BlackPixel(display, screen)
                                               : WhitePixel(display, screen));
        XFillRectangle(display, app.window, app.gc, item.x, item.y, item.w, item.h);
        XSetForeground(display, app.gc, BlackPixel(display, screen));
        XDrawRectangle(display, app.window, app.gc, item.x, item.y, item.w, item.h);
        XSetForeground(display, app.gc, active ? WhitePixel(display, screen)
                                               : BlackPixel(display, screen));
        int text_w = XTextWidth(app.font, item.label.c_str(), static_cast<int>(item.label.size()));
        int text_x = item.x + (item.w - text_w) / 2;
        int text_y = item.y + app.font->ascent + (item.h - app.font->ascent - app.font->descent) / 2;
        XDrawImageString(display, app.window, app.gc, text_x, text_y,
                         item.label.c_str(), static_cast<int>(item.label.size()));
    }
    XFlush(display);
    app.dirty = false;
}

void activate(state& app, button_id id) {
    switch (id) {
        case button_id::events:
            app.show_events = !app.show_events;
            break;
        case button_id::guard:
            app.show_guard = !app.show_guard;
            break;
        case button_id::stats:
            app.show_stats = !app.show_stats;
            break;
        case button_id::degraded:
            app.show_degraded = !app.show_degraded;
            break;
        case button_id::pause:
            app.paused = !app.paused;
            break;
        case button_id::clear:
            app.rows.clear();
            break;
        case button_id::quit:
            app.running = false;
            break;
    }
    app.dirty = true;
}

void click(state& app, int x, int y) {
    std::vector<button> buttons = make_buttons(kMargin, kWidth - 2 * kMargin);
    for (const button& item : buttons) {
        if (x >= item.x && x < item.x + item.w && y >= item.y && y < item.y + item.h) {
            activate(app, item.id);
            return;
        }
    }
}

void key(state& app, XKeyEvent& event) {
    char text[32] = {0};
    XLookupString(&event, text, sizeof(text), nullptr, nullptr);
    switch (text[0]) {
        case '1':
            activate(app, button_id::events);
            break;
        case '2':
            activate(app, button_id::guard);
            break;
        case '3':
            activate(app, button_id::stats);
            break;
        case '4':
            activate(app, button_id::degraded);
            break;
        case 'c':
            activate(app, button_id::clear);
            break;
        case 'q':
            activate(app, button_id::quit);
            break;
        default:
            break;
    }
}

void cleanup(state& app) {
    if (app.child_pid > 0) {
        kill(app.child_pid, SIGTERM);
        waitpid(app.child_pid, nullptr, 0);
        app.child_pid = -1;
    }
    if (app.child_fd >= 0) {
        close(app.child_fd);
        app.child_fd = -1;
    }
    if (app.font != nullptr) {
        XFreeFont(app.display, app.font);
        app.font = nullptr;
    }
    if (app.gc != nullptr) {
        XFreeGC(app.display, app.gc);
        app.gc = nullptr;
    }
    if (app.window != 0) {
        XDestroyWindow(app.display, app.window);
        app.window = 0;
    }
    if (app.display != nullptr) {
        XCloseDisplay(app.display);
        app.display = nullptr;
    }
}

}

int main(int argc, char** argv) {
    state app;
    app.display = XOpenDisplay(nullptr);
    if (app.display == nullptr) {
        std::fprintf(stderr, "apgui: display unavailable\n");
        return 1;
    }
    int screen = DefaultScreen(app.display);
    int x = (DisplayWidth(app.display, screen) - kWidth) / 2;
    int y = (DisplayHeight(app.display, screen) - kHeight) / 2;
    XSetWindowAttributes attrs;
    attrs.background_pixel = WhitePixel(app.display, screen);
    attrs.border_pixel = BlackPixel(app.display, screen);
    attrs.override_redirect = True;
    app.window = XCreateWindow(app.display, DefaultRootWindow(app.display),
                               x, y, kWidth, kHeight, 0, CopyFromParent,
                               InputOutput, CopyFromParent,
                               CWBackPixel | CWBorderPixel | CWOverrideRedirect,
                               &attrs);
    XStoreName(app.display, app.window, "ap");
    XSelectInput(app.display, app.window,
                 ExposureMask | ButtonPressMask | KeyPressMask | StructureNotifyMask);
    XMapRaised(app.display, app.window);
    XFlush(app.display);
    app.gc = XCreateGC(app.display, app.window, 0, nullptr);
    app.font = XLoadQueryFont(app.display, "fixed");
    if (app.font == nullptr) {
        app.font = XLoadQueryFont(app.display, "monospace");
    }
    if (app.gc == nullptr || app.font == nullptr) {
        std::fprintf(stderr, "apgui: font or graphics context unavailable\n");
        cleanup(app);
        return 1;
    }

    if (!spawn_child(app, argc, argv)) {
        std::fprintf(stderr, "apgui: engine start failed\n");
        cleanup(app);
        return 1;
    }

    while (app.running) {
        while (XPending(app.display) > 0) {
            XEvent event;
            XNextEvent(app.display, &event);
            if (event.type == Expose) {
                app.dirty = true;
            } else if (event.type == ButtonPress) {
                click(app, event.xbutton.x, event.xbutton.y);
            } else if (event.type == KeyPress) {
                key(app, event.xkey);
            }
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        int x_fd = ConnectionNumber(app.display);
        FD_SET(x_fd, &read_fds);
        int max_fd = x_fd;
        if (app.child_fd >= 0) {
            FD_SET(app.child_fd, &read_fds);
            if (app.child_fd > max_fd) {
                max_fd = app.child_fd;
            }
        }
        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        int ready = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (app.child_fd >= 0 && FD_ISSET(app.child_fd, &read_fds)) {
            read_child(app);
        }
        wait_child(app);
        if (app.dirty) {
            draw(app);
        }
    }

    cleanup(app);
    return 0;
}
