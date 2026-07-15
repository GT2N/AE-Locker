// lock::tui — ftxui-driven menu UI (Wave A: framework + main menu only).
//
// Scope for Wave A:
//   - `lock --tui` shows the main menu (Encrypt / Decrypt / List / Quit).
//   - Selecting Encrypt / Decrypt / List renders a placeholder screen that
//     prompts the user to press Enter to return to the main menu.
//   - Quit exits with ExitCode::Ok.
//
// Wave B will replace the placeholder with per-subcommand submenus. Keeping
// this file self-contained — all ftxui headers are pulled in here so the
// public `include/lock/tui.hpp` stays ftxui-free.
#include <lock/tui.hpp>

#include <lock/i18n.hpp>

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <cstdio>
#include <string>
#include <unistd.h>
#include <vector>

namespace lock::tui {

namespace {

bool stdin_is_tty() noexcept {
    return ::isatty(STDIN_FILENO) != 0;
}

bool stderr_is_tty() noexcept {
    return ::isatty(STDERR_FILENO) != 0;
}

ExitCode run_tui_impl() {
    auto screen = ftxui::ScreenInteractive::Fullscreen();

    int selected = 0;
    std::vector<std::string> entries = {
        std::string(tr(Str::Tui_menu_encrypt)),
        std::string(tr(Str::Tui_menu_decrypt)),
        std::string(tr(Str::Tui_menu_list)),
        std::string(tr(Str::Tui_menu_quit)),
    };

    auto menu = ftxui::Menu(&entries, &selected);

    auto menu_card = ftxui::Renderer(menu, [&] {
        return ftxui::vbox({
                   ftxui::text(tr(Str::Tui_menu_title))
                       | ftxui::bold | ftxui::center,
                   ftxui::separator(),
                   menu->Render(),
               }) |
               ftxui::border | ftxui::center;
    });

    auto placeholder_card = ftxui::Renderer([=] {
        return ftxui::vbox({
                   ftxui::text(entries[static_cast<size_t>(selected)]),
                   ftxui::separator(),
                   ftxui::text(tr(Str::Tui_not_implemented_yet))
                       | ftxui::dim | ftxui::center,
                   ftxui::separator(),
                   ftxui::text(tr(Str::Tui_press_enter_to_return))
                       | ftxui::center,
               }) |
               ftxui::border | ftxui::center;
    });

    // 0 = main menu, 1 = "not implemented yet" placeholder.
    int screen_idx = 0;
    auto app = ftxui::Container::Tab({menu_card, placeholder_card}, &screen_idx) |
               ftxui::CatchEvent([&](ftxui::Event ev) {
                   if (screen_idx == 0) {
                       if (ev == ftxui::Event::Return) {
                           if (selected == 3) {  // Quit
                               screen.Exit();
                               return true;
                           }
                           if (selected >= 0 && selected < 3) {
                               screen_idx = 1;
                               return true;
                           }
                       }
                       return false;
                   }
                   // Placeholder screen: Enter / Esc / q returns to the menu.
                   if (ev == ftxui::Event::Return ||
                       ev == ftxui::Event::Escape ||
                       ev == ftxui::Event::Character('q') ||
                       ev == ftxui::Event::Character('Q')) {
                       screen_idx = 0;
                       return true;
                   }
                   return false;
               });

    screen.Loop(app);
    return ExitCode::Ok;
}

}  // namespace

ExitCode run_tui() {
    if (!stdin_is_tty() || !stderr_is_tty()) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(),
                     tr(Str::Err_tui_not_a_tty));
        return ExitCode::Arg;
    }
    if (!color_enabled()) {
        std::fprintf(stderr, "%s%s\n",
                     color_error(tr(Str::Err_label)).c_str(),
                     tr(Str::Err_tui_no_color));
        return ExitCode::Arg;
    }
    return run_tui_impl();
}

}  // namespace lock::tui
