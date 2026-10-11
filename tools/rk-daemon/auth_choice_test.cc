// rk-daemon's authentication mode: flags, the saved choice, the first-run
// question (through a scripted Prompter) and writing revkit.conf.
#include "auth_choice.h"

#include <gtest/gtest.h>

#include <deque>
#include <fstream>
#include <sstream>

#include <unistd.h>

namespace revkit::daemon {
namespace {

namespace fs = std::filesystem;

class Scripted : public Prompter {
 public:
  explicit Scripted(std::deque<std::string> answers) : answers_(std::move(answers)) {}
  void say(const std::string &text) override { said += text; }
  std::optional<std::string> line(const std::string &q) override { return next(q); }
  std::optional<std::string> secret(const std::string &q) override { return next(q); }
  std::string said;
  std::vector<std::string> asked;
  std::size_t left() const { return answers_.size(); }

 private:
  std::optional<std::string> next(const std::string &q) {
    asked.push_back(q);
    if (answers_.empty()) return std::nullopt;
    std::string a = answers_.front();
    answers_.pop_front();
    return a;
  }
  std::deque<std::string> answers_;
};

class AuthChoiceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    dir_ = fs::temp_directory_path() / ("rk-auth-choice-" + std::to_string(::getpid()) + "-" +
                                        ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(dir_);
    fs::create_directories(dir_);
    user_ = dir_ / "home/.config/revkit/revkit.conf";
    etc_ = dir_ / "etc/revkit/revkit.conf";
    in_.config_files = {user_, etc_};
    in_.user_config = user_;
    in_.no_accounts = [this] { return accounts_.empty(); };
    in_.create_admin = [this](const std::string &n, const std::string &p) {
      if (p.size() < 8) throw std::runtime_error("the password is shorter than 8 characters");
      accounts_.push_back(n + ":" + p);
    };
  }
  void TearDown() override { fs::remove_all(dir_); }

  static void Write(const fs::path &p, const std::string &text) {
    fs::create_directories(p.parent_path());
    std::ofstream(p) << text;
  }
  static std::string Read(const fs::path &p) {
    std::ifstream in(p);
    std::stringstream s;
    s << in.rdbuf();
    return s.str();
  }

  fs::path dir_, user_, etc_;
  AuthChoiceInput in_;
  std::vector<std::string> accounts_;
};

TEST_F(AuthChoiceTest, FlagsOverrideTheSavedChoice) {
  Write(user_, "auth = none\n");
  Scripted p({});
  in_.interactive = true;
  in_.auth_flag = true;
  AuthChoice c = choose_auth(in_, p);
  EXPECT_EQ(c.mode, AuthMode::accounts);
  EXPECT_EQ(c.source, "--auth");
  in_.auth_flag = false;
  Write(user_, "auth = accounts\n");
  in_.no_auth_flag = true;
  c = choose_auth(in_, p);
  EXPECT_EQ(c.mode, AuthMode::none);
  EXPECT_EQ(describe(c), "no sign-in (--no-auth; --auth to require accounts)");
  in_.auth_flag = true;
  EXPECT_THROW(choose_auth(in_, p), std::runtime_error);
  EXPECT_TRUE(p.asked.empty());
}

TEST_F(AuthChoiceTest, SavedChoiceUserFileWins) {
  Scripted p({});
  in_.interactive = true;
  Write(etc_, "# site\nauth = accounts\n");
  AuthChoice c = choose_auth(in_, p);
  EXPECT_EQ(c.mode, AuthMode::accounts);
  EXPECT_EQ(c.source, "auth = accounts in " + etc_.string());
  Write(user_, "ghidra = /opt/ghidra\nauth = \"none\"   # mine\n");
  c = choose_auth(in_, p);
  EXPECT_EQ(c.mode, AuthMode::none);
  EXPECT_NE(describe(c).find("auth = none in " + user_.string()), std::string::npos) << describe(c);
  EXPECT_TRUE(p.asked.empty());  // a saved choice is never asked again
  Write(user_, "auth = maybe\n");
  EXPECT_THROW(choose_auth(in_, p), std::runtime_error);
}

TEST_F(AuthChoiceTest, NoTerminalNeverAsks) {
  Scripted p({"1", "y"});
  AuthChoice c = choose_auth(in_, p);  // no accounts, nothing saved, no terminal
  EXPECT_EQ(c.mode, AuthMode::accounts);
  EXPECT_EQ(c.source, "the default");
  EXPECT_TRUE(p.asked.empty());
  EXPECT_FALSE(fs::exists(user_));
  in_.ask_flag = true;
  EXPECT_THROW(choose_auth(in_, p), std::runtime_error);  // --ask needs a terminal
  EXPECT_TRUE(p.asked.empty());
}

TEST_F(AuthChoiceTest, AccountsAlreadyThereNeverAsks) {
  accounts_.push_back("alice:x");
  Scripted p({"1"});
  in_.interactive = true;
  EXPECT_EQ(choose_auth(in_, p).mode, AuthMode::accounts);
  EXPECT_TRUE(p.asked.empty());
}

TEST_F(AuthChoiceTest, NoSignInRemembered) {
  Write(user_, "# my settings\nghidra = /opt/ghidra_12.1.4_PUBLIC\n\nallow-host = box.lan\n");
  Scripted p({"3", "1", "y"});
  in_.interactive = true;
  AuthChoice c = choose_auth(in_, p);
  EXPECT_EQ(c.mode, AuthMode::none);
  EXPECT_EQ(p.left(), 0u);
  EXPECT_NE(p.said.find("No sign-in"), std::string::npos);
  EXPECT_EQ(Read(user_), "# my settings\nghidra = /opt/ghidra_12.1.4_PUBLIC\n\nallow-host = box.lan\nauth = none\n");
  EXPECT_NE(c.source.find("saved in"), std::string::npos);
  // Next start: no question.
  Scripted again({});
  EXPECT_EQ(choose_auth(in_, again).mode, AuthMode::none);
  EXPECT_TRUE(again.asked.empty());
  // --ask asks again, and the answer replaces the line in place.
  in_.ask_flag = true;
  Scripted ask({"2", "root", "correct horse", "correct horse", "yes"});
  EXPECT_EQ(choose_auth(in_, ask).mode, AuthMode::accounts);
  EXPECT_EQ(Read(user_), "# my settings\nghidra = /opt/ghidra_12.1.4_PUBLIC\n\nallow-host = box.lan\nauth = accounts\n");
}

TEST_F(AuthChoiceTest, AccountsMakeAnAdminAndNotRemembered) {
  in_.interactive = true;
  // Passwords that differ, then one too short, then a good one; then no.
  Scripted p({"2", "alice", "secret-one", "secret-two", "alice", "short", "short", "alice", "long enough",
              "long enough", "n"});
  AuthChoice c = choose_auth(in_, p);
  EXPECT_EQ(c.mode, AuthMode::accounts);
  EXPECT_EQ(c.source, "your answer");
  EXPECT_EQ(accounts_, std::vector<std::string>{"alice:long enough"});
  EXPECT_NE(p.said.find("The passwords differ"), std::string::npos);
  EXPECT_NE(p.said.find("shorter than 8"), std::string::npos);
  EXPECT_FALSE(fs::exists(user_));
  // Abandoned (end of input): an error, nothing made.
  accounts_.clear();
  Scripted gone({"2"});
  EXPECT_THROW(choose_auth(in_, gone), std::runtime_error);
  EXPECT_TRUE(accounts_.empty());
}

TEST_F(AuthChoiceTest, SaveAuthMakesTheFileAndKeepsOneLine) {
  save_auth(user_, AuthMode::accounts);
  EXPECT_EQ(Read(user_), "auth = accounts\n");
  Write(user_, "auth = none\nx = 1\nauth = accounts # old\n");
  save_auth(user_, AuthMode::accounts);
  EXPECT_EQ(Read(user_), "auth = accounts\nx = 1\n");
  EXPECT_EQ(saved_auth({user_})->first, AuthMode::accounts);
}

}  // namespace
}  // namespace revkit::daemon
