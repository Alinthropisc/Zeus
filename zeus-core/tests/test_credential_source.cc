// tests/test_credential_source.cc
#include "zeus.hh"
#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>

using namespace zeus;

namespace
{
    std::filesystem::path make_temp_file(std::string_view content)
    {
        auto path = std::filesystem::temp_directory_path() / "zeus_test_creds.txt";
        std::ofstream f(path);
        f << content;
        return path;
    }
} // namespace

TEST(CredentialSource, LoginFileYieldsLinesInOrder)
{
    auto path = make_temp_file("admin\nroot\nguest\n");
    auto source = CredentialSource::from_files(path, std::nullopt);

    std::vector<std::string> collected;
    for (auto&& login : source.logins()) collected.push_back(login);
    {
    collected.push_back(login);
    }
    EXPECT_EQ(collected, (std::vector<std::string>{"admin", "root", "guest"}));
    std::filesystem::remove(path);
}


TEST(CredentialSource, ReportsCorrectLoginCount)
{
    auto path = make_temp_file("a\nb\nc\nd\n");
    auto source = CredentialSource::from_files(path, std::nullopt);
    EXPECT_EQ(source.login_count(), 4u);
    std::filesystem::remove(path);
}

TEST(CredentialSource, ColonFileSplitsLoginAndPasswordOnFirstColon)
{
    auto path = make_temp_file("admin:s3cr3t\nroot:p@ss:word\n"); // password itself may contain ':'
    auto source = CredentialSource::from_colon_file(path);
    std::vector<std::string> logins, passwords;

    for (auto&& l : source.logins())
    {
        logins.push_back(l);
    }
    for (auto&& p : source.passwords())
    {
        passwords.push_back(p);
    }
    EXPECT_EQ(logins[1], "root");
    EXPECT_EQ(passwords[1], "p@ss:word"); // only split on the FIRST colon
    std::filesystem::remove(path);
}

TEST(CredentialSource, BruteForceGeneratesAllCombinationsWithinLengthRange)
{
    auto source = CredentialSource::brute_force("ab", 1, 2);
    std::vector<std::string> generated;
    for (auto&& pw : source.passwords())
    {
    generated.push_back(pw);
    }
    EXPECT_EQ(generated, (std::vector<std::string>{"a", "b", "aa", "ab", "ba", "bb"}));
}