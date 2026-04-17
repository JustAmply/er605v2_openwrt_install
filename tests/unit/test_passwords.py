import unittest

from er605_installer.core.passwords import derive_passwords, normalize_mac


class PasswordTests(unittest.TestCase):
    def test_normalize_mac_accepts_dash_separator(self) -> None:
        self.assertEqual(normalize_mac("b8-fb-b3-2c-d7-69"), "B8:FB:B3:2C:D7:69")

    def test_derive_passwords_matches_repo_logic(self) -> None:
        passwords = derive_passwords("B8-FB-B3-2C-D7-69", "justus")
        self.assertEqual(passwords["normalized_mac"], "B8:FB:B3:2C:D7:69")
        self.assertEqual(passwords["root_password"], "5e57b1a0bd7b4e04")
        self.assertEqual(passwords["debug_password"], "35bb07df68b0c2b4")


if __name__ == "__main__":
    unittest.main()
