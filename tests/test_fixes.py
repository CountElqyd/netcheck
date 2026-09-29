import io
import unittest

from netcheck import Config, apply_fixes, prompt_yes_no


class TestFixes(unittest.TestCase):
    def test_prompt_yes(self):
        tty = io.StringIO("y\n")
        self.assertTrue(prompt_yes_no("Do it?", tty=tty))

    def test_prompt_no(self):
        self.assertFalse(prompt_yes_no("Do it?", tty=io.StringIO("n\n")))

    def test_no_fix_skips(self):
        self.assertEqual(apply_fixes(Config(), allow_fix=False, tty=io.StringIO("y\n")), [])


if __name__ == "__main__":
    unittest.main()
