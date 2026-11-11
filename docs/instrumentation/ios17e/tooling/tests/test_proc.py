import sys
import unittest

from i17e_runner.errors import CommandFailed, CommandTimeout
from i17e_runner.proc import CommandRunner, CmdResult, looks_like_usb_drop


class ProcTests(unittest.TestCase):
    def test_timeout_is_reported(self):
        runner = CommandRunner()
        result = runner.run(
            [sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.2
        )
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)

    def test_check_raises_timeout(self):
        runner = CommandRunner()
        with self.assertRaises(CommandTimeout):
            runner.run([sys.executable, "-c", "import time; time.sleep(2)"],
                       timeout=0.2, check=True)

    def test_check_raises_command_failed(self):
        runner = CommandRunner()
        with self.assertRaises(CommandFailed):
            runner.run([sys.executable, "-c", "import sys; sys.exit(7)"],
                       check=True)

    def test_usb_drop_classification(self):
        result = CmdResult(cmd=["pymobiledevice3", "usbmux", "list"],
                           returncode=1, stderr="ERROR: Device is not connected")
        self.assertTrue(looks_like_usb_drop(result))
        other = CmdResult(cmd=["x"], returncode=1, stderr="bad argument")
        self.assertFalse(looks_like_usb_drop(other))


if __name__ == "__main__":
    unittest.main()
