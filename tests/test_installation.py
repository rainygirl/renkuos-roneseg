"""Optional native IPC integration tests. Build the helper and set RONESEG_DECODER."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get('RONESEG_DECODER'), 'set RONESEG_DECODER to the native helper')
class InstallationTests(unittest.TestCase):
    def run_worker(self, commands=b''):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / 'data/roneseg'
            (data / 'decoder').mkdir(parents=True)
            shutil.copyfile(os.environ['RONESEG_DECODER'], data / 'decoder/run')
            (data / 'decoder/run').chmod(0o755)
            shutil.copyfile(root / 'tests/fixtures/auth.bin', data / 'link-auth.bin')
            # Neither the worker nor its launcher can find an interpreter here.
            env = dict(os.environ, PATH='/nonexistent', PYTHONPATH='/nonexistent',
                       LIBUNICORN_PATH='/nonexistent')
            return subprocess.run([str(data / 'decoder/run'), '--replay',
                str(root / 'tests/fixtures/native_exchange.bin')], input=commands,
                capture_output=True, cwd=directory, env=env, timeout=15)

    def messages(self, process):
        output, messages = process.stdout, []
        while output:
            self.assertGreaterEqual(len(output), 5)
            size = struct.unpack('<I', output[1:5])[0]
            self.assertGreaterEqual(len(output), 5 + size)
            messages.append((output[:1], output[5:5 + size]))
            output = output[5 + size:]
        return messages

    def test_native_executable_without_python_or_settings(self):
        process = self.run_worker(b'Q' + bytes(4))
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        kinds = [kind for kind, _ in self.messages(process)]
        self.assertIn(b'R', kinds)
        self.assertNotIn(b'E', kinds)

    def test_reset_and_partial_usb_input(self):
        process = self.run_worker(b'R' + bytes(4) + b'D' + struct.pack('<I', 3)
                                  + b'abc' + b'Q' + bytes(4))
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual([kind for kind, _ in self.messages(process)],
                         [b'N', b'N', b'R', b'R', b'T'])

    def test_oversized_pipe_message_is_rejected(self):
        process = self.run_worker(b'D' + struct.pack('<I', 1024 * 1024 + 1))
        self.assertEqual(process.returncode, 1)
        self.assertEqual(self.messages(process)[-1][0], b'E')

    def test_unknown_command_is_rejected(self):
        process = self.run_worker(b'X' + bytes(4))
        self.assertEqual(process.returncode, 1)
        self.assertEqual(self.messages(process)[-1][0], b'E')


if __name__ == '__main__':
    unittest.main()
