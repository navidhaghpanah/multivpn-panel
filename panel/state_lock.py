"""Reentrant thread and process lock for the panel's JSON transactions."""
import os
import threading
from functools import wraps
from pathlib import Path


class StateLock:
    def __init__(self, path):
        self.path = Path(path)
        self.thread_lock = threading.RLock()
        self.local = threading.local()

    def __enter__(self):
        self.thread_lock.acquire()
        depth = getattr(self.local, 'depth', 0)
        try:
            if depth == 0:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
                self.local.fd = fd
                if os.name == 'nt':
                    import msvcrt
                    if os.fstat(fd).st_size == 0:
                        os.write(fd, b'0')
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
            self.local.depth = depth + 1
            return self
        except BaseException:
            if depth == 0 and hasattr(self.local, 'fd'):
                os.close(self.local.fd)
                del self.local.fd
            self.thread_lock.release()
            raise

    def __exit__(self, *args):
        self.local.depth -= 1
        try:
            if self.local.depth == 0:
                fd = self.local.fd
                try:
                    if os.name == 'nt':
                        import msvcrt
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
                    del self.local.fd
        finally:
            self.thread_lock.release()

    def transaction(self, fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            with self:
                return fn(*args, **kwargs)
        return wrapped
