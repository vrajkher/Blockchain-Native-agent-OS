#!/usr/bin/env python3
"""Fallback squashfs extractor (pip install PySquashfsImage) for hosts without unsquashfs."""

import os
import stat
import sys

from PySquashfsImage import SquashFsImage


def main(image: str, dest: str) -> None:
    with SquashFsImage.from_file(image) as img:
        for entry in img:
            path = os.path.join(dest, entry.path.lstrip("/"))
            mode = stat.S_IMODE(entry.mode)
            if entry.is_dir:
                os.makedirs(path, exist_ok=True)
            elif entry.is_symlink:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                os.symlink(entry.readlink(), path)
                continue
            elif entry.is_file:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as fh:
                    for block in entry.iter_bytes():
                        fh.write(block)
            else:
                continue  # device nodes etc.: devtmpfs provides /dev at boot
            os.chmod(path, mode)
            os.lchown(path, entry.uid, entry.gid)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
