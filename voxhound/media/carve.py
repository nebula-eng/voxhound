"""Magic-byte carving for streams that carry files without saying so.

HTTP has ``Content-Type``; chat clients and game protocols do not. This module
scans the retained head of a stream for known container signatures and emits
whatever it finds as an artifact, so a QQ voice note that starts mid-connection
still shows up in the media tab.

Deliberately conservative: it only carves from the *start* of a signature to
the end of the retained buffer and labels the result as possibly truncated.
Reconstructing exact lengths for a dozen containers is guesswork dressed up as
precision, and a corrupt 3 MB artifact wastes an analyst's time.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.model import Artifact
from ..core.util import sha256_hex

#: (magic, mime, extension, minimum total size to be worth carving)
SIGNATURES: tuple[tuple[bytes, str, str, int], ...] = (
    (b"#!SILK_V3", "audio/silk", "silk", 32),
    (b"#!AMR-WB\n", "audio/amr-wb", "amrwb", 32),
    (b"#!AMR\n", "audio/amr", "amr", 32),
    (b"OggS", "audio/ogg", "ogg", 128),
    (b"ID3", "audio/mpeg", "mp3", 256),
    (b"RIFF", "audio/wav", "wav", 128),
    (b"fLaC", "audio/flac", "flac", 128),
    (b"\x89PNG\r\n\x1a\n", "image/png", "png", 64),
    (b"\xff\xd8\xff", "image/jpeg", "jpg", 256),
    (b"GIF89a", "image/gif", "gif", 64),
    (b"%PDF-", "application/pdf", "pdf", 256),
    (b"PK\x03\x04", "application/zip", "zip", 256),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7z", 256),
    (b"Rar!\x1a\x07", "application/vnd.rar", "rar", 256),
    (b"SQLite format 3\x00", "application/vnd.sqlite3", "sqlite", 512),
    (b"\x1aE\xdf\xa3", "video/webm", "webm", 512),
    (b"FLV\x01", "video/x-flv", "flv", 256),
)

#: Containers whose header starts with a size field we can trust (4 bytes at 0,
#: big-endian) — lets us carve exactly the declared length when it is present.
SELF_SIZING = {b"PK\x03\x04"}


@dataclass(slots=True)
class CarvedBlob:
    offset: int
    mime: str
    ext: str
    data: bytes
    truncated: bool


def scan(buffer: bytes, *, max_blobs: int = 4, min_size: int = 64) -> list[CarvedBlob]:
    """Find embedded containers in a stream head."""
    blobs: list[CarvedBlob] = []
    for magic, mime, ext, minimum in SIGNATURES:
        start = 0
        while len(blobs) < max_blobs:
            index = buffer.find(magic, start)
            if index < 0:
                break
            start = index + len(magic)
            blob = buffer[index:]
            if len(blob) < max(minimum, min_size):
                continue
            truncated = True
            if magic in SELF_SIZING and len(blob) >= 22:
                declared = int.from_bytes(blob[18:22], "little")
                if 22 <= declared <= len(blob):
                    blob = blob[:declared]
                    truncated = False
            blobs.append(CarvedBlob(offset=index, mime=mime, ext=ext, data=blob, truncated=truncated))
    blobs.sort(key=lambda b: b.offset)
    return blobs[:max_blobs]


def make_artifacts(
    blobs: list[CarvedBlob], *, stream_id: int, flow_key: object, source: str = "stream"
) -> list[Artifact]:
    out: list[Artifact] = []
    for i, blob in enumerate(blobs):
        out.append(
            Artifact(
                ts=0.0,
                kind=blob.mime,
                name=f"stream{stream_id}-offset{blob.offset}.{blob.ext}",
                data=blob.data,
                source=source,
                flow_key=flow_key,  # type: ignore[arg-type]
                stream_id=stream_id,
                meta={"offset": blob.offset, "truncated": blob.truncated, "index": i},
                sha256=sha256_hex(blob.data),
            )
        )
    return out
