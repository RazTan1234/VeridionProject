from pathlib import Path
import hashlib

def content_ref(payload: bytes) -> str:
    hash=hashlib.sha256(payload).hexdigest()
    return f"sha256:{hash}"

def content_path(root: Path, ref:str) ->Path:
    digest=ref.split(":", 1)[1]
    return root / "content" / digest[:2] / digest

def write_content(root: Path, payload: bytes) -> str:
    ref=content_ref(payload)
    path=content_path(root,ref)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return ref


def read_content(root: Path, ref: str) -> bytes:
    path=content_path(root,ref)
    return path.read_bytes()


def write_records(path: Path, records) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count=0
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(record.model_dump_json() + "\n")
            count+=1
    return count


def read_records(path: Path, model):
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            yield model.model_validate_json(line)
