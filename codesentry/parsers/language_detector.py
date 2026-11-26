from pathlib import Path

LANGUAGE_MAP = {
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".sql": "sql"
}


def detect_language(filename: str) -> str | None:
    extension = Path(filename).suffix.lower()

    return LANGUAGE_MAP.get(extension)