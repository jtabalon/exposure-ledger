from pathlib import Path

Path("REPOSITORY_CONTENT_WAS_EXECUTED").write_text("unsafe", encoding="utf-8")
