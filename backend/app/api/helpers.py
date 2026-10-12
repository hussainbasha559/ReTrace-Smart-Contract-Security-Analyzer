from __future__ import annotations

from datetime import datetime

from app.deps import err


def paging(page: int, page_size: int) -> tuple[int, int, int]:
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    return page, page_size, (page - 1) * page_size


def parse_date(value: str | None, end: bool = False) -> datetime | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(value[:10])
    except ValueError:
        raise err(422, "bad_date", "Dates must look like YYYY-MM-DD.")
    return d.replace(hour=23, minute=59, second=59) if end else d


def like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
