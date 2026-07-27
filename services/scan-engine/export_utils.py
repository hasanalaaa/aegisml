"""Small standard-library helpers shared by analytics and research exports."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
import csv
from datetime import date, datetime, timedelta
import io


def render_csv(
    fieldnames: Sequence[str], rows: Iterable[Mapping[str, object]]
) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        extrasaction="ignore",
        lineterminator="\r\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def daily_trends(
    records: Iterable[tuple[datetime, str]], start_day: date, end_day: date
) -> list[dict[str, int | str]]:
    counts = Counter((created_at.date(), risk_level) for created_at, risk_level in records)
    data: list[dict[str, int | str]] = []
    current = start_day
    while current <= end_day:
        data.append(
            {
                "date": current.isoformat(),
                "safe": counts[(current, "clean")] + counts[(current, "suspicious")],
                "threats": counts[(current, "malicious")] + counts[(current, "critical")],
            }
        )
        current += timedelta(days=1)
    return data
