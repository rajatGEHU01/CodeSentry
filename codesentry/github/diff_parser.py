import re

from dataclasses import dataclass, field


@dataclass
class DiffResult:

    added_lines: set[int] = field(default_factory=set)

    deleted_lines: set[int] = field(default_factory=set)

    context_lines: set[int] = field(default_factory=set)

    hunks: int = 0

    complete: bool = True

    def intersects(self, start: int, end: int) -> bool:

        return any(
            start <= line <= end
            for line in self.added_lines
        )


class DiffParser:

    HUNK_PATTERN = re.compile(
        r"^@@ -(\d+)(?:,(\d+))? "
        r"\+(\d+)(?:,(\d+))? @@"
    )

    def parse(self, patch: str | None) -> DiffResult:

        result = DiffResult()

        if not patch:

            result.complete = False
            return result

        old_line = 0
        new_line = 0

        old_remaining = 0
        new_remaining = 0

        in_hunk = False

        for line in patch.split("\n"):

            match = self.HUNK_PATTERN.match(line)

            if match:

                if in_hunk and (
                    old_remaining != 0
                    or new_remaining != 0
                ):
                    result.complete = False

                old_line = int(match.group(1))
                new_line = int(match.group(3))

                old_remaining = int(
                    match.group(2)
                    if match.group(2) is not None
                    else 1
                )

                new_remaining = int(
                    match.group(4)
                    if match.group(4) is not None
                    else 1
                )

                result.hunks += 1

                in_hunk = True

                continue

            if not in_hunk:
                continue

            if line.startswith("\\ No newline"):
                continue

            if old_remaining == 0 and new_remaining == 0:

                in_hunk = False
                continue

            if line.startswith("+"):

                result.added_lines.add(new_line)

                new_line += 1
                new_remaining -= 1

            elif line.startswith("-"):

                result.deleted_lines.add(old_line)

                old_line += 1
                old_remaining -= 1

            elif line.startswith(" "):

                result.context_lines.add(new_line)

                old_line += 1
                new_line += 1

                old_remaining -= 1
                new_remaining -= 1

            elif not line:

                continue

            else:

                result.complete = False

            if old_remaining < 0 or new_remaining < 0:

                result.complete = False

        if old_remaining != 0 or new_remaining != 0:

            result.complete = False

        if result.hunks == 0:

            result.complete = False

        return result