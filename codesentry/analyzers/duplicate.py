from collections import defaultdict
from collections.abc import Iterator

from codesentry.core.models import (
    Token,
    Finding,
    Severity,
    DuplicateBlock,
    DuplicationResult
)

from codesentry.parsers.tokenizer import normalize_tokens
from codesentry.parsers.language_detector import detect_language


class DuplicateDetector:

    BASE = 257
    MOD = 1_000_000_007

    MAX_CANDIDATES = 64

    def __init__(
        self,
        min_tokens: int = 30,
        min_lines: int = 4
    ):

        if min_tokens < 1:
            raise ValueError("min_tokens must be positive")

        if min_lines < 1:
            raise ValueError("min_lines must be positive")

        self.min_tokens = min_tokens
        self.min_lines = min_lines

    def rolling_hash(
        self,
        values: list[int]
    ) -> Iterator[tuple[int, int]]:

        k = self.min_tokens
        n = len(values)

        if n < k:
            return

        power = pow(self.BASE, k - 1, self.MOD)
        current_hash = 0

        for value in values[:k]:

            current_hash = (
                current_hash * self.BASE + value
            ) % self.MOD

        yield 0, current_hash

        for i in range(k, n):

            current_hash = (
                (
                    current_hash
                    - values[i - k] * power
                ) * self.BASE + values[i]
            ) % self.MOD

            yield i - k + 1, current_hash

    def detect_repository(
        self,
        files: dict[str, list[Token]]
    ) -> DuplicationResult:

        result = DuplicationResult()

        fingerprints = defaultdict(list)
        duplicated = defaultdict(set)

        token_ids = {}
        encoded_files = {}

        k = self.min_tokens

        # Encode normalized tokens using shared IDs.
        for path, tokens in files.items():

            normalized = normalize_tokens(tokens)
            values = []

            for token in normalized:

                if token not in token_ids:
                    token_ids[token] = len(token_ids) + 1

                values.append(token_ids[token])

            encoded_files[path] = values
            result.total_tokens += len(values)

        # Detect duplicate blocks across supported files.
        for path, values in encoded_files.items():

            language = detect_language(path)

            if language is None:
                continue

            tokens = files[path]
            covered_until = 0

            for start, hash_value in self.rolling_hash(values):

                key = (language, hash_value)
                candidates = fingerprints[key]

                if start >= covered_until:

                    best_match = None
                    best_length = 0

                    for previous_path, previous_start in (
                        candidates[-self.MAX_CANDIDATES:]
                    ):

                        previous_values = encoded_files[
                            previous_path
                        ]

                        # Prevent overlapping same-file matches.
                        if (
                            previous_path == path
                            and previous_start + k > start
                        ):
                            continue

                        # Verify actual tokens after hash matching.
                        if (
                            previous_values[
                                previous_start:previous_start + k
                            ]
                            != values[start:start + k]
                        ):
                            continue

                        length = k

                        # Extend the matching block.
                        while (
                            start + length < len(values)
                            and previous_start + length
                            < len(previous_values)
                        ):

                            if (
                                previous_path == path
                                and previous_start + length >= start
                            ):
                                break

                            if (
                                previous_values[
                                    previous_start + length
                                ]
                                != values[start + length]
                            ):
                                break

                            length += 1

                        previous_tokens = files[previous_path]

                        current_lines = (
                            tokens[start + length - 1].line
                            - tokens[start].line + 1
                        )

                        previous_lines = (
                            previous_tokens[
                                previous_start + length - 1
                            ].line
                            - previous_tokens[previous_start].line
                            + 1
                        )

                        # Reject blocks that span too few lines.
                        if (
                            current_lines < self.min_lines
                            or previous_lines < self.min_lines
                        ):
                            continue

                        if length > best_length:

                            best_length = length

                            best_match = (
                                previous_path,
                                previous_start
                            )

                    if best_match is not None:

                        previous_path, previous_start = best_match

                        previous_tokens = files[previous_path]

                        result.blocks.append(
                            DuplicateBlock(
                                original_file=previous_path,

                                original_start=previous_tokens[
                                    previous_start
                                ].line,

                                original_end=previous_tokens[
                                    previous_start + best_length - 1
                                ].line,

                                duplicate_file=path,

                                duplicate_start=tokens[
                                    start
                                ].line,

                                duplicate_end=tokens[
                                    start + best_length - 1
                                ].line,

                                token_count=best_length
                            )
                        )

                        # Count each duplicated token only once.
                        duplicated[previous_path].update(
                            range(
                                previous_start,
                                previous_start + best_length
                            )
                        )

                        duplicated[path].update(
                            range(
                                start,
                                start + best_length
                            )
                        )

                        covered_until = start + best_length

                candidates.append((path, start))

        result.duplicated_tokens = sum(
            len(indices)
            for indices in duplicated.values()
        )

        return result

    def detect(
        self,
        tokens: list[Token],
        file_path: str
    ) -> list[Finding]:

        result = self.detect_repository({
            file_path: tokens
        })

        return [
            Finding(
                rule_id="DUP001",

                message=(
                    f"Potential duplicate code "
                    f"({block.token_count} tokens). "
                    f"Similar block in "
                    f"{block.original_file}:"
                    f"{block.original_start}."
                ),

                severity=Severity.MEDIUM,

                file_path=block.duplicate_file,

                start_line=block.duplicate_start,

                end_line=block.duplicate_end,

                suggestion=(
                    "Extract common logic into "
                    "a reusable function."
                )
            )
            for block in result.blocks
        ]