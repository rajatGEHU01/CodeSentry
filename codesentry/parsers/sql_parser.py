import sqlglot


class SQLParser:

    def parse(
        self,
        source_code: str,
        dialect: str | None = None
    ):

        return sqlglot.parse(
            source_code,
            read=dialect
        )