from tree_sitter import Language, Parser
import tree_sitter_cpp


class CppParser:

    def __init__(self):
        self.language = Language(
            tree_sitter_cpp.language()
        )

        self.parser = Parser(self.language)

    def parse(self, source_code: str):
        return self.parser.parse(
            source_code.encode("utf-8")
        )