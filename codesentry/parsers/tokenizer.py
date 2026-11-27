from codesentry.core.models import Token
from codesentry.parsers.ast_utils import get_node_text


def tokenize(root, source_code: str) -> list[Token]:

    source_bytes = source_code.encode("utf-8")

    tokens = []
    stack = [root]

    literal_types = {
        "string_literal",
        "char_literal",
        "raw_string_literal",
        "number_literal",
        "integer",
        "float"
    }

    while stack:

        node = stack.pop()

        if node.type == "comment" or node.is_missing:
            continue

        is_literal = node.type in literal_types

        if node.type == "string":
            is_literal = not any(
                child.type == "interpolation"
                for child in node.named_children
            )

        if node.child_count == 0 or is_literal:

            value = get_node_text(node, source_bytes)

            if not value.strip():
                continue

            tokens.append(
                Token(
                    value=value,
                    type=node.type,
                    line=node.start_point.row + 1,
                    column=node.start_point.column + 1
                )
            )

        else:
            stack.extend(reversed(node.children))

    return tokens


def normalize_tokens(tokens: list[Token]) -> list[str]:

    return [
        "ID" if token.type == "identifier"
        else token.value
        for token in tokens
    ]