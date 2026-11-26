from collections.abc import Iterator
from tree_sitter import Node


def traverse_ast(root: Node) -> Iterator[Node]:

    stack = [root]

    while stack:

        node = stack.pop()

        yield node

        stack.extend(reversed(node.children))


def get_node_text(node: Node, source_bytes: bytes) -> str:

    return source_bytes[
        node.start_byte:node.end_byte
    ].decode("utf-8")