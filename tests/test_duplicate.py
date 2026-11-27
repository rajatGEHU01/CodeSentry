from codesentry.parsers.cpp_parser import CppParser
from codesentry.parsers.tokenizer import tokenize
from codesentry.analyzers.duplicate import DuplicateDetector


def get_tokens(source):

    tree = CppParser().parse(source)

    return tokenize(tree.root_node, source)


def analyze(source, min_tokens=20):

    tokens = get_tokens(source)

    detector = DuplicateDetector(
        min_tokens=min_tokens,
        min_lines=1
    )

    return detector.detect(tokens, "test.cpp")


def test_duplicate_code():

    source = """
    int sum(int a, int b) {
        int result = a + b;
        return result;
    }

    int add(int x, int y) {
        int total = x + y;
        return total;
    }
    """

    findings = analyze(source)

    assert len(findings) > 0


def test_no_duplicate():

    source = """
    int sum(int a, int b) {
        return a + b;
    }
    """

    assert len(analyze(source)) == 0


def test_empty_source():

    assert len(analyze("")) == 0


def test_rolling_hash():

    detector = DuplicateDetector(min_tokens=3)

    hashes = dict(
        detector.rolling_hash([1, 2, 3, 1, 2, 3])
    )

    assert hashes[0] == hashes[3]


def test_cross_file_duplicates():

    source1 = """
    int sum(int a, int b) {
        int result = a + b;
        return result;
    }
    """

    source2 = """
    int add(int x, int y) {
        int total = x + y;
        return total;
    }
    """

    detector = DuplicateDetector(
        min_tokens=20,
        min_lines=1
    )

    result = detector.detect_repository({
        "first.cpp": get_tokens(source1),
        "second.cpp": get_tokens(source2)
    })

    assert len(result.blocks) == 1
    assert result.duplication_percentage == 100.0

    assert result.blocks[0].original_file == "first.cpp"
    assert result.blocks[0].duplicate_file == "second.cpp"


def test_empty_repository():

    result = DuplicateDetector().detect_repository({})

    assert result.total_tokens == 0
    assert result.duplicated_tokens == 0
    assert result.duplication_percentage == 0.0
    assert result.blocks == []


def test_different_languages():

    tokens = get_tokens(
        "int add(int a, int b) { return a + b; }"
    )

    result = DuplicateDetector(
        min_tokens=5
    ).detect_repository({
        "first.cpp": tokens,
        "second.py": tokens
    })

    assert result.blocks == []


def test_minimum_line_threshold():

    source = "int add(int a, int b) { return a + b; }"

    detector = DuplicateDetector(
        min_tokens=5,
        min_lines=4
    )

    result = detector.detect_repository({
        "first.cpp": get_tokens(source),
        "second.cpp": get_tokens(source)
    })

    assert result.blocks == []
    assert result.duplication_percentage == 0.0


def test_preserve_numeric_literals():

    source1 = "int calculate() { return 100; }"
    source2 = "int calculate() { return 200; }"

    tokens1 = get_tokens(source1)
    tokens2 = get_tokens(source2)

    detector = DuplicateDetector(
        min_tokens=len(tokens1),
        min_lines=1
    )

    result = detector.detect_repository({
        "first.cpp": tokens1,
        "second.cpp": tokens2
    })

    assert result.blocks == []