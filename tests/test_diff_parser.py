from codesentry.github.diff_parser import DiffParser


def test_added_lines():

    patch = (
        "@@ -1,2 +1,3 @@\n"
        " first\n"
        "+added\n"
        " last"
    )

    result = DiffParser().parse(patch)

    assert result.added_lines == {2}

    assert result.complete


def test_deleted_lines():

    patch = (
        "@@ -1,3 +1,2 @@\n"
        " first\n"
        "-removed\n"
        " last"
    )

    result = DiffParser().parse(patch)

    assert result.deleted_lines == {2}

    assert result.added_lines == set()

    assert result.complete


def test_modified_lines():

    patch = (
        "@@ -1,2 +1,2 @@\n"
        " first\n"
        "-old\n"
        "+new"
    )

    result = DiffParser().parse(patch)

    assert result.added_lines == {2}

    assert result.deleted_lines == {2}

    assert result.complete


def test_multiple_hunks():

    patch = (
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "@@ -10 +10 @@\n"
        "-old2\n"
        "+new2"
    )

    result = DiffParser().parse(patch)

    assert result.added_lines == {1, 10}

    assert result.hunks == 2

    assert result.complete


def test_empty_patch():

    result = DiffParser().parse("")

    assert not result.complete


def test_missing_patch():

    result = DiffParser().parse(None)

    assert not result.complete


def test_incomplete_patch():

    patch = (
        "@@ -1,3 +1,4 @@\n"
        " first\n"
        "+new"
    )

    result = DiffParser().parse(patch)

    assert not result.complete


def test_line_intersection():

    patch = (
        "@@ -5 +5,2 @@\n"
        " existing\n"
        "+new"
    )

    result = DiffParser().parse(patch)

    assert result.intersects(5, 7)

    assert not result.intersects(1, 4)


def test_new_file():

    patch = (
        "@@ -0,0 +1,2 @@\n"
        "+first\n"
        "+second"
    )

    result = DiffParser().parse(patch)

    assert result.added_lines == {1, 2}

    assert result.complete


def test_no_newline_marker():

    patch = (
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "\\ No newline at end of file"
    )

    result = DiffParser().parse(patch)

    assert result.added_lines == {1}

    assert result.complete