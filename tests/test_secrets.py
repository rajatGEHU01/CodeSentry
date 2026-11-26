import pytest

from codesentry.analyzers.secrets import SecretDetector


@pytest.fixture
def detector():
    return SecretDetector()


def test_hardcoded_password(detector):

    findings = detector.analyze(
        'password = "Admin123456!"',
        "test.py"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC010"


def test_high_entropy_secret(detector):

    findings = detector.analyze(
        'api_key = "aB7xK9mP2qR5vT8zN4wY6"',
        "test.py"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC009"


def test_github_token(detector):

    token = "ghp_" + "A" * 36

    findings = detector.analyze(
        f'github_token = "{token}"',
        "test.py"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC002"


def test_aws_key(detector):

    findings = detector.analyze(
        'aws_key = "AKIAABCDEFGHIJKLMNOP"',
        "test.py"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"


def test_private_key(detector):

    findings = detector.analyze(
        "-----BEGIN RSA PRIVATE KEY-----",
        "test.pem"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"


def test_database_credentials(detector):

    findings = detector.analyze(
        'url = "postgresql://admin:FakePass@localhost/db"',
        "test.py"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC008"


def test_environment_variable(detector):

    findings = detector.analyze(
        'api_key = os.getenv("API_KEY")',
        "test.py"
    )

    assert findings == []


def test_placeholder(detector):

    findings = detector.analyze(
        'api_key = "your_api_key"',
        "test.py"
    )

    assert findings == []


def test_normal_variable(detector):

    findings = detector.analyze(
        'username = "admin"',
        "test.py"
    )

    assert findings == []


def test_empty_source(detector):

    assert detector.analyze("", "test.py") == []


def test_entropy(detector):

    assert detector.shannon_entropy("aaaaaa") == 0

    assert detector.shannon_entropy("abcd") == 2.0


def test_secret_not_exposed(detector):

    secret = "Admin123456!"

    findings = detector.analyze(
        f'password = "{secret}"',
        "test.py"
    )

    for finding in findings:

        assert secret not in finding.message
        assert secret not in finding.suggestion
        assert secret not in repr(finding)


def test_line_number(detector):

    source = (
        'username = "admin"\n'
        'password = "Admin123456!"'
    )

    findings = detector.analyze(source, "test.py")

    assert findings[0].start_line == 2