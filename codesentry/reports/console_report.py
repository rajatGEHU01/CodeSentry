from codesentry.core.report import RepositoryReport


class ConsoleReporter:

    @staticmethod
    def display(report: RepositoryReport):

        print("\n" + "=" * 55)
        print("              CODESENTRY ANALYSIS")
        print("=" * 55)

        print(f"Files analyzed: {len(report.files)}")
        print(f"Files skipped: {len(report.skipped_files)}")
        print(f"Total findings: {len(report.findings)}")
        print(f"Analysis errors: {len(report.errors)}")
        print(f"Duration: {report.duration_seconds}s")

        print("\n--- DUPLICATION ---")

        print(
            f"Total tokens: "
            f"{report.duplication.total_tokens}"
        )

        print(
            f"Duplicated tokens: "
            f"{report.duplication.duplicated_tokens}"
        )

        print(
            f"Duplication: "
            f"{report.duplication.duplication_percentage}%"
        )

        print("\n--- SEVERITY SUMMARY ---")

        for severity, count in report.severity_counts.items():

            print(f"{severity.upper()}: {count}")

        print("\n--- FINDINGS ---")

        for finding in report.findings:

            print(
                f"\n[{finding.severity.value.upper()}] "
                f"{finding.rule_id}"
            )

            print(
                f"Location: {finding.file_path}:"
                f"{finding.start_line}-{finding.end_line}"
            )

            print(f"Message: {finding.message}")
            print(f"Suggestion: {finding.suggestion}")

        if report.errors:

            print("\n--- ANALYSIS ERRORS ---")

            for error in report.errors:

                print(
                    f"{error.file_path} | "
                    f"{error.stage} | "
                    f"{error.message}"
                )

        if report.skipped_files:

            print("\n--- SKIPPED FILES ---")

            for path, reason in report.skipped_files.items():

                print(f"{path}: {reason}")