import re
import os

def search_sql_injection_risks(root_directory):
    """
    Search for potential SQL injection vulnerabilities in code within a specified root directory.

    Args:
        root_directory (str): Path to the root directory to search.

    Returns:
        list: A list of potential SQL injection risks with code lines and their file locations.
    """
    patterns = [
        r"execute\(.+\+.+\)",  # Concatenation in execute function
        r"execute\(.+format\(.+\)\)",  # Format method in execute function
        r"execute\(.+%\s*[^,]+\)",  # Percent formatting in execute function
        r"execute\(f\".+\"\)"  # f-string in execute function
    ]

    risks = []

    for subdir, dirs, files in os.walk(root_directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(subdir, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        for pattern in patterns:
                            if re.search(pattern, line):
                                risk = f"{file_path}: Line {i + 1} - {line.strip()}"
                                risks.append(risk)

    return risks

if __name__ == "__main__":
    # Search for SQL injection risks in the current directory
    risks_found = search_sql_injection_risks('.')
    for risk in risks_found:
        print(risk)


