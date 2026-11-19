"""File-type detection: which files are reviewable source, config, or never sent."""
from __future__ import annotations

from pathlib import PurePosixPath

# extension -> language key. The key selects prompts/languages/<key>.md when present.
SOURCE_EXTENSIONS = {
    '.java': 'java', '.kt': 'java', '.kts': 'java', '.scala': 'java', '.groovy': 'java',
    '.py': 'python',
    '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'javascript', '.tsx': 'javascript', '.vue': 'javascript', '.svelte': 'javascript',
    '.go': 'go',
    '.cs': 'csharp', '.vb': 'csharp', '.cshtml': 'csharp', '.razor': 'csharp',
    '.php': 'php',
    '.rb': 'ruby', '.erb': 'ruby',
    '.c': 'c_cpp', '.h': 'c_cpp', '.cc': 'c_cpp', '.cpp': 'c_cpp', '.cxx': 'c_cpp',
    '.hpp': 'c_cpp', '.hh': 'c_cpp', '.m': 'c_cpp', '.mm': 'c_cpp',
    '.rs': 'rust',
    '.swift': 'swift',
    '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.ps1': 'shell',
    '.sql': 'sql',
    '.html': 'web', '.htm': 'web', '.jsp': 'java', '.jspx': 'java',
}

# Configuration / infrastructure files. Sent only with --include-config because
# they are more likely to hold environment-specific values.
CONFIG_EXTENSIONS = {
    '.xml': 'config', '.yml': 'config', '.yaml': 'config', '.properties': 'config',
    '.toml': 'config', '.ini': 'config', '.conf': 'config', '.cfg': 'config',
    '.gradle': 'config', '.tf': 'config', '.hcl': 'config', '.json': 'config',
}
CONFIG_FILENAMES = {
    'dockerfile': 'config', 'containerfile': 'config', 'docker-compose.yml': 'config',
    'makefile': 'config', 'jenkinsfile': 'config', 'nginx.conf': 'config',
    'requirements.txt': 'config', 'gemfile': 'config', 'pipfile': 'config',
}

# Directories that are almost never first-party source.
EXCLUDED_DIRS = {
    '.git', '.hg', '.svn', '.github', '.idea', '.vscode', '.gradle', '.mvn',
    'node_modules', 'bower_components', 'vendor', 'third_party', 'third-party',
    'dist', 'build', 'out', 'target', 'bin', 'obj', 'coverage', '.next', '.nuxt',
    '.venv', 'venv', 'env', '__pycache__', '.mypy_cache', '.pytest_cache', '.tox',
    'output', 'security-audit-output', 'evaluation', 'vulnshop-eval',
}

# Never sent to the model, regardless of options: credential stores, keys, lock files,
# minified bundles, and anything that looks like an answer key.
NEVER_SEND_SUFFIXES = (
    '.pem', '.key', '.p12', '.pfx', '.jks', '.keystore', '.crt', '.cer', '.der',
    '.min.js', '.min.css', '.map', '.lock',
)
NEVER_SEND_NAMES = {
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', '.npmrc', '.pypirc', '.netrc',
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'composer.lock',
    'cargo.lock', 'go.sum', 'gemfile.lock', 'credentials', 'credentials.json',
}

LANGUAGE_LABELS = {
    'java': 'Java/JVM', 'python': 'Python', 'javascript': 'JavaScript/TypeScript', 'go': 'Go',
    'csharp': 'C#/.NET', 'php': 'PHP', 'ruby': 'Ruby', 'c_cpp': 'C/C++/Objective-C',
    'rust': 'Rust', 'swift': 'Swift', 'shell': 'Shell', 'sql': 'SQL', 'web': 'HTML',
    'config': 'Configuration/IaC',
}


def never_send(rel: str) -> str | None:
    """Return a reason if the file must never leave the machine, else None."""
    name = PurePosixPath(rel).name.lower()
    if name == '.env' or name.startswith('.env.') or name.endswith('.env'):
        return 'environment file (may contain secrets)'
    if name in NEVER_SEND_NAMES or name.startswith('id_rsa'):
        return 'credential or lock file'
    if name.endswith(NEVER_SEND_SUFFIXES):
        return 'key material, lock file or minified bundle'
    if 'answer_key' in name or 'answer-key' in name:
        return 'evaluation answer key'
    return None


def classify(rel: str, include_config: bool) -> str | None:
    """Return the language key for a reviewable file, or None if it should be skipped."""
    path = PurePosixPath(rel)
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in SOURCE_EXTENSIONS:
        return SOURCE_EXTENSIONS[suffix]
    if include_config:
        if name in CONFIG_FILENAMES:
            return CONFIG_FILENAMES[name]
        if suffix in CONFIG_EXTENSIONS:
            return CONFIG_EXTENSIONS[suffix]
    return None
