# Secure-Vibe — one-shot deep-scan image
# Includes the optional deep engines (semgrep, pip-audit) that the local install
# treats as best-effort. Build:  docker build -t secure-vibe .
# Scan a repo:   docker run --rm -v /path/to/repo:/src secure-vibe sast /src --fail-on high
# Validate code: docker run --rm secure-vibe validate --code 'eval(user_input)'

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt cli.py config.yaml VERSION ./
COPY core/ ./core/
COPY rules/ ./rules/
COPY blacklist/ ./blacklist/
COPY templates/ ./templates/
COPY hooks/ ./hooks/

# pyyaml is the only hard dependency; semgrep/pip-audit enable the deep engines,
# tree-sitter (+ grammars) enables the js/java xast engine (core/xast.py)
RUN pip install --no-cache-dir pyyaml semgrep pip-audit tree-sitter tree-sitter-javascript

ENTRYPOINT ["python", "cli.py"]
