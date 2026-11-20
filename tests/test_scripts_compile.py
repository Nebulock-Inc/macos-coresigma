"""Every script and collector the docs tell users to run at least compiles."""
import py_compile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("path", sorted((ROOT / "scripts").glob("*.py")) + sorted((ROOT / "collectors").glob("*.py")),
                         ids=lambda p: p.name)
def test_compiles(path, tmp_path):
    py_compile.compile(str(path), cfile=str(tmp_path / "out.pyc"), doraise=True)


# Options that take a value (-u root, -e K=V, -w dir, -n 50, --tail 50); bare ones (-t, -it, --tail=5) take none.
DOCKER_FLAGS = r"(?:(?:--tail|--user|--env|--workdir|-[uewn]) +\S+ +|--?[\w-]+(?:=\S+)? +)*"
DOCKER_CMD = r"docker (?:exec|logs|restart|stop|start|rm|inspect|kill) +" + DOCKER_FLAGS + r"([\w-]+)"


@pytest.mark.parametrize("line,name", [
    ("docker exec -it coresigma-splunk sh", "coresigma-splunk"),
    ("docker exec -t coresigma-splunk sh", "coresigma-splunk"),
    ("docker exec -e FOO=1 coresigma-splunk sh", "coresigma-splunk"),
    ("docker exec -u root coresigma-splunk sh", "coresigma-splunk"),
    ("docker logs --tail 50 coresigma-kibana", "coresigma-kibana"),
    ("docker logs --tail=5 -t coresigma-kibana", "coresigma-kibana"),
])
def test_docker_cmd_pattern(line, name):
    import re
    assert re.search(DOCKER_CMD, line).group(1) == name


def test_docker_commands_name_compose_containers():
    """Scripts and docs reach the bench containers by the compose file's container_name."""
    import re
    names = set(re.findall(r"^\s+container_name:\s*(\S+)", (ROOT / "docker-compose.yml").read_text(), re.M))
    used = set()
    patterns = ("scripts/**/*", "collectors/**/*", "simulations/**/*", "docs/*.md", "*.md")
    paths = [p for pattern in patterns for p in ROOT.glob(pattern) if p.is_file()]
    for path in paths:
        text = path.read_text(errors="ignore")
        used |= set(re.findall(DOCKER_CMD, text))
        used |= set(re.findall(r'"docker", "(?:exec|logs|restart|stop|start|rm|inspect|kill)", "([\w-]+)"', text))
        used |= set(re.findall(r"docker cp \S+ ([\w-]+):", text))
    assert used and used <= names, f"not a container_name in docker-compose.yml: {sorted(used - names)}"
