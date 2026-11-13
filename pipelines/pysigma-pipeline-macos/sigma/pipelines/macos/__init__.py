"""macOS pySigma pipeline."""

from .esf import macos_esf_ecs
from .falcon import macos_falcon
from .ul import macos_ul_ecs, macos_ul_raw

# Factories, not instances (SigmaHQ convention): each conversion builds its own pipeline.
pipelines = {
    "macos_esf_ecs": macos_esf_ecs,
    "macos_falcon": macos_falcon,
    "macos_ul_ecs": macos_ul_ecs,
    "macos_ul_raw": macos_ul_raw,
}
