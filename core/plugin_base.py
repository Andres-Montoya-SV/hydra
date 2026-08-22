"""Base class and registry for reconnaissance tool plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from core.logger import get_logger
from core.models import PipelineContext, ToolInfo, ToolStatus

if TYPE_CHECKING:
    from config.settings import Settings


@dataclass
class PluginResult:
    """Result returned by a plugin execution."""

    success: bool
    output_path: Path | None = None
    lines_produced: int = 0
    message: str = ""
    data: dict | None = None
    skipped: bool = False


class ReconPlugin(ABC):
    """Abstract base for all reconnaissance tool plugins.

    Subclasses must set class attributes and implement run().
    Registration happens automatically via __init_subclass__.
    """

    name: ClassVar[str]
    display_name: ClassVar[str]
    required: ClassVar[bool] = False
    external_dependency: ClassVar[bool] = True
    stage_order: ClassVar[int] = 100
    # Whether a plugin's result may be replayed from the result cache for
    # identical input. Must be False for plugins whose entire purpose is to
    # re-check a live, time-varying network property (e.g. current TCP port
    # state) — caching such a result defeats "verification" by silently
    # replaying a stale observation instead of re-probing the target.
    cacheable: ClassVar[bool] = True
    # Declarative collector contract. Artifacts remain the primary output;
    # these fields tell the runner what the plugin is allowed to produce and
    # whether it may touch the network.
    produces: ClassVar[tuple[str, ...]] = ()
    followup_kinds: ClassVar[tuple[str, ...]] = ()
    capability: ClassVar[str] = ""
    active_collection: ClassVar[bool] = False
    strict_opsec_allowed: ClassVar[bool] = False
    _registry: ClassVar[list[type[ReconPlugin]]] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "name") and cls.name:
            ReconPlugin._registry.append(cls)

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.logger = get_logger(self.name)

    @classmethod
    def all_plugins(cls) -> list[type[ReconPlugin]]:
        """Return all registered plugin classes sorted by stage order."""
        return sorted(cls._registry, key=lambda p: p.stage_order)

    @classmethod
    def get_plugin(cls, name: str) -> type[ReconPlugin] | None:
        for plugin_cls in cls._registry:
            if plugin_cls.name == name:
                return plugin_cls
        return None

    @abstractmethod
    def is_enabled(self) -> bool:
        """Return whether this plugin should run based on configuration."""

    @abstractmethod
    def get_binary_path(self) -> Path:
        """Return configured path to the external tool binary."""

    @abstractmethod
    def get_install_hint(self) -> str:
        """Return human-readable installation instructions."""

    @abstractmethod
    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        """Execute the tool and return results."""

    def build_tool_info(self) -> ToolInfo:
        return ToolInfo(
            name=self.name,
            display_name=self.display_name,
            required=self.required,
            enabled=self.is_enabled(),
        )

    def update_status(self, context: PipelineContext, status: ToolStatus, **kwargs: object) -> None:
        info = context.tool_states.setdefault(self.name, self.build_tool_info())
        info.status = status
        for key, value in kwargs.items():
            if hasattr(info, key):
                setattr(info, key, value)
