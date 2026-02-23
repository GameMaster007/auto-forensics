from __future__ import annotations

from dataclasses import dataclass, field
import importlib.util
import logging
from pathlib import Path
from typing import Protocol, Sequence

logger = logging.getLogger(__name__)

from .binary_analysis import analyze_binary
from .models import (
    ArtifactEvent,
    BinaryFeature,
    CaseReport,
    Finding,
    IOC,
    IOCEnrichment,
    TimelineEvent,
)


class ArtifactParserPlugin(Protocol):
    name: str

    @property
    def supported_suffixes(self) -> Sequence[str]:
        ...

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        ...


class BinaryAnalyzerPlugin(Protocol):
    name: str

    def analyze(self, binary_path: Path) -> BinaryFeature:
        ...


class FindingDetectorPlugin(Protocol):
    name: str

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        ...


class IOCEnricherPlugin(Protocol):
    name: str

    def enrich(self, ioc: IOC) -> IOCEnrichment | None:
        ...


class ReporterPlugin(Protocol):
    name: str
    format_name: str

    def render(self, report: CaseReport) -> str:
        ...


@dataclass(slots=True)
class DefaultBinaryAnalyzer:
    name: str = "default-heuristics"

    def analyze(self, binary_path: Path) -> BinaryFeature:
        return analyze_binary(binary_path)


@dataclass(slots=True)
class ArtifactParserRegistry:
    parsers: list[ArtifactParserPlugin] = field(default_factory=list)
    _suffix_index: dict[str, ArtifactParserPlugin] = field(default_factory=dict, init=False, repr=False)
    _name_index: dict[str, ArtifactParserPlugin] = field(default_factory=dict, init=False, repr=False)

    @staticmethod
    def _normalize_suffix(value: str) -> str:
        value = value.strip().lower()
        if not value:
            return ""
        return value if value.startswith(".") else f".{value}"

    def register(self, parser: ArtifactParserPlugin) -> None:
        self.parsers.append(parser)
        for raw_suffix in parser.supported_suffixes:
            suffix = self._normalize_suffix(raw_suffix)
            if suffix:
                self._suffix_index[suffix] = parser
        for raw_name in getattr(parser, "supported_names", ()):
            normalized = raw_name.strip().lower()
            if normalized:
                self._name_index[normalized] = parser

    def register_defaults(self) -> None:
        if self.parsers:
            return
        from .artifacts import (
            CsvArtifactParser,
            EvtxArtifactParser,
            JsonArtifactParser,
            MemoryDumpArtifactParser,
            MftArtifactParser,
            PcapArtifactParser,
            PrefetchArtifactParser,
            RegistryArtifactParser,
            TextArtifactParser,
        )

        self.register(JsonArtifactParser())
        self.register(CsvArtifactParser())
        self.register(TextArtifactParser())
        self.register(EvtxArtifactParser())
        self.register(PcapArtifactParser())
        self.register(PrefetchArtifactParser())
        self.register(RegistryArtifactParser())
        self.register(MftArtifactParser())
        self.register(MemoryDumpArtifactParser())

    def parser_for_suffix(self, suffix: str) -> ArtifactParserPlugin | None:
        return self._suffix_index.get(self._normalize_suffix(suffix))

    def parser_for_name(self, name: str) -> ArtifactParserPlugin | None:
        return self._name_index.get(name.strip().lower())

    def parser_for_path(self, path: Path) -> ArtifactParserPlugin | None:
        parser = self.parser_for_suffix(path.suffix)
        if parser is not None:
            return parser
        return self.parser_for_name(path.name)

    def parse(self, path: Path, max_text_bytes: int = 4 * 1024 * 1024) -> list[ArtifactEvent]:
        parser = self.parser_for_path(path)
        if parser is None:
            return []
        return parser.parse(path, max_text_bytes=max_text_bytes)


@dataclass(slots=True)
class DetectorRegistry:
    detectors: list[FindingDetectorPlugin] = field(default_factory=list)

    def register(self, detector: FindingDetectorPlugin) -> None:
        self.detectors.append(detector)

    def detect(
        self,
        artifacts: list[ArtifactEvent],
        binary_features: list[BinaryFeature],
        timeline: list[TimelineEvent],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.detect(artifacts, binary_features, timeline))
        return findings


@dataclass(slots=True)
class EnricherRegistry:
    enrichers: list[IOCEnricherPlugin] = field(default_factory=list)

    def register(self, enricher: IOCEnricherPlugin) -> None:
        self.enrichers.append(enricher)

    def enrich(self, ioc: IOC) -> list[IOCEnrichment]:
        output: list[IOCEnrichment] = []
        for enricher in self.enrichers:
            value = enricher.enrich(ioc)
            if value is not None:
                output.append(value)
        return output


@dataclass(slots=True)
class ReporterRegistry:
    reporters: list[ReporterPlugin] = field(default_factory=list)

    def register(self, reporter: ReporterPlugin) -> None:
        self.reporters.append(reporter)

    def render_all(self, report: CaseReport) -> dict[str, str]:
        payload: dict[str, str] = {}
        for reporter in self.reporters:
            payload[reporter.format_name] = reporter.render(report)
        return payload


@dataclass(slots=True)
class PluginRegistry:
    artifact_parsers: ArtifactParserRegistry = field(default_factory=ArtifactParserRegistry)
    binary_analyzers: list[BinaryAnalyzerPlugin] = field(default_factory=list)
    detectors: DetectorRegistry = field(default_factory=DetectorRegistry)
    enrichers: EnricherRegistry = field(default_factory=EnricherRegistry)
    reporters: ReporterRegistry = field(default_factory=ReporterRegistry)

    def register_defaults(self) -> None:
        self.artifact_parsers.register_defaults()
        if not self.binary_analyzers:
            self.binary_analyzers.append(DefaultBinaryAnalyzer())
        if not self.detectors.detectors:
            from .builtin_detectors import DefenderDetector, RDPDetector, SuricataDetector, SysmonDetector, ZeekDetector

            self.detectors.register(SysmonDetector())
            self.detectors.register(DefenderDetector())
            self.detectors.register(ZeekDetector())
            self.detectors.register(SuricataDetector())
            self.detectors.register(RDPDetector())

    def analyze_binary(self, path: Path) -> BinaryFeature:
        if not self.binary_analyzers:
            self.register_defaults()
        return self.binary_analyzers[0].analyze(path)

    def load_external_plugins(self, plugin_dirs: list[Path]) -> list[str]:
        loaded: list[str] = []
        for plugin_dir in plugin_dirs:
            if not plugin_dir.exists() or not plugin_dir.is_dir():
                continue
            for plugin_path in sorted(plugin_dir.glob("*.py")):
                module_name = f"auto_forensics_ext_{plugin_path.stem}_{abs(hash(plugin_path))}"
                try:
                    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
                    if spec is None or spec.loader is None:
                        logger.warning("Could not load plugin spec from %s", plugin_path)
                        continue
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                except Exception as exc:
                    logger.error("Failed to import plugin module %s: %s", plugin_path, exc)
                    continue

                register = getattr(module, "register", None)
                if callable(register):
                    try:
                        register(self)
                        loaded.append(str(plugin_path))
                        logger.debug("Loaded plugin: %s", plugin_path)
                    except Exception as exc:
                        logger.error("Plugin register() failed for %s: %s", plugin_path, exc)
                        continue
                else:
                    logger.warning("Plugin %s has no register() function, skipping", plugin_path)
        return loaded
