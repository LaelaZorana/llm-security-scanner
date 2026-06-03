"""
llm-security-scanner — security-test any LLM endpoint and produce a governance
package (vulnerability report + NIST AI RMF / ISO 42001 model card + risk
register).

Public API:

    from llm_security_scanner import Scanner, get_provider, load_probes
    result = Scanner(get_provider("stub")).run()
    print(result.severity_counts())
"""

from .models import (
    Finding,
    Probe,
    ProbeOutcome,
    ScanResult,
    Severity,
)
from .providers import Provider, StubProvider, OpenAIProvider, get_provider
from .detectors import DETECTORS, get_detector
from .engine import Scanner, load_probes, available_categories
from .reporting import (
    write_json_report,
    write_html_report,
    render_html_report,
    summary_table,
)
from .governance import (
    write_governance_package,
    write_model_card,
    write_risk_register,
    render_model_card,
    render_risk_register,
)

__version__ = "0.1.0"

__all__ = [
    "Severity",
    "Probe",
    "Finding",
    "ProbeOutcome",
    "ScanResult",
    "Provider",
    "StubProvider",
    "OpenAIProvider",
    "get_provider",
    "DETECTORS",
    "get_detector",
    "Scanner",
    "load_probes",
    "available_categories",
    "write_json_report",
    "write_html_report",
    "render_html_report",
    "summary_table",
    "write_governance_package",
    "write_model_card",
    "write_risk_register",
    "render_model_card",
    "render_risk_register",
    "__version__",
]
