"""
Advisory decisioning layer.

Provides deterministic, explainable decision-making for CVE advisories
using a priority-ordered rule chain.
"""
from .rules import Rule, Decision, get_default_rules
from .rule_engine import RuleEngine
from .state_machine import AdvisoryStateMachine, StateType
from .explainer import DecisionExplainer


__all__ = [
    'Rule',
    'Decision',
    'RuleEngine',
    'AdvisoryStateMachine',
    'StateType',
    'DecisionExplainer',
    'get_default_rules',
]
