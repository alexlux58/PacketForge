from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Packet, Raw

ALLOWED_SCAPY_CLASSES: dict[str, type[Packet]] = {
    "Ether": Ether,
    "Dot1Q": Dot1Q,
    "ARP": ARP,
    "IP": IP,
    "IPv6": IPv6,
    "ICMP": ICMP,
    "ICMPv6EchoRequest": ICMPv6EchoRequest,
    "TCP": TCP,
    "UDP": UDP,
    "DNS": DNS,
    "DNSQR": DNSQR,
    "Raw": Raw,
}


class SafeScapyError(ValueError):
    """Raised when a Scapy expression is outside PacketForge's safe subset."""


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    message: str


def validate_scapy_expression(expression: str) -> ValidationResult:
    try:
        parse_scapy_expression(expression)
    except SafeScapyError as exc:
        return ValidationResult(False, str(exc))
    return ValidationResult(True, "Expression is valid.")


def parse_scapy_expression(expression: str) -> Packet:
    try:
        parsed = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as exc:
        raise SafeScapyError(f"syntax error: {exc.msg}") from exc
    evaluator = _SafeScapyEvaluator()
    value = evaluator.eval(parsed.body)
    if not isinstance(value, Packet):
        raise SafeScapyError("expression must produce a Scapy packet")
    return value


class _SafeScapyEvaluator:
    def eval(self, node: ast.AST) -> Any:
        if isinstance(node, ast.BinOp):
            return self._eval_binop(node)
        if isinstance(node, ast.Call):
            return self._eval_call(node)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return [self.eval(element) for element in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self.eval(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            result: dict[Any, Any] = {}
            for key, value in zip(node.keys, node.values, strict=True):
                if key is None:
                    raise SafeScapyError("expanded dictionary entries are not allowed")
                result[self.eval(key)] = self.eval(value)
            return result
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            operand = self.eval(node.operand)
            if isinstance(operand, (int, float)):
                return -operand
        if isinstance(node, ast.Name):
            raise SafeScapyError(f"name '{node.id}' is not allowed as a value")
        if isinstance(node, ast.Attribute):
            raise SafeScapyError("attribute access is not allowed")
        if isinstance(node, ast.Subscript):
            raise SafeScapyError("subscript access is not allowed")
        if isinstance(node, ast.Lambda):
            raise SafeScapyError("lambda expressions are not allowed")
        raise SafeScapyError(f"unsupported syntax: {type(node).__name__}")

    def _eval_binop(self, node: ast.BinOp) -> Packet:
        if not isinstance(node.op, ast.Div):
            raise SafeScapyError("only '/' packet layering is allowed")
        left = self.eval(node.left)
        right = self.eval(node.right)
        if not isinstance(left, Packet) or not isinstance(right, Packet):
            raise SafeScapyError("'/' can only combine Scapy packets")
        return left / right

    def _eval_call(self, node: ast.Call) -> Packet:
        if not isinstance(node.func, ast.Name):
            raise SafeScapyError("only direct approved Scapy class calls are allowed")
        class_name = node.func.id
        packet_class = ALLOWED_SCAPY_CLASSES.get(class_name)
        if packet_class is None:
            raise SafeScapyError(f"'{class_name}' is not an approved Scapy class")
        args = [self.eval(arg) for arg in node.args]
        kwargs: dict[str, Any] = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                raise SafeScapyError("expanded keyword arguments are not allowed")
            kwargs[keyword.arg] = self.eval(keyword.value)
        try:
            return packet_class(*args, **kwargs)
        except Exception as exc:
            raise SafeScapyError(f"{class_name} could not be built: {exc}") from exc
