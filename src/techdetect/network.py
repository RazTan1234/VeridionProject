from techdetect.models import Signal


def resolve_dns(domain: str) -> list[Signal]:
    raise NotImplementedError


def inspect_certificate(domain: str) -> list[Signal]:
    raise NotImplementedError
