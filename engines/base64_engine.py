import base64
import re


NAME = "Base64"


def decode(source: str) -> str:
    pattern = re.compile(
        r"""(["'])([A-Za-z0-9+/]{16,}={0,2})\1"""
    )

    changed = False

    def replace(match):
        nonlocal changed

        value = match.group(2)

        try:
            raw = base64.b64decode(
                value,
                validate=True
            )

            decoded = raw.decode("utf-8")

            printable = sum(
                1
                for char in decoded
                if char.isprintable()
                or char in "\r\n\t"
            )

            if decoded and printable / len(decoded) >= 0.8:
                changed = True
                return (
                    match.group(1)
                    + decoded
                    + match.group(1)
                )

        except Exception:
            pass

        return match.group(0)

    result = pattern.sub(
        replace,
        source
    )

    if not changed:
        raise RuntimeError(
            "ไม่พบ Base64 ที่สามารถถอดได้"
        )

    return result
