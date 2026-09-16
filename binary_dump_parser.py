#!/usr/bin/env python3
"""Binary dump analyzer and structured JSON exporter.

This utility is designed for raw binary dump files such as:
    202000152008_info_bin

It performs these steps in order:
1. Detects common compression headers (gzip / zlib)
2. Tries the most common binary serializers in sequence:
   - MessagePack
   - CBOR
   - BSON
3. Falls back to printable-string extraction if binary decoding fails
4. Writes a formatted JSON file next to the source file

Optional dependencies:
    pip install msgpack cbor2 pymongo
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import zlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import msgpack  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    msgpack = None

try:
    import cbor2  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    cbor2 = None

try:
    from bson import BSON  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    BSON = None


def detect_and_decompress(data: bytes) -> Tuple[bytes, Optional[str]]:
    """Return decompressed payload and compression label when detected."""
    if len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B:
        try:
            return gzip.decompress(data), "gzip"
        except Exception:
            return data, None

    if len(data) >= 2 and data[0] == 0x78 and data[1] in {0x01, 0x5E, 0x9C, 0xDA}:
        try:
            return zlib.decompress(data), "zlib"
        except Exception:
            return data, None

    return data, None


def clean_json_value(value: Any) -> Any:
    """Convert Python values into JSON-safe representations."""
    if isinstance(value, dict):
        return {str(k): clean_json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_json_value(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def try_messagepack(data: bytes) -> Any:
    if msgpack is None:
        raise RuntimeError("msgpack not installed")
    try:
        return msgpack.unpackb(data, raw=False, strict_map_key=False, unicode_errors="replace")
    except Exception:
        pass

    unpacker = msgpack.Unpacker(raw=False, strict_map_key=False, unicode_errors="replace")
    unpacker.feed(data)
    objs = []
    try:
        for obj in unpacker:
            objs.append(obj)
    except Exception:
        pass

    if objs:
        if isinstance(objs[0], dict):
            if len(objs) == 1:
                return objs[0]
            return {"root": objs[0], "stream_records": objs[1:]}
        return objs[0] if len(objs) == 1 else objs
    raise ValueError("MessagePack unpacking failed")


def try_cbor(data: bytes) -> Any:
    if cbor2 is None:
        raise RuntimeError("cbor2 not installed")
    return cbor2.loads(data)


def try_bson(data: bytes) -> Any:
    if BSON is None:
        raise RuntimeError("bson not installed")
    return BSON(data).decode()


def decode_with_serializers(data: bytes) -> Optional[Tuple[str, Any]]:
    """Attempt deserialization using common binary formats, preferring dict structures."""
    parsers: List[Tuple[str, Any]] = [
        ("messagepack", try_messagepack),
        ("cbor", try_cbor),
        ("bson", try_bson),
    ]

    candidate_offsets = [0]
    max_scan = min(64, len(data) - 4)
    for i in range(1, max_scan):
        if (0x80 <= data[i] <= 0x8F) or data[i] in {0xDE, 0xDF, 0xA7, 0x90, 0x91, 0x92, 0x93, 0x94}:
            candidate_offsets.append(i)
    for common_off in (4, 8, 11, 12, 16, 24, 32):
        if common_off < max_scan and common_off not in candidate_offsets:
            candidate_offsets.append(common_off)

    # Pass 1: look for a structured dictionary (root object)
    for offset in sorted(candidate_offsets):
        sliced = data[offset:] if offset > 0 else data
        for parser_name, parser_fn in parsers:
            try:
                parsed = parser_fn(sliced)
                if parsed is not None:
                    cleaned = clean_json_value(parsed)
                    if isinstance(cleaned, dict) and len(cleaned) > 0:
                        label = parser_name if offset == 0 else f"{parser_name} (offset 0x{offset:02x})"
                        return label, cleaned
            except Exception:
                continue

    # Pass 2: fallback to array/stream
    for offset in sorted(candidate_offsets):
        sliced = data[offset:] if offset > 0 else data
        for parser_name, parser_fn in parsers:
            try:
                parsed = parser_fn(sliced)
                if parsed is not None:
                    cleaned = clean_json_value(parsed)
                    if isinstance(cleaned, list) and len(cleaned) > 0:
                        label = parser_name if offset == 0 else f"{parser_name} (offset 0x{offset:02x})"
                        return label, cleaned
            except Exception:
                continue

    return None


def fallback_string_extraction(data: bytes, minimum_length: int = 3) -> List[str]:
    """Extract printable ASCII/UTF-8-like text from otherwise opaque binary data."""
    candidates: List[str] = []

    # ASCII-based printable strings (minimum 3 char)
    ascii_matches = re.findall(rb"[\x20-\x7E]{%d,}" % minimum_length, data)
    for match in ascii_matches:
        decoded = match.decode("ascii", errors="ignore").strip()
        if decoded and len(decoded) >= minimum_length:
            candidates.append(decoded)

    # UTF-8 tolerant fallback: decode the whole stream and scan for printable chunks
    try:
        text = data.decode("utf-8", errors="ignore")
        utf8_matches = re.findall(r"[\x20-\x7E]{%d,}" % minimum_length, text)
        for match in utf8_matches:
            cleaned = match.strip()
            if cleaned and len(cleaned) >= minimum_length and cleaned not in candidates:
                candidates.append(cleaned)
    except Exception:
        pass

    seen = set()
    ordered: List[str] = []
    for item in candidates:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)

    return ordered


def build_result(source_file: Path, raw_data: bytes) -> Dict[str, Any]:
    """Analyze the file and return a JSON-serializable structure."""
    decompressed, compression = detect_and_decompress(raw_data)
    payload = decompressed if decompression_necessary(raw_data) else raw_data

    result: Dict[str, Any] = {
        "source_file": str(source_file.name),
        "status": "error",
        "size_bytes": len(raw_data),
        "compression_detected": compression,
        "parser_used": None,
        "data": None,
        "extracted_strings": [],
    }

    if decompression_necessary(raw_data):
        result["decompressed_size_bytes"] = len(payload)

    parsed = decode_with_serializers(payload)
    if parsed is not None:
        parser_name, decoded = parsed
        result["status"] = "deserialized"
        result["parser_used"] = parser_name
        result["data"] = decoded
        return result

    extracted = fallback_string_extraction(payload)
    result["status"] = "partial_extraction"
    result["extracted_strings"] = extracted
    result["data"] = None
    return result


def decompression_necessary(data: bytes) -> bool:
    if len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B:
        return True
    if len(data) >= 2 and data[0] == 0x78 and data[1] in {0x01, 0x5E, 0x9C, 0xDA}:
        return True
    return False


def format_hexdump(data: bytes, offset: int = 0, length: Optional[int] = None) -> str:
    """Produce a canonical 16-byte hex dump string (like hexdump -C)."""
    if not data:
        return "Empty binary data."
    if offset < 0 or offset >= len(data):
        return f"Offset out of range (0..{len(data)-1})"

    end = len(data) if length is None else min(len(data), offset + length)
    slice_data = data[offset:end]

    lines: List[str] = []
    for i in range(0, len(slice_data), 16):
        chunk = slice_data[i:i + 16]
        curr_offset = offset + i

        hex_parts = [f"{b:02x}" for b in chunk]
        if len(hex_parts) > 8:
            hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
        else:
            hex_str = " ".join(hex_parts)

        padded_hex = f"{hex_str:<49}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{curr_offset:08x}  {padded_hex}  |{ascii_str}|")

    return "\n".join(lines)


def write_json_result(source_file: Path, payload: Dict[str, Any]) -> Path:
    output_path = source_file.parent / f"{source_file.name}.json"
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze a structured binary dump and export JSON / raw data.")
    parser.add_argument("input_file", help="Path to the binary file to inspect (example: 202000152008_info_bin)")
    parser.add_argument("-o", "--output", help="Optional output JSON file path. Defaults to '<input>.json'")
    parser.add_argument(
        "-d", "--dump-raw",
        nargs="?",
        const=True,
        default=False,
        help="Export decompressed payload to binary file (defaults to '<input>.raw.bin')"
    )
    parser.add_argument(
        "-s", "--strings-only",
        nargs="?",
        const=True,
        default=False,
        help="Extract printable strings to stdout or write to a specified .txt file"
    )
    parser.add_argument(
        "-x", "--hexdump",
        action="store_true",
        help="Display formatted canonical hex dump in terminal (hexdump -C style)"
    )
    parser.add_argument(
        "--offset",
        type=lambda v: int(v, 0),
        default=0,
        help="Starting byte offset for --hexdump (dec or hex e.g. 0x10)"
    )
    parser.add_argument(
        "--length",
        type=int,
        default=None,
        help="Max number of bytes to show in --hexdump"
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip creating the default .json output file"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_file = Path(args.input_file).expanduser().resolve()

    if not source_file.exists():
        raise FileNotFoundError(f"File not found: {source_file}")

    try:
        raw_data = source_file.read_bytes()
        decompressed, compression = detect_and_decompress(raw_data)
        payload = decompressed if decompression_necessary(raw_data) else raw_data

        # 1. Handle Hex Dump mode if requested
        if args.hexdump:
            print(f"--- Hex Dump: {source_file.name} ({len(payload)} bytes, compression: {compression or 'none'}) ---")
            print(format_hexdump(payload, offset=args.offset, length=args.length))
            if args.no_json:
                return 0

        # 2. Handle Strings-only mode if requested
        if args.strings_only:
            strings = fallback_string_extraction(payload)
            if isinstance(args.strings_only, str):
                out_txt = Path(args.strings_only).expanduser().resolve()
                out_txt.write_text("\n".join(strings) + "\n", encoding="utf-8")
                print(f"Extracted {len(strings)} strings to: {out_txt}")
            else:
                print(f"--- Extracted Strings ({len(strings)}) ---")
                for s in strings:
                    print(s)
            if args.no_json:
                return 0

        # 3. Handle Raw / Decompressed export if requested
        if args.dump_raw:
            if isinstance(args.dump_raw, str):
                raw_out = Path(args.dump_raw).expanduser().resolve()
            else:
                suffix = f".{compression}.bin" if compression else ".raw.bin"
                raw_out = source_file.parent / f"{source_file.name}{suffix}"
            raw_out.write_bytes(payload)
            print(f"Dumped raw payload ({len(payload)} bytes) to: {raw_out}")
            if args.no_json:
                return 0

        # 4. Standard JSON analysis & export
        if not args.no_json:
            result = build_result(source_file, raw_data)
            output_path = Path(args.output).expanduser().resolve() if args.output else write_json_result(source_file, result)

            if args.output:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            print(f"Saved JSON result to: {output_path}")
            print(f"Status: {result['status']}")
            if result.get("parser_used"):
                print(f"Parser: {result['parser_used']}")
            if result.get("extracted_strings"):
                print(f"Extracted strings: {len(result['extracted_strings'])}")

        return 0
    except Exception as exc:  # pragma: no cover - top-level guard
        print(f"ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

