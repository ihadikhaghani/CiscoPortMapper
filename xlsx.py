"""Minimal XLSX (Excel) writer using only the Python standard library.

``zipfile`` is enough to create a valid Office Open XML workbook.  The
writer supports several sheets, a bold frozen header row, an auto filter,
column widths and inline strings, which covers the exports of this tool.

No third-party packages are required.
"""

from __future__ import annotations

import math
import re
import zipfile
from typing import Iterable, Sequence
from xml.sax.saxutils import escape, quoteattr

_INVALID_XML = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
_INVALID_SHEET = re.compile(r"[\[\]:*?/\\]")
_CELL_LIMIT = 32767
_SAMPLE_ROWS = 200


def _clean(value: object) -> str:
    """Convert a cell value to safe XML text."""
    text = "" if value is None else str(value)
    text = _INVALID_XML.sub("", text)
    if len(text) > _CELL_LIMIT:
        text = text[:_CELL_LIMIT]
    return text


def _col_letter(index: int) -> str:
    letters = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _cell_xml(row: int, col: int, value: object, style: int) -> str:
    ref = f"{_col_letter(col)}{row}"
    if value is None or value == "":
        return f'<c r="{ref}" s="{style}"/>'
    if isinstance(value, bool):
        text = "TRUE" if value else "FALSE"
        return (
            f'<c r="{ref}" s="{style}" t="inlineStr"><is><t>{text}</t></is></c>'
        )
    if isinstance(value, int):
        return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
    if isinstance(value, float) and math.isfinite(value):
        return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
    text = escape(_clean(value))
    preserve = ' xml:space="preserve"' if text != text.strip() else ""
    return (
        f'<c r="{ref}" s="{style}" t="inlineStr">'
        f"<is><t{preserve}>{text}</t></is></c>"
    )


def _cols_xml(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    widths = []
    for index, header in enumerate(headers):
        longest = len(_clean(header))
        for row in rows[:_SAMPLE_ROWS]:
            if index < len(row):
                longest = max(longest, len(_clean(row[index])))
        widths.append(min(max(8, longest + 2), 60))
    parts = [
        f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(widths, 1)
    ]
    return "<cols>" + "".join(parts) + "</cols>"


def _sheet_xml(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    header_cells = "".join(
        _cell_xml(1, index, header, 1)
        for index, header in enumerate(headers, 1)
    )
    lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
        'state="frozen"/></sheetView></sheetViews>',
        '<sheetFormatPr defaultRowHeight="15"/>',
        _cols_xml(headers, rows),
        "<sheetData>",
        f'<row r="1" ht="18" customHeight="1">{header_cells}</row>',
    ]
    for row_index, row in enumerate(rows, 2):
        cells = "".join(
            _cell_xml(
                row_index,
                col_index,
                row[col_index - 1] if col_index - 1 < len(row) else "",
                2,
            )
            for col_index in range(1, len(headers) + 1)
        )
        lines.append(f'<row r="{row_index}">{cells}</row>')
    lines.append("</sheetData>")
    last_col = _col_letter(max(1, len(headers)))
    last_row = max(1, len(rows) + 1)
    lines.append(f'<autoFilter ref="A1:{last_col}{last_row}"/>')
    lines.append("</worksheet>")
    return "".join(lines)


def _sheet_names(names: Iterable[str]) -> list[str]:
    used: set[str] = set()
    result = []
    for index, name in enumerate(names, 1):
        base = _INVALID_SHEET.sub("_", str(name or "")).strip().strip("'")
        base = base[:31] or f"Sheet{index}"
        candidate = base
        counter = 2
        while candidate.lower() in used:
            suffix = f" ({counter})"
            candidate = base[: 31 - len(suffix)] + suffix
            counter += 1
        used.add(candidate.lower())
        result.append(candidate)
    return result


def _content_types(count: int) -> str:
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'spreadsheetml.worksheet+xml"/>'
        for index in range(1, count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/'
        'vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        + overrides
        + '<Override PartName="/xl/styles.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        "</Types>"
    )


def _root_rels() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def _workbook_xml(names: Sequence[str]) -> str:
    sheets = "".join(
        f"<sheet name={quoteattr(name)} sheetId=\"{index}\" r:id=\"rId{index}\"/>"
        for index, name in enumerate(names, 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<bookViews><workbookView activeTab="0"/></bookViews>'
        f"<sheets>{sheets}</sheets></workbook>"
    )


def _workbook_rels(count: int) -> str:
    rels = "".join(
        f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/'
        f'officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, count + 1)
    )
    rels += (
        f'<Relationship Id="rId{count + 1}" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + rels
        + "</Relationships>"
    )


_STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="2">'
    '<font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/></font>'
    "</fonts>"
    '<fills count="3">'
    '<fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/>'
    '<bgColor indexed="64"/></patternFill></fill>'
    "</fills>"
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/>'
    "</border></borders>"
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" '
    'borderId="0"/></cellStyleXfs>'
    '<cellXfs count="3">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" '
    'applyFont="1" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" '
    'applyAlignment="1"><alignment vertical="top"/></xf>'
    "</cellXfs>"
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/>'
    "</cellStyles>"
    "</styleSheet>"
)


def write_xlsx(path: str, sheets: Sequence[tuple]) -> None:
    """Write ``sheets`` to ``path`` as a valid .xlsx workbook.

    Each sheet is a ``(name, headers, rows)`` tuple.  ``headers`` is a
    sequence of column titles and ``rows`` is a sequence of value sequences.
    """
    prepared = []
    for name, headers, rows in sheets:
        headers = [str(header) for header in headers] or ["Value"]
        prepared.append((str(name), headers, [list(row) for row in rows]))
    if not prepared:
        raise ValueError("A workbook needs at least one sheet")

    names = _sheet_names(name for name, _, _ in prepared)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _content_types(len(prepared)))
        archive.writestr("_rels/.rels", _root_rels())
        archive.writestr("xl/workbook.xml", _workbook_xml(names))
        archive.writestr(
            "xl/_rels/workbook.xml.rels", _workbook_rels(len(prepared))
        )
        archive.writestr("xl/styles.xml", _STYLES)
        for index, (_name, headers, rows) in enumerate(prepared, 1):
            archive.writestr(
                f"xl/worksheets/sheet{index}.xml", _sheet_xml(headers, rows)
            )
