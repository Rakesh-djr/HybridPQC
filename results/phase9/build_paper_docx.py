from pathlib import Path
import re

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "results" / "phase9" / "research_paper_draft.md"
OUTPUT = ROOT / "results" / "phase9" / "research_paper_draft.docx"


def set_cell_shading(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shade = OxmlElement("w:shd")
    shade.set(qn("w:fill"), fill)
    tc_pr.append(shade)


def set_cell_margins(cell, top=100, start=105, bottom=100, end=105):
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    margins = tc_pr.first_child_found_in("w:tcMar")
    if margins is None:
        margins = OxmlElement("w:tcMar")
        tc_pr.append(margins)
    for edge, value in (("top", top), ("start", start),
                        ("bottom", bottom), ("end", end)):
        node = margins.find(qn(f"w:{edge}"))
        if node is None:
            node = OxmlElement(f"w:{edge}")
            margins.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_table_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    repeat = OxmlElement("w:tblHeader")
    repeat.set(qn("w:val"), "true")
    tr_pr.append(repeat)


def set_no_split(row):
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def add_page_field(paragraph):
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = " PAGE "
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    display = OxmlElement("w:t")
    display.text = "1"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instr, separate, display, end])


def add_inline(paragraph, text):
    text = text.replace("\\[", "").replace("\\]", "")
    if "\\frac" in text:
        text = "T_transfer(p) = 8 * B_hello(p) / R_kbps milliseconds"
    pattern = re.compile(r"(\*\*.+?\*\*|\*.+?\*|`.+?`|\[[^\]]+\]\([^)]+\))")
    pos = 0
    for match in pattern.finditer(text):
        if match.start() > pos:
            paragraph.add_run(text[pos:match.start()])
        token = match.group(0)
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            run.bold = True
        elif token.startswith("*"):
            run = paragraph.add_run(token[1:-1])
            run.italic = True
        elif token.startswith("`"):
            run = paragraph.add_run(token[1:-1])
            run.font.name = "Consolas"
            run.font.size = Pt(9.5)
        else:
            link = re.match(r"\[([^\]]+)\]\(([^)]+)\)", token)
            paragraph.add_run(f"{link.group(1)} ({link.group(2)})")
        pos = match.end()
    if pos < len(text):
        paragraph.add_run(text[pos:])


def split_table_row(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def add_table(document, lines):
    rows = [split_table_row(line) for line in lines]
    if len(rows) > 1 and all(re.fullmatch(r":?-{3,}:?", c) for c in rows[1]):
        rows.pop(1)
    cols = max(map(len, rows))
    table = document.add_table(rows=1, cols=cols)
    table.style = "Table Grid"
    table.autofit = True
    for row_index, values in enumerate(rows):
        cells = table.rows[0].cells if row_index == 0 else table.add_row().cells
        set_no_split(table.rows[row_index])
        for col in range(cols):
            cell = cells[col]
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            set_cell_margins(cell)
            cell.text = ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.line_spacing = 1.0
            add_inline(p, values[col] if col < len(values) else "")
            for run in p.runs:
                run.font.name = "Arial"
                run.font.size = Pt(8.5)
                if row_index == 0:
                    run.bold = True
                    run.font.color.rgb = RGBColor(255, 255, 255)
            if row_index == 0:
                set_cell_shading(cell, "233B5D")
            elif row_index % 2 == 0:
                set_cell_shading(cell, "F2F5F8")
        if row_index == 0:
            set_repeat_table_header(table.rows[row_index])
    document.add_paragraph().paragraph_format.space_after = Pt(2)


def configure(document):
    section = document.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = Inches(0.72)
    section.bottom_margin = Inches(0.72)
    section.left_margin = Inches(0.78)
    section.right_margin = Inches(0.78)

    styles = document.styles
    normal = styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor(0, 0, 0)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.08
    for name, size in (("Title", 19), ("Heading 1", 14),
                       ("Heading 2", 12), ("Heading 3", 11)):
        style = styles[name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.space_before = Pt(12 if name != "Title" else 0)
        style.paragraph_format.space_after = Pt(5)

    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = header.add_run("HYBRIDPQC  |  RESEARCH PAPER DRAFT")
    run.font.name = "Arial"
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(90, 90, 90)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("Phase 9 manuscript draft  •  ")
    add_page_field(footer)
    for run in footer.runs:
        run.font.name = "Arial"
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor(90, 90, 90)


def main():
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    doc = Document()
    configure(doc)
    i = 0
    author_block = False
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        if line.startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            add_table(doc, table_lines)
            continue
        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2).strip()
            p = doc.add_paragraph(style="Title" if title.startswith("An Experimental Study") else f"Heading {min(level, 3)}")
            if title.startswith("An Experimental Study"):
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            add_inline(p, title)
            author_block = title.startswith("An Experimental Study")
            i += 1
            continue
        if author_block and (line.startswith("**Rakesh") or line.startswith("Department of")):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            add_inline(p, line.replace("**", ""))
            if line.startswith("Department"):
                for run in p.runs:
                    run.font.size = Pt(9.5)
            i += 1
            continue
        author_block = False
        numbered = re.match(r"^\d+\.\s+(.+)$", line)
        bulleted = re.match(r"^-\s+(.+)$", line)
        if numbered:
            p = doc.add_paragraph(style="List Number")
            add_inline(p, numbered.group(1))
        elif bulleted:
            p = doc.add_paragraph(style="List Bullet")
            add_inline(p, bulleted.group(1))
        else:
            p = doc.add_paragraph()
            if line.startswith("\\[") or "\\frac" in line:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            add_inline(p, line)
        i += 1

    doc.core_properties.title = "An Experimental Study of Policy-Driven Crypto-Agility"
    doc.core_properties.author = "Rakesh Puttala"
    doc.core_properties.subject = "Phase 9 research paper draft for the HybridPQC project"
    doc.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
