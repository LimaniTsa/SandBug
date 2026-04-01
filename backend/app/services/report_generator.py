from __future__ import annotations
import math
from datetime import datetime, timezone
from fpdf import FPDF


#  Helpers 

def _fmt(b) -> str:
    try:
        b = int(b or 0)
    except (TypeError, ValueError):
        return '-'
    if b < 1024:       return f'{b} B'
    if b < 1_048_576:  return f'{b/1024:.1f} KB'
    return f'{b/1_048_576:.1f} MB'


_UNICODE_REPLACEMENTS = str.maketrans({
    '\u2014': '-',    # em dash
    '\u2013': '-',    # en dash
    '\u2018': "'",    # left single quote
    '\u2019': "'",    # right single quote
    '\u201c': '"',    # left double quote
    '\u201d': '"',    # right double quote
    '\u2026': '...',  # ellipsis
    '\u2022': '*',    # bullet
    '\u00b7': '.',    # middle dot
    '\u00a0': ' ',    # non-breaking space
})


def _s(v, fallback='-') -> str:
    """Safe string — strips None, sanitizes Unicode for PDF core fonts."""
    s = str(v).strip() if v is not None else fallback
    if not s:
        return fallback
    s = s.translate(_UNICODE_REPLACEMENTS)
    return s.encode('latin-1', errors='replace').decode('latin-1')


def _risk_color(level: str):
    return {
        'critical': (192, 57,  43),
        'high':     (211, 84,   0),
        'medium':   (184, 134,  11),
        'low':      ( 30, 126,  52),
        'clean':    ( 30, 126,  52),
    }.get((level or '').lower(), (85, 85, 85))


def _machine_name(hex_str: str) -> str:
    m = {
        '0x14c':  'x86 (32-bit)',
        '0x8664': 'x86-64 (64-bit)',
        '0x1c0':  'ARM',
        '0xaa64': 'ARM64',
        '0x200':  'Intel Itanium',
    }
    return m.get((hex_str or '').lower(), _s(hex_str))


def _subsystem_name(val) -> str:
    m = {
        1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
        5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE GUI',
        10: 'EFI Application', 14: 'Xbox',
    }
    try:
        return m.get(int(val), f'Unknown ({val})')
    except Exception:
        return _s(val)


def _fmt_timestamp(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime('%d %b %Y, %H:%M UTC')
    except Exception:
        return _s(ts)


def _dll_chars(hex_str: str) -> str:
    try:
        val = int(hex_str, 16)
    except Exception:
        return _s(hex_str)
    flags = []
    if val & 0x0040: flags.append('ASLR')
    if val & 0x0100: flags.append('Force Integrity')
    if val & 0x0400: flags.append('NX/DEP')
    if val & 0x1000: flags.append('Guard CF')
    if val & 0x8000: flags.append('Terminal Server')
    return ', '.join(flags) if flags else f'None (0x{val:04x})'


def _interesting_strings(strings_list: list, max_count: int = 40) -> list:
    """Return strings that look relevant for malware analysis, prioritised."""
    keywords = [
        'http', 'cmd', 'powershell', 'reg', 'hkey', 'system32',
        'execute', 'inject', 'shell', '.exe', '.dll', '.bat', '.ps1',
        'password', 'token', 'crypt', 'decrypt', 'encrypt', 'base64',
        'socket', 'connect', 'download', 'upload', 'ftp', 'proxy',
        'admin', 'root', 'bypass', 'disable', 'hook', 'vb', 'wscript',
        'taskkill', 'net use', 'schtasks', 'CreateProcess', 'VirtualAlloc',
    ]
    priority, others = [], []
    for s in strings_list:
        lower = s.lower()
        if any(kw in lower for kw in keywords):
            priority.append(s)
        else:
            others.append(s)
    result = priority[:max_count]
    if len(result) < max_count:
        result += others[:max_count - len(result)]
    return result[:max_count]


#  PDF class 

_CALIBRI_LOADED = False  # module-level flag so we only warn once


class ReportPDF(FPDF):
    def __init__(self, title: str, generated: str):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=15)
        self._title     = title
        self._generated = generated
        self._body_font = 'Helvetica'   # fallback; updated below if Calibri loads
        self._load_calibri()
        self.add_page()

    def set_font(self, family='', style='', size=0):
        """Substitute loaded body font for Helvetica when a Unicode font is available."""
        if family and family.lower() == 'helvetica' and self._body_font in ('Calibri', 'DejaVu'):
            family = self._body_font
        super().set_font(family, style, size)

    def _load_calibri(self):
        global _CALIBRI_LOADED
        import os

        # Try Calibri on Windows
        calibri_dir = r'C:\Windows\Fonts'
        calibri_files = {
            '':  'calibri.ttf',
            'B': 'calibrib.ttf',
            'I': 'calibrii.ttf',
            'BI':'calibriz.ttf',
        }
        try:
            for style, fname in calibri_files.items():
                path = os.path.join(calibri_dir, fname)
                if not os.path.exists(path):
                    raise FileNotFoundError
                self.add_font('Calibri', style, path)
            self._body_font = 'Calibri'
            _CALIBRI_LOADED = True
            return
        except Exception:
            pass

        # Try DejaVu on Linux (supports Unicode)
        dejavu_dir = '/usr/share/fonts/truetype/dejavu'
        dejavu_files = {
            '':  'DejaVuSans.ttf',
            'B': 'DejaVuSans-Bold.ttf',
            'I': 'DejaVuSans-Oblique.ttf',
            'BI':'DejaVuSans-BoldOblique.ttf',
        }
        try:
            for style, fname in dejavu_files.items():
                path = os.path.join(dejavu_dir, fname)
                if not os.path.exists(path):
                    raise FileNotFoundError
                self.add_font('DejaVu', style, path)
            self._body_font = 'DejaVu'
            return
        except Exception:
            pass  # fall back to Helvetica with sanitized text

    def _font(self, style='', size=10):
        """Set body font (Calibri if available, else Helvetica)."""
        self.set_font(self._body_font, style, size)

    def header(self):
        self._font('', 7)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, f'SandBug Analysis Report  |  {self._generated}',
                  new_x='LMARGIN', new_y='NEXT')
        self.ln(3)
        self.set_draw_color(220, 220, 220)
        self.set_line_width(0.2)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-12)
        self._font('', 7)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, f'SandBug Malware Analysis Platform  |  Page {self.page_no()}',
                  align='C', new_x='LMARGIN', new_y='NEXT')

    #  Primitives 

    def section_heading(self, text: str, accent_color=(79, 70, 229)):
        self.ln(3)
        y = self.get_y()
        # Colored left accent bar
        self.set_fill_color(*accent_color)
        self.rect(15, y, 2.5, 5.5, style='F')
        # Heading text
        self.set_x(20)
        self._font('B', 9)
        self.set_text_color(0, 0, 0)
        self.cell(0, 5.5, text.upper(), new_x='LMARGIN', new_y='NEXT')
        self.set_draw_color(210, 210, 215)
        self.set_line_width(0.3)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def sub_heading(self, text: str):
        self._font('B', 9)
        self.set_text_color(0, 0, 0)
        self.cell(0, 5.5, _s(text), new_x='LMARGIN', new_y='NEXT')
        self.set_draw_color(220, 220, 220)
        self.set_line_width(0.2)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(2.5)

    def kv_row(self, label: str, value: str, mono=True):
        """Key-value row: bold label left, value right."""
        self._font('B', 8)
        self.set_text_color(0, 0, 0)
        self.cell(42, 5.5, _s(label), new_x='RIGHT', new_y='TOP')
        if mono:
            self.set_font('Courier', '', 8)
        else:
            self._font('', 8)
        self.set_text_color(20, 20, 20)
        val = _s(value)
        if len(val) > 76:
            val = val[:73] + '...'
        self.multi_cell(138, 5.5, val, new_x='LMARGIN', new_y='NEXT')

    def divider(self, thick=False):
        if thick:
            self.set_draw_color(30, 30, 30)
        else:
            self.set_draw_color(210, 210, 210)
        self.set_line_width(0.5 if thick else 0.2)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(3)

    def table(self, headers: list, rows: list, col_widths: list = None):
        """Table with styled header row and alternating row shading."""
        if not rows:
            self._font('I', 8)
            self.set_text_color(80, 80, 80)
            self.cell(0, 5, 'None recorded.', new_x='LMARGIN', new_y='NEXT')
            self.set_text_color(0, 0, 0)
            return

        page_w = 180
        if col_widths is None:
            w = page_w / len(headers)
            col_widths = [w] * len(headers)

        # Header row
        self._font('B', 7.5)
        self.set_text_color(0, 0, 0)
        self.set_fill_color(230, 230, 238)
        for i, h in enumerate(headers):
            nx = 'RIGHT' if i < len(headers) - 1 else 'LMARGIN'
            ny = 'TOP'   if i < len(headers) - 1 else 'NEXT'
            self.cell(col_widths[i], 6, h.upper(), border='B', fill=True,
                      new_x=nx, new_y=ny)

        # Data rows
        self.set_font('Courier', '', 7.5)
        self.set_text_color(15, 15, 15)
        for idx, row in enumerate(rows):
            if self.get_y() > 265:
                self.add_page()
            shade = idx % 2 == 1
            if shade:
                self.set_fill_color(246, 246, 250)
            for i, cell_val in enumerate(row):
                val = _s(cell_val)
                max_ch = max(3, int(col_widths[i] / 1.75))
                if len(val) > max_ch:
                    val = val[:max_ch - 2] + '..'
                nx = 'RIGHT' if i < len(row) - 1 else 'LMARGIN'
                ny = 'TOP'   if i < len(row) - 1 else 'NEXT'
                self.cell(col_widths[i], 5, val, border='B', fill=shade,
                          new_x=nx, new_y=ny)
        self.ln(2)
        self.set_fill_color(255, 255, 255)
        self.set_text_color(0, 0, 0)

    def note(self, text: str):
        self._font('I', 8)
        self.set_text_color(60, 60, 60)
        self.cell(0, 5, _s(text), new_x='LMARGIN', new_y='NEXT')
        self.set_text_color(0, 0, 0)

    def bullet_list(self, items: list, mono=False):
        for item in items:
            val = _s(item)
            if len(val) > 92:
                val = val[:89] + '...'
            if mono:
                self.set_font('Courier', '', 8)
            else:
                self._font('', 8)
            self.set_text_color(10, 10, 10)
            self.cell(6, 5, '-', new_x='RIGHT', new_y='TOP')
            self.cell(0, 5, val, new_x='LMARGIN', new_y='NEXT')
        self.ln(2)

    #  Charts 

    def _draw_polygon(self, pts: list, style: str):
        """Draw a polygon; falls back to line-by-line if polygon() unavailable."""
        try:
            self.polygon(pts, style=style)
        except Exception:
            self.set_line_width(0.3)
            for j in range(len(pts)):
                x1, y1 = pts[j]
                x2, y2 = pts[(j + 1) % len(pts)]
                self.line(x1, y1, x2, y2)

    def draw_radar_chart(self, cx: float, cy: float, radius: float,
                         labels: list, values: list, title: str = ''):
        """Draw a radar/spider chart centered at (cx, cy) with given radius (mm)."""
        n = len(labels)
        if n < 3:
            return
        norm   = [min(max(float(v or 0), 0), 100) / 100 for v in values]
        angles = [2 * math.pi * i / n - math.pi / 2 for i in range(n)]

        # Title
        if title:
            self.set_font('Helvetica', 'B', 7)
            self.set_text_color(100, 100, 100)
            self.set_xy(cx - radius - 5, cy - radius - 10)
            self.cell((radius + 5) * 2 + 10, 5, title.upper(),
                      align='C', new_x='LMARGIN', new_y='NEXT')

        # Grid rings
        for level in [0.25, 0.5, 0.75, 1.0]:
            pts = [(cx + radius * level * math.cos(a),
                    cy + radius * level * math.sin(a)) for a in angles]
            self.set_draw_color(215, 215, 220)
            self.set_line_width(0.15)
            self._draw_polygon(pts, 'D')

        # Axis spokes
        self.set_draw_color(200, 200, 200)
        self.set_line_width(0.15)
        for a in angles:
            self.line(cx, cy, cx + radius * math.cos(a), cy + radius * math.sin(a))

        # Filled data polygon
        data_pts = [(cx + radius * v * math.cos(a),
                     cy + radius * v * math.sin(a))
                    for a, v in zip(angles, norm)]
        self.set_fill_color(190, 193, 240)
        self.set_draw_color(79, 70, 229)
        self.set_line_width(0.6)
        self._draw_polygon(data_pts, 'FD')

        # Vertex dots
        self.set_fill_color(79, 70, 229)
        for px, py in data_pts:
            self.ellipse(px - 1.0, py - 1.0, 2.0, 2.0, style='F')

        # Axis labels — wider cell so long names like "Dynamic" don't clip
        self._font('', 5.5)
        for i, (a, label) in enumerate(zip(angles, labels)):
            lx = cx + (radius + 8) * math.cos(a)
            ly = cy + (radius + 8) * math.sin(a)
            cos_a, sin_a = math.cos(a), math.sin(a)
            tw, th = 28, 4  # wider cell
            tx = lx if cos_a > 0.1 else (lx - tw if cos_a < -0.1 else lx - tw / 2)
            ty = ly if sin_a > 0.1 else (ly - th if sin_a < -0.1 else ly - th / 2)
            # Clamp to page margins
            tx = max(14, min(tx, 180))
            ty = max(14, ty)
            self.set_text_color(20, 20, 20)
            self.set_xy(tx, ty)
            val_int = int(round(float(values[i] or 0)))
            self.cell(tw, th, f'{_s(label)} {val_int}', new_x='LMARGIN', new_y='NEXT')

    def draw_entropy_bar_chart(self, x: float, y: float, w: float, h: float,
                                sections: list, title: str = ''):
        """Draw a bar chart of PE section entropy values."""
        data = [(s.get('name', '?'), float(s.get('entropy', 0) or 0))
                for s in sections if s.get('entropy') is not None]
        if not data:
            return

        chart_top = y
        if title:
            self.set_font('Helvetica', 'B', 7)
            self.set_text_color(100, 100, 100)
            self.set_xy(x, chart_top)
            self.cell(w, 5, title.upper(), align='C', new_x='LMARGIN', new_y='NEXT')
            chart_top += 6

        max_val   = 8.0
        threshold = 7.0
        label_h   = 5
        chart_h   = h - (6 if title else 0) - label_h
        n         = len(data)
        chart_x   = x + 6
        chart_w   = w - 8
        bar_w     = chart_w / n
        bar_inner = bar_w * 0.72
        bar_pad   = bar_w * 0.14

        # Horizontal grid lines + y-axis labels
        for level in [0, 2, 4, 6, 8]:
            gy = chart_top + chart_h - (level / max_val) * chart_h
            self.set_draw_color(210, 210, 210)
            self.set_line_width(0.12)
            self.line(chart_x, gy, chart_x + chart_w, gy)
            self.set_font('Helvetica', '', 5)
            self.set_text_color(30, 30, 30)
            self.set_xy(x - 1, gy - 1.5)
            self.cell(5, 3, str(level), align='R', new_x='LMARGIN', new_y='NEXT')

        # Threshold dashed line at 7.0
        thresh_y = chart_top + chart_h - (threshold / max_val) * chart_h
        self.set_draw_color(239, 68, 68)
        self.set_line_width(0.4)
        try:
            self.set_dash_pattern(dash=1.5, gap=1)
            self.line(chart_x, thresh_y, chart_x + chart_w, thresh_y)
            self.set_dash_pattern()
        except Exception:
            self.line(chart_x, thresh_y, chart_x + chart_w, thresh_y)
        self.set_font('Helvetica', '', 4.5)
        self.set_text_color(239, 68, 68)
        self.set_xy(chart_x + chart_w + 0.5, thresh_y - 1.5)
        self.cell(7, 3, '7.0', new_x='LMARGIN', new_y='NEXT')

        # Bars
        for i, (name, val) in enumerate(data):
            bx = chart_x + i * bar_w + bar_pad
            bh = max((val / max_val) * chart_h, 0.3)
            by = chart_top + chart_h - bh
            if val > 7.0:
                self.set_fill_color(239, 68, 68)
            elif val > 6.0:
                self.set_fill_color(249, 115, 22)
            else:
                self.set_fill_color(16, 185, 129)
            self.rect(bx, by, bar_inner, bh, style='F')

            # Value label above bar
            self.set_font('Helvetica', '', 5)
            self.set_text_color(0, 0, 0)
            self.set_xy(bx - 1, by - 4)
            self.cell(bar_inner + 2, 3.5, f'{val:.1f}', align='C',
                      new_x='LMARGIN', new_y='NEXT')

            # Section name below axis
            lbl = name[:6] if len(name) > 6 else name
            self.set_font('Helvetica', '', 5)
            self.set_text_color(10, 10, 10)
            self.set_xy(bx - 1, chart_top + chart_h + 0.5)
            self.cell(bar_inner + 2, 3, lbl, align='C',
                      new_x='LMARGIN', new_y='NEXT')

        # Bottom axis line
        self.set_draw_color(180, 180, 180)
        self.set_line_width(0.3)
        self.line(chart_x, chart_top + chart_h, chart_x + chart_w, chart_top + chart_h)

        # Legend
        self.set_xy(x, chart_top + chart_h + label_h + 1)
        for color, label in [
            ((16, 185, 129), 'Normal (<6)'),
            ((249, 115, 22), 'High (6-7)'),
            ((239, 68, 68),  'Packed (>7)'),
        ]:
            self.set_fill_color(*color)
            self.rect(self.get_x(), self.get_y() + 0.8, 3, 3, style='F')
            self.set_x(self.get_x() + 4)
            self.set_font('Helvetica', '', 5.5)
            self.set_text_color(10, 10, 10)
            self.cell(20, 4, label, new_x='RIGHT', new_y='TOP')

    def draw_imports_bar_chart(self, x: float, y: float, w: float,
                                imports: list, title: str = ''):
        """Horizontal bar chart of top DLLs by imported function count."""
        data = sorted(
            [(imp.get('dll', '?'), len(imp.get('functions') or [])) for imp in imports],
            key=lambda d: d[1], reverse=True
        )[:10]
        if not data:
            return

        chart_top = y
        if title:
            self._font('B', 8)
            self.set_text_color(0, 0, 0)
            self.set_xy(x, chart_top)
            self.cell(w, 5, title, new_x='LMARGIN', new_y='NEXT')
            chart_top += 7
            self._font('', 7)
            self.set_text_color(60, 60, 60)
            self.set_xy(x, chart_top)
            self.cell(w, 4, 'Top DLLs by imported function count',
                      new_x='LMARGIN', new_y='NEXT')
            chart_top += 5

        max_val   = max(v for _, v in data) or 1
        label_w   = 35
        chart_x   = x + label_w
        chart_w   = w - label_w - 15
        row_h     = 9
        n         = len(data)
        chart_bot = chart_top + n * row_h

        # Grid verticals
        for frac in [0, 0.25, 0.5, 0.75, 1.0]:
            gx = chart_x + frac * chart_w
            self.set_draw_color(215, 215, 215)
            self.set_line_width(0.12)
            self.line(gx, chart_top, gx, chart_bot)
            tick_val = round(max_val * frac)
            self._font('', 5)
            self.set_text_color(30, 30, 30)
            self.set_xy(gx - 5, chart_bot + 0.5)
            self.cell(10, 3.5, str(tick_val), align='C',
                      new_x='LMARGIN', new_y='NEXT')

        for i, (dll_name, count) in enumerate(data):
            row_y    = chart_top + i * row_h
            bar_y    = row_y + row_h * 0.18
            bar_h    = row_h * 0.64
            bar_w    = max((count / max_val) * chart_w, 0.5)

            # DLL label
            lbl = dll_name[:20] if len(dll_name) > 20 else dll_name
            self._font('', 6)
            self.set_text_color(0, 0, 0)
            self.set_xy(x, bar_y + bar_h / 2 - 2)
            self.cell(label_w - 2, 5, lbl, align='R',
                      new_x='LMARGIN', new_y='NEXT')

            # Bar (purple)
            self.set_fill_color(109, 40, 217)
            self.rect(chart_x, bar_y, bar_w, bar_h, style='F')

            # Count label
            self._font('B', 5.5)
            self.set_text_color(0, 0, 0)
            self.set_xy(chart_x + bar_w + 1.5, bar_y + bar_h / 2 - 2)
            self.cell(12, 5, str(count), new_x='LMARGIN', new_y='NEXT')

        # Bottom axis
        self.set_draw_color(130, 130, 130)
        self.set_line_width(0.3)
        self.line(chart_x, chart_top, chart_x, chart_bot)
        self.line(chart_x, chart_bot, chart_x + chart_w, chart_bot)

    def draw_signature_severity_chart(self, x: float, y: float, w: float,
                                       signatures: list, title: str = ''):
        """
        Two-part view: donut (severity split) on the left,
        signature name list with score badges on the right.
        """
        if not signatures:
            return

        low    = [s for s in signatures if int(s.get('score', 0) or 0) <= 3]
        medium = [s for s in signatures if 4 <= int(s.get('score', 0) or 0) <= 6]
        high   = [s for s in signatures if int(s.get('score', 0) or 0) >= 7]
        total  = len(signatures)
        counts = [len(low), len(medium), len(high)]
        colors = [(16, 185, 129), (245, 158, 11), (239, 68, 68)]
        leg_labels = ['Low (1–3)', 'Medium (4–6)', 'High (7–10)']

        chart_top = y
        if title:
            self._font('B', 8)
            self.set_text_color(0, 0, 0)
            self.set_xy(x, chart_top)
            self.cell(w, 5, title, new_x='LMARGIN', new_y='NEXT')
            chart_top += 7
            self._font('', 7)
            self.set_text_color(60, 60, 60)
            self.set_xy(x, chart_top)
            self.cell(w, 4, f'{total} behavioural signatures detected',
                      new_x='LMARGIN', new_y='NEXT')
            chart_top += 5

        radius   = 22
        cx       = x + radius + 5
        cy       = chart_top + radius + 4

        # Draw donut slices
        start_a = -math.pi / 2
        for count, color in zip(counts, colors):
            if count == 0:
                continue
            sweep = 2 * math.pi * count / total
            steps = max(int(sweep * 12), 3)
            pts   = [(cx, cy)]
            for step in range(steps + 1):
                a = start_a + sweep * step / steps
                pts.append((cx + radius * math.cos(a),
                             cy + radius * math.sin(a)))
            self.set_fill_color(*color)
            self._draw_polygon(pts, 'F')
            start_a += sweep

        # White donut hole
        inner_r = radius * 0.52
        self.set_fill_color(255, 255, 255)
        self.ellipse(cx - inner_r, cy - inner_r,
                     inner_r * 2, inner_r * 2, style='F')

        # Centre label
        self._font('B', 9)
        self.set_text_color(0, 0, 0)
        self.set_xy(cx - 10, cy - 4)
        self.cell(20, 8, str(total), align='C', new_x='LMARGIN', new_y='NEXT')
        self._font('', 5)
        self.set_xy(cx - 10, cy + 4)
        self.cell(20, 4, 'total', align='C', new_x='LMARGIN', new_y='NEXT')

        # Legend below donut
        leg_y = cy + radius + 4
        for i, (label, color, cnt) in enumerate(zip(leg_labels, colors, counts)):
            lx = cx - radius + i * (radius * 2 + 4) / 3 - 2
            self.set_fill_color(*color)
            self.rect(lx, leg_y, 3, 3, style='F')
            self._font('', 5.5)
            self.set_text_color(0, 0, 0)
            self.set_xy(lx + 4, leg_y - 0.5)
            self.cell(22, 4, f'{label}: {cnt}', new_x='LMARGIN', new_y='NEXT')

        # Right panel: signature list with score badges
        list_x   = cx + radius + 12
        list_w   = x + w - list_x
        list_y   = chart_top
        row_h_s  = 6.5
        max_rows = int((radius * 2 + 12) / row_h_s)

        self._font('B', 7)
        self.set_text_color(0, 0, 0)
        self.set_xy(list_x, list_y)
        self.cell(list_w, 5, 'Top Signatures', new_x='LMARGIN', new_y='NEXT')
        list_y += 6

        sorted_sigs = sorted(signatures, key=lambda s: int(s.get('score', 0) or 0),
                             reverse=True)
        for i, sig in enumerate(sorted_sigs[:max_rows]):
            if self.get_y() > 270:
                break
            score = int(sig.get('score', 0) or 0)
            name  = _s(sig.get('name', '-'))
            if len(name) > 32:
                name = name[:30] + '..'
            col = (239, 68, 68) if score >= 7 else (245, 158, 11) if score >= 4 else (16, 185, 129)

            # Score badge
            self.set_fill_color(*col)
            self._font('B', 6)
            self.set_text_color(255, 255, 255)
            self.set_xy(list_x, list_y + i * row_h_s)
            self.cell(10, 5.5, str(score), fill=True, align='C',
                      new_x='RIGHT', new_y='TOP')

            # Name
            self._font('', 6.5)
            self.set_text_color(0, 0, 0)
            self.cell(list_w - 12, 5.5, f'  {name}', new_x='LMARGIN', new_y='NEXT')

        self.set_fill_color(255, 255, 255)
        self.set_text_color(0, 0, 0)


#  Visual section builders 

def _write_security_checks(pdf: ReportPDF, u: dict, x_right: float, y_right: float):
    """Draw a security check status panel for URL analyses."""
    ssl        = u.get('ssl')          or {}
    heuristics = u.get('heuristics')   or {}
    redirects  = u.get('redirects')    or {}
    sb         = u.get('safe_browsing') or {}
    abuse      = u.get('ip_reputation') or {}
    grabber    = u.get('ip_grabber')   or {}

    ssl_ok   = ssl.get('valid', False)
    ssl_err  = bool(ssl.get('error'))
    heur_sc  = int(heuristics.get('score', 0) or 0)
    redir_n  = int(redirects.get('redirects', 0) or 0)
    sb_flag  = sb.get('flagged', False)
    sb_chk   = sb.get('checked', False)
    abuse_sc = int(abuse.get('abuse_score', 0) or 0)
    abuse_chk = abuse.get('checked', False)
    grab_det = grabber.get('detected', False)

    STATUS_COLORS = {
        'PASS': (16,  185, 129),
        'WARN': (245, 158,  11),
        'FAIL': (239,  68,  68),
        'INFO': (148, 163, 184),
    }

    checks = [
        ('SSL Certificate',
         'PASS' if ssl_ok else 'FAIL' if ssl_err else 'WARN',
         f"Valid, expires {_s(ssl.get('expiry', '-'))}" if ssl_ok
         else _s(ssl.get('error', 'Not valid'))),
        ('Heuristic Score',
         'FAIL' if heur_sc >= 50 else 'WARN' if heur_sc >= 20 else 'PASS',
         f'{heur_sc} / 100'),
        ('Redirect Chain',
         'WARN' if redir_n > 3 else 'PASS',
         f'{redir_n} hop(s)'),
        ('Safe Browsing',
         'FAIL' if sb_flag else 'PASS' if sb_chk else 'INFO',
         (', '.join(sb.get('threats') or []) or 'Clean') if sb_chk else 'Not checked'),
        ('IP Reputation',
         'FAIL' if abuse_sc >= 50 else 'WARN' if abuse_sc >= 20 else 'PASS' if abuse_chk else 'INFO',
         f'{abuse_sc}% abuse score' if abuse_chk else 'Not checked'),
        ('IP Grabber',
         'FAIL' if grab_det else 'PASS',
         _s(grabber.get('confidence', 'Clean'))),
    ]

    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(x_right, y_right)
    pdf.cell(80, 5, 'SECURITY CHECKS', new_x='LMARGIN', new_y='NEXT')
    y = y_right + 6
    for name, status, detail in checks:
        col = STATUS_COLORS.get(status, (85, 85, 85))
        pdf.set_xy(x_right, y)
        # Badge
        pdf.set_fill_color(*col)
        pdf.set_font('Helvetica', 'B', 6)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(13, 5.5, status, fill=True, align='C', new_x='RIGHT', new_y='TOP')
        # Name
        pdf.set_font('Helvetica', 'B', 7)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(33, 5.5, _s(name), new_x='RIGHT', new_y='TOP')
        # Detail
        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(15, 15, 15)
        det = _s(detail)
        if len(det) > 28:
            det = det[:25] + '...'
        pdf.cell(35, 5, det, new_x='LMARGIN', new_y='NEXT')
        y += 5.5

    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(26, 26, 26)


def _write_visual_file(pdf: ReportPDF, static_d: dict, dynamic_d: dict):
    """All visualisations stacked vertically on their own page(s)."""
    entropy_d  = static_d.get('entropy')              or {}
    yara_d     = static_d.get('yara')                 or {}
    inds       = static_d.get('suspicious_indicators') or []
    imports    = static_d.get('imports')              or []
    sections   = static_d.get('sections')             or []
    triage_d   = (dynamic_d or {}).get('triage')      or {}
    triage_sc  = float(triage_d.get('triage_score', 0) or 0)
    sigs       = triage_d.get('signatures')           or []
    entropy_v  = float(entropy_d.get('overall', 0)   or 0)
    yara_count = len(yara_d.get('rules') or [])

    radar_values = [
        round((entropy_v / 8.0) * 100),
        min(yara_count * 25, 100),
        min(len(inds) * 6, 100),
        min(len(imports) * 5, 100),
        int(triage_sc * 10),
    ]
    radar_labels = ['Entropy', 'YARA', 'Indicators', 'Imports', 'Dynamic']

    has_radar   = any(radar_values)
    has_entropy = bool(sections and any(s.get('entropy') is not None for s in sections))
    has_imports = bool(imports)
    has_sigs    = bool(sigs)

    if not has_radar and not has_entropy and not has_imports and not has_sigs:
        return

    pdf.add_page()
    pdf.section_heading('Visual Analysis')

    #  1. Risk Profile radar — full-width centred 
    if has_radar:
        cy = pdf.get_y()
        pdf.draw_radar_chart(cx=105, cy=cy + 46, radius=40,
                             labels=radar_labels, values=radar_values,
                             title='Risk Profile')
        pdf.set_y(cy + 97)
        pdf.divider()

    #  2. Section Entropy bar chart — full width 
    if has_entropy:
        if pdf.get_y() > 210:
            pdf.add_page()
        cy = pdf.get_y()
        pdf.draw_entropy_bar_chart(x=15, y=cy, w=180, h=90,
                                   sections=sections,
                                   title='Section Entropy')
        pdf.set_y(cy + 96)
        pdf.divider()

    #  3. Imports by DLL horizontal bar 
    if has_imports:
        n_dlls  = min(len(imports), 10)
        chart_h = n_dlls * 9 + 28   # rows + header + x-axis
        if pdf.get_y() + chart_h > 275:
            pdf.add_page()
        cy = pdf.get_y()
        pdf.draw_imports_bar_chart(x=15, y=cy, w=180,
                                   imports=imports, title='Imports by DLL')
        pdf.set_y(cy + chart_h)
        pdf.ln(3)
        pdf.divider()

    #  4. Signature Severity (dynamic only) 
    if has_sigs:
        sig_h = max(len(sigs[:15]) * 6.5 + 24, 68)
        if pdf.get_y() + sig_h > 275:
            pdf.add_page()
        cy = pdf.get_y()
        pdf.draw_signature_severity_chart(x=15, y=cy, w=180,
                                          signatures=sigs,
                                          title='Signature Severity')
        pdf.set_y(cy + sig_h)
        pdf.ln(3)


def _write_visual_url(pdf: ReportPDF, u: dict):
    """Radar + security checks panel for URL analyses."""
    ssl        = u.get('ssl')           or {}
    heuristics = u.get('heuristics')    or {}
    redirects  = u.get('redirects')     or {}
    sb         = u.get('safe_browsing') or {}
    abuse      = u.get('ip_reputation') or {}
    grabber    = u.get('ip_grabber')    or {}

    ssl_score  = 0 if ssl.get('valid', False) else (60 if ssl.get('error') else 30)
    heur_sc    = float(heuristics.get('score', 0) or 0)
    redir_val  = min(int(redirects.get('redirects', 0) or 0) * 20, 100)
    sb_val     = 100 if sb.get('flagged') else 0
    grab_val   = float(grabber.get('score', 0) or (100 if grabber.get('detected') else 0))
    abuse_val  = float(abuse.get('abuse_score', 0) or 0)

    radar_values = [ssl_score, heur_sc, redir_val, sb_val, grab_val, abuse_val]
    radar_labels = ['SSL Risk', 'Heuristics', 'Redirects', 'Safe Browse', 'IP Grab', 'IP Abuse']

    if pdf.get_y() > 165:
        pdf.add_page()

    pdf.section_heading('Visual Analysis')
    cy = pdf.get_y()

    pdf.draw_radar_chart(cx=58, cy=cy + 44, radius=38,
                         labels=radar_labels, values=radar_values,
                         title='URL Risk Profile')
    _write_security_checks(pdf, u, x_right=113, y_right=cy)
    pdf.set_y(cy + 95)
    pdf.ln(2)


#  Section builders 

def _score_label(triage_score: int) -> str:
    if triage_score >= 8: return 'malicious behaviour confirmed'
    if triage_score >= 6: return 'suspicious behaviour detected'
    if triage_score >= 4: return 'minor suspicious activity'
    if triage_score >= 1: return 'normal / low-risk behaviour'
    return 'no suspicious behaviour'


_STATUS_COLORS = {
    'PASS': (16, 185, 129),
    'WARN': (245, 158, 11),
    'FAIL': (239, 68, 68),
    'INFO': (148, 163, 184),
}


def _write_file_checks_table(pdf: ReportPDF, static_d: dict, dynamic_d: dict):
    """
    Full-width structured table showing every analysis check with a coloured
    PASS / WARN / FAIL / INFO badge — the centrepiece of the report's first page.
    """
    if not static_d:
        return

    entropy_d = static_d.get('entropy') or {}
    yara_d    = static_d.get('yara')    or {}
    inds      = static_d.get('suspicious_indicators') or []
    sections  = static_d.get('sections') or []
    imports   = static_d.get('imports')  or []
    sig       = static_d.get('signature') or {}
    triage_d  = (dynamic_d or {}).get('triage') or {}

    entropy_val  = float(entropy_d.get('overall', 0) or 0)
    yara_rules   = yara_d.get('rules') or []
    yara_matched = bool(yara_rules)
    yara_count   = len(yara_rules)
    triage_score = int(triage_d.get('triage_score', 0) or 0)
    is_signed    = bool(sig.get('valid', False))
    sig_status_s = sig.get('status', 'NotSigned')
    publisher    = sig.get('publisher') or ''

    suspicious_sections = [sc for sc in sections if sc.get('suspicious')]
    high_ent_sections   = [sc for sc in sections
                           if float(sc.get('entropy', 0) or 0) >= 7.5]

    dynamic_available = bool(triage_d)
    dynamic_error     = (dynamic_d or {}).get('error') if not dynamic_available else None

    #  Build check list 
    checks = []

    # 1. Digital Signature
    if is_signed:
        sig_st  = 'PASS'
        sig_det = f'Valid Authenticode — {publisher}' if publisher else 'Valid Authenticode certificate'
    elif sig_status_s == 'HashMismatch':
        sig_st  = 'FAIL'
        sig_det = 'Signature present but TAMPERED (hash mismatch)'
    elif sig_status_s in ('NotTrusted', 'UnknownError'):
        sig_st  = 'WARN'
        sig_det = f'Signature present but not trusted ({sig_status_s})'
    else:
        sig_st  = 'INFO'
        sig_det = 'File is not digitally signed'
    checks.append(('Digital Signature', sig_st, sig_det))

    # 2. YARA Signature Scan
    if yara_matched:
        severities = [r.get('meta', {}).get('severity', 'low') for r in yara_rules]
        top_sev = ('critical' if 'critical' in severities
                   else 'high' if 'high' in severities else 'medium')
        yara_st  = 'FAIL'
        yara_det = f'{yara_count} rule(s) matched — highest severity: {top_sev.upper()}'
    else:
        yara_st  = 'PASS'
        yara_det = 'No malware signatures matched (0 rules triggered)'
    checks.append(('YARA Signature Scan', yara_st, yara_det))

    # 3. File Entropy
    if entropy_val >= 7.8:
        ent_st  = 'FAIL'
        ent_det = f'{entropy_val:.2f} / 8.0 — very high, likely packed or encrypted'
    elif entropy_val >= 7.0:
        ent_st  = 'WARN'
        ent_det = f'{entropy_val:.2f} / 8.0 — elevated, may contain compressed resources'
    elif entropy_val > 0:
        ent_st  = 'PASS'
        ent_det = f'{entropy_val:.2f} / 8.0 — within normal range'
    else:
        ent_st  = 'INFO'
        ent_det = 'Entropy not available (non-PE file)'
    checks.append(('File Entropy Analysis', ent_st, ent_det))

    # 4. PE Section Analysis
    if sections:
        if suspicious_sections and high_ent_sections:
            sect_st  = 'FAIL'
            sect_det = (f'{len(suspicious_sections)} suspicious name(s) + '
                        f'{len(high_ent_sections)} high-entropy section(s) of {len(sections)} total')
        elif suspicious_sections:
            sect_st  = 'WARN'
            sect_det = f'{len(suspicious_sections)} suspicious section name(s) of {len(sections)} total'
        elif high_ent_sections:
            sect_st  = 'WARN'
            sect_det = f'{len(high_ent_sections)} high-entropy section(s) of {len(sections)} total'
        else:
            sect_st  = 'PASS'
            sect_det = f'{len(sections)} sections — all within normal parameters'
    else:
        sect_st  = 'INFO'
        sect_det = 'No PE section data (non-PE file)'
    checks.append(('PE Section Analysis', sect_st, sect_det))

    # 5. Import / Library Analysis
    if imports:
        fn_count = sum(len(imp.get('functions') or []) for imp in imports)
        checks.append(('Import Analysis', 'PASS',
                        f'{len(imports)} DLL(s), {fn_count} function(s) — reviewed for suspicious APIs'))
    else:
        checks.append(('Import Analysis', 'INFO', 'No import table (non-PE or stripped binary)'))

    # 6. Suspicious Indicators
    ind_count = len(inds)
    if ind_count >= 5:
        ind_st  = 'FAIL'
        ind_det = f'{ind_count} suspicious indicator(s) detected by static heuristics'
    elif ind_count >= 1:
        ind_st  = 'WARN'
        ind_det = f'{ind_count} indicator(s) flagged by static analysis'
    else:
        ind_st  = 'PASS'
        ind_det = 'No suspicious indicators detected'
    checks.append(('Suspicious Indicators', ind_st, ind_det))

    # 7. Dynamic Sandbox (Triage)
    if dynamic_available:
        if triage_score >= 7:
            dyn_st = 'FAIL'
        elif triage_score >= 4:
            dyn_st = 'WARN'
        else:
            dyn_st = 'PASS'
        dyn_det = f'Triage score {triage_score}/10 — {_score_label(triage_score)}'
    elif dynamic_error:
        dyn_st  = 'INFO'
        dyn_det = 'Sandbox timed out or encountered an error'
    else:
        dyn_st  = 'INFO'
        dyn_det = 'Dynamic sandbox not performed — static analysis only'
    checks.append(('Dynamic Sandbox (Triage)', dyn_st, dyn_det))

    #  Outcome counts 
    outcomes = [c[1] for c in checks]
    n_pass = outcomes.count('PASS')
    n_warn = outcomes.count('WARN')
    n_fail = outcomes.count('FAIL')
    n_info = outcomes.count('INFO')

    pdf.section_heading('Analysis Results Summary')

    # Outcome summary line
    for label, count, color in [
        ('PASSED', n_pass, (16, 185, 129)),
        ('WARNINGS', n_warn, (245, 158, 11)),
        ('FAILED', n_fail, (239, 68, 68)),
        ('INFO', n_info, (148, 163, 184)),
    ]:
        pdf.set_fill_color(*color)
        pdf.set_font('Helvetica', 'B', 7)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(28, 6, f'{count}  {label}', fill=True, align='C',
                 new_x='RIGHT', new_y='TOP')
        pdf.set_x(pdf.get_x() + 2)
    pdf.ln(9)

    # Column widths: Name | Result | Detail
    cw = [63, 20, 97]

    # Header row
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(225, 225, 238)
    for label, w, last in [('CHECK / TEST', cw[0], False),
                             ('RESULT',      cw[1], False),
                             ('DETAIL',      cw[2], True)]:
        nx = 'LMARGIN' if last else 'RIGHT'
        ny = 'NEXT'    if last else 'TOP'
        pdf.cell(w, 6.5, label, border='B', fill=True,
                 align='C' if label == 'RESULT' else 'L',
                 new_x=nx, new_y=ny)

    # Data rows
    for idx, (name, status, detail) in enumerate(checks):
        if pdf.get_y() > 265:
            pdf.add_page()
        col   = _STATUS_COLORS.get(status, (85, 85, 85))
        shade = idx % 2 == 1
        bg    = (246, 246, 252) if shade else (255, 255, 255)

        # Name cell
        pdf.set_fill_color(*bg)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(cw[0], 7.5, _s(name), border='B', fill=True,
                 new_x='RIGHT', new_y='TOP')

        # Status badge (coloured fill, white text)
        pdf.set_fill_color(*col)
        pdf.set_font('Helvetica', 'B', 7)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(cw[1], 7.5, status, border='B', fill=True, align='C',
                 new_x='RIGHT', new_y='TOP')

        # Detail cell
        pdf.set_fill_color(*bg)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(10, 10, 10)
        det = _s(detail)
        if len(det) > 72:
            det = det[:69] + '...'
        pdf.cell(cw[2], 7.5, det, border='B', fill=True,
                 new_x='LMARGIN', new_y='NEXT')

    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(26, 26, 26)
    pdf.ln(4)


def _write_static(pdf: ReportPDF, s: dict, meta: dict):
    if not s:
        return

    fi   = s.get('file_info')    or {}
    hdrs = s.get('pe_headers')   or {}
    nt   = hdrs.get('nt_headers')      or {}
    opt  = hdrs.get('optional_header') or {}

    pdf.section_heading('Static Analysis')

    #  File Information 
    pdf.sub_heading('File Information')
    pdf.kv_row('Filename',  _s(fi.get('filename')  or meta.get('filename')),  mono=False)
    pdf.kv_row('File Type', _s(fi.get('file_type') or meta.get('file_type')), mono=False)
    pdf.kv_row('Size',      _fmt(fi.get('size')    or meta.get('file_size')), mono=False)
    pdf.kv_row('MD5',       _s(fi.get('md5')))
    pdf.kv_row('SHA1',      _s(fi.get('sha1')))
    pdf.kv_row('SHA256',    _s(fi.get('sha256')    or meta.get('file_hash')))
    pdf.ln(2)

    #  Digital Signature 
    sig = s.get('signature') or {}
    if sig:
        pdf.sub_heading('Digital Signature')
        status_s  = sig.get('status', 'NotSigned')
        is_valid  = sig.get('valid', False)
        publisher = sig.get('publisher')

        if is_valid:
            col_sig = (16, 185, 129)
            label   = 'VALID'
        elif status_s == 'HashMismatch':
            col_sig = (239, 68, 68)
            label   = 'TAMPERED'
        elif status_s in ('NotSigned', 'UnknownError'):
            col_sig = (148, 163, 184)
            label   = 'NOT SIGNED'
        else:
            col_sig = (245, 158, 11)
            label   = status_s.upper()

        # Draw coloured badge + status text
        pdf.set_fill_color(*col_sig)
        pdf.set_font('Helvetica', 'B', 7)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(24, 6.5, label, fill=True, align='C', new_x='RIGHT', new_y='TOP')
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(0, 0, 0)
        detail = publisher if publisher else ('Authenticode signature is valid' if is_valid else 'No Authenticode signature present')
        pdf.cell(0, 6, f'  {_s(detail)}', new_x='LMARGIN', new_y='NEXT')

        if publisher:
            pdf.kv_row('Publisher', publisher, mono=False)
        pdf.kv_row('Status', _s(status_s), mono=False)
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(26, 26, 26)
        pdf.ln(2)

    #  PE Header Details 
    if nt or opt:
        pdf.sub_heading('PE Header Details')
        if nt.get('machine'):
            pdf.kv_row('Architecture',    _machine_name(nt['machine']),        mono=False)
        if nt.get('timestamp'):
            pdf.kv_row('Compile Time',    _fmt_timestamp(nt['timestamp']),     mono=False)
        if nt.get('number_of_sections') is not None:
            pdf.kv_row('Section Count',   _s(nt['number_of_sections']),        mono=False)
        if nt.get('characteristics'):
            pdf.kv_row('Characteristics', _s(nt['characteristics']))
        if opt.get('entry_point'):
            pdf.kv_row('Entry Point',     _s(opt['entry_point']))
        if opt.get('image_base'):
            pdf.kv_row('Image Base',      _s(opt['image_base']))
        if opt.get('subsystem') is not None:
            pdf.kv_row('Subsystem',       _subsystem_name(opt['subsystem']),   mono=False)
        if opt.get('dll_characteristics'):
            pdf.kv_row('Security Flags',  _dll_chars(opt['dll_characteristics']), mono=False)
        pdf.ln(2)

    #  Entropy 
    entropy = s.get('entropy') or {}
    if entropy and not entropy.get('error'):
        pdf.sub_heading('Entropy Analysis')
        pdf.kv_row('Overall',        f"{entropy.get('overall', '-')} / 8.0", mono=False)
        pdf.kv_row('Interpretation', _s(entropy.get('interpretation')),       mono=False)
        pdf.ln(2)

    #  YARA Signatures 
    yara    = s.get('yara') or {}
    matched = yara.get('matched', False)
    rules   = yara.get('rules') or []
    label   = f'{len(rules)} rule(s) matched' if matched else 'No matches'
    pdf.sub_heading(f'YARA Signatures  ({label})')
    if not matched:
        pdf.note('No YARA signatures matched.')
    else:
        for r in rules:
            meta_b = r.get('meta') or {}
            sev    = _s(meta_b.get('severity', ''))
            desc   = _s(meta_b.get('description', ''))
            rtags  = r.get('tags') or []
            if pdf.get_y() > 262:
                pdf.add_page()
            pdf.set_font('Courier', 'B', 7.5)
            pdf.set_text_color(26, 26, 26)
            rule_line = _s(r.get('rule', '-'))
            if sev:
                rule_line += f'  [{sev.upper()}]'
            pdf.cell(0, 4.5, rule_line, new_x='LMARGIN', new_y='NEXT')
            if desc and desc != '-':
                pdf.set_font('Helvetica', '', 8)
                pdf.set_text_color(20, 20, 20)
                pdf.multi_cell(0, 4.5, desc, new_x='LMARGIN', new_y='NEXT')
            if rtags:
                pdf.set_font('Helvetica', 'I', 7.5)
                pdf.set_text_color(40, 40, 40)
                pdf.cell(0, 4, ', '.join(_s(t) for t in rtags[:10]),
                         new_x='LMARGIN', new_y='NEXT')
            pdf.ln(1)
    pdf.ln(2)

    #  Suspicious Indicators 
    inds = s.get('suspicious_indicators') or []
    if inds:
        pdf.sub_heading(f'Suspicious Indicators  ({len(inds)})')
        pdf.bullet_list(inds, mono=True)

    #  PE Sections 
    sections = s.get('sections') or []
    if sections:
        pdf.sub_heading(f'PE Sections  ({len(sections)})')
        pdf.table(
            ['Name', 'Virt. Addr', 'Virt. Size', 'Raw Size', 'Entropy', 'Note'],
            [[_s(sc.get('name')),
              _s(sc.get('virtual_address', '-')),
              _s(sc.get('virtual_size')),
              _s(sc.get('raw_size')),
              _s(sc.get('entropy')),
              _s(sc.get('suspicious') or '-')] for sc in sections],
            [24, 26, 25, 25, 22, 58]
        )

    # Imports
    imports = s.get('imports') or []
    if imports:
        pdf.sub_heading(f'Imported Libraries  ({len(imports)} DLL(s))')
        for imp in imports[:20]:
            fns = imp.get('functions') or []
            dll = _s(imp.get('dll'))
            if pdf.get_y() > 262:
                pdf.add_page()
            pdf.set_font('Courier', 'B', 7.5)
            pdf.set_text_color(26, 26, 26)
            pdf.cell(0, 4.5, dll, new_x='LMARGIN', new_y='NEXT')
            fn_str = ', '.join(_s(f) for f in fns[:15])
            if len(fns) > 15:
                fn_str += f'  (+{len(fns)-15} more)'
            pdf.set_font('Courier', '', 7.5)
            pdf.set_text_color(15, 15, 15)
            pdf.multi_cell(0, 4.5, fn_str, new_x='LMARGIN', new_y='NEXT')
        if len(imports) > 20:
            pdf.note(f'  ({len(imports)-20} additional DLLs not shown)')
        pdf.ln(2)

    # Exports
    exports = s.get('exports') or []
    if exports:
        pdf.sub_heading(f'Exported Functions  ({len(exports)})')
        pdf.table(
            ['Function Name', 'Address'],
            [[_s(e.get('name')), _s(e.get('address'))] for e in exports[:40]],
            [130, 50]
        )
        if len(exports) > 40:
            pdf.note(f'  ({len(exports)-40} additional exports not shown)')

    #Extracted Strings 
    strings_d   = s.get('strings') or {}
    ascii_strs  = strings_d.get('ascii')   or []
    unicode_strs = strings_d.get('unicode') or []
    if ascii_strs or unicode_strs:
        total = len(ascii_strs) + len(unicode_strs)
        pdf.sub_heading(f'Extracted Strings  ({total} total — showing notable)')

        if ascii_strs:
            shown = _interesting_strings(ascii_strs, max_count=50)
            if pdf.get_y() > 245:
                pdf.add_page()
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 5, f'ASCII  ({len(ascii_strs)} extracted, {len(shown)} shown)',
                     new_x='LMARGIN', new_y='NEXT')
            pdf.table(['String'], [[_s(st)] for st in shown], [180])
            if len(ascii_strs) > len(shown):
                pdf.note(f'  ({len(ascii_strs) - len(shown)} additional strings not shown)')

        if unicode_strs:
            shown_u = _interesting_strings(unicode_strs, max_count=20)
            if pdf.get_y() > 245:
                pdf.add_page()
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 5, f'Unicode  ({len(unicode_strs)} extracted, {len(shown_u)} shown)',
                     new_x='LMARGIN', new_y='NEXT')
            pdf.table(['String'], [[_s(st)] for st in shown_u], [180])
            if len(unicode_strs) > len(shown_u):
                pdf.note(f'  ({len(unicode_strs) - len(shown_u)} additional strings not shown)')
        pdf.ln(2)


def _write_dynamic(pdf: ReportPDF, d: dict):
    if not d:
        return

    t = d.get('triage') or {}
    error = d.get('error') or (t.get('error') if t else None)

    if error and not t:
        pdf.add_page()
        pdf.section_heading('Dynamic Analysis', accent_color=(79, 70, 229))
        pdf.note(f'Dynamic analysis unavailable: {_s(error)}')
        return

    if not t:
        pdf.add_page()
        pdf.section_heading('Dynamic Analysis', accent_color=(79, 70, 229))
        pdf.note('Dynamic analysis was not performed for this file.')
        return

    pdf.add_page()
    pdf.section_heading('Dynamic Analysis', accent_color=(79, 70, 229))

    #Sandbox metadata 
    pdf.sub_heading('Sandbox Information')
    pdf.kv_row('Sandbox',      _s(t.get('sandbox', 'Hatching Triage')), mono=False)
    pdf.kv_row('Sample ID',    _s(t.get('sample_id') or '-'))
    pdf.kv_row('Triage Score', f"{t.get('triage_score', 0)} / 10",      mono=False)
    if t.get('report_url'):
        pdf.kv_row('Full Report', _s(t['report_url']),                  mono=False)
    tags = t.get('tags') or []
    if tags:
        pdf.kv_row('Tags', ', '.join(_s(tg) for tg in tags),            mono=False)
    pdf.ln(2)

    #Behavioural Signatures
    sigs = t.get('signatures') or []
    if sigs:
        pdf.sub_heading(f'Behavioural Signatures  ({len(sigs)})')
        for sig in sigs:
            name     = _s(sig.get('name'))
            score    = sig.get('score', 0)
            desc     = _s(sig.get('description', ''))
            sig_tags = sig.get('tags') or []
            if pdf.get_y() > 262:
                pdf.add_page()
            pdf.set_font('Courier', 'B', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 5, f'{name}  [{score}/10]', new_x='LMARGIN', new_y='NEXT')
            if desc and desc != '-':
                d_str = desc if len(desc) <= 110 else desc[:107] + '...'
                pdf._font('', 8)
                pdf.set_text_color(30, 30, 30)
                pdf.multi_cell(0, 4.5, d_str, new_x='LMARGIN', new_y='NEXT')
            if sig_tags:
                pdf._font('I', 7.5)
                pdf.set_text_color(50, 50, 50)
                pdf.cell(0, 4, ', '.join(_s(tg) for tg in sig_tags[:10]),
                         new_x='LMARGIN', new_y='NEXT')
            pdf.ln(1)
        pdf.ln(2)

    #Network Activity 
    net      = t.get('network')      or {}
    domains  = net.get('domains')    or []
    hosts    = net.get('hosts')      or []
    http_req = net.get('http_requests') or []
    dns_req  = net.get('dns_requests')  or []

    if domains or hosts or http_req or dns_req:
        pdf.sub_heading('Network Activity')
        if domains:
            pdf._font('B', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 5, 'Contacted Domains', new_x='LMARGIN', new_y='NEXT')
            pdf.table(
                ['Domain', 'IP'],
                [[_s(dom.get('domain')), _s(dom.get('ip') or '-')] for dom in domains],
                [110, 70]
            )
        if hosts:
            pdf._font('B', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 5, 'Contacted Hosts / IPs', new_x='LMARGIN', new_y='NEXT')
            pdf.table(['Host / IP'], [[_s(h)] for h in hosts[:25]], [180])
        if http_req:
            pdf._font('B', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 5, 'HTTP Requests', new_x='LMARGIN', new_y='NEXT')
            pdf.table(
                ['Method', 'URL', 'Status'],
                [[_s(r.get('method')), _s(r.get('url')), _s(r.get('status') or '-')]
                 for r in http_req[:20]],
                [20, 140, 20]
            )
        if dns_req:
            pdf._font('B', 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 5, 'DNS Queries', new_x='LMARGIN', new_y='NEXT')
            pdf.table(
                ['Query', 'Type'],
                [[_s(q.get('query')), _s(q.get('type'))] for q in dns_req[:30]],
                [145, 35]
            )

    # Processes
    procs = t.get('processes') or []
    if procs:
        pdf.sub_heading(f'Processes  ({len(procs)})')
        pdf.table(
            ['PID', 'Name', 'Command', 'Injected'],
            [[_s(p.get('pid')), _s(p.get('name')),
              _s(p.get('cmd') or '-'),
              'YES' if p.get('injected') else '-'] for p in procs],
            [15, 42, 103, 20]
        )
        for p in procs:
            p_sigs = p.get('signatures') or []
            if p_sigs:
                pdf._font('', 8)
                pdf.set_text_color(20, 20, 20)
                sig_str = ', '.join(_s(ps) for ps in p_sigs[:8])
                pdf.cell(0, 4.5, f'  Signatures for {_s(p.get("name"))}: {sig_str}',
                         new_x='LMARGIN', new_y='NEXT')
        pdf.ln(2)

    # Dropped Files
    dropped = t.get('dropped_files') or []
    if dropped:
        pdf.sub_heading(f'Dropped Files  ({len(dropped)})')
        pdf.table(
            ['Name', 'Size', 'Type', 'MD5', 'SHA256'],
            [[_s(f.get('name')), _fmt(f.get('size')), _s(f.get('type') or '-'),
              _s(f.get('md5')), _s(f.get('sha256'))]
             for f in dropped],
            [50, 18, 25, 46, 41]
        )

    # Registry Operations
    reg = t.get('registry') or []
    if reg:
        pdf.sub_heading(f'Registry Operations  ({len(reg)})')
        pdf.table(
            ['Operation', 'Key', 'Value'],
            [[_s(r.get('op')), _s(r.get('key')), _s(r.get('value') or '-')]
             for r in reg[:40]],
            [22, 105, 53]
        )
        if len(reg) > 40:
            pdf.note(f'  ({len(reg)-40} additional operations not shown)')

    # Mutexes
    mutexes = t.get('mutexes') or []
    if mutexes:
        pdf.sub_heading(f'Mutexes  ({len(mutexes)})')
        pdf.bullet_list(mutexes, mono=True)

    #Sandbox Errors 
    errors = t.get('errors') or []
    if errors:
        pdf.sub_heading('Sandbox Errors / Warnings')
        pdf.bullet_list(errors)

    if not (sigs or domains or hosts or http_req or dns_req or procs or dropped or reg or mutexes):
        pdf.note('No suspicious runtime behaviour detected.')


def _write_url(pdf: ReportPDF, a: dict):
    u = a.get('static_analysis') or {}
    if not u:
        return

    redirects  = u.get('redirects')     or {}
    heuristics = u.get('heuristics')    or {}
    grabber    = u.get('ip_grabber')    or {}
    sb         = u.get('safe_browsing') or {}
    abuse      = u.get('ip_reputation') or {}
    ssl        = u.get('ssl')           or {}

    url_str           = _s(u.get('url') or a.get('filename'))
    final_url         = _s(redirects.get('final_url') or url_str)
    ip_addr           = _s(u.get('ip') or '-')
    redirect_count    = redirects.get('redirects', 0)
    heuristic_score   = heuristics.get('score', 0)
    abuseipdb_reports = abuse.get('total_reports', 0)
    is_ip_grabber     = grabber.get('detected', False)
    sb_threats        = sb.get('threats') or []
    sb_str            = ', '.join(sb_threats) if sb_threats else 'Clean'
    patterns          = heuristics.get('indicators') or []
    chain             = redirects.get('chain') or []

    pdf.section_heading('URL Intelligence')

    # Overview 
    pdf.sub_heading('Overview')
    pdf.kv_row('URL',             url_str,                                       mono=False)
    pdf.kv_row('Final URL',       final_url,                                     mono=False)
    pdf.kv_row('Hostname',        _s(u.get('hostname', '-')),                    mono=False)
    pdf.kv_row('IP Address',      ip_addr)
    pdf.kv_row('Redirect Count',  _s(redirect_count),                            mono=False)
    pdf.kv_row('Heuristic Score', f'{heuristic_score} / 100',                    mono=False)
    grabber_val = f'Detected  ({grabber.get("confidence", "")})' if is_ip_grabber else 'None'
    pdf.kv_row('IP Grabber',      grabber_val,                                   mono=False)
    pdf.kv_row('Safe Browsing',   sb_str,                                        mono=False)
    pdf.ln(2)

    # SSL / TLS
    if ssl:
        pdf.sub_heading('SSL / TLS Certificate')
        pdf.kv_row('Valid', 'Yes' if ssl.get('valid') else 'No',                 mono=False)
        if ssl.get('expiry'):
            pdf.kv_row('Expiry',    _s(ssl['expiry']),                           mono=False)
        if ssl.get('days_remaining') is not None:
            pdf.kv_row('Days Left', _s(ssl['days_remaining']),                   mono=False)
        if ssl.get('error'):
            pdf.kv_row('Error',     _s(ssl['error']),                            mono=False)
        pdf.ln(2)

    # IP Reputation 
    if abuse.get('checked'):
        pdf.sub_heading('IP Reputation  (AbuseIPDB)')
        pdf.kv_row('Abuse Score',   f"{abuse.get('abuse_score', 0)} / 100",      mono=False)
        pdf.kv_row('Total Reports', _s(abuseipdb_reports),                       mono=False)
        if abuse.get('country'):
            pdf.kv_row('Country',   _s(abuse['country']),                        mono=False)
        if abuse.get('isp'):
            pdf.kv_row('ISP',       _s(abuse['isp']),                            mono=False)
        pdf.kv_row('Tor Exit',      'Yes' if abuse.get('is_tor') else 'No',      mono=False)
        pdf.ln(2)

    # Heuristic Indicators 
    if patterns:
        pdf.sub_heading(f'Heuristic Indicators  ({len(patterns)})')
        pdf.bullet_list(patterns, mono=True)

    # Redirect Chain 
    if chain:
        pdf.sub_heading(f'Redirect Chain  ({len(chain)} hop(s))')
        for i, r in enumerate(chain, 1):
            val = _s(r)
            if len(val) > 90:
                val = val[:87] + '...'
            pdf.set_font('Courier', '', 7.5)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(8, 4.5, f'{i}.', new_x='RIGHT', new_y='TOP')
            pdf.cell(0, 4.5, val,     new_x='LMARGIN', new_y='NEXT')
        pdf.ln(2)

    # IP Grabber Details
    if grabber.get('detected'):
        pdf.sub_heading('IP Grabber Analysis')
        pdf.kv_row('Confidence',    _s(grabber.get('confidence')),               mono=False)
        pdf.kv_row('Score',         _s(grabber.get('score', 0)),                 mono=False)
        matched_d = grabber.get('matched_domain')
        if matched_d:
            pdf.kv_row('Matched Domain', _s(matched_d),                         mono=False)
        reasons = grabber.get('reasons') or []
        if reasons:
            pdf.bullet_list(reasons, mono=True)


# Main builder

def build_pdf(analysis_record) -> bytes:
    """Convert an Analysis ORM instance or plain dict to PDF bytes."""
    try:
        from fpdf import FPDF
    except ImportError:
        raise RuntimeError('fpdf2 is not installed. Run: pip install fpdf2')

    if hasattr(analysis_record, 'to_dict'):
        data = analysis_record.to_dict(include_results=True)
    else:
        data = analysis_record

    risk   = (data.get('risk_level') or 'unknown').lower()
    score  = data.get('risk_score') or (data.get('static_analysis') or {}).get('risk_score', 0)
    col    = _risk_color(risk)
    is_url = data.get('file_type') == 'URL'
    now    = datetime.now().strftime('%d %b %Y, %H:%M')
    title  = _s(data.get('filename'))

    def _parse_dt(val):
        if not val:
            return '-'
        try:
            return datetime.fromisoformat(
                str(val).replace('Z', '+00:00')
            ).strftime('%d %b %Y, %H:%M')
        except Exception:
            return _s(val)

    submitted = _parse_dt(data.get('submitted_at'))
    completed = _parse_dt(data.get('completed_at'))

    pdf = ReportPDF(title=title, generated=now)

    # Title block
    pdf.set_font('Helvetica', 'B', 7)
    pdf.set_text_color(160, 160, 160)
    pdf.cell(0, 5, 'SANDBUG  -  ANALYSIS REPORT', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(1)

    pdf.set_font('Helvetica', 'B', 15)
    pdf.set_text_color(0, 0, 0)
    display_title = title if len(title) <= 75 else title[:72] + '...'
    pdf.cell(0, 8, display_title, new_x='LMARGIN', new_y='NEXT')
    pdf.ln(1)

    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(60, 60, 60)
    analysis_type = 'URL Analysis' if is_url else 'File Analysis'
    pdf.cell(0, 5,
        f'Generated {now}   |   ID {data.get("id")}   |   '
        f'{analysis_type}   |   {_s(data.get("status"))}',
        new_x='LMARGIN', new_y='NEXT')
    pdf.ln(2)
    pdf.divider(thick=True)

    # Risk hero
    pdf.set_font('Helvetica', 'B', 38)
    pdf.set_text_color(*col)
    pdf.cell(32, 15, str(score), new_x='RIGHT', new_y='TOP')

    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(*col)
    pdf.cell(44, 15, risk.upper(), new_x='RIGHT', new_y='TOP')

    # Right meta block
    x0 = 110
    pdf.set_x(x0)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(15, 15, 15)
    if not is_url:
        h = _s(data.get('file_hash', ''))
        pdf.cell(0, 4.5, f'File:  {_s(data.get("filename"))}',    new_x='LMARGIN', new_y='NEXT')
        pdf.set_x(x0)
        pdf.cell(0, 4.5, f'Size:  {_fmt(data.get("file_size"))}',  new_x='LMARGIN', new_y='NEXT')
        pdf.set_x(x0)
        pdf.set_font('Courier', '', 7.5)
        pdf.cell(0, 4.5, f'SHA256: {h[:32]}',                      new_x='LMARGIN', new_y='NEXT')
        if len(h) > 32:
            pdf.set_x(x0)
            pdf.cell(0, 4.5, f'        {h[32:]}',                  new_x='LMARGIN', new_y='NEXT')
    else:
        short_url = display_title if len(display_title) <= 58 else display_title[:55] + '...'
        pdf.cell(0, 4.5, f'URL:  {short_url}', new_x='LMARGIN', new_y='NEXT')

    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(15, 15, 15)
    pdf.set_x(x0)
    pdf.cell(0, 4.5, f'Submitted:  {submitted}', new_x='LMARGIN', new_y='NEXT')
    pdf.set_x(x0)
    pdf.cell(0, 4.5, f'Completed:  {completed}', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)
    pdf.divider()

    # Score breakdown (file analyses)
    if not is_url:
        static_d  = data.get('static_analysis')  or {}
        dynamic_d = data.get('dynamic_analysis') or {}
        triage_d  = dynamic_d.get('triage') if dynamic_d else {}
        s_score   = static_d.get('risk_score')
        t_score   = (triage_d or {}).get('triage_score')
        if s_score is not None or t_score is not None:
            parts = []
            if s_score is not None:
                parts.append(f'Static: {s_score}/100  (50%)')
            if t_score is not None:
                parts.append(f'Triage sandbox: {t_score}/10  (50%)')
            parts.append(f'Combined risk score: {score}/100')
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(0, 5, '  |  '.join(parts), new_x='LMARGIN', new_y='NEXT')
            pdf.ln(2)
            pdf.divider()

    # Analysis Results Summary (file only)
    if not is_url:
        _write_file_checks_table(pdf,
                                 data.get('static_analysis')  or {},
                                 data.get('dynamic_analysis') or {})

    # AI Summary
    ai = _s(data.get('ai_summary', ''))
    if ai and ai != '-':
        pdf.section_heading('AI Summary', accent_color=(79, 70, 229))
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5.5, ai, new_x='LMARGIN', new_y='NEXT')
        pdf.ln(2)

    # Visual Analysis
    if is_url:
        _write_visual_url(pdf, data.get('static_analysis') or {})
    else:
        _write_visual_file(pdf,
                           data.get('static_analysis')  or {},
                           data.get('dynamic_analysis') or {})

    # Detailed sections
    if is_url:
        _write_url(pdf, data)
    else:
        _write_static(pdf, data.get('static_analysis') or {}, data)
        _write_dynamic(pdf, data.get('dynamic_analysis') or {})

    result = bytes(pdf.output())
    print(f'[PDF] Generated OK: {len(result)} bytes', flush=True)
    return result


# HTML report

def build_html(analysis_record) -> str:
    """Return a self-contained styled HTML report string."""
    import html as _html
    import json as _json

    if hasattr(analysis_record, 'to_dict'):
        data = analysis_record.to_dict(include_results=True)
    else:
        data = analysis_record

    def h(v):
        return _html.escape(str(v)) if v is not None else '-'

    def _parse_dt(val):
        if not val:
            return '-'
        try:
            return datetime.fromisoformat(str(val).replace('Z', '+00:00')).strftime('%d %b %Y, %H:%M UTC')
        except Exception:
            return str(val)

    risk    = (data.get('risk_level') or 'unknown').lower()
    score   = data.get('risk_score') or (data.get('static_analysis') or {}).get('risk_score', 0)
    is_url  = data.get('file_type') == 'URL'
    title   = data.get('filename') or 'Unknown'
    now     = datetime.now().strftime('%d %b %Y, %H:%M')

    risk_colors = {
        'critical': '#c0392b', 'high': '#d35400',
        'medium': '#b8860b',   'low': '#1e7e34', 'clean': '#1e7e34',
    }
    risk_color = risk_colors.get(risk, '#555')

    static  = data.get('static_analysis') or {}
    dynamic = data.get('dynamic_analysis') or {}
    summary = data.get('ai_summary') or ''

    def section(title_text, body_html):
        return f'''
        <div class="section">
          <h2>{h(title_text)}</h2>
          {body_html}
        </div>'''

    def kv_table(rows):
        if not rows:
            return '<p class="empty">No data available.</p>'
        cells = ''.join(
            f'<tr><th>{h(k)}</th><td>{h(v)}</td></tr>'
            for k, v in rows
        )
        return f'<table class="kv">{cells}</table>'

    # Metadata
    meta_rows = [
        ('Analysis ID', data.get('id')),
        ('Type',        'URL Analysis' if is_url else 'File Analysis'),
        ('Status',      data.get('status')),
        ('Submitted',   _parse_dt(data.get('submitted_at'))),
        ('Completed',   _parse_dt(data.get('completed_at'))),
    ]
    if not is_url:
        meta_rows += [
            ('File Size', _fmt(data.get('file_size'))),
            ('File Type', data.get('file_type')),
            ('SHA-256',   data.get('file_hash')),
        ]
    meta_section = section('Overview', kv_table(meta_rows))

    # AI Summary
    summary_section = ''
    if summary:
        summary_section = section('AI Summary', f'<p class="summary">{h(summary)}</p>')

    # Static / URL details 
    details_section = ''
    if is_url:
        url_rows = [
            ('URL',         title),
            ('Risk Score',  score),
            ('Risk Level',  risk.upper()),
        ]
        for k in ('domain_age_days', 'ip_address', 'asn', 'country', 'dns_records'):
            v = static.get(k)
            if v is not None:
                url_rows.append((k.replace('_', ' ').title(), v if not isinstance(v, (list, dict)) else _json.dumps(v)))
        details_section = section('URL Details', kv_table(url_rows))
    else:
        pe = static.get('pe_info') or {}
        static_rows = [
            ('Risk Score',       static.get('risk_score', score)),
            ('Entropy',          static.get('entropy')),
            ('YARA Matches',     ', '.join(static.get('yara_matches') or []) or 'None'),
            ('Suspicious Imports', ', '.join(static.get('suspicious_imports') or []) or 'None'),
        ]
        if pe:
            static_rows += [
                ('Architecture',  pe.get('machine')),
                ('Compilation',   _fmt_timestamp(pe.get('timestamp'))),
                ('Sections',      pe.get('number_of_sections')),
            ]
        details_section = section('Static Analysis', kv_table(static_rows))

    #Dynamic
    dynamic_section = ''
    if dynamic and 'error' not in dynamic:
        dyn_rows = [
            ('Triage Score',    dynamic.get('triage_score')),
            ('Verdict',         dynamic.get('verdict')),
            ('Sample ID',       dynamic.get('sample_id')),
            ('Report URL',      dynamic.get('report_url')),
        ]
        signatures = dynamic.get('signatures') or []
        if signatures:
            dyn_rows.append(('Signatures', '; '.join(
                s.get('name', '') for s in signatures[:10]
            )))
        dynamic_section = section('Dynamic Analysis', kv_table(dyn_rows))

    body = meta_section + summary_section + details_section + dynamic_section

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SandBug Report — {h(title)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f5f5f7; color: #1d1d1f; padding: 2rem; }}
    .report {{ max-width: 900px; margin: 0 auto; background: #fff;
               border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,.1); overflow: hidden; }}
    .header {{ background: #1d1d1f; color: #fff; padding: 2rem 2.5rem; }}
    .header h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: .25rem; }}
    .header .meta {{ font-size: .8rem; color: #aaa; }}
    .risk-badge {{ display: inline-block; margin-top: .75rem;
                   padding: .3rem .9rem; border-radius: 6px; font-weight: 700;
                   font-size: 1.1rem; background: {risk_color}; color: #fff; }}
    .section {{ padding: 1.5rem 2.5rem; border-bottom: 1px solid #e5e5ea; }}
    .section:last-child {{ border-bottom: none; }}
    .section h2 {{ font-size: 1rem; font-weight: 600; color: #6e6e73;
                   text-transform: uppercase; letter-spacing: .05em; margin-bottom: 1rem; }}
    table.kv {{ width: 100%; border-collapse: collapse; font-size: .88rem; }}
    table.kv th {{ width: 38%; text-align: left; padding: .45rem .75rem;
                   background: #f5f5f7; color: #555; font-weight: 500; border-radius: 4px; }}
    table.kv td {{ padding: .45rem .75rem; word-break: break-all; }}
    table.kv tr:nth-child(even) th,
    table.kv tr:nth-child(even) td {{ background: #fafafa; }}
    p.summary {{ font-size: .9rem; line-height: 1.7; color: #333; }}
    p.empty {{ color: #aaa; font-size: .85rem; }}
    .footer {{ text-align: center; font-size: .75rem; color: #aaa; padding: 1rem; }}
  </style>
</head>
<body>
<div class="report">
  <div class="header">
    <h1>{h(title)}</h1>
    <div class="meta">Generated {now} &nbsp;|&nbsp; SandBug Malware Analysis Platform</div>
    <div class="risk-badge">{risk.upper()} &nbsp; {score}/100</div>
  </div>
  {body}
  <div class="footer">SandBug &mdash; Automated Malware Analysis</div>
</div>
</body>
</html>'''
