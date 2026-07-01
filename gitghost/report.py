"""Render the scan into a standalone, shareable HTML dossier."""

import html
from datetime import datetime, timezone

from .metadata import MetadataReport
from .rules import Finding
from .score import ScoreCard

_BAND_ANGLE = {"CRITICAL": -8, "HIGH": -6, "MODERATE": -4, "LOW": -3, "MINIMAL": -2}


def _esc(s: str) -> str:
    return html.escape(str(s))


def _finding_row(f: Finding) -> str:
    tone = "ghost" if f.is_ghost else "live"
    where = _esc(f.path) if f.path else ""
    loc = f"{where}:{f.line_no}" if not f.is_ghost else where
    commit = f'<span class="commit">{_esc(f.commit)}</span>' if f.is_ghost and f.commit else ""
    return f"""
      <tr class="frow {tone}">
        <td class="sev"><span class="sev-dot s{f.severity}">{f.severity}</span></td>
        <td class="lbl">{_esc(f.label)}</td>
        <td class="val"><code class="redaction">{_esc(f.redacted)}</code></td>
        <td class="loc">{loc} {commit}<div class="rem">{_esc(f.remediation)}</div></td>
      </tr>"""


def render_report(identity: str, card: ScoreCard, findings: list[Finding],
                  meta: MetadataReport, repos_scanned: int) -> str:
    live = sorted((f for f in findings if f.kind == "secret" and not f.is_ghost),
                  key=lambda f: -f.severity)
    ghosts = sorted((f for f in findings if f.is_ghost), key=lambda f: -f.severity)
    infra = sorted((f for f in findings if f.kind == "infra"), key=lambda f: -f.severity)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    angle = _BAND_ANGLE.get(card.band, -6)

    meter_pct = card.score
    drivers = "".join(f"<li>{_esc(d)}</li>" for d in card.drivers) or "<li>Nothing notable surfaced. Rare, and good.</li>"

    ghost_section = ""
    if ghosts:
        ghost_section = f"""
        <section class="block ghost-block">
          <div class="block-head">
            <span class="eyebrow">Recovered from history</span>
            <h2>The secrets you deleted didn't leave.</h2>
            <p class="note">{len(ghosts)} secret{'s' if len(ghosts)!=1 else ''} removed from the current code but still reachable in git history. To anyone who clones the repo, these are one command away.</p>
          </div>
          <table class="findings"><tbody>{''.join(_finding_row(f) for f in ghosts)}</tbody></table>
        </section>"""

    live_section = ""
    if live:
        live_section = f"""
        <section class="block">
          <div class="block-head">
            <span class="eyebrow hot">Live in current code</span>
            <h2>{len(live)} secret{'s' if len(live)!=1 else ''} sitting in HEAD right now.</h2>
          </div>
          <table class="findings"><tbody>{''.join(_finding_row(f) for f in live)}</tbody></table>
        </section>"""

    infra_section = ""
    if infra:
        infra_section = f"""
        <section class="block">
          <div class="block-head"><span class="eyebrow">Infrastructure breadcrumbs</span></div>
          <table class="findings"><tbody>{''.join(_finding_row(f) for f in infra)}</tbody></table>
        </section>"""

    emails = ", ".join(_esc(e) for e in meta.emails[:3]) or "none exposed"
    meta_section = f"""
    <section class="block">
      <div class="block-head"><span class="eyebrow">What your commits reveal about you</span></div>
      <div class="meta-grid">
        <div class="meta-cell"><div class="mk">Author email</div><div class="mv">{emails}</div></div>
        <div class="meta-cell"><div class="mk">Timezone (inferred)</div><div class="mv">{_esc(meta.dominant_utc_offset or '—')}</div></div>
        <div class="meta-cell"><div class="mk">Active hours (inferred)</div><div class="mv">{_esc(meta.likely_active_hours or '—')}</div></div>
        <div class="meta-cell"><div class="mk">Commits analyzed</div><div class="mv">{meta.commit_count:,}</div></div>
      </div>
    </section>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>gitghost dossier — {_esc(identity)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;600;800;900&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --paper:#E7E4DB; --panel:#F1EEE7; --ink:#17150F; --muted:#8A8577;
    --hazard:#E4491C; --ghost:#3E5C6B; --line:rgba(23,21,15,.16);
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--paper); color:var(--ink);
    font-family:'Archivo',system-ui,sans-serif; -webkit-font-smoothing:antialiased; }}
  .sheet {{ max-width:940px; margin:0 auto; padding:40px 28px 80px; }}
  code, .mono {{ font-family:'Space Mono',monospace; }}

  .top {{ display:flex; justify-content:space-between; align-items:baseline;
    border-bottom:2px solid var(--ink); padding-bottom:10px; gap:16px; flex-wrap:wrap; }}
  .brand {{ font-weight:900; letter-spacing:-.02em; font-size:20px; }}
  .brand b {{ color:var(--hazard); }}
  .filed {{ font-family:'Space Mono',monospace; font-size:12px; color:var(--muted); text-align:right; }}

  .hero {{ display:grid; grid-template-columns:1.1fr .9fr; gap:28px; margin:34px 0 10px; align-items:center; }}
  @media(max-width:720px){{ .hero{{ grid-template-columns:1fr; }} }}
  .target-eyebrow {{ font-family:'Space Mono',monospace; font-size:12px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--muted); }}
  .target {{ font-size:clamp(34px,7vw,58px); font-weight:900; letter-spacing:-.03em; line-height:.98; margin:6px 0 14px; word-break:break-word; }}
  .target span {{ color:var(--hazard); }}
  .scope {{ font-family:'Space Mono',monospace; font-size:12.5px; color:var(--muted); max-width:40ch; }}

  .scorebox {{ position:relative; background:var(--panel); border:2px solid var(--ink);
    padding:22px 24px 20px; }}
  .scorebox .k {{ font-family:'Space Mono',monospace; font-size:11px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--muted); }}
  .bignum {{ font-size:96px; font-weight:900; line-height:.86; letter-spacing:-.04em; margin:2px 0 0; }}
  .bignum small {{ font-size:26px; color:var(--muted); font-weight:600; }}
  .meter {{ height:12px; background:repeating-linear-gradient(90deg,var(--line) 0 1px,transparent 1px 5%);
    border:1px solid var(--ink); margin:14px 0 6px; position:relative; }}
  .meter i {{ position:absolute; inset:0 auto 0 0; width:{meter_pct}%;
    background:var(--hazard); mix-blend-mode:multiply; }}
  .stamp {{ position:absolute; top:14px; right:16px; transform:rotate({angle}deg);
    border:3px double var(--hazard); color:var(--hazard); font-weight:800;
    font-family:'Space Mono',monospace; letter-spacing:.06em; padding:4px 10px;
    font-size:15px; opacity:.9; }}
  .grade {{ font-family:'Space Mono',monospace; font-size:13px; color:var(--muted); margin-top:2px; }}
  .grade b {{ color:var(--ink); }}

  .drivers {{ background:var(--ink); color:var(--paper); padding:20px 24px; margin:26px 0 8px; }}
  .drivers h3 {{ margin:0 0 10px; font-size:12px; letter-spacing:.14em; text-transform:uppercase;
    font-family:'Space Mono',monospace; color:#c9c4b6; font-weight:400; }}
  .drivers ul {{ margin:0; padding-left:18px; }}
  .drivers li {{ margin:5px 0; font-size:15px; }}

  .block {{ margin:40px 0 0; }}
  .block-head {{ border-bottom:1px solid var(--line); padding-bottom:8px; margin-bottom:6px; }}
  .eyebrow {{ font-family:'Space Mono',monospace; font-size:12px; letter-spacing:.14em;
    text-transform:uppercase; color:var(--ghost); }}
  .eyebrow.hot {{ color:var(--hazard); }}
  .block-head h2 {{ font-size:clamp(21px,3.4vw,30px); font-weight:800; letter-spacing:-.02em; margin:6px 0 2px; }}
  .note {{ font-size:14px; color:var(--muted); max-width:62ch; margin:2px 0 0; }}
  .ghost-block .block-head {{ border-color:var(--ghost); }}

  table.findings {{ width:100%; border-collapse:collapse; margin-top:4px; }}
  .frow td {{ border-bottom:1px solid var(--line); padding:12px 8px; vertical-align:top; }}
  .sev {{ width:34px; }}
  .sev-dot {{ display:inline-grid; place-items:center; width:26px; height:26px; border-radius:50%;
    font-family:'Space Mono',monospace; font-weight:700; font-size:13px; color:var(--paper); background:var(--muted); }}
  .sev-dot.s10,.sev-dot.s9 {{ background:var(--hazard); }}
  .sev-dot.s8,.sev-dot.s7 {{ background:#C4531F; }}
  .sev-dot.s6,.sev-dot.s5 {{ background:#B8862B; }}
  .lbl {{ font-weight:600; width:210px; font-size:15px; }}
  .frow.ghost .lbl {{ color:var(--ghost); }}
  .val {{ min-width:180px; }}
  code.redaction {{ background:var(--ink); color:var(--paper); padding:3px 8px; font-size:13px;
    display:inline-block; letter-spacing:.02em; }}
  .frow.ghost code.redaction {{ background:var(--ghost); }}
  .loc {{ font-family:'Space Mono',monospace; font-size:12px; color:var(--muted); }}
  .commit {{ color:var(--ghost); }}
  .rem {{ margin-top:6px; font-family:'Archivo',sans-serif; font-size:13px; color:var(--ink); max-width:52ch; }}

  .meta-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:var(--line);
    border:1px solid var(--line); margin-top:12px; }}
  @media(max-width:640px){{ .meta-grid{{ grid-template-columns:repeat(2,1fr); }} }}
  .meta-cell {{ background:var(--panel); padding:16px; }}
  .mk {{ font-family:'Space Mono',monospace; font-size:11px; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); }}
  .mv {{ font-family:'Space Mono',monospace; font-size:14px; margin-top:6px; word-break:break-word; }}

  .foot {{ margin-top:56px; border-top:2px solid var(--ink); padding-top:16px;
    font-family:'Space Mono',monospace; font-size:12px; color:var(--muted); line-height:1.6; }}
  .foot b {{ color:var(--ink); }}
</style></head>
<body><div class="sheet">

  <div class="top">
    <div class="brand">git<b>ghost</b> // exposure dossier</div>
    <div class="filed">FILED {ts}<br>{repos_scanned} public repo{'s' if repos_scanned!=1 else ''} scanned</div>
  </div>

  <div class="hero">
    <div>
      <div class="target-eyebrow">Subject of report</div>
      <div class="target">@<span>{_esc(identity)}</span></div>
      <div class="scope">Public repositories only. Detection-only: no discovered
      credential was ever tested against its provider.</div>
    </div>
    <div class="scorebox">
      <div class="stamp">{_esc(card.band)}</div>
      <div class="k">Exposure Score</div>
      <div class="bignum">{card.score}<small>/100</small></div>
      <div class="meter"><i></i></div>
      <div class="grade">Grade <b>{_esc(card.grade)}</b> · higher is worse · worst find: {_esc(card.worst)}</div>
    </div>
  </div>

  <div class="drivers">
    <h3>What's driving this score</h3>
    <ul>{drivers}</ul>
  </div>

  {ghost_section}
  {live_section}
  {infra_section}
  {meta_section}

  <div class="foot">
    <b>gitghost</b> — an exposure audit built from public data. It surfaces and
    scores what a GitHub identity already published, including material believed
    deleted but still recoverable from git history.<br>
    It is <b>detection-only by design</b>: it reports that a string matches a
    credential format and stops. It never authenticates with a discovered secret,
    never touches private repositories, and is meant for auditing your own
    identity or one you're authorized to assess.<br>
    Every finding is shown as a non-reversible fingerprint (a safe prefix, a
    length, and a partial hash) — never recoverable key material — so this report
    is safe to share. gitghost does not retain the raw secret past the match.
  </div>

</div></body></html>"""
