"""Interactive pieces of 'The problem' page: the year replay, the field of 39,953 dots, and two diagrams.

Each function returns HTML. The two animations run in the browser (inside st.components.v1.html) on data computed
by the page; every number they show is passed in from Python."""
import json

FONTS = ("<link rel='preconnect' href='https://fonts.googleapis.com'>"
         "<link href='https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:"
         "wght@400;500;600&family=Source+Serif+4:opsz,wght@8..60,600&display=swap' rel='stylesheet'>")

BASE_CSS = """
*{box-sizing:border-box} html,body{margin:0;padding:0;background:#fff;color:#14181f;
font-family:'IBM Plex Sans',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;-webkit-font-smoothing:antialiased}
.lab{font:600 11px/1.2 'IBM Plex Mono',ui-monospace,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:#5b6470}
button{font:500 13px/1 'IBM Plex Sans',system-ui,sans-serif;border:1px solid #cfd6de;background:#fff;color:#14181f;
border-radius:999px;padding:8px 14px;cursor:pointer;transition:all .15s ease}
button:hover{border-color:#1f5fa8;color:#1f5fa8} button.on{background:#14181f;border-color:#14181f;color:#fff}
"""

# --------------------------------------------------------------------------- the year replay
TIMELAPSE = """<!doctype html><html><head><meta charset='utf-8'>__FONTS__<style>__BASE__
.wrap{border:1px solid #e3e7ec;border-radius:16px;padding:18px 20px 14px;background:linear-gradient(180deg,#fbfcfd,#fff)}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px}
.date{font:600 26px/1 'Source Serif 4',Georgia,serif;letter-spacing:-.01em}
.row{display:grid;grid-template-columns:1fr 1fr 1.4fr;gap:18px;margin:6px 0 12px}
.val{font:600 34px/1.05 'IBM Plex Mono',ui-monospace,monospace;letter-spacing:-.02em;margin-top:6px}
.val.red{color:#c8372d}
.ids{margin-top:8px;display:flex;flex-direction:column;gap:3px;min-height:76px}
.id{font:500 13px/1.25 'IBM Plex Mono',monospace;color:#5b6470;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
animation:in .35s ease both}
.id.x{color:#c8372d;font-weight:600}
@keyframes in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
canvas{display:block;width:100%;height:120px}
.axis{display:flex;justify-content:space-between;font:500 11px/1 'IBM Plex Mono',monospace;color:#8a929c;margin-top:6px}
.note{font-size:12.5px;color:#5b6470;margin-top:10px;line-height:1.45}
@media (max-width:620px){.wrap{padding:14px 14px 10px}.row{grid-template-columns:1fr 1fr;gap:10px;margin-bottom:8px}
.row>div:last-child{display:none}.val{font-size:24px}.date{font-size:20px}canvas{height:96px}.note{font-size:11.5px}}
</style></head><body><div class='wrap'>
<div class='top'><div><div class='lab'>2024, replayed day by day</div><div class='date' id='date'>&nbsp;</div></div>
<button id='play'>Replay</button></div>
<div class='row'>
<div><div class='lab'>flaws published so far</div><div class='val' id='cn'>0</div></div>
<div><div class='lab'>later confirmed attacked</div><div class='val red' id='cx'>0</div></div>
<div><div class='lab'>just published</div><div class='ids' id='ids'></div></div></div>
<canvas id='bars'></canvas><div class='axis' id='axis'></div>
<div class='note'>Each bar is one day of 2024; its height is the number of flaws published that day. Red marks the days
with at least one flaw that attackers later used. On the day itself, nobody could tell which ones those were.</div>
</div><script>
const D=__DATA__, N=D.length, DUR=15000;
const cv=document.getElementById('bars'), ctx=cv.getContext('2d');
const el=id=>document.getElementById(id), fmt=n=>n.toLocaleString('en-US');
const months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
el('axis').innerHTML=months.map(m=>'<span>'+m+'</span>').join('');
const cumN=[],cumX=[];let a=0,b=0;D.forEach(d=>{a+=d.n;b+=d.x;cumN.push(a);cumX.push(b)});
const maxN=Math.max(...D.map(d=>d.n));
function size(){const r=window.devicePixelRatio||1;cv.width=cv.clientWidth*r;cv.height=cv.clientHeight*r;ctx.setTransform(r,0,0,r,0,0)}
function draw(upto){const W=cv.clientWidth,H=cv.clientHeight,bw=W/N;ctx.clearRect(0,0,W,H);
 for(let i=0;i<N;i++){const h=Math.max(1,Math.sqrt(D[i].n/maxN)*(H-14));const on=i<=upto;
  ctx.fillStyle=on?'#1f5fa8':'#e6ebf1';ctx.globalAlpha=on?(i===upto?1:.78):1;
  ctx.fillRect(i*bw+bw*.12,H-h,Math.max(1,bw*.76),h);
  if(on&&D[i].x>0){ctx.globalAlpha=1;ctx.fillStyle='#c8372d';ctx.fillRect(i*bw-.5,H-h-7,Math.max(2,bw+1),4)}}
 ctx.globalAlpha=1}
let last=-1,lastIds=0;
function show(i,force){if(i===last)return;last=i;const d=D[i];
 el('date').textContent=new Date(d.d+'T12:00:00Z').toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric',timeZone:'UTC'});
 el('cn').textContent=fmt(cumN[i]);el('cx').textContent=fmt(cumX[i]);
 const now=performance.now();if(force||now-lastIds>260||d.xi.length){lastIds=now;const box=el('ids');const pick=d.xi.length?[d.xi[0],...d.ids.filter(x=>x!==d.xi[0])]:d.ids;
 box.innerHTML=pick.slice(0,4).map(x=>'<div class="id'+(d.xi.includes(x)?' x':'')+'">'+x+(d.xi.includes(x)?'  attacked later':'')+'</div>').join('')}
 draw(i)}
let t0=null,raf=null;
function step(ts){if(t0===null)t0=ts;const p=Math.min(1,(ts-t0)/DUR);const e=p<.5?2*p*p:1-Math.pow(-2*p+2,2)/2;
 show(Math.min(N-1,Math.floor(e*N)));if(p<1)raf=requestAnimationFrame(step);else{last=-1;show(N-1,true);raf=null}}
function play(){if(raf)cancelAnimationFrame(raf);t0=null;last=-1;raf=requestAnimationFrame(step)}
el('play').onclick=play;size();
window.addEventListener('resize',()=>{size();draw(last<0?N-1:last)});
const reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
if(reduce){show(N-1,true)}else{show(0,true);let started=false;const go=()=>{if(!started){started=true;play()}};
 try{new IntersectionObserver((en,ob)=>{if(en[0].isIntersecting){go();ob.disconnect()}},{threshold:.35}).observe(document.body)}catch(e){go()}
 setTimeout(go,4000)}
</script></body></html>"""


def timelapse_html(days):
    return (TIMELAPSE.replace("__FONTS__", FONTS).replace("__BASE__", BASE_CSS)
            .replace("__DATA__", json.dumps(days, separators=(",", ":"))))


# --------------------------------------------------------------------------- the field of dots
DOTFIELD = """<!doctype html><html><head><meta charset='utf-8'>__FONTS__<style>__BASE__
.wrap{border:1px solid #e3e7ec;border-radius:16px;padding:16px 18px 14px;background:#fff}
.modes{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.story{display:grid;grid-template-columns:auto 1fr;gap:18px;align-items:center;min-height:74px;margin-bottom:12px}
@media (max-width:620px){.story{min-height:124px}}
.big{font:600 44px/1 'Source Serif 4',Georgia,serif;letter-spacing:-.02em;min-width:2.4em}
.big.red{color:#c8372d}.big.blue{color:#1f5fa8}.big.green{color:#14946a}
.txt{font-size:15px;line-height:1.5;color:#2c343e} .txt b{color:#14181f}
canvas{display:block;width:100%;border-radius:8px}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:10px;font-size:12.5px;color:#5b6470}
.k{display:inline-flex;align-items:center;gap:7px}.k i{width:10px;height:10px;border-radius:2px;display:inline-block}
@media (max-width:620px){.big{font-size:32px}.txt{font-size:13.5px}.story{gap:12px}}
</style></head><body><div class='wrap' id='wrap'>
<div class='modes' id='modes'></div>
<div class='story'><div class='big' id='big'></div><div class='txt' id='txt'></div></div>
<canvas id='cv'></canvas>
<div class='legend' id='legend'></div></div><script>
const S=__STATS__, CODES='__CODES__', N=CODES.length, HEIGHT=__HEIGHT__;
const ex=new Uint8Array(N),sev=new Uint8Array(N),topf=new Uint8Array(N);
for(let i=0;i<N;i++){const c=CODES.charCodeAt(i)-48;ex[i]=c&1;sev[i]=(c>>1)&1;topf[i]=(c>>2)&1}
const order=(flag)=>{const a=[],b=[];for(let i=0;i<N;i++)(flag[i]?a:b).push(i);const pos=new Float32Array(N);
 a.concat(b).forEach((id,p)=>pos[id]=p);return [pos,a.length]};
const ident=new Float32Array(N);for(let i=0;i<N;i++)ident[i]=i;
const [posSev,nSev]=order(sev),[posTop,nTop]=order(topf);
const MODES=[
 {key:'all',label:'Every flaw of 2024',pos:ident,cut:0,big:S.n_fmt,tone:'',
  txt:'Each square is <b>one software flaw</b> made public in 2024, in the order they were published: '+S.n_fmt+' in all, about '+S.per_day+' a day.'},
 {key:'attacked',label:'The ones attackers used',pos:ident,cut:0,big:S.k_fmt,tone:'red',
  txt:'Only <b>'+S.k_fmt+'</b> were later confirmed as used in real attacks, <b>1 in '+S.one_in+'</b>. They are scattered across the year with no obvious pattern.'},
 {key:'severity',label:'Rule of thumb: fix everything rated 7+',pos:posSev,cut:nSev,big:S.sev_share,tone:'blue',
  txt:'Fixing every flaw its maker rated <b>7.0 or higher</b> means '+S.sev_n+' fixes, <b>'+S.sev_share+' of the year</b>. It catches '+S.sev_caught+' of the '+S.k_fmt+' attacked flaws and leaves <b>'+S.sev_missed+'</b> in the pile it never touches.'},
 {key:'model',label:"NeedlePoint: top 10%",pos:posTop,cut:nTop,big:S.top_caught+'/'+S.k_fmt,tone:'green',
  txt:'Handling only the <b>top 10%</b> of a ranked list ('+S.top_n+' flaws) catches <b>'+S.top_caught+'</b> of the '+S.k_fmt+' attacked flaws, using only what was known on the day each was published.'}];
const cv=document.getElementById('cv'),ctx=cv.getContext('2d');let W=0,H=0,cell=3,cols=1;
function layout(){W=cv.clientWidth;const avail=window.innerHeight-cv.getBoundingClientRect().top-
 document.getElementById('legend').offsetHeight-34;H=Math.max(140,Math.min(HEIGHT,avail));cell=Math.sqrt(W*H/N);cols=Math.max(1,Math.floor(W/cell));cell=W/cols;
 H=Math.ceil(N/cols)*cell;const r=window.devicePixelRatio||1;cv.style.height=H+'px';cv.width=W*r;cv.height=H*r;ctx.setTransform(r,0,0,r,0,0)}
let cur=new Float32Array(N),from=new Float32Array(N),mode=MODES[0],t0=0,anim=false,prevCut=0;
for(let i=0;i<N;i++)cur[i]=i;
function xy(p){return [(p%cols)*cell,Math.floor(p/cols)*cell]}
function colour(i){const k=mode.key;
 if(k==='all')return '#b9c6d4';
 if(k==='attacked')return ex[i]?'#c8372d':'#e9edf2';
 const f=k==='severity'?sev[i]:topf[i];
 if(ex[i])return '#c8372d';return f?(k==='severity'?'#6f9bd1':'#5fbf9d'):'#e9edf2'}
function frame(ts){const p=anim?Math.min(1,(ts-t0)/900):1;const e=p<.5?4*p*p*p:1-Math.pow(-2*p+2,3)/2;
 ctx.clearRect(0,0,W,H);const s=cell>2.6?cell-0.8:cell;
 const hide=mode.key==='all';
 for(let i=0;i<N;i++){if(ex[i]&&!hide)continue;const q=from[i]+(mode.pos[i]-from[i])*e;cur[i]=q;
  const x=(q%cols),r=Math.floor(q/cols);ctx.fillStyle=colour(i);ctx.fillRect(x*cell,r*cell,s,s)}
 if(mode.cut>0){const c=prevCut+(mode.cut-prevCut)*e,[x,y]=xy(c);ctx.fillStyle='#14181f';
  ctx.fillRect(x,y,2,cell);ctx.fillRect(0,y+cell,x,1.6);ctx.fillRect(x,y,W-x,1.6)}
 const big=Math.max(cell*2.2,5);
 for(let i=0;i<N;i++){if(!ex[i]||hide)continue;const q=from[i]+(mode.pos[i]-from[i])*e;cur[i]=q;
  const x=(q%cols)*cell+cell/2,y=Math.floor(q/cols)*cell+cell/2;ctx.fillStyle=colour(i);
  ctx.beginPath();ctx.arc(x,y,big/2,0,6.2832);ctx.fill();if(mode.key!=='all'){ctx.strokeStyle='#fff';ctx.lineWidth=1;ctx.stroke()}}
 if(p<1)requestAnimationFrame(frame);else{anim=false;prevCut=mode.cut}}
function setMode(m){from=cur.slice();mode=m;t0=performance.now();anim=true;
 document.querySelectorAll('#modes button').forEach(b=>b.classList.toggle('on',b.dataset.k===m.key));
 const big=document.getElementById('big');big.textContent=m.big;big.className='big '+m.tone;
 document.getElementById('txt').innerHTML=m.txt;
 const L={all:[['#b9c6d4','one flaw']],attacked:[['#c8372d','later used in attacks'],['#e9edf2','never confirmed as attacked']],
  severity:[['#6f9bd1','fixed by the rule (top-left, before the black line)'],['#c8372d','attacked'],['#e9edf2','not fixed']],
  model:[['#5fbf9d','in the top 10% of the ranking (before the black line)'],['#c8372d','attacked'],['#e9edf2','lower down the list']]}[m.key];
 document.getElementById('legend').innerHTML=L.map(l=>"<span class='k'><i style='background:"+l[0]+"'></i>"+l[1]+'</span>').join('');
 requestAnimationFrame(frame)}
const box=document.getElementById('modes');
MODES.forEach(m=>{const b=document.createElement('button');b.textContent=m.label;b.dataset.k=m.key;b.onclick=()=>setMode(m);box.appendChild(b)});
setMode(MODES[0]);layout();from=mode.pos.slice();anim=false;requestAnimationFrame(frame);
window.addEventListener('resize',()=>{layout();anim=false;from=mode.pos.slice();requestAnimationFrame(frame)});
</script></body></html>"""


def dotfield_html(codes, stats, height=380):
    return (DOTFIELD.replace("__FONTS__", FONTS).replace("__BASE__", BASE_CSS)
            .replace("__STATS__", json.dumps(stats)).replace("__CODES__", codes).replace("__HEIGHT__", str(height)))


# --------------------------------------------------------------------------- diagrams (inline SVG)
def anatomy_svg(cve):
    "A real CVE record, annotated: what is known on the day it is published."
    desc = cve["description"]
    lines, line = [], ""
    for word in desc.split():
        if len(line) + len(word) + 1 > 62:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    lines.append(line)
    lines = lines[:4] + (["…"] if len(lines) > 4 else [])
    desc_svg = "".join(f"<tspan x='40' dy='{0 if i == 0 else 19}'>{_esc(t)}</tspan>" for i, t in enumerate(lines))
    h = 330 + 19 * (len(lines) - 1)
    note = lambda x, y, x2, y2, label, sub: (                                   # noqa: E731
        f"<line x1='{x}' y1='{y}' x2='{x2}' y2='{y2}' stroke='#1f5fa8' stroke-width='1.2' stroke-dasharray='3 3'/>"
        f"<circle cx='{x}' cy='{y}' r='3.5' fill='#1f5fa8'/>"
        f"<text x='{x2 + 8}' y='{y2 - 4}' class='n1'>{label}</text><text x='{x2 + 8}' y='{y2 + 13}' class='n2'>{sub}</text>")
    return f"""<svg viewBox='0 0 1000 {h}' width='100%' role='img' aria-label='Anatomy of {cve['id']}'
 xmlns='http://www.w3.org/2000/svg' style='width:100%;min-width:760px;display:block;margin:.4rem 0 1rem'>
<style>.t{{font:600 22px 'IBM Plex Mono',monospace;fill:#14181f}} .m{{font:500 14px 'IBM Plex Sans',sans-serif;fill:#5b6470}}
.d{{font:400 15px 'IBM Plex Sans',sans-serif;fill:#2c343e}} .b{{font:600 13px 'IBM Plex Mono',monospace;fill:#fff}}
.n1{{font:600 13px 'IBM Plex Sans',sans-serif;fill:#14181f}} .n2{{font:400 12.5px 'IBM Plex Sans',sans-serif;fill:#5b6470}}</style>
<rect x='20' y='20' width='600' height='{h - 40}' rx='16' fill='#fbfcfd' stroke='#d9dfe6'/>
<text x='40' y='62' class='t'>{cve['id']}</text>
<text x='40' y='90' class='m'>Published {cve['published']} by {_esc(cve['publisher'])}</text>
<rect x='40' y='110' width='{86 + 7 * len(cve['severity'])}' height='28' rx='14' fill='#c8372d'/>
<text x='54' y='129' class='b'>{cve['score']} {cve['severity'].upper()}</text>
<text x='40' y='170' class='m'>Weakness: {_esc(cve['weakness'])}</text>
<text x='40' y='206' class='d'>{desc_svg}</text>
{note(604, 56, 650, 56, 'An ID, like a parcel tracking number', 'Every public flaw gets one: a CVE number.')}
{note(604, 85, 650, 118, 'Who published it', 'Usually the maker of the product.')}
{note(604, 124, 650, 180, "The maker's severity score, 0 to 10", 'How bad it would be if attacked.')}
{note(604, 166, 650, 242, 'The kind of mistake in the code', cve['weakness_plain'])}
{note(604, 206, 650, 304, 'A short description', 'Written for experts; often vague.')}
</svg>"""


def pipeline_svg():
    "How the project turns three public sources into the ranked list and the answers."
    box = lambda x, y, w, h, t1, t2, fill, stroke: (                                          # noqa: E731
        f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='12' fill='{fill}' stroke='{stroke}' stroke-width='1.3'/>"
        f"<text x='{x + w / 2}' y='{y + 26}' text-anchor='middle' class='h'>{t1}</text>"
        + "".join(f"<text x='{x + w / 2}' y='{y + 46 + 17 * i}' text-anchor='middle' class='s'>{s}</text>"
                  for i, s in enumerate(t2)))
    arrow = lambda x1, y1, x2, y2: (f"<path d='M{x1},{y1} C{(x1 + x2) / 2},{y1} {(x1 + x2) / 2},{y2} {x2},{y2}' fill='none' "  # noqa: E731
                                    f"stroke='#8a929c' stroke-width='1.4' marker-end='url(#ah)'/>")
    return f"""<svg viewBox='0 0 1000 330' width='100%' role='img' aria-label='How the project works'
 xmlns='http://www.w3.org/2000/svg' style='width:100%;min-width:760px;display:block;margin:.6rem 0 .4rem'>
<defs><marker id='ah' viewBox='0 0 8 8' refX='7' refY='4' markerWidth='7' markerHeight='7' orient='auto'>
<path d='M0,0 L8,4 L0,8 z' fill='#8a929c'/></marker></defs>
<style>.h{{font:600 14px 'IBM Plex Sans',sans-serif;fill:#14181f}} .s{{font:400 12.5px 'IBM Plex Sans',sans-serif;fill:#5b6470}}
.c{{font:600 11px 'IBM Plex Mono',monospace;fill:#8a929c;letter-spacing:.1em}}</style>
<text x='20' y='18' class='c'>1 · COLLECT</text><text x='300' y='18' class='c'>2 · ORGANISE</text>
<text x='560' y='18' class='c'>3 · ANALYSE</text><text x='840' y='18' class='c'>4 · USE</text>
{box(20, 34, 220, 78, 'NVD (US government)', ['every flaw published', '2016–2024, by API'], '#eef3fb', '#1f5fa8')}
{box(20, 126, 220, 78, 'CISA KEV catalogue', ['which flaws were attacked,', 'and when it was confirmed'], '#eef3fb', '#1f5fa8')}
{box(20, 218, 220, 78, 'FIRST EPSS', ["the industry's daily", 'prediction score'], '#eef3fb', '#1f5fa8')}
{box(300, 106, 200, 120, 'One clean table', ['Python, pandas, NumPy:', 'one row per flaw, only what', 'was known on its first day'], '#f5f6f8', '#8a929c')}
{box(560, 34, 220, 78, 'What goes with attacks?', ['Q1 traits · Q3 timing'], '#e4f4ee', '#14946a')}
{box(560, 126, 220, 78, 'A ranked to-do list', ['Q2: a model trained on', 'Nov 2021–2023, tested on 2024'], '#e4f4ee', '#14946a')}
{box(560, 218, 220, 78, 'Against the industry score', ['Q4: the ranking vs EPSS'], '#e4f4ee', '#14946a')}
{box(840, 106, 140, 120, 'NeedlePoint', ['this app: rank flaws,', 'replay 2024,', 'explore the findings'], '#fff', '#14181f')}
{arrow(240, 73, 300, 150)}{arrow(240, 165, 300, 166)}{arrow(240, 257, 300, 182)}
{arrow(500, 150, 560, 73)}{arrow(500, 166, 560, 165)}{arrow(500, 182, 560, 257)}
{arrow(780, 73, 840, 150)}{arrow(780, 165, 840, 166)}{arrow(780, 257, 840, 182)}
</svg>"""


def triage_svg(per_day):
    "The emergency-room analogy, as a three-step flow."
    step = lambda x, n, t, lines, tone: (                                                    # noqa: E731
        f"<circle cx='{x + 22}' cy='40' r='18' fill='{tone}'/><text x='{x + 22}' y='46' text-anchor='middle' class='k'>{n}</text>"
        f"<text x='{x}' y='92' class='h'>{t}</text>"
        + "".join(f"<text x='{x}' y='{116 + 19 * i}' class='s'>{s}</text>" for i, s in enumerate(lines)))
    return f"""<svg viewBox='0 0 1000 200' width='100%' role='img' aria-label='Triage in an emergency room and for software flaws'
 xmlns='http://www.w3.org/2000/svg' style='width:100%;min-width:760px;display:block;margin:.4rem 0 .2rem'>
<style>.h{{font:600 16px 'Source Serif 4',Georgia,serif;fill:#14181f}} .s{{font:400 13.5px 'IBM Plex Sans',sans-serif;fill:#3a434e}}
.k{{font:600 16px 'IBM Plex Mono',monospace;fill:#fff}}</style>
<line x1='60' y1='40' x2='880' y2='40' stroke='#d9dfe6' stroke-width='2' stroke-dasharray='5 5'/>
{step(20, 1, 'Patients arrive', ['Too many to see at once.', f'For flaws: about {per_day:.0f} a day.'], '#8a929c')}
{step(350, 2, 'A nurse sorts them', ['Using only what is visible now:', 'symptoms, age, history. For flaws:', 'who made it, what kind of mistake.'], '#1f5fa8')}
{step(690, 3, 'Most urgent first', ['Doctors start at the top', 'of the list. For flaws: fix the', 'top of the ranking first.'], '#14946a')}
</svg>"""


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;"))
