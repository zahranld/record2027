/* ============================================================
   نظام إدارة وتسجيل التدريب 2027 — مرتبط بنظام الاحتياجات التدريبية plan2027
   ============================================================ */
const MONTHS=['يناير','فبراير','مارس','أبريل','مايو','يونيو','يوليو','أغسطس','سبتمبر','أكتوبر','نوفمبر','ديسمبر'];
const CATS={T:'فني',S:'سلوكي',M:'إداري'};const CK=['T','S','M'];
const CATVAR={T:'--c-tech',S:'--c-soft',M:'--c-mgr'};
const SESS_ST=['مخطط','منفذ','مؤجل','ملغي'];
const ATT_ST=['حاضر','متأخر','غائب','اعتذر'];
const INTERNAL='تدريب داخلي (قاعة)';
/* رابط القراءة فقط لبيانات نظام الاحتياجات (نفس مصدر https://zahranld.github.io/plan2027/) */
const PLAN_LINK={page:'https://2.dejn-tr.com/',url:'https://oazwbhiuabdmevmlmfeq.supabase.co',key:'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9hendiaGl1YWJkbWV2bWxtZmVxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTIwODQwMzgsImV4cCI6MjEwNzY2MDAzOH0.HYgpU1JHDGWBrEMMfQva8ZIzC7WnUAQcq1Cntdp5qNY'};
const RKEY='zahran_trs_2027_v1',PCACHE='zahran_trs_plan_cache',THKEY='zahran_trs_theme';

/* ===================== أدوات ===================== */
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=(n,d=0)=>Number(n||0).toLocaleString('en-US',{maximumFractionDigits:d});
const num=v=>{const x=parseFloat(String(v??'').replace(/[^\d.\-]/g,''));return isNaN(x)?0:x};
const uid=()=>Math.random().toString(36).slice(2,10);
const iso=d=>`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
const pd=s=>{const [y,m,d]=String(s).split('-').map(Number);return new Date(y,(m||1)-1,d||1)};
const today=()=>iso(new Date());
const pct=(a,b)=>b?Math.round(a/b*100):0;
const pc=n=>`<bdi dir="ltr">${n}%</bdi>`;
const avg=a=>a.length?a.reduce((x,y)=>x+y,0)/a.length:null;
const chip=k=>CATS[k]?`<span class="chip ${k}">${CATS[k]}</span>`:'';
const cdc=c=>`<span class="cd">${esc(c)}</span>`;
const fmtD=x=>{if(!x)return '—';const d=pd(x);return `${d.getDate()} ${MONTHS[d.getMonth()]}`};
const fmtDY=x=>x?`${fmtD(x)} ${pd(x).getFullYear()}`:'—';
const rng=(a,b)=>!a?'—':(a===b||!b)?fmtD(a):`${fmtD(a)} - ${fmtD(b)}`;
function toast(m,err){const el=$('toast');el.textContent=m;el.className='toast show'+(err?' err':'');clearTimeout(el._t);el._t=setTimeout(()=>el.className='toast',3200)}
const opt=(arr,v,ph)=>(ph!==undefined?`<option value="">${esc(ph)}</option>`:'')+arr.map(o=>{const [val,lab]=Array.isArray(o)?o:[o,o];return `<option value="${esc(val)}" ${String(val)===String(v??'')?'selected':''}>${esc(lab)}</option>`}).join('');
function dl(blob,name){const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},500)}
function normKey(s){return String(s||'').trim().replace(/\s+/g,' ').replace(/[أإآ]/g,'ا').replace(/ة/g,'ه').replace(/ى/g,'ي')}

/* SHA-256 مختصر لكلمة السر */
const K256=[],H256=[];(()=>{let n=2,c=0;const isP=x=>{for(let i=2;i*i<=x;i++)if(x%i===0)return false;return true};while(c<64){if(isP(n)){if(c<8)H256.push((Math.pow(n,1/2)%1)*4294967296|0);K256.push((Math.pow(n,1/3)%1)*4294967296|0);c++}n++}})();
function sha256(msg){const ror=(x,n)=>(x>>>n)|(x<<(32-n));const by=new TextEncoder().encode(msg);const l=by.length;const buf=new Uint8Array(((l+9+63)>>6)<<6);buf.set(by);buf[l]=0x80;
  const dv=new DataView(buf.buffer);dv.setUint32(buf.length-4,(l*8)>>>0);dv.setUint32(buf.length-8,Math.floor(l*8/4294967296));let h=H256.slice();const w=new Array(64);
  for(let i=0;i<buf.length;i+=64){for(let j=0;j<16;j++)w[j]=dv.getUint32(i+j*4)|0;
    for(let j=16;j<64;j++){const a=w[j-15],b=w[j-2];w[j]=(w[j-16]+(ror(a,7)^ror(a,18)^(a>>>3))+w[j-7]+(ror(b,17)^ror(b,19)^(b>>>10)))|0}
    let [a,b,c,d,e,f,g,k]=h;
    for(let j=0;j<64;j++){const t1=(k+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+K256[j]+w[j])|0;const t2=((ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c)))|0;k=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0}
    h=[h[0]+a,h[1]+b,h[2]+c,h[3]+d,h[4]+e,h[5]+f,h[6]+g,h[7]+k].map(x=>x|0)}
  return h.map(x=>(x>>>0).toString(16).padStart(8,'0')).join('')}
const pwPrintSync=p=>sha256('zahran-trs-sync|'+p);

/* ===================== بيانات الخطة (مصدر الربط) ===================== */
let P={settings:{},needs:[],programs:[]},PLAN_SRC='snapshot',PLAN_AT='',PLAN_ST='';
function setPlan(d,src,at){if(!d||!Array.isArray(d.programs)||!Array.isArray(d.needs))return false;P={settings:d.settings||{},needs:d.needs,programs:d.programs};PLAN_SRC=src;PLAN_AT=at||'';return true}
function loadPlan(){
  try{const c=JSON.parse(localStorage.getItem(PCACHE)||'null');if(c&&setPlan(c.data,c.src||'cache',c.at))return}catch(e){}
}
function cachePlan(src){try{localStorage.setItem(PCACHE,JSON.stringify({data:P,src,at:PLAN_AT}))}catch(e){}}
/* بيانات الخطة تُقرأ عبر دالة محمية بكلمة سر هذا النظام (trs_get_plan) — لا قراءة عامة */
async function pullPlan(manual){
  let pw='';try{pw=sessionStorage.getItem('zahran_trs_sync_pw')||''}catch(e){}
  if(!pw){if(manual)toast('ادخل بكلمة السر أولًا',true);return}
  PLAN_ST='جارٍ التحديث...';renderChrome();
  try{const r=await fetch(PLAN_LINK.url+'/rest/v1/rpc/trs_get_plan',{method:'POST',cache:'no-store',headers:{apikey:PLAN_LINK.key,Authorization:'Bearer '+PLAN_LINK.key,'Content-Type':'application/json'},body:JSON.stringify({pw})});
    const res=await r.json().catch(()=>null);if(!r.ok||!res||!res.ok||!setPlan(res.data,'live',new Date().toLocaleString('en-GB')))throw 0;
    cachePlan('live');PLAN_ST='';trackPlan();if(manual)toast(`تم تحديث الخطة: ${P.programs.length} برنامج و ${P.needs.length} احتياج`);
    if(!$('modal').classList.contains('show'))render();else renderChrome();
  }catch(e){PLAN_ST='تعذر الاتصال';renderChrome();if(manual)toast('تعذر الاتصال بنظام الاحتياجات. يعمل النظام على آخر نسخة محفوظة.',true)}
}
const PS=()=>P.settings||{};
const YEAR=()=>+(PS().year||2027);
const ORG=()=>PS().org||'زهران ماركت';
const UNIT=()=>PS().unit||'قسم التدريب والتطوير - إدارة الموارد البشرية';
const needsOf=p=>P.needs.filter(n=>n.programId===p.id);
const pTrainees=p=>+p.traineesOverride>0?+p.traineesOverride:needsOf(p).reduce((a,n)=>a+(+n.trainees||0),0);
const pGroups=p=>+p.groups>0?+p.groups:Math.max(1,Math.ceil(pTrainees(p)/(+PS().groupSize||20)));
function rateOf(m){const r=(PS().rates||{})[m]||{};return{day:+r.day||0,head:+r.head||0}}
const pDays=p=>Math.max(1,Math.ceil((+p.hours||0)/(+PS().hoursPerDay||6)));
const pEst=p=>{const r=rateOf(p.method);return Math.round(pGroups(p)*pDays(p)*r.day+pTrainees(p)*r.head)};
const pBudget=p=>p.method===INTERNAL?0:(+p.budget>0?+p.budget:pEst(p));
const pLog=p=>+p.logistics>0?+p.logistics:(p.method===INTERNAL?(+p.budget||pEst(p)):0);

/* ===================== تعديلات الخطة: نسخة الأساس + سجل التغييرات ===================== */
/* الخطة تقديرية: أي تعديل في نظام الاحتياجات (برامج/أعداد/ميزانية/فترة) يُرصد تلقائيًا ويُقارن بنسخة الأساس */
const perTxt=(a,b)=>a===b?MONTHS[a]:`${MONTHS[a]} - ${MONTHS[b]}`;
function planSummary(){const o={};P.programs.forEach(p=>{if(p.status==='ملغي')return;const ss=(p.sessions||[]).filter(x=>x&&x.from);
  o[p.id]={code:p.code||'',name:p.name||'',cat:p.category||'',method:p.method||'',tr:pTrainees(p),ss:ss.length||1,h:+p.hours||0,cost:pBudget(p)+pLog(p),per:perTxt(+p.startMonth||0,+p.endMonth||0)}});return o}
const planMeta=()=>({needs:P.needs.length,linked:P.needs.filter(n=>n.programId).length});
function planTotals(sm){const v=Object.values(sm||{});return{n:v.length,ss:v.reduce((a,x)=>a+x.ss,0),tr:v.reduce((a,x)=>a+x.tr,0),hrs:v.reduce((a,x)=>a+x.h*x.ss,0),cost:v.reduce((a,x)=>a+x.cost,0)}}
const DF=[['name','اسم البرنامج'],['cat','الفئة',v=>CATS[v]||v],['method','أسلوب التدريب'],['tr','عدد المتدربين',v=>fmt(v)],['ss','عدد الجلسات',v=>fmt(v)],['h','ساعات الجلسة',v=>fmt(v,1)],['cost','الميزانية (ج.م)',v=>fmt(v)],['per','الفترة']];
function planDiff(a,b){const out=[];a=a||{};b=b||{};
  Object.keys(b).forEach(id=>{const x=b[id];if(!a[id])out.push({t:'add',id,code:x.code,name:x.name,cost:x.cost,tr:x.tr});else{const y=a[id];const f=DF.filter(([k])=>String(y[k]??'')!==String(x[k]??'')).map(([k,l,fm])=>({k,l,from:fm?fm(y[k]):y[k],to:fm?fm(x[k]):x[k],d:typeof x[k]==='number'?x[k]-(+y[k]||0):null}));if(f.length)out.push({t:'mod',id,code:x.code,name:x.name,f})}});
  Object.keys(a).forEach(id=>{if(!b[id])out.push({t:'del',id,code:a[id].code,name:a[id].name,cost:a[id].cost,tr:a[id].tr})});return out}
const diffCount=d=>({add:d.filter(x=>x.t==='add').length,del:d.filter(x=>x.t==='del').length,mod:d.filter(x=>x.t==='mod').length});
const curBase=()=>R.baselines.find(b=>b.id===R.activeBase)||R.baselines[R.baselines.length-1]||null;
function trackPlan(){if(!P.programs.length)return;const cur=planSummary();let ch=false;
  if(!R.baselines.length){R.baselines.push({id:uid(),name:'النسخة التقديرية الأولى',auto:true,at:today(),src:PLAN_AT||PLAN_SRC,progs:cur,meta:planMeta()});ch=true}
  if(R.lastSeen){const d=planDiff(R.lastSeen,cur);if(d.length){R.planLog.unshift({at:new Date().toISOString(),src:PLAN_SRC,changes:d,before:planTotals(R.lastSeen),after:planTotals(cur)});R.planLog=R.planLog.slice(0,300);ch=true}}
  if(!R.lastSeen||ch){R.lastSeen=cur;ch=true}if(ch)save()}

/* ===================== بيانات التنفيذ (هذا النظام) ===================== */
function defaultsR(){return{settings:{coordName:'',coordPhone:'',hrManager:'أ/ أيمن الشهابي',formRev:'2',formDate:'11/2026',waTpl:'invite',passMark:70,l3Days:90,hoursTarget:12,venues:['قاعة التدريب - الإدارة العامة','قاعة فرع الإسكندرية','أونلاين (Teams / Zoom)','داخل الفرع (OJT)'],seqU:0},
  trainers:[],employees:[],recs:{},adhoc:[],evals:{},baselines:[],planLog:[],lastSeen:null,activeBase:''}}
let R=loadR();
function loadR(){const d=defaultsR();try{const x=JSON.parse(localStorage.getItem(RKEY)||'null');if(x){Object.assign(d.settings,x.settings||{});['trainers','employees','adhoc','baselines','planLog'].forEach(k=>{if(Array.isArray(x[k]))d[k]=x[k]});if(x.activeBase)d.activeBase=x.activeBase;['recs','evals','lastSeen'].forEach(k=>{if(x[k]&&typeof x[k]==='object')d[k]=x[k]})}}catch(e){}return d}
function save(){try{localStorage.setItem(RKEY,JSON.stringify(R))}catch(e){toast('تعذر الحفظ على هذا المتصفح — صدّر نسخة احتياطية الآن',true)}if(window.SBSync)window.SBSync.onLocalSave()}

/* ===================== النموذج الموحد (خطة + تنفيذ) ===================== */
let M=null;
function buildModel(){
  const progs=[],byId={},slots=[],seen=new Set();const yr=YEAR();
  P.programs.filter(p=>p.status!=='ملغي').forEach(p=>{const ns=needsOf(p);
    const o={id:p.id,code:p.code||'',name:p.name||'',cat:p.category||'',method:p.method||'',provider:p.provider||'',owner:p.owner||'',hours:+p.hours||0,objective:p.objective||'',kpi:p.kpi||'',evalLevel:p.evalLevel||'',sm:+p.startMonth||0,em:+p.endMonth||0,pstatus:p.status||'',
      trainees:pTrainees(p),groups:pGroups(p),planCost:pBudget(p)+pLog(p),needs:ns,depts:[...new Set(ns.map(n=>n.dept).filter(Boolean))],adhoc:false,raw:p,slots:[]};
    progs.push(o);byId[o.id]=o});
  R.adhoc.forEach(a=>{const o={id:a.id,code:a.code,name:a.name,cat:a.category||'',method:a.method||'',provider:a.provider||'',owner:'',hours:+a.hours||0,objective:a.objective||'',kpi:a.kpi||'',evalLevel:'',sm:0,em:11,pstatus:'غير مخطط',
    trainees:+a.trainees||0,groups:0,planCost:0,needs:[],depts:a.dept?[a.dept]:[],adhoc:true,raw:a,slots:[]};progs.push(o);byId[o.id]=o});
  progs.filter(o=>!o.adhoc).forEach(o=>{let ss=(o.raw.sessions||[]).filter(s=>s&&s.from);
    if(!ss.length){const f=iso(new Date(yr,o.sm,1));ss=[{g:1,from:f,to:f}]}
    const seats=Math.ceil(o.trainees/ss.length);
    ss.forEach((s,i)=>{const g=+s.g||i+1;const key=o.id+'|'+g;if(seen.has(key))return;seen.add(key);slots.push(mkSlot(o,key,g,s.from,s.to||s.from,seats))})});
  Object.values(R.recs).forEach(r=>{if(seen.has(r.key))return;seen.add(r.key);let o=byId[r.progId];
    if(!o){const sn=r.snap||{};o={id:r.progId||'orph',code:sn.code||'؟',name:(sn.name||'برنامج محذوف من الخطة')+' (غير موجود بالخطة الحالية)',cat:sn.cat||'',method:sn.method||'',provider:'',hours:+sn.hours||0,trainees:0,groups:0,planCost:0,needs:[],depts:[],adhoc:true,orphan:true,raw:{},slots:[],kpi:'',evalLevel:'',objective:''};progs.push(o);byId[o.id]=o}
    const sl=mkSlot(o,r.key,r.g||1,r.pFrom||r.from,r.pTo||r.to||r.from,o.adhoc?(+r.seats||0):0);sl.unlinked=!!o.orphan||!o.adhoc;slots.push(sl)});
  slots.forEach(s=>s.prog.slots.push(s));
  slots.sort((a,b)=>String(a.from).localeCompare(String(b.from))||String(a.prog.code).localeCompare(String(b.prog.code))||a.g-b.g);
  M={progs,byId,slots};return M}
function mkSlot(o,key,g,pf,pt,seats){
  const r=R.recs[key]||null;const st=r?r.status||'مخطط':'مخطط';const from=(r&&r.from)||pf||'';const to=(r&&r.to)||pt||from;
  const att=r&&Array.isArray(r.att)?r.att:[];const present=att.filter(a=>a.st==='حاضر'||a.st==='متأخر');
  const done=st==='منفذ';const hours=r&&r.hours!==''&&r.hours!=null?num(r.hours):o.hours;
  const attended=done?(present.length||num(r&&r.attCount)):0;
  const sats=present.map(a=>num(a.sat)).filter(x=>x>0);const l1=sats.length?avg(sats):(r&&num(r.l1)>0?num(r.l1):null);
  const pre=present.map(a=>a.pre===''||a.pre==null?null:num(a.pre)),post=present.map(a=>a.post===''||a.post==null?null:num(a.post));
  const pairs=present.map((a,i)=>[pre[i],post[i]]).filter(x=>x[0]!=null&&x[1]!=null);
  const posts=post.filter(x=>x!=null);
  const pending=st==='مخطط'||st==='مؤجل';const t0=today();
  return{key,prog:o,g,pFrom:pf,pTo:pt,from,to,rec:r,status:st,done,pending,overdue:pending&&!!to&&to<t0,
    hours,seats:o.adhoc?(+(r&&r.seats)||0):seats,att,attended,registered:att.length,presentN:present.length,
    l1,l1n:done&&l1!=null?(sats.length||attended||1):0,
    preAvg:avg(pairs.map(x=>x[0])),postAvg:avg(pairs.map(x=>x[1])),pairs:pairs.length,pass:posts.filter(x=>x>=+R.settings.passMark).length,posted:posts.length,
    cost:done||st==='ملغي'?num(r&&r.costT)+num(r&&r.costL):0,trainer:(r&&r.trainer)||'',venue:(r&&r.venue)||'',month:from?pd(from).getMonth():-1}}
const dispSt=s=>s.overdue?'متأخر':s.status;
const stCls={'منفذ':'done','مخطط':'plan','مؤجل':'post','ملغي':'cancel','متأخر':'late'};
const stPill=s=>`<span class="st ${stCls[dispSt(s)]}">${dispSt(s)}</span>`;

function agg(S){
  const d=S.filter(s=>s.done);const reg=d.filter(s=>s.registered);
  const l1w=d.filter(s=>s.l1!=null);const l1=l1w.length?l1w.reduce((a,s)=>a+s.l1*s.l1n,0)/l1w.reduce((a,s)=>a+s.l1n,0):null;
  const pr=d.filter(s=>s.pairs);const pw=pr.reduce((a,s)=>a+s.pairs,0);
  const emp=new Set();d.forEach(s=>s.att.forEach(a=>{if(a.st==='حاضر'||a.st==='متأخر'){const k=a.code?'c:'+String(a.code).trim():'n:'+normKey(a.name);if(k.length>2)emp.add(k)}}));
  return{total:S.length,done:d.length,pending:S.filter(s=>s.pending).length,overdue:S.filter(s=>s.overdue).length,post:S.filter(s=>s.status==='مؤجل').length,cancel:S.filter(s=>s.status==='ملغي').length,
    seats:S.filter(s=>s.status!=='ملغي').reduce((a,s)=>a+s.seats,0),seatsDone:d.reduce((a,s)=>a+s.seats,0),attended:d.reduce((a,s)=>a+s.attended,0),
    registered:reg.reduce((a,s)=>a+s.registered,0),present:reg.reduce((a,s)=>a+s.presentN,0),
    hours:d.reduce((a,s)=>a+s.hours,0),planHours:S.filter(s=>s.status!=='ملغي').reduce((a,s)=>a+s.hours,0),manHours:d.reduce((a,s)=>a+s.attended*s.hours,0),
    l1,l1pct:l1!=null?Math.round(l1/5*100):null,
    pre:pw?pr.reduce((a,s)=>a+s.preAvg*s.pairs,0)/pw:null,post:pw?pr.reduce((a,s)=>a+s.postAvg*s.pairs,0)/pw:null,
    pass:d.reduce((a,s)=>a+s.pass,0),posted:d.reduce((a,s)=>a+s.posted,0),cost:S.reduce((a,s)=>a+s.cost,0),uniq:emp.size}}
const progStatus=o=>{const s=o.slots;if(!s.length)return'—';const d=s.filter(x=>x.done).length,live=s.filter(x=>x.status!=='ملغي').length;
  if(!live)return 'ملغي';if(d>=live)return 'مكتمل';if(d>0)return 'جارٍ التنفيذ';if(s.some(x=>x.overdue))return 'متأخر';return 'لم يبدأ'};
const progStCls={'مكتمل':'done','جارٍ التنفيذ':'post','لم يبدأ':'plan','متأخر':'late','ملغي':'cancel','—':'cancel'};

/* ===================== الواجهة العامة ===================== */
let VIEW='dash';
const VIEWS=[{k:'dash',t:'لوحة القيادة'},{k:'exec',t:'التنفيذ والحضور',cnt:()=>M.slots.filter(s=>s.overdue).length,warn:true},{k:'progs',t:'البرامج'},{k:'people',t:'الموظفون'},
  {k:'eval',t:'التقييم'},{k:'budget',t:'الميزانية'},{k:'needs',t:'الاحتياجات'},{k:'changes',t:'تعديلات الخطة',cnt:()=>M.slots.filter(s=>s.unlinked).length},{k:'trainers',t:'المدربون'},{k:'reports',t:'التقارير'},{k:'set',t:'الإعدادات'}];
function logoHTML(){const lg=PS().logo||(typeof PLAN_LOGO!=='undefined'?PLAN_LOGO:'');return lg?`<img src="${lg}" alt="${esc(ORG())}">`:`<span class="logo-txt">زهـ<span>ـران</span></span>`}
function renderChrome(){
  $('nav').innerHTML=VIEWS.map(v=>{const c=v.cnt?v.cnt():0;return `<button class="${VIEW===v.k?'on':''}" onclick="go('${v.k}')">${v.t}${c?`<span class="cnt" title="${v.k==='exec'?'جلسات متأخرة':'تسجيلات تحتاج إعادة ربط'}">${c}</span>`:''}</button>`}).join('');
  $('logoBox').innerHTML=logoHTML()+`<span><small>نظام إدارة وتسجيل التدريب ${YEAR()}</small></span>`;
  const lp=$('linkPill');const live=PLAN_SRC==='live';
  lp.className='linkpill '+(live?'live':'snap');
  const srcT=live?'الخطة: مباشر':PLAN_SRC==='import'?'الخطة: ملف مستورد':PLAN_SRC==='cache'?'الخطة: آخر نسخة':'الخطة: نسخة مدمجة';lp.innerHTML=`<i></i>${PLAN_ST==='تعذر الاتصال'?(live?'الخطة: آخر نسخة':srcT)+' (غير متصل)':PLAN_ST==='جارٍ التحديث...'?'الخطة: تحديث…':srcT}`;if(PLAN_ST==='تعذر الاتصال')lp.className='linkpill snap';
  lp.title='اضغط لتحديث البيانات من نظام الاحتياجات'+(PLAN_AT?` — آخر تحديث: ${PLAN_AT}`:'');
  if(window.SBSync)window.SBSync.paint();
  $('ftOrg').innerHTML=`<b>${esc(ORG())}</b> | ${esc(UNIT())}`;
  document.title=`نظام إدارة وتسجيل التدريب ${YEAR()} | ${ORG()}`}
function go(v){VIEW=v;closeModal();render();window.scrollTo(0,0)}
function render(){buildModel();renderChrome();const f={changes:vChanges,dash:vDash,exec:vExec,progs:vProgs,people:vPeople,eval:vEval,budget:vBudget,needs:vNeeds,trainers:vTrainers,reports:vReports,set:vSet}[VIEW]||vDash;
  $('main').innerHTML=f();if(VIEW==='exec')drawExec();if(VIEW==='people')drawPeople();if(VIEW==='progs')drawProgs();if(VIEW==='reports')drawReport()}
const printHead=()=>`<div class="print-head">${esc(ORG())} | ${esc(UNIT())} | تاريخ الطباعة: ${today()}</div>`;
const pageTop=(title,sub,acts='')=>printHead()+`<section class="pband"><div class="in"><div><h1>${title}</h1>${sub?`<p>${sub}</p>`:''}</div><div class="acts">${acts}</div></div></section><div class="in wrap">`;
const sec=(h,p)=>`<div class="sec"><h2>${h}</h2>${p?`<p>${p}</p>`:''}</div>`;
const kpi=(l,v,s='',bar=null,hl=false)=>`<div class="kpi${hl?' hl':''}"><div class="l">${l}</div><div class="v">${v}</div>${s?`<div class="s">${s}</div>`:''}${bar!=null?`<div class="bar"><i style="width:${Math.min(100,bar)}%"></i></div>`:''}</div>`;
let NEED_RENDER=false;
function closeModal(){const m=$('modal');m.classList.remove('show');m.innerHTML='';document.body.classList.remove('print-modal');if(NEED_RENDER){NEED_RENDER=false;setTimeout(render,0)}}
function openModal(html,cls=''){const m=$('modal');m.innerHTML=`<div class="modal ${cls}">${html}</div>`;m.classList.add('show')}
/* tooltip */
document.addEventListener('mouseover',e=>{const t=e.target.closest('[data-tip]');const tip=$('tip');if(!t){tip.style.display='none';return}tip.textContent=t.dataset.tip;tip.style.display='block'});
document.addEventListener('mousemove',e=>{const tip=$('tip');if(tip.style.display!=='block')return;const w=tip.offsetWidth,h=tip.offsetHeight;let x=e.clientX+14,y=e.clientY+14;if(x+w>innerWidth-8)x=e.clientX-w-14;if(y+h>innerHeight-8)y=e.clientY-h-14;tip.style.left=x+'px';tip.style.top=y+'px'});

/* ===================== لوحة القيادة ===================== */
function vDash(){
  const S=M.slots,A=agg(S),t0=today();const ytd=S.filter(s=>s.to&&s.to<=t0);const Y=agg(ytd);
  const live=M.progs.filter(o=>!o.adhoc);const started=live.filter(o=>o.slots.some(s=>s.done)).length;const complete=live.filter(o=>progStatus(o)==='مكتمل').length;
  const planCost=live.reduce((a,o)=>a+o.planCost,0);
  const needsL=P.needs.filter(n=>n.programId&&M.byId[n.programId]);const needsCovered=needsL.filter(n=>M.byId[n.programId].slots.some(s=>s.done)).length;
  let h=pageTop(`لوحة القيادة التنفيذية — تدريب ${YEAR()}`,`متابعة تنفيذ الخطة التدريبية المعتمدة في نظام الاحتياجات (${live.length} برنامج | ${S.filter(s=>!s.prog.adhoc).length} جلسة مخططة) مقابل التنفيذ الفعلي.`,
    `<button class="btn-out" onclick="go('reports')">التقرير الأسبوعي</button><button class="btn-out" onclick="exportExcel()">تصدير Excel</button><button class="btn" onclick="go('exec')">تسجيل تنفيذ جلسة</button>`);
  if(!P.programs.length)h+=`<div class="alert err">لا توجد بيانات خطة بعد. افتح الإعدادات > الربط بالخطة واضغط "تحديث من نظام الاحتياجات" أو استورد نسخة JSON من نظام الاحتياجات.</div>`;
  const B=curBase();if(B){const d=planDiff(B.progs,planSummary());if(d.length){const c=diffCount(d),tb=planTotals(B.progs),tc=planTotals(planSummary());h+=`<div class="alert info"><b>الخطة الحالية معدّلة عن نسخة الأساس "${esc(B.name)}":</b> ${c.add} برنامج مضاف، ${c.del} محذوف، ${c.mod} معدّل | المتدربون ${fmt(tb.tr)} ← ${fmt(tc.tr)} | الميزانية ${fmt(tb.cost)} ← ${fmt(tc.cost)} ج.م. كل المؤشرات تُحسب على الخطة الحالية. <button class="btn-ghost" onclick="go('changes')">عرض التعديلات</button></div>`}}
  const UL=S.filter(s=>s.unlinked).length;if(UL)h+=`<div class="alert err"><b>${UL} تسجيل تنفيذ</b> لم يعد مرتبطًا بجلسة في الخطة الحالية (حُذف البرنامج أو قلّ عدد مجموعاته). <button class="btn-ghost" onclick="go('changes')">إعادة الربط</button></div>`;
  if(A.overdue)h+=`<div class="alert err"><b>${A.overdue} جلسة متأخرة</b> عن موعدها المخطط ولم يُسجَّل تنفيذها. <button class="btn-ghost" onclick="EF=Object.assign(blankEF(),{st:'متأخر'});go('exec')">عرض الجلسات المتأخرة</button></div>`;
  h+=`<div class="kpis">
    ${kpi('الجلسات المنفذة',`${fmt(A.done)}<small>من ${fmt(A.total-A.cancel)}</small>`,`حتى اليوم: ${fmt(Y.done)} من ${fmt(ytd.length-Y.cancel)} مستحقة (${pct(Y.done,ytd.length-Y.cancel)}%)`,pct(A.done,A.total-A.cancel),true)}
    ${kpi('البرامج',`${fmt(started)}<small>بدأت من ${fmt(live.length)}</small>`,`مكتملة: ${fmt(complete)} | غير مخططة: ${fmt(M.progs.filter(o=>o.adhoc&&!o.orphan).length)}`,pct(started,live.length))}
    ${kpi('المتدربون (حضور فعلي)',`${fmt(A.attended)}<small>من ${fmt(A.seats)} مقعد</small>`,`موظفون فريدون: ${fmt(A.uniq)}`,pct(A.attended,A.seats))}
    ${kpi('ساعات التدريب',`${fmt(A.hours)}<small>من ${fmt(A.planHours)}</small>`,`ساعات متدرب: ${fmt(A.manHours)}`,pct(A.hours,A.planHours))}
    ${kpi('نسبة الحضور',A.registered?pc(pct(A.present,A.registered)):'—',A.registered?`${fmt(A.present)} حاضر من ${fmt(A.registered)} مسجل`:'تُحسب عند تسجيل كشوف الحضور',A.registered?pct(A.present,A.registered):null)}
    ${kpi('رضا المتدربين (L1)',A.l1pct!=null?pc(A.l1pct):'—',A.l1!=null?`متوسط ${A.l1.toFixed(2)} من 5`:'لا توجد تقييمات بعد',A.l1pct)}
    ${kpi('التعلم (L2)',A.post!=null?`${pc(Math.round(A.post-A.pre))}<small>تحسن</small>`:'—',A.posted?`قبلي ${Math.round(A.pre||0)}% ← بعدي ${Math.round(A.post||0)}% | نجاح ${pct(A.pass,A.posted)}%`:'يُحسب من الاختبار القبلي والبعدي')}
    ${kpi('التكلفة الفعلية',`${fmt(A.cost)}<small>ج.م</small>`,`المخطط: ${fmt(planCost)} ج.م (${pct(A.cost,planCost)}%)`,pct(A.cost,planCost))}
    ${kpi('تغطية الاحتياجات',`${fmt(needsCovered)}<small>من ${fmt(needsL.length)}</small>`,'احتياجات بدأ تنفيذ برامجها',pct(needsCovered,needsL.length))}
  </div>`;
  /* monthly chart */
  const mm=MONTHS.map((_,i)=>{const s=S.filter(x=>x.month===i&&x.status!=='ملغي');return{p:s.length,d:s.filter(x=>x.done).length,a:s.reduce((a,x)=>a+x.attended,0)}});const mx=Math.max(1,...mm.map(x=>x.p));
  h+=`<div class="grid g2" style="margin-top:14px"><div class="card"><h3 style="margin:0 0 4px;font-size:15px">الجلسات المخططة مقابل المنفذة شهريًا</h3>
    <div class="legend"><span><i style="background:var(--c-track)"></i>مخطط</span><span><i style="background:var(--c-act)"></i>منفذ</span></div>
    <div class="mchart">${mm.map((x,i)=>`<div class="mcol" data-tip="${MONTHS[i]}\nمخطط: ${x.p} جلسة\nمنفذ: ${x.d} جلسة (${pct(x.d,x.p)}%)\nمتدربون: ${fmt(x.a)}"><div class="stack"><div class="trk" style="height:${x.p/mx*100}%"></div><div class="act" style="height:${x.d/mx*100}%"></div></div></div>`).join('')}</div>
    <div class="mlabels">${MONTHS.map(m=>`<span>${m.slice(0,3)}</span>`).join('')}</div>
    <details class="no-print"><summary class="sub" style="cursor:pointer">عرض كجدول</summary><div class="tbl-wrap" style="margin-top:6px"><table><thead><tr><th>الشهر</th><th class="num">مخطط</th><th class="num">منفذ</th><th class="num">%</th><th class="num">متدربون</th></tr></thead><tbody>${mm.map((x,i)=>`<tr><td>${MONTHS[i]}</td><td class="num">${x.p}</td><td class="num">${x.d}</td><td class="num">${pc(pct(x.d,x.p))}</td><td class="num">${fmt(x.a)}</td></tr>`).join('')}</tbody></table></div></details></div>`;
  /* category mix */
  const tg=Object.assign({T:40,S:35,M:25},PS().targets||{});const byC={T:0,S:0,M:0};S.filter(s=>s.done).forEach(s=>{if(byC[s.prog.cat]!=null)byC[s.prog.cat]+=s.attended*s.hours});const tot=CK.reduce((a,k)=>a+byC[k],0);
  const pbyC={T:0,S:0,M:0};S.filter(s=>s.status!=='ملغي').forEach(s=>{if(pbyC[s.prog.cat]!=null)pbyC[s.prog.cat]+=s.seats*s.hours});const ptot=CK.reduce((a,k)=>a+pbyC[k],0);
  const bar=(o,t)=>`<div class="sbar">${CK.filter(k=>o[k]>0).map(k=>`<span style="width:${o[k]/t*100}%;background:var(${CATVAR[k]})" data-tip="${CATS[k]}: ${pct(o[k],t)}% (${fmt(o[k])} ساعة متدرب)"></span>`).join('')||'<span style="width:100%;background:var(--c-track)"></span>'}</div>`;
  h+=`<div class="card"><h3 style="margin:0 0 4px;font-size:15px">توازن التدريب حسب الفئة (ساعات متدرب)</h3>
    <div class="legend">${CK.map(k=>`<span><i style="background:var(${CATVAR[k]})"></i>${CATS[k]}</span>`).join('')}</div>
    <div class="sub" style="margin-top:6px">المخطط</div>${bar(pbyC,ptot||1)}<div class="sub" style="margin-top:10px">المنفذ فعليًا</div>${bar(byC,tot||1)}
    <div class="tbl-wrap" style="margin-top:12px"><table><thead><tr><th>الفئة</th><th class="num">المستهدف بالخطة</th><th class="num">المخطط</th><th class="num">المنفذ</th></tr></thead><tbody>${CK.map(k=>`<tr><td>${chip(k)}</td><td class="num">${pc(tg[k]||0)}</td><td class="num">${pc(pct(pbyC[k],ptot))}</td><td class="num">${tot?pc(pct(byC[k],tot)):'—'}</td></tr>`).join('')}</tbody></table></div></div></div>`;
  /* upcoming + overdue */
  const up=S.filter(s=>s.pending&&s.from>=t0).slice(0,8);const od=S.filter(s=>s.overdue).slice(-8).reverse();
  const li=s=>`<div class="li" onclick="openSession('${s.key}')"><span>${cdc(s.prog.code)} ${esc(s.prog.name)} <span class="sub">| مجموعة ${s.g}</span></span><span class="sub">${rng(s.from,s.to)}</span></div>`;
  h+=`<div class="grid g2" style="margin-top:14px"><div class="card"><h3 style="margin:0 0 8px;font-size:15px">الجلسات القادمة</h3><div class="list">${up.map(li).join('')||'<div class="empty">لا توجد جلسات قادمة</div>'}</div></div>
    <div class="card"><h3 style="margin:0 0 8px;font-size:15px">جلسات متأخرة تحتاج تسجيل أو إعادة جدولة</h3><div class="list">${od.map(li).join('')||'<div class="empty">لا توجد جلسات متأخرة</div>'}</div></div></div>`;
  /* departments */
  const dm={};P.needs.filter(n=>n.programId&&M.byId[n.programId]).forEach(n=>{const o=M.byId[n.programId];const d=n.dept||'—';dm[d]=dm[d]||{need:0,req:0,cov:0};dm[d].need++;dm[d].req+=+n.trainees||0;if(o.slots.some(s=>s.done))dm[d].cov++});
  const dl=Object.entries(dm).sort((a,b)=>b[1].need-a[1].need);
  h+=sec('تقدم التنفيذ حسب الإدارة','عدد احتياجات كل إدارة المرتبطة ببرامج، ونسبة ما بدأ تنفيذه منها.')+`<div class="card hbars">${dl.map(([d,x])=>`<div class="row"><span>${esc(d)}</span><div class="trk2" data-tip="${esc(d)}\n${x.cov} من ${x.need} احتياج بدأ تنفيذه\nمتدربون مطلوبون: ${x.req}"><i style="width:${pct(x.cov,x.need)}%"></i></div><span class="sub">${x.cov}/${x.need} (${pct(x.cov,x.need)}%)</span></div>`).join('')||'<div class="empty">لا توجد بيانات</div>'}</div>`;
  return h}

/* ===================== التنفيذ والحضور ===================== */
const blankEF=()=>({q:'',m:'',st:'',cat:'',method:'',dept:''});let EF=blankEF();
function vExec(){const methods=[...new Set(M.progs.map(o=>o.method).filter(Boolean))];const depts=[...new Set(M.progs.flatMap(o=>o.depts))].sort();
  return pageTop('التنفيذ والحضور','كل جلسة مخططة في الخطة السنوية تظهر هنا تلقائيًا. افتح الجلسة لتسجيل التنفيذ الفعلي، المدرب، التكلفة، كشف الحضور ودرجات التقييم.',
    `<button class="btn-out" onclick="newAdhoc()">+ تدريب غير مخطط</button><button class="btn-out" onclick="exportExcel()">تصدير Excel</button>`)+
  `<div class="filters"><input type="search" placeholder="بحث بالبرنامج / الكود / المدرب..." value="${esc(EF.q)}" oninput="EF.q=this.value;drawExec()">
   <select onchange="EF.m=this.value;drawExec()">${opt(MONTHS.map((m,i)=>[i,m]),EF.m,'كل الشهور')}</select>
   <select onchange="EF.st=this.value;drawExec()">${opt([...SESS_ST,'متأخر'],EF.st,'كل الحالات')}</select>
   <select onchange="EF.cat=this.value;drawExec()">${opt(CK.map(k=>[k,CATS[k]]),EF.cat,'كل الفئات')}</select>
   <select onchange="EF.method=this.value;drawExec()">${opt(methods,EF.method,'كل الأساليب')}</select>
   <select onchange="EF.dept=this.value;drawExec()">${opt(depts,EF.dept,'كل الإدارات')}</select>
   <button class="btn-ghost" onclick="EF=blankEF();render()">مسح الفلاتر</button><span class="sub" id="execCnt"></span></div><div id="execTbl"></div>`}
function execFiltered(){const q=normKey(EF.q).toLowerCase();return M.slots.filter(s=>{
  if(EF.m!==''&&s.month!==+EF.m)return false;if(EF.st&&dispSt(s)!==EF.st)return false;if(EF.cat&&s.prog.cat!==EF.cat)return false;if(EF.method&&s.prog.method!==EF.method)return false;
  if(EF.dept&&!s.prog.depts.includes(EF.dept))return false;
  if(q&&!normKey([s.prog.code,s.prog.name,s.trainer,s.venue,s.prog.provider].join(' ')).toLowerCase().includes(q))return false;return true})}
function drawExec(){const el=$('execTbl');if(!el)return;const L=execFiltered();const A=agg(L);
  $('execCnt').textContent=`${L.length} جلسة | منفذ ${A.done} | متأخر ${A.overdue}`;
  el.innerHTML=`<div class="tbl-wrap"><table><thead><tr><th>التاريخ</th><th>البرنامج</th><th class="num">المجموعة</th><th>الفئة</th><th>الأسلوب / الجهة</th><th>المدرب</th><th class="num">المقاعد</th><th class="num">الحضور</th><th class="num">الرضا</th><th>الحالة</th><th></th></tr></thead><tbody>${
    L.slice(0,800).map(s=>`<tr><td>${rng(s.from,s.to)}${s.rec&&s.rec.from&&s.rec.from!==s.pFrom?`<div class="sub">المخطط: ${fmtD(s.pFrom)}</div>`:''}</td>
    <td>${cdc(s.prog.code)} <b>${esc(s.prog.name)}</b>${s.prog.adhoc&&!s.prog.orphan?' <span class="sub">(غير مخطط)</span>':''}<div class="sub">${esc(s.prog.depts.slice(0,3).join('، '))}${s.prog.depts.length>3?' ...':''}</div></td>
    <td class="num">${s.g}</td><td>${chip(s.prog.cat)}</td><td>${esc(s.prog.method)}<div class="sub">${esc(s.prog.provider)}</div></td><td>${esc(s.trainer)||'<span class="sub">—</span>'}</td>
    <td class="num">${s.seats||'—'}</td><td class="num">${s.done?`<b>${s.attended}</b>${s.registered?`<div class="sub">${pct(s.presentN,s.registered)}%</div>`:''}`:'—'}</td>
    <td class="num">${s.l1!=null?pc(Math.round(s.l1/5*100)):'—'}</td><td>${stPill(s)}</td>
    <td><button class="btn-out btn-sm" onclick="openSession('${s.key}')">${s.done?'عرض / تعديل':'تسجيل'}</button></td></tr>`).join('')||`<tr><td colspan="11" class="empty">لا توجد جلسات مطابقة</td></tr>`}</tbody></table></div>${L.length>800?'<div class="sub">يُعرض أول 800 جلسة — استخدم الفلاتر لتضييق النتائج.</div>':''}`}

/* ---- نافذة تسجيل الجلسة ---- */
let ATT=[],CUR=null;
function openSession(key){buildModel();const s=M.slots.find(x=>x.key===key);if(!s){toast('الجلسة غير موجودة',true);return}CUR=s;const r=s.rec||{};const o=s.prog;
  ATT=(r.att||[]).map(a=>Object.assign({},a));
  const trainers=R.trainers.map(t=>t.name);
  openModal(`<div class="mh"><div><h3>${cdc(o.code)} ${esc(o.name)} — مجموعة ${s.g}</h3><div class="sub">${chip(o.cat)} ${esc(o.method)} ${o.provider?'| '+esc(o.provider):''}</div></div><button class="x" onclick="closeModal()">×</button></div>
  <form class="mb" id="sessForm" onsubmit="event.preventDefault();saveSession()">
   ${s.unlinked?`<div class="alert err" style="margin-top:0"><b>هذا التسجيل غير مرتبط بجلسة في الخطة الحالية</b> (حُذف البرنامج أو تغيّر عدد مجموعاته في نظام الاحتياجات). البيانات محفوظة كما هي — اختر الجلسة المقابلة في الخطة الحالية لإعادة ربطها:<select name="relink" style="margin-top:8px">${opt(M.slots.filter(x=>!x.rec&&!x.prog.adhoc).map(x=>[x.key,`${x.prog.code} ${x.prog.name} — مجموعة ${x.g} (${fmtD(x.pFrom)})`]),'','— إبقاء التسجيل كما هو —')}</select></div>`:''}
   <div class="info-row"><span><b>الموعد المخطط:</b>${rng(s.pFrom,s.pTo)}</span><span><b>ساعات الجلسة:</b>${o.hours}</span><span><b>المقاعد المخططة:</b>${s.seats||'—'}</span><span><b>المستهدف بالتقييم:</b>${esc(o.evalLevel||'—')}</span><span><b>مؤشر الأداء:</b>${esc(o.kpi||'—')}</span><span><b>الإدارات:</b>${esc(o.depts.join('، ')||'—')}</span></div>
   <div class="fgrid">
    <div class="f"><label>حالة الجلسة</label><select name="status">${opt(SESS_ST,s.status)}</select></div>
    <div class="f"><label>تاريخ التنفيذ الفعلي (من)</label><input type="date" name="from" value="${esc(s.from)}"></div>
    <div class="f"><label>إلى</label><input type="date" name="to" value="${esc(s.to)}"></div>
    <div class="f"><label>من الساعة</label><input type="time" name="tFrom" value="${esc(r.tFrom||'')}"></div>
    <div class="f"><label>إلى الساعة</label><input type="time" name="tTo" value="${esc(r.tTo||'')}"></div>
    <div class="f"><label>الساعات الفعلية</label><input type="number" step="0.5" min="0" name="hours" value="${esc(r.hours??o.hours)}"></div>
    <div class="f"><label>المدرب</label><input name="trainer" list="dlTr" value="${esc(r.trainer||'')}" placeholder="اختر أو اكتب"><datalist id="dlTr">${trainers.map(x=>`<option value="${esc(x)}">`).join('')}</datalist></div>
    <div class="f"><label>مكان التنفيذ</label><input name="venue" list="dlVen" value="${esc(r.venue||'')}"><datalist id="dlVen">${(R.settings.venues||[]).map(x=>`<option value="${esc(x)}">`).join('')}</datalist></div>
    <div class="f"><label>تكلفة المدرب / الجهة (ج.م)</label><input type="number" min="0" name="costT" value="${esc(r.costT||'')}"></div>
    <div class="f"><label>تكلفة لوجستية (قاعة/ضيافة/انتقالات)</label><input type="number" min="0" name="costL" value="${esc(r.costL||'')}"></div>
    ${o.adhoc?`<div class="f"><label>المقاعد المخططة</label><input type="number" min="0" name="seats" value="${esc(r.seats||'')}"></div>`:''}
    <div class="f"><label>عدد الحضور (إن لم تُسجَّل الأسماء)</label><input type="number" min="0" name="attCount" value="${esc(r.attCount||'')}"><span class="hint">يُستخدم فقط إذا كان كشف الأسماء فارغًا</span></div>
    <div class="f"><label>تقييم الجلسة الإجمالي (1-5)</label><input type="number" min="0" max="5" step="0.1" name="l1" value="${esc(r.l1||'')}"><span class="hint">يُحسب تلقائيًا من تقييمات المتدربين إن وُجدت</span></div>
    <div class="f wall"><label>ملاحظات / سبب التأجيل أو الإلغاء</label><textarea name="notes" style="min-height:54px">${esc(r.notes||'')}</textarea></div>
   </div>
   <div class="sec" style="margin-top:18px"><h2>المرشحون وكشف الحضور والتقييم</h2><p>أضف المرشحين بعد إرسال الدعوة، واكتب رقم الموبايل، ثم اضغط أيقونة واتساب بجوار الاسم لإرسال الرسالة. الحالة: حاضر / متأخر / غائب / اعتذر — القبلي والبعدي من 100 — الرضا من 1 إلى 5. كتابة الكود الوظيفي تستكمل الاسم والموبايل من بيانات الموظفين.</p></div>
   <div class="filters no-print" style="margin:0 0 8px"><label class="sub">رسالة واتساب:</label><select id="waTpl" onchange="R.settings.waTpl=this.value">${opt(Object.entries(WA_TPL).map(([k,v])=>[k,v.t]),R.settings.waTpl||'invite')}</select><span class="sub">النماذج الرسمية لهذه الجلسة:</span><button type="button" class="btn-out btn-sm" onclick="printForm('F09')">إخطار متدربين TR-P-F09</button><button type="button" class="btn-out btn-sm" onclick="printForm('F03')">بيان حضور TR-P-F03</button><button type="button" class="btn-out btn-sm" onclick="printForm('F04')">استمارات تقييم TR-P-F04</button></div>
   <div class="acts no-print" style="margin-bottom:8px"><button type="button" class="btn-out btn-sm" onclick="addAtt()">+ متدرب</button><button type="button" class="btn-out btn-sm" onclick="pasteAtt()">لصق من Excel</button><button type="button" class="btn-out btn-sm" onclick="$('fileA').click()">استيراد ملف Excel</button><button type="button" class="btn-out btn-sm" onclick="ATT.forEach(a=>a.st='حاضر');drawAtt()">تحديد الكل حاضر</button><button type="button" class="btn-out btn-sm" onclick="attTemplate()">نموذج كشف حضور</button></div>
   <div id="attBox"></div>
  </form>
  <div class="mf">${s.rec?`<button class="btn-out" style="color:var(--danger)" onclick="clearSession()">مسح التسجيل</button>`:''}<button class="btn-out" onclick="closeModal()">إلغاء</button><button class="btn" onclick="saveSession()">حفظ</button></div>`);
  drawAtt()}
function drawAtt(){const el=$('attBox');if(!el)return;
  const sum=ATT.length?`<div class="sub" style="margin-top:6px">المسجلون: ${ATT.length} | الحاضرون: ${ATT.filter(a=>a.st==='حاضر'||a.st==='متأخر').length} | لهم رقم موبايل: ${ATT.filter(a=>waNum(a.phone)).length} | أُرسلت لهم رسالة: ${ATT.filter(a=>a.waAt).length}</div>`:'';
  el.innerHTML=ATT.length?`<div class="tbl-wrap"><table class="att"><thead><tr><th>#</th><th>الكود</th><th>الاسم</th><th>الموبايل</th><th title="إرسال واتساب">واتساب</th><th>الإدارة</th><th>الفرع / الموقع</th><th>الوظيفة</th><th>الحضور</th><th>قبلي</th><th>بعدي</th><th>الرضا</th><th></th></tr></thead><tbody>${ATT.map((a,i)=>`<tr><td class="sub">${i+1}</td>
    <td><input class="c" value="${esc(a.code||'')}" onchange="ua(${i},'code',this.value)"></td><td><input value="${esc(a.name||'')}" onchange="ua(${i},'name',this.value)" style="min-width:150px"></td><td><input class="ph" dir="ltr" inputmode="tel" placeholder="01xxxxxxxxx" value="${esc(a.phone||'')}" onchange="ua(${i},'phone',this.value)"></td><td class="num"><button type="button" class="wa${a.waAt?' sent':''}" onclick="sendWA(${i})" data-tip="${a.waAt?`تم الإرسال (${esc((WA_TPL[a.waType]||{}).t||'')}) ${esc(String(a.waAt).slice(0,16).replace('T',' '))}\nاضغط للإرسال مرة أخرى`:'إرسال رسالة واتساب'}">${WA_SVG}</button></td>
    <td><input value="${esc(a.dept||'')}" onchange="ua(${i},'dept',this.value)" style="min-width:110px"></td><td><input value="${esc(a.branch||'')}" onchange="ua(${i},'branch',this.value)" style="min-width:100px"></td><td><input value="${esc(a.job||'')}" onchange="ua(${i},'job',this.value)" style="min-width:100px"></td>
    <td><select onchange="ua(${i},'st',this.value)">${opt(ATT_ST,a.st||'حاضر')}</select></td>
    <td><input class="n" type="number" min="0" max="100" value="${esc(a.pre??'')}" onchange="ua(${i},'pre',this.value)"></td><td><input class="n" type="number" min="0" max="100" value="${esc(a.post??'')}" onchange="ua(${i},'post',this.value)"></td>
    <td><input class="n" type="number" min="0" max="5" step="0.5" value="${esc(a.sat??'')}" onchange="ua(${i},'sat',this.value)"></td><td><button type="button" class="btn-del" onclick="ATT.splice(${i},1);drawAtt()">حذف</button></td></tr>`).join('')}</tbody></table></div>${sum}`
  :`<div class="empty" style="border:1px dashed var(--line);border-radius:10px">لا يوجد متدربون مسجلون. أضف متدربًا أو الصق الكشف من Excel (الأعمدة: الكود، الاسم، الإدارة، الفرع، الوظيفة).</div>`}
const empIdx=()=>{const m={};R.employees.forEach(e=>{if(e.code)m[String(e.code).trim()]=e});return m};
function fillEmp(a,idx){const e=a.code&&idx[String(a.code).trim()];if(e){['name','dept','branch','job','phone'].forEach(k=>{if(!a[k])a[k]=e[k]||''})}return a}
function ua(i,k,v){ATT[i][k]=v;if(k==='code'){const before=ATT[i].name+'|'+(ATT[i].phone||'');fillEmp(ATT[i],empIdx());if(before!==ATT[i].name+'|'+(ATT[i].phone||''))drawAtt()}}
function addAtt(){ATT.push({code:'',name:'',phone:'',dept:'',branch:'',job:'',st:'حاضر',pre:'',post:'',sat:''});drawAtt();const ins=document.querySelectorAll('#attBox tbody tr:last-child input');if(ins[0])ins[0].focus()}
function parseRows(text){return String(text).replace(/\r/g,'').split('\n').map(l=>l.trim()?l.split('\t').map(x=>x.trim()):null).filter(Boolean)}
const HDR={phone:/موبايل|محمول|هاتف|تليفون|جوال|واتس|phone|mobile|whats/i,code:/كود|الرقم الوظيفي|رقم|code|id/i,name:/اسم|name/i,dept:/ادار|إدار|قسم|dept|department/i,branch:/فرع|موقع|branch|location/i,job:/وظيف|مسمى|job|title|position/i,st:/حضور|حالة|status|attend/i,pre:/قبل|pre/i,post:/بعد|post/i,sat:/رضا|تقييم|sat|rating/i};
function matchHdr(h){const hm={};Object.keys(HDR).forEach(k=>{const i=h.findIndex((c,j)=>HDR[k].test(c)&&!(k==='name'&&/برنامج|دورة|مدرب|مدير/.test(c))&&!(k==='code'&&/برنامج|دورة/.test(c))&&!Object.values(hm).includes(j));if(i>=0)hm[k]=i});return hm}
/* يتعرف على صف العناوين أينما كان (أول 25 صفًا) — يدعم النماذج الرسمية TR-P-F03 / F09 */
function rowsToPeople(rows){if(!rows.length)return[];let map=null;
  for(let r=0;r<Math.min(rows.length,25);r++){const cells=rows[r].map(x=>String(x||'').trim());const hm=matchHdr(cells);const n=Object.keys(hm).filter(k=>k!=='phone').length;if((n>=2||(n===1&&cells.filter(Boolean).length===1))&&(hm.name!=null||hm.code!=null)){map=hm;rows=rows.slice(r+1);break}}
  return rows.map(r=>{let a;if(map){a={};Object.keys(map).forEach(k=>a[k]=String(r[map[k]]??'').trim())}
    else if(r.length===1){const v=String(r[0]).trim();const m=v.match(/^(\d+)\s+(.+)$/);a=m?{code:m[1],name:m[2]}:/^\d+$/.test(v)?{code:v}:{name:v}}
    else{const first=/^\d+$/.test(String(r[0]).trim());a=first?{code:r[0],name:r[1],dept:r[2],branch:r[3],job:r[4]}:{name:r[0],dept:r[1],branch:r[2],job:r[3]}}
    const st=String(a.st||'');a.st=/غائب|absent/i.test(st)?'غائب':/متأخر|late/i.test(st)?'متأخر':/اعتذ|excus/i.test(st)?'اعتذر':'حاضر';
    if(a.phone)a.phone=String(a.phone).replace(/[^\d+]/g,'');if(a.phone&&/^1\d{9}$/.test(a.phone))a.phone='0'+a.phone;
    a.code=String(a.code||'').trim();a.name=String(a.name||'').trim();
    return Object.assign({code:'',name:'',phone:'',dept:'',branch:'',job:'',pre:'',post:'',sat:''},a)})
    .filter(a=>(a.name||a.code)&&!(a.code&&!/^[A-Za-z0-9\-]+$/.test(a.code))&&!(map&&!a.name&&!/^\d+$/.test(a.code))&&!/^\d+$/.test(a.name))}
function pasteAtt(){openModal2(`<div class="mh"><h3>لصق كشف الحضور من Excel</h3><button class="x" onclick="closeModal2()">×</button></div><div class="mb"><p class="sub">انسخ الصفوف من Excel والصقها هنا. إذا كان الصف الأول عناوين (الكود، الاسم، الإدارة، الفرع، الوظيفة، الحضور، قبلي، بعدي، الرضا) سيتم التعرف عليها تلقائيًا.</p><textarea id="pasteBox" style="min-height:220px" placeholder="1025	أحمد محمد	العمليات (الفروع)	فرع سموحة	مدير فرع"></textarea></div><div class="mf"><button class="btn-out" onclick="closeModal2()">إلغاء</button><button class="btn" onclick="doPaste()">إضافة</button></div>`)}
function doPaste(){const L=rowsToPeople(parseRows($('pasteBox').value));const idx=empIdx();L.forEach(a=>ATT.push(fillEmp(a,idx)));closeModal2();drawAtt();toast(`تمت إضافة ${L.length} متدرب`)}
function readXL(file,cb){if(!file)return;const isCSV=/\.csv$/i.test(file.name);const rd=new FileReader();
  rd.onload=e=>{try{if(isCSV){cb(String(e.target.result).replace(/^﻿/,'').split(/\r?\n/).filter(Boolean).map(l=>l.split(/,|;|\t/)));return}
    if(typeof XLSX==='undefined'){toast('مكتبة Excel لم تُحمّل بعد (تحتاج إنترنت). استخدم اللصق أو CSV.',true);return}
    const wb=XLSX.read(new Uint8Array(e.target.result),{type:'array',cellDates:true});cb(XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]],{header:1,defval:''}).filter(r=>r.some(c=>String(c).trim())))}catch(err){toast('تعذر قراءة الملف',true)}};
  isCSV?rd.readAsText(file,'utf-8'):rd.readAsArrayBuffer(file)}
function importAttFile(file){readXL(file,rows=>{const L=rowsToPeople(rows.map(r=>r.map(c=>String(c))));const idx=empIdx();L.forEach(a=>ATT.push(fillEmp(a,idx)));drawAtt();toast(`تم استيراد ${L.length} متدرب`)})}
function attTemplate(){const hd=['الكود','الاسم','الإدارة','الفرع','الوظيفة','الحضور','قبلي','بعدي','الرضا'];
  if(typeof XLSX!=='undefined'){const wb=XLSX.utils.book_new();const ws=XLSX.utils.aoa_to_sheet([hd,['1025','أحمد محمد','العمليات (الفروع)','فرع سموحة','مدير فرع','حاضر',55,85,5]]);ws['!cols']=hd.map(()=>({wch:18}));wb.Workbook={Views:[{RTL:true}]};XLSX.utils.book_append_sheet(wb,ws,'كشف الحضور');XLSX.writeFile(wb,'نموذج_كشف_حضور.xlsx')}
  else dl(new Blob(['﻿'+hd.join(',')+'\n'],{type:'text/csv'}),'نموذج_كشف_حضور.csv')}
function saveSession(keep){const f=$('sessForm');if(!f||!CUR)return;const s=CUR;const fd=Object.fromEntries(new FormData(f).entries());
  if(fd.status==='منفذ'&&!fd.from){toast('حدد تاريخ التنفيذ',true);return}
  if(fd.to&&fd.from&&fd.to<fd.from)fd.to=fd.from;
  const att=ATT.filter(a=>String(a.name||'').trim()||String(a.code||'').trim());
  const T=fd.relink?M.slots.find(x=>x.key===fd.relink)||s:s;if(T!==s)delete R.recs[s.key];
  const r=Object.assign({},s.rec||{},{key:T.key,progId:T.prog.id,g:T.g,pFrom:T.pFrom,pTo:T.pTo,status:fd.status,from:fd.from,to:fd.to||fd.from,tFrom:fd.tFrom||'',tTo:fd.tTo||'',hours:fd.hours,trainer:fd.trainer.trim(),venue:fd.venue.trim(),
    costT:fd.costT,costL:fd.costL,attCount:fd.attCount,l1:fd.l1,notes:fd.notes,att,updatedAt:new Date().toISOString(),snap:{code:T.prog.code,name:T.prog.name,cat:T.prog.cat,method:T.prog.method,hours:T.prog.hours}});
  if(fd.seats!==undefined)r.seats=fd.seats;
  if(r.trainer&&!R.trainers.some(t=>normKey(t.name)===normKey(r.trainer)))R.trainers.push({id:uid(),name:r.trainer,type:/داخل/.test(s.prog.method)?'داخلي':'خارجي',org:s.prog.provider||'',phone:'',spec:''});
  const idx=empIdx();att.forEach(a=>{const c=String(a.code||'').trim();if(!c)return;const ex=idx[c];if(!ex&&a.name){const e={code:c,name:a.name,dept:a.dept||'',branch:a.branch||'',job:a.job||'',phone:a.phone||''};R.employees.push(e);idx[c]=e}else if(ex&&a.phone&&ex.phone!==a.phone)ex.phone=a.phone});
  R.recs[T.key]=r;save();if(keep&&T===s){CUR=Object.assign({},s,{rec:r});return}closeModal();render();toast(T!==s?'تمت إعادة ربط التسجيل بالخطة الحالية':'تم حفظ تسجيل الجلسة')}
function clearSession(){if(!CUR||!confirm('مسح كل بيانات التنفيذ والحضور لهذه الجلسة؟'))return;const s=CUR;delete R.recs[s.key];
  if(s.prog.adhoc&&!s.prog.orphan&&!Object.values(R.recs).some(r=>r.progId===s.prog.id)){R.adhoc=R.adhoc.filter(a=>a.id!==s.prog.id)}save();closeModal();render();toast('تم المسح')}
function printSession(){document.body.classList.add('print-modal');window.print();setTimeout(()=>document.body.classList.remove('print-modal'),400)}
/* نافذة ثانوية فوق النافذة الأساسية */
function openModal2(html){let m=$('modal2');if(!m){m=document.createElement('div');m.id='modal2';m.className='modal-back';m.style.zIndex=150;document.body.appendChild(m)}m.innerHTML=`<div class="modal sm">${html}</div>`;m.classList.add('show')}
function closeModal2(){const m=$('modal2');if(m){m.classList.remove('show');m.innerHTML=''}}


/* ===================== واتساب + النماذج الرسمية TR-P ===================== */
const WA_SVG='<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a10 10 0 0 0-8.6 15.1L2 22l5-1.3A10 10 0 1 0 12 2zm0 18.2c-1.5 0-3-.4-4.3-1.2l-.3-.2-3 .8.8-2.9-.2-.3A8.2 8.2 0 1 1 12 20.2zm4.5-6.1c-.2-.1-1.5-.7-1.7-.8-.2-.1-.4-.1-.6.1l-.8 1c-.1.2-.3.2-.5.1a6.7 6.7 0 0 1-3.3-2.9c-.3-.4.3-.4.7-1.4.1-.2 0-.3 0-.4l-.8-1.8c-.2-.5-.4-.4-.6-.4h-.5a1 1 0 0 0-.7.3c-.2.3-.9.9-.9 2.2s.9 2.5 1 2.7c.1.2 1.8 2.8 4.4 3.9 1.6.7 2.3.8 3.1.6.5-.1 1.5-.6 1.7-1.2.2-.6.2-1.1.2-1.2-.1-.1-.3-.2-.6-.3z"/></svg>';
const AR_DAYS=['الأحد','الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'];
const dmy=x=>{if(!x)return '';const d=pd(x);return `${d.getDate()}/${d.getMonth()+1}/${d.getFullYear()}`};
const dayName=x=>x?AR_DAYS[pd(x).getDay()]:'';
const t12=t=>{if(!t)return '';let [h,m]=t.split(':').map(Number);const ap=h<12?'ص':'م';h=h%12||12;return `${h}:${String(m).padStart(2,'0')} ${ap}`};
function waNum(p){let d=String(p||'').replace(/\D/g,'');if(d.startsWith('00'))d=d.slice(2);if(/^01\d{9}$/.test(d))return '2'+d;if(/^1\d{9}$/.test(d))return '20'+d;if(/^201\d{9}$/.test(d))return d;if(d.length>=10&&d.length<=15&&!d.startsWith('0'))return d;return ''}
function sessData(){const f=$('sessForm');const g=n=>f&&f[n]?String(f[n].value||'').trim():'';const s=CUR||{};const o=s.prog||{};
  return{code:o.code||'',name:o.name||'',g:s.g||'',from:g('from')||s.from||'',to:g('to')||g('from')||s.to||'',tFrom:g('tFrom'),tTo:g('tTo'),venue:g('venue'),trainer:g('trainer'),provider:o.provider||'',hours:g('hours')||o.hours||'',notes:g('notes'),method:o.method||'',objective:o.objective||''}}
const timeTxt=d=>d.tFrom?` من ${t12(d.tFrom)}${d.tTo?' لـ '+t12(d.tTo):''}`:'';
const dateTxt=d=>d.from?`${dayName(d.from)} ${dmy(d.from)}${d.to&&d.to!==d.from?' إلى '+dayName(d.to)+' '+dmy(d.to):''}`:'[التاريخ]';
const coordTxt=()=>R.settings.coordPhone?` على ${R.settings.coordPhone}${R.settings.coordName?' ('+R.settings.coordName+')':''}`:'';
const WA_TPL={
  invite:{t:'دعوة للبرنامج',f:(a,d)=>`أهلًا ${a.name||''}، معاك قسم التدريب في ${ORG()}.\nاترشحت لبرنامج *${d.name}*\nالمعاد: ${dateTxt(d)}${timeTxt(d)}\nالمكان: ${d.venue||'[المكان]'}${d.trainer?'\nالمدرب: '+d.trainer:''}\nمن فضلك أكد حضورك برد «تم» على الرسالة دي، ولو عندك عذر بلغنا قبل المعاد بـ 3 أيام على الأقل${coordTxt()}.`},
  remind:{t:'تذكير قبلها بيوم',f:(a,d)=>`أهلًا ${a.name||''}، تذكير ببرنامج *${d.name}* بكرة ${dayName(d.from)}${d.tFrom?' الساعة '+t12(d.tFrom):''} في ${d.venue||'[المكان]'}.\nيُفضل توصل قبل المعاد بـ 15 دقيقة.\nلو فيه أي ظرف بلغنا دلوقتي${coordTxt()} عشان ندي المكان لزميل تاني.\nمستنيينك!`},
  online:{t:'دعوة أونلاين',f:(a,d)=>`أهلًا ${a.name||''}، معاك قسم التدريب في ${ORG()}.\nاترشحت لبرنامج *${d.name}* أونلاين.\nالمعاد: ${dateTxt(d)}${timeTxt(d)}\nرابط الدخول: ${d.venue&&/^https?:/.test(d.venue)?d.venue:'[الرابط]'}\nادخل قبل المعاد بـ 10 دقايق.\nمن فضلك أكد حضورك برد «تم».`},
  postpone:{t:'تأجيل البرنامج',f:(a,d)=>`أهلًا ${a.name||''}، نعتذر عن تأجيل برنامج *${d.name}*.\nالمعاد الجديد: ${dateTxt(d)}${timeTxt(d)} في ${d.venue||'[المكان]'}.${d.notes?'\nالسبب: '+d.notes:''}\nمن فضلك أكد مناسبة المعاد الجديد برد «تم».`},
  thanks:{t:'شكر بعد البرنامج',f:(a,d)=>`أهلًا ${a.name||''}، شكرًا لحضورك برنامج *${d.name}*.\nاتضاف ${d.hours||''} ساعات لسجلك التدريبي.\nاختار فكرتين من اللي اتعلمتهم وطبقهم في شغلك الأسبوعين الجايين، وهنتابع معاك ومع مديرك.\nمع تمنياتنا بالتوفيق — قسم التدريب، ${ORG()}`}};
function sendWA(i){const a=ATT[i];if(!a)return;const n=waNum(a.phone);
  if(!n){toast('اكتب رقم موبايل صحيح للموظف أولًا (مثال: 01012345678)',true);const el=document.querySelectorAll('#attBox .ph')[i];if(el)el.focus();return}
  const k=($('waTpl')&&$('waTpl').value)||R.settings.waTpl||'invite';R.settings.waTpl=k;
  const msg=WA_TPL[k].f(a,sessData());window.open(`https://wa.me/${n}?text=${encodeURIComponent(msg)}`,'_blank','noopener');
  a.waAt=new Date().toISOString();a.waType=k;drawAtt();saveSession(true)}
/* ---- النماذج الرسمية للطباعة (نفس ترويسة نماذج الشركة) ---- */
function formHead(title,code){const st=R.settings;return `<table class="pf-hd"><tr><td rowspan="4" class="pf-logo">${PS().logo?`<img src="${PS().logo}" alt="">`:'<b>زهران ماركت</b>'}</td><td colspan="3" class="pf-co">شركة زهران ماركت</td></tr>
  <tr><td rowspan="3" class="pf-title">${title}</td><td class="pf-k">الكود</td><td class="pf-v">${code}</td></tr><tr><td class="pf-k">رقم الإصدار</td><td class="pf-v">${esc(st.formRev||'2')}</td></tr><tr><td class="pf-k">تاريخ الإصدار</td><td class="pf-v">${esc(st.formDate||'')}</td></tr></table>`}
const formFoot=code=>`<div class="pf-ft"><span>الكود: ${code}</span><span>رقم الإصدار: ${esc(R.settings.formRev||'2')}</span><span>تاريخ الإصدار: ${esc(R.settings.formDate||'')}</span></div>`;
function sessDays(d){if(!d.from)return[''];const out=[];for(let x=pd(d.from);iso(x)<=(d.to||d.from)&&out.length<5;x.setDate(x.getDate()+1)){if(x.getDay()!==5)out.push(iso(x))}return out.length?out:[d.from]}
function formF09(d,L){const br=[...new Set(L.map(a=>a.branch).filter(Boolean))];const dp=[...new Set(L.map(a=>a.dept).filter(Boolean))];
  const rows=L.map(a=>`<tr><td>${esc(a.code)}</td><td>${esc(a.name)}</td><td>${esc(a.job)}</td><td>${esc(a.branch||a.dept)}</td><td>${esc(d.code)} ${esc(d.name)}${d.g?' — م'+d.g:''}</td><td>${dateTxt(d)}</td><td>${d.tFrom?t12(d.tFrom)+(d.tTo?' - '+t12(d.tTo):''):''}</td><td>${esc(d.venue)}</td></tr>`).join('');
  const pad=Array.from({length:Math.max(0,12-L.length)},()=>'<tr>'+'<td>&nbsp;</td>'.repeat(8)+'</tr>').join('');
  return `<section class="pf-page">${formHead('إخطار متدربين','TR-P-F09')}
   <p class="pf-l"><b>من:</b> إدارة الموارد البشرية (التدريب والتطوير)</p><p class="pf-l"><b>إلى:</b> السادة/ ${esc(dp.join('، ')||'موظفي فروع زهران ماركت')}${br.length?' — '+esc(br.join('، ')):''}</p>
   <p class="pf-l">نحيط علم سيادتكم بقرب ميعاد الدورات التدريبية الخاصة بإدارتكم طبقًا للجدول الآتي (الموعد مرفق في البريد):</p>
   <table class="pf-t"><thead><tr><th>الكود</th><th>الاسم</th><th>الوظيفة</th><th>الفرع</th><th>البرنامج التدريبي</th><th>التاريخ</th><th>الوقت</th><th>المكان</th></tr></thead><tbody>${rows}${pad}</tbody></table>
   <p class="pf-l">برجاء إفادتنا بأي حالات اعتذار عن الدورات قبل <b>ثلاثة أيام</b> من ميعاد بدء الدورة طبقًا للجدول المبين أعلاه، مع ترشيح بديل.</p><p class="pf-l">وتفضلوا بقبول فائق الاحترام،،،</p>
   <table class="pf-sig"><tr><td>مدير الموارد البشرية</td><td>${esc(R.settings.hrManager||'')}</td><td>التوقيع: ....................</td></tr></table>${formFoot('TR-P-F09')}</section>`}
function formF03(d,L){const days=sessDays(d);const n=Math.max(18,L.length);
  const rows=Array.from({length:n},(_,i)=>{const a=L[i]||{};return `<tr><td>${i+1}</td><td class="pf-nm">${esc(a.name||'')}</td><td>${esc(a.code||'')}</td><td>${esc(a.job||'')}</td><td>${esc(a.dept||'')}</td><td>${esc(a.branch||'')}</td>${days.map(()=>'<td></td>').join('')}<td></td><td></td><td></td></tr>`}).join('');
  return `<section class="pf-page pf-land">${formHead('بيان حضور دورة تدريبية','TR-P-F03')}
   <table class="pf-info"><tr><td><b>البرنامج التدريبي:</b> ${esc(d.code)} — ${esc(d.name)}</td><td><b>المجموعة:</b> ${esc(d.g)}</td><td><b>عدد الساعات:</b> ${esc(d.hours)}</td></tr>
   <tr><td><b>تاريخ بدء التدريب:</b> ${dateTxt(d)}</td><td><b>الوقت:</b> ${d.tFrom?t12(d.tFrom)+(d.tTo?' - '+t12(d.tTo):''):'..........'}</td><td><b>المكان:</b> ${esc(d.venue)||'..........'}</td></tr>
   <tr><td colspan="3"><b>القائم بالتدريب / جهة التدريب:</b> ${esc(d.trainer||'')}${d.provider?' — '+esc(d.provider):''}</td></tr></table>
   <table class="pf-t"><thead><tr><th rowspan="2">م</th><th rowspan="2">اسم المتدرب</th><th rowspan="2">الكود الوظيفي</th><th rowspan="2">الوظيفة</th><th rowspan="2">الإدارة</th><th rowspan="2">الفرع</th><th colspan="${days.length}">التوقيع بالحضور</th><th rowspan="2">قبلي<br>/100</th><th rowspan="2">بعدي<br>/100</th><th rowspan="2">الرضا<br>1-5</th></tr>
   <tr>${days.map(x=>`<th>${x?dmy(x):'التاريخ'}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table>
   <table class="pf-sig"><tr><td>توقيع المدرب: ....................</td><td>توقيع مسؤول التدريب: ....................</td><td>تم الإدخال على النظام بتاريخ: ..........</td></tr></table>${formFoot('TR-P-F03')}</section>`}
const F04_INS=[['معرفة المحاضر للمادة العلمية معرفة جيدة','Instructor was knowledgeable about the subject'],['المحاضر كان مستعدًا استعدادًا جيدًا للمحاضرة','Instructor was prepared for each session'],['استخدام المحاضر للوسائل المرئية ساعد في العملية التعليمية','Visual materials were helpful to learning'],['التفاعل بين المحاضر والمتدربين','Instructor / trainee interaction'],['المناقشات كانت مرتبطة بمحتوى المادة','Discussions were relevant to course content'],['كان متمكنًا من ربط المادة العلمية بنشاط الشركة','Instructor related the content to your job'],['تقييم المحاضر بصفة عامة','Overall rating of the instructor']];
const F04_CRS=[['كانت المادة العلمية مرتبطة بأهداف البرنامج التدريبي','Courseware related to the program objectives'],['مدى تأثير هذا البرنامج على عملك','How will this program affect your work?'],['هذا البرنامج التدريبي كان استثمارًا مفيدًا لعملي ووظيفتي','The program is a worthwhile investment'],['بالنظر إلى خبراتي التعليمية الأخرى، أقيّم هذا البرنامج','Compared to other learning experiences'],['التنظيم والقاعة والتوقيت','Organization, venue and timing']];
function formF04(d,a){const sc=['5 ممتاز','4 جيد جدًا','3 جيد','2 مقبول','1 ضعيف'];const box='<td class="pf-bx">☐</td>';
  const grid=(arr,start)=>arr.map(([ar,en],i)=>`<tr><td class="pf-q">${start+i}. ${ar}<br><small>${en}</small></td>${box.repeat(5)}</tr>`).join('');
  return `<section class="pf-page pf-f04">${formHead('استمارة تقييم حلقة عمل','TR-P-F04')}
   <table class="pf-info"><tr><td><b>البرنامج / Course:</b> ${esc(d.code)} — ${esc(d.name)}</td><td><b>المجموعة:</b> ${esc(d.g)}</td><td><b>التاريخ / Date:</b> ${dmy(d.from)}</td></tr>
   <tr><td><b>المحاضر / Instructor:</b> ${esc(d.trainer||'')}</td><td colspan="2"><b>جهة التدريب / Provider:</b> ${esc(d.provider||'L&D Section')}</td></tr>
   <tr><td><b>اسم المتدرب (اختياري):</b> ${esc(a&&a.name||'')}</td><td colspan="2"><b>الكود الوظيفي:</b> ${esc(a&&a.code||'')}</td></tr></table>
   <p class="pf-s">الهدف من هذا التقييم مساعدتنا كإدارة تدريب في تقييم المحاضر والمادة العلمية. ضع علامة ✓ في الخانة المناسبة (5 = ممتاز ... 1 = ضعيف).</p>
   <table class="pf-t pf-ev"><thead><tr><th>المحاضر — Instructor</th>${sc.map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${grid(F04_INS,1)}</tbody>
   <thead><tr><th>المادة العلمية والبرنامج — Course</th>${sc.map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${grid(F04_CRS,8)}</tbody></table>
   <table class="pf-t pf-ev"><tr><td class="pf-q"><b>13. بشكل عام كنت راضيًا عن هذه الدورة التدريبية</b><br><small>Overall, I was satisfied with this course — يُسجَّل في عمود «الرضا» بالنظام</small></td>${box.repeat(5)}</tr>
   <tr><td class="pf-q">14. أوصي بتقديم هذا البرنامج التدريبي لزملائي<br><small>I'd recommend this course</small></td><td colspan="2">☐ نعم</td><td colspan="3">☐ لا</td></tr></table>
   <p class="pf-s"><b>نتائج البرنامج — Program results</b></p><p class="pf-s">1. ما أكثر الأشياء التي تعلمتها في هذا البرنامج؟ ......................................................................................................</p>
   <p class="pf-s">2. ما الذي ستطبقه في عملك خلال الأسبوعين القادمين؟ ...............................................................................................</p>
   <p class="pf-s">3. ما الموضوعات التي ترغب في تعلمها فيما بعد؟ ......................................................................................................</p>
   <p class="pf-s"><b>ملاحظات — Comments:</b> ..........................................................................................................................</p>
   <p class="pf-s pf-note">لاستخدام قسم التدريب: متوسط البند 13 لكل المتدربين = رضا الجلسة (من 5) في نظام إدارة وتسجيل التدريب.</p>${formFoot('TR-P-F04')}</section>`}
function printForm(k){const d=sessData();const L=ATT.filter(a=>String(a.name||'').trim()||String(a.code||'').trim());
  if(k==='F09'&&!L.length){toast('أضف المرشحين أولًا لإصدار الإخطار',true);return}
  const html=k==='F09'?formF09(d,L):k==='F03'?formF03(d,L):(L.length?L:[null]).map(a=>formF04(d,a)).join('');
  let pa=$('printArea');if(!pa){pa=document.createElement('div');pa.id='printArea';document.body.appendChild(pa)}pa.className='pf';pa.innerHTML=html;
  document.body.classList.add('print-form');const done=()=>{document.body.classList.remove('print-form');pa.innerHTML=''};
  setTimeout(()=>{window.print();setTimeout(done,500)},150)}

/* ---- تدريب غير مخطط ---- */
function newAdhoc(){const depts=PS().departments||[];const methods=PS().methods||[INTERNAL];
  openModal(`<div class="mh"><h3>تسجيل تدريب غير مخطط</h3><button class="x" onclick="closeModal()">×</button></div><form class="mb" id="adForm" onsubmit="event.preventDefault();saveAdhoc()"><p class="sub">لأي تدريب طارئ أو بطلب مباشر غير موجود في الخطة السنوية — يُحتسب في التنفيذ الفعلي ويظهر منفصلًا في التقارير كتدريب غير مخطط.</p><div class="fgrid">
   <div class="f w2"><label>اسم البرنامج *</label><input name="name" required></div><div class="f"><label>الفئة</label><select name="category">${opt(CK.map(k=>[k,CATS[k]]),'T')}</select></div>
   <div class="f"><label>الإدارة الطالبة</label><select name="dept">${opt(depts,'','—')}</select></div><div class="f"><label>أسلوب التدريب</label><select name="method">${opt(methods,INTERNAL)}</select></div>
   <div class="f"><label>الجهة / المنفذ</label><input name="provider"></div><div class="f"><label>ساعات الجلسة</label><input type="number" name="hours" value="6" min="0"></div>
   <div class="f"><label>عدد الجلسات / المجموعات</label><input type="number" name="n" value="1" min="1" max="60"></div><div class="f"><label>تاريخ أول جلسة</label><input type="date" name="from" value="${today()}"></div>
   <div class="f w2"><label>الهدف / سبب التدريب</label><input name="objective"></div></div></form>
   <div class="mf"><button class="btn-out" onclick="closeModal()">إلغاء</button><button class="btn" onclick="saveAdhoc()">إنشاء</button></div>`,'sm')}
function saveAdhoc(){const fd=Object.fromEntries(new FormData($('adForm')).entries());if(!fd.name.trim()){toast('اكتب اسم البرنامج',true);return}
  R.settings.seqU=(+R.settings.seqU||0)+1;const a={id:'U'+uid(),code:`UP${String(YEAR()).slice(-2)}-${String(R.settings.seqU).padStart(3,'0')}`,name:fd.name.trim(),category:fd.category,dept:fd.dept,method:fd.method,provider:fd.provider,hours:num(fd.hours),objective:fd.objective};
  R.adhoc.push(a);const n=Math.max(1,Math.min(60,num(fd.n)||1));let first='';
  for(let g=1;g<=n;g++){const key=a.id+'|'+g;if(g===1)first=key;R.recs[key]={key,progId:a.id,g,status:'مخطط',from:fd.from,to:fd.from,pFrom:fd.from,pTo:fd.from,hours:a.hours,att:[],snap:{code:a.code,name:a.name,cat:a.category,method:a.method,hours:a.hours}}}
  save();closeModal();VIEW='exec';render();openSession(first)}

/* ===================== البرامج ===================== */
let PF={q:'',st:'',cat:''};
function vProgs(){return pageTop('البرامج التدريبية — المخطط مقابل الفعلي','كل برنامج من الخطة السنوية مع نسبة تنفيذ جلساته، المتدربين الفعليين، الساعات، التكلفة والتقييم.',`<button class="btn-out" onclick="exportExcel()">تصدير Excel</button>`)+
  `<div class="filters"><input type="search" placeholder="بحث..." value="${esc(PF.q)}" oninput="PF.q=this.value;drawProgs()"><select onchange="PF.st=this.value;drawProgs()">${opt(['لم يبدأ','جارٍ التنفيذ','مكتمل','متأخر'],PF.st,'كل الحالات')}</select><select onchange="PF.cat=this.value;drawProgs()">${opt(CK.map(k=>[k,CATS[k]]),PF.cat,'كل الفئات')}</select></div><div id="progTbl"></div>`}
function drawProgs(){const el=$('progTbl');if(!el)return;const q=normKey(PF.q).toLowerCase();
  const L=M.progs.filter(o=>(!PF.st||progStatus(o)===PF.st)&&(!PF.cat||o.cat===PF.cat)&&(!q||normKey(o.code+' '+o.name+' '+o.provider+' '+o.depts.join(' ')).toLowerCase().includes(q)));
  let T={pc:0,ac:0,seats:0,att:0};
  el.innerHTML=`<div class="tbl-wrap"><table><thead><tr><th>الكود</th><th>البرنامج</th><th>الفئة</th><th>الفترة</th><th class="num">الجلسات</th><th>التقدم</th><th class="num">المتدربون</th><th class="num">ساعات متدرب</th><th class="num">الرضا</th><th class="num">التكلفة المخططة</th><th class="num">الفعلية</th><th>الحالة</th></tr></thead><tbody>${L.map(o=>{const A=agg(o.slots);const live=o.slots.filter(s=>s.status!=='ملغي').length;const ps=progStatus(o);
    T.pc+=o.planCost;T.ac+=A.cost;T.seats+=o.trainees;T.att+=A.attended;
    return `<tr style="cursor:pointer" onclick="openProg('${o.id}')"><td>${cdc(o.code)}</td><td><b>${esc(o.name)}</b>${o.adhoc?' <span class="sub">(غير مخطط)</span>':''}<div class="sub">${esc(o.method)}${o.provider?' | '+esc(o.provider):''}</div></td><td>${chip(o.cat)}</td>
    <td class="sub">${o.adhoc?'—':o.sm===o.em?MONTHS[o.sm]:MONTHS[o.sm]+' - '+MONTHS[o.em]}</td><td class="num">${A.done}/${live}</td><td><div class="prog ${ps==='مكتمل'?'ok':''}" data-tip="${pct(A.done,live)}% من الجلسات منفذة"><i style="width:${pct(A.done,live)}%"></i></div></td>
    <td class="num">${fmt(A.attended)}<span class="sub"> / ${fmt(o.trainees)}</span></td><td class="num">${fmt(A.manHours)}</td><td class="num">${A.l1pct!=null?pc(A.l1pct):'—'}</td>
    <td class="num">${fmt(o.planCost)}</td><td class="num">${fmt(A.cost)}</td><td><span class="st ${progStCls[ps]}">${ps}</span></td></tr>`}).join('')||'<tr><td colspan="12" class="empty">لا توجد برامج</td></tr>'}</tbody>
    <tfoot><tr><td colspan="6">الإجمالي (${L.length} برنامج)</td><td class="num">${fmt(T.att)} / ${fmt(T.seats)}</td><td></td><td></td><td class="num">${fmt(T.pc)}</td><td class="num">${fmt(T.ac)}</td><td></td></tr></tfoot></table></div>`}
function openProg(id){const o=M.byId[id];if(!o)return;const A=agg(o.slots);
  openModal(`<div class="mh"><div><h3>${cdc(o.code)} ${esc(o.name)}</h3><div class="sub">${chip(o.cat)} ${esc(o.method)} ${o.provider?'| '+esc(o.provider):''} | ${esc(o.objective)}</div></div><button class="x" onclick="closeModal()">×</button></div><div class="mb">
   <div class="kpis">${kpi('الجلسات المنفذة',`${A.done}<small>من ${A.total-A.cancel}</small>`,'',pct(A.done,A.total-A.cancel))}${kpi('المتدربون',`${fmt(A.attended)}<small>من ${fmt(o.trainees)}</small>`,'',pct(A.attended,o.trainees))}${kpi('ساعات متدرب',fmt(A.manHours))}${kpi('الرضا L1',A.l1pct!=null?pc(A.l1pct):'—')}${kpi('L2 قبلي ← بعدي',A.post!=null?`${Math.round(A.pre)}% ← ${Math.round(A.post)}%`:'—')}${kpi('التكلفة',`${fmt(A.cost)}<small>/ ${fmt(o.planCost)}</small>`)}</div>
   ${sec('الجلسات')}<div class="tbl-wrap"><table><thead><tr><th class="num">المجموعة</th><th>المخطط</th><th>الفعلي</th><th>المدرب</th><th class="num">الحضور</th><th class="num">الرضا</th><th>الحالة</th><th></th></tr></thead><tbody>${o.slots.map(s=>`<tr><td class="num">${s.g}</td><td>${rng(s.pFrom,s.pTo)}</td><td>${s.rec?rng(s.from,s.to):'—'}</td><td>${esc(s.trainer)||'—'}</td><td class="num">${s.done?s.attended:'—'}</td><td class="num">${s.l1!=null?pc(Math.round(s.l1/5*100)):'—'}</td><td>${stPill(s)}</td><td><button class="btn-out btn-sm" onclick="openSession('${s.key}')">فتح</button></td></tr>`).join('')}</tbody></table></div>
   ${o.needs.length?sec('الاحتياجات التدريبية المرتبطة (من نظام الاحتياجات)')+`<div class="tbl-wrap"><table><thead><tr><th>الكود</th><th>الاحتياج</th><th>الإدارة</th><th>الفئة المستهدفة</th><th class="num">العدد</th><th>حالة الاحتياج</th></tr></thead><tbody>${o.needs.map(n=>`<tr><td>${cdc(n.code)}</td><td>${esc(n.title)}</td><td>${esc(n.dept)}</td><td class="sub">${esc(n.jobTitle)}</td><td class="num">${+n.trainees||0}</td><td>${esc(n.status)}</td></tr>`).join('')}</tbody></table></div>`:''}
  </div><div class="mf"><button class="btn-out" onclick="go('eval')">التقييم L3/L4</button><button class="btn-out" onclick="closeModal()">إغلاق</button></div>`)}

/* ===================== سجل الموظفين ===================== */
let PQ='';
function empRecords(){const m={};const add=(k,base)=>{if(!m[k])m[k]=Object.assign({code:'',name:'',dept:'',branch:'',job:'',hours:0,progs:new Set(),items:[],last:''},base);return m[k]};
  R.employees.forEach(e=>add('c:'+String(e.code).trim(),e));
  M.slots.filter(s=>s.done).forEach(s=>s.att.forEach(a=>{const k=a.code?'c:'+String(a.code).trim():'n:'+normKey(a.name);if(k.length<3)return;const e=add(k,{code:a.code||'',name:a.name||'',dept:a.dept||'',branch:a.branch||'',job:a.job||''});
    ['name','dept','branch','job'].forEach(x=>{if(!e[x]&&a[x])e[x]=a[x]});const ok=a.st==='حاضر'||a.st==='متأخر';
    e.items.push({s,a,ok});if(ok){e.hours+=s.hours;e.progs.add(s.prog.id);if(s.to>e.last)e.last=s.to}}));
  return Object.values(m)}
function vPeople(){return pageTop('السجل التدريبي للموظفين','السجل التراكمي لكل موظف: البرامج التي حضرها، الساعات، النتائج والتقييم — مع مقارنة بالمستهدف السنوي لساعات التدريب.',`<button class="btn-out" onclick="go('set');setTimeout(()=>{const e=$('empSec');e&&e.scrollIntoView()},50)">بيانات الموظفين</button>`)+
  `<div class="filters"><input type="search" placeholder="بحث بالكود أو الاسم أو الإدارة أو الفرع..." value="${esc(PQ)}" oninput="PQ=this.value;drawPeople()"><span class="sub" id="pplCnt"></span></div><div id="pplTbl"></div>`}
function drawPeople(){const el=$('pplTbl');if(!el)return;const q=normKey(PQ).toLowerCase();const tgt=+R.settings.hoursTarget||0;
  const L=empRecords().filter(e=>!q||normKey([e.code,e.name,e.dept,e.branch,e.job].join(' ')).toLowerCase().includes(q)).sort((a,b)=>b.hours-a.hours);
  const trained=L.filter(e=>e.hours>0).length;$('pplCnt').textContent=`${L.length} موظف | تدربوا: ${trained} | بدون تدريب: ${L.length-trained}${tgt?` | حققوا مستهدف ${tgt} ساعة: ${L.filter(e=>e.hours>=tgt).length}`:''}`;
  el.innerHTML=`<div class="tbl-wrap"><table><thead><tr><th>الكود</th><th>الاسم</th><th>الإدارة</th><th>الفرع</th><th>الوظيفة</th><th class="num">البرامج</th><th class="num">الساعات</th>${tgt?'<th>المستهدف</th>':''}<th>آخر تدريب</th><th></th></tr></thead><tbody>${L.slice(0,1500).map(e=>`<tr><td>${cdc(e.code)}</td><td><b>${esc(e.name)}</b></td><td>${esc(e.dept)}</td><td>${esc(e.branch)}</td><td class="sub">${esc(e.job)}</td><td class="num">${e.progs.size}</td><td class="num">${fmt(e.hours,1)}</td>${tgt?`<td><div class="prog ${e.hours>=tgt?'ok':''}" data-tip="${fmt(e.hours,1)} من ${tgt} ساعة"><i style="width:${pct(e.hours,tgt)}%"></i></div></td>`:''}<td class="sub">${e.last?fmtD(e.last):'—'}</td><td><button class="btn-out btn-sm" onclick="openEmp('${esc(e.code?'c:'+String(e.code).trim():'n:'+normKey(e.name))}')">السجل</button></td></tr>`).join('')||`<tr><td colspan="10" class="empty">لا توجد سجلات بعد. تُبنى السجلات تلقائيًا من كشوف الحضور، ويمكن استيراد قائمة الموظفين من الإعدادات.</td></tr>`}</tbody></table></div>`}
function openEmp(k){const e=empRecords().find(x=>(x.code?'c:'+String(x.code).trim():'n:'+normKey(x.name))===k);if(!e)return;
  openModal(`<div class="mh"><div><h3>السجل التدريبي — ${esc(e.name)}</h3><div class="sub">${e.code?'كود '+esc(e.code)+' | ':''}${esc(e.dept)} ${e.branch?'| '+esc(e.branch):''} ${e.job?'| '+esc(e.job):''}</div></div><button class="x" onclick="closeModal()">×</button></div><div class="mb">${printHead()}
   <div class="kpis">${kpi('البرامج',e.progs.size)}${kpi('ساعات التدريب',fmt(e.hours,1),R.settings.hoursTarget?`المستهدف ${R.settings.hoursTarget} ساعة`:'',R.settings.hoursTarget?pct(e.hours,R.settings.hoursTarget):null)}${kpi('مرات الغياب',e.items.filter(x=>!x.ok).length)}</div>
   <div class="tbl-wrap" style="margin-top:14px"><table><thead><tr><th>التاريخ</th><th>البرنامج</th><th>الفئة</th><th class="num">الساعات</th><th>الحضور</th><th class="num">قبلي</th><th class="num">بعدي</th><th class="num">الرضا</th><th>المدرب</th></tr></thead><tbody>${e.items.sort((a,b)=>String(a.s.from).localeCompare(b.s.from)).map(x=>`<tr><td>${rng(x.s.from,x.s.to)}</td><td>${cdc(x.s.prog.code)} ${esc(x.s.prog.name)}</td><td>${chip(x.s.prog.cat)}</td><td class="num">${x.ok?x.s.hours:0}</td><td>${esc(x.a.st)}</td><td class="num">${esc(x.a.pre??'')}</td><td class="num">${esc(x.a.post??'')}</td><td class="num">${esc(x.a.sat??'')}</td><td>${esc(x.s.trainer)}</td></tr>`).join('')||'<tr><td colspan="9" class="empty">لم يحضر أي تدريب بعد</td></tr>'}</tbody></table></div></div>
   <div class="mf"><button class="btn-out" onclick="printSession()">طباعة السجل</button><button class="btn-out" onclick="closeModal()">إغلاق</button></div>`)}

/* ===================== التقييم (كيركباتريك) ===================== */
function vEval(){const pm=+R.settings.passMark;const L=M.progs.filter(o=>o.slots.some(s=>s.done));const t0=today();const A=agg(M.slots);
  let h=pageTop('تقييم أثر التدريب — نموذج كيركباتريك','L1 رد الفعل والرضا | L2 التعلم (قبلي/بعدي) | L3 تطبيق السلوك في العمل (متابعة المدير بعد التدريب) | L4 النتائج على مؤشر الأداء المحدد في الخطة.')+
  `<div class="kpis">${kpi('L1 رضا المتدربين',A.l1pct!=null?pc(A.l1pct):'—')}${kpi('L2 متوسط التحسن',A.post!=null?pc(Math.round(A.post-A.pre)):'—',A.posted?`نسبة النجاح (≥${pm}): ${pct(A.pass,A.posted)}%`:'')}${kpi('L3 متابعات مسجلة',Object.values(R.evals).filter(x=>x.l3&&x.l3.score!=='').length)}${kpi('L4 نتائج مسجلة',Object.values(R.evals).filter(x=>x.l4&&x.l4.actual!=='').length)}</div>`;
  h+=sec('التقييم حسب البرنامج',`موعد متابعة L3 = آخر جلسة منفذة + ${R.settings.l3Days} يومًا. اضغط "تسجيل" لإدخال نتائج L3/L4.`)+`<div class="tbl-wrap"><table><thead><tr><th>البرنامج</th><th>المستوى المستهدف</th><th class="num">L1 الرضا</th><th class="num">L2 قبلي</th><th class="num">L2 بعدي</th><th class="num">النجاح</th><th>L3 موعد المتابعة</th><th class="num">L3 التطبيق</th><th>L4 المؤشر</th><th>L4 النتيجة</th><th></th></tr></thead><tbody>${L.map(o=>{const a=agg(o.slots);const ev=R.evals[o.id]||{};const last=o.slots.filter(s=>s.done).map(s=>s.to).sort().pop();
    const due=last?iso(new Date(pd(last).getTime()+(+R.settings.l3Days||90)*864e5)):'';const l3=ev.l3||{};const l4=ev.l4||{};const need3=/3|4/.test(o.evalLevel||'');const late3=need3&&due&&due<=t0&&(l3.score===''||l3.score==null);
    return `<tr><td>${cdc(o.code)} <b>${esc(o.name)}</b></td><td class="sub">${esc(o.evalLevel||'—')}</td><td class="num">${a.l1pct!=null?pc(a.l1pct):'—'}</td><td class="num">${a.pre!=null?Math.round(a.pre):'—'}</td><td class="num">${a.post!=null?Math.round(a.post):'—'}</td><td class="num">${a.posted?pc(pct(a.pass,a.posted)):'—'}</td>
    <td>${due?fmtD(due):'—'}${late3?' <span class="flag">مستحقة</span>':''}</td><td class="num">${l3.score!==''&&l3.score!=null?pc(l3.score):'—'}</td><td class="sub">${esc(l4.kpi||o.kpi||'—')}</td><td>${l4.actual!==''&&l4.actual!=null?`${esc(l4.base||'?')} ← <b>${esc(l4.actual)}</b> <span class="sub">(مستهدف ${esc(l4.target||'?')})</span>`:'—'}</td><td><button class="btn-out btn-sm" onclick="openEval('${o.id}')">تسجيل</button></td></tr>`}).join('')||'<tr><td colspan="11" class="empty">لا توجد برامج منفذة بعد</td></tr>'}</tbody></table></div>`;
  return h}
function openEval(id){const o=M.byId[id];const ev=R.evals[id]||{};const l3=ev.l3||{},l4=ev.l4||{};
  openModal(`<div class="mh"><div><h3>تقييم الأثر — ${esc(o.name)}</h3><div class="sub">المستوى المستهدف: ${esc(o.evalLevel||'—')}</div></div><button class="x" onclick="closeModal()">×</button></div><form class="mb" id="evForm">
   ${sec('المستوى 3: السلوك (التطبيق في العمل)','متوسط تقييم المديرين المباشرين لمدى تطبيق المتدربين لما تعلموه (نسبة مئوية) بعد فترة المتابعة.')}
   <div class="fgrid"><div class="f"><label>تاريخ المتابعة</label><input type="date" name="l3date" value="${esc(l3.date||'')}"></div><div class="f"><label>نسبة التطبيق %</label><input type="number" min="0" max="100" name="l3score" value="${esc(l3.score??'')}"></div><div class="f"><label>عدد من تمت متابعتهم</label><input type="number" min="0" name="l3n" value="${esc(l3.n||'')}"></div><div class="f wall"><label>ملاحظات / أدلة التطبيق</label><input name="l3note" value="${esc(l3.note||'')}"></div></div>
   ${sec('المستوى 4: النتائج (الأثر على مؤشر الأداء)','مؤشر الأداء من الخطة: '+esc(o.kpi||'غير محدد'))}
   <div class="fgrid"><div class="f w2"><label>المؤشر</label><input name="l4kpi" value="${esc(l4.kpi||o.kpi||'')}"></div><div class="f"><label>القيمة قبل التدريب</label><input name="l4base" value="${esc(l4.base||'')}"></div><div class="f"><label>المستهدف</label><input name="l4target" value="${esc(l4.target||'')}"></div><div class="f"><label>القيمة الفعلية بعد التدريب</label><input name="l4actual" value="${esc(l4.actual??'')}"></div><div class="f"><label>تاريخ القياس</label><input type="date" name="l4date" value="${esc(l4.date||'')}"></div><div class="f wall"><label>التحليل والملاحظات</label><input name="l4note" value="${esc(l4.note||'')}"></div></div>
  </form><div class="mf"><button class="btn-out" onclick="closeModal()">إلغاء</button><button class="btn" onclick="saveEval('${id}')">حفظ</button></div>`,'sm')}
function saveEval(id){const fd=Object.fromEntries(new FormData($('evForm')).entries());R.evals[id]={l3:{date:fd.l3date,score:fd.l3score,n:fd.l3n,note:fd.l3note},l4:{kpi:fd.l4kpi,base:fd.l4base,target:fd.l4target,actual:fd.l4actual,date:fd.l4date,note:fd.l4note}};save();closeModal();render();toast('تم حفظ التقييم')}

/* ===================== تعديلات الخطة ===================== */
function chgTxt(c){if(c.t==='add')return `<b>إضافة برنامج:</b> ${esc(c.code)} ${esc(c.name)} (${fmt(c.tr)} متدرب | ${fmt(c.cost)} ج.م)`;
  if(c.t==='del')return `<b>حذف / إلغاء برنامج:</b> ${esc(c.code)} ${esc(c.name)} (كان ${fmt(c.tr)} متدرب | ${fmt(c.cost)} ج.م)`;
  return `<b>تعديل:</b> ${esc(c.code)} ${esc(c.name)} — ${c.f.map(f=>`${f.l}: ${esc(f.from)} ← ${esc(f.to)}`).join(' | ')}`}
const dlt=(a,b,money)=>{const d=b-a;if(!d)return '<span class="sub">بدون تغيير</span>';const p=a?Math.round(d/a*100):null;return `<b style="color:${d>0?'var(--warn)':'var(--tech)'}">${d>0?'+':''}${fmt(d)}${money?' ج.م':''}</b>${p!=null?` <span class="sub">(${d>0?'+':''}${p}%)</span>`:''}`};
function vChanges(){const B=curBase();const cur=planSummary();const tc=planTotals(cur);const A=agg(M.slots);const started=M.progs.filter(o=>!o.adhoc&&o.slots.some(s=>s.done)).length;
  let h=pageTop('تعديلات الخطة','الخطة التدريبية تقديرية وتُعدّل في نظام الاحتياجات (إضافة/حذف برامج، أعداد، ميزانية، فترات). النظام يقرأ التعديل تلقائيًا ويحسب كل المؤشرات على الخطة الحالية، ويقارنها بنسخة الأساس، ويحتفظ بسجل لكل تعديل.',
    `<button class="btn" onclick="newBaseline()">اعتماد الخطة الحالية كنسخة أساس</button>`);
  const UL=M.slots.filter(s=>s.unlinked);
  if(UL.length)h+=sec('تسجيلات تحتاج إعادة ربط',`${UL.length} تسجيل تنفيذ لجلسات لم تعد موجودة في الخطة الحالية. البيانات محفوظة ولم تُحذف — افتح كل تسجيل واختر الجلسة المقابلة في الخطة الحالية، أو امسحه إن لم يعد مطلوبًا.`)+`<div class="tbl-wrap"><table><thead><tr><th>البرنامج (وقت التسجيل)</th><th class="num">المجموعة</th><th>التاريخ</th><th>الحالة</th><th class="num">الحضور</th><th></th></tr></thead><tbody>${UL.map(s=>`<tr><td>${cdc(s.prog.code)} ${esc(s.prog.name)}</td><td class="num">${s.g}</td><td>${rng(s.from,s.to)}</td><td>${stPill(s)}</td><td class="num">${s.done?s.attended:'—'}</td><td><button class="btn-out btn-sm" onclick="openSession('${s.key}')">إعادة ربط</button></td></tr>`).join('')}</tbody></table></div>`;
  if(!B)return h+`<div class="alert info">لا توجد نسخة أساس بعد.</div>`;
  const tb=planTotals(B.progs);const d=planDiff(B.progs,cur);const c=diffCount(d);const mb=B.meta||{};const mc=planMeta();
  h+=`<div class="filters"><label class="sub">المقارنة مع نسخة الأساس:</label><select onchange="R.activeBase=this.value;save();render()">${opt(R.baselines.map(b=>[b.id,`${b.name} (${b.at})`]),B.id)}</select>${R.baselines.length>1?`<button class="btn-del" onclick="delBaseline('${B.id}')">حذف هذه النسخة</button>`:''}<span class="sub">${R.baselines.length} نسخة محفوظة</span></div>`;
  h+=sec('الأساس مقابل الخطة الحالية مقابل الفعلي')+`<div class="tbl-wrap"><table><thead><tr><th>المؤشر</th><th class="num">نسخة الأساس</th><th class="num">الخطة الحالية</th><th class="num">التغير</th><th class="num">الفعلي حتى الآن</th><th class="num">نسبة الإنجاز من الحالية</th></tr></thead><tbody>
    <tr><td>البرامج</td><td class="num">${fmt(tb.n)}</td><td class="num">${fmt(tc.n)}</td><td class="num">${dlt(tb.n,tc.n)}</td><td class="num">${fmt(started)} بدأ</td><td class="num">${pc(pct(started,tc.n))}</td></tr>
    <tr><td>الجلسات / المجموعات</td><td class="num">${fmt(tb.ss)}</td><td class="num">${fmt(tc.ss)}</td><td class="num">${dlt(tb.ss,tc.ss)}</td><td class="num">${fmt(A.done)} منفذة</td><td class="num">${pc(pct(A.done,tc.ss))}</td></tr>
    <tr><td>المتدربون المستهدفون</td><td class="num">${fmt(tb.tr)}</td><td class="num">${fmt(tc.tr)}</td><td class="num">${dlt(tb.tr,tc.tr)}</td><td class="num">${fmt(A.attended)} حضروا</td><td class="num">${pc(pct(A.attended,tc.tr))}</td></tr>
    <tr><td>ساعات التدريب</td><td class="num">${fmt(tb.hrs)}</td><td class="num">${fmt(tc.hrs)}</td><td class="num">${dlt(tb.hrs,tc.hrs)}</td><td class="num">${fmt(A.hours)}</td><td class="num">${pc(pct(A.hours,tc.hrs))}</td></tr>
    <tr><td>الميزانية (ج.م)</td><td class="num">${fmt(tb.cost)}</td><td class="num">${fmt(tc.cost)}</td><td class="num">${dlt(tb.cost,tc.cost,1)}</td><td class="num">${fmt(A.cost)} منصرف</td><td class="num">${pc(pct(A.cost,tc.cost))}</td></tr>
    ${mb.needs!=null?`<tr><td>الاحتياجات المسجلة / المرتبطة ببرامج</td><td class="num">${fmt(mb.needs)} / ${fmt(mb.linked)}</td><td class="num">${fmt(mc.needs)} / ${fmt(mc.linked)}</td><td class="num">${dlt(mb.linked,mc.linked)}</td><td></td><td></td></tr>`:''}
  </tbody></table></div>`;
  h+=sec(`التعديلات على مستوى البرامج (${d.length})`,`${c.add} مضاف | ${c.del} محذوف أو ملغي | ${c.mod} معدّل`)+`<div class="tbl-wrap"><table><thead><tr><th>النوع</th><th>البرنامج</th><th>البند</th><th>في الأساس</th><th>في الخطة الحالية</th><th class="num">الفرق</th></tr></thead><tbody>${d.flatMap(x=>x.t==='mod'?x.f.map((f,i)=>`<tr><td>${i?'':'<span class="st post">معدّل</span>'}</td><td>${i?'':cdc(x.code)+' '+esc(x.name)}</td><td>${f.l}</td><td>${esc(f.from)}</td><td><b>${esc(f.to)}</b></td><td class="num">${f.d!=null?(f.d>0?'+':'')+fmt(f.d,1):''}</td></tr>`):[`<tr><td><span class="st ${x.t==='add'?'done':'late'}">${x.t==='add'?'مضاف':'محذوف'}</span></td><td>${cdc(x.code)} ${esc(x.name)}</td><td>البرنامج كاملًا</td><td>${x.t==='del'?`${fmt(x.tr)} متدرب | ${fmt(x.cost)} ج.م`:'—'}</td><td>${x.t==='add'?`${fmt(x.tr)} متدرب | ${fmt(x.cost)} ج.م`:'—'}</td><td></td></tr>`]).join('')||'<tr><td colspan="6" class="empty">الخطة الحالية مطابقة لنسخة الأساس</td></tr>'}</tbody></table></div>`;
  h+=sec('سجل التعديلات المرصودة تلقائيًا','كل مرة تتغير فيها الخطة في نظام الاحتياجات يُسجَّل هنا ما تغيّر وتوقيته (آخر 300 تعديل).')+`<div class="list">${R.planLog.slice(0,60).map(e=>{const k=diffCount(e.changes);return `<details class="li" style="display:block;cursor:default"><summary style="cursor:pointer;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><span><b>${e.at.slice(0,10)}</b> <span class="sub">${e.at.slice(11,16)}</span> — ${k.add?k.add+' مضاف ':''}${k.del?k.del+' محذوف ':''}${k.mod?k.mod+' معدّل':''}</span><span class="sub">المتدربون ${fmt(e.before.tr)} ← ${fmt(e.after.tr)} | الميزانية ${fmt(e.before.cost)} ← ${fmt(e.after.cost)}</span></summary><ul style="margin:8px 0 0">${e.changes.map(c=>`<li>${chgTxt(c)}</li>`).join('')}</ul></details>`}).join('')||'<div class="empty">لم تُرصد تعديلات بعد. أي تعديل في نظام الاحتياجات سيظهر هنا تلقائيًا.</div>'}</div>`;
  return h}
function newBaseline(){const n=prompt('اسم نسخة الأساس:',`الخطة المعتمدة ${today()}`);if(!n)return;const b={id:uid(),name:n.trim(),at:today(),src:PLAN_AT||PLAN_SRC,progs:planSummary(),meta:planMeta()};R.baselines.push(b);R.activeBase=b.id;save();render();toast('تم حفظ نسخة الأساس — ستُقارن بها أي تعديلات لاحقة')}
function delBaseline(id){if(R.baselines.length<2||!confirm('حذف نسخة الأساس هذه؟'))return;R.baselines=R.baselines.filter(b=>b.id!==id);R.activeBase='';save();render()}

/* ===================== الميزانية ===================== */
function vBudget(){const BB=curBase();const bp=BB?BB.progs:{};const L=M.progs.filter(o=>o.planCost||o.slots.some(s=>s.cost)||(bp[o.id]&&bp[o.id].cost));const tp=L.reduce((a,o)=>a+o.planCost,0);const ta=agg(M.slots).cost;const cap=+PS().budgetCap||0;
  const mm=MONTHS.map((_,i)=>M.slots.filter(s=>s.month===i).reduce((a,s)=>a+s.cost,0));const mp=MONTHS.map((_,i)=>M.progs.filter(o=>!o.adhoc).reduce((a,o)=>{const n=o.slots.filter(s=>s.status!=='ملغي').length||1;return a+o.slots.filter(s=>s.month===i&&s.status!=='ملغي').length*o.planCost/n},0));const mx=Math.max(1,...mm,...mp);
  const done=M.progs.filter(o=>!o.adhoc&&progStatus(o)==='مكتمل');const dv=done.reduce((a,o)=>a+agg(o.slots).cost-o.planCost,0);
  return pageTop('الميزانية — المخطط مقابل الفعلي','التكلفة المخططة من نظام الاحتياجات (ميزانية الجهة الخارجية + اللوجستيات) مقابل التكلفة الفعلية المسجلة لكل جلسة.',`<button class="btn-out" onclick="exportExcel()">تصدير Excel</button>`)+
  `<div class="kpis">${BB?kpi('ميزانية نسخة الأساس',`${fmt(planTotals(bp).cost)}<small>ج.م</small>`,esc(BB.name)):''}${kpi('الميزانية المخططة (الحالية)',`${fmt(tp)}<small>ج.م</small>`,cap?`سقف الميزانية: ${fmt(cap)} ج.م`:BB?`التغير عن الأساس: ${tp-planTotals(bp).cost>0?'+':''}${fmt(tp-planTotals(bp).cost)} ج.م`:'')}${kpi('المنصرف الفعلي',`${fmt(ta)}<small>ج.م</small>`,`${pct(ta,tp)}% من المخطط`,pct(ta,tp),true)}${kpi('المتبقي',`${fmt(tp-ta)}<small>ج.م</small>`)}${kpi('انحراف البرامج المكتملة',`${dv>0?'+':''}${fmt(dv)}<small>ج.م</small>`,`${done.length} برنامج مكتمل | ${dv>0?'تجاوز':'وفر'}`)}${kpi('تكلفة ساعة المتدرب',agg(M.slots).manHours?`${fmt(ta/agg(M.slots).manHours,1)}<small>ج.م</small>`:'—')}</div>
  <div class="card" style="margin-top:14px"><h3 style="margin:0 0 4px;font-size:15px">الإنفاق الشهري: المخطط مقابل الفعلي</h3><div class="legend"><span><i style="background:var(--c-track)"></i>مخطط</span><span><i style="background:var(--c-act)"></i>فعلي</span></div>
  <div class="mchart">${mm.map((x,i)=>`<div class="mcol" data-tip="${MONTHS[i]}\nمخطط: ${fmt(mp[i])} ج.م\nفعلي: ${fmt(x)} ج.م"><div class="stack"><div class="trk" style="height:${mp[i]/mx*100}%"></div><div class="act" style="height:${x/mx*100}%"></div></div></div>`).join('')}</div><div class="mlabels">${MONTHS.map(m=>`<span>${m.slice(0,3)}</span>`).join('')}</div></div>
  ${sec('حسب البرنامج')}<div class="tbl-wrap"><table><thead><tr><th>البرنامج</th><th>الأسلوب</th>${BB?'<th class="num">الأساس</th>':''}<th class="num">المخطط الحالي</th><th class="num">الفعلي</th><th class="num">الانحراف</th><th class="num">نسبة الصرف</th><th>الحالة</th></tr></thead><tbody>${L.map(o=>{const a=agg(o.slots).cost;const ps=progStatus(o);return `<tr><td>${cdc(o.code)} ${esc(o.name)}</td><td class="sub">${esc(o.method)}</td>${BB?`<td class="num sub">${bp[o.id]?fmt(bp[o.id].cost):'جديد'}</td>`:''}<td class="num">${fmt(o.planCost)}</td><td class="num">${fmt(a)}</td><td class="num" style="color:${a>o.planCost&&o.planCost?'var(--danger)':'inherit'}">${fmt(a-o.planCost)}</td><td class="num">${o.planCost?pc(pct(a,o.planCost)):'—'}</td><td><span class="st ${progStCls[ps]}">${ps}</span></td></tr>`}).join('')}</tbody><tfoot><tr><td colspan="2">الإجمالي</td>${BB?`<td class="num">${fmt(planTotals(bp).cost)}</td>`:''}<td class="num">${fmt(tp)}</td><td class="num">${fmt(ta)}</td><td class="num">${fmt(ta-tp)}</td><td class="num">${pc(pct(ta,tp))}</td><td></td></tr></tfoot></table></div>`}

/* ===================== تغطية الاحتياجات ===================== */
let NF={dept:'',st:''};
function needState(n){if(!n.programId)return n.status==='مرفوض'||n.status==='مؤجل'?n.status:'غير مرتبط ببرنامج';const o=M.byId[n.programId];if(!o)return 'برنامج ملغي';const ps=progStatus(o);return ps==='مكتمل'?'تمت التلبية':ps==='جارٍ التنفيذ'?'جارٍ التلبية':ps==='متأخر'?'متأخر':'لم يبدأ'}
const nsCls={'تمت التلبية':'done','جارٍ التلبية':'post','لم يبدأ':'plan','متأخر':'late','غير مرتبط ببرنامج':'cancel','مرفوض':'cancel','مؤجل':'cancel','برنامج ملغي':'cancel'};
function vNeeds(){const N=P.needs;const depts=[...new Set(N.map(n=>n.dept))].filter(Boolean).sort();const states=Object.keys(nsCls);
  const L=N.filter(n=>(!NF.dept||n.dept===NF.dept)&&(!NF.st||needState(n)===NF.st));const cnt={};N.forEach(n=>{const s=needState(n);cnt[s]=(cnt[s]||0)+1});
  return pageTop('تغطية الاحتياجات التدريبية','الربط المباشر بين كل احتياج مسجل في نظام الاحتياجات والبرنامج الذي يلبيه وحالة تنفيذه — لإغلاق دورة: احتياج ← برنامج ← تنفيذ ← أثر.',`<a class="btn-out" style="text-decoration:none" href="${PLAN_LINK.page}" target="_blank" rel="noopener">فتح نظام الاحتياجات ↗</a>`)+
  `<div class="kpis">${['تمت التلبية','جارٍ التلبية','لم يبدأ','متأخر','غير مرتبط ببرنامج'].map(s=>kpi(s,fmt(cnt[s]||0),`${pct(cnt[s]||0,N.length)}% من ${N.length} احتياج`)).join('')}</div>
  <div class="filters"><select onchange="NF.dept=this.value;render()">${opt(depts,NF.dept,'كل الإدارات')}</select><select onchange="NF.st=this.value;render()">${opt(states,NF.st,'كل الحالات')}</select><span class="sub">${L.length} احتياج</span></div>
  <div class="tbl-wrap"><table><thead><tr><th>كود الاحتياج</th><th>الاحتياج</th><th>الإدارة</th><th>الفئة</th><th class="num">المطلوب</th><th>البرنامج</th><th>التقدم</th><th>الحالة</th></tr></thead><tbody>${L.map(n=>{const o=n.programId&&M.byId[n.programId];const a=o?agg(o.slots):null;const live=o?o.slots.filter(s=>s.status!=='ملغي').length:0;const st=needState(n);
    return `<tr><td>${cdc(n.code)}</td><td>${esc(n.title)}<div class="sub">${esc(n.jobTitle||'')}</div></td><td>${esc(n.dept)}</td><td>${chip(n.category)}</td><td class="num">${+n.trainees||0}</td><td>${o?`<button class="btn-ghost" onclick="openProg('${o.id}')">${esc(o.code)} ${esc(o.name)}</button>`:'—'}</td><td>${o?`<div class="prog" data-tip="${a.done} من ${live} جلسة"><i style="width:${pct(a.done,live)}%"></i></div>`:''}</td><td><span class="st ${nsCls[st]}">${st}</span></td></tr>`}).join('')||'<tr><td colspan="8" class="empty">لا توجد احتياجات</td></tr>'}</tbody></table></div>`}

/* ===================== المدربون ===================== */
function vTrainers(){const S=M.slots.filter(s=>s.done);
  return pageTop('المدربون والجهات التدريبية','سجل المدربين الداخليين والخارجيين وأداؤهم: عدد الجلسات، الساعات، المتدربون ومتوسط تقييم الرضا.',`<button class="btn" onclick="editTrainer()">+ مدرب</button>`)+
  `<div class="tbl-wrap"><table><thead><tr><th>المدرب</th><th>النوع</th><th>الجهة</th><th>التخصص</th><th>التواصل</th><th class="num">الجلسات</th><th class="num">الساعات</th><th class="num">المتدربون</th><th class="num">متوسط الرضا</th><th></th></tr></thead><tbody>${R.trainers.map(t=>{const ss=S.filter(s=>normKey(s.trainer)===normKey(t.name));const a=agg(ss);
   return `<tr><td><b>${esc(t.name)}</b></td><td>${esc(t.type)}</td><td>${esc(t.org)}</td><td class="sub">${esc(t.spec)}</td><td class="cd">${esc(t.phone)}</td><td class="num">${ss.length}</td><td class="num">${fmt(a.hours)}</td><td class="num">${fmt(a.attended)}</td><td class="num">${a.l1pct!=null?pc(a.l1pct):'—'}</td><td><button class="btn-ghost" onclick="editTrainer('${t.id}')">تعديل</button><button class="btn-del" onclick="delTrainer('${t.id}')">حذف</button></td></tr>`}).join('')||'<tr><td colspan="10" class="empty">لا يوجد مدربون مسجلون. يُضاف المدرب تلقائيًا عند كتابته في تسجيل الجلسة.</td></tr>'}</tbody></table></div>`}
function editTrainer(id){const t=R.trainers.find(x=>x.id===id)||{id:'',name:'',type:'داخلي',org:'',phone:'',spec:''};
  openModal(`<div class="mh"><h3>${id?'تعديل مدرب':'مدرب جديد'}</h3><button class="x" onclick="closeModal()">×</button></div><form class="mb" id="trForm"><div class="fgrid"><div class="f w2"><label>الاسم *</label><input name="name" value="${esc(t.name)}" required></div><div class="f"><label>النوع</label><select name="type">${opt(['داخلي','خارجي'],t.type)}</select></div><div class="f"><label>الجهة</label><input name="org" value="${esc(t.org)}"></div><div class="f"><label>التخصص</label><input name="spec" value="${esc(t.spec)}"></div><div class="f"><label>الهاتف / البريد</label><input name="phone" value="${esc(t.phone)}"></div></div></form><div class="mf"><button class="btn-out" onclick="closeModal()">إلغاء</button><button class="btn" onclick="saveTrainer('${id||''}')">حفظ</button></div>`,'sm')}
function saveTrainer(id){const fd=Object.fromEntries(new FormData($('trForm')).entries());if(!fd.name.trim()){toast('اكتب الاسم',true);return}
  const t=R.trainers.find(x=>x.id===id);if(t){const old=t.name;Object.assign(t,fd);if(old!==fd.name)Object.values(R.recs).forEach(r=>{if(normKey(r.trainer)===normKey(old))r.trainer=fd.name})}else R.trainers.push(Object.assign({id:uid()},fd));save();closeModal();render()}
function delTrainer(id){if(!confirm('حذف المدرب من القائمة؟ (لن تتأثر الجلسات المسجلة)'))return;R.trainers=R.trainers.filter(x=>x.id!==id);save();render()}

/* ===================== التقارير ===================== */
let RP={preset:'week',from:'',to:''};
function presetRange(p){const d=new Date();const t0=iso(d);const yr=YEAR();
  const wk=x=>{const z=new Date(x);const off=(z.getDay()+1)%7;z.setDate(z.getDate()-off);return z};/* بداية الأسبوع السبت */
  if(p==='week'){const s=wk(d);const e=new Date(s);e.setDate(e.getDate()+6);return[iso(s),iso(e)]}
  if(p==='lastweek'){const s=wk(d);s.setDate(s.getDate()-7);const e=new Date(s);e.setDate(e.getDate()+6);return[iso(s),iso(e)]}
  if(p==='month')return[iso(new Date(d.getFullYear(),d.getMonth(),1)),iso(new Date(d.getFullYear(),d.getMonth()+1,0))];
  if(p==='lastmonth')return[iso(new Date(d.getFullYear(),d.getMonth()-1,1)),iso(new Date(d.getFullYear(),d.getMonth(),0))];
  if(p==='quarter'){const q=Math.floor(d.getMonth()/3);return[iso(new Date(d.getFullYear(),q*3,1)),iso(new Date(d.getFullYear(),q*3+3,0))]}
  if(p==='ytd')return[`${yr}-01-01`,t0<`${yr}-01-01`?`${yr}-01-01`:t0>`${yr}-12-31`?`${yr}-12-31`:t0];
  if(p==='year')return[`${yr}-01-01`,`${yr}-12-31`];
  return[RP.from||t0,RP.to||t0]}
function vReports(){if(!RP.from){const [a,b]=presetRange(RP.preset);RP.from=a;RP.to=b}
  const P2=[['week','هذا الأسبوع'],['lastweek','الأسبوع الماضي'],['month','هذا الشهر'],['lastmonth','الشهر الماضي'],['quarter','هذا الربع'],['ytd','من بداية العام'],['year','العام كاملًا']];
  return pageTop('التقارير التنفيذية','تقرير جاهز للإدارة العليا عن أي فترة: المنفذ مقابل المخطط، المتدربون، الساعات، الجودة، التكلفة، المتأخرات والخطوة القادمة — مع نص جاهز للإرسال.',`<button class="btn-out" onclick="window.print()">طباعة / PDF</button><button class="btn-out" onclick="copyReport()">نسخ نص التقرير</button><button class="btn-out" onclick="exportExcel()">تصدير Excel</button>`)+
  `<div class="tabs">${P2.map(([k,l])=>`<button class="${RP.preset===k?'on':''}" onclick="RP.preset='${k}';const r=presetRange('${k}');RP.from=r[0];RP.to=r[1];render()">${l}</button>`).join('')}</div>
   <div class="filters"><label class="sub">من</label><input type="date" value="${RP.from}" onchange="RP.preset='custom';RP.from=this.value;render()"><label class="sub">إلى</label><input type="date" value="${RP.to}" onchange="RP.preset='custom';RP.to=this.value;render()"></div><div id="repBox"></div>`}
function reportData(){const a=RP.from,b=RP.to;const S=M.slots;const inR=s=>s.from&&s.from<=b&&(s.to||s.from)>=a;
  const due=S.filter(s=>inR(s));const done=due.filter(s=>s.done);const A=agg(due);const nb=new Date(pd(b));nb.setDate(nb.getDate()+1);const ne=new Date(nb);ne.setDate(ne.getDate()+6);
  const next=S.filter(s=>s.pending&&s.from>=iso(nb)&&s.from<=iso(ne));const ytd=S.filter(s=>s.from&&s.from<=b);const Y=agg(ytd);
  const late=S.filter(s=>s.overdue);const issues=due.filter(s=>s.status==='مؤجل'||s.status==='ملغي');
  const log=R.planLog.filter(e=>e.at.slice(0,10)>=a&&e.at.slice(0,10)<=b);const chg=[];log.slice().reverse().forEach(e=>e.changes.forEach(c=>chg.push(c)));
  return{a,b,due,done,A,next,nb:iso(nb),ne:iso(ne),Y,ytdN:ytd.length,late,issues,chg}}
function drawReport(){const el=$('repBox');if(!el)return;const d=reportData();const A=d.A,Y=d.Y;
  const row=s=>`<tr><td>${rng(s.from,s.to)}</td><td>${cdc(s.prog.code)} ${esc(s.prog.name)}</td><td class="num">${s.g}</td><td>${chip(s.prog.cat)}</td><td>${esc(s.trainer||'—')}</td><td class="num">${s.done?s.attended:'—'}</td><td class="num">${s.done?fmt(s.attended*s.hours):'—'}</td><td class="num">${s.l1!=null?pc(Math.round(s.l1/5*100)):'—'}</td><td>${stPill(s)}</td></tr>`;
  const th=`<thead><tr><th>التاريخ</th><th>البرنامج</th><th class="num">مجموعة</th><th>الفئة</th><th>المدرب</th><th class="num">المتدربون</th><th class="num">ساعات متدرب</th><th class="num">الرضا</th><th>الحالة</th></tr></thead>`;
  el.innerHTML=`<div class="report">${printHead()}<h2>تقرير التدريب والتطوير | ${fmtDY(d.a)} — ${fmtDY(d.b)}</h2><div class="sub">${esc(ORG())} — ${esc(UNIT())}</div>
   <h3>أولًا: الملخص التنفيذي للفترة</h3><div class="kpis">${kpi('الجلسات المنفذة',`${A.done}<small>من ${A.total-A.cancel}</small>`,`نسبة الإنجاز ${pct(A.done,A.total-A.cancel)}%`,pct(A.done,A.total-A.cancel))}${kpi('المتدربون',fmt(A.attended),`موظفون فريدون ${fmt(A.uniq)}`)}${kpi('ساعات التدريب',fmt(A.hours),`ساعات متدرب ${fmt(A.manHours)}`)}${kpi('نسبة الحضور',A.registered?pc(pct(A.present,A.registered)):'—')}${kpi('رضا المتدربين',A.l1pct!=null?pc(A.l1pct):'—')}${kpi('التكلفة الفعلية',`${fmt(A.cost)}<small>ج.م</small>`)}</div>
   <h3>ثانيًا: الجلسات خلال الفترة (${d.due.length})</h3><div class="tbl-wrap"><table>${th}<tbody>${d.due.map(row).join('')||'<tr><td colspan="9" class="empty">لا توجد جلسات في هذه الفترة</td></tr>'}</tbody></table></div>
   <h3>ثالثًا: المتأخرات والانحرافات</h3>${d.late.length||d.issues.length?`<ul>${d.issues.map(s=>`<li>${s.status}: ${esc(s.prog.name)} (مجموعة ${s.g}) ${s.rec&&s.rec.notes?'— '+esc(s.rec.notes):''}</li>`).join('')}${d.late.length?`<li><b>${d.late.length} جلسة متأخرة</b> حتى اليوم عن موعدها المخطط دون تسجيل تنفيذ: ${d.late.slice(0,6).map(s=>esc(s.prog.name)).join('، ')}${d.late.length>6?' ...':''}</li>`:''}</ul>`:'<p class="sub">لا توجد انحرافات.</p>'}
   <h3>رابعًا: المخطط للأسبوع التالي (${rng(d.nb,d.ne)})</h3><div class="tbl-wrap"><table>${th}<tbody>${d.next.map(row).join('')||'<tr><td colspan="9" class="empty">لا توجد جلسات مخططة</td></tr>'}</tbody></table></div>
   <h3>تعديلات الخطة خلال الفترة (${d.chg.length})</h3>${d.chg.length?`<ul>${d.chg.slice(0,20).map(c=>`<li>${chgTxt(c)}</li>`).join('')}</ul>${d.chg.length>20?'<p class="sub">... التفاصيل الكاملة في صفحة تعديلات الخطة</p>':''}`:'<p class="sub">لم تُرصد تعديلات على الخطة خلال الفترة.</p>'}
   <h3>خامسًا: الموقف التراكمي من بداية العام حتى ${fmtD(d.b)}</h3><div class="kpis">${kpi('الجلسات',`${Y.done}<small>من ${d.ytdN-Y.cancel} مستحقة</small>`,'',pct(Y.done,d.ytdN-Y.cancel))}${kpi('المتدربون',fmt(Y.attended))}${kpi('ساعات متدرب',fmt(Y.manHours))}${kpi('رضا المتدربين',Y.l1pct!=null?pc(Y.l1pct):'—')}${kpi('التكلفة',`${fmt(Y.cost)}<small>ج.م</small>`)}</div>
   <h3>نص التقرير (جاهز للنسخ في البريد / واتساب)</h3><textarea id="repTxt" style="min-height:260px" readonly>${esc(reportText(d))}</textarea></div>`}
function reportText(d){const A=d.A,Y=d.Y;const L=[];
  L.push(`تقرير التدريب والتطوير | ${d.a} إلى ${d.b}`);L.push(`${ORG()} — ${UNIT()}`);L.push('');
  L.push('▪ الملخص التنفيذي:');
  L.push(`• الجلسات المنفذة: ${A.done} من ${A.total-A.cancel} مخططة (${pct(A.done,A.total-A.cancel)}%)`);
  L.push(`• المتدربون: ${fmt(A.attended)} متدربًا${A.registered?` | نسبة الحضور ${pct(A.present,A.registered)}%`:''}`);
  L.push(`• ساعات التدريب: ${fmt(A.hours)} ساعة | ساعات متدرب: ${fmt(A.manHours)}`);
  if(A.l1pct!=null)L.push(`• رضا المتدربين: ${A.l1pct}%`);if(A.post!=null)L.push(`• التعلم: تحسن ${Math.round(A.post-A.pre)} نقطة (قبلي ${Math.round(A.pre)}% ← بعدي ${Math.round(A.post)}%)`);
  L.push(`• التكلفة الفعلية: ${fmt(A.cost)} ج.م`);L.push('');
  if(d.done.length){L.push('▪ البرامج المنفذة:');const g={};d.done.forEach(s=>{g[s.prog.name]=g[s.prog.name]||{n:0,a:0};g[s.prog.name].n++;g[s.prog.name].a+=s.attended});Object.entries(g).forEach(([k,v])=>L.push(`• ${k}: ${v.n} جلسة | ${v.a} متدرب`));L.push('')}
  if(d.issues.length||d.late.length){L.push('▪ الانحرافات:');d.issues.forEach(s=>L.push(`• ${s.status}: ${s.prog.name} (مجموعة ${s.g})${s.rec&&s.rec.notes?' — '+s.rec.notes:''}`));if(d.late.length)L.push(`• ${d.late.length} جلسة متأخرة عن موعدها دون تسجيل تنفيذ`);L.push('')}
  L.push(`▪ المخطط للأسبوع التالي (${d.nb} إلى ${d.ne}): ${d.next.length} جلسة`);d.next.slice(0,10).forEach(s=>L.push(`• ${s.from}: ${s.prog.name} (مجموعة ${s.g})`));L.push('');
  if(d.chg.length){L.push(`▪ تعديلات الخطة خلال الفترة (${d.chg.length}):`);d.chg.slice(0,10).forEach(c=>L.push('• '+chgTxt(c).replace(/<[^>]+>/g,'')));L.push('')}
  L.push(`▪ التراكمي حتى ${d.b}: ${Y.done} جلسة من ${d.ytdN-Y.cancel} مستحقة (${pct(Y.done,d.ytdN-Y.cancel)}%) | ${fmt(Y.attended)} متدرب | ${fmt(Y.manHours)} ساعة متدرب | ${fmt(Y.cost)} ج.م`);
  return L.join('\n')}
function copyReport(){const t=$('repTxt');if(!t)return;t.select();try{navigator.clipboard.writeText(t.value).then(()=>toast('تم نسخ نص التقرير'),()=>{document.execCommand('copy');toast('تم نسخ نص التقرير')})}catch(e){document.execCommand('copy');toast('تم نسخ نص التقرير')}}

/* ===================== الإعدادات ===================== */
function vSet(){const st=R.settings;
  return pageTop('الإعدادات','الربط بنظام الاحتياجات، معايير التقييم، بيانات الموظفين، النسخ الاحتياطي والأمان.')+
  sec('الربط بنظام الاحتياجات والخطة السنوية')+`<div class="card"><div class="info-row" style="margin:0 0 12px"><span><b>المصدر الحالي:</b>${PLAN_SRC==='live'?'مباشر من نظام الاحتياجات':PLAN_SRC==='import'?'ملف مستورد':PLAN_SRC==='cache'?'آخر نسخة محفوظة':'نسخة مدمجة داخل الملف'}</span><span><b>آخر تحديث:</b>${esc(PLAN_AT||'—')}</span><span><b>البرامج:</b>${P.programs.length}</span><span><b>الاحتياجات:</b>${P.needs.length}</span><span><b>الجلسات المخططة:</b>${M.slots.filter(s=>!s.prog.adhoc).length}</span></div>
   <p class="sub" style="margin-top:0">يقرأ النظام البرامج والجلسات والاحتياجات مباشرة من <a href="${PLAN_LINK.page}" target="_blank" rel="noopener">نظام الاحتياجات التدريبية</a> (قراءة فقط) عند كل فتح وكل 5 دقائق. أي تعديل على الخطة هناك يظهر هنا تلقائيًا، وتبقى بيانات التنفيذ محفوظة ومربوطة بكود البرنامج ورقم المجموعة.</p>
   <div class="acts"><button class="btn" onclick="pullPlan(true)">تحديث من نظام الاحتياجات الآن</button><button class="btn-out" onclick="$('fileP').click()">استيراد نسخة JSON من نظام الاحتياجات</button></div></div>`+
  sec('بيانات المراسلات والنماذج الرسمية','تظهر في رسائل واتساب وفي النماذج المطبوعة (TR-P-F03 / F04 / F09).')+`<div class="card"><div class="fgrid"><div class="f"><label>اسم منسق التدريب</label><input id="s_cn" value="${esc(st.coordName||'')}"></div><div class="f"><label>رقم منسق التدريب</label><input id="s_cp" dir="ltr" value="${esc(st.coordPhone||'')}"></div><div class="f"><label>مدير الموارد البشرية (توقيع الإخطار)</label><input id="s_hr" value="${esc(st.hrManager||'')}"></div><div class="f"><label>رقم إصدار النماذج</label><input id="s_fr" value="${esc(st.formRev||'2')}"></div><div class="f"><label>تاريخ إصدار النماذج</label><input id="s_fd" value="${esc(st.formDate||'')}"></div></div><div class="acts" style="margin-top:10px"><button class="btn" onclick="saveSet()">حفظ</button></div></div>`+
  sec('معايير التنفيذ والتقييم')+`<div class="card"><div class="fgrid"><div class="f"><label>درجة النجاح في الاختبار البعدي %</label><input id="s_pass" type="number" value="${esc(st.passMark)}"></div><div class="f"><label>موعد متابعة L3 بعد التدريب (يوم)</label><input id="s_l3" type="number" value="${esc(st.l3Days)}"></div><div class="f"><label>المستهدف السنوي لساعات تدريب الموظف</label><input id="s_ht" type="number" value="${esc(st.hoursTarget)}"></div><div class="f wall"><label>أماكن التنفيذ (سطر لكل مكان)</label><textarea id="s_ven">${esc((st.venues||[]).join('\n'))}</textarea></div></div><div class="acts" style="margin-top:10px"><button class="btn" onclick="saveSet()">حفظ</button></div></div>`+
  `<div id="empSec">${sec('بيانات الموظفين (Master Data)',`${R.employees.length} موظف — تُستخدم لاستكمال الأسماء تلقائيًا من الكود ولمعرفة من لم يحصل على تدريب. الأعمدة: الكود، الاسم، الإدارة، الفرع، الوظيفة.`)}</div><div class="card"><div class="acts"><button class="btn-out" onclick="$('fileE').click()">استيراد من Excel</button><button class="btn-out" onclick="pasteEmp()">لصق من Excel</button><button class="btn-out" onclick="exportEmp()">تصدير القائمة</button><button class="btn-out" style="color:var(--danger)" onclick="if(confirm('حذف قائمة الموظفين؟ (لا يؤثر على كشوف الحضور)')){R.employees=[];save();render()}">حذف القائمة</button></div></div>`+
  sec('النسخ الاحتياطي والتصدير','البيانات محفوظة على الخادم المشترك ومتزامنة بين كل الأجهزة. الخادم يحتفظ بآخر نسخة فقط — خذ نسخة احتياطية JSON أسبوعيًا.')+`<div class="card"><div class="acts"><button class="btn" onclick="exportJSON()">تنزيل نسخة احتياطية JSON</button><button class="btn-out" onclick="$('fileJ').click()">استعادة نسخة احتياطية</button><button class="btn-out" onclick="exportExcel()">تصدير كل البيانات Excel</button><button class="btn-out" style="color:var(--danger)" onclick="clearAll()">حذف كل بيانات التنفيذ</button></div></div>`+
  sec('المزامنة المشتركة بين الأجهزة','البيانات محفوظة على خادم مشترك ومحمية بكلمة السر — أي تعديل على أي جهاز يُرفع تلقائيًا خلال ثوانٍ، وتحديثات الأجهزة الأخرى تصل كل دقيقة. لو عدّل جهازان في نفس الوقت يُحفظ تعديل الاثنين.')+`<div class="card"><div class="fgrid"><div class="f"><label>اسم هذا الجهاز (اختياري)</label><input id="syncDevice" placeholder="مثال: مكتب التدريب" value="${esc(window.SBSync?window.SBSync.device():'')}" onchange="SBSync.setDevice(this.value)"></div></div><div class="acts" style="margin-top:10px"><button class="btn" onclick="SBSync.sync({manual:true})">مزامنة الآن ⟳</button><button class="btn-out" onclick="SBSync.logout()">تسجيل الخروج من هذا الجهاز</button></div><div id="syncLine" class="alert info" style="margin-bottom:0"></div></div>`}
function saveSet(){const st=R.settings;const gv=id=>$(id)?$(id).value.trim():null;[['s_cn','coordName'],['s_cp','coordPhone'],['s_hr','hrManager'],['s_fr','formRev'],['s_fd','formDate']].forEach(([i,k])=>{const v=gv(i);if(v!==null)st[k]=v});if(!$('s_pass')){save();render();toast('تم حفظ الإعدادات');return}st.passMark=num($('s_pass').value)||70;st.l3Days=num($('s_l3').value)||90;st.hoursTarget=num($('s_ht').value);st.venues=[...new Set($('s_ven').value.split('\n').map(x=>x.trim()).filter(Boolean))];save();render();toast('تم حفظ الإعدادات')}
function resetPlan(){try{localStorage.removeItem(PCACHE)}catch(e){}if(typeof PLAN_SNAPSHOT!=='undefined')setPlan(PLAN_SNAPSHOT,'snapshot',PLAN_SNAPSHOT_AT);trackPlan();render();toast('تم الرجوع للنسخة المدمجة')}
function importPlan(file){if(!file)return;const rd=new FileReader();rd.onload=e=>{try{const x=JSON.parse(e.target.result);if(!setPlan(x,'import',new Date().toLocaleString('en-GB')))throw 0;cachePlan('import');trackPlan();render();toast(`تم استيراد الخطة: ${P.programs.length} برنامج`)}catch(err){toast('الملف ليس نسخة صحيحة من نظام الاحتياجات',true)}};rd.readAsText(file)}
function mergeEmp(L){const idx=empIdx();let add=0,upd=0;L.forEach(a=>{const c=String(a.code||'').trim();if(!c)return;const e=idx[c];const v={code:c,name:a.name||'',dept:a.dept||'',branch:a.branch||'',job:a.job||'',phone:a.phone||''};if(e){Object.keys(v).forEach(k=>{if(v[k])e[k]=v[k]});upd++}else{R.employees.push(v);idx[c]=v;add++}});save();render();toast(`تمت إضافة ${add} وتحديث ${upd} موظف`)}
function importEmp(file){readXL(file,rows=>mergeEmp(rowsToPeople(rows.map(r=>r.map(c=>String(c))))))}
function pasteEmp(){openModal(`<div class="mh"><h3>لصق قائمة الموظفين</h3><button class="x" onclick="closeModal()">×</button></div><div class="mb"><p class="sub">الأعمدة: الكود، الاسم، الإدارة، الفرع، الوظيفة (صف العناوين اختياري).</p><textarea id="pasteE" style="min-height:240px"></textarea></div><div class="mf"><button class="btn-out" onclick="closeModal()">إلغاء</button><button class="btn" onclick="const L=rowsToPeople(parseRows($('pasteE').value));closeModal();mergeEmp(L)">إضافة</button></div>`,'sm')}
function exportEmp(){const rows=R.employees.map(e=>({'الكود':e.code,'الاسم':e.name,'الإدارة':e.dept,'الفرع':e.branch,'الوظيفة':e.job,'رقم الموبايل':e.phone||''}));xlBook([['الموظفين',rows]],'قائمة_الموظفين')}
function exportJSON(){dl(new Blob([JSON.stringify(R,null,1)],{type:'application/json'}),`نسخة_احتياطية_سجل_التدريب_${today()}.json`)}
function importJSON(file){if(!file)return;const rd=new FileReader();rd.onload=e=>{try{const x=JSON.parse(e.target.result);if(!x||typeof x.recs!=='object')throw 0;if(!confirm('سيتم استبدال بيانات التنفيذ الحالية بالنسخة المستوردة على كل الأجهزة المتزامنة. متابعة؟'))return;localStorage.setItem(RKEY,JSON.stringify(x));R=loadR();render();toast('تمت استعادة النسخة الاحتياطية')}catch(err){toast('ملف غير صالح',true)}};rd.readAsText(file)}
function clearAll(){if(!confirm('سيتم حذف كل بيانات التنفيذ والحضور والتقييم نهائيًا من كل الأجهزة المتزامنة. هل أخذت نسخة احتياطية؟'))return;R=defaultsR();save();render();toast('تم الحذف')}
const lsGet=k=>{try{return localStorage.getItem(k)}catch(e){return null}};

/* ===================== تصدير Excel ===================== */
function xlBook(sheets,name){if(typeof XLSX==='undefined'){const [n,rows]=sheets[0];if(!rows.length){toast('لا توجد بيانات',true);return}const hd=Object.keys(rows[0]);dl(new Blob(['﻿'+[hd,...rows.map(r=>hd.map(h=>r[h]))].map(r=>r.map(c=>`"${String(c??'').replace(/"/g,'""')}"`).join(',')).join('\n')],{type:'text/csv'}),name+'.csv');toast('مكتبة Excel غير متاحة — تم تصدير CSV للورقة الأولى',true);return}
  const wb=XLSX.utils.book_new();wb.Workbook={Views:[{RTL:true}]};sheets.forEach(([n,rows])=>{const ws=rows.length?XLSX.utils.json_to_sheet(rows):XLSX.utils.aoa_to_sheet([['لا توجد بيانات']]);if(rows.length)ws['!cols']=Object.keys(rows[0]).map(k=>({wch:Math.min(45,Math.max(10,k.length+4,...rows.slice(0,200).map(r=>String(r[k]??'').length+2)))}));XLSX.utils.book_append_sheet(wb,ws,n.slice(0,31))});
  XLSX.writeFile(wb,`${name}_${today()}.xlsx`)}
function exportExcel(){buildModel();const r1=x=>x==null?'':Math.round(x*10)/10;
  const sess=M.slots.map(s=>({'كود البرنامج':s.prog.code,'البرنامج':s.prog.name,'نوع':s.prog.adhoc?'غير مخطط':'من الخطة','الفئة':CATS[s.prog.cat]||'','المجموعة':s.g,'الأسلوب':s.prog.method,'الجهة':s.prog.provider,'المخطط من':s.pFrom,'المخطط إلى':s.pTo,'الفعلي من':s.rec?s.from:'','الفعلي إلى':s.rec?s.to:'','الحالة':dispSt(s),'المدرب':s.trainer,'المكان':s.venue,'الساعات':s.hours,'المقاعد المخططة':s.seats,'المسجلون':s.registered,'الحضور':s.attended,'ساعات متدرب':s.done?s.attended*s.hours:0,'الرضا من 5':r1(s.l1),'متوسط قبلي':r1(s.preAvg),'متوسط بعدي':r1(s.postAvg),'تكلفة المدرب':num(s.rec&&s.rec.costT),'تكلفة لوجستية':num(s.rec&&s.rec.costL),'ملاحظات':s.rec?s.rec.notes||'':''}));
  const att=[];M.slots.filter(s=>s.rec).forEach(s=>s.att.forEach(a=>att.push({'التاريخ':s.from,'كود البرنامج':s.prog.code,'البرنامج':s.prog.name,'المجموعة':s.g,'الكود':a.code,'الاسم':a.name,'الموبايل':a.phone||'','رسالة واتساب':a.waAt?String(a.waAt).slice(0,10):'','الإدارة':a.dept,'الفرع':a.branch,'الوظيفة':a.job,'الحضور':a.st,'قبلي':a.pre,'بعدي':a.post,'الرضا':a.sat,'الساعات':(a.st==='حاضر'||a.st==='متأخر')&&s.done?s.hours:0})));
  const progs=M.progs.map(o=>{const a=agg(o.slots);const live=o.slots.filter(s=>s.status!=='ملغي').length;return{'الكود':o.code,'البرنامج':o.name,'الفئة':CATS[o.cat]||'','الأسلوب':o.method,'الجهة':o.provider,'الجلسات المخططة':live,'المنفذة':a.done,'نسبة التنفيذ %':pct(a.done,live),'المتدربون المخططون':o.trainees,'الحضور الفعلي':a.attended,'ساعات متدرب':a.manHours,'الرضا %':a.l1pct??'','قبلي':r1(a.pre),'بعدي':r1(a.post),'التكلفة المخططة':o.planCost,'التكلفة الفعلية':a.cost,'الحالة':progStatus(o)}});
  const emps=empRecords().map(e=>({'الكود':e.code,'الاسم':e.name,'الإدارة':e.dept,'الفرع':e.branch,'الوظيفة':e.job,'عدد البرامج':e.progs.size,'ساعات التدريب':e.hours,'آخر تدريب':e.last}));
  const needs=P.needs.map(n=>{const o=n.programId&&M.byId[n.programId];return{'كود الاحتياج':n.code,'الاحتياج':n.title,'الإدارة':n.dept,'العدد المطلوب':+n.trainees||0,'البرنامج':o?o.code+' '+o.name:'','حالة التلبية':needState(n)}});
  const evals=M.progs.filter(o=>o.slots.some(s=>s.done)).map(o=>{const a=agg(o.slots);const ev=R.evals[o.id]||{};const l3=ev.l3||{},l4=ev.l4||{};return{'البرنامج':o.code+' '+o.name,'المستوى المستهدف':o.evalLevel,'L1 الرضا %':a.l1pct??'','L2 قبلي':r1(a.pre),'L2 بعدي':r1(a.post),'نسبة النجاح %':a.posted?pct(a.pass,a.posted):'','L3 التطبيق %':l3.score||'','L3 التاريخ':l3.date||'','L4 المؤشر':l4.kpi||o.kpi,'L4 قبل':l4.base||'','L4 المستهدف':l4.target||'','L4 الفعلي':l4.actual||''}});
  const tr=R.trainers.map(t=>{const ss=M.slots.filter(s=>s.done&&normKey(s.trainer)===normKey(t.name));const a=agg(ss);return{'المدرب':t.name,'النوع':t.type,'الجهة':t.org,'الجلسات':ss.length,'الساعات':a.hours,'المتدربون':a.attended,'الرضا %':a.l1pct??''}});
  const B=curBase();const chgRows=B?planDiff(B.progs,planSummary()).flatMap(c=>c.t==='mod'?c.f.map(f=>({'النوع':'معدّل','الكود':c.code,'البرنامج':c.name,'البند':f.l,'في الأساس':f.from,'في الخطة الحالية':f.to})):[{'النوع':c.t==='add'?'مضاف':'محذوف','الكود':c.code,'البرنامج':c.name,'البند':'البرنامج كاملًا','في الأساس':c.t==='add'?'':`${fmt(c.tr)} متدرب | ${fmt(c.cost)} ج.م`,'في الخطة الحالية':c.t==='add'?`${fmt(c.tr)} متدرب | ${fmt(c.cost)} ج.م`:''}]):[];
  xlBook([['البرامج - مخطط مقابل فعلي',progs],['تعديلات الخطة عن الأساس',chgRows],['الجلسات',sess],['كشوف الحضور',att],['السجل التدريبي للموظفين',emps],['تغطية الاحتياجات',needs],['التقييم',evals],['المدربون',tr]],`سجل_التدريب_${YEAR()}`)}


/* ===================== المزامنة المشتركة بين الأجهزة (Supabase) ===================== */
/* كل البيانات تمر عبر دوال trs_* المحمية بكلمة السر؛ لا قراءة ولا كتابة مباشرة على الجداول */
const SYNC_PW_KEY='zahran_trs_sync_pw';
const SBSync=(function(){
  const SB_URL=PLAN_LINK.url,SB_KEY=PLAN_LINK.key;
  const OFF_KEY='zahran_trs_pw_print',BASE_KEY='zahran_trs_sb_base',DEV_KEY='zahran_trs_device';
  const PUSH_DELAY=2000,POLL_EVERY=60*1000;
  let pw='',busy=false,pending=false,pushTimer=null,lastSyncAt=0,started=false,ST={k:'off',t:'المزامنة غير مفعّلة'};
  try{['zahran_trs_pwh','zahran_trs_unlocked'].forEach(k=>{localStorage.removeItem(k);sessionStorage.removeItem(k)})}catch(e){} /* القفل المحلي القديم */
  const loadBase=()=>{try{return JSON.parse(localStorage.getItem(BASE_KEY)||'null')}catch(e){return null}};
  const saveBase=b=>{try{localStorage.setItem(BASE_KEY,JSON.stringify(b))}catch(e){}};
  const device=()=>{try{return localStorage.getItem(DEV_KEY)||''}catch(e){return ''}};
  const setDevice=v=>{try{localStorage.setItem(DEV_KEY,String(v||'').trim())}catch(e){}};
  function stable(v){if(v===null||typeof v!=='object')return JSON.stringify(v);if(Array.isArray(v))return '['+v.map(stable).join(',')+']';return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}'}
  function hash(str){let h1=0xdeadbeef,h2=0x41c6ce57;for(let i=0;i<str.length;i++){const ch=str.charCodeAt(i);h1=Math.imul(h1^ch,2654435761);h2=Math.imul(h2^ch,1597334677)}
    h1=Math.imul(h1^(h1>>>16),2246822507)^Math.imul(h2^(h2>>>13),3266489909);h2=Math.imul(h2^(h2>>>16),2246822507)^Math.imul(h1^(h1>>>13),3266489909);return (4294967296*(2097151&h2)+(h1>>>0)).toString(36)}
  const hRec=r=>hash(stable(r));
  /* كل مجموعة بيانات تتحول لخريطة سجلات بمفتاح ثابت → دمج على مستوى السجل */
  const COLS={trainers:x=>x&&x.id,employees:x=>x&&String(x.code||'').trim(),adhoc:x=>x&&x.id,baselines:x=>x&&x.id,planLog:x=>x&&hash(stable({at:x.at,c:x.changes}))};
  const OBJS=['recs','evals'];const ALL=[...Object.keys(COLS),...OBJS,'_s'];
  function toMaps(d){const m={};Object.keys(COLS).forEach(k=>{m[k]={};(d[k]||[]).forEach(r=>{const id=COLS[k](r);if(id)m[k][id]=r})});OBJS.forEach(k=>{m[k]=Object.assign({},d[k]||{})});
    m._s={settings:d.settings||{},lastSeen:d.lastSeen||null,activeBase:d.activeBase||''};return m}
  function fromMaps(m,local){const d=defaultsR();Object.keys(COLS).forEach(k=>{const ord=new Map((local[k]||[]).map((r,i)=>[COLS[k](r),i]));
      d[k]=Object.entries(m[k]).sort((a,b)=>(ord.has(a[0])?ord.get(a[0]):1e9)-(ord.has(b[0])?ord.get(b[0]):1e9)).map(e=>e[1])});
    d.planLog.sort((a,b)=>String(b.at).localeCompare(String(a.at)));d.planLog=d.planLog.slice(0,300);
    OBJS.forEach(k=>d[k]=m[k]);d.settings=Object.assign(defaultsR().settings,(m._s.settings)||{});d.lastSeen=m._s.lastSeen||null;d.activeBase=m._s.activeBase||'';
    /* نسخة أساس تلقائية واحدة فقط على مستوى كل الأجهزة (الأقدم) */
    const autos=d.baselines.filter(b=>b.auto).sort((a,b)=>String(a.at).localeCompare(String(b.at))||String(a.id).localeCompare(String(b.id)));
    if(autos.length>1){const drop=new Set(autos.slice(1).map(b=>b.id));d.baselines=d.baselines.filter(b=>!drop.has(b.id));if(drop.has(d.activeBase))d.activeBase=''}
    return d}
  const hashMaps=m=>{const h={};ALL.forEach(k=>{h[k]={};Object.keys(m[k]||{}).forEach(id=>h[k][id]=hRec(m[k][id]))});return h};
  const dataHash=d=>hash(stable(hashMaps(toMaps(d))));
  const newer=(a,b)=>(b&&a&&(b.updatedAt||'')>(a.updatedAt||''))?b:a;
  function mergeMap(L,Rm,B){const out={};new Set([...Object.keys(L||{}),...Object.keys(Rm||{})]).forEach(id=>{const l=L[id],r=Rm[id],b=B?B[id]:undefined;
      if(l!==undefined&&r!==undefined){const hl=hRec(l),hr=hRec(r);if(hl===hr||hr===b)out[id]=l;else if(hl===b)out[id]=r;else out[id]=newer(l,r)}
      else if(l!==undefined){if(b&&hRec(l)===b)return;out[id]=l}
      else if(r!==undefined){if(b&&hRec(r)===b)return;out[id]=r}});return out}
  function merge(local,remote,base){const lm=toMaps(local),rm=toMaps(remote),m={};ALL.forEach(k=>m[k]=mergeMap(lm[k]||{},rm[k]||{},base&&base.h?base.h[k]:null));return fromMaps(m,local)}
  const isEmpty=d=>!Object.keys(d.recs||{}).length&&!(d.employees||[]).length&&!(d.trainers||[]).length&&!(d.adhoc||[]).length&&!Object.keys(d.evals||{}).length;
  async function rpc(fn,body){const r=await fetch(`${SB_URL}/rest/v1/rpc/${fn}`,{method:'POST',cache:'no-store',headers:{apikey:SB_KEY,Authorization:'Bearer '+SB_KEY,'Content-Type':'application/json'},body:JSON.stringify(body)});
    const res=await r.json().catch(()=>null);if(!r.ok)throw new Error('خطأ من الخادم ('+r.status+')'+(res&&res.message?' '+res.message:''));return res}
  /* true = صحيحة | false = خطأ | 'offline' = لا يوجد اتصال ولا بصمة محفوظة */
  async function verify(p){try{const ok=await rpc('trs_check_pw',{pw:p});if(ok===true)try{localStorage.setItem(OFF_KEY,pwPrintSync(p))}catch(e){}return ok===true}
    catch(err){let saved='';try{saved=localStorage.getItem(OFF_KEY)||''}catch(e){}return saved&&pwPrintSync(p)===saved?true:'offline'}}
  function paint(){const pill=$('syncPill');if(pill){pill.className='linkpill sync-'+ST.k;pill.innerHTML=`<i></i>${esc(ST.t)}`;pill.title='اضغط للمزامنة الآن'}
    const line=$('syncLine');if(line){line.className='alert '+(ST.k==='ok'?'ok':ST.k==='err'?'err':'info');line.style.marginBottom='0';line.textContent=ST.t+(device()?` — هذا الجهاز: ${device()}`:'')}}
  function setStatus(k,t){ST={k,t};paint()}
  function refreshUI(){if($('modal').classList.contains('show')||($('modal2')&&$('modal2').classList.contains('show'))){NEED_RENDER=true;toast('وصلت تحديثات من جهاز آخر — ستظهر بعد إغلاق النافذة')}else render()}
  function lockOut(msg){pw='';try{sessionStorage.removeItem(SYNC_PW_KEY);localStorage.removeItem(OFF_KEY)}catch(e){}setStatus('err',msg||'كلمة السر اتغيّرت — ادخل بالكلمة الجديدة');showGate(msg||'كلمة السر اتغيّرت — ادخل بالكلمة الجديدة')}
  async function sync(opts){opts=opts||{};
    if(!pw){setStatus('off','المزامنة غير مفعّلة');return}
    if(!navigator.onLine){setStatus('err','لا يوجد إنترنت — ستتم المزامنة عند عودة الاتصال');return}
    if(busy){pending=true;return}
    busy=true;setStatus('busy','جارٍ المزامنة…');
    try{for(let attempt=1;attempt<=4;attempt++){
        const base=loadBase();const res=await rpc('trs_get_state',{pw,known_version:base?base.version:-1});
        if(!res||!res.ok){if(res&&res.error==='bad_pw'){lockOut();return}throw new Error((res&&res.error)||'رد غير متوقع من الخادم')}
        const local=R;let merged,remoteHash;
        if(res.unchanged){merged=local;remoteHash=base.dh}
        else{const rd=res.data;const remote=rd&&typeof rd.recs==='object'&&rd.recs!==null?rd:null;
          merged=remote?merge(local,remote,base):local;remoteHash=remote?dataHash(remote):null}
        const mh=dataHash(merged);const changedLocal=mh!==dataHash(local);
        if(changedLocal){R=merged;try{localStorage.setItem(RKEY,JSON.stringify(R))}catch(e){}refreshUI()}
        let version=res.version;
        if(remoteHash!==mh&&!(isEmpty(merged)&&remoteHash===null)){
          const sv=await rpc('trs_save_state',{pw,new_data:merged,base_version:version,device:device()});
          if(!sv||!sv.ok){if(sv&&sv.error==='bad_pw'){lockOut();return}if(sv&&sv.error==='conflict'&&attempt<4)continue;
            throw new Error(sv&&sv.error==='conflict'?'أجهزة كثيرة تحفظ في نفس اللحظة — حاول مرة أخرى':'تعذّر الحفظ ('+((sv&&sv.error)||'?')+')')}
          version=sv.version}
        saveBase({version,h:hashMaps(toMaps(merged)),dh:mh,at:new Date().toISOString()});lastSyncAt=Date.now();
        setStatus('ok',`متزامن ${new Date().toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'})}`);
        if(opts.manual)toast(changedLocal?'تمت المزامنة ووصلت تحديثات من أجهزة أخرى':'تمت المزامنة — البيانات متطابقة');
        break}
    }catch(err){console.warn('sync failed',err);let m=err.message||String(err);if(/failed to fetch|networkerror|load failed/i.test(m))m='تعذّر الوصول للخادم — تأكد من الإنترنت';
      setStatus('err','فشلت المزامنة: '+m);if(opts.manual)toast('فشلت المزامنة: '+m,true)}
    finally{busy=false;if(pending){pending=false;setTimeout(()=>sync(),500)}}}
  function onLocalSave(){if(!pw)return;setStatus('wait','في انتظار الرفع…');clearTimeout(pushTimer);pushTimer=setTimeout(()=>sync(),PUSH_DELAY)}
  function start(p){pw=p;try{sessionStorage.setItem(SYNC_PW_KEY,p)}catch(e){}sync();if(started)return;started=true;
    document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&pw&&Date.now()-lastSyncAt>30000)sync()});
    window.addEventListener('online',()=>{if(pw)sync()});
    setInterval(()=>{if(document.visibilityState==='visible'&&pw)sync()},POLL_EVERY)}
  function logout(){if(!confirm('سيتم قفل النظام على هذا الجهاز، والدخول مرة أخرى يحتاج كلمة السر. البيانات على الخادم لن تُحذف.'))return;clearTimeout(pushTimer);try{sessionStorage.removeItem(SYNC_PW_KEY)}catch(e){}location.reload()}
  return{start,sync,verify,onLocalSave,logout,paint,device,setDevice,_merge:merge,_dataHash:dataHash,status:()=>ST}
})();
window.SBSync=SBSync;

/* ---- بوابة الدخول (كلمة السر يتحقق منها الخادم) ---- */
function showGate(msg){closeModal();document.body.classList.add('locked');$('lkLogo').innerHTML=logoHTML();$('lkPw').value='';$('lkErr').textContent=msg||'';setTimeout(()=>$('lkPw').focus(),50)}
let GATE_BUSY=false;
async function tryUnlock(){const p=$('lkPw').value;const btn=$('lkBtn');if(!p||GATE_BUSY)return;GATE_BUSY=true;btn.disabled=true;btn.textContent='جارٍ التحقق…';$('lkErr').textContent='';
  let res;try{res=await SBSync.verify(p)}finally{GATE_BUSY=false;btn.disabled=false;btn.textContent='دخول'}
  if(res===true){$('lkPw').value='';document.body.classList.remove('locked');SBSync.start(p);render();pullPlan(false)}
  else{$('lkErr').textContent=res==='offline'?'تعذّر الاتصال بالخادم — تأكد من الإنترنت وحاول مرة أخرى':'كلمة السر غير صحيحة';$('lkPw').value='';$('lkPw').focus()}}

/* ===================== تشغيل ===================== */
function applyTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem(THKEY,t)}catch(e){}}
function toggleTheme(){applyTheme(document.documentElement.dataset.theme==='dark'?'light':'dark')}
applyTheme(lsGet(THKEY)||'dark');
loadPlan();trackPlan();render();
(()=>{let saved='';try{saved=sessionStorage.getItem(SYNC_PW_KEY)||''}catch(e){}if(saved)SBSync.start(saved);else showGate('')})();
document.addEventListener('keydown',e=>{if(e.key==='Escape'){if($('modal2')&&$('modal2').classList.contains('show'))closeModal2();else closeModal()}});
pullPlan(false);setInterval(()=>{if(!document.hidden)pullPlan(false)},300000);
