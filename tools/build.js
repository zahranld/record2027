// يجمع ملف index.html واحد: الخط المدمج من plan2027 + نسخة مدمجة من الخطة + الكود
const fs=require('fs'),path=require('path');
const [,,planHtml,srcDir,out]=process.argv;
const h=fs.readFileSync(planHtml,'utf8');
const fonts=(h.match(/@font-face\{[^}]*\}/g)||[]).join('\n');
const a=h.indexOf('const EMBED=')+12,b=h.indexOf('</script>',a);
const E=JSON.parse(h.slice(a,b).trim().replace(/;\s*$/,''));
const snap={settings:E.settings,needs:E.needs,programs:E.programs};
const at=process.env.SNAP_AT||new Date().toISOString().slice(0,10);
let shell=fs.readFileSync(path.join(srcDir,'shell.html'),'utf8');
const rep=(k,v)=>{shell=shell.split(k).join(v)};
rep('/*FONT*/',fonts);
rep('/*CSS*/',fs.readFileSync(path.join(srcDir,'app.css'),'utf8'));
rep('/*SNAPSHOT*/','const PLAN_SNAPSHOT_AT='+JSON.stringify('نسخة '+at)+';\nconst PLAN_SNAPSHOT='+JSON.stringify(snap).replace(/<\/script/gi,'<\\/script')+';');
rep('/*JS*/',fs.readFileSync(path.join(srcDir,'app.js'),'utf8'));
fs.writeFileSync(out,shell);
console.log('fonts',fonts.length,'needs',snap.needs.length,'programs',snap.programs.length,'size',shell.length);
