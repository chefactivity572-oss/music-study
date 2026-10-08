const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const {Pool}=require("pg");
const PORT=Number(process.env.PORT||3000);
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:false,max:Number(process.env.DB_POOL_MAX||10)});
const PROD=process.env.NODE_ENV==="production";
const MAX_BODY=70000;
const attempts=new Map();

const sec={
 "X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY",
 "Referrer-Policy":"strict-origin-when-cross-origin",
 "Content-Security-Policy":"default-src 'self';style-src 'self' 'unsafe-inline';script-src 'self';connect-src 'self';img-src 'self' data:",
 "Permissions-Policy":"camera=(),microphone=(),geolocation=()"
};
const send=(r,s,d,e={})=>{r.writeHead(s,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...sec,...e});r.end(JSON.stringify(d))};
const clientKey=q=>{
  if(process.env.TRUST_PROXY==="1") return String(q.headers["x-forwarded-for"]||q.socket.remoteAddress||"unknown").split(",")[0].trim();
  return q.socket.remoteAddress||"unknown";
};
function limited(q,k){let key=k+":"+clientKey(q),now=Date.now(),x=attempts.get(key)||{n:0,t:now};if(now-x.t>60000)x={n:0,t:now};x.n++;attempts.set(key,x);return x.n<=Number(process.env.RATE_LIMIT_PER_MIN||30)}
function body(q){return new Promise((ok,no)=>{let s="",n=0;q.on("data",c=>{n+=c.length;if(n>MAX_BODY){no(Error("too_large"));q.destroy();return}s+=c});q.on("end",()=>{try{ok(JSON.parse(s||"{}"))}catch{no(Error("bad_json"))}});q.on("error",no)})}
function hash(p,s=crypto.randomBytes(16).toString("hex")){return s+":"+crypto.scryptSync(p,s,64).toString("hex")}
function verify(p,v){let[a,h]=String(v).split(":");if(!a||!h)return false;let x=crypto.scryptSync(p,a,64),y=Buffer.from(h,"hex");return x.length===y.length&&crypto.timingSafeEqual(x,y)}
const tok=()=>crypto.randomBytes(32).toString("base64url"),th=x=>crypto.createHash("sha256").update(x).digest("hex");
const cookie=(v,n)=>`ms_session=${v}; Max-Age=${n}; Path=/; HttpOnly; SameSite=Lax${PROD?"; Secure":""}`;
const csrf=q=>!PROD||q.headers["x-requested-with"]==="MUSIC-STUDY";
async function uid(q){let m=(q.headers.cookie||"").match(/(?:^|;\s*)ms_session=([^;]+)/);if(!m)return null;let x=await pool.query("SELECT user_id FROM sessions WHERE token_hash=$1 AND expires_at>NOW()",[th(m[1])]);return x.rowCount?x.rows[0].user_id:null}
function level(x){return x>=900?5:x>=500?4:x>=250?3:x>=100?2:1}
async function teacher(id){let x=await pool.query("SELECT teacher_json FROM teachers WHERE user_id=$1",[id]);return x.rowCount?x.rows[0].teacher_json:null}
async function init(){
 await pool.query(`CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS teachers(user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,teacher_json JSONB NOT NULL,updated_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS learning_events(id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,type TEXT NOT NULL,payload_json JSONB NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
 CREATE INDEX IF NOT EXISTS events_user_idx ON learning_events(user_id,created_at DESC);`);
}
async function aiConference(topic,teachers){
 if(!process.env.OPENAI_API_KEY)return teachers.map(t=>({name:t.name,field:t.field,opinion:`${t.field}の視点から「${topic}」を検討します。前提条件・根拠・反対説を確認します。`}));
 const prompt=`MUSIC STUDYのAI先生会議。議題:${topic}。先生:${teachers.map(t=>t.name+"("+t.field+")").join(",")}。各先生が専門分野から120字以内で意見。JSON配列のみ。形式:[{"name":"","field":"","opinion":""}] 日本語。`;
 const rr=await fetch("https://api.openai.com/v1/responses",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+process.env.OPENAI_API_KEY},body:JSON.stringify({model:process.env.OPENAI_MODEL||"gpt-5.6-luna",input:prompt})});
 if(!rr.ok)throw Error("AI API error");const j=await rr.json();let s="";for(const o of(j.output||[]))for(const c of(o.content||[]))if(c.text)s+=c.text;
 try{return JSON.parse(s.replace(/^```json\s*|\s*```$/g,"").trim())}catch{return teachers.map(t=>({name:t.name,field:t.field,opinion:`${t.field}の視点で、根拠と反対説を確認します。`}))}
}
async function main(q,r){
 try{
  if(q.method==="GET"&&q.url==="/"){r.writeHead(200,{"Content-Type":"text/html; charset=utf-8",...sec});return r.end(fs.readFileSync(path.join(__dirname,"index.html")))}
  if(q.method==="GET"&&q.url==="/health"){return send(r,200,{ok:true,service:"MUSIC STUDY",version:"23.0.0"})}
  if(q.method==="GET"&&q.url==="/api/me"){let id=await uid(q);return send(r,200,{authenticated:!!id,teacher:id?await teacher(id):null})}
  if(q.method==="POST"&&q.url==="/api/signup"){if(!limited(q,"signup")||!csrf(q))return send(r,429,{error:"しばらく待ってから再試行してください"});let b=await body(q),e=String(b.email||"").trim().toLowerCase(),p=b.password;if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)||typeof p!=="string"||p.length<10)return send(r,400,{error:"メールまたはパスワードが不正です"});if((await pool.query("SELECT 1 FROM users WHERE email=$1",[e])).rowCount)return send(r,409,{error:"登録済みです"});let u=await pool.query("INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id",[e,hash(p)]),t=tok();await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",[th(t),u.rows[0].id]);return send(r,201,{ok:true},{"Set-Cookie":cookie(t,2592000)})}
  if(q.method==="POST"&&q.url==="/api/login"){if(!limited(q,"login")||!csrf(q))return send(r,429,{error:"しばらく待ってから再試行してください"});let b=await body(q),e=String(b.email||"").trim().toLowerCase(),u=await pool.query("SELECT * FROM users WHERE email=$1",[e]);if(!u.rowCount||typeof b.password!=="string"||!verify(b.password,u.rows[0].password_hash))return send(r,401,{error:"ログイン情報が正しくありません"});let t=tok();await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",[th(t),u.rows[0].id]);return send(r,200,{ok:true},{"Set-Cookie":cookie(t,2592000)})}
  if(q.method==="POST"&&q.url==="/api/logout"){if(!csrf(q))return send(r,403,{error:"CSRF検証に失敗しました"});let m=(q.headers.cookie||"").match(/(?:^|;\s*)ms_session=([^;]+)/);if(m)await pool.query("DELETE FROM sessions WHERE token_hash=$1",[th(m[1])]);return send(r,200,{ok:true},{"Set-Cookie":cookie("",0)})}
  if(q.method==="PUT"&&q.url==="/api/teacher"){let id=await uid(q);if(!id)return send(r,401,{error:"ログインが必要です"});if(!csrf(q))return send(r,403,{error:"CSRF検証に失敗しました"});let b=await body(q),t=b.teacher;if(!t||typeof t!=="object")return send(r,400,{error:"先生データが必要です"});t.name=String(t.name||"先生").slice(0,60);t.xp=Math.max(0,Math.min(Number(t.xp)||0,1000000));t.level=level(t.xp);t.dna=Array.isArray(t.dna)?t.dna.slice(0,30).map(x=>String(x).slice(0,50)):[];t.memory=Array.isArray(t.memory)?t.memory.slice(0,50):[];t.traits=t.traits&&typeof t.traits==="object"?t.traits:{};await pool.query(`INSERT INTO teachers(user_id,teacher_json) VALUES($1,$2::jsonb) ON CONFLICT(user_id) DO UPDATE SET teacher_json=EXCLUDED.teacher_json,updated_at=NOW()`,[id,JSON.stringify(t)]);return send(r,200,{teacher:t})}
  if(q.method==="POST"&&q.url==="/api/event"){let id=await uid(q);if(!id)return send(r,401,{error:"ログインが必要です"});if(!csrf(q))return send(r,403,{error:"CSRF検証に失敗しました"});let b=await body(q);await pool.query("INSERT INTO learning_events(user_id,type,payload_json) VALUES($1,$2,$3::jsonb)",[id,String(b.type||"event").slice(0,60),JSON.stringify(b.payload||{})]);return send(r,201,{ok:true})}
  if(q.method==="GET"&&q.url==="/api/history"){let id=await uid(q);if(!id)return send(r,401,{error:"ログインが必要です"});let x=await pool.query("SELECT type,payload_json,created_at FROM learning_events WHERE user_id=$1 ORDER BY id DESC LIMIT 50",[id]);return send(r,200,{events:x.rows})}
  if(q.method==="POST"&&q.url==="/api/conference"){let id=await uid(q);if(!id)return send(r,401,{error:"ログインが必要です"});if(!csrf(q))return send(r,403,{error:"CSRF検証に失敗しました"});let b=await body(q),topic=String(b.topic||"").slice(0,500),ts=[{name:"ソラ",field:"生物"},{name:"カイ",field:"法律"},{name:"ユウ",field:"医学"},{name:"ミナ",field:"数学"}],opinions=await aiConference(topic,ts);await pool.query("INSERT INTO learning_events(user_id,type,payload_json) VALUES($1,$2,$3::jsonb)",[id,"conference",JSON.stringify({topic,opinions})]);return send(r,200,{topic,opinions})}
  r.writeHead(404,{...sec,"Content-Type":"text/plain; charset=utf-8"});r.end("Not Found")
 }catch(e){console.error(e);send(r,500,{error:"サーバー内部エラー"})}
}
init().then(()=>http.createServer(main).listen(PORT,()=>console.log("MUSIC STUDY v22 listening on "+PORT))).catch(e=>{console.error(e);process.exit(1)});
process.on("SIGTERM",async()=>{await pool.end();process.exit(0)});
