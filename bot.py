import asyncio,requests,time,uuid,random,threading,os
from hashlib import md5
from telethon import TelegramClient,events,Button
from concurrent.futures import ThreadPoolExecutor
API_ID='6'
API_HASH='eb06d4abfb49dc3eeb1aeb98ae0f581e'
BOT_TOKEN='8212390051:AAHSarI_2mYnekOVIGkKgIv50kH2An2h0IY'
ADMIN_ID=1725301348
usr_sts,usr_dt,act_tsk={},{},{}
bot_set={'cnt_lnk':"https://t.me/HloSpidey",'chn_lnk':"https://t.me/YourChannel"}
exctr=ThreadPoolExecutor(max_workers=10)
lck=threading.Lock()
clnt=TelegramClient('spd_bot',API_ID,API_HASH).start(bot_token=BOT_TOKEN)
print("Bot Is Running... 🕸️")
def _lgn_snc(usr,pas):
 try:
  s=requests.Session()
  cstkn=''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',k=32))
  cks={'csrftoken':cstkn,'ig_did':str(uuid.uuid4()).upper(),'mid':str(uuid.uuid4()).upper().replace("-","")[:26]}
  hdrs={'authority':'www.instagram.com','accept':'*/*','accept-language':'en-US,en;q=0.9','content-type':'application/x-www-form-urlencoded','origin':'https://www.instagram.com','referer':'https://www.instagram.com/','user-agent':'Mozilla/5.0 (Linux; Android 14; SM-A235F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36','x-csrftoken':cstkn,'x-ig-app-id':'1217981644879628','x-ig-www-claim':'0','x-requested-with':'XMLHttpRequest'}
  dt={'username':usr,'enc_password':f'#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{pas}','queryParams':'{}','optIntoOneTap':'false','stopDeletionNonce':'','trustedDeviceRecords':'{}'}
  rsp=s.post('https://www.instagram.com/api/v1/web/accounts/login/ajax/',cookies=cks,headers=hdrs,data=dt,timeout=30)
  rs=rsp.json()
  if rs.get("authenticated"):s_id=rsp.cookies.get("sessionid");u_id=rs.get("userId")
  if s_id and u_id:return s_id,u_id
  return None,None
 except:return None,None

def get_flw_snc(s_id,u_id):
 try:
  s=requests.Session()
  s.cookies.set("sessionid",s_id)
  cstkn=md5(str(time.time()).encode()).hexdigest()
  s.cookies.set("csrftoken",cstkn)
  hdrs={'user-agent':'Instagram 155.0.0.37.107 Android','x-csrftoken':cstkn,'x-ig-app-id':'936619743392459','cookie':f'sessionid={s_id}; csrftoken={cstkn}'}
  mx_id,flws="",[]
  while True:
   url=f"https://i.instagram.com/api/v1/friendships/{u_id}/following/?count=100"
   if mx_id:url+=f"&max_id={mx_id}"
   rs=s.get(url,headers=hdrs,timeout=30)
   if rs.status_code!=200:break
   js=rs.json()
   if'users'in js:flws.extend(js.get("users",[]))
   else:break
   mx_id=js.get("next_max_id")
   if not mx_id:break
  return len(flws),flws
 except:return 0,[]

def unflw_usr_snc(uid,usid,sid):
 try:
  s=requests.Session()
  s.cookies.set("sessionid",sid)
  cstkn=md5(str(time.time()).encode()).hexdigest()
  s.cookies.set("csrftoken",cstkn)
  hdrs={'user-agent':'Instagram 155.0.0.37.107 Android','x-csrftoken':cstkn,'x-ig-app-id':'936619743392459'}
  for _ in range(3):
   rsp=s.post(f"https://www.instagram.com/api/v1/friendships/destroy/{uid}/",headers=hdrs)
   if rsp.status_code==200:return rsp
   time.sleep(1)
  return rsp
 except:return type('obj',(object,),{'status_code':500})()

@clnt.on(events.NewMessage(pattern='/start'))
async def str_hnd(evt):
 uid=evt.sender_id
 with lck:usr_sts[uid]=None
 btns=[[Button.url("🕸️ Contact Me",bot_set['cnt_lnk']),Button.url("Channel 🕸️",bot_set['chn_lnk'])],[Button.inline("🚀 Unfollow",b"unfollow"),Button.inline("🔑 Get Session",b"session")]]
 wlc_txt="""**I'm Unfollow Bot, By @HloSpidey** 🕷️

✨ **Features:**
• Auto Unfollow Instagram
• Session Extractor  
• Safe & Secure

**Use Buttons Below To Start :**"""
 img_urls=["https://raw.githubusercontent.com/HloSpidey/Insta-Acc-Creater/refs/heads/main/IMG_20251118_215835_364.jpg"]
 for img in img_urls:
  try:await evt.reply(wlc_txt,file=img,buttons=btns,parse_mode='md');return
  except:continue
 await evt.reply(wlc_txt,buttons=btns,parse_mode='md')

@clnt.on(events.NewMessage(pattern='/stop'))
async def stp_hnd(evt):
 uid=evt.sender_id
 with lck:
  if uid in usr_sts:
   usr_sts[uid]=None
   if uid in usr_dt:del usr_dt[uid]
   if uid in act_tsk:act_tsk[uid].cancel();del act_tsk[uid]
   await evt.reply("✅ Process Stopped Successfully")
  else:await evt.reply("❌ No Active Process Found")

@clnt.on(events.NewMessage(pattern='/addlink'))
async def addlnk_hnd(evt):
 uid=evt.sender_id
 if uid!=ADMIN_ID:await evt.reply("❌ This Command Is For Admin Only");return
 with lck:usr_sts[uid]="awaiting_contact_link"
 await evt.reply("📝 Send Contact Button Link")

@clnt.on(events.NewMessage(pattern='/unfollow'))
async def unflw_hnd(evt):
 uid=evt.sender_id
 with lck:
  if uid in usr_sts and usr_sts[uid]!=None:await evt.reply("❌ You Already Have An Active Process. Use /stop First.");return
  usr_sts[uid]="awaiting_username"
 await evt.reply("👤 Send Your Insta Username Without @")

@clnt.on(events.NewMessage(pattern='/session'))
async def ssn_hnd(evt):
 uid=evt.sender_id
 with lck:
  if uid in usr_sts and usr_sts[uid]!=None:await evt.reply("❌ You Already Have An Active Process. Use /stop First.");return
  usr_sts[uid]="awaiting_session_username"
 await evt.reply("👤 Send Your Insta Username For Session")

@clnt.on(events.CallbackQuery)
async def clbk_hnd(evt):
 uid=evt.sender_id
 dt=evt.data.decode('utf-8')
 with lck:
  if uid in usr_sts and usr_sts[uid]!=None:await evt.edit("❌ You already have an active process. Use /stop first.");return
 if dt=="unfollow":
  with lck:usr_sts[uid]="awaiting_username"
  await evt.edit("👤 Send Your Insta Username Without @")
 elif dt=="session":
  with lck:usr_sts[uid]="awaiting_session_username"
  await evt.edit("👤 Send Your Insta Username For Session")

@clnt.on(events.NewMessage)
async def msg_hnd(evt):
 uid=evt.sender_id
 msg_txt=evt.text
 if msg_txt.startswith('/'):return
 with lck:cur_sts=usr_sts.get(uid)
 if not cur_sts:return
 
 if cur_sts=="awaiting_contact_link" and uid==ADMIN_ID:
  if msg_txt.startswith("https://"):
   bot_set['cnt_lnk']=msg_txt
   with lck:usr_sts[uid]="awaiting_channel_link"
   await evt.reply("✅ Contact Link Updated\n📝 Now Send Channel Button Link")
  else:await evt.reply("❌ Invalid Link Format")
  return
 
 elif cur_sts=="awaiting_channel_link" and uid==ADMIN_ID:
  if msg_txt.startswith("https://"):
   bot_set['chn_lnk']=msg_txt
   with lck:usr_sts[uid]=None
   await evt.reply("✅ Channel Link Updated\n✅ Both Links Have Been Updated Successfully")
  else:await evt.reply("❌ Invalid Link Format")
  return
 
 elif cur_sts=="awaiting_username":
  usr=msg_txt.replace('@','').strip()
  if not usr:await evt.reply("❌ Enter a Valid Username");return
  with lck:usr_dt[uid]={'username':usr};usr_sts[uid]="awaiting_password"
  await evt.reply("🔑 Send Your Insta Password")
  return
 
 elif cur_sts=="awaiting_session_username":
  usr=msg_txt.replace('@','').strip()
  if not usr:await evt.reply("❌ Enter a Valid Username");return
  with lck:usr_dt[uid]={'username':usr};usr_sts[uid]="awaiting_session_password"
  await evt.reply("🔑 Send Your Insta Password For Session")
  return
 
 elif cur_sts=="awaiting_password":
  pas=msg_txt
  if not pas:await evt.reply("❌ Enter Your Password");return
  with lck:
   if uid not in usr_dt:await evt.reply("❌ Session Expired. Start again.");usr_sts[uid]=None;return
   usr=usr_dt[uid]['username']
  prc_msg=await evt.reply("⏳ Extracting Session...")
  loop=asyncio.get_event_loop()
  s_id,u_id=await loop.run_in_executor(exctr,_lgn_snc,usr,pas)
  await prc_msg.delete()
  if s_id and u_id:
   await evt.reply(f"`{s_id}`")
   await asyncio.sleep(1)
   ext_msg=await evt.reply("⏳ Fetching following list...")
   flw_cnt,flws=await loop.run_in_executor(exctr,get_flw_snc,s_id,u_id)
   await ext_msg.delete()
   with lck:usr_dt[uid].update({'session_id':s_id,'user_id_ig':u_id,'unfollow_count':0,'following_count':flw_cnt,'followings':flws})
   sts_txt=f"✅ Login Successfully\n👤 User: @{usr}\n\n📊 Following List: {flw_cnt}\n\n➤ Unfollow Done: 0"
   sts_msg=await evt.reply(sts_txt)
   with lck:usr_dt[uid]['status_msg']=sts_msg
   tsk=asyncio.create_task(unflw_prc(uid,sts_msg))
   with lck:act_tsk[uid]=tsk
  else:
   await evt.reply("❌ Login Failed! Check Your Credentials And Try Again.")
   with lck:usr_sts[uid]=None
   if uid in usr_dt:del usr_dt[uid]
  return
 
 elif cur_sts=="awaiting_session_password":
  pas=msg_txt
  if not pas:await evt.reply("❌ Enter Your Password");return
  with lck:
   if uid not in usr_dt:await evt.reply("❌ Session Expired. Start Again.");usr_sts[uid]=None;return
   usr=usr_dt[uid]['username']
  prc_msg=await evt.reply("⏳ Extracting Session...")
  loop=asyncio.get_event_loop()
  s_id,u_id=await loop.run_in_executor(exctr,_lgn_snc,usr,pas)
  await prc_msg.delete()
  if s_id and u_id:
   await evt.reply(f"`{s_id}`")
   await evt.reply("✅ Session Extracted Successfully")
  else:await evt.reply("❌ Login Failed! Check Your Credentials And Try Again.")
  with lck:usr_sts[uid]=None
  if uid in usr_dt:del usr_dt[uid]
  return

async def unflw_prc(uid,sts_msg):
 try:
  with lck:
   if uid not in usr_dt:return
   s_id=usr_dt[uid]['session_id'];u_id=usr_dt[uid]['user_id_ig'];usr=usr_dt[uid]['username']
   flws=usr_dt[uid]['followings'];unflw_cnt=usr_dt[uid]['unfollow_count']
  cns_unflw,stp_pt=0,random.randint(15,20)
  for usr_flw in flws[unflw_cnt:]:
   with lck:
    if uid not in usr_sts or usr_sts[uid]==None:break
   uid_flw=usr_flw["pk"]
   loop=asyncio.get_event_loop()
   rsp=await loop.run_in_executor(exctr,unflw_usr_snc,uid_flw,u_id,s_id)
   if rsp.status_code==200:
    with lck:
     if uid not in usr_dt:break
     unflw_cnt+=1;cns_unflw+=1;usr_dt[uid]['unfollow_count']=unflw_cnt
    rem_flw=usr_dt[uid]['following_count']-unflw_cnt
    sts_txt=f"✅ Login Successfully\n👤 User: @{usr}\n\n📊 Following List: {rem_flw}\n\n➤ Unfollow Done: {unflw_cnt}"
    try:await sts_msg.edit(sts_txt)
    except:pass
    if cns_unflw>=random.randint(2,4):
     await asyncio.sleep(random.uniform(1.5,2.9));cns_unflw=0
    elif unflw_cnt%random.randint(5,7)==0 and unflw_cnt>0:
     await asyncio.sleep(random.uniform(5.0,8.0))
    else:await asyncio.sleep(random.uniform(1.0,2.5))
   elif rsp.status_code==400:
    rem_flw=usr_dt[uid]['following_count']-unflw_cnt
    fin_txt=f"✅ Login Successfully\n🟢 Unfollow Process Stopped For Safety\n⏰ Wait 1 Minute And Then Try Again\n\n👤 User: @{usr}\n\n📊 Following List: {rem_flw}\n\n➤ Unfollow Done: {unflw_cnt}"
    try:await sts_msg.edit(fin_txt)
    except:pass
    err_msg="Insta Ne Detect Karliya, Ja Ke Apni ID Dubara Login Kar And /unfollow Command Use Kar\n\n(Bulk Unfollow Matt Karna ID Pe Limit Lag Jati Hai So 1 Din Mein Kuch Kuch Ghante Baad 40-50 Unfollow Karte Rehna)"
    await sts_msg.reply(err_msg)
    break
   else:
    rem_flw=usr_dt[uid]['following_count']-unflw_cnt
    fin_txt=f"✅ Login Successfully\n🟢 Unfollow Process Stopped For Safety\n⏰ Wait 1 Minute And Then Try Again\n\n👤 User: @{usr}\n\n📊 Following List: {rem_flw}\n\n➤ Unfollow Done: {unflw_cnt}"
    try:await sts_msg.edit(fin_txt)
    except:pass
    await asyncio.sleep(random.uniform(2.0,4.0))
   if unflw_cnt>=stp_pt:
    rem_flw=usr_dt[uid]['following_count']-unflw_cnt
    fin_txt=f"✅ Login Successfully\n🟢 Unfollow Process Stopped For Safety\n⏰ Wait 1 Minute And Then Try Again\n\n👤 User: @{usr}\n\n📊 Following List: {rem_flw}\n\n➤ Unfollow Done: {unflw_cnt}"
    try:await sts_msg.edit(fin_txt)
    except:pass
    break
  with lck:
   if uid in usr_sts:usr_sts[uid]=None
   if uid in usr_dt:del usr_dt[uid]
   if uid in act_tsk:del act_tsk[uid]
 except asyncio.CancelledError:pass
 except Exception as e:
  with lck:
   if uid in usr_sts:usr_sts[uid]=None
   if uid in usr_dt:del usr_dt[uid]
   if uid in act_tsk:del act_tsk[uid]

if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def home():
        return "Bot Is Running 🕸️"
    
    def run_flask():
        app.run(host='0.0.0.0', port=8080)
    
    import threading
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    print("Bot Is Running... 🕸️")
    clnt.run_until_disconnected()
