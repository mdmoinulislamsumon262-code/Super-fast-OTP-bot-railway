# Telegram Number + Temp Mail Bot — Railway Ready

এটি Python 3.11 এবং SQLite-ভিত্তিক Telegram bot। Railway-এ Docker দিয়ে deploy
করার জন্য `Dockerfile`, `run.sh` ও `/health` endpoint প্রস্তুত করা হয়েছে।

## Package-এ যা আছে

- `main.py`, `shop_integration.py`, `temp_mail_engine.py` — bot ও এর feature-গুলো
- `requirements.txt`, `Dockerfile`, `.python-version` — runtime/build configuration
- `run.sh`, `Procfile` — environment check ও start command
- `.env.example` — local setup-এর নমুনা; secret-এর আসল মান নয়
- `.gitignore`, `.dockerignore` — secret, database ও runtime data বাদ রাখে

## Railway-এ deploy

1. ZIP extract করে **সব ফাইল repository root-এ** রেখে একটি private GitHub
   repository-তে push করুন; `main.py` ও `Dockerfile` root-এ থাকতে হবে।
2. Railway dashboard-এ **New Project → Deploy from GitHub Repo** দিয়ে repository
   নির্বাচন করুন। Railway Dockerfile দেখে Python 3.11 image তৈরি করবে।
3. Production data রাখার জন্য service-এ Railway **Volume** যোগ করে mount path
   `/app/data` দিন. Volume-টি bot-কে প্রথমবার live চালানোর আগেই attach করুন।
4. Service Variables-এ `BOT_TOKEN` এবং সংখ্যাসূচক `ADMIN_ID` যোগ করুন। Railway
   volume mount হলে `RAILWAY_VOLUME_MOUNT_PATH` নিজে থেকেই পাওয়া যায়; চাইলে
   `DATA_DIR`-কে `/app/data`-এ সেট করুন। Secret GitHub বা chat-এ রাখবেন না।
5. Deployment চালু করে **Networking → Generate Domain** করুন। Health check-এর
   জন্য `/health` path-টি ব্যবহার করা হয়; app Railway-এর `PORT`-এ listen করে।
6. একই bot token-এর জন্য একটি active long-polling instance/replica-ই রাখুন।
   Deploy-এর পর Telegram-এ `/start` পাঠিয়ে পরীক্ষা করুন।

Botটি web page নয়; Railway-এর HTTP endpoint শুধু health check-এর জন্য।
Telegram updates long polling দিয়ে আসে। একই token দিয়ে আরেকটি bot process চালালে
Telegram polling conflict হতে পারে।

## Storage, cleanup ও data safety

- SQLite database এবং temporary-mail state `DATA_DIR`-এ থাকে. Railway Volume-টি
  app চালুর আগে mount না করলে container filesystem restart/redeploy-এ টিকে থাকার
  নিশ্চয়তা নেই।
- Temporary mailbox, তার credentials/seen-message state এবং delivery-ledger
  entry এক ঘণ্টা পর expire হয়। Interrupted backup/restore/temp files-ও এক ঘণ্টার
  বেশি পুরনো হলে cleanup হয়।
- Auto SMS-এর message body/phone payload আর নতুন করে ledger-এ রাখা হয় না;
  পুরনো payload এক ঘণ্টা পর scrub হয়। Restart-এর পর duplicate আটকানোর compact
  hash key সর্বোচ্চ সাত দিন রাখা হয়।
- User, balance, referrals, OTP history/search, allocations, withdrawals,
  product/order/shop/payment records এবং settings cleanup করে মুছে ফেলা হয় না;
  এগুলো feature-গুলোর স্থায়ী data। তাই কোনো storage capacity-ই অনির্দিষ্টকাল
  full হবে না—এমন নিশ্চয়তা দেওয়া যায় না। Railway Volume-এর ব্যবহার monitor
  করুন এবং Admin Backup দিয়ে প্রয়োজনীয় backup নিন।
- `/start` data reset করে না। `DATA_DIR` বদলালে নতুন database তৈরি হতে পারে।
  একই directory-তে পুরনো `voltx.db` থাকলে startup-এ বর্তমান database-এ migrate
  হবে; পুরনো database অন্য path-এ থাকলে আগে backup/restore করুন।

## Features

- Number/OTP allocation ও multiple SMS-panel integration; admin panel থেকে API
  key, enable/disable, range/access settings পরিচালনা
- OTP polling, user delivery, duplicate suppression, timeout, history/search,
  wallet/earnings, referral, withdrawal request ও force-join
- Auto SMS forwarding, demo SMS controls, admin monitoring এবং manual backup/
  restore
- Shop menu, products, coupons/offers, cart/order/delivery, top-up, balance,
  transaction history এবং shop admin controls
- Temporary mail creation, background inbox polling, one-hour mailbox expiry
  ও OTP-only notification

Shop ও bot data একই SQLite database-এ থাকে। Manual database backup-এ Main bot ও
Shop-এর durable records অন্তর্ভুক্ত হয়। Admin panel-এ দেওয়া API key এবং IMAP
password database-এ AES-GCM দিয়ে encrypted থাকে; temporary mailbox-এর token ও
password-ও state file-এ encrypted থাকে। `BOT_DATA_ENCRYPTION_KEY` স্থায়ীভাবে
সেট করা ভালো; না থাকলে `BOT_TOKEN` থেকে encryption key তৈরি হয়। Encryption key
হারালে বা বদলালে পুরোনো encrypted value খোলা যাবে না। স্বয়ংক্রিয় key rotation
নেই, তাই key অপরিবর্তিত রাখুন এবং database backup-এর বাইরে নিরাপদে সংরক্ষণ করুন।
API provider-এর key admin panel-এ দেওয়ার সময়ও শুধু প্রয়োজনীয় provider-এর key
ব্যবহার করুন।

SMShadi ও Lamix endpoint default-ভাবে বন্ধ। Railway Variables-এ তাদের HTTPS URL
না দিলে, বা HTTP URL দিলে, bot credential পাঠাবে না। HTTP endpoint-এ key পাঠানো
নিরাপদ নয়।

## Temp Mail

একাধিক public provider ও admin-configured IMAP domain-এ fallback করে; নতুন
mailbox-এ প্রথম তিন মিনিট ৫ সেকেন্ড পরপর poll হয়, পরে ১০ সেকেন্ড পরপর। এক cycle-এ
সর্বোচ্চ ১০টি mailbox batch হয় এবং provider-এ একসঙ্গে সর্বোচ্চ ৫টি check চলে।
সর্বোচ্চ ৫০০টি active mailbox রাখা হয়; একটি inbox-এ প্রতি check-এ সর্বোচ্চ ২০টি
message, HTTP provider-এর প্রতি response সর্বোচ্চ ২ MiB এবং IMAP-এ সর্বোচ্চ ১০টি
message-এর ১২৮ KiB করে পড়া হয়। এর বেশি response হলে সেই provider check বাতিল
হয়। Mail body HTML থেকে text করে OTP খোঁজা হয় এবং একই message ID আবার deliver
হয় না। Mailbox এক ঘণ্টা পরে expire হয়; notification-এ sender/subject/body না
দেখিয়ে কেবল code দেখানো হয়।

## RAM ও concurrent কাজ

- Telegram message handler ২টি worker thread-এ সীমিত।
- Temporary Mail-এর active mailbox ও প্রতিটি provider response-এর message/body
  সীমাবদ্ধ; পূর্ণ user list একসঙ্গে memory-তে না তুলে broadcast ব্যাচে চলে এবং
  admin export অস্থায়ী ফাইলে stream হয়।
- SMS-panel API JSON response সর্বোচ্চ ২ MiB; OTP response থেকে সর্বোচ্চ ১,০০০টি
  record process হয়। SMShadi/Lamix polling ৮টি shared worker ব্যবহার করে এবং
  একবারে সর্বোচ্চ ২০টি allocation-এর chunk জমা দেয়।
- Shop-এর Mail OTP auto-refresh প্রতি user-এর জন্য আলাদা thread না খুলে ৪টি
  shared worker ব্যবহার করে। একসঙ্গে সর্বোচ্চ ৩২টি auto-refresh session চলে;
  সীমা পূর্ণ হলে ওই session-এর **এখনই চেক করুন** বোতাম ব্যবহার করা যাবে।
- Shop UI/session state, Main user/admin input state ও Get Code Center-এর
  অস্থায়ী credential state এক ঘণ্টা inactivity-এর পর expire হয়। এতে users,
  balances, OTP history, products, orders বা transactions মুছে যায় না।
- বেশি concurrent user থাকলে polling queue-তে অপেক্ষার কারণে OTP check কিছুটা
  দেরি হতে পারে। Railway-এর memory graph দেখে প্রয়োজন হলে worker/batch limit
  বাড়ান; ছোট RAM plan-এ হঠাৎ অনেক worker বাড়াবেন না।

## ZebraSMS

ZebraSMS number allocation, OTP update ও live-range check-এর জন্য documented
API path ব্যবহার করে:

| কাজ | Endpoint |
|---|---|
| Number নেওয়া | `POST /api/v1/publicapi/getnum` — `MAuth` header, `{"range":"RANGE"}` body |
| OTP update | `GET /api/v1/publicapi/getupdate` — `MAuth` header |
| Live ranges | `GET /api/v1/publicapi/liveaccess` — `MAuth` header |

Admin Panel → Settings → API Management → **ZebraSMS** থেকে key ও status
পরিচালনা করুন। Auto SMS চালাতে bot-কে target group/channel-এ প্রয়োজনীয় admin
permission দিন এবং numeric chat ID সেট করুন।

## Security / troubleshooting

- `BOT_TOKEN`, panel API key বা real `.env` কখনো GitHub/public chat-এ দেবেন না।
- `BOT_TOKEN`/`ADMIN_ID` Railway **Variables**-এ রাখুন; repository private রাখুন।
- `BOT_DATA_ENCRYPTION_KEY` Railway **Variables**-এ স্থায়ী secret হিসেবে দিন।
  সেট না থাকলে `BOT_TOKEN` key source হিসেবে ব্যবহার হবে; BOT_TOKEN বদলালে
  encrypted data খোলা যাবে না। পুরোনো deployment-এর জন্য
  `IMAP_DATA_ENCRYPTION_KEY` compatibility fallback হিসেবে পড়া হয়।
- `SMSHADI_URL` ও `LAMIX_URL` দিলে শুধু HTTPS URL ব্যবহার করুন। HTTP endpoint
  ইচ্ছাকৃতভাবে block করা হয়।
- Restart/crash হলে Railway deployment logs-এর প্রথম traceback দেখুন। Logs
  কাউকে পাঠানোর আগে token ও API key মুছে দিন।
- Railway Volume-এর mount path যেন `DATA_DIR`-এর সঙ্গে মেলে তা যাচাই করুন।
- Long polling-এ একই token-এর জন্য একটি service/replica রাখুন; পুরনো server-এ
  একই bot চালু থাকলে সেটি বন্ধ করুন।
