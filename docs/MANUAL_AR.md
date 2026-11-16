<div dir="rtl">

# الدليل الفني الشامل لأداة SysDrift Auditor

**المؤلف والمطوّر:** أحمد أ. أحمد (Ahmed A. Ahmed) — الهوية المهنية: Mr. Deffult
**الإصدار:** 1.0.0 — **الرخصة:** MIT — **لغة البرمجة:** Python 3

---

## 1. مقدمة شاملة عن الأداة وفلسفة عملها في اكتشاف الانحراف الأمني

### 1.1 ما هو الانحراف الأمني (Configuration Drift)؟

الانحراف الأمني هو الفارق التدريجي أو المفاجئ بين **الحالة الآمنة المعتمدة** للنظام والحالة **الفعلية** التي يعمل بها الآن. ينشأ هذا الفارق لأسباب متعددة:

- تعديلات يدوية عاجلة لا تُوثَّق، أو أخطاء بشرية أثناء الصيانة.
- تحديثات الحزم التي تُغيّر الملفات الثنائية وإعدادات الخدمات.
- **اختراق فعلي**: يضيف المهاجم حساباً بصلاحيات الجذر، أو يزرع ملفاً ثنائياً بخاصية SUID، أو يُدخل مهمة cron للبقاء في النظام (Persistence)، أو يفتح الدخول المباشر للجذر عبر SSH.

الخطورة أن المهاجم الماهر لا يترك ضجيجاً؛ فهو يُجري **تغييرات صغيرة** في ملفات حساسة. ومن لا يملك نقطة مرجعية يقارن بها لن يلاحظ هذه التغييرات.

### 1.2 فلسفة التصميم

تقوم الأداة على أربعة مبادئ:

1. **الحالة المرجعية أولاً:** لا تحاول الأداة «تخمين» ما هو سليم، بل تقارن الحاضر بلقطة موثوقة التُقطت في وقت معلوم السلامة.
2. **الدقة لا الضجيج:** تحلّل الأداة المحتوى بنيوياً (حسابات `passwd`، توجيهات `sshd_config`، أسطر cron الفعّالة، قواعد `sudoers`) لتفرّق بين تعديل تعليق وتعديل يمنح صلاحية.
3. **أقل صلاحية وأقل اطلاع:** لا يُقرأ محتوى `/etc/shadow` إطلاقاً؛ يُسجَّل وجوده وصلاحياته ومالكه فقط.
4. **سلامة الأداة نفسها:** ملف الحالة المرجعية قد يكون هدفاً للمهاجم، لذلك يمكن توقيعه بـ **HMAC-SHA256** بمفتاح سري خارج الخادم.

### 1.3 ما الذي تفعله الأداة وما الذي لا تفعله

| تفعله | لا تفعله |
|---|---|
| كشف التغيّر عن الحالة المرجعية (كاشفة Detective) | منع الاختراق (ليست جداراً نارياً ولا IPS) |
| تصنيف النتائج بحسب الخطورة وتوصية الإصلاح | الحكم على نية التغيير (قد يكون تحديثاً مشروعاً) |
| العمل دون خدمات خلفية ودون اتصال بالشبكة | كشف الـ Rootkit على مستوى النواة |

---

## 2. أهمية مراقبة الحالة المرجعية (Golden Baseline) لمديري الأنظمة

الحالة المرجعية الذهبية هي لقطة موقَّعة وموثَّقة من الإعدادات الحرجة، تُؤخذ بعد التثبيت والتحصين مباشرة. أهميتها لمدير النظام:

1. **سرعة الكشف:** بدلاً من مراجعة آلاف الملفات يدوياً، يعرض التقرير الفروق فقط، مرتبة بالخطورة.
2. **الأدلة الجنائية:** تُثبت الأداة أن الملف تغيّر عن حالة معلومة، بتجزئة SHA-256 قبل/بعد.
3. **الامتثال والتدقيق:** تدعم متطلبات مراقبة سلامة الملفات (File Integrity Monitoring) في المعايير الأمنية مثل CIS وPCI-DSS.
4. **ضبط التغيير (Change Control):** أي فرق غير مبرَّر بتذكرة تغيير يُعامل كحادث محتمل.
5. **ثبات الأسطول:** مقارنة الخوادم المتماثلة بحالة موحّدة تكشف الخادم الشاذ.

**قاعدة ذهبية:** تُؤخذ اللقطة المرجعية فقط من نظام **موثوق السلامة**؛ لقطة تُؤخذ من نظام مخترق تُشرعن الاختراق.

---

## 3. المعمارية الهندسية وتصميم الموديولات البرمجية

### 3.1 هيكل المستودع

```text
sysdrift-auditor/
├── pyproject.toml            # بيانات الحزمة ونقطة الدخول sysdrift
├── requirements.txt          # PyYAML>=6.0.1 و cryptography>=42.0.0
├── README.md
├── LICENSE
├── docs/MANUAL_AR.md         # هذا الدليل
├── sysdrift/
│   ├── __init__.py           # الإصدار وهوية المؤلف
│   ├── __main__.py           # python -m sysdrift
│   ├── errors.py             # هرمية الاستثناءات
│   ├── utils.py              # التجزئة، فحص الملفات، مسح SUID، تحليل passwd
│   ├── sshd.py               # محلّل sshd_config مع Include وMatch
│   ├── baseline.py           # محرك الحالة المرجعية والتوقيع
│   ├── auditor.py            # محرك كشف الانحراف
│   ├── report.py             # مخرجات نصية وJSON وYAML
│   └── cli.py                # واجهة سطر الأوامر
└── tests/test_sysdrift.py    # 29 اختباراً آلياً
```

### 3.2 مخطط التدفق

```text
  sysdrift init                          sysdrift audit / report
       │                                         │
  ScanConfig ──► collect_state()          load_baseline() ──► التحقق من التوقيع
       │         (يلتقط الحالة)                  │                 │
       ▼                                         ▼                 ▼
  build_baseline() ──► توقيع HMAC        collect_state() (الحالة الحية)
       │                                         │
  save_baseline() (0600، كتابة ذرّية)            ▼
       │                                  Auditor.run() ── تحليل الفروق (Delta)
       ▼                                         │
   baseline.json                          build_report() ──► نص / JSON / YAML
```

### 3.3 تفصيل الموديولات

**`utils.py` — الأدوات القاعدية**
- `inspect_path()`: تجمع الوجود والنوع والصلاحيات (octal) والمالك وSHA-256. تُحسب التجزئة من البايتات نفسها التي حُلّل محتواها لتفادي التعارض بين التجزئة والمحتوى. الحالة `exists: None` تعني «تعذّر الفحص» (مثلاً لعدم الصلاحية) ولا تُعامل كحذف.
- `scan_suid_sgid()`: تمسح المسارات دون اتباع الروابط الرمزية وتستثني `/proc` و`/sys` و`/dev` و`/run` افتراضياً، وتسجل تجزئة كل ملف ثنائي.
- `parse_passwd()` و`parse_active_lines()`: تحليل الحسابات واستخراج الأسطر الفعّالة (مع معاملة `#include` و`#includedir` في sudoers كتوجيهات حيّة).

**`sshd.py` — محلّل إعدادات SSH**
يقرأ التوجيهات بصيغتي `Key value` و`Key=value`، ويتتبع `Include` (مع حماية من الحلقات وحد أقصى للعمق)، ويفصل كتل `Match` عن الإعدادات العامة. تُخزَّن القيم بترتيب ظهورها لأن sshd يعتمد «أول قيمة تنتصر».

**`baseline.py` — محرك الحالة المرجعية الذهبية**
- `ScanConfig`: يحدد الأهداف ويُحفظ داخل الملف المرجعي ليستخدمه التدقيق نفسه (فلا يمكن تدقيق أهداف مختلفة عن التي سُجّلت).
- `collect_state()`: يلتقط `passwd` و`group` و`shadow` (صلاحيات فقط) و`sudoers` و`sudoers.d` وإعدادات SSH ومهام cron وملفات SUID/SGID والملفات الإضافية.
- التوقيع: `HMAC-SHA256` عبر مكتبة `cryptography` عند توفّر مفتاح، وإلا `SHA-256` للكشف عن التلف فقط. يُرفض الملف غير الموقّع إن قُدّم مفتاح (منع هجوم الاستبدال/التخفيض)، وكذلك الموقّع دون مفتاح.
- `save_baseline()`: كتابة ذرّية (`os.replace`) بصلاحية `0600` ورفض الكتابة فوق ملف قائم دون `--force`.

**`auditor.py` — محرك كشف الانحراف**
يقارن الحالة المحمّلة بالحالة الحية وينتج كائنات `Finding` فيها: المعرّف والخطورة والفئة والمسار والتفاصيل وقيمتا «قبل/بعد» والتوصية.

| الفئة | قاعدة الكشف | الخطورة |
|---|---|---|
| `FILE_MODIFIED` | اختلاف SHA-256 | حرجة لـ passwd/shadow وإلا عالية |
| `SUID_ADDED` | ملف SUID/SGID جديد | حرجة |
| `SUID_MODIFIED` | تغيّر محتوى ملف SUID | حرجة |
| `PERMISSIONS_CHANGED` | تغيّر الصلاحيات/المالك | منخفضة إلى حرجة (قابل للكتابة من الجميع أو قراءة shadow للعامة = حرجة) |
| `INSECURE_PERMISSIONS` | صلاحيات غير آمنة حتى لو لم تتغير | حرجة/عالية |
| `ACCOUNT_ADDED` | حساب جديد | حرجة إن UID=0 |
| `ACCOUNT_MODIFIED` | تغيّر UID/shell/home | حتى حرجة |
| `SSH_SETTING_CHANGED` | تغيّر توجيه sshd | حرجة عند تفعيل `PermitRootLogin yes` أو `PermitEmptyPasswords yes` |
| `SSH_MATCH_BLOCK_CHANGED` | تغيّر كتل Match | عالية |
| `SUDOERS_RULE_ADDED` | قاعدة sudo جديدة | حرجة عند `NOPASSWD`/`ALL` |
| `CRON_JOB_ADDED` | مهمة cron فعّالة جديدة | عالية، وحرجة عند أنماط مشبوهة (`/dev/tcp`، `curl \| sh`، `base64 -d`…) |
| `CRON_FILE_MODIFIED` | تغيّر تعليقات فقط | منخفضة |

تفصيلات تحليلية:
- في **sshd** تُحسب القيمة الفعّالة مع القيم الافتراضية: حذف `PasswordAuthentication no` يعني رجوعاً إلى الافتراضي `yes` فيُعدّ إضعافاً.
- في **cron** تُقارن الأسطر الفعّالة وليس الملف كله، فتعديل تعليق لا يُنتج إنذاراً مرتفعاً.
- في **sudoers** يُعدّ تغيير الترتيب فرقاً لأن «آخر قاعدة مطابقة تنتصر».

**`report.py`** يولّد تقريراً نصياً ملوّناً أو JSON أو YAML.
**`cli.py`** يدير الأوامر ورموز الخروج.

---

## 4. دليل التثبيت والتشغيل خطوة بخطوة

### 4.1 المتطلبات
- لينكس، وPython 3.8 أو أحدث.
- صلاحيات الجذر للتغطية الكاملة (ملف `/etc/sudoers` مثلاً لا يُقرأ بدونها). عند التشغيل دون جذر تحذّر الأداة بأن النتائج ناقصة.

### 4.2 التثبيت

```bash
# 1) الحصول على المشروع وفك الضغط
tar -xzf sysdrift-auditor.tar.gz && cd sysdrift-auditor

# 2) بيئة معزولة (مستحسن)
python3 -m venv .venv && source .venv/bin/activate

# 3) التثبيت (ينشئ الأمر sysdrift)
pip install .

# أو دون تثبيت:
pip install -r requirements.txt
python3 -m sysdrift --version
```

### 4.3 الأوامر

**أ) توليد مفتاح التوقيع (مرة واحدة)**
```bash
sudo sysdrift keygen --output /root/sysdrift.key
```
يُنشأ مفتاح عشوائي (256 بت) بصلاحية `0600`. **احفظ نسخة منه خارج الخادم.**

**ب) إنشاء الحالة المرجعية**
```bash
sudo sysdrift init --output baseline.json --key-file /root/sysdrift.key
```
الخيارات: `--config ملف.yaml` لتخصيص الأهداف، `--force` للكتابة فوق ملف قائم، `--no-suid-scan` لتخطي مسح SUID البطيء، ويمكن إعطاء المفتاح عبر المتغير `SYSDRIFT_KEY`.

**ج) التدقيق**
```bash
sudo sysdrift audit --baseline baseline.json --key-file /root/sysdrift.key
```
الخيارات: `--format text|json|yaml`، `--output ملف`، `--min-severity`، `--fail-on` (الافتراضي `low`)، `--no-color`.

**د) التقرير المنظّم**
```bash
sudo sysdrift report --baseline baseline.json --key-file /root/sysdrift.key --format json
sudo sysdrift report -b baseline.json -k /root/sysdrift.key -f yaml -o report.yaml --min-severity high
```
الأمر `report` يخرج بالرمز 0 افتراضياً (إلا إن حُدد `--fail-on`).

### 4.4 رموز الخروج

| الرمز | المعنى |
|---|---|
| 0 | لا انحراف (أو الأمر نجح) |
| 1 | اكتُشف انحراف عند/فوق عتبة `--fail-on` |
| 2 | خطأ في الاستخدام أو التشغيل |
| 3 | فشل سلامة/توقيع الحالة المرجعية (يُعامل كحادث أمني) |

### 4.5 ملف التهيئة (اختياري)

```yaml
# scan.yaml
suid_roots: ["/"]
suid_exclude: ["/proc", "/sys", "/dev", "/run", "/var/lib/docker"]
extra_files:
  - /etc/pam.d/sshd
  - /etc/hosts
  - /root/.ssh/authorized_keys
```
```bash
sudo sysdrift init -o baseline.json -c scan.yaml -k /root/sysdrift.key
```
المفاتيح المسموحة: `passwd, group, shadow, sudoers, sudoers_dir, sshd_config, cron_files, cron_policy_files, cron_tab_dirs, cron_script_dirs, scan_suid, suid_roots, suid_exclude, extra_files`. أي مفتاح آخر يُرفض.

### 4.5 مثال توضيحي للمخرجات

```text
DRIFT DETECTED: 2 finding(s) - 1 critical, 1 high

[CRITICAL] SD-0001  SUID_ADDED
  Title : New SUID binary appeared
  Path  : /usr/local/bin/helper
  Detail: mode 4755 uid=0 gid=0 sha256=9f2c...
  Fix   : Identify the file's origin (dpkg -S / rpm -qf)...
```

### 4.6 الجدولة الدورية (systemd)

```ini
# /etc/systemd/system/sysdrift.service
[Unit]
Description=SysDrift Auditor drift check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sysdrift audit --baseline /var/lib/sysdrift/baseline.json --key-file /root/sysdrift.key --format json --output /var/log/sysdrift-last.json --fail-on high
```
```ini
# /etc/systemd/system/sysdrift.timer
[Unit]
Description=Run SysDrift hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now sysdrift.timer
```
تظهر حالة الفشل (رمز 1 أو 3) في `systemctl status` ويمكن ربطها بالتنبيه.

---

## 5. سيناريوهات الاستخدام العملي في تأمين السيرفرات واكتشاف الاختراقات الخفية

**السيناريو 1 — حساب جذر خفي.** يضيف المهاجم `toor:x:0:0::/root:/bin/bash` إلى `/etc/passwd`. تُصدر الأداة `ACCOUNT_ADDED` (حرجة) و`FILE_MODIFIED` (حرجة) وتُظهر اسم الحساب وقيمة UID.

**السيناريو 2 — زرع ملف SUID للبقاء.** نسخة من `bash` بخاصية SUID في `/tmp` أو `/usr/local/bin`. تكشفها `SUID_ADDED` لأن المسح يشمل كل الأقسام ما لم تُستثنَ.

**السيناريو 3 — استبدال ملف ثنائي شرعي.** استبدال `/usr/bin/passwd` بنسخة مفخخة مع بقاء SUID. تكشفه `SUID_MODIFIED`. وللتمييز عن تحديث مشروع: قارن بـ `dpkg -V` أو `rpm -V`، وبعد تأكيد المشروعية أعد `sysdrift init`.

**السيناريو 4 — إضعاف SSH.** تحويل `PermitRootLogin no` إلى `yes`، أو إضافة كتلة `Match Address` تسمح بكلمات المرور من نطاق معيّن. تظهر `SSH_SETTING_CHANGED` أو `SSH_MATCH_BLOCK_CHANGED` مع القيمة قبل وبعد.

**السيناريو 5 — الثبات عبر cron.** إضافة سطر `* * * * * root bash -i >& /dev/tcp/…` إلى `/etc/cron.d/`. تكشفه `CRON_JOB_ADDED` بخطورة حرجة نتيجة النمط المشبوه.

**السيناريو 6 — تصعيد عبر sudoers.** إسقاط ملف `/etc/sudoers.d/99-x` فيه `NOPASSWD: ALL`. تكشفه `SUDOERS_FILE_ADDED` (حرجة).

**السيناريو 7 — تسريب كلمات المرور المجزأة.** تغيير صلاحية `/etc/shadow` إلى `0644`. تصدر `PERMISSIONS_CHANGED` (حرجة)، دون قراءة محتوى الملف إطلاقاً.

**السيناريو 8 — العبث بالأداة نفسها.** إن عدّل المهاجم `baseline.json` ليُخفي أثره، يفشل التحقق ويخرج الأمر بالرمز 3 مع رسالة `INTEGRITY FAILURE`.

### 5.1 أفضل الممارسات التشغيلية

1. **خذ اللقطة بعد التحصين مباشرة** وعلى نظام موثوق.
2. **وقّع الحالة المرجعية** وخزّن المفتاح ونسخة من الملف المرجعي **خارج الخادم** (وسيط للقراءة فقط أو خادم إدارة).
3. **أعد إنشاء اللقطة** بعد كل تحديث أو تغيير معتمد، وسجّل ذلك في سجل التغييرات.
4. **شغّل التدقيق دورياً** واربط رمز الخروج بنظام التنبيه.
5. **اجمع التقارير بصيغة JSON** في نظام السجلات المركزي لمقارنة الأسطول.
6. **عند الإنذار الحرج**: اعزل الخادم، واحفظ التقرير والسجلات، ولا تُعد اللقطة قبل انتهاء التحقيق.

### 5.2 حدود الأداة (شفافية فنية)

- هي أداة **كشف** وليست منعاً؛ وتحتاج لمن يتابع نتائجها.
- مهاجم يملك صلاحية الجذر قد يعدّل الأداة أو البيئة نفسها؛ لذلك يلزم التوقيع والتخزين الخارجي وتشغيلها من وسط موثوق عند الشك.
- لا تكشف الـ Rootkits النواتية ولا ثغرات الذاكرة.
- المسح الكامل لـ SUID قد يستغرق وقتاً على الأقراص الكبيرة، ويمكن تضييقه بـ `suid_exclude`.
- تغيّر ملفات SUID بعد تحديث الحزم متوقع، وهو يظهر كفرق حتى تُعاد اللقطة.
- التحليل ثابت (ملفات) ولا يُنفّذ `sshd -T` ولا يقيّم دلالات sudoers الكاملة.

### 5.3 تشغيل الاختبارات

```bash
python3 -m unittest discover -s tests -v
```

---

**حقوق الملكية:** © 2026 أحمد أ. أحمد (Mr. Deffult) — مرخّص بموجب رخصة MIT.

</div>
