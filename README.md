# Cisco Port Mapper

> **Overview (English)**
>
> A Windows desktop tool that answers *"which switch and which port is this device on?"* using **SSH only** (no SNMP). It reads `show interfaces status`, `show interfaces switchport`, `show interfaces trunk`, CDP/LLDP neighbours, the MAC address table and ARP from every selected Cisco switch, then correlates them into one row per port.
>
> It also actively discovers **IP cameras** and **PCs/hosts** on the LAN, resolves their MAC addresses and matches those against the collected switch tables. Tabs: **Ports**, **Cameras**, **PCs / Hosts**.
>
> Every match has a **Port status** — `Confirmed`, `Probable`, `Candidates` or `Unknown` — and a human-readable **Port reason**. When data is ambiguous the switch/port fields are deliberately left empty; the tool never guesses a port.
>
> Filters (text + status), double-click detail windows, CSV export and a pure-standard-library XLSX writer are included. No Python packages are needed: SSH is delegated to `plink.exe` or the Windows OpenSSH client.
>
> Run `py -3 selftest.py` for the offline unit tests and `py -3 regression.py` to replay captured switch transcripts.
>
> **Security note:** the real switch inventory (`inventory.json`), captured transcripts (`raw_*.txt`), the downloaded `plink.exe` and an optional full `oui.csv` are intentionally **not** in this repository. Copy `inventory.example.json` to `inventory.json` and add your own devices. The full Persian documentation follows below.

برنامه‌ی ویندوزی برای بررسی سوییچ‌های سیسکو از طریق **SSH** (بدون SNMP).
برای هر اینترفیس نشان می‌دهد چه دستگاهی وصل است: نام دستگاه، IP، پلتفرم، پورت مقابل،
VLAN، سرعت و MACهای یادگرفته‌شده.

همچنین می‌تواند **دوربین‌های تحت شبکه** را با IP و MAC در شبکه پیدا کند و MAC آن‌ها
را با جدول MAC سوییچ‌ها تطبیق دهد تا مشخص شود هر دوربین روی **کدام پورت کدام
سوییچ** و در کدام VLAN وصل است (تب **Cameras**).

همین کار برای **کامپیوترها و بقیه‌ی دستگاه‌های شبکه** هم انجام می‌شود: IP و MAC
با اسکن شبکه پیدا می‌شود، در صورت امکان نام سیستم (DNS/NetBIOS/mDNS) خوانده
می‌شود و پورت سوییچ گزارش می‌شود (تب **PCs / Hosts**).

رابط کاربری بازطراحی شده است: هدر تیره با نشانگر وضعیت SSH، نوار ابزار کارتی،
جدول‌های راه‌راه، تم روشن و پنجره‌های جزئیات هماهنگ. در هر دو تب **Cameras** و
**PCs / Hosts** یک تیک مشترک **Only devices on the scanned switch** وجود دارد
که دستگاه‌های یادگرفته‌شده از پورت uplink/trunk (یعنی دستگاه‌های سوییچ‌های
دیگر) را پنهان می‌کند.

![نوع برنامه](https://img.shields.io/badge/Windows-10%2F11-blue) ![Python](https://img.shields.io/badge/Python-3.9%2B-green) ![Dependencies](https://img.shields.io/badge/pip%20packages-none-brightgreen)

> **هیچ پکیج پایتونی لازم نیست.** نه `paramiko`، نه `pip install`. برنامه از
> `plink.exe` (همراه PuTTY) یا `ssh.exe` خود ویندوز برای اتصال SSH استفاده می‌کند.

## چه چیزی جمع‌آوری می‌کند؟

از خود سوییچ این دستورها گرفته می‌شود:

| دستور | کاربرد |
|---|---|
| `show version` | نام سوییچ |
| `show interfaces status` | وضعیت، VLAN، سرعت و description هر پورت |
| `show interfaces switchport` | mode واقعی access/trunk، access/native VLAN و VLANهای مجاز |
| `show interfaces trunk` | وضعیت واقعی trunk، native VLAN و VLANهای فعال/forwarding |
| `show cdp neighbors detail` | دستگاه‌های سیسکو، تلفن IP، سوییچ‌های مجاور |
| `show lldp neighbors detail` | سرورها، APها و تجهیزات غیرسیسکو |
| `show mac address-table` | MAC یادگرفته‌شده روی هر پورت (fallback) |
| `show ip arp` | تبدیل MAC به IP |

اولویت تشخیص:

1. **CDP** (دقیق‌ترین: نام، IP، پلتفرم، پورت مقابل)
2. **LLDP** اگر CDP اطلاعاتی نداشت
3. **جدول MAC + ARP** اگر هیچ‌کدام فعال نبودند (در این حالت فقط MAC و حدس سازنده از روی OUI داریم)

اگر نسخه‌ی IOS در خروجی `show lldp neighbors detail` خط `Local Intf` را ننویسد،
برنامه همسایه‌ی LLDP را از روی **MAC موجود در Chassis id** با پورت متناظر در
جدول MAC تطبیق می‌دهد؛ بنابراین نام دستگاه‌های غیرسیسکو (AP، تلفن، سرور) هم
تا حد امکان نمایش داده می‌شود.

پورت‌هایی که بیش از ۳ MAC دارند و همسایه‌ی CDP/LLDP ندارند به‌صورت
`Unmanaged switch / AP?` علامت می‌خورند.

## وضعیت پورت و دلیل (بدون حدس)

برای هر دستگاه یک ستون **Port status** و یک ستون **Port reason** نمایش داده می‌شود:

| وضعیت | معنی |
|---|---|
| `Confirmed` | MAC روی یک پورت access یاد گرفته شده، پورت up است و تنها MAC آن پورت است |
| `Probable` | یک کاندید access وجود دارد، ولی چند MAC روی پورت است، وضعیت پورت نامعلوم/down است، یا تطبیق فقط از روی IP انجام شده |
| `Candidates` | چند پورت access یا فقط پورت uplink/trunk پیدا شده؛ برنامه هیچ پورتی را ادعا نمی‌کند و کاندیدها را نشان می‌دهد |
| `Unknown` | MAC پیدا نشد یا داده کافی نیست |

در حالت‌های `Candidates` و `Unknown` ستون‌های Switch/Port **خالی** می‌مانند و
برنامه حدس نمی‌زند. دلیل کامل و لیست کاندیدها در پنجره‌ی جزئیات (دابل‌کلیک روی ردیف) دیده می‌شود.

## پیش‌نیازها

- ویندوز ۱۰ یا ۱۱
- Python 3.9 یا بالاتر — **لازم نیست دستی نصب شود**؛ `run.bat` در صورت نبود،
  خودش Python را با `winget` نصب می‌کند.
- **یکی** از این دو کلاینت SSH — برنامه در اولین اجرا خودش پیشنهاد نصب می‌دهد:
  - **`plink.exe` از PuTTY** — پیشنهادی، چون ورود با پسورد را پشتیبانی می‌کند.
  - **OpenSSH Client ویندوز** — رایگان و داخلی، ولی فقط با کلید/`ssh-agent` کار می‌کند (بدون پسورد).
- دسترسی SSH به سوییچ‌ها (کاربری با اجازه‌ی اجرای `show`؛ برای `terminal length 0` بهتر است سطح enable داشته باشید)

## آماده‌سازی کلاینت SSH

برنامه در اولین اجرا بررسی می‌کند که کلاینت SSH وجود دارد یا نه. اگر نبود،
یک پیام نمایش می‌دهد و با تأیید شما **آخرین نسخه‌ی رسمی `plink.exe` را از
putty.org دانلود و کنار برنامه ذخیره می‌کند** (بدون نیاز به Administrator).
همین کار از دکمه‌ی **Setup...** در بالای پنجره و از نوار زرد هشدار هم انجام
می‌شود. اگر دانلود ممکن نبود، روش دستی زیر هم کار می‌کند.

### روش ۱ (پیشنهادی): plink.exe از PuTTY

1. ساده‌ترین راه: در پنجره‌ی برنامه **Setup...** را بزنید و
   **Download plink.exe automatically** را انتخاب کنید. فایل کنار برنامه
   ذخیره می‌شود و از همان لحظه استفاده می‌شود.
2. اگر می‌خواهید دستی انجام دهید: PuTTY را از <https://www.putty.org/> دانلود
   و نصب کنید (نسخه‌ی 64-bit) و `plink.exe` را از پوشه‌ی نصب کنار `app.py`
   کپی کنید.
3. برنامه خودش `plink.exe` را در این مسیرها پیدا می‌کند:

   ```
   همین پوشه‌ی برنامه
   PATH ویندوز
   %LOCALAPPDATA%\Programs\PuTTY
   C:\Program Files\PuTTY
   C:\Program Files (x86)\PuTTY
   ```

نصب/بررسی از خط فرمان هم ممکن است:

```bat
python prereq.py --check
python prereq.py --install-plink
python prereq.py --install-openssh
```

`--install-openssh` به دسترسی Administrator نیاز دارد و همان قابلیت اختیاری
ویندوز را فعال می‌کند.

اولین اتصال به هر سوییچ، کلید هاست را به‌صورت خودکار می‌پذیرد: برنامه
fingerprint را از خروجی خود `plink` می‌خواند و از آن به بعد با `-hostkey` وصل
می‌شود، بنابراین هیچ پرسش تعاملی پیش نمی‌آید و اسکن کند نمی‌شود.
(پرسش `Store key in cache?` در plink وقتی ورودی از pipe می‌آید از stdin خوانده
نمی‌شود؛ برای همین از `-hostkey` استفاده می‌کنیم.)

اگر باز هم خطای `host key` دیدید، یک‌بار در Command Prompt دستی اجرا کنید و
`y` بزنید:

```bat
plink -ssh admin@192.168.1.10
```

#### سوییچ‌های قدیمی و الگوریتم ضعیف SSH

بعضی سوییچ‌های قدیمی Cisco فقط `diffie-hellman-group1-sha1` را پیشنهاد
می‌دهند. PuTTY این الگوریتم را «زیر خط هشدار» می‌داند و در حالت `-batch` اتصال
را قطع می‌کند:

```text
The first key-exchange algorithm supported by the server is
diffie-hellman-group1-sha1, which is below the configured warning threshold.
```

برنامه این حالت را خودکار تشخیص می‌دهد: یک Session خصوصی در رجیستری ویندوز با
نام `CiscoPortMapper` می‌سازد که فقط مقدار `KEX` را دارد (الگوریتم ضعیف بالاتر
از خط `WARN` قرار می‌گیرد و همه‌ی الگوریتم‌های قوی همچنان اولویت دارند) و همان
اتصال را با `-load CiscoPortMapper` تکرار می‌کند. تنظیمات PuTTY شما تغییر
نمی‌کند و هیچ پسورد یا کلیدی در رجیستری ذخیره نمی‌شود.

اگر باز هم خطا داد (مثلاً PuTTY تنظیماتش را جای دیگری نگه می‌دارد)، یک‌بار
دستی انجام دهید:

1. `PuTTY` را باز کنید و `Default Settings` را در لیست Saved Sessions انتخاب کنید.
2. `Connection > SSH > Kex` را باز کنید.
3. خط `Warn below here` را انتخاب کنید و با دکمه‌ی `Down` تا انتهای لیست پایین ببرید.
4. به `Session` برگردید و `Save` بزنید.

> الگوریتم‌های ضعیف امنیت کمی دارند؛ این راه‌حل فقط برای سوییچ‌های قدیمی در
> شبکه‌ی داخلی است. در صورت امکان firmware سوییچ را به‌روز کنید.

### روش ۲: OpenSSH Client ویندوز

نصب از طریق Settings:

```
Settings > Apps > Optional features > Add a feature > OpenSSH Client
```

یا در PowerShell با دسترسی Administrator:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

این کلاینت در حالت غیرتعاملی **پسورد نمی‌پذیرد**؛ باید کلید SSH داشته باشید:

```bat
ssh-keygen -t rsa -b 4096
type %USERPROFILE%\.ssh\id_rsa.pub
```

کلید عمومی را روی سوییچ ثبت کنید (نمونه برای IOS):

```
conf t
ip ssh pubkey-chain
  username admin
    key-string
      ssh-rsa AAAAB3Nza...   ← محتوای فایل id_rsa.pub
    exit
  exit
end
```

سپس در فرم برنامه، فیلد پسورد را خالی بگذارید. برنامه از کلید یا `ssh-agent`
استفاده می‌کند. اگر `ssh-agent` را فعال کرده‌اید، کلید را یک‌بار اضافه کنید:

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_rsa
```

## اجرا

ساده‌ترین راه: روی `run.bat` دوبار کلیک کنید. این فایل:

1. Python 3 را پیدا می‌کند و اگر نبود با `winget` نصب می‌کند؛
2. اگر هیچ کلاینت SSH نبود، یک‌بار `plink.exe` را دانلود می‌کند؛
3. برنامه را اجرا می‌کند.

هیچ پکیج پایتونی (`pip install`) لازم نیست.

دستی:

```bat
cd CiscoPortMapper
python app.py
```

تست parserها و منطق تقسیم خروجی، بدون نیاز به سوییچ:

```bat
python selftest.py
```

تست رگرسیون روی فایل‌های واقعی `raw_*.txt` (بازپخش با همان parserها و منطق تطبیق):

```bat
python regression.py
```

## ساخت فایل exe

```bat
build.bat
```

خروجی: `dist\CiscoPortMapper.exe` (تک‌فایل، بدون نیاز به نصب Python روی سیستم مقصد).
`build.bat` خودش `plink.exe` را (اگر نبود دانلود می‌کند و) کنار exe در `dist`
کپی می‌کند. `inventory.json` و در صورت نیاز `oui.csv` را هم کنار exe بگذارید.
کاربر نهایی فقط کافی است exe را اجرا کند؛ اگر `plink.exe` نبود، برنامه خودش
پیشنهاد دانلود می‌دهد.

> `build.bat` فقط برای ساخت exe به **PyInstaller** نیاز دارد و اگر اینترنت به
> PyPI نرسد، خودش چند میرور را امتحان می‌کند. برنامه‌ی نهایی هیچ پکیج پایتونی لازم ندارد.

## استفاده

رابط جدید از تم روشن `clam`، فونت Segoe UI، هدر تیره با نشانگر وضعیت SSH و
نوار ابزار کارتی استفاده می‌کند. پنجره در وسط صفحه باز می‌شود و روی
نمایشگرهای High-DPI شارپ رندر می‌شود. اگر کلاینت SSH نصب نباشد، یک نوار زرد
بالای پنجره و پیام شروع، دانلود خودکار `plink.exe` را پیشنهاد می‌دهند.

1. **Add switch** → آدرس IP، پورت SSH (پیش‌فرض 22)، یوزرنیم، پسورد و در صورت نیاز enable secret.
   - اگر `enable secret` وارد کنید، برنامه قبل از دستورها `enable` می‌زند تا `terminal length 0` و `show`های کامل کار کنند.
2. سوییچ‌ها را انتخاب کنید و **Scan selected** یا **Scan all** بزنید.
3. تب **Ports** نتیجه را نشان می‌دهد؛ تب **Log** جزئیات اتصال، کلاینت SSH استفاده‌شده و خطاها.
4. با دوبار کلیک روی هر ردیف، جزئیات کامل (لیست MAC، IP، سازنده، VLAN) باز می‌شود.
5. **Export CSV** خروجی اکسل‌پسند می‌دهد (`UTF-8 with BOM`).
6. فیلتر بالای صفحه روی همه‌ی ستون‌ها جست‌وجو می‌کند. تیک
   **Show disconnected ports** پورت‌های خاموش را هم نشان می‌دهد.

ستون‌ها: Switch، Interface، Description، Status، VLAN، Speed، Connected device،
IP، Platform، Remote port، MAC addresses، Source (CDP/LLDP/MAC).

## پیدا کردن دوربین‌ها و پورت سوییچ (تب Cameras)

این تب یک اسکن **فعال** روی شبکه انجام می‌دهد و برای هر دوربین می‌گوید روی
کدام پورت کدام سوییچ با کدام IP و VLAN وصل است.

### نحوه‌ی کار

1. **IP و MAC**: برای همه‌ی آدرس‌های محدوده، ARP ویندوز (`SendARP`) اجرا می‌شود.
   این کار به Administrator یا ICMP نیاز ندارد و حتی اگر فایروال دوربین
   ping را ببندد، MAC از لایه‌ی ۲ خوانده می‌شود. اگر دوربین در VLAN دیگری
   باشد (پشت روتر/FortiGate)، MAC از طریق ONVIF `GetNetworkInterfaces` یا
   Hikvision ISAPI خوانده می‌شود؛ این MAC هم برای تطبیق با جدول MAC سوییچ
   استفاده می‌شود.
2. **تشخیص دوربین**: پورت‌های RTSP (`554`/`8554`)، ONVIF (`80`/`8080`)،
   پورت‌های مخصوص سازنده (`8000` هیک‌ویژن، `37777` داهوا) و صفحه‌ی وب دستگاه
   بررسی می‌شود. عنوان صفحه، هدر `Server`، `WWW-Authenticate`، پاسخ RTSP و
   `GetDeviceInformation` مربوط به ONVIF برای تشخیص نام/مدل به کار می‌رود.
   برای **Hikvision** مسیر اختصاصی `/ISAPI/System/deviceInfo` و برای **Dahua**
   مسیرهای `/cgi-bin/magicBox.cgi` خوانده می‌شوند؛ حتی پاسخ `401` هم سازنده را
   مشخص می‌کند و در صورت دسترسی بدون پسورد، مدل/سریال/فریمور هم استخراج می‌شود.
3. **تطبیق MAC با سوییچ**: هنگام اسکن سوییچ، جدول MAC و ARP آن خوانده و
   ایندکس می‌شود. MAC هر دوربین با جدول MAC همه‌ی سوییچ‌های اسکن‌شده تطبیق
   داده می‌شود. پورت‌هایی که بیش از ۸ MAC دارند (uplink/trunk) نادیده گرفته
   می‌شوند تا پورت واقعی دوربین گزارش شود؛ پورت‌های کاندید دیگر در پنجره‌ی
   جزئیات (دوبار کلیک) نمایش داده می‌شوند.
4. **fallback بر اساس IP**: اگر دوربین در VLAN دیگری باشد و MAC آن از این
   کامپیوتر دیده نشود، از IP موجود در CDP/LLDP یا جدول ARP خود سوییچ
   استفاده می‌شود.
5. **تشخیص از روی MAC**: OUIهای معروف دوربین (Hikvision، Dahua، Axis،
   Vivotek، Uniview، Reolink، Hanwha/Samsung Techwin، ACTi، Arecont،
   Mobotix) داخل برنامه هستند. بنابراین حتی در حالت L2 و بدون ARP هم اگر
   MAC دوربین در جدول MAC سوییچ باشد، ردیف آن به‌صورت `Switch side` نمایش
   داده می‌شود. برای دیتابیس کامل، `oui.csv` را کنار برنامه بگذارید.

### استفاده

1. محدوده‌ها را در کادر چندخطی **Subnets / ranges** وارد کنید؛ هر رنج در یک
   خط (یا با کاما/فاصله). حالت‌های پشتیبانی‌شده:
   - `172.16.40.0/24` (CIDR)
   - `192.168.217.1-192.168.217.254` (رنج کامل)
   - `192.168.217.1-254` (فقط اوکتت آخر)
   - `192.168.217.*` (کل /24)
   - `172.16.40.7` (یک آدرس)
   - `#` برای توضیح/کامنت؛ خطوط کامنت نادیده گرفته می‌شوند.
   مثال چند VLAN با هم:
   ```
   # camera VLANs
   192.168.217.1-192.168.217.254
   192.168.218.1-254
   172.16.50.0/24
   ```
   تعداد آدرس‌های محاسبه‌شده کنار دکمه‌ها نمایش داده می‌شود و پیش‌فرض،
   subnetهای کامپیوتر شماست.
2. تیک **Re-scan switches before matching** را بزنید تا سوییچ‌های انتخاب‌شده
   (یا اگر هیچ‌کدام انتخاب نشده باشد، همه‌ی سوییچ‌ها) دوباره خوانده شوند.
   اگر جدول MAC سوییچ‌ها را همین حالا در تب Ports اسکن کرده‌اید، می‌توانید
   تیک را بردارید و فقط **Match only** بزنید.
3. **Discover cameras** را بزنید.
4. ستون‌ها: Camera IP، MAC، Vendor، Name/model، Confidence، Open ports،
   Switch، Switch port، VLAN، Port description، Match، Evidence.
   - Confidence: `High` / `Medium` / `Low` بر اساس شواهد (RTSP، ONVIF،
     fingerprint سازنده).
   - Match: `MAC matched` یعنی پورت پیدا شد؛ `MAC unknown` یعنی دوربین از
     subnet دیگری است و MAC دیده نشده؛ `IP matched via switch` یعنی از
     CDP/LLDP/ARP سوییچ تطبیق داده شده.
   - ردیف‌های آبی (`Switch side`) دوربین‌هایی هستند که فقط از طریق CDP/LLDP
     سوییچ شناسایی شده‌اند (مثلاً وقتی اسکنر در VLAN دوربین نیست).
5. دوبار کلیک روی هر ردیف، جزئیات کامل و همه‌ی پورت‌های کاندید را نشان می‌دهد.
6. **Export CSV** خروجی اکسل‌پسند می‌دهد.

### ورود جدول ARP از روتر (Load ARP table…)

اگر دوربین‌ها در VLANهای routed هستند و MAC آن‌ها از این کامپیوتر دیده
نمی‌شود، جدول ARP دستگاه لایه ۳ (همان FortiGate که ترانک و gateway همه‌ی
VLANها روی آن است) را بگیرید و در برنامه وارد کنید:

1. روی FortiGate این دستور را بزنید و خروجی را در یک فایل متنی ذخیره کنید:
   ```
   get system arp
   ```
   (روی سوییچ سیسکو: `show ip arp`؛ روی ویندوز: `arp -a`)
2. در تب **Cameras** دکمه‌ی **Load ARP table...** را بزنید و آن فایل را انتخاب
   کنید. فرمت‌های FortiGate، سیسکو (MAC نقطه‌ای مثل `3cef.8c11.2255`) و ویندوز
   هر سه پشتیبانی می‌شوند.
3. برنامه همه‌ی جفت‌های `IP ↔ MAC` را می‌خواند، آن‌ها را با جدول MAC
   سوییچ‌های اسکن‌شده تطبیق می‌دهد و دوربین‌های قبلی را دوباره `match`
   می‌کند. ستون Match در این حالت `MAC matched (switch ARP)` می‌شود.

نکته‌ها:

- این کار **اسکن شبکه را جایگزین نمی‌کند**؛ فقط MAC دوربین‌های routed را
  تأمین می‌کند. اول با **Discover cameras** دوربین‌ها را پیدا کنید، بعد جدول
  ARP را وارد کنید.
- ورودی‌های ARP دستی با نتایج ARP خود سوییچ‌ها ادغام می‌شوند و تا بستن
  برنامه باقی می‌مانند.
- اگر جدول ARP قدیمی باشد، ممکن است MAC عوض شده باشد؛ در این حالت دوباره
  `get system arp` بگیرید.

> اسکن فعال فقط روی شبکه‌ای انجام شود که مالک آن هستید یا اجازه‌ی تست دارید.
> اسکن یک /24 حدود ۲۰ تا ۶۰ ثانیه طول می‌کشد (بسته به تعداد دستگاه‌های زنده).

### محدودیت‌ها

- **MAC در subnet مستقیم یا از ONVIF/ISAPI**: ARP از روی روتر عبور نمی‌کند.
  رنج‌های routed (مثل وقتی از طریق FortiGate/ترانک به همه‌ی VLANها دسترسی
  دارید) همچنان **اسکن می‌شوند** و IP، سازنده، مدل و پورت‌های بازشان پیدا
  می‌شود. MAC هم اگر دوربین ONVIF/ISAPI بدهد خوانده می‌شود؛ در غیر این صورت:
  - جدول ARP دستگاه لایه ۳ (مثلاً FortiGate با `get system arp`) را با
    **Load ARP table...** وارد کنید (بهترین راه برای ترانک FortiGate)، **یا**
  - اسکنر را روی یک PC/پورت داخل همان VLAN اجرا کنید، **یا**
  - از سوییچ لایه ۳ استفاده کنید تا جدول ARP آن، IP را به MAC تبدیل کند، **یا**
  - به تطبیق از طریق CDP/LLDP/ARP سوییچ (ستون `IP matched via switch`)
    تکیه کنید.
- بعضی دوربین‌ها برای ONVIF/ISAPI نیاز به یوزر/پسورد دارند؛ در این حالت
  ممکن است مدل دقیق نمایش داده نشود ولی پورت‌ها و MAC همچنان شناسایی می‌شوند.
- پورت 554 باز به‌تنهایی می‌تواند مربوط به NVR، سرور رسانه یا هر دستگاه
  RTSP دیگری باشد؛ برای همین ستون Confidence و Evidence نمایش داده می‌شود.
- اسکن پورت ممکن است توسط سیستم‌های IDS/IPS یا فایروال دوربین محدود شود.
- دوربین‌هایی که در حالت sleep یا با IP اشتباه/تکراری هستند ممکن است دیده نشوند.

## پیدا کردن PCها و پورت سوییچ (تب PCs / Hosts)

این تب دقیقاً همان کاری را که تب Cameras برای دوربین‌ها انجام می‌دهد، برای
کامپیوترها و بقیه‌ی دستگاه‌های شبکه انجام می‌دهد: IP و MAC را با اسکن شبکه
پیدا می‌کند، در صورت امکان نام سیستم را می‌خواند، و MAC را با جدول MAC
سوییچ‌های اسکن‌شده تطبیق می‌دهد تا بگوید به کدام پورت کدام سوییچ وصل است.

### نحوه‌ی کار

1. **IP و MAC**: روی subnetهای مستقیم، ARP ویندوز (`SendARP`) اجرا می‌شود؛
   به Administrator، ping یا باز بودن پورت نیاز ندارد. آدرس‌های routed هم
   بررسی می‌شوند، ولی MAC آن‌ها از ARP این کامپیوتر دیده نمی‌شود و باید از
   جدول ARP روتر/سوییچ تأمین شود (بخش «Load ARP table…»).
2. **نام سیستم**: به ترتیب سه روش امتحان می‌شود و اولین پاسخ استفاده می‌شود:
   - **DNS معکوس** (PTR) با resolver ویندوز؛
   - **NetBIOS node-status** روی UDP/137 (برای ویندوزهای domain/workgroup)؛
   - **mDNS معکوس** روی UDP/5353 (برای دستگاه‌های `<name>.local`).
   اگر سوییچ از طریق CDP/LLDP نام دستگاه را گزارش کند، به‌عنوان مکمل
   استفاده می‌شود. همه‌ی این روش‌ها best-effort هستند.
3. **نوع دستگاه**: چند پورت TCP کوتاه بررسی می‌شود و از روی آن‌ها نوع حدس
   زده می‌شود:
   - `135/139/445/3389` → **Windows PC** (باز بودن `3389` یعنی RDP)
   - `22` → **Linux host**
   - `548` → **macOS**
   - `515/631/9100` → **Printer**
   - `62078` → **Phone / tablet**
   - `5900` (VNC) و `8080` هم در فهرست پورت‌های بررسی‌شده هستند.
   روی آدرس‌های routed فقط پورت‌های امضادار (`22,135,139,445,3389`) بررسی
   می‌شوند تا اسکن کند بماند؛ اگر هیچ نام و پورتی پاسخ ندهد، آن آدرس نادیده
   گرفته می‌شود.
4. **تطبیق MAC با سوییچ**: همان موتور تطبیق تب Cameras استفاده می‌شود.
   پورت‌هایی که بیش از ۸ MAC دارند (uplink/trunk) کنار گذاشته می‌شوند و
   نزدیک‌ترین پورت access گزارش می‌شود. اگر MAC از ARP سوییچ/روتر آمده باشد،
   ستون Match مقدار `MAC matched (switch ARP)` را نشان می‌دهد.
5. **fallback بر اساس IP**: اگر MAC در دسترس نباشد ولی IP در CDP/LLDP یا
   ARP سوییچ باشد، از IP برای پیدا کردن پورت استفاده می‌شود
   (`IP matched via switch`).

### استفاده

1. محدوده‌ها را در کادر **Subnets / ranges** وارد کنید. همه‌ی حالت‌های تب
   Cameras پشتیبانی می‌شوند:
   - `172.16.4.0/24` (CIDR)
   - `192.168.217.1-192.168.217.254` (رنج کامل)
   - `192.168.217.1-254` (فقط اوکتت آخر)
   - `192.168.217.*` (کل /24)
   - `172.16.4.7` (یک آدرس)
   - `#` برای کامنت؛ چند رنج در چند خط یا با کاما/فاصله.
   تعداد آدرس‌ها کنار دکمه‌ها به‌صورت زنده نمایش داده می‌شود.
2. گزینه‌ها:
   - **Re-scan switches before matching**: قبل از تطبیق، سوییچ‌های
     انتخاب‌شده (یا همه‌ی سوییچ‌ها) دوباره خوانده می‌شوند. اگر همین حالا در
     تب Ports اسکن کرده‌اید، تیک را بردارید.
   - **Resolve names (DNS / NetBIOS / mDNS)**: جست‌وجوی نام را روشن/خاموش
     می‌کند. خاموش کردن آن اسکن را سریع‌تر می‌کند.
   - **Only computers (hide printers/phones)**: چاپگرها و گوشی/تبلت‌ها را از
     نتیجه حذف می‌کند.
   - **Only devices on the scanned switch (hide uplink/trunk devices)**: فقط
     دستگاه‌هایی را نشان می‌دهد که مستقیماً به سوییچ اسکن‌شده وصل‌اند؛ همین تیک
     با تب Cameras مشترک است (بخش مربوطه را ببینید).
   - **Filter**: جست‌وجوی زنده روی همه‌ی ستون‌ها.
3. **Discover hosts** را بزنید. برنامه ابتدا هاست‌ها را پیدا می‌کند، بعد
   (در صورت تیک) سوییچ‌ها را اسکن می‌کند و در پایان خودکار تطبیق می‌دهد.
4. اگر جدول MAC سوییچ‌ها از قبل بارگذاری شده است، با **Match only** فقط
   تطبیق را دوباره اجرا کنید (مثلاً بعد از عوض شدن کابل یا VLAN).
5. ستون‌ها: IP، MAC، Hostname، Vendor، Type، Confidence، Open ports، Switch،
   Switch port، VLAN، Port description، Match، Evidence.
   - ردیف سبز: MAC با یک پورت تطبیق داده شد.
   - ردیف نارنجی: MAC ناشناخته یا پورت پیدا نشد (جزئیات با دوبار کلیک).
6. دوبار کلیک روی ردیف، جزئیات کامل (نام، نوع، شواهد، پورت‌های کاندید و
   هشدارها) را نشان می‌دهد. `Ctrl+C` ردیف انتخاب‌شده را کپی می‌کند.
7. **Export CSV** خروجی اکسل‌پسند (`UTF-8 with BOM`) می‌دهد.

### Load ARP table… برای PCها

همان دکمه‌ی **Load ARP table...** در این تب هم هست و همان فرمت‌ها را
می‌خواند (FortiGate `get system arp`، سیسکو `show ip arp`، ویندوز `arp -a`).
اگر PCها در VLANهای routed هستند و MAC آن‌ها از این کامپیوتر دیده نمی‌شود:

1. اول **Discover hosts** را بزنید تا IP و نام دستگاه‌ها پیدا شود.
2. خروجی ARP دستگاه لایه ۳ (مثلاً FortiGate) را در فایل متنی ذخیره کنید.
3. **Load ARP table...** را بزنید و فایل را انتخاب کنید؛ جدول PCها فوراً
   دوباره تطبیق داده می‌شود.

### محدودیت‌ها

- **ARP از روتر عبور نمی‌کند.** رنج‌های routed اسکن می‌شوند و IP، نام و
  پورت‌های بازشان پیدا می‌شود، ولی MAC فقط از این راه‌ها به دست می‌آید:
  - جدول ARP دستگاه لایه ۳ با **Load ARP table...** (بهترین راه برای ترانک
    FortiGate)؛
  - اجرای اسکنر روی یک PC داخل همان VLAN؛
  - استفاده از سوییچ لایه ۳ که جدول ARP/IP آن خوانده می‌شود؛
  - تطبیق از طریق CDP/LLDP/ARP خود سوییچ (`IP matched via switch`).
- **فایروال ویندوز** ممکن است NetBIOS (UDP/137) و mDNS (UDP/5353) و حتی
  پورت‌های 135/139/445 را ببندد؛ در این حالت نام و نوع دستگاه ممکن است
  `Unknown` بماند ولی MAC (اگر در subnet مستقیم باشد) و پورت سوییچ همچنان
  پیدا می‌شود.
- دستگاه‌های خاموش، در حالت sleep، یا با MAC تصادفی (privacy MAC در گوشی‌ها)
  ممکن است اشتباه یا ناقص نمایش داده شوند.
- یک MAC می‌تواند روی چند پورت دیده شود (سوییچ غیرمدیریتی، مجازی‌سازی،
  roaming وایرلس)؛ در این حالت کم‌بارترین پورت انتخاب و در جزئیات هشدار
  داده می‌شود.
- اسکن پورت ممکن است توسط IDS/IPS یا فایروال مرکزی محدود یا لاگ شود.

## نمایش فقط دستگاه‌های همین سوییچ (Only devices on the scanned switch)

وقتی چند سوییچ به هم uplink/trunk شده‌اند، جدول MAC سوییچ اسکن‌شده شامل MAC
دستگاه‌هایی هم هست که پشت سوییچ‌های دیگر هستند. تیک مشترک
**Only devices on the scanned switch** در تب‌های **Cameras** و **PCs / Hosts**
این ردیف‌ها را پنهان می‌کند تا فقط دستگاه‌های فیزیکاً وصل‌شده به همان سوییچ
بمانند.

برنامه پورت uplink را از این نشانه‌ها تشخیص می‌دهد:

- VLAN پورت `trunk` باشد؛
- description شامل واژه‌هایی مثل `uplink`، `trunk`، `interswitch`، `backbone`،
  `to core` باشد؛
- همسایه‌ی CDP/LLDP یک سوییچ/روتر باشد (مدل‌هایی مثل `WS-C2960X`، `C9300`،
  `Nexus`، `Aruba`، `ProCurve`، `EX`/`QFX` و …)؛
- پورت بیش از ۸ MAC داشته باشد (همان heuristic قبلی برای ترانک‌های بزرگ).

ردیف‌هایی که فقط روی uplink دیده شده‌اند، در حالت عادی با متن
`Only on a shared/uplink port (best guess)` علامت می‌خورند و با این تیک حذف
می‌شوند.
**Export CSV** و **Export Excel** در هر تب فقط ردیف‌های قابل‌مشاهده (بعد از فیلتر
متنی، فیلتر وضعیت و این تیک) را ذخیره می‌کنند.

## تشخیص سازنده از MAC

یک جدول کوچک از OUIهای معروف داخل برنامه هست. برای دیتابیس کامل:

1. فایل `oui.csv` را از <https://standards-oui.ieee.org/oui/oui.csv> دانلود کنید.
2. آن را کنار `app.py` (یا کنار exe) قرار دهید. خودکار خوانده می‌شود.

## جست‌وجو و خروجی

- کادر **Filter** در هر سه تب: اگر یک **IP کامل** یا **MAC کامل** وارد کنید،
  تطبیق دقیق است (فرمت‌های `AA:BB:CC:DD:EE:FF`، `AA-BB-...`، `aabb.ccdd.eeff`
  و ۱۲ رقم خام). هر متن دیگر به‌صورت زیررشته‌ای جست‌وجو می‌شود.
- فیلتر **Port status** فقط ردیف‌های Confirmed / Probable / Candidates / Unknown
  را نشان می‌دهد و با فیلتر متنی و گزینه‌ی «Only devices on the scanned switch» ترکیب می‌شود.
- **Export CSV** و **Export Excel** هر دو فقط ردیف‌های قابل‌مشاهده با فیلتر فعلی را می‌نویسند.
- خروجی Excel کاملاً با کتابخانه‌ی استاندارد ساخته می‌شود (بدون `openpyxl`):
  هدر Bold و Frozen، AutoFilter و عرض ستون خودکار.

## محدودیت‌ها و نکات

- اگر روی سوییچ **نه CDP و نه LLDP** فعال باشد، نام دقیق دستگاه قابل تشخیص نیست؛
  فقط MAC و سازنده (از روی OUI) و IP (از ARP) نمایش داده می‌شود.
- CDP/LLDP فقط همسایه‌ی مستقیم را نشان می‌دهد؛ برای دستگاه پشت یک سوییچ
  غیرمدیریتی، همان سوییچ به‌عنوان همسایه دیده می‌شود.
- گزینه‌ی «Enable LLDP» در فرم سوییچ، در صورت نبود LLDP دستور `lldp run` را
  در حالت config اجرا می‌کند (تغییر تنظیمات دستگاه است؛ پیش‌فرض خاموش است).
- روی NX-OS یا IOSهای خیلی قدیمی ممکن است برخی دستورها متفاوت باشند؛
  برنامه دستور جایگزین را امتحان می‌کند ولی همه‌ی پلتفرم‌ها تست نشده‌اند.
- در سوییچ‌های L2، `show ip arp` ممکن است خالی باشد؛ در آن صورت ستون IP خالی می‌ماند.
- `plink.exe` نسخه‌های قدیمی از الگوریتم‌های جدید SSH پشتیبانی نمی‌کنند؛ از نسخه‌ی
  جدید PuTTY (0.78 یا بالاتر) استفاده کنید.

## امنیت

- پسوردها فقط **Base64** می‌شوند (مخفی‌سازی واقعی نیست) و در `inventory.json`
  ذخیره می‌شوند. فایل را در مسیر امن نگه دارید یا از پسورد اختصاصی و محدود استفاده کنید.
- `plink` پسورد را با سوئیچ `-pw` روی خط فرمان می‌گیرد؛ در طول اتصال، پسورد
  برای چند لحظه در لیست پردازه‌های ویندوز قابل دیدن است. برای محیط حساس‌تر از
  کلید SSH استفاده کنید:
  - فیلد پسورد **خالی** + وجود `ssh.exe` → برنامه از کلیدهای OpenSSH
    (`%USERPROFILE%\.ssh`) یا `ssh-agent` ویندوز استفاده می‌کند.
  - فیلد پسورد **خالی** + نبودن `ssh.exe` → `plink` ابتدا کلیدهای Pageant/PuTTY
    را امتحان می‌کند؛ Pageant را قبل از اجرای برنامه باز کنید.
  - فیلد پسورد **پر** → `plink` با `-pw` وارد می‌شود.
- کلید هاست SSH در اولین اتصال به‌صورت خودکار (TOFU) پذیرفته می‌شود: برنامه
  fingerprint را از خود `plink` می‌خواند و با `-hostkey` وصل می‌شود. برای امنیت
  سخت‌گیرانه، fingerprint را از قبل با `plink <host>` یا `ssh-keyscan` ثبت و
  بررسی کنید.
- هیچ داده‌ای به اینترنت فرستاده نمی‌شود؛ همه‌چیز به شبکه و سوییچ‌های خودتان
  محدود است.
- تب Cameras یک اسکن فعال (ARP + پورت‌های RTSP/ONVIF/HTTP) انجام می‌دهد.
  این کار را فقط روی شبکه‌ای اجرا کنید که مالک آن هستید یا اجازه‌ی اسکن
  دارید؛ بعضی سیستم‌های IDS/IPS آن را به‌عنوان port scan تشخیص می‌دهند.

## عیب‌یابی

| مشکل | راه‌حل |
|---|---|
| `No SSH client found` یا پیام مشابه | دکمه‌ی **Setup...** در بالای پنجره را بزنید و **Download plink.exe automatically** را انتخاب کنید (بدون Administrator)؛ یا OpenSSH Client را نصب کنید |
| `ssh.exe needs an SSH key` / `key/agent login only` | `ssh.exe` پسورد نمی‌پذیرد؛ plink نصب کنید یا کلید SSH بسازید |
| `Authentication failed` | یوزر/پسورد و مجاز بودن SSH را بررسی کنید (`ip ssh version 2`, `line vty ... transport input ssh`) |
| `host key not cached` / خطای کلید هاست | برنامه خودکار fingerprint را می‌خواند؛ اگر باز هم نشد یک‌بار `plink -ssh admin@<switch-ip>` را دستی اجرا و `y` بزنید |
| `the first key-exchange algorithm supported by the server is ... below the configured warning threshold` | سوییچ قدیمی است و الگوریتم ضعیف دارد؛ برنامه خودکار Session `CiscoPortMapper` را می‌سازد و با `-load` وصل می‌شود. اگر باز هم نشد، `Warn below here` را در `Connection > SSH > Kex` به انتهای لیست ببرید و `Default Settings` را Save کنید |
| `Could not enter enable mode` | enable secret را در فرم سوییچ وارد کنید |
| `timed out ... --More--` | دستور `terminal length 0` اجرا نشده؛ سطح دسترسی/secret را بررسی کنید |
| LLDP خالی است | یا LLDP روی سوییچ فعال نیست، یا دستگاه مقابل LLDP نمی‌فرستد؛ CDP را چک کنید |
| جدول MAC خالی | پورت trunk/port-channel را بررسی کنید یا روی سوییچ لایه ۳ اسکن کنید |
| **هیچ ردیفی نشان داده نمی‌شود** | اول `python diagnose.py <switch-ip> <username>` را اجرا کنید و فایل `diagnose_<ip>.txt` را بفرستید؛ دلیل دقیق (عدم اتصال، prompt ناشناس، `--More--`، صفر ردیف) در آن نوشته است |
| در تب Cameras هیچ دوربینی پیدا نشد | subnet درست را وارد کنید (پیش‌فرض فقط subnet همین PC است)، تیک «Show non-camera devices too» را بزنید و Log را ببینید؛ بعضی دوربین‌ها پورت 554/80 را فقط از subnet خودشان باز می‌کنند |
| دوربین پیدا شد ولی ستون Switch/Port خالی است | MAC دوربین از این PC دیده نشده (VLAN دیگر)؛ از PC داخل VLAN دوربین اسکن کنید یا سوییچ لایه ۳ را اسکن کنید. اگر MAC در جدول سوییچ هست، `oui.csv` را کنار برنامه بگذارید یا از ردیف‌های `Switch side` استفاده کنید |
| ستون Match با `Unknown:` شروع می‌شود | MAC پیدا نشد یا داده کافی نیست؛ سوییچ درست اسکن نشده یا MAC دوربین روی سوییچ دیگری است. همه‌ی سوییچ‌ها را اسکن کنید و مطمئن شوید جدول MAC در تب Ports پر شده است |
| ستون Match با `Candidates:` شروع می‌شود | MAC فقط روی پورت uplink/پورت‌های پرMAC دیده شده یا چند کاندید دارد؛ برنامه عمداً پورتی را ادعا نمی‌کند. سوییچی که دوربین مستقیماً به آن وصل است را هم اسکن کنید یا تیک «Only devices on the scanned switch» را بردارید |
| نصب PyInstaller با timeout به `pypi.org` شکست خورد | `build.bat` خودش میرورها را امتحان می‌کند؛ یا PyInstaller را با `-i https://mirror-pypi.runflare.com/simple` نصب کنید |

### ابزار تشخیص `diagnose.py`

اگر برنامه اسکن می‌کند ولی چیزی نشان نمی‌دهد، این را در همان پوشه اجرا کنید:

```bat
python diagnose.py 192.168.1.10 admin
```

از شما پسورد می‌پرسد (برای ورود با کلید، خالی بگذارید). سپس:

- نسخه‌ی Python و مسیر/نسخه‌ی `plink.exe`
- **متن خام** پاسخ سوییچ با نمایش کاراکترهای کنترلی
- این‌که کدام دستور خروجی داشته و کدام نداشته
- لیست ردیف‌های پارس‌شده با نام دستگاه و MAC

و همه را در `diagnose_<ip>.txt` ذخیره می‌کند.

```bat
python diagnose.py 192.168.1.10 admin --secret ENABLEPASS
python diagnose.py 192.168.1.10 admin --raw
python diagnose.py 192.168.1.10 admin --commands "show version" --no-rows
```

برنامه‌ی گرافیکی هم حالا هر بار لاگ را در `cisco_port_mapper.log` کنار خودش
ذخیره می‌کند؛ اگر خطایی دیدید همان فایل را بفرستید.

علاوه بر این، بعد از هر اسکن موفق فایل `raw_<switch-ip>.txt` ساخته می‌شود که
خروجی خام هر دستور و کل متن SSH را دارد. اگر اتصال برقرار شد ولی جدول خالی ماند،
همان فایل بیشترین کمک را می‌کند.

`regression.py` همین فایل‌های `raw_*.txt` را با همان parserها و منطق تطبیق برنامه
بازپخش می‌کند و این قواعد را بررسی می‌کند: هیچ پورتی برای `Candidates`/`Unknown`
ادعا نشود، ردیف‌های `Confirmed`/`Probable` پورت داشته باشند، دلیل و لیست کاندیدها
موجود باشد و خروجی Excel سالم باشد. فایل‌های ناقص (اسکن قطع‌شده) به‌عنوان
`SKIPPED` گزارش می‌شوند، نه خطا.

## ساختار فایل‌ها

```
CiscoPortMapper/
├── app.py               رابط گرافیکی (tkinter)
├── cisco.py             دستورها و parserها + ایندکس MAC/ARP
├── cameras.py           اسکن فعال دوربین و تطبیق MAC با پورت سوییچ
├── hosts.py             اسکن فعال PC/هاست، نام‌گذاری DNS/NetBIOS/mDNS و تطبیق
├── sshexec.py           اجرای SSH با plink.exe / ssh.exe و تقسیم خروجی
├── xlsx.py              خروجی Excel فقط با کتابخانه استاندارد (zipfile)
├── oui.py               تشخیص سازنده از MAC
├── prereq.py            بررسی/نصب خودکار کلاینت SSH (دانلود plink.exe، OpenSSH)
├── selftest.py          تست offline بدون سوییچ
├── regression.py        بازپخش فایل‌های raw_*.txt و بررسی invariantها
├── diagnose.py          ابزار تشخیص خط فرمان (متن خام SSH)
├── requirements.txt     بدون وابستگی (فقط توضیح)
├── run.bat              اجرا + نصب خودکار Python و plink.exe
├── build.bat            ساخت exe با PyInstaller + کپی plink.exe در dist
├── inventory.example.json
└── README.md
```

> رابط کاربری انگلیسی است چون tkinter متن فارسی را درست (چسبیده و راست‌به‌چپ)
> رندر نمی‌کند. در صورت نیاز می‌توان نسخه‌ی PySide6 با رابط کامل فارسی ساخت.
