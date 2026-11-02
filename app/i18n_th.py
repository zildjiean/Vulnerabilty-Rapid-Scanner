"""Thai catalog for the user interface: exact English source string -> Thai. See app/i18n.py.

Glossary (keep these the same everywhere; tone follows docs/USER_GUIDE.th.md: short, direct, no ครับ/ค่ะ):
  Kept in English inside Thai sentences:
    issue, finding, scan, nmap, nuclei, subfinder, httpx, template, scope, campaign, CVE, KEV, EPSS, CVSS, job,
    inventory, preset, profile (scan profile), host, service, port, asset, subdomain, version rule, rule (in
    "version rule"), schedule (noun in sentences), webhook, Slack, Teams, Jira, GitLab, API, API key, token, SLA,
    AI, provider, prompt, log, CSV, JSON, dashboard (in sentences), audit log, 0-day, proof, payload, URL, CSRF
    severity names: critical / high / medium / low / info / unknown
  Translated:
    Dashboard แดชบอร์ด · Reports รายงาน · Settings ตั้งค่า · Users ผู้ใช้ · Updates อัปเดต · Integrations การเชื่อมต่อ
    Scanning การสแกน · New scan สแกนใหม่ · Automation อัตโนมัติ · Schedules ตารางสแกน · Detection library คลังการตรวจจับ
    Version rules กฎเวอร์ชัน · Changes การเปลี่ยนแปลง · Discovered ที่ค้นพบ · Raw findings ผลดิบ (finding)
    0-day watch เฝ้าระวัง 0-day · AI assistant ผู้ช่วย AI · System ระบบ
    status: New ใหม่ · Triaged คัดกรองแล้ว · In progress กำลังแก้ · Fixed แก้แล้ว · Resolved ปิดแล้ว ·
            False positive False positive · Accepted risk ยอมรับความเสี่ยง
    confidence: Suspected สงสัย · Confirmed ยืนยันแล้ว · Verified พิสูจน์แล้ว
    roles: Admin ผู้ดูแลระบบ · Analyst นักวิเคราะห์ · Viewer ผู้ดู
    Save บันทึก · Cancel ยกเลิก · Delete ลบ · Edit แก้ไข · Add เพิ่ม · Create สร้าง · Search ค้นหา · Filter กรอง
    Enable/Disable เปิดใช้/ปิดใช้ · Pause หยุดชั่วคราว · Run now รันเลย · Verify now ตรวจซ้ำเลย · Re-verify ตรวจซ้ำ
    Assignee ผู้รับผิดชอบ · Due date วันครบกำหนด · Overdue เกินกำหนด · Owner เจ้าของ · Criticality ความสำคัญ
    Severity ความรุนแรง · Status สถานะ · Target(s) เป้าหมาย · Exclusions ยกเว้น · Timeline ไทม์ไลน์
    Comment ความเห็น · Reason เหตุผล · Next step ขั้นต่อไป · More actions การทำงานเพิ่มเติม · Get started เริ่มต้นใช้งาน
    Remediation การแก้ไข · Vulnerability ช่องโหว่ · Exposure ความเสี่ยงที่เปิดเผย · Evidence หลักฐาน
    Advanced options ตัวเลือกขั้นสูง · Optional (ไม่บังคับ) · Required ต้องระบุ
    "No X yet" -> "ยังไม่มี X" · "{n} item(s)" -> "{n} รายการ"
"""

CATALOG_TH: dict[str, str] = {
    # ------------------------------------------------------------- shell: base.html, navigation, account
    "Scanner": "Scanner",
    "Skip to content": "ข้ามไปที่เนื้อหา",
    "Primary navigation": "เมนูหลัก",
    "0-Day Rapid Scanner home": "หน้าแรก 0-Day Rapid Scanner",
    "Enterprise exposure platform": "แพลตฟอร์มดูแลความเสี่ยงองค์กร",
    "Collapse sidebar": "ย่อแถบเมนู",
    "Collapse": "ย่อเมนู",
    "Changelog": "บันทึกการเปลี่ยนแปลง",
    "Open navigation": "เปิดเมนู",
    "Breadcrumb": "ตำแหน่งหน้า",
    "Toggle dark mode": "สลับโหมดมืด",
    "Toggle theme": "สลับธีม",
    "Your profile": "โปรไฟล์ของคุณ",
    "Logout": "ออกจากระบบ",
    "Please confirm": "โปรดยืนยัน",
    "Cancel": "ยกเลิก",
    "Confirm": "ยืนยัน",
    "Language": "ภาษา",
    # app/static/app.js (i18n.JS_STRINGS)
    "Dismiss": "ปิด",
    "Copied to clipboard": "คัดลอกแล้ว",
    "Copy failed: select the text and copy it manually": "คัดลอกไม่สำเร็จ ให้เลือกข้อความแล้วคัดลอกเอง",
    "No templates match.": "ไม่พบ template ที่ตรงกัน",
    "Search failed; try again.": "ค้นหาไม่สำเร็จ ลองอีกครั้ง",
    "Job #{id} {status}": "Job #{id} {status}",
    "Remove {name}": "เอา {name} ออก",
    "1 result": "1 รายการ",
    "{n} results": "{n} รายการ",
    "Add all": "เพิ่มทั้งหมด",
    "nmap {n} target(s) ({ports}) → nuclei ({preset}) on the services found":
        "nmap {n} เป้าหมาย ({ports}) → nuclei ({preset}) กับ service ที่พบ",
    # sign-in, password, profile, error pages
    "Sign in": "เข้าสู่ระบบ",
    "Use your operator account to continue.": "ใช้บัญชีผู้ปฏิบัติงานของคุณเพื่อดำเนินการต่อ",
    "Username": "ชื่อผู้ใช้",
    "Password": "รหัสผ่าน",
    "Default account is": "บัญชีเริ่มต้นคือ",
    ". The password must be changed on first login.": " ต้องเปลี่ยนรหัสผ่านเมื่อเข้าสู่ระบบครั้งแรก",
    "Too many failed attempts. Try again in a minute.": "ลองผิดหลายครั้งเกินไป รอสักครู่แล้วลองใหม่",
    "Invalid username or password.": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
    "Account": "บัญชี",
    "Set a new password": "ตั้งรหัสผ่านใหม่",
    "Change password": "เปลี่ยนรหัสผ่าน",
    "Choose a strong password of at least 12 characters.": "เลือกรหัสผ่านที่คาดเดายาก อย่างน้อย 12 ตัวอักษร",
    "Current password": "รหัสผ่านปัจจุบัน",
    "New password": "รหัสผ่านใหม่",
    "Minimum 12 characters. Use a passphrase or a password manager.":
        "อย่างน้อย 12 ตัวอักษร แนะนำให้ใช้วลีรหัสผ่านหรือโปรแกรมจัดการรหัสผ่าน",
    "Confirm new password": "ยืนยันรหัสผ่านใหม่",
    "Save password": "บันทึกรหัสผ่าน",
    "The default password must be changed before you can use the scanner.":
        "ต้องเปลี่ยนรหัสผ่านเริ่มต้นก่อนใช้งานระบบ",
    "Current password is incorrect.": "รหัสผ่านปัจจุบันไม่ถูกต้อง",
    "New password must be at least {n} characters.": "รหัสผ่านใหม่ต้องมีอย่างน้อย {n} ตัวอักษร",
    "Passwords do not match.": "รหัสผ่านไม่ตรงกัน",
    "New password must differ from the current one.": "รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านปัจจุบัน",
    "Password updated": "เปลี่ยนรหัสผ่านแล้ว",
    "Profile": "โปรไฟล์",
    "Your details, what your role allows and your recent activity.":
        "ข้อมูลของคุณ สิ่งที่บทบาทของคุณทำได้ และกิจกรรมล่าสุด",
    "Your details": "ข้อมูลของคุณ",
    "Display name": "ชื่อที่แสดง",
    "Email": "อีเมล",
    "Used for notifications in a later release.": "ใช้สำหรับการแจ้งเตือนในเวอร์ชันถัดไป",
    "Save": "บันทึก",
    "Role": "บทบาท",
    "Show Get started again": "แสดง Get started อีกครั้ง",
    "Brings the checklist back to the Dashboard.": "นำรายการขั้นตอนเริ่มต้นกลับมาที่แดชบอร์ด",
    "Show all menu items": "แสดงเมนูทั้งหมด",
    "The sidebar normally lists what your role works with. Turn this on to list every page you may open.":
        "ปกติแถบเมนูแสดงเฉพาะส่วนที่บทบาทของคุณใช้งาน เปิดตัวเลือกนี้เพื่อแสดงทุกหน้าที่คุณเปิดได้",
    "Save menu preference": "บันทึกการตั้งค่าเมนู",
    "Language of menus, buttons and messages. Scan results, CVE details and exports stay as they are.":
        "ภาษาของเมนู ปุ่ม และข้อความ ผลสแกน รายละเอียด CVE และไฟล์ export คงเดิม",
    "Save language": "บันทึกภาษา",
    "Last sign-in": "เข้าสู่ระบบล่าสุด",
    "now": "ขณะนี้",
    "Member since": "เป็นสมาชิกตั้งแต่",
    "Your recent activity": "กิจกรรมล่าสุดของคุณ",
    "When": "เวลา",
    "Action": "การกระทำ",
    "Target": "เป้าหมาย",
    "No activity yet": "ยังไม่มีกิจกรรม",
    "Profile saved": "บันทึกโปรไฟล์แล้ว",
    "Menu preference saved": "บันทึกการตั้งค่าเมนูแล้ว",
    "That email address does not look valid.": "รูปแบบอีเมลไม่ถูกต้อง",
    "{label} pages": "หน้าใน {label}",
    "Error": "ข้อผิดพลาด",
    "Access denied": "ไม่มีสิทธิ์เข้าถึง",
    "Your role does not allow this action ({perm}).": "บทบาทของคุณไม่มีสิทธิ์ทำสิ่งนี้ ({perm})",
    "The form expired or the request was not sent from this application. Reload the page and try again.":
        "ฟอร์มหมดอายุหรือคำขอไม่ได้ส่งมาจากระบบนี้ โหลดหน้าใหม่แล้วลองอีกครั้ง",
    "Not found": "ไม่พบหน้า",
    "The page or item you asked for does not exist.": "ไม่พบหน้าหรือรายการที่คุณต้องการ",
    "You are signed in as": "คุณเข้าสู่ระบบในชื่อ",
    "with the": "ด้วยบทบาท",
    "role. Ask an administrator if you need more access.": "หากต้องการสิทธิ์เพิ่ม ให้ติดต่อผู้ดูแลระบบ",
    "Go back": "ย้อนกลับ",
    # nav groups / items / tabs (app/navigation.py)
    "Dashboard": "แดชบอร์ด",
    "Issues": "Issues",
    "Raw findings": "ผลดิบ (finding)",
    "Campaigns": "Campaigns",
    "0-day watch": "เฝ้าระวัง 0-day",
    "Inventory": "Inventory",
    "Changes": "การเปลี่ยนแปลง",
    "Discovered": "ที่ค้นพบ",
    "Reports": "รายงาน",
    "Scanning": "การสแกน",
    "New scan": "สแกนใหม่",
    "Quick": "Quick",
    "Nmap": "Nmap",
    "Nuclei": "Nuclei",
    "Discovery": "Discovery",
    "Jobs": "Jobs",
    "Automation": "อัตโนมัติ",
    "Scopes": "Scopes",
    "Schedules": "ตารางสแกน",
    "Detection library": "คลังการตรวจจับ",
    "Templates & rules": "Templates และกฎ",
    "Templates": "Templates",
    "Version rules": "กฎเวอร์ชัน",
    "System": "ระบบ",
    "Updates": "อัปเดต",
    "API": "API",
    "Users": "ผู้ใช้",
    "Settings": "ตั้งค่า",
    "Integrations": "การเชื่อมต่อ",
    "AI assistant": "ผู้ช่วย AI",
    "Audit log": "Audit log",
    # roles and permissions (app/authz.py)
    "Admin": "ผู้ดูแลระบบ",
    "Analyst": "นักวิเคราะห์",
    "Viewer": "ผู้ดู",
    "Everything, including updates, user management and the audit log.":
        "ทำได้ทุกอย่าง รวมถึงอัปเดต จัดการผู้ใช้ และดู audit log",
    "Run scans, triage issues, manage inventory, version rules and templates.":
        "สั่งสแกน คัดกรอง issue จัดการ inventory, version rule และ template",
    "Read-only access to every page.": "ดูได้ทุกหน้า แก้ไขไม่ได้",
    "Read every page, job log, finding and inventory row": "ดูทุกหน้า, log ของ job, finding และ inventory",
    "Start nmap / nuclei scans and cancel jobs": "สั่งสแกน nmap / nuclei และยกเลิก job",
    "Delete inventory services or clear the inventory": "ลบ service ใน inventory หรือล้าง inventory",
    "Create, edit, toggle, delete and evaluate version rules": "สร้าง แก้ไข เปิด/ปิด ลบ และประเมิน version rule",
    "Upload, pull, delete and reindex nuclei templates": "อัปโหลด ดึง ลบ และ reindex nuclei template",
    "Triage issues: change status, assign, change severity, comment":
        "คัดกรอง issue: เปลี่ยนสถานะ มอบหมาย เปลี่ยน severity และแสดงความเห็น",
    "Create and run 0-day campaigns: intel, version rules, templates":
        "สร้างและรัน campaign 0-day: intel, version rule, template",
    "Define scopes (asset groups, owners, criticality) and scheduled scans":
        "กำหนด scope (กลุ่ม asset, เจ้าของ, ความสำคัญ) และตารางสแกน",
    "Update nmap, nuclei and the nuclei templates": "อัปเดต nmap, nuclei และ nuclei template",
    "Create, edit, deactivate and delete users": "สร้าง แก้ไข ปิดการใช้งาน และลบผู้ใช้",
    "Read and export the audit log": "ดูและ export audit log",
    "Change platform settings such as remediation SLAs": "เปลี่ยนการตั้งค่าระบบ เช่น SLA การแก้ไข",
    "Configure notification channels, rules and ticketing integrations":
        "ตั้งค่าช่องทางแจ้งเตือน กฎ และการเชื่อมต่อระบบ ticket",
    "Ask the AI assistant: drafts, explanations, triage, search, summaries":
        "ใช้ผู้ช่วย AI: ร่าง campaign อธิบาย คัดกรอง ค้นหา และสรุป",
    "Configure AI providers and API keys, see AI usage": "ตั้งค่า AI provider และ API key ดูการใช้งาน AI",
}

# Areas still being translated live in app/i18n_th_*.py (ENTRIES dicts) and are merged here.
import importlib as _importlib  # noqa: E402
import pkgutil as _pkgutil  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

for _m in sorted(_pkgutil.iter_modules([str(_Path(__file__).parent)]), key=lambda m: m.name):
    if _m.name.startswith("i18n_th_"):
        CATALOG_TH.update(_importlib.import_module(f"app.{_m.name}").ENTRIES)
