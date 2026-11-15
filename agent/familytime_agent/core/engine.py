"""Логика агента без привязки к Windows: учёт времени, режимы, сообщения, связь с сервером.

Всё, что касается Windows, — в объекте platform (familytime_agent.win.platform), поэтому
логику можно проверять на любой системе с поддельной платформой.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass

from .. import VERSION
from . import rules
from .client import ApiError, Client
from .state import State, Store

log = logging.getLogger("familytime.engine")

TICK = 5
HEARTBEAT = 60
CLOSE_GRACE = 10          # с: после WM_CLOSE программа закрывается принудительно
HELPER_MISSING_LOGOFF = 90
HELPER_RESTART = 60       # с: помощник молчит дольше — перезапуск
LOCK_GRACE = 4            # с: помощник не заблокировал экран — блокирует служба (отключает сеанс)
POLICY_LIMIT = 1000       # столько адресов принимают политики браузеров
BLOCK_REPEAT = 3          # с: как часто повторять закрытие вкладки с запрещённым сайтом
LIST_KEYS = ("edu_apps", "edu_domains", "blocked_apps", "blocked_domains", "restricted_domains")
DEFAULT_DEVICE = {
    "mode": "control", "edu_apps": [], "edu_domains": [], "restricted_domains": [],
    "blocked_domains": [],
    "browsers": ["chrome.exe", "msedge.exe", "browser.exe"], "blocked_apps": [],
    "restricted_kill": [], "idle_minutes": 15, "warn_minutes": [10, 5],
    "location_interval": 900, "portal_url": "", "lost": {"on": False, "lock": False, "message": ""},
}


@dataclass
class Session:
    id: int
    user: str          # sAMAccountName в нижнем регистре
    domain: str
    locked: bool

    @property
    def state(self) -> str:
        return "locked" if self.locked else "active"


class Engine:
    def __init__(self, cfg: dict, store: Store, platform, client: Client | None = None,
                 clock=time.time, mono=time.monotonic):
        self.cfg = cfg
        self.store = store
        self.st: State = store.load()
        self.p = platform
        self.client = client or Client(cfg["server_url"], f"familytime-agent/{VERSION}")
        self.clock = clock
        self.mono = mono
        self.last_mono: float | None = None
        self.last_heartbeat = -1e9
        self.last_enroll_try = -1e9
        self.helper_launch_at: dict[int, float] = {}
        self.helper_seen: dict[int, float] = {}
        self.mode_by_user: dict[str, str] = {}
        self.browser_policy: dict[tuple, tuple | None] = {}
        self.close_seen: dict[int, float] = {}
        self.notify_seq = 0
        self.notify: dict | None = None
        self.close_browsers: dict | None = None
        self.last_restricted_toast = -1e9
        self.last_logoff = -1e9
        self.unlocked_since: dict[int, float] = {}
        self.last_service_lock = -1e9
        self.notice_state: str | None = "?"      # что сейчас на экране входа (неизвестно)
        self.ext: dict = {}                      # внешний адрес: {"at", "ip", "geo"}
        self.want_wifi = False
        self.last_current: dict = {}
        self.block_sent: dict[str, float] = {}
        self.block_toast = -1e9
        self.update_tries: dict[str, float] = {}     # версия → когда пробовали обновиться
        self.update_thread = None
        self.lists_path = os.path.join(os.path.dirname(store.path) or ".", "lists.json")
        self.lists: dict = self._load_lists()
        self._rules_cache: dict[str, tuple] = {}
        self._dev_key = None
        self._dev_src = None
        self._dev: dict = {}
        if not self.st.hostname:
            self.st.hostname = platform.hostname()

    # ---------- списки (сервер 1.1+: отдельно, по версии) ----------

    def _load_lists(self) -> dict:
        try:
            with open(self.lists_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save_lists(self) -> None:
        tmp = self.lists_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.lists, f, ensure_ascii=False)
            os.replace(tmp, self.lists_path)
        except OSError as e:
            log.warning("не удалось сохранить списки: %s", e)

    def _fetch_lists(self, user: str, want: str) -> dict | None:
        try:
            r = self.client.post("/api/agent/lists", {"user": user} if user else {}, self.st.token)
        except (ApiError, OSError, ValueError) as e:
            log.warning("списки%s не загружены: %s", f" ({user})" if user else "", e)
            return None
        got = {k: r.get(k, []) for k in LIST_KEYS}
        got["version"] = r.get("version", want)
        log.info("списки%s обновлены: %s", f" ({user})" if user else "",
                 {k: len(got[k]) for k in LIST_KEYS})
        return got

    def sync_lists(self) -> None:
        """Сервер 1.2: у каждого ребёнка свои списки (версия — в его политике).
        Сервер 1.1: один набор на компьютер (версия — в политике устройства)."""
        changed = False
        want = (self.st.device or {}).get("lists_version")
        if want and want != self.lists.get("version"):
            got = self._fetch_lists("", want)
            if got:
                self.lists = {**got, "users": self.lists.get("users", {})}
                changed = True
        users = self.lists.setdefault("users", {})
        for user, pol in (self.st.users or {}).items():
            want = pol.get("lists_version") if pol.get("child") else None
            if want and want != users.get(user, {}).get("version"):
                got = self._fetch_lists(user, want)
                if got:
                    users[user] = got
                    changed = True
        for user in [u for u in users if not (self.st.users.get(u) or {}).get("child")]:
            del users[user]                       # ребёнка убрали из списка — его списки не нужны
            changed = True
        if changed:
            self._save_lists()
            self._rules_cache.clear()

    # ---------- общее ----------

    @staticmethod
    def _finish(d: dict) -> dict:
        """Списки — множества для быстрого поиска (их бывают сотни тысяч); порядок для
        политик браузеров — в *_order (ручные записи сервер ставит первыми)."""
        d["blocked_domains_order"] = list(d["blocked_domains"])
        d["restricted_domains"] = list(d["restricted_domains"])
        for k in ("edu_apps", "edu_domains", "blocked_apps", "blocked_domains"):
            d[k] = frozenset(d[k])
        return d

    def _base(self) -> dict:
        d = dict(DEFAULT_DEVICE)
        d["mode"] = self.cfg.get("mode", "control")
        d.update(self.st.device or {})
        if d.get("lists_version") and self.lists.get("version"):
            d.update({k: self.lists.get(k, []) for k in LIST_KEYS})
        return d

    @property
    def dev(self) -> dict:
        """Политика устройства: режим, локация, «потерян» и общий набор списков (сервер 1.1)."""
        # сам объект st.device (не id: адрес освобождённого словаря может достаться новому)
        key = (self.lists.get("version"), self.cfg.get("mode"))
        if self._dev_key == key and self._dev_src is self.st.device:
            return self._dev
        d = self._finish(self._base())
        self._dev_key, self._dev, self._dev_src = key, d, self.st.device
        return d

    def rules_for(self, user: str, pol: dict) -> dict:
        """Правила для вошедшего ребёнка: его списки, простой и предупреждения поверх
        политики устройства. На сервере 1.1 у ребёнка своих нет — берётся общий набор."""
        own = (self.lists.get("users") or {}).get(user)
        if not pol.get("lists_version") and "idle_minutes" not in pol:
            return self.dev
        c = self._rules_cache.get(user)
        ver = (own or {}).get("version")
        if c and c[0] is self.st.device and c[1] is pol and c[2] == ver:
            return c[3]
        d = self._base()
        if pol.get("lists_version"):
            d.update({k: (own or {}).get(k, []) for k in LIST_KEYS})
        for k in ("idle_minutes", "warn_minutes", "restricted_kill"):
            if k in pol:
                d[k] = pol[k]
        d = self._finish(d)
        self._rules_cache[user] = (self.st.device, pol, ver, d)
        return d

    def now_local(self, wall: float):
        return rules.local_now(self.st.server_offset, self.st.utc_offset, wall)

    def save(self) -> None:
        try:
            self.store.save(self.st)
        except OSError as e:
            log.warning("не удалось сохранить состояние: %s", e)

    def _notify(self, kind: str, text: str, wall: float, ttl: int, modal: bool = False) -> None:
        self.notify_seq += 1
        self.notify = {"id": f"{int(wall)}-{self.notify_seq}", "kind": kind, "text": text,
                       "modal": modal, "expires": wall + ttl,
                       "portal": self.dev.get("portal_url", "")}

    # ---------- шаг (каждые TICK секунд) ----------

    def step(self) -> None:
        wall, mono = self.clock(), self.mono()
        dt = 0.0 if self.last_mono is None else max(0.0, min(mono - self.last_mono, 30.0))
        self.last_mono = mono
        self.ensure_token(mono)

        sess = self.p.console_session()
        report = self.p.helper_report(sess.id) if sess else None
        if sess:
            if report is not None:
                self.helper_seen[sess.id] = mono
            elif (mono - self.helper_launch_at.get(sess.id, -1e9) > HELPER_RESTART
                  and mono - self.helper_seen.get(sess.id, -1e9) > HELPER_RESTART):
                # не было ни запуска, ни отчёта минуту — (пере)запускаем; пропуск пары
                # отчётов у живого помощника перезапуска не вызывает
                self.helper_launch_at[sess.id] = mono
                self.helper_seen.setdefault(sess.id, mono)
                try:
                    self.p.launch_helper(sess.id)
                except Exception as e:  # noqa: BLE001
                    log.warning("помощник не запустился: %s", e)

        dev = self.dev
        directive = {"mode": "none", "close": [], "close_browsers": False, "lost": None,
                     "want_wifi": self.want_wifi, "remaining": None, "notify": None}
        lost_lock = bool(dev["lost"].get("on") and dev["lost"].get("lock"))
        if dev["lost"].get("on"):
            directive["lost"] = {"message": dev["lost"].get("message", ""), "lock": lost_lock}
        # сообщение на экране входа — только пока компьютер потерян с запретом входа
        self.set_logon_notice(dev["lost"].get("message", "") if lost_lock else None)
        if lost_lock and sess:
            self.lock(sess, mono, directive, "компьютер потерян")

        user = sess.user if sess else ""
        pol = self.st.users.get(user) if user else None
        if sess and dev["mode"] == "control" and pol and pol.get("child"):
            rules_ = self.rules_for(user, pol)       # сайты, программы, простой — этого ребёнка
            self.account(sess, report, dt, wall, rules_)
            self.enforce(sess, report, wall, mono, pol, rules_, directive)
        elif sess and (pol is not None or dev["mode"] != "control"):
            # не ребёнок (или компьютер «только локация») — снять всё, что агент мог оставить:
            # запреты сайтов, «только учёба», отключённые инкогнито и гостевой режим
            self.release_all(sess)
        if sess and not directive.get("lock"):
            self.unlocked_since.pop(sess.id, None)      # блокировать больше не нужно
        if self.notify and self.notify["expires"] > wall:
            directive["notify"] = self.notify
        if self.close_browsers and self.close_browsers["expires"] > wall \
                and directive["mode"] == "restricted":
            directive["close_browsers"] = self.close_browsers["id"]
        if sess:
            self.p.set_directive(sess.id, directive)

        if mono - self.last_heartbeat >= HEARTBEAT or (user and user not in self.st.users
                                                         and mono - self.last_heartbeat >= 10):
            self.last_heartbeat = mono
            if self.heartbeat(sess, report, wall) and self.st.pending \
                    and wall - self.st.pending[0]["t"] > 90:
                self.heartbeat(sess, report, wall)      # догоняем накопленное без связи
        if wall - self.st.last_location >= dev["location_interval"]:
            self.location(sess, report, wall)

    # ---------- блокировка ----------

    def lock(self, sess: Session, mono: float, directive: dict, why: str) -> None:
        """Заблокировать экран сразу (Win+L делает помощник) и держать заблокированным:
        если сеанс разблокирован дольше LOCK_GRACE, служба отключает его сама."""
        directive["lock"] = True
        if sess.locked:
            self.unlocked_since.pop(sess.id, None)
            return
        first = self.unlocked_since.setdefault(sess.id, mono)
        if mono - first >= LOCK_GRACE and mono - self.last_service_lock >= LOCK_GRACE:
            self.last_service_lock = mono
            log.info("%s: блокирую сеанс %s (%s)", sess.user, sess.id, why)
            try:
                self.p.lock_session(sess.id)
            except Exception as e:  # noqa: BLE001
                log.warning("сеанс не заблокирован: %s", e)

    def set_logon_notice(self, text: str | None) -> None:
        if text == self.notice_state:
            return
        try:
            self.p.set_logon_notice("Компьютер потерян" if text else None, text)
            self.notice_state = text
        except Exception as e:  # noqa: BLE001
            log.warning("сообщение на экране входа: %s", e)

    # ---------- учёт ----------

    def is_active(self, sess: Session, report: dict | None, dev: dict) -> bool:
        if sess.locked:
            return False
        if report is None:
            return True                     # без помощника — считаем, что работает
        if report.get("locked"):
            return False
        idle_lim = int(dev.get("idle_minutes") or 0) * 60
        if idle_lim and report.get("idle", 0) >= idle_lim and not report.get("fullscreen"):
            return False
        return True

    def account(self, sess: Session, report: dict | None, dt: float, wall: float, dev: dict) -> None:
        fg = (report or {}).get("fg") or {}
        exe, domain = rules.norm_exe(fg.get("exe")), rules.norm_domain(fg.get("domain"))
        app = (fg.get("app") or "")[:80]
        self.last_current = {"exe": exe, "domain": domain, "app": app}
        if dt <= 0 or not self.is_active(sess, report, dev):
            return
        free = rules.is_free(exe, domain, dev)
        start = wall - dt
        last = self.st.pending[-1] if self.st.pending else None
        if (last and last["user"] == sess.user and last["exe"] == exe and last["domain"] == domain
                and abs(last["t"] + last["sec"] - start) < 15 and last["sec"] < 3000
                and self.now_local(last["t"]).date() == self.now_local(wall).date()):
            last["sec"] += dt
            if app:
                last["app"] = app
        else:
            self.st.pending.append({"t": start, "user": sess.user, "sec": dt, "exe": exe,
                                    "domain": domain, "app": app, "free": free})

    def pending_counted(self, user: str, wall: float) -> int:
        today = self.now_local(wall).date()
        samples = list(self.st.pending)
        if self.st.inflight:
            samples += self.st.inflight["samples"]
        return int(sum(s["sec"] for s in samples
                       if s["user"] == user and not s.get("free")
                       and self.now_local(s["t"]).date() == today))

    # ---------- режимы ----------

    def enforce(self, sess, report, wall, mono, pol, dev, directive) -> None:
        user = sess.user
        ev = rules.evaluate(pol, self.now_local(wall), self.pending_counted(user, wall))
        prev = self.mode_by_user.get(user)
        self.mode_by_user[user] = ev["mode"]
        directive.update(mode=ev["mode"], remaining=ev["remaining"], reason=ev["reason"])
        msgs = pol.get("messages", {})
        day = self.now_local(wall).date().isoformat()
        w = self.st.warned.get(user)
        if not w or w.get("day") != day:
            w = self.st.warned[user] = {"day": day, "levels": []}

        if ev["mode"] == "normal" and ev["remaining"] is not None:
            due = [m for m in dev["warn_minutes"] if ev["remaining"] <= m * 60]
            new = [m for m in due if m not in w["levels"]]
            if new:
                w["levels"] = sorted(set(w["levels"]) | set(due))
                text = msgs.get("warn", "").replace("{left}", rules.fmt_minutes(ev["remaining"]))
                self._notify("warn", text, wall, ttl=60)
        if ev["mode"] == "normal" and ev["remaining"] is not None and w["levels"]:
            # дали ещё времени — предупреждения снова сработают
            w["levels"] = [m for m in w["levels"] if ev["remaining"] <= m * 60]

        if ev["mode"] == "blocked":
            if prev != "blocked":
                log.info("%s: время блокировки — компьютер заблокирован", user)
            directive["block"] = {"message": msgs.get("block", "")}
            self.set_browsers(sess, True, dev)
            self.lock(sess, mono, directive, "время блокировки")
            return
        if ev["mode"] == "restricted" and prev != "restricted":
            text = msgs.get(ev["reason"] or "limit", "")
            self._notify(ev["reason"] or "limit", text, wall, ttl=600, modal=True)
            self.last_restricted_toast = mono       # не перекрывать главное сообщение
            if prev is not None:
                # браузеры закрываются один раз, чтобы открытые страницы попали под политику
                self.close_browsers = {"id": self.notify["id"], "expires": wall + 60}
            log.info("%s: режим «только учёба» (%s)", user, ev["reason"])
        if ev["mode"] == "normal" and prev == "restricted":
            log.info("%s: обычный режим", user)

        self.set_browsers(sess, ev["mode"] == "restricted", dev)
        self.block_site(report, wall, mono, dev, directive)

        # процессы
        kill_always = set(dev.get("blocked_apps", []))
        kill_restricted = set(dev.get("restricted_kill", []))
        for pid, exe in self.p.session_processes(sess.id):
            exe = rules.norm_exe(exe)
            if exe in kill_always or (ev["mode"] == "restricted" and exe in kill_restricted):
                log.info("%s: закрываю %s (%s)", user, exe, pid)
                self.p.kill(pid)
        if ev["mode"] == "restricted":
            if report is not None:
                alive = set()
                for win in report.get("windows", []):
                    pid, exe = int(win.get("pid", 0)), rules.norm_exe(win.get("exe"))
                    if not pid or rules.allowed_in_restricted(exe, dev):
                        continue
                    alive.add(pid)
                    first = self.close_seen.setdefault(pid, mono)
                    directive["close"].append(pid)
                    if mono - first >= CLOSE_GRACE:
                        log.info("%s: принудительно закрываю %s (%s)", user, exe, pid)
                        self.p.kill(pid)
                    if mono - self.last_restricted_toast > 60:
                        self.last_restricted_toast = mono
                        self._notify("info", msgs.get(
                            "restricted", "Сейчас работают только учебные программы и сайты."),
                            wall, ttl=15)
                self.close_seen = {k: v for k, v in self.close_seen.items() if k in alive}
            elif mono - self.helper_seen.get(sess.id, mono) > HELPER_MISSING_LOGOFF \
                    and not sess.locked and mono - self.last_logoff > 60:
                self.last_logoff = mono
                log.warning("%s: помощник не отвечает в режиме «только учёба» — выход", user)
                self.p.logoff(sess.id)
        else:
            self.close_seen.clear()

    def block_site(self, report, wall, mono, dev, directive) -> None:
        """Запрещённый сайт в активной вкладке — закрыть вкладку. Это для записей сверх
        POLICY_LIMIT и для вкладок, открытых до обновления политики."""
        fg = (report or {}).get("fg") or {}
        exe, domain = rules.norm_exe(fg.get("exe")), rules.norm_domain(fg.get("domain"))
        if not domain or exe not in dev["browsers"] \
                or not rules.domain_matches(domain, dev["blocked_domains"]):
            return
        if mono - self.block_sent.get(domain, -1e9) < BLOCK_REPEAT:
            return
        self.block_sent[domain] = mono
        self.notify_seq += 1
        directive["close_tab"] = {"id": f"{int(wall)}-{self.notify_seq}",
                                  "hwnd": fg.get("hwnd"), "domain": domain}
        log.info("запрещённый сайт %s — закрываю вкладку", domain)
        if mono - self.block_toast > 30:
            self.block_toast = mono
            self._notify("info", f"Сайт {domain} запрещён.", wall, ttl=10)

    def set_browsers(self, sess: Session, restricted: bool, dev: dict) -> None:
        key = (sess.id, sess.user)
        blocked = tuple(dev["blocked_domains_order"][:POLICY_LIMIT])
        allowed = None
        if restricted:
            allowed = tuple(d for d in dev["restricted_domains"]
                            if not rules.domain_matches(d, dev["blocked_domains"]))[:POLICY_LIMIT]
        want = (allowed, blocked)
        if self.browser_policy.get(key, "unknown") == want:
            return
        try:
            self.p.set_browser_policy(sess.id, sess.user, sess.domain,
                                      list(allowed) if allowed is not None else None,
                                      list(blocked))
            self.browser_policy[key] = want
        except Exception as e:  # noqa: BLE001
            log.warning("политики браузеров: %s", e)

    def release_all(self, sess: Session) -> None:
        """Снимает политики браузеров у текущего пользователя (один раз за запуск службы — это
        чистит и то, что осталось с прошлых запусков) и у всех, кому агент их ставил."""
        keys = {(sess.id, sess.user): sess.domain}
        keys.update({k: "" for k in self.browser_policy if k not in keys})
        for (sid, user), domain in keys.items():
            if self.browser_policy.get((sid, user)) == "cleared":
                continue
            try:
                self.p.clear_browser_policy(sid, user, domain)
                self.browser_policy[(sid, user)] = "cleared"
            except Exception as e:  # noqa: BLE001
                log.warning("политики браузеров: %s", e)

    # ---------- сервер ----------

    def ensure_token(self, mono: float) -> None:
        if self.st.token or mono - self.last_enroll_try < 60:
            return
        self.last_enroll_try = mono
        try:
            r = self.client.post("/api/agent/enroll", {
                "hostname": self.st.hostname, "secret": self.cfg.get("enroll_secret", ""),
                "mode": self.cfg.get("mode", "control"), "os": self.p.os_version(),
                "agent_version": VERSION})
            self.st.token = r["token"]
            self.save()
            log.info("зарегистрирован как %s", r.get("hostname"))
        except (ApiError, OSError, ValueError, KeyError) as e:
            log.warning("регистрация не удалась: %s", e)

    def heartbeat(self, sess: Session | None, report: dict | None, wall: float) -> bool:
        if not self.st.token:
            return False
        if not self.st.inflight:
            samples = []
            for s in self.st.pending:
                sec = int(round(s["sec"]))
                if sec >= 1:
                    samples.append({"t": int(s["t"]), "user": s["user"], "sec": min(sec, 3600),
                                    "exe": s["exe"], "domain": s["domain"],
                                    "app": s.get("app", ""), "free": s.get("free", False)})
            self.st.inflight = {"seq": self.st.seq + 1, "samples": samples[:4000]}
            self.st.pending = []
            self.save()
        batch = self.st.inflight
        body = {
            "seq": batch["seq"], "agent_version": VERSION, "os": self.p.os_version(),
            "session": sess.state if sess else "none", "user": sess.user if sess else "",
            "current": self.last_current if sess else None,
            "samples": [{k: v for k, v in s.items() if k != "free"} for s in batch["samples"]],
            "caps": ["lists", "userlists", "update"],
        }
        t0 = self.clock()
        try:
            r = self.client.post("/api/agent/heartbeat", body, self.st.token)
        except ApiError as e:
            if e.status == 401:
                log.warning("сервер не знает токен — регистрируюсь заново")
                self.st.token = ""
                self.save()
            else:
                log.warning("пульс: %s", e)
            return False
        except (OSError, ValueError) as e:
            log.info("нет связи с сервером: %s", e)
            return False
        t1 = self.clock()
        self.st.seq = batch["seq"]
        self.st.inflight = None
        self.st.device = r.get("device") or {}
        for u, p in (r.get("users") or {}).items():
            self.st.users[u] = p
        self.st.server_offset = float(r.get("server_time", t1)) - (t0 + t1) / 2
        self.st.utc_offset = int(r.get("utc_offset", self.st.utc_offset))
        self.st.policy_wall = t1
        self.save()
        self.sync_lists()
        self.maybe_update(r.get("update"), t1)
        return True

    UPDATE_RETRY = 6 * 3600

    def maybe_update(self, upd: dict | None, wall: float) -> None:
        """Сервер предложил новую версию: скачать, проверить и переустановиться (в фоне).
        Неудачная попытка повторяется не раньше чем через 6 часов."""
        if not upd or not hasattr(self.p, "self_update"):
            return
        ver = str(upd.get("version") or "")
        sha = str(upd.get("sha256") or "")
        if not ver or ver == VERSION or not sha:
            return
        if wall - self.update_tries.get(ver, -1e18) < self.UPDATE_RETRY:
            return
        if self.update_thread is not None and self.update_thread.is_alive():
            return
        self.update_tries[ver] = wall
        url = self.cfg["server_url"].rstrip("/") + str(upd.get("url") or "/agent/package.zip")

        def run():
            try:
                log.info("обновление до %s: скачиваю %s", ver, url)
                self.p.self_update(url, sha, ver)
                log.info("обновление до %s запущено — служба перезапустится", ver)
            except Exception as e:  # noqa: BLE001
                log.warning("обновление до %s не удалось: %s", ver, e)

        self.update_thread = threading.Thread(target=run, name="update", daemon=True)
        self.update_thread.start()

    def external_ip(self, wall: float) -> dict:
        """Внешний адрес компьютера и место по нему — у службы вроде ip-api.com, напрямую
        с компьютера. Не чаще раза в 5 минут; не вышло — последний известный."""
        url = self.dev.get("ext_ip_url")
        if not url:
            return {}
        if self.ext and wall - self.ext.get("at", 0) < 300:
            return self.ext
        try:
            d = self.p.http_json(url)
        except Exception as e:  # noqa: BLE001
            log.info("внешний адрес не получен: %s", e)
            return self.ext
        ip = str(d.get("query") or d.get("ip") or "").strip()
        if not ip or d.get("status") == "fail":
            return self.ext
        geo = None
        lat, lon = d.get("lat", d.get("latitude")), d.get("lon", d.get("longitude"))
        if lat not in (None, "") and lon not in (None, ""):
            geo = {"lat": float(lat), "lon": float(lon), "city": str(d.get("city") or "")[:60]}
        self.ext = {"at": wall, "ip": ip[:64], "geo": geo}
        return self.ext

    def location(self, sess: Session | None, report: dict | None, wall: float) -> None:
        if not self.st.token:
            return
        interval = self.dev["location_interval"]
        wifi = self.p.wifi_scan()
        if wifi is None:                     # служба не может сканировать — просим помощника
            self.want_wifi = True
            rw = (report or {}).get("wifi")
            wifi = rw["aps"] if rw and wall - rw.get("at", 0) < 300 else []
        battery, on_ac = self.p.battery()
        ext = self.external_ip(wall)
        body = {"wifi": wifi[:100], "battery": battery, "on_ac": on_ac,
                "session": sess.state if sess else "none", "user": sess.user if sess else "",
                "ext_ip": ext.get("ip", ""), "ext_geo": ext.get("geo"),
                "reason": "lost" if self.dev["lost"].get("on") else "timer"}
        try:
            r = self.client.post("/api/agent/location", body, self.st.token)
            self.st.last_location = wall
            nxt = int(r.get("next_interval") or interval)
            if nxt != interval:
                self.st.device = {**self.st.device, "location_interval": nxt}
        except (ApiError, OSError, ValueError) as e:
            log.info("локация: %s", e)
            self.st.last_location = wall - interval + 120     # повтор через 2 минуты
        self.save()
