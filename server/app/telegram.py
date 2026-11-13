"""Уведомления родителям в Telegram: запрос дополнительного времени с кнопками «Дать» / «Отказать».

Опрос Telegram ведёт один узел — держатель pg_try_advisory_lock (второй ждёт и подхватывает).
"""
from __future__ import annotations

import asyncio
import html
import logging
from datetime import datetime, timezone

import httpx

from . import db

log = logging.getLogger("familytime.telegram")


class Telegram:
    def __init__(self, cfg, http: httpx.AsyncClient, pool):
        self.cfg = cfg
        self.http = http
        self.pool = pool

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.telegram_token and self.cfg.telegram_chat_ids)

    def _url(self, method: str) -> str:
        return f"https://api.telegram.org/bot{self.cfg.telegram_token}/{method}"

    async def call(self, method: str, **params):
        r = await self.http.post(self._url(method), json=params, timeout=40)
        data = r.json()
        if not data.get("ok"):
            log.warning("telegram %s: %s", method, data.get("description"))
        return data.get("result")

    async def notify_request(self, req_id: int, child_name: str, minutes: int, reason: str,
                             status_line: str) -> None:
        if not self.enabled:
            return
        text = (f"⏱ <b>{html.escape(child_name)}</b> просит ещё <b>{minutes} мин</b>\n"
                f"{html.escape(status_line)}")
        if reason:
            text += f"\nПричина: {html.escape(reason)}"
        kb = {"inline_keyboard": [[
            {"text": f"✅ Дать {minutes} мин", "callback_data": f"ft:ok:{req_id}"},
            {"text": "❌ Отказать", "callback_data": f"ft:no:{req_id}"},
        ], [{"text": "Открыть портал", "url": self.cfg.public_url + "/requests"}]]}
        sent = []
        for chat in self.cfg.telegram_chat_ids:
            try:
                m = await self.call("sendMessage", chat_id=chat, text=text, parse_mode="HTML",
                                    reply_markup=kb)
                if m:
                    sent.append({"chat": chat, "id": m["message_id"], "text": text})
            except httpx.HTTPError as e:
                log.warning("telegram: %s", e)
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE ft_requests SET tg_messages = $2 WHERE id = $1", req_id, sent)

    async def mark_decided(self, req_id: int, line: str) -> None:
        """Убирает кнопки у всех копий уведомления и дописывает решение."""
        if not self.enabled:
            return
        async with self.pool.acquire() as conn:
            msgs = await conn.fetchval("SELECT tg_messages FROM ft_requests WHERE id = $1", req_id)
        for m in msgs or []:
            try:
                await self.call("editMessageText", chat_id=m["chat"], message_id=m["id"],
                                text=m["text"] + "\n\n" + html.escape(line), parse_mode="HTML")
            except httpx.HTTPError:
                pass

    async def _handle_callback(self, cb: dict) -> None:
        from . import requests_logic
        chat = str(cb.get("message", {}).get("chat", {}).get("id", ""))
        data = cb.get("data", "")
        who = cb.get("from", {})
        by = "telegram:" + (who.get("username") or str(who.get("id", "")))
        if chat not in self.cfg.telegram_chat_ids or not data.startswith("ft:"):
            await self.call("answerCallbackQuery", callback_query_id=cb["id"], text="Нет доступа")
            return
        _, action, rid = data.split(":", 2)
        res = await requests_logic.decide(self.pool, self.cfg, self, int(rid), action == "ok", by)
        await self.call("answerCallbackQuery", callback_query_id=cb["id"], text=res)

    async def run(self) -> None:
        """Фоновый опрос getUpdates под advisory lock."""
        if not self.enabled:
            return
        while True:
            try:
                async with self.pool.acquire() as conn:
                    got = await conn.fetchval("SELECT pg_try_advisory_lock($1)", db.TELEGRAM_LOCK)
                    if not got:
                        await asyncio.sleep(30)
                        continue
                    try:
                        await self._poll_loop(conn)
                    finally:
                        await conn.execute("SELECT pg_advisory_unlock($1)", db.TELEGRAM_LOCK)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — опрос не должен падать навсегда
                log.warning("telegram poll: %s", e)
                await asyncio.sleep(10)

    async def _poll_loop(self, conn) -> None:
        offset = int(await db.kv_get(conn, "tg_offset") or 0)
        while True:
            updates = await self.call("getUpdates", offset=offset, timeout=25,
                                      allowed_updates=["callback_query"]) or []
            for u in updates:
                offset = max(offset, u["update_id"] + 1)
                if "callback_query" in u:
                    try:
                        await self._handle_callback(u["callback_query"])
                    except Exception as e:  # noqa: BLE001
                        log.warning("telegram callback: %s", e)
            if updates:
                await db.kv_set(conn, "tg_offset", str(offset))
            else:
                await asyncio.sleep(1)      # на случай, если Telegram ответил сразу
            await conn.execute("SELECT 1")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
