"""Запросы дополнительного времени: создание ребёнком и решение родителем."""
from __future__ import annotations

from datetime import datetime, timezone

from . import db, policy


async def create(pool, cfg, tg, username: str, minutes: int, reason: str) -> str:
    now_local = datetime.now(timezone.utc).astimezone(cfg.tz)
    async with pool.acquire() as conn:
        child = await db.get_child(conn, username)
        if not child:
            return "Вы не в списке детей"
        pending = await conn.fetchval(
            "SELECT count(*) FROM ft_requests WHERE username = $1 AND status = 'pending' "
            "AND day = $2", username, now_local.date())
        if pending:
            return "Запрос уже отправлен, дождись ответа"
        rid = await conn.fetchval(
            "INSERT INTO ft_requests (username, day, minutes, reason) VALUES ($1,$2,$3,$4) RETURNING id",
            username, now_local.date(), minutes, reason[:300])
        st = await db.child_status(conn, username, now_local)
        chats = await tg.chats_for(conn, username)
    line = (f"Сегодня: {policy.fmt_minutes(st['counted_seconds'])} из "
            f"{policy.fmt_minutes(st['limit_seconds'])}, учёба {policy.fmt_minutes(st['free_seconds'])}")
    await tg.notify_request(rid, child["display_name"], minutes, reason, line, chats)
    return "Запрос отправлен родителям"


async def decide(pool, cfg, tg, req_id: int, approve: bool, by: str) -> str:
    async with pool.acquire() as conn:
        async with conn.transaction():
            r = await conn.fetchrow("SELECT * FROM ft_requests WHERE id = $1 FOR UPDATE", req_id)
            if not r:
                return "Запрос не найден"
            if r["status"] != "pending":
                return "Уже решено: " + ("дано" if r["status"] == "approved" else "отказано")
            status = "approved" if approve else "denied"
            await conn.execute(
                "UPDATE ft_requests SET status = $2, decided_by = $3, decided_at = now() WHERE id = $1",
                req_id, status, by)
            if approve:
                await db.add_bonus(conn, r["username"], r["day"], r["minutes"],
                                   "по запросу: " + (r["reason"] or ""), by)
    line = (f"✅ Дано {r['minutes']} мин ({by})" if approve else f"❌ Отказано ({by})")
    await tg.mark_decided(req_id, line)
    return "Готово: " + ("дано" if approve else "отказано")
