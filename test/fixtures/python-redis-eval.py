async def ok(redis_client, script, key):
  # Redis uses `.eval(...)` to run Lua scripts; this should not be flagged as
  # Python built-in `eval(...)`.
  return await redis_client.eval(script, 1, key)

