async def handler(request):
    body = await request.body()
    return body

