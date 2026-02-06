def handler(request, response):
    # This should be flagged.
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")

