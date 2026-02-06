from starlette.middleware.cors import CORSMiddleware


def add(app):
    # This should be flagged.
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)

