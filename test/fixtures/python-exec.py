def bad(user_input: str):
    # This should be flagged.
    exec(user_input)

