import re

filepath = "/Users/safwanonakkal/Gitea/nwc_polar/node_manage/lnd_node.py"

with open(filepath, 'r') as f:
    content = f.read()

def replacement(match):
    indent = match.group(1)
    log_stmt = match.group(2)
    return_stmt = match.group(3)
    
    # We only care about replacing standard {"error": str(e)} lines
    if '"error": str(e)' not in return_stmt and 'return []' not in return_stmt and 'return' != return_stmt.strip():
        return match.group(0) # don't touch
    
    # extract action name from logger
    action_match = re.search(r'Error (.*?):', log_stmt)
    action_name = action_match.group(1) if action_match else "during request"

    # special handling if there's no error return
    if 'return []' in return_stmt or 'return' == return_stmt.strip():
        # Maybe just leave them alone or log them?
        # User said "return {"error": str(e)}"
        pass

    fallback_return = return_stmt.replace('str(e)', 'e.response.text if e.response is not None else str(e)')

    new_block = f"""{indent}except requests.exceptions.HTTPError as e:
{indent}    logger.error(f"HTTP error {action_name}: {{e}}")
{indent}    try:
{indent}        if e.response is not None:
{indent}            error_body = e.response.json()
{indent}            if "message" in error_body:
{indent}                return {{"error": error_body["message"]}}
{indent}    except Exception:
{indent}        pass
{indent}    return {{"error": e.response.text if e.response is not None else str(e)}}
{indent}except Exception as e:
{log_stmt}
{return_stmt}"""
    return new_block

pattern = re.compile(
    r'( +)except Exception as e:\n(\s+logger\.error\([^\n]+\))\n(\s+return \{"error": str\(e\)\}|\s+return \[\]|\s+return)',
    re.MULTILINE
)

# Wait, `settle_hold_invoice` is already handled, let's not double-add to it.
# Actually it was already changed to `except requests.exceptions.HTTPError as e:` so the pattern `except Exception as e:` won't match its log statement because it's not the first except block... wait, yes it is.
# Let's ensure we don't double wrap.

new_content = pattern.sub(replacement, content)

with open(filepath, 'w') as f:
    f.write(new_content)
