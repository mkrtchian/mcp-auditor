Output demo.gif

Set Shell "bash"
Set FontSize 19
Set Width 1200
Set Height 600
Set Padding 20
Set TypingSpeed 80ms
Set PlaybackSpeed 4
Set Theme "Catppuccin Mocha"

Env PS1 "$ "

# Setup: install tool and cd to neutral directory (hidden)
Hide
Type "uv tool install --force --from ../.. mcp-auditor -q" Enter
Sleep 10s
Type "mkdir -p /tmp/sandbox && cd /tmp/sandbox" Enter
Sleep 500ms
Type "clear" Enter
Sleep 500ms
Show

# Type the command (4 tools that reliably produce findings)
Type "mcp-auditor run --budget 5 --tools read_file,write_file,directory_tree,move_file -- npx @modelcontextprotocol/server-filesystem /tmp/sandbox"
Sleep 1s
Enter

# Wait for audit to complete (~40s with 4 tools at budget 5)
Sleep 50s

# Pause on the final output so the viewer can read the results
Sleep 10s
