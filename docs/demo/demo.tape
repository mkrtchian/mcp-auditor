Output demo.gif

Set Shell "bash"
Set FontSize 22
Set Width 1200
Set Height 600
Set Padding 20
Set TypingSpeed 80ms
Set PlaybackSpeed 4
Set Theme "Catppuccin Mocha"

Env PS1 "$ "

# Setup sandbox directory (hidden)
Hide
Type "mkdir -p /tmp/sandbox" Enter
Sleep 500ms
Show

# Type the command (4 tools that reliably produce findings)
Type "uv run mcp-auditor run --tools read_file,write_file,directory_tree,move_file -- npx @modelcontextprotocol/server-filesystem /tmp/sandbox"
Sleep 1s
Enter

# 4 tools takes ~1min15 + margin for summary display
Sleep 90s
