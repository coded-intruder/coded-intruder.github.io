#!/bin/bash
 
# ================================
# 🧠 Jekyll Blog Publish Script
# Author: Coded-Intruder (codedintrusion.com)
# Purpose: Preview your Jekyll site locally, then push changes.
# ================================
 
set -e
 
# Check for commit message
if [ -z "$1" ]; then
  echo "❌ Commit message required!"
  echo "Usage: ./publish.sh \"post: your message\""
  exit 1
fi
 
# Build locally and preview before pushing
echo "🧪 Building and serving locally..."
echo "👉 Visit http://127.0.0.1:4000 to preview your site."
 
# Run Jekyll serve in background
bundle exec jekyll serve --livereload &
 
# Capture PID to stop server later
JEKYLL_PID=$!
 
# Wait a bit for server to start
sleep 5
 
read -p "👀 Preview done? Type 'y' to push, anything else to cancel: " confirm
 
if [[ $confirm == "y" || $confirm == "Y" ]]; then
    echo "🚀 Pushing changes to GitHub..."
    git add .
    git commit -m "$1"
    git push origin main
    echo "✅ Done! Blog will update on codedintrusion.com shortly."
else
    echo "🛑 Cancelled. No changes pushed."
fi
 
# Kill local Jekyll server
kill $JEKYLL_PID >/dev/null 2>&1
