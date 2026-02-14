#!/bin/bash

# 1. 기존 서버 종료 (포트 3000)
echo "Stopping existing server on port 3000..."
PID=$(lsof -ti:3000)
if [ -n "$PID" ]; then
  kill -9 $PID
  echo "Server stopped (PID: $PID)"
else
  echo "No server running on port 3000"
fi

# 2. 빌드 실행
echo "Building application..."
npm run build

# 3. 빌드 성공 시 서버 시작
if [ $? -eq 0 ]; then
  echo "Build successful! Starting server..."
  npm start
else
  echo "Build failed. Please check the errors above."
  exit 1
fi
