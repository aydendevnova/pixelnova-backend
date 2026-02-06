const { execSync } = require("child_process");

const PORT = process.env.PORT || 8787;

try {
  const command =
    process.platform === "win32"
      ? `netstat -ano | findstr :${PORT} && FOR /F "tokens=5" %a in ('netstat -ano | findstr :${PORT}') do taskkill /F /PID %a`
      : `lsof -i :${PORT} | grep LISTEN | awk '{print $2}' | xargs kill -9`;

  execSync(command, { stdio: "inherit" });
} catch (error) {
  // Ignore errors if no process is found
}
