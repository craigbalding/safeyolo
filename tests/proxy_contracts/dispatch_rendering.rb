# Run with the existing Pages pipeline's github-pages 232 gem environment:
# SAFEYOLO_BUILD_REVISION=<full commit> SAFEYOLO_BUILD_PROFILE=production bundle exec ruby \
#   tests/proxy_contracts/dispatch_rendering.rb /absolute/path/to/safeyolo
# This focused native producer/Jekyll consumer test does not publish a site.

require "cgi"
require "fileutils"
require "open3"
require "tmpdir"

gem "jekyll", "3.10.0"
gem "liquid", "4.0.4"
gem "kramdown", "2.4.0"
gem "kramdown-parser-gfm", "1.1.0"
gem "rouge", "3.30.0"
require "jekyll"

native = File.realpath(ARGV.fetch(0))
revision = ENV.fetch("SAFEYOLO_BUILD_REVISION")
profile = ENV.fetch("SAFEYOLO_BUILD_PROFILE", "production")
version, error, status = Open3.capture3(native, "--version")
raise "native identity mismatch: #{version} #{error}" unless status.success? &&
  revision.match?(/\A[0-9a-f]{40}\z/) && version.include?(revision) && version.include?("profile=#{profile}")

repo = File.expand_path("../..", __dir__)
fixture = File.join(__dir__, "fixtures/dispatch-inert.json")

Dir.mktmpdir("dispatch-rendering-") do |temporary|
  source = File.join(temporary, "site")
  destination = File.join(temporary, "rendered")
  manifests = File.join(source, "_sources/dispatch")
  FileUtils.mkdir_p(manifests)
  FileUtils.cp(fixture, File.join(manifests, "source.json"))
  commands = [
    ["dispatch", "generate", fixture, "--output-root", source],
    ["dispatch", "generate", fixture, "--output-root", source, "--check"],
    ["dispatch", "check-site", "--site-root", source]
  ]
  commands.each do |arguments|
    output, error, status = Open3.capture3(native, *arguments)
    raise "#{arguments.join(' ')}: #{output} #{error}" unless status.success?
  end

  # Use the repository's publication configuration and theme. The raw control
  # establishes that Liquid is actually evaluated in this rendering run.
  FileUtils.cp(File.join(repo, "site/_config.yml"), File.join(source, "_config.yml"))
  File.write(File.join(source, "control.md"),
    "---\nlayout: default\npermalink: /control/\n---\n\nCONTROL {{ 17 | plus: 4 }}\n\nENTITY CONTROL Probe &amp; end.\n\nSTRIKE CONTROL Probe ~~gone~~ end.\n")
  config = Jekyll.configuration("source" => source, "destination" => destination,
    "config" => File.join(source, "_config.yml"), "quiet" => true)
  Jekyll::Site.new(config).process

  visible = lambda do |path|
    html = File.read(File.join(destination, path))
    [html, CGI.unescapeHTML(html.gsub(/<[^>]*>/, ""))]
  end
  control_html, control = visible.call("control/index.html")
  raise "raw Liquid control did not evaluate" unless control.include?("CONTROL 21")
  raise "raw entity control did not decode" unless control.include?("ENTITY CONTROL Probe & end.")
  raise "raw strikethrough control did not format" unless control_html.match?(/<(?:s|del)>gone<\/(?:s|del)>/)
  pages = {
    "dispatch/2026-08-29/index.html" => ["Theme", "Title", "Body liquid", "Definition",
      "Evidence", "Snippet", "Lesson"],
    "topics/literal-copy/index.html" => ["Topic", "Summary liquid", "Definition", "State",
      "Topic evidence"]
  }
  pages.each do |path, labels|
    html, text = visible.call(path)
    labels.each do |label|
      expected = "#{label} {{ 17 | plus: 4 }} {% endraw %} &amp; ~~gone~~"
      raise "literal copy changed: #{expected}" unless text.include?(expected)
    end
    raise "editorial link became active" if html.include?('href="a"') || html.include?('href="missing"')
    raise "editorial strikethrough became active" if html.match?(/<(?:s|del)(?:\s|>)/)
    raise "public evidence link changed" unless html.include?('href="https://github.com/craigbalding/safeyolo/issues/437"')
  end
  _, dispatch = visible.call("dispatch/2026-08-29/index.html")
  ["[a](a)", "{{- 17 | plus: 4 -}}", "{{ '{{' }}", "{% include missing %}",
    "after [example](missing)", "Probe &amp; end.", "Probe ~~gone~~ end."].each do |expected|
    raise "literal example changed: #{expected}" unless dispatch.include?(expected)
  end
end

puts "Native Dispatch generation/checking and pinned Jekyll literal rendering passed."
puts version.strip
puts "Jekyll #{Jekyll::VERSION}; Liquid #{Liquid::VERSION}; Kramdown #{Kramdown::VERSION}"
