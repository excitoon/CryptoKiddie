#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "net/http"
require "open3"
require "uri"

BRIDGE_URL = ENV.fetch("CRYPTOKIDDIE_GOSUSLUGI_BRIDGE_URL", "http://127.0.0.1:18765")
TARGET_URL = ENV.fetch("CRYPTOKIDDIE_GOSUSLUGI_TAB_URL", "gosuslugi")

def safari_javascript(script)
  apple_script = <<~APPLESCRIPT
    tell application "Safari"
      repeat with w in windows
        repeat with t in tabs of w
          if (URL of t) contains #{TARGET_URL.to_json} then
            return do JavaScript #{script.to_json} in t
          end if
        end repeat
      end repeat
      error "No Safari tab URL contains #{TARGET_URL}"
    end tell
  APPLESCRIPT
  stdout, stderr, status = Open3.capture3("osascript", stdin_data: apple_script)
  abort(stderr.empty? ? "osascript failed" : stderr) unless status.success?
  stdout.strip
end

requests_json = safari_javascript(<<~JAVASCRIPT)
  JSON.stringify(
    window.__cryptokiddieBridgeQueue && window.__cryptokiddieBridgeQueue.requests
      ? window.__cryptokiddieBridgeQueue.requests.splice(0)
      : []
  )
JAVASCRIPT

requests = JSON.parse(requests_json.empty? ? "[]" : requests_json)
puts "requests=#{requests.length}"

requests.each do |request|
  id = request.fetch("id")
  path = request.fetch("path")
  payload = request.fetch("payload")
  uri = URI.join(BRIDGE_URL, path)

  begin
    response = Net::HTTP.post(uri, JSON.generate(payload), "content-type" => "application/json")
    ok = response.is_a?(Net::HTTPSuccess)
    body = ok ? JSON.parse(response.body) : { "error" => "CryptoKiddie bridge HTTP #{response.code}" }
  rescue StandardError => error
    ok = false
    body = { "error" => error.message }
  end

  safari_javascript("window.__cryptokiddieBridgeDeliver(#{id.to_json}, #{ok ? "true" : "false"}, #{JSON.generate(body)});")
  puts "delivered id=#{id} path=#{path} ok=#{ok}"
end