# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The iOS half: the Objective-C++ TurboModule and the Swift beside it
# (ios/Bridge), over the Sipral Swift package. That package is the one
# scripts/package/xcframework.sh writes -- a binary target around the
# library -- and SIPRAL_SWIFT_PACKAGE names where it is: a directory, or the
# URL of a git repository holding it. Nothing is published yet, so there is
# no default to fall back on, and pod install says so rather than guess.

require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))
swift_package = ENV["SIPRAL_SWIFT_PACKAGE"]

Pod::Spec.new do |s|
  s.name         = "sipral-react-native"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.license      = package["license"]
  s.author       = package["author"]
  s.homepage     = package["homepage"]
  s.source       = { :path => "." }
  s.platforms    = { :ios => "16.0" }
  s.swift_version = "5.9"

  s.source_files = "ios/*.mm", "ios/Bridge/*.swift"
  s.pod_target_xcconfig = { "DEFINES_MODULE" => "YES" }

  if swift_package.nil? || swift_package.empty?
    raise "sipral-react-native: set SIPRAL_SWIFT_PACKAGE to the Sipral Swift package " \
          "(the directory scripts/package/xcframework.sh wrote, or a git URL holding it) before pod install"
  end
  spm_dependency(s,
    url: swift_package,
    requirement: { kind: "exactVersion", version: package["version"] },
    products: ["Sipral"]
  )

  install_modules_dependencies(s)
end
