# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The iOS half: the Objective-C++ TurboModule and the Swift beside it
# (ios/Bridge), over the Sipral Swift package. That package is the root
# Package.swift of Sipral's own repository, whose binary target is the
# XCFramework a release carries as an asset (scripts/package/xcframework.sh
# --release), so by default the pod asks for that repository at exactly this
# package's version. SIPRAL_SWIFT_PACKAGE names another place for it: a
# directory, such as the spm/ directory scripts/package/xcframework.sh
# writes, or the URL of another repository holding it.

require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))
swift_package = ENV["SIPRAL_SWIFT_PACKAGE"]
if swift_package.nil? || swift_package.empty?
  swift_package = package["repository"]["url"] + ".git"
end

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

  spm_dependency(s,
    url: swift_package,
    requirement: { kind: "exactVersion", version: package["version"] },
    products: ["Sipral"]
  )

  install_modules_dependencies(s)
end
