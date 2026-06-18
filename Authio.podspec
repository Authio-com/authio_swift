# Deprecated: CocoaPods trunk publishing was removed after trunk sunset.
# This podspec supports git-sourced installs only (see README).
Pod::Spec.new do |s|
  s.name             = "Authio"
  s.version          = "0.2.0"
  s.summary          = "Authio Swift SDK — passwordless, multi-org auth for iOS / macOS / visionOS."
  s.description      = <<-DESC
    Authio is the developer-first passwordless auth platform for B2B SaaS.
    This Swift SDK ships first-class passkeys (ASAuthorizationController),
    OAuth via ASWebAuthenticationSession, magic links, and secure session
    storage in the Keychain. Built for iOS 16+, macOS 13+, and visionOS 1+.
  DESC
  s.homepage         = "https://authio.com"
  s.license          = { :type => "MIT", :file => "LICENSE" }
  s.author           = { "Authio" => "releases@authio.com" }
  s.source           = {
    :git => "https://github.com/authio-com/authio_swift.git",
    :tag => "v#{s.version}"
  }

  s.swift_version    = "5.9"
  s.ios.deployment_target     = "16.0"
  s.osx.deployment_target     = "13.0"
  s.visionos.deployment_target = "1.0"

  s.source_files     = "Sources/Authio/**/*.swift"
  s.frameworks       = "Foundation", "AuthenticationServices"
end
