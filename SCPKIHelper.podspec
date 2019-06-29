#
# Be sure to run `pod lib lint SCPKIHelper.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'SCPKIHelper'
  s.version          = '0.1.2'
  s.summary          = 'A set of functions to manage Public Key Infraestructure objects.'
  s.swift_versions   = '5.0'
  s.description      = <<-DESC
A set of functions to manage Public Key Infraestructure objects, like: Creating public and private keys, store and retrieve them. Generate CSR, verify signatures, encrypt and decrypt.                       
                       DESC

  s.homepage         = 'https://github.com/libscudo/SCPKIHelper-iOS'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'eaceto' => 'ezequiel.aceto@gmail.com' }
  s.source           = { :git => 'https://github.com/libscudo/SCPKIHelper-iOS.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/eaceto_public'

  s.ios.deployment_target = '10.0'

  s.source_files = 'SCPKIHelper/Classes/**/*'
  
end
