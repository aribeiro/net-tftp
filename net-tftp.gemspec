require 'rubygems'
require './lib/net/tftp'

spec = Gem::Specification.new do |s|
  s.name = 'net-tftp'
  s.version = Net::TFTP::VERSION
  s.platform = Gem::Platform::RUBY
  s.summary =
    "Net::TFTP is a pure Ruby implementation of the Trivial File Transfer Protocol (RFC 1350)"
  s.files = ["lib/net/tftp.rb"]
  s.files << "README.txt"
  s.files << "LICENSE.txt"
  s.files << "GPL.txt"
  s.require_path = 'lib'
  s.autorequire = 'net/tftp'

  s.has_rdoc=true

#  s.test_suite_file = 'test/ALL-TESTS.rb'

  s.author = "Guillaume Marcais"
  s.email = "guillaume.marcais@free.fr"
  s.homepage = "http://net-tftp.rubyforge.org"
end

if $0 == __FILE__
  Gem::manage_gems rescue nil
  Gem::Builder.new(spec).build
end
