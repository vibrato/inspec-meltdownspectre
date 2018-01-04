# encoding: utf-8
# author: Nathan Dines

control 'Meltdown and Spectre Vulnerability Check' do
  impact 1.0
  title 'Linux Patch status for Meltdown and Spectre vulnerabilities'
  desc 'Validates status of infrastructure against Meltdown and Spectre'

  if os.linux? then
    describe file('/proc/cpuinfo') do
      its('content') { should match /^bugs\s+:.* cpu_insecure / }
    end
  end
end
