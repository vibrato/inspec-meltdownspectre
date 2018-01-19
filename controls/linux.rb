
# author: Nathan Dines

control 'Meltdown and Spectre Vulnerability Check (Linux)' do
  impact 1.0
  title 'Linux Patch status for Meltdown and Spectre vulnerabilities'
  desc 'Validates status of infrastructure against Meltdown and Spectre'

  only_if do
    result_array = []

    result_array << os.linux?
    # AMD Processors are allegedly not vulnerable due to a different
    # architecture. Do not test if running AMD.
    result_array << !/^vendor_id\s+: AuthenticAMD/.match(file('/proc/cpuinfo').content)

    result_array.all?
  end

  describe file('/proc/cpuinfo') do
    its('content') { should match(/^bugs\s+:.*\bcpu_insecure\b/) }
  end
end
