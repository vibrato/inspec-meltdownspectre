# encoding: utf-8
# author: Nathan Dines

control 'Meltdown and Spectre Vulnerability Check (Windows)' do
  impact 1.0
  title 'Windows Patch status for Meltdown and Spectre vulnerabilities'
  desc 'Validates status of infrastructure against Meltdown and Spectre'

  only_if do
    os.windows?
  end

  # Microsoft Windows KB IDs
  #
  # Source: https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
  #
  # Windows Server, version 1709 (Server Core Installation):  KB4056892
  # Windows Server 2016:                                      KB4056890
  # Windows Server 2012 R2:                                   KB4056898
  # Windows Server 2012:                                      Not available
  # Windows Server 2008 R2:                                   KB4056897
  # Windows Server 2008:                                      Not available

  hotfixes = %w{ KB4056892 KB4056890 KB4056898 KB4056897 }

  describe.one do
    hotfixes.each do |hotfix|
      describe windows_hotfix(hotfix) do
        it { should be_installed }
      end
    end
  end

  describe registry_key('FeatureSettingOverride','HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management') do
    its('FeatureSettingsOverride') { should eq 0 }
  end

  describe registry_key('FeatureSettingOverridemask','HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management') do
    its('FeatureSettingsOverrideMask') { should eq 3 }
  end

  describe registry_key('MinVmVersionForCpuBasedMitigations','HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization') do
    its('MinVmVersionForCpuBasedMitigations') { should eq '1.0'}
  end
end
